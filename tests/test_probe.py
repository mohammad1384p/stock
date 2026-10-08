"""تست‌های ابزار کاوش امنیتی (probe_order) و یکدست‌سازی هدرهای شناسایی."""
import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import requests

import probe_order
from exir_auth import login, save_token
from exir_bot import (Stats, build_session, clientid_value, format_request, identity_notes,
                      send_order, preview_request)

BASE = "https://broker.example"


def fake_jwt(exp_offset: int = 3600) -> str:
    def enc(obj):
        raw = json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc({'sub': 'tester', 'exp': time.time() + exp_offset})}.sig"


class FakeBroker:
    """کارگزار جعلی: بر اساس هدرهای درخواست سفارش، 9009 یا 422 برمی‌گرداند."""

    def __init__(self, decide):
        self.decide = decide
        self.requests: list[dict] = []
        broker = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):  # noqa: N802
                self._reply(200, {"ok": True})

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else ""
                broker.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                status, payload = broker.decide(dict(self.headers), body)
                self._reply(status, payload)

            def _reply(self, status, payload):
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def order_requests(self):
        return [r for r in self.requests if r["path"].endswith("/api/v1/order")]


class ProbeTests(unittest.TestCase):
    def probe_args(self, extra):
        with TemporaryDirectory() as tmp:
            token_file = Path(tmp) / "token.json"
            save_token(token_file, "http://127.0.0.1:1", "x")  # فقط برای ساخت پوشه
            return probe_order.parse_args(["--token-file", str(token_file)] + extra)

    def test_body_is_always_invalid_unless_forced(self):
        body = probe_order.safe_body()
        self.assertEqual((body["quantity"], body["price"]), (0, 0))
        self.assertEqual(body["insMaxLcode"], probe_order.SAFE_ISIN)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "order.json"
            path.write_text(json.dumps({"quantity": 500, "price": 12345}), encoding="utf-8")
            kept, _ = probe_order.body_from_file(str(path), allow_real=True)
            self.assertEqual((kept["quantity"], kept["price"]), (500, 12345))
            zeroed, _ = probe_order.body_from_file(str(path), allow_real=False)
            self.assertEqual((zeroed["quantity"], zeroed["price"]), (0, 0))
            self.assertEqual(kept["price"], 12345)  # فایل دست‌نخورده می‌ماند

    def test_classify(self):
        self.assertEqual(probe_order.classify(403, {"errorCode": 9009})[0], probe_order.VERDICT_SECURITY)
        self.assertEqual(probe_order.classify(401, {})[0], probe_order.VERDICT_SECURITY)
        self.assertEqual(probe_order.classify(422, {"type": "error"})[0], probe_order.VERDICT_PASSED)
        self.assertEqual(probe_order.classify(200, {"type": "success"})[0], probe_order.VERDICT_ACCEPTED)
        self.assertEqual(probe_order.classify(302, {})[0], probe_order.VERDICT_REDIRECT)

    def test_unknown_variant_is_rejected(self):
        variants = [probe_order.Variant("current", "x")]
        with self.assertRaises(SystemExit):
            probe_order.select_variants(variants, ["nope"])

    def test_variants_cover_the_login_headers_not_sent_before(self):
        args = probe_order.parse_args([])
        names = [v.name for v in probe_order.build_variants(args, BASE)]
        for expected in ("current", "no-clientid", "app-n-digits", "no-app-n", "bearer",
                         "jwt-only-cookie", "warm-page", "referer-login"):
            self.assertIn(expected, names)
        with_candidates = probe_order.parse_args(["--app-n-candidate", "2018887747744.29964494",
                                                  "--clientid-candidate", "abc"])
        names = [v.name for v in probe_order.build_variants(with_candidates, BASE)]
        self.assertIn("app-n-copied", names)
        self.assertIn("clientid-value", names)

    def test_probe_finds_the_header_that_matters(self):
        candidate = "2018887747744.29964494"

        def decide(headers, _body):
            if headers.get("x-app-n") == candidate:
                return 422, {"type": "error", "description": "قیمت نامعتبر"}
            return 403, {"type": "error", "errorCode": 9009, "description": "مشکل امنیتی"}

        broker = FakeBroker(decide)
        try:
            with TemporaryDirectory() as tmp:
                token_file = Path(tmp) / "token.json"
                save_token(token_file, broker.base, fake_jwt(), {"appN": "NaN.12345678"})
                report_path = Path(tmp) / "report.json"
                code = probe_order.main(["--yes", "--base-url", broker.base,
                                         "--token-file", str(token_file),
                                         "--app-n-candidate", candidate,
                                         "--delay", "0", "--timeout", "5",
                                         "--json", str(report_path)])
                self.assertEqual(code, 0)
                report = json.loads(report_path.read_text(encoding="utf-8"))
            verdicts = {r["variant"]: r["verdict"] for r in report["results"]}
            self.assertEqual(verdicts["current"], probe_order.VERDICT_SECURITY)
            self.assertEqual(verdicts["no-clientid"], probe_order.VERDICT_SECURITY)
            self.assertEqual(verdicts["app-n-copied"], probe_order.VERDICT_PASSED)
            self.assertEqual([c["variant"] for c in report["fix_candidates"]], ["app-n-copied"])
            # هر درخواستی که رفت، بدنه‌ی نامعتبر داشت → هیچ سفارش واقعی ثبت نمی‌شود
            for sent in broker.order_requests():
                payload = json.loads(sent["body"])
                self.assertEqual((payload["quantity"], payload["price"]), (0, 0))
            # خروجی گزارش نباید مقدار حساس توکن را داشته باشد
            self.assertNotIn("sig", json.dumps(report["results"][0]["request"]))
        finally:
            broker.close()

    def test_probe_without_yes_sends_nothing(self):
        calls = []

        def decide(headers, body):  # pragma: no cover - نباید صدا زده شود
            calls.append(headers)
            return 200, {}

        broker = FakeBroker(decide)
        try:
            with TemporaryDirectory() as tmp:
                token_file = Path(tmp) / "token.json"
                save_token(token_file, broker.base, fake_jwt())
                code = probe_order.main(["--base-url", broker.base, "--token-file", str(token_file)])
            self.assertEqual(code, 0)
            self.assertEqual(broker.requests, [])
        finally:
            broker.close()

    def test_real_body_requires_a_single_variant(self):
        broker = FakeBroker(lambda h, b: (200, {}))
        try:
            with TemporaryDirectory() as tmp:
                token_file = Path(tmp) / "token.json"
                save_token(token_file, broker.base, fake_jwt())
                code = probe_order.main(["--yes", "--allow-real-body", "--base-url", broker.base,
                                         "--token-file", str(token_file), "--delay", "0"])
            self.assertEqual(code, 2)
            self.assertEqual(broker.requests, [])
        finally:
            broker.close()

    def test_probe_stops_without_token(self):
        broker = FakeBroker(lambda h, b: (200, {}))
        try:
            with TemporaryDirectory() as tmp:
                code = probe_order.main(["--yes", "--base-url", broker.base,
                                         "--token-file", str(Path(tmp) / "missing.json")])
            self.assertEqual(code, 2)
            self.assertEqual(broker.requests, [])
        finally:
            broker.close()


class IdentityHeaderTests(unittest.TestCase):
    def test_clientid_defaults_to_empty_like_the_browser_login_request(self):
        args = SimpleNamespace(base_url=BASE, cookie=None, app_n=None, header=[])
        session = build_session(args, 1)
        req = session.prepare_request(requests.Request("POST", BASE + "/api/v1/order", json={}))
        self.assertIn("clientid", req.headers)
        self.assertEqual(req.headers["clientid"], "")

    def test_clientid_off_and_explicit_value_and_H_override(self):
        args = SimpleNamespace(base_url=BASE, cookie=None, app_n=None, header=[], clientid="off")
        self.assertIsNone(clientid_value(args))
        self.assertNotIn("clientid", build_session(args, 1).headers)
        args.clientid = "device-1"
        self.assertEqual(build_session(args, 1).headers["clientid"], "device-1")
        args.header = ["clientid: from-H"]
        self.assertEqual(build_session(args, 1).headers["clientid"], "from-H")

    def test_login_sends_the_session_clientid(self):
        session = requests.Session()
        session.headers["clientid"] = "device-42"
        response = requests.Response()
        response.status_code = 200
        response._content = b'{"authToken":"t"}'
        with patch("exir_auth.fetch_captcha", return_value=b"img"), patch("exir_auth.show_captcha"), \
                patch("exir_auth.obtain_captcha", return_value=("1234", "stdin")), \
                patch.object(session, "post", return_value=response) as post:
            login(session, BASE, "u", "p", captcha_url=None, otp=None, captcha_path=None,
                  log=lambda _: None)
        self.assertEqual(post.call_args.kwargs["headers"]["clientid"], "device-42")

    def test_identity_notes_warn_about_nan_pattern(self):
        session = requests.Session()
        session.headers["x-app-n"] = "NaN.12345678"
        notes = identity_notes(session)
        self.assertTrue(any("NaN" in n for n in notes))
        session.headers.pop("x-app-n")
        self.assertTrue(any("x-app-n فرستاده نمی‌شود" in n for n in identity_notes(session)))


class RequestDumpTests(unittest.TestCase):
    def test_format_request_masks_secrets(self):
        session = requests.Session()
        session.headers["Authorization"] = "Bearer supersecrettokenvalue"
        prepared = session.prepare_request(requests.Request("POST", BASE + "/api/v1/order",
                                                            headers={"Cookie": "JWT-TOKEN=abcdefghijklmnop"},
                                                            json={"quantity": 1}))
        dump = format_request(prepared)
        self.assertIn("POST /api/v1/order HTTP/1.1", dump)
        self.assertIn("JWT-TOKEN=abcdefgh…", dump)
        self.assertNotIn("supersecrettokenvalue", dump)
        self.assertIn('"quantity":1', dump.replace(" ", ""))

    def test_preview_request_matches_session_headers(self):
        args = SimpleNamespace(base_url=BASE, cookie=None, app_n="app-1", header=[], clientid="cid")
        session = build_session(args, 1)
        dump = preview_request(session, "POST", BASE + "/api/v1/order", b'{"a":1}')
        self.assertIn("x-app-n: app-1", dump)
        self.assertIn("clientid: cid", dump)

    def test_send_order_logs_the_request_that_was_sent_once(self):
        args = SimpleNamespace(base_url=BASE, cookie=None, app_n="app-1", header=[], clientid="cid")
        session = build_session(args, 1)
        prepared = session.prepare_request(requests.Request("POST", BASE + "/api/v1/order",
                                                            headers={"Cookie": "JWT-TOKEN=abcdefghijklmnop"},
                                                            data=b"{}"))
        response = requests.Response()
        response.status_code = 403
        response.request = prepared
        response.headers["Content-Type"] = "application/json"
        response._content = json.dumps({"type": "error", "errorCode": 9009}).encode()
        stats = Stats()
        stats.sent = 2
        event = threading.Event()
        logged: list[str] = []
        with patch.object(session, "post", return_value=response), patch("exir_bot.log", side_effect=logged.append):
            send_order(1, session, BASE + "/api/v1/order", b"{}", 1, None, stats, event, True)
            send_order(2, session, BASE + "/api/v1/order", b"{}", 1, None, stats, event, True)
        text = "\n".join(str(x) for x in logged)
        self.assertEqual(text.count("📤"), 1)  # فقط یک‌بار در هر اجرا
        self.assertIn("JWT-TOKEN=abcdefgh…", text)
        self.assertIn("clientid: cid", text)
        self.assertTrue(event.is_set())


if __name__ == "__main__":
    unittest.main()
