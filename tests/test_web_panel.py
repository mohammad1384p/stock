import json
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

import web_panel
from web_panel import PanelState, fmt_ms, panel_handler, strip_ansi, validate_run_request
from datetime import datetime

REQ = {
    "symbol": "وتوصا",
    "quantity": "10",
    "price": "6700",
    "time": "08:44:59.700",
    "side": "buy",
    "duration": "10",
    "interval": "305",
}


def call(url: str, data: dict | None = None, method: str | None = None):
    body = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    req = UrlRequest(url, data=body, headers=headers, method=method)
    try:
        with urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, resp.headers, raw
    except HTTPError as e:  # 4xx/5xx
        return e.code, e.headers, e.read()


class ValidationTests(unittest.TestCase):
    def test_valid_request_is_cleaned(self):
        out = validate_run_request(REQ)
        self.assertEqual(out["symbol"], "وتوصا")
        self.assertEqual(out["quantity"], 10)
        self.assertEqual(out["price"], 6700)
        self.assertEqual(out["duration"], 10.0)
        self.assertEqual(out["interval"], 305)
        self.assertEqual(out["time"], "08:44:59.700")
        self.assertEqual(out["side"], "buy")
        self.assertFalse(out["dry_run"])
        self.assertFalse(out["now"])

    def test_persian_digits_separators_and_defaults(self):
        out = validate_run_request(dict(REQ, symbol="IRO7TONP0001", quantity="1,000"))
        self.assertEqual(out["quantity"], 1000)
        self.assertEqual(out["duration"], 10.0)   # پیش‌فرض
        self.assertEqual(out["interval"], 305)    # پیش‌فرض

    def test_missing_symbol(self):
        with self.assertRaises(ValueError):
            validate_run_request(dict(REQ, symbol="  "))

    def test_bad_numbers_and_empty_time(self):
        with self.assertRaises(ValueError):
            validate_run_request(dict(REQ, quantity="abc"))
        with self.assertRaises(ValueError):
            validate_run_request(dict(REQ, quantity="0"))
        with self.assertRaises(ValueError):
            validate_run_request(dict(REQ, time=""))
        with self.assertRaises(ValueError):
            validate_run_request(dict(REQ, time="8:44:59 pm"))

    def test_now_mode_needs_no_time(self):
        out = validate_run_request(dict(REQ, time="", now=True))
        self.assertTrue(out["now"])

    def test_request_count_guard(self):
        with self.assertRaises(ValueError):
            validate_run_request(dict(REQ, duration=600, interval=1))

    def test_helpers(self):
        self.assertEqual(strip_ansi("\x1b[32mسلام\x1b[0m"), "سلام")
        today = datetime(2026, 10, 8, 8, 44, 59, 700000)
        with mock.patch("web_panel.clock") as fake:
            fake.now.return_value = datetime(2026, 10, 8, 0, 0).timestamp()
            self.assertEqual(fmt_ms(today), "08:44:59.700")


class CaptchaProxyTests(unittest.TestCase):
    """پروکسی صفحه‌ی کپچا روی همان پورت پنل (بدون باز کردن پورت دوم)."""

    @staticmethod
    def _make_stub():
        seen = {}

        class Stub(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):  # noqa: N802
                seen["path"] = self.path
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", "4")
                self.end_headers()
                self.wfile.write(b"pong")

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                seen["body"] = self.rfile.read(n).decode()
                data = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Stub)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        return server, seen

    @classmethod
    def setUpClass(cls):
        cls.stub, cls.seen = cls._make_stub()

    @classmethod
    def tearDownClass(cls):
        cls.stub.shutdown()
        cls.stub.server_close()

    def test_proxy_forwards_get_post_and_body(self):
        portal = SimpleNamespace(port=self.stub.server_address[1], base="/Tok3n")
        status, headers, raw = web_panel.proxy_captcha(portal, "GET", "/Tok3n/captcha.jpg", None, None)
        self.assertEqual(status, 200)
        self.assertEqual(raw, b"pong")
        self.assertEqual(self.seen["path"], "/Tok3n/captcha.jpg")
        self.assertFalse([h for h in headers if h[0].lower() == "transfer-encoding"])

        status, _, raw = web_panel.proxy_captcha(portal, "POST", "/Tok3n/code", b"code=1234",
                                                 "application/x-www-form-urlencoded")
        self.assertEqual(status, 200)
        self.assertEqual(raw, b"ok")
        self.assertEqual(self.seen["body"], "code=1234")


class PanelHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        args = web_panel.parse_args([
            "--host", "127.0.0.1", "--port", "0", "--time-sync", "off",
            "--token-file", str(Path(cls.tmp.name) / "token.json"),
            "--captcha-file", str(Path(cls.tmp.name) / "captcha.png"),
            "--username", "user1",
        ])
        cls.state = PanelState(args)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), panel_handler(cls.state))
        cls.stub, cls.seen = CaptchaProxyTests._make_stub()   # سرور جعلیِ صفحه‌ی کپچا
        cls.httpd.daemon_threads = True
        cls.state.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.state.port}"
        threading.Thread(target=cls.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True, name="panel-test").start()

    @classmethod
    def tearDownClass(cls):
        cls.state.shutdown()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.stub.shutdown()
        cls.stub.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        with self.state.lock:
            self.state.status = "idle"
            self.state.message = "آماده"
            self.state.plan = None
            self.state.stats = None
            self.state.start_ts = None
            self.state.stop_evt = None
            self.state.portal = None
            self.state.login_state = "idle"
            self.state.login_message = ""
        self.state.clear_log()

    def poll_until(self, predicate, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            _, _, raw = call(self.base + "/api/state?after=0")
            snap = json.loads(raw)
            if predicate(snap):
                return snap
            time.sleep(0.05)
        self.fail("وضعیت مورد انتظار در زمان مقرر نرسید")

    def test_index_page_is_served(self):
        status, headers, raw = call(self.base + "/")
        self.assertEqual(status, 200)
        body = raw.decode("utf-8")
        self.assertIn("پنل ربات", body)
        self.assertIn("api/start", body)
        self.assertNotIn("__PORT__", body)
        self.assertIn(str(self.state.port), body)
        self.assertNotIn("x-frame-options", {k.lower() for k in headers.keys()})

    def test_health_state_and_404(self):
        status, _, raw = call(self.base + "/api/health")
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(raw)["ok"])

        status, _, raw = call(self.base + "/api/state?after=0")
        snap = json.loads(raw)
        self.assertEqual(snap["status"], "idle")
        self.assertEqual(snap["tz"], "Asia/Tehran")
        self.assertIn("clock", snap)
        self.assertIn("token", snap)
        self.assertIn("login", snap)

        status, _, _ = call(self.base + "/nope")
        self.assertEqual(status, 404)

    def test_start_rejects_invalid_input(self):
        status, _, raw = call(self.base + "/api/start", {"symbol": "", "quantity": 1, "price": 1}, method="POST")
        self.assertEqual(status, 400)
        self.assertIn("نماد", json.loads(raw)["error"])

    def test_stop_without_run(self):
        status, _, raw = call(self.base + "/api/stop", {}, method="POST")
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(raw)["stopped"])

    def test_keep_alive_connection_survives_post_with_body(self):
        # بدنه‌ی POST باید خوانده شود؛ وگرنه درخواست بعدی روی همان اتصال خراب می‌شود
        import requests

        with requests.Session() as s:
            for _ in range(3):
                r = s.post(self.base + "/api/stop", json={}, timeout=10)
                self.assertEqual(r.status_code, 200, r.text)
            r = s.get(self.base + "/api/state?after=0", timeout=10)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["status"], "idle")

    def test_dry_run_offline_end_to_end(self):
        req = dict(REQ, symbol="IRO7TONP0001", dry_run=True, time_sync="off", now=True)
        status, _, raw = call(self.base + "/api/start", req, method="POST")
        self.assertEqual(status, 200, raw)
        snap = self.poll_until(lambda s: s["status"] == "dry-run")
        self.assertTrue(snap["plan"]["dry_run"])
        self.assertEqual(snap["plan"]["isin"], "IRO7TONP0001")
        self.assertEqual(snap["plan"]["count"], 33)
        logs = "\n".join(line[2] for line in snap["logs"])
        self.assertIn("dry-run", logs)
        self.assertIn("خلاصه‌ی سفارش", logs)
        # بعد از اجرا، دوباره می‌توان شروع کرد (قفل اجرا آزاد است)
        self.assertFalse(self.state.is_running())

    def test_captcha_page_is_proxied_through_panel(self):
        portal = SimpleNamespace(port=self.stub_port(), base="/Tok3n")
        with self.state.lock:
            self.state.portal = portal
        try:
            status, _, raw = call(self.base + "/Tok3n/captcha.jpg")
            self.assertEqual(status, 200, raw)
            self.assertEqual(raw, b"pong")
            status, _, raw = call(self.base + "/api/state")
            self.assertEqual(json.loads(raw)["login"]["captcha"], "/Tok3n/")
        finally:
            with self.state.lock:
                self.state.portal = None

    def stub_port(self) -> int:
        return self.stub.server_address[1]


if __name__ == "__main__":
    unittest.main()
