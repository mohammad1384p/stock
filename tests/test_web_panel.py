import json
import os
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


def call(url: str, data: dict | None = None, method: str | None = None, key: str | None = None,
         extra_headers: dict | None = None):
    body = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    if key:
        headers[web_panel.PANEL_KEY_HEADER] = key
    headers.update(extra_headers or {})
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
        cls.key = cls.state.panel_key
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
            _, _, raw = call(self.base + "/api/state?after=0", key=self.key)
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

        status, _, raw = call(self.base + "/api/state?after=0", key=self.key)
        snap = json.loads(raw)
        self.assertEqual(snap["status"], "idle")
        self.assertEqual(snap["tz"], "Asia/Tehran")
        self.assertIn("clock", snap)
        self.assertIn("token", snap)
        self.assertIn("login", snap)

        status, _, _ = call(self.base + "/nope", key=self.key)
        self.assertEqual(status, 404)

    def test_start_rejects_invalid_input(self):
        status, _, raw = call(self.base + "/api/start", {"symbol": "", "quantity": 1, "price": 1},
                              method="POST", key=self.key)
        self.assertEqual(status, 400)
        self.assertIn("نماد", json.loads(raw)["error"])

    def test_stop_without_run(self):
        status, _, raw = call(self.base + "/api/stop", {}, method="POST", key=self.key)
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(raw)["stopped"])

    def test_keep_alive_connection_survives_post_with_body(self):
        # بدنه‌ی POST باید خوانده شود؛ وگرنه درخواست بعدی روی همان اتصال خراب می‌شود
        import requests

        with requests.Session() as s:
            s.headers[web_panel.PANEL_KEY_HEADER] = self.key
            for _ in range(3):
                r = s.post(self.base + "/api/stop", json={}, timeout=10)
                self.assertEqual(r.status_code, 200, r.text)
            r = s.get(self.base + "/api/state?after=0", timeout=10)
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["status"], "idle")

    def test_dry_run_offline_end_to_end(self):
        req = dict(REQ, symbol="IRO7TONP0001", dry_run=True, time_sync="off", now=True)
        status, _, raw = call(self.base + "/api/start", req, method="POST", key=self.key)
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
            status, _, raw = call(self.base + "/api/state", key=self.key)
            self.assertEqual(json.loads(raw)["login"]["captcha"], "/Tok3n/")
        finally:
            with self.state.lock:
                self.state.portal = None

    def stub_port(self) -> int:
        return self.stub.server_address[1]

    # ---------- کلید پنل ----------
    def test_api_refuses_requests_without_the_panel_key(self):
        for url in ("/api/state?after=0", "/api/symbols", "/nope"):
            status, _, raw = call(self.base + url)
            self.assertEqual(status, 401, url)
            self.assertIn("X-Panel-Key", json.loads(raw)["error"])
        status, _, _ = call(self.base + "/api/state?after=0", key="w" * 32)
        self.assertEqual(status, 401)
        self.assertEqual(call(self.base + "/api/state?after=0", key=self.key)[0], 200)

    def test_public_paths_stay_open_without_key(self):
        status, _, raw = call(self.base + "/")
        self.assertEqual(status, 200)
        self.assertIn("X-Panel-Key", raw.decode("utf-8"))   # صفحه‌ی پنل هدر کلید را می‌فرستد
        status, _, raw = call(self.base + "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), {"ok": True})      # بدون کلید: فقط سلامت، بدون نسخه/وضعیت
        _, _, raw = call(self.base + "/api/health", key=self.key)
        self.assertIn("version", json.loads(raw))

    def test_post_without_key_cannot_start_a_run(self):
        req = dict(REQ, symbol="IRO7TONP0001", dry_run=True, time_sync="off", now=True)
        status, _, raw = call(self.base + "/api/start", req, method="POST")
        self.assertEqual(status, 401, raw)
        self.assertFalse(self.state.is_running())
        self.assertEqual(self.state.status, "idle")

    def test_wrong_key_is_refused_for_every_action(self):
        req = dict(REQ, symbol="IRO7TONP0001", dry_run=True, time_sync="off", now=True)
        actions = (("/api/start", req), ("/api/login", {"username": "u", "password": "p"}),
                   ("/api/forget-token", {}), ("/api/clear-log", {}), ("/api/sync", {}), ("/api/stop", {}))
        for path, body in actions:
            status, _, _ = call(self.base + path, body, method="POST", key="w" * 32)
            self.assertEqual(status, 401, path)
        self.assertFalse(self.state.is_running())
        self.assertEqual(self.state.login_state, "idle")

    def test_text_plain_form_post_from_another_site_is_refused(self):
        # فرم HTML بیرونی: Content-Type متن ساده و بدون هدر کلید؛ حتی با Origin جعلی نباید اجرا شود
        req = dict(REQ, symbol="IRO7TONP0001", dry_run=True, time_sync="off", now=True)
        status, _, _ = call(self.base + "/api/start", req, method="POST",
                            extra_headers={"Content-Type": "text/plain", "Origin": "https://evil.example"})
        self.assertEqual(status, 401)
        self.assertFalse(self.state.is_running())

    def test_cors_preflight_is_not_answered(self):
        # پاسخ پیش‌پرواز CORS نباید مجوز بدهد؛ پس مرورگر درخواست واقعی با هدر کلید را نمی‌فرستد
        status, headers, _ = call(self.base + "/api/start", None, method="OPTIONS",
                                  extra_headers={"Origin": "https://evil.example",
                                                 "Access-Control-Request-Method": "POST",
                                                 "Access-Control-Request-Headers": "x-panel-key"})
        self.assertNotEqual(status, 200)
        self.assertIsNone(headers.get("Access-Control-Allow-Origin"))


class PanelKeyConfigTests(unittest.TestCase):
    def test_default_host_is_loopback_only(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("EXIR_PANEL_HOST", None)
            args = web_panel.parse_args([])
        self.assertEqual(args.host, "127.0.0.1")

    def test_panel_key_from_flag_or_env_and_minimum_length(self):
        self.assertEqual(web_panel.parse_args(["--panel-key", "k" * 20]).panel_key, "k" * 20)
        with mock.patch.dict(os.environ, {"EXIR_PANEL_KEY": "e" * 18}):
            self.assertEqual(web_panel.parse_args([]).panel_key, "e" * 18)
        with self.assertRaises(SystemExit):
            web_panel.parse_args(["--panel-key", "short"])

    def test_generated_keys_are_random_and_long(self):
        first, second = web_panel.new_panel_key(), web_panel.new_panel_key()
        self.assertGreaterEqual(len(first), 32)
        self.assertNotEqual(first, second)
        self.assertEqual(web_panel.new_panel_key("x" * 16), "x" * 16)
        with self.assertRaises(ValueError):
            web_panel.new_panel_key("short")


if __name__ == "__main__":
    unittest.main()
