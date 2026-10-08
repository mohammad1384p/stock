#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
تست‌های «نشستِ مرورگر» — همان چیزی که خطای ۴۰۳/۹۰۰۹ را رفع می‌کند:

  * `session_capture.parse_browser_session`  (Copy as cURL / fetch / هدر خام / رشته‌ی Cookie)
  * `session_capture.apply_captured`         (کوکی/هدرها روی نشست ربات)
  * `session_capture.browser_bootstrap`      (رفتار مرورگر: کوکی چالش فایروال)
  * `exir_bot.apply_import_session`          (ذخیره‌ی نشست + توکن داخل آن)
  * مسیر پنل: `/api/import-session` و ارسال با کوکی تازه‌شده

کارگزار جعلی این تست‌ها همان لایه‌ی امنیتی اکسیر را تقلید می‌کند: بدون کوکی چالش
(`cookiesession1`) هر `POST /api/v1/order` با `403 / errorCode 9009` رد می‌شود و با آن
کوکی، سفارش به مرحله‌ی اعتبارسنجی می‌رسد (`422`) — یعنی «امنیت پاس شد».
"""

from __future__ import annotations

import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import browser_capture
import exir_bot
import session_capture
import web_panel
from exir_auth import save_token
from session_capture import apply_captured, browser_bootstrap, parse_browser_session

BROWSER_ONLY_VALUE = "BROWSER-WAF-TOKEN"


def fake_jwt(exp_offset: int = 3600, sub: str = "tester") -> str:
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc({'sub': sub, 'exp': time.time() + exp_offset})}.sig"


def broker_args(base: str, token_file: Path, **extra) -> SimpleNamespace:
    args = SimpleNamespace(base_url=base, token_file=str(token_file), token=None,
                           clientid=None, app_n=None, cookie=None, header=None,
                           captcha_url=None, timeout=5.0, tz=None, no_stop=False,
                           browser_show=False, browser_timeout=30.0, bootstrap="off")
    for key, value in extra.items():
        setattr(args, key, value)
    return args


class FakeBroker:
    """
    کارگزار جعلی با لایه‌ی امنیتی:

      * `GET /` و `GET /captcha` کوکی `cookiesession1` و `client_login_id` را ست می‌کنند،
      * بدون کوکی چالش → `403 / 9009`؛ با کوکی چالش → `422` (اعتبارسنجی بدنه).
    """

    def __init__(self, *, require_value: str | None = None):
        self.require_value = require_value        # اگر مقدار بدهیم، فقط همان کوکی قبول است
        self.orders: list[dict] = []
        broker = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status, body: bytes, ctype="application/json", cookies=()):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                for cookie in cookies:
                    self.send_header("Set-Cookie", cookie)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                path = self.path.rstrip("/") or "/"
                if path == "/captcha":
                    return self._send(200, b"\xff\xd8\xff\xe0", "image/jpeg",
                                      ["client_login_id=cid-2; Path=/"])
                if path.startswith("/static"):
                    return self._send(200, b"//app", "application/javascript")
                html = b"<html><script src='/static/app.js'></script></html>"
                return self._send(200, html, "text/html",
                                  ["cookiesession1=waf-1; Path=/", "client_login_id=cid-1; Path=/"])

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else ""
                cookie = self.headers.get("Cookie") or ""
                broker.orders.append({"path": self.path, "cookie": cookie, "body": body,
                                      "headers": dict(self.headers)})
                if broker.require_value is not None:
                    allowed = f"cookiesession1={broker.require_value}" in cookie
                else:
                    allowed = "cookiesession1=" in cookie
                if not allowed:
                    return self._send(403, json.dumps({
                        "type": "error", "msgType": "error",
                        "description": "مشکل امنیتی.درخواست معتبر نمی باشد",
                        "descriptionEn": "Security problem.Invalid request",
                        "errorCode": 9009}, ensure_ascii=False).encode("utf-8"))
                return self._send(422, json.dumps(
                    {"type": "error", "description": "قیمت نامعتبر"}, ensure_ascii=False).encode("utf-8"))

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True, name="fake-broker-session").start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


CURL_SNIPPET = """curl 'http://BROKER/api/v1/order' -X POST \\
  -H 'accept: application/json, text/plain, */*' \\
  -H 'clientid: 9911223' \\
  -H 'x-app-n: 2018887747744.29964494' \\
  -H 'user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141' \\
  -H 'content-length: 265' \\
  -H 'host: BROKER' \\
  -H 'cookie: JWT-TOKEN=%s; cookiesession1=%s; client_login_id=cid-browser' \\
  --data-raw '{"insMaxLcode":"IRO7TONP0001","quantity":10,"price":6700}'"""


class ParseBrowserSessionTests(unittest.TestCase):
    def test_curl_snippet_yields_cookies_and_headers(self):
        text = CURL_SNIPPET % (fake_jwt(), BROWSER_ONLY_VALUE)
        captured = parse_browser_session(text)
        names = [name for name, _ in captured["cookies"]]
        self.assertEqual(names, ["JWT-TOKEN", "cookiesession1", "client_login_id"])
        self.assertEqual(captured["headers"]["x-app-n"], "2018887747744.29964494")
        self.assertEqual(captured["headers"]["clientid"], "9911223")
        # هدر `cookie` هرگز در فهرست هدرها نمی‌آید (به کوکی‌ها تبدیل می‌شود)
        self.assertNotIn("cookie", captured["headers"])
        self.assertEqual(captured["kind"], "curl")

    def test_fetch_snippet_and_bare_cookie_string(self):
        fetch = ("fetch(\"http://b/api/v1/order\", {\"headers\": {\"x-app-n\": \"111.222\","
                 " \"cookie\": \"a=1; b=2\"}, \"body\": \"{}\", \"method\": \"POST\"});")
        captured = parse_browser_session(fetch)
        self.assertEqual([n for n, _ in captured["cookies"]], ["a", "b"])
        self.assertEqual(captured["headers"]["x-app-n"], "111.222")
        raw = parse_browser_session("Cookie: cookiesession1=just-a-cookie-value")
        self.assertEqual(raw["cookies"], [("cookiesession1", "just-a-cookie-value")])

    def test_hidden_blank_line_tokens_are_ignored(self):
        captured = parse_browser_session("  \n\ncookie: x=1\n")
        self.assertEqual(captured["cookies"], [("x", "1")])


class ApplyCapturedTests(unittest.TestCase):
    def setUp(self):
        import requests

        self.session = requests.Session()
        self.base = "https://khobregan.exirbroker.com"

    def test_cookies_and_identity_headers_applied_but_token_cookie_skipped(self):
        text = CURL_SNIPPET % (fake_jwt(), BROWSER_ONLY_VALUE)
        summary = apply_captured(self.session, self.base, parse_browser_session(text), None)
        self.assertEqual(sorted(summary["cookies"]), ["client_login_id", "cookiesession1"])
        self.assertEqual(self.session.headers.get("x-app-n"), "2018887747744.29964494")
        self.assertEqual(self.session.headers.get("clientid"), "9911223")
        # هدرهای مدیریت‌شده/انتقالی (host/content-length/…) روی نشست اعمال نمی‌شوند
        for hop in ("content-length", "host", "cookie"):
            self.assertIsNone(self.session.headers.get(hop))
        prepared = self.session.prepare_request(
            __import__("requests").Request("POST", self.base + "/api/v1/order", data=b"{}"))
        self.assertIsNone(prepared.headers.get("Authorization"))
        self.assertIn("cookiesession1=" + BROWSER_ONLY_VALUE, prepared.headers.get("Cookie", ""))

    def test_token_cookie_is_reported_but_not_applied(self):
        captured = parse_browser_session(CURL_SNIPPET % ("browser-token-123", "waf"))
        self.assertEqual(session_capture.imported_token(captured), "browser-token-123")
        self.assertEqual([name for name, _ in captured["cookies"]][0], "JWT-TOKEN")
        apply_captured(self.session, self.base, captured, None)
        self.assertNotIn("browser-token-123",
                         self.session.prepare_request(
                             __import__("requests").Request("GET", self.base + "/")).headers.get("Cookie", ""))


class BootstrapAgainstFakeBrokerTests(unittest.TestCase):
    def setUp(self):
        self.broker = FakeBroker()
        self.session = exir_bot.build_session(broker_args(self.broker.base, Path("unused.json")), pool=2)

    def tearDown(self):
        self.broker.close()

    def _order(self):
        return self.session.post(self.broker.base + exir_bot.ORDER_PATH,
                                 data=b'{"insMaxLcode":"IRO7TONP0001","quantity":10,"price":6700}',
                                 timeout=5, allow_redirects=False)

    def test_order_is_rejected_before_bootstrap_and_passes_after_it(self):
        first = self._order()
        self.assertEqual(first.status_code, 403)
        self.assertEqual(first.json()["errorCode"], 9009)

        report = browser_bootstrap(self.session, self.broker.base, log=None)
        self.assertTrue(report["ok"])
        self.assertIn("cookiesession1", report["new_cookies"])

        second = self._order()
        self.assertEqual(second.status_code, 422)          # امنیت پاس شد، فقط بدنه نامعتبر بود
        self.assertEqual(self.session.cookies.get("cookiesession1"), "waf-1")

    def test_bootstrap_off_leaves_the_session_without_challenge_cookie(self):
        report = browser_bootstrap(self.session, self.broker.base, log=None, mode="off")
        self.assertEqual(report["mode"], "off")
        self.assertFalse(report["ok"])
        self.assertIsNone(self.session.cookies.get("cookiesession1"))
        self.assertEqual(self._order().status_code, 403)


class ImportSessionFixesBrowserOnlyCookieTests(unittest.TestCase):
    """کوکی‌ای که هیچ درخواست ساده‌ای نمی‌گیرد (فقط در مرورگر ساخته می‌شود)."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.token_file = Path(self.tmp.name) / "token.json"
        self.broker = FakeBroker(require_value=BROWSER_ONLY_VALUE)
        self.args = broker_args(self.broker.base, self.token_file, token=None)
        self.session = exir_bot.build_session(self.args, pool=2)

    def tearDown(self):
        self.broker.close()
        self.tmp.cleanup()

    def _order(self):
        return self.session.post(self.broker.base + exir_bot.ORDER_PATH,
                                 data=b'{"insMaxLcode":"IRO7TONP0001","quantity":10,"price":6700}',
                                 timeout=5, allow_redirects=False)

    def test_import_session_applies_cookies_and_saves_them_for_later_runs(self):
        with self.assertRaises(Exception):
            exir_bot.read_import_text("/nonexistent/browser.txt")

        self.assertEqual(self._order().status_code, 403)          # خط پایه: ۹۰۰۹
        browser_bootstrap(self.session, self.broker.base, log=None)
        self.assertEqual(self._order().status_code, 403)          # bootstrap هم کافی نیست

        text = (CURL_SNIPPET % (fake_jwt(), BROWSER_ONLY_VALUE)).replace("http://BROKER",
                                                                        self.broker.base)
        summary = exir_bot.apply_import_session(self.session, self.args, lambda m: None, text=text)
        self.assertEqual(sorted(summary["cookies"]), ["client_login_id", "cookiesession1"])
        self.assertEqual(self._order().status_code, 422)           # امنیت پاس شد

        # کوکی‌ها در فایل توکن ذخیره شده‌اند (اجرای بعدی هم بدون import کار می‌کند)
        self.assertEqual(session_capture.load_captured_session(self.token_file, self.broker.base)
                         ["cookies"][1], ["cookiesession1", BROWSER_ONLY_VALUE])
        fresh = exir_bot.build_session(self.args, pool=2)
        self.assertIsNotNone(exir_bot.apply_saved_captured_session(fresh, self.args, lambda m: None))
        response = fresh.post(self.broker.base + exir_bot.ORDER_PATH, data=b"{}", timeout=5,
                              allow_redirects=False)
        self.assertEqual(response.status_code, 422)

    def test_reapplied_session_beats_cookies_that_server_responses_write(self):
        """پاسخ سرور می‌تواند کوکی چالش را با مقدار خودش عوض کند؛ مقدار مرورگر باید برد."""
        text = (CURL_SNIPPET % (fake_jwt(), BROWSER_ONLY_VALUE)).replace("http://BROKER",
                                                                        self.broker.base)
        exir_bot.apply_import_session(self.session, self.args, lambda m: None, text=text)
        # مثل warm-up/bootstrap: سرور کوکی چالش را با مقدار خودش بازنویسی می‌کند
        self.session.get(self.broker.base + "/", timeout=5)
        self.assertNotEqual(self.session.cookies.get("cookiesession1"), BROWSER_ONLY_VALUE)
        self.assertEqual(self._order().status_code, 403)

        # پیش از ارسال، نشستِ مرورگر دوباره اعمال می‌شود (همان کاری که ربات سر ثانیه می‌کند)
        exir_bot.apply_saved_captured_session(self.session, self.args, lambda m: None, quiet=True)
        self.assertEqual(self.session.cookies.get("cookiesession1"), BROWSER_ONLY_VALUE)
        self.assertEqual(self._order().status_code, 422)

    def test_import_session_stores_the_imported_token_when_it_is_valid(self):
        text = (CURL_SNIPPET % (fake_jwt(sub="browser-user"), BROWSER_ONLY_VALUE)).replace(
            "http://BROKER", self.broker.base)
        exir_bot.apply_import_session(self.session, self.args, lambda m: None, text=text)
        saved = __import__("exir_auth").load_saved_token(self.token_file, self.broker.base)
        self.assertTrue(saved["token"].startswith("ey"))
        self.assertEqual(saved["appN"], "2018887747744.29964494")
        self.assertIn("client_login_id", [c[0] for c in saved["captured_session"]["cookies"]])

    def test_expired_imported_token_is_not_used(self):
        text = (CURL_SNIPPET % (fake_jwt(exp_offset=-3600), BROWSER_ONLY_VALUE)).replace(
            "http://BROKER", self.broker.base)
        save_token(self.token_file, self.broker.base, fake_jwt(sub="saved-user"), {"appN": "1.2"})
        messages: list[str] = []
        exir_bot.apply_import_session(self.session, self.args, messages.append, text=text)
        saved = __import__("exir_auth").load_saved_token(self.token_file, self.broker.base)
        self.assertEqual(saved["token"], self.session.cookies.get("JWT-TOKEN") or saved["token"])
        self.assertTrue(any("منقضی" in m or "old" in m for m in messages))


class SaveTokenKeepsCapturedSessionTests(unittest.TestCase):
    def test_save_token_merge_does_not_drop_captured_session(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "token.json"
            base = "https://khobregan.exirbroker.com"
            save_token(path, base, fake_jwt(sub="one"),
                       {"appN": "1.2", "captured_session": {"kind": "curl", "cookies": [["a", "b"]]}})
            save_token(path, base, fake_jwt(sub="two"), {"appN": "3.4"})
            data = json.loads(path.read_text())
            self.assertEqual(data[base]["appN"], "3.4")
            self.assertEqual(data[base]["captured_session"]["cookies"], [["a", "b"]])


class SecurityWarningsTests(unittest.TestCase):
    def test_missing_browser_cookie_is_reported(self):
        import requests

        session = requests.Session()
        warnings = session_capture.security_cookie_warnings(session, "https://khobregan.exirbroker.com")
        text = "\n".join(warnings)
        self.assertIn("cookiesession1", text)
        self.assertIn("client_login_id", text)


class PanelImportSessionEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = TemporaryDirectory()
        cls.token_file = Path(cls.tmp.name) / "token.json"
        cls.broker = FakeBroker(require_value=BROWSER_ONLY_VALUE)
        save_token(cls.token_file, cls.broker.base, fake_jwt(), {"appN": "1.2"})
        args = web_panel.parse_args([
            "--host", "127.0.0.1", "--port", "0", "--time-sync", "off",
            "--base-url", cls.broker.base, "--token-file", str(cls.token_file),
            "--captcha-file", str(Path(cls.tmp.name) / "captcha.png"),
        ])
        cls.state = web_panel.PanelState(args)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), web_panel.panel_handler(cls.state))
        cls.httpd.daemon_threads = True
        cls.state.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.state.port}"
        threading.Thread(target=cls.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True, name="panel-import").start()

    @classmethod
    def tearDownClass(cls):
        cls.state.shutdown()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.broker.close()
        cls.tmp.cleanup()

    def _call(self, path: str, data: dict | None = None):
        import requests

        headers = {web_panel.PANEL_KEY_HEADER: self.state.panel_key}
        response = requests.post(self.base + path, json=data or {}, headers=headers, timeout=20)
        return response.status_code, response.json()

    def test_import_session_endpoint_saves_and_reports(self):
        text = (CURL_SNIPPET % (fake_jwt(), BROWSER_ONLY_VALUE)).replace("http://BROKER", self.broker.base)
        status, payload = self._call("/api/import-session", {"text": text})
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertIn("cookiesession1", payload["session"]["cookies"])
        # نشست ذخیره‌شده در اجرای بعدی هم اعمال می‌شود
        self.assertEqual(session_capture.load_captured_session(self.token_file, self.broker.base)
                         ["cookies"][1], ["cookiesession1", BROWSER_ONLY_VALUE])
        # ورودی خالی/نامعتبر باید خطای واضح بدهد، نه ۵۰۰
        status, payload = self._call("/api/import-session", {"text": "   "})
        self.assertEqual(status, 400)
        self.assertIn("error", payload)
