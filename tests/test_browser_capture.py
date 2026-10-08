"""تست «ورود با مرورگر واقعی» (Playwright) با مرورگر جعلی — بدون نیاز به نصب Playwright.

مرورگر جعلی همان قراردادهایی را شبیه‌سازی می‌کند که `browser_capture.capture_browser_session`
استفاده می‌کند: goto / fill / click / evaluate / get_attribute / cookies / on("request").
"""

import threading
import time
import unittest
import unittest.mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import browser_capture
import requests
from exir_auth import load_saved_token, save_token
from exir_bot import apply_import_session, build_session
from session_capture import apply_captured, load_captured_session, parse_browser_session
from tests.test_session_capture import broker_args, fake_jwt

BROKER_COOKIE = "BROWSER-WAF-TOKEN"


class FakeResponse:
    def body(self) -> bytes:
        return b"\xff\xd8\xff\xe0jpg"


class FakeRequestContext:
    def get(self, url):
        return FakeResponse()


class FakeLocator:
    def __init__(self, exists: bool):
        self._exists = exists

    def count(self) -> int:
        return 1 if self._exists else 0


class FakeRequest:
    def __init__(self, url: str, method: str, headers: dict):
        self.url = url
        self.method = method
        self.headers = headers


class FakeKeyboard:
    def press(self, _key):
        pass


class FakePage:
    def __init__(self, base: str):
        self.context = None
        self.url = base + "/"
        self.keyboard = FakeKeyboard()
        self._logged_in = False

    # --- انتخابگرها ---
    def locator(self, selector: str) -> FakeLocator:
        known = {
            "#userNameInput": True, "#mat-input-2": True, "#captchaText": True,
            "#captcha": True, "#btn-login": True,
            "input[name='otp']": False, "#otp": False,
        }
        return FakeLocator(known.get(selector, False))

    def fill(self, selector, value):
        assert value

    def get_attribute(self, selector, name):
        if name == "src":
            return "data:image/jpeg;base64,/9j/4AAQSkZJRg=="
        return None

    def screenshot(self, path=None):
        pass

    def click(self, selector):
        # کلیک روی «ورود» = یک POST مرورگر + رفتن به صفحه‌ی اصلی
        self.context._emit_request(FakeRequest(self.context.base + "/api/v2/login", "POST",
                                               {"x-app-n": "802547130322.33659654", "clientid": "",
                                                "user-agent": "Mozilla/5.0 RealChrome"}))
        self._logged_in = True
        self.url = self.context.base + "/exir/mainNew"

    def goto(self, url, wait_until=None, timeout=None):
        self.url = url

    def wait_for_timeout(self, _ms):
        pass

    def wait_for_load_state(self, *a, **k):
        pass

    def evaluate(self, script):
        if "userAgent" in script:
            return "Mozilla/5.0 RealChrome"
        return {"local": {"token": "x"}, "session": {}}


class FakeContext:
    def __init__(self, base: str):
        self.base = base
        self._handlers = []
        self.request = FakeRequestContext()
        self._cookies = [
            {"name": "JWT-TOKEN", "value": fake_jwt(), "domain": "127.0.0.1", "path": "/"},
            {"name": "cookiesession1", "value": BROKER_COOKIE, "domain": "127.0.0.1", "path": "/"},
            {"name": "client_login_id", "value": "browser-cid", "domain": "127.0.0.1", "path": "/"},
        ]

    def on(self, event, handler):
        assert event == "request"
        self._handlers.append(handler)

    def _emit_request(self, request):
        for handler in self._handlers:
            handler(request)

    def new_page(self) -> FakePage:
        page = FakePage(self.base)
        page.context = self
        return page

    def cookies(self):
        return list(self._cookies)


class FakeBrowser:
    def __init__(self, base: str):
        self.base = base
        self.closed = False

    def new_context(self, **kwargs) -> FakeContext:
        return FakeContext(self.base)

    def close(self):
        self.closed = True


class FakeChromium:
    def __init__(self, base: str):
        self.base = base

    def launch(self, headless=True, **kwargs) -> FakeBrowser:
        return FakeBrowser(self.base)


class FakePlaywright:
    def __init__(self, base: str):
        self.chromium = FakeChromium(base)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeBroker:
    """کارگزار جعلی که فقط کوکی چالشِ خودِ مرورگر را قبول می‌کند (۴۰۳/۹۰۰۹ در غیر آن)."""

    def __init__(self):
        self.orders: list[dict] = []
        broker = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _send(self, status, body: bytes, ctype: str, cookies=()):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                for c in cookies:
                    self.send_header("Set-Cookie", c)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):  # noqa: N802
                return self._send(200, b"<html></html>", "text/html")

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                broker.orders.append({"headers": dict(self.headers)})
                if f"cookiesession1={BROKER_COOKIE}" in (self.headers.get("Cookie") or ""):
                    return self._send(422, b'{"type":"error"}', "application/json")
                return self._send(403, b'{"type":"error","errorCode":9009}', "application/json")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True, name="fake-broker-browser").start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class BrowserCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.token_file = Path(self.tmp.name) / "token.json"
        self.broker = FakeBroker()
        self.fake_pw = FakePlaywright(self.broker.base)
        self._orig_loader = browser_capture._load_playwright
        browser_capture._load_playwright = lambda: (lambda: self.fake_pw)

    def tearDown(self):
        browser_capture._load_playwright = self._orig_loader
        self.broker.close()
        self.tmp.cleanup()

    def test_capture_returns_bundle_with_cookies_and_identity_headers(self):
        logs: list[str] = []
        bundle = browser_capture.capture_browser_session(
            self.broker.base, username="u", password="p", otp="",
            captcha_provider=lambda image: "1234", log=lambda *a: logs.append(" ".join(map(str, a))),
            headless=True, timeout=5.0, wait_after_login=0.0)
        names = [n for n, _ in bundle["cookies"]]
        self.assertIn("cookiesession1", names)
        self.assertIn("JWT-TOKEN", names)
        self.assertEqual(bundle["headers"]["x-app-n"], "802547130322.33659654")
        self.assertEqual(bundle["kind"], "browser")
        self.assertTrue(any("نشست مرورگر گرفته شد" in line for line in logs))

    def test_capture_requires_captcha_and_credentials(self):
        with self.assertRaises(RuntimeError):
            browser_capture.capture_browser_session(self.broker.base, username="", password="p",
                                                    captcha_provider=lambda i: "1")
        with self.assertRaises(RuntimeError):
            browser_capture.capture_browser_session(self.broker.base, username="u", password="p",
                                                    captcha_provider=None)

    def test_bundle_round_trips_through_import_session(self):
        bundle = browser_capture.capture_browser_session(
            self.broker.base, username="u", password="p", captcha_provider=lambda i: "1",
            log=lambda *a: None, timeout=5.0, wait_after_login=0.0)
        text = browser_capture.session_json(bundle)
        parsed = parse_browser_session(text)
        self.assertEqual(parsed["kind"], "browser")
        self.assertIn("cookiesession1", [n for n, _ in parsed["cookies"]])

        args = broker_args(self.broker.base, str(self.token_file))
        session = build_session(args, 4)
        apply_import_session(session, args, lambda *a: None, text=text)
        response = session.post(self.broker.base + "/api/v1/order", data=b"{}", allow_redirects=False)
        self.assertEqual(response.status_code, 422)   # امنیت پاس شد
        self.assertIn(f"cookiesession1={BROKER_COOKIE}", self.broker.orders[-1]["headers"]["Cookie"])
        self.assertTrue(load_saved_token(self.token_file, self.broker.base))
        self.assertTrue(load_captured_session(self.token_file, self.broker.base))

    def test_stored_bundle_is_applied_on_later_runs(self):
        bundle = browser_capture.capture_browser_session(
            self.broker.base, username="u", password="p", captcha_provider=lambda i: "1",
            log=lambda *a: None, timeout=5.0, wait_after_login=0.0)
        args = broker_args(self.broker.base, str(self.token_file))
        session = build_session(args, 4)
        apply_import_session(session, args, lambda *a: None, text=browser_capture.session_json(bundle))

        # اجرای بعدی: فقط از فایل توکن، بدون import دوباره
        fresh = build_session(args, 4)
        captured = load_captured_session(self.token_file, self.broker.base)
        apply_captured(fresh, self.broker.base, captured, None)
        self.assertEqual(fresh.post(self.broker.base + "/api/v1/order", data=b"{}",
                                    allow_redirects=False).status_code, 422)

    def test_playwright_missing_message(self):
        browser_capture._load_playwright = self._orig_loader
        with unittest.mock.patch.object(browser_capture, "_load_playwright", return_value=None):
            self.assertFalse(browser_capture.playwright_available())
            with self.assertRaises(RuntimeError) as ctx:
                browser_capture.capture_browser_session(self.broker.base, username="u", password="p",
                                                        captcha_provider=lambda i: "1")
            self.assertIn("playwright", str(ctx.exception).lower())

    def test_captcha_provider_falls_back_to_terminal(self):
        provider = browser_capture.captcha_provider_from_portal(None, lambda *a: None)
        with unittest.mock.patch("builtins.input", return_value="9876"):
            with unittest.mock.patch("sys.stdin") as stdin:
                stdin.isatty.return_value = True
                self.assertEqual(provider(b"img"), "9876")


class FakePortal:
    """صفحه‌ی کپچای جعلی (به‌جای وب‌سرور واقعی) که کد را فوراً تحویل می‌دهد."""

    def __init__(self, *a, **k):
        self.base = "/captcha-test"
        self.port = 1
        self.stdin_ok = False

    def start(self):
        return True

    def stop(self):
        pass

    def set_image(self, image):
        pass

    def announce(self):
        pass

    def set_state(self, *a):
        pass

    def wait_for_code(self, ttl):
        return "1234", "web"


class PanelBrowserLoginEndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import web_panel
        from web_panel import PanelState, panel_handler
        cls.web_panel = web_panel
        cls._portal_patch = unittest.mock.patch.object(web_panel, "CaptchaPortal", FakePortal)
        cls._portal_patch.start()
        cls.broker = FakeBroker()
        cls.tmp = TemporaryDirectory()
        cls.token_file = Path(cls.tmp.name) / "token.json"
        save_token(cls.token_file, cls.broker.base, fake_jwt(), {"name": "t", "cookies": []})
        args = web_panel.parse_args([
            "--host", "127.0.0.1", "--port", "0", "--time-sync", "off",
            "--base-url", cls.broker.base, "--token-file", str(cls.token_file),
            "--captcha-file", str(Path(cls.tmp.name) / "captcha.png"),
            "--panel-key", "test-panel-key-1234",
        ])
        cls.state = PanelState(args)
        cls.fake_pw = FakePlaywright(cls.broker.base)
        cls._orig_loader = browser_capture._load_playwright
        browser_capture._load_playwright = lambda: (lambda: cls.fake_pw)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), panel_handler(cls.state))
        cls.httpd.daemon_threads = True
        cls.state.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.state.port}"
        threading.Thread(target=cls.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True, name="panel-browser-login").start()

    @classmethod
    def tearDownClass(cls):
        browser_capture._load_playwright = cls._orig_loader
        cls._portal_patch.stop()
        cls.state.shutdown()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.broker.close()
        cls.tmp.cleanup()

    def call(self, url, data=None):
        import json
        from urllib.error import HTTPError
        from urllib.request import Request as UrlRequest
        from urllib.request import urlopen
        body = json.dumps(data).encode("utf-8") if data is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        headers[self.web_panel.PANEL_KEY_HEADER] = self.state.panel_key
        try:
            with urlopen(UrlRequest(url, data=body, headers=headers), timeout=25) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_browser_login_endpoint_saves_browser_session(self):
        status, body = self.call(self.base + "/api/browser-login",
                                 {"username": "u", "password": "p", "otp": ""})
        self.assertEqual(status, 200, body)
        deadline = time.time() + 20
        while time.time() < deadline and self.state.login_busy:
            time.sleep(0.1)
        self.assertFalse(self.state.login_busy)
        self.assertEqual(self.state.login_state, "ok", self.state.login_message)
        captured = load_captured_session(self.token_file, self.broker.base)
        self.assertIsNotNone(captured)
        self.assertEqual(captured["kind"], "browser")
        self.assertIn("cookiesession1", [n for n, _ in captured["cookies"]])

        # از این پس سفارش با همان کوکی چالش می‌رود
        session = build_session(SimpleNamespace(base_url=self.broker.base, cookie=None, app_n=None,
                                                clientid=None, header=[], auth_mode="cookie",
                                                token=None, token_file=str(self.token_file),
                                                timeout=5.0), 4)
        apply_captured(session, self.broker.base, captured, None)
        response = session.post(self.broker.base + "/api/v1/order", data=b"{}", allow_redirects=False)
        self.assertEqual(response.status_code, 422)

    def test_browser_login_without_playwright_reports_help(self):
        with unittest.mock.patch.object(browser_capture, "_load_playwright", return_value=None):
            status, body = self.call(self.base + "/api/browser-login",
                                     {"username": "u", "password": "p", "otp": ""})
            self.assertEqual(status, 200, body)
            deadline = time.time() + 15
            while time.time() < deadline and self.state.login_busy:
                time.sleep(0.05)
            self.assertEqual(self.state.login_state, "error")
            self.assertIn("Playwright", self.state.login_message)


if __name__ == "__main__":
    unittest.main()


class BrowserSessionCaptureTests(unittest.TestCase):
    """`capture_browser_session` با Playwright جعلی — همان قالبی که --import-session می‌فهمد."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.token_file = Path(self.tmp.name) / "token.json"
        self.base = "https://broker.example"
        self.fake = FakePlaywright(self.base)
        self._orig = browser_capture._load_playwright
        browser_capture._load_playwright = lambda: (lambda: self.fake)

    def tearDown(self):
        browser_capture._load_playwright = self._orig
        self.tmp.cleanup()

    def test_browser_login_produces_a_usable_session_bundle(self):
        messages: list[str] = []
        bundle = browser_capture.capture_browser_session(
            self.base, username="u", password="p", captcha_provider=lambda image: "1234",
            log=messages.append)
        names = [name for name, _ in bundle["cookies"]]
        self.assertEqual(names, ["JWT-TOKEN", "cookiesession1", "client_login_id"])
        self.assertEqual(bundle["headers"]["x-app-n"], "802547130322.33659654")
        self.assertEqual(bundle["kind"], "browser")
        # همان قالب JSON را --import-session می‌فهمد و کوکی چالش روی نشست می‌نشیند
        import exir_bot
        import requests

        session = requests.Session()
        args = SimpleNamespace(base_url=self.base, token_file=str(self.token_file), token=None,
                               clientid=None, app_n=None, cookie=None, header=None,
                               captcha_url=None, timeout=5.0, tz=None, no_stop=False,
                               bootstrap="off")
        exir_bot.apply_import_session(session, args, messages.append,
                                      text=browser_capture.session_json(bundle))
        prepared = session.prepare_request(requests.Request("POST", self.base + "/api/v1/order"))
        self.assertIn("cookiesession1=BROWSER-WAF-TOKEN", prepared.headers.get("Cookie", ""))

    def test_probe_after_login_runs_inside_the_same_browser(self):
        seen: list[str] = []

        def probe(page):
            seen.append(page.url)
            return {"status": 422, "body": "{\"type\":\"error\"}", "ms": 12}

        bundle = browser_capture.capture_browser_session(
            self.base, username="u", password="p", captcha_provider=lambda image: "1234",
            log=lambda *a: None, after_login=probe)
        self.assertTrue(seen and seen[0].endswith("/exir/mainNew"))
        self.assertEqual(bundle["probe"]["status"], 422)

    def test_playwright_missing_message_mentions_install_and_alternative(self):
        browser_capture._load_playwright = lambda: None
        with self.assertRaises(RuntimeError) as ctx:
            browser_capture.capture_browser_session(self.base, username="u", password="p",
                                                    captcha_provider=lambda image: "1")
        text = str(ctx.exception)
        self.assertIn("playwright install chromium", text)
        self.assertIn("--import-session", text)

    def test_captcha_provider_from_portal_uses_the_shared_page(self):
        class Portal:
            def __init__(self):
                self.image = None
                self.codes = ["4321"]

            def set_image(self, image):
                self.image = image

            def announce(self):
                pass

            def set_state(self, *a):
                pass

            def wait_for_code(self, _ttl):
                return self.codes.pop(0), "web"

        portal = Portal()
        provider = browser_capture.captcha_provider_from_portal(portal, lambda *a: None, 5)
        self.assertEqual(provider(b"img"), "4321")
        self.assertEqual(portal.image, b"img")


class JsonBundleSummaryTests(unittest.TestCase):
    def test_session_json_bundle_round_trips_and_reports_names(self):
        bundle = {"kind": "browser", "url": "https://broker.example/", "headers": {"x-app-n": "1.2"},
                  "cookies": [["JWT-TOKEN", "t"], ["cookiesession1", "w"], ["client_login_id", "c"]],
                  "storage": {"local": {}, "session": {}}}
        captured = parse_browser_session(browser_capture.session_json(bundle))
        self.assertEqual([n for n, _ in captured["cookies"]],
                         ["JWT-TOKEN", "cookiesession1", "client_login_id"])
        self.assertEqual(captured["headers"]["x-app-n"], "1.2")
