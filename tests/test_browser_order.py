#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
تست‌های «ارسال سفارش از داخل مرورگر واقعی» (browser_order.py) با یک Playwright جعلی.

هدف: مطمئن شویم
  * کوکی‌های نشستِ ذخیره‌شده به مرورگر داده می‌شوند و صفحه‌ی کارگزاری باز می‌شود،
  * زمان‌بندی با اختلاف ساعت مرورگر جبران می‌شود (و هدرهای ممنوعه حذف می‌شوند)،
  * نتیجه‌ها با همان قالب لاگ ربات ثبت می‌شوند و ۴۰۳/۹۰۰۹ بقیه‌ی ارسال‌ها را متوقف می‌کند،
  * بدون Playwright، پیام نصب روشن داده می‌شود (نه خطای مبهم).
"""

from __future__ import annotations

import json
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import browser_capture
import browser_order
import exir_bot
from exir_auth import save_token
from session_capture import save_captured_session


def fake_jwt(exp_offset: int = 3600) -> str:
    import base64
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc({'sub': 'tester', 'exp': time.time() + exp_offset})}.sig"


class FakePage:
    def __init__(self, owner: "FakeContext"):
        self.owner = owner
        self.url = owner.base + "/"
        self.scripts: list[tuple[str, object]] = []
        self.configs: list[dict] = []

    # -- Playwright API (بخش مورد استفاده‌ی ما) -- #
    def goto(self, url, wait_until=None, timeout=None):
        self.url = url

    def evaluate(self, script, arg=None):
        self.scripts.append((script, arg))
        if "() => Date.now()" in script:
            return self.owner.browser_now_ms
        if "async (cfg)" in script:          # PROBE_JS
            return dict(self.owner.probe_result)
        if "const cfg" in script:            # SCHEDULER_JS
            self.configs.append(dict(arg or {}))
            self.owner.done = bool(self.owner.done_after_schedule)
            return {"planned": len((arg or {}).get("times") or []), "started": True}
        if "running: s.running" in script:   # state()
            return {"running": bool(self.owner.running), "done": bool(self.owner.done),
                    "stop": bool(self.owner.stop), "fired": len(self.owner.results),
                    "got": len(self.owner.results)}
        if "__exirOrders.results" in script:  # results()
            return list(self.owner.results)
        return None


class FakeContext:
    def __init__(self, base: str, browser_now_ms: int):
        self.base = base
        self.browser_now_ms = browser_now_ms
        self.cookies: list[dict] = []
        self.init_scripts: list[str] = []
        self.results: list[dict] = []
        self.running = True
        self.done = False
        self.done_after_schedule = False
        self.stop = False
        self.kwargs: dict = {}
        self.probe_result: dict = {"ok": True, "status": 422, "ms": 41, "body": '{"type":"error"}'}
        self.page = FakePage(self)

    def add_cookies(self, cookies):
        self.cookies.extend(cookies)

    def add_init_script(self, script):
        self.init_scripts.append(script)

    def new_page(self):
        return self.page

    def close(self):
        pass


class FakeBrowser:
    def __init__(self, context: FakeContext):
        self.context = context

    def new_context(self, **kwargs):
        self.context.kwargs = kwargs
        return self.context

    def close(self):
        pass


class FakeChromium:
    def __init__(self, context: FakeContext):
        self.context = context

    def launch(self, headless=True, **kwargs):
        self.context.headless = headless
        return FakeBrowser(self.context)


class FakePlaywright:
    def __init__(self, context: FakeContext):
        self.context = context
        self.chromium = FakeChromium(context)

    def start(self):
        return self

    def stop(self):
        pass


class BrowserOrdersTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.token_file = Path(self.tmp.name) / "token.json"
        self.context = FakeContext("https://broker.example", browser_now_ms=1_700_000_123_456)
        self.fake_pw = FakePlaywright(self.context)
        self._orig_loader = browser_capture._load_playwright
        browser_capture._load_playwright = lambda: (lambda: self.fake_pw)
        self.bundle = {
            "kind": "browser", "url": "https://broker.example/new-exir/mainNew",
            "cookies": [["JWT-TOKEN", fake_jwt()], ["cookiesession1", "waf-value"],
                        ["client_login_id", "cid-browser"]],
            "headers": {"x-app-n": "2018887747744.29964494", "clientid": "9911223",
                        "user-agent": "Mozilla/5.0 BrowserUA"},
            "storage": {"local": {"token": "abc"}, "session": {}},
            "user_agent": "Mozilla/5.0 BrowserUA",
        }

    def tearDown(self):
        browser_capture._load_playwright = self._orig_loader
        self.tmp.cleanup()

    def test_open_gives_cookies_storage_and_user_agent_to_the_browser(self):
        orders = BrowserOrders = browser_order.BrowserOrders("https://broker.example",
                                                             bundle=self.bundle, log=lambda *a: None)
        orders.open()
        self.assertIn("localStorage.setItem", self.context.init_scripts[0])   # localStorage تزریق شد
        self.assertEqual(self.context.kwargs["user_agent"], "Mozilla/5.0 BrowserUA")
        names = [c["name"] for c in self.context.cookies]
        self.assertEqual(names, ["JWT-TOKEN", "cookiesession1", "client_login_id"])
        self.assertEqual(self.context.page.url, "https://broker.example/")
        orders.close()

    def test_schedule_shifts_times_by_the_browser_clock_offset(self):
        orders = browser_order.BrowserOrders("https://broker.example", bundle=self.bundle,
                                             log=lambda *a: None)
        orders.open()
        report = orders.schedule("https://broker.example/api/v1/order", b'{"a":1}',
                                [1_700_000_100_000, 1_700_000_100_305],
                                headers={"x-app-n": "1.2", "cookie": "nope=1", "host": "x"},
                                now_ms=1_700_000_100_000)
        cfg = self.context.page.configs[0]
        self.assertEqual(cfg["times"], [1_700_000_123_456, 1_700_000_123_761])
        self.assertEqual(cfg["headers"], {"x-app-n": "1.2"})           # cookie/host حذف شدند
        self.assertEqual(report["offset_ms"], 23_456)
        self.assertEqual(report["planned"], 2)
        orders.close()

    def test_probe_reports_status_and_body(self):
        orders = browser_order.BrowserOrders("https://broker.example", bundle=self.bundle,
                                             log=lambda *a: None)
        orders.open()
        result = orders.probe("https://broker.example/api/v1/order", b"{}")
        self.assertEqual(result["status"], 422)
        orders.close()

    def test_missing_playwright_gives_install_hint(self):
        browser_capture._load_playwright = lambda: None
        orders = browser_order.BrowserOrders("https://broker.example", log=lambda *a: None)
        with self.assertRaises(RuntimeError) as ctx:
            orders.open()
        self.assertIn("playwright", str(ctx.exception).lower())
        self.assertIn("pip install playwright", str(ctx.exception))


class RunBrowserOrdersTests(unittest.TestCase):
    """مسیر کامل `exir_bot.run_browser_orders`: ثبت نتیجه‌ها + توقف امنیتی."""

    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.token_file = Path(self.tmp.name) / "token.json"
        self.base = "https://broker.example"
        save_token(self.token_file, self.base, fake_jwt(), {"appN": "1.2"})
        save_captured_session(self.token_file, self.base,
                              {"kind": "browser", "cookies": [["JWT-TOKEN", fake_jwt()],
                                                              ["cookiesession1", "waf"]],
                               "headers": {"x-app-n": "2018887747744.29964494",
                                           "clientid": "9911223"},
                               "storage": {}, "url": self.base + "/"})
        self.context = FakeContext(self.base, browser_now_ms=1_700_000_000_000)
        self.fake_pw = FakePlaywright(self.context)
        self._orig_loader = browser_capture._load_playwright
        browser_capture._load_playwright = lambda: (lambda: self.fake_pw)

    def tearDown(self):
        browser_capture._load_playwright = self._orig_loader
        self.tmp.cleanup()

    def _args(self, **extra):
        args = SimpleNamespace(base_url=self.base, token_file=str(self.token_file), token=None,
                              clientid=None, app_n=None, cookie=None, header=None,
                              captcha_url=None, timeout=5.0, tz=None, no_stop=False,
                              browser_show=False, browser_timeout=30.0,
                              import_session=None, bootstrap="off")
        for key, value in extra.items():
            setattr(args, key, value)
        return args

    def _run(self, results: list[dict], schedule: list[float]):
        self.context.results = results
        self.context.done_after_schedule = True
        logs: list[str] = []
        stats = exir_bot.Stats()
        stop_evt = threading.Event()
        exir_bot.run_browser_orders(None, self._args(), logs.append, base=self.base,
                                    url=self.base + exir_bot.ORDER_PATH, payload=b"{}",
                                    schedule=schedule, stats=stats, stop_evt=stop_evt,
                                    tz=None)
        return stats, stop_evt, "\n".join(logs)

    def test_security_response_stops_the_rest_and_is_reported(self):
        results = [{"k": 1, "target": 0, "sent": 1_700_000_000_000, "got": 1_700_000_000_045,
                    "status": 403, "body": json.dumps({"type": "error", "errorCode": 9009,
                                                       "description": "مشکل امنیتی.درخواست معتبر نمی‌باشد"},
                                                      ensure_ascii=False), "error": None}]
        stats, stop_evt, log_text = self._run(results, [1_700_000_000.0, 1_700_000_000.305])
        self.assertEqual(stats.sent, 1)
        self.assertEqual(stats.stop_reason, "security")
        self.assertTrue(stop_evt.is_set())
        self.assertIn("HTTP 403", log_text)
        self.assertIn("مرورگر", log_text)
        # درخواست توقف در صفحه هم زده شده است
        self.assertTrue(any("stop = true" in script for script, _ in self.context.page.scripts))

    def test_validation_error_does_not_stop_a_browser_run(self):
        results = [{"k": 1, "sent": 1_700_000_000_000, "got": 1_700_000_000_030, "status": 422,
                    "body": json.dumps({"type": "error", "description": "قیمت نامعتبر"},
                                       ensure_ascii=False), "error": None}]
        stats, stop_evt, log_text = self._run(results, [1_700_000_000.0])
        self.assertEqual(stats.failed, 1)
        self.assertEqual(stats.success, 0)
        self.assertIsNone(stats.stop_reason)
        self.assertFalse(stop_evt.is_set())
        self.assertIn("422", log_text)

    def test_successful_order_stops_the_run_by_default(self):
        results = [{"k": 1, "sent": 1_700_000_000_000, "got": 1_700_000_000_090, "status": 200,
                    "body": json.dumps({"type": "orderSuccess", "orderId": 12345}), "error": None}]
        stats, stop_evt, log_text = self._run(results, [1_700_000_000.0])
        self.assertEqual(stats.success, 1)
        self.assertEqual(stats.stop_reason, "success")
        self.assertTrue(stop_evt.is_set())
        self.assertIn("orderSuccess", log_text)


class BrowserOrderCliTests(unittest.TestCase):
    def test_browser_orders_available_reflects_playwright(self):
        original = browser_capture._load_playwright
        try:
            browser_capture._load_playwright = lambda: None
            self.assertFalse(exir_bot.browser_orders_available())
            browser_capture._load_playwright = lambda: (lambda: FakePlaywright(
                FakeContext("https://x", 0)))
            self.assertTrue(exir_bot.browser_orders_available())
        finally:
            browser_capture._load_playwright = original

    def test_probe_payload_is_deliberately_invalid(self):
        body = json.loads(exir_bot.probe_payload(SimpleNamespace()))
        self.assertEqual(body["quantity"], 0)
        self.assertEqual(body["price"], 0)
        self.assertEqual(body["insMaxLcode"], "IR0000000000")
