"""
تست‌های لایه‌ی لاگینگ (exir_logging) و ابزارهای دیباگِ ردِ امنیتی در exir_bot.

سه چیز اینجا guarantee می‌شود:
1. هیچ مقدار حساسی (توکن، کوکی، رمز، Authorization) وارد لاگ نمی‌شود؛
2. رخدادهای کلیدی (order.security_rejected، session.*، run.stopped) با فیلدهای
   لازم برای دیباگ ثبت می‌شوند؛
3. پیکربندی (سطح/فایل/قالب) همان‌طور که انتظار می‌رود کار می‌کند.
"""
import json
import logging
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zoneinfo import ZoneInfo

import requests

import exir_bot
from exir_auth import TOKEN_COOKIE, save_token
from exir_logging import (LEVELS, JsonFormatter, TextFormatter, capture_records, emit, get_logger,
                          mask, redact, redact_headers, setup_logging)

JWT = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0ZXIiLCJleHAiOjk5OTk5OTk5OTl9."
       "c2lnbmF0dXJlLXZhbHVlLTEyMzQ1Njc4OTA")
COOKIE = f"{TOKEN_COOKIE}={JWT}; cookiesession1=ABCDEF0123456789ABCDEF0123456789"


def fake_jwt() -> str:
    import base64
    import time as _t
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc({'sub': 'tester', 'exp': _t.time() + 3600})}.sig"


class RedactionTests(unittest.TestCase):
    def test_mask_keeps_length_but_not_value(self):
        self.assertNotIn("s3cr3t-value", mask("s3cr3t-value"))
        self.assertIn("len=", mask("a" * 40))
        self.assertEqual("***", mask("ab"))

    def test_mask_is_idempotent(self):
        once = mask("supersecretvalue")
        self.assertEqual(once, mask(once))

    def test_redact_hides_jwt_and_cookie_values(self):
        text = f"Cookie: {COOKIE} Authorization: Bearer {JWT} body={{\"password\": \"s3cr3t\"}}"
        out = redact(text)
        self.assertNotIn(JWT, out)
        self.assertNotIn("s3cr3t", out)
        self.assertNotIn("ABCDEF0123456789", out)
        self.assertIn(TOKEN_COOKIE, out)          # نام کوکی برای دیباگ لازم است
        self.assertEqual(out, redact(out))        # پوشاندنِ دوباره خروجی را عوض نمی‌کند

    def test_redact_headers_masks_secrets_only(self):
        headers = redact_headers({"Cookie": COOKIE, "Authorization": f"Bearer {JWT}",
                                  "X-App-N": "2018887747744.29964494",
                                  "Referer": "https://khobregan.exirbroker.com/new-exir/market-view"})
        self.assertNotIn(JWT, json.dumps(headers, ensure_ascii=False))
        self.assertEqual("2018887747744.29964494", headers["x-app-n"])     # هدرِ شناسایی لازم است
        self.assertTrue(headers["referer"].endswith("market-view"))
        self.assertTrue(headers["authorization"].startswith("Bearer "))
        self.assertIn("…***", headers["cookie"])

    def test_registered_secret_is_masked_everywhere(self):
        from exir_logging import forget_secrets, register_secret
        key = "panel-access-key-9876543210"
        try:
            register_secret(key)
            self.assertNotIn(key, redact(f"panel url: http://x/#key={key}"))
            log = get_logger("test.secret")
            with capture_records(log) as records:
                log.info("کلید پنل: %s", key)
            self.assertNotIn(key, records[0].getMessage())
            self.assertIn("…***", records[0].getMessage())
        finally:
            forget_secrets()
        self.assertIn(key, redact(key))      # بعد از فراموشی دیگر پوشیده نمی‌شود

    def test_filter_redacts_third_party_records(self):
        log = get_logger("test.filter")
        with capture_records(log) as records:
            log.warning("urllib3 says: %s", f"Cookie: {COOKIE}")
        self.assertEqual(len(records), 1)
        self.assertNotIn(JWT, records[0].getMessage())


class SetupTests(unittest.TestCase):
    def tearDown(self):
        setup_logging("info", console="off")     # پاک‌سازی هندلرهای تستِ قبلی

    def test_file_logging_and_json_format(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "exir.log"
            log = setup_logging("debug", str(path), "json", console="off")
            emit(log, logging.ERROR, "order.security_rejected", "رد شد", status=403,
                 error_code="9009", headers=redact_headers({"Cookie": COOKIE}))
            for handler in list(log.handlers):
                handler.flush()
            lines = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
            self.assertEqual(len(lines), 1)
            row = lines[0]
            self.assertEqual(row["event"], "order.security_rejected")
            self.assertEqual(row["level"], "ERROR")
            self.assertEqual(row["status"], 403)
            self.assertEqual(row["error_code"], "9009")
            self.assertNotIn(JWT, path.read_text(encoding="utf-8"))

    def test_text_format_includes_event_and_fields(self):
        log = get_logger("test.text")
        handler = logging.Handler()
        handler.setFormatter(TextFormatter())
        with capture_records(log) as records:
            emit(log, logging.WARNING, "order.failed", "ناموفق", status=422)
        text = TextFormatter().format(records[0])
        self.assertIn("[order.failed]", text)
        self.assertIn("status=422", text)
        self.assertIn("WARNING", text)

    def test_json_formatter_never_overwrites_reserved_keys(self):
        record = logging.LogRecord("exir", logging.INFO, __file__, 1, "msg", None, None)
        record.exir_event = "demo"
        record.exir_fields = {"level": "ساختگی", "custom": 1}
        row = json.loads(JsonFormatter().format(record))
        self.assertEqual(row["level"], "INFO")           # مقدار اصلی دست‌نخورده
        self.assertEqual(row["field_level"], "ساختگی")

    def test_level_filtering(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "a.log"
            log = setup_logging("warning", str(path), console="off")
            emit(log, logging.DEBUG, "order.request", "دیده نشود")
            emit(log, logging.WARNING, "order.failed", "دیده شود")
            for handler in list(log.handlers):
                handler.flush()
            content = path.read_text(encoding="utf-8")
            self.assertIn("دیده شود", content)
            self.assertNotIn("دیده نشود", content)
        self.assertIn("debug", LEVELS)

    def test_console_levels(self):
        log = setup_logging("debug", console="auto")
        streams = [h for h in log.handlers if getattr(h, "_exir_handler", False)
                   and isinstance(h, logging.StreamHandler)]
        self.assertEqual(streams[0].level, logging.WARNING)   # ترمینال شلوغ نمی‌شود
        log = setup_logging("debug", console="on")
        streams = [h for h in log.handlers if getattr(h, "_exir_handler", False)
                   and isinstance(h, logging.StreamHandler)]
        self.assertEqual(streams[0].level, logging.DEBUG)


class SessionSnapshotTests(unittest.TestCase):
    def session(self, base="https://khobregan.exirbroker.com", *, with_token=True,
                challenge=True, app_n="2018887747744.29964494"):
        args = exir_bot.parse_args(["--base-url", base, "--time-sync", "off", "--now"])
        s = exir_bot.build_session(args, pool=1)
        if app_n:
            s.headers["x-app-n"] = app_n
        if with_token:
            s.cookies.set(TOKEN_COOKIE, fake_jwt(), domain="khobregan.exirbroker.com", path="/")
        if challenge:
            s.cookies.set("cookiesession1", "ABCDEF0123456789", domain="khobregan.exirbroker.com", path="/")
        return s

    def test_snapshot_has_names_but_no_values(self):
        s = self.session()
        snap = exir_bot.session_snapshot(s, "https://khobregan.exirbroker.com")
        blob = json.dumps(snap, ensure_ascii=False, default=str)
        self.assertIn(TOKEN_COOKIE, snap["cookie_names"])
        self.assertIn("cookiesession1", snap["cookie_names"])
        self.assertNotIn(fake_jwt(), blob)
        self.assertNotIn("ABCDEF0123456789", blob)
        self.assertTrue(snap["token_cookie"])
        self.assertFalse(snap["token"]["expired"])
        self.assertEqual("2018887747744.29964494", snap["identity_headers"]["x-app-n"])

    def test_snapshot_flags_missing_pieces(self):
        s = self.session(with_token=False, challenge=False, app_n=None)
        snap = exir_bot.session_snapshot(s, "https://khobregan.exirbroker.com")
        self.assertFalse(snap["token_cookie"])
        self.assertIn("cookiesession1", snap["missing_browser_cookies"])
        self.assertNotIn("x-app-n", snap["identity_headers"])

    def test_log_snapshot_emits_event(self):
        s = self.session()
        logger = get_logger("bot")
        with capture_records(logger, level=logging.INFO) as records:
            exir_bot.log_snapshot("session.pre_send", s, "https://khobregan.exirbroker.com",
                                  token=fake_jwt(), auth_mode="cookie")
        events = [r.exir_event for r in records]
        self.assertIn("session.pre_send", events)
        payload = records[events.index("session.pre_send")].exir_fields
        self.assertTrue(payload["token_cookie"])
        self.assertNotIn("headers", payload)      # هدرهای کامل فقط در debug

    def test_log_snapshot_includes_headers_at_debug(self):
        s = self.session()
        logger = get_logger("bot")
        with capture_records(logger):
            logger.setLevel(logging.DEBUG)
            try:
                with capture_records(logger) as records:
                    exir_bot.log_snapshot("session.pre_send", s,
                                          "https://khobregan.exirbroker.com", token=fake_jwt())
            finally:
                logger.setLevel(logging.NOTSET)
        snapshot = [r for r in records if r.exir_event == "session.pre_send"][0].exir_fields
        self.assertIn("headers", snapshot)
        self.assertIn("cookie", snapshot["headers"])

    def test_checklist_reports_problems(self):
        s = self.session(with_token=False, challenge=False, app_n="NaN.12345678")
        checks = exir_bot.security_checklist(s, "https://khobregan.exirbroker.com", clock_offset=9.0)
        joined = "\n".join(checks)
        self.assertIn("✘", joined)
        self.assertIn(TOKEN_COOKIE, joined)
        self.assertIn("cookiesession1", joined)
        self.assertIn("NaN", joined)
        self.assertIn("ساعت", joined)

    def test_checklist_ok_for_healthy_session(self):
        s = self.session()
        checks = exir_bot.security_checklist(s, "https://khobregan.exirbroker.com")
        self.assertTrue(any(c.startswith("✔ توکن معتبر") for c in checks))
        self.assertTrue(any("x-app-n" in c and c.startswith("✔") for c in checks))

    def test_checklist_flags_redirect_response(self):
        s = self.session()
        response = requests.Response()
        response.status_code = 302
        response.headers["location"] = "/new-exir/login"
        checks = exir_bot.security_checklist(s, "https://khobregan.exirbroker.com", response=response)
        self.assertTrue(any("ریدایرکت" in c for c in checks))


class OrderLoggingTests(unittest.TestCase):
    def send(self, status, data, *, headers=None, cookie=f"{TOKEN_COOKIE}=jwt-value"):
        session = requests.Session()
        session.headers.update({"x-app-n": "2018887747744.29964494", "clientid": ""})
        session.cookies.set(TOKEN_COOKIE, fake_jwt(), domain="broker.example", path="/")
        response = requests.Response()
        response.status_code = status
        response.headers.update(headers or {"Content-Type": "application/json"})
        response._content = json.dumps(data).encode()
        request = session.prepare_request(
            requests.Request("POST", "https://broker.example/api/v1/order",
                             data=b'{"insMaxLcode":"IRO7TONP0001"}'))
        request.headers["Cookie"] = cookie      # مقدار خام (در لاگ باید پوشیده شود)
        response.request = request
        stats = exir_bot.Stats()
        stats.sent = 1
        event = threading.Event()
        logger = get_logger("bot")
        with patch.object(session, "post", return_value=response), patch("exir_bot.log"):
            with capture_records(logger) as records:
                exir_bot.send_order(1, session, "https://broker.example/api/v1/order",
                                    b'{"insMaxLcode":"IRO7TONP0001"}', 1, ZoneInfo("Asia/Tehran"),
                                    stats, event, True, base="https://broker.example")
        return stats, event, records

    def test_success_is_logged(self):
        stats, _event, records = self.send(200, {"type": "success"})
        events = [r.exir_event for r in records]
        self.assertIn("order.result", events)
        self.assertNotIn("order.security_rejected", events)
        row = [r for r in records if r.exir_event == "order.result"][0].exir_fields
        self.assertTrue(row["ok"])
        self.assertEqual(200, row["status"])
        self.assertEqual(1, row["idx"])
        self.assertIsInstance(row["elapsed_ms"], float)

    def test_security_rejection_logs_full_context(self):
        stats, event, records = self.send(403, {"type": "error", "errorCode": "9009",
                                                "description": "مشکل امنیتی"})
        events = [r.exir_event for r in records]
        self.assertIn("order.security_rejected", events)
        self.assertEqual(stats.stop_reason, "security")
        self.assertTrue(event.is_set())
        row = [r for r in records if r.exir_event == "order.security_rejected"][0]
        fields = row.exir_fields
        self.assertEqual("9009", str(fields["error_code"]))
        self.assertEqual(403, fields["status"])
        self.assertIn("مشکل امنیتی", fields["description"])
        self.assertTrue(fields["checklist"])          # چک‌لیستِ فرضیه‌ها ضمیمه شده
        self.assertIn("x-app-n", fields["request"])   # درخواستِ واقعی (با کوکی پوشیده)
        self.assertNotIn("jwt-value", json.dumps(fields, ensure_ascii=False, default=str))
        self.assertEqual(logging.ERROR, row.levelno)

    def test_failure_without_security_code_is_not_security_event(self):
        _stats, event, records = self.send(422, {"type": "error", "description": "قیمت نامعتبر"})
        events = [r.exir_event for r in records]
        self.assertIn("order.failed", events)
        self.assertNotIn("order.security_rejected", events)
        self.assertFalse(event.is_set())

    def test_unauthorized_is_security_event(self):
        _stats, event, records = self.send(401, {"type": "error"})
        self.assertIn("order.security_rejected", [r.exir_event for r in records])
        self.assertTrue(event.is_set())

    def test_network_error_is_logged(self):
        session = requests.Session()
        stats, event = exir_bot.Stats(), threading.Event()
        logger = get_logger("bot")
        with patch.object(session, "post", side_effect=requests.Timeout("timeout!")), \
                patch("exir_bot.log"):
            with capture_records(logger) as records:
                exir_bot.send_order(3, session, "https://broker.example/api/v1/order", b"{}", 1,
                                    ZoneInfo("Asia/Tehran"), stats, event, True,
                                    base="https://broker.example")
        self.assertIn("order.network_error", [r.exir_event for r in records])

    def test_request_headers_logged_at_debug(self):
        _stats, _event, records = self.send(200, {"type": "success"})
        logger = get_logger("bot")
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            _stats, _event, records = self.send(200, {"type": "success"})
        finally:
            logger.setLevel(previous)
        events = [r.exir_event for r in records]
        self.assertIn("order.request", events)
        fields = [r for r in records if r.exir_event == "order.request"][0].exir_fields
        self.assertIn("headers", fields)
        self.assertIn("clientid", fields["headers"])
        self.assertIn("IRO7TONP0001", str(fields["body"]))


class CliTests(unittest.TestCase):
    def test_log_flags_have_defaults(self):
        args = exir_bot.parse_args(["--now", "--time-sync", "off"])
        self.assertEqual("info", args.log_level)
        self.assertEqual("text", args.log_format)
        self.assertEqual("auto", args.log_console)
        self.assertIsNone(args.log_file)

    def test_panel_accepts_log_flags(self):
        import web_panel
        args = web_panel.parse_args(["--panel-key", "k" * 20, "--log-level", "debug",
                                     "--log-file", "logs/panel.log", "--log-format", "json"])
        self.assertEqual("debug", args.log_level)
        self.assertEqual("logs/panel.log", args.log_file)
        self.assertEqual("json", args.log_format)

    def test_log_flags_are_settable(self):
        args = exir_bot.parse_args(["--now", "--time-sync", "off", "--log-level", "debug",
                                    "--log-file", "logs/x.log", "--log-format", "json"])
        self.assertEqual("debug", args.log_level)
        self.assertEqual("logs/x.log", args.log_file)
        self.assertEqual("json", args.log_format)

    def test_report_emits_run_report(self):
        stats = exir_bot.Stats()
        stats.sent, stats.success, stats.failed = 2, 1, 1
        stats.results = [(1, "10:00:00.000", 403, "مشکل امنیتی")]
        logger = get_logger("bot")
        with patch("exir_bot.log"):
            with capture_records(logger) as records:
                exir_bot._print_report(stats, ZoneInfo("Asia/Tehran"))
        row = [r for r in records if r.exir_event == "run.report"][0]
        self.assertEqual(2, row.exir_fields["sent"])
        self.assertEqual(403, row.exir_fields["results"][0]["status"])

    def test_stop_is_logged_with_reason(self):
        stats = exir_bot.Stats()
        stats.stop_reason = "security"
        logger = get_logger("bot")
        with patch("exir_bot.log"):
            with capture_records(logger) as records:
                exir_bot._log_stop(stats, 30)
        row = [r for r in records if r.exir_event == "run.stopped"][0]
        self.assertEqual("security", row.exir_fields["reason"])
        self.assertEqual(30, row.exir_fields["remaining"])
        self.assertEqual(logging.ERROR, row.levelno)


class TokenFileTests(unittest.TestCase):
    def test_saved_session_snapshot_is_safe(self):
        """فایل توکنِ واقعی را بخوان و مطمئن شو لاگِ نشست چیزی را فاش نمی‌کند."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "token.json"
            token = fake_jwt()
            save_token(path, "https://broker.example", token,
                       {"cookies": [{"name": "cookiesession1", "value": "SUPERSECRETCOOKIEVALUE",
                                     "domain": "broker.example", "path": "/"}]})
            from exir_auth import apply_token, restore_session_cookies
            saved = __import__("exir_auth").load_saved_token(path, "https://broker.example")
            args = exir_bot.parse_args(["--base-url", "https://broker.example", "--time-sync", "off"])
            session = exir_bot.build_session(args, pool=1)
            restore_session_cookies(session, "https://broker.example", saved.get("cookies", []))
            apply_token(session, "https://broker.example", saved["token"], "cookie")
            logger = get_logger("bot")
            with capture_records(logger) as records:
                exir_bot.log_snapshot("session.after_login", session, "https://broker.example",
                                      token=saved["token"], auth_mode="cookie")
            blob = "\n".join(TextFormatter().format(r) for r in records)
            self.assertNotIn(token, blob)
            self.assertNotIn("SUPERSECRETCOOKIEVALUE", blob)
            self.assertIn("cookiesession1", blob)      # نام کوکی هست، مقدار نه


if __name__ == "__main__":
    unittest.main()
