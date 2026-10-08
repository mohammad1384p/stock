import json
import threading
import unittest
from concurrent.futures import Future
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import patch
from zoneinfo import ZoneInfo

import requests

import web_panel
from diagnose_session import session_report
from exir_auth import save_token
from exir_bot import Stats, send_order, stop_message


class OrderResponseTests(unittest.TestCase):
    def send(self, status, data, stop_on_success=True, content_type="application/json"):
        session = requests.Session()
        response = requests.Response()
        response.status_code = status
        response.headers["Content-Type"] = content_type
        response._content = json.dumps(data).encode()
        stats = Stats()
        stats.sent = 1
        event = threading.Event()
        with patch.object(session, "post", return_value=response) as post, patch("exir_bot.log"):
            send_order(1, session, "https://broker.example/api/v1/order", b"{}", 1,
                       ZoneInfo("Asia/Tehran"), stats, event, stop_on_success)
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        return stats, event

    def test_security_rejection_stops_even_when_no_stop_on_success(self):
        for code in (9009, "9009"):
            stats, event = self.send(403, {"type": "error", "errorCode": code}, False)
            self.assertTrue(event.is_set())
            self.assertEqual(stats.stop_reason, "security")
            self.assertEqual((stats.success, stats.failed), (0, 1))
            self.assertNotIn("✅", stop_message(stats, 32))

    def test_unauthorized_stops(self):
        stats, event = self.send(401, {})
        self.assertTrue(event.is_set())
        self.assertEqual(stats.stop_reason, "security")

    def test_validation_error_does_not_claim_success(self):
        stats, event = self.send(422, {"type": "error"})
        self.assertFalse(event.is_set())
        self.assertEqual((stats.success, stats.failed), (0, 1))

    def test_success_and_no_stop_option(self):
        stats, event = self.send(200, {"type": "success"})
        self.assertTrue(event.is_set())
        self.assertEqual(stats.stop_reason, "success")
        self.assertIn("✅", stop_message(stats, 32))
        stats, event = self.send(200, {"type": "success"}, False)
        self.assertFalse(event.is_set())
        self.assertEqual(stats.success, 1)

    def test_redirect_and_html_are_not_successful_orders(self):
        for status, ctype in ((302, "text/html"), (200, "text/html")):
            stats, event = self.send(status, {}, content_type=ctype)
            self.assertEqual((stats.success, stats.failed), (0, 1))
            self.assertFalse(event.is_set())

    def test_manual_stop_message_does_not_claim_success(self):
        self.assertIn("کاربر", stop_message(Stats(), 8))
        self.assertNotIn("موفق", stop_message(Stats(), 8))


class InlineExecutor:
    """Deterministic response before the scheduler advances to the next order."""
    def __init__(self, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def submit(self, fn, *args):
        future = Future()
        future.set_result(fn(*args))
        return future


class PanelStopTests(unittest.TestCase):
    def test_security_and_manual_stop_in_scheduler(self):
        for reason in ("security", None, "success"):
            with self.subTest(reason=reason), TemporaryDirectory() as tmp:
                args = web_panel.parse_args(["--token-file", str(Path(tmp) / "token.json"),
                                             "--time-sync", "off"])
                state = web_panel.PanelState(args)
                req = web_panel.validate_run_request({"symbol": "IRO7TONP0001", "quantity": 1,
                                                      "price": 6700, "now": True, "time_sync": "off"})
                cfg = web_panel._run_cfg(state, req)
                cfg.now_mode, cfg.body_text = True, ""
                stats, event = Stats(), threading.Event()

                def complete(*args):
                    stats.stop_reason = reason
                    stats.success = int(reason == "success")
                    stats.failed = int(reason != "success")
                    event.set()

                with patch("web_panel.time_sync"), patch("web_panel.wait_until"), \
                        patch("web_panel.warmup"), patch("web_panel.ThreadPoolExecutor", InlineExecutor), \
                        patch("web_panel.send_order", side_effect=complete), patch("web_panel.panel_log") as log:
                    web_panel._fire(state, cfg, requests.Session(), state.base, event, stats)
                self.assertEqual(stats.sent, 1)
                messages = "\n".join(str(c.args[0]) for c in log.call_args_list)
                if reason == "security":
                    self.assertEqual(state.status, "error")
                    self.assertNotIn("✅", messages)
                elif reason is None:
                    self.assertEqual(state.status, "stopped")
                    self.assertNotIn("✅", messages)
                else:
                    self.assertEqual(state.status, "finished")
                    self.assertIn("✅", messages)


class DiagnosticTests(unittest.TestCase):
    def test_report_is_offline_and_contains_no_secrets(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "token.json"
            base = "https://trade.broker.example"
            save_token(path, base, "PRIVATE_JWT", {"name": "PRIVATE_NAME", "appN": "NaN.12345678",
                       "cookies": [{"name": "companion", "value": "PRIVATE_COOKIE",
                                    "domain": ".broker.example", "path": "/", "secure": True}]})
            args = web_panel.parse_args(["--base-url", base, "--token-file", str(path)])
            with patch("requests.Session.send", side_effect=AssertionError("must be offline")):
                report = session_report(args)
            text = json.dumps(report)
            for secret in ("PRIVATE_JWT", "PRIVATE_NAME", "PRIVATE_COOKIE", "NaN.12345678"):
                self.assertNotIn(secret, text)
            self.assertEqual(report["requests_sent"], 0)
            self.assertTrue(report["saved_token_available"])
            self.assertTrue(report["x_app_n"]["fallback_nan_pattern"])
            self.assertTrue(report["x_app_n"]["matches_saved"])
            self.assertEqual(report["cookie_names_sent"], ["companion", "JWT-TOKEN"])


if __name__ == "__main__":
    unittest.main()
