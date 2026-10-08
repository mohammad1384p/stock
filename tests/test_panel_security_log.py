"""اجرای کامل پنل روی یک کارگزار جعلی که سفارش را با 403/9009 رد می‌کند.

هدف: مطمئن شویم در همین حالت، لاگ پنل «درخواستی که فرستاده شد» را نشان می‌دهد،
راهنمای probe_order.py را چاپ می‌کند و اجرا را همان‌جا متوقف می‌کند.
"""
import base64
import json
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

import web_panel
from exir_auth import save_token
from web_panel import PanelState, panel_handler


def fake_jwt(exp_offset: int = 3600) -> str:
    enc = lambda obj: base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'none'})}.{enc({'sub': 'tester', 'exp': time.time() + exp_offset})}.sig"


class FakeBroker:
    """کارگزار جعلی: سفارش را همیشه با 403/9009 رد می‌کند."""

    def __init__(self):
        self.orders: list[dict] = []
        broker = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def _json(self, status, payload):
                data = json.dumps(payload, ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Date", "Tue, 08 Oct 2026 10:00:00 GMT")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):  # noqa: N802
                self._json(200, {"ok": True})

            def do_POST(self):  # noqa: N802
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else ""
                broker.orders.append({"path": self.path, "headers": dict(self.headers), "body": body})
                self._json(403, {"type": "error", "msgType": "error",
                                 "description": "مشکل امنیتی.درخواست معتبر نمی باشد",
                                 "descriptionEn": "Security problem.Invalid request",
                                 "errorCode": 9009})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True, name="fake-broker").start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def call(url: str, data: dict | None = None):
    body = json.dumps(data).encode("utf-8") if data is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    try:
        with urlopen(UrlRequest(url, data=body, headers=headers), timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except HTTPError as e:  # 4xx/5xx
        return e.code, json.loads(e.read() or b"{}")


class PanelSecurityRejectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.broker = FakeBroker()
        cls.tmp = TemporaryDirectory()
        cls.token_file = Path(cls.tmp.name) / "token.json"
        save_token(cls.token_file, cls.broker.base, fake_jwt(),
                   {"name": "tester", "sendOrderDelay": 400, "appN": "2018887747744.29964494",
                    "cookies": [{"name": "client_login_id", "value": "cid", "domain": "127.0.0.1",
                                 "path": "/", "secure": False, "expires": None, "rest": {}}]})
        args = web_panel.parse_args([
            "--host", "127.0.0.1", "--port", "0", "--time-sync", "off",
            "--base-url", cls.broker.base, "--token-file", str(cls.token_file),
            "--captcha-file", str(Path(cls.tmp.name) / "captcha.png"),
        ])
        cls.state = PanelState(args)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), panel_handler(cls.state))
        cls.httpd.daemon_threads = True
        cls.state.port = cls.httpd.server_address[1]
        cls.base = f"http://127.0.0.1:{cls.state.port}"
        threading.Thread(target=cls.httpd.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True, name="panel-9009").start()

    @classmethod
    def tearDownClass(cls):
        cls.state.shutdown()
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.broker.close()
        cls.tmp.cleanup()

    def test_run_is_stopped_and_the_sent_request_is_logged(self):
        status, snap = call(self.base + "/api/start", {
            "symbol": "IRO7TONP0001", "quantity": "10", "price": "6700",
            "time": "", "now": True, "dry_run": False, "duration": "1", "interval": "305",
            "time_sync": "off",
        })
        self.assertEqual(status, 200, snap)

        deadline = time.time() + 25
        log_text = ""
        while time.time() < deadline:
            _, snap = call(self.base + "/api/state?after=0")
            log_text = "\n".join(entry[2] for entry in snap["logs"])
            if snap["status"] in ("error", "finished", "stopped") and snap["stats"]:
                break
            time.sleep(0.1)

        self.assertEqual(self.state.status, "error")
        self.assertIn("9009", log_text)
        # درخواست واقعیِ ارسال‌شده در لاگ چاپ می‌شود (با مقدار کوتاه‌شده‌ی کوکی)
        self.assertIn("📤", log_text)
        self.assertIn("POST /api/v1/order HTTP/1.1", log_text)
        self.assertIn("clientid:", log_text)
        self.assertIn("x-app-n: 2018887747744.29964494", log_text)
        self.assertIn("JWT-TOKEN=", log_text)
        self.assertNotIn(fake_jwt()[:40], log_text)   # مقدار کامل توکن لو نمی‌رود
        # راهنمای ابزار کاوش
        self.assertIn("probe_order.py", log_text)
        # فقط یک درخواست ارسال شد و ارسال‌های بعدی متوقف شدند
        self.assertEqual(len(self.broker.orders), 1)
        self.assertEqual(self.state.stats.sent, 1)
        self.assertEqual(self.state.stats.stop_reason, "security")
        first = snap["stats"]["results"][0]
        self.assertEqual(first["status"], 403)
        self.assertIn("امنیتی", first["desc"])

    def test_probe_plan_is_listed_without_contacting_broker(self):
        status, snap = call(self.base + "/api/state?after=0")
        self.assertEqual(status, 200)
        self.assertIn("login", snap)
        self.assertIn("token", snap)


if __name__ == "__main__":
    unittest.main()
