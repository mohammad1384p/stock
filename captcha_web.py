# -*- coding: utf-8 -*-
"""
نمایش تصویر کپچا در مرورگر خودِ کاربر و گرفتن کد از او — برای سرورهای بدون نمایشگر.

چرا به این ماژول نیاز است؟
  کپچای اکسیر به کوکی ``client_login_id`` همان نشست (session) گره خورده است. اگر تصویر
  کپچا را با مرورگر خودتان مستقیماً از کارگزاری بگیرید، آن تصویر به نشست مرورگرِ شما گره
  می‌خورد، ولی درخواست لاگین از سرور با ``client_login_id`` سرور فرستاده می‌شود؛ نتیجه
  خطای ۹۰۰۹ «مشکل امنیتی. درخواست معتبر نمی‌باشد» (HTTP 403) است.
  پس تصویر باید با همان session ربات گرفته شود و فقط *کد* از کاربر پرسیده شود.

راه‌حل: این ماژول یک وب‌سرور موقت روی همان سروری که ربات اجرا می‌شود بالا می‌آورد و
همان تصویرِ گرفته‌شده با session ربات را در مرورگر شما نشان می‌دهد؛ کدی که در مرورگر
(یا در ترمینال سرور) وارد کنید به ربات می‌رسد و ربات با session خودش لاگین می‌کند.

امنیت: آدرس با یک توکن تصادفی محافظت می‌شود، تصویر کش نمی‌شود و وب‌سرور بعد از لاگین
(یا لغو) بسته می‌شود.
"""

from __future__ import annotations

import html
import json
import os
import queue
import secrets
import select
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DEFAULT_PORT = 8765
DEFAULT_TTL = 120.0


# --------------------------------------------------------------------------- #
#  ابزارهای کمکی
# --------------------------------------------------------------------------- #
def sniff_type(data: bytes) -> str:
    """نوع تصویر را از روی محتوایش تشخیص می‌دهد."""
    if data[:4] == b"\x89PNG":
        return "image/png"
    if data[:2] == b"\xff\xd8":
        return "image/jpeg"
    if data[:4] == b"GIF8":
        return "image/gif"
    if b"<svg" in data[:300].lower():
        return "image/svg+xml; charset=utf-8"
    if data[:2] in (b"BM",):
        return "image/bmp"
    return "application/octet-stream"


def local_ip() -> str | None:
    """IP محلی این ماشین در شبکه (برای آدرس دادن به مرورگر)."""
    for probe in (("8.8.8.8", 80), ("1.1.1.1", 80)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(probe)
                return s.getsockname()[0]
            finally:
                s.close()
        except OSError:
            continue
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return None


def resolve_mode(value: str | None) -> int | None:
    """
    مقدار --captcha-web / EXIR_CAPTCHA_WEB را به «پورت» تبدیل می‌کند.

    None یا "" یا "auto"/"on" → فعال با پورت پیش‌فرض/خودکار (۰ = خودکار)
    "off"/"no"/"0"/"false"/"disable" → غیرفعال (None)
    عدد مثل "8080" → فعال روی همان پورت
    """
    v = (value or "").strip().lower()
    if v in ("", "auto", "on", "yes", "true", "1"):
        return 0
    if v in ("off", "no", "none", "false", "disable", "disabled"):
        return None
    if v.isdigit():
        return int(v)
    return 0


# --------------------------------------------------------------------------- #
#  صفحه‌ی HTML
# --------------------------------------------------------------------------- #
_PAGE = """<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>کپچا — ربات Exir</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: Tahoma, system-ui, -apple-system, sans-serif; max-width: 540px;
         margin: 24px auto; padding: 0 16px; line-height: 1.9; }
  h2 { margin: 0 0 6px; }
  img#cap { display:block; width:100%; max-width:420px; margin:14px auto; border:1px solid #8884;
            border-radius:10px; background:#fff; min-height:80px; }
  input[type=text] { font-size:1.4rem; width:100%; box-sizing:border-box; padding:10px;
                     text-align:center; letter-spacing:.25em; border-radius:10px;
                     border:1px solid #8886; background:#8881; }
  button { font-size:1.1rem; width:100%; margin-top:10px; padding:12px; border:0;
           border-radius:10px; background:#2563eb; color:#fff; cursor:pointer; }
  a { color:#2563eb; }
  .muted { opacity:.75; font-size:.95rem; }
  .ok { color:#16a34a; font-weight:bold; }
  .err { color:#dc2626; font-weight:bold; }
  .box { background:#8881; border-radius:10px; padding:10px 14px; margin-top:14px;
         white-space:pre-wrap; word-break:break-word; }
</style>
</head>
<body>
<h2>🖼 کپچای اکسیر</h2>
<p>کدی را که در تصویر می‌بینید <b>در ترمینال سرور</b> وارد کنید، یا همین‌جا در کادر زیر
بنویسید و «ارسال به ربات» را بزنید. (لاگین با نشست همان سرور انجام می‌شود)</p>
<img id="cap" src="__IMG__?v=0" alt="تصویر کپچا">
<p class="muted">⏳ اعتبار تصویر: <span id="left">…</span></p>
<form method="post" action="__CODE__" autocomplete="off">
  <input type="text" name="code" placeholder="کد کپچا" autocomplete="off" autocapitalize="off"
         spellcheck="false" autofocus>
  <button type="submit">ارسال به ربات</button>
</form>
<p class="muted"><a href="__NEW__" id="newlink">🔄 کپچای جدید (اگر ناخوانا بود)</a></p>
<div class="box muted" id="msg">__MSG__</div>
<script>
(function () {
  var IMG = "__IMG__", STATUS = "__STATUS__", NEW = "__NEW__";
  var ver = -1;
  function el(id) { return document.getElementById(id); }
  function msg(t, cls) { var m = el("msg"); m.className = "box " + (cls || "muted"); m.textContent = t; }
  function tick() {
    fetch(STATUS, { cache: "no-store" }).then(function (r) { return r.json(); }).then(function (s) {
      if (s.version !== ver) {
        ver = s.version;
        el("cap").src = IMG + "?v=" + s.version + "&t=" + Date.now();
        if (s.version > 1) msg("تصویر کپچا به‌روز شد.");
      }
      el("left").textContent = s.left > 0 ? Math.round(s.left) + " ثانیه" : "منقضی شد";
      if (s.state === "ok") msg(s.message, "ok");
      else if (s.state === "error") msg(s.message, "err");
      else if (s.state === "submitting") msg(s.message || "کد دریافت شد؛ در حال لاگین…");
    }).catch(function () { el("left").textContent = "اتصال قطع شد"; });
  }
  el("newlink").addEventListener("click", function (e) {
    e.preventDefault();
    fetch(NEW, { cache: "no-store" }).then(function () {
      msg("درخواست کپچای جدید ثبت شد؛ تصویر خودکار عوض می‌شود…");
    });
  });
  setInterval(tick, 1500);
  tick();
})();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
#  وب‌سرور موقت کپچا
# --------------------------------------------------------------------------- #
class CaptchaPortal:
    """
    تصویر کپچا را به مرورگر کاربر نشان می‌دهد و کد را از او می‌گیرد.

    - ``set_image(bytes)`` تصویر گرفته‌شده با session ربات را روی صفحه می‌گذارد.
    - ``announce()`` آدرس صفحه را در ترمینال چاپ می‌کند.
    - ``wait_for_code(ttl)`` منتظر کد از مرورگر یا ترمینال می‌ماند.
    - ``finish(ok)``/``stop()`` نتیجه را نشان می‌دهد و سرور را می‌بندد.
    """

    def __init__(self, log=None, host: str = "0.0.0.0", port: int = 0, ttl: float = DEFAULT_TTL):
        self.log = log
        self.host = host or "0.0.0.0"
        self.port = int(port or 0)
        self.ttl = float(ttl)
        self.token = secrets.token_urlsafe(9)
        self.base = "/" + self.token
        self.ctype = "application/octet-stream"
        self.state = "starting"
        self.message = ""
        # فقط روی سیستم‌هایی که ترمینال واقعی دارند از stdin هم می‌خوانیم
        self.stdin_ok = sys.stdin is not None and (os.name != "nt" or sys.stdin.isatty())
        self.urls: list[str] = []
        self._img = b""
        self._version = 0
        self._fetched_at = 0.0
        self._lock = threading.RLock()
        self._events: "queue.Queue[tuple[str, str]]" = queue.Queue()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._announced = False

    # ---------------- چرخه‌ی عمر ----------------
    def start(self) -> bool:
        """وب‌سرور را روی پورت دلخواه (یا خودکار) بالا می‌آورد. False = نشد."""
        ports = [self.port] if self.port else [DEFAULT_PORT, 0]
        last_err: Exception | None = None
        for p in ports:
            try:
                httpd = ThreadingHTTPServer((self.host, p), _handler(self))
            except OSError as e:
                last_err = e
                continue
            httpd.daemon_threads = True
            self._httpd = httpd
            self.port = httpd.server_address[1]
            self._thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.2},
                                            name="captcha-web", daemon=True)
            self._thread.start()
            self.urls = self._build_urls()
            return True
        if self.log:
            self.log(f"⚠️  بالا آوردن وب‌سرور کپچا ممکن نشد ({last_err}) — از تصویر محلی/ترمینال استفاده کنید.")
        return False

    def _build_urls(self) -> list[str]:
        path = self.base + "/"
        hosts: list[str] = []
        if self.host in ("0.0.0.0", "::", ""):  # روی همه‌ی کارت‌های شبکه
            hosts += ["127.0.0.1", local_ip() or ""]
        elif self.host in ("127.0.0.1", "localhost"):
            hosts += ["127.0.0.1", local_ip() or ""]  # حتی با بایند لوکال، نمایش IP مفید است
        else:
            hosts += [self.host]
        urls = []
        for h in hosts:
            if h and h not in [u.split("//")[1].split(":")[0] for u in urls]:
                urls.append(f"http://{h}:{self.port}{path}")
        return urls

    def announce(self) -> None:
        """آدرس را یک‌بار در ترمینال چاپ می‌کند."""
        if self._announced or not self.log or not self.urls:
            return
        self._announced = True
        self.log("🌐 کپچا را در مرورگر باز کنید (یکی از این آدرس‌ها):")
        for u in self.urls:
            self.log("   " + u)
        if self.host in ("127.0.0.1", "localhost"):
            self.log("   (فقط از خودِ سرور قابل دسترسی است؛ برای کامپیوتر خودتان تونل بزنید)")
        self.log(f"   اگر سرور از راه دور است: روی کامپیوتر خودتان اجرا کنید →  ssh -L {self.port}:127.0.0.1:{self.port} user@server")
        self.log("   کد را می‌توانید در ترمینال سرور وارد کنید یا در همان صفحه بفرستید.")

    def stop(self) -> None:
        httpd, self._httpd = self._httpd, None
        if httpd is None:
            return
        try:
            httpd.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            httpd.server_close()
        except Exception:  # noqa: BLE001
            pass

    # ---------------- تصویر و وضعیت ----------------
    def set_image(self, img: bytes) -> None:
        with self._lock:
            self._img = img
            self.ctype = sniff_type(img)
            self._version += 1
            self._fetched_at = time.time()
            self.state = "waiting"
            self.message = ""

    def image(self) -> tuple[bytes, int]:
        with self._lock:
            return self._img, self._version

    def status(self) -> dict:
        with self._lock:
            age = (time.time() - self._fetched_at) if self._fetched_at else 0.0
            return {
                "version": self._version,
                "age": round(age, 1),
                "left": round(max(0.0, self.ttl - age), 1),
                "state": self.state,
                "message": self.message,
            }

    def set_state(self, state: str, message: str = "") -> None:
        self.state = state
        self.message = message

    def page(self, note: str = "") -> str:
        """HTML صفحه‌ی کپچا."""
        if not note:
            if self.state == "ok":
                note = self.message or "✅ ورود موفق بود."
            elif self.state == "error":
                note = self.message or "✘ ورود ناموفق بود؛ به ترمینال سرور برگردید."
            else:
                note = "منتظر کد هستم… (می‌توانید کد را در ترمینال سرور هم وارد کنید)"
        return (_PAGE
                .replace("__IMG__", self.base + "/captcha.jpg")
                .replace("__CODE__", self.base + "/code")
                .replace("__NEW__", self.base + "/new")
                .replace("__STATUS__", self.base + "/status")
                .replace("__MSG__", html.escape(note)))

    def finish(self, ok: bool, message: str = "") -> None:
        self.set_state("ok" if ok else "error",
                       message or ("✅ ورود موفق بود؛ این صفحه را ببندید." if ok
                                   else "✘ ورود ناموفق بود؛ به ترمینال سرور برگردید."))

    # ---------------- گرفتن کد ----------------
    def submit(self, code: str) -> None:
        """کد را از مرورگر می‌گیرد (رشته‌ی خالی = درخواست کپچای جدید)."""
        code = (code or "").strip()
        self._events.put(("code", code) if code else ("new", ""))

    def request_new(self) -> None:
        self._events.put(("new", ""))

    def _stdin_ready(self, timeout: float) -> bool:
        if os.name == "nt":
            try:
                import msvcrt
                return bool(msvcrt.kbhit())  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                self.stdin_ok = False
                return False
        try:
            return bool(select.select([sys.stdin], [], [], timeout)[0])
        except Exception:  # noqa: BLE001
            self.stdin_ok = False
            return False

    def wait_for_code(self, timeout: float | None = None) -> tuple[str | None, str]:
        """
        منتظر کد می‌ماند.

        خروجی ``(code, source)``:
          - ``code`` رشته‌ی کد، رشته‌ی خالی (کاربر کپچای جدید خواست) یا None (مهلت تمام شد)
          - ``source`` یکی از ``"web"``، ``"stdin"``، ``"timeout"``
        """
        deadline = time.time() + (self.ttl if timeout is None else float(timeout))
        stdin_open = self.stdin_ok
        while True:
            if stdin_open and self._stdin_ready(0.05):
                line = sys.stdin.readline()
                if not line:  # EOF (مثلاً ورودی pipe)
                    stdin_open = False
                else:
                    return line.strip(), "stdin"
                continue
            try:
                kind, value = self._events.get_nowait()
            except queue.Empty:
                pass
            else:
                return (value, "web") if kind == "code" else ("", "web")
            if time.time() >= deadline:
                return None, "timeout"


# --------------------------------------------------------------------------- #
#  handler وب‌سرور
# --------------------------------------------------------------------------- #
def _handler(portal: CaptchaPortal):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ExirCaptcha/1.0"
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:  # بی‌صدا
            pass

        # ---------- کمکی ----------
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Pragma", "no-cache")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _html(self, text: str, code: int = 200) -> None:
            self._send(code, text.encode("utf-8"), "text/html; charset=utf-8")

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _not_found(self) -> None:
            self._html("<h3>۴۰۴</h3><p>آدرس درست نیست یا وب‌سرور کپچا بسته شده است.</p>", 404)

        # ---------- مسیرها ----------
        def do_GET(self) -> None:  # noqa: N802
            base = portal.base.rstrip("/")  # توکن خالی → base = "" و صفحه روی "/" سرو می‌شود
            path = urlparse(self.path).path
            path = path.rstrip("/") or "/"
            if path == (base or "/"):
                self._html(portal.page())
            elif path == base + "/captcha.jpg":
                img, _ = portal.image()
                if not img:
                    self._send(404, b"no captcha yet", "text/plain; charset=utf-8")
                else:
                    self._send(200, img, portal.ctype)
            elif path == base + "/new":
                portal.request_new()
                self._html(portal.page("درخواست کپچای جدید ثبت شد؛ تصویر به‌زودی عوض می‌شود…"))
            elif path == base + "/status":
                self._json(portal.status())
            else:
                self._not_found()

        def do_HEAD(self) -> None:  # noqa: N802
            self._send(200, b"", "text/plain; charset=utf-8")

        def do_POST(self) -> None:  # noqa: N802
            base = portal.base.rstrip("/")
            path = urlparse(self.path).path
            path = path.rstrip("/") or "/"
            if path != base + "/code":
                self._not_found()
                return
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            body = self.rfile.read(n).decode("utf-8", "replace") if n > 0 else ""
            code = (parse_qs(body).get("code") or [""])[0].strip()
            if code:
                portal.submit(code)
                self._html(portal.page("✅ کد دریافت شد؛ در حال لاگین با نشست سرور…"))
            else:
                portal.request_new()
                self._html(portal.page("کادر خالی بود؛ کپچای جدید درخواست شد…"))

    return Handler
