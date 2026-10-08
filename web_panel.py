#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
وب‌پنل ربات سفارش زمان‌دار اکسیر.

همان منطقِ ``exir_bot.py`` را در یک وب‌سرور سبک (کتابخانه‌ی استاندارد، بدون وابستگی
اضافه) بالا می‌آورد تا بتوانید از مرورگر:

  * سفارش را فرم کنید (نماد، تعداد، قیمت، ساعت، خرید/فروش، مدت و فاصله)،
  * ساعت را با NTP/سرور کارگزاری همگام کنید،
  * لاگین کنید و کپچا را **در همین صفحه** بفرستید (صفحه‌ی کپچا از پنل پروکسی می‌شود)،
  * ارسال را شروع/متوقف کنید و پاسخ هر درخواست را زنده ببینید.

نمونه:
    python web_panel.py --host 127.0.0.1 --port 2345
    python web_panel.py --port 8000 --time-sync off          # برای تست سریع

امنیت: پنل می‌تواند سفارش واقعی بفرستد و توکن/رمز را در خود دارد؛ پیش‌فرض روی
``0.0.0.0`` بالا می‌آید تا از مرورگر همان شبکه/تونل SSH در دسترس باشد. اگر لازم
نیست، با ``--host 127.0.0.1`` فقط روی خود سرور بایند کنید.
"""

from __future__ import annotations

import argparse
import html as html_mod
import http.client
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

try:
    import requests  # noqa: F401  (فقط برای بررسی نصب بودن)
except ImportError:  # pragma: no cover
    print("کتابخانه‌ی requests نصب نیست. اجرا کنید:  pip install -r requirements.txt")
    sys.exit(1)

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

import exir_bot
from captcha_web import CaptchaPortal, local_ip
from exir_auth import (CAPTCHA_TTL, apply_token, clean_token, describe_token, jwt_exp,
                       load_saved_token, login, restore_session_cookies, save_token,
                       session_cookies)
from exir_bot import (DEFAULT_BASE_URL, ORDER_PATH, Stats, apply_replay, build_session,
                      parse_fetch_snippet, parse_target_time, resolve_isin, send_order,
                      wait_until, warmup)
from timesync import clock, sync as time_sync

__version__ = "1.0"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
TIME_RE = re.compile(r"^\s*\d{1,2}:\d{1,2}(?::\d{1,2}(?:[.,]\d{1,3})?)?\s*$")
MAX_REQUESTS = 5000
RUNNING_STATES = ("preparing", "syncing", "waiting", "firing")


def strip_ansi(text: str) -> str:
    """حذف کدهای رنگی ترمینال برای نمایش در مرورگر."""
    return _ANSI_RE.sub("", text)


def fmt_ms(moment: datetime) -> str:
    """قالب ``HH:MM:SS.mmm`` برای ساعت‌های دقیق (یا تاریخ کامل اگر امروز نباشد)."""
    today = datetime.fromtimestamp(clock.now(), moment.tzinfo).date() if moment.tzinfo else datetime.now().date()
    base = "%H:%M:%S.%f" if moment.date() == today else "%Y-%m-%d %H:%M:%S.%f"
    return moment.strftime(base)[:-3]


# --------------------------------------------------------------------------- #
#  مسیردهی لاگ: هم ترمینال، هم بافر پنل
# --------------------------------------------------------------------------- #
_TERMINAL_LOG = exir_bot.log
STATE: "PanelState | None" = None


def panel_log(*parts) -> None:
    text = " ".join(str(p) for p in parts)
    state = STATE
    if state is not None:
        state.add_log(strip_ansi(text))
    _TERMINAL_LOG(*parts)


exir_bot.log = panel_log  # تا پیام‌های داخلی ربات (send_order و…) هم در پنل دیده شوند


class PanelError(RuntimeError):
    """خطای قابل‌نمایش به کاربر (پیامش مستقیم در UI نشان داده می‌شود)."""


class Stopped(Exception):
    """اجرا به‌خواست کاربر متوقف شد."""


# --------------------------------------------------------------------------- #
#  اعتبارسنجی درخواست اجرا
# --------------------------------------------------------------------------- #
def _as_int(raw, label: str, minimum: int = 1, default: int | None = None) -> int:
    if raw is None or str(raw).strip() == "":
        if default is None:
            raise ValueError(f"{label} را وارد کنید.")
        return default
    text = str(raw).replace(",", "").replace("٬", "").replace("،", "").strip()
    try:
        value = int(float(text))
    except ValueError:
        raise ValueError(f"{label} باید عدد باشد.") from None
    if value < minimum:
        raise ValueError(f"{label} باید حداقل {minimum} باشد.")
    return value


def _as_float(raw, label: str, minimum: float = 0.0, default: float | None = None) -> float:
    if raw is None or str(raw).strip() == "":
        if default is None:
            raise ValueError(f"{label} را وارد کنید.")
        return default
    text = str(raw).replace(",", "").strip()
    try:
        value = float(text)
    except ValueError:
        raise ValueError(f"{label} باید عدد باشد.") from None
    if value < minimum:
        raise ValueError(f"{label} باید حداقل {minimum:g} باشد.")
    return value


def validate_run_request(data: dict) -> dict:
    """ورودی خام صفحه را بررسی و تمیز می‌کند. خطای کاربر → ``ValueError`` با پیام فارسی."""
    if not isinstance(data, dict):
        raise ValueError("بدنه‌ی درخواست JSON معتبر نیست.")

    symbol = str(data.get("symbol") or "").strip()
    if not symbol:
        raise ValueError("نماد / ISIN را وارد کنید.")

    quantity = _as_int(data.get("quantity"), "تعداد")
    price = _as_int(data.get("price"), "قیمت")
    duration = _as_float(data.get("duration"), "مدت ارسال (ثانیه)", 0.0, default=10.0)
    interval = _as_int(data.get("interval"), "فاصله‌ی درخواست‌ها (میلی‌ثانیه)", 1, default=305)

    count = int(duration / (interval / 1000.0) + 1e-9) + 1
    if count > MAX_REQUESTS:
        raise ValueError(f"تعداد درخواست‌ها ({count}) بیش از حد مجاز ({MAX_REQUESTS}) است؛ "
                         "مدت را کم یا فاصله را زیاد کنید.")

    now_mode = bool(data.get("now"))
    start_time = str(data.get("time") or "").strip()
    if not now_mode:
        if not start_time:
            raise ValueError("ساعت شروع را وارد کنید (HH:MM:SS یا HH:MM:SS.mmm).")
        if not TIME_RE.match(start_time):
            raise ValueError("قالب ساعت شروع باید HH:MM:SS یا HH:MM:SS.mmm باشد.")

    side = "sell" if str(data.get("side") or "buy").lower() == "sell" else "buy"
    mode = str(data.get("time_sync") or "").strip().lower()
    if mode not in ("auto", "ntp", "server", "off", ""):
        mode = ""

    return {
        "symbol": symbol,
        "quantity": quantity,
        "price": price,
        "duration": duration,
        "interval": interval,
        "time": start_time,
        "now": now_mode,
        "side": side,
        "no_stop": bool(data.get("no_stop")),
        "dry_run": bool(data.get("dry_run")),
        "time_sync": mode,
        "body": str(data.get("body") or "").strip(),
    }


# --------------------------------------------------------------------------- #
#  وضعیت پنل
# --------------------------------------------------------------------------- #
class PanelState:
    """همه‌ی آنچه بین درخواست‌های HTTP و رشته‌های کاری مشترک است."""

    def __init__(self, args: argparse.Namespace) -> None:
        global STATE
        STATE = self  # تا پیام‌های داخلی ربات (panel_log) در بافر همین پنل بنشینند
        self.args = args
        self.base = (args.base_url or DEFAULT_BASE_URL).rstrip("/")
        self.tz_name = args.tz or "Asia/Tehran"
        self.tz = None
        if ZoneInfo is not None:
            try:
                self.tz = ZoneInfo(self.tz_name)
            except Exception:  # noqa: BLE001
                panel_log(f"⚠️  منطقه‌ی زمانی «{self.tz_name}» شناخته نشد؛ ساعت محلی سیستم استفاده می‌شود.")
        self.lock = threading.RLock()
        self._logs: list[list] = []
        self._seq = 0
        self.log_limit = max(200, int(os.environ.get("EXIR_PANEL_LOG_LIMIT", "5000")))
        self.status = "idle"
        self.message = "آماده؛ پارامترها را پر کنید و «شروع» را بزنید."
        self.start_ts: float | None = None
        self.plan: dict | None = None
        self.stats: Stats | None = None
        self.stop_evt: threading.Event | None = None
        self.run_thread: threading.Thread | None = None
        self.sync_busy = False
        self.portal: CaptchaPortal | None = None
        self.login_busy = False
        self.login_state = "idle"          # idle | starting | captcha | ok | error
        self.login_message = ""
        self.token: str | None = None
        self.token_desc = "—"
        self.token_exp: float | None = None
        self.started_at = time.time()
        self.refresh_token()

    # ---------------- لاگ ----------------
    def add_log(self, text: str) -> None:
        stamp = datetime.fromtimestamp(time.time(), self.tz).strftime("%H:%M:%S")
        with self.lock:
            for line in (str(text).splitlines() or [""]):
                self._seq += 1
                self._logs.append([self._seq, stamp, line])
            extra = len(self._logs) - self.log_limit
            if extra > 0:
                del self._logs[:extra]

    def clear_log(self) -> None:
        with self.lock:
            self._logs.clear()

    # ---------------- وضعیت ----------------
    def is_running(self) -> bool:
        return self.status in RUNNING_STATES

    def set_status(self, status: str, message: str | None = None) -> None:
        with self.lock:
            self.status = status
            if message is not None:
                self.message = message

    def set_login(self, status: str, message: str = "") -> None:
        with self.lock:
            self.login_state = status
            self.login_message = message

    # ---------------- توکن ----------------
    def refresh_token(self) -> None:
        """توکن را از ``--token`` یا فایل ذخیره می‌خواند (فقط برای نمایش وضعیت)."""
        raw = (getattr(self.args, "token", None) or "").strip()
        if raw:
            token: str | None = clean_token(raw)
        else:
            saved = load_saved_token(Path(self.args.token_file), self.base)
            token = saved.get("token") if saved else None
        with self.lock:
            self.token = token
            self.token_exp = jwt_exp(token) if token else None
            self.token_desc = describe_token(token) if token else "توکن ذخیره‌شده‌ای نیست"

    def forget_token(self) -> bool:
        path = Path(self.args.token_file)
        removed = False
        if path.exists():
            try:
                path.unlink()
                removed = True
            except OSError as e:  # noqa: BLE001
                raise PanelError(f"حذف فایل توکن ممکن نشد: {e}") from e
        with self.lock:
            self.token = None
            self.token_exp = None
            self.token_desc = "توکن ذخیره‌شده‌ای نیست"
        return removed

    # ---------------- اجرا ----------------
    def start_run(self, req: dict) -> None:
        with self.lock:
            if self.is_running():
                raise PanelError("یک اجرا همین حالا در جریان است؛ اول «توقف» را بزنید.")
            self.stats = Stats()
            self.stop_evt = threading.Event()
            self.plan = None
            self.start_ts = None
            self.status = "preparing"
            self.message = "آماده‌سازی درخواست…"
            thread = threading.Thread(target=_worker_run, args=(self, req), name="exir-run", daemon=True)
            self.run_thread = thread
        panel_log("─" * 24)
        panel_log(f"▶️ اجرای جدید: {req['symbol']} | {'فروش' if req['side'] == 'sell' else 'خرید'} "
                  f"{req['quantity']:,} @ {req['price']:,} ریال"
                  + (" | اجرای آزمایشی" if req["dry_run"] else ""))
        thread.start()

    def request_stop(self) -> bool:
        with self.lock:
            evt = self.stop_evt
            running = self.is_running()
            if evt is None or not running:
                return False
            if self.status == "waiting":
                self.status = "stopped"
                self.start_ts = None
                self.message = "لغو شد؛ ارسالی انجام نشد."
        evt.set()
        panel_log("⏹ درخواست توقف ثبت شد.")
        return True

    def start_sync(self) -> None:
        with self.lock:
            if self.sync_busy:
                raise PanelError("همگام‌سازی ساعت همین حالا در جریان است.")
            self.sync_busy = True
        threading.Thread(target=_worker_sync, args=(self,), name="exir-sync", daemon=True).start()

    def start_login(self, username: str, password: str, otp: str = "") -> None:
        if not username.strip() or not password:
            raise PanelError("نام کاربری و رمز عبور را وارد کنید.")
        with self.lock:
            if self.login_busy:
                raise PanelError("یک ورود همین حالا در جریان است.")
            self.login_busy = True
            self.login_state = "starting"
            self.login_message = "شروع ورود…"
        threading.Thread(target=_worker_login, args=(self, username.strip(), password, otp.strip()),
                         name="exir-login", daemon=True).start()

    def shutdown(self) -> None:
        with self.lock:
            evt = self.stop_evt
            portal = self.portal
        if evt is not None:
            evt.set()
        if portal is not None:
            portal.stop()

    # ---------------- snapshot برای مرورگر ----------------
    def snapshot(self, after: int = 0) -> dict:
        now = clock.now()
        with self.lock:
            logs = [entry for entry in self._logs if entry[0] > after]
            cursor = self._logs[-1][0] if self._logs else after
            remaining = None
            if self.start_ts and self.status in ("waiting",):
                remaining = max(0.0, self.start_ts - now)
            stats = None
            if self.stats is not None:
                with self.stats.lock:
                    stats = {
                        "sent": self.stats.sent,
                        "success": self.stats.success,
                        "failed": self.stats.failed,
                        "results": [
                            {"idx": idx, "at": at, "status": status, "desc": desc}
                            for idx, at, status, desc in sorted(self.stats.results)
                        ],
                    }
            portal = self.portal
            return {
                "version": __version__,
                "status": self.status,
                "message": self.message,
                "plan": self.plan,
                "stats": stats,
                "remaining": remaining,
                "start_ts": self.start_ts,
                "logs": logs,
                "cursor": cursor,
                "now": now,
                "server_time": datetime.fromtimestamp(now, self.tz).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "tz": self.tz_name,
                "base": self.base,
                "uptime": round(time.time() - self.started_at),
                "clock": {
                    "source": clock.source,
                    "offset_ms": round(clock.offset * 1000, 1),
                    "accuracy_ms": round(clock.accuracy * 1000, 1) if clock.accuracy is not None else None,
                    "synced_at": clock.synced_at,
                },
                "token": {
                    "present": bool(self.token),
                    "desc": self.token_desc,
                    "exp": self.token_exp,
                },
                "login": {
                    "busy": self.login_busy,
                    "state": self.login_state,
                    "message": self.login_message,
                    "captcha": (portal.base + "/") if portal is not None else None,
                },
                "defaults": {
                    "duration": 10.0,
                    "interval": 305,
                    "side": "buy",
                    "time_sync": _default_time_sync(self.args),
                    "username": getattr(self.args, "username", "") or "",
                },
                "port": getattr(self, "port", 0),
            }


# --------------------------------------------------------------------------- #
#  رشته‌های کاری (worker)
# --------------------------------------------------------------------------- #
def _base_cfg(state: PanelState) -> SimpleNamespace:
    """آرگومان‌های مشترک (base_url، هدرها، توکن، تز) برای توابع exir_bot/exir_auth."""
    args = state.args
    return SimpleNamespace(
        base_url=state.base,
        cookie=getattr(args, "cookie", None),
        app_n=getattr(args, "app_n", None),
        header=list(getattr(args, "header", None) or []),
        auth_mode=getattr(args, "auth_mode", "cookie"),
        token=getattr(args, "token", None),
        token_file=getattr(args, "token_file", ".exir_token.json"),
        captcha_url=getattr(args, "captcha_url", None),
        captcha_file=getattr(args, "captcha_file", "captcha.jpg"),
        username=getattr(args, "username", None),
        timeout=getattr(args, "timeout", 10.0),
        tz=state.tz_name,
    )


def _run_cfg(state: PanelState, req: dict) -> SimpleNamespace:
    cfg = _base_cfg(state)
    cfg.symbol = req["symbol"]
    cfg.quantity = req["quantity"]
    cfg.price = req["price"]
    cfg.time = req["time"]
    cfg.side = req["side"]
    cfg.duration = req["duration"]
    cfg.interval = req["interval"]
    cfg.no_stop = req["no_stop"]
    cfg.dry_run = req["dry_run"]
    cfg.time_sync = req["time_sync"] or _default_time_sync(state.args)
    cfg.ntp_server = getattr(state.args, "ntp_server", None)
    return cfg


def _default_time_sync(args: argparse.Namespace) -> str:
    return getattr(args, "time_sync", None) or "auto"


def _load_token_into(session, cfg: SimpleNamespace, base: str) -> str | None:
    """توکن را از ``--token`` یا فایل ذخیره روی session می‌گذارد (بدون پرسیدن از کاربر)."""
    token: str | None = clean_token(cfg.token) if cfg.token else None
    if not token:
        saved = load_saved_token(Path(cfg.token_file), base)
        if saved:
            token = saved.get("token")
            restore_session_cookies(session, base, saved.get("cookies", []))
            if not session.headers.get("x-app-n") and saved.get("appN"):
                session.headers["x-app-n"] = saved["appN"]
            panel_log(f"🔑 توکن ذخیره‌شده استفاده شد ({describe_token(token)})")
    if token:
        apply_token(session, base, token, cfg.auth_mode)
    return token


def _fire(state: PanelState, cfg: SimpleNamespace, session, base: str, stop_evt: threading.Event,
          stats: Stats) -> None:
    """انتظار تا زمان هدف و ارسال زمان‌بندی‌شده (همان منطق exir_bot.main)."""
    tz = state.tz
    isin = resolve_isin(cfg.symbol, False)          # نماد → ISIN (symbols.json / TSETMC)

    state.set_status("syncing", "همگام‌سازی ساعت…")
    time_sync(cfg.time_sync, session=session, base_url=base,
              ntp_servers=cfg.ntp_server, log=panel_log)
    if stop_evt.is_set():
        raise Stopped()

    if cfg.now_mode:
        target = datetime.fromtimestamp(clock.now(), tz) + timedelta(seconds=3)
    else:
        try:
            target = parse_target_time(cfg.time, tz, allow_tomorrow=False)
        except ValueError as e:
            raise PanelError(str(e)) from None
        if target.timestamp() + cfg.duration < clock.now():
            raise PanelError(f"⏰ زمان {target:%H:%M:%S} گذشته است؛ ساعت درست را وارد کنید "
                             "یا از «شروع فوری» استفاده کنید.")

    interval = cfg.interval / 1000.0
    count = int(cfg.duration / interval + 1e-9) + 1
    start_ts = target.timestamp()
    schedule = [start_ts + k * interval for k in range(count)]
    url = base + ORDER_PATH

    # ---- بدنه‌ی سفارش: پیش‌فرض ربات یا بازپخش «Copy as fetch» ----
    replay = None
    if cfg.body_text:
        snippet = parse_fetch_snippet(cfg.body_text)
        if snippet.get("headers"):
            apply_replay(session, snippet["headers"], panel_log, preserve_session=bool(state.token))
        replay = snippet.get("body")
        if not replay:
            raise PanelError("در بدنه‌ی سفارشی، JSON یا خروجی «Copy as fetch» پیدا نشد.")
        panel_log("🧩 بدنه‌ی سفارش از متنِ داده‌شده بازپخش می‌شود.")
    if replay:
        try:
            body = json.loads(replay)
        except ValueError:
            raise PanelError("بدنه‌ی سفارشی JSON معتبر نیست.") from None
        if not isinstance(body, dict):
            raise PanelError("بدنه‌ی سفارشی باید یک آبجکت JSON باشد.")
        payload = replay.encode("utf-8")
    else:
        body = exir_bot.build_body(cfg, isin)
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")

    plan = {
        "symbol": cfg.symbol,
        "isin": isin,
        "side": cfg.side,
        "quantity": cfg.quantity,
        "price": cfg.price,
        "value": cfg.quantity * cfg.price,
        "start_display": fmt_ms(target),
        "duration": cfg.duration,
        "interval": cfg.interval,
        "count": count,
        "stop_on_success": not cfg.no_stop,
        "dry_run": cfg.dry_run,
        "now_mode": cfg.now_mode,
        "base": base,
        "tz": state.tz_name,
        "clock": clock.source,
        "clock_offset_ms": round(clock.offset * 1000, 1),
        "token": describe_token(state.token) if state.token else "ندارد",
        "body": body,
    }
    with state.lock:
        state.plan = plan

    panel_log("خلاصه‌ی سفارش:")
    panel_log(f"  نماد/ISIN  : {cfg.symbol}  →  {isin}")
    panel_log(f"  نوع        : {'فروش' if cfg.side == 'sell' else 'خرید'}")
    panel_log(f"  تعداد      : {cfg.quantity:,}")
    panel_log(f"  قیمت       : {cfg.price:,} ریال   (ارزش کل ≈ {cfg.quantity * cfg.price:,} ریال)")
    panel_log(f"  شروع       : {plan['start_display']} ({state.tz_name})")
    panel_log(f"  مدت/فاصله  : {cfg.duration:g} ثانیه / {cfg.interval} میلی‌ثانیه  →  {count} درخواست")
    panel_log(f"  توقف پس از موفقیت: {'بله' if not cfg.no_stop else 'خیر'}")
    exp = jwt_exp(state.token) if state.token else None
    if exp and exp < start_ts + cfg.duration and not cfg.dry_run:
        panel_log("⚠️  توکن قبل از پایان زمان ارسال منقضی می‌شود؛ تازه لاگین کنید.")
    panel_log(f"  بدنه       : {json.dumps(body, ensure_ascii=False)}")

    if cfg.dry_run:
        panel_log("[dry-run] هیچ درخواستی ارسال نمی‌شود. هدرها:")
        for key, value in session.headers.items():
            if key.lower() == "authorization":
                value = value[:16] + "…"
            panel_log(f"  {key}: {value}")
        state.set_status("dry-run", "اجرای آزمایشی تمام شد؛ درخواستی ارسال نشد.")
        return

    # ---- انتظار تا زمان شروع ----
    warm_ts = start_ts - 5
    with state.lock:
        state.start_ts = start_ts
    state.set_status("waiting", f"انتظار تا {target:%H:%M:%S}…")
    panel_log(f"⏳ انتظار تا {fmt_ms(target)} …")

    last_note = 0.0
    resynced = False
    while clock.now() < warm_ts:
        if stop_evt.is_set():
            raise Stopped("پیش از شروع لغو شد؛ هیچ درخواستی ارسال نشد.")
        now = time.time()
        remaining = start_ts - clock.now()
        if (not resynced and cfg.time_sync != "off" and remaining <= 45
                and clock.synced_at and now - clock.synced_at > 90):
            resynced = True
            panel_log("🕒 همگام‌سازی دوباره‌ی ساعت پیش از شروع…")
            time_sync(cfg.time_sync, session=session, base_url=base,
                      ntp_servers=cfg.ntp_server, log=panel_log)
            remaining = start_ts - clock.now()
        if (remaining <= 60 and now - last_note >= 5) or now - last_note >= 30:
            last_note = now
            panel_log(f"   باقی‌مانده {int(remaining) // 60:02d}:{int(remaining) % 60:02d} "
                      f"| اکنون {datetime.fromtimestamp(clock.now(), tz):%H:%M:%S}")
        time.sleep(min(0.25, max(0.0, warm_ts - clock.now())))

    if stop_evt.is_set():
        raise Stopped("پیش از شروع لغو شد؛ هیچ درخواستی ارسال نشد.")
    if clock.now() < start_ts - 0.5:
        warmup(session, base, tz)

    with state.lock:
        state.start_ts = None
    state.set_status("firing", f"در حال ارسال {count} درخواست…")
    panel_log(f"🚀 شروع ارسال در {fmt_ms(target)}")
    with ThreadPoolExecutor(max_workers=min(count, 64)) as pool:
        for k, ts in enumerate(schedule, 1):
            if stop_evt.is_set():
                panel_log(f"✅ سفارش موفق؛ {count - k + 1} درخواست باقی‌مانده ارسال نشد.")
                break
            wait_until(ts)
            if stop_evt.is_set():
                panel_log(f"✅ سفارش موفق؛ {count - k + 1} درخواست باقی‌مانده ارسال نشد.")
                break
            with stats.lock:
                stats.sent += 1
            pool.submit(send_order, k, session, url, payload, cfg.timeout, tz,
                        stats, stop_evt, not cfg.no_stop)
        panel_log("… منتظر دریافت پاسخ درخواست‌های در جریان")

    with stats.lock:
        sent, ok, failed = stats.sent, stats.success, stats.failed
    panel_log(f"📊 گزارش نهایی — ارسال‌شده: {sent} | موفق: {ok} | ناموفق: {failed}")
    if stop_evt.is_set() and ok:
        state.set_status("finished", f"سفارش موفق ثبت شد ({ok} پاسخ موفق از {sent} درخواست).")
    elif stop_evt.is_set():
        state.set_status("stopped", "اجرا متوقف شد.")
    else:
        state.set_status("finished", f"پایان اجرا — موفق: {ok} | ناموفق: {failed}")


def _worker_run(state: PanelState, req: dict) -> None:
    base = state.base
    my_evt: threading.Event | None = None
    stats = state.stats
    try:
        cfg = _run_cfg(state, req)
        cfg.now_mode = req["now"]
        cfg.body_text = req["body"]
        assert stats is not None and state.stop_evt is not None
        my_evt = state.stop_evt

        session = build_session(cfg, 64)
        token = _load_token_into(session, cfg, base)
        state.refresh_token()
        if not token and not cfg.dry_run:
            raise PanelError("توکن معتبری موجود نیست؛ از بخش «ورود / توکن» لاگین کنید.")
        if token and not cfg.dry_run:
            exp = jwt_exp(token)
            if exp and exp < clock.now():
                raise PanelError("توکن ذخیره‌شده منقضی شده است؛ دوباره لاگین کنید.")
        _fire(state, cfg, session, base, my_evt, stats)
    except Stopped as e:
        state.set_status("stopped", str(e) or "اجرا متوقف شد.")
        panel_log(f"⏹ {e}")
    except PanelError as e:
        panel_log(f"✘ {e}")
        state.set_status("error", str(e))
    except SystemExit:  # resolve_isin برای نماد نامعتبر sys.exit می‌کند
        msg = "کد ISIN نماد پیدا نشد؛ مستقیماً ISIN بدهید یا symbols.json را کامل کنید."
        panel_log(f"✘ {msg}")
        state.set_status("error", msg)
    except Exception as e:  # noqa: BLE001
        panel_log(f"✘ خطای غیرمنتظره: {e!r}")
        state.set_status("error", f"خطا: {e}")
    finally:
        with state.lock:
            state.start_ts = None
            if state.stop_evt is my_evt:
                state.stop_evt = None
        if state.status in RUNNING_STATES:  # هر مسیر خروجی نامشخص
            state.set_status("idle", "اجرا تمام شد.")


def _worker_sync(state: PanelState) -> None:
    try:
        cfg = _base_cfg(state)
        session = build_session(cfg, 8)
        panel_log("🔄 همگام‌سازی دستی ساعت…")
        ok = time_sync(_default_time_sync(state.args), session=session, base_url=state.base,
                       ntp_servers=getattr(state.args, "ntp_server", None), log=panel_log)
        if not ok:
            panel_log("⚠️  همگام‌سازی ناموفق بود؛ از ساعت سیستم استفاده می‌شود.")
    except Exception as e:  # noqa: BLE001
        panel_log(f"✘ همگام‌سازی ساعت: {e}")
    finally:
        with state.lock:
            state.sync_busy = False


def _stop_portal_later(portal: CaptchaPortal, state: PanelState, delay: float) -> None:
    """چند ثانیه صفحه‌ی کپچا را باز نگه می‌دارد تا کاربر نتیجه را ببیند."""

    def _run() -> None:
        time.sleep(delay)
        try:
            portal.stop()
        finally:
            with state.lock:
                if state.portal is portal:
                    state.portal = None

    threading.Thread(target=_run, name="captcha-portal-stop", daemon=True).start()


def _worker_login(state: PanelState, username: str, password: str, otp: str) -> None:
    base = state.base
    portal: CaptchaPortal | None = None
    success = False
    try:
        cfg = _base_cfg(state)
        session = build_session(cfg, 8)
        portal = CaptchaPortal(log=panel_log, host="127.0.0.1", port=0, ttl=CAPTCHA_TTL)
        if portal.start():
            with state.lock:
                state.portal = portal
            panel_log("🌐 صفحه‌ی کپچا در همین پنل باز شد؛ کد تصویر را همان‌جا بفرستید.")
        else:
            portal = None
            panel_log("⚠️  وب‌سرور کپچا بالا نیامد؛ کد را در ترمینال سرور وارد کنید.")

        state.set_login("captcha" if portal is not None else "starting",
                        "منتظر کد کپچا…" if portal is not None else "منتظر ورودی ترمینال…")
        data = login(session, base, username, password, captcha_url=cfg.captcha_url, otp=otp or None,
                     captcha_path=Path(cfg.captcha_file), log=panel_log, portal=portal,
                     app_n=cfg.app_n)
        token = data["authToken"]
        app_n = data.get("_appN")
        name = f"{data.get('firstName', '')} {data.get('lastName', '')}".strip()
        save_token(Path(cfg.token_file), base, token,
                   {"name": name, "sendOrderDelay": data.get("sendOrderDelay"), "appN": app_n,
                    "cookies": session_cookies(session, base)})
        with state.lock:
            state.token = token
            state.token_exp = jwt_exp(token)
            state.token_desc = describe_token(token)
        success = True
        panel_log(f"✔ ورود موفق{(' — ' + name) if name else ''} ({describe_token(token)})")
        if data.get("sendOrderDelay"):
            panel_log(f"ℹ️  sendOrderDelay کارگزار: {data['sendOrderDelay']}ms")
        panel_log(f"💾 توکن در {cfg.token_file} ذخیره شد.")
        state.set_login("ok", f"ورود موفق{(' — ' + name) if name else ''}؛ توکن ذخیره شد.")
    except Exception as e:  # noqa: BLE001
        state.set_login("error", f"ورود ناموفق: {e}")
        panel_log(f"✘ ورود ناموفق: {e}")
    finally:
        with state.lock:
            state.login_busy = False
        if portal is not None:
            _stop_portal_later(portal, state, 60 if success else 25)


# --------------------------------------------------------------------------- #
#  پروکسی صفحه‌ی کپچا (تا همه‌چیز روی یک پورت باشد)
# --------------------------------------------------------------------------- #
_HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                "te", "trailer", "transfer-encoding", "upgrade", "content-length"}


def proxy_captcha(portal, method: str, path: str, body: bytes | None,
                  content_type: str | None, timeout: float = 20.0):
    """درخواست را به وب‌سرور داخلی کپچا (127.0.0.1) می‌فرستد: ``(status, headers, body)``."""
    conn = http.client.HTTPConnection("127.0.0.1", int(portal.port), timeout=timeout)
    try:
        headers = {"Connection": "close"}
        if content_type:
            headers["Content-Type"] = content_type
        if body:
            headers["Content-Length"] = str(len(body))
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        head = [(k, v) for k, v in resp.getheaders() if k.lower() not in _HOP_HEADERS]
        return resp.status, head, data
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
#  وب‌سرور پنل
# --------------------------------------------------------------------------- #
def panel_handler(state: PanelState):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ExirPanel/" + __version__
        protocol_version = "HTTP/1.1"

        def log_message(self, *args) -> None:  # بی‌صدا (لاگ خودمان را داریم)
            pass

        # ---------- کمکی ----------
        def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, obj, code: int = 200) -> None:
            self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _html(self, text: str, code: int = 200) -> None:
            self._send(code, text.encode("utf-8"), "text/html; charset=utf-8")

        def _not_found(self) -> None:
            self._html("<h3>۴۰۴</h3><p>آدرس درست نیست.</p>", 404)

        def _read_body(self) -> bytes:
            """بدنه‌ی درخواست را یک‌بار می‌خواند (کش می‌شود تا اتصال keep-alive سالم بماند)."""
            cached = getattr(self, "_body_cache", None)
            if cached is not None:
                return cached
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            data = self.rfile.read(min(length, 4 * 1024 * 1024)) if length > 0 else b""
            self._body_cache = data
            return data

        def _read_json(self) -> dict:
            raw = self._read_body()
            if not raw:
                return {}
            try:
                data = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                raise PanelError("بدنه‌ی درخواست JSON معتبر نیست.") from None
            if not isinstance(data, dict):
                raise PanelError("بدنه‌ی درخواست باید آبجکت JSON باشد.")
            return data

        # ---------- مسیرها ----------
        def do_GET(self) -> None:  # noqa: N802
            self._route("GET")

        def do_HEAD(self) -> None:  # noqa: N802
            self._route("HEAD")

        def do_POST(self) -> None:  # noqa: N802
            self._route("POST")

        def _route(self, method: str) -> None:
            self._body_cache = None  # هر درخواست روی همان اتصال، بدنه‌ی خودش را دارد
            self._read_body()  # تخلیه‌ی بدنه تا اتصال keep-alive برای درخواست بعدی خراب نشود
            parsed = urlparse(self.path)
            path = parsed.path
            query = parse_qs(parsed.query)
            portal = state.portal

            # صفحه‌ی کپچا روی همان دامنه/پورت پنل پروکسی می‌شود
            if portal is not None and (path.rstrip("/") == portal.base or path.startswith(portal.base + "/")):
                return self._proxy_captcha(portal, method, parsed)

            if path in ("/", "/index.html"):
                return self._html(PAGE.replace("__PORT__", str(getattr(state, "port", 0))))
            if path == "/favicon.ico":
                return self._send(200, b"", "image/x-icon")
            if path == "/api/state":
                try:
                    after = int((query.get("after") or ["0"])[0] or 0)
                except ValueError:
                    after = 0
                return self._json(state.snapshot(after))
            if path == "/api/symbols":
                return self._json(_symbols())
            if path == "/api/health":
                return self._json({"ok": True, "version": __version__, "status": state.status})

            if method != "POST":
                return self._not_found()
            try:
                if path == "/api/start":
                    self._api_start()
                elif path == "/api/stop":
                    self._json({"ok": True, "stopped": state.request_stop(), "status": state.status})
                elif path == "/api/sync":
                    state.start_sync()
                    self._json({"ok": True, "message": "همگام‌سازی ساعت شروع شد."})
                elif path == "/api/login":
                    data = self._read_json()
                    state.start_login(str(data.get("username") or ""), str(data.get("password") or ""),
                                      str(data.get("otp") or ""))
                    self._json({"ok": True, "message": "ورود آغاز شد."})
                elif path == "/api/forget-token":
                    removed = state.forget_token()
                    panel_log("🗑 توکن ذخیره‌شده پاک شد." if removed else "ℹ️  فایل توکنی برای پاک‌کردن نبود.")
                    self._json({"ok": True, "removed": removed})
                elif path == "/api/clear-log":
                    state.clear_log()
                    self._json({"ok": True})
                else:
                    self._not_found()
            except PanelError as e:
                self._json({"error": str(e)}, 400)
            except Exception as e:  # noqa: BLE001
                panel_log(f"✘ خطا در پردازش {path}: {e!r}")
                self._json({"error": f"خطای سرور: {e}"}, 500)

        def _api_start(self) -> None:
            data = self._read_json()
            try:
                req = validate_run_request(data)
            except ValueError as e:
                return self._json({"error": str(e)}, 400)
            try:
                state.start_run(req)
            except PanelError as e:
                return self._json({"error": str(e)}, 409)
            return self._json({"ok": True, "status": state.status})

        # ---------- پروکسی ----------
        def _proxy_captcha(self, portal, method: str, parsed) -> None:
            body = self._read_body() if method in ("POST", "PUT") else None
            path = parsed.path + (("?" + parsed.query) if parsed.query else "")
            try:
                code, head, data = proxy_captcha(portal, method, path, body,
                                                 self.headers.get("Content-Type"))
            except Exception as e:  # noqa: BLE001
                return self._html(f"<h3>صفحه‌ی کپچا در دسترس نیست</h3><p>{html_mod.escape(str(e))}</p>", 502)
            self.send_response(code)
            for key, value in head:
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if method != "HEAD":
                self.wfile.write(data)

    return Handler


def _symbols() -> dict:
    """نمادهای محلی (symbols.json) برای پیشنهاد در فرم."""
    path = Path(exir_bot.SYMBOLS_FILE)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k): str(v) for k, v in data.items()}


# --------------------------------------------------------------------------- #
#  صفحه‌ی پنل (HTML/CSS/JS تک‌فایلی، بدون وابستگی بیرونی)
# --------------------------------------------------------------------------- #
PAGE = r"""<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>پنل ربات سفارش اکسیر</title>
<style>
  :root{
    --bg:#0e1116; --card:#161b22; --card2:#1c2230; --line:#262d3a; --fg:#e6edf3;
    --dim:#8b949e; --ok:#2ea043; --err:#da3633; --warn:#d29922; --run:#1f6feb; --acc:#8957e5;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--fg);font-family:Vazirmatn,Tahoma,"Segoe UI",system-ui,sans-serif;font-size:14px}
  a{color:#58a6ff}
  header{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;
         padding:14px 18px;border-bottom:1px solid var(--line);background:#12161d;position:sticky;top:0;z-index:5}
  h1{font-size:17px;margin:0}
  .chips{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
  .chip{background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:4px 10px;color:var(--dim);font-size:12px}
  .pill{background:var(--card2);border:1px solid var(--line);border-radius:999px;padding:4px 12px;font-size:12px}
  .pill.idle{color:var(--dim)}
  .pill.preparing,.pill.syncing,.pill.waiting{color:var(--warn);border-color:#4a3a12}
  .pill.firing{color:#79c0ff;border-color:#123a6b;background:#0d2547}
  .pill.finished{color:#7ee787;border-color:#1c4526;background:#0f2a17}
  .pill.error{color:#ff7b72;border-color:#5c1d1a;background:#2d1211}
  .pill.stopped,.pill.dry-run{color:var(--acc);border-color:#3a2a5c}
  main{display:grid;grid-template-columns:repeat(auto-fit,minmax(360px,1fr));gap:14px;padding:14px;max-width:1500px;margin:0 auto}
  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}
  .card h2{font-size:14px;margin:0 0 12px;color:#c9d1d9}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
  label{display:flex;flex-direction:column;gap:5px;color:var(--dim);font-size:12px}
  input,select,textarea,button{font-family:inherit;font-size:13px}
  input,select,textarea{background:#0d1117;border:1px solid var(--line);color:var(--fg);border-radius:8px;padding:8px 10px;width:100%}
  input:focus,select:focus,textarea:focus{outline:1px solid #388bfd;border-color:#388bfd}
  textarea{min-height:64px;resize:vertical;font-family:ui-monospace,Menlo,Consolas,monospace;direction:ltr;text-align:left}
  .check{flex-direction:row;align-items:center;gap:8px;color:var(--fg);font-size:13px}
  .check input{width:auto}
  button{background:var(--card2);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:9px 14px;cursor:pointer}
  button:hover:not(:disabled){border-color:#3d4756;background:#222a38}
  button:disabled{opacity:.45;cursor:not-allowed}
  button.primary{background:#1f6feb;border-color:#1f6feb;color:#fff}
  button.primary:hover:not(:disabled){background:#388bfd}
  button.ok{background:#238636;border-color:#238636;color:#fff}
  button.danger{background:#2d1211;border-color:#5c1d1a;color:#ff7b72}
  .btns{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
  .kv{display:grid;grid-template-columns:auto 1fr;gap:6px 12px;font-size:13px}
  .kv .k{color:var(--dim)}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace;direction:ltr;text-align:left}
  table{width:100%;border-collapse:collapse;font-size:12px}
  th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:right}
  th{color:var(--dim);font-weight:500}
  td.num{white-space:nowrap}
  .st-ok{color:#7ee787}.st-err{color:#ff7b72}.st-none{color:var(--warn)}
  #console{background:#0a0d12;border:1px solid var(--line);border-radius:8px;padding:10px;
           max-height:340px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;
           line-height:1.7;direction:ltr;text-align:left;white-space:pre-wrap;margin:0}
  #console .t{color:#6e7681;margin-right:8px}
  #console .ln{border-bottom:1px solid #12161d;display:block;padding:1px 0}
  iframe{width:100%;height:340px;border:1px solid var(--line);border-radius:8px;background:#fff}
  .msg{margin-top:10px;padding:8px 10px;border-radius:8px;font-size:13px;display:none}
  .msg.show{display:block}
  .msg.err{background:#2d1211;border:1px solid #5c1d1a;color:#ff7b72}
  .msg.info{background:#0d2547;border:1px solid #123a6b;color:#79c0ff}
  .hint{color:var(--dim);font-size:12px;margin-top:8px;line-height:1.9}
  .countdown{font-size:20px;font-weight:600;color:#79c0ff}
  .wide{grid-column:1/-1}
  code{background:#0d1117;border:1px solid var(--line);border-radius:5px;padding:1px 5px;direction:ltr;display:inline-block}
</style>
</head>
<body>
<header>
  <h1>⚡ پنل ربات سفارش زمان‌دار اکسیر</h1>
  <div class="chips">
    <span id="pill" class="pill idle">آماده</span>
    <span class="chip" id="clockChip">ساعت: —</span>
    <span class="chip" id="tokenChip">توکن: —</span>
    <span class="chip" id="baseChip">—</span>
  </div>
</header>

<main>
  <!-- ۱) سفارش -->
  <section class="card">
    <h2>۱) مشخصات سفارش</h2>
    <div class="grid">
      <label>نماد / نام / ISIN
        <input id="symbol" list="symbolList" placeholder="وتوصا یا IRO7TONP0001">
        <datalist id="symbolList"></datalist>
      </label>
      <label>تعداد
        <input id="quantity" type="number" min="1" step="1" value="10">
      </label>
      <label>قیمت (ریال)
        <input id="price" type="number" min="1" step="1" value="6700">
      </label>
      <label>نوع
        <select id="side"><option value="buy">خرید</option><option value="sell">فروش</option></select>
      </label>
      <label>ساعت شروع (HH:MM:SS.mmm)
        <input id="time" class="mono" placeholder="08:44:59.700">
      </label>
      <label>مدت ارسال (ثانیه)
        <input id="duration" type="number" min="0" step="0.5" value="10">
      </label>
      <label>فاصله‌ی درخواست‌ها (میلی‌ثانیه)
        <input id="interval" type="number" min="1" step="5" value="305">
      </label>
      <label>همگام‌سازی ساعت
        <select id="timeSync">
          <option value="auto">auto (NTP، بعد سرور کارگزاری)</option>
          <option value="ntp">ntp</option>
          <option value="server">سرور کارگزاری</option>
          <option value="off">خاموش</option>
        </select>
      </label>
    </div>
    <div class="btns">
      <label class="check"><input type="checkbox" id="stopOnSuccess" checked> توقف پس از اولین موفقیت</label>
      <label class="check"><input type="checkbox" id="dryRun"> اجرای آزمایشی (بدون ارسال)</label>
    </div>
    <div class="btns">
      <button id="btnStart" class="primary">⏱ زمان‌بندی و شروع</button>
      <button id="btnNow" class="ok">⚡ شروع فوری (۳ ثانیه بعد)</button>
      <button id="btnStop" class="danger" disabled>⏹ توقف</button>
      <button id="btnSync">🔄 همگام‌سازی ساعت</button>
    </div>
    <div id="startMsg" class="msg"></div>
    <details style="margin-top:10px">
      <summary style="color:var(--dim);cursor:pointer;font-size:12px">بدنه‌ی سفارشی (Copy as fetch / JSON) — اختیاری</summary>
      <textarea id="body" placeholder='{"insMaxLcode":"IRO7TONP0001","quantity":10,...} یا خروجی Copy as fetch'></textarea>
      <div class="hint">اگر پر شود، عیناً همین بدنه فرستاده می‌شود (هدرهای نمونه‌ی مرورگر هم اعمال می‌شوند).</div>
    </details>
  </section>

  <!-- ۲) لاگین -->
  <section class="card">
    <h2>۲) ورود / توکن</h2>
    <div class="grid">
      <label>نام کاربری<input id="username" autocomplete="username"></label>
      <label>رمز عبور<input id="password" type="password" autocomplete="current-password"></label>
      <label>کد یکبار مصرف (OTP)<input id="otp" inputmode="numeric"></label>
    </div>
    <div class="btns">
      <button id="btnLogin" class="primary">🔐 ورود و ذخیره‌ی توکن</button>
      <button id="btnForget">🗑 پاک‌کردن توکن ذخیره‌شده</button>
    </div>
    <div id="loginMsg" class="msg"></div>
    <div id="captchaBox" style="display:none;margin-top:12px">
      <div class="hint">کد تصویر زیر را در همان صفحه وارد کنید و «ارسال» را بزنید:</div>
      <iframe id="captchaFrame" src="about:blank" title="کپچا"></iframe>
      <div class="btns"><a id="captchaLink" href="#" target="_blank" rel="noopener"><button>↗ باز کردن در تب جدید</button></a></div>
    </div>
    <div class="hint">
      تصویر کپچا با نشست همین سرور گرفته می‌شود (نه مرورگر شما) و از پنل نمایش داده می‌شود؛
      توکن در <code>.exir_token.json</code> ذخیره و تا زمان انقضا استفاده می‌شود.
    </div>
  </section>

  <!-- ۳) وضعیت -->
  <section class="card">
    <h2>۳) وضعیت اجرا</h2>
    <div id="countdown" class="countdown" style="display:none"></div>
    <div id="plan" class="kv"><div class="k">—</div><div>هنوز اجرایی شروع نشده است.</div></div>
  </section>

  <!-- ۴) پاسخ‌ها -->
  <section class="card">
    <h2>۴) پاسخ درخواست‌ها <span id="statLine" class="hint" style="margin:0"></span></h2>
    <div style="max-height:300px;overflow:auto">
      <table>
        <thead><tr><th>#</th><th>ارسال</th><th>HTTP</th><th>توضیح</th></tr></thead>
        <tbody id="results"><tr><td colspan="4" style="color:var(--dim)">—</td></tr></tbody>
      </table>
    </div>
  </section>

  <!-- ۵) لاگ -->
  <section class="card wide">
    <h2>۵) لاگ زنده <button id="btnClear" style="float:left;padding:4px 10px;font-size:12px">پاک‌کردن</button></h2>
    <pre id="console"></pre>
    <div class="hint">
      این پنل روی همان سروری اجرا می‌شود که ربات را می‌فرستد؛ اگر از راه دور وصل می‌شوید پورت را تونل کنید:
      <code>ssh -L __PORT__:127.0.0.1:__PORT__ user@server</code>
    </div>
  </section>
</main>

<script>
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var cursor = 0, localStamp = Date.now(), serverNow = 0, startTs = null, pollTimer = null;
  var CAPTCHA_PATH = null;

  function fmt(n) { return (n === null || n === undefined) ? "—" : Number(n).toLocaleString("fa-IR"); }
  function esc(s) { var d = document.createElement("div"); d.textContent = (s === null || s === undefined) ? "" : String(s); return d.innerHTML; }

  function show(box, text, kind) {
    var el = $(box);
    el.textContent = text;
    el.className = "msg show " + (kind || "info");
  }
  function hide(box) { $(box).className = "msg"; }

  function payload(nowMode) {
    return {
      symbol: $("symbol").value.trim(),
      quantity: $("quantity").value,
      price: $("price").value,
      time: $("time").value.trim(),
      side: $("side").value,
      duration: $("duration").value,
      interval: $("interval").value,
      time_sync: $("timeSync").value,
      no_stop: !$("stopOnSuccess").checked,
      dry_run: $("dryRun").checked,
      now: !!nowMode,
      body: $("body").value.trim()
    };
  }

  function post(path, data) {
    return fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data || {})
    }).then(function (r) { return r.json().catch(function () { return {}; }).then(function (j) {
      if (!r.ok) { throw new Error(j.error || ("HTTP " + r.status)); }
      return j;
    }); });
  }

  function saveForm() {
    try {
      var keys = ["symbol", "quantity", "price", "time", "side", "duration", "interval", "timeSync", "body"];
      var obj = {};
      keys.forEach(function (k) { obj[k] = $(k).value; });
      obj.stopOnSuccess = $("stopOnSuccess").checked;
      localStorage.setItem("exirPanelForm", JSON.stringify(obj));
    } catch (e) {}
  }
  function loadForm() {
    try {
      var obj = JSON.parse(localStorage.getItem("exirPanelForm") || "null");
      if (!obj) { return; }
      Object.keys(obj).forEach(function (k) {
        if (k === "stopOnSuccess") { $("stopOnSuccess").checked = !!obj[k]; }
        else if ($(k)) { $(k).value = obj[k]; }
      });
    } catch (e) {}
  }

  function setBusy(running) {
    $("btnStart").disabled = running;
    $("btnNow").disabled = running;
    $("btnStop").disabled = !running;
    $("btnLogin").disabled = running;
  }

  function renderPlan(s) {
    var box = $("plan");
    var p = s.plan;
    if (!p) {
      box.innerHTML = '<div class="k">وضعیت</div><div>' + esc(s.message) + '</div>';
      return;
    }
    var rows = [
      ["نماد / ISIN", esc(p.symbol) + " → " + '<span class="mono">' + esc(p.isin) + "</span>"],
      ["نوع", p.side === "sell" ? "فروش" : "خرید"],
      ["تعداد × قیمت", fmt(p.quantity) + " × " + fmt(p.price) + " ریال"],
      ["ارزش کل", fmt(p.value) + " ریال"],
      ["شروع", '<span class="mono">' + esc(p.start_display) + "</span> (" + esc(p.tz) + ")"],
      ["مدت / فاصله", p.duration + " ثانیه / " + p.interval + "ms"],
      ["تعداد درخواست", fmt(p.count)],
      ["توقف پس از موفقیت", p.stop_on_success ? "بله" : "خیر"],
      ["اجرای آزمایشی", p.dry_run ? "بله (چیزی ارسال نمی‌شود)" : "خیر"],
      ["ساعت مرجع", esc(p.clock) + " (" + (p.clock_offset_ms >= 0 ? "+" : "") + p.clock_offset_ms + "ms)"],
      ["توکن", esc(p.token)]
    ];
    box.innerHTML = rows.map(function (r) {
      return '<div class="k">' + r[0] + "</div><div>" + r[1] + "</div>";
    }).join("");
  }

  function renderResults(s) {
    var body = $("results");
    var st = s.stats;
    if (!st || !st.results.length) {
      $("statLine").textContent = st ? ("ارسال‌شده " + fmt(st.sent) + " | موفق " + fmt(st.success) + " | ناموفق " + fmt(st.failed)) : "";
      if (!st || !st.sent) { body.innerHTML = '<tr><td colspan="4" style="color:var(--dim)">—</td></tr>'; }
      return;
    }
    $("statLine").textContent = "ارسال‌شده " + fmt(st.sent) + " | موفق " + fmt(st.success) + " | ناموفق " + fmt(st.failed);
    body.innerHTML = st.results.map(function (r) {
      var cls = r.status === null ? "st-none" : (r.status >= 200 && r.status < 300 ? "st-ok" : "st-err");
      return "<tr><td>" + r.idx + '</td><td class="mono">' + esc(r.at) + '</td><td class="' + cls + '">' +
             (r.status === null ? "خطای شبکه" : r.status) + "</td><td>" + esc(r.desc) + "</td></tr>";
    }).join("");
  }

  function renderLogs(s) {
    var box = $("console");
    var stick = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
    (s.logs || []).forEach(function (entry) {
      var span = document.createElement("span");
      span.className = "ln";
      span.innerHTML = '<span class="t">' + esc(entry[1]) + "</span>" + esc(entry[2]);
      box.appendChild(span);
    });
    if ((s.logs || []).length && stick) { box.scrollTop = box.scrollHeight; }
  }

  function renderCaptcha(s) {
    var login = s.login || {};
    var want = login.captcha;
    if (want) {
      if (CAPTCHA_PATH !== want) {
        CAPTCHA_PATH = want;
        $("captchaFrame").src = want;
        $("captchaLink").href = want;
        $("captchaBox").style.display = "block";
      }
    } else if (CAPTCHA_PATH) {
      CAPTCHA_PATH = null;
      $("captchaFrame").src = "about:blank";
      $("captchaBox").style.display = "none";
    }
    if (login.message) {
      var kind = login.state === "error" ? "err" : (login.state === "ok" ? "info" : "info");
      show("loginMsg", login.message, kind);
    }
  }

  function renderClock(s) {
    var c = s.clock || {};
    var acc = c.accuracy_ms === null || c.accuracy_ms === undefined ? "" : (" ±" + c.accuracy_ms + "ms");
    $("clockChip").textContent = "ساعت: " + s.server_time + " | " + (c.source || "—") + acc;
    $("tokenChip").textContent = "توکن: " + ((s.token && s.token.present) ? s.token.desc : "ندارد");
    $("baseChip").textContent = s.base || "";
  }

  function tickCountdown() {
    if (!startTs) { $("countdown").style.display = "none"; return; }
    var left = startTs - (serverNow + (Date.now() - localStamp) / 1000);
    if (left < -2) { $("countdown").style.display = "none"; return; }
    var t = Math.max(0, left);
    var mm = String(Math.floor(t / 60)).padStart(2, "0");
    var ss = String(Math.floor(t % 60)).padStart(2, "0");
    $("countdown").style.display = "block";
    $("countdown").textContent = "⏳ باقی‌مانده تا شروع: " + mm + ":" + ss;
  }

  var firstApply = true;
  function apply(s) {
    cursor = s.cursor;
    if (firstApply) {
      firstApply = false;
      var def = (s.defaults || {});
      if (!$("username").value && def.username) { $("username").value = def.username; }
    }
    serverNow = s.now;
    localStamp = Date.now();
    startTs = s.status === "waiting" ? s.start_ts : null;
    var pill = $("pill");
    pill.className = "pill " + s.status;
    pill.textContent = s.message || s.status;
    setBusy(s.status === "preparing" || s.status === "syncing" || s.status === "waiting" || s.status === "firing");
    renderClock(s);
    renderPlan(s);
    renderResults(s);
    renderLogs(s);
    renderCaptcha(s);
    tickCountdown();
  }

  function poll() {
    fetch("api/state?after=" + cursor, { cache: "no-store" })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        apply(s);
        var fast = ["preparing", "syncing", "waiting", "firing", "idle"].indexOf(s.status) >= 0;
        var delay = (s.status === "waiting" || s.status === "firing") ? 350 : 800;
        pollTimer = setTimeout(poll, delay);
      })
      .catch(function () { pollTimer = setTimeout(poll, 1500); });
  }

  function onStart(nowMode) {
    hide("startMsg");
    post("api/start", payload(nowMode))
      .then(function () { show("startMsg", nowMode ? "شروع فوری ثبت شد." : "زمان‌بندی ثبت شد؛ منتظر بمانید.", "info"); })
      .catch(function (e) { show("startMsg", "✘ " + e.message, "err"); });
  }

  $("btnStart").addEventListener("click", function () { saveForm(); onStart(false); });
  $("btnNow").addEventListener("click", function () { saveForm(); onStart(true); });
  $("btnStop").addEventListener("click", function () {
    post("api/stop").then(function (r) { show("startMsg", r.stopped ? "درخواست توقف فرستاده شد." : "اجرایی در جریان نیست.", "info"); })
      .catch(function (e) { show("startMsg", "✘ " + e.message, "err"); });
  });
  $("btnSync").addEventListener("click", function () {
    post("api/sync").then(function () { show("startMsg", "همگام‌سازی ساعت آغاز شد…", "info"); })
      .catch(function (e) { show("startMsg", "✘ " + e.message, "err"); });
  });
  $("btnLogin").addEventListener("click", function () {
    hide("loginMsg");
    post("api/login", { username: $("username").value.trim(), password: $("password").value, otp: $("otp").value.trim() })
      .then(function () { show("loginMsg", "ورود آغاز شد؛ کد کپچا را در کادر پایین بفرستید.", "info"); })
      .catch(function (e) { show("loginMsg", "✘ " + e.message, "err"); });
  });
  $("btnForget").addEventListener("click", function () {
    if (!confirm("فایل توکن ذخیره‌شده پاک شود؟")) { return; }
    post("api/forget-token").then(function (r) { show("loginMsg", r.removed ? "توکن پاک شد." : "فایلی برای پاک‌کردن نبود.", "info"); })
      .catch(function (e) { show("loginMsg", "✘ " + e.message, "err"); });
  });
  $("btnClear").addEventListener("click", function () { post("api/clear-log").then(function () { $("console").innerHTML = ""; }); });
  ["symbol", "quantity", "price", "time", "side", "duration", "interval", "timeSync", "body"].forEach(function (k) {
    $(k).addEventListener("change", saveForm);
  });

  loadForm();
  $("interval").value = $("interval").value || "305";
  fetch("api/symbols").then(function (r) { return r.json(); }).then(function (map) {
    var dl = $("symbolList");
    Object.keys(map || {}).forEach(function (name) {
      var opt = document.createElement("option");
      opt.value = name;
      opt.label = map[name];
      dl.appendChild(opt);
    });
  }).catch(function () {});
  poll();
})();
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #
def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="وب‌پنل ربات سفارش زمان‌دار اکسیر (فرم سفارش + لاگین/کپچا + لاگ زنده)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--host", default=os.environ.get("EXIR_PANEL_HOST", "0.0.0.0"),
                   help="آدرس بایند وب‌سرور پنل (127.0.0.1 = فقط خود سرور)")
    p.add_argument("--port", type=int, default=int(os.environ.get("EXIR_PANEL_PORT", "8000")),
                   help="پورت وب‌سرور پنل (0 = پورت آزاد تصادفی)")
    p.add_argument("--base-url", default=os.environ.get("EXIR_BASE_URL", DEFAULT_BASE_URL),
                   help="آدرس کارگزاری")
    g = p.add_argument_group("توکن و هدرها")
    g.add_argument("--token", default=os.environ.get("EXIR_TOKEN"),
                   help="توکن JWT آماده (به‌جای لاگین)")
    g.add_argument("--token-file", default=os.environ.get("EXIR_TOKEN_FILE", ".exir_token.json"),
                   help="فایل ذخیره‌ی توکن/کوکی‌ها")
    g.add_argument("--cookie", default=os.environ.get("EXIR_COOKIE"),
                   help="کوکی‌های نشست مرورگر: 'a=1; b=2'")
    g.add_argument("--app-n", default=os.environ.get("EXIR_APP_N"),
                   help="مقدار هدر x-app-n (برای ورود و سفارش یکسان می‌شود)")
    g.add_argument("-H", "--header", action="append", default=[],
                   help="هدر دلخواه 'Name: value' (چند بار مجاز)")
    g.add_argument("--auth-mode", choices=["cookie", "bearer", "both"], default="cookie",
                   help="توکن به‌صورت کوکی JWT-TOKEN یا هدر Authorization")
    g.add_argument("--username", default=os.environ.get("EXIR_USERNAME"),
                   help="نام کاربری پیش‌فرض فرم ورود")
    p.add_argument("--captcha-url", default=os.environ.get("EXIR_CAPTCHA_URL", "/captcha"),
                   help="مسیر تصویر کپچا")
    p.add_argument("--captcha-file", default="captcha.jpg",
                   help="مسیر ذخیره‌ی تصویر کپچا روی سرور")
    p.add_argument("--tz", default=os.environ.get("EXIR_TZ", "Asia/Tehran"), help="منطقه‌ی زمانی")
    p.add_argument("--time-sync", choices=["auto", "ntp", "server", "off"],
                   default=os.environ.get("EXIR_TIME_SYNC", "auto"), help="روش همگام‌سازی ساعت")
    p.add_argument("--ntp-server", action="append",
                   help="سرور NTP دلخواه (چند بار مجاز)")
    p.add_argument("--timeout", type=float, default=10.0, help="timeout هر درخواست سفارش (ثانیه)")
    return p.parse_args(argv)


def _banner(state: PanelState, args: argparse.Namespace) -> None:
    hosts = ["127.0.0.1"]
    if args.host in ("0.0.0.0", "::", ""):
        ip = local_ip()
        if ip:
            hosts.append(ip)
    else:
        hosts = [args.host]
    key = state.base
    saved = load_saved_token(Path(args.token_file), key)
    panel_log("═" * 52)
    panel_log("  ⚡ وب‌پنل ربات سفارش اکسیر")
    panel_log(f"  کارگزاری : {state.base}   |   منطقه‌ی زمانی: {state.tz_name}")
    panel_log(f"  توکن     : {describe_token(state.token) if state.token else 'ذخیره نشده (از پنل لاگین کنید)'}")
    if saved and saved.get("name"):
        panel_log(f"  حساب     : {saved['name']}")
    panel_log("  آدرس پنل در مرورگر (یکی از این‌ها):")
    for host in hosts:
        panel_log(f"    http://{host}:{state.port}/")
    panel_log(f"  اگر سرور از راه دور است:  ssh -L {state.port}:127.0.0.1:{state.port} user@server")
    if args.host in ("0.0.0.0", "::", ""):
        panel_log("  ⚠️  پنل روی همه‌ی کارت‌های شبکه باز است و می‌تواند سفارش واقعی بفرستد؛")
        panel_log("      اگر لازم نیست، با --host 127.0.0.1 فقط روی خود سرور بایند کنید.")
    panel_log("═" * 52)


def main(argv=None) -> int:
    global STATE
    args = parse_args(argv)
    state = PanelState(args)
    STATE = state
    try:
        server = ThreadingHTTPServer((args.host, args.port), panel_handler(state))
    except OSError as e:
        panel_log(f"✘ بالا آوردن پنل روی {args.host}:{args.port} ممکن نشد: {e}")
        panel_log("   پورت دیگری بدهید (مثلاً --port 8001) یا با --port 0 پورت آزاد بگیرید.")
        return 4
    server.daemon_threads = True
    args.port = server.server_address[1]
    state.port = args.port
    _banner(state, args)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        panel_log("\n⛔ بستن پنل…")
    finally:
        server.shutdown()
        server.server_close()
        state.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
