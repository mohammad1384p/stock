#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
لاگینگ ساخت‌یافته، سطح‌بندی‌شده و «ضدِ فاش‌شدنِ راز» برای ربات اکسیر.

چرا این ماژول وجود دارد؟
    وقتی کارگزاری درخواست ثبت سفارش را با ``403``/``errorCode=9009``
    («مشکل امنیتی») رد می‌کند، تنها راهِ فهمیدنِ علت این است که بدانیم
    **دقیقاً چه فرستاده‌ایم**: کدام هدرها، کدام کوکی‌ها (فقط نام، نه مقدار)،
    توکن چند ثانیه‌اش مانده، آیا ساعت با کارگزار همگام است و سرور در پاسخ چه
    کوکی‌ای را عوض کرده است. این ماژول همان اطلاعات را با سطح‌های مختلف
    (``debug``/``info``/``warning``/``error``) در ترمینال و فایل لاگ می‌نویسد،
    در حالی که رمز عبور، توکن، کوکی و هدر ``Authorization`` را پیش از نوشته‌شدن
    پوشیده (mask) می‌کند تا لاگ قابل اشتراک‌گذاری باشد.

سه جزء اصلی:

* :func:`setup_logging` — پیکربندی لاگرها (ترمینال + فایل چرخشی، متن یا JSON).
* :func:`emit` — ثبت یک رخدادِ ساخت‌یافته: ``emit(logger, logging.ERROR,
  "order.security_rejected", status=403, error_code="9009")``.
* :func:`redact` / :func:`redact_headers` — پوشاندن مقادیر حساس در هر رشته یا
  مجموعه‌ای از هدرها (حتی پیام‌های کتابخانه‌های دیگر که از همین هندلر عبور
  می‌کنند).

استفاده‌ی مستقل (دیباگِ سریع)::

    python exir_bot.py ... --log-level debug --log-file logs/exir.log
    python exir_bot.py ... --log-format json --log-file logs/exir.jsonl

متغیرهای محیطی: ``EXIR_LOG_LEVEL`` و ``EXIR_LOG_FILE`` (مثل پرچم‌های بالا).
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

__all__ = [
    "ROOT_LOGGER", "LEVELS", "mask", "redact", "redact_headers", "redact_value",
    "setup_logging", "get_logger", "emit", "bridge", "capture_records",
    "install_excepthook", "register_secret", "forget_secrets",
]

# نام لاگرِ والد؛ همه‌ی لاگرهای پروژه زیر این شاخه‌اند (exir.bot، exir.panel و…)
ROOT_LOGGER = "exir"

LEVELS = {"debug": logging.DEBUG, "info": logging.INFO,
          "warning": logging.WARNING, "error": logging.ERROR}

# محدودیت‌های فایل لاگ
DEFAULT_MAX_BYTES = 2 * 1024 * 1024   # هر فایل تا ۲ مگابایت
DEFAULT_BACKUPS = 3                   # و ۳ نسخه‌ی قبلی نگه داشته می‌شود
MAX_TEXT = 2000                       # حداکثر طولِ مقدارهای متنی در یک فیلد


# --------------------------------------------------------------------------- #
#  پوشاندن مقادیر حساس
# --------------------------------------------------------------------------- #
# هدرهایی که مقدارشان هرگز نباید وارد لاگ شود (نام به صورت کوچک)
SECRET_HEADERS = {
    "authorization", "proxy-authorization", "cookie", "set-cookie", "cookie2",
    "x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token",
}
# کلیدهایی که مقدارشان در هر جا (JSON بدنه، متن، آدرس) باید پوشیده شود
SECRET_KEYS = (
    "password", "passwd", "pwd", "pass", "otp", "secret", "captcha",
    "captchacode", "captchavalue", "token", "accesstoken", "refreshtoken",
    "jwt-token", "authtoken", "clientsecret", "apikey", "api-key",
)
# توکن JWT و الگوهای مشابه ( Bearer/Basic و «کوکی=مقدارِ بلند» )
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_.-]*)?")
_AUTH_SCHEME_RE = re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})")
_SECRET_KV_RE = re.compile(
    r"(?i)([\"']?(?:" + "|".join(SECRET_KEYS) + r")[\"']?\s*[:=]\s*)"
    r"(\"[^\"]*\"|'[^']*'|[^\s,;)}\]]+)"
)
# یک خط/عبارتِ شبیه «Cookie: …» یا «set-cookie=…» در متنِ آزاد لاگ
_COOKIE_LINE_RE = re.compile(r"(?i)\b(cookie2?|set-cookie)\b(\s*[:=]\s*)([^\r\n]{0,4000})")
# کوکی‌هایی که مقدارشان شناسه‌ی نشست/چالش است و حتی در متنِ آزاد باید پوشیده شوند
SECRET_COOKIE_NAMES = (
    "cookiesession1", "cookiesession", "client_login_id", "jsessionid",
    "asp.net_sessionid", "__cf_bm", "cf_clearance", "__cflb", "incap_ses",
)
_SECRET_COOKIE_RE = re.compile(
    r"(?i)\b(" + "|".join(re.escape(n) for n in SECRET_COOKIE_NAMES) + r")\s*=\s*"
    r"([A-Za-z0-9_\-%+/=.]{6,})")


def mask(value, head: int = 4, keep_len: bool = True) -> str:
    """مقدار حساس را به شکل ``abcd…***(len=84)`` کوتاه می‌کند.

    چند نویسه‌ی اول نگه داشته می‌شود چون برای مقایسه‌ی «همان توکن/همان کوکی
    بود؟» کافی است، ولی اصلِ مقدار هرگز نوشته نمی‌شود. پوشاندن تکرارپذیر است
    (idempotent): مقداری که از قبل پوشیده شده دست‌نخورده می‌ماند.
    """
    text = "" if value is None else str(value)
    if not text:
        return ""
    if "…***" in text:                      # قبلاً پوشیده شده
        return text
    if len(text) <= max(head, 2) + 2:
        return "***"
    suffix = f"(len={len(text)})" if keep_len else ""
    return f"{text[:head]}…***{suffix}"


# ویژگی‌های هدر Set-Cookie که مقدارشان حساس نیست و باید خوانا بماند
_COOKIE_ATTRS = {"path", "domain", "expires", "max-age", "samesite", "secure",
                 "httponly", "priority", "partitioned"}


def _mask_cookie_header(value: str) -> str:
    """هدر Cookie/Set-Cookie: نام‌ها سالم، مقدارها پوشیده."""
    out = []
    for part in str(value).split(";"):
        piece = part.strip()
        if not piece:
            continue
        if "=" in piece:
            name, val = piece.split("=", 1)
            name, val = name.strip(), val.strip()
            if name.lower() in _COOKIE_ATTRS:      # Path=/ یا SameSite=Lax و …
                out.append(f"{name}={val}")
            else:
                out.append(f"{name}={mask(val, head=3)}")
        else:
            out.append(piece)                      # Secure / HttpOnly
    return "; ".join(out)


def redact_headers(headers) -> dict:
    """هدرها را برای لاگ آماده می‌کند: کلیدها کوچک، مقدارهای حساس پوشیده.

    خروجی فقط برای لاگ است و هیچ مقدار کوکی/توکنی را سالم نگه نمی‌دارد.
    """
    out: dict[str, str] = {}
    try:
        items = list(headers.items()) if hasattr(headers, "items") else list(headers or [])
    except Exception:  # noqa: BLE001
        return out
    for name, value in items:
        low = str(name).lower()
        text = "" if value is None else str(value)
        if low in SECRET_HEADERS:
            if "cookie" in low:
                text = _mask_cookie_header(text)
            else:
                scheme, sep, rest = text.partition(" ")
                # «Bearer <توکن>»: طرح هدر برای دیباگ مفید است، خود توکن نه
                text = f"{scheme} {mask(rest, head=4)}" if (sep and rest) else mask(text, head=7)
        elif len(text) > MAX_TEXT:
            text = text[:MAX_TEXT] + f"…(+{len(text) - MAX_TEXT})"
        out[low] = text
    return out


def redact_value(value, *, depth: int = 0):
    """پوشاندن بازگشتی داخل dict/list/tuple (برای فیلدهای ساخت‌یافته)."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return redact(value)
    if depth >= 4:
        return str(value)[:MAX_TEXT]
    if isinstance(value, dict):
        clean = {}
        for key, val in value.items():
            if str(key).strip().lower().replace("-", "").replace("_", "") in {
                    k.replace("-", "").replace("_", "") for k in SECRET_KEYS}:
                clean[str(key)] = mask(val, head=3)
            else:
                clean[str(key)] = redact_value(val, depth=depth + 1)
        return clean
    if isinstance(value, (list, tuple, set)):
        return [redact_value(v, depth=depth + 1) for v in value]
    return redact(str(value))


def _cookie_line(m: re.Match) -> str:
    """«Cookie: a=1; b=2» در متن آزاد: نام‌ها سالم، مقدارها پوشیده."""
    value = m.group(3)
    return f"{m.group(1)}{m.group(2)}{_mask_cookie_header(value) if '…***' not in value else value}"


# مقادیرِ مشخصی که برنامه می‌شناسد و هرگز نباید در لاگ بیایند (مثل کلید پنل)
_secrets: set = set()
_secrets_lock = threading.Lock()


def register_secret(value, *, min_len: int = 6) -> None:
    """یک مقدارِ مشخص (کلید پنل، توکنِ دستی …) را در همه‌ی لاگ‌ها می‌پوشاند."""
    text = "" if value is None else str(value).strip()
    if len(text) >= min_len:
        with _secrets_lock:
            _secrets.add(text)


def forget_secrets() -> None:
    with _secrets_lock:
        _secrets.clear()


def redact(text) -> str:
    """هر رشته را پیش از نوشته‌شدن در لاگ از مقادیر حساس پاک می‌کند.

    یک‌بار مصرف (idempotent): اگر مقداری از قبل پوشیده شده باشد دست‌نخورده
    می‌ماند، چون یک رکورد ممکن است هم در :func:`emit` و هم در فیلترِ هندلر
    پردازش شود.
    """
    s = "" if text is None else str(text)
    if not s:
        return s

    def _jwt(m: re.Match) -> str:
        return m.group(0) if "…***" in m.group(0) else mask(m.group(0), head=7)

    def _scheme(m: re.Match) -> str:
        return m.group(0) if "…***" in m.group(0) else f"{m.group(1)} {mask(m.group(2), head=4)}"

    def _kv(m: re.Match) -> str:
        raw = m.group(2)
        quote = raw[0] if raw[:1] in ('"', "'") else ""
        value = raw.strip('"\'')
        if "…***" in value:
            return m.group(0)
        return f"{m.group(1)}{quote}{mask(value, head=3)}{quote}"

    for secret in list(_secrets):      # مقادیر ثبت‌شده (مثل کلید دسترسی پنل)
        if secret in s:
            s = s.replace(secret, mask(secret, head=3))
    s = _JWT_RE.sub(_jwt, s)
    s = _AUTH_SCHEME_RE.sub(_scheme, s)
    s = _COOKIE_LINE_RE.sub(_cookie_line, s)
    s = _SECRET_COOKIE_RE.sub(
        lambda m: m.group(0) if "…***" in m.group(2) else f"{m.group(1)}={mask(m.group(2), head=3)}", s)
    s = _SECRET_KV_RE.sub(_kv, s)
    return s


# --------------------------------------------------------------------------- #
#  قالب‌بندی: متنِ خوانا یا JSONِ یک‌خطی
# --------------------------------------------------------------------------- #
class RedactingFilter(logging.Filter):
    """پوشاندنِ پیام و فیلدهای هر رکورد — حتی پیامِ کتابخانه‌های دیگر."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            record.msg = redact(record.getMessage())
            record.args = ()
        except Exception:  # noqa: BLE001  (لاگ نباید خودش باعث شکستن برنامه شود)
            pass
        fields = getattr(record, "exir_fields", None)
        if fields:
            try:
                record.exir_fields = {k: redact_value(v) for k, v in fields.items()}
            except Exception:  # noqa: BLE001
                record.exir_fields = {k: str(v)[:MAX_TEXT] for k, v in fields.items()}
        if getattr(record, "exir_event", None):
            record.exir_event = str(record.exir_event)
        return True


def _field_text(value) -> str:
    if isinstance(value, (dict, list, tuple)):
        try:
            value = json.dumps(value, ensure_ascii=False, sort_keys=False)
        except Exception:  # noqa: BLE001
            value = str(value)
    text = redact(str(value))
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + f"…(+{len(text) - MAX_TEXT})"
    if "\n" in text:      # بلوک‌های چندخطی (درخواست/پاسخ) تورفتگی می‌گیرند
        text = text.replace("\n", "\n      ")
    return text if text.strip() else '""'


class TextFormatter(logging.Formatter):
    """``زمان  سطح  لاگر  رخداد  پیام  key=value…``"""

    def __init__(self) -> None:
        super().__init__("%(asctime)s.%(msecs)03d %(levelname)-5s %(name)s",
                         datefmt="%Y-%m-%d %H:%M:%S")

    def format(self, record: logging.LogRecord) -> str:
        head = super().format(record)
        event = getattr(record, "exir_event", None) or "-"
        message = record.getMessage()
        parts = [head, f"[{event}]"]
        if message:
            parts.append(message)
        fields = getattr(record, "exir_fields", None) or {}
        for key, value in fields.items():
            parts.append(f"{key}={_field_text(value)}")
        text = " ".join(parts)
        if record.exc_info:
            text += "\n" + self.formatException(record.exc_info)
        return text


class JsonFormatter(logging.Formatter):
    """هر رکورد یک خط JSON (برای jq / گرافانا / جست‌وجوی دقیق)."""

    _RESERVED = ("ts", "level", "logger", "event", "msg")

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created).astimezone().isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "exir_event", None) or "log",
            "msg": record.getMessage(),
        }
        for key, value in (getattr(record, "exir_fields", None) or {}).items():
            name = str(key)
            if name in self._RESERVED:
                name = "field_" + name
            try:
                payload[name] = redact_value(value)
            except Exception:  # noqa: BLE001
                payload[name] = str(value)[:MAX_TEXT]
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------- #
#  پیکربندی
# --------------------------------------------------------------------------- #
_config_lock = threading.Lock()


def _level(value, default: int = logging.INFO) -> int:
    if isinstance(value, int):
        return value
    return LEVELS.get(str(value or "").strip().lower(), default)


def _make_formatter(fmt: str) -> logging.Formatter:
    return JsonFormatter() if str(fmt).strip().lower() == "json" else TextFormatter()


def setup_logging(level="info", log_file=None, fmt: str = "text", *, console: str = "auto",
                  max_bytes: int = DEFAULT_MAX_BYTES, backups: int = DEFAULT_BACKUPS,
                  logger_name: str = ROOT_LOGGER) -> logging.Logger:
    """
    لاگرهای پروژه را پیکربندی می‌کند و لاگر والد را برمی‌گرداند.

    ``console``:
        * ``"auto"`` (پیش‌فرض): ترمینال فقط ``WARNING`` به بالا را نشان می‌دهد
          (خروجیِ رنگیِ خودِ ربات از قبل روی ترمینال است، پس تکرار نمی‌شود)،
        * ``"on"``: همه‌چیزِ عبورکرده از ``level`` روی ترمینال هم می‌آید،
        * ``"off"``: فقط فایل (برای اجرای پنل در پس‌زمینه).
    """
    log = logging.getLogger(logger_name)
    lvl = _level(level)
    with _config_lock:
        for handler in list(log.handlers):
            if getattr(handler, "_exir_handler", False):
                log.removeHandler(handler)
                try:
                    handler.close()
                except Exception:  # noqa: BLE001
                    pass
        log.setLevel(lvl)
        log.propagate = False        # جلوگیری از چاپ دوباره توسط لاگر ریشه
        formatter = _make_formatter(fmt)
        shield = RedactingFilter()

        console_mode = str(console or "auto").strip().lower()
        if console_mode in ("on", "true", "yes", "1"):
            console_level = lvl
        elif console_mode in ("off", "none", "false", "0"):
            console_level = None
        else:
            console_level = max(lvl, logging.WARNING)
        if console_level is not None:
            stream = logging.StreamHandler(sys.stderr)
            stream.setLevel(console_level)
            stream.setFormatter(formatter)
            stream.addFilter(shield)
            stream._exir_handler = True  # type: ignore[attr-defined]
            log.addHandler(stream)

        if log_file:
            path = Path(str(log_file)).expanduser()
            try:
                if path.parent and str(path.parent) not in ("", "."):
                    path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = RotatingFileHandler(path, maxBytes=max_bytes,
                                                   backupCount=backups, encoding="utf-8")
                file_handler.setLevel(lvl)
                file_handler.setFormatter(formatter)
                file_handler.addFilter(shield)
                file_handler._exir_handler = True  # type: ignore[attr-defined]
                log.addHandler(file_handler)
                try:  # لاگِ دیباگ می‌تواند سرنخ‌هایی از نشست داشته باشد
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            except OSError as e:  # لاگ نباید جلوی اجرای ربات را بگیرد
                log.warning("نوشتن لاگ در فایل ممکن نیست (%s): %s", path, e)
    return log


def get_logger(name: str) -> logging.Logger:
    """لاگرِ زیرشاخه: ``get_logger("bot")`` → ``exir.bot``."""
    return logging.getLogger(f"{ROOT_LOGGER}.{name}")


def emit(logger, level: int, event: str, message=None, **fields) -> None:
    """
    ثبت یک رخدادِ ساخت‌یافته.

    ``message`` متنِ خوانا برای انسان است و ``fields`` همان اطلاعات را به شکل
    جفت‌های ``key=value`` (قالب متنی) یا کلیدِ JSON (قالب json) اضافه می‌کند::

        emit(LOG, logging.ERROR, "order.security_rejected",
             "کارگزاری درخواست را از نظر امنیتی رد کرد",
             status=403, error_code="9009", cookie_names=[...])
    """
    try:
        if not logger.isEnabledFor(level):
            return
        # فقط وقتی واقعاً درون یک except هستیم traceback ضمیمه می‌شود
        exc_info = bool(fields.pop("exc_info", False)) and sys.exc_info()[0] is not None
        clean = {k: v for k, v in fields.items() if v is not None}
        logger.log(level, message if message is not None else event, exc_info=exc_info,
                   extra={"exir_event": event, "exir_fields": clean})
    except Exception:  # noqa: BLE001  (هرگز به‌خاطر لاگ خراب نشو)
        pass


def bridge(name: str = "bot", level: int = logging.INFO, event: str = "console"):
    """
    یک تابع ``log(*parts)`` می‌سازد که خروجیِ ترمینالی را به لاگر می‌فرستد.

    برای جاهایی که یک callable شبیه ``log`` می‌خواهند (exir_auth، session_capture،
    timesync و …) و می‌خواهیم پیام‌شان در فایل لاگ هم باشد.
    """
    log = get_logger(name)

    def _log(*parts, **kwargs) -> None:
        text = " ".join(str(p) for p in parts if p is not None)
        if not text.strip():
            return
        emit(log, _level(kwargs.get("level"), level), event, text)

    return _log


class _CaptureHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self.setFormatter(TextFormatter())
        self.addFilter(RedactingFilter())   # دقیقاً همان چیزی که در فایل لاگ می‌نشیند

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def capture_records(logger=None, *, level: int = logging.DEBUG):
    """
    Context manager برای تست‌ها: رکوردهای لاگ را در حافظه جمع می‌کند.

    مثال::

        with capture_records(get_logger("bot")) as records:
            send_order(...)
        events = [r.exir_event for r in records]
    """
    import contextlib

    target = logger or logging.getLogger(ROOT_LOGGER)

    @contextlib.contextmanager
    def _ctx():
        handler = _CaptureHandler()
        handler.setLevel(level)
        previous = target.level
        target.addHandler(handler)
        if target.getEffectiveLevel() > level:   # سطحِ مؤثر ممکن است از والد ارث برسد
            target.setLevel(level)
        try:
            yield handler.records
        finally:
            target.removeHandler(handler)
            target.setLevel(previous)

    return _ctx()


def install_excepthook(logger=None, event: str = "uncaught_exception") -> None:
    """استثناهای کنترل‌نشده را (بعد از پوشاندن) در لاگ می‌نویسد."""
    log = logger or get_logger("bot")
    previous = sys.excepthook

    def hook(exc_type, exc, tb) -> None:
        try:
            log.critical("%s: %s", getattr(exc_type, "__name__", exc_type), exc,
                         exc_info=(exc_type, exc, tb),
                         extra={"exir_event": event, "exir_fields": {}})
        except Exception:  # noqa: BLE001
            pass
        if previous:
            previous(exc_type, exc, tb)

    sys.excepthook = hook


# --------------------------------------------------------------------------- #
#  اجرای مستقل: تستِ سریعِ پوشاندنِ رازها و قالب خروجی
# --------------------------------------------------------------------------- #
def _demo() -> None:
    logger = setup_logging("debug", fmt=os.environ.get("EXIR_LOG_FORMAT", "text"))
    emit(logger, logging.INFO, "demo.start", "نمونه‌ی لاگ",
         headers=redact_headers({"Cookie": "JWT-TOKEN=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig; "
                                            "cookiesession1=ABCDEF0123456789ABCDEF0123456789",
                                 "Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sig",
                                 "x-app-n": "2018887747744.29964494",
                                 "Referer": "https://khobregan.exirbroker.com/new-exir/market-view"}),
         body='{"password": "s3cr3t", "insMaxLcode": "IRO7TONP0001"}')
    emit(logger, logging.ERROR, "order.security_rejected", "نمونه‌ی ردِ امنیتی",
         status=403, error_code="9009", cookie_names=["JWT-TOKEN", "cookiesession1"])


if __name__ == "__main__":
    _demo()
