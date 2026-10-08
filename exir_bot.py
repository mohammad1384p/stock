#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ربات ارسال سفارش زمان‌دار برای سامانه‌ی معاملاتی Exir (اکسیر).

در زمان مشخص‌شده (ساعت:دقیقه:ثانیه) شروع به ارسال درخواست ثبت سفارش می‌کند و
به مدت N ثانیه (پیش‌فرض ۱۰) با فاصله‌ی M میلی‌ثانیه (پیش‌فرض ۳۰۵) تکرار می‌کند.
پاسخ هر درخواست در ترمینال چاپ می‌شود.

نمونه:
    python exir_bot.py -s IRO7TONP0001 -q 10 -p 6700 -t 08:44:59.500
    python exir_bot.py               # همه‌چیز به‌صورت تعاملی پرسیده می‌شود
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:  # pragma: no cover
    print("کتابخانه‌ی requests نصب نیست. اجرا کنید:  pip install -r requirements.txt")
    sys.exit(1)

from timesync import clock, sync as time_sync, DEFAULT_NTP_SERVERS
from exir_auth import (ensure_token, jwt_exp, load_saved_token, describe_token, clean_token,
                       security_hint)

try:
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    ZoneInfo = None  # type: ignore

DEFAULT_BASE_URL = "https://khobregan.exirbroker.com"
ORDER_PATH = "/api/v1/order"
USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36"
)
SYMBOLS_FILE = Path(__file__).with_name("symbols.json")
ISIN_RE = re.compile(r"^IR[A-Z0-9]{10}$")

# --------------------------------------------------------------------------- #
#  چاپ رنگی و thread-safe
# --------------------------------------------------------------------------- #
_print_lock = threading.Lock()
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def green(s): return _c("32", s)
def red(s): return _c("31", s)
def yellow(s): return _c("33", s)
def cyan(s): return _c("36", s)
def bold(s): return _c("1", s)


def log(*args) -> None:
    with _print_lock:
        print(*args, flush=True)


def now_str(tz) -> str:
    return datetime.fromtimestamp(clock.now(), tz).strftime("%H:%M:%S.%f")[:-3]


# --------------------------------------------------------------------------- #
#  پیدا کردن کد ISIN (insMaxLcode) از روی نماد / نام / تگ
# --------------------------------------------------------------------------- #
def normalize_fa(s: str) -> str:
    """یکسان‌سازی حروف فارسی/عربی و حذف فاصله‌های اضافی."""
    s = s.strip()
    for a, b in (("ي", "ی"), ("ك", "ک"), ("ى", "ی"), ("\u200c", " "), ("ة", "ه")):
        s = s.replace(a, b)
    return re.sub(r"\s+", " ", s)


def load_local_symbols() -> dict[str, str]:
    """symbols.json: {"وتوصا": "IRO7TONP0001", ...}"""
    if not SYMBOLS_FILE.exists():
        return {}
    try:
        data = json.loads(SYMBOLS_FILE.read_text(encoding="utf-8"))
        return {normalize_fa(k): v.strip().upper() for k, v in data.items()}
    except Exception as e:  # noqa: BLE001
        log(yellow(f"⚠️  خواندن symbols.json ناموفق بود: {e}"))
        return {}


def save_local_symbol(symbol: str, isin: str) -> None:
    try:
        data = {}
        if SYMBOLS_FILE.exists():
            data = json.loads(SYMBOLS_FILE.read_text(encoding="utf-8"))
        data[normalize_fa(symbol)] = isin
        SYMBOLS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


def tsetmc_lookup(query: str, interactive: bool) -> str | None:
    """جستجوی نماد در TSETMC و برگرداندن ISIN."""
    q = normalize_fa(query)
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    url = f"https://cdn.tsetmc.com/api/Instrument/GetInstrumentSearch/{requests.utils.quote(q)}"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        items = r.json().get("instrumentSearch") or []
    except Exception as e:  # noqa: BLE001
        log(yellow(f"⚠️  جستجو در TSETMC ناموفق بود: {e}"))
        return None

    if not items:
        return None

    exact = [it for it in items if normalize_fa(str(it.get("lVal18AFC", ""))) == q]
    candidates = exact or items
    # نمادهای حذف‌شده/قدیمی را در انتها قرار بده
    candidates.sort(key=lambda it: (int(bool(it.get("lastDate"))), 0 if it.get("flow") else 1))

    chosen = candidates[0]
    if len(candidates) > 1 and interactive and not exact:
        log(cyan("چند نتیجه پیدا شد:"))
        for i, it in enumerate(candidates[:10], 1):
            log(f"  {i}) {it.get('lVal18AFC')} - {it.get('lVal30')}")
        sel = input("شماره‌ی مورد نظر [1]: ").strip() or "1"
        try:
            chosen = candidates[int(sel) - 1]
        except (ValueError, IndexError):
            log(red("انتخاب نامعتبر."))
            return None

    isin = chosen.get("instrumentID")
    if not isin:
        ins_code = chosen.get("insCode")
        try:
            r = requests.get(
                f"https://cdn.tsetmc.com/api/Instrument/GetInstrumentInfo/{ins_code}",
                headers=headers, timeout=10,
            )
            r.raise_for_status()
            isin = (r.json().get("instrumentInfo") or {}).get("instrumentID")
        except Exception as e:  # noqa: BLE001
            log(yellow(f"⚠️  گرفتن اطلاعات نماد از TSETMC ناموفق بود: {e}"))
            return None
    if isin:
        log(green(f"✔ نماد «{chosen.get('lVal18AFC')}» ({chosen.get('lVal30')}) → {isin}"))
    return isin


def resolve_isin(query: str, interactive: bool) -> str:
    raw = query.strip()
    if ISIN_RE.match(raw.upper()):
        return raw.upper()

    local = load_local_symbols()
    key = normalize_fa(raw)
    if key in local:
        log(green(f"✔ «{raw}» از symbols.json → {local[key]}"))
        return local[key]

    log(cyan(f"… جستجوی «{raw}» در TSETMC"))
    isin = tsetmc_lookup(raw, interactive)
    if isin:
        save_local_symbol(raw, isin)
        return isin

    if interactive:
        isin = input("نماد پیدا نشد. کد ISIN (مثل IRO7TONP0001) را وارد کنید: ").strip().upper()
        if ISIN_RE.match(isin):
            save_local_symbol(raw, isin)
            return isin
    log(red("✘ کد ISIN نماد پیدا نشد. مستقیماً کد ISIN را با -s بدهید یا آن را در symbols.json اضافه کنید."))
    sys.exit(2)


# --------------------------------------------------------------------------- #
#  زمان
# --------------------------------------------------------------------------- #
def parse_target_time(s: str, tz, allow_tomorrow: bool) -> datetime:
    m = re.fullmatch(r"\s*(\d{1,2}):(\d{1,2})(?::(\d{1,2})(?:[.,](\d{1,3}))?)?\s*", s)
    if not m:
        raise ValueError("فرمت زمان باید HH:MM:SS یا HH:MM:SS.mmm باشد")
    h, mi = int(m.group(1)), int(m.group(2))
    sec = int(m.group(3) or 0)
    ms = int((m.group(4) or "0").ljust(3, "0"))
    now = datetime.fromtimestamp(clock.now(), tz)
    target = now.replace(hour=h, minute=mi, second=sec, microsecond=ms * 1000)
    if target < now and allow_tomorrow:
        target += timedelta(days=1)
    return target


def wait_until(ts: float) -> None:
    """صبر دقیق تا زمان epoch مشخص (بر اساس ساعت همگام‌شده؛ sleep درشت + busy-wait در انتها)."""
    while True:
        remaining = ts - clock.now()
        if remaining <= 0:
            return
        if remaining > 0.05:
            time.sleep(min(remaining - 0.03, 0.5))
        # کمتر از ۵۰ میلی‌ثانیه: busy-wait برای دقت بالا


# --------------------------------------------------------------------------- #
#  ساخت session و هدرها
# --------------------------------------------------------------------------- #
def build_session(args, pool: int) -> requests.Session:
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=4, pool_maxsize=max(pool, 10))
    s.mount("https://", adapter)
    s.mount("http://", adapter)

    base = args.base_url.rstrip("/")
    s.headers.update({
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-US,en;q=0.9,fa;q=0.8,nl;q=0.7,zh-CN;q=0.6,zh;q=0.4",
        "content-type": "application/json",
        "origin": base,
        "referer": f"{base}/new-exir/market-view",
        "user-agent": USER_AGENT,
        "pragma": "no-cache",
        "cache-control": "no-cache",
        "sec-ch-ua": '"Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    })
    if args.cookie:
        host = requests.utils.urlparse(base).hostname or ""
        for part in args.cookie.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                s.cookies.set(k.strip(), v.strip(), domain=host, path="/")
    if args.app_n:
        s.headers["x-app-n"] = args.app_n.strip()
    for h in args.header or []:
        if ":" not in h:
            log(yellow(f"⚠️  هدر نامعتبر نادیده گرفته شد: {h}"))
            continue
        k, v = h.split(":", 1)
        s.headers[k.strip()] = v.strip()
    return s


def build_body(args, isin: str) -> dict:
    return {
        "insMaxLcode": isin,
        "bankAccountId": -1,
        "side": "SIDE_SELL" if args.side == "sell" else "SIDE_BUY",
        "orderType": "ORDER_TYPE_LIMIT",
        "quantity": int(args.quantity),
        "price": int(args.price),
        "validityType": "VALIDITY_TYPE_DAY",
        "validityDate": "",
        "coreType": "c",
        "hasUnderCautionAgreement": True,
        "dividedOrder": False,
        "etfTypeCode": None,
    }


# --------------------------------------------------------------------------- #
#  بازپخش درخواست مرورگر (Copy as fetch) — برای پیدا کردن علت خطای ۴۲۲
# --------------------------------------------------------------------------- #
# هدرهایی که نباید دستی ست شوند (خودِ requests/سرور تعیین می‌کند)
_HOP_HEADERS = {"content-length", "host", "connection", "cookie", "accept-encoding",
                "transfer-encoding", "content-encoding"}


def _js_string(lit: str) -> str:
    """رشته‌ی جاوااسکریپتی ("..." یا '...') را به متن تبدیل می‌کند."""
    q = lit[0]
    body = lit[1:-1]
    if q == '"':
        try:
            return json.loads(lit)
        except ValueError:
            pass
    return (body.replace("\\" + q, q).replace("\\n", "\n").replace("\\t", "\t")
            .replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\"))


def parse_fetch_snippet(text: str) -> dict:
    """
    از خروجی «Copy as fetch» کروم (DevTools ← Request ← Copy → Copy as fetch)
    هدرها و بدنه را بیرون می‌کشد: {"headers": {...}, "body": "<متن JSON>"} .
    """
    out: dict = {"headers": {}, "body": None}
    try:  # شاید مستقیم JSON خالص باشد
        json.loads(text)
        out["body"] = text
        return out
    except ValueError:
        pass
    m = re.search(r"[\"']?body[\"']?\s*:\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')", text, re.S)
    if m:
        out["body"] = _js_string(m.group(1))

    m = re.search(r"[\"']?headers[\"']?\s*:\s*\{", text)
    block = ""
    if m:
        # بلاک هدرها را با شمارش آکولاد جدا می‌کنیم (مقدارها ممکن است } داشته باشند)
        start = m.end() - 1
        depth = 0
        for j in range(start, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    block = text[start + 1:j]
                    break
    for k, v in re.findall(r"[\"']([^\"']+)[\"']\s*:\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')", block):
        out["headers"][k.strip().lower()] = _js_string(v)
    return out


def apply_replay(session: requests.Session, headers: dict, log, *, preserve_session: bool = False) -> None:
    """هدرهای خروجی Copy as fetch را روی session می‌گذارد (کوکی‌ها merge می‌شوند)."""
    for k, v in headers.items():
        k = k.lower()
        if preserve_session and k in {
            "cookie", "authorization", "x-app-n", "user-agent",
            "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
            "origin", "referer",
        }:
            log(f"ℹ️  هدر {k} از فایل اعمال نشد؛ نشست ورود فعلی حفظ شد.")
            continue
        if k in _HOP_HEADERS:
            if k == "cookie":
                host = requests.utils.urlparse(session.headers.get("origin", "")).hostname or ""
                for part in v.split(";"):
                    if "=" in part:
                        ck, cv = part.split("=", 1)
                        session.cookies.set(ck.strip(), cv.strip(), domain=host, path="/")
            continue
        session.headers[k] = v
    if session.headers.get("x-app-n"):
        log(f"🧩 هدرهای مرورگر اعمال شد (x-app-n = {session.headers['x-app-n']})")


def order_hint(status: int, data) -> str:
    """توضیح خطاهای رایج ثبت سفارش."""
    hint = security_hint(status, data)
    if hint:
        return hint
    if status != 422:
        return ""
    return (
        "ℹ️  ۴۲۲ یعنی «امنیت اوکی است، ولی بدنه‌ی سفارش از نظر اعتبارسنجی رد شد».\n"
        "    فیلد خطادار را در همین پاسخ سرور ببینید (کلیدهای errors/description). دلایل رایج:\n"
        "    قیمت خارج از دامنه‌ی مجاز روز (±۵٪ دامنه/توقف) یا غیرمضرب در گام قیمت،\n"
        "    تعداد بیش از حد مجاز (سقف حجم هر سفارش)، نماد در حال توقف/عدم امکان سفارش،\n"
        "    یا بسته بودن سمت سفارش (مثلاً صف/دامنه در آن لحظه).\n"
        "    برای فرستادن دقیقاً همان بدنه‌ی مرورگر: DevTools ← Request ← Copy as fetch،\n"
        "    ذخیره در فایل و اجرا با  --body-file <فایل>  (هدرها و بدنه هر دو اعمال می‌شوند)."
    )


def warmup(session: requests.Session, base: str, tz) -> None:
    """برقراری اتصال TLS قبل از زمان هدف + نمایش اختلاف ساعت با سرور."""
    try:
        t0 = time.time()
        r = session.get(base + "/", timeout=3, allow_redirects=False)
        t1 = time.time()
        rtt = (t1 - t0) * 1000
        msg = f"🔌 اتصال آماده شد (HTTP {r.status_code}, RTT ≈ {rtt:.0f}ms)"
        date_h = r.headers.get("Date")
        if date_h:
            server = parsedate_to_datetime(date_h).timestamp() + 0.5
            offset = server - ((t0 + t1) / 2 + clock.offset)  # دقت حدود ±۰.۵ ثانیه (هدر Date ثانیه‌ای است)
            msg += f" | ساعت سرور کارگزاری نسبت به ساعت همگام‌شده: {offset:+.1f}s"
        log(cyan(msg))
    except Exception as e:  # noqa: BLE001
        log(yellow(f"⚠️  warm-up ناموفق بود (مشکلی نیست، ادامه می‌دهیم): {e}"))


# --------------------------------------------------------------------------- #
#  ارسال سفارش
# --------------------------------------------------------------------------- #
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.sent = 0
        self.success = 0
        self.failed = 0
        self.stop_reason: str | None = None
        self.results: list[tuple[int, str, int | None, str]] = []


def is_success(status: int, data) -> bool:
    if not (200 <= status < 300):
        return False
    if isinstance(data, dict):
        t = str(data.get("type", "")).lower()
        if t == "error" or data.get("error") or data.get("errors"):
            return False
        if t:
            return "success" in t
    return True


def security_rejected(status: int, data) -> bool:
    """Do not keep submitting unchanged orders after an auth/security rejection."""
    if status == 401:
        return True
    if status != 403 or not isinstance(data, dict):
        return False
    return str(data.get("errorCode", "")) == "9009"


def stop_message(stats: Stats, remaining: int) -> str:
    with stats.lock:
        reason = stats.stop_reason
    if reason == "security":
        detail = "⛔ ارسال به‌علت رد احراز هویت/امنیت کارگزاری متوقف شد"
    elif reason == "success":
        detail = "✅ پاسخ موفق سفارش دریافت شد"
    else:
        detail = "⏹ اجرا با درخواست کاربر متوقف شد"
    return f"{detail}؛ {remaining} درخواست باقی‌مانده ارسال نشد."


def send_order(idx: int, session: requests.Session, url: str, payload: bytes,
               timeout: float, tz, stats: Stats, stop_evt: threading.Event,
               stop_on_success: bool) -> None:
    sent_at = now_str(tz)
    t0 = time.perf_counter()
    try:
        # Never follow an order redirect to a login HTML page and call it a
        # successful order; also avoid replaying POST data to a redirect target.
        r = session.post(url, data=payload, timeout=timeout, allow_redirects=False)
        ms = (time.perf_counter() - t0) * 1000
        try:
            data = r.json()
            body = json.dumps(data, ensure_ascii=False, indent=2)
        except ValueError:
            data = None
            body = r.text[:2000] or "<empty>"
        ok = is_success(r.status_code, data)
        if "text/html" in r.headers.get("content-type", "").lower():
            ok = False
        rejected = security_rejected(r.status_code, data)
        desc = ""
        if isinstance(data, dict):
            desc = str(data.get("description") or data.get("message") or data.get("type") or "")
        with stats.lock:
            stats.success += ok
            stats.failed += (not ok)
            stats.results.append((idx, sent_at, r.status_code, desc))
            if rejected or (ok and stop_on_success):
                if stats.stop_reason is None:
                    stats.stop_reason = "security" if rejected else "success"
                stop_evt.set()
        head = f"#{idx:02d}  ارسال {sent_at}  ←  دریافت {now_str(tz)}  ({ms:.0f}ms)  HTTP {r.status_code}"
        extra = ""
        if not ok:
            hint = order_hint(r.status_code, data if data is not None else body)
            if hint:
                extra = "\n" + yellow(hint)
        log((green("✔ " + head) if ok else red("✘ " + head)) + "\n" + body + extra + "\n" + "─" * 60)
    except Exception as e:  # noqa: BLE001
        ms = (time.perf_counter() - t0) * 1000
        with stats.lock:
            stats.failed += 1
            stats.results.append((idx, sent_at, None, str(e)))
        log(red(f"✘ #{idx:02d}  ارسال {sent_at}  ({ms:.0f}ms)  خطای شبکه: {e}") + "\n" + "─" * 60)


# --------------------------------------------------------------------------- #
#  ورودی‌ها
# --------------------------------------------------------------------------- #
def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        v = input(f"{prompt}{suffix}: ").strip()
        if v:
            return v
        if default is not None:
            return default


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="ربات ارسال سفارش زمان‌دار برای Exir (هر آرگومانی که ندهید، تعاملی پرسیده می‌شود)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-s", "--symbol", help="نماد / نام / تگ سهم یا کد ISIN (مثل IRO7TONP0001 یا وتوصا)")
    p.add_argument("-q", "--quantity", type=int, help="تعداد سهم")
    p.add_argument("-p", "--price", type=int, help="قیمت هر سهم (ریال)")
    p.add_argument("-t", "--time", help="زمان شروع HH:MM:SS یا HH:MM:SS.mmm")
    p.add_argument("--side", choices=["buy", "sell"], default="buy", help="خرید یا فروش")
    p.add_argument("-d", "--duration", type=float, default=10.0, help="مدت ارسال (ثانیه)")
    p.add_argument("-i", "--interval", type=int, default=305, help="فاصله‌ی بین درخواست‌ها (میلی‌ثانیه)")
    g = p.add_argument_group("لاگین / توکن")
    g.add_argument("--token", default=os.environ.get("EXIR_TOKEN"),
                   help="توکن JWT (مقدار کوکی JWT-TOKEN یا authToken). اگر ندهید از فایل ذخیره یا لاگین گرفته می‌شود")
    g.add_argument("--login", action="store_true", help="لاگین اجباری (حتی اگر توکن ذخیره‌شده معتبر باشد)")
    g.add_argument("--login-only", action="store_true", help="فقط لاگین کن و توکن را ذخیره کن")
    g.add_argument("--username", default=os.environ.get("EXIR_USERNAME"), help="نام کاربری (یا EXIR_USERNAME)")
    g.add_argument("--password", default=os.environ.get("EXIR_PASSWORD"),
                   help="رمز عبور (یا EXIR_PASSWORD). بهتر است ندهید تا مخفی پرسیده شود")
    g.add_argument("--otp", default=None, help="کد یکبار مصرف (در صورت فعال بودن ورود دو مرحله‌ای)")
    g.add_argument("--captcha-url", default=os.environ.get("EXIR_CAPTCHA_URL"),
                   help="آدرس تصویر کپچا (پیش‌فرض /captcha)")
    g.add_argument("--token-file", default=os.environ.get("EXIR_TOKEN_FILE", ".exir_token.json"),
                   help="فایل ذخیره‌ی توکن")
    g.add_argument("--captcha-file", default="captcha.jpg", help="مسیر ذخیره‌ی تصویر کپچا (پسوند خودکار تنظیم می‌شود)")
    g.add_argument("--captcha-web", nargs="?", const="auto", metavar="PORT",
                   default=os.environ.get("EXIR_CAPTCHA_WEB"),
                   help="تصویر کپچا را در مرورگر نشان بده و کد را از آن‌جا بگیر "
                        "(پیش‌فرض: auto=روشن؛ عدد بدهید تا روی همان پورت بالا بیاید، off=خاموش)")
    g.add_argument("--captcha-web-host", default=os.environ.get("EXIR_CAPTCHA_WEB_HOST", "0.0.0.0"),
                   metavar="HOST",
                   help="آدرسی که وب‌سرور کپچا روی آن گوش می‌دهد (127.0.0.1 = فقط خود سرور)")
    g.add_argument("--auth-mode", choices=["cookie", "bearer", "both"],
                   default=os.environ.get("EXIR_AUTH_MODE", "cookie"),
                   help="ارسال توکن به‌صورت کوکی JWT-TOKEN (مثل مرورگر)، هدر Authorization، یا هر دو")
    g.add_argument("--cookie", default=os.environ.get("EXIR_COOKIE"),
                   help="کوکی‌های اضافه به شکل 'a=1; b=2' (اختیاری، یا EXIR_COOKIE)")
    g.add_argument("--app-n", default=os.environ.get("EXIR_APP_N"),
                   help="مقدار هدر x-app-n (اختیاری، یا EXIR_APP_N)")
    p.add_argument("-H", "--header", action="append",
                   help="هدر اضافه به شکل 'name: value' (قابل تکرار)")
    p.add_argument("--base-url", default=os.environ.get("EXIR_BASE_URL", DEFAULT_BASE_URL),
                   help="آدرس کارگزاری")
    p.add_argument("--tz", default=os.environ.get("EXIR_TZ", "Asia/Tehran"),
                   help="منطقه‌ی زمانی برای تفسیر ساعت (خالی = ساعت سیستم)")
    p.add_argument("--time-sync", choices=["auto", "ntp", "server", "off"],
                   default=os.environ.get("EXIR_TIME_SYNC", "auto"),
                   help="همگام‌سازی خودکار زمان: auto=اول NTP بعد ساعت سرور کارگزاری، off=ساعت سیستم")
    p.add_argument("--ntp-server", action="append",
                   help="سرور NTP دلخواه (قابل تکرار). پیش‌فرض: " + ", ".join(DEFAULT_NTP_SERVERS))
    p.add_argument("--body-json", metavar="JSON",
                   help="بدنه‌ی سفارش را عیناً همین JSON بفرست (برای بازپخش درخواست مرورگر)")
    p.add_argument("--body-file", metavar="FILE",
                   help="فایل حاوی بدنه‌ی JSON سفارش، یا خروجی «Copy as fetch» کروم "
                        "(هدرها و بدنه هر دو اعمال می‌شوند) — برای رفع خطای ۴۲۲")
    p.add_argument("--timeout", type=float, default=10.0, help="timeout هر درخواست (ثانیه)")
    p.add_argument("--no-stop", action="store_true",
                   help="بعد از اولین سفارش موفق هم ارسال را ادامه بده (پیش‌فرض: توقف)")
    p.add_argument("--now", action="store_true", help="بدون انتظار، همین الان شروع کن (برای تست)")
    p.add_argument("--dry-run", action="store_true", help="فقط نمایش درخواست، بدون ارسال")
    p.add_argument("-y", "--yes", action="store_true", help="بدون پرسیدن تأیید نهایی")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    interactive = sys.stdin.isatty()

    tz = None
    if args.tz and ZoneInfo is not None:
        try:
            tz = ZoneInfo(args.tz)
        except Exception:  # noqa: BLE001
            log(yellow(f"⚠️  منطقه‌ی زمانی «{args.tz}» شناخته نشد؛ از ساعت سیستم استفاده می‌شود."))

    log(bold(cyan("\n═══════════  ربات سفارش Exir  ═══════════\n")))

    base = args.base_url.rstrip("/")
    session = build_session(args, pool=64)

    # ---------- لاگین / توکن ----------
    token = None
    try:
        if args.dry_run and not (args.login or args.login_only):
            if args.token:
                token = clean_token(args.token)
            else:
                saved = load_saved_token(Path(args.token_file), base)
                token = saved["token"] if saved else None
            if token:
                from exir_auth import apply_token
                apply_token(session, base, token, args.auth_mode)
        else:
            token = ensure_token(session, args, log, interactive)
    except (EOFError, KeyboardInterrupt):
        log(red("\nلغو شد."))
        sys.exit(1)
    except Exception as e:  # noqa: BLE001
        log(red(f"✘ {e}"))
        sys.exit(3)
    if args.login_only:
        return

    # ---------- بدنه: پیش‌فرض ربات یا بازپخش درخواست مرورگر ----------
    replay_text: str | None = None
    if args.body_json:
        replay_text = args.body_json
    elif args.body_file:
        raw = Path(args.body_file).read_text(encoding="utf-8")
        snippet = parse_fetch_snippet(raw)   # JSON خالص یا خروجی «Copy as fetch»
        replay_text = snippet["body"]
        if snippet["headers"]:
            apply_replay(session, snippet["headers"], log, preserve_session=bool(token))
        if not replay_text:
            log(red("✘ در فایل بدنه‌ی سفارشی، JSON یا بدنه‌ی Copy as fetch پیدا نشد."))
            sys.exit(2)
    replay_body: dict | None = None
    if replay_text:
        try:
            replay_body = json.loads(replay_text)
        except ValueError:
            log(red("✘ بدنه‌ی سفارشی JSON معتبر نیست."))
            sys.exit(2)
        if not isinstance(replay_body, dict):
            log(red("✘ بدنه‌ی سفارشی باید یک آبجکت JSON باشد."))
            sys.exit(2)
        log(yellow("🧩 بدنه‌ی سفارش از درخواست مرورگر بازپخش می‌شود (بدون بازسازی فیلدها)."))

    # ---------- ورودی‌ها ----------
    try:
        if not args.symbol:
            args.symbol = (str(replay_body["insMaxLcode"]) if replay_body and replay_body.get("insMaxLcode")
                           else ask("نماد / نام / ISIN سهم"))
        if args.quantity is None:
            args.quantity = (int(replay_body["quantity"]) if replay_body and replay_body.get("quantity") is not None
                             else int(ask("تعداد")))
        if args.price is None:
            args.price = (int(replay_body["price"]) if replay_body and replay_body.get("price") is not None
                          else int(ask("قیمت (ریال)")))
        if not args.time and not args.now:
            args.time = ask("ساعت شروع (HH:MM:SS)")
    except (EOFError, KeyboardInterrupt):
        log(red("\nلغو شد."))
        sys.exit(1)
    except ValueError:
        log(red("مقدار عددی نامعتبر."))
        sys.exit(2)

    if args.quantity <= 0 or args.price <= 0:
        log(red("تعداد و قیمت باید بزرگ‌تر از صفر باشند."))
        sys.exit(2)
    if args.interval <= 0 or args.duration < 0:
        log(red("interval باید مثبت و duration نامنفی باشد."))
        sys.exit(2)

    isin = resolve_isin(args.symbol, interactive)

    def do_sync() -> None:
        time_sync(args.time_sync, session=session, base_url=base,
                  ntp_servers=args.ntp_server, log=lambda m: log(cyan(m)))

    do_sync()

    if args.now:
        target = datetime.fromtimestamp(clock.now(), tz) + timedelta(seconds=3)
    else:
        try:
            target = parse_target_time(args.time, tz, allow_tomorrow=False)
        except ValueError as e:
            log(red(str(e)))
            sys.exit(2)
        if target.timestamp() + args.duration < clock.now():
            log(red(f"⏰ زمان {target:%H:%M:%S} گذشته است. (برای تست فوری از --now استفاده کنید)"))
            sys.exit(2)

    interval = args.interval / 1000.0
    count = int(args.duration / interval + 1e-9) + 1
    start_ts = target.timestamp()
    schedule = [start_ts + k * interval for k in range(count)]

    url = base + ORDER_PATH
    if replay_body is not None:
        body = replay_body
        payload = replay_text.encode("utf-8")   # عیناً همان بایت‌های مرورگر
    else:
        body = build_body(args, isin)
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")

    # ---------- خلاصه ----------
    log(bold("خلاصه‌ی سفارش:"))
    log(f"  کارگزاری   : {base}")
    log(f"  نماد/ISIN  : {args.symbol}  →  {isin}")
    log(f"  نوع        : {'خرید' if args.side == 'buy' else 'فروش'}")
    log(f"  تعداد      : {args.quantity:,}")
    log(f"  قیمت       : {args.price:,} ریال   (ارزش کل ≈ {args.quantity * args.price:,} ریال)")
    log(f"  شروع       : {target.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]} ({args.tz or 'system'})")
    log(f"  مدت/فاصله  : {args.duration:g} ثانیه / {args.interval} میلی‌ثانیه  →  {count} درخواست")
    log(f"  توقف پس از موفقیت: {'خیر' if args.no_stop else 'بله'}")
    acc = f" ±{clock.accuracy * 1000:.0f}ms" if clock.accuracy is not None else ""
    log(f"  ساعت مرجع  : {clock.source}{acc}  (اختلاف با سیستم {clock.offset * 1000:+.0f}ms)")
    log(f"  توکن       : {describe_token(token) if token else red('ندارد')}")
    exp = jwt_exp(token) if token else None
    if exp and exp < start_ts + args.duration:
        log(red("  ⚠️  توکن قبل از پایان زمان ارسال منقضی می‌شود! با --login دوباره وارد شوید."))
    saved = load_saved_token(Path(args.token_file), base) or {}
    delay = saved.get("sendOrderDelay")
    if delay and args.interval < int(delay):
        log(yellow(f"  ⚠️  کارگزار sendOrderDelay={delay}ms اعلام کرده؛ فاصله‌ی {args.interval}ms ممکن است خطای محدودیت بگیرد."))
    log(f"  بدنه       : {json.dumps(body, ensure_ascii=False)}")
    if args.dry_run:
        log(yellow("\n[dry-run] هیچ درخواستی ارسال نشد.\nهدرها:"))
        for k, v in session.headers.items():
            if k.lower() == "authorization":
                v = v[:16] + "…"
            log(f"  {k}: {v}")
        for c in session.cookies:
            log(f"  cookie {c.name}={c.value[:10]}…")
        return

    if interactive and not args.yes:
        if input("\nادامه بدهم؟ (y/n) [y]: ").strip().lower() not in ("", "y", "yes", "بله", "ب"):
            log("لغو شد.")
            return

    # ---------- انتظار ----------
    stats = Stats()
    stop_evt = threading.Event()
    try:
        # warm-up حدود ۵ ثانیه قبل از شروع (یا همین الان اگر زمان کمی مانده)
        warm_ts = start_ts - 5
        if warm_ts - clock.now() > 0:
            log(cyan(f"\n⏳ منتظر تا {target:%H:%M:%S} … (Ctrl+C برای لغو)"))
            last_print = 0.0
            resynced = False
            while clock.now() < warm_ts:
                rem = start_ts - clock.now()
                # همگام‌سازی دوباره حدود ۴۵ ثانیه قبل از شروع (جبران drift ساعت در انتظار طولانی)
                if (not resynced and args.time_sync != "off" and rem <= 45
                        and clock.synced_at and time.time() - clock.synced_at > 90):
                    resynced = True
                    print()
                    do_sync()
                if time.time() - last_print >= 1:
                    with _print_lock:
                        sys.stdout.write(f"\r   زمان فعلی {now_str(tz)}   |   باقی‌مانده {int(rem)//3600:02d}:{int(rem)%3600//60:02d}:{int(rem)%60:02d}   ")
                        sys.stdout.flush()
                    last_print = time.time()
                time.sleep(min(0.2, max(0.0, warm_ts - clock.now())))
            print()
        if clock.now() < start_ts - 0.5:
            warmup(session, base, tz)

        # ---------- ارسال ----------
        log(bold(yellow(f"\n🚀 شروع ارسال در {target:%H:%M:%S.%f}"[:-3] + "\n")))
        with ThreadPoolExecutor(max_workers=min(count, 64)) as pool:
            for k, ts in enumerate(schedule, 1):
                if stop_evt.is_set():
                    log(stop_message(stats, count - k + 1))
                    break
                wait_until(ts)
                if stop_evt.is_set():
                    log(stop_message(stats, count - k + 1))
                    break
                with stats.lock:
                    stats.sent += 1
                pool.submit(send_order, k, session, url, payload, args.timeout, tz,
                            stats, stop_evt, not args.no_stop)
            log(cyan("… منتظر دریافت پاسخ درخواست‌های در جریان"))
    except KeyboardInterrupt:
        log(red("\n⛔ توسط کاربر متوقف شد."))

    # ---------- گزارش ----------
    log(bold("\n═══════════  گزارش نهایی  ═══════════"))
    log(f"  ارسال‌شده: {stats.sent}   موفق: {green(str(stats.success))}   ناموفق: {red(str(stats.failed))}")
    for idx, sent_at, status, desc in sorted(stats.results):
        st = status if status is not None else "ERR"
        log(f"  #{idx:02d}  {sent_at}  HTTP {st}  {desc[:100]}")


if __name__ == "__main__":
    main()
