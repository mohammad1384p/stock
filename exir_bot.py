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
import getpass
import json
import logging
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
from captcha_web import CaptchaPortal, resolve_mode
from exir_auth import (CAPTCHA_TTL, TOKEN_COOKIE, cookie_matches_host, ensure_token, jwt_exp,
                       jwt_payload, load_saved_token, describe_token,
                       clean_token, security_hint)
from exir_logging import (LEVELS, emit, get_logger, install_excepthook, mask, redact_headers,
                          setup_logging)
from session_capture import (apply_captured, browser_bootstrap, imported_token,
                             load_captured_session, normalize_mode, parse_browser_session,
                             save_captured_session, security_cookie_warnings, session_summary)

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
# مقادیری که برای --clientid یعنی «این هدر را نفرست»
OFF_VALUES = {"off", "none", "-", "خاموش", "بدون"}

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


LOG = get_logger("bot")


def log(*args) -> None:
    """چاپ رنگی روی ترمینال + یک ردیف لاگ (برای فایل لاگ/دیباگ)."""
    with _print_lock:
        print(*args, flush=True)
    text = " ".join(str(a) for a in args if a is not None)
    if text.strip():
        emit(LOG, logging.INFO, "console", text)


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
def clientid_value(args) -> str | None:
    """مقدار هدر ``clientid`` — ``None`` یعنی این هدر فرستاده نشود."""
    raw = getattr(args, "clientid", None)
    if raw is None:
        raw = os.environ.get("EXIR_CLIENTID")
    if raw is None:
        return ""  # مثل درخواست ورودِ مرورگر: هدر هست، مقدارش خالی است
    value = str(raw).strip()
    return None if value.lower() in OFF_VALUES else value


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
    # هدر clientid در درخواست ورودِ مرورگر وجود دارد؛ برای سفارش‌ها هم همان مقدار
    # (پیش‌فرض: خالی) فرستاده می‌شود تا نشست بین «ورود» و «سفارش» یکدست بماند.
    clientid = clientid_value(args)
    if clientid is None:
        s.headers.pop("clientid", None)
    else:
        s.headers["clientid"] = clientid
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
            "cookie", "authorization", "x-app-n", "clientid", "user-agent",
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


# --------------------------------------------------------------------------- #
#  نشستِ مرورگر: import از DevTools و bootstrap رفتار مرورگر
# --------------------------------------------------------------------------- #
def read_import_text(source: str) -> str:
    """متن کپی‌شده از DevTools را از فایل می‌خواند (``-`` یعنی stdin)."""
    if source == "-":
        return sys.stdin.read()
    path = Path(source)
    if not path.exists():
        raise RuntimeError(f"فایل نشست پیدا نشد: {source}")
    return path.read_text(encoding="utf-8", errors="replace")


def apply_import_session(session: requests.Session, args, log, text: str | None = None) -> dict:
    """
    «نشست مرورگر» (Copy as cURL/fetch، هدرهای خام یا رشته‌ی Cookie) را روی session می‌گذارد
    و در فایل توکن ذخیره می‌کند تا اجراهای بعدی هم همان کوکی/هدرها را بفرستند.

    اگر در کوکی‌های کپی‌شده ``JWT-TOKEN`` باشد و توکن تازه‌ای نداشته باشیم، همان توکن
    هم ذخیره می‌شود؛ پس ورودِ مرورگرِ خودتان هم برای ربات کافی است.
    """
    base = args.base_url.rstrip("/")
    raw = text if text is not None else read_import_text(args.import_session)
    captured = parse_browser_session(raw)
    summary = apply_captured(session, base, captured, log)
    save_captured_session(Path(args.token_file), base, captured)
    log(f"💾 نشستِ واردشده در {args.token_file} ذخیره شد (در اجراهای بعدی هم اعمال می‌شود).")

    token = imported_token(captured)
    if token and not getattr(args, "token", None):
        exp = jwt_exp(token)
        if exp is None or exp > time.time() + 60:
            # کوکی/هدرها و توکنِ همان نشست باید با هم یکدست بمانند (x-app-n و کوکی چالش
            # به همان ورود گره خورده‌اند)؛ پس توکنِ خودِ این نشست جایگزین توکن قبلی می‌شود.
            from exir_auth import save_token
            save_token(Path(args.token_file), base, token,
                       {"appN": (captured.get("headers") or {}).get("x-app-n")})
            log(f"🔑 توکن داخل نشستِ واردشده ذخیره شد ({describe_token(token)}) — "
                "کوکی‌ها، هدرها و توکن از یک نشست‌اند.")
        else:
            log(yellow("⚠️ توکن داخل نشستِ واردشده منقضی است؛ توکن ذخیره‌شده‌ی قبلی استفاده می‌شود. "
                       "برای نشست یکدست، دوباره از مرورگر «Copy as cURL» بگیرید."))
    return summary


def apply_saved_captured_session(session: requests.Session, args, log,
                                 *, quiet: bool = False) -> dict | None:
    """
    نشستِ ذخیره‌شده‌ی مرورگر (از ``--import-session`` یا کادر پنل) را روی session می‌گذارد.

    با ``quiet=True`` جای جزئیات، فقط یک خط خلاصه چاپ می‌شود (برای اجرای دوباره پیش از ارسال).
    """
    base = args.base_url.rstrip("/")
    captured = load_captured_session(Path(args.token_file), base)
    if not captured:
        return None
    summary = apply_captured(session, base, captured, None if quiet else log)
    if quiet:
        applied = [name for name in summary["cookies"]]
        log(f"🧩 نشست مرورگر دوباره اعمال شد (تا پاسخ‌های سرور مقدارهای آن را بازنویسی نکنند): "
            f"{len(applied)} کوکی [{', '.join(applied) or '—'}]")
    return summary


def run_bootstrap(session: requests.Session, args, log, *, budget: float | None = None,
                  timeout: float | None = None) -> dict | None:
    """bootstrap رفتار مرورگر (بارگذاری صفحه + تازه‌کردن کوکی کپچا) — اگر خاموش نباشد."""
    base = args.base_url.rstrip("/")
    mode = normalize_mode(getattr(args, "bootstrap", None))
    if mode == "off":
        return None
    if timeout is None:
        timeout = min(float(getattr(args, "timeout", 10.0) or 10.0), 10.0)
    report = browser_bootstrap(session, base, log=log, mode=mode,
                               captcha_url=getattr(args, "captcha_url", None),
                               timeout=timeout, budget=budget)
    for line in security_cookie_warnings(session, base):
        log(yellow(line))
    return report


def run_browser_login(session: requests.Session, args, log) -> dict:
    """
    ورود با مرورگر واقعی (Playwright) روی همین سرور و ذخیره‌ی نشست آن.

    این تنها راه گرفتن کوکی‌هایی است که مرورگر با اجرای جاوااسکریپت (چالش فایروال)
    می‌گیرد؛ همان کوکی‌هایی که نبودشان باعث ۴۰۳/۹۰۰۹ می‌شود.
    """
    from browser_capture import capture_browser_session, captcha_provider_from_portal, session_json
    base = args.base_url.rstrip("/")
    probe = None
    if getattr(args, "browser_probe", False):
        from browser_order import probe_in_page
        probe = lambda page: probe_in_page(page, base + ORDER_PATH,           # noqa: E731
                                           probe_payload(args), headers=session.headers)
    username = (getattr(args, "username", None) or "").strip() or input("نام کاربری: ").strip()
    password = getattr(args, "password", None) or getpass.getpass("رمز عبور (نمایش داده نمی‌شود): ")

    portal: CaptchaPortal | None = None
    want_port = resolve_mode(getattr(args, "captcha_web", None))
    if want_port is not None:
        portal = CaptchaPortal(log=log, host=getattr(args, "captcha_web_host", None) or "0.0.0.0",
                               port=want_port, ttl=CAPTCHA_TTL)
        if not portal.start():
            log("⚠️  وب‌سرور کپچا بالا نیامد؛ کد را در ترمینال وارد کنید.")
            portal = None
    probe_result: dict | None = None

    def after_login(page) -> dict | None:
        """داخل همان مرورگرِ لاگین‌شده یک درخواست سفارشِ نامعتبر می‌فرستد (اختیاری)."""
        nonlocal probe_result
        if probe is None:
            return None
        log(cyan("🧪 آزمایش امنیتی داخل همین مرورگر: یک POST سفارشِ عمداً نامعتبر "
                 "(تعداد/قیمت ۰، نماد ناموجود) فرستاده می‌شود…"))
        try:
            probe_result = probe(page)
        except Exception as e:  # noqa: BLE001
            log(yellow(f"⚠️  آزمایش داخل مرورگر ناموفق بود: {e}"))
            return None
        status = int(probe_result.get("status") or 0)
        body = str(probe_result.get("body") or "")
        log(f"🧪 پاسخ مرورگر: HTTP {status or 'ERR'}  ({probe_result.get('ms', 0)}ms)\n{body[:800]}")
        if status == 422:
            log(green("✅ امنیت پاس شد (۴۲۲ = درخواست معتبر است، فقط بدنه‌ی سفارش نامعتبر بود). "
                      "یعنی همین مرورگر می‌تواند سفارش بفرستد → با --browser-order اجرا کنید."))
        elif status in (401, 403):
            log(red("⛔ همان مرورگر هم رد شد؛ مشکل از هدر/کوکی نیست، از نشست/توکن یا سطح دسترسی "
                    "است (توکن را روی همین سرور دوباره بگیرید)."))
        return probe_result

    try:
        bundle = capture_browser_session(
            base, username=username, password=password, otp=getattr(args, "otp", None) or "",
            captcha_provider=captcha_provider_from_portal(portal, log, CAPTCHA_TTL),
            log=log, headless=not getattr(args, "browser_show", False),
            timeout=float(getattr(args, "browser_timeout", 90.0) or 90.0),
            after_login=after_login,
        )
    finally:
        if portal is not None:
            portal.stop()
    if probe_result is not None:
        bundle["probe"] = probe_result
    apply_import_session(session, args, log, text=session_json(bundle))
    if bundle.get("storage"):
        names = ", ".join(sorted(bundle["storage"].keys()))
        log(f"ℹ️  localStorage/sessionStorage مرورگر هم گرفته شد ({names or '—'}).")
    return bundle


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


def _short(value: str, head: int = 12) -> str:
    value = str(value)
    return value if len(value) <= head else f"{value[:head]}…({len(value)} کاراکتر)"


def _mask_cookie(value: str) -> str:
    """``Cookie`` را به فهرست «نام + مقدار کوتاه‌شده» تبدیل می‌کند."""
    out = []
    for part in value.split(";"):
        if "=" in part:
            name, val = part.split("=", 1)
            out.append(f"{name.strip()}={_short(val.strip(), 8)}")
        elif part.strip():
            out.append(part.strip())
    return "; ".join(out)


def format_request(request, *, mask: bool = True) -> str:
    """
    درخواستی که واقعاً فرستاده شده را به شکل DevTools (خط اول + هدرها + بدنه) برمی‌گرداند.

    با ``mask=True`` مقدار کوکی/توکن کوتاه می‌شود تا لاگ قابل اشتراک‌گذاری باشد.
    """
    if request is None:
        return "<درخواست ثبت نشد>"
    headers = {k: v for k, v in (getattr(request, "headers", None) or {}).items()}
    if not any(k.lower() == "host" for k in headers):
        host = requests.utils.urlparse(getattr(request, "url", "") or "").netloc
        if host:
            headers = {"Host": host, **headers}
    body = getattr(request, "body", None)
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    lines = [f"{getattr(request, 'method', 'POST')} {requests.utils.urlparse(getattr(request, 'url', '')).path} HTTP/1.1"]
    for name, value in headers.items():
        low = name.lower()
        if mask and low == "cookie":
            value = _mask_cookie(value)
        elif mask and low == "authorization":
            value = _short(value)
        lines.append(f"{name}: {value}")
    if body:
        lines.append("")
        lines.append(str(body))
    return "\n".join(lines)


def preview_request(session: requests.Session, method: str, url: str, payload=None,
                    *, mask: bool = True) -> str:
    """درخواستی را که *فرستاده می‌شود* بدون ارسال می‌سازد و قالب‌بندی می‌کند (برای dry-run)."""
    try:
        prepared = session.prepare_request(requests.Request(method, url, data=payload))
    except Exception as e:  # noqa: BLE001
        return f"<ساخت پیش‌نمایش درخواست ناموفق بود: {e}>"
    return format_request(prepared, mask=mask)


def identity_notes(session: requests.Session) -> list[str]:
    """هشدارهای مربوط به هدرهای شناسایی (x-app-n / clientid) برای لاگ."""
    notes = []
    app_n = session.headers.get("x-app-n")
    if app_n is None:
        notes.append("⚠️  هدر x-app-n فرستاده نمی‌شود؛ اگر ۹۰۰۹ گرفتید مقدار مرورگر را با "
                     "--app-n یا -H 'x-app-n: …' بدهید.")
    elif re.fullmatch(r"NaN\.[0-9]+", str(app_n).strip()):
        notes.append("⚠️  x-app-n الگوی جایگزین «NaN.<عدد>» است؛ نمونه‌ی مرورگر شکل "
                     "<۱۳ رقم>.<۸ رقم> دارد. اگر ۴۰۳/۹۰۰۹ گرفتید مقدار مرورگر را با --app-n بدهید "
                     "یا با «python probe_order.py --app-n-candidate <مقدار> --yes» امتحان کنید.")
    notes.append(f"ℹ️  هدرهای شناسایی: clientid={session.headers.get('clientid', '«فرستاده نمی‌شود»')!r}"
                 f"  x-app-n={app_n if app_n is not None else '«فرستاده نمی‌شود»'!r}")
    return notes


# --------------------------------------------------------------------------- #
#  عکسِ لحظه‌ای از نشست + چک‌لیستِ امنیتی (برای دیباگِ ۴۰۳/۹۰۰۹)
# --------------------------------------------------------------------------- #
def session_snapshot(session: requests.Session, base: str, *, token: str | None = None,
                     auth_mode: str | None = None) -> dict:
    """
    وضعیتِ نشست را برای لاگ توصیف می‌کند — **بدون هیچ مقدار حساس**.

    فقط نام کوکی‌ها (نه مقدار)، حضور/شکلِ هدرهای شناسایی، و سنِ توکن. این
    همان چیزی است که هنگام ردِ امنیتی لازم داریم: «این درخواست با کدام نشست و
    کدام هدرها رفت؟»
    """
    summary = session_summary(session, base)
    host = requests.utils.urlparse(base).hostname or ""
    jar = [c for c in session.cookies if cookie_matches_host(getattr(c, "domain", "") or "", host)]
    if token is None:      # توکنِ نشست را از کوکی‌اش بخوان (بدون نیاز به ارجاع از بیرون)
        for cookie in jar:
            if getattr(cookie, "name", "") == TOKEN_COOKIE and getattr(cookie, "value", ""):
                token = cookie.value
                break
    names = sorted({getattr(c, "name", "") for c in jar if getattr(c, "name", "")})
    # هدرهایی که **واقعاً** با درخواست سفارش می‌روند (شامل هدر Cookie که requests
    # از cookie-jar می‌سازد) — بدون ارسالِ هیچ درخواستی.
    try:
        prepped = session.prepare_request(requests.Request("POST", base + ORDER_PATH, data=b"{}"))
        sent_headers = prepped.headers
    except Exception:  # noqa: BLE001
        sent_headers = session.headers
    low_headers = {str(k).lower() for k in sent_headers}
    info: dict = {
        "base": base,
        "auth_mode": auth_mode,
        "cookie_names": names,
        "token_cookie": TOKEN_COOKIE in names,
        "token_cookie_count": sum(1 for c in jar if getattr(c, "name", "") == TOKEN_COOKIE),
        "authorization_header": "authorization" in low_headers,
        "missing_browser_cookies": summary.get("missing_browser_cookies", []),
        "identity_headers": {k: sent_headers.get(k) for k in ("x-app-n", "clientid")
                             if k in low_headers},
        "headers": redact_headers(sent_headers),
    }
    if token:
        payload = jwt_payload(token)
        exp = jwt_exp(token)
        info["token"] = {
            "present": True,
            "sub": payload.get("sub"),
            "expires_at": (datetime.fromtimestamp(exp).isoformat(timespec="seconds") if exp else None),
            "expires_in_s": int(exp - time.time()) if exp else None,
            "expired": bool(exp and exp <= time.time()),
        }
    else:
        info["token"] = {"present": bool(token)}
    return info


def log_snapshot(event: str, session: requests.Session, base: str, *, token: str | None = None,
                 auth_mode: str | None = None, level: int = logging.INFO, message: str | None = None,
                 **fields) -> dict:
    """یک :func:`session_snapshot` کامل در لاگ می‌نویسد و آن را برمی‌گرداند."""
    snap = session_snapshot(session, base, token=token, auth_mode=auth_mode)
    payload = {k: v for k, v in snap.items() if k != "headers"}
    if LOG.isEnabledFor(logging.DEBUG):     # هدرهای کامل فقط در سطح debug
        payload["headers"] = snap["headers"]
    payload.update(fields)
    emit(LOG, level, event, message, **payload)
    return snap


def security_checklist(session: requests.Session, base: str, *, token: str | None = None,
                       response=None, clock_offset: float | None = None) -> list[str]:
    """
    چک‌لیستِ «چرا کارگزاری درخواست را امنیتی رد کرد؟».

    هر خط یک فرضیه‌ی قابل بررسی است (توکن، کوکیِ چالش، شکلِ x-app-n،
    referer/origin، ساعت سیستم و …) و مستقیماً در لاگ نوشته می‌شود تا هنگام
    ۴۰۳/۹۰۰۹ لازم نباشد حدس بزنیم.
    """
    snap = session_snapshot(session, base, token=token)
    host = requests.utils.urlparse(base).hostname or ""
    checks: list[str] = []

    info = snap.get("token") or {}
    if not info.get("present"):
        checks.append("✘ هیچ توکنی روی نشست نیست (لاگین انجام نشده یا توکن منقضی بوده است).")
    elif info.get("expired"):
        checks.append("✘ توکن منقضی شده است؛ دوباره لاگین کنید (--login).")
    else:
        left = info.get("expires_in_s")
        checks.append(f"✔ توکن معتبر است (حدود {left} ثانیه تا انقضا)"
                      if left is not None else "✔ توکن روی نشست ست شده است.")

    if snap["auth_mode"] in (None, "cookie", "both"):
        if not snap["token_cookie"]:
            checks.append(f"✘ کوکی {TOKEN_COOKIE} برای {host} در نشست نیست "
                          "(--auth-mode cookie یا both را بررسی کنید).")
        elif snap["token_cookie_count"] > 1:
            checks.append(f"⚠ {snap['token_cookie_count']} مقدار مختلف برای کوکی {TOKEN_COOKIE} "
                          "در نشست است؛ احراز هویت مبهم می‌شود (نشست را پاک و دوباره لاگین کنید).")
        else:
            checks.append(f"✔ کوکی {TOKEN_COOKIE} دقیقاً یک بار ارسال می‌شود.")
    if snap["authorization_header"]:
        checks.append("ℹ هدر Authorization هم فرستاده می‌شود (--auth-mode bearer/both).")

    missing = snap["missing_browser_cookies"]
    if missing:
        checks.append("⚠ کوکی‌های چالش/مرورگر که در این نشست نیستند: " + ", ".join(missing)
                      + " — با --import-session (Copy as cURL) یا --browser-login اضافه کنید.")
    else:
        checks.append("✔ کوکی‌های چالشِ شناخته‌شده در نشست هستند.")

    app_n = (snap["identity_headers"] or {}).get("x-app-n")
    if app_n is None:
        checks.append("⚠ هدر x-app-n فرستاده نمی‌شود؛ اگر مرورگر آن را می‌فرستد با --app-n بدهید.")
    elif re.fullmatch(r"NaN\.[0-9]+", str(app_n).strip()):
        checks.append("⚠ x-app-n الگوی «NaN.<عدد>» دارد (شکلِ نمونه‌ی مرورگر <۱۳ رقم>.<۸ رقم> است)؛ "
                      "مقدار واقعی را با --app-n بدهید.")
    else:
        checks.append(f"✔ x-app-n ست شده است ({app_n}).")
    checks.append("ℹ clientid=" + repr((snap["identity_headers"] or {}).get("clientid", "«فرستاده نمی‌شود»")))

    headers = {k.lower(): v for k, v in session.headers.items()}
    origin_ok = str(headers.get("origin", "")).rstrip("/") == base
    referer = str(headers.get("referer", ""))
    checks.append(f"{'✔' if origin_ok else '⚠'} origin={'هم‌ریشه با کارگزار' if origin_ok else headers.get('origin')}")
    checks.append(f"{'✔' if referer.startswith(base) else '⚠'} referer={referer or '«ست نشده»'}")

    if response is not None:
        set_cookie = response.headers.get("set-cookie")
        if set_cookie:
            names = [p.split("=")[0].strip() for p in set_cookie.split(",") if "=" in p]
            checks.append("ℹ کارگزار در همین پاسخ کوکی ست کرده است: " + (", ".join(names) or "?"))
        if response.status_code in (301, 302, 303, 307, 308):
            checks.append(f"✘ پاسخ ریدایرکت ({response.status_code}) است؛ یعنی نشست از دید کارگزار "
                          "معتمد نبود (معمولاً توکن/کوکیِ چالش).")

    if clock_offset is not None and abs(clock_offset) > 2:
        checks.append(f"⚠ اختلاف ساعت شما با سرور کارگزاری {clock_offset:+.1f}s است؛ "
                      "برای درخواست‌های زمان‌دار/امضا‌شده مشکل‌ساز است (--time-sync ntp).")
    return checks


def warmup(session: requests.Session, base: str, tz) -> None:
    """برقراری اتصال TLS قبل از زمان هدف + نمایش اختلاف ساعت با سرور."""
    try:
        t0 = time.time()
        r = session.get(base + "/", timeout=3, allow_redirects=False)
        t1 = time.time()
        rtt = (t1 - t0) * 1000
        msg = f"🔌 اتصال آماده شد (HTTP {r.status_code}, RTT ≈ {rtt:.0f}ms)"
        date_h = r.headers.get("Date")
        offset = None
        if date_h:
            server = parsedate_to_datetime(date_h).timestamp() + 0.5
            offset = server - ((t0 + t1) / 2 + clock.offset)  # دقت حدود ±۰.۵ ثانیه (هدر Date ثانیه‌ای است)
            msg += f" | ساعت سرور کارگزاری نسبت به ساعت همگام‌شده: {offset:+.1f}s"
        emit(LOG, logging.INFO, "session.warmup", msg, status=r.status_code,
             rtt_ms=round(rtt, 1), server_offset_s=None if offset is None else round(offset, 2))
        log(cyan(msg))
    except Exception as e:  # noqa: BLE001
        log(yellow(f"⚠️  warm-up ناموفق بود (مشکلی نیست، ادامه می‌دهیم): {e}"))


# --------------------------------------------------------------------------- #
#  ارسال سفارش
# --------------------------------------------------------------------------- #
class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.planned = 0
        self.sent = 0
        self.success = 0
        self.failed = 0
        self.stop_reason: str | None = None
        self.results: list[tuple[int, str, int | None, str]] = []
        # فقط یک‌بار در هر اجرا، درخواستِ ردشده را کامل چاپ می‌کنیم (نه ۳۲ بار)
        self.request_dumped = False


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


def _log_stop(stats: Stats, remaining: int) -> None:
    """توقفِ ارسال را هم روی ترمینال می‌نویسد و هم در لاگ (با علت و تعدادِ باقی‌مانده)."""
    with stats.lock:
        reason = stats.stop_reason
    emit(LOG, logging.ERROR if reason == "security" else logging.WARNING,
         "run.stopped", stop_message(stats, remaining),
         reason=reason or "user", remaining=remaining,
         sent=stats.sent, success=stats.success, failed=stats.failed)
    log(stop_message(stats, remaining))


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
               stop_on_success: bool, *, base: str | None = None) -> None:
    sent_at = now_str(tz)
    t0 = time.perf_counter()
    site = base or "/".join(url.split("/")[:3])
    # هدر/بدنه‌ای که واقعاً می‌رود: در سطح debug همیشه لاگ می‌شود تا بعداً بتوان
    # درخواستِ ربات را با درخواستِ مرورگر (DevTools) مقایسه کرد.
    if LOG.isEnabledFor(logging.DEBUG):
        try:
            prepped = session.prepare_request(requests.Request("POST", url, data=payload))
            emit(LOG, logging.DEBUG, "order.request", f"#{idx:02d} → POST {url}",
                 idx=idx, url=url, headers=redact_headers(prepped.headers),
                 body=payload.decode("utf-8", "replace") if isinstance(payload, bytes) else payload)
        except Exception as e:  # noqa: BLE001
            emit(LOG, logging.DEBUG, "order.request", f"#{idx:02d} آماده‌سازی درخواست ناموفق: {e}",
                 idx=idx, url=url)
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
        show_request = False
        with stats.lock:
            stats.success += ok
            stats.failed += (not ok)
            stats.results.append((idx, sent_at, r.status_code, desc))
            if not ok and not stats.request_dumped:
                # عیب‌یابی: عینِ درخواستی که رفت، یک‌بار چاپ می‌شود (مقادیر حساس کوتاه‌شده)
                stats.request_dumped = True
                show_request = True
            if rejected or (ok and stop_on_success):
                if stats.stop_reason is None:
                    stats.stop_reason = "security" if rejected else "success"
                stop_evt.set()
        head = f"#{idx:02d}  ارسال {sent_at}  ←  دریافت {now_str(tz)}  ({ms:.0f}ms)  HTTP {r.status_code}"
        extra = ""
        # ---- لاگِ ساخت‌یافته‌ی نتیجه (فایل لاگ/سطح debug) ----
        result_fields = {"idx": idx, "status": r.status_code, "elapsed_ms": round(ms, 1),
                         "ok": ok, "rejected": rejected, "sent_at": sent_at,
                         "content_type": r.headers.get("content-type"),
                         "redirect_to": r.headers.get("location"),
                         "set_cookie_names": [p.split("=")[0].strip()
                                              for p in (r.headers.get("set-cookie") or "").split(",")
                                              if "=" in p] or None}
        if isinstance(data, dict):
            result_fields["error_code"] = data.get("errorCode")
            result_fields["description"] = desc
        if LOG.isEnabledFor(logging.DEBUG):
            result_fields["response_headers"] = redact_headers(r.headers)
            result_fields["response_body"] = (body or "")[:4000]
        emit(LOG, logging.INFO if ok else logging.WARNING,
             "order.result" if ok else "order.failed", head, **result_fields)
        if rejected:
            # ردِ احراز هویت/امنیت: خطا با بالاترین سطح + چک‌لیستِ فرضیه‌ها
            emit(LOG, logging.ERROR, "order.security_rejected",
                 f"#{idx:02d} کارگزاری درخواست را با HTTP {r.status_code} و خطای امنیتی رد کرد؛ "
                 "ادامه‌ی ارسال متوقف می‌شود",
                 idx=idx, status=r.status_code,
                 error_code=(data or {}).get("errorCode") if isinstance(data, dict) else None,
                 description=desc,
                 request=format_request(getattr(r, "request", None), mask=True),
                 response_body=(body or "")[:4000],
                 checklist=security_checklist(session, site, response=r,
                                              clock_offset=clock.offset),
                 hint="برای مقایسه با مرورگر: DevTools ← Copy as fetch ← "
                      "python compare_request.py <فایل> | یا python probe_order.py --app-n-candidate <مقدار> --yes")
        if not ok:
            hint = order_hint(r.status_code, data if data is not None else body)
            if hint:
                extra = "\n" + yellow(hint)
            if show_request:
                extra += ("\n" + cyan("📤 درخواستی که فرستاده شد (مقدار کوکی/توکن کوتاه شده) — این را با "
                                      "درخواست مرورگر در DevTools مقایسه کنید:") + "\n"
                          + format_request(getattr(r, "request", None), mask=True))
        log((green("✔ " + head) if ok else red("✘ " + head)) + "\n" + body + extra + "\n" + "─" * 60)
    except Exception as e:  # noqa: BLE001
        ms = (time.perf_counter() - t0) * 1000
        with stats.lock:
            stats.failed += 1
            stats.results.append((idx, sent_at, None, str(e)))
        emit(LOG, logging.ERROR, "order.network_error", f"#{idx:02d} خطای شبکه: {e}",
             idx=idx, elapsed_ms=round(ms, 1), url=url, error=repr(e))
        log(red(f"✘ #{idx:02d}  ارسال {sent_at}  ({ms:.0f}ms)  خطای شبکه: {e}") + "\n" + "─" * 60)


# --------------------------------------------------------------------------- #
#  ارسال از داخل مرورگر واقعی (Playwright) — راه پشتیبان برای ۴۰۳/۹۰۰۹
# --------------------------------------------------------------------------- #
def probe_payload(args) -> bytes:
    """
    بدنه‌ی سفارشِ عمداً نامعتبر برای «آزمایشِ امنیتی» از داخل مرورگر: نماد ناموجود،
    تعداد ۰ و قیمت ۰ → هیچ سفارش واقعی ثبت نمی‌شود؛ ولی اگر پاسخ `422` باشد یعنی
    لایه‌ی امنیتی درخواست را پذیرفته است (همان نشانه‌ای که در probe_order.py هم هست).
    """
    from probe_order import safe_body
    body = safe_body(0, 0)
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def browser_orders_available() -> bool:
    """آیا مسیر «ارسال از داخل مرورگر واقعی» در دسترس است؟"""
    try:
        from browser_order import browser_available
    except Exception:  # noqa: BLE001
        return False
    return browser_available()


def browser_session_bundle(session: requests.Session, args, base: str) -> dict:
    """
    نشستِ مناسب برای مرورگر: کوکی/هدر/استوریجِ ذخیره‌شده (از --import-session یا
    --browser-login) و اگر نبود، کوکی‌های نشست فعلی ربات.
    """
    bundle = load_captured_session(Path(args.token_file), base) or {}
    cookies = bundle.get("cookies") or []
    if not cookies:
        from exir_auth import session_cookies
        cookies = [[c["name"], c["value"]] for c in session_cookies(session, base) if c.get("name")]
    return {"kind": bundle.get("kind") or "token", "url": bundle.get("url") or base + "/",
            "cookies": cookies, "headers": dict(bundle.get("headers") or {}),
            "storage": dict(bundle.get("storage") or {}),
            "user_agent": bundle.get("user_agent") or ""}


def record_browser_result(res: dict, *, tz, stats: Stats, log, offset_ms: int = 0,
                          stop_on_success: bool = True) -> bool:
    """
    نتیجه‌ی یک درخواستِ داخل مرورگر را با همان قالب لاگ/آمارِ send_order چاپ می‌کند.

    خروجی: آیا باید ارسال بقیه‌ی درخواست‌ها متوقف شود؟
    """
    idx = int(res.get("k") or 0)
    status = int(res.get("status") or 0)
    sent_ms = res.get("sent") or 0
    got_ms = res.get("got") or sent_ms
    sent_dt = datetime.fromtimestamp((int(sent_ms) - offset_ms) / 1000, tz)
    got_dt = datetime.fromtimestamp((int(got_ms) - offset_ms) / 1000, tz)
    ms = max(0, int(got_ms) - int(sent_ms))
    text = str(res.get("body") or "")
    try:
        data = json.loads(text) if text.strip() else None
        body = json.dumps(data, ensure_ascii=False, indent=2) if data is not None else (text[:2000] or "<empty>")
    except ValueError:
        data = None
        body = text[:2000] or "<empty>"
    network_error = res.get("error")
    ok = bool(status) and is_success(status, data)
    rejected = bool(status) and security_rejected(status, data)
    desc = ""
    if isinstance(data, dict):
        desc = str(data.get("description") or data.get("message") or data.get("type") or "")
    if network_error:
        desc = str(network_error)
    should_stop = False
    with stats.lock:
        stats.sent += 1
        stats.success += ok
        stats.failed += (not ok)
        stats.results.append((idx, sent_dt.strftime("%H:%M:%S.%f")[:-3], status or None, desc or ""))
        if rejected or (ok and stop_on_success):
            if stats.stop_reason is None:
                stats.stop_reason = "security" if rejected else "success"
            should_stop = True
    head = (f"#{idx:02d}  ارسال {sent_dt.strftime('%H:%M:%S.%f')[:-3]}  ←  دریافت "
            f"{got_dt.strftime('%H:%M:%S.%f')[:-3]}  ({ms}ms)  HTTP {status or 'ERR'}  🌐مرورگر")
    extra = ""
    fields = {"idx": idx, "status": status or None, "elapsed_ms": ms, "ok": ok, "rejected": rejected,
              "browser": True, "error": network_error, "description": desc or None}
    if isinstance(data, dict):
        fields["error_code"] = data.get("errorCode")
    if LOG.isEnabledFor(logging.DEBUG):
        fields["response_body"] = (body or "")[:4000]
    emit(LOG, logging.INFO if ok else logging.WARNING,
         "order.result" if ok else "order.failed", head, **fields)
    if rejected:
        emit(LOG, logging.ERROR, "order.security_rejected",
             f"#{idx:02d} کارگزاری درخواستِ داخل مرورگر را با HTTP {status} رد کرد؛ ارسال متوقف می‌شود",
             idx=idx, status=status, browser=True, description=desc,
             response_body=(body or "")[:4000],
             hint="حتی درخواستِ مرورگرِ واقعی رد شده است: کوکی/هدرِ نشست را با "
                  "--browser-login دوباره بسازید و با probe_order.py بررسی کنید.")
    if not ok:
        hint = order_hint(status, data if data is not None else body)
        if hint:
            extra = "\n" + yellow(hint)
    log((green("✔ " + head) if ok else red("✘ " + head)) + "\n" + body + extra + "\n" + "─" * 60)
    return should_stop


def run_browser_orders(session: requests.Session, args, log, *, base: str, url: str, payload: bytes,
                       schedule: list[float], stats: Stats, stop_evt: threading.Event, tz) -> None:
    """سفارش‌ها را از داخل یک مرورگر واقعی (Chromium) و در زمان‌بندی دقیق می‌فرستد."""
    from browser_order import BrowserOrders, identity_headers_from_session_url

    bundle = browser_session_bundle(session, args, base)
    headers = identity_headers_from_session_url(base, bundle, session)
    cookie_names = sorted({str(c[0]) for c in bundle["cookies"]
                           if isinstance(c, (list, tuple)) and c})
    shown = [f"{k}={_short(str(v), 12)}" for k, v in sorted(headers.items())
             if k.lower() in ("x-app-n", "clientid")]
    log(cyan(f"🌐 ارسال از داخل مرورگر واقعی: {len(bundle['cookies'])} کوکی "
             f"[{', '.join(cookie_names) or '—'}] | هدرهای شناسایی: {'، '.join(shown) or '—'}"))
    if not bundle["cookies"]:
        log(yellow("⚠️  هیچ کوکی‌ای برای مرورگر پیدا نشد؛ اول لاگین کنید (یا --browser-login)."))

    orders = BrowserOrders(base, bundle=bundle, headless=not getattr(args, "browser_show", False),
                           log=log, timeout=max(30.0, float(getattr(args, "browser_timeout", 60.0))))
    orders.open()
    try:
        orders.warm()
        times_ms = [int(round(ts * 1000)) for ts in schedule]
        report = orders.schedule(url, payload, times_ms, headers=headers, stop_on_security=True)
        log(cyan(f"🌐 {report.get('planned', 0)} درخواست داخل مرورگر زمان‌بندی شد "
                 f"(اختلاف ساعت مرورگر و ساعت مرجع {report.get('offset_ms', 0):+d}ms)."))
        offset_ms = int(report.get("offset_ms") or 0)
        seen = 0
        deadline = schedule[-1] + max(15.0, float(args.timeout) * 3)
        while True:
            if stop_evt.is_set():
                orders.request_stop()
            try:
                results = sorted(orders.results(), key=lambda r: r.get("k") or 0)
            except Exception as e:  # noqa: BLE001  (مرورگر بسته شده/صفحه عوض شده)
                log(yellow(f"⚠️  خواندن نتیجه‌های مرورگر ناموفق بود: {e}"))
                break
            while seen < len(results):
                should_stop = record_browser_result(results[seen], tz=tz, stats=stats, log=log,
                                                    offset_ms=offset_ms,
                                                    stop_on_success=not args.no_stop)
                seen += 1
                if should_stop:
                    stop_evt.set()
                    orders.request_stop()
            state_info = orders.state()
            if state_info.get("done") or seen >= len(times_ms):
                break
            if clock.now() > deadline:
                log(yellow("⚠️  مهلت دریافت پاسخ‌های مرورگر تمام شد؛ بقیه در گزارش نیست."))
                break
            time.sleep(0.05)
    finally:
        orders.close()


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


def parse_args(argv=None) -> argparse.Namespace:
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
    g.add_argument("--clientid", default=os.environ.get("EXIR_CLIENTID"),
                   help="مقدار هدر clientid (پیش‌فرض: مثل درخواست ورودِ مرورگر، خالی). "
                        "«off» بدهید تا این هدر اصلاً فرستاده نشود (یا EXIR_CLIENTID)")
    g.add_argument("--bootstrap", choices=["off", "page", "captcha", "page+captcha"],
                   default=os.environ.get("EXIR_BOOTSTRAP", "page+captcha"),
                   help="رفتار مرورگر با همان نشست ربات پیش از ورود/ارسال: بارگذاری صفحه‌ها و/یا "
                        "تازه‌کردن کوکی کپچا (رفع ۴۰۳/۹۰۰۹). «off» = خاموش (یا EXIR_BOOTSTRAP)")
    g.add_argument("--import-session", metavar="FILE",
                   help="نشست مرورگر را از خروجی DevTools (Copy as cURL / Copy as fetch / هدرهای خام) "
                        "یا رشته‌ی Cookie بخوان؛ فایل یا «-» برای stdin. کوکی/هدرها در فایل توکن ذخیره می‌شوند")
    g.add_argument("--browser-login", action="store_true",
                   help="ورود با مرورگر واقعی (Playwright) روی همین سرور و ذخیره‌ی کوکی/هدرهای آن "
                        "(قطعی‌ترین راه برای کوکی چالش فایروال)؛ نیاز به: python -m playwright install chromium")
    g.add_argument("--browser-show", action="store_true",
                   help="مرورگر Playwright را با پنجره اجرا کن (اگر نمایشگر دارید؛ پیش‌فرض: بی‌سر)")
    g.add_argument("--browser-timeout", type=float, default=90.0,
                   help="مهلت ورود/بالا آمدن مرورگر (ثانیه)")
    g.add_argument("--browser-order", action="store_true",
                   help="سفارش‌ها را از داخل مرورگر واقعی (Playwright) بفرست، نه با requests — "
                        "بالاترین وفاداری به درخواست مرورگر برای دور زدن ۴۰۳/۹۰۰۹ "
                        "(نیاز به: python -m playwright install chromium)")
    g.add_argument("--browser-probe", action="store_true",
                   help="با --browser-login: بعد از ورود، همان مرورگر یک درخواست سفارشِ عمداً "
                        "نامعتبر می‌فرستد و پاسخ را چاپ می‌کند (هیچ سفارش واقعی ثبت نمی‌شود)")
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
    g = p.add_argument_group("لاگ / دیباگ (برای رفع ۴۰۳/۹۰۰۹)")
    g.add_argument("--log-level", choices=sorted(LEVELS),
                   default=(os.environ.get("EXIR_LOG_LEVEL") or "info").strip().lower(),
                   help="سطح لاگ: debug = هدرها و بدنه‌ی کامل هر درخواست/پاسخ (مقادیر حساس پوشیده می‌شود)")
    g.add_argument("--log-file", default=os.environ.get("EXIR_LOG_FILE"),
                   help="مسیر فایل لاگ (چرخشی؛ پیش‌فرض: فقط ترمینال). مثال: logs/exir.log")
    g.add_argument("--log-format", choices=["text", "json"],
                   default=(os.environ.get("EXIR_LOG_FORMAT") or "text").strip().lower(),
                   help="قالب فایل لاگ: متن خوانا یا JSON یک‌خطی (برای jq)")
    g.add_argument("--log-console", choices=["auto", "on", "off"],
                   default=(os.environ.get("EXIR_LOG_CONSOLE") or "auto").strip().lower(),
                   help="نمایش لاگ روی ترمینال: auto = فقط warning به بالا (خروجی رنگی تکرار نمی‌شود)")
    p.add_argument("--now", action="store_true", help="بدون انتظار، همین الان شروع کن (برای تست)")
    p.add_argument("--dry-run", action="store_true", help="فقط نمایش درخواست، بدون ارسال")
    p.add_argument("-y", "--yes", action="store_true", help="بدون پرسیدن تأیید نهایی")
    return p.parse_args(argv)


def main() -> None:
    args = parse_args()
    interactive = sys.stdin.isatty()

    # ---------- لاگینگ (پیش از هر کاری، تا خطاهای زودهنگام هم ثبت شوند) ----------
    if args.log_level not in LEVELS:      # مقدارِ نامعتبر از متغیر محیطی
        args.log_level = "info"
    setup_logging(args.log_level, args.log_file, args.log_format, console=args.log_console)
    install_excepthook(LOG)
    emit(LOG, logging.INFO, "run.start", "اجرای ربات شروع شد",
         base=args.base_url, tz=args.tz or "system", side=args.side,
         duration=args.duration, interval_ms=args.interval, timeout=args.timeout,
         auth_mode=args.auth_mode, bootstrap=getattr(args, "bootstrap", None),
         browser_order=bool(getattr(args, "browser_order", False)),
         dry_run=bool(args.dry_run), log_level=args.log_level,
         log_file=args.log_file or None, log_format=args.log_format)

    tz = None
    if args.tz and ZoneInfo is not None:
        try:
            tz = ZoneInfo(args.tz)
        except Exception:  # noqa: BLE001
            log(yellow(f"⚠️  منطقه‌ی زمانی «{args.tz}» شناخته نشد؛ از ساعت سیستم استفاده می‌شود."))

    log(bold(cyan("\n═══════════  ربات سفارش Exir  ═══════════\n")))

    base = args.base_url.rstrip("/")
    session = build_session(args, pool=64)

    # ---------- نشستِ مرورگر (کوکی/هدرهای import‌شده) + bootstrap رفتار مرورگر ----------
    try:
        if getattr(args, "import_session", None):
            apply_import_session(session, args, log)
        else:
            apply_saved_captured_session(session, args, log)
    except Exception as e:  # noqa: BLE001
        log(red(f"✘ خواندن «نشست مرورگر» ناموفق بود: {e}"))
        sys.exit(2)
    if not args.dry_run or args.login or args.login_only:
        run_bootstrap(session, args, log)

    # ---------- ورود با مرورگر واقعی (اختیاری) ----------
    if getattr(args, "browser_login", False):
        try:
            run_browser_login(session, args, log)
        except Exception as e:  # noqa: BLE001
            log(red(f"✘ ورود با مرورگر ناموفق بود: {e}"))
            sys.exit(3)

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
    # نشست پس از لاگین/بازیابی توکن: اولین عکسِ لحظه‌ای برای دیباگِ ۴۰۳/۹۰۰۹
    log_snapshot("session.after_login", session, base, token=token, auth_mode=args.auth_mode,
                 message="نشست پس از لاگین (فقط نام کوکی‌ها، نه مقدار)")
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
    log(f"  ارسال با   : {'مرورگر واقعی (Playwright)' if getattr(args, 'browser_order', False) else 'requests'}")
    for note in identity_notes(session):
        log(yellow("  " + note) if note.startswith("⚠️") else "  " + note)
    if args.dry_run:
        log(yellow("\n[dry-run] هیچ درخواستی ارسال نشد. درخواستی که فرستاده می‌شد:"))
        log(preview_request(session, "POST", url, payload))
        emit(LOG, logging.INFO, "order.dry_run", "درخواستِ فرضی (ارسال نشد)",
             url=url, body=payload.decode("utf-8", "replace"),
             request=preview_request(session, "POST", url, payload),
             snapshot=session_snapshot(session, base, token=token, auth_mode=args.auth_mode),
             checklist=security_checklist(session, base, clock_offset=clock.offset))
        return

    if getattr(args, "browser_order", False) and not browser_orders_available():
        log(red("✘ ارسال با مرورگر واقعی خواسته شده، ولی Playwright نصب نیست."))
        log("   نصب:  python -m pip install playwright  &&  python -m playwright install chromium")
        log("   یا بدون --browser-order اجرا کنید (ارسال با requests)، یا از «Copy as cURL» + "
            "--import-session استفاده کنید.")
        sys.exit(2)

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
        # تازه‌کردن نشست/کوکی‌های چالش درست پیش از شروع (چند ثانیه مانده به ارسال)
        run_bootstrap(session, args, log, budget=3.0, timeout=min(3.0, args.timeout))
        if clock.now() < start_ts - 0.5:
            warmup(session, base, tz)
        # آخرین حرف را «نشست مرورگر» می‌زند: پاسخِ همان warm-up هم می‌تواند کوکی چالش را
        # با مقدار دیگری بازنویسی کند (سرور برای درخواستِ بدونِ نشانه‌ی مرورگر مقدار تازه می‌دهد).
        apply_saved_captured_session(session, args, log, quiet=True)
        # مهم‌ترین عکسِ لحظه‌ای: دقیقاً همان نشستی که سفارش‌ها با آن فرستاده می‌شوند
        log_snapshot("session.pre_send", session, base, token=token, auth_mode=args.auth_mode,
                     message="نشست در لحظه‌ی ارسال (آخرین bootstrap انجام شده)",
                     requests=count, start=target.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                     clock_source=clock.source, clock_offset_s=round(clock.offset, 3))

        # ---------- ارسال ----------
        emit(LOG, logging.INFO, "run.schedule", f"{count} درخواست زمان‌بندی شد",
             count=count, start=target.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
             interval_ms=args.interval, duration_s=args.duration,
             stop_on_success=not args.no_stop,
             transport="browser" if getattr(args, "browser_order", False) else "requests")
        log(bold(yellow(f"\n🚀 شروع ارسال در {target:%H:%M:%S.%f}"[:-3] + "\n")))
        if getattr(args, "browser_order", False):
            run_browser_orders(session, args, log, base=base, url=url, payload=payload,
                               schedule=schedule, stats=stats, stop_evt=stop_evt, tz=tz)
            _print_report(stats, tz)
            return
        with ThreadPoolExecutor(max_workers=min(count, 64)) as pool:
            for k, ts in enumerate(schedule, 1):
                if stop_evt.is_set():
                    _log_stop(stats, count - k + 1)
                    break
                wait_until(ts)
                if stop_evt.is_set():
                    _log_stop(stats, count - k + 1)
                    break
                with stats.lock:
                    stats.sent += 1
                pool.submit(send_order, k, session, url, payload, args.timeout, tz,
                            stats, stop_evt, not args.no_stop, base=base)
            log(cyan("… منتظر دریافت پاسخ درخواست‌های در جریان"))
    except KeyboardInterrupt:
        log(red("\n⛔ توسط کاربر متوقف شد."))

    _print_report(stats, tz)


def _print_report(stats: Stats, tz) -> None:
    """گزارش نهایی (مشترک بین ارسال با requests و داخل مرورگر)."""
    emit(LOG, logging.INFO, "run.report", "گزارش نهایی",
         sent=stats.sent, success=stats.success, failed=stats.failed,
         stop_reason=stats.stop_reason,
         results=[{"idx": i, "sent_at": at, "status": st, "description": d}
                  for i, at, st, d in sorted(stats.results)])
    log(bold("\n═══════════  گزارش نهایی  ═══════════"))
    log(f"  ارسال‌شده: {stats.sent}   موفق: {green(str(stats.success))}   ناموفق: {red(str(stats.failed))}")
    for idx, sent_at, status, desc in sorted(stats.results):
        st = status if status is not None else "ERR"
        log(f"  #{idx:02d}  {sent_at}  HTTP {st}  {desc[:100]}")


if __name__ == "__main__":
    main()
