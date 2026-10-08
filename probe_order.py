#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
کاوشِ علت خطای `HTTP 403 / errorCode 9009` در ثبت سفارش (شکار تکتک فرضیه‌ها).

مسئله: ورود موفق است، ولی اولین درخواست `POST /api/v1/order` با
«مشکل امنیتی.درخواست معتبر نمی باشد» رد می‌شود. مشخص نیست کدام تفاوتِ کوچکِ
درخواست (هدر، کوکی، referer، توکن) لایه‌ی امنیت را ناراضی می‌کند.

راه‌حل این ابزار: **حذف فرضیه‌ها**. هر «واریانت» یک تفاوت کوچک با درخواست فعلی
ربات دارد؛ اگر پاسخ از `403/9009` به یک خطای اعتبارسنجی سفارش (مثل `422`) تغییر
کند، یعنی لایه‌ی امنیت همان واریانت را پذیرفته و علت پیدا شده است.

    ⚠️ هیچ سفارش واقعی‌ای ثبت نمی‌شود: بدنه‌ی هر درخواست عمداً نامعتبر است
    (نماد ناموجود + تعداد ۰ + قیمت ۰)، پس حتی اگر امنیت اجازه بدهد، کارگزار
    سفارش را در مرحله‌ی اعتبارسنجی رد می‌کند.

نمونه:
    python probe_order.py                      # فقط فهرست واریانت‌ها (بدون شبکه)
    python probe_order.py --yes                # اجرای واقعی (کمتر از ۲۰ ثانیه)
    python probe_order.py --yes --only current --only no-clientid
    python probe_order.py --yes --app-n-candidate "2018887747744.29964494"
    python probe_order.py --yes --clientid-candidate "<مقدار مرورگر>"
    python probe_order.py --yes --json probe.json     # گزارش برای اشتراک‌گذاری
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

try:
    import requests
except ImportError:  # pragma: no cover
    print("کتابخانه‌ی requests نصب نیست. اجرا کنید:  pip install -r requirements.txt")
    sys.exit(1)

from exir_auth import (apply_token, clean_token, describe_token, jwt_exp, load_saved_token,
                       restore_session_cookies)
from exir_bot import DEFAULT_BASE_URL, ORDER_PATH, build_session, format_request

# بدنه‌ی «سالم ولی نامعتبر»: قالبِ ISIN درست است ولی چنین نمادی وجود ندارد و
# تعداد/قیمت صفر است؛ چنین سفارشی در هیچ بازاری قابل ثبت نیست.
SAFE_ISIN = "IR0000000000"
SECURITY_CODES = {"9009"}
VALIDATION_STATUSES = (400, 409, 415, 422)

VERDICT_SECURITY = "security"
VERDICT_PASSED = "passed"
VERDICT_ACCEPTED = "accepted"
VERDICT_THROTTLED = "throttled"
VERDICT_SERVER = "server"
VERDICT_REDIRECT = "redirect"
VERDICT_OTHER = "other"

_VERDICT_LABEL = {
    VERDICT_SECURITY: "✖ لایه‌ی امنیت رد کرد",
    VERDICT_PASSED: "✅ امنیت پاس شد (به اعتبارسنجی سفارش رسید)",
    VERDICT_ACCEPTED: "⚠️ پاسخ موفق دریافت شد",
    VERDICT_THROTTLED: "⏳ محدودیت نرخ (نتیجه مبهم)",
    VERDICT_SERVER: "⚠️ خطای سرور (نتیجه مبهم)",
    VERDICT_REDIRECT: "⚠️ ریدایرکت/HTML (نشست یا WAF)",
    VERDICT_OTHER: "؟ نامشخص",
}


def _c(code: str, s: str) -> str:
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return f"\033[{code}m{s}\033[0m"
    return s


def green(s): return _c("32", s)
def red(s): return _c("31", s)
def yellow(s): return _c("33", s)
def cyan(s): return _c("36", s)
def bold(s): return _c("1", s)


# --------------------------------------------------------------------------- #
#  بدنه‌ی امن
# --------------------------------------------------------------------------- #
def safe_body(quantity: int = 0, price: int = 0, isin: str = SAFE_ISIN,
              side: str = "buy", allow_real: bool = False) -> dict:
    """بدنه‌ی سفارشِ عمداً نامعتبر (کمترین ریسک: هیچ سفارشی اجرا نمی‌شود)."""
    if allow_real:
        quantity, price = int(quantity), int(price)
    return {
        "insMaxLcode": isin,
        "bankAccountId": -1,
        "side": "SIDE_SELL" if side == "sell" else "SIDE_BUY",
        "orderType": "ORDER_TYPE_LIMIT",
        "quantity": int(quantity),
        "price": int(price),
        "validityType": "VALIDITY_TYPE_DAY",
        "validityDate": "",
        "coreType": "c",
        "hasUnderCautionAgreement": True,
        "dividedOrder": False,
        "etfTypeCode": None,
    }


def body_from_file(path: str, allow_real: bool) -> tuple[dict, str]:
    """بدنه‌ی کاربر (فایل یا JSON خام) — مگر با ``--allow-real-body``، تعداد صفر می‌شود."""
    text = Path(path).read_text(encoding="utf-8") if os.path.exists(path) else path
    body = json.loads(text)
    if not isinstance(body, dict):
        raise ValueError("بدنه باید یک آبجکت JSON باشد.")
    if allow_real:
        return body, "بدنه‌ی داده‌شده، بدون تغییر (❗ممکن است سفارش واقعی ثبت شود)"
    body = dict(body)
    body["quantity"], body["price"] = 0, 0
    return body, "بدنه‌ی داده‌شده با تعداد/قیمت صفر"


# --------------------------------------------------------------------------- #
#  واریانت‌ها
# --------------------------------------------------------------------------- #
@dataclass
class Variant:
    name: str
    why: str                 # این واریانت چه چیزی را ثابت می‌کند
    fix: str = ""            # اگر این واریانت جواب داد، ربات را چطور اجرا کنیم
    mutate: Callable[[requests.Session], None] | None = None
    pre: Callable[[requests.Session], None] | None = None


@dataclass
class Result:
    variant: Variant
    status: int | None
    error_code: str
    description: str
    elapsed_ms: float
    request_dump: str = ""
    error: str = ""
    verdict: str = VERDICT_OTHER
    body_note: str = ""


def build_variants(args, base: str) -> list[Variant]:
    """فهرست فرضیه‌ها — هر کدام یک تفاوت کوچک با درخواست فعلی ربات."""

    def set_header(session, name, value):
        session.headers[name] = value

    def drop_header(session, name):
        session.headers.pop(name, None)

    def digits_app_n(session):
        set_header(session, "x-app-n", f"{random.randint(10**12, 10**13 - 1)}.{random.randint(10**7, 10**8 - 1)}")

    def warm_market_view(session):
        """مرورگر قبل از سفارش، صفحه‌ی بازار را می‌بیند (کوکی/نشانه‌ی WAF تازه می‌شود)."""
        try:
            session.get(f"{base}/new-exir/market-view", timeout=10)
        except Exception:  # noqa: BLE001
            pass

    variants = [
        Variant("current",
                "همان درخواستی که ربات الان می‌فرستد (خط پایه)",
                mutate=None),
        Variant("no-clientid",
                "هدر clientid حذف می‌شود (وضعیت نسخه‌های قبلی ربات)",
                "بات را با  --clientid off  اجرا کنید",
                mutate=lambda s: drop_header(s, "clientid")),
        Variant("no-app-n",
                "هدر x-app-n حذف می‌شود (نقش این هدر در سفارش چیست؟)",
                "در ربات:  -H 'x-app-n: '  یا حذف --app-n"),
        Variant("app-n-digits",
                "x-app-n با شکل نمونه‌ی مرورگر (۱۳ رقم . ۸ رقم) فرستاده می‌شود",
                "--app-n \"<مقدار ۱۳رقمی.۸رقمی>\"",
                mutate=digits_app_n),
        Variant("referer-login",
                "referer مثل صفحه‌ی ورود می‌شود (اختلاف ورود/سفارش)",
                f"-H 'referer: {base}/new-exir/login'",
                mutate=lambda s: set_header(s, "referer", f"{base}/new-exir/login")),
        Variant("bearer",
                "توکن در هدر Authorization (بدون کوکی JWT) — یعنی -auth-mode bearer",
                "با  --auth-mode bearer  اجرا کنید",
                mutate=lambda s: _set_bearer(s, base)),
        Variant("jwt-only-cookie",
                "تنها کوکی JWT-TOKEN می‌رود (کوکی کپچا/دیگر کوکی‌ها حذف)",
                "برای ربات: پاک‌کردن توکن و لاگین تازه، یا بررسی کوکی‌های ذخیره‌شده",
                mutate=lambda s: _keep_only_jwt(s)),
        Variant("warm-page",
                "اول صفحه‌ی market-view دیده می‌شود، بعد سفارش (رفتار مرورگر)",
                "صفحه‌ی بازار را روی همان سرور/نشست قبل از اجرا یک‌بار بخوانید",
                pre=warm_market_view),
        Variant("no-sec-headers",
                "هدرهای sec-ch-ua*/sec-fetch-* حذف می‌شوند (اثر انگشت مرورگر ناهمخوان)",
                "با  -H  قابل حذف نیست؛ لازم می‌شود کد تغییر کند",
                mutate=lambda s: [drop_header(s, k) for k in
                                  [k for k in list(s.headers) if k.lower().startswith(("sec-ch-ua", "sec-fetch-"))]]),
    ]
    if args.app_n_candidate:
        variants.insert(3, Variant("app-n-copied",
                                   "x-app-n دقیقاً همان مقدار کپی‌شده از مرورگر (قوی‌ترین آزمون)",
                                   f"--app-n \"{args.app_n_candidate}\"",
                                   mutate=lambda s: set_header(s, "x-app-n", args.app_n_candidate)))
    if args.clientid_candidate is not None:
        variants.insert(2, Variant("clientid-value",
                                   "clientid با مقدار واقعیِ دیده‌شده در مرورگر فرستاده می‌شود",
                                   f"--clientid \"{args.clientid_candidate}\"",
                                   mutate=lambda s: set_header(s, "clientid", args.clientid_candidate)))
    return variants


def _set_bearer(session: requests.Session, base: str) -> None:
    token = None
    for cookie in list(session.cookies):
        if cookie.name == "JWT-TOKEN":
            token = cookie.value
            session.cookies.clear(cookie.domain, cookie.path, cookie.name)
    if token:
        session.headers["Authorization"] = f"Bearer {token}"


def _keep_only_jwt(session: requests.Session) -> None:
    for cookie in list(session.cookies):
        if cookie.name != "JWT-TOKEN":
            session.cookies.clear(cookie.domain, cookie.path, cookie.name)


def select_variants(all_variants: list[Variant], only: list[str] | None) -> list[Variant]:
    if not only:
        return all_variants
    wanted = [n.strip().lower() for n in only if n.strip()]
    chosen = [v for v in all_variants if v.name.lower() in wanted]
    unknown = [n for n in wanted if n not in {v.name.lower() for v in chosen}]
    if unknown:
        raise SystemExit(f"✖ واریانت ناشناس: {', '.join(unknown)}  (فهرست: {', '.join(v.name for v in all_variants)})")
    return chosen


# --------------------------------------------------------------------------- #
#  نشست و اجرا
# --------------------------------------------------------------------------- #
def classify(status: int | None, data) -> tuple[str, str]:
    """``(verdict, توضیح)`` برای هر پاسخ."""
    if status is None:
        return VERDICT_OTHER, "پاسخی دریافت نشد"
    code = ""
    desc = ""
    if isinstance(data, dict):
        code = str(data.get("errorCode") or "")
        desc = str(data.get("description") or data.get("message") or "")
    if code in SECURITY_CODES or status in (401, 403):
        return VERDICT_SECURITY, f"رد امنیتی (HTTP {status}{' / ' + code if code else ''}) {desc}".strip()
    if status in VALIDATION_STATUSES:
        return VERDICT_PASSED, f"اعتبارسنجی سفارش (HTTP {status}) {desc}".strip()
    if 200 <= status < 300:
        return VERDICT_ACCEPTED, f"HTTP {status} — پاسخ موفق"
    if status in (301, 302, 303, 307, 308):
        return VERDICT_REDIRECT, f"ریدایرکت HTTP {status} (احتمالاً صفحه‌ی ورود)"
    if status == 429:
        return VERDICT_THROTTLED, "HTTP 429 — محدودیت نرخ"
    if 500 <= status < 600:
        return VERDICT_SERVER, f"HTTP {status}"
    return VERDICT_OTHER, f"HTTP {status} — الگوی ناشناس"


def build_probe_session(args, token: str, base: str) -> requests.Session:
    session = build_session(args, pool=4)
    saved = load_saved_token(Path(args.token_file), base)
    if saved:
        restore_session_cookies(session, base, saved.get("cookies", []))
        if not session.headers.get("x-app-n") and saved.get("appN"):
            session.headers["x-app-n"] = saved["appN"]
    apply_token(session, base, token, args.auth_mode)
    return session


def run_variant(variant: Variant, args, token: str, base: str, payload: bytes) -> Result:
    url = base + ORDER_PATH
    session = build_probe_session(args, token, base)
    if variant.mutate:
        variant.mutate(session)
    if variant.pre:
        variant.pre(session)
    t0 = time.perf_counter()
    try:
        r = session.post(url, data=payload, timeout=args.timeout, allow_redirects=False)
    except Exception as e:  # noqa: BLE001
        return Result(variant, None, "", "", (time.perf_counter() - t0) * 1000,
                      request_dump="", error=str(e), verdict=VERDICT_OTHER)
    elapsed = (time.perf_counter() - t0) * 1000
    try:
        data = r.json()
    except ValueError:
        data = None
    if data is None and "text/html" in r.headers.get("content-type", "").lower():
        verdict, note = VERDICT_REDIRECT, "پاسخ HTML (صفحه‌ی ورود/بلاک WAF)"
        code, desc = "", ""
    else:
        verdict, note = classify(r.status_code, data)
        code = str((data or {}).get("errorCode") or "") if isinstance(data, dict) else ""
        desc = str((data or {}).get("description") or (data or {}).get("message") or "") if isinstance(data, dict) else ""
    return Result(variant, r.status_code, code, desc, elapsed,
                  request_dump=format_request(getattr(r, "request", None), mask=True),
                  verdict=verdict, body_note=note)


def print_plan(variants: list[Variant], args, base: str) -> None:
    print(bold(cyan(f"\n🧪 کاوش علت ۴۰۳/۹۰۰۹ — {len(variants)} واریانت روی {base}{ORDER_PATH}")))
    print(f"   بدنه: {json.dumps(safe_body(allow_real=args.allow_real_body), ensure_ascii=False) if args.allow_real_body else 'نماد ناموجود + تعداد ۰ + قیمت ۰ (هیچ سفارش واقعی ثبت نمی‌شود)'}")
    print()
    for i, v in enumerate(variants, 1):
        print(f"  {i:2d}) {bold(f'{v.name:<22}')} {v.why}")
        if v.fix:
            print(f"      ↳ اگر جواب داد: {cyan(v.fix)}")
    print()


def print_report(results: list[Result], args) -> list[Result]:
    print(bold("\n──── نتیجه ────"))
    width = max(len(r.variant.name) for r in results) + 2
    for r in results:
        status = r.status if r.status is not None else "ERR"
        code = r.error_code or "—"
        print(f"  {r.variant.name:<{width}} HTTP {str(status):<5} code {code:<6} {_VERDICT_LABEL.get(r.verdict, r.verdict)}")
        if r.error:
            print(red(f"      شبکه: {r.error}"))
        elif r.body_note:
            print(cyan(f"      {r.body_note}"))
    good = [r for r in results if r.verdict == VERDICT_PASSED or r.verdict == VERDICT_ACCEPTED]
    print()
    if not good:
        print(yellow("  ⚠️  هیچ واریانتی از لایه‌ی امنیت رد نشد. یعنی مشکل در همین چند هدر/کوکی نیست؛"))
        print(yellow("      نشست را با --login تازه کنید (روی همان سرور و همان IP) و اگر باز هم ۹۰۰۹ بود،"))
        print(yellow("      «درخواست مرورگر» را از DevTools (Copy as fetch) بگیرید و با این ابزار مقایسه کنید:"))
        print(cyan("        python compare_request.py browser.txt -s <نماد> -q <تعداد> -p <قیمت>"))
        print(cyan("      و اگر لازم شد همان اسنیپت را با --body-file بازپخش کنید."))
    else:
        print(green("  ✅ این واریانت‌ها لایه‌ی امنیت را پاس کردند:"))
        for r in good:
            print(f"     • {bold(r.variant.name)} — {r.body_note}")
            if r.variant.fix:
                print(cyan(f"       ↳ {r.variant.fix}"))
        if args.app_n_candidate and any(r.variant.name == "app-n-copied" for r in good):
            print(cyan("       ↳ یعنی شکل/مقدار x-app-n واقعاً بررسی می‌شود؛ همیشه مقدار تازه‌ی مرورگر را بدهید."))
        print()
        print(yellow("  ℹ️  توجه: پاس شدن یک واریانت یعنی «این تفاوت، رد امنیتی را برمی‌دارد»؛ قبل از اجرای واقعی،"))
        print(yellow("      یک ترکیب با فاصله‌ی مجاز (sendOrderDelay) و مقادیر درست قیمت/تعداد امتحان کنید."))
    return good


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #
def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="کاوش علت ۴۰۳/۹۰۰۹ با فرستادن درخواست‌های عمداً نامعتبر (هیچ سفارش واقعی ثبت نمی‌شود)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--yes", action="store_true", help="بدون این پرچم هیچ درخواستی فرستاده نمی‌شود (فقط فهرست)")
    p.add_argument("--only", action="append", metavar="NAME",
                   help="فقط این واریانت(ها) را اجرا کن (قابل تکرار)")
    p.add_argument("--base-url", default=os.environ.get("EXIR_BASE_URL", DEFAULT_BASE_URL))
    p.add_argument("--token", default=os.environ.get("EXIR_TOKEN"), help="توکن JWT (پیش‌فرض: از فایل)")
    p.add_argument("--token-file", default=os.environ.get("EXIR_TOKEN_FILE", ".exir_token.json"))
    p.add_argument("--auth-mode", choices=["cookie", "bearer", "both"],
                   default=os.environ.get("EXIR_AUTH_MODE", "cookie"))
    p.add_argument("--app-n", default=os.environ.get("EXIR_APP_N"), help="همان --app-n ربات")
    p.add_argument("--app-n-candidate", metavar="VALUE",
                   help="مقدار x-app-n کپی‌شده از مرورگر (فقط برای یک واریانت امتحان می‌شود)")
    p.add_argument("--clientid", default=os.environ.get("EXIR_CLIENTID"),
                   help="مقدار clientid ربات (پیش‌فرض: خالی، «off» = نفرست)")
    p.add_argument("--clientid-candidate", metavar="VALUE",
                   help="مقدار clientid دیده‌شده در درخواست مرورگر (برای یک واریانت)")
    p.add_argument("--cookie", default=os.environ.get("EXIR_COOKIE"), help="کوکی‌های اضافه: 'a=1; b=2'")
    p.add_argument("-H", "--header", action="append", help="هدر اضافه به شکل 'name: value'")
    p.add_argument("--body-file", help="بدنه‌ی JSON دلخواه (تعداد/قیمت با پرچم زیر صفر می‌شود)")
    p.add_argument("--allow-real-body", action="store_true",
                   help="❗بدنه را بدون تغییر بفرست (ممکن است سفارش واقعی ثبت شود؛ به‌طور پیش‌فرض تعداد/قیمت صفر می‌شود)")
    p.add_argument("--delay", type=float, default=None,
                   help="فاصله‌ی بین واریانت‌ها (ثانیه). پیش‌فرض: sendOrderDelay فایل توکن + ۰.۵ (حداقل ۱.۵)")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", metavar="FILE", help="نوشتن گزارش (بدون مقدار حساس) در فایل JSON")
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    base = args.base_url.rstrip("/")
    variants = select_variants(build_variants(args, base), args.only)

    if args.allow_real_body and len(variants) != 1:
        print(red("✘ با --allow-real-body (ارسال بدنه‌ی واقعی) فقط یک واریانت مجاز است؛ "
                  "مثلاً:  python probe_order.py --yes --allow-real-body --only current"))
        return 2

    token = clean_token(args.token) if args.token else None
    saved = load_saved_token(Path(args.token_file), base)
    if not token:
        token = (saved or {}).get("token")
    print(bold(cyan("\n═══════ کاوش امنیتی درخواست سفارش ═══════")))
    if not token:
        print(red(f"✘ توکن معتبری در {args.token_file} نیست؛ اول لاگین کنید (--login در CLI یا بخش ورود در پنل)."))
        return 2
    exp = jwt_exp(token)
    if exp and exp < time.time():
        print(red("✘ توکن منقضی شده است؛ دوباره لاگین کنید."))
        return 2
    print(f"  توکن: {describe_token(token)}")
    if args.allow_real_body:
        print(red("  ❗ --allow-real-body روشن است: بدنه عیناً فرستاده می‌شود و ممکن است سفارش واقعی ثبت شود."))
    print_plan(variants, args, base)

    if not args.yes:
        print(yellow("  برای اجرا:  python probe_order.py --yes"))
        print(yellow("  (هیچ درخواستی تا این لحظه فرستاده نشده است.)\n"))
        return 0

    if args.body_file:
        try:
            body, note = body_from_file(args.body_file, args.allow_real_body)
        except Exception as e:  # noqa: BLE001
            print(red(f"✘ بدنه‌ی داده‌شده قابل خواندن نیست: {e}"))
            return 2
    else:
        body, note = safe_body(), "نماد ناموجود + تعداد ۰ + قیمت ۰"
    payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
    print(cyan(f"  منبع بدنه: {note}"))

    delay = args.delay
    if delay is None:
        announced = (saved or {}).get("sendOrderDelay")
        delay = max(1.5, (float(announced) / 1000.0 + 0.5) if isinstance(announced, (int, float)) else 0.0)
    print(cyan(f"  بدنه‌ی ارسالی: {json.dumps(body, ensure_ascii=False)}"))
    print(cyan(f"  فاصله‌ی بین واریانت‌ها: {delay:.1f} ثانیه | تایم‌اوت: {args.timeout:g}s\n"))

    results: list[Result] = []
    for i, variant in enumerate(variants, 1):
        print(bold(f"▶️  ({i}/{len(variants)}) {variant.name} — {variant.why}"))
        r = run_variant(variant, args, token, base, payload)
        results.append(r)
        colour = green if r.verdict in (VERDICT_PASSED, VERDICT_ACCEPTED) else (red if r.verdict == VERDICT_SECURITY else yellow)
        status = r.status if r.status is not None else "ERR"
        print(colour(f"    ← HTTP {status}  code {r.error_code or '—'}  ({r.elapsed_ms:.0f}ms)  {r.body_note}"))
        if r.request_dump and i == 1:
            print(cyan("    📤 درخواست خط پایه (مقدار کوکی/توکن کوتاه شده):"))
            for line in r.request_dump.splitlines():
                print(cyan("       " + line))
        if i < len(variants):
            time.sleep(delay)
    print()

    good = print_report(results, args)

    if args.json:
        report = {
            "base_url": base,
            "order_path": ORDER_PATH,
            "token": describe_token(token),
            "clock": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "body": body,
            "base_identity": None,
            "results": [
                {"variant": r.variant.name, "why": r.variant.why, "verdict": r.verdict,
                 "http": r.status, "error_code": r.error_code, "description": r.description,
                 "ms": round(r.elapsed_ms, 1), "request": r.request_dump, "error": r.error}
                for r in results
            ],
            "fix_candidates": [{"variant": r.variant.name, "fix": r.variant.fix} for r in good],
            "note": "مقادیر کوکی/توکن در request کوتاه شده‌اند.",
        }
        Path(args.json).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(cyan(f"\n💾 گزارش در {args.json} ذخیره شد."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
