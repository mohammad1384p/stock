#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
مقایسه‌ی درخواست «مرورگر» با درخواست «ربات» — هدرها و بدنه.

پاسخ به این سؤال: «هدر درسته و کامله؟ چه چیزی کم/زیاد است؟»

سه شکل ورودی پشتیبانی می‌شود (هر کدام را از DevTools کپی کرده باشید):
  1) هدرهای خام:   POST /api/v1/order HTTP/1.1
                   Accept: application/json, text/plain, *\/*
                   ...
  2) خروجی «Copy as fetch» کروم
  3) خروجی «Copy as cURL»

نمونه:
    python compare_request.py browser.txt -s IRO7TONP0001 -q 10 -p 6700
    pbpaste | python compare_request.py - -q 10 -p 6700        # مستقیم از کلیپ‌بورد
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

try:
    import requests
except ImportError:  # pragma: no cover
    print("کتابخانه‌ی requests نصب نیست:  pip install -r requirements.txt")
    sys.exit(1)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exir_bot import (  # noqa: E402
    ISIN_RE, build_body, build_session, load_local_symbols, normalize_fa, parse_fetch_snippet,
)

# هدرهایی که کلاینت/سرور خودشان مدیریت می‌کنند و مقایسه‌ی مقدارشان بی‌معنی است
AUTO_HEADERS = {"host", "content-length", "connection", "accept-encoding",
                "transfer-encoding", "cookie"}
# هدرهای تلهمتری (Sentry و …) — نبودنشان در ربات هیچ اثری روی اعتبارسنجی ندارد
TELEMETRY_RE = re.compile(r"^(baggage|sentry-|traceparent|tracestate|x-b3-|newrelic)", re.I)
# هدرهای ظاهری: تفاوتشان بی‌اثر است (هر مرورگری مقدار خودش را می‌فرستد)
COSMETIC_HEADERS = {"accept-language"}
# توضیح نام کوکی‌های مرورگر
COOKIE_NOTES = {
    "jwt-token": "توکن نشست — ربات هم دارد (مقدارش طبیعتاً متفاوت است)",
    "client_login_id": "از مرحله‌ی کپچا ست می‌شود — ربات در لاگینِ خودش می‌گیرد",
    "cookiesession1": "کوکی WAF؛ سرور خودش ست می‌کند. اگر لازم باشد: --cookie 'cookiesession1=…'",
    "_ga": "کوکی تحلیلی گوگل — بی‌اثر",
    "_ga_b1ed8594cw": "کوکی تحلیلی گوگل — بی‌اثر",
}


def shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def emit_curl(headers: dict, cookies: list, url: str, payload: bytes | None,
              show_token: bool = False) -> str:
    """دستور curl معادلِ دقیقِ درخواست ربات (برای بازپخش/مقایسه در محیط خودتان)."""
    skip = {"accept-encoding", "content-length", "connection", "host", "cookie"}
    lines = [f"curl -X POST {shell_quote(url)}"]
    for k, v in headers.items():
        if k.lower() in skip:
            continue
        if k.lower() == "authorization" and not show_token:
            v = v[:16] + "…"
        lines.append(f"  -H {shell_quote(f'{k}: {v}')}")
    if cookies:
        jar = "; ".join(f"{n}={v}" for n, v in cookies)
        lines.append(f"  -H {shell_quote('Cookie: ' + jar)}")
    if payload is not None:
        lines.append(f"  --data-raw {shell_quote(payload.decode('utf-8'))}")
    return " \\\n".join(lines)


# --------------------------------------------------------------------------- #
#  چاپ
# --------------------------------------------------------------------------- #
def _c(code: str, s: str) -> str:
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return f"\033[{code}m{s}\033[0m"
    return s


def green(s: str) -> str: return _c("32", s)
def red(s: str) -> str: return _c("31", s)
def yellow(s: str) -> str: return _c("33", s)
def cyan(s: str) -> str: return _c("36", s)
def bold(s: str) -> str: return _c("1", s)


def mask(value: str, head: int = 12) -> str:
    """مقدار حساس را کوتاه می‌کند (طول + ابتدای مقدار)."""
    value = value.strip()
    if len(value) <= head:
        return value
    return f"{value[:head]}…({len(value)} کاراکتر)"


# --------------------------------------------------------------------------- #
#  تجزیه‌ی ورودی کاربر
# --------------------------------------------------------------------------- #
def parse_raw_http(text: str) -> dict:
    """هدرهای خام کپی‌شده از DevTools (شامل خط اول POST ... HTTP/1.1)."""
    lines = text.splitlines()
    start = 0
    for i, ln in enumerate(lines):
        if re.match(r"^\s*(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+\S+\s+HTTP/", ln):
            start = i + 1
            break
    else:
        return {}
    headers: dict = {}
    last_key: str | None = None
    for ln in lines[start:]:
        if not ln.strip():
            break  # خط خالی = شروع بدنه؛ در DevTools هدرها تمام شده‌اند
        if ln[0] in " \t" and last_key:  # هدر ادامه‌دار (folded) مثل کوکی‌های طولانی
            headers[last_key] += " " + ln.strip()
            continue
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        last_key = k.strip().lower()
        headers[last_key] = v.strip()
    return headers


def parse_curl(text: str) -> dict:
    """خروجی «Copy as cURL» (bash/PowerShell/cmd)."""
    text = re.sub(r"\\\r?\n", " ", text)          # ادامه‌ی خط bash
    text = re.sub(r"`\r?\n", " ", text)           # ادامه‌ی خط PowerShell
    text = re.sub(r"\^\r?\n", " ", text)          # ادامه‌ی خط cmd
    out: dict = {"headers": {}, "body": None}
    for m in re.finditer(r"""-H\s+(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""", text, re.S):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        raw = raw.replace('\\"', '"').replace("\\'", "'").replace("\\/", "/")
        if ":" in raw:
            k, v = raw.split(":", 1)
            out["headers"][k.strip().lower()] = v.strip()
    for m in re.finditer(r"""(?:--data-raw|--data-binary|--data|-d)\s+(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""",
                         text, re.S):
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        out["body"] = raw.replace('\\"', '"').replace("\\'", "'").replace("\\/", "/")
    return out


def parse_browser_input(text: str) -> dict:
    """هر سه شکل ورودی را تشخیص می‌دهد → {"headers": {...}, "body": str|None, "kind": str}"""
    text = text.strip()
    try:
        json.loads(text)
        return {"headers": {}, "body": text, "kind": "json"}
    except ValueError:
        pass
    if re.search(r"\bcurl\b", text) and re.search(r"-H\s", text):
        d = parse_curl(text)
        d["kind"] = "curl"
        return d
    if re.search(r"fetch\s*\(", text) or re.search(r"[\"']?headers[\"']?\s*:", text):
        d = parse_fetch_snippet(text)
        d["kind"] = "fetch"
        return d
    return {"headers": parse_raw_http(text), "body": None, "kind": "raw"}


# --------------------------------------------------------------------------- #
#  ساخت درخواست ربات
# --------------------------------------------------------------------------- #
def bot_request(args) -> tuple[dict, list[str], dict | None, list[tuple[str, str]]]:
    """هدرها/نام کوکی‌ها/بدنه/جفت‌های کوکی که ربات می‌فرستد."""
    ns = argparse.Namespace(base_url=args.base_url, cookie=args.cookie,
                            app_n=args.app_n, clientid=getattr(args, "clientid", None),
                            header=args.header or [])
    session = build_session(ns, pool=16)

    token = args.token
    if not token and not args.no_token:
        try:
            from exir_auth import load_saved_token
            saved = load_saved_token(Path(args.token_file), args.base_url.rstrip("/"))
            token = (saved or {}).get("token")
        except Exception:  # noqa: BLE001
            token = None
    if token:
        from exir_auth import apply_token, clean_token
        apply_token(session, args.base_url.rstrip("/"), clean_token(token), args.auth_mode)

    body = None
    if args.quantity is not None and args.price is not None and args.symbol:
        isin = args.symbol.strip().upper()
        if not ISIN_RE.match(isin):
            isin = load_local_symbols().get(normalize_fa(args.symbol), isin)
        ns2 = argparse.Namespace(quantity=args.quantity, price=args.price, side=args.side)
        body = build_body(ns2, isin)
    pairs = [(c.name, c.value) for c in session.cookies]
    return dict(session.headers), [n for n, _ in pairs], body, pairs


# --------------------------------------------------------------------------- #
#  مقایسه
# --------------------------------------------------------------------------- #
def compare_headers(browser: dict, bot: dict, bot_cookies: list[str], app_n: str | None,
                    bot_cookie_pairs: list[tuple[str, str]] | None = None) -> tuple[int, int]:
    br = {k.lower().strip(): v for k, v in browser.items() if k != "__status__"}
    bt = {k.lower().strip(): v for k, v in bot.items()}
    bkeys = set(br) - {"cookie"}
    common = bkeys & set(bt)
    is_trivial = lambda k: k in AUTO_HEADERS or bool(TELEMETRY_RE.match(k))  # noqa: E731
    same = sorted(k for k in common if br[k].strip() == bt[k].strip() and not is_trivial(k))
    raw_diff = sorted(k for k in common if br[k].strip() != bt[k].strip())
    diff = [k for k in raw_diff if k not in COSMETIC_HEADERS and not is_trivial(k)]
    cosmetic = [k for k in raw_diff if k in COSMETIC_HEADERS]
    auto_diff = [k for k in raw_diff if k not in COSMETIC_HEADERS and is_trivial(k)]
    only_browser = sorted(bkeys - set(bt))
    only_bot = sorted(set(bt) - bkeys)
    b_auto = [k for k in only_browser if k in AUTO_HEADERS]
    b_tel = [k for k in only_browser if k not in AUTO_HEADERS and TELEMETRY_RE.match(k)]
    b_missing = [k for k in only_browser if k not in b_auto and k not in b_tel]
    o_auto = [k for k in only_bot if k in AUTO_HEADERS]
    o_rest = [k for k in only_bot if k not in AUTO_HEADERS]

    print(bold("\n──── هدرها ────"))
    print(green(f"  ✔ یکسان ({len(same)}): ") + ", ".join(same))

    if diff:
        print(yellow(f"\n  ⚠️  متفاوت ({len(diff)}):"))
        for k in diff:
            b, o = br[k].strip(), bt[k].strip()
            if k == "user-agent":
                b, o = mask(b, 40), mask(o, 40)
            print(f"     {k}:")
            print(f"        مرورگر: {b}")
            print(f"        ربات  : {o}")
    if cosmetic:
        print(cyan(f"\n  ℹ️  تفاوت بی‌اثر ({len(cosmetic)}): ") + ", ".join(cosmetic)
              + "  (مقدارش بین مرورگرهای مختلف هم متفاوت است)")
    if auto_diff:
        print(cyan(f"  ℹ️  تفاوت خودکار ({len(auto_diff)}): ") + ", ".join(auto_diff)
              + "  (کلاینت/سرور تعیین می‌کند؛ بی‌اثر)")

    if b_missing:
        print(red(f"\n  ✖ مهم: در مرورگر هست، ربات نمی‌فرستد ({len(b_missing)}):"))
        for k in b_missing:
            print(f"     {red(k)} = {mask(br[k], 40)}")
    else:
        print(green("\n  ✔ هیچ هدر مهمی نیست که مرورگر بفرستد و ربات نفرستد."))

    if b_tel:
        print(cyan(f"  ℹ️  تلهمتری ({len(b_tel)}، بی‌اثر در اعتبارسنجی): ") + ", ".join(b_tel))
    if b_auto:
        print(cyan(f"  ℹ️  خودکار ({len(b_auto)}): ") + ", ".join(b_auto)
              + "  (خودِ کلاینت/سرور تعیین می‌کند)")
    if o_rest:
        print(cyan(f"  ＋ فقط ربات ({len(o_rest)}): ") + ", ".join(o_rest))
    if o_auto:
        print(cyan(f"  ℹ️  خودکار از سمت ربات: ") + ", ".join(o_auto))

    # کوکی‌ها
    if "cookie" in br:
        names_b = [p.split("=", 1)[0].strip() for p in br["cookie"].split(";") if "=" in p]
        print(bold("\n──── کوکی‌ها ────"))
        for n in names_b:
            has = n in bot_cookies
            print(f"  {green('✔') if has else yellow('✖')} {n}"
                  + ("" if has else "  — " + COOKIE_NOTES.get(n.lower(), "ربات این کوکی را ندارد")))
        for n in [x for x in bot_cookies if x not in names_b]:
            print(f"  ＋ {n}  (فقط ربات می‌فرستد)")
        print(cyan("  ℹ️  مقدار کوکی‌ها طبیعی است که فرق کند؛ مهم «نام» آن‌هاست (هر کلاینت نشست خودش را دارد)."))

    if app_n:
        print(cyan(f"  ℹ️  برای تطبیق x-app-n با مرورگر:  --app-n {app_n}"))
    return len(diff), len(b_missing)


def compare_body(browser_body: str | None, bot_body: dict | None) -> None:
    print(bold("\n──── بدنه (Payload) ────"))
    if browser_body is None:
        print(yellow("  ⚠️  در ورودی داده‌شده بدنه‌ای نبود. بدنه را از DevTools → Payload کپی کنید "
                     "یا از «Copy as fetch» استفاده کنید."))
        return
    try:
        b = json.loads(browser_body)
    except ValueError:
        print(yellow(f"  ⚠️  بدنه‌ی مرورگر JSON معتبر نیست ({len(browser_body)} کاراکتر): {browser_body[:120]}…"))
        return
    raw = json.dumps(b, separators=(",", ":"))
    print(f"  بدنه‌ی مرورگر: {len(raw.encode())} بایت | {len(b)} فیلد")
    print("  " + json.dumps(b, ensure_ascii=False))
    if bot_body is None:
        print(cyan("  ℹ️  برای مقایسه‌ی فیلدبه‌فیلد، -s/-q/-p هم بدهید."))
        return
    braw = json.dumps(bot_body, separators=(",", ":"))
    print(f"\n  بدنه‌ی ربات  : {len(braw.encode())} بایت | {len(bot_body)} فیلد")
    print("  " + json.dumps(bot_body, ensure_ascii=False))

    fields = list(dict.fromkeys(list(b) + list(bot_body)))
    diffs = []
    print(bold("\n  فیلد            مرورگر                     ربات"))
    for f in fields:
        bv, ov = b.get(f, "«نیست»"), bot_body.get(f, "«نیست»")
        ok = json.dumps(bv, ensure_ascii=False, sort_keys=True) == json.dumps(ov, ensure_ascii=False, sort_keys=True)
        if not ok:
            diffs.append(f)
        print(f"  {'✔' if ok else red('✖')} {f:<14} {str(bv):<26} {str(ov)}")
    if not diffs:
        print(green("\n  ✅ بدنه دقیقاً یکسان است (خودِ بایت‌ها هم همین طول را می‌دهند)."))
        print(cyan("  پس اگر پاسخ ۴۲۲ است، مشکل از هدر/بدنه نیست؛ مقدار «قیمت/تعداد» یا وضعیت نماد"
                   " در آن لحظه از نظر کارگزار مجاز نیست — متن پاسخ ۴۲۲ را ببینید."))
    else:
        print(red(f"\n  ✖ {len(diffs)} فیلد متفاوت: ") + ", ".join(diffs))
        print(cyan("  برای فرستادن عینِ بدنه‌ی مرورگر:  python exir_bot.py --body-file <همین فایل>"))


def main() -> None:
    p = argparse.ArgumentParser(description="مقایسه‌ی درخواست مرورگر (DevTools) با درخواست ربات",
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("input", help="فایل درخواست مرورگر؛ یا - برای خواندن از stdin")
    g = p.add_argument_group("request ربات (برای مقایسه‌ی بدنه)")
    g.add_argument("-s", "--symbol")
    g.add_argument("-q", "--quantity", type=int)
    g.add_argument("-p", "--price", type=int)
    g.add_argument("--side", choices=["buy", "sell"], default="buy")
    p.add_argument("--base-url", default="https://khobregan.exirbroker.com")
    p.add_argument("--app-n", dest="app_n", help="مقدار x-app-n که ربات می‌فرستد")
    p.add_argument("--clientid", default=os.environ.get("EXIR_CLIENTID"),
                   help="مقدار هدر clientid ربات (پیش‌فرض: خالی، «off» = نفرست)")
    p.add_argument("--cookie", help="کوکی‌های اضافه‌ی ربات: 'a=1; b=2'")
    p.add_argument("-H", "--header", action="append", help="هدر اضافه‌ی ربات: 'name: value'")
    p.add_argument("--token", help="توکن JWT ربات (برای مقایسه‌ی کوکی JWT-TOKEN)")
    p.add_argument("--token-file", default=".exir_token.json", help="فایل توکن ذخیره‌شده")
    p.add_argument("--auth-mode", choices=["cookie", "bearer", "both"], default="cookie")
    p.add_argument("--no-token", action="store_true", help="کوکی توکن را در مقایسه نیاور")
    p.add_argument("--order-path", default="/api/v1/order", help="مسیر ثبت سفارش")
    p.add_argument("--emit-curl", action="store_true",
                   help="دستور curl معادلِ درخواست ربات را هم چاپ کن (برای بازپخش/مقایسه)")
    p.add_argument("--show-token", action="store_true", help="توکن را در خروجی curl کامل نشان بده")
    args = p.parse_args()

    text = sys.stdin.read() if args.input == "-" else Path(args.input).read_text(encoding="utf-8")
    browser = parse_browser_input(text)
    if not browser["headers"] and not browser["body"]:
        print(red("✘ ورودی قابل تشخیص نبود. هدرهای خام DevTools، «Copy as fetch» یا «Copy as cURL» را بدهید."))
        sys.exit(2)

    kinds = {"raw": "هدرهای خام DevTools", "fetch": "Copy as fetch", "curl": "Copy as cURL",
             "json": "بدنه‌ی JSON"}
    print(bold(cyan(f"\n🔍 مقایسه‌ی درخواست مرورگر ({kinds.get(browser['kind'], '?')}) با ربات")))
    print(f"   کارگزاری: {args.base_url}")

    bot_headers, bot_cookies, bot_body, bot_pairs = bot_request(args)
    compare_headers(browser["headers"], bot_headers, bot_cookies, args.app_n)
    compare_body(browser["body"], bot_body)

    if args.emit_curl:
        payload = json.dumps(bot_body, separators=(",", ":")).encode() if bot_body else None
        url = args.base_url.rstrip("/") + args.order_path
        print(bold("\n──── curl معادلِ درخواست ربات (دقیقاً همان چیزی که ربات می‌فرستد) ────"))
        if not args.show_token:
            print(cyan("  ℹ️  توکن در خروجی کوتاه شده؛ برای مقدار کامل --show-token را اضافه کنید."))
        print(cyan("  این را می‌توانید در ترمینال سرور اجرا کنید، یا در Console مرورگر خودتان به فرم fetch تبدیل کنید."))
        print(emit_curl(bot_headers, bot_pairs, url, payload, args.show_token))
        print()

    print(bold("\n──── نتیجه ────"))
    print("  هدرها: اگر در لیست «در مرورگر هست و ربات نمی‌فرستد» فقط هدرهای Sentry باشد، هدرها کامل‌اند.")
    print("  یادآوری: پاسخ ۴۲۲ یعنی لایه‌ی امنیت (هدر/کوکی/JWT) پاس شده و مسئله در «بدنه‌ی سفارش» است.")
    print("  ۴۰۳ با errorCode 9009 یعنی مشکل امنیتی/کپچا/نشست — نه ۴۲۲.\n")


if __name__ == "__main__":
    main()
