# -*- coding: utf-8 -*-
"""
لاگین به Exir و مدیریت توکن.

جریان لاگین (طبق درخواست مرورگر):
  1) گرفتن تصویر کپچا  (سرور کوکی client_login_id را ست می‌کند)
  2) POST /api/v2/login  با {username, password, captcha, otp}
  3) سرور کوکی JWT-TOKEN را ست می‌کند و در بدنه هم authToken برمی‌گرداند
  4) برای درخواست‌های بعدی (مثل ثبت سفارش) مرورگر فقط کوکی JWT-TOKEN را می‌فرستد

توکن در فایل محلی ذخیره می‌شود و تا زمان انقضا (exp داخل JWT) دوباره استفاده می‌شود.
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import random
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import requests

from captcha_web import CaptchaPortal, resolve_mode

LOGIN_PATH = "/api/v2/login"
# GET /captcha → image/jpeg + کوکی client_login_id (اعتبار ۱۲۰ ثانیه)
# بقیه فقط به‌عنوان جایگزین امتحان می‌شوند. آدرس دلخواه را با --captcha-url بدهید.
CAPTCHA_TTL = 120
CAPTCHA_CANDIDATES = (
    "/captcha",
    "/api/v2/captcha",
    "/api/v1/captcha",
    "/api/v2/login/captcha",
    "/api/v1/login/captcha",
    "/api/v2/captcha/image",
    "/api/v1/captcha/image",
)
TOKEN_COOKIE = "JWT-TOKEN"


def _yellow(s: str) -> str:
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return f"\033[33m{s}\033[0m"
    return s


# --------------------------------------------------------------------------- #
#  JWT و ذخیره‌ی توکن
# --------------------------------------------------------------------------- #
def jwt_payload(token: str) -> dict:
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:  # noqa: BLE001
        return {}


def jwt_exp(token: str) -> float | None:
    exp = jwt_payload(token).get("exp")
    return float(exp) if exp else None


def clean_token(tok: str) -> str:
    """پذیرش «Bearer xxx» یا «JWT-TOKEN=xxx; ...» یا خود توکن."""
    tok = tok.strip().strip('"').strip("'")
    m = re.search(r"JWT-TOKEN=([^;\s]+)", tok)
    if m:
        return m.group(1)
    if tok.lower().startswith("bearer "):
        tok = tok[7:].strip()
    return tok


def load_saved_token(path: Path, base: str) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    entry = data.get(base)
    if not entry or not entry.get("token"):
        return None
    exp = jwt_exp(entry["token"])
    if exp and exp < time.time() + 60:
        return None
    return entry


def save_token(path: Path, base: str, token: str, extra: dict | None = None) -> None:
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = {}
    entry = {"token": token, "saved_at": datetime.now().isoformat(timespec="seconds")}
    entry.update(extra or {})
    data[base] = entry
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def cookie_matches_host(domain: str, host: str) -> bool:
    """Accept exact-host and parent-domain cookies, not lookalike domains."""
    domain = domain.lstrip(".").lower()
    host = host.lower()
    return bool(domain) and (host == domain or host.endswith("." + domain))


def session_cookies(session: requests.Session, base: str) -> list[dict]:
    """Keep broker cookies with their scope/expiry, never unrelated domains."""
    host = urlparse(base).hostname or ""
    return [
        {"name": c.name, "value": c.value, "domain": c.domain,
         "path": c.path, "secure": c.secure, "expires": c.expires,
         "rest": dict(c._rest)}
        for c in session.cookies
        if cookie_matches_host(c.domain, host) and not c.is_expired()
        and c.name != TOKEN_COOKIE
    ]


def restore_session_cookies(session: requests.Session, base: str, cookies) -> None:
    host = urlparse(base).hostname or ""
    for item in cookies if isinstance(cookies, list) else []:
        try:
            cookie = requests.cookies.create_cookie(**item)
        except (TypeError, ValueError, AttributeError):
            continue
        if not cookie_matches_host(cookie.domain, host) or cookie.is_expired():
            continue
        if cookie.name == TOKEN_COOKIE:
            continue
        # Explicit --cookie values take precedence over saved values.
        if any(c.name == cookie.name and c.domain == cookie.domain
               and c.path == cookie.path for c in session.cookies):
            continue
        session.cookies.set_cookie(cookie)


def apply_token(session: requests.Session, base: str, token: str, mode: str) -> None:
    """قرار دادن توکن روی session: به‌صورت کوکی JWT-TOKEN و/یا هدر Authorization."""
    host = urlparse(base).hostname or ""
    # A login or explicit Cookie header may leave another JWT at a parent
    # domain/path. Sending two JWT-TOKEN values makes authentication ambiguous.
    for cookie in list(session.cookies):
        if cookie.name == TOKEN_COOKIE and cookie_matches_host(cookie.domain, host):
            session.cookies.clear(cookie.domain, cookie.path, cookie.name)
    session.headers.pop("Authorization", None)
    if mode in ("cookie", "both"):
        session.cookies.set(TOKEN_COOKIE, token, domain=host, path="/")
    if mode in ("bearer", "both"):
        session.headers["Authorization"] = f"Bearer {token}"


def describe_token(token: str) -> str:
    p = jwt_payload(token)
    exp = p.get("exp")
    parts = []
    if p.get("sub"):
        parts.append(f"کاربر {p['sub']}")
    if exp:
        left = exp - time.time()
        parts.append(f"انقضا {datetime.fromtimestamp(exp):%Y-%m-%d %H:%M:%S}"
                     f" ({'منقضی شده' if left <= 0 else f'{int(left // 3600)}h{int(left % 3600 // 60):02d}m مانده'})")
    return " | ".join(parts) or "نامشخص"


# --------------------------------------------------------------------------- #
#  کپچا
# --------------------------------------------------------------------------- #
def _extract_image(resp: requests.Response) -> bytes | None:
    ctype = resp.headers.get("content-type", "").lower()
    if ctype.startswith("image/"):
        return resp.content
    if "json" in ctype or resp.text[:1] in "{[":
        try:
            data = resp.json()
        except ValueError:
            return None
        stack = [data]
        while stack:
            cur = stack.pop()
            if isinstance(cur, dict):
                stack.extend(cur.values())
            elif isinstance(cur, list):
                stack.extend(cur)
            elif isinstance(cur, str) and len(cur) > 200:
                s = cur.split(",", 1)[1] if cur.startswith("data:image") else cur
                try:
                    raw = base64.b64decode(s + "=" * (-len(s) % 4))
                except Exception:  # noqa: BLE001
                    continue
                if raw[:4] in (b"\x89PNG", b"GIF8") or raw[:2] == b"\xff\xd8" or b"<svg" in raw[:200]:
                    return raw
    if "svg" in ctype or resp.text.lstrip().startswith("<svg"):
        return resp.content
    return None


def fetch_captcha(session: requests.Session, base: str, captcha_url: str | None, log) -> bytes:
    urls = [captcha_url] if captcha_url else [base + p for p in CAPTCHA_CANDIDATES]
    last_err = ""
    for u in urls:
        if not u.startswith("http"):
            u = base + (u if u.startswith("/") else "/" + u)
        try:
            r = session.get(u, timeout=10,
                            headers={"accept": "application/json, text/plain, */*",
                                     "referer": f"{base}/new-exir/login"})
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            continue
        if r.status_code == 200:
            img = _extract_image(r)
            if img:
                # اگر کوکی به هر دلیلی در jar ننشست، از هدر client_login_id بردار
                cid = r.headers.get("client_login_id")
                if cid and not session.cookies.get("client_login_id"):
                    session.cookies.set("client_login_id", cid,
                                        domain=urlparse(base).hostname or "", path="/")
                return img
        last_err = f"{u} → HTTP {r.status_code}"
    raise RuntimeError(
        "دریافت کپچا ناموفق بود (" + last_err + ").\n"
        "در مرورگر F12 ← Network، صفحه‌ی لاگین را رفرش کنید و آدرس درخواستِ تصویر کپچا را با --captcha-url بدهید."
    )


def show_captcha(img: bytes, path: Path, log) -> None:
    ext = ".svg" if b"<svg" in img[:300] else ".png" if img[:4] == b"\x89PNG" else ".jpg" if img[:2] == b"\xff\xd8" else ".gif"
    path = path.with_suffix(ext)
    path.write_bytes(img)
    log(f"🖼  تصویر کپچا ذخیره شد: {path.resolve()}")

    # باز کردن با نمایشگر سیستم
    for cmd in (["termux-open", str(path)], ["xdg-open", str(path)], ["open", str(path)]):
        if shutil.which(cmd[0]):
            try:
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except Exception:  # noqa: BLE001
                pass
    if sys.platform.startswith("win"):
        try:
            os.startfile(str(path))  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- #
#  لاگین
# --------------------------------------------------------------------------- #
def _mask(data):
    if isinstance(data, dict):
        return {k: (str(v)[:10] + "…" if k in ("authToken", "rlcAuthHeader", "nt") and v else _mask(v))
                for k, v in data.items()}
    if isinstance(data, list):
        return [_mask(x) for x in data]
    return data


def obtain_captcha(portal: CaptchaPortal | None, log) -> tuple[str | None, str]:
    """
    کد کپچا را از مرورگر (portal) یا ترمینال می‌گیرد.

    خروجی ``(code, source)``: کد، یا "" اگر کاربر کپچای جدید خواست، یا None اگر مهلت تمام شد.
    """
    prompt = (f"کد کپچا را وارد کنید (حداکثر {CAPTCHA_TTL} ثانیه، "
              "Enter خالی = کپچای جدید): ")
    if portal is None:
        return input(prompt).strip(), "stdin"
    if portal.stdin_ok:
        sys.stdout.write(prompt)
        sys.stdout.flush()
    code, source = portal.wait_for_code(CAPTCHA_TTL)
    if source != "stdin":
        print()  # بستن خطِ prompt ترمینال وقتی کد از مرورگر آمد
    if code:
        log(f"⌨️  کد کپچا از {'مرورگر' if source == 'web' else 'ترمینال'} دریافت شد: {code}")
    return code, source


def generate_app_n() -> str:
    """
    یک مقدار تولیدی برای هدر ``x-app-n`` با همان *شکلِ* دیده‌شده در مرورگر::

        <۱۳ رقم>.<۸ رقم>        مثل: 2018887747744.29964494

    این مقدار از مرورگر نیامده است؛ فقط شکلش مثل نمونه‌ی رسمی است (نسخه‌های قبلی
    ``NaN.<عدد>`` می‌ساختند که هیچ‌وقت در درخواست مرورگر دیده نشده). اگر مقدار واقعیِ
    مرورگر را دارید، آن را با ``--app-n`` بدهید.
    """
    return f"{random.randint(10 ** 12, 10 ** 13 - 1)}.{random.randint(10 ** 7, 10 ** 8 - 1)}"


def security_hint(status: int, data) -> str:
    """توضیح خطای ۹۰۰۹ (مشکل امنیتی) برای کاربر."""
    if status != 403:
        return ""
    blob = json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data
    if "9009" not in blob and "امنیت" not in blob:
        return ""
    return (
        "ℹ️  خطای ۹۰۰۹ یعنی درخواست از نظر امنیتی رد شده؛ علت دقیق از این کد مشخص نیست.\n"
        "    ورود موفق و نمایش نام حساب، معتبر بودن درخواست سفارش را تضمین نمی‌کند.\n"
        "    کوکی‌های همراه نشست و هدر x-app-n را بین ورود و سفارش مقایسه کنید.\n"
        "    «درخواستی که فرستاده شد» در همین لاگ (با مقادیر حساس کوتاه‌شده) چاپ شده است؛\n"
        "    آن را با درخواست مرورگر در DevTools (Network ← Copy → Copy as fetch) مقایسه کنید.\n"
        "    برای پیدا کردن علت با حذف فرضیه‌ها (هیچ سفارش واقعی ثبت نمی‌شود):\n"
        "        python probe_order.py --yes\n"
        "    و برای گزارش بدون رمز/توکن و بدون ارسال درخواست: python diagnose_session.py"
    )


def login(session: requests.Session, base: str, username: str, password: str, *,
          captcha_url: str | None, otp: str | None, captcha_path: Path,
          log, portal: CaptchaPortal | None = None, app_n: str | None = None,
          max_tries: int = 3) -> dict:
    """لاگین تعاملی. خروجی: دیکشنری پاسخ سرور (شامل authToken)."""
    url = base + LOGIN_PATH
    app_n = (app_n or session.headers.get("x-app-n") or "").strip()
    if not app_n:
        app_n = generate_app_n()
        log(f"🧩 هدر x-app-n تنظیم نشده بود؛ مقدار تولیدی با شکل نمونه‌ی مرورگر ساخته شد: {app_n}\n"
            "    (اگر مقدار واقعی مرورگر را دارید با --app-n بدهید — همان برای ورود و سفارش‌ها می‌رود.)")
    session.headers["x-app-n"] = app_n
    for attempt in range(1, max_tries + 1):
        while True:
            img = fetch_captcha(session, base, captcha_url, log)
            t_captcha = time.time()
            show_captcha(img, captcha_path, log)
            if portal is not None:
                portal.set_image(img)
                portal.announce()
            captcha, source = obtain_captcha(portal, log)
            if captcha is None:
                log("⌛ مهلت کپچا (۱۲۰ ثانیه) تمام شد؛ کپچای جدید گرفته می‌شود.")
                continue
            if not captcha:
                log("🔄 کپچای جدید گرفته می‌شود…")
                continue
            if time.time() - t_captcha > CAPTCHA_TTL - 3:
                log("⌛ کپچا منقضی شد (۱۲۰ ثانیه)؛ کپچای جدید گرفته می‌شود.")
                continue
            break
        if portal is not None:
            portal.set_state("submitting", "کد دریافت شد؛ در حال لاگین با نشست سرور…")
        body = {"username": username, "password": password, "captcha": captcha, "otp": otp or ""}
        headers = {
            "accept": "application/json, text/plain, */*",
            "referer": f"{base}/new-exir/login",
            # همان clientidی که روی نشست تنظیم شده (پیش‌فرض: خالی، مثل درخواست مرورگر)؛
            # اگر --clientid مقدار داشته باشد، همان برای ورود و سفارش‌ها فرستاده می‌شود.
            "clientid": session.headers.get("clientid", ""),
            "x-app-n": app_n,
        }
        r = session.post(url, json=body, headers=headers, timeout=15)
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text[:1000]}

        token = (data.get("authToken") if isinstance(data, dict) else None) or session.cookies.get(TOKEN_COOKIE)
        if r.status_code == 200 and token:
            data["authToken"] = token
            data["_appN"] = app_n  # تا سفارش‌ها هم با همان x-app-nِ لاگین بروند
            if portal is not None:
                portal.finish(True, "✅ ورود موفق بود؛ می‌توانید این صفحه را ببندید.")
            return data

        log(f"✘ لاگین ناموفق (HTTP {r.status_code}):\n{json.dumps(_mask(data), ensure_ascii=False, indent=2)}")
        hint = security_hint(r.status_code, data)
        if hint:
            log(_yellow(hint))
        if portal is not None:
            portal.finish(False, f"✘ لاگین ناموفق (HTTP {r.status_code}). به ترمینال سرور برگردید.")
        text = json.dumps(data, ensure_ascii=False).lower()
        if not otp and ("otp" in text or "یکبار" in text or "پیامک" in text or "دو مرحله" in text):
            otp = input("کد یکبار مصرف (OTP): ").strip()
        if attempt < max_tries:
            log(f"… تلاش دوباره ({attempt + 1}/{max_tries})")
            if portal is not None:
                portal.set_state("waiting", "تلاش دوباره…")
    raise RuntimeError("لاگین بعد از چند تلاش ناموفق بود.")


def ensure_token(session: requests.Session, args, log, interactive: bool) -> str:
    """توکن را از --token، فایل ذخیره، یا لاگین تعاملی به‌دست می‌آورد و روی session قرار می‌دهد."""
    base = args.base_url.rstrip("/")
    token_file = Path(args.token_file)

    token: str | None = None
    app_n: str | None = (getattr(args, "app_n", None) or session.headers.get("x-app-n") or "").strip() or None
    if args.token and not args.login:
        token = clean_token(args.token)
        log(f"🔑 استفاده از توکن داده‌شده ({describe_token(token)})")
    elif not args.login:
        saved = load_saved_token(token_file, base)
        if saved:
            token = saved["token"]
            restore_session_cookies(session, base, saved.get("cookies", []))
            if not app_n and saved.get("appN"):
                app_n = saved["appN"]  # همان x-app-nِ لاگین را برای سفارش‌ها هم بفرست
            log(f"🔑 استفاده از توکن ذخیره‌شده در {token_file} ({describe_token(token)})")

    if not token:
        if not interactive and not (args.username and args.password):
            raise RuntimeError("توکن معتبری نیست و ورودی تعاملی هم در دسترس نیست. --token یا --username/--password بدهید.")
        log("🔐 ورود به حساب کاربری")
        username = args.username or input("نام کاربری: ").strip()
        password = args.password or getpass.getpass("رمز عبور (نمایش داده نمی‌شود): ")

        # وب‌سرور موقت برای دیدن کپچا در مرورگر (سرورهای بدون نمایشگر)
        portal: CaptchaPortal | None = None
        want_port = resolve_mode(getattr(args, "captcha_web", None))
        if want_port is not None:
            portal = CaptchaPortal(log=log,
                                   host=getattr(args, "captcha_web_host", None) or "0.0.0.0",
                                   port=want_port, ttl=CAPTCHA_TTL)
            if not portal.start():
                portal = None
        try:
            data = login(session, base, username, password,
                         captcha_url=args.captcha_url, otp=args.otp,
                         captcha_path=Path(args.captcha_file), log=log, portal=portal,
                         app_n=app_n)
        finally:
            if portal is not None:
                portal.stop()
        token = data["authToken"]
        app_n = data.get("_appN") or app_n
        name = f"{data.get('firstName', '')} {data.get('lastName', '')}".strip()
        log(f"✔ ورود موفق{(' — ' + name) if name else ''} ({describe_token(token)})")
        if data.get("sendOrderDelay"):
            log(f"ℹ️  sendOrderDelay کارگزار: {data['sendOrderDelay']}ms")
        save_token(token_file, base, token,
                   {"name": name, "sendOrderDelay": data.get("sendOrderDelay"), "appN": app_n,
                    "cookies": session_cookies(session, base)})
        log(f"💾 توکن در {token_file} ذخیره شد (دفعه‌ی بعد تا زمان انقضا نیازی به لاگین نیست).")

    apply_token(session, base, token, args.auth_mode)
    if app_n:
        session.headers["x-app-n"] = app_n  # ثبات x-app-n بین لاگین و سفارش‌ها
    return token
