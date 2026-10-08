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

LOGIN_PATH = "/api/v2/login"
# آدرس دقیق کپچا در درخواست‌های ارسالی مشخص نبود؛ این‌ها به ترتیب امتحان می‌شوند.
# اگر هیچ‌کدام کار نکرد، آدرس درست را با --captcha-url بدهید.
CAPTCHA_CANDIDATES = (
    "/api/v2/captcha",
    "/api/v1/captcha",
    "/api/v2/login/captcha",
    "/api/v1/login/captcha",
    "/api/v2/captcha/image",
    "/api/v1/captcha/image",
    "/captcha",
)
TOKEN_COOKIE = "JWT-TOKEN"


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


def apply_token(session: requests.Session, base: str, token: str, mode: str) -> None:
    """قرار دادن توکن روی session: به‌صورت کوکی JWT-TOKEN و/یا هدر Authorization."""
    host = urlparse(base).hostname or ""
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
            r = session.get(u, params={"t": int(time.time() * 1000)}, timeout=10,
                            headers={"accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8, application/json",
                                     "referer": f"{base}/new-exir/login"})
        except Exception as e:  # noqa: BLE001
            last_err = str(e)
            continue
        if r.status_code == 200:
            img = _extract_image(r)
            if img:
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

    # نمایش داخل ترمینال (در صورت نصب بودن Pillow)
    if ext != ".svg":
        try:
            from io import BytesIO
            from PIL import Image  # type: ignore

            im = Image.open(BytesIO(img)).convert("RGB")
            width = min(80, shutil.get_terminal_size((80, 24)).columns - 2)
            h = max(2, int(im.height * width / im.width))
            h += h % 2
            im = im.resize((width, h))
            px = im.load()
            out = []
            for y in range(0, h, 2):
                row = []
                for x in range(width):
                    r1, g1, b1 = px[x, y]
                    r2, g2, b2 = px[x, y + 1]
                    row.append(f"\033[38;2;{r1};{g1};{b1}m\033[48;2;{r2};{g2};{b2}m▀")
                out.append("".join(row) + "\033[0m")
            print("\n".join(out), flush=True)
            return
        except Exception:  # noqa: BLE001
            pass

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


def login(session: requests.Session, base: str, username: str, password: str, *,
          captcha_url: str | None, otp: str | None, captcha_path: Path,
          log, max_tries: int = 3) -> dict:
    """لاگین تعاملی. خروجی: دیکشنری پاسخ سرور (شامل authToken)."""
    url = base + LOGIN_PATH
    for attempt in range(1, max_tries + 1):
        img = fetch_captcha(session, base, captcha_url, log)
        show_captcha(img, captcha_path, log)
        captcha = input("کد کپچا را وارد کنید: ").strip()
        body = {"username": username, "password": password, "captcha": captcha, "otp": otp or ""}
        headers = {
            "accept": "application/json",
            "referer": f"{base}/new-exir/login",
            "clientid": "",
            "x-app-n": f"NaN.{random.randint(10_000_000, 99_999_999)}",
        }
        r = session.post(url, json=body, headers=headers, timeout=15)
        try:
            data = r.json()
        except ValueError:
            data = {"raw": r.text[:1000]}

        token = (data.get("authToken") if isinstance(data, dict) else None) or session.cookies.get(TOKEN_COOKIE)
        if r.status_code == 200 and token:
            data["authToken"] = token
            return data

        log(f"✘ لاگین ناموفق (HTTP {r.status_code}):\n{json.dumps(_mask(data), ensure_ascii=False, indent=2)}")
        text = json.dumps(data, ensure_ascii=False).lower()
        if not otp and ("otp" in text or "یکبار" in text or "پیامک" in text or "دو مرحله" in text):
            otp = input("کد یکبار مصرف (OTP): ").strip()
        if attempt < max_tries:
            log(f"… تلاش دوباره ({attempt + 1}/{max_tries})")
    raise RuntimeError("لاگین بعد از چند تلاش ناموفق بود.")


def ensure_token(session: requests.Session, args, log, interactive: bool) -> str:
    """توکن را از --token، فایل ذخیره، یا لاگین تعاملی به‌دست می‌آورد و روی session قرار می‌دهد."""
    base = args.base_url.rstrip("/")
    token_file = Path(args.token_file)

    token: str | None = None
    if args.token and not args.login:
        token = clean_token(args.token)
        log(f"🔑 استفاده از توکن داده‌شده ({describe_token(token)})")
    elif not args.login:
        saved = load_saved_token(token_file, base)
        if saved:
            token = saved["token"]
            log(f"🔑 استفاده از توکن ذخیره‌شده در {token_file} ({describe_token(token)})")

    if not token:
        if not interactive and not (args.username and args.password):
            raise RuntimeError("توکن معتبری نیست و ورودی تعاملی هم در دسترس نیست. --token یا --username/--password بدهید.")
        log("🔐 ورود به حساب کاربری")
        username = args.username or input("نام کاربری: ").strip()
        password = args.password or getpass.getpass("رمز عبور (نمایش داده نمی‌شود): ")
        data = login(session, base, username, password,
                     captcha_url=args.captcha_url, otp=args.otp,
                     captcha_path=Path(args.captcha_file), log=log)
        token = data["authToken"]
        name = f"{data.get('firstName', '')} {data.get('lastName', '')}".strip()
        log(f"✔ ورود موفق{(' — ' + name) if name else ''} ({describe_token(token)})")
        if data.get("sendOrderDelay"):
            log(f"ℹ️  sendOrderDelay کارگزار: {data['sendOrderDelay']}ms")
        save_token(token_file, base, token, {"name": name, "sendOrderDelay": data.get("sendOrderDelay")})
        log(f"💾 توکن در {token_file} ذخیره شد (دفعه‌ی بعد تا زمان انقضا نیازی به لاگین نیست).")

    apply_token(session, base, token, args.auth_mode)
    return token
