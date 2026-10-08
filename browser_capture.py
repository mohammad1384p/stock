#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ورود با مرورگر واقعی و استخراج «نشستِ مرورگر» (Playwright) — راه قطعی برای کوکی‌هایی که
`requests` نمی‌تواند بگیرد.

مسئله: بخشی از کوکی‌های لایه‌ی امنیتی (مثل کوکی چالش فایروال) را مرورگر با *اجرای
جاوااسکریپت* می‌گیرد؛ هیچ درخواست ساده‌ای (requests) آن‌ها را به دست نمی‌آورد. به همین
دلیل لاگین موفق است ولی سفارش با `403 / errorCode 9009` رد می‌شود.

راه‌حل: یک مرورگر واقعی (Chromium بی‌سر) روی **همان سروری** که سفارش‌ها را می‌فرستد بالا
می‌آید، خودِ کارگزاری را باز می‌کند، فرم ورود را پر می‌کند، تصویر کپچا را به کاربر نشان
می‌دهد (همان صفحه‌ی کپچای پنل/ترمینال) و بعد از ورود، **کوکی‌ها + هدرهای واقعی درخواست‌ها
+ localStorage** را برمی‌گرداند. ربات آن نشست را ذخیره می‌کند و بعد ارسال‌های سریع و
زمان‌بندی‌شده را با `requests` انجام می‌دهد (دقت میلی‌ثانیه‌ای حفظ می‌شود).

نصب (اختیاری):
    python -m pip install playwright
    python -m playwright install chromium

اگر Playwright نصب نباشد، همه‌چیز مثل قبل کار می‌کند و فقط همین قابلیت در دسترس نیست
(جایگزین: «Copy as cURL» از مرورگر خودتان + `--import-session`).
"""

from __future__ import annotations

import base64
import json
import re
from urllib.parse import urlparse

# انتخابگرهای صفحه‌ی ورود اکسیر (از روی DOM واقعی سامانه؛ اگر نسخه‌ی دیگری بود،
# اولین انتخابگرِ موجود استفاده می‌شود).
LOGIN_SELECTORS: dict[str, list[str]] = {
    "username": ["#userNameInput", "input[name='username']", "#username", "input[type='text']"],
    "password": ["#mat-input-2", "input[type='password']", "#password"],
    "captcha": ["#captchaText", "input[name='captcha']", "#captcha-input", "#captchaInput"],
    "captcha_image": ["#captcha", "img#captchaImg", "img[alt*='captcha' i]", "img[src*='captcha']"],
    "otp": ["#otp", "input[name='otp']"],
    "submit": ["#btn-login", "button[type='submit']", "button:has-text('ورود')"],
}

# هدرهایی که از آخرین درخواست XHR مرورگر برداشته می‌شود (بقیه را ربات خودش دارد)
IDENTITY_HEADERS = ("x-app-n", "clientid", "user-agent", "origin", "referer", "accept",
                    "accept-language", "content-type")


def playwright_available() -> bool:
    """آیا Playwright نصب است؟"""
    return _load_playwright() is not None


def _load_playwright():
    """``sync_playwright`` را برمی‌گرداند یا ``None``."""
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:  # noqa: BLE001  (ImportError یا خطای محیط)
        return None
    return sync_playwright


def _first_present(page, selectors: list[str]) -> str | None:
    for selector in selectors:
        try:
            if page.locator(selector).count() > 0:
                return selector
        except Exception:  # noqa: BLE001
            continue
    return None


def _captcha_bytes(page, selectors: list[str]) -> bytes | None:
    """تصویر کپچا را از خودِ صفحه می‌گیرد (data:image یا آدرس تصویر با کوکی مرورگر)."""
    selector = _first_present(page, selectors)
    if selector is None:
        return None
    try:
        src = page.get_attribute(selector, "src") or ""
    except Exception:  # noqa: BLE001
        return None
    if src.startswith("data:image"):
        _, _, payload = src.partition(",")
        try:
            return base64.b64decode(payload + "=" * (-len(payload) % 4))
        except Exception:  # noqa: BLE001
            return None
    if not src:
        return None
    try:
        if src.startswith("/"):
            src = page.url.rstrip("/") + src
        request_ctx = getattr(getattr(page, "context", None), "request", None) or getattr(page, "request", None)
        response = request_ctx.get(src)
        return response.body()
    except Exception:  # noqa: BLE001
        return None


def capture_browser_session(base: str, *, username: str, password: str, otp: str = "",
                            captcha_provider=None, log=lambda *a: None,
                            headless: bool = True, timeout: float = 90.0,
                            wait_after_login: float = 3.0,
                            selectors: dict | None = None,
                            keep_open: bool = False,
                            after_login=None) -> dict:
    """
    با مرورگر واقعی وارد کارگزاری می‌شود و نشستش را برمی‌گرداند.

    ``after_login`` (اختیاری) بعد از ورود موفق و *پیش از بستن مرورگر* با صفحه صدا زده
    می‌شود؛ برای «آزمایش امنیتی داخل همان مرورگر لاگین‌شده» (``--browser-probe``) استفاده
    می‌شود و خروجی‌اش در کلید ``probe`` همان نشست می‌آید.

    ``captcha_provider`` یک تابع است که تصویر کپچا (bytes) می‌گیرد و کد را برمی‌گرداند
    (در ربات: همان صفحه‌ی کپچای پنل/ترمینال). خروجی:

        {"kind": "browser", "url", "cookies": [(name, value)], "headers": {...},
         "storage": {"local": {...}, "session": {...}}, "user_agent": "..."}

    این خروجی دقیقاً همان قالبِ «نشستِ مرورگر» است که `session_capture.apply_captured`
    (و `--import-session`) می‌فهمد؛ پس ذخیره/اعمالش یک مسیر مشترک دارد.
    """
    sync_playwright = _load_playwright()
    if sync_playwright is None:
        raise RuntimeError(
            "Playwright نصب نیست. برای ورود با مرورگر واقعی:\n"
            "    python -m pip install playwright\n"
            "    python -m playwright install chromium\n"
            "اگر نصب آن ممکن نیست، از مرورگر خودتان «Copy as cURL» بگیرید و با "
            "--import-session بدهید."
        )
    if not username or not password:
        raise RuntimeError("نام کاربری و رمز عبور برای ورود با مرورگر لازم است.")
    if captcha_provider is None:
        raise RuntimeError("برای ورود با مرورگر باید تصویر کپچا به کاربر نشان داده شود "
                           "(captcha_provider تنظیم نشده است).")

    sel = {k: list(v) for k, v in LOGIN_SELECTORS.items()}
    for key, value in (selectors or {}).items():
        if key in sel and value:
            sel[key] = [value] if isinstance(value, str) else list(value)

    base = base.rstrip("/")
    host = urlparse(base).hostname or ""
    captured_requests: list[dict] = []
    bundle_probe: dict | None = None
    cookies: list[dict] = []
    storage: dict = {}
    user_agent = ""
    order_headers: dict = {}

    def on_request(request) -> None:
        try:
            if urlparse(request.url).hostname != host:
                return
            if request.method not in ("POST", "PUT", "PATCH"):
                return
            headers = {k.lower(): v for k, v in (request.headers or {}).items()}
            captured_requests.append({"url": request.url, "method": request.method, "headers": headers})
        except Exception:  # noqa: BLE001
            return

    log("🌐 مرورگر واقعی در حال بالا آمدن (Chromium)…")
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context(locale="fa-IR", timezone_id="Asia/Tehran",
                                      viewport={"width": 1280, "height": 900})
        context.on("request", on_request)
        page = context.new_page()
        try:
            log(f"🌐 باز کردن {base}/ …")
            page.goto(base + "/", wait_until="domcontentloaded", timeout=timeout * 1000)

            user_selector = _first_present(page, sel["username"])
            pass_selector = _first_present(page, sel["password"])
            if not user_selector or not pass_selector:
                raise RuntimeError("فرم ورود در صفحه پیدا نشد؛ صفحه‌ی ورود کارگزاری باز نشد "
                                   "(یا ساختار آن تغییر کرده است).")
            page.fill(user_selector, username)
            page.fill(pass_selector, password)

            captcha_selector = _first_present(page, sel["captcha"])
            image_selector = _first_present(page, sel["captcha_image"])
            image = _captcha_bytes(page, sel["captcha_image"]) if image_selector else None
            if not image:
                log("⚠️  تصویر کپچا از DOM خوانده نشد؛ از اسکرین‌شات عنصر استفاده می‌شود.")
                if image_selector:
                    page.screenshot(path="captcha_browser.png")
            code = captcha_provider(image) if image else None
            if not code:
                raise RuntimeError("کد کپچا دریافت نشد (کاربر کدی نفرستاد یا تصویر پیدا نشد).")

            if captcha_selector:
                page.fill(captcha_selector, code)
            if otp:
                otp_selector = _first_present(page, sel["otp"])
                if otp_selector:
                    page.fill(otp_selector, otp)

            submit_selector = _first_present(page, sel["submit"])
            if submit_selector:
                page.click(submit_selector)
            else:
                page.keyboard.press("Enter")

            # انتظار برای ترک صفحه‌ی ورود (ورود موفق) — تا سقف timeout
            login_url = base.rstrip("/") + "/"
            waited = 0.0
            step = 0.5
            while waited < timeout:
                current = (page.url or "")
                if current and not current.rstrip("/").endswith("login") and current.rstrip("/") != login_url.rstrip("/"):
                    break
                page.wait_for_timeout(int(step * 1000))
                waited += step
            try:
                page.wait_for_load_state("networkidle", timeout=10_000)
            except Exception:  # noqa: BLE001
                pass
            if wait_after_login > 0:
                page.wait_for_timeout(int(wait_after_login * 1000))

            user_agent = page.evaluate("() => navigator.userAgent") or ""
            try:
                storage = page.evaluate(
                    "() => ({local: {...localStorage}, session: {...sessionStorage}})")
            except Exception:  # noqa: BLE001
                storage = {}
            if after_login is not None:
                probe_result = after_login(page)
                if probe_result is not None:
                    bundle_probe = probe_result
            cookies = context.cookies()
            final_url = page.url or ""
            if keep_open:
                log("ℹ️  مرورگر باز نگه داشته می‌شود تا خودتان بررسی کنید (Ctrl+C برای بستن).")
                try:
                    page.wait_for_timeout(int(timeout * 1000))
                except Exception:  # noqa: BLE001
                    pass
        finally:
            try:
                browser.close()
            except Exception:  # noqa: BLE001
                pass

    # هدرهای شناسایی از «آخرین» درخواست POST مرورگر (همان‌هایی که لایه‌ی امنیتی می‌بیند)
    if captured_requests:
        last = captured_requests[-1]
        order_headers = {k: v for k, v in last["headers"].items() if k in IDENTITY_HEADERS}

    bundle = {
        "kind": "browser",
        "url": final_url or (base + "/"),
        "cookies": [[c.get("name", ""), c.get("value", "")] for c in cookies if c.get("name")],
        "headers": order_headers,
        "storage": storage,
        "user_agent": user_agent,
        "captured_requests": len(captured_requests),
    }
    if bundle_probe is not None:
        bundle["probe"] = bundle_probe
    names = [name for name, _ in bundle["cookies"]]
    log(f"🌐 نشست مرورگر گرفته شد: {len(names)} کوکی [{', '.join(names) or '—'}]"
        + (f" | هدرها: {', '.join(sorted(order_headers))}" if order_headers else
           " | (هیچ درخواست POST مرورگر دیده نشد؛ هدرهای شناسایی از کوکی‌ها می‌آید)"))
    return bundle


def captcha_provider_from_portal(portal, log, ttl: int = 120):
    """
    سازگار با ``capture_browser_session``: تصویر را در صفحه‌ی کپچای پنل/ترمینال نشان می‌دهد
    و کد را از کاربر می‌گیرد (منبع مشترک با لاگین معمولی).
    """
    def provider(image: bytes | None):
        if image and portal is not None:
            portal.set_image(image)
            portal.announce()
        elif portal is not None:
            portal.set_state("captcha", "تصویر کپچا در دسترس نیست؛ کد را در ترمینال وارد کنید.")
        if portal is None:
            # بدون صفحه‌ی کپچا: اگر ترمینال تعاملی است، همان‌جا کد را بپرس
            try:
                import sys
                if sys.stdin is not None and sys.stdin.isatty():
                    return input("کد کپچای تصویر مرورگر را وارد کنید: ").strip() or None
            except Exception:  # noqa: BLE001
                return None
            return None
        code, source = portal.wait_for_code(ttl)
        if code:
            log(f"⌨️  کد کپچا از {'مرورگر' if source == 'web' else 'ترمینال'} دریافت شد: {code}")
        return code or None
    return provider


def session_json(bundle: dict) -> str:
    """نشست را به JSON قابل ذخیره/انتقال تبدیل می‌کند (قالبِ مشترک با --import-session)."""
    return json.dumps(bundle, ensure_ascii=False)


_JSON_COOKIE_KEYS = ("cookies", "headers")


def looks_like_bundle(text: str) -> bool:
    """آیا متن یک نشستِ JSON (خروجی مرورگر/import) است؟"""
    stripped = (text or "").strip()
    if not stripped.startswith("{"):
        return False
    if not re.search(r"\"" + "|".join(_JSON_COOKIE_KEYS), stripped):
        return False
    try:
        data = json.loads(stripped)
    except ValueError:
        return False
    return isinstance(data, dict) and "cookies" in data
