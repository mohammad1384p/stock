#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
«نشستِ مرورگر» برای رفع خطای `HTTP 403 / errorCode 9009` (مشکل امنیتی.درخواست معتبر نمی باشد).

چرا لازم است؟
    لایه‌ی امنیتی سامانه‌های اکسیر فقط با «ورود موفق» قانع نمی‌شود؛ درخواست سفارش باید
    از نظر کوکی/هدر هم مثل یک مرورگر واقعی باشد. بخشی از این کوکی‌ها را `requests` هیچ‌وقت
    نمی‌گیرد، چون مرورگر آن‌ها را با بارگذاری صفحه و اجرای جاوااسکریپت (چالش فایروال/WAF)
    ست می‌کند؛ نه با یک درخواست ساده. نتیجه: لاگین موفق، ولی سفارش → «مشکل امنیتی».

این ماژول دو راه برای پر کردن این شکاف می‌دهد:

۱) `import` از مرورگر خودتان (بدون هیچ وابستگی جدید):
   خروجی «Copy as cURL» / «Copy as fetch» / هدرهای خام DevTools یا حتی یک رشته‌ی
   `Cookie: …` را به `parse_browser_session` بدهید؛ کوکی‌ها و هدرهای شناسایی
   (x-app-n، clientid، user-agent، origin، referer، sec-ch-ua*، …) بیرون کشیده می‌شوند و
   `apply_captured` آن‌ها را روی نشست ربات می‌گذارد. مقدارهای حساس هیچ‌جا چاپ نمی‌شوند.

۲) `browser_bootstrap` — رفتار مرورگر با همان نشست ربات:
   `GET /` (با دنبال‌کردن ریدایرکت‌ها)، خواندن صفحه‌ی ورود، گرفتن یک دارایی استاتیک و
   یک `GET /captcha` تازه. این کار کوکی‌های نشست/چالش (مثل `client_login_id` و اگر
   فایروال بدهد `cookiesession1`) را داخل *همان* نشستی می‌آورد که سفارش‌ها را می‌فرستد.

هر دو راه «قبل از ارسال» اجرا می‌شوند و نشستِ حاصل در فایل توکن ذخیره می‌شود تا اجرای
بعدی هم از همان کوکی‌ها استفاده کند.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests

# هدرهایی که هرگز از فایل import اعمال نمی‌شوند: یا transport هستند یا خودِ ربات
# (توکن/بدنه) آن‌ها را مدیریت می‌کند.
NEVER_IMPORT_HEADERS = frozenset({
    "cookie", "host", "content-length", "content-type", "connection", "accept-encoding",
    "transfer-encoding", "content-encoding", "authorization", "upgrade", "keep-alive",
    "te", "trailer", "proxy-authorization", "proxy-authenticate", "expect",
})

# کوکی‌هایی که در نمونه‌ی درخواست مرورگر دیده شده‌اند و ربات به‌تنهایی نمی‌تواند
# همه‌شان را بسازد (اسم‌ها برای هشدار/گزارش؛ مقدارها هیچ‌وقت چاپ نمی‌شوند).
BROWSER_ONLY_COOKIE_HINTS = {
    "cookiesession1": "کوکی چالش فایروال/WAF — مرورگر با اجرای جاوااسکریپت می‌گیرد",
    "client_login_id": "کوکی مرحله‌ی کپچا — bootstrap آن را تازه می‌کند",
}

_HEAD_RE = re.compile(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"\\]+")


def _c(code: str, s: str) -> str:
    try:
        import os
        import sys
        if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
            return f"\033[{code}m{s}\033[0m"
    except Exception:  # noqa: BLE001
        pass
    return s


def _log(log, text: str) -> None:
    if log is not None:
        log(text)


# --------------------------------------------------------------------------- #
#  تجزیه‌ی ورودی DevTools
# --------------------------------------------------------------------------- #
def parse_cookies(text: str) -> list[tuple[str, str]]:
    """رشته‌ی کوکی (``a=1; b=2`` یا خط ``Cookie: …``) → ``[(name, value), …]``."""
    out: list[tuple[str, str]] = []
    if not text:
        return out
    text = re.sub(r"^\s*(?:cookie|set-cookie)\s*:\s*", "", str(text).strip(), flags=re.I)
    for part in re.split(r"[;\n]", text):
        part = part.strip().strip(",")
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name = name.strip()
        if not name or " " in name:
            continue
        out.append((name, value.strip().strip('"')))
    return out


def _js_string(lit: str) -> str:
    q = lit[0]
    body = lit[1:-1]
    if q == '"':
        try:
            return json.loads(lit)
        except ValueError:
            pass
    return (body.replace("\\" + q, q).replace("\\n", "\n").replace("\\t", "\t")
            .replace('\\"', '"').replace("\\'", "'").replace("\\\\", "\\"))


def _parse_header_block(block: str) -> dict:
    """بلوک «name: 'value'» جاوااسکریپتی → دیکشنری هدر."""
    out: dict = {}
    for key, value in re.findall(
            r"[\"']([^\"']+)[\"']\s*:\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')", block):
        out[key.strip().lower()] = _js_string(value)
    return out


def _parse_curl(text: str) -> dict:
    url = ""
    method = ""
    headers: dict = {}
    cookie_text = ""
    for m in re.finditer(r"(?:^|\s)-H\s+(?:'([^']*)'|\"([^\"]*)\"|(\S+))", text):
        raw = next(g for g in m.groups() if g is not None)
        if ":" in raw:
            k, v = raw.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    for m in re.finditer(r"(?:^|\s)(?:--url|-X|--request|-b|--cookie|--data-raw|--data)\s+"
                         r"(?:'([^']*)'|\"([^\"]*)\"|(\S+))", text):
        flag = m.group(0).strip().split()[0]
        value = next(g for g in m.groups() if g is not None)
        if flag in ("-X", "--request"):
            method = value.strip().upper()
        elif flag in ("-b", "--cookie"):
            cookie_text = value
    m = re.search(r"(?:^|\s)(?:--url\s+)?(?:'|\")?(https?://[^\s'\"\\]+)", text)
    if m:
        url = m.group(1)
    if headers.get("cookie"):
        cookie_text = headers.pop("cookie")
    return {"kind": "curl", "url": url, "method": method, "headers": headers,
            "cookies": parse_cookies(cookie_text), "cookie_source": "curl -b" if cookie_text else ""}


def _parse_fetch(text: str) -> dict:
    url = ""
    m = re.search(r"fetch\s*\(\s*(\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*')", text)
    if m:
        url = _js_string(m.group(1))
    elif (u := _URL_RE.search(text)) is not None:
        url = u.group(0)

    headers: dict = {}
    m = re.search(r"[\"']?headers[\"']?\s*:\s*\{", text)
    if m:
        start = m.end() - 1
        depth = 0
        for j in range(start, len(text)):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    headers = _parse_header_block(text[start + 1:j])
                    break
    method = ""
    if (mm := re.search(r"[\"']?method[\"']?\s*:\s*[\"'](\w+)[\"']", text)):
        method = mm.group(1).upper()
    cookie_text = headers.pop("cookie", "")
    return {"kind": "fetch", "url": url, "method": method, "headers": headers,
            "cookies": parse_cookies(cookie_text), "cookie_source": "fetch headers.cookie" if cookie_text else ""}


def _parse_raw(text: str) -> dict:
    lines = text.splitlines()
    method = ""
    path = ""
    url = ""
    headers: dict = {}
    for i, ln in enumerate(lines):
        if (m := _HEAD_RE.match(ln)):
            method = m.group(1).upper()
            path = m.group(2)
            lines = lines[i + 1:]
            break
    url = path if path.startswith("http") else ""
    for ln in lines:
        if not ln.strip():
            break
        if ":" not in ln:
            continue
        k, v = ln.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    cookie_text = headers.pop("cookie", "")
    return {"kind": "raw", "url": url, "method": method, "headers": headers,
            "cookies": parse_cookies(cookie_text), "cookie_source": "raw Cookie header" if cookie_text else ""}


def _parse_bundle(text: str) -> dict | None:
    """نشستِ JSON (خروجی «ورود با مرورگر» یا فایل import) را می‌خواند."""
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict) or not any(k in data for k in ("cookies", "headers")):
        return None
    cookies: list[tuple[str, str]] = []
    for item in data.get("cookies") or []:
        if isinstance(item, dict):
            name, value = item.get("name"), item.get("value")
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            name, value = item[0], item[1]
        else:
            continue
        if name:
            cookies.append((str(name), str(value if value is not None else "")))
    headers = {str(k).lower(): str(v) for k, v in (data.get("headers") or {}).items()}
    return {"kind": str(data.get("kind") or "json"),
            "url": str(data.get("url") or ""),
            "method": str(data.get("method") or ""),
            "headers": headers,
            "cookies": cookies,
            "cookie_source": "json bundle",
            "storage": data.get("storage") if isinstance(data.get("storage"), dict) else None}


def parse_browser_session(text: str) -> dict:
    """
    ورودی کاربر (Copy as cURL / Copy as fetch / هدرهای خام / رشته‌ی کوکی) را می‌شکند.

    خروجی: ``{"kind", "url", "method", "headers", "cookies": [(name, value), …]}``
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("متنی برای وارد کردن نشست داده نشده است.")
    if raw.startswith("{"):
        bundle = _parse_bundle(raw)
        if bundle is not None:
            return bundle
    if re.search(r"(?:^|\s)curl\s", raw, re.I) or raw.lower().startswith("curl"):
        parsed = _parse_curl(raw)
    elif re.search(r"\bfetch\s*\(", raw):
        parsed = _parse_fetch(raw)
    elif _HEAD_RE.match(raw.splitlines()[0]):
        parsed = _parse_raw(raw)
    else:
        pairs = parse_cookies(raw)
        if not pairs:
            raise ValueError("در متن داده‌شده نه کوکی پیدا شد و نه هدر (Copy as cURL/fetch یا رشته‌ی Cookie بدهید).")
        parsed = {"kind": "cookie", "url": "", "method": "", "headers": {},
                  "cookies": pairs, "cookie_source": "cookie string"}
    if not parsed["cookies"] and not parsed["headers"]:
        raise ValueError("در متن داده‌شده نه کوکی پیدا شد و نه هدر.")
    parsed.setdefault("storage", None)
    return parsed


# --------------------------------------------------------------------------- #
#  اعمال روی نشست
# --------------------------------------------------------------------------- #
def host_family(host: str) -> str:
    """دامنه‌ی مادر یک میزبان (برای پذیرش کوکی‌های ``domain=.example.com``)."""
    host = (host or "").lower().lstrip(".")
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def host_is_same_site(captured_host: str, base_host: str) -> bool:
    if not captured_host or not base_host:
        return False
    captured_host = captured_host.lower()
    base_host = base_host.lower()
    if captured_host == base_host:
        return True
    return host_family(captured_host) == host_family(base_host)


# کوکی‌هایی که import نباید جایشان را بگیرد: توکن نشست را خودِ ربات (تازه) می‌گذارد.
IMPORT_SKIP_COOKIES = ("JWT-TOKEN",)


def imported_token(captured: dict) -> str | None:
    """اگر در کوکی‌های کپی‌شده از مرورگر توکن نشست بود، همان را برمی‌گرداند."""
    for name, value in captured.get("cookies") or []:
        if name.lower() == "jwt-token" and value:
            return value
    return None


def apply_captured(session: requests.Session, base: str, captured: dict,
                   log=None, *, replace_cookies: bool = True,
                   skip_cookies: tuple[str, ...] = IMPORT_SKIP_COOKIES) -> dict:
    """
    کوکی‌ها و هدرهای «نشستِ مرورگر» را روی ``session`` می‌گذارد.

    - کوکی‌ها روی میزبان کارگزاری ست می‌شوند (طوری‌که هنگام سفارش هم فرستاده شوند).
    - هدرهای مدیریّت‌شده (`Cookie`، `Authorization`، `Content-Length`، …) اعمال نمی‌شوند.
    - کوکی توکن (`JWT-TOKEN`) عمداً از فایل import اعمال نمی‌شود؛ توکن تازه را `apply_token`
      می‌گذارد تا نشست با یک توکن معتبر یکدست بماند (مقدار توکن مرورگر جداگانه استفاده می‌شود).
    - خروجی: خلاصه‌ای امن برای لاگ/گزارش (فقط نام‌ها، بدون مقدار).
    """
    base_host = urlparse(base).hostname or ""
    captured_host = urlparse(captured.get("url") or "").hostname or ""
    same_site = host_is_same_site(captured_host, base_host) if captured_host else True
    cookie_domain = captured_host if (captured_host and same_site) else base_host

    applied_headers: list[str] = []
    for name, value in (captured.get("headers") or {}).items():
        low = name.lower()
        if low in NEVER_IMPORT_HEADERS:
            continue
        if low in {"origin", "referer"} and not same_site:
            continue
        session.headers[low] = value
        applied_headers.append(low)

    applied_cookies: list[str] = []
    skipped_cookies: list[str] = []
    skip = {name.lower() for name in skip_cookies}
    for name, value in captured.get("cookies") or []:
        if name.lower() in skip:
            skipped_cookies.append(name)
            continue
        if replace_cookies:
            # مقدار تازه‌ی مرورگر باید جای مقدار قدیمی را بگیرد؛ چند کوکی هم‌نام با
            # دامنه/مسیر متفاوت باعث فرستادن دو مقدار هم‌نام و ابهام می‌شود.
            for existing in list(session.cookies):
                if existing.name == name and existing.domain and base_host \
                        and host_is_same_site(existing.domain, base_host):
                    session.cookies.clear(existing.domain, existing.path, existing.name)
        session.cookies.set(name, value, domain=cookie_domain or base_host, path="/")
        if name not in applied_cookies:
            applied_cookies.append(name)

    summary = {
        "kind": captured.get("kind", "?"),
        "url_host": captured_host or None,
        "same_site": bool(same_site),
        "cookies": applied_cookies,
        "skipped_cookies": sorted(set(skipped_cookies)),
        "headers": sorted(applied_headers),
        "identity": {k: session.headers.get(k, "") for k in ("x-app-n", "clientid") if session.headers.get(k) is not None},
    }
    if cookie_domain:
        session.headers.setdefault("origin", f"https://{base_host}")
    _log(log, f"🧩 نشست مرورگر اعمال شد ({summary['kind']}): "
              f"{len(applied_cookies)} کوکی [{', '.join(applied_cookies) or '—'}]"
              + (f" + {len(applied_headers)} هدر [{', '.join(sorted(applied_headers)) or '—'}]"
                 if applied_headers else ""))
    if not same_site and captured_host:
        _log(log, f"⚠️  آدرس درخواست کپی‌شده ({captured_host}) با کارگزاری ({base_host}) یکی نیست؛ "
                  "هدرهای origin/referer از آن اعمال نشدند.")
    return summary


def session_summary(session: requests.Session, base: str) -> dict:
    """نام کوکی‌ها/هدرهای شناسایی نشست فعلی (برای لاگ و گزارش؛ بدون مقدار حساس)."""
    host = urlparse(base).hostname or ""
    names = sorted({c.name for c in session.cookies if not c.domain or host_is_same_site(c.domain, host)})
    header_keys = {k.lower() for k in session.headers}
    return {
        "cookie_names": names,
        "identity_headers": {k: k in header_keys for k in ("x-app-n", "clientid", "user-agent", "origin", "referer")},
        "missing_browser_cookies": [n for n in BROWSER_ONLY_COOKIE_HINTS if n not in names],
    }


def security_cookie_warnings(session: requests.Session, base: str) -> list[str]:
    """هشدارهای آماده برای لاگ: کوکی‌هایی که در نشست مرورگر هست ولی در نشست ربات نیست."""
    missing = session_summary(session, base)["missing_browser_cookies"]
    if not missing:
        return []
    lines = ["⚠️  این کوکی‌ها در نشست فعلی نیستند (در نمونه‌ی درخواست مرورگر دیده شده‌اند):"]
    for name in missing:
        lines.append(f"      • {name} — {BROWSER_ONLY_COOKIE_HINTS[name]}")
    lines.append("      برای اضافه‌کردن: از مرورگر «Copy as cURL» بگیرید و با --import-session بدهید "
                 "(یا در پنل، کادر «نشست مرورگر» را پر کنید)، یا bootstrap را روشن نگه دارید.")
    return lines


# --------------------------------------------------------------------------- #
#  bootstrap رفتار مرورگر
# --------------------------------------------------------------------------- #
DEFAULT_PAGES = ("/", "/new-exir/login")
_ASSET_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+\.(?:js|css)[^"']*)["']""", re.I)
LOGIN_BOOTSTRAP_MODES = ("off", "page", "captcha", "page+captcha")


def normalize_mode(mode: str | None) -> str:
    """`auto`/`on`/`full` → رفتار کامل، `off`/خالی → خاموش."""
    raw = (mode or "").strip().lower()
    if raw in ("", "auto", "on", "full", "all", "default"):
        return "page+captcha"
    if raw in ("off", "none", "خاموش", "0", "no"):
        return "off"
    if raw in LOGIN_BOOTSTRAP_MODES:
        return raw
    return "page+captcha"


def browser_bootstrap(session: requests.Session, base: str, log=None, *,
                      mode: str = "page+captcha", captcha_url: str | None = None,
                      pages: tuple[str, ...] = DEFAULT_PAGES, assets: int = 1,
                      timeout: float = 10.0, budget: float | None = None) -> dict:
    """
    رفتار «بارگذاری صفحه»ی مرورگر را با همان نشستِ ربات انجام می‌دهد:

      * `GET /` و صفحه‌ی ورود، با **دنبال‌کردن** ریدایرکت‌ها (کوکی هر مرحله گرفته می‌شود)،
      * خواندن یک فایل استاتیک همان صفحه (js/css) — مرورگر این کار را هم می‌کند،
      * `GET /captcha` تازه (کوکی `client_login_id` را به‌روز می‌کند؛ خودِ تصویر دور ریخته می‌شود).

    هیچ کدی خوانده/حل نمی‌شود و هیچ سفارشی فرستاده نمی‌شود. خروجی: گزارش امن برای لاگ.
    """
    mode = normalize_mode(mode)
    report: dict = {"mode": mode, "pages": [], "assets": 0, "captcha": False,
                    "new_cookies": [], "final_url": None, "redirected": False,
                    "ok": False, "errors": [], "elapsed_ms": 0.0}
    if mode == "off":
        return report

    import time
    host_before = {c.name for c in session.cookies}
    started = time.perf_counter()

    def over_budget() -> bool:
        return budget is not None and (time.perf_counter() - started) > budget

    want_pages = mode in ("page", "page+captcha")
    want_captcha = mode in ("captcha", "page+captcha")
    html = ""
    for path in (pages if want_pages else ()):
        if over_budget():
            break
        url = base + (path if path.startswith("/") else "/" + path)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True,
                            headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                     "sec-fetch-dest": "document", "sec-fetch-mode": "navigate",
                                     "sec-fetch-site": "none" if path == "/" else "same-origin"})
        except Exception as e:  # noqa: BLE001
            report["errors"].append(f"GET {path}: {e}")
            continue
        entry = {"path": path, "status": r.status_code, "url": r.url}
        report["pages"].append(entry)
        if report["final_url"] is None and r.history:
            report["redirected"] = True
            report["final_url"] = r.url
        if not html and r.headers.get("content-type", "").lower().startswith("text/html"):
            html = r.text[:200_000]

    if want_pages and html and assets > 0 and not over_budget():
        urls = []
        for m in _ASSET_RE.finditer(html):
            target = urljoin(base + "/", m.group(1))
            if urlparse(target).netloc == urlparse(base).netloc and target not in urls:
                urls.append(target)
            if len(urls) >= assets:
                break
        for target in urls:
            if over_budget():
                break
            try:
                # فقط سرآیندها لازم است (کوکی/چالش)؛ بدنه دانلود نمی‌شود.
                with session.get(target, timeout=timeout, stream=True, allow_redirects=True,
                                 headers={"accept": "*/*", "sec-fetch-dest": "script",
                                          "sec-fetch-mode": "no-cors", "sec-fetch-site": "same-origin"}) as r:
                    r.close()
                report["assets"] += 1
            except Exception as e:  # noqa: BLE001
                report["errors"].append(f"GET asset: {e}")

    if want_captcha and not over_budget():
        candidates = [captcha_url] if captcha_url else ["/captcha"]
        for candidate in candidates:
            url = candidate if str(candidate).startswith("http") else base + "/" + str(candidate).lstrip("/")
            try:
                r = session.get(url, timeout=timeout, allow_redirects=False,
                                headers={"accept": "application/json, text/plain, */*",
                                         "sec-fetch-dest": "empty", "sec-fetch-mode": "cors",
                                         "sec-fetch-site": "same-origin"})
            except Exception as e:  # noqa: BLE001
                report["errors"].append(f"GET captcha: {e}")
                continue
            if r.status_code == 200:
                # اگر کوکی کپچا در هدر آمد و در jar ننشست، دستی اضافه شود.
                cid = r.headers.get("client_login_id")
                host = urlparse(base).hostname or ""
                if cid and not session.cookies.get("client_login_id"):
                    session.cookies.set("client_login_id", cid, domain=host, path="/")
                report["captcha"] = True
                break
            report["errors"].append(f"GET captcha → HTTP {r.status_code}")

    now_cookies = {c.name for c in session.cookies}
    report["new_cookies"] = sorted(now_cookies - host_before)
    report["ok"] = bool(report["pages"] or report["captcha"])
    report["elapsed_ms"] = round((time.perf_counter() - started) * 1000, 1)

    if report["ok"]:
        details = []
        if report["pages"]:
            last = report["pages"][-1]
            details.append(f"صفحه {last['status']} ({len(report['pages'])} مورد)")
        if report["assets"]:
            details.append(f"{report['assets']} فایل استاتیک")
        if report["captcha"]:
            details.append("کوکی کپچا تازه شد")
        _log(log, f"🧭 bootstrap مرورگر: " + " | ".join(details)
                  + (f" | {report['elapsed_ms']:.0f}ms" if report["elapsed_ms"] else ""))
        if report["new_cookies"]:
            _log(log, "🍪 کوکی‌های تازه در نشست: " + ", ".join(report["new_cookies"]))
        if report["redirected"] and report["final_url"]:
            _log(log, f"ℹ️  مسیر نهایی صفحه: {report['final_url']}")
    elif report["errors"]:
        _log(log, "⚠️  bootstrap مرورگر نیمه‌کاره ماند: " + "; ".join(report["errors"][:3]))
    return report


# --------------------------------------------------------------------------- #
#  ذخیره/بازخوانی نشستِ واردشده در فایل توکن
# --------------------------------------------------------------------------- #
def load_captured_session(path: Path, base: str) -> dict | None:
    """نشستِ ذخیره‌شده (کوکی/هدرهای واردشده) را از فایل توکن می‌خواند."""
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
    entry = data.get(base) or {}
    captured = entry.get("captured_session")
    return captured if isinstance(captured, dict) else None


def save_captured_session(path: Path, base: str, captured: dict) -> None:
    """نشستِ واردشده را کنار توکن در فایل ذخیره می‌کند (بدون دست‌زدن به توکن)."""
    data = {}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = {}
    entry = data.get(base)
    if not isinstance(entry, dict):
        entry = {}
    entry["captured_session"] = captured
    data[base] = entry
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        import os
        os.chmod(path, 0o600)
    except OSError:
        pass
