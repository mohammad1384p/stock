#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ارسال سفارش از **داخل مرورگر واقعی** (Playwright) — باوفادارترین راه به درخواست مرورگر.

چرا لازم است: اگر لایه‌ی امنیتی کارگزاری کوکی/نشانه‌ای را بخواهد که فقط با اجرای
جاوااسکریپت در یک مرورگر واقعی ساخته می‌شود (چالش فایروال، اثر انگشت TLS/HTTP2،
هدرهای خودِ مرورگر)، درخواستی که با `requests` می‌رود «معتبر» شمرده نمی‌شود و با
`403 / errorCode 9009` («مشکل امنیتی.درخواست معتبر نمی باشد») رد می‌شود.

راه‌حل: یک Chromium (بی‌سر) باز می‌شود، نشستِ ذخیره‌شده (کوکی/هدرهای همان مرورگر یا
نشست import‌شده) به آن داده می‌شود، صفحه‌ی خودِ کارگزاری باز می‌ماند و سفارش‌ها با
`fetch` از **داخل همان صفحه** و در زمان دقیق (setTimeout + اسپینِ چند میلی‌ثانیه‌ی
آخر) فرستاده می‌شوند. یعنی کوکی‌ها، هدرهای خودکار مرورگر و لایه‌ی شبکه همه مثل یک
کاربر واقعی است، ولی زمان‌بندی هنوز با ربات است.

نکته‌ها:
  * این ماژول با `requests` کار نمی‌کند؛ برای مسیر عادی (سریع و سبک) همان exir_bot.py
    کافی است. این قابلیت «راه پشتیبان» است، نه پیش‌فرض.
  * نیاز به نصب جداگانه:  python -m pip install playwright && python -m playwright install chromium
  * دقت زمان‌بندی حدود چند میلی‌ثانیه است (تایمر مرورگر)؛ در برابر «یک بار در زمان
    مشخص و بعد تکرار» کاملاً کافی است.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlparse

import browser_capture

# هدرهایی که fetch اجازه‌ی فرستادنشان را ندارد یا خود مرورگر می‌گذارد (نباید دستی داده شوند)
FORBIDDEN_FETCH_HEADERS = {
    "accept-charset", "accept-encoding", "connection", "content-length", "cookie", "cookie2",
    "date", "dnt", "expect", "host", "keep-alive", "origin", "referer", "set-cookie", "te",
    "trailer", "transfer-encoding", "upgrade", "user-agent", "via",
}

# کارهایی که از داخل صفحه انجام می‌شود: تزریق زمان‌بند + خواندن نتیجه‌ها
SCHEDULER_JS = r"""
(() => {
  const cfg = __CFG__;
  const state = window.__exirOrders = {running: true, stop: false, done: false,
                                       fired: 0, results: [], error: null};
  const forbidden = new Set(cfg.forbidden || []);
  const clean = {};
  for (const [k, v] of Object.entries(cfg.headers || {})) {
    const key = String(k).toLowerCase();
    if (forbidden.has(key) || key.startsWith('sec-') || key.startsWith('proxy-')) continue;
    clean[k] = v;
  }
  const fire = (k, target) => {
    const sentAt = Date.now();
    const opts = {method: cfg.method || 'POST', headers: clean, credentials: 'include',
                  cache: 'no-store'};
    if (cfg.body !== null && cfg.body !== undefined) opts.body = cfg.body;
    return fetch(cfg.url, opts).then(async (resp) => {
      let text = '';
      try { text = await resp.text(); } catch (e) { text = ''; }
      state.results.push({k: k, target: target, sent: sentAt, got: Date.now(),
                          status: resp.status, body: String(text).slice(0, 4000), error: null});
      if (cfg.stop_on_security && (resp.status === 401 || resp.status === 403)) state.stop = true;
    }).catch((err) => {
      state.results.push({k: k, target: target, sent: sentAt, got: Date.now(), status: 0,
                          body: '', error: String(err)});
    });
  };
  const spinTo = (target) => {            // چند میلی‌ثانیه‌ی آخر را دقیق می‌زنیم
    const delta = target - Date.now();
    if (delta > 8) return false;
    const until = performance.now() + Math.max(0, delta);
    while (performance.now() < until) { /* busy wait */ }
    return true;
  };
  const tick = () => {
    if (!state.running) return;
    const now = Date.now();
    let next = null;
    while (!state.stop && state.fired < cfg.times.length) {
      const target = cfg.times[state.fired];
      if (target - now > 8) { next = target; break; }
      if (!spinTo(target)) { next = target; break; }
      fire(state.fired + 1, target);
      state.fired += 1;
      break;                              // بقیه در تیک‌های بعدی (تا صفحه قفل نشود)
    }
    if (state.stop) { state.done = true; state.running = false; return; }
    if (state.fired >= cfg.times.length) {
      if (state.results.length >= cfg.times.length) { state.done = true; state.running = false; return; }
      setTimeout(tick, 20);               // منتظر پاسخ درخواست‌های در جریان
      return;
    }
    const wait = (next !== null ? next : now + 1) - Date.now() - 4;
    setTimeout(tick, Math.max(0, wait));
  };
  tick();
  return {planned: cfg.times.length, started: state.running};
})()
"""

PROBE_JS = r"""
async (cfg) => {
  const forbidden = new Set(cfg.forbidden || []);
  const clean = {};
  for (const [k, v] of Object.entries(cfg.headers || {})) {
    const key = String(k).toLowerCase();
    if (forbidden.has(key) || key.startsWith('sec-') || key.startsWith('proxy-')) continue;
    clean[k] = v;
  }
  const t0 = Date.now();
  try {
    const resp = await fetch(cfg.url, {method: 'POST', headers: clean, body: cfg.body,
                                       credentials: 'include', cache: 'no-store'});
    let text = '';
    try { text = await resp.text(); } catch (e) { text = ''; }
    return {ok: true, status: resp.status, ms: Date.now() - t0, body: String(text).slice(0, 4000)};
  } catch (err) {
    return {ok: false, status: 0, ms: Date.now() - t0, body: '', error: String(err)};
  }
}
"""


def browser_available() -> bool:
    """آیا Playwright نصب است؟ (وگرنه فقط مسیر `requests` در دسترس است)"""
    return browser_capture._load_playwright() is not None


def _clean_headers(headers: dict | None) -> dict:
    """هدرهای امن برای fetch داخل صفحه: بدون هدرهای ممنوعه/خودکارِ مرورگر."""
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if value is None:
            continue
        name = str(key).strip()
        if not name:
            continue
        low = name.lower()
        if low in FORBIDDEN_FETCH_HEADERS or low.startswith("sec-") or low.startswith("proxy-"):
            continue
        out[name] = str(value)
    return out


class BrowserOrders:
    """
    یک مرورگر واقعی که صفحه‌ی کارگزاری را باز نگه می‌دارد و سفارش‌ها را از داخل صفحه می‌فرستد.

    استفاده:

        orders = BrowserOrders(base, bundle=bundle, log=print)
        orders.open()
        try:
            orders.schedule(url, payload, times_ms, headers=headers)
            ...
        finally:
            orders.close()
    """

    def __init__(self, base: str, *, bundle: dict | None = None, headless: bool = True,
                 timeout: float = 60.0, log=lambda *a: None, path: str = "/",
                 locale: str = "fa-IR", timezone_id: str = "Asia/Tehran",
                 keep_open: bool = False):
        self.base = base.rstrip("/")
        self.origin = f"{urlparse(self.base).scheme}://{urlparse(self.base).netloc}"
        self.bundle = bundle or {}
        self.headless = headless
        self.timeout = timeout
        self.log = log
        self.path = path
        self.locale = locale
        self.timezone_id = timezone_id
        self.keep_open = keep_open
        self._pw = None
        self._browser = None
        self._context = None
        self.page = None
        self.final_url = ""

    # -- چرخه‌ی عمر ---------------------------------------------------------- #
    def open(self) -> None:
        sync_playwright = browser_capture._load_playwright()
        if sync_playwright is None:
            raise RuntimeError(
                "Playwright نصب نیست. برای ارسال سفارش از داخل مرورگر واقعی:\n"
                "    python -m pip install playwright\n"
                "    python -m playwright install chromium\n"
                "اگر نصب آن ممکن نیست، مسیر عادی (requests) یا «Copy as cURL» را استفاده کنید."
            )
        self.log("🌐 مرورگر واقعی (Chromium) برای ارسال سفارش بالا می‌آید…")
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)
        kwargs: dict = {"locale": self.locale, "timezone_id": self.timezone_id,
                        "viewport": {"width": 1280, "height": 900}}
        user_agent = (self.bundle or {}).get("user_agent")
        if user_agent:
            kwargs["user_agent"] = user_agent
        self._context = self._browser.new_context(**kwargs)
        self._apply_storage()
        self._apply_cookies()
        self.page = self._context.new_page()
        self.log(f"🌐 باز کردن {self.base}{self.path} …")
        self.page.goto(self.base + self.path, wait_until="domcontentloaded",
                       timeout=self.timeout * 1000)
        self.final_url = getattr(self.page, "url", "") or ""
        if self.final_url:
            self.log(f"🌐 صفحه‌ی مرورگر: {self.final_url}")

    def _apply_cookies(self) -> None:
        host = urlparse(self.base).hostname or ""
        cookies = []
        raw = (self.bundle or {}).get("cookies") or []
        for item in raw:
            if isinstance(item, dict):
                name, value = item.get("name"), item.get("value")
                extra = {k: item[k] for k in ("domain", "path") if item.get(k)}
            else:
                name, value = (list(item) + [""])[:2] if isinstance(item, (list, tuple)) else (None, None)
                extra = {}
            if not name:
                continue
            cookie = {"name": str(name), "value": "" if value is None else str(value),
                      "url": self.origin}
            cookie.update({k: str(v) for k, v in extra.items()})
            if host and "domain" not in cookie:
                cookie["domain"] = host
            cookies.append(cookie)
        if cookies:
            try:
                self._context.add_cookies(cookies)
                self.log(f"🍪 {len(cookies)} کوکی نشست به مرورگر داده شد "
                         f"[{', '.join(c['name'] for c in cookies)}]")
            except Exception as e:  # noqa: BLE001
                self.log(f"⚠️  افزودن کوکی‌ها به مرورگر ناموفق بود: {e}")

    def _apply_storage(self) -> None:
        storage = (self.bundle or {}).get("storage") or {}
        local = storage.get("local") or {}
        session = storage.get("session") or {}
        if not local and not session:
            return
        script = ("(() => { try { const s = %s;"
                  " for (const [k, v] of Object.entries(s.local || {})) localStorage.setItem(k, v);"
                  " for (const [k, v] of Object.entries(s.session || {})) sessionStorage.setItem(k, v);"
                  " } catch (e) {} })()" % json.dumps({"local": local, "session": session}))
        try:
            self._context.add_init_script(script)
            self.log("🗂️  localStorage/sessionStorage نشست به مرورگر داده شد.")
        except Exception as e:  # noqa: BLE001
            self.log(f"⚠️  اعمال localStorage ناموفق بود: {e}")

    def close(self) -> None:
        for closer in ("close",):
            for obj in (self._context, self._browser):
                try:
                    if obj is not None:
                        getattr(obj, closer)()
                except Exception:  # noqa: BLE001
                    pass
        try:
            if self._pw is not None:
                self._pw.stop()
        except Exception:  # noqa: BLE001
            pass
        self._context = self._browser = self._pw = None

    # -- کمکی‌ها ------------------------------------------------------------- #
    def page_now_ms(self) -> int:
        """ساعت مرورگر (میلی‌ثانیه‌ی epoch) — برای هم‌ترازکردن زمان‌بندی."""
        return int(self.page.evaluate("() => Date.now()") or 0)

    def results(self) -> list[dict]:
        """نتیجه‌های تا این لحظه (به ترتیب ارسال)."""
        data = self.page.evaluate("() => (window.__exirOrders && window.__exirOrders.results) || []")
        return list(data or [])

    def state(self) -> dict:
        return dict(self.page.evaluate(
            "() => { const s = window.__exirOrders; return s ? {running: s.running, done: s.done,"
            " stop: s.stop, fired: s.fired, got: s.results.length} : {}; }") or {})

    def request_stop(self) -> None:
        """جلوگیری از ارسال درخواست‌های بعدی (درخواست‌های در جریان پاسخ می‌دهند)."""
        try:
            self.page.evaluate("() => { if (window.__exirOrders) window.__exirOrders.stop = true; }")
        except Exception:  # noqa: BLE001
            pass

    def warm(self, path: str = "/new-exir/market-view") -> None:
        """یک GET سبک از داخل صفحه، برای گرم‌کردن اتصال HTTP/2 پیش از ارسال."""
        try:
            self.page.evaluate(
                "(url) => { fetch(url, {credentials: 'include', cache: 'no-store'})"
                ".catch(() => {}); }", self.base + path)
        except Exception:  # noqa: BLE001
            pass

    # -- ارسال --------------------------------------------------------------- #
    def probe(self, url: str, payload: bytes, *, headers: dict | None = None,
              timeout: float = 15.0) -> dict:
        """یک POST آزمایشی از داخل صفحه (بدنه اختیاری: برای آزمایش، نامعتبر بدهید)."""
        cfg = {"url": url, "body": payload.decode("utf-8", "replace"),
               "headers": _clean_headers(headers), "forbidden": sorted(FORBIDDEN_FETCH_HEADERS)}
        result = self.page.evaluate(PROBE_JS, cfg)
        return dict(result or {})

    def schedule(self, url: str, payload: bytes, times_ms: list[int], *,
                 headers: dict | None = None, stop_on_security: bool = True,
                 now_ms: int | None = None, offset_ms: int | None = None) -> dict:
        """
        زمان‌بندی ارسال را داخل صفحه تزریق می‌کند.

        ``times_ms`` برحسب ساعت **ربات** (ساعت تصحیح‌شده) است؛ اختلاف ساعت مرورگر با
        ربات خودکار جبران می‌شود تا درخواست‌ها دقیقاً سر ثانیه بروند.
        """
        if not times_ms:
            return {"planned": 0}
        if offset_ms is None:
            # اختلاف ساعت مرورگر با ساعت ربات (دو نمونه‌گیری، وسط بازه)
            before = int(now_ms if now_ms is not None else time.time() * 1000)
            page_ms = self.page_now_ms()
            after = int(now_ms if now_ms is not None else time.time() * 1000)
            offset_ms = page_ms - int((before + after) / 2)
        shifted = [int(t) + int(offset_ms) for t in times_ms]
        cfg = {"url": url, "body": payload.decode("utf-8", "replace"), "times": shifted,
               "headers": _clean_headers(headers), "stop_on_security": bool(stop_on_security),
               "forbidden": sorted(FORBIDDEN_FETCH_HEADERS), "method": "POST"}
        report = dict(self.page.evaluate(SCHEDULER_JS, cfg) or {})
        report["offset_ms"] = int(offset_ms)
        report["planned"] = len(shifted)
        return report


def probe_in_page(page, url: str, payload: bytes, *, headers: dict | None = None) -> dict:
    """
    POST آزمایشی از داخل صفحه‌ای که همین حالا باز است (بدون راه‌اندازی مرورگر جدید).

    برای `capture_browser_session(..., probe=...)` استفاده می‌شود: بعد از لاگین موفق،
    *همان مرورگرِ لاگین‌شده* یک درخواست سفارشِ عمداً نامعتبر می‌فرستد تا معلوم شود
    لایه‌ی امنیتی درخواستِ داخلِ مرورگر را می‌پذیرد یا نه.
    """
    cfg = {"url": url, "body": payload.decode("utf-8", "replace"),
           "headers": _clean_headers(headers), "forbidden": sorted(FORBIDDEN_FETCH_HEADERS)}
    return dict(page.evaluate(PROBE_JS, cfg) or {})


def identity_headers_from_session_url(base: str, bundle: dict | None, session) -> dict:
    """
    هدرهای شناسایی برای fetch داخل صفحه: اول از نشستِ مرورگرِ ذخیره‌شده، بعد از خودِ
    session ربات (x-app-n/clientid/هدرهای اضافه‌ی کاربر) — «x-app-n» همانی می‌ماند که
    در لاگین استفاده شده است.
    """
    headers: dict[str, str] = {}
    for key, value in ((bundle or {}).get("headers") or {}).items():
        if value:
            headers[str(key)] = str(value)
    try:
        for name in ("x-app-n", "clientid"):
            value = session.headers.get(name)
            if value:
                headers[name] = str(value)
        for name, value in session.headers.items():
            low = str(name).lower()
            if low.startswith("x-") and low not in ("x-app-n",):
                headers.setdefault(str(name), str(value))
    except Exception:  # noqa: BLE001
        pass
    return _clean_headers(headers)
