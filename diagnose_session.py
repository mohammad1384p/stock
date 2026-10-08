#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Offline, value-free diagnostic of the saved broker session. Sends no requests."""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from urllib.parse import urlparse

import requests

from exir_auth import (TOKEN_COOKIE, apply_token, load_saved_token,
                       restore_session_cookies)
from exir_bot import DEFAULT_BASE_URL, ORDER_PATH, build_session
from session_capture import (BROWSER_ONLY_COOKIE_HINTS, apply_captured, load_captured_session,
                             session_summary)


def _browser_order_available() -> bool:
    """آیا مسیر «ارسال از داخل مرورگر واقعی» (Playwright) در دسترس است؟"""
    try:
        from browser_order import browser_available
    except Exception:  # noqa: BLE001
        return False
    try:
        return bool(browser_available())
    except Exception:  # noqa: BLE001
        return False


def session_report(args) -> dict:
    base = args.base_url.rstrip("/")
    saved = load_saved_token(Path(args.token_file), base)
    session = build_session(args, pool=1)
    if saved:
        restore_session_cookies(session, base, saved.get("cookies", []))
        if not session.headers.get("x-app-n") and saved.get("appN"):
            session.headers["x-app-n"] = saved["appN"]
    captured = load_captured_session(Path(args.token_file), base)
    if captured:
        # کوکی/هدرهای «نشست مرورگر» که با --import-session (یا کادر پنل) ذخیره شده‌اند
        apply_captured(session, base, captured, None)
    if saved:
        apply_token(session, base, saved["token"], args.auth_mode)

    # prepare_request computes the actual Cookie header, including path, secure
    # and expiry filtering. No send(), GET or POST occurs in this script.
    prepared = session.prepare_request(requests.Request("POST", base + ORDER_PATH, json={}))
    cookie_names = [part.split("=", 1)[0].strip()
                    for part in prepared.headers.get("Cookie", "").split(";") if "=" in part]
    app_n = prepared.headers.get("x-app-n", "")
    warnings = []
    if not saved:
        warnings.append("No unexpired saved token for this broker; log in again.")
    if saved and not saved.get("cookies") and not captured:
        warnings.append("Saved session has no companion cookies; a fresh login may be needed.")
    if re.fullmatch(r"NaN\.\d+", app_n):
        warnings.append("x-app-n uses the fallback NaN pattern; compare its shape with the broker browser request "
                        "(or probe it: python probe_order.py --app-n-candidate <browser value> --yes).")
    if not app_n:
        warnings.append("x-app-n is missing.")
    if "Cookie" in session.headers:
        warnings.append("A manually configured Cookie header overrides the session cookie jar.")
    if cookie_names.count(TOKEN_COOKIE) > 1:
        warnings.append("Multiple JWT-TOKEN cookies would be sent.")
    summary = session_summary(session, base)
    for name in summary["missing_browser_cookies"]:
        warnings.append(f"Cookie '{name}' (seen in the broker browser request) is not in this session: "
                        f"{BROWSER_ONLY_COOKIE_HINTS[name]}. Import a browser request "
                        "(--import-session, or the panel's browser-session box) or keep --bootstrap on.")
    report = {
        "offline": True,
        "requests_sent": 0,
        "broker_host": urlparse(base).hostname,
        "order_path": ORDER_PATH,
        "saved_token_available": bool(saved),
        "auth_mode": args.auth_mode,
        "broker_send_order_delay_ms": (saved.get("sendOrderDelay")
                                       if saved and isinstance(saved.get("sendOrderDelay"), (int, float))
                                       else None),
        "clientid": {"present": "clientid" in {k.lower() for k in prepared.headers},
                     "empty": prepared.headers.get("clientid", None) == ""},
        "x_app_n": {"present": bool(app_n), "length": len(app_n),
                    "fallback_nan_pattern": bool(re.fullmatch(r"NaN\.\d+", app_n)),
                    "matches_saved": bool(saved and app_n and app_n == saved.get("appN"))},
        "header_names": sorted(prepared.headers.keys(), key=str.lower),
        "cookie_names_sent": cookie_names,
        "captured_session": ({"source": captured.get("kind", "?"),
                              "cookies": [str(n) for n, _ in (captured.get("cookies") or [])],
                              "headers": sorted(str(k) for k in (captured.get("headers") or {}).keys())}
                             if captured else None),
        "missing_browser_cookies": summary["missing_browser_cookies"],
        "browser_order_available": _browser_order_available(),
        "cookies": [{"name": c.name, "domain": c.domain, "path": c.path,
                     "secure": c.secure, "expires": c.expires}
                    for c in session.cookies],
        "warnings": warnings,
        "note": "Cookie/token/header VALUES and account details are not included. "
                "If security cookies are missing (or 403/9009 persists), run with "
                "browser_order_available=true (python exir_bot.py --browser-order) or import a "
                "real browser session (--import-session / the panel's browser-session box). "
                "This checks local request preparation, not broker acceptance. "
                "CLI/env overrides must match the running panel.",
    }
    session.close()
    return report


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base-url", default=os.environ.get("EXIR_BASE_URL", DEFAULT_BASE_URL))
    p.add_argument("--token-file", default=os.environ.get("EXIR_TOKEN_FILE", ".exir_token.json"))
    p.add_argument("--app-n", default=os.environ.get("EXIR_APP_N"))
    p.add_argument("--clientid", default=os.environ.get("EXIR_CLIENTID"))
    p.add_argument("-H", "--header", action="append", default=[])
    p.add_argument("--cookie", default=os.environ.get("EXIR_COOKIE"))
    p.add_argument("--auth-mode", choices=["cookie", "bearer", "both"], default="cookie")
    args = p.parse_args(argv)
    print(json.dumps(session_report(args), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
