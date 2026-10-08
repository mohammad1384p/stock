# -*- coding: utf-8 -*-
"""
همگام‌سازی خودکار زمان (بدون نیاز به root و بدون تغییر ساعت سیستم).

اختلاف ساعت سیستم با زمان دقیق اندازه‌گیری می‌شود و همه‌ی زمان‌بندی‌های ربات با
    clock.now() = time.time() + offset
انجام می‌شود.

روش‌ها:
  ntp    : پرس‌وجوی SNTP (UDP/123) از چند سرور، انتخاب نمونه با کمترین تأخیر (دقت چند میلی‌ثانیه)
  server : استفاده از هدر Date سرور کارگزاری. هدر ثانیه‌ای است، اما با ارسال پشت‌سرهم درخواست‌ها
           و پیدا کردن لحظه‌ی عوض شدن ثانیه، دقت به حدود RTT می‌رسد.
  auto   : اول ntp، اگر نشد server
  off    : ساعت سیستم بدون تغییر
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from email.utils import parsedate_to_datetime

NTP_EPOCH_DELTA = 2208988800  # 1900-01-01 → 1970-01-01
DEFAULT_NTP_SERVERS = (
    "ir.pool.ntp.org",
    "time.google.com",
    "time.cloudflare.com",
    "pool.ntp.org",
    "time.windows.com",
    "time.apple.com",
)


class Clock:
    """ساعت تصحیح‌شده (thread-safe)."""

    def __init__(self) -> None:
        self._offset = 0.0
        self._lock = threading.Lock()
        self.source = "system"
        self.accuracy: float | None = None  # ± ثانیه
        self.synced_at: float | None = None

    @property
    def offset(self) -> float:
        return self._offset

    def set(self, offset: float, source: str, accuracy: float | None) -> None:
        with self._lock:
            self._offset = offset
            self.source = source
            self.accuracy = accuracy
            self.synced_at = time.time()

    def now(self) -> float:
        return time.time() + self._offset


clock = Clock()


# --------------------------------------------------------------------------- #
#  NTP
# --------------------------------------------------------------------------- #
def _ntp_to_unix(sec: int, frac: int) -> float:
    return sec - NTP_EPOCH_DELTA + frac / 2**32


def ntp_query(server: str, timeout: float = 1.5) -> tuple[float, float]:
    """یک درخواست SNTP. خروجی: (offset, delay) به ثانیه."""
    host, port = server, 123
    if server.count(":") == 1:  # host:port (IPv6 بدون پورت را دست نزن)
        host, p = server.rsplit(":", 1)
        port = int(p)
    addr = socket.getaddrinfo(host, port, 0, socket.SOCK_DGRAM)[0][4]
    family = socket.AF_INET6 if ":" in addr[0] else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        pkt = bytearray(48)
        pkt[0] = 0x23  # LI=0, VN=4, Mode=3 (client)
        t0 = time.time()
        sec = int(t0) + NTP_EPOCH_DELTA
        frac = int((t0 % 1) * 2**32)
        struct.pack_into("!II", pkt, 40, sec, frac)  # transmit timestamp
        s.sendto(bytes(pkt), addr)
        data, _ = s.recvfrom(512)
        t3 = time.time()
    if len(data) < 48:
        raise ValueError("پاسخ NTP کوتاه است")
    mode = data[0] & 0x7
    stratum = data[1]
    if mode not in (4, 5) or stratum == 0 or stratum > 15:
        raise ValueError(f"پاسخ NTP نامعتبر (mode={mode}, stratum={stratum})")
    if struct.unpack("!II", data[24:32]) != (sec, frac):
        raise ValueError("پاسخ NTP با درخواست مطابقت ندارد")
    t1 = _ntp_to_unix(*struct.unpack("!II", data[32:40]))  # receive
    t2 = _ntp_to_unix(*struct.unpack("!II", data[40:48]))  # transmit
    offset = ((t1 - t0) + (t2 - t3)) / 2
    delay = (t3 - t0) - (t2 - t1)
    return offset, max(delay, 0.0)


def ntp_offset(servers=DEFAULT_NTP_SERVERS, samples: int = 4, timeout: float = 1.5):
    """از چند سرور به‌صورت موازی؛ خروجی (offset, accuracy, server) یا None."""

    def probe(server: str):
        best = None
        for _ in range(samples):
            try:
                off, dly = ntp_query(server, timeout)
            except Exception:  # noqa: BLE001
                if best is None:
                    return None  # سرور جواب نمی‌دهد، وقت تلف نکن
                continue
            if best is None or dly < best[1]:
                best = (off, dly)
            time.sleep(0.05)
        return (best[0], best[1], server) if best else None

    with ThreadPoolExecutor(max_workers=len(servers)) as ex:
        results = [r for r in ex.map(probe, servers) if r]
    if not results:
        return None
    results.sort(key=lambda r: r[1])
    # میانه‌ی offset سه نتیجه‌ی کم‌تأخیر برای مقاومت در برابر سرور خراب
    top = results[:3]
    offs = sorted(r[0] for r in top)
    median = offs[len(offs) // 2]
    best = min(top, key=lambda r: abs(r[0] - median))
    return best[0], best[1] / 2, best[2]


# --------------------------------------------------------------------------- #
#  هدر Date سرور (HTTP)
# --------------------------------------------------------------------------- #
def http_offset(session, url: str, spread: float = 1.2, probes: int = 20, refine: int = 4):
    """
    هر پاسخ می‌گوید: زمان سرور در بازه‌ی [t_send, t_recv] داخل ثانیه‌ی D بوده است، پس
        D - t_recv  <=  offset  <  D + 1 - t_send
    فاز ۱: درخواست‌ها در ~۱.۲ ثانیه پخش می‌شوند تا حتماً از یک مرز ثانیه عبور کنند.
    فاز ۲: در ثانیه‌های بعد، یک درخواست دقیقاً روی مرز تخمینی فرستاده می‌شود (جستجوی دودویی)
           تا عدم قطعیت تا حد RTT کم شود.
    خروجی: (offset, accuracy, n) یا None
    """
    lo, hi = float("-inf"), float("inf")
    mids: list[float] = []
    rtts: list[float] = []
    n = 0

    def probe() -> bool:
        nonlocal lo, hi, n
        n += 1
        t0 = time.time()
        try:
            r = session.head(url, timeout=5, allow_redirects=False)
        except Exception:  # noqa: BLE001
            return False
        t1 = time.time()
        d = r.headers.get("Date")
        if not d:
            raise LookupError("no Date header")
        D = parsedate_to_datetime(d).timestamp()
        rtts.append(t1 - t0)
        lo = max(lo, D - t1)
        hi = min(hi, D + 1 - t0)
        mids.append(D + 0.5 - (t0 + t1) / 2)
        return True

    try:
        # فاز ۱
        gap = spread / probes
        t_end = time.time() + spread
        while time.time() < t_end:
            t_start = time.time()
            probe()
            time.sleep(max(0.0, gap - (time.time() - t_start)))
        if not mids:
            return None
        if lo > hi:
            raise ValueError("inconsistent")
        # فاز ۲: جستجوی دودویی روی مرز ثانیه
        for _ in range(refine):
            rtt = min(rtts)
            if hi - lo <= rtt * 1.2 + 0.002:
                break
            est = (lo + hi) / 2
            # مرز بعدی ثانیه‌ی سرور به وقت محلی (حداقل ۱۰۰ms جلوتر)
            k = int(time.time() + est + 0.1) + 1
            t_send = k - est - rtt / 2
            delay = t_send - time.time()
            if delay > 0:
                time.sleep(delay)
            probe()
            if lo > hi:
                raise ValueError("inconsistent")
    except LookupError:
        return None
    except ValueError:
        # ناسازگاری (مثلاً چند سرور پشت load balancer با ساعت‌های متفاوت): تخمین درشت
        mids.sort()
        return mids[len(mids) // 2], 0.5, n

    if hi - lo < 1.0:
        return (lo + hi) / 2, (hi - lo) / 2, n
    mids.sort()
    return mids[len(mids) // 2], 0.5, n


# --------------------------------------------------------------------------- #
def sync(mode: str, session=None, base_url: str | None = None, ntp_servers=None, log=print) -> bool:
    """همگام‌سازی و تنظیم clock. خروجی: موفق بود یا نه."""
    if mode == "off":
        clock.set(0.0, "system", None)
        return True

    if mode in ("auto", "ntp"):
        res = ntp_offset(ntp_servers or DEFAULT_NTP_SERVERS)
        if res:
            off, acc, server = res
            clock.set(off, f"NTP {server}", acc)
            log(f"🕒 همگام‌سازی با {server}: ساعت سیستم {_fmt(-off)} | دقت ±{acc * 1000:.0f}ms")
            return True
        log("⚠️  NTP در دسترس نبود" + ("؛ همگام‌سازی با ساعت سرور کارگزاری…" if mode == "auto" else ""))
        if mode == "ntp":
            return False

    if session is not None and base_url:
        res = http_offset(session, base_url.rstrip("/") + "/")
        if res:
            off, acc, n = res
            clock.set(off, "broker Date header", acc)
            log(f"🕒 همگام‌سازی با ساعت سرور کارگزاری ({n} درخواست): ساعت سیستم {_fmt(-off)}"
                f" | دقت ±{acc * 1000:.0f}ms")
            return True
    log("⚠️  همگام‌سازی زمان ناموفق بود؛ از ساعت سیستم استفاده می‌شود.")
    return False


def _fmt(sys_minus_true: float) -> str:
    ms = sys_minus_true * 1000
    if abs(ms) < 1:
        return "دقیق است"
    return f"{abs(ms):.0f}ms {'جلو' if ms > 0 else 'عقب'} است"
