"""Güvenlik katmanı: HTTP güvenlik başlıkları, parola özeti (scrypt), TOTP (RFC 6238), oturum, CSRF,
giriş hız sınırı ve hash zincirli denetim kaydı. Yalnızca standart kütüphane + cryptography kullanır."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os as _os
import secrets
import struct
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from urllib.parse import quote

_LOCAL_HTTP = _os.environ.get("DC_ALLOW_HTTP_LOCAL") == "1"

# ---------------------------------------------------------------- HTTP güvenlik başlıkları
_CSP_BASE = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
             "font-src 'self'; connect-src 'self'; manifest-src 'self'; worker-src 'self'; "
             "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
CSP = _CSP_BASE if _LOCAL_HTTP else f"{_CSP_BASE}; upgrade-insecure-requests"
BASE_HEADERS = [
    (b"strict-transport-security", b"max-age=63072000; includeSubDomains; preload"),
    (b"content-security-policy", CSP.encode()),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    # OWASP önerisi: eski tarayıcı XSS denetçisi kapalı (0); koruma CSP ile sağlanır.
    (b"x-xss-protection", b"0"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
                            b"magnetometer=(), gyroscope=(), accelerometer=(), browsing-topics=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cross-origin-embedder-policy", b"require-corp"),
    (b"x-permitted-cross-domain-policies", b"none"),
]
NO_STORE_PREFIXES = ("/app/api", "/auth", "/form", "/view", "/admin", "/calendar", "/api/public")


def client_ip_from(xff: str | None, peer: str | None) -> str:
    """Güvenilir proxy zincirinde gerçek istemci IP'si (CWE-290).

    X-Forwarded-For listesi SAĞDAN okunur: son `TRUSTED_PROXY_HOPS` girdi güvenilir proxy'lerin yazdığı
    değerlerdir; istemcinin sola eklediği sahte IP'ler hesaba katılmaz. TRUSTED_PROXY=1 değilse başlık yok sayılır.
    """
    if _os.environ.get("TRUSTED_PROXY") == "1":
        parts = [p.strip() for p in (xff or "").split(",") if p.strip()]
        if parts:
            try:
                hops = max(1, int(_os.environ.get("TRUSTED_PROXY_HOPS", "1")))
            except ValueError:
                hops = 1
            return (parts[-hops] if len(parts) >= hops else parts[0])[:64]
    return peer or "-"
STRIP = {b"server", b"x-powered-by"}


class SecurityHeadersMiddleware:
    """Saf ASGI ara katmanı: her yanıta güvenlik başlıkları ve X-Request-ID ekler, sunucu kimliğini siler."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        no_store = path.startswith(NO_STORE_PREFIXES)
        req_id = ""
        for hk, hv in scope.get("headers") or ():
            if hk.lower() == b"x-request-id":
                cand = hv.decode("ascii", errors="ignore").strip()[:32]
                if cand and all(ch.isalnum() or ch in "-_" for ch in cand):
                    req_id = cand
                break
        if not req_id:
            req_id = secrets.token_hex(8)
        req_id_bytes = req_id.encode("ascii")

        async def _send(msg):
            if msg["type"] == "http.response.start":
                hdrs = [(k, v) for k, v in msg.get("headers", []) if k.lower() not in STRIP]
                present = {k.lower() for k, _ in hdrs}
                hdrs += [(k, v) for k, v in BASE_HEADERS if k not in present]
                if b"x-request-id" not in present:
                    hdrs.append((b"x-request-id", req_id_bytes))
                if no_store:
                    hdrs = [(k, v) for k, v in hdrs if k.lower() != b"cache-control"]
                    hdrs.append((b"cache-control", b"no-store"))
                msg["headers"] = hdrs
            await send(msg)

        await self.app(scope, receive, _send)


# ---------------------------------------------------------------- Parola (scrypt, bellek-yoğun)
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1


def hash_password(pw: str) -> str:
    if len(pw) < 12:
        raise ValueError("Parola en az 12 karakter olmalı")
    if len(set(pw)) < 4 or not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
        raise ValueError("Parola en az 1 harf, 1 rakam ve en az 4 farklı karakter içermelidir")
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, maxmem=2 ** 26, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        dk = hashlib.scrypt(pw.encode(), salt=base64.b64decode(salt_b64), n=int(n), r=int(r), p=int(p),
                            maxmem=2 ** 26, dklen=32)
        return hmac.compare_digest(dk, base64.b64decode(dk_b64))
    except (ValueError, TypeError):
        return False


# Kullanıcı yokken de aynı sürede cevap vermek için sahte özet (kullanıcı adı tahmini engeli)
_dummy: list[str] = []


def dummy_hash() -> str:
    if not _dummy:
        _dummy.append(hash_password(secrets.token_urlsafe(24)))
    return _dummy[0]


# ---------------------------------------------------------------- TOTP (RFC 6238, SHA1, 30 sn, 6 hane)
def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _b32(secret: str) -> bytes:
    s = secret.upper().replace(" ", "")
    return base64.b32decode(s + "=" * (-len(s) % 8))


def hotp(key: bytes, counter: int, digits: int = 6) -> str:
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_now(secret: str, at: float | None = None) -> str:
    return hotp(_b32(secret), int((at or time.time()) // 30))


def totp_verify(secret: str, code: str, last_step: int, at: float | None = None) -> int | None:
    """Kod doğruysa kullanılan adımı döner; ±1 adım (±30 sn) saat kayması tolere edilir.
    Daha önce kullanılmış adım (tekrar oynatma) reddedilir."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    step = int((at or time.time()) // 30)
    key = _b32(secret)
    for s in (step - 1, step, step + 1):
        if s > last_step and hmac.compare_digest(hotp(key, s), code):
            return s
    return None


def totp_uri(secret: str, email: str, issuer: str = "DentaCore") -> str:
    return f"otpauth://totp/{quote(issuer)}:{quote(email)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period=30"


# ---------------------------------------------------------------- Oturum
COOKIE = "dc_session" if _LOCAL_HTTP else "__Host-dc_session"
IDLE_SECONDS = 15 * 60          # 15 dk hareketsizlikte oturum düşer (klinik ortam standardı)
ABSOLUTE_SECONDS = 12 * 3600    # en uzun 12 saat


def new_session_token() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def session_hash(raw: str) -> str:
    return hashlib.sha256((raw or "").encode()).hexdigest()


def cookie_header(raw: str, max_age: int = ABSOLUTE_SECONDS) -> str:
    sec_flag = "" if _LOCAL_HTTP else " Secure;"
    return f"{COOKIE}={raw}; Path=/; Max-Age={max_age}; HttpOnly;{sec_flag} SameSite=Strict"


def clear_cookie_header() -> str:
    sec_flag = "" if _LOCAL_HTTP else " Secure;"
    return f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly;{sec_flag} SameSite=Strict"


# ---------------------------------------------------------------- Hız sınırı (Redis, yoksa bellek)
_RL_SYNC_LOCK = threading.Lock()

class RateLimiter:
    """Redis varsa tüm işçiler ortak sayaç kullanır. Redis anahtar/bağlantı hatası verirse (kesinti) istek 500 olmaz ve
    sınır atlanmaz: o işçide süreç içi sayaca düşülür (sınır işçi başına uygulanır, yani geçici olarak gevşer).
    `redis_errors` ve `degraded` sağlık/izleme için okunabilir."""

    def __init__(self, redis=None):
        self.redis = redis
        self.mem: dict[str, tuple[int, float]] = {}
        self.redis_errors = 0
        self.degraded = False

    def _hit_mem(self, key: str, limit: int, window: int) -> bool:
        now = time.time()
        if len(self.mem) > 2048:
            self.mem = {k: v for k, v in self.mem.items() if v[1] > now}
        n, exp = self.mem.get(key, (0, now + window))
        if now > exp:
            n, exp = 0, now + window
        n += 1
        self.mem[key] = (n, exp)
        return n <= limit

    async def hit(self, key: str, limit: int, window: int) -> bool:
        """True: izin var. False: sınır aşıldı."""
        if self.redis:
            k = f"dc:rl:{key}"
            try:
                n = await self.redis.incr(k)
                # Süreç kesilse bile anahtarın süresiz kalmaması için her çağrıda nx=True ile TTL güvencesi
                try:
                    await self.redis.expire(k, window, nx=True)
                except TypeError:
                    if n == 1:
                        await self.redis.expire(k, window)
                self.degraded = False
                return n <= limit
            except Exception:  # noqa: BLE001 - Redis kesintisi: süreç içi sayaca düş (loglanır, sayılır)
                self.redis_errors += 1
                self.degraded = True
                if self.redis_errors == 1 or self.redis_errors % 100 == 0:
                    import logging
                    logging.getLogger("dentacore.ratelimit").error("Redis hız sınırı hatası (toplam %d); süreç içi sayaca düşüldü", self.redis_errors)
        return self._hit_mem(key, limit, window)

    def hit_sync(self, key: str, limit: int, window: int) -> bool:
        """Senkron uçlar için süreç içi sayaç (thread güvenli). True: izin var."""
        with _RL_SYNC_LOCK:
            now = time.time()
            if len(self.mem) > 2048:
                self.mem = {k: v for k, v in self.mem.items() if v[1] > now}
            n, exp = self.mem.get(key, (0, now + window))
            if now > exp:
                n, exp = 0, now + window
            n += 1
            self.mem[key] = (n, exp)
            return n <= limit

    async def reset(self, key: str):
        if self.redis:
            try:
                await self.redis.delete(f"dc:rl:{key}")
            except Exception:  # noqa: BLE001 - Redis kesintisinde sıfırlama sessizce yalnız yerelde yapılır
                self.redis_errors += 1
        self.mem.pop(key, None)


# ---------------------------------------------------------------- Hash zincirli denetim kaydı
GENESIS = "0" * 64


def audit_digest(prev: str, ts: str, actor: str, action: str, target: str, meta: str) -> str:
    return hashlib.sha256("\x1f".join((prev, ts, actor, action, target, meta)).encode()).hexdigest()


async def audit(actor_id: int | None, actor: str, action: str, target: str = "", ip_h: str = "", meta: dict | None = None, clinic_id: int = 1):
    """Kayıt atomik ve sıralı yazılır (advisory lock). Kişisel sağlık verisi meta'ya yazılmaz."""
    from .core import tx
    m = json.dumps(meta or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    ts = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    async with tx() as t:
        await t.q("SELECT pg_advisory_xact_lock(74210001)")
        last = await t.q1("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
        prev = last["hash"] if last else GENESIS
        h = audit_digest(prev, ts, actor, action, target, m)
        await t.q("""INSERT INTO audit_log (clinic_id, ts, actor_id, actor, action, target, ip_hash, meta, prev_hash, hash)
                     VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""", clinic_id, ts, actor_id, actor, action, target, ip_h, m, prev, h)


def verify_chain(rows: list[dict]) -> dict:
    prev = GENESIS
    for idx, r in enumerate(rows):
        if r["prev_hash"] != prev or audit_digest(prev, r["ts"], r["actor"], r["action"], r["target"], r["meta"]) != r["hash"]:
            return {"ok": False, "broken_at": r["id"], "checked": idx}
        prev = r["hash"]
    return {"ok": True, "checked": len(rows), "head": prev}


# ---------------------------------------------------------------- Webhook TTL Dedup Önbelleği
class WebhookDedupCache:
    """Sınırlı boyutlu (10.000) ve TTL'li (24 saat) webhook tekrar işleme engeli."""

    def __init__(self, max_size: int = 10_000, ttl_seconds: int = 86_400):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._items: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def seen_or_add(self, msg_id: str, now: float | None = None) -> bool:
        if not msg_id:
            return False
        ts = time.monotonic() if now is None else now
        with self._lock:
            cutoff = ts - self.ttl_seconds
            while self._items:
                _, oldest_ts = next(iter(self._items.items()))
                if oldest_ts <= cutoff:
                    self._items.popitem(last=False)
                else:
                    break
            if msg_id in self._items:
                self._items.move_to_end(msg_id)
                return True
            while len(self._items) >= self.max_size:
                self._items.popitem(last=False)
            self._items[msg_id] = ts
            return False


# ---------------------------------------------------------------- KVKK Metinleri & Rıza Yardımcıları
KVKK_METIN_VER = "2026-11-v2"


def kvkk_texts(clinic_name: str) -> dict[str, str]:
    c = (clinic_name or "Kliniğimiz").strip()
    return {
        "aydinlatma": (
            f"Veri Sorumlusu: {c}. Kimlik, iletişim ve beyan ettiğiniz sağlık bilgileriniz; randevu, "
            "muayene ve tedavi planlaması amaçlarıyla şifreli olarak işlenir, yalnızca yetkili klinik hekim ve "
            "personelince görülür. 6698 sayılı KVKK m.11 kapsamındaki bilgi, düzeltme, silme ve rıza geri alma "
            "taleplerinizi kliniğimize iletebilirsiniz."
        ),
        "saglik": (
            f"Sağlık verilerimin (anamnez cevapları ve klinik değerlendirme kayıtları) yalnızca muayene ve tedavi "
            f"planlaması amacıyla {c} tarafından işlenmesine açık rıza veriyorum."
        ),
        "yurt_disi": (
            "İletişim ve randevu hatırlatmaları kapsamında verilerimin yurt dışındaki mesajlaşma/altyapı "
            "sağlayıcılarına (ör. WhatsApp/Meta veya bulut yapay zekâ servisleri) aktarılmasına açık rıza veriyorum "
            "(isteğe bağlıdır)."
        ),
        "lead": (
            "Aydınlatma metnini okudum; klinik adı ve iletişim bilgilerimin yalnızca tanıtım ve demo talebime "
            "dönüş yapılması amacıyla işlenmesine açık rıza veriyorum."
        ),
        "lead_yurt_disi": (
            "Tanıtım iletişiminde yurt dışı bulut/mesajlaşma sağlayıcılarına aktarım yapılmasına izin veriyorum (isteğe bağlı)."
        ),
    }


def kvkk_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_checked(val: object) -> bool:
    if isinstance(val, bool):
        return val
    return str(val or "").strip().lower() in ("1", "true", "on", "yes", "evet")
