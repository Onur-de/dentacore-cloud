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
import time
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
NO_STORE_PREFIXES = ("/app/api", "/auth", "/form", "/view", "/admin")
STRIP = {b"server", b"x-powered-by"}


class SecurityHeadersMiddleware:
    """Saf ASGI ara katmanı: her yanıta güvenlik başlıklarını ekler, sunucu kimliğini siler."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")
        no_store = path.startswith(NO_STORE_PREFIXES)

        async def _send(msg):
            if msg["type"] == "http.response.start":
                hdrs = [(k, v) for k, v in msg.get("headers", []) if k.lower() not in STRIP]
                present = {k.lower() for k, _ in hdrs}
                hdrs += [(k, v) for k, v in BASE_HEADERS if k not in present]
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
class RateLimiter:
    def __init__(self, redis=None):
        self.redis = redis
        self.mem: dict[str, tuple[int, float]] = {}

    async def hit(self, key: str, limit: int, window: int) -> bool:
        """True: izin var. False: sınır aşıldı."""
        if self.redis:
            k = f"dc:rl:{key}"
            n = await self.redis.incr(k)
            if n == 1:
                await self.redis.expire(k, window)
            return n <= limit
        now = time.time()
        n, exp = self.mem.get(key, (0, now + window))
        if now > exp:
            n, exp = 0, now + window
        n += 1
        self.mem[key] = (n, exp)
        return n <= limit

    async def reset(self, key: str):
        if self.redis:
            await self.redis.delete(f"dc:rl:{key}")
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
    for r in rows:
        if r["prev_hash"] != prev or audit_digest(prev, r["ts"], r["actor"], r["action"], r["target"], r["meta"]) != r["hash"]:
            return {"ok": False, "broken_at": r["id"], "checked": rows.index(r)}
        prev = r["hash"]
    return {"ok": True, "checked": len(rows), "head": prev}
