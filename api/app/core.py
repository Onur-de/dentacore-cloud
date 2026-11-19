"""Ayarlar, şifreleme, veritabanı ve ortak yardımcılar."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import time

from cryptography.fernet import Fernet
try:
    from psycopg.rows import dict_row
    from psycopg_pool import AsyncConnectionPool
except ImportError:
    dict_row = None
    AsyncConnectionPool = None


def env(k: str, d: str = "") -> str:
    return os.environ.get(k, d)


class S:
    clinic = env("CLINIC_NAME", "Klinik")
    public_url = env("PUBLIC_URL", "http://localhost:8000").rstrip("/")
    admin_token = env("ADMIN_TOKEN")
    phone_hmac_key = env("PHONE_HMAC_KEY").encode()
    data_key = env("DATA_ENCRYPTION_KEY")
    database_url = env("DATABASE_URL")
    redis_url = env("REDIS_URL")
    doctor_on_call = env("DOCTOR_ON_CALL_PHONE")
    doctor_owner = env("DOCTOR_OWNER_PHONE")
    google_review_url = env("GOOGLE_REVIEW_URL")
    chairs = int(env("CHAIRS", "2"))
    work_minutes = int(env("WORK_MINUTES", "600"))


_fernet: Fernet | None = None


COMPROMISED_SECRETS_DENYLIST = frozenset({
    "Tet8XeZ17zgbFNprLrV7y-W8hnfGvpk4D-25FMXF2y8=",
    "112ebe88d9b687f7b3fca9a6d2be2008d84864e61c518604f7b140894c842493",
    "cbcf8564524ac511c47bc9b4a43383c9258086a1f173532807b385166c4f1a90",
    "bdb9da38d70a587792bee84a2325986ed118af25d92f40cc",
    "f20c9368ab6fe62e31b297c30d01ee9c99b66d74f8a7764c",
    "cb32c4870441f2432e6bd4c58fea77e1",
    "e1858736338792a95f809dc4ea3b094a",
})


def is_compromised_secret(val: str | None) -> bool:
    return bool(val and val.strip() in COMPROMISED_SECRETS_DENYLIST)


def fernet() -> Fernet:
    global _fernet
    if _fernet is None:
        if not S.data_key:
            raise RuntimeError("DATA_ENCRYPTION_KEY tanımlı değil")
        if is_compromised_secret(S.data_key):
            raise RuntimeError("Güvenlik ihlali: c4d6a2f sızıntı DATA_ENCRYPTION_KEY anahtarı kullanılamaz")
        _fernet = Fernet(S.data_key.encode())
    return _fernet


def enc(s: str) -> str:
    return fernet().encrypt(s.encode()).decode()


def dec(s: str) -> str:
    return fernet().decrypt(s.encode()).decode()


def norm_phone(p: str) -> str:
    d = re.sub(r"\D", "", p or "")
    if d.startswith("00"):
        d = d[2:]
    if d.startswith("900") and len(d) == 13:  # P0-2: "+90 0532 ..." yazımı
        d = "90" + d[3:]
    if d.startswith("0") and len(d) == 11:
        d = "90" + d[1:]
    if len(d) == 10 and d.startswith("5"):
        d = "90" + d
    return d


def phone_hmac(p: str) -> str:
    return hmac.new(S.phone_hmac_key, norm_phone(p).encode(), hashlib.sha256).hexdigest()


def sign(path: str, ttl: int = 86400) -> str:
    exp = int(time.time()) + ttl
    sig = hmac.new(S.admin_token.encode(), f"{path}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{S.public_url}{path}?exp={exp}&sig={sig}"


def verify_sig(path: str, exp: str, sig: str) -> bool:
    try:
        if int(exp) < time.time():
            return False
    except ValueError:
        return False
    good = hmac.new(S.admin_token.encode(), f"{path}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(good, sig or "")


# ---------------- veritabanı ----------------
pool: AsyncConnectionPool | None = None


async def db_open():
    global pool
    pool = AsyncConnectionPool(S.database_url, min_size=1, max_size=10, open=False, kwargs={"row_factory": dict_row})
    await pool.open()


async def db_close():
    if pool:
        await pool.close()


_SQL_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")


def _clean_sql_args(args: tuple) -> tuple:
    return tuple(_SQL_CTRL_RE.sub("", a) if isinstance(a, str) else a for a in args)


async def q(sql: str, *args) -> list[dict]:
    clean = _clean_sql_args(args)
    async with pool.connection() as c:
        cur = await c.execute(sql, clean)
        return await cur.fetchall() if cur.description else []


async def q1(sql: str, *args) -> dict | None:
    rows = await q(sql, *args)
    return rows[0] if rows else None


async def upsert_patient(phone: str, lang: str | None = None, name: str | None = None, clinic_id: int = 1) -> int:
    p = norm_phone(phone)
    row = await q1(
        """INSERT INTO patients (clinic_id, phone_hmac, phone_enc, display_name, lang)
           VALUES (%s, %s, %s, %s, COALESCE(%s, 'tr'))
           ON CONFLICT (clinic_id, phone_hmac) DO UPDATE
             SET display_name = COALESCE(patients.display_name, EXCLUDED.display_name)
           RETURNING id""",
        clinic_id, phone_hmac(p), enc(p), name, lang)
    return row["id"]


async def upsert_identity(key: str, channel: str, lang: str | None = None, name: str | None = None, clinic_id: int = 1) -> int:
    """Telefon dışı kanallar (ör. Instagram 'ig:<id>') için hasta kimliği. Telefon normalizasyonu uygulanmaz."""
    h = hmac.new(S.phone_hmac_key, key.encode(), hashlib.sha256).hexdigest()
    row = await q1(
        """INSERT INTO patients (clinic_id, phone_hmac, phone_enc, display_name, lang, channel)
           VALUES (%s, %s, %s, %s, COALESCE(%s, 'tr'), %s)
           ON CONFLICT (clinic_id, phone_hmac) DO UPDATE
             SET display_name = COALESCE(patients.display_name, EXCLUDED.display_name)
           RETURNING id""",
        clinic_id, h, enc(key), name, lang, channel)
    return row["id"]


def mask_phone(p: str | None) -> str:
    raw = str(p or "")
    if raw.startswith("ig:"):
        return "Instagram"
    d = re.sub(r"\D", "", raw)
    return f"+{d[:2]} {d[2:3]}** *** {d[-4:-2]} {d[-2:]}" if len(d) >= 10 else "***"


def ip_hash(ip: str | None) -> str:
    """Denetim kaydında IP'nin kendisi değil anahtarlı özeti tutulur (kişisel veri minimizasyonu)."""
    return hmac.new(S.phone_hmac_key, (ip or "-").encode(), hashlib.sha256).hexdigest()[:16]


class tx:
    """Tek bağlantı üzerinde işlem (transaction). Hata olursa her şey geri alınır."""

    async def __aenter__(self):
        self._cm = pool.connection()
        self.conn = await self._cm.__aenter__()
        self._tx = self.conn.transaction()
        await self._tx.__aenter__()
        return self

    async def __aexit__(self, et, ev, tb):
        try:
            await self._tx.__aexit__(et, ev, tb)
        finally:
            await self._cm.__aexit__(et, ev, tb)
        return False

    async def q(self, sql: str, *args) -> list[dict]:
        cur = await self.conn.execute(sql, _clean_sql_args(args))
        return await cur.fetchall() if cur.description else []

    async def q1(self, sql: str, *args) -> dict | None:
        rows = await self.q(sql, *args)
        return rows[0] if rows else None


async def run_migrations(path: str):
    with open(path, encoding="utf-8") as f:
        sql = f.read()
    async with pool.connection() as c:
        await c.execute(sql)


async def patient(pid: int) -> dict:
    r = await q1("SELECT * FROM patients WHERE id=%s", pid)
    if not r:
        raise KeyError(pid)
    r["phone"] = dec(r["phone_enc"])
    return r


async def has_consent(pid: int, kind: str) -> bool:
    return bool(await q1("SELECT 1 FROM consents WHERE patient_id=%s AND kind=%s AND revoked_at IS NULL", pid, kind))


async def add_consent(pid: int, kind: str, version: str, text: str, channel: str):
    await q("INSERT INTO consents (patient_id, kind, text_version, text_sha256, channel) VALUES (%s,%s,%s,%s,%s)",
            pid, kind, version, hashlib.sha256(text.encode()).hexdigest(), channel)


def dec_msg_body(raw: str | None) -> str | None:
    if raw is None or raw == "":
        return raw
    try:
        return dec(raw)
    except Exception:
        return raw


async def log_msg(
    pid: int | None,
    direction: str,
    layer: str | None = None,
    intent: str | None = None,
    tin: int = 0,
    tout: int = 0,
    clinic_id: int | None = None,
    body: str | None = None,
    delivery_status: str | None = None,
    delivery_error: str | None = None,
):
    if clinic_id is None:
        if pid is not None:
            row = await q1("SELECT clinic_id FROM patients WHERE id=%s", pid)
            clinic_id = int(row["clinic_id"]) if row else 1
        else:
            clinic_id = 1
    body_enc = enc(body[:2000]) if body else ("" if body == "" else None)
    await q(
        """INSERT INTO message_log
           (clinic_id, patient_id, direction, layer, intent, tokens_in, tokens_out, body, delivery_status, delivery_error)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        clinic_id, pid, direction, layer, intent, tin, tout, body_enc, delivery_status, delivery_error,
    )


async def add_alert(pid: int | None, kind: str, detail: str, clinic_id: int | None = None) -> int:
    if clinic_id is None:
        if pid is not None:
            row = await q1("SELECT clinic_id FROM patients WHERE id=%s", pid)
            clinic_id = int(row["clinic_id"]) if row else 1
        else:
            clinic_id = 1
    r = await q1("INSERT INTO alerts (clinic_id, patient_id, kind, detail) VALUES (%s,%s,%s,%s) RETURNING id", clinic_id, pid, kind, detail)
    return r["id"]
