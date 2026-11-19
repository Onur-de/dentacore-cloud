"""DentaCore v5.0 Yerel Sunucu (PostgreSQL/Docker gerektirmeden anında çalışan tam sürüm).
- Port: 8000 (http://localhost:8000 ve http://localhost:8000/app) · DC_HOST/DC_PORT/PUBLIC_URL ortam değişkenleriyle değiştirilebilir
- Veritabanı: SQLite (dentacore_local.db) — Çoklu klinik (multi-tenant) izolasyonu
- Güvenlik: 12 HTTP güvenlik başlığı, scrypt parola özeti, TOTP 2FA, CSRF, SHA-256 hash-zincirli denetim kaydı
- Takvim: iPhone (Apple Takvim .ics + webcal://) ve Android (Google Takvim + .ics) canlı entegrasyon
- LLM Gateway: OmniRoute (http://127.0.0.1:20128/v1 · model: free-auto) + 3 katmanlı Token Router
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import html as html_lib
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import threading
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Literal
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
from cryptography.fernet import Fernet
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
import uvicorn

ROOT = Path(__file__).resolve().parent
API_DIR = ROOT / "api"
WEB = API_DIR / "app" / "web"
DB_PATH = Path(os.environ.get("DC_DB_PATH") or (ROOT / "dentacore_local.db"))
# P0-8: Anahtar dosyasının yolu import anında, anahtarlar yüklenmeden ÖNCE ortamdan okunur
# (bulut başlatıcı run_cloud.py import sonrası atama yaptığında anahtarlar geçici dizinden yükleniyordu).
SECRETS_PATH = Path(os.environ.get("DC_SECRETS_PATH") or (ROOT / ".local_secrets.json"))
DC_ENV = (os.environ.get("DC_ENV") or "local").strip().lower()
IS_PROD = DC_ENV in ("prod", "production")
TZ = ZoneInfo("Europe/Istanbul")
_SECRET_KEYS = ("DATA_ENCRYPTION_KEY", "PHONE_HMAC_KEY", "ADMIN_TOKEN")
# P0-10 (c4d6a2f): Git geçmişinde açığa çıkmış eski QA test anahtarları kalıcı kara listededir.
COMPROMISED_SECRETS_DENYLIST = frozenset({
    "Tet8XeZ17zgbFNprLrV7y-W8hnfGvpk4D-25FMXF2y8=",
    "112ebe88d9b687f7b3fca9a6d2be2008d84864e61c518604f7b140894c842493",
    "cbcf8564524ac511c47bc9b4a43383c9258086a1f173532807b385166c4f1a90",
    "bdb9da38d70a587792bee84a2325986ed118af25d92f40cc",
    "f20c9368ab6fe62e31b297c30d01ee9c99b66d74f8a7764c",
    "cb32c4870441f2432e6bd4c58fea77e1",
    "e1858736338792a95f809dc4ea3b094a",
})


def _validate_not_compromised(sec_dict: dict[str, str]) -> None:
    for k, val in sec_dict.items():
        if isinstance(val, str) and val.strip() in COMPROMISED_SECRETS_DENYLIST:
            raise RuntimeError(
                f"Güvenlik ihlali: {k} için Git geçmişinde (c4d6a2f) açığa çıkmış eski test anahtarı kullanılamaz. "
                "Lütfen yeni bir anahtar üretin."
            )
    for env_k in ("WA_APP_SECRET", "IG_APP_SECRET", "WA_VERIFY_TOKEN", "IG_VERIFY_TOKEN"):
        if os.environ.get(env_k, "").strip() in COMPROMISED_SECRETS_DENYLIST:
            raise RuntimeError(f"Güvenlik ihlali: {env_k} için c4d6a2f sızıntı anahtarı kullanılamaz.")


def _load_secrets() -> dict[str, str]:
    data: dict[str, str] = {}
    if SECRETS_PATH.exists():
        try:
            data = json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
        except Exception:
            data = {}
    # Ortam değişkeni dosyadan önceliklidir; böylece uygulama ve api/app modülleri aynı anahtarı kullanır.
    for k in _SECRET_KEYS:
        if os.environ.get(k):
            data[k] = os.environ[k]
    _validate_not_compromised(data)
    if all(data.get(k) for k in _SECRET_KEYS):
        return data
    if IS_PROD:
        raise RuntimeError(
            "Üretimde (DC_ENV=prod) şifreleme anahtarları eksik: DATA_ENCRYPTION_KEY, PHONE_HMAC_KEY, ADMIN_TOKEN "
            "ortam değişkeni veya kalıcı DC_SECRETS_PATH dosyası zorunludur. Yeni anahtar üretilirse eski şifreli veriler açılamaz."
        )
    data.setdefault("DATA_ENCRYPTION_KEY", Fernet.generate_key().decode())
    data.setdefault("PHONE_HMAC_KEY", secrets.token_hex(32))
    data.setdefault("ADMIN_TOKEN", secrets.token_hex(32))
    SECRETS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SECRETS_PATH.write_text(json.dumps({k: data[k] for k in _SECRET_KEYS}, indent=2), encoding="utf-8")
    return data


_SECRETS = _load_secrets()
if DC_ENV == "local":
    # HTTP yalnız yerel (localhost) kurulumda serbest; staging/prod'da Secure/__Host- çerez ve HTTPS zorunlu kalır.
    os.environ.setdefault("DC_ALLOW_HTTP_LOCAL", "1")
os.environ["DATA_ENCRYPTION_KEY"] = _SECRETS["DATA_ENCRYPTION_KEY"]
os.environ["PHONE_HMAC_KEY"] = _SECRETS["PHONE_HMAC_KEY"]
os.environ["ADMIN_TOKEN"] = _SECRETS["ADMIN_TOKEN"]
os.environ.setdefault("LLM_BASE_URL", "http://127.0.0.1:20128/v1")
os.environ.setdefault("LLM_SMALL_MODEL", "free-auto")
os.environ.setdefault("LLM_MAIN_MODEL", "free-auto")
os.environ.setdefault("CLINIC_NAME", "Özel DentaCore Merkez Polikliniği")

sys.path.insert(0, str(API_DIR))
from app import cal, enterprise_ext as ent, media, security as sec, wa  # noqa: E402
from app.dental_catalog import (  # noqa: E402
    FDI_TOOTH_CATALOG,
    ODO_ALL_STATUSES,
    ODO_BILLABLE_STATUSES,
    ODO_PLANNED_STATUSES,
    PATIENT_SOURCE_LABELS,
    PERMISSION_KEYS,
    STAFF_PROFESSIONS,
    compute_ai_cost_report,
    compute_bank_discount,
    detect_acquisition_source,
    is_bot_traffic,
    normalize_source,
    resolve_permissions,
    validate_ethical_group_tag,
)
from app.router import TokenRouter, normalize  # noqa: E402

log = logging.getLogger("dentacore.local")
_SEEN_WEBHOOK_IDS = sec.WebhookDedupCache(max_size=10_000, ttl_seconds=86_400)
_SCHED_TASK: asyncio.Task | None = None
_SCHED_LOCK = asyncio.Lock()

_FERNET = Fernet(_SECRETS["DATA_ENCRYPTION_KEY"].encode())
_HMAC_KEY = _SECRETS["PHONE_HMAC_KEY"].encode()
_ADMIN_KEY = _SECRETS["ADMIN_TOKEN"].encode()
_DB_LOCK = threading.RLock()
_CONN: sqlite3.Connection | None = None
_LIMITER = sec.RateLimiter()
_ROUTER = TokenRouter()

ANAMNEZ_SORULAR = [
    ("kan_sulandirici", "Kan sulandırıcı kullanıyor musunuz? (Coumadin/warfarin, aspirin, Xarelto, Eliquis vb.)", True),
    ("kanama_bozuklugu", "Kanama/pıhtılaşma bozukluğunuz var mı?", True),
    ("penisilin_alerji", "Penisilin veya başka bir antibiyotiğe alerjiniz var mı?", True),
    ("anestezi_alerji", "Lokal anesteziye (uyuşturma) karşı alerji veya kötü deneyim yaşadınız mı?", True),
    ("diyabet", "Diyabet (şeker hastalığı) var mı?", True),
    ("kalp", "Kalp hastalığı, kalp kapak sorunu, pil (pacemaker) veya son 6 ayda kalp krizi/inme öykünüz var mı?", True),
    ("tansiyon", "Yüksek tansiyon tedavisi görüyor musunuz?", False),
    ("bifosfonat", "Kemik erimesi veya kanser tedavisi için bifosfonat/denosumab (Fosamax, Zometa, Prolia vb.) kullandınız mı?", True),
    ("radyoterapi", "Baş-boyun bölgesine radyoterapi aldınız mı?", True),
    ("hamilelik", "Hamile misiniz veya hamilelik ihtimali var mı?", True),
    ("sigara", "Sigara kullanıyor musunuz?", False),
]


def enc(s: str) -> str:
    return _FERNET.encrypt(str(s).encode()).decode()


def dec(s: str) -> str:
    return _FERNET.decrypt(str(s).encode()).decode()


def _dec_msg_body(raw: str | None) -> str | None:
    if raw is None or raw == "":
        return raw
    try:
        return dec(raw)
    except Exception:
        return raw


def _has_consent(pid: int | None, kind: str) -> bool:
    if not pid:
        return False
    return bool(q1("SELECT 1 FROM consents WHERE patient_id=? AND kind=? AND granted_at IS NOT NULL AND revoked_at IS NULL LIMIT 1", pid, kind))


def norm_phone(p: str) -> str:
    d = re.sub(r"\D", "", p or "")
    if d.startswith("00"):
        d = d[2:]
    # P0-2: "+90 0532 ..." / "0090 0532 ..." gibi ülke kodu + başta sıfır yazımı (900 5xx..., 13 hane)
    if d.startswith("900") and len(d) == 13:
        d = "90" + d[3:]
    if d.startswith("0") and len(d) == 11:
        d = "90" + d[1:]
    if len(d) == 10 and d.startswith("5"):
        d = "90" + d
    return d


def phone_hmac(p: str) -> str:
    return hmac.new(_HMAC_KEY, norm_phone(p).encode(), hashlib.sha256).hexdigest()


def ip_hash(ip: str | None) -> str:
    return hmac.new(_HMAC_KEY, (ip or "-").encode(), hashlib.sha256).hexdigest()[:16]


def sign_path(path: str, ttl: int = 86400) -> str:
    exp = int(datetime.now(timezone.utc).timestamp()) + ttl
    sig = hmac.new(_ADMIN_KEY, f"{path}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return f"{path}?exp={exp}&sig={sig}"


def verify_sig(path: str, exp: str, sig: str) -> bool:
    try:
        if int(exp) < datetime.now(timezone.utc).timestamp():
            return False
    except ValueError:
        return False
    good = hmac.new(_ADMIN_KEY, f"{path}|{exp}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(good, sig or "")


def _hash_pw(pw: str) -> str:
    try:
        return sec.hash_password(pw)
    except ValueError as e:
        raise HTTPException(400, str(e))


def kurus(v: Decimal | float | int | str) -> int:
    return int((Decimal(str(v if v is not None else 0)) * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def tl(k: int | None) -> float:
    return round((k or 0) / 100, 2)


def mask_phone(p: str) -> str:
    if p.startswith("ig:"):
        return "Instagram"
    d = re.sub(r"\D", "", p)
    return f"+{d[:2]} {d[2:3]}** *** {d[-4:-2]} {d[-2:]}" if len(d) >= 10 else "***"


def client_ip(request: Request) -> str:
    if os.environ.get("TRUSTED_PROXY") == "1":
        xff = (request.headers.get("x-forwarded-for") or "").strip()
        if xff:
            first = xff.split(",")[0].strip()
            if first:
                return first[:64]
    return request.client.host if request.client else "-"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def db() -> sqlite3.Connection:
    global _CONN
    if _CONN is None:
        _CONN = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=15.0)
        _CONN.row_factory = sqlite3.Row
        _CONN.execute("PRAGMA journal_mode = WAL")
        _CONN.execute("PRAGMA synchronous = NORMAL")
        _CONN.execute("PRAGMA busy_timeout = 5000")
        _CONN.execute("PRAGMA foreign_keys = ON")
    return _CONN


_SQL_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u00ad\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")


def _clean_sql_args(args: tuple) -> tuple:
    return tuple(_SQL_CTRL_RE.sub("", a) if isinstance(a, str) else a for a in args)


def q(sql: str, *args) -> list[dict]:
    clean = _clean_sql_args(args)
    with _DB_LOCK:
        cur = db().execute(sql, clean)
        return [dict(r) for r in cur.fetchall()]


def q1(sql: str, *args) -> dict | None:
    rows = q(sql, *args)
    return rows[0] if rows else None


def ex(sql: str, *args) -> int:
    clean = _clean_sql_args(args)
    with _DB_LOCK:
        c = db()
        cur = c.execute(sql, clean)
        c.commit()
        return cur.lastrowid


def write_audit(actor_id: int | None, actor: str, action: str, target: str = "", ip_h: str = "", meta: dict | None = None, clinic_id: int = 1):
    m = json.dumps(meta or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    ts = now_utc().isoformat(timespec="microseconds")
    with _DB_LOCK:
        c = db()
        last = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        prev = last["hash"] if last else sec.GENESIS
        h = sec.audit_digest(prev, ts, actor, action, target, m)
        c.execute(
            "INSERT INTO audit_log (clinic_id, ts, actor_id, actor, action, target, ip_hash, meta, prev_hash, hash) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (clinic_id, ts, actor_id, actor, action, target, ip_h, m, prev, h),
        )
        c.commit()


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS clinics (
  id                 INTEGER PRIMARY KEY AUTOINCREMENT,
  name               TEXT NOT NULL,
  slug               TEXT UNIQUE NOT NULL,
  city               TEXT NOT NULL DEFAULT 'İstanbul',
  address            TEXT NOT NULL DEFAULT '',
  phone              TEXT NOT NULL DEFAULT '',
  chairs             INTEGER NOT NULL DEFAULT 2,
  work_minutes       INTEGER NOT NULL DEFAULT 600,
  google_review_url  TEXT NOT NULL DEFAULT '',
  autopilot_name     TEXT NOT NULL DEFAULT 'DentaCore Asistan',
  default_lang       TEXT NOT NULL DEFAULT 'tr',
  slot_step_min      INTEGER NOT NULL DEFAULT 15,
  working_hours_json TEXT NOT NULL DEFAULT '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}',
  buffer_min         INTEGER NOT NULL DEFAULT 0,
  ai_custom_rules_json TEXT NOT NULL DEFAULT '{}',
  wa_phone_id        TEXT NOT NULL DEFAULT '',
  ig_handle          TEXT NOT NULL DEFAULT '',
  cal_token_version  INTEGER NOT NULL DEFAULT 1,
  active             INTEGER NOT NULL DEFAULT 1,
  created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS staff_users (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id       INTEGER NOT NULL DEFAULT 1,
  email           TEXT UNIQUE NOT NULL,
  full_name       TEXT NOT NULL,
  role            TEXT NOT NULL,
  pw_hash         TEXT NOT NULL,
  phone_hmac      TEXT UNIQUE,
  share_pct       REAL NOT NULL DEFAULT 0,
  totp_secret_enc TEXT,
  totp_enabled    INTEGER NOT NULL DEFAULT 0,
  totp_last_step  INTEGER NOT NULL DEFAULT 0,
  failed_count    INTEGER NOT NULL DEFAULT 0,
  locked_until    TEXT,
  active          INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash          TEXT PRIMARY KEY,
  user_id          INTEGER NOT NULL,
  active_clinic_id INTEGER,
  csrf             TEXT NOT NULL,
  created_at       TEXT NOT NULL,
  last_seen        TEXT NOT NULL,
  expires_at       TEXT NOT NULL,
  revoked          INTEGER NOT NULL DEFAULT 0,
  ua               TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id   INTEGER NOT NULL DEFAULT 1,
  ts          TEXT NOT NULL,
  actor_id    INTEGER,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  ip_hash     TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS patients (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id     INTEGER NOT NULL DEFAULT 1,
  phone_hmac    TEXT NOT NULL,
  phone_enc     TEXT NOT NULL,
  display_name  TEXT,
  lang          TEXT NOT NULL DEFAULT 'tr',
  channel       TEXT NOT NULL DEFAULT 'wa',
  created_at    TEXT NOT NULL,
  UNIQUE(clinic_id, phone_hmac)
);

CREATE TABLE IF NOT EXISTS consents (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id   INTEGER NOT NULL,
  kind         TEXT NOT NULL,
  text_version TEXT NOT NULL,
  text_sha256  TEXT NOT NULL,
  channel      TEXT NOT NULL,
  granted_at   TEXT NOT NULL,
  revoked_at   TEXT
);

CREATE TABLE IF NOT EXISTS appointments (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id   INTEGER NOT NULL DEFAULT 1,
  patient_id  INTEGER,
  starts_at   TEXT NOT NULL,
  duration_min INTEGER NOT NULL DEFAULT 30,
  treatment   TEXT NOT NULL,
  chair       TEXT NOT NULL DEFAULT '1',
  doctor_id   INTEGER,
  status           TEXT NOT NULL DEFAULT 'booked',
  source           TEXT NOT NULL DEFAULT 'panel',
  reminder_sent_at TEXT,
  followup_sent_at TEXT,
  created_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS waitlist (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id  INTEGER NOT NULL,
  treatment   TEXT NOT NULL,
  earliest    TEXT NOT NULL,
  active      INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS slot_offers (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  appointment_id INTEGER NOT NULL,
  waitlist_id    INTEGER NOT NULL,
  wave           INTEGER NOT NULL,
  sent_at        TEXT NOT NULL,
  expires_at     TEXT,
  status         TEXT NOT NULL DEFAULT 'sent'
);

CREATE TABLE IF NOT EXISTS anamnesis (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id       INTEGER NOT NULL,
  answers_enc      TEXT NOT NULL,
  red_flags_json   TEXT NOT NULL DEFAULT '[]',
  signer_name      TEXT NOT NULL,
  signature_sha256 TEXT NOT NULL,
  signed_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS anamnesis_tokens (
  token       TEXT PRIMARY KEY,
  patient_id  INTEGER NOT NULL,
  expires_at  TEXT NOT NULL,
  used_at     TEXT
);

CREATE TABLE IF NOT EXISTS postop_checks (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  patient_id  INTEGER NOT NULL,
  procedure   TEXT NOT NULL,
  due_at      TEXT NOT NULL,
  stage       TEXT NOT NULL,
  sent_at     TEXT,
  pain_score  INTEGER,
  answered_at TEXT,
  alarm       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inventory_items (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id       INTEGER NOT NULL DEFAULT 1,
  name            TEXT NOT NULL,
  sku             TEXT,
  unit            TEXT NOT NULL DEFAULT 'adet',
  qty             REAL NOT NULL DEFAULT 0 CHECK (qty >= 0),
  min_qty         REAL NOT NULL DEFAULT 0 CHECK (min_qty >= 0),
  unit_cost_kurus INTEGER NOT NULL DEFAULT 0 CHECK (unit_cost_kurus >= 0),
  active          INTEGER NOT NULL DEFAULT 1,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS stock_moves (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id     INTEGER NOT NULL,
  delta       REAL NOT NULL,
  qty_after   REAL NOT NULL,
  reason      TEXT NOT NULL,
  actor_id    INTEGER,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS charges (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id       INTEGER NOT NULL DEFAULT 1,
  patient_id      INTEGER NOT NULL,
  description     TEXT NOT NULL,
  amount_kurus    INTEGER NOT NULL CHECK (amount_kurus > 0),
  doctor_id       INTEGER,
  created_by      INTEGER,
  created_at      TEXT NOT NULL,
  voided_at       TEXT,
  void_reason     TEXT,
  idempotency_key TEXT
);

CREATE TABLE IF NOT EXISTS payments (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id       INTEGER NOT NULL DEFAULT 1,
  patient_id      INTEGER NOT NULL,
  amount_kurus    INTEGER NOT NULL CHECK (amount_kurus > 0),
  method          TEXT NOT NULL,
  created_by      INTEGER,
  created_at      TEXT NOT NULL,
  voided_at       TEXT,
  void_reason     TEXT,
  idempotency_key TEXT
);

CREATE TABLE IF NOT EXISTS tooth_records (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id       INTEGER NOT NULL DEFAULT 1,
  patient_id      INTEGER NOT NULL,
  tooth_fdi       INTEGER NOT NULL CHECK ((tooth_fdi BETWEEN 11 AND 48) OR (tooth_fdi BETWEEN 51 AND 85)),
  surface         TEXT NOT NULL DEFAULT 'FULL' CHECK (surface IN ('M','D','O','B','L','FULL')),
  status          TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('healthy','caries','planned','treated','implant','crown','root_canal','missing','extraction')),
  procedure_code  TEXT NOT NULL DEFAULT '',
  procedure_name  TEXT NOT NULL DEFAULT '',
  amount_kurus    INTEGER NOT NULL DEFAULT 0 CHECK (amount_kurus >= 0),
  doctor_id       INTEGER,
  note            TEXT NOT NULL DEFAULT '',
  created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tooth_records_patient_idx ON tooth_records(clinic_id, patient_id, tooth_fdi);

CREATE TABLE IF NOT EXISTS message_log (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id       INTEGER NOT NULL DEFAULT 1,
  patient_id      INTEGER,
  direction       TEXT NOT NULL,
  layer           TEXT,
  intent          TEXT,
  tokens_in       INTEGER NOT NULL DEFAULT 0,
  tokens_out      INTEGER NOT NULL DEFAULT 0,
  body            TEXT,
  delivery_status TEXT,
  delivery_error  TEXT,
  created_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id       INTEGER NOT NULL DEFAULT 1,
  patient_id      INTEGER,
  kind            TEXT NOT NULL,
  detail          TEXT NOT NULL,
  created_at      TEXT NOT NULL,
  acknowledged_at TEXT
);

CREATE TABLE IF NOT EXISTS message_templates (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id  INTEGER NOT NULL DEFAULT 1,
  name       TEXT NOT NULL,
  channel    TEXT NOT NULL DEFAULT 'whatsapp',
  lang       TEXT NOT NULL DEFAULT 'tr',
  category   TEXT NOT NULL DEFAULT 'UTILITY',
  body       TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'APPROVED',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
  id                  INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id           INTEGER NOT NULL DEFAULT 1,
  name                TEXT NOT NULL,
  source              TEXT NOT NULL DEFAULT 'meta_ads',
  clicks              INTEGER NOT NULL DEFAULT 0,
  conversations       INTEGER NOT NULL DEFAULT 0,
  appointments_booked INTEGER NOT NULL DEFAULT 0,
  revenue_kurus       INTEGER NOT NULL DEFAULT 0,
  created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS leads (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic         TEXT NOT NULL,
  contact_enc    TEXT NOT NULL,
  city           TEXT,
  chairs         INTEGER,
  kvkk_version   TEXT NOT NULL DEFAULT '',
  kvkk_sha256    TEXT NOT NULL DEFAULT '',
  yurt_disi_riza INTEGER NOT NULL DEFAULT 0,
  created_at     TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log yalnizca eklemeye aciktir');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN
  SELECT RAISE(ABORT, 'audit_log yalnizca eklemeye aciktir');
END;
"""


def _migrate_sqlite():
    with _DB_LOCK:
        c = db()
        sess_cols = {r["name"] for r in c.execute("PRAGMA table_info(sessions)").fetchall()}
        if "active_clinic_id" not in sess_cols:
            c.execute("ALTER TABLE sessions ADD COLUMN active_clinic_id INTEGER")
        audit_cols = {r["name"] for r in c.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "clinic_id" not in audit_cols:
            c.execute("ALTER TABLE audit_log ADD COLUMN clinic_id INTEGER NOT NULL DEFAULT 1")
            c.execute("""UPDATE audit_log SET clinic_id = COALESCE(
                            (SELECT s.clinic_id FROM staff_users s WHERE s.id = audit_log.actor_id), 1
                         )""")
        msg_cols = {r["name"] for r in c.execute("PRAGMA table_info(message_log)").fetchall()}
        if "clinic_id" not in msg_cols:
            c.execute("ALTER TABLE message_log ADD COLUMN clinic_id INTEGER NOT NULL DEFAULT 1")
            c.execute("""UPDATE message_log SET clinic_id = COALESCE(
                            (SELECT p.clinic_id FROM patients p WHERE p.id = message_log.patient_id), 1
                         )""")
        if "body" not in msg_cols:
            c.execute("ALTER TABLE message_log ADD COLUMN body TEXT")
        if "delivery_status" not in msg_cols:
            c.execute("ALTER TABLE message_log ADD COLUMN delivery_status TEXT")
        if "delivery_error" not in msg_cols:
            c.execute("ALTER TABLE message_log ADD COLUMN delivery_error TEXT")
        for mrow in c.execute("SELECT id, body FROM message_log WHERE body IS NOT NULL AND body <> ''").fetchall():
            try:
                dec(mrow["body"])
            except Exception:
                c.execute("UPDATE message_log SET body=? WHERE id=?", (enc(mrow["body"]), mrow["id"]))
        so_cols = {r["name"] for r in c.execute("PRAGMA table_info(slot_offers)").fetchall()}
        if "expires_at" not in so_cols:
            c.execute("ALTER TABLE slot_offers ADD COLUMN expires_at TEXT")
        appt_cols = {r["name"] for r in c.execute("PRAGMA table_info(appointments)").fetchall()}
        if "reminder_sent_at" not in appt_cols:
            c.execute("ALTER TABLE appointments ADD COLUMN reminder_sent_at TEXT")
        if "followup_sent_at" not in appt_cols:
            c.execute("ALTER TABLE appointments ADD COLUMN followup_sent_at TEXT")
        pat_sql_row = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='patients'").fetchone()
        pat_sql = (pat_sql_row["sql"] or "") if pat_sql_row else ""
        if "UNIQUE(CLINIC_ID,PHONE_HMAC)" not in re.sub(r"\s+", "", pat_sql).upper():
            c.execute("PRAGMA foreign_keys = OFF")
            c.executescript("""
                CREATE TABLE patients_new (
                  id            INTEGER PRIMARY KEY AUTOINCREMENT,
                  clinic_id     INTEGER NOT NULL DEFAULT 1,
                  phone_hmac    TEXT NOT NULL,
                  phone_enc     TEXT NOT NULL,
                  display_name  TEXT,
                  lang          TEXT NOT NULL DEFAULT 'tr',
                  channel       TEXT NOT NULL DEFAULT 'wa',
                  created_at    TEXT NOT NULL,
                  UNIQUE(clinic_id, phone_hmac)
                );
                INSERT INTO patients_new (id, clinic_id, phone_hmac, phone_enc, display_name, lang, channel, created_at)
                SELECT id, clinic_id, phone_hmac, phone_enc, display_name, lang, channel, created_at FROM patients;
                DROP TABLE patients;
                ALTER TABLE patients_new RENAME TO patients;
            """)
            c.execute("PRAGMA foreign_keys = ON")
        pat_cols = {r["name"] for r in c.execute("PRAGMA table_info(patients)").fetchall()}
        if "active" not in pat_cols:
            c.execute("ALTER TABLE patients ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        clinic_cols = {r["name"] for r in c.execute("PRAGMA table_info(clinics)").fetchall()}
        if "working_hours_json" not in clinic_cols:
            c.execute("""ALTER TABLE clinics ADD COLUMN working_hours_json TEXT NOT NULL DEFAULT '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}'""")
        if "buffer_min" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN buffer_min INTEGER NOT NULL DEFAULT 0")
        if "ai_custom_rules_json" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN ai_custom_rules_json TEXT NOT NULL DEFAULT '{}'")
        if "wa_phone_id" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN wa_phone_id TEXT NOT NULL DEFAULT ''")
        if "ig_handle" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN ig_handle TEXT NOT NULL DEFAULT ''")
        if "cal_token_version" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN cal_token_version INTEGER NOT NULL DEFAULT 1")
        lead_cols = {r["name"] for r in c.execute("PRAGMA table_info(leads)").fetchall()}
        if "kvkk_version" not in lead_cols:
            c.execute("ALTER TABLE leads ADD COLUMN kvkk_version TEXT NOT NULL DEFAULT ''")
        if "kvkk_sha256" not in lead_cols:
            c.execute("ALTER TABLE leads ADD COLUMN kvkk_sha256 TEXT NOT NULL DEFAULT ''")
        if "yurt_disi_riza" not in lead_cols:
            c.execute("ALTER TABLE leads ADD COLUMN yurt_disi_riza INTEGER NOT NULL DEFAULT 0")
        chg_cols = {r["name"] for r in c.execute("PRAGMA table_info(charges)").fetchall()}
        if "idempotency_key" not in chg_cols:
            c.execute("ALTER TABLE charges ADD COLUMN idempotency_key TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS charges_idem_uq ON charges(clinic_id, idempotency_key) WHERE idempotency_key IS NOT NULL")
        pay_cols = {r["name"] for r in c.execute("PRAGMA table_info(payments)").fetchall()}
        if "idempotency_key" not in pay_cols:
            c.execute("ALTER TABLE payments ADD COLUMN idempotency_key TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS payments_idem_uq ON payments(clinic_id, idempotency_key) WHERE idempotency_key IS NOT NULL")
        c.executescript("""
            CREATE TABLE IF NOT EXISTS tooth_records (
              id              INTEGER PRIMARY KEY AUTOINCREMENT,
              clinic_id       INTEGER NOT NULL DEFAULT 1,
              patient_id      INTEGER NOT NULL,
              tooth_fdi       INTEGER NOT NULL CHECK ((tooth_fdi BETWEEN 11 AND 48) OR (tooth_fdi BETWEEN 51 AND 85)),
              surface         TEXT NOT NULL DEFAULT 'FULL' CHECK (surface IN ('M','D','O','B','L','FULL')),
              status          TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('healthy','caries','planned','treated','implant','crown','root_canal','missing','extraction')),
              procedure_code  TEXT NOT NULL DEFAULT '',
              procedure_name  TEXT NOT NULL DEFAULT '',
              amount_kurus    INTEGER NOT NULL DEFAULT 0 CHECK (amount_kurus >= 0),
              doctor_id       INTEGER,
              note            TEXT NOT NULL DEFAULT '',
              created_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS tooth_records_patient_idx ON tooth_records(clinic_id, patient_id, tooth_fdi);
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log yalnizca eklemeye aciktir'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log yalnizca eklemeye aciktir'); END;
        """)
        ent.migrate_enterprise_sqlite(c, iso_now())
        c.commit()


def _bootstrap_prod_owner():
    """Üretim kurulumu: yalnız ortamdan verilen tek klinik + tek yönetici. Demo veri yok."""
    if q1("SELECT 1 FROM clinics LIMIT 1"):
        return
    email = (os.environ.get("OWNER_EMAIL") or "").strip().lower()
    password = os.environ.get("OWNER_PASSWORD") or ""
    if not email or len(password) < 12:
        raise RuntimeError("DC_ENV=prod ilk kurulum için OWNER_EMAIL ve en az 12 karakterli OWNER_PASSWORD gereklidir.")
    t0 = iso_now()
    ex(
        "INSERT INTO clinics (id,name,slug,city,created_at) VALUES (?,?,?,?,?)",
        1, os.environ.get("CLINIC_NAME") or "Klinik", "klinik-1", os.environ.get("CLINIC_CITY") or "İstanbul", t0,
    )
    ex(
        "INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,share_pct,created_at) VALUES (?,?,?,?,?,?,?)",
        1, email, os.environ.get("OWNER_NAME") or "Klinik Yöneticisi", "owner", sec.hash_password(password), 0.0, t0,
    )
    write_audit(None, "system", "clinic.bootstrap_prod", "clinic:1", clinic_id=1)


def _seed_clinic3():
    if IS_PROD or q1("SELECT 1 FROM clinics WHERE id=3"):
        return
    t0 = iso_now()
    ex(
        "INSERT INTO clinics (id,name,slug,city,address,phone,chairs,google_review_url,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        3, "Ankara Çankaya Estetik Diş Polikliniği", "ankara-cankaya-estetik-dis", "Ankara",
        "Tunalı Hilmi Cad. No:88, Çankaya / Ankara", "+90 312 555 03 03", 3,
        "https://search.google.com/local/writereview?placeid=ChIJExample3", t0,
    )
    pw3 = sec.hash_password("AnkaraDis2026!")
    u3 = ex(
        "INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,phone_hmac,share_pct,created_at) VALUES (?,?,?,?,?,?,?,?)",
        3, "klinik@ankaradis.com", "Dt. Zeynep Demir", "owner", pw3, phone_hmac("+905320000003"), 50.0, t0,
    )
    p6 = ex(
        "INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
        3, phone_hmac("+905361112233"), enc("905361112233"), "Mehmet Öz (Ankara)", "tr", "wa", t0,
    )
    p7 = ex(
        "INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
        3, phone_hmac("+905374445566"), enc("905374445566"), "Zehra Ak (Ankara)", "tr", "wa", t0,
    )
    today = datetime.now(TZ).replace(hour=11, minute=0, second=0, microsecond=0)
    ex(
        "INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        3, p6, today.isoformat(), 45, "Estetik Lamine Prova", "1", u3, "confirmed", "panel", t0,
    )
    ex(
        "INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        3, p7, (today + timedelta(hours=2)).isoformat(), 30, "Diş Beyazlatma", "2", u3, "booked", "whatsapp_ai", t0,
    )
    i3 = ex(
        "INSERT INTO inventory_items (clinic_id,name,sku,unit,qty,min_qty,unit_cost_kurus,created_at) VALUES (?,?,?,?,?,?,?,?)",
        3, "Ivoclar IPS e.max Press Blok", "EMAX-A1", "adet", 6, 3, 240000, t0,
    )
    ex("INSERT INTO stock_moves (item_id,delta,qty_after,reason,actor_id,created_at) VALUES (?,?,?,?,?,?)",
       i3, 6, 6, "İlk stok", u3, t0)
    ex(
        "INSERT INTO charges (clinic_id,patient_id,description,amount_kurus,doctor_id,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
        3, p6, "E-max Lamine x4", 2400000, u3, u3, t0,
    )
    ex(
        "INSERT INTO payments (clinic_id,patient_id,amount_kurus,method,created_by,created_at) VALUES (?,?,?,?,?,?)",
        3, p6, 1200000, "kart", u3, t0,
    )
    ex(
        "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,?,?,?)",
        3, p6, "gorsel_alindi", "Mehmet Öz (#6) gülüş tasarımı ön fotoğrafı yükledi.", t0,
    )
    ex(
        "INSERT INTO message_templates (clinic_id,name,channel,lang,category,body,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
        3, "randevu_hatirlatma", "whatsapp", "tr", "UTILITY", "Sayın {{1}}, yarın saat {{2}} Ankara Çankaya şubemizde randevunuz vardır.", "APPROVED", t0,
    )
    ex("INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,?,?,?,?,?,?)",
       3, p6, "in", None, "wa:text", 0, 0, t0)
    ex("INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,?,?,?,?,?,?)",
       3, p6, "out", "L1-sss", "konum", 0, 0, t0)
    write_audit(u3, "klinik@ankaradis.com", "clinic.seed", "clinic:3", clinic_id=3)


def init_and_seed():
    with _DB_LOCK:
        c = db()
        c.executescript(SCHEMA_SQL)
        pat_cols = {r["name"] for r in c.execute("PRAGMA table_info(patients)").fetchall()}
        if "active" not in pat_cols:
            c.execute("ALTER TABLE patients ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        clinic_cols = {r["name"] for r in c.execute("PRAGMA table_info(clinics)").fetchall()}
        if "working_hours_json" not in clinic_cols:
            c.execute("""ALTER TABLE clinics ADD COLUMN working_hours_json TEXT NOT NULL DEFAULT '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}'""")
        if "buffer_min" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN buffer_min INTEGER NOT NULL DEFAULT 0")
        if "ai_custom_rules_json" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN ai_custom_rules_json TEXT NOT NULL DEFAULT '{}'")
        if "wa_phone_id" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN wa_phone_id TEXT NOT NULL DEFAULT ''")
        if "ig_handle" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN ig_handle TEXT NOT NULL DEFAULT ''")
        if "cal_token_version" not in clinic_cols:
            c.execute("ALTER TABLE clinics ADD COLUMN cal_token_version INTEGER NOT NULL DEFAULT 1")
        lead_cols = {r["name"] for r in c.execute("PRAGMA table_info(leads)").fetchall()}
        if "kvkk_version" not in lead_cols:
            c.execute("ALTER TABLE leads ADD COLUMN kvkk_version TEXT NOT NULL DEFAULT ''")
        if "kvkk_sha256" not in lead_cols:
            c.execute("ALTER TABLE leads ADD COLUMN kvkk_sha256 TEXT NOT NULL DEFAULT ''")
        if "yurt_disi_riza" not in lead_cols:
            c.execute("ALTER TABLE leads ADD COLUMN yurt_disi_riza INTEGER NOT NULL DEFAULT 0")
        chg_cols = {r["name"] for r in c.execute("PRAGMA table_info(charges)").fetchall()}
        if "idempotency_key" not in chg_cols:
            c.execute("ALTER TABLE charges ADD COLUMN idempotency_key TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS charges_idem_uq ON charges(clinic_id, idempotency_key) WHERE idempotency_key IS NOT NULL")
        pay_cols = {r["name"] for r in c.execute("PRAGMA table_info(payments)").fetchall()}
        if "idempotency_key" not in pay_cols:
            c.execute("ALTER TABLE payments ADD COLUMN idempotency_key TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS payments_idem_uq ON payments(clinic_id, idempotency_key) WHERE idempotency_key IS NOT NULL")
        c.executescript("""
            CREATE TABLE IF NOT EXISTS tooth_records (
              id              INTEGER PRIMARY KEY AUTOINCREMENT,
              clinic_id       INTEGER NOT NULL DEFAULT 1,
              patient_id      INTEGER NOT NULL,
              tooth_fdi       INTEGER NOT NULL CHECK ((tooth_fdi BETWEEN 11 AND 48) OR (tooth_fdi BETWEEN 51 AND 85)),
              surface         TEXT NOT NULL DEFAULT 'FULL' CHECK (surface IN ('M','D','O','B','L','FULL')),
              status          TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('healthy','caries','planned','treated','implant','crown','root_canal','missing','extraction')),
              procedure_code  TEXT NOT NULL DEFAULT '',
              procedure_name  TEXT NOT NULL DEFAULT '',
              amount_kurus    INTEGER NOT NULL DEFAULT 0 CHECK (amount_kurus >= 0),
              doctor_id       INTEGER,
              note            TEXT NOT NULL DEFAULT '',
              created_at      TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS tooth_records_patient_idx ON tooth_records(clinic_id, patient_id, tooth_fdi);
            CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log yalnizca eklemeye aciktir'); END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
            BEGIN SELECT RAISE(ABORT, 'audit_log yalnizca eklemeye aciktir'); END;
        """)
        ent.migrate_enterprise_sqlite(c, iso_now())
        c.commit()
    _migrate_sqlite()
    if IS_PROD:
        # P0 (E): Üretimde bilinen parolalı demo klinik/hesap/hasta ASLA oluşturulmaz.
        _bootstrap_prod_owner()
        return
    if q1("SELECT 1 FROM clinics LIMIT 1"):
        _seed_clinic3()
        return
    t0 = iso_now()
    ex(
        "INSERT INTO clinics (id,name,slug,city,address,phone,chairs,google_review_url,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        1, "Özel DentaCore Merkez Polikliniği", "merkez-poliklinik", "İstanbul",
        "Bağdat Cad. No:142, Kadıköy / İstanbul", "+90 216 555 01 01", 3,
        "https://search.google.com/local/writereview?placeid=ChIJExample1", t0,
    )
    ex(
        "INSERT INTO clinics (id,name,slug,city,address,phone,chairs,google_review_url,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        2, "Özel Bursa Gülüş Diş Polikliniği", "bursa-gulus-dis", "Bursa",
        "FSM Bulvarı No:48, Nilüfer / Bursa", "+90 224 555 02 02", 2,
        "https://search.google.com/local/writereview?placeid=ChIJExample2", t0,
    )
    pw1 = sec.hash_password("DentaCore2026!")
    pw2 = sec.hash_password("BursaDis2026!")
    u1 = ex("INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,phone_hmac,share_pct,created_at) VALUES (?,?,?,?,?,?,?,?)",
            1, "yonetici@dentacore.com", "Dt. Onur Aksoy", "owner", pw1, phone_hmac("+905320000001"), 50.0, t0)
    u2 = ex("INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,share_pct,created_at) VALUES (?,?,?,?,?,?,?)",
            1, "elif.hekim@dentacore.com", "Dt. Elif Yıldız", "doctor", pw1, 40.0, t0)
    ex("INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,share_pct,created_at) VALUES (?,?,?,?,?,?,?)",
       1, "sekreter@dentacore.com", "Selin Kaya", "secretary", pw1, 0.0, t0)
    ex("INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,phone_hmac,share_pct,created_at) VALUES (?,?,?,?,?,?,?,?)",
       2, "klinik@bursadis.com", "Dt. Kemal Aydın", "owner", pw2, phone_hmac("+905320000002"), 50.0, t0)

    # Hastalar (Klinik 1)
    p1 = ex("INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
            1, phone_hmac("+905321112233"), enc("905321112233"), "Ayşe Kaya", "tr", "wa", t0)
    p2 = ex("INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
            1, phone_hmac("+905334445566"), enc("905334445566"), "Ahmet Yılmaz", "tr", "wa", t0)
    p3 = ex("INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
            1, hmac.new(_HMAC_KEY, b"ig:99887766", hashlib.sha256).hexdigest(), enc("ig:99887766"), "Selin Arslan", "tr", "ig", t0)
    p4 = ex("INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
            1, phone_hmac("+447700900123"), enc("447700900123"), "Oliver Grant (London)", "en", "wa", t0)

    # Hastalar (Klinik 2 — izole kiracı örneği)
    p5 = ex("INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
            2, phone_hmac("+905357778899"), enc("905357778899"), "Murat Çelik", "tr", "wa", t0)

    # Anamnez + kırmızı bayrak (Ayşe Kaya)
    ans_p1 = json.dumps({"kan_sulandirici": "evet", "diyabet": "evet", "ilaclar": "Coraspin 100mg"}, ensure_ascii=False)
    sig_p1 = hashlib.sha256(f"{p1}|Ayse Kaya|{t0}".encode()).hexdigest()
    ex("INSERT INTO anamnesis (patient_id,answers_enc,red_flags_json,signer_name,signature_sha256,signed_at) VALUES (?,?,?,?,?,?)",
       p1, enc(ans_p1), json.dumps(["kan_sulandirici", "diyabet"]), "Ayşe Kaya", sig_p1, t0)
    ex("INSERT INTO consents (patient_id,kind,text_version,text_sha256,channel,granted_at) VALUES (?,?,?,?,?,?)",
       p1, "saglik_verisi_acik_riza", "2026-11", hashlib.sha256(b"kvkk").hexdigest(), "web_form", t0)

    # Randevular (Bugün ve yarın)
    today = datetime.now(TZ).replace(hour=10, minute=0, second=0, microsecond=0)
    ex("INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
       1, p2, today.isoformat(), 45, "İmplant Kontrol", "1", u1, "confirmed", "whatsapp_ai", t0)
    ex("INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
       1, p1, (today + timedelta(hours=1, minutes=30)).isoformat(), 60, "Yirmi Yaş Cerrahi Çekim", "1", u1, "booked", "panel", t0)
    ex("INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
       1, p3, (today + timedelta(hours=4)).isoformat(), 45, "Zirkonyum Prova", "2", u2, "confirmed", "instagram_ai", t0)
    ex("INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
       1, p4, (today + timedelta(days=1, hours=2)).isoformat(), 60, "All-on-4 Ön Değerlendirme", "1", u1, "booked", "whatsapp_ai", t0)
    ex("INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,status,source,created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
       2, p5, (today + timedelta(hours=3)).isoformat(), 30, "Kanal Tedavisi", "1", 4, "confirmed", "panel", t0)

    # Bekleme listesi
    ex("INSERT INTO waitlist (patient_id,treatment,earliest,active,created_at) VALUES (?,?,?,?,?)", p3, "Zirkonyum", t0, 1, t0)
    ex("INSERT INTO waitlist (patient_id,treatment,earliest,active,created_at) VALUES (?,?,?,?,?)", p4, "herhangi", t0, 1, t0)

    # Envanter
    i1 = ex("INSERT INTO inventory_items (clinic_id,name,sku,unit,qty,min_qty,unit_cost_kurus,created_at) VALUES (?,?,?,?,?,?,?,?)",
            1, "Straumann Kemik Seviyesi İmplant 4.1x10", "STR-4110", "adet", 2, 5, 420000, t0)
    ex("INSERT INTO stock_moves (item_id,delta,qty_after,reason,actor_id,created_at) VALUES (?,?,?,?,?,?)", i1, 2, 2, "İlk stok", u1, t0)
    i2 = ex("INSERT INTO inventory_items (clinic_id,name,sku,unit,qty,min_qty,unit_cost_kurus,created_at) VALUES (?,?,?,?,?,?,?,?)",
            1, "3M Filtek Ultimate Kompozit A2", "3M-A2", "tüp", 14, 4, 115000, t0)
    ex("INSERT INTO stock_moves (item_id,delta,qty_after,reason,actor_id,created_at) VALUES (?,?,?,?,?,?)", i2, 14, 14, "Satın alma", u1, t0)

    # Kasa
    ex("INSERT INTO charges (clinic_id,patient_id,description,amount_kurus,doctor_id,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
       1, p1, "Cerrahi Çekim + Panoramik Görüntüleme", 450000, u1, u1, t0)
    ex("INSERT INTO charges (clinic_id,patient_id,description,amount_kurus,doctor_id,created_by,created_at) VALUES (?,?,?,?,?,?,?)",
       1, p2, "İmplant Üst Yapı + Zirkonyum Kron x2", 1850000, u1, u1, t0)
    ex("INSERT INTO payments (clinic_id,patient_id,amount_kurus,method,created_by,created_at) VALUES (?,?,?,?,?,?)",
       1, p2, 1850000, "kart", u1, t0)

    # Uyarılar
    ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,?,?,?)",
       1, p1, "anamnez_kirmizi", "KIRMIZI BAYRAK: Ayşe Kaya (#1) bugünkü randevusu öncesi kan_sulandirici + diyabet bildirdi.", t0)
    ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,?,?,?)",
       1, None, "stok_kritik", "Stok kritik seviyede: Straumann Kemik Seviyesi İmplant 4.1x10 (2 adet, alt sınır 5)", t0)

    # Şablonlar & Kampanyalar
    ex("INSERT INTO message_templates (clinic_id,name,channel,lang,category,body,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
       1, "randevu_hatirlatma", "whatsapp", "tr", "UTILITY", "Sayın {{1}}, yarın saat {{2}} için kliniğimizde randevunuz vardır. Onay için 1 yazınız.", "APPROVED", t0)
    ex("INSERT INTO message_templates (clinic_id,name,channel,lang,category,body,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
       1, "bekleme_listesi_teklif", "whatsapp", "tr", "UTILITY", "Bugün saat {{1}} için {{2}} koltuğunda yer açıldı. Almak için EVET yazınız.", "APPROVED", t0)
    ex("INSERT INTO campaigns (clinic_id,name,source,clicks,conversations,appointments_booked,revenue_kurus,created_at) VALUES (?,?,?,?,?,?,?,?)",
       1, "ÖRNEK VERİ · İstanbul İmplant & Zirkonyum Meta Kampanyası", "meta_ads", 420, 86, 24, 14800000, t0)

    # Mesaj logları (son 14 gün dağılımı)
    for d_off in range(14):
        ts_day = (now_utc() - timedelta(days=d_off)).isoformat()
        for _ in range(3 + (14 - d_off) % 5):
            ex("INSERT INTO message_log (patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,?,?,?,?,?)",
               p2, "in", None, "wa:text", 0, 0, ts_day)
            ex("INSERT INTO message_log (patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,?,?,?,?,?)",
               p2, "out", "L1-sss", "konum", 0, 0, ts_day)
    ex("INSERT INTO message_log (patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,?,?,?,?,?)",
       p4, "out", "L3-ana-model", "genel", 140, 85, t0)

    write_audit(None, "system", "clinic.bootstrap", "clinic:1,clinic:2", clinic_id=1)
    _seed_clinic3()


# ---------------- Kimlik Doğrulama ----------------
def current_user(request: Request) -> dict:
    raw = request.cookies.get(sec.COOKIE, "")
    if not raw:
        raise HTTPException(401, "oturum yok")
    s = q1(
        """SELECT s.id_hash, s.csrf, s.last_seen, s.expires_at, s.active_clinic_id,
                  u.id, u.clinic_id AS home_clinic_id, u.email, u.full_name, u.role,
                  u.job_title, u.permissions_json, u.totp_enabled, u.share_pct,
                  c.name AS clinic_name, c.address AS clinic_address
           FROM sessions s JOIN staff_users u ON u.id = s.user_id
           LEFT JOIN clinics c ON c.id = COALESCE(s.active_clinic_id, u.clinic_id)
           WHERE s.id_hash=? AND s.revoked=0 AND u.active=1""",
        sec.session_hash(raw),
    )
    now = now_utc()
    if not s or datetime.fromisoformat(s["expires_at"]) < now or (now - datetime.fromisoformat(s["last_seen"])).total_seconds() > sec.IDLE_SECONDS:
        if s:
            ex("UPDATE sessions SET revoked=1 WHERE id_hash=?", s["id_hash"])
        raise HTTPException(401, "oturum süresi doldu")
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != request.headers.get("host", ""):
            raise HTTPException(403, "köken reddedildi")
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), s["csrf"]):
            raise HTTPException(403, "CSRF doğrulaması başarısız")
    perms = resolve_permissions(s.get("role"), s.get("job_title"), s.get("permissions_json"))
    if not perms.get("view", False) and not request.url.path.startswith("/auth/"):
        raise HTTPException(403, "Sistem görüntüleme yetkiniz bulunmamaktadır")
    ex("UPDATE sessions SET last_seen=? WHERE id_hash=?", iso_now(), s["id_hash"])
    s["ip_h"] = ip_hash(client_ip(request))
    s["home_clinic_id"] = int(s.get("home_clinic_id") or 1)
    s["is_hq"] = (s["home_clinic_id"] == 1 and s["role"] == "owner")
    active_cid = int(s.get("active_clinic_id") or s["home_clinic_id"])
    if not s["is_hq"] and active_cid != s["home_clinic_id"]:
        active_cid = s["home_clinic_id"]
    s["clinic_id"] = active_cid
    s["permissions"] = perms
    return s


def need(*roles: str):
    def dep(u: dict = Depends(current_user)) -> dict:
        if roles and u["role"] not in roles:
            raise HTTPException(403, "bu işlem için yetkiniz yok")
        return u
    return dep


ANY = need()
OWNER = need("owner")
CLINICAL = need("owner", "doctor")


def need_hq():
    def dep(u: dict = Depends(OWNER)) -> dict:
        if not u.get("is_hq"):
            raise HTTPException(403, "Bu işlem yalnızca platform/merkez yönetici (HQ) yetkisindedir")
        return u
    return dep


HQ_OWNER = need_hq()


def require_perm(*perm_keys: str):
    def dep(u: dict = Depends(current_user)) -> dict:
        perms = u.get("permissions") or resolve_permissions(u.get("role"), u.get("job_title"), u.get("permissions_json"))
        for pk in perm_keys:
            if not perms.get(pk, False):
                raise HTTPException(403, f"Bu işlem için '{pk}' yetkisi gereklidir")
        return u
    return dep


def _enforce_doc_own_patient(cid: int, pid: int, u: dict) -> None:
    perms = u.get("permissions") or {}
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        p = q1("SELECT primary_doctor_id, created_by FROM patients WHERE id=? AND clinic_id=?", pid, cid)
        if not p:
            raise HTTPException(404, "hasta yok")
        uid = u["id"]
        if p.get("primary_doctor_id") != uid and p.get("created_by") != uid:
            owns = (
                q1("SELECT 1 FROM appointments WHERE clinic_id=? AND patient_id=? AND doctor_id=? LIMIT 1", cid, pid, uid)
                or q1("SELECT 1 FROM tooth_records WHERE clinic_id=? AND patient_id=? AND doctor_id=? LIMIT 1", cid, pid, uid)
                or q1("SELECT 1 FROM charges WHERE clinic_id=? AND patient_id=? AND doctor_id=? LIMIT 1", cid, pid, uid)
            )
            if not owns:
                raise HTTPException(403, "Yalnızca kendi sorumluluğunuzdaki veya tedavisini yaptığınız hastaları görüntüleyebilirsiniz")

app = FastAPI(title="DentaCore Local v5.0", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(sec.SecurityHeadersMiddleware)


@app.on_event("startup")
async def _on_startup():
    global _SCHED_TASK
    init_and_seed()
    if _SCHED_TASK is None or _SCHED_TASK.done():
        _SCHED_TASK = asyncio.create_task(_scheduler_loop())


@app.on_event("shutdown")
async def _on_shutdown():
    global _SCHED_TASK
    if _SCHED_TASK and not _SCHED_TASK.done():
        _SCHED_TASK.cancel()
        try:
            await _SCHED_TASK
        except asyncio.CancelledError:
            pass
    _SCHED_TASK = None


@app.get("/health")
def health():
    q1("SELECT 1")
    return {"ok": True, "mode": "local-sqlite", "gateway": os.environ.get("LLM_BASE_URL")}


@app.get("/", include_in_schema=False)
def landing():
    return FileResponse(WEB / "index.html")


@app.get("/app", include_in_schema=False)
def app_shell():
    return FileResponse(WEB / "app.html")


@app.get("/app/", include_in_schema=False)
def app_slash():
    return RedirectResponse("/app")


STATIC_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*\.(js|css|svg|png|webp|ico|json|webmanifest|woff2)$")


@app.get("/static/{name}", include_in_schema=False)
def static(name: str):
    if not STATIC_RE.fullmatch(name) or ".." in name:
        raise HTTPException(404)
    p = (WEB / name).resolve()
    if p.parent != WEB.resolve() or not p.is_file():
        raise HTTPException(404)
    return FileResponse(p, headers={"cache-control": "public, max-age=3600"})


@app.get("/manifest.webmanifest", include_in_schema=False)
def manifest():
    p = WEB / "manifest.webmanifest"
    if p.is_file():
        return FileResponse(p, media_type="application/manifest+json")
    return JSONResponse({
        "name": "DentaCore Klinik İşletim Sistemi",
        "short_name": "DentaCore",
        "start_url": "/app",
        "scope": "/",
        "display": "standalone",
        "background_color": "#0A2540",
        "theme_color": "#0D9488",
        "icons": [{"src": "/static/favicon.svg", "sizes": "any", "type": "image/svg+xml"}],
    }, media_type="application/manifest+json")


@app.get("/sw.js", include_in_schema=False)
def service_worker():
    p = WEB / "sw.js"
    hdrs = {"Service-Worker-Allowed": "/", "cache-control": "no-cache"}
    if p.is_file():
        return FileResponse(p, media_type="application/javascript; charset=utf-8", headers=hdrs)
    return Response(
        "self.addEventListener('install', () => self.skipWaiting());\n"
        "self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));\n",
        media_type="application/javascript; charset=utf-8",
        headers=hdrs,
    )


@app.get("/sitemap.xml", include_in_schema=False)
def sitemap(request: Request):
    base = str(request.base_url).rstrip("/")
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f'  <url><loc>{base}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>\n'
        f'  <url><loc>{base}/app</loc><changefreq>monthly</changefreq><priority>0.8</priority></url>\n'
        '</urlset>\n'
    )
    return Response(xml, media_type="application/xml; charset=utf-8")


@app.get("/robots.txt", include_in_schema=False)
def robots(request: Request):
    base = str(request.base_url).rstrip("/")
    return PlainTextResponse(
        "User-agent: *\nAllow: /$\nDisallow: /app\nDisallow: /calendar/\nDisallow: /form/\nDisallow: /view/\n"
        f"Sitemap: {base}/sitemap.xml\n"
    )


# ---------------- Auth ----------------
class LoginIn(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)
    totp: str | None = Field(default=None, max_length=8)


@app.post("/auth/login")
async def login(body: LoginIn, request: Request, response: Response):
    email = body.email.strip().lower()
    ip = client_ip(request)
    if not await _LIMITER.hit(f"ip:{ip}", int(os.environ.get("DC_LOGIN_IP_LIMIT", "50")), 900) or not await _LIMITER.hit(f"em:{email}", int(os.environ.get("DC_LOGIN_EMAIL_LIMIT", "15")), 900):
        raise HTTPException(429, "Çok fazla deneme. Daha sonra tekrar deneyin.")
    u = q1("SELECT * FROM staff_users WHERE email=? AND active=1", email)
    now = now_utc()
    expired_lock = False
    if u and u.get("locked_until"):
        try:
            lu = datetime.fromisoformat(u["locked_until"])
            if lu.tzinfo is None:
                lu = lu.replace(tzinfo=timezone.utc)
            if lu > now:
                raise HTTPException(423, "Hesap geçici olarak kilitli. 15 dakika sonra tekrar deneyin.")
            expired_lock = True
        except ValueError:
            pass
    ok = await asyncio.to_thread(sec.verify_password, body.password, u["pw_hash"] if u else sec.dummy_hash())

    def _record_fail():
        fc = 1 if expired_lock else (int(u.get("failed_count") or 0) + 1)
        locked = (now + timedelta(minutes=15)).isoformat() if fc >= 10 else None
        ex("UPDATE staff_users SET failed_count=?, locked_until=? WHERE id=?", fc, locked, u["id"])

    if not u or not ok:
        if u:
            _record_fail()
        write_audit(u["id"] if u else None, email, "auth.fail", "", ip_hash(ip), clinic_id=int(u["clinic_id"]) if u else 1)
        raise HTTPException(401, "E-posta veya parola hatalı")
    if u["totp_enabled"]:
        if not body.totp:
            return {"need_totp": True}
        step = sec.totp_verify(dec(u["totp_secret_enc"]), body.totp, u["totp_last_step"])
        if step is None:
            _record_fail()
            write_audit(u["id"], email, "auth.totp_fail", "", ip_hash(ip), clinic_id=int(u["clinic_id"]))
            raise HTTPException(401, "Doğrulama kodu hatalı")
        ex("UPDATE staff_users SET totp_last_step=? WHERE id=?", step, u["id"])
    perms_u = resolve_permissions(u["role"], u.get("job_title"), u.get("permissions_json"))
    if not perms_u.get("view", False):
        raise HTTPException(403, "Bu personel hesabının yönetim paneli görüntüleme yetkisi bulunmamaktadır")
    raw, h = sec.new_session_token()
    csrf = sec.new_session_token()[0]
    exp = (now_utc() + timedelta(seconds=sec.ABSOLUTE_SECONDS)).isoformat()
    home_cid = int(u["clinic_id"])
    is_hq = (home_cid == 1 and u["role"] == "owner")
    ex("INSERT INTO sessions (id_hash,user_id,active_clinic_id,csrf,created_at,last_seen,expires_at,ua) VALUES (?,?,?,?,?,?,?,?)",
       h, u["id"], home_cid, csrf, iso_now(), iso_now(), exp, (request.headers.get("user-agent") or "")[:200])
    ex("UPDATE staff_users SET failed_count=0, locked_until=NULL WHERE id=?", u["id"])
    await _LIMITER.reset(f"em:{email}")
    write_audit(u["id"], email, "auth.login", f"clinic:{home_cid}", ip_hash(ip), clinic_id=home_cid)
    response.headers["set-cookie"] = sec.cookie_header(raw)
    return {"ok": True, "csrf": csrf, "user": {"id": u["id"], "clinic_id": home_cid, "email": u["email"],
                                               "full_name": u["full_name"], "role": u["role"],
                                               "job_title": u.get("job_title") or u["role"],
                                               "permissions": perms_u,
                                               "totp_enabled": bool(u["totp_enabled"]), "is_hq": is_hq}}


@app.post("/auth/logout")
def logout(response: Response, u: dict = Depends(ANY)):
    ex("UPDATE sessions SET revoked=1 WHERE id_hash=?", u["id_hash"])
    write_audit(u["id"], u["email"], "auth.logout", "", u["ip_h"], clinic_id=u["clinic_id"])
    response.headers["set-cookie"] = sec.clear_cookie_header()
    return {"ok": True}


@app.get("/auth/me")
def me(u: dict = Depends(ANY)):
    return {
        "csrf": u["csrf"],
        "user": {
            "id": u["id"],
            "clinic_id": u["clinic_id"],
            "email": u["email"],
            "full_name": u["full_name"],
            "role": u["role"],
            "job_title": u.get("job_title") or u["role"],
            "permissions": u.get("permissions") or resolve_permissions(u["role"], u.get("job_title"), u.get("permissions_json")),
            "totp_enabled": bool(u["totp_enabled"]),
            "is_hq": u["is_hq"],
        },
        "clinic": u["clinic_name"],
        "clinic_id": u["clinic_id"],
        "home_clinic_id": u["home_clinic_id"],
        "idle_seconds": sec.IDLE_SECONDS,
        "is_demo": not IS_PROD,
    }


class ReauthIn(BaseModel):
    password: str


@app.post("/auth/totp/setup")
def totp_setup(body: ReauthIn, u: dict = Depends(ANY)):
    row = q1("SELECT pw_hash FROM staff_users WHERE id=?", u["id"])
    if not sec.verify_password(body.password, row["pw_hash"]):
        raise HTTPException(400, "Parola hatalı")
    secret = sec.new_totp_secret()
    ex("UPDATE staff_users SET totp_secret_enc=?, totp_enabled=0, totp_last_step=0 WHERE id=?", enc(secret), u["id"])
    write_audit(u["id"], u["email"], "auth.totp_setup", "", u["ip_h"], clinic_id=u["clinic_id"])
    return {"secret": secret, "uri": sec.totp_uri(secret, u["email"])}


class CodeIn(BaseModel):
    code: str


@app.post("/auth/totp/enable")
def totp_enable(body: CodeIn, u: dict = Depends(ANY)):
    row = q1("SELECT totp_secret_enc, totp_last_step FROM staff_users WHERE id=?", u["id"])
    if not row or not row.get("totp_secret_enc"):
        raise HTTPException(400, "Önce kurulum başlatın")
    step = sec.totp_verify(dec(row["totp_secret_enc"]), body.code, row["totp_last_step"])
    if step is None:
        raise HTTPException(400, "Kod hatalı")
    ex("UPDATE staff_users SET totp_enabled=1, totp_last_step=? WHERE id=?", step, u["id"])
    write_audit(u["id"], u["email"], "auth.totp_enabled", "", u["ip_h"], clinic_id=u["clinic_id"])
    return {"ok": True}


class PwIn(BaseModel):
    current: str
    new: str = Field(min_length=12)


@app.post("/auth/password")
def change_password(body: PwIn, u: dict = Depends(ANY)):
    row = q1("SELECT pw_hash FROM staff_users WHERE id=?", u["id"])
    if not sec.verify_password(body.current, row["pw_hash"]):
        raise HTTPException(400, "Parola hatalı")
    ex("UPDATE staff_users SET pw_hash=? WHERE id=?", _hash_pw(body.new), u["id"])
    ex("UPDATE sessions SET revoked=1 WHERE user_id=? AND id_hash<>?", u["id"], u["id_hash"])
    write_audit(u["id"], u["email"], "auth.password_changed", "", u["ip_h"], clinic_id=u["clinic_id"])
    return {"ok": True}


@app.post("/auth/sessions/revoke-all")
def revoke_all(response: Response, u: dict = Depends(ANY)):
    ex("UPDATE sessions SET revoked=1 WHERE user_id=?", u["id"])
    write_audit(u["id"], u["email"], "auth.revoke_all", "", u["ip_h"], clinic_id=u["clinic_id"])
    response.headers["set-cookie"] = sec.clear_cookie_header()
    return {"ok": True}


# ---------------- Genel Bakış & Takvim + iOS / Android ----------------
@app.get("/app/api/overview")
def overview(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    cinfo = q1("SELECT chairs, work_minutes FROM clinics WHERE id=?", cid) or {"chairs": 2, "work_minutes": 600}
    now_loc = datetime.now(TZ)
    today_ymd = now_loc.strftime("%Y-%m-%d")
    month_start_dt = now_loc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    cutoff_30d_dt = now_loc - timedelta(days=30)
    cutoff_90d_dt = now_loc - timedelta(days=90)
    cutoff_7d_dt = now_loc - timedelta(days=7)

    appts = q("SELECT starts_at, duration_min, status FROM appointments WHERE clinic_id=?", cid)
    today_active = []
    done = 0
    noshow = 0
    for a in appts:
        a_dt = _parse_dt_tz(a["starts_at"]).astimezone(TZ)
        if a_dt.strftime("%Y-%m-%d") == today_ymd and a["status"] in ("booked", "confirmed"):
            today_active.append(a)
        if cutoff_30d_dt <= a_dt <= now_loc:
            if a["status"] == "done":
                done += 1
            elif a["status"] == "noshow":
                noshow += 1
    occ = round(100 * sum(a["duration_min"] for a in today_active) / max(1, cinfo["chairs"] * cinfo["work_minutes"]))

    chg_rows = q("SELECT amount_kurus, created_at FROM charges WHERE clinic_id=? AND voided_at IS NULL", cid)
    pay_rows = q("SELECT amount_kurus, status, method, created_at FROM payments WHERE clinic_id=? AND voided_at IS NULL", cid)
    chg_90d = [r["amount_kurus"] for r in chg_rows if _parse_dt_tz(r["created_at"]) >= cutoff_90d_dt]
    avg_ticket = int(sum(chg_90d) / len(chg_90d)) if chg_90d else 350000
    billed = sum(r["amount_kurus"] for r in chg_rows if _parse_dt_tz(r["created_at"]) >= month_start_dt)
    paid_in = sum(
        int(r["amount_kurus"] or 0)
        for r in pay_rows
        if _parse_dt_tz(r["created_at"]) >= month_start_dt
        and (r.get("status") or "completed") == "completed"
        and r.get("method") != "avans_mahsup"
    )
    paid_ref = sum(
        int(r["amount_kurus"] or 0)
        for r in pay_rows
        if _parse_dt_tz(r["created_at"]) >= month_start_dt and r.get("status") == "refunded"
    )
    paid = max(0, paid_in - paid_ref)

    msgs = q("SELECT m.layer, m.tokens_in, m.tokens_out, m.direction, m.created_at FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id WHERE COALESCE(p.clinic_id, m.clinic_id, 1)=?", cid)
    msgs_30d = [m for m in msgs if _parse_dt_tz(m["created_at"]) >= cutoff_30d_dt]
    out_m = [m for m in msgs_30d if m["direction"] == "out"]
    free = sum(1 for m in out_m if (m["layer"] or "").startswith("L1"))

    refill_rows = q("SELECT created_at FROM alerts WHERE clinic_id=? AND kind='koltuk_dolduruldu'", cid)
    refills_30d = sum(1 for r in refill_rows if _parse_dt_tz(r["created_at"]) >= cutoff_30d_dt)
    postop_rows = q("SELECT pc.answered_at, pc.due_at FROM postop_checks pc JOIN patients p ON p.id=pc.patient_id WHERE p.clinic_id=? AND pc.alarm=1", cid)
    postop_7d = sum(1 for r in postop_rows if _parse_dt_tz(r.get("answered_at") or r["due_at"]) >= cutoff_7d_dt)

    series = []
    for i in range(13, -1, -1):
        day_dt = now_loc - timedelta(days=i)
        d = day_dt.strftime("%Y-%m-%d")
        lbl = day_dt.strftime("%d.%m")
        mc = sum(1 for m in msgs if m["direction"] == "in" and _parse_dt_tz(m["created_at"]).astimezone(TZ).strftime("%Y-%m-%d") == d)
        ac = sum(1 for a in appts if _parse_dt_tz(a["starts_at"]).astimezone(TZ).strftime("%Y-%m-%d") == d)
        series.append({"day": lbl, "msgs": mc, "appts": ac})
    can_fin_view = bool((u.get("permissions") or {}).get("finance_view", False))
    res_ov = {
        "today": {"appointments": len(today_active), "confirmed": sum(1 for a in today_active if a["status"] == "confirmed"), "occupancy": occ},
        "attendance_30d": {"done": done, "noshow": noshow, "noshow_rate": round(100 * noshow / max(1, done + noshow))},
        "tokens_30d": {"replies": len(out_m), "llm_free_pct": round(100 * free / len(out_m)) if out_m else None,
                       "tokens": sum(m["tokens_in"] + m["tokens_out"] for m in out_m)},
        "counts": {
            "alerts": q1("SELECT count(*) AS n FROM alerts WHERE clinic_id=? AND acknowledged_at IS NULL", cid)["n"],
            "waitlist": q1("SELECT count(*) AS n FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE p.clinic_id=? AND w.active=1", cid)["n"],
            "refills": refills_30d,
            "low_stock": q1("SELECT count(*) AS n FROM inventory_items WHERE clinic_id=? AND active=1 AND qty <= min_qty AND min_qty > 0", cid)["n"],
            "postop_alarms": postop_7d,
        },
        "series": series,
    }
    if can_fin_view:
        res_ov["loss"] = {"noshow_30d_try": tl(noshow * avg_ticket), "avg_ticket_try": tl(avg_ticket)}
        res_ov["month"] = {"billed_try": tl(billed), "paid_try": tl(paid)}
    return res_ov


@app.get("/app/api/appointments")
def list_appts(start: datetime, end: datetime, u: dict = Depends(ANY)):
    s_dt = start if start.tzinfo else start.replace(tzinfo=TZ)
    e_dt = end if end.tzinfo else end.replace(tzinfo=TZ)
    if e_dt - s_dt > timedelta(days=62):
        raise HTTPException(400, "aralık en fazla 62 gün")
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    sql_a = """SELECT a.*, p.display_name AS patient, d.full_name AS doctor,
                      EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=a.patient_id AND x.red_flags_json <> '[]') AS red_flag
               FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
               WHERE a.clinic_id=?"""
    args_a: list = [cid]
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        sql_a += " AND (a.doctor_id=? OR p.primary_doctor_id=?)"
        args_a.extend([u["id"], u["id"]])
    sql_a += " ORDER BY a.starts_at"
    rows = q(sql_a, *args_a)
    out = []
    for r in rows:
        dt = datetime.fromisoformat(r["starts_at"])
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ)
        if s_dt <= dt < e_dt:
            r["red_flag"] = bool(r["red_flag"])
            r["google_cal_url"] = cal.google_calendar_url(r, u["clinic_name"], u["clinic_address"])
            out.append(r)
    return out


DEFAULT_WORKING_HOURS_JSON = '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}'
VALID_FDI_TEETH = {
    *{n for qd in (10, 20, 30, 40) for n in range(qd + 1, qd + 9)},
    *{n for qd in (50, 60, 70, 80) for n in range(qd + 1, qd + 6)},
}


def _parse_hhmm(val: str) -> int:
    parts = str(val or "00:00").strip().split(":")
    return int(parts[0]) * 60 + (int(parts[1]) if len(parts) > 1 else 0)


def _clinic_day_hours(dt_loc: datetime, working_hours_json: str | None = None) -> tuple[int, int] | None:
    try:
        wh = json.loads(working_hours_json or DEFAULT_WORKING_HOURS_JSON)
        if not isinstance(wh, dict):
            wh = json.loads(DEFAULT_WORKING_HOURS_JSON)
    except Exception:
        wh = json.loads(DEFAULT_WORKING_HOURS_JSON)

    wd = dt_loc.weekday()
    day_keys = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    dkey = day_keys[wd]
    if dkey in wh:
        hrs = wh[dkey]
    elif wd < 5:
        hrs = wh.get("mon_fri", ["09:00", "19:00"])
    elif wd == 5:
        hrs = wh.get("sat", ["09:00", "15:00"])
    else:
        hrs = wh.get("sun", None)

    if not hrs or not isinstance(hrs, (list, tuple)) or len(hrs) < 2 or not hrs[0] or not hrs[1]:
        return None
    return _parse_hhmm(hrs[0]), _parse_hhmm(hrs[1])


def is_within_working_hours(now_dt: datetime | None = None, working_hours_json: str | None = None) -> bool:
    dt_loc = ((now_dt or now_utc()) if (now_dt is None or now_dt.tzinfo) else now_dt.replace(tzinfo=TZ)).astimezone(TZ)
    span = _clinic_day_hours(dt_loc, working_hours_json)
    if not span:
        return False
    open_m, close_m = span
    cur_m = dt_loc.hour * 60 + dt_loc.minute
    return open_m <= cur_m < close_m


def validate_working_hours(starts: datetime, duration_min: int, working_hours_json: str | None = None):
    s_loc = (starts if starts.tzinfo else starts.replace(tzinfo=TZ)).astimezone(TZ)
    e_loc = (s_loc + timedelta(minutes=duration_min)).astimezone(TZ)
    if s_loc.date() != e_loc.date():
        raise HTTPException(422, "Randevu aynı gün içinde başlamalı ve bitmelidir")
    span = _clinic_day_hours(s_loc, working_hours_json)
    if not span:
        raise HTTPException(422, "Seçilen gün klinik kapalıdır (kapalı güne randevu oluşturulamaz)")

    open_m, close_m = span
    s_m = s_loc.hour * 60 + s_loc.minute
    e_m = e_loc.hour * 60 + e_loc.minute
    if s_m < open_m or e_m > close_m:
        hrs_lbl = f"{open_m // 60:02d}:{open_m % 60:02d}-{close_m // 60:02d}:{close_m % 60:02d}"
        raise HTTPException(422, f"Randevu saati klinik çalışma saatleri ({hrs_lbl}) dışındadır")


_OPTOUT_WORDS = {"stop", "durdur", "mesaj istemiyorum", "mesajlari durdur", "abonelikten cik", "iletisim istemiyorum"}


def _wa_require_consent() -> bool:
    v = os.environ.get("DC_WA_REQUIRE_CONSENT")
    return (v == "1") if v is not None else IS_PROD


def _wa_consent_block(pid: int | None) -> str | None:
    if not pid:
        return None
    active = _has_consent(pid, "iletisim")
    if not active and q1("SELECT 1 FROM consents WHERE patient_id=? AND kind='iletisim' AND revoked_at IS NOT NULL LIMIT 1", pid):
        return "opt_out"
    if not active and _wa_require_consent():
        return "no_consent"
    return None


async def _deliver_wa(
    clinic_id: int,
    patient_id: int | None,
    phone: str,
    text: str,
    layer: str = "L1-otomasyon",
    intent: str = "bildirim",
    tpl: str = "",
    params: list[str] | None = None,
    tokens_in: int = 0,
    tokens_out: int = 0,
    require_consent: bool = False,
) -> dict:
    err_msg: str | None = None
    raw_res: dict = {}
    # P0-5/6: Otomatik (proaktif) mesajlarda iletişim izni kontrolü. "DURDUR" diyen hastaya hiç gönderilmez;
    # DC_WA_REQUIRE_CONSENT=1 iken (üretim varsayılanı) kayıtlı iletişim izni olmayan hastaya da gönderilmez.
    block = _wa_consent_block(patient_id) if (require_consent and patient_id) else None
    if block:
        ex(
            """INSERT INTO message_log
               (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,body,delivery_status,delivery_error,created_at)
               VALUES (?,?,'out',?,?,0,0,'',?,?,?)""",
            clinic_id, patient_id, layer, intent, "skipped_consent", block, iso_now(),
        )
        return {"ok": True, "status": "skipped_consent", "dry_run": False, "error": block, "raw": {}}
    try:
        if tpl:
            raw_res = await wa.send_text_or_template(phone, text, tpl, params or [])
        else:
            raw_res = await wa.send_text(phone, text)
        if raw_res.get("dry_run"):
            status = "dry_run"
        elif raw_res.get("error"):
            status = "failed"
            err_msg = json.dumps(raw_res["error"], ensure_ascii=False)[:500]
        elif raw_res.get("skipped"):
            status = "dry_run"
            err_msg = str(raw_res["skipped"])
        else:
            status = "sent"
    except Exception as exc:
        status = "failed"
        err_msg = str(exc)[:500]
        raw_res = {"error": err_msg}

    ex(
        """INSERT INTO message_log
           (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,body,delivery_status,delivery_error,created_at)
           VALUES (?,?,'out',?,?,?,?,?,?,?,?)""",
        clinic_id, patient_id, layer, intent, tokens_in, tokens_out, enc(text[:2000]) if text else "", status, err_msg, iso_now(),
    )
    return {"ok": status != "failed", "status": status, "dry_run": status == "dry_run", "error": err_msg, "raw": raw_res}


def _parse_dt_tz(raw: str | datetime) -> datetime:
    dt = raw if isinstance(raw, datetime) else datetime.fromisoformat(str(raw))
    return dt if dt.tzinfo else dt.replace(tzinfo=TZ)


def _find_appt_conflicts(
    c: sqlite3.Connection,
    cid: int,
    starts: datetime,
    duration_min: int,
    chair: str,
    doctor_id: int | None,
    buf_min: int,
    exclude_aid: int | None = None,
):
    ends = starts + timedelta(minutes=duration_min + buf_min)
    sql = "SELECT id, starts_at, duration_min, chair, doctor_id FROM appointments WHERE clinic_id=? AND status IN ('booked','confirmed')"
    params: list = [cid]
    if exclude_aid is not None:
        sql += " AND id<>?"
        params.append(exclude_aid)
    for ex_a in c.execute(sql, tuple(params)).fetchall():
        s2 = _parse_dt_tz(ex_a["starts_at"])
        e2 = s2 + timedelta(minutes=int(ex_a["duration_min"] or 30) + buf_min)
        if s2 < ends and e2 > starts:
            if str(ex_a["chair"]) == str(chair):
                return "chair", ex_a["id"]
            if doctor_id is not None and ex_a["doctor_id"] == doctor_id:
                return "doctor", ex_a["id"]
    return None


async def _offer_waitlist_wave(appt: dict, wave: int, now_dt: datetime | None = None) -> int:
    cid = int(appt["clinic_id"])
    aid = int(appt["id"])
    t_now_dt = now_dt or now_utc()
    t_now = t_now_dt.isoformat()
    exp_at = (t_now_dt + timedelta(hours=2)).isoformat()
    treat = str(appt.get("treatment") or "").lower()
    rows = q(
        """SELECT w.id, w.patient_id, w.treatment, p.phone_enc, p.display_name
           FROM waitlist w
           JOIN patients p ON p.id = w.patient_id
           WHERE p.clinic_id=? AND w.active=1 AND COALESCE(p.active, 1)=1
             AND (? IS NULL OR w.patient_id <> ?)
             AND NOT EXISTS (SELECT 1 FROM slot_offers o WHERE o.appointment_id=? AND o.waitlist_id=w.id)
           ORDER BY w.id ASC""",
        cid, appt.get("patient_id"), appt.get("patient_id"), aid,
    )
    cands = []
    seen_pids: set[int] = set()
    for r in rows:
        pid = int(r["patient_id"])
        if pid in seen_pids:
            continue
        wt = str(r.get("treatment") or "herhangi").strip().lower()
        if wt == "herhangi" or not treat or wt in treat or treat in wt:
            seen_pids.add(pid)
            cands.append(r)
        if len(cands) >= 5:
            break
    if not cands and rows:
        for r in rows:
            pid = int(r["patient_id"])
            if pid not in seen_pids:
                seen_pids.add(pid)
                cands.append(r)
            if len(cands) >= 5:
                break

    dt_loc = _parse_dt_tz(appt["starts_at"]).astimezone(TZ)
    d_str, h_str = dt_loc.strftime("%d.%m.%Y"), dt_loc.strftime("%H:%M")
    c_row = q1("SELECT name FROM clinics WHERE id=?", cid)
    c_name = (c_row and c_row["name"]) or "Kliniğimiz"
    offers = 0
    for cand in cands:
        ex(
            "INSERT INTO slot_offers (appointment_id,waitlist_id,wave,sent_at,expires_at,status) VALUES (?,?,?,?,?,'sent')",
            aid, cand["id"], wave, t_now, exp_at,
        )
        offers += 1
        p_name = cand.get("display_name") or "Sayın Hastamız"
        msg = (
            f"Sayın {p_name}, {c_name} kliniğimizde {d_str} saat {h_str} için boş yer açıldı "
            f"(Dalga {wave}). Randevuyu almak için EVET yazabilirsiniz."
        )
        await _deliver_wa(
            cid,
            int(cand["patient_id"]),
            dec(cand["phone_enc"]),
            msg,
            layer="L1-otomasyon",
            intent="bekleme_listesi_teklif",
            require_consent=True,
            tpl=os.environ.get("WA_TPL_WAITLIST", "bekleme_listesi_teklif"),
            params=[h_str, str(appt["treatment"])],
        )
    return offers


async def _cancel_appt_and_refill(cid: int, aid: int, actor_id: int | None, actor: str, ip_h: str = "") -> int:
    with _DB_LOCK:
        c = db()
        a = c.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (aid, cid)).fetchone()
        if not a:
            raise HTTPException(404, "randevu yok")
        a_dict = dict(a)
        c.execute("UPDATE appointments SET status='cancelled' WHERE id=? AND clinic_id=?", (aid, cid))
        c.commit()
    offers = 0
    if _parse_dt_tz(a_dict["starts_at"]) > now_utc():
        offers = await _offer_waitlist_wave(a_dict, 1)
    write_audit(actor_id, actor, "appointment.cancel", f"appointment:{aid}", ip_h, {"offers": offers}, clinic_id=cid)
    return offers


async def _claim_slot_offer(cid: int, pid: int, offer_id: int | None = None) -> tuple[str, str, str] | None:
    now_dt = now_utc()
    now_iso = now_dt.isoformat()
    with _DB_LOCK:
        c = db()
        try:
            if offer_id is not None:
                off = c.execute(
                    """SELECT o.*, w.patient_id FROM slot_offers o
                       JOIN waitlist w ON w.id=o.waitlist_id
                       JOIN patients p ON p.id=w.patient_id
                       WHERE o.id=? AND w.patient_id=? AND p.clinic_id=?
                         AND o.status='sent' AND (o.expires_at IS NULL OR o.expires_at >= ?)""",
                    (offer_id, pid, cid, now_iso),
                ).fetchone()
            else:
                cutoff = (now_dt - timedelta(hours=2)).isoformat()
                off = c.execute(
                    """SELECT o.*, w.patient_id FROM slot_offers o
                       JOIN waitlist w ON w.id=o.waitlist_id
                       JOIN patients p ON p.id=w.patient_id
                       WHERE w.patient_id=? AND p.clinic_id=? AND o.status='sent'
                         AND o.sent_at >= ? AND (o.expires_at IS NULL OR o.expires_at >= ?)
                       ORDER BY o.id DESC LIMIT 1""",
                    (pid, cid, cutoff, now_iso),
                ).fetchone()
            if not off:
                return None
            cur_upd = c.execute(
                "UPDATE appointments SET status='booked', patient_id=?, reminder_sent_at=NULL, followup_sent_at=NULL WHERE id=? AND clinic_id=? AND status='cancelled'",
                (pid, off["appointment_id"], cid),
            )
            if cur_upd.rowcount == 0:
                c.execute("UPDATE slot_offers SET status='lost' WHERE id=?", (off["id"],))
                c.commit()
                return (
                    "Teşekkürler; bu saat az önce doldu. Bekleme listesindeki yeriniz korunuyor, yeni bir saat açıldığında tekrar haber vereceğiz.",
                    "L1-koltuk",
                    "bekleme_listesi",
                )
            appt = c.execute("SELECT * FROM appointments WHERE id=?", (off["appointment_id"],)).fetchone()
            c.execute("UPDATE slot_offers SET status='won' WHERE id=?", (off["id"],))
            c.execute("UPDATE slot_offers SET status='lost' WHERE appointment_id=? AND id<>? AND status='sent'", (off["appointment_id"], off["id"]))
            c.execute("UPDATE waitlist SET active=0 WHERE id=?", (off["waitlist_id"],))
            dt_loc = _parse_dt_tz(appt["starts_at"]).astimezone(TZ)
            c.execute(
                "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'koltuk_dolduruldu',?,?)",
                (cid, pid, f"İptal edilen {dt_loc:%d.%m.%Y %H:%M} ({appt['treatment']}) koltuğu bekleme listesinden dolduruldu.", iso_now()),
            )
            c.commit()
        except Exception:
            c.rollback()
            raise
    write_audit(None, f"patient:{pid}", "waitlist.claim_won", f"appointment:{off['appointment_id']}", clinic_id=cid)
    return (f"Randevunuz oluşturuldu: {dt_loc:%d.%m.%Y} saat {dt_loc:%H:%M}. Görüşmek üzere.", "L1-koltuk", "bekleme_listesi")


_CONFIRM_WORDS = {"evet", "tamam", "onayliyorum", "yes", "ok", "onay", "geliyorum", "gelecegim", "uygun"}
_CANCEL_WORDS = {"hayir", "iptal", "no", "iptal ediyorum", "iptal et", "gelemiyorum", "gelemeyecegim", "vazgectim"}


async def _handle_patient_reply(
    cid: int,
    pid: int,
    text: str,
    channel: str = "wa",
    payload: str = "",
    context_previous_turn: str | None = None,
) -> tuple[str, str, str] | None:
    raw_txt = text or ""
    cleaned = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", normalize(raw_txt))).strip()
    toks = cleaned.split()
    has_q = "?" in raw_txt

    # P0-6: "DURDUR/STOP" → iletişim izni geri alınır, otomatik mesajlar durur (tek seferlik teyit cevabı verilir).
    if not payload and cleaned in _OPTOUT_WORDS:
        t_now = iso_now()
        n = ex("UPDATE consents SET revoked_at=? WHERE patient_id=? AND kind='iletisim' AND revoked_at IS NULL", t_now, pid)
        if not q1("SELECT 1 FROM consents WHERE patient_id=? AND kind='iletisim' AND revoked_at IS NOT NULL LIMIT 1", pid):
            ex("INSERT INTO consents (patient_id,kind,text_version,text_sha256,channel,granted_at,revoked_at) VALUES (?,?,?,?,?,?,?)",
               pid, "iletisim", "opt_out_kaydi", "-", channel, t_now, t_now)
        write_audit(None, f"{channel}_patient:{pid}", "consent.opt_out", f"patient:{pid}", meta={"kind": "iletisim"}, clinic_id=cid)
        return ("Bilgilendirme mesajlarınız durduruldu. Yeniden almak isterseniz kliniğimizle iletişime geçebilirsiniz.",
                "L1-izin", "opt_out")

    # TECH-03: Tek başına 1..10 ağrı puanı asla randevu teyit/iptal sayılmaz; varsa bekleyen post-op kontrolüne yazılır.
    is_numeric_score = bool(re.fullmatch(r"\s*(10|[1-9])\s*", raw_txt)) and not payload

    is_confirm = False if is_numeric_score else bool(
        payload.startswith("RMD_OK_")
        or (not has_q and (
            cleaned in _CONFIRM_WORDS
            or (1 <= len(toks) <= 3 and any(t in {"evet", "onayliyorum", "yes", "tamam"} for t in toks)
                and not any(t in {"hayir", "iptal", "degil", "yok", "no"} for t in toks))
        ))
    )
    is_cancel = False if is_numeric_score else bool(
        payload.startswith("RMD_CHG_")
        or (not has_q and (
            cleaned in _CANCEL_WORDS
            or (1 <= len(toks) <= 3 and any(t in {"hayir", "iptal", "no", "vazgectim", "gelemiyorum", "gelemeyecegim"} for t in toks)
                and not any(t in {"evet", "onayliyorum"} for t in toks))
        ))
    )

    if payload.startswith("SLOT_"):
        try:
            oid = int(payload.split("_", 1)[1])
        except ValueError:
            oid = None
        claimed = await _claim_slot_offer(cid, pid, oid)
        if claimed:
            return claimed

    ctx_norm = normalize(context_previous_turn or "")
    prefers_appt_confirm = any(k in ctx_norm for k in ("randevu", "teyit", "hatirlat", "onay icin")) and "yer acildi" not in ctx_norm
    if not context_previous_turn and not payload and is_confirm and not prefers_appt_confirm:
        last_out = q1(
            "SELECT intent FROM message_log WHERE clinic_id=? AND patient_id=? AND direction='out' ORDER BY id DESC LIMIT 1",
            cid, pid,
        )
        if last_out and last_out.get("intent") in ("hatirlatma", "randevu_teyit", "takip"):
            prefers_appt_confirm = True

    if not payload and is_confirm and not prefers_appt_confirm:
        claimed = await _claim_slot_offer(cid, pid, None)
        if claimed:
            return claimed

    if is_confirm or is_cancel:
        target_appt = None
        if payload.startswith("RMD_"):
            try:
                aid_p = int(payload.rsplit("_", 1)[1])
                target_appt = q1("SELECT * FROM appointments WHERE id=? AND clinic_id=? AND patient_id=?", aid_p, cid, pid)
            except ValueError:
                target_appt = None
        else:
            if is_confirm:
                appts = q("SELECT * FROM appointments WHERE clinic_id=? AND patient_id=? AND status='booked'", cid, pid)
            else:
                appts = q("SELECT * FROM appointments WHERE clinic_id=? AND patient_id=? AND status IN ('booked','confirmed')", cid, pid)
            cutoff = now_utc() - timedelta(minutes=15)
            future = [a for a in appts if _parse_dt_tz(a["starts_at"]) >= cutoff]
            future.sort(key=lambda a: (
                0 if a["status"] == "booked" else 1,
                0 if a.get("reminder_sent_at") else 1,
                _parse_dt_tz(a["starts_at"]),
            ))
            target_appt = future[0] if future else None

        if target_appt:
            dt_loc = _parse_dt_tz(target_appt["starts_at"]).astimezone(TZ)
            dt_str = dt_loc.strftime("%d.%m.%Y %H:%M")
            t_now = iso_now()
            if is_confirm:
                ex("UPDATE appointments SET status='confirmed', confirmed_at=?, updated_at=?, sequence=COALESCE(sequence,0)+1 WHERE id=? AND clinic_id=?",
                   t_now, t_now, target_appt["id"], cid)
                write_audit(None, f"{channel}_patient:{pid}", "appointment.confirm_reply", f"appointment:{target_appt['id']}", clinic_id=cid)
                return (f"Teşekkürler, {dt_str} tarihli randevunuz teyit edildi.", "L1-hatirlatma", "teyit")
            ex("UPDATE appointments SET cancelled_at=?, cancel_reason='hasta_hayir_yaniti', updated_at=?, sequence=COALESCE(sequence,0)+1 WHERE id=? AND clinic_id=?",
               t_now, t_now, target_appt["id"], cid)
            await _cancel_appt_and_refill(cid, int(target_appt["id"]), None, f"{channel}_patient:{pid}")
            return (
                f"Randevunuz ({dt_str}) iptal edilerek serbest bırakıldı. Eğer farklı bir gün veya saate yeniden planlamak isterseniz uygun olduğunuz zamanı yazabilirsiniz; ekibimiz sizinle iletişime geçecektir.",
                "L1-hatirlatma",
                "iptal",
            )

    # Memnuniyet mesajı yanıtı kontrolü (Podium / Weave iki aşamalı standart: olumlu -> Google linki, olumsuz -> yönetici/sekreter alarmı)
    sat_appt = q1(
        "SELECT id, treatment FROM appointments WHERE clinic_id=? AND patient_id=? AND status='done' AND satisfaction_sent_at IS NOT NULL AND satisfaction_reply IS NULL ORDER BY id DESC LIMIT 1",
        cid, pid,
    )
    if sat_appt:
        neg_phrases = ("memnun degilim", "memnun kalmadim", "sikayet", "kotu", "berbat", "agrim var", "cok agri", "rezalet", "hic memnun", "uzgun", "pisman")
        pos_phrases = ("memnun kaldim", "cok memnun", "memnunum", "memnun", "cok iyi", "harika", "tesekkur", "super", "mukemmel", "gayet iyi", "elinize saglik")
        has_neg_phrase = any(w in cleaned for w in neg_phrases) or (cleaned in {"hayir", "no"} and not payload)
        has_pos_phrase = not has_neg_phrase and (any(w in cleaned for w in pos_phrases) or (cleaned in {"evet", "yes", "tamam"} and not payload))
        # Sayısal puan (1..10): aktif postop kontrolü yoksa memnuniyet puanı olarak değerlendirilir
        active_postop = q1(
            "SELECT id FROM postop_checks WHERE patient_id=? AND sent_at IS NOT NULL AND answered_at IS NULL ORDER BY id DESC LIMIT 1",
            pid,
        )
        num_val = int(raw_txt.strip()) if (is_numeric_score and not active_postop) else None
        is_sat_neg = has_neg_phrase or (num_val is not None and 1 <= num_val <= 4)
        is_sat_pos = has_pos_phrase or (num_val is not None and 8 <= num_val <= 10)
        if is_sat_neg or is_sat_pos:
            t_now = iso_now()
            if is_sat_neg:
                ex(
                    "UPDATE appointments SET satisfaction_reply=?, satisfaction_replied_at=?, satisfaction_status='negative' WHERE id=?",
                    raw_txt[:400], t_now, sat_appt["id"],
                )
                p_row = q1("SELECT display_name FROM patients WHERE id=?", pid)
                pname = (p_row and p_row["display_name"]) or f"Hasta #{pid}"
                ex(
                    "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'memnuniyetsiz_hasta',?,?)",
                    cid, pid, f"MEMNUNİYETSİZ HASTA UYARISI: {pname} (#{pid}) randevu sonrası olumsuz geri bildirim iletti: {raw_txt[:200]}", t_now,
                )
                ex(
                    "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'sekreter_gorev',?,?)",
                    cid, pid, f"ACİL YÖNETİCİ / SEKRETER GÖREVİ: Memnuniyetsiz hasta {pname} (#{pid}) ile hemen iletişime geçin.", t_now,
                )
                write_audit(None, f"{channel}_patient:{pid}", "appointment.satisfaction_negative", f"appointment:{sat_appt['id']}", clinic_id=cid)
                return (
                    "Yaşadığınız olumsuz deneyim için çok özür dileriz. Bildiriminiz başhekimliğimize ve klinik yöneticimize acil öncelikle iletildi; klinik yöneticimiz sizinle hemen ilgilenecektir.",
                    "L1-memnuniyet",
                    "memnuniyet_olumsuz",
                )
            cl_row = q1("SELECT name, google_review_url FROM clinics WHERE id=?", cid) or {}
            g_url = (cl_row.get("google_review_url") or "https://search.google.com/local/writereview").strip()
            ex(
                "UPDATE appointments SET satisfaction_reply=?, satisfaction_replied_at=?, satisfaction_status='positive', google_link_sent_at=? WHERE id=?",
                raw_txt[:400], t_now, t_now, sat_appt["id"],
            )
            write_audit(None, f"{channel}_patient:{pid}", "appointment.satisfaction_positive", f"appointment:{sat_appt['id']}", clinic_id=cid)
            return (
                f"Memnuniyetiniz bizi çok mutlu etti, değerli geri bildiriminiz için çok teşekkür ederiz! Deneyiminizi Google Haritalar üzerinde paylaşmanız kliniğimiz için çok değerli: {g_url}",
                "L1-memnuniyet",
                "memnuniyet_olumlu",
            )

    # Post-op yanıt kontrolü (son 12 saatte gönderilmiş cevapsız kontrol)
    postop_rows = q("SELECT * FROM postop_checks WHERE patient_id=? AND sent_at IS NOT NULL AND answered_at IS NULL ORDER BY id DESC LIMIT 3", pid)
    recent_cutoff = now_utc() - timedelta(hours=12)
    chk = next((r for r in postop_rows if _parse_dt_tz(r["sent_at"]) >= recent_cutoff), None)
    if chk:
        m = re.search(r"\b(10|[1-9])\b", raw_txt)
        emerg = _ROUTER.is_emergency(raw_txt)
        if m or emerg:
            score = int(m.group(1)) if m else None
            alarm = bool(emerg or (score is not None and score >= 8))
            t_now = iso_now()
            ex("UPDATE postop_checks SET pain_score=?, answered_at=?, alarm=? WHERE id=?", score, t_now, 1 if alarm else 0, chk["id"])
            if alarm:
                p_row = q1("SELECT display_name FROM patients WHERE id=?", pid)
                pname = (p_row and p_row["display_name"]) or f"Hasta #{pid}"
                ex(
                    "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'postop_alarm',?,?)",
                    cid, pid, f"İŞLEM SONRASI ALARM (Hekim Bildirimi): {pname} (#{pid}), {chk['procedure']} ({chk['stage']}), ağrı {score if score is not None else '?'}/10", t_now,
                )
                ex(
                    "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'sekreter_gorev',?,?)",
                    cid, pid, f"SEKRETER GÖREVİ: İşlem sonrası riskli yanıt veren {pname} (#{pid}) için acil kontrol/geri arama planlayın.", t_now,
                )
                return ("Bilginiz nöbetçi hekimimize ve klinik ekibimize iletildi, sizi en kısa sürede arayacağız. Acil durumda lütfen 112'yi arayın.", "L1-postop", "postop")
            return ("Teşekkürler, iyileşmeniz beklenen şekilde ilerliyor görünüyor. Sorunuz olursa buradan yazabilirsiniz.", "L1-postop", "postop")
    return None


async def _run_scheduler_tick(clinic_id: int | None = None, now_dt: datetime | None = None, respect_hours: bool = True) -> dict:
    async with _SCHED_LOCK:
        ref_now = (now_dt if now_dt.tzinfo else now_dt.replace(tzinfo=TZ)) if now_dt else now_utc()
        if clinic_id is not None:
            clinics = q("SELECT id, name, working_hours_json FROM clinics WHERE active=1 AND id=?", clinic_id)
        else:
            clinics = q("SELECT id, name, working_hours_json FROM clinics WHERE active=1")
        stats = {
            "ok": True,
            "at": ref_now.isoformat(),
            "skipped_outside_hours": False,
            "skipped_clinics": [],
            "reminders_sent": 0,
            "waves_advanced": 0,
            "followups_sent": 0,
            "postop_sent": 0,
        }
        for cl in clinics:
            cid = int(cl["id"])
            if respect_hours and not is_within_working_hours(ref_now, cl.get("working_hours_json")):
                stats["skipped_clinics"].append(cid)
                continue

            # 1) 24 saat öncesi randevu hatırlatma (20-28 saat penceresi, bir kez)
            w_start = ref_now + timedelta(hours=20)
            w_end = ref_now + timedelta(hours=28)
            rmd_rows = q(
                """SELECT a.id, a.patient_id, a.starts_at, a.treatment, p.phone_enc, p.display_name
                   FROM appointments a
                   JOIN patients p ON p.id = a.patient_id
                   WHERE a.clinic_id=? AND a.status='booked' AND a.reminder_sent_at IS NULL
                     AND a.patient_id IS NOT NULL AND COALESCE(p.active, 1)=1""",
                cid,
            )
            for r in rmd_rows:
                st_dt = _parse_dt_tz(r["starts_at"])
                if w_start <= st_dt <= w_end:
                    dt_loc = st_dt.astimezone(TZ)
                    d_str, h_str = dt_loc.strftime("%d.%m.%Y"), dt_loc.strftime("%H:%M")
                    p_name = r.get("display_name") or "Sayın Hastamız"
                    msg = (
                        f"Sayın {p_name}, {cl['name']} kliniğimizde {d_str} saat {h_str} için randevunuz vardır. "
                        f"Onaylamak için EVET, iptal etmek için HAYIR yazınız."
                    )
                    d_res = await _deliver_wa(
                        cid, int(r["patient_id"]), dec(r["phone_enc"]), msg,
                        layer="L1-otomasyon", intent="hatirlatma",
                        tpl=os.environ.get("WA_TPL_REMINDER", "randevu_hatirlatma"), params=[p_name, h_str], require_consent=True,
                    )
                    if d_res.get("status") != "failed":
                        ex("UPDATE appointments SET reminder_sent_at=? WHERE id=? AND reminder_sent_at IS NULL", ref_now.isoformat(), r["id"])
                        write_audit(None, "scheduler", "appointment.reminder_sent", f"appointment:{r['id']}", clinic_id=cid)
                        stats["reminders_sent"] += 1

            # 2) Bekleme listesi tekliflerinde 3 dk yanıt yoksa sonraki dalga (maks 4 dalga)
            offer_appts = q(
                """SELECT a.*, max(o.wave) AS max_wave, max(o.sent_at) AS last_sent,
                          sum(CASE WHEN o.status='won' THEN 1 ELSE 0 END) AS won_cnt,
                          sum(CASE WHEN o.status='sent' THEN 1 ELSE 0 END) AS sent_cnt
                   FROM appointments a
                   JOIN slot_offers o ON o.appointment_id = a.id
                   WHERE a.clinic_id=? AND a.status='cancelled'
                   GROUP BY a.id""",
                cid,
            )
            for oa in offer_appts:
                if int(oa.get("won_cnt") or 0) > 0 or int(oa.get("sent_cnt") or 0) == 0:
                    continue
                if _parse_dt_tz(oa["starts_at"]) <= ref_now:
                    continue
                if _parse_dt_tz(oa["last_sent"]) <= ref_now - timedelta(minutes=3):
                    ex("UPDATE slot_offers SET status='expired' WHERE appointment_id=? AND status='sent'", oa["id"])
                    cur_wave = int(oa["max_wave"] or 1)
                    if cur_wave < 4:
                        sent_n = await _offer_waitlist_wave(oa, cur_wave + 1, now_dt=ref_now)
                        if sent_n:
                            write_audit(None, "scheduler", "waitlist.wave_advanced", f"appointment:{oa['id']}", meta={"wave": cur_wave + 1, "offers": sent_n}, clinic_id=cid)
                            stats["waves_advanced"] += 1

            # 3) Cevap vermeyen hastaya takip (hatırlatmadan 4+ saat geçmiş ve hâlâ booked) + zamanı gelen post-op
            unans_rows = q(
                """SELECT a.id, a.patient_id, a.starts_at, a.treatment, a.reminder_sent_at, p.phone_enc, p.display_name
                   FROM appointments a
                   JOIN patients p ON p.id = a.patient_id
                   WHERE a.clinic_id=? AND a.status='booked'
                     AND a.reminder_sent_at IS NOT NULL AND a.followup_sent_at IS NULL
                     AND COALESCE(p.active, 1)=1""",
                cid,
            )
            for ur in unans_rows:
                st_dt = _parse_dt_tz(ur["starts_at"])
                rmd_dt = _parse_dt_tz(ur["reminder_sent_at"])
                if st_dt > ref_now + timedelta(hours=1) and rmd_dt <= ref_now - timedelta(hours=4):
                    dt_loc = st_dt.astimezone(TZ)
                    p_name = ur.get("display_name") or "Sayın Hastamız"
                    msg = (
                        f"Sayın {p_name}, {dt_loc:%d.%m.%Y %H:%M} tarihli randevunuz için henüz teyidinizi alamadık. "
                        f"Katılım durumunuzu EVET veya HAYIR yazarak paylaşabilirsiniz."
                    )
                    d_res = await _deliver_wa(cid, int(ur["patient_id"]), dec(ur["phone_enc"]), msg, layer="L1-otomasyon", intent="takip", require_consent=True)
                    if d_res.get("status") != "failed":
                        ex("UPDATE appointments SET followup_sent_at=? WHERE id=?", ref_now.isoformat(), ur["id"])
                        if st_dt <= ref_now + timedelta(hours=12):
                            ex(
                                "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'randevu_takip',?,?)",
                                cid, ur["patient_id"], f"Teyit yanıtı alınamadı: {p_name} ({dt_loc:%d.%m.%Y %H:%M})", ref_now.isoformat(),
                            )
                        write_audit(None, "scheduler", "appointment.followup_sent", f"appointment:{ur['id']}", clinic_id=cid)
                        stats["followups_sent"] += 1

            postop_due = q(
                """SELECT pc.*, p.phone_enc, p.display_name
                   FROM postop_checks pc
                   JOIN patients p ON p.id = pc.patient_id
                   WHERE p.clinic_id=? AND pc.sent_at IS NULL AND COALESCE(p.active, 1)=1""",
                cid,
            )
            for pc in postop_due:
                due_dt = _parse_dt_tz(pc["due_at"])
                if ref_now - timedelta(hours=6) <= due_dt <= ref_now:
                    p_name = pc.get("display_name") or "Sayın Hastamız"
                    msg = f"Sayın {p_name}, tedaviniz sonrası kontrol mesajımızdır. Ağrı durumunuzu 1-10 arası puanla paylaşır mısınız?"
                    d_res = await _deliver_wa(
                        cid, int(pc["patient_id"]), dec(pc["phone_enc"]), msg,
                        layer="L1-otomasyon", intent="postop_kontrol",
                        tpl=os.environ.get("WA_TPL_POSTOP", "postop_kontrol"), params=["tedaviniz"], require_consent=True,
                    )
                    if d_res.get("status") != "failed":
                        ex("UPDATE postop_checks SET sent_at=? WHERE id=?", ref_now.isoformat(), pc["id"])
                        stats["postop_sent"] += 1

        if clinic_id is not None and clinic_id in stats["skipped_clinics"]:
            stats["skipped_outside_hours"] = True
        elif clinics and len(stats["skipped_clinics"]) == len(clinics):
            stats["skipped_outside_hours"] = True
        return stats


async def _scheduler_loop():
    while True:
        try:
            await asyncio.sleep(60)
            await _run_scheduler_tick(respect_hours=True)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("zamanlayıcı hatası: %s", exc)


def _require_active_patient_row(c: sqlite3.Connection, pid: int, cid: int) -> sqlite3.Row:
    row = c.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (pid, cid)).fetchone()
    if not row:
        raise HTTPException(404, "hasta yok")
    act = row["active"] if "active" in row.keys() else 1
    if not int(act if act is not None else 1):
        raise HTTPException(409, "Arşivlenmiş hasta için yeni işlem oluşturulamaz; önce aktifleştirin")
    return row


@app.get("/app/api/appointments/available")
def available_appts(
    date: str | None = None,
    duration: int = Query(30, ge=5, le=480),
    chair: str | None = None,
    u: dict = Depends(ANY),
):
    cid = u["clinic_id"]
    if date:
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(400, "Geçersiz tarih formatı (YYYY-MM-DD olmalı)")
    else:
        target_date = datetime.now(TZ).date()

    cinfo = q1("SELECT chairs, slot_step_min, working_hours_json, buffer_min FROM clinics WHERE id=?", cid) or {
        "chairs": 2,
        "slot_step_min": 15,
        "working_hours_json": DEFAULT_WORKING_HOURS_JSON,
        "buffer_min": 0,
    }
    max_chairs = max(1, int(cinfo.get("chairs") or 2))
    step_min = max(5, int(cinfo.get("slot_step_min") or 30))
    buf_min = max(0, int(cinfo.get("buffer_min") or 0))
    if chair is not None:
        if not str(chair).isdigit() or not (1 <= int(chair) <= max_chairs):
            raise HTTPException(400, f"Geçersiz koltuk numarası (bu şubede {max_chairs} koltuk var)")
        chair_list = [str(chair)]
    else:
        chair_list = [str(i) for i in range(1, max_chairs + 1)]

    day_start_loc = datetime(target_date.year, target_date.month, target_date.day, 0, 0, tzinfo=TZ)
    span = _clinic_day_hours(day_start_loc, cinfo.get("working_hours_json"))
    if not span:
        return {"date": target_date.isoformat(), "duration": duration, "chairs": max_chairs, "closed": True, "slots": []}

    open_m, close_m = span
    active_rows = q(
        "SELECT starts_at, duration_min, chair FROM appointments WHERE clinic_id=? AND status IN ('booked','confirmed')",
        cid,
    )
    busy: list[tuple[datetime, datetime, str]] = []
    for ex_a in active_rows:
        s2 = _parse_dt_tz(ex_a["starts_at"])
        e2 = s2 + timedelta(minutes=int(ex_a["duration_min"] or 30) + buf_min)
        busy.append((s2, e2, str(ex_a["chair"])))

    min_start = now_utc() - timedelta(minutes=1)
    slots: list[dict] = []
    cur_m = open_m
    while cur_m + duration <= close_m:
        cand_s = day_start_loc + timedelta(minutes=cur_m)
        if cand_s >= min_start:
            cand_e = cand_s + timedelta(minutes=duration + buf_min)
            free_chairs = [
                ch for ch in chair_list
                if not any(s2 < cand_e and e2 > cand_s and ch2 == ch for s2, e2, ch2 in busy)
            ]
            if free_chairs:
                slots.append({
                    "starts_at": cand_s.isoformat(),
                    "time": cand_s.strftime("%H:%M"),
                    "end_time": (cand_s + timedelta(minutes=duration)).strftime("%H:%M"),
                    "available_chairs": free_chairs,
                })
        cur_m += step_min

    return {
        "date": target_date.isoformat(),
        "duration": duration,
        "chairs": max_chairs,
        "closed": False,
        "working_hours": [f"{open_m // 60:02d}:{open_m % 60:02d}", f"{close_m // 60:02d}:{close_m % 60:02d}"],
        "slots": slots,
    }


class ApptCreate(BaseModel):
    patient_id: int | None = None
    phone: str | None = None
    name: str | None = None
    starts_at: datetime
    duration_min: int = Field(30, ge=5, le=480)
    treatment: str = Field(min_length=2, max_length=80)
    chair: str = "1"
    doctor_id: int | None = None


@app.post("/app/api/appointments")
async def create_appt(b: ApptCreate, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    starts = b.starts_at if b.starts_at.tzinfo else b.starts_at.replace(tzinfo=TZ)
    cinfo = q1("SELECT name, chairs, working_hours_json, buffer_min FROM clinics WHERE id=?", cid) or {
        "name": u.get("clinic_name") or "Kliniğimiz",
        "chairs": 2,
        "working_hours_json": DEFAULT_WORKING_HOURS_JSON,
        "buffer_min": 0,
    }
    max_chairs = int(cinfo.get("chairs") or 2)
    if not str(b.chair).isdigit() or not (1 <= int(b.chair) <= max_chairs):
        raise HTTPException(400, f"Geçersiz koltuk numarası (bu şubede {max_chairs} koltuk var)")
    if starts < now_utc() - timedelta(minutes=5):
        raise HTTPException(400, "Geçmiş tarihe randevu oluşturulamaz")
    validate_working_hours(starts, b.duration_min, cinfo.get("working_hours_json"))

    with _DB_LOCK:
        c = db()
        try:
            if b.doctor_id is not None:
                if not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.doctor_id, cid)).fetchone():
                    raise HTTPException(404, "hekim yok")
            pid = b.patient_id
            new_patient_data: tuple[str, str, str | None] | None = None
            if pid is not None:
                _enforce_doc_own_patient(cid, pid, u)
                p_row = _require_active_patient_row(c, pid, cid)
                p_phone_enc = p_row["phone_enc"]
                p_name = p_row["display_name"]
            else:
                if not b.phone or len(norm_phone(b.phone)) < 10:
                    raise HTTPException(400, "Hasta seçin veya geçerli telefon girin")
                ph = phone_hmac(b.phone)
                row = c.execute("SELECT id, active, phone_enc, display_name FROM patients WHERE clinic_id=? AND phone_hmac=?", (cid, ph)).fetchone()
                if row:
                    if not int(row["active"] if row["active"] is not None else 1):
                        raise HTTPException(409, "Arşivlenmiş hasta için yeni işlem oluşturulamaz; önce aktifleştirin")
                    pid = row["id"]
                    _enforce_doc_own_patient(cid, pid, u)
                    p_phone_enc = row["phone_enc"]
                    p_name = row["display_name"]
                else:
                    p_phone_enc = enc(norm_phone(b.phone))
                    p_name = b.name
                    new_patient_data = (ph, p_phone_enc, b.name)
            buf_min = max(0, int(cinfo.get("buffer_min") or 0))
            conflict = _find_appt_conflicts(c, cid, starts, b.duration_min, str(b.chair), b.doctor_id, buf_min)
            if conflict:
                kind, ex_id = conflict
                if kind == "chair":
                    raise HTTPException(409, f"Koltuk {b.chair} bu saatte dolu (randevu #{ex_id})")
                raise HTTPException(409, f"Seçilen hekim bu saatte başka koltukta dolu (randevu #{ex_id})")
            if new_patient_data is not None:
                ph, p_phone_enc, new_name = new_patient_data
                cur_p = c.execute(
                    "INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,active,created_at) VALUES (?,?,?,?,?,?,1,?)",
                    (cid, ph, p_phone_enc, new_name, "tr", "wa", iso_now()),
                )
                pid = cur_p.lastrowid
            cur_a = c.execute(
                "INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,source,created_at) VALUES (?,?,?,?,?,?,?,'panel',?)",
                (cid, pid, starts.isoformat(), b.duration_min, b.treatment, b.chair, b.doctor_id, iso_now()),
            )
            aid = cur_a.lastrowid
            c.commit()
        except Exception:
            c.rollback()
            raise

    dt_loc = starts.astimezone(TZ)
    d_str, h_str = dt_loc.strftime("%d.%m.%Y"), dt_loc.strftime("%H:%M")
    msg_text = (
        f"Sayın {p_name or 'Hastamız'}, {cinfo.get('name') or 'kliniğimiz'} bünyesinde "
        f"{d_str} saat {h_str} için randevunuz oluşturulmuştur. Onaylamak için EVET yazabilirsiniz."
    )
    delivery = await _deliver_wa(
        cid,
        pid,
        dec(p_phone_enc),
        msg_text,
        layer="L1-otomasyon",
        intent="randevu_teyit",
        require_consent=True,
        tpl=os.environ.get("WA_TPL_REMINDER", "randevu_hatirlatma"),
        params=[d_str, h_str],
    )
    write_audit(u["id"], u["email"], "appointment.create", f"appointment:{aid}", u["ip_h"], {"chair": b.chair, "msg_status": delivery["status"]}, clinic_id=cid)
    return {"id": aid, "patient_id": pid, "delivery": delivery}


class ApptUpdate(BaseModel):
    starts_at: datetime | None = None
    duration_min: int | None = Field(default=None, ge=5, le=480)
    treatment: str | None = Field(default=None, min_length=2, max_length=80)
    chair: str | None = None
    doctor_id: int | None = None
    status: Literal["booked", "confirmed", "done", "noshow", "cancelled"] | None = None


@app.patch("/app/api/appointments/{aid}")
def update_appt(aid: int, b: ApptUpdate, u: dict = Depends(require_perm("edit"))):
    cid = u["clinic_id"]
    if b.status == "cancelled" and not (u.get("permissions") or {}).get("delete_cancel", False):
        raise HTTPException(403, "Randevu iptal etme (delete_cancel) yetkiniz bulunmamaktadır")
    with _DB_LOCK:
        c = db()
        cur_row = c.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (aid, cid)).fetchone()
        if not cur_row:
            raise HTTPException(404, "randevu yok")
        if cur_row["patient_id"]:
            _enforce_doc_own_patient(cid, int(cur_row["patient_id"]), u)
        if cur_row["status"] == "cancelled" and b.status not in ("booked", "confirmed"):
            raise HTTPException(409, "İptal edilmiş randevu düzenlenemez")
        cinfo = c.execute("SELECT chairs, working_hours_json, buffer_min FROM clinics WHERE id=?", (cid,)).fetchone()
        max_chairs = int((cinfo and cinfo["chairs"]) or 2)
        chair = str(b.chair if b.chair is not None else cur_row["chair"])
        if not chair.isdigit() or not (1 <= int(chair) <= max_chairs):
            raise HTTPException(400, "Geçersiz koltuk numarası")
        doc_id = b.doctor_id if b.doctor_id is not None else cur_row["doctor_id"]
        if doc_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (doc_id, cid)).fetchone():
            raise HTTPException(404, "hekim yok")
        starts = _parse_dt_tz(b.starts_at if b.starts_at else cur_row["starts_at"])
        if b.starts_at is not None and starts < now_utc() - timedelta(minutes=5):
            raise HTTPException(400, "Geçmiş tarihe randevu taşınamaz")
        dur = b.duration_min if b.duration_min is not None else cur_row["duration_min"]
        if b.starts_at is not None or b.duration_min is not None:
            validate_working_hours(starts, dur, (cinfo and cinfo["working_hours_json"]) or DEFAULT_WORKING_HOURS_JSON)
        treat = b.treatment if b.treatment is not None else cur_row["treatment"]
        new_st = b.status if b.status is not None else cur_row["status"]
        buf_min = max(0, int((cinfo and cinfo["buffer_min"]) or 0))
        if new_st in ("booked", "confirmed"):
            conflict = _find_appt_conflicts(c, cid, starts, dur, chair, doc_id, buf_min, exclude_aid=aid)
            if conflict:
                kind, _ = conflict
                if kind == "chair":
                    raise HTTPException(409, f"Koltuk {chair} bu saatte dolu")
                raise HTTPException(409, "Seçilen hekim bu saatte dolu")
        t_now = iso_now()
        c.execute(
            "UPDATE appointments SET starts_at=?, duration_min=?, treatment=?, chair=?, doctor_id=?, status=?, updated_at=?, sequence=COALESCE(sequence,0)+1 WHERE id=? AND clinic_id=?",
            (starts.isoformat(), dur, treat, chair, doc_id, new_st, t_now, aid, cid),
        )
        c.commit()
    write_audit(u["id"], u["email"], "appointment.update", f"appointment:{aid}", u["ip_h"], {"chair": chair, "status": new_st}, clinic_id=cid)
    return {"ok": True, "id": aid, "status": new_st}


class StatusIn(BaseModel):
    status: Literal["booked", "confirmed", "done", "noshow", "cancelled"]


@app.post("/app/api/appointments/{aid}/status")
async def appt_status(aid: int, b: StatusIn, request: Request, u: dict = Depends(require_perm("edit"))):
    cid = u["clinic_id"]
    if b.status == "cancelled" and not (u.get("permissions") or {}).get("delete_cancel", False):
        raise HTTPException(403, "Randevu iptal etme (delete_cancel) yetkiniz bulunmamaktadır")
    t_now = iso_now()
    with _DB_LOCK:
        c = db()
        a = c.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (aid, cid)).fetchone()
        if not a:
            raise HTTPException(404, "randevu yok")
        if a["patient_id"]:
            _enforce_doc_own_patient(cid, int(a["patient_id"]), u)
        prev_status = a["status"]
        if b.status in ("booked", "confirmed") and prev_status not in ("booked", "confirmed"):
            cinfo = c.execute("SELECT buffer_min FROM clinics WHERE id=?", (cid,)).fetchone()
            buf_min = max(0, int((cinfo and cinfo["buffer_min"]) or 0))
            conflict = _find_appt_conflicts(
                c, cid, _parse_dt_tz(a["starts_at"]), int(a["duration_min"] or 30),
                str(a["chair"]), a["doctor_id"], buf_min, exclude_aid=aid,
            )
            if conflict:
                kind, ex_id = conflict
                if kind == "chair":
                    raise HTTPException(409, f"Koltuk {a['chair']} bu saatte artık dolu (randevu #{ex_id}); randevu geri alınamıyor")
                raise HTTPException(409, f"Seçilen hekim bu saatte artık başka koltukta dolu (randevu #{ex_id}); randevu geri alınamıyor")
            c.execute("UPDATE slot_offers SET status='expired' WHERE appointment_id=? AND status='sent'", (aid,))
        a_dict = dict(a)
        if b.status == "confirmed":
            c.execute("UPDATE appointments SET status=?, confirmed_at=COALESCE(confirmed_at,?), updated_at=?, sequence=COALESCE(sequence,0)+1 WHERE id=? AND clinic_id=?", (b.status, t_now, t_now, aid, cid))
        elif b.status == "cancelled":
            c.execute("UPDATE appointments SET status=?, cancelled_at=?, updated_at=?, sequence=COALESCE(sequence,0)+1 WHERE id=? AND clinic_id=?", (b.status, t_now, t_now, aid, cid))
        else:
            c.execute("UPDATE appointments SET status=?, updated_at=?, sequence=COALESCE(sequence,0)+1 WHERE id=? AND clinic_id=?", (b.status, t_now, aid, cid))
        c.commit()

    if b.status == "cancelled":
        offers = 0
        if _parse_dt_tz(a_dict["starts_at"]) > now_utc():
            offers = await _offer_waitlist_wave(a_dict, 1)
        write_audit(u["id"], u["email"], "appointment.cancel", f"appointment:{aid}", u["ip_h"], {"offers": offers, "from": prev_status}, clinic_id=cid)
        return {"ok": True, "waitlist_offers": offers}

    if b.status == "done" and a_dict.get("patient_id") and not a_dict.get("satisfaction_sent_at"):
        p_row = q1("SELECT phone_enc, display_name FROM patients WHERE id=? AND clinic_id=?", a_dict["patient_id"], cid)
        if p_row:
            fb_link = f"{public_base(request)}{sign_path('/form/geri-bildirim', 7 * 86400)}"
            p_name = p_row.get("display_name") or "Sayın Hastamız"
            treat = a_dict.get("treatment") or "tedavi"
            sat_msg = (
                f"Merhaba {p_name}, bugün kliniğimizi ziyaret ettiğiniz için teşekkür ederiz. "
                f"Aldığınız {treat} hizmetimizden memnun kaldınız mı? "
                f"Yanıt olarak 'Memnun kaldım' veya 'Şikayetim var' yazabilir ya da 1-10 arası puan verebilirsiniz. "
                f"(Kliniğimize doğrudan özel geri bildirim iletmek için: {fb_link})"
            )
            await _deliver_wa(cid, int(a_dict["patient_id"]), dec(p_row["phone_enc"]), sat_msg, layer="L1-memnuniyet", intent="memnuniyet_sorusu", require_consent=True)
            ex("UPDATE appointments SET satisfaction_sent_at=?, satisfaction_status='asked' WHERE id=?", t_now, aid)

    audit_action = "appointment.undo_cancel" if (prev_status == "cancelled" and b.status == "booked") else f"appointment.{b.status}"
    write_audit(u["id"], u["email"], audit_action, f"appointment:{aid}", u["ip_h"], {"from": prev_status, "to": b.status}, clinic_id=cid)
    return {"ok": True, "status": b.status}


@app.post("/app/api/appointments/{aid}/done")
async def appt_mark_done_alias(aid: int, request: Request, u: dict = Depends(require_perm("edit"))):
    return await appt_status(aid, StatusIn(status="done"), request, u)


@app.get("/app/api/appointments/{aid}/ics")
def appt_ics(aid: int, u: dict = Depends(ANY)):
    r = q1(
        """SELECT a.*, p.display_name AS patient, d.full_name AS doctor
           FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
           WHERE a.id=? AND a.clinic_id=?""",
        aid, u["clinic_id"],
    )
    if not r:
        raise HTTPException(404, "randevu yok")
    if r.get("patient_id"):
        _enforce_doc_own_patient(u["clinic_id"], int(r["patient_id"]), u)
    return PlainTextResponse(cal.appointment_ics(r, u["clinic_name"], u["clinic_address"]),
                             media_type="text/calendar; charset=utf-8",
                             headers={"content-disposition": f'attachment; filename="randevu-{aid}.ics"'})


def _build_calendar_links(request: Request, cid: int, version: int) -> dict:
    tok = cal.calendar_feed_token(cid, version=version)
    base = str(request.base_url).rstrip("/")
    ics_url = f"{base}/calendar/{tok}.ics"
    webcal_url = "webcal://" + ics_url.split("://", 1)[-1]
    google_subscribe_url = "https://calendar.google.com/calendar/r?cid=" + quote(webcal_url, safe="")
    google_oauth_ok = bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))
    return {
        "ics_url": ics_url,
        "webcal_url": webcal_url,
        "google_subscribe_url": google_subscribe_url,
        "token_version": version,
        "expires_days": 90,
        "sync_mode": "one_way_ics",
        "google_oauth_configured": google_oauth_ok,
        "ios_limitations_tr": (
            "Apple/iOS ve Android ICS (webcal://) abonelikleri RFC 5545 standardı gereği tek yönlüdür (salt-okunur). "
            "Panelde yapılan randevu oluşturma, saat değişikliği ve iptaller SEQUENCE sayacı ve sabit UID ile beslemeye anında yansır; "
            "ancak telefon takvim uygulamasının yeni veriyi çekme sıklığı cihazın abonelik yenileme aralığına (iOS'ta genelde 15 dk - birkaç saat) bağlıdır."
        ),
        "iphone_guide": "Ayarlar > Takvim > Hesaplar > Hesap Ekle > Diğer > Abone Olunan Takvim Ekle kısmına webcal adresini yapıştırın.",
        "android_guide": "Her randevudaki '+ Android' butonuna basarak Google Takvime ekleyin veya Google Takvim webde URL ile abone olun.",
    }


@app.get("/app/api/calendar-links")
def calendar_links(request: Request, u: dict = Depends(ANY)):
    c = q1("SELECT coalesce(cal_token_version, 1) AS ver FROM clinics WHERE id=?", u["clinic_id"])
    ver = int(c["ver"]) if c else 1
    return _build_calendar_links(request, u["clinic_id"], ver)


@app.post("/app/api/calendar-links/rotate")
def calendar_links_rotate(request: Request, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    ex("UPDATE clinics SET cal_token_version = coalesce(cal_token_version, 1) + 1 WHERE id=?", cid)
    c = q1("SELECT coalesce(cal_token_version, 1) AS ver FROM clinics WHERE id=?", cid)
    ver = int(c["ver"]) if c else 2
    write_audit(u["id"], u["email"], "calendar.token_rotate", f"clinic:{cid}", u["ip_h"], {"version": ver}, clinic_id=cid)
    return _build_calendar_links(request, cid, ver)


@app.get("/app/api/calendar/all.ics")
def calendar_all_ics(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    sql_ics = """SELECT a.*, p.display_name AS patient, d.full_name AS doctor
                 FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
                 WHERE a.clinic_id=? AND a.status IN ('booked','confirmed')"""
    args_ics: list = [cid]
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        sql_ics += " AND (a.doctor_id=? OR p.primary_doctor_id=?)"
        args_ics.extend([u["id"], u["id"]])
    sql_ics += " ORDER BY a.starts_at LIMIT 500"
    rows = q(sql_ics, *args_ics)
    return PlainTextResponse(
        cal.feed_ics(rows, u["clinic_name"], u["clinic_address"]),
        media_type="text/calendar; charset=utf-8",
        headers={"content-disposition": f'attachment; filename="dentacore-klinik-{cid}-takvim.ics"'},
    )


@app.get("/calendar/{token}.ics")
def calendar_feed(token: str):
    parsed = cal.verify_feed_token_parts(token)
    if not parsed:
        raise HTTPException(403, "geçersiz veya süresi dolmuş takvim bağlantısı")
    cid, ver = parsed
    c = q1("SELECT name, address, coalesce(cal_token_version, 1) AS ver FROM clinics WHERE id=? AND active=1", cid)
    if not c or int(c["ver"]) != ver:
        raise HTTPException(403, "takvim bağlantısı iptal edilmiş veya geçersiz")
    rows = q(
        """SELECT a.*, p.display_name AS patient, d.full_name AS doctor
           FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
           WHERE a.clinic_id=? AND a.starts_at >= ? ORDER BY a.starts_at LIMIT 2000""",
        cid, (now_utc() - timedelta(days=30)).isoformat(),
    )
    return PlainTextResponse(cal.feed_ics(rows, c["name"], c["address"]), media_type="text/calendar; charset=utf-8")


# ---------------- Hastalar, Odontogram, Bekleme Listesi, Uyarılar, Envanter, Kasa ----------------
@app.get("/app/api/patients")
def list_patients(
    search: str = "",
    include_archived: bool = False,
    group_id: int | None = None,
    source: str | None = None,
    primary_doctor_id: int | None = None,
    u: dict = Depends(require_perm("patient_view")),
):
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    sql_base = """
        SELECT p.*,
               d.full_name AS primary_doctor_name,
               ba.bank_name AS bank_agreement_name,
               ba.discount_pct AS bank_discount_pct,
               COALESCE((SELECT sum(t.amount_kurus) FROM tooth_records t WHERE t.patient_id=p.id AND t.clinic_id=p.clinic_id AND t.status IN ('planned','caries','extraction')), 0) AS planned_k,
               COALESCE((SELECT sum(c.amount_kurus) FROM charges c WHERE c.patient_id=p.id AND c.voided_at IS NULL), 0) AS billed_k,
               COALESCE((SELECT sum(y.amount_kurus) FROM payments y WHERE y.patient_id=p.id AND y.voided_at IS NULL AND COALESCE(y.status,'completed')='completed' AND y.method<>'avans_mahsup'), 0) AS paid_k,
               COALESCE((SELECT sum(y2.amount_kurus) FROM payments y2 WHERE y2.patient_id=p.id AND y2.voided_at IS NULL AND y2.status='refunded'), 0) AS refunded_k,
               EXISTS (SELECT 1 FROM anamnesis a WHERE a.patient_id=p.id AND a.red_flags_json <> '[]') AS rf,
               (SELECT max(ap.starts_at) FROM appointments ap WHERE ap.patient_id=p.id) AS last_appt
        FROM patients p
        LEFT JOIN staff_users d ON d.id=p.primary_doctor_id
        LEFT JOIN bank_agreements ba ON ba.id=p.bank_agreement_id
        WHERE p.clinic_id=?
    """
    params: list = [cid]
    if not include_archived:
        sql_base += " AND p.active=1"
    if perms.get("doctor_own_patients_only") and u["role"] != "owner":
        sql_base += """ AND (p.primary_doctor_id=? OR EXISTS (SELECT 1 FROM appointments ap WHERE ap.patient_id=p.id AND ap.doctor_id=?)
                        OR EXISTS (SELECT 1 FROM tooth_records tr WHERE tr.patient_id=p.id AND tr.doctor_id=?))"""
        params.extend([u["id"], u["id"], u["id"]])
    if group_id is not None:
        sql_base += " AND EXISTS (SELECT 1 FROM patient_group_members pgm WHERE pgm.patient_id=p.id AND pgm.clinic_id=p.clinic_id AND pgm.group_id=?)"
        params.append(group_id)
    if source:
        norm_s = normalize_source(source)
        sql_base += " AND (p.first_source=? OR p.last_source=?)"
        params.extend([norm_s, norm_s])
    if primary_doctor_id is not None:
        sql_base += " AND p.primary_doctor_id=?"
        params.append(primary_doctor_id)
    sql_base += " ORDER BY p.id DESC"
    rows = q(sql_base, *params)

    grp_rows = q(
        """SELECT m.patient_id, g.id AS group_id, g.name, g.color, g.is_restricted, m.reason
           FROM patient_group_members m JOIN patient_groups g ON g.id=m.group_id
           WHERE m.clinic_id=? ORDER BY g.name""",
        cid,
    )
    groups_by_pid: dict[int, list[dict]] = {}
    for gr in grp_rows:
        groups_by_pid.setdefault(int(gr["patient_id"]), []).append({
            "id": gr["group_id"],
            "name": gr["name"],
            "color": gr["color"],
            "is_restricted": bool(gr["is_restricted"]),
            "reason": gr["reason"],
        })

    s = search.strip().lower()
    s_hmac = phone_hmac(s) if s else ""
    can_fin_view = bool(perms.get("finance_view", False))
    out = []
    for p in rows:
        if s and s not in (p["display_name"] or "").lower() and s_hmac != p["phone_hmac"]:
            continue
        billed_k = int(p["billed_k"] or 0)
        net_paid_k = max(0, int(p["paid_k"] or 0) - int(p["refunded_k"] or 0))
        rem_debt_k = max(0, billed_k - net_paid_k)
        fs = p.get("first_source") or ("instagram" if p.get("channel") == "ig" else "whatsapp")
        ls = p.get("last_source") or fs
        out.append({
            "id": p["id"],
            "display_name": p["display_name"],
            "lang": p["lang"],
            "channel": p["channel"],
            "active": bool(p.get("active", 1)),
            "first_source": fs,
            "first_source_label": PATIENT_SOURCE_LABELS.get(fs, fs),
            "last_source": ls,
            "last_source_label": PATIENT_SOURCE_LABELS.get(ls, ls),
            "primary_doctor_id": p.get("primary_doctor_id"),
            "primary_doctor_name": p.get("primary_doctor_name"),
            "bank_agreement_id": p.get("bank_agreement_id"),
            "bank_agreement_name": p.get("bank_agreement_name"),
            "groups": groups_by_pid.get(int(p["id"]), []),
            "planned_total": tl(int(p.get("planned_k") or 0)) if can_fin_view else 0.0,
            "completed_net_debt": tl(billed_k) if can_fin_view else 0.0,
            "collected_paid": tl(net_paid_k) if can_fin_view else 0.0,
            "net_remaining_debt": tl(rem_debt_k) if can_fin_view else 0.0,
            "balance": tl(billed_k - net_paid_k) if can_fin_view else 0.0,
            "red_flag": bool(p["rf"]),
            "last_appt": p["last_appt"],
            "created_at": p.get("created_at"),
        })
    return out


class PatientIn(BaseModel):
    phone: str = Field(max_length=30)
    name: str = Field(min_length=2, max_length=80)
    lang: Literal["tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he"] = "tr"
    source: str | None = Field(default=None, max_length=40)
    first_source: str | None = Field(default=None, max_length=40)
    campaign_id: int | None = None
    utm_source: str = Field("", max_length=80)
    utm_medium: str = Field("", max_length=80)
    utm_campaign: str = Field("", max_length=120)
    click_id: str = Field("", max_length=120)
    primary_doctor_id: int | None = None
    bank_agreement_id: int | None = None
    group_id: int | None = None
    group_reason: str = Field("", max_length=240)
    notes: str = Field("", max_length=1000)
    birth_date: str = Field("", max_length=20)


@app.post("/app/api/patients")
def create_patient(b: PatientIn, u: dict = Depends(require_perm("patient_edit", "create"))):
    norm_p = norm_phone(b.phone)
    if len(norm_p) < 10:
        raise HTTPException(400, "Geçerli telefon girin")
    cid = u["clinic_id"]
    ph = phone_hmac(norm_p)
    pe = enc(norm_p)
    t_now = iso_now()
    detected_src = detect_acquisition_source(
        explicit_source=b.first_source or b.source,
        utm_source=b.utm_source,
        utm_medium=b.utm_medium,
        click_id=b.click_id,
        default_source="phone",
    )
    ch_val = "ig" if detected_src in ("instagram", "meta_ads") else ("web" if detected_src in ("website", "google_ads", "google_organic", "qr_form") else "wa")
    with _DB_LOCK:
        c = db()
        if b.primary_doctor_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.primary_doctor_id, cid)).fetchone():
            raise HTTPException(404, "Seçilen sorumlu doktor bulunamadı")
        if b.bank_agreement_id is not None and not c.execute("SELECT id FROM bank_agreements WHERE id=? AND clinic_id=? AND active=1", (b.bank_agreement_id, cid)).fetchone():
            raise HTTPException(404, "Seçilen banka anlaşması bulunamadı")
        ex_p = c.execute("SELECT id, display_name, first_source, last_source FROM patients WHERE clinic_id=? AND phone_hmac=?", _clean_sql_args((cid, ph))).fetchone()
        if ex_p:
            # İlk geliş kaynağı (first_source) ASLA otomatik değişmez; yalnızca son temas kaynağı (last_source) güncellenir.
            if b.source or b.first_source or b.utm_source or b.click_id:
                c.execute(
                    "UPDATE patients SET last_source=?, campaign_id=COALESCE(?, campaign_id) WHERE id=? AND clinic_id=?",
                    _clean_sql_args((detected_src, b.campaign_id, ex_p["id"], cid)),
                )
                c.commit()
            return {
                "id": ex_p["id"],
                "duplicate": True,
                "existing_name": ex_p["display_name"],
                "first_source": ex_p["first_source"],
                "last_source": detected_src if (b.source or b.first_source or b.utm_source or b.click_id) else ex_p["last_source"],
            }
        camp_id = b.campaign_id
        if camp_id is None and b.utm_campaign:
            cp_row = c.execute("SELECT id FROM campaigns WHERE clinic_id=? AND (code=? OR utm_campaign=? OR name=?) LIMIT 1", (cid, b.utm_campaign, b.utm_campaign, b.utm_campaign)).fetchone()
            if cp_row:
                camp_id = int(cp_row["id"])
        try:
            cur = c.execute(
                """INSERT INTO patients
                   (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,first_source,last_source,campaign_id,
                    utm_source,utm_medium,utm_campaign,click_id,primary_doctor_id,bank_agreement_id,created_by,notes,birth_date,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                _clean_sql_args((
                    cid, ph, pe, b.name.strip(), b.lang, ch_val, detected_src, detected_src, camp_id,
                    b.utm_source.strip(), b.utm_medium.strip(), b.utm_campaign.strip(), b.click_id.strip(),
                    b.primary_doctor_id, b.bank_agreement_id, u["id"], b.notes.strip(), b.birth_date.strip(), t_now,
                )),
            )
            pid = cur.lastrowid
            if b.group_id is not None:
                grp = c.execute("SELECT id, name, is_restricted FROM patient_groups WHERE id=? AND clinic_id=?", (b.group_id, cid)).fetchone()
                if grp:
                    if grp["is_restricted"] and len(b.group_reason.strip()) < 3:
                        c.rollback()
                        raise HTTPException(400, f"'{grp['name']}' grubu için kısa ve nesnel bir açıklama (reason) zorunludur")
                    ok_eth, err_eth = validate_ethical_group_tag(grp["name"], b.group_reason)
                    if not ok_eth:
                        c.rollback()
                        raise HTTPException(400, err_eth)
                    c.execute(
                        "INSERT OR IGNORE INTO patient_group_members (clinic_id,patient_id,group_id,reason,added_by,added_by_name,added_at) VALUES (?,?,?,?,?,?,?)",
                        (cid, pid, b.group_id, b.group_reason.strip(), u["id"], u.get("name") or u["email"], t_now),
                    )
            if camp_id is not None:
                c.execute(
                    """INSERT INTO campaign_events
                       (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,click_id,patient_id,created_at)
                       VALUES (?,?,'patient_created',?,?,?,?,?,?,?)""",
                    (cid, camp_id, detected_src, b.utm_source, b.utm_medium, b.utm_campaign, b.click_id, pid, t_now),
                )
                c.execute("UPDATE campaigns SET conversations = conversations + 1 WHERE id=? AND clinic_id=?", (camp_id, cid))
            c.commit()
        except sqlite3.IntegrityError:
            ex_p2 = c.execute("SELECT id, display_name, first_source, last_source FROM patients WHERE clinic_id=? AND phone_hmac=?", _clean_sql_args((cid, ph))).fetchone()
            if ex_p2:
                return {"id": ex_p2["id"], "duplicate": True, "existing_name": ex_p2["display_name"], "first_source": ex_p2["first_source"], "last_source": ex_p2["last_source"]}
            raise HTTPException(409, "Bu telefon numarası zaten kayıtlı")
    write_audit(u["id"], u["email"], "patient.create", f"patient:{pid}", u["ip_h"],
                {"first_source": detected_src, "primary_doctor_id": b.primary_doctor_id, "campaign_id": camp_id}, clinic_id=cid)
    return {"id": pid, "duplicate": False, "first_source": detected_src, "last_source": detected_src, "primary_doctor_id": b.primary_doctor_id}


class PatientUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    phone: str | None = Field(default=None, max_length=30)
    lang: Literal["tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he"] | None = None
    source: str | None = Field(default=None, max_length=40)
    last_source: str | None = Field(default=None, max_length=40)
    first_source: str | None = Field(default=None, max_length=40)
    manual_first_source_change: bool = False
    first_source_reason: str = Field("", max_length=240)
    source_change_reason: str = Field("", max_length=240)
    campaign_id: int | None = None
    primary_doctor_id: int | None = None
    clear_primary_doctor: bool = False
    bank_agreement_id: int | None = None
    clear_bank_agreement: bool = False
    notes: str | None = Field(default=None, max_length=1000)
    birth_date: str | None = Field(default=None, max_length=20)


@app.patch("/app/api/patients/{pid}")
def update_patient(pid: int, b: PatientUpdateIn, u: dict = Depends(require_perm("patient_edit", "edit"))):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    t_now = iso_now()
    first_source_audit: dict | None = None
    with _DB_LOCK:
        c = db()
        p = c.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (pid, cid)).fetchone()
        if not p:
            raise HTTPException(404, "hasta yok")
        new_name = b.name.strip() if b.name is not None else p["display_name"]
        new_lang = b.lang if b.lang is not None else p["lang"]
        if b.phone is not None:
            if len(norm_phone(b.phone)) < 10:
                raise HTTPException(400, "Geçerli telefon girin")
            ph = phone_hmac(b.phone)
            pe = enc(norm_phone(b.phone))
            dup = c.execute("SELECT id FROM patients WHERE clinic_id=? AND phone_hmac=? AND id<>?", (cid, ph, pid)).fetchone()
            if dup:
                raise HTTPException(409, "Bu telefon numarası kliniğinizde başka bir hastaya kayıtlı")
        else:
            ph = p["phone_hmac"]
            pe = p["phone_enc"]

        old_fs = p["first_source"] or "whatsapp"
        new_fs = old_fs
        new_ls = normalize_source(b.last_source or b.source) if (b.last_source or b.source) else (p["last_source"] or old_fs)
        if b.first_source is not None:
            cand_fs = normalize_source(b.first_source)
            if cand_fs != old_fs:
                if u["role"] not in ("owner", "doctor"):
                    raise HTTPException(403, "İlk geliş kaynağını (first_source) yalnızca klinik yöneticisi veya hekim değiştirebilir")
                eff_reason = (b.first_source_reason or b.source_change_reason or "").strip()
                if len(eff_reason) < 3:
                    raise HTTPException(400, "İlk geliş kaynağını değiştirmek için en az 3 karakterlik gerekçe (first_source_reason) zorunludur")
                new_fs = cand_fs
                first_source_audit = {
                    "old_value": old_fs,
                    "new_value": new_fs,
                    "actor_id": u["id"],
                    "actor": u["email"],
                    "reason": eff_reason,
                    "ts": t_now,
                }

        new_doc = None if b.clear_primary_doctor else (b.primary_doctor_id if b.primary_doctor_id is not None else p["primary_doctor_id"])
        if new_doc is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (new_doc, cid)).fetchone():
            raise HTTPException(404, "Seçilen sorumlu doktor bulunamadı")
        new_bank = None if b.clear_bank_agreement else (b.bank_agreement_id if b.bank_agreement_id is not None else p["bank_agreement_id"])
        if new_bank is not None and not c.execute("SELECT id FROM bank_agreements WHERE id=? AND clinic_id=?", (new_bank, cid)).fetchone():
            raise HTTPException(404, "Seçilen banka anlaşması bulunamadı")
        new_camp = b.campaign_id if b.campaign_id is not None else p["campaign_id"]
        new_notes = b.notes if b.notes is not None else (p["notes"] or "")
        new_bdate = b.birth_date if b.birth_date is not None else (p["birth_date"] or "")
        try:
            c.execute(
                """UPDATE patients
                   SET display_name=?, lang=?, phone_hmac=?, phone_enc=?, first_source=?, last_source=?,
                       campaign_id=?, primary_doctor_id=?, bank_agreement_id=?, notes=?, birth_date=?
                   WHERE id=? AND clinic_id=?""",
                _clean_sql_args((new_name, new_lang, ph, pe, new_fs, new_ls, new_camp, new_doc, new_bank, new_notes, new_bdate, pid, cid)),
            )
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Bu telefon numarası kliniğinizde başka bir hastaya kayıtlı")
    if first_source_audit:
        write_audit(u["id"], u["email"], "patient.first_source_change", f"patient:{pid}", u["ip_h"], first_source_audit, clinic_id=cid)
    write_audit(u["id"], u["email"], "patient.update", f"patient:{pid}", u["ip_h"],
                {"first_source": new_fs, "last_source": new_ls, "primary_doctor_id": new_doc, "bank_agreement_id": new_bank}, clinic_id=cid)
    return {"ok": True, "id": pid, "first_source": new_fs, "last_source": new_ls, "primary_doctor_id": new_doc, "bank_agreement_id": new_bank}


@app.post("/app/api/patients/{pid}/archive")
def archive_patient(pid: int, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    ex("UPDATE patients SET active=0 WHERE id=? AND clinic_id=?", pid, cid)
    write_audit(u["id"], u["email"], "patient.archive", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.post("/app/api/patients/{pid}/unarchive")
def unarchive_patient(pid: int, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    ex("UPDATE patients SET active=1 WHERE id=? AND clinic_id=?", pid, cid)
    write_audit(u["id"], u["email"], "patient.unarchive", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


def _media_dir() -> Path:
    custom = os.environ.get("DC_MEDIA_DIR", "").strip()
    if custom:
        return Path(custom)
    db_p = os.environ.get("DC_DB_PATH", "").strip()
    if db_p:
        return Path(db_p).resolve().parent / "encrypted_media"
    return ROOT / "encrypted_media"


@app.post("/app/api/patients/{pid}/media")
async def upload_patient_media(pid: int, request: Request, u: dict = Depends(require_perm("patient_edit"))):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    data = b""
    qp = request.query_params
    filename = qp.get("filename") or "upload.jpg"
    mime = ""
    category = qp.get("category") if qp.get("category") in ("xray", "photo", "document") else "photo"
    stage = qp.get("stage") if qp.get("stage") in ("general", "before", "after") else "general"
    appointment_id: int | None = int(qp["appointment_id"]) if (qp.get("appointment_id") and str(qp.get("appointment_id")).isdigit()) else None
    tooth_record_id: int | None = int(qp["tooth_record_id"]) if (qp.get("tooth_record_id") and str(qp.get("tooth_record_id")).isdigit()) else None
    note = (qp.get("note") or "")[:300]
    ctype = request.headers.get("content-type", "")
    if "multipart/form-data" in ctype:
        try:
            form = await request.form()
            up = form.get("file")
            if up and hasattr(up, "read"):
                data = await up.read()
                filename = getattr(up, "filename", "") or filename
                mime = getattr(up, "content_type", "") or ""
            if form.get("category") in ("xray", "photo", "document"):
                category = str(form.get("category"))
            if form.get("stage") in ("general", "before", "after"):
                stage = str(form.get("stage"))
            if form.get("appointment_id"):
                try:
                    appointment_id = int(str(form.get("appointment_id")))
                except ValueError:
                    raise HTTPException(400, "Geçersiz randevu kimliği")
            if form.get("tooth_record_id"):
                try:
                    tooth_record_id = int(str(form.get("tooth_record_id")))
                except ValueError:
                    raise HTTPException(400, "Geçersiz diş kaydı kimliği")
            if form.get("note"):
                note = str(form.get("note"))[:300]
        except HTTPException:
            raise
        except Exception:
            raw_body = await request.body()
            idx = raw_body.find(b"\xff\xd8\xff")
            if idx != -1:
                end_idx = raw_body.rfind(b"\xff\xd9")
                data = raw_body[idx:end_idx + 2] if end_idx != -1 else raw_body[idx:]
    else:
        data = await request.body()
    if appointment_id is not None and not q1("SELECT id FROM appointments WHERE id=? AND clinic_id=? AND patient_id=?", appointment_id, cid, pid):
        raise HTTPException(400, "Seçilen randevu bu hasta/klinik ile eşleşmiyor")
    if tooth_record_id is not None and not q1("SELECT id FROM tooth_records WHERE id=? AND clinic_id=? AND patient_id=?", tooth_record_id, cid, pid):
        raise HTTPException(400, "Seçilen diş kaydı bu hasta/klinik ile eşleşmiyor")
    if not data or len(data) > 15 * 1024 * 1024:
        raise HTTPException(400, "Geçersiz dosya boyutu (en fazla 15 MB)")
    raw_base_fn = Path(str(filename or "upload.jpg").replace("\\", "/")).name
    if ".." in str(filename or "") or "/" in str(filename or "") or "\\" in str(filename or ""):
        # Path traversal attempt in filename: strip directory components
        filename = raw_base_fn
    safe_filename = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_base_fn)[:120] or "upload.jpg"
    try:
        qc = media.assess_media_file(data, filename=safe_filename, mime=mime)
    except ValueError as ve:
        raise HTTPException(400, str(ve))
    except Exception:
        raise HTTPException(400, "Geçersiz görsel veya belge formatı (yalnız JPEG, PNG, WebP, PDF ve DICOM desteklenir)")
    is_dcm = bool(qc.get("is_dicom") or qc.get("kind") == "dicom")
    eff_mime = str(qc.get("mime_type") or qc.get("mime") or "image/jpeg")
    if is_dcm:
        category = "xray"
        ext = "dcm"
    elif eff_mime == "application/pdf" or qc.get("kind") == "pdf":
        if category == "photo":
            category = "document"
        ext = "pdf"
    else:
        ext = "png" if "png" in eff_mime else ("webp" if "webp" in eff_mime else str(qc.get("format") or "jpg").lower())
    img_dir = _media_dir()
    img_dir.mkdir(parents=True, exist_ok=True)
    enc_name = f"p{pid}_{secrets.token_hex(6)}.{ext}.enc"
    enc_path = img_dir / enc_name
    enc_path.write_bytes(_FERNET.encrypt(data))
    t_now = iso_now()
    media_id = ex(
        """INSERT INTO patient_media
           (clinic_id,patient_id,appointment_id,tooth_record_id,category,stage,original_filename,mime_type,file_size_bytes,
            sha256_hash,encrypted_path,is_dicom,width,height,sharpness,brightness,qc_verdict,note,uploaded_by,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        cid, pid, appointment_id, tooth_record_id, category, stage, safe_filename,
        eff_mime, len(data), qc.get("sha256", ""), enc_name,
        1 if is_dcm else 0, int(qc.get("w") or 0), int(qc.get("h") or 0),
        float(qc.get("sharpness") or 0), float(qc.get("brightness") or 0),
        qc["verdict"], note, u["id"], t_now,
    )
    if qc["verdict"] == "ok":
        ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'gorsel_alindi',?,?)",
           cid, pid, f"Hasta #{pid} için {category} ({ext}) yüklendi.", t_now)
    write_audit(u["id"], u["email"], "patient.media_upload", f"patient:{pid}:media:{media_id}", u["ip_h"],
                {"verdict": qc["verdict"], "category": category, "stage": stage, "mime_type": eff_mime, "is_dicom": is_dcm}, clinic_id=cid)
    return {**qc, "id": media_id, "media_id": media_id, "category": category, "stage": stage, "filename": safe_filename, "encrypted_file": enc_name}


@app.get("/app/api/patients/{pid}")
def get_patient(pid: int, reveal: bool = False, u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    p = q1(
        """SELECT p.*, d.full_name AS primary_doctor_name, c_u.full_name AS created_by_name,
                  ba.bank_name AS bank_agreement_name, ba.discount_pct AS bank_discount_pct,
                  cp.name AS campaign_name
           FROM patients p
           LEFT JOIN staff_users d ON d.id=p.primary_doctor_id
           LEFT JOIN staff_users c_u ON c_u.id=p.created_by
           LEFT JOIN bank_agreements ba ON ba.id=p.bank_agreement_id
           LEFT JOIN campaigns cp ON cp.id=p.campaign_id
           WHERE p.id=? AND p.clinic_id=?""",
        pid, cid,
    )
    if not p:
        raise HTTPException(404, "hasta yok")
    perms = u.get("permissions") or {}
    if perms.get("doctor_own_patients_only") and u["role"] != "owner":
        owns = (
            p.get("primary_doctor_id") == u["id"]
            or q1("SELECT 1 FROM appointments WHERE patient_id=? AND doctor_id=? LIMIT 1", pid, u["id"])
            or q1("SELECT 1 FROM tooth_records WHERE patient_id=? AND doctor_id=? LIMIT 1", pid, u["id"])
        )
        if not owns:
            raise HTTPException(403, "Yalnızca kendi sorumluluğunuzdaki veya tedavisini yaptığınız hastaları görüntüleyebilirsiniz")
    phone = dec(p["phone_enc"])
    norm_p = norm_phone(phone)
    tel_href = f"tel:+{norm_p}" if norm_p else ""
    write_audit(u["id"], u["email"], "patient.reveal_phone" if reveal else "patient.view", f"patient:{pid}", u["ip_h"], clinic_id=cid)

    with _DB_LOCK:
        fin = ent.compute_patient_finance_summary(db(), cid, pid, tl)

    charges = q(
        """SELECT c.id, c.description, c.amount_kurus, c.gross_amount_kurus, c.discount_kurus,
                  c.bank_agreement_id, c.discount_reason, c.doctor_id, s.full_name AS doctor_name,
                  c.created_at, c.voided_at, c.void_reason
           FROM charges c LEFT JOIN staff_users s ON s.id=c.doctor_id
           WHERE c.patient_id=? AND c.clinic_id=? ORDER BY c.id DESC""",
        pid, cid,
    )
    for c_row in charges:
        ak = int(c_row.pop("amount_kurus") or 0)
        gk = int(c_row.pop("gross_amount_kurus") or ak)
        dk = int(c_row.pop("discount_kurus") or 0)
        c_row["amount"] = tl(ak)
        c_row["gross_amount"] = tl(gk)
        c_row["discount"] = tl(dk)

    pays = q(
        """SELECT y.id, y.amount_kurus, y.method, COALESCE(y.status,'completed') AS status,
                  y.is_advance, y.applied_charge_id, y.refund_of_id, y.doctor_id,
                  s.full_name AS doctor_name, y.note, y.created_at, y.voided_at, y.void_reason
           FROM payments y LEFT JOIN staff_users s ON s.id=y.doctor_id
           WHERE y.patient_id=? AND y.clinic_id=? ORDER BY y.id DESC""",
        pid, cid,
    )
    for y_row in pays:
        y_row["amount"] = tl(int(y_row.pop("amount_kurus") or 0))
        y_row["is_advance"] = bool(y_row.get("is_advance"))

    anam = q("SELECT id, red_flags_json, signed_at FROM anamnesis WHERE patient_id=? ORDER BY id DESC", pid)
    for a in anam:
        flags = json.loads(a.pop("red_flags_json") or "[]")
        if u["role"] not in ("owner", "doctor") and flags:
            a["red_flags"] = ["Klinik Uyarı (Hekim Kontrolü)"]
        else:
            a["red_flags"] = flags

    appts = q(
        """SELECT a.id, a.starts_at, a.duration_min, a.treatment, a.status, a.chair,
                  a.doctor_id, s.full_name AS doctor_name, a.confirmed_at, a.cancelled_at,
                  a.satisfaction_sent_at, a.satisfaction_reply, a.satisfaction_status, a.google_link_sent_at, a.created_at
           FROM appointments a LEFT JOIN staff_users s ON s.id=a.doctor_id
           WHERE a.patient_id=? AND a.clinic_id=? ORDER BY a.starts_at DESC""",
        pid, cid,
    )
    tooth_recs = q(
        """SELECT t.*, s.full_name AS doctor_name, ba.bank_name AS bank_agreement_name
           FROM tooth_records t
           LEFT JOIN staff_users s ON s.id=t.doctor_id
           LEFT JOIN bank_agreements ba ON ba.id=t.bank_agreement_id
           WHERE t.patient_id=? AND t.clinic_id=? ORDER BY t.id DESC""",
        pid, cid,
    )
    for tr in tooth_recs:
        tr["amount_try"] = tl(int(tr.get("amount_kurus") or 0))
        tr["gross_amount_try"] = tl(int(tr.get("gross_amount_kurus") or tr.get("amount_kurus") or 0))
        tr["discount_try"] = tl(int(tr.get("discount_kurus") or 0))

    groups = q(
        """SELECT m.id, m.group_id, g.name, g.color, g.is_restricted, m.reason, m.added_by_name, m.added_at AS created_at
           FROM patient_group_members m JOIN patient_groups g ON g.id=m.group_id
           WHERE m.patient_id=? AND m.clinic_id=? ORDER BY m.id DESC""",
        pid, cid,
    )
    media_files = q(
        """SELECT id, category, stage, original_filename AS filename, mime_type, file_size_bytes AS size_bytes,
                  width, height, sha256_hash AS sha256, is_dicom, sharpness, brightness,
                  qc_verdict, note, created_at
           FROM patient_media WHERE patient_id=? AND clinic_id=? ORDER BY id DESC""",
        pid, cid,
    )
    installments = q(
        """SELECT id, installment_no, total_installments, due_date, amount_kurus, paid_kurus, status, paid_payment_id, note, created_at
           FROM payment_installments WHERE patient_id=? AND clinic_id=? AND status<>'voided' ORDER BY due_date ASC""",
        pid, cid,
    )
    for inst in installments:
        inst["title"] = f"Taksit {inst.get('installment_no', 1)}/{inst.get('total_installments', 1)}"
        inst["amount"] = tl(int(inst.pop("amount_kurus") or 0))
        inst["paid"] = tl(int(inst.pop("paid_kurus") or 0))

    consents = q("SELECT id, kind, text_version, text_sha256, channel, granted_at, revoked_at FROM consents WHERE patient_id=? ORDER BY id DESC", pid)
    treatment_consents = q(
        """SELECT id, doctor_id, token, plan_summary_json, total_amount_kurus, document_version, content_sha256,
                  signer_name, consent_type AS approval_type, status, signed_at, expires_at, created_at
           FROM treatment_consents WHERE patient_id=? AND clinic_id=? ORDER BY id DESC""",
        pid, cid,
    )
    lab_orders = q(
        """SELECT id, lab_name, procedure_type AS work_type, tooth_fdi, shade_color AS shade,
                  sent_date AS sent_at, due_date, delivered_date AS delivered_at, cost_kurus, status, note, created_at
           FROM lab_orders WHERE patient_id=? AND clinic_id=? ORDER BY id DESC""",
        pid, cid,
    )
    for lo in lab_orders:
        lo["cost"] = tl(int(lo.pop("cost_kurus") or 0))

    implant_records = q(
        """SELECT id, tooth_fdi, brand, model, diameter_mm, length_mm, lot_number, serial_number,
                  uts_barcode AS barcode_udi, uts_notification_status, doctor_id, used_at AS placed_at, note, created_at
           FROM implant_records WHERE patient_id=? AND clinic_id=? ORDER BY id DESC""",
        pid, cid,
    )
    periodontal_exams = q(
        """SELECT id, doctor_id, exam_date, mean_pd, max_pd, plaque_pct AS plaque_index_pct,
                  bop_pct AS bleeding_index_pct, doctor_approved, doctor_note AS note, created_at
           FROM periodontal_exams WHERE patient_id=? AND clinic_id=? ORDER BY id DESC""",
        pid, cid,
    )

    # Kronolojik zaman çizelgesi (Bölüm 6: kayıttan son işleme tüm hareketler)
    timeline: list[dict] = []
    if p.get("created_at"):
        fs_code = p.get("first_source") or "whatsapp"
        timeline.append({
            "ts": p["created_at"],
            "type": "patient_created",
            "title": "Hasta Kaydı Oluşturuldu",
            "detail": f"İlk kaynak: {PATIENT_SOURCE_LABELS.get(fs_code, fs_code)} · Kaydeden: {p.get('created_by_name') or 'Sistem'}",
        })
    for ap in appts:
        timeline.append({
            "ts": ap.get("created_at") or ap["starts_at"],
            "type": "appointment",
            "title": f"Randevu ({ap['status']}): {ap['treatment']}",
            "detail": f"Tarih: {str(ap['starts_at'])[:16].replace('T',' ')} · Koltuk {ap['chair']} · Hekim: {ap.get('doctor_name') or '-'}",
        })
    for tr in tooth_recs:
        timeline.append({
            "ts": tr["created_at"],
            "type": "treatment",
            "title": f"Diş #{tr['tooth_fdi']} ({tr['surface']}) — {tr['procedure_name']}",
            "detail": f"Durum: {tr['status']} · Tedaviyi Yapan Doktor: {tr.get('doctor_name') or '-'} · Tutar: {tr['amount_try']:.2f} TL",
        })
    for ch_r in charges:
        timeline.append({
            "ts": ch_r["created_at"],
            "type": "charge",
            "title": f"Hizmet Tahakkuku: {ch_r['description']}",
            "detail": f"Brüt: {ch_r['gross_amount']:.2f} TL · İndirim: {ch_r['discount']:.2f} TL · Net: {ch_r['amount']:.2f} TL",
        })
    for py_r in pays:
        timeline.append({
            "ts": py_r["created_at"],
            "type": "payment",
            "title": f"Ödeme ({py_r['method']} · {py_r['status']})",
            "detail": f"Tutar: {py_r['amount']:.2f} TL",
        })
    for mf in media_files:
        timeline.append({
            "ts": mf["created_at"],
            "type": "media",
            "title": f"Dosya/Görsel Yüklendi ({mf['category']})",
            "detail": f"{mf['filename']} · Aşama: {mf['stage']}",
        })
    timeline.sort(key=lambda x: str(x.get("ts") or ""), reverse=True)

    fs = p.get("first_source") or ("instagram" if p.get("channel") == "ig" else "whatsapp")
    ls = p.get("last_source") or fs
    can_fin_view = bool((u.get("permissions") or {}).get("finance_view", False))
    res_p = {
        "id": p["id"],
        "name": p["display_name"],
        "display_name": p["display_name"],
        "lang": p["lang"],
        "channel": p["channel"],
        "active": bool(p.get("active", 1)),
        "phone": phone if reveal else mask_phone(phone),
        "tel_href": tel_href,
        "birth_date": p.get("birth_date") or "",
        "notes": p.get("notes") or "",
        "created_at": p.get("created_at"),
        "created_by": p.get("created_by"),
        "created_by_name": p.get("created_by_name") or "Sistem",
        "first_source": fs,
        "first_source_label": PATIENT_SOURCE_LABELS.get(fs, fs),
        "last_source": ls,
        "last_source_label": PATIENT_SOURCE_LABELS.get(ls, ls),
        "campaign_id": p.get("campaign_id"),
        "campaign_name": p.get("campaign_name"),
        "utm_source": p.get("utm_source") or "",
        "utm_medium": p.get("utm_medium") or "",
        "utm_campaign": p.get("utm_campaign") or "",
        "click_id": p.get("click_id") or "",
        "primary_doctor_id": p.get("primary_doctor_id"),
        "primary_doctor_name": p.get("primary_doctor_name"),
        "bank_agreement_id": p.get("bank_agreement_id"),
        "bank_agreement_name": p.get("bank_agreement_name"),
        "bank_discount_pct": p.get("bank_discount_pct"),
        "groups": groups,
        "balance": fin["balance"] if can_fin_view else 0.0,
        "finance_summary": fin if can_fin_view else {"masked": True},
        "treatments_summary": {
            "planned": [t for t in tooth_recs if t["status"] in ("planned", "caries", "extraction")],
            "completed": [t for t in tooth_recs if t["status"] in ODO_BILLABLE_STATUSES],
            "postponed": [t for t in tooth_recs if t["status"] == "postponed"],
            "cancelled": [t for t in tooth_recs if t["status"] == "cancelled"],
        },
        "tooth_records": tooth_recs,
        "appointments": appts,
        "payments": pays if can_fin_view else [],
        "installments": installments if can_fin_view else [],
        "anamnesis": anam,
        "consents": consents,
        "treatment_consents": treatment_consents,
        "lab_orders": lab_orders,
        "implant_records": implant_records,
        "periodontal_exams": periodontal_exams,
        "media_files": media_files,
        "timeline": timeline,
        "anamnesis_links": {a["id"]: sign_path(f"/view/anamnez/{a['id']}", 900) for a in anam} if u["role"] in ("owner", "doctor") else {},
    }
    if can_fin_view:
        res_p["charges"] = charges
    return res_p


class ConsentRevokeIn(BaseModel):
    kind: Literal["kvkk_aydinlatma", "saglik_verisi_acik_riza", "iletisim", "yurt_disi_aktarim", "all"] | None = None
    consent_id: int | None = None


@app.post("/app/api/patients/{pid}/consents/revoke")
def revoke_patient_consent(pid: int, b: ConsentRevokeIn, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    now_s = iso_now()
    with _DB_LOCK:
        c = db()
        if b.consent_id is not None:
            cur = c.execute(
                "UPDATE consents SET revoked_at=? WHERE id=? AND patient_id=? AND revoked_at IS NULL",
                (now_s, b.consent_id, pid),
            )
        elif b.kind and b.kind != "all":
            cur = c.execute(
                "UPDATE consents SET revoked_at=? WHERE patient_id=? AND kind=? AND revoked_at IS NULL",
                (now_s, pid, b.kind),
            )
        else:
            cur = c.execute(
                "UPDATE consents SET revoked_at=? WHERE patient_id=? AND revoked_at IS NULL",
                (now_s, pid),
            )
        cnt = cur.rowcount
        c.commit()
    write_audit(u["id"], u["email"], "patient.consent_revoke", f"patient:{pid}", u["ip_h"],
                {"kind": b.kind or f"id:{b.consent_id}", "count": cnt}, clinic_id=cid)
    return {"ok": True, "patient_id": pid, "revoked_count": cnt, "revoked_at": now_s}


@app.get("/app/api/patients/{pid}/export")
def export_patient_data(pid: int, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    p = q1("SELECT * FROM patients WHERE id=? AND clinic_id=?", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    try:
        phone = dec(p["phone_enc"])
    except Exception:
        phone = "***"
    anam_rows = q("SELECT id, answers_enc, red_flags_json, signer_name, signature_sha256, signed_at FROM anamnesis WHERE patient_id=? ORDER BY id", pid)
    anam_out = []
    for a in anam_rows:
        try:
            ans = json.loads(dec(a["answers_enc"]))
        except Exception:
            ans = {}
        anam_out.append({
            "id": a["id"], "answers": ans,
            "red_flags": json.loads(a.get("red_flags_json") or "[]"),
            "signer_name": a["signer_name"], "signature_sha256": a["signature_sha256"], "signed_at": a["signed_at"],
        })
    charges = q("SELECT id, description, amount_kurus, created_at, voided_at, void_reason FROM charges WHERE patient_id=? ORDER BY id", pid)
    pays = q("SELECT id, amount_kurus, method, created_at, voided_at, void_reason FROM payments WHERE patient_id=? ORDER BY id", pid)
    for c in charges + pays:
        c["amount"] = tl(c.pop("amount_kurus"))
    write_audit(u["id"], u["email"], "patient.export", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {
        "exported_at": iso_now(),
        "clinic_id": cid,
        "patient": {
            "id": p["id"], "display_name": p["display_name"], "phone": phone,
            "lang": p["lang"], "channel": p["channel"], "active": bool(p.get("active", 1)), "created_at": p["created_at"],
        },
        "consents": q("SELECT id, kind, text_version, text_sha256, channel, granted_at, revoked_at FROM consents WHERE patient_id=? ORDER BY id", pid),
        "anamnesis": anam_out,
        "appointments": q("SELECT id, starts_at, duration_min, treatment, chair, status, source, created_at FROM appointments WHERE patient_id=? ORDER BY id", pid),
        "tooth_records": q("SELECT id, tooth_fdi, surface, status, procedure_code, procedure_name, note, created_at FROM tooth_records WHERE patient_id=? AND clinic_id=? ORDER BY id", pid, cid),
        "charges": charges,
        "payments": pays,
        "waitlist": q("SELECT id, treatment, earliest, active, created_at FROM waitlist WHERE patient_id=? ORDER BY id", pid),
        "postop_checks": q("SELECT id, procedure, stage, due_at, sent_at, pain_score, answered_at, alarm FROM postop_checks WHERE patient_id=? ORDER BY id", pid),
    }


def _anonymize_patient_impl(pid: int, u: dict) -> dict:
    cid = u["clinic_id"]
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    now_s = iso_now()
    anon_hmac = hmac.new(_HMAC_KEY, f"anon:{cid}:{pid}:{secrets.token_hex(8)}".encode(), hashlib.sha256).hexdigest()
    anon_enc = enc(f"anon-{pid}")
    anon_ans = enc(json.dumps({"anonymized": True, "at": now_s}))
    anon_sig = hashlib.sha256(f"anon:{pid}:{now_s}".encode()).hexdigest()
    with _DB_LOCK:
        c = db()
        try:
            c.execute(
                "UPDATE patients SET display_name=?, phone_hmac=?, phone_enc=?, active=0 WHERE id=? AND clinic_id=?",
                (f"Anonim Hasta #{pid}", anon_hmac, anon_enc, pid, cid),
            )
            c.execute(
                "UPDATE anamnesis SET signer_name='Anonimleştirildi', answers_enc=?, red_flags_json='[]', signature_sha256=? WHERE patient_id=?",
                (anon_ans, anon_sig, pid),
            )
            c.execute("DELETE FROM anamnesis_tokens WHERE patient_id=?", (pid,))
            c.execute("DELETE FROM slot_offers WHERE waitlist_id IN (SELECT id FROM waitlist WHERE patient_id=?)", (pid,))
            c.execute("DELETE FROM postop_checks WHERE patient_id=?", (pid,))
            c.execute("UPDATE message_log SET body='', delivery_error=NULL WHERE patient_id=?", (pid,))
            c.execute("UPDATE consents SET revoked_at=coalesce(revoked_at, ?) WHERE patient_id=?", (now_s, pid))
            c.execute(
                "UPDATE alerts SET detail=?, acknowledged_at=coalesce(acknowledged_at, ?) WHERE patient_id=?",
                (f"Anonimleştirilmiş hasta (#{pid}) kaydı.", now_s, pid),
            )
            c.execute("UPDATE waitlist SET active=0 WHERE patient_id=?", (pid,))
            c.commit()
        except Exception:
            c.rollback()
            raise
    for img_dir in (_media_dir(), ROOT / "encrypted_media"):
        if img_dir.is_dir():
            for fp in img_dir.glob(f"p{pid}_*.enc"):
                fp.unlink(missing_ok=True)
    write_audit(u["id"], u["email"], "patient.anonymize", f"patient:{pid}", u["ip_h"],
                {"financial_records_preserved": True}, clinic_id=cid)
    return {"ok": True, "patient_id": pid, "anonymized": True, "financial_records_preserved": True}


@app.post("/app/api/patients/{pid}/anonymize")
def anonymize_patient(pid: int, u: dict = Depends(OWNER)):
    return _anonymize_patient_impl(pid, u)


@app.delete("/app/api/patients/{pid}")
def delete_patient(pid: int, u: dict = Depends(OWNER)):
    return _anonymize_patient_impl(pid, u)


class OdontogramIn(BaseModel):
    tooth_fdi: int
    surface: Literal["M", "D", "O", "B", "L", "FULL"] = "FULL"
    status: Literal[
        "healthy", "caries", "planned", "treated", "completed", "filling",
        "implant", "crown", "bridge", "root_canal", "missing", "extraction",
        "postponed", "cancelled"
    ] = "planned"
    procedure_code: str = Field("", max_length=40)
    procedure_name: str = Field(min_length=2, max_length=120)
    amount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    discount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    bank_agreement_id: int | None = None
    use_patient_bank_agreement: bool = True
    discount_reason: str = Field("", max_length=200)
    doctor_id: int | None = None
    note: str = Field("", max_length=300)
    auto_charge: bool = False
    idempotency_key: str | None = Field(default=None, max_length=80)

    @field_validator("tooth_fdi")
    @classmethod
    def check_fdi(cls, v: int) -> int:
        if v not in VALID_FDI_TEETH:
            raise ValueError("Geçersiz FDI diş numarası (11-48 daimi veya 51-85 süt dişi olmalı)")
        return v

    @field_validator("status")
    @classmethod
    def norm_status(cls, v: str) -> str:
        return "treated" if v == "completed" else v


class OdontogramUpdateIn(BaseModel):
    surface: Literal["M", "D", "O", "B", "L", "FULL"] | None = None
    status: Literal[
        "healthy", "caries", "planned", "treated", "completed", "filling",
        "implant", "crown", "bridge", "root_canal", "missing", "extraction",
        "postponed", "cancelled"
    ] | None = None
    procedure_code: str | None = Field(default=None, max_length=40)
    procedure_name: str | None = Field(default=None, min_length=2, max_length=120)
    amount: Decimal | None = Field(default=None, ge=0, le=10_000_000)
    discount: Decimal | None = Field(default=None, ge=0, le=10_000_000)
    bank_agreement_id: int | None = None
    discount_reason: str | None = Field(default=None, max_length=200)
    doctor_id: int | None = None
    note: str | None = Field(default=None, max_length=300)

    @field_validator("status")
    @classmethod
    def norm_status(cls, v: str | None) -> str | None:
        return "treated" if v == "completed" else v


# P0-1: Yalnız gerçekleşmiş (tamamlanmış) diş işlemleri hasta borcuna yazılır.
# Planlanan/çürük/çekim planı/eksik/ertelenen/iptal kayıtları tedavi planıdır; kasaya borç oluşturmaz.
ODO_BILLABLE_STATUSES = frozenset({"treated", "filling", "implant", "crown", "bridge", "root_canal"})


def _odo_charge_key(rid: int, client_key: str | None = None) -> str:
    """Şema değişikliği olmadan diş kaydı ↔ borç bağını charges.idempotency_key ile kurar."""
    return f"odo:{int(rid)}:{(client_key or '')[:60]}"[:80]


def _odo_charge_desc(fdi: int, surface: str, name: str) -> str:
    return f"Diş #{fdi} ({surface}) - {name}"[:120]


def _odo_linked_charges(c, cid: int, pid: int, rec: dict) -> list:
    """Diş kaydına bağlı, iptal edilmemiş borçlar. Eski kayıtlar için birebir açıklama eşleşmesi yedektir."""
    rows = c.execute(
        "SELECT id FROM charges WHERE clinic_id=? AND patient_id=? AND voided_at IS NULL AND (idempotency_key LIKE ? OR tooth_record_id=?)",
        (cid, pid, f"odo:{int(rec['id'])}:%", int(rec["id"])),
    ).fetchall()
    if rows:
        return [r["id"] for r in rows]
    legacy = c.execute(
        """SELECT id FROM charges WHERE clinic_id=? AND patient_id=? AND voided_at IS NULL
           AND description=? AND amount_kurus=? AND (idempotency_key IS NULL OR idempotency_key NOT LIKE 'odo:%')
           ORDER BY id LIMIT 1""",
        (cid, pid, _odo_charge_desc(rec["tooth_fdi"], rec["surface"], rec["procedure_name"]), rec["amount_kurus"]),
    ).fetchall()
    return [r["id"] for r in legacy]


def _odo_void_charges(c, cid: int, ids: list, reason: str, t_now: str) -> None:
    for ch_id in ids:
        c.execute(
            "UPDATE charges SET voided_at=?, void_reason=? WHERE id=? AND clinic_id=? AND voided_at IS NULL",
            (t_now, reason[:200], ch_id, cid),
        )


@app.get("/app/api/patients/{pid}/odontogram")
def get_odontogram(pid: int, u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    p = q1(
        """SELECT p.id, p.display_name, p.primary_doctor_id, d.full_name AS primary_doctor_name,
                  p.bank_agreement_id, ba.bank_name AS bank_agreement_name, ba.discount_pct AS bank_discount_pct
           FROM patients p
           LEFT JOIN staff_users d ON d.id=p.primary_doctor_id
           LEFT JOIN bank_agreements ba ON ba.id=p.bank_agreement_id
           WHERE p.id=? AND p.clinic_id=?""",
        pid, cid,
    )
    if not p:
        raise HTTPException(404, "hasta yok")
    rows = q(
        """SELECT t.*, s.full_name AS doctor_name, ba.bank_name AS bank_agreement_name
           FROM tooth_records t
           LEFT JOIN staff_users s ON s.id=t.doctor_id
           LEFT JOIN bank_agreements ba ON ba.id=t.bank_agreement_id
           WHERE t.clinic_id=? AND t.patient_id=? ORDER BY t.tooth_fdi, t.id DESC""",
        cid, pid,
    )
    for r in rows:
        r["amount_try"] = tl(r["amount_kurus"])
        r["gross_amount_try"] = tl(int(r.get("gross_amount_kurus") or r["amount_kurus"]))
        r["discount_try"] = tl(int(r.get("discount_kurus") or 0))
    return {
        "patient_id": pid,
        "clinic_id": cid,
        "primary_doctor_id": p.get("primary_doctor_id"),
        "primary_doctor_name": p.get("primary_doctor_name"),
        "bank_agreement_id": p.get("bank_agreement_id"),
        "bank_agreement_name": p.get("bank_agreement_name"),
        "bank_discount_pct": p.get("bank_discount_pct"),
        "records": rows,
        "summary": {
            "total_records": len(rows),
            "treated_count": sum(1 for r in rows if r["status"] in ODO_BILLABLE_STATUSES),
            "planned_count": sum(1 for r in rows if r["status"] in ("planned", "caries", "extraction")),
            "postponed_count": sum(1 for r in rows if r["status"] == "postponed"),
            "cancelled_count": sum(1 for r in rows if r["status"] == "cancelled"),
        },
    }


@app.post("/app/api/patients/{pid}/odontogram")
def add_odontogram_record(pid: int, b: OdontogramIn, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    charge_id = None
    with _DB_LOCK:
        c = db()
        p_row = _require_active_patient_row(c, pid, cid)
        if b.doctor_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.doctor_id, cid)).fetchone():
            raise HTTPException(404, "hekim yok")
        eff_bank_id = b.bank_agreement_id if b.bank_agreement_id is not None else (p_row["bank_agreement_id"] if b.use_patient_bank_agreement else None)
        bank_row = None
        if eff_bank_id is not None:
            bank_row = c.execute("SELECT * FROM bank_agreements WHERE id=? AND clinic_id=? AND active=1", (eff_bank_id, cid)).fetchone()
        calc = compute_bank_discount(
            gross_kurus=kurus(b.amount),
            agreement=dict(bank_row) if bank_row else None,
            procedure_name=f"{b.procedure_code} {b.procedure_name}".strip(),
            manual_discount_kurus=kurus(b.discount),
        )
        gross_k = int(calc["gross_kurus"])
        disc_k = int(calc["total_discount_kurus"])
        amt_k = int(calc["net_kurus"])
        disc_reason = b.discount_reason.strip() or (str(calc.get("explanation") or "") if disc_k > 0 else "")
        used_bank_id = int(bank_row["id"]) if (bank_row and calc.get("eligible")) else None

        t_now = iso_now()
        # Bölüm 7: Tedaviyi yapan doktor (doctor_id) yalnız bu işlem kaydına yazılır; hastanın Sorumlu Doktoru (primary_doctor_id) korunur!
        perf_doc_id = b.doctor_id or u["id"]
        cur_t = c.execute(
            """INSERT INTO tooth_records
               (clinic_id,patient_id,tooth_fdi,surface,status,procedure_code,procedure_name,
                amount_kurus,gross_amount_kurus,discount_kurus,bank_agreement_id,discount_reason,
                doctor_id,created_by,note,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                cid, pid, b.tooth_fdi, b.surface, b.status, b.procedure_code, b.procedure_name,
                amt_k, gross_k, disc_k, used_bank_id, disc_reason,
                perf_doc_id, u["id"], b.note, t_now,
            ),
        )
        rid = cur_t.lastrowid
        charge_skipped = None
        if b.auto_charge and amt_k > 0 and b.status not in ODO_BILLABLE_STATUSES:
            charge_skipped = "planned_not_billable"
        elif b.auto_charge and amt_k > 0:
            if b.idempotency_key:
                dup = c.execute(
                    "SELECT id FROM charges WHERE clinic_id=? AND (idempotency_key=? OR idempotency_key LIKE ?)",
                    (cid, b.idempotency_key, f"odo:%:{b.idempotency_key[:60]}"),
                ).fetchone()
                if dup:
                    c.rollback()
                    raise HTTPException(409, "Bu odontogram hizmet borçlandırması zaten işlendi")
            cur_ch = c.execute(
                """INSERT INTO charges
                   (clinic_id,patient_id,description,amount_kurus,gross_amount_kurus,discount_kurus,
                    bank_agreement_id,discount_reason,tooth_record_id,doctor_id,created_by,created_at,idempotency_key)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cid, pid, _odo_charge_desc(b.tooth_fdi, b.surface, b.procedure_name),
                    amt_k, gross_k, disc_k, used_bank_id, disc_reason, rid,
                    perf_doc_id, u["id"], t_now, _odo_charge_key(rid, b.idempotency_key),
                ),
            )
            charge_id = cur_ch.lastrowid
        c.commit()
    write_audit(
        u["id"], u["email"], "odontogram.create", f"patient:{pid}:tooth:{b.tooth_fdi}", u["ip_h"],
        {
            "surface": b.surface, "status": b.status, "charge_id": charge_id, "charge_skipped": charge_skipped,
            "performing_doctor_id": perf_doc_id, "gross_kurus": gross_k, "discount_kurus": disc_k, "net_kurus": amt_k,
        },
        clinic_id=cid,
    )
    return {
        "id": rid, "tooth_fdi": b.tooth_fdi, "surface": b.surface, "status": b.status,
        "charge_id": charge_id, "charge_skipped": charge_skipped,
        "gross_amount": tl(gross_k), "discount": tl(disc_k), "net_amount": tl(amt_k),
        "performing_doctor_id": perf_doc_id,
    }


@app.patch("/app/api/patients/{pid}/odontogram/{rid}")
def update_odontogram_record(pid: int, rid: int, b: OdontogramUpdateIn, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    rec = q1("SELECT * FROM tooth_records WHERE id=? AND patient_id=? AND clinic_id=?", rid, pid, cid)
    if not rec:
        raise HTTPException(404, "diş kaydı yok")
    if b.doctor_id is not None and not q1("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", b.doctor_id, cid):
        raise HTTPException(404, "Seçilen hekim bu klinikte bulunamadı")
    new_surface = b.surface if b.surface is not None else rec["surface"]
    new_status = b.status if b.status is not None else rec["status"]
    new_code = b.procedure_code if b.procedure_code is not None else rec["procedure_code"]
    new_name = b.procedure_name if b.procedure_name is not None else rec["procedure_name"]
    new_doc = b.doctor_id if b.doctor_id is not None else rec["doctor_id"]
    new_note = b.note if b.note is not None else rec["note"]
    t_now = iso_now()
    voided: list = []
    new_charge_id = None
    with _DB_LOCK:
        c = db()
        if b.amount is not None or b.discount is not None or b.bank_agreement_id is not None:
            gross_dec = b.amount if b.amount is not None else Decimal(str(tl(int(rec.get("gross_amount_kurus") or rec["amount_kurus"]))))
            man_disc_dec = b.discount if b.discount is not None else Decimal(0)
            eff_bank_id = b.bank_agreement_id if b.bank_agreement_id is not None else rec.get("bank_agreement_id")
            bank_row = c.execute("SELECT * FROM bank_agreements WHERE id=? AND clinic_id=? AND active=1", (eff_bank_id, cid)).fetchone() if eff_bank_id else None
            calc = compute_bank_discount(
                gross_kurus=kurus(gross_dec),
                agreement=dict(bank_row) if bank_row else None,
                procedure_name=f"{new_code} {new_name}".strip(),
                manual_discount_kurus=kurus(man_disc_dec),
            )
            new_gross = int(calc["gross_kurus"])
            new_disc = int(calc["total_discount_kurus"])
            new_amt = int(calc["net_kurus"])
            new_bank = int(bank_row["id"]) if (bank_row and calc.get("eligible")) else eff_bank_id
            new_reason = b.discount_reason if b.discount_reason is not None else ((str(calc.get("explanation") or "") if new_disc > 0 else "") or rec.get("discount_reason") or "")
        else:
            new_amt = int(rec["amount_kurus"] or 0)
            new_gross = int(rec.get("gross_amount_kurus") or new_amt)
            new_disc = int(rec.get("discount_kurus") or 0)
            new_bank = rec.get("bank_agreement_id")
            new_reason = b.discount_reason if b.discount_reason is not None else (rec.get("discount_reason") or "")

        linked = _odo_linked_charges(c, cid, pid, rec)
        c.execute(
            """UPDATE tooth_records
               SET surface=?, status=?, procedure_code=?, procedure_name=?, amount_kurus=?,
                   gross_amount_kurus=?, discount_kurus=?, bank_agreement_id=?, discount_reason=?,
                   doctor_id=?, note=?
               WHERE id=? AND patient_id=? AND clinic_id=?""",
            (new_surface, new_status, new_code, new_name, new_amt, new_gross, new_disc, new_bank, new_reason, new_doc, new_note, rid, pid, cid),
        )
        # P0-1: Borç, diş kaydının gerçek durumunu izler. Silme yok; iptal hareketi + yeni borç.
        billable = new_status in ODO_BILLABLE_STATUSES and new_amt > 0
        changed = (new_amt != rec["amount_kurus"] or new_surface != rec["surface"] or new_name != rec["procedure_name"])
        if linked and (not billable or changed):
            reason = "Diş kaydı tamamlanmadı/plana döndü" if not billable else "Diş kaydı tutarı/bilgisi güncellendi"
            _odo_void_charges(c, cid, linked, reason, t_now)
            voided = list(linked)
            linked = []
        if billable and not linked:
            cur_ch = c.execute(
                """INSERT INTO charges
                   (clinic_id,patient_id,description,amount_kurus,gross_amount_kurus,discount_kurus,
                    bank_agreement_id,discount_reason,tooth_record_id,doctor_id,created_by,created_at,idempotency_key)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    cid, pid, _odo_charge_desc(rec["tooth_fdi"], new_surface, new_name),
                    new_amt, new_gross, new_disc, new_bank, new_reason, rid,
                    new_doc or u["id"], u["id"], t_now, _odo_charge_key(rid, f"u{secrets.token_hex(6)}"),
                ),
            )
            new_charge_id = cur_ch.lastrowid
        c.commit()
    write_audit(u["id"], u["email"], "odontogram.update", f"tooth_record:{rid}", u["ip_h"],
                {"status": new_status, "voided_charges": voided, "charge_id": new_charge_id}, clinic_id=cid)
    return {"ok": True, "id": rid, "voided_charges": voided, "charge_id": new_charge_id, "new_charge_id": new_charge_id,
            "gross_amount": tl(new_gross), "discount": tl(new_disc), "net_amount": tl(new_amt)}


@app.delete("/app/api/patients/{pid}/odontogram/{rid}")
def delete_odontogram_record(pid: int, rid: int, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    rec = q1("SELECT * FROM tooth_records WHERE id=? AND patient_id=? AND clinic_id=?", rid, pid, cid)
    if not rec:
        raise HTTPException(404, "diş kaydı yok")
    with _DB_LOCK:
        c = db()
        linked = _odo_linked_charges(c, cid, pid, rec)
        _odo_void_charges(c, cid, linked, "Diş kaydı silindi", iso_now())
        c.execute("DELETE FROM tooth_records WHERE id=? AND patient_id=? AND clinic_id=?", (rid, pid, cid))
        c.commit()
    write_audit(u["id"], u["email"], "odontogram.delete", f"tooth_record:{rid}", u["ip_h"],
                {"tooth_fdi": rec["tooth_fdi"], "voided_charges": linked}, clinic_id=cid)
    return {"ok": True, "voided_charges": linked}


@app.post("/app/api/patients/{pid}/anamnesis")
async def send_anam(pid: int, request: Request, u: dict = Depends(require_perm("patient_edit"))):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    with _DB_LOCK:
        p_row = _require_active_patient_row(db(), pid, cid)
        p_phone = dec(p_row["phone_enc"])
        p_name = p_row["display_name"] or "Hastamız"
    tok = secrets.token_urlsafe(24)
    ex("INSERT INTO anamnesis_tokens (token,patient_id,expires_at) VALUES (?,?,?)",
       tok, pid, (now_utc() + timedelta(hours=48)).isoformat())
    link = f"{public_base(request)}/form/anamnez/{tok}"
    msg_text = (
        f"Sayın {p_name}, randevunuz öncesinde sağlık bilgi ve KVKK onam formunu "
        f"aşağıdaki bağlantıdan 1 dakikada doldurabilirsiniz: {link}"
    )
    delivery = await _deliver_wa(
        cid,
        pid,
        p_phone,
        msg_text,
        layer="L1-otomasyon",
        intent="anamnez_form",
        tpl=os.environ.get("WA_TPL_ANAMNESIS", "anamnez"),
        params=[link],
    )
    write_audit(u["id"], u["email"], "anamnesis.send", f"patient:{pid}", u["ip_h"], {"delivery": delivery["status"]}, clinic_id=cid)
    return {"link": link, "delivery": delivery["status"], "dry_run": delivery["dry_run"], "error": delivery["error"]}


def public_base(request: Request) -> str:
    """Hastaya giden bağlantıların kök adresi: PUBLIC_URL (canlı alan adı) yoksa panelin açıldığı adres."""
    env_url = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
    return env_url or str(request.base_url).rstrip("/")


_PATIENT_CSS = """
@font-face{font-family:Inter;font-weight:100 900;font-display:swap;src:url(/static/inter-latin.woff2) format('woff2');unicode-range:U+0000-00FF,U+0131,U+2000-206F,U+20AC}
@font-face{font-family:Inter;font-weight:100 900;font-display:swap;src:url(/static/inter-latin-ext.woff2) format('woff2');unicode-range:U+0100-02BA,U+1E00-1E9F}
:root{--ink:#0E1B2E;--muted:#46576B;--line:#E2E8F0;--bg:#F6F9FB;--card:#FFFFFF;--teal:#0F766E;--teal-h:#115E59;--mint:#F0FDF9;--mint-b:#99F6E4;--red:#B91C1C;--red-bg:#FEF2F2;--font:Inter,"Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,"Noto Sans",system-ui,sans-serif}
*{box-sizing:border-box}html,body{margin:0;overflow-x:clip;background:var(--bg);color:var(--ink);font-family:var(--font);font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
main{max-width:600px;margin:0 auto;padding:24px 16px 48px}
.head{display:flex;align-items:center;gap:12px;margin-bottom:16px}.head svg{flex:none}
.head b{display:block;font-size:17px}.head small{color:var(--muted);font-size:13.5px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px 18px;box-shadow:0 1px 3px rgba(10,37,64,.05)}
h1{font-size:22px;line-height:1.3;margin:0 0 6px}p.lead{color:var(--muted);margin:0 0 18px;font-size:15px}
.note{display:flex;gap:10px;background:var(--mint);border:1px solid var(--mint-b);border-radius:10px;padding:12px;font-size:14px;color:#115E59;margin-bottom:18px}
fieldset{border:0;border-top:1px solid var(--line);margin:0;padding:14px 0}legend{padding:0;font-weight:600;font-size:15px;line-height:1.45;float:left;width:100%;margin-bottom:10px}
.opts{clear:both;display:flex;gap:10px}.opts label{flex:1;display:flex;align-items:center;justify-content:center;gap:8px;min-height:46px;border:1px solid #CBD5E1;border-radius:10px;cursor:pointer;font-weight:500;transition:background-color .15s,border-color .15s}
.opts input{accent-color:var(--teal);width:18px;height:18px}.opts label:has(input:checked){border-color:var(--teal);background:var(--mint)}
label.f{display:block;font-weight:600;font-size:14.5px;margin:18px 0 6px}input[type=text],textarea{width:100%;min-height:48px;padding:10px 12px;font:inherit;border:1px solid #64748B;border-radius:10px}
.kvkk{display:flex;gap:10px;align-items:flex-start;font-size:13.5px;color:var(--muted);margin-top:14px}.kvkk input{margin-top:3px;width:18px;height:18px;accent-color:var(--teal);flex:none}
button{width:100%;min-height:50px;margin-top:18px;background:var(--teal);color:#fff;border:0;border-radius:10px;font:inherit;font-weight:700;font-size:16px;cursor:pointer;transition:background-color .15s}button:hover{background:var(--teal-h)}
:focus-visible{outline:3px solid #5EEAD4;outline-offset:2px}
.foot{color:var(--muted);font-size:12.5px;text-align:center;margin-top:18px}
.err-box{background:var(--red-bg);border:1px solid #FECACA;color:var(--red);border-radius:10px;padding:12px;font-weight:600;font-size:14px;margin-bottom:14px}
.f-err{color:var(--red);font-size:13px;font-weight:600;margin:6px 0 0}
.has-err{border-color:var(--red)!important}
.btn-back{display:inline-flex;align-items:center;justify-content:center;min-height:48px;padding:10px 18px;margin-top:14px;background:var(--ink);color:#fff;border-radius:10px;text-decoration:none;font-weight:700;font-size:15px}
table{width:100%;border-collapse:collapse;font-size:14.5px}td{border-top:1px solid var(--line);padding:10px 6px;vertical-align:top}td.a{font-weight:700;white-space:nowrap;text-align:right}
tr.flag td{background:var(--red-bg);color:var(--red)}.ok{color:var(--teal);font-weight:700}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

_SHIELD = ('<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#0F766E" stroke-width="1.8" stroke-linecap="round" '
           'stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>')


def _patient_page(title: str, clinic: str, inner: str, status: int = 200, with_validate: bool = False) -> HTMLResponse:
    js_tag = '<script src="/form/validate.js" defer></script>' if with_validate else ""
    page = (f"<!doctype html><html lang=tr><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta name=robots content='noindex,nofollow'><title>{html_lib.escape(title)}</title><style>{_PATIENT_CSS}</style></head><body><main>"
            f"<div class=head>{_SHIELD}<div><b>{html_lib.escape(clinic)}</b><small>Güvenli hasta formu</small></div></div>"
            f"<div class=card>{inner}</div><p class=foot>Bilgileriniz şifrelenerek yalnızca hekiminizle paylaşılır.</p>{js_tag}</main></body></html>")
    return HTMLResponse(page, status_code=status)


_FORM_VALIDATE_JS = """document.addEventListener("DOMContentLoaded",function(){
  var f=document.querySelector("form[novalidate]");
  if(!f)return;
  var box=document.getElementById("form-err");
  function clearErr(){
    f.querySelectorAll(".f-err").forEach(function(n){n.remove();});
    f.querySelectorAll(".has-err").forEach(function(n){n.classList.remove("has-err");});
    if(box){box.style.display="none";box.textContent="";}
  }
  function addErr(host,msg){
    var p=document.createElement("p");
    p.className="f-err";
    p.textContent=msg;
    host.classList.add("has-err");
    host.appendChild(p);
  }
  f.addEventListener("change",function(ev){
    var fs=ev.target.closest("fieldset,label");
    if(fs){fs.classList.remove("has-err");fs.querySelectorAll(".f-err").forEach(function(n){n.remove();});}
  });
  f.addEventListener("input",function(ev){
    var p=ev.target.parentElement;
    if(p){p.classList.remove("has-err");p.querySelectorAll(".f-err").forEach(function(n){n.remove();});}
  });
  f.addEventListener("submit",function(e){
    clearErr();
    var first=null;
    f.querySelectorAll("fieldset").forEach(function(fs){
      var reqRadio=fs.querySelector("input[type=radio][required]");
      if(reqRadio && !fs.querySelector("input[type=radio]:checked")){
        addErr(fs,"Lütfen bu soruyu yanıtlayın.");
        if(!first)first=reqRadio;
      }
    });
    f.querySelectorAll("input[required]:not([type=radio]):not([type=checkbox]),textarea[required]").forEach(function(el){
      var v=(el.value||"").trim();
      var ml=parseInt(el.getAttribute("minlength")||"0",10);
      if(!v || (ml && v.length<ml)){
        var msg=el.name==="imza"?"Lütfen adınızı ve soyadınızı yazın (en az 2 karakter).":"Lütfen bu alanı doldurun.";
        addErr(el.parentElement,msg);
        if(!first)first=el;
      }
    });
    f.querySelectorAll("input[type=checkbox][required]").forEach(function(cb){
      if(!cb.checked){
        var lbl=cb.closest("label")||cb.parentElement;
        var p=document.createElement("p");
        p.className="f-err";
        p.textContent="Lütfen zorunlu onay kutusunu işaretleyin.";
        lbl.classList.add("has-err");
        lbl.insertAdjacentElement("afterend",p);
        if(!first)first=cb;
      }
    });
    if(first){
      e.preventDefault();
      if(box){box.textContent="Lütfen işaretlenen eksik alanları tamamlayın.";box.style.display="block";}
      first.scrollIntoView({behavior:"smooth",block:"center"});
      try{first.focus({preventScroll:true});}catch(_){}
    }
  });
});
"""


@app.get("/form/validate.js", include_in_schema=False)
def form_validate_js():
    return Response(_FORM_VALIDATE_JS, media_type="application/javascript; charset=utf-8", headers={"cache-control": "no-store"})


def _anam_token(token: str):
    t = q1("SELECT * FROM anamnesis_tokens WHERE token=? AND used_at IS NULL", token)
    if not t or (t.get("expires_at") and datetime.fromisoformat(t["expires_at"]) < now_utc()):
        return None, None
    c = q1("SELECT c.name FROM patients p JOIN clinics c ON c.id=p.clinic_id WHERE p.id=?", t["patient_id"])
    return t, (c["name"] if c else os.environ.get("CLINIC_NAME", "Kliniğimiz"))


_INVALID_LINK = ("<h1>Bu bağlantı artık geçerli değil</h1><p class=lead>Form daha önce doldurulmuş ya da 48 saatlik süresi dolmuş olabilir. "
                 "Yeni bir bağlantı için lütfen kliniğinizi arayın.</p>"
                 "<a class=btn-back href=\"/\">Kliniğe / Ana Sayfaya Dön</a>")


@app.get("/form/anamnez/{token}", response_class=HTMLResponse)
def anamnez_form(token: str):
    t, clinic = _anam_token(token)
    if not t:
        return _patient_page("Bağlantı geçersiz", os.environ.get("CLINIC_NAME", "Kliniğimiz"), _INVALID_LINK, 400)
    texts = sec.kvkk_texts(clinic)
    rows = "".join(
        f"<fieldset><legend>{i}. {html_lib.escape(q_text)}</legend><div class=opts>"
        f"<label><input type=radio name={k} value=evet required> Evet</label>"
        f"<label><input type=radio name={k} value=hayir> Hayır</label></div></fieldset>"
        for i, (k, q_text, _) in enumerate(ANAMNEZ_SORULAR, 1))
    inner = (
        "<h1>Sağlık Bilgi Formu</h1><p class=lead>Tedaviniz güvenle planlansın diye 11 kısa soru. Yaklaşık 2 dakika sürer.</p>"
        "<div class=note>Emin olmadığınız bir soru varsa \"Evet\" işaretleyin; hekiminiz muayenede sizinle birlikte netleştirir.</div>"
        "<div id=form-err class=err-box role=alert style='display:none'></div>"
        f"<form method=post novalidate>{rows}<div><label class=f for=imza>Adınız ve soyadınız</label>"
        "<input type=text id=imza name=imza required minlength=2 maxlength=80 autocomplete=name></div>"
        f"<div class=note style='margin-top:14px;margin-bottom:8px;display:block'><strong>KVKK Aydınlatma Metni:</strong> {html_lib.escape(texts['aydinlatma'])}</div>"
        "<label class=kvkk><input type=checkbox name=kvkk_aydinlatma value=1 required> Aydınlatma Metni'ni okudum ve anladım.</label>"
        f"<label class=kvkk><input type=checkbox name=saglik_riza value=1 required> {html_lib.escape(texts['saglik'])}</label>"
        f"<label class=kvkk><input type=checkbox name=yurt_disi_riza value=1> {html_lib.escape(texts['yurt_disi'])}</label>"
        "<button type=submit>Onayla ve gönder</button></form>"
    )
    return _patient_page("Sağlık Bilgi Formu", clinic, inner, with_validate=True)


@app.post("/form/anamnez/{token}", response_class=HTMLResponse)
async def anamnez_submit(token: str, request: Request):
    t, clinic = _anam_token(token)
    if not t:
        return _patient_page("Bağlantı geçersiz", os.environ.get("CLINIC_NAME", "Kliniğimiz"), _INVALID_LINK, 400)
    form = dict(await request.form())
    has_ayd = sec.is_checked(form.get("kvkk_aydinlatma"))
    has_saglik = sec.is_checked(form.get("saglik_riza")) or sec.is_checked(form.get("acik_riza"))
    imza = str(form.get("imza", "")).strip()[:80]
    if not (has_ayd and has_saglik and len(imza) >= 2):
        return _patient_page(
            "Onay gerekli",
            clinic,
            "<h1>Aydınlatma ve açık rıza onayı gerekli</h1>"
            "<p class=lead>Formu göndermek için aydınlatma metni ile sağlık verisi açık rıza kutularını işaretleyin ve adınızı soyadınızı yazın. "
            "Geri dönüp tekrar deneyebilirsiniz.</p>"
            "<a class=btn-back href=\"/\">Kliniğe / Ana Sayfaya Dön</a>",
            400,
        )
    ans = {k: str(form.get(k, "")) for k, _, _ in ANAMNEZ_SORULAR}
    flags = [k for k, _, red in ANAMNEZ_SORULAR if red and ans.get(k) == "evet"]
    sig = hashlib.sha256(f"{t['patient_id']}|{imza}".encode()).hexdigest()
    now_s = iso_now()
    with _DB_LOCK:
        c = db()
        cur_t = c.execute("UPDATE anamnesis_tokens SET used_at=? WHERE token=? AND used_at IS NULL", (now_s, token))
        if cur_t.rowcount == 0:
            c.rollback()
            return _patient_page("Bağlantı geçersiz", clinic, _INVALID_LINK, 409)
        c.execute(
            "INSERT INTO anamnesis (patient_id,answers_enc,red_flags_json,signer_name,signature_sha256,signed_at) VALUES (?,?,?,?,?,?)",
            (t["patient_id"], enc(json.dumps(ans)), json.dumps(flags), imza, sig, now_s),
        )
        c.commit()
    texts = sec.kvkk_texts(clinic)
    ex("INSERT INTO consents (patient_id,kind,text_version,text_sha256,channel,granted_at) VALUES (?,?,?,?,?,?)",
       t["patient_id"], "kvkk_aydinlatma", sec.KVKK_METIN_VER, sec.kvkk_sha256(texts["aydinlatma"]), "web_form", now_s)
    ex("INSERT INTO consents (patient_id,kind,text_version,text_sha256,channel,granted_at) VALUES (?,?,?,?,?,?)",
       t["patient_id"], "saglik_verisi_acik_riza", sec.KVKK_METIN_VER, sec.kvkk_sha256(texts["saglik"]), "web_form", now_s)
    if sec.is_checked(form.get("yurt_disi_riza")):
        ex("INSERT INTO consents (patient_id,kind,text_version,text_sha256,channel,granted_at) VALUES (?,?,?,?,?,?)",
           t["patient_id"], "yurt_disi_aktarim", sec.KVKK_METIN_VER, sec.kvkk_sha256(texts["yurt_disi"]), "web_form", now_s)
    if flags:
        p_row = q1("SELECT clinic_id, display_name FROM patients WHERE id=?", t["patient_id"])
        cid_p = int(p_row["clinic_id"]) if p_row and p_row.get("clinic_id") else 1
        pname = (p_row and p_row.get("display_name")) or f"Hasta #{t['patient_id']}"
        ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'anamnez_kirmizi',?,?)",
           cid_p, t["patient_id"], f"KIRMIZI BAYRAK: {pname} (#{t['patient_id']}) anamnezinde {', '.join(flags)} bildirdi.", now_s)
    return _patient_page("Teşekkürler", clinic, "<h1>Formunuz hekiminize ulaştı</h1><p class=lead>Cevaplarınız şifrelenerek kaydedildi. "
                         "Randevunuzda görüşmek üzere. Bu sayfayı kapatabilirsiniz.</p>")


@app.get("/form/geri-bildirim", response_class=HTMLResponse)
def feedback_form():
    import html as _html
    clinic = os.environ.get("CLINIC_NAME", "Özel DentaCore Merkez Polikliniği")
    qs = sign_path("/form/geri-bildirim", 3600).split("?", 1)[1]
    tok = _html.escape(qs, quote=True)
    inner = (
        "<h1>Başhekimliğe Doğrudan İlet</h1>"
        "<p class=lead>Görüşünüz doğrudan başhekime ulaşır.</p>"
        "<div id=form-err class=err-box role=alert style='display:none'></div>"
        "<form method=post novalidate>"
        f"<input type=hidden name=csrf_token value=\"{tok}\">"
        "<div><label class=f for=mesaj>Mesajınız</label>"
        "<textarea id=mesaj name=mesaj rows=5 required maxlength=1500></textarea></div>"
        "<label class=f for=iletisim>Telefon (isteğe bağlı)</label>"
        "<input type=text id=iletisim name=iletisim maxlength=40>"
        "<button type=submit>Gönder</button></form>"
    )
    return _patient_page("Başhekimliğe İlet", clinic, inner, with_validate=True)


@app.post("/form/geri-bildirim", response_class=HTMLResponse)
async def feedback_submit(request: Request):
    clinic = os.environ.get("CLINIC_NAME", "Özel DentaCore Merkez Polikliniği")
    f = dict(await request.form())
    from urllib.parse import parse_qs
    tok_p = parse_qs(str(f.get("csrf_token", "")))
    if not verify_sig("/form/geri-bildirim", (tok_p.get("exp") or [""])[0], (tok_p.get("sig") or [""])[0]):
        raise HTTPException(403, "Form oturumu geçersiz veya süresi dolmuş")
    msg = str(f.get("mesaj", "")).strip()[:1500]
    if not msg:
        return _patient_page(
            "Mesaj gerekli",
            clinic,
            "<h1>Lütfen mesajınızı yazın</h1><p class=lead>Boş geri bildirim gönderilemez. Geri dönüp mesajınızı yazabilirsiniz.</p>"
            "<a class=btn-back href=\"/\">Kliniğe / Ana Sayfaya Dön</a>",
            400,
        )
    ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (1,NULL,'geri_bildirim',?,?)",
       f"Başhekimliğe geri bildirim: {msg[:500]}", iso_now())
    return _patient_page("Teşekkürler", clinic, "<h1>Teşekkür ederiz, mesajınız başhekimliğe iletildi.</h1>")


@app.get("/view/anamnez/{aid}", response_class=HTMLResponse)
def anamnez_view(aid: int, exp: str = "", sig: str = ""):
    if not verify_sig(f"/view/anamnez/{aid}", exp, sig):
        raise HTTPException(403, "bağlantı geçersiz")
    a = q1("SELECT * FROM anamnesis WHERE id=?", aid)
    if not a:
        return HTMLResponse("Bulunamadı", status_code=404)
    ans = json.loads(dec(a["answers_enc"]))
    labels = {k: (q_text, red) for k, q_text, red in ANAMNEZ_SORULAR}
    rows = ""
    for k, v in ans.items():
        q_text, red = labels.get(k, (k, False))
        flag = red and v == "evet"
        shown = "Evet" if v == "evet" else ("Hayır" if v == "hayir" else (v or "-"))
        rows += f"<tr class={'flag' if flag else ''}><td>{html_lib.escape(q_text)}</td><td class=a>{html_lib.escape(shown)}</td></tr>"
    c = q1("SELECT c.name FROM patients p JOIN clinics c ON c.id=p.clinic_id WHERE p.id=?", a["patient_id"])
    nflag = len(json.loads(a.get("red_flags_json") or "[]"))
    summary = f"<p class=lead><b style='color:#B91C1C'>{nflag} kırmızı bayrak</b> işaretli; işlem öncesi değerlendirin.</p>" if nflag else "<p class='lead ok'>Kırmızı bayrak yok.</p>"
    inner = (f"<h1>Anamnez #{aid}</h1><p class=lead>İmzalayan: {html_lib.escape(a.get('signer_name') or '-')} · {html_lib.escape(str(a.get('signed_at') or '')[:16].replace('T', ' '))}</p>"
             f"{summary}<table>{rows}</table>")
    return _patient_page(f"Anamnez #{aid}", c["name"] if c else "Klinik", inner)


@app.get("/app/api/waitlist")
def waitlist(u: dict = Depends(ANY)):
    return q("SELECT w.id, w.treatment, w.earliest, w.created_at, p.display_name AS patient, w.patient_id FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE p.clinic_id=? AND w.active=1", u["clinic_id"])


@app.get("/app/api/waitlist/offers")
def list_waitlist_offers(status: str | None = None, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    sql = """SELECT o.id, o.appointment_id, o.waitlist_id, o.wave, o.sent_at, o.status,
                    w.patient_id, w.treatment AS waitlist_treatment,
                    p.display_name AS patient,
                    a.starts_at, a.treatment, a.chair, a.status AS appointment_status
             FROM slot_offers o
             JOIN waitlist w ON w.id = o.waitlist_id
             JOIN patients p ON p.id = w.patient_id
             JOIN appointments a ON a.id = o.appointment_id
             WHERE p.clinic_id = ? AND a.clinic_id = ?"""
    params: list = [cid, cid]
    if status:
        sql += " AND o.status = ?"
        params.append(status)
    sql += " ORDER BY o.id DESC LIMIT 100"
    return q(sql, *params)


class WaitIn(BaseModel):
    patient_id: int
    treatment: str = Field("herhangi", max_length=80)


@app.post("/app/api/waitlist")
def add_wait(b: WaitIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    with _DB_LOCK:
        _require_active_patient_row(db(), b.patient_id, cid)
    wid = ex("INSERT INTO waitlist (patient_id,treatment,earliest,active,created_at) VALUES (?,?,?,1,?)", b.patient_id, b.treatment, iso_now(), iso_now())
    write_audit(u["id"], u["email"], "waitlist.add", f"patient:{b.patient_id}", u["ip_h"], clinic_id=cid)
    return {"id": wid}


@app.post("/app/api/waitlist/{wid}/remove")
def rm_wait(wid: int, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    w = q1("SELECT w.id FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE w.id=? AND p.clinic_id=?", wid, cid)
    if not w:
        raise HTTPException(404, "bekleme kaydı yok")
    ex("UPDATE waitlist SET active=0 WHERE id=?", wid)
    write_audit(u["id"], u["email"], "waitlist.remove", f"waitlist:{wid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


class OfferRespondIn(BaseModel):
    action: Literal["accept", "reject", "expire"] = "accept"


@app.post("/app/api/waitlist/offers/{oid}/respond")
def respond_slot_offer(oid: int, b: OfferRespondIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    with _DB_LOCK:
        c = db()
        off = c.execute(
            """SELECT o.*, w.patient_id, p.clinic_id FROM slot_offers o
               JOIN waitlist w ON w.id=o.waitlist_id
               JOIN patients p ON p.id=w.patient_id
               WHERE o.id=? AND p.clinic_id=?""",
            (oid, cid),
        ).fetchone()
        if not off:
            raise HTTPException(404, "teklif yok")
        if b.action == "reject":
            c.execute("UPDATE slot_offers SET status='lost' WHERE id=?", (oid,))
            c.commit()
            return {"ok": True, "status": "rejected"}
        if b.action == "expire":
            c.execute("UPDATE slot_offers SET status='expired' WHERE id=?", (oid,))
            c.commit()
            return {"ok": True, "status": "expired"}
        # Atomik slot kapma: yalnızca randevu hâlâ 'cancelled' ise kazanır!
        cur_upd = c.execute(
            "UPDATE appointments SET status='booked', patient_id=? WHERE id=? AND clinic_id=? AND status='cancelled'",
            (off["patient_id"], off["appointment_id"], cid),
        )
        if cur_upd.rowcount == 0:
            c.execute("UPDATE slot_offers SET status='lost' WHERE id=?", (oid,))
            c.commit()
            raise HTTPException(409, "Bu koltuk az önce başka bir hasta tarafından alındı")
        c.execute("UPDATE slot_offers SET status='won' WHERE id=?", (oid,))
        c.execute("UPDATE slot_offers SET status='lost' WHERE appointment_id=? AND id<>? AND status='sent'", (off["appointment_id"], oid))
        c.execute("UPDATE waitlist SET active=0 WHERE id=?", (off["waitlist_id"],))
        c.execute(
            "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'koltuk_dolduruldu',?,?)",
            (cid, off["patient_id"], f"İptal edilen randevu #{off['appointment_id']} bekleme listesinden dolduruldu.", iso_now()),
        )
        c.commit()
    write_audit(u["id"], u["email"], "waitlist.claim_won", f"appointment:{off['appointment_id']}", u["ip_h"], clinic_id=cid)
    return {"ok": True, "status": "won", "appointment_id": off["appointment_id"]}


class PostopSchedIn(BaseModel):
    patient_id: int
    procedure: str = Field(min_length=2, max_length=120)


@app.post("/app/api/postop/schedule")
def schedule_postop_local(b: PostopSchedIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", b.patient_id, cid):
        raise HTTPException(404, "hasta yok")
    t_now = now_utc()
    ids = []
    for stage, hours in (("2s", 2), ("24s", 24), ("72s", 72)):
        due = (t_now + timedelta(hours=hours)).isoformat()
        cid_row = ex("INSERT INTO postop_checks (patient_id,procedure,due_at,stage,sent_at,alarm) VALUES (?,?,?,?,?,0)",
                     b.patient_id, b.procedure, due, stage, t_now.isoformat())
        ids.append(cid_row)
    write_audit(u["id"], u["email"], "postop.schedule", f"patient:{b.patient_id}", u["ip_h"], clinic_id=cid)
    return {"ok": True, "stages": ["2s", "24s", "72s"], "ids": ids}


class PostopReplyIn(BaseModel):
    patient_id: int
    stage: Literal["2s", "24s", "72s"] = "2s"
    pain_score: int = Field(ge=1, le=10)
    emergency: bool = False


@app.post("/app/api/postop/reply")
def reply_postop_local(b: PostopReplyIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    p = q1("SELECT id, display_name FROM patients WHERE id=? AND clinic_id=?", b.patient_id, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    chk = q1("SELECT * FROM postop_checks WHERE patient_id=? AND stage=? ORDER BY id DESC LIMIT 1", b.patient_id, b.stage)
    alarm = bool(b.emergency or b.pain_score >= 8)
    if chk:
        ex("UPDATE postop_checks SET pain_score=?, answered_at=?, alarm=? WHERE id=?",
           b.pain_score, iso_now(), 1 if alarm else 0, chk["id"])
    if alarm:
        ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'postop_alarm',?,?)",
           cid, b.patient_id, f"İŞLEM SONRASI ALARM: {p['display_name']} (#{b.patient_id}), {b.stage} kontrolü, ağrı {b.pain_score}/10", iso_now())
    write_audit(u["id"], u["email"], "postop.reply", f"patient:{b.patient_id}", u["ip_h"], {"score": b.pain_score, "alarm": alarm}, clinic_id=cid)
    return {"ok": True, "alarm": alarm, "pain_score": b.pain_score}


def _extract_campaign_ref(c: sqlite3.Connection, clinic_id: int, text: str) -> dict | None:
    if not text:
        return None
    m = re.search(r"\[?\bref\s*[:=-]\s*([a-zA-Z0-9_-]{2,64})\]?", text, re.IGNORECASE)
    cand = m.group(1).strip() if m else ""
    if not cand:
        for row in c.execute("SELECT * FROM campaigns WHERE clinic_id=? AND COALESCE(is_sample,0)=0 ORDER BY id DESC", (clinic_id,)).fetchall():
            code_v = (row["code"] or "").strip()
            if code_v and len(code_v) >= 4 and re.search(r"\b" + re.escape(code_v) + r"\b", text, re.IGNORECASE):
                return dict(row)
        return None
    row = c.execute(
        "SELECT * FROM campaigns WHERE clinic_id=? AND (LOWER(code)=LOWER(?) OR LOWER(utm_campaign)=LOWER(?)) ORDER BY id DESC LIMIT 1",
        (clinic_id, cand, cand),
    ).fetchone()
    return dict(row) if row else None


async def _process_inbound_webhook_msg(sender: str, profile_name: str | None, mtype: str, text: str, channel: str = "wa", clinic_id: int = 1, payload: str = ""):
    from app.router import detect_lang
    if channel == "wa" and text:
        st_row = q1("SELECT id, clinic_id, role, full_name FROM staff_users WHERE phone_hmac=? AND active=1", phone_hmac(sender))
        if st_row:
            write_audit(st_row["id"], st_row["full_name"], "staff_bot.command", f"wa:{sender[-4:]}", clinic_id=int(st_row["clinic_id"] or 1))
            return

    lang = detect_lang(text) if text else "tr"
    raw_id = f"ig:{sender}" if channel == "ig" else norm_phone(sender)
    ph = hmac.new(_HMAC_KEY, raw_id.encode(), hashlib.sha256).hexdigest() if channel == "ig" else phone_hmac(sender)
    t_now = iso_now()
    default_ch_src = "instagram" if channel == "ig" else "whatsapp"

    with _DB_LOCK:
        c = db()
        camp = _extract_campaign_ref(c, clinic_id, f"{text} {payload}".strip())
        if camp:
            det_src = detect_acquisition_source(
                explicit_source=camp.get("channel") or camp.get("source"),
                utm_source=camp.get("utm_source") or "",
                utm_medium=camp.get("utm_medium") or "",
                default_source=default_ch_src,
            )
            camp_id = int(camp["id"])
            utm_s = (camp.get("utm_source") or det_src)[:80]
            utm_m = (camp.get("utm_medium") or "cpc")[:80]
            utm_c = (camp.get("utm_campaign") or camp.get("code") or "")[:120]
        else:
            det_src = default_ch_src
            camp_id = None
            utm_s, utm_m, utm_c = "", "", ""

        row = c.execute("SELECT id, display_name, first_source, campaign_id FROM patients WHERE clinic_id=? AND phone_hmac=?", (clinic_id, ph)).fetchone()
        if row:
            pid = row["id"]
            if profile_name and not row["display_name"]:
                c.execute("UPDATE patients SET display_name=?, lang=? WHERE id=?", (profile_name, lang, pid))
            if camp_id is not None:
                c.execute(
                    """UPDATE patients
                       SET last_source=?,
                           campaign_id=COALESCE(campaign_id, ?),
                           utm_source=CASE WHEN utm_source='' AND ?<>'' THEN ? ELSE utm_source END,
                           utm_medium=CASE WHEN utm_medium='' AND ?<>'' THEN ? ELSE utm_medium END,
                           utm_campaign=CASE WHEN utm_campaign='' AND ?<>'' THEN ? ELSE utm_campaign END
                       WHERE id=? AND clinic_id=?""",
                    (det_src, camp_id, utm_s, utm_s, utm_m, utm_m, utm_c, utm_c, pid, clinic_id),
                )
            else:
                c.execute("UPDATE patients SET last_source=? WHERE id=? AND clinic_id=?", (default_ch_src, pid, clinic_id))
        else:
            cur_p = c.execute(
                """INSERT INTO patients
                   (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,first_source,last_source,campaign_id,utm_source,utm_medium,utm_campaign,active,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
                (clinic_id, ph, enc(raw_id), profile_name or f"Misafir ({sender[-4:]})", lang, channel, det_src, det_src, camp_id, utm_s, utm_m, utm_c, t_now),
            )
            pid = cur_p.lastrowid
        if camp_id is not None:
            has_ev = c.execute(
                "SELECT 1 FROM campaign_events WHERE clinic_id=? AND campaign_id=? AND patient_id=? AND event_type='patient_created' LIMIT 1",
                (clinic_id, camp_id, pid),
            ).fetchone()
            if not has_ev:
                c.execute(
                    """INSERT INTO campaign_events
                       (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,is_bot,is_unique,patient_id,created_at)
                       VALUES (?,?,'patient_created',?,?,?,?,0,1,?,?)""",
                    (clinic_id, camp_id, det_src, utm_s, utm_m, utm_c, pid, t_now),
                )
                c.execute("UPDATE campaigns SET conversations = conversations + 1 WHERE id=? AND clinic_id=?", (camp_id, clinic_id))
        raw_body = (text or payload)[:2000]
        c.execute(
            "INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,body,delivery_status,created_at) VALUES (?,?,'in',NULL,?,0,0,?,'received',?)",
            (clinic_id, pid, f"{channel}:{mtype}", enc(raw_body) if raw_body else "", t_now),
        )
        c.commit()

    if not text and not payload:
        return

    handled = await _handle_patient_reply(clinic_id, pid, text, channel=channel, payload=payload)
    if handled:
        ans, layer, intent = handled
        await _deliver_wa(clinic_id, pid, raw_id, ans, layer=layer, intent=intent)
        write_audit(None, f"{channel}_webhook", f"webhook.{channel}", f"patient:{pid}", meta={"intent": intent, "layer": layer}, clinic_id=clinic_id)
        return

    c_row = q1("SELECT name, address, phone, ai_custom_rules_json FROM clinics WHERE id=?", clinic_id)
    all_branches = q("SELECT id, name, city, address, phone FROM clinics WHERE active=1")
    facts: dict = {
        "clinic": (c_row and c_row["name"]) or os.environ.get("CLINIC_NAME", "Özel DentaCore Merkez Polikliniği"),
        "branches": all_branches,
    }
    if c_row and c_row.get("address"):
        facts["adres"] = c_row["address"]
    if c_row and c_row.get("phone"):
        facts["telefon"] = c_row["phone"]
    if c_row and c_row.get("ai_custom_rules_json"):
        facts["ai_custom_rules_json"] = c_row["ai_custom_rules_json"]

    allow_llm = _has_consent(pid, "yurt_disi_aktarim")
    try:
        res = await asyncio.wait_for(_ROUTER.route(text, lang=lang, clinic_facts=facts, allow_llm=allow_llm, patient_id=pid), timeout=10.0)
    except Exception:
        res = await _ROUTER.route(text, lang=lang, clinic_facts=facts, allow_llm=False, patient_id=pid)

    await _deliver_wa(
        clinic_id, pid, raw_id, res.answer,
        layer=res.layer, intent=res.intent, tokens_in=res.tokens_in, tokens_out=res.tokens_out,
    )
    if res.alert == "acil":
        ex(
            "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'acil',?,?)",
            clinic_id, pid, f"ACİL MESAJ: {profile_name or 'Hasta'} (#{pid}) acil belirti bildirdi: {text[:160]}", iso_now(),
        )
    elif res.alert == "sikayet":
        ex(
            "INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'sikayet',?,?)",
            clinic_id, pid, f"ŞİKAYET: {profile_name or 'Hasta'} (#{pid}) memnuniyetsizlik bildirdi: {text[:160]}", iso_now(),
        )
    write_audit(None, f"{channel}_webhook", f"webhook.{channel}", f"patient:{pid}", meta={"intent": res.intent, "layer": res.layer}, clinic_id=clinic_id)


def _resolve_webhook_clinic(channel: str, channel_id: str) -> int | None:
    if not channel_id:
        # P0-9: Kanal kimliği boş mesaj artık otomatik Merkez kliniğe (1) atanmaz.
        # Tek aktif klinik varsa ona gider; çok şubede eşlenemeyen mesaj reddedilir (tenant karışması önlenir).
        rows = q("SELECT id FROM clinics WHERE active=1 LIMIT 2")
        return int(rows[0]["id"]) if len(rows) == 1 else None
    if channel == "wa":
        row = q1("SELECT id FROM clinics WHERE wa_phone_id=? AND active=1 LIMIT 1", channel_id)
    else:
        row = q1("SELECT id FROM clinics WHERE ig_handle=? AND active=1 LIMIT 1", channel_id)
    if row:
        return int(row["id"])
    log.error("Eşleşmeyen webhook kanalı: channel=%s id=%s", channel, channel_id or "<boş>")
    write_audit(
        None,
        f"{channel}_webhook",
        "webhook.unmapped_clinic",
        f"{channel}:{channel_id or 'missing'}",
        meta={"channel": channel, "channel_id": channel_id[:80]},
        clinic_id=1,
    )
    return None


@app.post("/webhook/whatsapp")
@app.post("/webhooks/whatsapp")
async def wa_webhook_local(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    raw = await request.body()
    secret = os.environ.get("WA_APP_SECRET", "")
    if not secret or not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256="):
        raise HTTPException(401, "imza geçersiz")
    good = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, x_hub_signature_256[7:]):
        raise HTTPException(401, "imza geçersiz")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Geçersiz JSON gövdesi")
    processed = 0
    dedup = 0
    unmapped = 0
    for entry in body.get("entry", []):
        for ch in entry.get("changes", []):
            v = ch.get("value", {})
            phone_number_id = str((v.get("metadata") or {}).get("phone_number_id") or "").strip()
            clinic_id = _resolve_webhook_clinic("wa", phone_number_id)
            if not clinic_id:
                unmapped += len(v.get("messages", [])) or 1
                continue
            names = {c.get("wa_id"): (c.get("profile") or {}).get("name") for c in v.get("contacts", []) if isinstance(c, dict)}
            for m in v.get("messages", []):
                mid = str(m.get("id") or "")
                if mid and _SEEN_WEBHOOK_IDS.seen_or_add(mid):
                    dedup += 1
                    continue
                sender = str(m.get("from") or "")
                mtype = str(m.get("type") or "text")
                text = ""
                payload = ""
                if mtype == "text":
                    text = str((m.get("text") or {}).get("body") or "")
                elif mtype == "button":
                    text = str((m.get("button") or {}).get("text") or "")
                    payload = str((m.get("button") or {}).get("payload") or "")
                elif mtype == "interactive":
                    it = m.get("interactive") or {}
                    rep = it.get("button_reply") or it.get("list_reply") or {}
                    text = str(rep.get("title") or "")
                    payload = str(rep.get("id") or "")
                if sender:
                    await _process_inbound_webhook_msg(sender, names.get(sender), mtype, text, channel="wa", clinic_id=clinic_id, payload=payload)
                processed += 1
    return {"ok": True, "processed": processed, "dedup": dedup, "unmapped": unmapped}


@app.post("/webhook/instagram")
@app.post("/webhooks/instagram")
async def ig_webhook_local(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    raw = await request.body()
    secret = os.environ.get("IG_APP_SECRET") or os.environ.get("WA_APP_SECRET", "")
    if not secret or not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256="):
        raise HTTPException(401, "imza geçersiz")
    good = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, x_hub_signature_256[7:]):
        raise HTTPException(401, "imza geçersiz")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(400, "Geçersiz JSON gövdesi")
    processed = 0
    dedup = 0
    unmapped = 0
    for entry in body.get("entry", []):
        entry_id = str(entry.get("id") or "").strip()
        for ev in entry.get("messaging", []):
            msg = ev.get("message") or {}
            if msg.get("is_echo") or not msg.get("text"):
                continue
            ig_target = str((ev.get("recipient") or {}).get("id") or entry_id).strip()
            clinic_id = _resolve_webhook_clinic("ig", ig_target)
            if not clinic_id:
                unmapped += 1
                continue
            mid = str(msg.get("mid") or "")
            if mid and _SEEN_WEBHOOK_IDS.seen_or_add(mid):
                dedup += 1
                continue
            sender = str((ev.get("sender") or {}).get("id") or "")
            if sender:
                await _process_inbound_webhook_msg(sender, None, "text", str(msg["text"]), channel="ig", clinic_id=clinic_id)
                processed += 1
    return {"ok": True, "processed": processed, "dedup": dedup, "unmapped": unmapped}


@app.get("/app/api/alerts")
def alerts(u: dict = Depends(ANY)):
    rows = q("SELECT id, patient_id, kind, detail, created_at FROM alerts WHERE clinic_id=? AND acknowledged_at IS NULL ORDER BY id DESC", u["clinic_id"])
    if u["role"] not in ("owner", "doctor"):
        for r in rows:
            if r.get("kind") in ("anamnez_kirmizi", "postop_alarm", "acil"):
                r["detail"] = "Klinik Uyarı (Hekim Kontrolü)"
    return rows


@app.post("/app/api/alerts/{aid}/ack")
def ack(aid: int, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    if not q1("SELECT id FROM alerts WHERE id=? AND clinic_id=? AND acknowledged_at IS NULL", aid, cid):
        raise HTTPException(404, "uyarı yok")
    ex("UPDATE alerts SET acknowledged_at=? WHERE id=? AND clinic_id=?", iso_now(), aid, cid)
    write_audit(u["id"], u["email"], "alert.ack", f"alert:{aid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.get("/app/api/inventory")
def inventory(u: dict = Depends(require_perm("inventory_manage"))):
    rows = q("SELECT * FROM inventory_items WHERE clinic_id=? AND active=1 ORDER BY id", u["clinic_id"])
    today_iso = datetime.now(TZ).date().isoformat()
    for r in rows:
        r["unit_cost"] = tl(r.pop("unit_cost_kurus"))
        r["value"] = round(r["qty"] * r["unit_cost"], 2)
        r["low"] = bool(r["min_qty"] > 0 and r["qty"] <= r["min_qty"])
        exp = (r.get("expiry_date") or "").strip()
        r["expired"] = bool(exp and exp < today_iso)
    return rows


class ItemIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    sku: str | None = Field(default=None, max_length=40)
    category: str = Field("Sarf Malzeme", max_length=60)
    unit: str = Field("adet", max_length=16)
    qty: Decimal = Field(Decimal(0), ge=0, le=1_000_000)
    min_qty: Decimal = Field(Decimal(0), ge=0, le=1_000_000)
    unit_cost: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    supplier: str = Field("", max_length=120)
    expiry_date: str = Field("", max_length=20)
    lot_number: str = Field("", max_length=60)
    warehouse: str = Field("Ana Depo", max_length=60)


@app.post("/app/api/inventory")
def add_item(b: ItemIn, u: dict = Depends(require_perm("inventory_manage"))):
    exp_d = b.expiry_date.strip()
    if exp_d:
        try:
            date.fromisoformat(exp_d[:10])
        except ValueError:
            raise HTTPException(422, "Geçersiz son kullanma tarihi (YYYY-MM-DD formatında olmalıdır)")
    t_now = iso_now()
    iid = ex(
        """INSERT INTO inventory_items
           (clinic_id,name,sku,category,unit,qty,min_qty,unit_cost_kurus,supplier,expiry_date,lot_number,warehouse,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        u["clinic_id"], b.name.strip(), b.sku, b.category.strip(), b.unit.strip(),
        float(b.qty), float(b.min_qty), kurus(b.unit_cost),
        b.supplier.strip(), exp_d[:10] if exp_d else "", b.lot_number.strip(), b.warehouse.strip() or "Ana Depo", t_now,
    )
    if b.qty > 0:
        ex(
            "INSERT INTO stock_moves (item_id,delta,qty_after,reason,move_type,lot_number,actor_id,created_at) VALUES (?,?,?,'ilk stok','in',?,?,?)",
            iid, float(b.qty), float(b.qty), b.lot_number.strip(), u["id"], t_now,
        )
    return {"id": iid}


class MoveIn(BaseModel):
    delta: Decimal = Field(ge=-1_000_000, le=1_000_000)
    reason: str = Field(min_length=2, max_length=120)
    move_type: Literal["in", "out", "wastage", "return", "transfer"] | None = None
    lot_number: str = Field("", max_length=60)

    @field_validator("delta")
    @classmethod
    def nonzero(cls, v):
        if v == 0:
            raise ValueError("miktar sıfır olamaz")
        return v


@app.post("/app/api/inventory/{iid}/move")
def move_item(iid: int, b: MoveIn, u: dict = Depends(require_perm("inventory_manage"))):
    cid = u["clinic_id"]
    delta_f = float(b.delta)
    m_type = b.move_type or ("in" if delta_f > 0 else "out")
    if m_type in ("out", "wastage") and delta_f > 0:
        delta_f = -abs(delta_f)
    with _DB_LOCK:
        c = db()
        it = c.execute("SELECT * FROM inventory_items WHERE id=? AND clinic_id=? AND active=1", (iid, cid)).fetchone()
        if not it:
            raise HTTPException(404, "ürün yok")
        if float(it["qty"]) + delta_f < 0:
            raise HTTPException(409, "Stok yetersiz")
        new_qty = round(float(it["qty"]) + delta_f, 4)
        cur_u = c.execute(
            "UPDATE inventory_items SET qty=? WHERE id=? AND clinic_id=? AND active=1 AND qty + ? >= 0",
            (new_qty, iid, cid, delta_f),
        )
        if cur_u.rowcount == 0:
            raise HTTPException(409, "Stok yetersiz")
        c.execute(
            "INSERT INTO stock_moves (item_id,delta,qty_after,reason,move_type,lot_number,actor_id,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (iid, delta_f, new_qty, b.reason, m_type, b.lot_number.strip() or (it["lot_number"] or ""), u["id"], iso_now()),
        )
        if new_qty <= float(it["min_qty"]) and float(it["min_qty"]) > 0:
            c.execute(
                "INSERT INTO alerts (clinic_id,kind,detail,created_at) VALUES (?,'stok_kritik',?,?)",
                (cid, f"Stok kritik: {it['name']} ({new_qty} {it['unit']})", iso_now()),
            )
        c.commit()
    write_audit(u["id"], u["email"], "inventory.move", f"item:{iid}", u["ip_h"], {"delta": str(delta_f), "move_type": m_type}, clinic_id=cid)
    return {"ok": True, "qty": new_qty, "move_type": m_type}


class StockTransferIn(BaseModel):
    target_clinic_id: int
    qty: Decimal = Field(gt=0, le=1_000_000)
    reason: str = Field("Şubeler arası transfer", min_length=2, max_length=120)


@app.post("/app/api/inventory/{iid}/transfer")
def transfer_item(iid: int, b: StockTransferIn, u: dict = Depends(HQ_OWNER)):
    cid = u["clinic_id"]
    if b.target_clinic_id == cid:
        raise HTTPException(400, "Hedef şube kaynak şubeyle aynı olamaz")
    qty_f = float(b.qty)
    t_now = iso_now()
    with _DB_LOCK:
        c = db()
        if not c.execute("SELECT id FROM clinics WHERE id=? AND active=1", (b.target_clinic_id,)).fetchone():
            raise HTTPException(404, "hedef şube yok")
        src = c.execute("SELECT * FROM inventory_items WHERE id=? AND clinic_id=? AND active=1", (iid, cid)).fetchone()
        if not src:
            raise HTTPException(404, "ürün yok")
        if float(src["qty"]) < qty_f:
            raise HTTPException(409, "Transfer için stok yetersiz")
        new_src_qty = round(float(src["qty"]) - qty_f, 4)
        c.execute("UPDATE inventory_items SET qty=? WHERE id=? AND clinic_id=?", (new_src_qty, iid, cid))
        c.execute("INSERT INTO stock_moves (item_id,delta,qty_after,reason,move_type,actor_id,created_at) VALUES (?,?,?,?,?,?,?)",
                  (iid, -qty_f, new_src_qty, f"Transfer -> Şube #{b.target_clinic_id}: {b.reason}", "transfer", u["id"], t_now))
        dst = c.execute("SELECT * FROM inventory_items WHERE clinic_id=? AND name=? AND active=1", (b.target_clinic_id, src["name"])).fetchone()
        if dst:
            new_dst_qty = round(float(dst["qty"]) + qty_f, 4)
            c.execute("UPDATE inventory_items SET qty=? WHERE id=?", (new_dst_qty, dst["id"]))
            dst_id = dst["id"]
        else:
            cur_d = c.execute(
                """INSERT INTO inventory_items
                   (clinic_id,name,sku,category,unit,qty,min_qty,unit_cost_kurus,supplier,expiry_date,lot_number,warehouse,active,created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)""",
                (
                    b.target_clinic_id, src["name"], src["sku"], src["category"] or "Sarf Malzeme", src["unit"],
                    qty_f, src["min_qty"], src["unit_cost_kurus"], src["supplier"] or "",
                    src["expiry_date"] or "", src["lot_number"] or "", src["warehouse"] or "Ana Depo", t_now,
                ),
            )
            dst_id = cur_d.lastrowid
            new_dst_qty = qty_f
        c.execute("INSERT INTO stock_moves (item_id,delta,qty_after,reason,move_type,actor_id,created_at) VALUES (?,?,?,?,?,?,?)",
                  (dst_id, qty_f, new_dst_qty, f"Transfer <- Şube #{cid}: {b.reason}", "transfer", u["id"], t_now))
        c.commit()
    write_audit(u["id"], u["email"], "inventory.transfer", f"item:{iid}->clinic:{b.target_clinic_id}", u["ip_h"], {"qty": qty_f}, clinic_id=cid)
    return {"ok": True, "src_qty": new_src_qty, "dst_item_id": dst_id, "dst_qty": new_dst_qty}


@app.get("/app/api/inventory/{iid}/moves")
def item_moves(iid: int, u: dict = Depends(require_perm("inventory_manage"))):
    if not q1("SELECT id FROM inventory_items WHERE id=? AND clinic_id=?", iid, u["clinic_id"]):
        raise HTTPException(404, "ürün yok")
    return q("SELECT m.*, s.full_name AS actor FROM stock_moves m LEFT JOIN staff_users s ON s.id=m.actor_id WHERE m.item_id=? ORDER BY m.id DESC", iid)


class ChargeIn(BaseModel):
    patient_id: int
    description: str = Field(min_length=2, max_length=120)
    amount: Decimal = Field(gt=0, le=10_000_000)
    discount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    bank_agreement_id: int | None = None
    use_patient_bank_agreement: bool = False
    discount_reason: str = Field("", max_length=200)
    doctor_id: int | None = None
    idempotency_key: str | None = Field(default=None, max_length=80)
    allow_duplicate: bool = False


@app.post("/app/api/charges")
async def add_charge(b: ChargeIn, u: dict = Depends(require_perm("finance_edit"))):
    if not await _LIMITER.hit(f"chg:{u['id']}", 60, 60):
        raise HTTPException(429, "Çok fazla hizmet ekleme isteği")
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, b.patient_id, u)
    with _DB_LOCK:
        c = db()
        p_row = _require_active_patient_row(c, b.patient_id, cid)
        if b.doctor_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.doctor_id, cid)).fetchone():
            raise HTTPException(404, "hekim yok")
        eff_bank_id = b.bank_agreement_id if b.bank_agreement_id is not None else (p_row["bank_agreement_id"] if b.use_patient_bank_agreement else None)
        bank_row = c.execute("SELECT * FROM bank_agreements WHERE id=? AND clinic_id=? AND active=1", (eff_bank_id, cid)).fetchone() if eff_bank_id else None
        if bank_row:
            calc = compute_bank_discount(
                gross_kurus=kurus(b.amount),
                agreement=dict(bank_row),
                procedure_name=b.description,
                manual_discount_kurus=kurus(b.discount),
            )
            gross_k = int(calc["gross_kurus"])
            disc_k = int(calc["total_discount_kurus"])
            net_k = int(calc["net_kurus"])
            disc_reason = b.discount_reason.strip() or (str(calc.get("explanation") or "") if disc_k > 0 else "")
            used_bank_id = int(bank_row["id"]) if calc.get("eligible") else None
        else:
            net_amount = b.amount - b.discount
            if net_amount <= 0:
                raise HTTPException(400, "İndirim sonrası tutar sıfırdan büyük olmalıdır")
            gross_k = kurus(b.amount)
            disc_k = kurus(b.discount)
            net_k = kurus(net_amount)
            disc_reason = b.discount_reason.strip()
            used_bank_id = None
        if net_k <= 0:
            raise HTTPException(400, "İndirim sonrası tutar sıfırdan büyük olmalıdır")
        desc_suffix = f" ({disc_reason})" if (disc_k > 0 and disc_reason) else (f" (İndirim: {tl(disc_k):.2f} TL)" if disc_k > 0 else "")
        desc = f"{b.description}{desc_suffix}"[:120]
        if b.idempotency_key:
            dup = c.execute("SELECT id FROM charges WHERE clinic_id=? AND idempotency_key=?", (cid, b.idempotency_key)).fetchone()
            if dup:
                raise HTTPException(409, "Bu hizmet borçlandırması zaten işlendi (mükerrer işlem engellendi)")
        elif not b.allow_duplicate:
            cutoff_iso = (now_utc() - timedelta(seconds=15)).isoformat()
            recent_dup = c.execute(
                """SELECT id FROM charges WHERE clinic_id=? AND patient_id=? AND description=? AND amount_kurus=?
                   AND COALESCE(doctor_id,0)=COALESCE(?,0) AND voided_at IS NULL AND created_at >= ? LIMIT 1""",
                (cid, b.patient_id, desc, net_k, b.doctor_id, cutoff_iso),
            ).fetchone()
            if recent_dup:
                raise HTTPException(409, "Aynı hizmet borcu az önce eklendi (çift tıklama / mükerrer borç engellendi)")
        try:
            cur_ch = c.execute(
                """INSERT INTO charges
                   (clinic_id,patient_id,description,amount_kurus,gross_amount_kurus,discount_kurus,
                    bank_agreement_id,discount_reason,doctor_id,created_by,created_at,idempotency_key)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cid, b.patient_id, desc, net_k, gross_k, disc_k, used_bank_id, disc_reason, b.doctor_id, u["id"], iso_now(), b.idempotency_key),
            )
            cid_id = cur_ch.lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Mükerrer hizmet borçlandırması engellendi")
    write_audit(u["id"], u["email"], "kasa.charge", f"charge:{cid_id}", u["ip_h"],
                {"gross_kurus": gross_k, "discount_kurus": disc_k, "kurus": net_k, "bank_agreement_id": used_bank_id}, clinic_id=cid)
    return {
        "id": cid_id,
        "gross_kurus": gross_k,
        "discount_kurus": disc_k,
        "net_kurus": net_k,
        "gross_amount": tl(gross_k),
        "discount_amount": tl(disc_k),
        "net_amount": tl(net_k),
        "bank_agreement_id": used_bank_id,
    }


class PaymentIn(BaseModel):
    patient_id: int
    amount: Decimal = Field(gt=0, le=10_000_000)
    method: Literal["nakit", "kart", "kredi_karti", "banka_karti", "havale", "taksitli", "avans_mahsup", "diger"]
    status: Literal["completed", "pending", "failed"] = "completed"
    doctor_id: int | None = None
    applied_charge_id: int | None = None
    note: str = Field("", max_length=240)
    idempotency_key: str | None = Field(default=None, max_length=80)
    allow_advance: bool = False


@app.post("/app/api/payments")
async def add_payment(b: PaymentIn, u: dict = Depends(require_perm("finance_edit"))):
    if not await _LIMITER.hit(f"pay:{u['id']}", 60, 60):
        raise HTTPException(429, "Çok fazla tahsilat isteği")
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, b.patient_id, u)
    amt_k = kurus(b.amount)
    with _DB_LOCK:
        c = db()
        _require_active_patient_row(c, b.patient_id, cid)
        if b.doctor_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.doctor_id, cid)).fetchone():
            raise HTTPException(404, "Seçilen hekim bu klinikte bulunamadı")
        if b.applied_charge_id is not None and not c.execute("SELECT id FROM charges WHERE id=? AND clinic_id=? AND patient_id=? AND voided_at IS NULL", (b.applied_charge_id, cid, b.patient_id)).fetchone():
            raise HTTPException(404, "İlişkili hizmet borcu bu hasta/klinik için bulunamadı")
        if b.idempotency_key:
            dup = c.execute("SELECT id FROM payments WHERE clinic_id=? AND idempotency_key=?", (cid, b.idempotency_key)).fetchone()
            if dup:
                raise HTTPException(409, "Bu ödeme zaten işlendi (mükerrer işlem engellendi)")
        fin_before = ent.compute_patient_finance_summary(c, cid, b.patient_id, tl)
        rem_debt_k = kurus(fin_before["net_remaining_debt"])
        is_adv = 0
        if b.status == "completed" and amt_k > rem_debt_k:
            if not b.allow_advance:
                raise HTTPException(
                    422,
                    f"Hastanın açık bakiyesi {tl(rem_debt_k):.2f} TL; bakiye üstü tahsilat için avans onayı (allow_advance=true) gereklidir",
                )
            is_adv = 1
        try:
            cur_p = c.execute(
                """INSERT INTO payments
                   (clinic_id,patient_id,amount_kurus,method,status,doctor_id,is_advance,applied_charge_id,note,created_by,created_at,idempotency_key)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cid, b.patient_id, amt_k, b.method, b.status, b.doctor_id, is_adv, b.applied_charge_id, b.note.strip(), u["id"], iso_now(), b.idempotency_key),
            )
            pid_id = cur_p.lastrowid
            c.commit()
            fin_after = ent.compute_patient_finance_summary(c, cid, b.patient_id, tl)
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Mükerrer ödeme engellendi")
    write_audit(u["id"], u["email"], "kasa.payment", f"payment:{pid_id}", u["ip_h"],
                {"kurus": amt_k, "status": b.status, "method": b.method, "is_advance": bool(is_adv)}, clinic_id=cid)
    return {"id": pid_id, "status": b.status, "is_advance": bool(is_adv), "finance_summary": fin_after}


class VoidIn(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


@app.post("/app/api/{kind}/{eid}/void")
def void_entry(kind: Literal["charges", "payments"], eid: int, b: VoidIn, u: dict = Depends(require_perm("finance_view", "finance_edit", "delete_cancel"))):
    cid = u["clinic_id"]
    sel_sql = (
        "SELECT id FROM charges WHERE id=? AND clinic_id=? AND voided_at IS NULL"
        if kind == "charges"
        else "SELECT id FROM payments WHERE id=? AND clinic_id=? AND voided_at IS NULL"
    )
    if not q1(sel_sql, eid, cid):
        raise HTTPException(404, "kayıt yok veya zaten iptal")
    upd_sql = (
        "UPDATE charges SET voided_at=?, void_reason=? WHERE id=? AND clinic_id=? AND voided_at IS NULL"
        if kind == "charges"
        else "UPDATE payments SET voided_at=?, void_reason=? WHERE id=? AND clinic_id=? AND voided_at IS NULL"
    )
    ex(upd_sql, iso_now(), b.reason, eid, cid)
    write_audit(u["id"], u["email"], f"kasa.void_{kind}", f"{kind}:{eid}", u["ip_h"], {"reason": b.reason}, clinic_id=cid)
    return {"ok": True}


@app.get("/app/api/kasa")
def kasa(start: datetime | None = None, end: datetime | None = None, u: dict = Depends(require_perm("finance_view"))):
    cid = u["clinic_id"]
    now_loc = datetime.now(TZ)
    s_raw = start or now_loc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    e_raw = end or (now_loc + timedelta(days=1))
    s_dt = s_raw if s_raw.tzinfo else s_raw.replace(tzinfo=TZ)
    e_dt = e_raw if e_raw.tzinfo else e_raw.replace(tzinfo=TZ)
    if s_dt > e_dt:
        raise HTTPException(422, "Başlangıç tarihi bitiş tarihinden büyük olamaz")
    ch_all = q("SELECT c.*, p.display_name AS patient FROM charges c JOIN patients p ON p.id=c.patient_id WHERE c.clinic_id=? ORDER BY c.id DESC", cid)
    py_all = q("SELECT y.*, p.display_name AS patient FROM payments y JOIN patients p ON p.id=y.patient_id WHERE y.clinic_id=? ORDER BY y.id DESC", cid)
    odo_planned_all = q(
        "SELECT amount_kurus, created_at FROM tooth_records WHERE clinic_id=? AND status IN ('planned','caries','extraction')",
        cid,
    )

    def _in_range(iso: str) -> bool:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ)
        return s_dt <= dt < e_dt

    ch = [x for x in ch_all if _in_range(x["created_at"])]
    py = [x for x in py_all if _in_range(x["created_at"])]
    odo_p = [x for x in odo_planned_all if _in_range(x["created_at"])]

    planned_k = sum(int(x["amount_kurus"] or 0) for x in odo_p)
    active_ch = [x for x in ch if not x["voided_at"]]
    billed = sum(int(x["amount_kurus"] or 0) for x in active_ch)
    discount_k = sum(int(x.get("discount_kurus") or 0) for x in active_ch)
    gross_k = sum(int(x.get("gross_amount_kurus") or (int(x["amount_kurus"] or 0) + int(x.get("discount_kurus") or 0))) for x in active_ch)

    active_py = [x for x in py if not x["voided_at"]]
    # Yalnız status='completed' tahsilata dahil edilir; pending ve failed borçtan düşülmez!
    paid = sum(int(x["amount_kurus"] or 0) for x in active_py if (x.get("status") or "completed") == "completed" and x["method"] != "avans_mahsup")
    pending_k = sum(int(x["amount_kurus"] or 0) for x in active_py if x.get("status") == "pending")
    failed_k = sum(int(x["amount_kurus"] or 0) for x in active_py if x.get("status") == "failed")
    refunded_k = sum(int(x["amount_kurus"] or 0) for x in active_py if x.get("status") == "refunded")

    total_billed = sum(int(x["amount_kurus"] or 0) for x in ch_all if not x["voided_at"])
    total_paid = sum(
        int(x["amount_kurus"] or 0)
        for x in py_all
        if not x["voided_at"] and (x.get("status") or "completed") == "completed" and x["method"] != "avans_mahsup"
    )
    total_refunded = sum(int(x["amount_kurus"] or 0) for x in py_all if not x["voided_at"] and x.get("status") == "refunded")
    net_total_paid = max(0, total_paid - total_refunded)

    # Hasta bazlı açık borç ve kullanılabilir avans toplamı
    by_pid_ch: dict[int, int] = {}
    by_pid_py: dict[int, int] = {}
    for x in ch_all:
        if not x["voided_at"]:
            by_pid_ch[int(x["patient_id"])] = by_pid_ch.get(int(x["patient_id"]), 0) + int(x["amount_kurus"] or 0)
    for x in py_all:
        if not x["voided_at"]:
            st = x.get("status") or "completed"
            if st == "completed" and x["method"] != "avans_mahsup":
                by_pid_py[int(x["patient_id"])] = by_pid_py.get(int(x["patient_id"]), 0) + int(x["amount_kurus"] or 0)
            elif st == "refunded":
                by_pid_py[int(x["patient_id"])] = by_pid_py.get(int(x["patient_id"]), 0) - int(x["amount_kurus"] or 0)
    all_pids = set(by_pid_ch.keys()) | set(by_pid_py.keys())
    total_remaining_debt_k = sum(max(0, by_pid_ch.get(p_i, 0) - max(0, by_pid_py.get(p_i, 0))) for p_i in all_pids)
    total_advance_k = sum(max(0, max(0, by_pid_py.get(p_i, 0)) - by_pid_ch.get(p_i, 0)) for p_i in all_pids)

    methods: dict[str, int] = {}
    for x in active_py:
        if (x.get("status") or "completed") == "completed" and x["method"] != "avans_mahsup":
            methods[x["method"]] = methods.get(x["method"], 0) + int(x["amount_kurus"] or 0)
    entries = [
        {
            "type": "hizmet", "id": x["id"], "created_at": x["created_at"], "patient": x["patient"],
            "patient_id": x["patient_id"], "info": x["description"],
            "gross_amount": tl(int(x.get("gross_amount_kurus") or x["amount_kurus"])),
            "discount": tl(int(x.get("discount_kurus") or 0)),
            "amount": tl(x["amount_kurus"]), "status": "completed", "voided_at": x["voided_at"],
        }
        for x in ch
    ]
    entries += [
        {
            "type": "iade" if x.get("status") == "refunded" else "tahsilat",
            "id": x["id"], "created_at": x["created_at"], "patient": x["patient"],
            "patient_id": x["patient_id"],
            "info": f"{x['method']} ({x.get('status') or 'completed'})",
            "method": x["method"],
            "status": x.get("status") or "completed",
            "is_advance": bool(x.get("is_advance")),
            "amount": tl(x["amount_kurus"]), "voided_at": x["voided_at"],
        }
        for x in py
    ]
    entries.sort(key=lambda x: x["created_at"], reverse=True)
    shares = []
    if u["role"] == "owner":
        for d in q("SELECT id, full_name, share_pct FROM staff_users WHERE clinic_id=? AND role IN ('owner','doctor') AND active=1", cid):
            dbilled = sum(int(x["amount_kurus"] or 0) for x in active_ch if x["doctor_id"] == d["id"])
            owned_cnt = q1("SELECT count(*) AS n FROM patients WHERE clinic_id=? AND primary_doctor_id=?", cid, d["id"])["n"]
            shares.append({
                "doctor_id": d["id"],
                "full_name": d["full_name"],
                "share_pct": d["share_pct"],
                "owned_patients_count": owned_cnt,
                "billed": tl(dbilled),
                "share_try": tl(int(dbilled * d["share_pct"] / 100)),
            })
    exp_all = q("SELECT amount_kurus, paid_at, voided_at FROM expenses WHERE clinic_id=?", cid)
    expenses_k = sum(int(e["amount_kurus"] or 0) for e in exp_all if not e.get("voided_at") and _in_range(e["paid_at"]))
    net_paid_range_k = max(0, paid - refunded_k)
    net_cash_flow_k = net_paid_range_k - expenses_k
    return {
        "planned_total": tl(planned_k),
        "completed_gross": tl(gross_k),
        "gross_billed": tl(gross_k),
        "discount_total": tl(discount_k),
        "billed": tl(billed),
        "completed_net_debt": tl(billed),
        "paid": tl(paid),
        "collected_paid": tl(paid),
        "pending_payment": tl(pending_k),
        "failed_payment": tl(failed_k),
        "refunded_total": tl(refunded_k),
        "net_paid_after_refund": tl(net_paid_range_k),
        "expenses_total": tl(expenses_k),
        "net_cash_flow": tl(net_cash_flow_k),
        "available_advance": tl(total_advance_k),
        "net_remaining_debt": tl(total_remaining_debt_k),
        "receivable": tl(total_billed - net_total_paid),
        "methods": [{"method": k, "amount": tl(v)} for k, v in methods.items()],
        "entries": entries,
        "shares": shares,
        "sources_explanation": {
            "planned_total": "tooth_records tablosunda status IN ('planned','caries','extraction') olan tedavi planları (borç oluşturmaz).",
            "completed_gross": "charges tablosunda gerçekleşmiş hizmetlerin indirim öncesi brüt toplamı.",
            "discount_total": "charges.discount_kurus (banka anlaşması + özel indirim) toplamı.",
            "completed_net_debt": "Gerçekleşen Brüt Hizmet - İndirim (charges.amount_kurus).",
            "collected_paid": "payments tablosunda status='completed' olan başarılı tahsilatlar.",
            "pending_payment": "payments tablosunda status='pending' olan bekleyen ödemeler (borçtan düşülmez).",
            "failed_payment": "payments tablosunda status='failed' olan başarısız ödemeler (borçtan düşülmez).",
            "refunded_total": "payments tablosunda status='refunded' olan denetim kayıtlı iadeler.",
            "available_advance": "Hasta bazında net tahsilatın gerçekleşmiş hizmet borcunu aşan avans kısmı.",
            "net_remaining_debt": "Hasta bazında kalan net borçların toplamı.",
        },
    }


# ---------------- Ekip, Zincir Klinikler, Mesajlar, Şablonlar, Analiz, Ayarlar, Asistan ----------------
@app.get("/app/api/staff")
def staff(u: dict = Depends(ANY)):
    rows = q(
        """SELECT id, email, full_name, role, job_title, permissions_json, share_pct,
                  totp_enabled, active, (phone_hmac IS NOT NULL) AS whatsapp
           FROM staff_users WHERE clinic_id=? ORDER BY id""",
        u["clinic_id"],
    )
    prof_map = {k: v["label"] for k, v in STAFF_PROFESSIONS.items()}
    for r in rows:
        r["totp_enabled"] = bool(r["totp_enabled"])
        r["active"] = bool(r["active"])
        r["whatsapp"] = bool(r["whatsapp"])
        jt = r.get("job_title") or ("clinic_manager" if r["role"] == "owner" else ("dentist" if r["role"] == "doctor" else "secretary"))
        r["job_title"] = jt
        r["job_title_label"] = prof_map.get(jt, jt)
        r["permissions"] = resolve_permissions(r["role"], jt, r.pop("permissions_json", "{}"))
        if u["role"] != "owner":
            r.pop("email", None)
            r.pop("share_pct", None)
    return rows


class StaffIn(BaseModel):
    email: str
    full_name: str
    role: Literal["owner", "doctor", "secretary", "accounting", "clinical_support", "lab_tech", "warehouse", "no_access"] = "secretary"
    job_title: str = Field("", max_length=60)
    permissions: dict[str, bool] | None = None
    password: str = Field(min_length=12)
    phone: str | None = None
    share_pct: Decimal = Decimal(0)


@app.post("/app/api/staff")
def add_staff(b: StaffIn, u: dict = Depends(OWNER)):
    email = b.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Geçerli e-posta girin")
    jt = b.job_title.strip().lower() or ("clinic_manager" if b.role == "owner" else ("dentist" if b.role == "doctor" else ("cleaning" if b.role == "no_access" else "secretary")))
    if jt == "cleaning_staff":
        jt = "cleaning"
    if jt not in STAFF_PROFESSIONS:
        raise HTTPException(400, f"Geçersiz meslek seçimi: {jt}")
    perms_clean = {k: bool(v) for k, v in (b.permissions or {}).items() if k in PERMISSION_KEYS}
    try:
        sid = ex(
            """INSERT INTO staff_users
               (clinic_id,email,full_name,role,job_title,permissions_json,pw_hash,phone_hmac,share_pct,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            u["clinic_id"], email, b.full_name.strip(), b.role, jt,
            json.dumps(perms_clean, ensure_ascii=False), _hash_pw(b.password),
            phone_hmac(b.phone) if b.phone else None, float(b.share_pct), iso_now(),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Bu e-posta veya telefon zaten kayıtlı")
    write_audit(u["id"], u["email"], "staff.create", f"staff:{sid}", u["ip_h"], {"role": b.role, "job_title": jt}, clinic_id=u["clinic_id"])
    return {"id": sid, "role": b.role, "job_title": jt}


class ActiveIn(BaseModel):
    active: bool


@app.post("/app/api/staff/{sid}/active")
def staff_active(sid: int, b: ActiveIn, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    if sid == u["id"] and not b.active:
        raise HTTPException(400, "Kendi hesabınızı kapatamazsınız")
    if not q1("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", sid, cid):
        raise HTTPException(404, "personel yok")
    ex("UPDATE staff_users SET active=? WHERE id=? AND clinic_id=?", 1 if b.active else 0, sid, cid)
    if not b.active:
        ex("UPDATE sessions SET revoked=1 WHERE user_id=?", sid)
    write_audit(u["id"], u["email"], "staff.activate" if b.active else "staff.deactivate", f"staff:{sid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.get("/app/api/clinics")
def list_clinics(request: Request, u: dict = Depends(OWNER)):
    if u["is_hq"]:
        rows = q("SELECT * FROM clinics ORDER BY id")
    else:
        rows = q("SELECT * FROM clinics WHERE id=? ORDER BY id", u["home_clinic_id"])
    base = str(request.base_url).rstrip("/")
    for c in rows:
        ow = q1("SELECT email FROM staff_users WHERE clinic_id=? AND role='owner' ORDER BY id LIMIT 1", c["id"])
        c["owner_email"] = ow["email"] if ow else None
        c["staff_count"] = q1("SELECT count(*) AS n FROM staff_users WHERE clinic_id=? AND active=1", c["id"])["n"]
        c["patient_count"] = q1("SELECT count(*) AS n FROM patients WHERE clinic_id=?", c["id"])["n"]
        c["active_appts"] = q1("SELECT count(*) AS n FROM appointments WHERE clinic_id=? AND status IN ('booked','confirmed')", c["id"])["n"]
        paid_k = (q1(
            """SELECT COALESCE(sum(
                 CASE WHEN status='refunded' THEN -amount_kurus
                      WHEN COALESCE(status,'completed')='completed' AND method<>'avans_mahsup' THEN amount_kurus
                      ELSE 0 END
               ),0) AS s FROM payments WHERE clinic_id=? AND voided_at IS NULL""",
            c["id"],
        ) or {})["s"]
        c["paid_try"] = tl(max(0, int(paid_k or 0)))
        c["active"] = bool(c["active"])
        tok = cal.calendar_feed_token(c["id"], version=int(c.get("cal_token_version") or 1))
        c["ics_url"] = f"{base}/calendar/{tok}.ics"
        c["webcal_url"] = "webcal://" + c["ics_url"].split("://", 1)[-1]
    return rows


class ClinicCreateIn(BaseModel):
    clinic_name: str = Field(min_length=2, max_length=120)
    city: str = Field("İstanbul", max_length=40)
    address: str = Field("", max_length=200)
    phone: str = Field("", max_length=30)
    chairs: int = Field(2, ge=1, le=200)
    owner_name: str = Field(min_length=2, max_length=80)
    owner_email: str = Field(max_length=200)
    owner_password: str = Field(min_length=12, max_length=200)


@app.post("/app/api/clinics")
def create_clinic(b: ClinicCreateIn, request: Request, u: dict = Depends(OWNER)):
    if not u["is_hq"]:
        raise HTTPException(403, "Yalnızca merkez yönetici (HQ) yeni klinik açabilir")
    email = b.owner_email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Geçerli yönetici e-postası girin")
    if q1("SELECT 1 FROM staff_users WHERE email=?", email):
        raise HTTPException(409, "Bu yönetici e-postası zaten kayıtlı")
    slug = re.sub(r"[^a-z0-9]+", "-", b.clinic_name.lower()).strip("-")[:35] + f"-{int(now_utc().timestamp()) % 10000}"
    cid = ex("INSERT INTO clinics (name,slug,city,address,phone,chairs,created_at) VALUES (?,?,?,?,?,?,?)",
             b.clinic_name, slug, b.city, b.address, b.phone, b.chairs, iso_now())
    uid = ex("INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,share_pct,created_at) VALUES (?,?,?,?,?,50,?)",
             cid, email, b.owner_name, "owner", _hash_pw(b.owner_password), iso_now())
    ex("INSERT INTO message_templates (clinic_id,name,channel,lang,category,body,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
       cid, "randevu_hatirlatma", "whatsapp", "tr", "UTILITY", "Sayın {{1}}, yarın {{2}} randevunuzu hatırlatırız.", "APPROVED", iso_now())
    write_audit(u["id"], u["email"], "clinic.create", f"clinic:{cid}", u["ip_h"], {"email": email}, clinic_id=u["clinic_id"])
    base = str(request.base_url).rstrip("/")
    tok = cal.calendar_feed_token(cid)
    ics_url = f"{base}/calendar/{tok}.ics"
    webcal_url = "webcal://" + ics_url.split("://", 1)[-1]
    google_subscribe_url = "https://calendar.google.com/calendar/r?cid=" + quote(webcal_url, safe="")
    return {"clinic_id": cid, "user_id": uid, "email": email, "slug": slug,
            "login_url": f"{base}/app", "ics_url": ics_url, "webcal_url": webcal_url,
            "google_subscribe_url": google_subscribe_url}


@app.post("/app/api/clinics/{cid}/switch")
def switch_clinic(cid: int, u: dict = Depends(OWNER)):
    if not u["is_hq"]:
        raise HTTPException(403, "Yalnızca merkez yönetici (HQ) klinik değiştirebilir")
    c = q1("SELECT id, name FROM clinics WHERE id=? AND active=1", cid)
    if not c:
        raise HTTPException(404, "klinik yok")
    ex("UPDATE sessions SET active_clinic_id=? WHERE id_hash=?", cid, u["id_hash"])
    write_audit(u["id"], u["email"], "clinic.switch", f"clinic:{cid}", u["ip_h"],
                {"from": u["clinic_id"], "to": cid}, clinic_id=u["home_clinic_id"])
    return {"ok": True, "clinic_id": cid, "clinic": c["name"]}


@app.get("/app/api/conversations")
def list_conversations(u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    perms = u.get("permissions") or {}
    sql_c = "SELECT id, display_name, channel, lang FROM patients WHERE clinic_id=? AND active=1"
    args_c: list = [cid]
    if perms.get("doctor_own_patients_only") and u.get("role") != "owner":
        sql_c += """ AND (primary_doctor_id=? OR created_by=?
                         OR EXISTS (SELECT 1 FROM appointments ap WHERE ap.patient_id=patients.id AND ap.doctor_id=?)
                         OR EXISTS (SELECT 1 FROM tooth_records tr WHERE tr.patient_id=patients.id AND tr.doctor_id=?))"""
        args_c.extend([u["id"], u["id"], u["id"], u["id"]])
    sql_c += " ORDER BY id DESC"
    rows = q(sql_c, *args_c)
    all_logs = q(
        """SELECT patient_id, layer, intent, direction, body, delivery_status, delivery_error, created_at
           FROM message_log WHERE clinic_id=? AND patient_id IS NOT NULL ORDER BY id DESC""",
        cid,
    )
    by_pid: dict[int, list[dict]] = {}
    for lg in all_logs:
        by_pid.setdefault(lg["patient_id"], []).append(lg)
    for r in rows:
        logs = by_pid.get(r["id"], [])
        out_logs = [l for l in logs if l["direction"] == "out"]
        body_logs = [l for l in logs if l.get("body")]
        r["last_at"] = logs[0]["created_at"] if logs else None
        r["last_layer"] = out_logs[0]["layer"] if out_logs else None
        r["last_intent"] = logs[0]["intent"] if logs else None
        r["last_body"] = _dec_msg_body(body_logs[0]["body"]) if body_logs else None
        r["last_dir"] = body_logs[0]["direction"] if body_logs else (logs[0]["direction"] if logs else None)
        r["last_delivery_status"] = out_logs[0].get("delivery_status") if out_logs else None
        r["last_delivery_error"] = out_logs[0].get("delivery_error") if out_logs else None
        r["msg_count"] = len(logs)
    return rows


@app.get("/app/api/conversations/{pid}/messages")
def list_conv_messages(pid: int, u: dict = Depends(require_perm("patient_view"))):
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    rows = q(
        """SELECT id, direction, layer, intent, body, delivery_status, delivery_error, created_at
           FROM message_log WHERE patient_id=? AND clinic_id=? ORDER BY id DESC LIMIT 100""",
        pid, cid,
    )
    for r in rows:
        r["body"] = _dec_msg_body(r.get("body"))
    return rows


class ReplyIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


@app.post("/app/api/conversations/{pid}/send")
async def send_conv(pid: int, b: ReplyIn, u: dict = Depends(require_perm("patient_edit"))):
    if not await _LIMITER.hit(f"conv_send:{u['id']}", 30, 60):
        raise HTTPException(429, "Çok fazla mesaj gönderildi; lütfen 1 dakika bekleyin")
    cid = u["clinic_id"]
    _enforce_doc_own_patient(cid, pid, u)
    with _DB_LOCK:
        p_row = _require_active_patient_row(db(), pid, cid)
        p_phone = dec(p_row["phone_enc"])
    delivery = await _deliver_wa(cid, pid, p_phone, b.text, layer="panel-manuel", intent="personel")
    write_audit(u["id"], u["email"], "conversation.send", f"patient:{pid}", u["ip_h"], {"status": delivery["status"]}, clinic_id=cid)
    return {
        "ok": delivery["ok"],
        "status": delivery["status"],
        "dry_run": delivery["dry_run"],
        "error": delivery["error"],
    }


class TickIn(BaseModel):
    force: bool = False
    at: datetime | None = None


@app.post("/app/api/admin/scheduler/tick")
async def admin_scheduler_tick(b: TickIn | None = Body(default=None), u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    if not await _LIMITER.hit(f"sched_tick:{cid}", 20, 60):
        raise HTTPException(429, "Çok fazla zamanlayıcı isteği gönderildi; lütfen 1 dakika bekleyin")
    now_dt = b.at if b and b.at else None
    respect = not (b.force if b else False)
    res = await _run_scheduler_tick(clinic_id=cid, now_dt=now_dt, respect_hours=respect)
    write_audit(u["id"], u["email"], "scheduler.tick", f"clinic:{cid}", u["ip_h"],
                {"reminders": res["reminders_sent"], "waves": res["waves_advanced"], "followups": res["followups_sent"], "skipped": res["skipped_outside_hours"]},
                clinic_id=cid)
    return res


@app.post("/app/api/reminders/send")
async def manual_send_reminders(b: TickIn | None = Body(default=None), u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    if not await _LIMITER.hit(f"rem_send:{cid}", 20, 60):
        raise HTTPException(429, "Çok fazla hatırlatma isteği gönderildi; lütfen 1 dakika bekleyin")
    now_dt = b.at if b and b.at else None
    respect = not (b.force if b else False)
    res = await _run_scheduler_tick(clinic_id=cid, now_dt=now_dt, respect_hours=respect)
    write_audit(u["id"], u["email"], "reminders.send", f"clinic:{cid}", u["ip_h"], {"reminders": res["reminders_sent"]}, clinic_id=cid)
    return res


class SimIn(BaseModel):
    text: str = Field(min_length=1, max_length=1200)
    lang: str | None = Field(default=None, max_length=10)
    session_id: str | None = Field(default=None, max_length=80)
    patient_id: int | None = None
    context_previous_turn: str | None = Field(default=None, max_length=1200)


@app.post("/app/api/conversations/simulate")
async def simulate_conversation(b: SimIn, u: dict = Depends(ANY)):
    sim_limit = 20 if u["role"] == "secretary" else (40 if u["role"] == "doctor" else 60)
    if not await _LIMITER.hit(f"sim:{u['id']}", sim_limit, 60):
        raise HTTPException(429, "Çok fazla simülasyon isteği gönderildi; lütfen 1 dakika bekleyin")
    cid = u["clinic_id"]
    c_quota = q1("SELECT ai_monthly_token_limit, ai_hard_stop FROM clinics WHERE id=?", cid) or {}
    if int(c_quota.get("ai_hard_stop") or 0) == 1:
        tok_limit = max(1, int(c_quota.get("ai_monthly_token_limit") or 1_500_000))
        cutoff_30d_iso = (now_utc() - timedelta(days=30)).isoformat()
        used_row = q1(
            """SELECT COALESCE(sum(m.tokens_in + m.tokens_out), 0) AS t
               FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id
               WHERE m.direction='out' AND COALESCE(p.clinic_id, m.clinic_id, 1)=? AND m.created_at >= ?""",
            cid, cutoff_30d_iso,
        ) or {}
        if int(used_row.get("t") or 0) >= tok_limit:
            raise HTTPException(429, "Aylık yapay zekâ token/bütçe kotası (%100) aşıldı ve hard_stop aktif")
    if b.patient_id is not None:
        if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", b.patient_id, cid):
            raise HTTPException(404, "hasta yok")
        _enforce_doc_own_patient(cid, b.patient_id, u)
        with _DB_LOCK:
            c_sim = db()
            camp_sim = _extract_campaign_ref(c_sim, cid, b.text)
            if camp_sim:
                det_s = detect_acquisition_source(
                    explicit_source=camp_sim.get("channel") or camp_sim.get("source"),
                    utm_source=camp_sim.get("utm_source") or "",
                    utm_medium=camp_sim.get("utm_medium") or "",
                    default_source="whatsapp",
                )
                cp_id_sim = int(camp_sim["id"])
                us_sim = (camp_sim.get("utm_source") or det_s)[:80]
                um_sim = (camp_sim.get("utm_medium") or "cpc")[:80]
                uc_sim = (camp_sim.get("utm_campaign") or camp_sim.get("code") or "")[:120]
                c_sim.execute(
                    """UPDATE patients
                       SET last_source=?, campaign_id=?,
                           utm_source=CASE WHEN ?<>'' THEN ? ELSE utm_source END,
                           utm_medium=CASE WHEN ?<>'' THEN ? ELSE utm_medium END,
                           utm_campaign=CASE WHEN ?<>'' THEN ? ELSE utm_campaign END
                       WHERE id=? AND clinic_id=?""",
                    (det_s, cp_id_sim, us_sim, us_sim, um_sim, um_sim, uc_sim, uc_sim, b.patient_id, cid),
                )
                has_ev_sim = c_sim.execute(
                    "SELECT 1 FROM campaign_events WHERE clinic_id=? AND campaign_id=? AND patient_id=? AND event_type='patient_created' LIMIT 1",
                    (cid, cp_id_sim, b.patient_id),
                ).fetchone()
                if not has_ev_sim:
                    c_sim.execute(
                        """INSERT INTO campaign_events
                           (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,is_bot,is_unique,patient_id,created_at)
                           VALUES (?,?,'patient_created',?,?,?,?,0,1,?,?)""",
                        (cid, cp_id_sim, det_s, us_sim, um_sim, uc_sim, b.patient_id, iso_now()),
                    )
                    c_sim.execute("UPDATE campaigns SET conversations = conversations + 1 WHERE id=? AND clinic_id=?", (cp_id_sim, cid))
                c_sim.commit()
        handled = await _handle_patient_reply(
            cid, b.patient_id, b.text, channel="simulator", context_previous_turn=b.context_previous_turn
        )
        if handled:
            ans, layer, intent = handled
            t_now = iso_now()
            ex(
                "INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,body,delivery_status,created_at) VALUES (?,?,'in',NULL,'simulator',0,0,?,'received',?)",
                cid, b.patient_id, enc(b.text[:1200]) if b.text else "", t_now,
            )
            ex(
                "INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,body,delivery_status,created_at) VALUES (?,?,'out',?,?,0,0,?,'dry_run',?)",
                cid, b.patient_id, layer, f"simulator:{intent}", enc(ans[:2000]) if ans else "", t_now,
            )
            write_audit(u["id"], u["email"], "conversation.simulate", f"patient:{b.patient_id}", u["ip_h"],
                        {"lang": b.lang or "tr", "layer": layer, "intent": intent}, clinic_id=cid)
            return {
                "answer": ans,
                "layer": layer,
                "intent": intent,
                "lang": b.lang or "tr",
                "tokens_in": 0,
                "tokens_out": 0,
                "alert": None,
                "handoff": False,
                "meta": {"patient_id": b.patient_id},
            }

    c = q1("SELECT name, address, phone, ai_custom_rules_json FROM clinics WHERE id=?", cid)
    all_branches = q("SELECT id, name, city, address, phone FROM clinics WHERE active=1")
    facts: dict = {
        "clinic": (c and c["name"]) or u["clinic_name"],
        "branches": all_branches,
    }
    if c and c.get("address"):
        facts["adres"] = c["address"]
    if c and c.get("phone"):
        facts["telefon"] = c["phone"]
    if c and c.get("ai_custom_rules_json"):
        facts["ai_custom_rules_json"] = c["ai_custom_rules_json"]
    allow_llm = _has_consent(b.patient_id, "yurt_disi_aktarim") if b.patient_id is not None else True
    try:
        res = await asyncio.wait_for(
            _ROUTER.route(
                b.text,
                lang=b.lang,
                clinic_facts=facts,
                allow_llm=allow_llm,
                session_id=b.session_id,
                patient_id=b.patient_id,
                context_previous_turn=b.context_previous_turn,
            ),
            timeout=16.0,
        )
    except Exception:
        res = await _ROUTER.route(
            b.text,
            lang=b.lang,
            clinic_facts=facts,
            allow_llm=False,
            session_id=b.session_id,
            patient_id=b.patient_id,
            context_previous_turn=b.context_previous_turn,
        )
    ex("INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,body,delivery_status,created_at) VALUES (?,?,'in',NULL,'simulator',0,0,?,'received',?)",
       cid, b.patient_id, enc(b.text[:1200]) if b.text else "", iso_now())
    ex("INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,body,delivery_status,created_at) VALUES (?,?,'out',?,?,?,?,?,'dry_run',?)",
       cid, b.patient_id, res.layer, f"simulator:{res.intent}", res.tokens_in, res.tokens_out, enc(res.answer[:2000]) if res.answer else "", iso_now())
    write_audit(u["id"], u["email"], "conversation.simulate", f"clinic:{cid}", u["ip_h"],
                {"lang": res.lang, "layer": res.layer, "intent": res.intent}, clinic_id=cid)
    return {
        "answer": res.answer,
        "layer": res.layer,
        "intent": res.intent,
        "lang": res.lang,
        "tokens_in": res.tokens_in,
        "tokens_out": res.tokens_out,
        "alert": res.alert,
        "handoff": res.handoff,
        "meta": res.meta,
    }


async def _probe_http(url: str) -> bool:
    try:
        async with httpx.AsyncClient(timeout=0.18) as c:
            resp = await c.get(url)
            return resp.status_code < 500
    except Exception:
        return False


@app.get("/app/api/ecosystem-status")
async def ecosystem_status(u: dict = Depends(ANY)):
    omni_url = os.environ.get("LLM_BASE_URL", "http://127.0.0.1:20128/v1").rstrip("/")
    omni_base = omni_url[:-3] if omni_url.endswith("/v1") else omni_url
    headroom_url = os.environ.get("HEADROOM_URL", "http://127.0.0.1:8787").rstrip("/")
    aioffice_url = os.environ.get("AI_OFFICE_URL", "http://127.0.0.1:20140").rstrip("/")
    omni_ok, head_ok, aio_ok, voice_ok, seo_ok, op_ok, cal_ok, chat_ok = await asyncio.gather(
        _probe_http(f"{omni_base}/v1/models"),
        _probe_http(f"{headroom_url}/health"),
        _probe_http(f"{aioffice_url}/health"),
        _probe_http("http://127.0.0.1:3900/health"),
        _probe_http("http://127.0.0.1:3001/api/health"),
        _probe_http("http://127.0.0.1:8080/health_checks/default"),
        _probe_http("http://127.0.0.1:3002/api/version"),
        _probe_http("http://127.0.0.1:3000/api"),
    )
    local = os.environ.get("LOCALAPPDATA", "")
    apps = [
        {"id": "open-generative-ai", "name": "Open Generative AI", "ok": bool(local and (Path(local) / "Open Generative AI" / "Open Generative AI.exe").exists())},
        {"id": "voicestudio", "name": "VoiceStudio", "ok": voice_ok or bool(local and (Path(local) / "Programs" / "VoiceStudio" / "VoiceStudio.exe").exists())},
        {"id": "open-seo", "name": "OpenSEO", "ok": seo_ok},
        {"id": "appflowy", "name": "AppFlowy", "ok": bool(local and (Path(local) / "Programs" / "AppFlowy" / "AppFlowy" / "AppFlowy.exe").exists())},
        {"id": "openwhispr", "name": "OpenWhispr", "ok": bool(local and (Path(local) / "Programs" / "OpenWhispr" / "OpenWhispr.exe").exists())},
        {"id": "openproject", "name": "OpenProject CE", "ok": op_ok},
        {"id": "cal-diy", "name": "Cal.diy", "ok": cal_ok},
        {"id": "chatwoot", "name": "Chatwoot Community", "ok": chat_ok},
        {"id": "cap", "name": "Cap", "ok": bool(local and (Path(local) / "Cap" / "Cap.exe").exists())},
    ]
    return {
        "omniroute": {"ok": omni_ok, "url": omni_base},
        "headroom": {"ok": head_ok, "url": headroom_url},
        "ai_office": {"ok": aio_ok, "url": aioffice_url},
        "langs": 16,
        "security_headers": 12,
        "apps": apps,
    }


@app.get("/app/api/templates")
def list_templates(u: dict = Depends(ANY)):
    return q("SELECT * FROM message_templates WHERE clinic_id=? ORDER BY id DESC", u["clinic_id"])


class TemplateIn(BaseModel):
    name: str
    channel: str = "whatsapp"
    lang: str = "tr"
    category: str = "UTILITY"
    body: str


@app.post("/app/api/templates")
def create_template(b: TemplateIn, u: dict = Depends(OWNER)):
    tid = ex("INSERT INTO message_templates (clinic_id,name,channel,lang,category,body,status,created_at) VALUES (?,?,?,?,?,?,'APPROVED',?)",
             u["clinic_id"], b.name, b.channel, b.lang, b.category, b.body, iso_now())
    return {"id": tid}


@app.get("/app/api/analytics")
def analytics(request: Request, u: dict = Depends(require_perm("finance_view"))):
    cid = u["clinic_id"]
    cutoff_30d = now_utc() - timedelta(days=30)
    raw_appts = q("SELECT starts_at, created_at FROM appointments WHERE clinic_id=?", cid)
    appts = [a for a in raw_appts if _parse_dt_tz(a["created_at"]) >= cutoff_30d]
    off = 0
    for a in appts:
        dt = _parse_dt_tz(a["starts_at"]).astimezone(TZ)
        if dt.hour < 9 or dt.hour >= 19 or dt.weekday() == 6:
            off += 1
    base = str(request.base_url).rstrip("/")
    camps = q("SELECT * FROM campaigns WHERE clinic_id=? ORDER BY id DESC", cid)
    for c in camps:
        cp_id = int(c["id"])
        code = c.get("code") or f"kampanya-{cp_id}"
        c["code"] = code
        c["tracking_url"] = f"{base}/c/{code}"
        ev_rows = q("SELECT event_type, is_bot, is_unique FROM campaign_events WHERE clinic_id=? AND campaign_id=?", cid, cp_id)
        click_evs = [e for e in ev_rows if e["event_type"] == "click"]
        c["tracked_total_clicks"] = len(click_evs)
        c["tracked_bot_clicks"] = sum(1 for e in click_evs if e["is_bot"])
        c["tracked_unique_clicks"] = sum(1 for e in click_evs if not e["is_bot"] and e["is_unique"])
        c["form_starts"] = sum(1 for e in ev_rows if e["event_type"] == "form_start" and not e["is_bot"])
        c["form_submits"] = sum(1 for e in ev_rows if e["event_type"] == "form_submit" and not e["is_bot"])
        p_ids = [r["id"] for r in q("SELECT id FROM patients WHERE clinic_id=? AND campaign_id=?", cid, cp_id)]
        c["patients_created"] = len(p_ids)
        if p_ids:
            ph_in = ",".join("?" for _ in p_ids)
            ap_rows = q(f"SELECT status FROM appointments WHERE clinic_id=? AND (campaign_id=? OR patient_id IN ({ph_in}))", cid, cp_id, *p_ids)
            real_appts = len(ap_rows)
            real_done = sum(1 for a in ap_rows if a["status"] == "done")
            rev_row = q1(
                f"""SELECT COALESCE(sum(
                      CASE WHEN status='refunded' THEN -amount_kurus
                           WHEN COALESCE(status,'completed')='completed' AND method<>'avans_mahsup' THEN amount_kurus
                           ELSE 0 END
                    ),0) AS s FROM payments WHERE clinic_id=? AND voided_at IS NULL AND patient_id IN ({ph_in})""",
                cid, *p_ids,
            )
            real_rev_k = max(0, int((rev_row or {}).get("s") or 0))
        else:
            real_appts = 0
            real_done = 0
            real_rev_k = 0
        c["tracked_appointments"] = real_appts
        c["visits_completed"] = real_done
        c["collected_revenue_try"] = tl(real_rev_k)
        c["declared_revenue_try"] = tl(int(c.pop("revenue_kurus") or 0))
        c["revenue_try"] = c["collected_revenue_try"] if (real_rev_k > 0 or not c.get("is_sample")) else c["declared_revenue_try"]
        c["is_sample"] = bool(c.get("is_sample"))
    return {
        "total_appts_30d": len(appts),
        "off_hours_appts": off,
        "off_hours_pct": round(100 * off / len(appts)) if appts else 0,
        "campaigns": camps,
        "tracking_limitations_tr": (
            "Gerçek sunucu-taraflı tıklama (/c/{code}) ve kasa tahsilat eşleşmesi aktif. "
            "Reklam engelleyici (AdBlock), iOS Özel Geçiş (Private Relay) veya çerez reddi kullanan ziyaretçilerde "
            "tekilleştirme oturum karma (visitor_hash) sınırları dahilinde yaklaşık ölçülür."
        ),
    }


class CampaignIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    source: str = Field("meta_ads", max_length=40)
    code: str | None = Field(default=None, max_length=60)
    utm_source: str = Field("", max_length=60)
    utm_medium: str = Field("cpc", max_length=60)
    utm_campaign: str = Field("", max_length=80)
    target_url: str = Field("/", max_length=300)
    clicks: int = Field(0, ge=0, le=10_000_000)
    conversations: int = Field(0, ge=0, le=10_000_000)
    appointments_booked: int = Field(0, ge=0, le=1_000_000)
    revenue_try: Decimal = Field(Decimal(0), ge=0, le=1_000_000_000)


@app.post("/app/api/campaigns")
def add_campaign(b: CampaignIn, request: Request, u: dict = Depends(OWNER)):
    norm_s = normalize_source(b.source)
    legacy_s = "meta_ads" if norm_s in ("instagram", "meta_ads") else ("google_ads" if norm_s == "google_ads" else "organik")
    if b.code and b.code.strip():
        code = re.sub(r"[^a-z0-9_-]+", "-", b.code.strip().lower()).strip("-")[:48]
        if q1("SELECT id FROM campaigns WHERE code=? AND clinic_id<>?", code, u["clinic_id"]):
            code = f"{code}-c{u['clinic_id']}"
    else:
        raw_code = re.sub(r"[^a-z0-9]+", "-", b.name.lower()).strip("-")[:32] or "kampanya"
        code = f"{raw_code}-{secrets.token_hex(2)}"
    utm_s = b.utm_source.strip() or norm_s
    utm_c = b.utm_campaign.strip() or code
    cid_id = ex(
        """INSERT INTO campaigns
           (clinic_id,name,source,code,channel,utm_source,utm_medium,utm_campaign,target_url,is_sample,clicks,conversations,appointments_booked,revenue_kurus,created_at)
           VALUES (?,?,?,?,?,?,?,?,?,0,?,?,?,?,?)""",
        u["clinic_id"], b.name.strip(), legacy_s, code, norm_s, utm_s, b.utm_medium.strip(), utm_c,
        b.target_url.strip() or "/", b.clicks, b.conversations, b.appointments_booked, kurus(b.revenue_try), iso_now(),
    )
    base = str(request.base_url).rstrip("/")
    return {"id": cid_id, "code": code, "channel": norm_s, "tracking_url": f"{base}/c/{code}"}


@app.get("/app/api/settings")
def get_settings(u: dict = Depends(ANY)):
    return q1("SELECT * FROM clinics WHERE id=?", u["clinic_id"])


class SettingsIn(BaseModel):
    name: str
    city: str = "İstanbul"
    address: str = ""
    phone: str = ""
    autopilot_name: str = "DentaCore Asistan"
    default_lang: str = "tr"
    slot_step_min: int = 15
    google_review_url: str = ""
    working_hours_json: str | None = None
    buffer_min: int = Field(0, ge=0, le=120)
    ai_custom_rules_json: str | None = None
    wa_phone_id: str | None = Field(default=None, max_length=80)
    ig_handle: str | None = Field(default=None, max_length=80)


@app.post("/app/api/settings")
def save_settings(b: SettingsIn, u: dict = Depends(OWNER)):
    cid = u["clinic_id"]
    rev_url = (b.google_review_url or "").strip()
    if rev_url and not re.match(r"^https?://", rev_url, re.IGNORECASE):
        raise HTTPException(400, "Google değerlendirme bağlantısı http:// veya https:// ile başlamalıdır")
    wh_str = b.working_hours_json or DEFAULT_WORKING_HOURS_JSON
    try:
        parsed_wh = json.loads(wh_str)
        if not isinstance(parsed_wh, dict):
            raise ValueError("dict değil")
    except Exception:
        raise HTTPException(400, "Geçersiz çalışma saatleri JSON formatı")
    cur_c = q1("SELECT ai_custom_rules_json, wa_phone_id, ig_handle FROM clinics WHERE id=?", cid) or {}
    ai_rules_str = b.ai_custom_rules_json if b.ai_custom_rules_json is not None else (cur_c.get("ai_custom_rules_json") or "{}")
    try:
        parsed_ai = json.loads(ai_rules_str)
        if not isinstance(parsed_ai, dict):
            raise ValueError("dict değil")
    except Exception:
        raise HTTPException(400, "Geçersiz yapay zeka cevap kuralları JSON formatı")
    wa_pid = b.wa_phone_id.strip() if b.wa_phone_id is not None else (cur_c.get("wa_phone_id") or "")
    ig_hdl = b.ig_handle.strip() if b.ig_handle is not None else (cur_c.get("ig_handle") or "")
    if wa_pid and q1("SELECT id FROM clinics WHERE wa_phone_id=? AND id<>?", wa_pid, cid):
        raise HTTPException(409, "Bu WhatsApp telefon kimliği (wa_phone_id) başka bir şube tarafından kullanılıyor")
    if ig_hdl and q1("SELECT id FROM clinics WHERE ig_handle=? AND id<>?", ig_hdl, cid):
        raise HTTPException(409, "Bu Instagram hesabı (ig_handle) başka bir şube tarafından kullanılıyor")
    ex(
        "UPDATE clinics SET name=?,city=?,address=?,phone=?,autopilot_name=?,default_lang=?,slot_step_min=?,google_review_url=?,working_hours_json=?,buffer_min=?,ai_custom_rules_json=?,wa_phone_id=?,ig_handle=? WHERE id=?",
        b.name, b.city, b.address, b.phone, b.autopilot_name, b.default_lang, b.slot_step_min, rev_url, wh_str, b.buffer_min, ai_rules_str, wa_pid, ig_hdl, cid,
    )
    write_audit(u["id"], u["email"], "settings.update", f"clinic:{cid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


class AICustomRulesIn(BaseModel):
    tone: str = Field("resmi_samimi", max_length=40)
    coordinator_title: str = Field("Kıdemli Hasta Koordinatörü", max_length=80)
    greeting_style: str = Field("Merhabalar, {clinic} hasta danışma hattımıza hoş geldiniz.", max_length=300)
    price_policy: Literal["free_exam_invite", "starting_range", "direct_handoff"] = "free_exam_invite"
    exam_policy: str = Field("", max_length=400)
    cash_discount_note: str = Field("", max_length=400)
    payment_note: str = Field("", max_length=400)
    pain_comfort_note: str = Field("", max_length=400)
    kids_note: str = Field("", max_length=400)
    health_tourism_note: str = Field("", max_length=400)
    custom_extra_note: str = Field("", max_length=500)


@app.post("/app/api/settings/ai-rules")
def save_ai_custom_rules(b: AICustomRulesIn, u: dict = Depends(OWNER)):
    rules_str = json.dumps(b.model_dump(), ensure_ascii=False)
    ex("UPDATE clinics SET ai_custom_rules_json=? WHERE id=?", rules_str, u["clinic_id"])
    write_audit(u["id"], u["email"], "settings.ai_rules_update", f"clinic:{u['clinic_id']}", u["ip_h"], clinic_id=u["clinic_id"])
    return {"ok": True, "ai_custom_rules": b.model_dump()}


class AskIn(BaseModel):
    question: str


@app.post("/app/api/assistant")
async def assistant(b: AskIn, u: dict = Depends(ANY)):
    if not await _LIMITER.hit(f"asst:{u['id']}", 30, 60):
        raise HTTPException(429, "Çok fazla asistan sorgusu")
    cid = u["clinic_id"]
    txt = b.question.lower()
    if any(k in txt for k in ("kasa", "tahsilat", "ciro")):
        if not (u.get("permissions") or {}).get("finance_view", False):
            return {"answer": "Kasa özeti yalnızca hekim, muhasebe ve yöneticiye açık.", "tokens": 0}
        p = q1(
            """SELECT COALESCE(sum(
                 CASE WHEN status='refunded' THEN -amount_kurus
                      WHEN COALESCE(status,'completed')='completed' AND method<>'avans_mahsup' THEN amount_kurus
                      ELSE 0 END
               ),0) AS s FROM payments WHERE clinic_id=? AND voided_at IS NULL""",
            cid,
        )["s"]
        return {"answer": f"Toplam tahsilat: {tl(max(0, int(p or 0))):,.2f} TL (0 LLM tokenı harcandı).", "tokens": 0}
    if any(k in txt for k in ("stok", "envanter")):
        lows = q("SELECT name, qty, min_qty, unit FROM inventory_items WHERE clinic_id=? AND active=1 AND qty <= min_qty AND min_qty > 0", cid)
        ans = "\n".join(f"- {r['name']}: {r['qty']} {r['unit']} (alt sınır {r['min_qty']})" for r in lows) or "Kritik stok yok."
        return {"answer": ans, "tokens": 0}
    if any(k in txt for k in ("uyarı", "uyari", "kırmızı", "kirmizi")):
        als = q("SELECT kind, detail FROM alerts WHERE clinic_id=? AND acknowledged_at IS NULL", cid)
        lines = []
        for a in als:
            if u["role"] not in ("owner", "doctor") and a.get("kind") in ("anamnez_kirmizi", "postop_alarm", "acil"):
                lines.append("- Klinik Uyarı (Hekim Kontrolü)")
            else:
                lines.append(f"- {a['detail']}")
        return {"answer": "\n".join(lines) or "Açık uyarı yok.", "tokens": 0}
    appts = q("SELECT a.starts_at, a.treatment, a.chair, p.display_name FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id WHERE a.clinic_id=? AND a.status IN ('booked','confirmed') ORDER BY a.starts_at LIMIT 10", cid)
    ans = "\n".join(f"- {a['starts_at'][:16].replace('T',' ')} K{a['chair']} {a['display_name']} ({a['treatment']})" for a in appts) or "Aktif randevu yok."
    return {"answer": f"Yaklaşan Randevular:\n{ans}", "tokens": 0}


@app.post("/app/api/backup/create")
async def create_encrypted_backup(u: dict = Depends(HQ_OWNER)):
    if not await _LIMITER.hit(f"bak_c:{u['id']}", 10, 60):
        raise HTTPException(429, "Çok fazla yedekleme isteği")
    import gzip
    import tempfile
    bak_dir = ROOT / "backups"
    bak_dir.mkdir(parents=True, exist_ok=True)
    ts_str = datetime.now(TZ).strftime("%Y%m%d-%H%M%S")
    bak_file = bak_dir / f"dentacore-{ts_str}.db.gz.fernet"
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    try:
        with _DB_LOCK:
            dst_conn = sqlite3.connect(tmp_path)
            db().backup(dst_conn)
            dst_conn.close()
        raw_bytes = tmp_path.read_bytes()
        compressed = gzip.compress(raw_bytes, compresslevel=9)
        encrypted = _FERNET.encrypt(compressed)
        bak_file.write_bytes(encrypted)
        sha = hashlib.sha256(encrypted).hexdigest()
    finally:
        tmp_path.unlink(missing_ok=True)
    write_audit(u["id"], u["email"], "backup.create", bak_file.name, u["ip_h"], {"sha256": sha[:16]}, clinic_id=u["clinic_id"])
    return {"ok": True, "backup_path": str(bak_file), "size_bytes": len(encrypted), "sha256": sha}


class RestoreTestIn(BaseModel):
    backup_path: str
    target_db_path: str


@app.post("/app/api/backup/restore-test")
async def restore_encrypted_backup_test(b: RestoreTestIn, u: dict = Depends(HQ_OWNER)):
    if not await _LIMITER.hit(f"bak_r:{u['id']}", 10, 60):
        raise HTTPException(429, "Çok fazla geri yükleme testi isteği")
    import gzip
    backups_dir = (ROOT / "backups").resolve()
    backups_dir.mkdir(parents=True, exist_ok=True)
    src_file = Path(b.backup_path).resolve()
    dst_file = Path(b.target_db_path).resolve()
    if (
        not src_file.is_relative_to(backups_dir)
        or not dst_file.is_relative_to(backups_dir)
        or dst_file.parent != backups_dir
        or not src_file.name.endswith(".db.gz.fernet")
        or not dst_file.name.endswith(".db")
        or dst_file == DB_PATH.resolve()
    ):
        write_audit(u["id"], u["email"], "backup.restore_blocked", str(b.target_db_path)[:120], u["ip_h"], clinic_id=u["clinic_id"])
        raise HTTPException(400, "Güvenlik engeli: Yedek ve hedef veritabanı yalnızca backups/ dizini içinde (.db) olabilir")
    if not src_file.is_file():
        raise HTTPException(404, "Yedek dosyası bulunamadı")
    try:
        decrypted = _FERNET.decrypt(src_file.read_bytes())
        raw_db = gzip.decompress(decrypted)
    except Exception:
        raise HTTPException(400, "Yedek şifresi çözülemedi veya dosya bozuk")
    rconn = None
    try:
        dst_file.write_bytes(raw_db)
        rconn = sqlite3.connect(f"file:{dst_file}?mode=ro", uri=True)
        rconn.row_factory = sqlite3.Row
        p_cnt = rconn.execute("SELECT count(*) AS n FROM patients").fetchone()["n"]
        a_cnt = rconn.execute("SELECT count(*) AS n FROM appointments").fetchone()["n"]
        aud_rows = [dict(r) for r in rconn.execute("SELECT id, ts, actor, action, target, meta, prev_hash, hash FROM audit_log ORDER BY id").fetchall()]
        chain_res = sec.verify_chain(aud_rows)
    finally:
        if rconn is not None:
            rconn.close()
        dst_file.unlink(missing_ok=True)
    write_audit(u["id"], u["email"], "backup.restore_test", dst_file.name, u["ip_h"], {"patients": p_cnt}, clinic_id=u["clinic_id"])
    return {"ok": True, "restored_patients": p_cnt, "restored_appointments": a_cnt, "audit_chain_ok": chain_res["ok"]}


@app.get("/app/api/token-stats")
def token_stats(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    rows = q("""SELECT coalesce(m.layer,'-') AS layer, count(*) AS replies, coalesce(sum(m.tokens_in),0) AS tin, coalesce(sum(m.tokens_out),0) AS tout
                FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id
                WHERE m.direction='out' AND COALESCE(p.clinic_id, m.clinic_id, 1)=? GROUP BY m.layer ORDER BY replies DESC""", cid)
    return rows


@app.get("/app/api/audit")
def audit_list(u: dict = Depends(OWNER)):
    return q("SELECT id, ts, actor, action, target, meta, hash FROM audit_log WHERE clinic_id=? ORDER BY id DESC LIMIT 150", u["clinic_id"])


@app.get("/app/api/audit/verify")
def audit_verify(u: dict = Depends(HQ_OWNER)):
    rows = q("SELECT id, ts, actor, action, target, meta, prev_hash, hash FROM audit_log ORDER BY id")
    return sec.verify_chain(rows)


class LeadIn(BaseModel):
    clinic: str = Field(min_length=2, max_length=120)
    contact: str = Field(min_length=5, max_length=120)
    city: str | None = Field(default=None, max_length=40)
    chairs: int | None = Field(default=None, ge=1, le=200)
    source: str | None = Field(default=None, max_length=40)
    utm_source: str = Field("", max_length=80)
    utm_medium: str = Field("", max_length=80)
    utm_campaign: str = Field("", max_length=120)
    click_id: str = Field("", max_length=120)
    campaign_code: str = Field("", max_length=80)
    kvkk_aydinlatma: bool = False
    yurt_disi_riza: bool = False
    website: str | None = Field(default=None, max_length=200)


@app.post("/lead")
async def lead(b: LeadIn, request: Request):
    if b.website:
        return {"ok": True}
    if not b.kvkk_aydinlatma:
        raise HTTPException(400, "KVKK aydınlatma ve iletişim rızası onayı gereklidir")
    if not await _LIMITER.hit(f"lead:{client_ip(request)}", int(os.environ.get("DC_LEAD_LIMIT", "5")), 3600):
        raise HTTPException(429, "Çok fazla talep")
    texts = sec.kvkk_texts("DentaCore")
    k_hash = sec.kvkk_sha256(texts["lead"])
    det_src = detect_acquisition_source(
        explicit_source=b.source,
        utm_source=b.utm_source,
        utm_medium=b.utm_medium,
        click_id=b.click_id,
        referrer=request.headers.get("referer", ""),
        default_source="website",
    )
    t_now = iso_now()
    lead_id = ex(
        "INSERT INTO leads (clinic,contact_enc,city,chairs,kvkk_version,kvkk_sha256,yurt_disi_riza,created_at) VALUES (?,?,?,?,?,?,?,?)",
        b.clinic, enc(b.contact), b.city, b.chairs, sec.KVKK_METIN_VER, k_hash, 1 if b.yurt_disi_riza else 0, t_now,
    )
    camp_code = b.campaign_code.strip() or b.utm_campaign.strip()
    camp_row = q1("SELECT id, clinic_id FROM campaigns WHERE code=? OR utm_campaign=? LIMIT 1", camp_code, camp_code) if camp_code else None
    if camp_row:
        ua = request.headers.get("user-agent", "")
        bot_flag = 1 if is_bot_traffic(ua) else 0
        ex(
            """INSERT INTO campaign_events
               (clinic_id,campaign_id,event_type,source,utm_source,utm_medium,utm_campaign,click_id,is_bot,is_unique,user_agent_summary,created_at)
               VALUES (?,?,'form_submit',?,?,?,?,?,?,1,?,?)""",
            int(camp_row["clinic_id"]), int(camp_row["id"]), det_src, b.utm_source[:80], b.utm_medium[:80],
            b.utm_campaign[:120], b.click_id[:120], bot_flag, ua[:160], t_now,
        )
    ex("INSERT INTO alerts (clinic_id,kind,detail,created_at) VALUES (1,'web_talep',?,?)",
       f"Web sitesinden demo talebi ({PATIENT_SOURCE_LABELS.get(det_src, det_src)}): {b.clinic} ({b.city or '-'})", t_now)
    return {"ok": True, "lead_id": lead_id, "source": det_src}


ent.register_enterprise_routes(
    app,
    {
        "q": q,
        "q1": q1,
        "ex": ex,
        "db": db,
        "db_lock": _DB_LOCK,
        "current_user": current_user,
        "write_audit": write_audit,
        "enc": enc,
        "dec": dec,
        "norm_phone": norm_phone,
        "phone_hmac": phone_hmac,
        "mask_phone": mask_phone,
        "tl": tl,
        "kurus": kurus,
        "iso_now": iso_now,
        "now_utc": now_utc,
        "client_ip": client_ip,
        "root_dir": ROOT,
        "fernet": _FERNET,
    },
)


if __name__ == "__main__":
    host = os.environ.get("DC_HOST", "127.0.0.1")
    port = int(os.environ.get("DC_PORT", "8000"))
    trusted_proxy = os.environ.get("TRUSTED_PROXY") == "1"
    uvicorn.run(app, host=host, port=port, log_level="warning", server_header=False, proxy_headers=trusted_proxy)
