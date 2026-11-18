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
import os
import re
import secrets
import sqlite3
import sys
import threading
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from typing import Literal
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
from cryptography.fernet import Fernet
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
import uvicorn

ROOT = Path(__file__).resolve().parent
API_DIR = ROOT / "api"
WEB = API_DIR / "app" / "web"
DB_PATH = ROOT / "dentacore_local.db"
SECRETS_PATH = ROOT / ".local_secrets.json"
TZ = ZoneInfo("Europe/Istanbul")


def _load_secrets() -> dict[str, str]:
    if SECRETS_PATH.exists():
        try:
            return json.loads(SECRETS_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    sec_data = {
        "DATA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "PHONE_HMAC_KEY": secrets.token_hex(32),
        "ADMIN_TOKEN": secrets.token_hex(32),
    }
    SECRETS_PATH.write_text(json.dumps(sec_data, indent=2), encoding="utf-8")
    return sec_data


_SECRETS = _load_secrets()
os.environ.setdefault("DC_ALLOW_HTTP_LOCAL", "1")
os.environ.setdefault("DATA_ENCRYPTION_KEY", _SECRETS["DATA_ENCRYPTION_KEY"])
os.environ.setdefault("PHONE_HMAC_KEY", _SECRETS["PHONE_HMAC_KEY"])
os.environ.setdefault("ADMIN_TOKEN", _SECRETS["ADMIN_TOKEN"])
os.environ.setdefault("LLM_BASE_URL", "http://127.0.0.1:20128/v1")
os.environ.setdefault("LLM_SMALL_MODEL", "free-auto")
os.environ.setdefault("LLM_MAIN_MODEL", "free-auto")
os.environ.setdefault("CLINIC_NAME", "Özel DentaCore Merkez Polikliniği")

sys.path.insert(0, str(API_DIR))
from app import cal, media, security as sec  # noqa: E402
from app.router import TokenRouter  # noqa: E402

_SEEN_WEBHOOK_IDS: set[str] = set()

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


def norm_phone(p: str) -> str:
    d = re.sub(r"\D", "", p or "")
    if d.startswith("00"):
        d = d[2:]
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


def kurus(v: Decimal) -> int:
    return int((v * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def tl(k: int | None) -> float:
    return round((k or 0) / 100, 2)


def mask_phone(p: str) -> str:
    if p.startswith("ig:"):
        return "Instagram"
    d = re.sub(r"\D", "", p)
    return f"+{d[:2]} {d[2:3]}** *** {d[-4:-2]} {d[-2:]}" if len(d) >= 10 else "***"


def client_ip(request: Request) -> str:
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


def q(sql: str, *args) -> list[dict]:
    with _DB_LOCK:
        cur = db().execute(sql, args)
        return [dict(r) for r in cur.fetchall()]


def q1(sql: str, *args) -> dict | None:
    rows = q(sql, *args)
    return rows[0] if rows else None


def ex(sql: str, *args) -> int:
    with _DB_LOCK:
        c = db()
        cur = c.execute(sql, args)
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
  status      TEXT NOT NULL DEFAULT 'booked',
  source      TEXT NOT NULL DEFAULT 'panel',
  created_at  TEXT NOT NULL
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
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic_id   INTEGER NOT NULL DEFAULT 1,
  patient_id  INTEGER,
  direction   TEXT NOT NULL,
  layer       TEXT,
  intent      TEXT,
  tokens_in   INTEGER NOT NULL DEFAULT 0,
  tokens_out  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL
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
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  clinic      TEXT NOT NULL,
  contact_enc TEXT NOT NULL,
  city        TEXT,
  chairs      INTEGER,
  created_at  TEXT NOT NULL
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
        c.commit()


def _seed_clinic3():
    if q1("SELECT 1 FROM clinics WHERE id=3"):
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
        c.commit()
    _migrate_sqlite()
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
       1, "İstanbul İmplant & Zirkonyum Meta Kampanyası", "meta_ads", 420, 86, 24, 14800000, t0)

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
                  u.totp_enabled, u.share_pct, c.name AS clinic_name, c.address AS clinic_address
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
    ex("UPDATE sessions SET last_seen=? WHERE id_hash=?", iso_now(), s["id_hash"])
    s["ip_h"] = ip_hash(client_ip(request))
    s["home_clinic_id"] = int(s.get("home_clinic_id") or 1)
    s["is_hq"] = (s["home_clinic_id"] == 1 and s["role"] == "owner")
    active_cid = int(s.get("active_clinic_id") or s["home_clinic_id"])
    if not s["is_hq"] and active_cid != s["home_clinic_id"]:
        active_cid = s["home_clinic_id"]
    s["clinic_id"] = active_cid
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

app = FastAPI(title="DentaCore Local v5.0", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(sec.SecurityHeadersMiddleware)


@app.on_event("startup")
def _on_startup():
    init_and_seed()


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
    if not await _LIMITER.hit(f"ip:{ip}", 50, 900) or not await _LIMITER.hit(f"em:{email}", 15, 900):
        raise HTTPException(429, "Çok fazla deneme. Daha sonra tekrar deneyin.")
    u = q1("SELECT * FROM staff_users WHERE email=? AND active=1", email)
    ok = await asyncio.to_thread(sec.verify_password, body.password, u["pw_hash"] if u else sec.dummy_hash())
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
            "totp_enabled": bool(u["totp_enabled"]),
            "is_hq": u["is_hq"],
        },
        "clinic": u["clinic_name"],
        "clinic_id": u["clinic_id"],
        "home_clinic_id": u["home_clinic_id"],
        "idle_seconds": sec.IDLE_SECONDS,
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
    today_ymd = datetime.now(TZ).strftime("%Y-%m-%d")
    appts = q("SELECT starts_at, duration_min, status FROM appointments WHERE clinic_id=?", cid)
    today_active = [a for a in appts if a["starts_at"].startswith(today_ymd) and a["status"] in ("booked", "confirmed")]
    occ = round(100 * sum(a["duration_min"] for a in today_active) / max(1, cinfo["chairs"] * cinfo["work_minutes"]))
    done = sum(1 for a in appts if a["status"] == "done")
    noshow = sum(1 for a in appts if a["status"] == "noshow")
    avg = q1("SELECT avg(amount_kurus) AS a FROM charges WHERE clinic_id=? AND voided_at IS NULL", cid)
    avg_ticket = int(avg["a"]) if avg and avg["a"] else 350000
    billed = (q1("SELECT coalesce(sum(amount_kurus),0) AS s FROM charges WHERE clinic_id=? AND voided_at IS NULL", cid) or {})["s"]
    paid = (q1("SELECT coalesce(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND voided_at IS NULL", cid) or {})["s"]
    msgs = q("SELECT m.layer, m.tokens_in, m.tokens_out, m.direction, m.created_at FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id WHERE COALESCE(p.clinic_id, m.clinic_id, 1)=?", cid)
    out_m = [m for m in msgs if m["direction"] == "out"]
    free = sum(1 for m in out_m if (m["layer"] or "").startswith("L1"))
    series = []
    for i in range(13, -1, -1):
        d = (datetime.now(TZ) - timedelta(days=i)).strftime("%Y-%m-%d")
        lbl = (datetime.now(TZ) - timedelta(days=i)).strftime("%d.%m")
        mc = sum(1 for m in msgs if m["direction"] == "in" and m["created_at"].startswith(d))
        ac = sum(1 for a in appts if a["starts_at"].startswith(d))
        series.append({"day": lbl, "msgs": mc, "appts": ac})
    return {
        "today": {"appointments": len(today_active), "confirmed": sum(1 for a in today_active if a["status"] == "confirmed"), "occupancy": occ},
        "attendance_30d": {"done": done, "noshow": noshow, "noshow_rate": round(100 * noshow / max(1, done + noshow))},
        "loss": {"noshow_30d_try": tl(noshow * avg_ticket), "avg_ticket_try": tl(avg_ticket)},
        "month": {"billed_try": tl(billed), "paid_try": tl(paid)},
        "tokens_30d": {"replies": len(out_m), "llm_free_pct": round(100 * free / len(out_m)) if out_m else None,
                       "tokens": sum(m["tokens_in"] + m["tokens_out"] for m in out_m)},
        "counts": {
            "alerts": q1("SELECT count(*) AS n FROM alerts WHERE clinic_id=? AND acknowledged_at IS NULL", cid)["n"],
            "waitlist": q1("SELECT count(*) AS n FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE p.clinic_id=? AND w.active=1", cid)["n"],
            "refills": q1("SELECT count(*) AS n FROM alerts WHERE clinic_id=? AND kind='koltuk_dolduruldu'", cid)["n"],
            "low_stock": q1("SELECT count(*) AS n FROM inventory_items WHERE clinic_id=? AND active=1 AND qty <= min_qty AND min_qty > 0", cid)["n"],
            "postop_alarms": q1("SELECT count(*) AS n FROM postop_checks pc JOIN patients p ON p.id=pc.patient_id WHERE p.clinic_id=? AND pc.alarm=1", cid)["n"],
        },
        "series": series,
    }


@app.get("/app/api/appointments")
def list_appts(start: datetime, end: datetime, u: dict = Depends(ANY)):
    s_dt = start if start.tzinfo else start.replace(tzinfo=TZ)
    e_dt = end if end.tzinfo else end.replace(tzinfo=TZ)
    if e_dt - s_dt > timedelta(days=62):
        raise HTTPException(400, "aralık en fazla 62 gün")
    rows = q(
        """SELECT a.*, p.display_name AS patient, d.full_name AS doctor,
                  EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=a.patient_id AND x.red_flags_json <> '[]') AS red_flag
           FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
           WHERE a.clinic_id=? ORDER BY a.starts_at""",
        u["clinic_id"],
    )
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


def validate_working_hours(starts: datetime, duration_min: int, working_hours_json: str | None = None):
    s_loc = (starts if starts.tzinfo else starts.replace(tzinfo=TZ)).astimezone(TZ)
    e_loc = (s_loc + timedelta(minutes=duration_min)).astimezone(TZ)
    if s_loc.date() != e_loc.date():
        raise HTTPException(422, "Randevu aynı gün içinde başlamalı ve bitmelidir")
    try:
        wh = json.loads(working_hours_json or DEFAULT_WORKING_HOURS_JSON)
        if not isinstance(wh, dict):
            wh = json.loads(DEFAULT_WORKING_HOURS_JSON)
    except Exception:
        wh = json.loads(DEFAULT_WORKING_HOURS_JSON)

    wd = s_loc.weekday()
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
        raise HTTPException(422, "Seçilen gün klinik kapalıdır (kapalı güne randevu oluşturulamaz)")

    open_m = _parse_hhmm(hrs[0])
    close_m = _parse_hhmm(hrs[1])
    s_m = s_loc.hour * 60 + s_loc.minute
    e_m = e_loc.hour * 60 + e_loc.minute
    if s_m < open_m or e_m > close_m:
        raise HTTPException(422, f"Randevu saati klinik çalışma saatleri ({hrs[0]}-{hrs[1]}) dışındadır")


def _require_active_patient_row(c: sqlite3.Connection, pid: int, cid: int) -> sqlite3.Row:
    row = c.execute("SELECT * FROM patients WHERE id=? AND clinic_id=?", (pid, cid)).fetchone()
    if not row:
        raise HTTPException(404, "hasta yok")
    act = row["active"] if "active" in row.keys() else 1
    if not int(act if act is not None else 1):
        raise HTTPException(409, "Arşivlenmiş hasta için yeni işlem oluşturulamaz; önce aktifleştirin")
    return row


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
def create_appt(b: ApptCreate, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    starts = b.starts_at if b.starts_at.tzinfo else b.starts_at.replace(tzinfo=TZ)
    cinfo = q1("SELECT chairs, working_hours_json, buffer_min FROM clinics WHERE id=?", cid) or {
        "chairs": 2,
        "working_hours_json": DEFAULT_WORKING_HOURS_JSON,
        "buffer_min": 0,
    }
    max_chairs = int(cinfo.get("chairs") or 2)
    if not str(b.chair).isdigit() or not (1 <= int(b.chair) <= max_chairs):
        raise HTTPException(400, f"Geçersiz koltuk numarası (bu şubede {max_chairs} koltuk var)")

    with _DB_LOCK:
        c = db()
        pid = b.patient_id
        if pid is not None:
            _require_active_patient_row(c, pid, cid)
        else:
            if not b.phone or len(norm_phone(b.phone)) < 10:
                raise HTTPException(400, "Hasta seçin veya geçerli telefon girin")
            ph = phone_hmac(b.phone)
            row = c.execute("SELECT id, active FROM patients WHERE clinic_id=? AND phone_hmac=?", (cid, ph)).fetchone()
            if row:
                if not int(row["active"] if row["active"] is not None else 1):
                    raise HTTPException(409, "Arşivlenmiş hasta için yeni işlem oluşturulamaz; önce aktifleştirin")
                pid = row["id"]
            else:
                cur_p = c.execute(
                    "INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,active,created_at) VALUES (?,?,?,?,?,?,1,?)",
                    (cid, ph, enc(norm_phone(b.phone)), b.name, "tr", "wa", iso_now()),
                )
                pid = cur_p.lastrowid
        if b.doctor_id is not None:
            if not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.doctor_id, cid)).fetchone():
                raise HTTPException(404, "hekim yok")
        if starts < now_utc() - timedelta(minutes=5):
            raise HTTPException(400, "Geçmiş tarihe randevu oluşturulamaz")
        validate_working_hours(starts, b.duration_min, cinfo.get("working_hours_json"))
        buf_min = max(0, int(cinfo.get("buffer_min") or 0))
        ends = starts + timedelta(minutes=b.duration_min + buf_min)
        active_rows = c.execute(
            "SELECT id, starts_at, duration_min, chair, doctor_id FROM appointments WHERE clinic_id=? AND status IN ('booked','confirmed')",
            (cid,),
        ).fetchall()
        for ex_a in active_rows:
            s2 = datetime.fromisoformat(ex_a["starts_at"])
            if s2.tzinfo is None:
                s2 = s2.replace(tzinfo=TZ)
            e2 = s2 + timedelta(minutes=ex_a["duration_min"] + buf_min)
            if s2 < ends and e2 > starts:
                if str(ex_a["chair"]) == str(b.chair):
                    raise HTTPException(409, f"Koltuk {b.chair} bu saatte dolu (randevu #{ex_a['id']})")
                if b.doctor_id is not None and ex_a["doctor_id"] == b.doctor_id:
                    raise HTTPException(409, f"Seçilen hekim bu saatte başka koltukta dolu (randevu #{ex_a['id']})")
        cur_a = c.execute(
            "INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,doctor_id,source,created_at) VALUES (?,?,?,?,?,?,?,'panel',?)",
            (cid, pid, starts.isoformat(), b.duration_min, b.treatment, b.chair, b.doctor_id, iso_now()),
        )
        aid = cur_a.lastrowid
        c.commit()
    write_audit(u["id"], u["email"], "appointment.create", f"appointment:{aid}", u["ip_h"], {"chair": b.chair}, clinic_id=cid)
    return {"id": aid, "patient_id": pid}


class ApptUpdate(BaseModel):
    starts_at: datetime | None = None
    duration_min: int | None = Field(default=None, ge=5, le=480)
    treatment: str | None = Field(default=None, min_length=2, max_length=80)
    chair: str | None = None
    doctor_id: int | None = None


@app.patch("/app/api/appointments/{aid}")
def update_appt(aid: int, b: ApptUpdate, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    with _DB_LOCK:
        c = db()
        cur_row = c.execute("SELECT * FROM appointments WHERE id=? AND clinic_id=?", (aid, cid)).fetchone()
        if not cur_row:
            raise HTTPException(404, "randevu yok")
        cinfo = c.execute("SELECT chairs, working_hours_json, buffer_min FROM clinics WHERE id=?", (cid,)).fetchone()
        max_chairs = int((cinfo and cinfo["chairs"]) or 2)
        chair = str(b.chair if b.chair is not None else cur_row["chair"])
        if not chair.isdigit() or not (1 <= int(chair) <= max_chairs):
            raise HTTPException(400, "Geçersiz koltuk numarası")
        doc_id = b.doctor_id if b.doctor_id is not None else cur_row["doctor_id"]
        if doc_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (doc_id, cid)).fetchone():
            raise HTTPException(404, "hekim yok")
        starts = (b.starts_at if b.starts_at.tzinfo else b.starts_at.replace(tzinfo=TZ)) if b.starts_at else datetime.fromisoformat(cur_row["starts_at"])
        if starts.tzinfo is None:
            starts = starts.replace(tzinfo=TZ)
        if starts < now_utc() - timedelta(minutes=5):
            raise HTTPException(400, "Geçmiş tarihe randevu taşınamaz")
        dur = b.duration_min if b.duration_min is not None else cur_row["duration_min"]
        validate_working_hours(starts, dur, (cinfo and cinfo["working_hours_json"]) or DEFAULT_WORKING_HOURS_JSON)
        treat = b.treatment if b.treatment is not None else cur_row["treatment"]
        buf_min = max(0, int((cinfo and cinfo["buffer_min"]) or 0))
        ends = starts + timedelta(minutes=dur + buf_min)
        others = c.execute(
            "SELECT id, starts_at, duration_min, chair, doctor_id FROM appointments WHERE clinic_id=? AND id<>? AND status IN ('booked','confirmed')",
            (cid, aid),
        ).fetchall()
        for ex_a in others:
            s2 = datetime.fromisoformat(ex_a["starts_at"])
            if s2.tzinfo is None:
                s2 = s2.replace(tzinfo=TZ)
            e2 = s2 + timedelta(minutes=ex_a["duration_min"] + buf_min)
            if s2 < ends and e2 > starts:
                if str(ex_a["chair"]) == chair:
                    raise HTTPException(409, f"Koltuk {chair} bu saatte dolu")
                if doc_id is not None and ex_a["doctor_id"] == doc_id:
                    raise HTTPException(409, "Seçilen hekim bu saatte dolu")
        c.execute(
            "UPDATE appointments SET starts_at=?, duration_min=?, treatment=?, chair=?, doctor_id=? WHERE id=? AND clinic_id=?",
            (starts.isoformat(), dur, treat, chair, doc_id, aid, cid),
        )
        c.commit()
    write_audit(u["id"], u["email"], "appointment.update", f"appointment:{aid}", u["ip_h"], {"chair": chair}, clinic_id=cid)
    return {"ok": True, "id": aid}


class StatusIn(BaseModel):
    status: Literal["confirmed", "done", "noshow", "cancelled"]


@app.post("/app/api/appointments/{aid}/status")
def appt_status(aid: int, b: StatusIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    a = q1("SELECT * FROM appointments WHERE id=? AND clinic_id=?", aid, cid)
    if not a:
        raise HTTPException(404, "randevu yok")
    ex("UPDATE appointments SET status=? WHERE id=? AND clinic_id=?", b.status, aid, cid)
    offers = 0
    if b.status == "cancelled":
        cands = q("SELECT w.id FROM waitlist w JOIN patients p ON p.id=w.patient_id WHERE p.clinic_id=? AND w.active=1 AND (? IS NULL OR w.patient_id <> ?) LIMIT 5",
                  cid, a["patient_id"], a["patient_id"])
        for c in cands:
            ex("INSERT INTO slot_offers (appointment_id,waitlist_id,wave,sent_at,status) VALUES (?,?,1,?,'sent')", aid, c["id"], iso_now())
            offers += 1
        write_audit(u["id"], u["email"], "appointment.cancel", f"appointment:{aid}", u["ip_h"], {"offers": offers}, clinic_id=cid)
        return {"ok": True, "waitlist_offers": offers}
    write_audit(u["id"], u["email"], f"appointment.{b.status}", f"appointment:{aid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.get("/app/api/appointments/{aid}/ics")
def appt_ics(aid: int, u: dict = Depends(ANY)):
    r = q1(
        """SELECT a.*, p.display_name AS patient, d.full_name AS doctor,
                  EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=a.patient_id AND x.red_flags_json <> '[]') AS red_flag
           FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
           WHERE a.id=? AND a.clinic_id=?""",
        aid, u["clinic_id"],
    )
    if not r:
        raise HTTPException(404, "randevu yok")
    return PlainTextResponse(cal.appointment_ics(r, u["clinic_name"], u["clinic_address"]),
                             media_type="text/calendar; charset=utf-8",
                             headers={"content-disposition": f'attachment; filename="randevu-{aid}.ics"'})


@app.get("/app/api/calendar-links")
def calendar_links(request: Request, u: dict = Depends(ANY)):
    tok = cal.calendar_feed_token(u["clinic_id"])
    base = str(request.base_url).rstrip("/")
    ics_url = f"{base}/calendar/{tok}.ics"
    webcal_url = "webcal://" + ics_url.split("://", 1)[-1]
    google_subscribe_url = "https://calendar.google.com/calendar/r?cid=" + quote(webcal_url, safe="")
    return {"ics_url": ics_url, "webcal_url": webcal_url, "google_subscribe_url": google_subscribe_url,
            "iphone_guide": "Ayarlar > Takvim > Hesaplar > Hesap Ekle > Diğer > Abone Olunan Takvim Ekle kısmına webcal adresini yapıştırın.",
            "android_guide": "Her randevudaki '+ Android' butonuna basarak Google Takvime ekleyin veya Google Takvim webde URL ile abone olun."}


@app.get("/app/api/calendar/all.ics")
def calendar_all_ics(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    rows = q(
        """SELECT a.*, p.display_name AS patient, d.full_name AS doctor,
                  EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=a.patient_id AND x.red_flags_json <> '[]') AS red_flag
           FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
           WHERE a.clinic_id=? AND a.status IN ('booked','confirmed') ORDER BY a.starts_at LIMIT 500""",
        cid,
    )
    return PlainTextResponse(
        cal.feed_ics(rows, u["clinic_name"], u["clinic_address"]),
        media_type="text/calendar; charset=utf-8",
        headers={"content-disposition": f'attachment; filename="dentacore-klinik-{cid}-takvim.ics"'},
    )


@app.get("/calendar/{token}.ics")
def calendar_feed(token: str):
    cid = cal.verify_feed_token(token)
    if not cid:
        raise HTTPException(403, "geçersiz takvim bağlantısı")
    c = q1("SELECT name, address FROM clinics WHERE id=?", cid) or {"name": "DentaCore", "address": ""}
    rows = q(
        """SELECT a.*, p.display_name AS patient, d.full_name AS doctor,
                  EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=a.patient_id AND x.red_flags_json <> '[]') AS red_flag
           FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id LEFT JOIN staff_users d ON d.id=a.doctor_id
           WHERE a.clinic_id=? ORDER BY a.starts_at LIMIT 500""",
        cid,
    )
    return PlainTextResponse(cal.feed_ics(rows, c["name"], c["address"]), media_type="text/calendar; charset=utf-8")


# ---------------- Hastalar, Odontogram, Bekleme Listesi, Uyarılar, Envanter, Kasa ----------------
@app.get("/app/api/patients")
def list_patients(search: str = "", include_archived: bool = False, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    if include_archived:
        rows = q("SELECT * FROM patients WHERE clinic_id=? ORDER BY id DESC", cid)
    else:
        rows = q("SELECT * FROM patients WHERE clinic_id=? AND active=1 ORDER BY id DESC", cid)
    s = search.strip().lower()
    out = []
    for p in rows:
        if s and s not in (p["display_name"] or "").lower() and phone_hmac(s) != p["phone_hmac"]:
            continue
        billed = q1("SELECT coalesce(sum(amount_kurus),0) AS k FROM charges WHERE patient_id=? AND voided_at IS NULL", p["id"])["k"]
        paid = q1("SELECT coalesce(sum(amount_kurus),0) AS k FROM payments WHERE patient_id=? AND voided_at IS NULL", p["id"])["k"]
        rf = q1("SELECT 1 FROM anamnesis WHERE patient_id=? AND red_flags_json <> '[]'", p["id"])
        la = q1("SELECT max(starts_at) AS d FROM appointments WHERE patient_id=?", p["id"])
        out.append({"id": p["id"], "display_name": p["display_name"], "lang": p["lang"], "channel": p["channel"],
                    "active": bool(p.get("active", 1)), "balance": tl(billed - paid), "red_flag": bool(rf), "last_appt": la["d"] if la else None})
    return out


class PatientIn(BaseModel):
    phone: str = Field(max_length=30)
    name: str = Field(min_length=2, max_length=80)
    lang: Literal["tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he"] = "tr"


@app.post("/app/api/patients")
def create_patient(b: PatientIn, u: dict = Depends(ANY)):
    if len(norm_phone(b.phone)) < 10:
        raise HTTPException(400, "Geçerli telefon girin")
    cid = u["clinic_id"]
    ph = phone_hmac(b.phone)
    ex_p = q1("SELECT id FROM patients WHERE clinic_id=? AND phone_hmac=?", cid, ph)
    if ex_p:
        return {"id": ex_p["id"], "duplicate": True}
    pid = ex("INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,created_at) VALUES (?,?,?,?,?,?,?)",
             cid, ph, enc(norm_phone(b.phone)), b.name, b.lang, "wa", iso_now())
    write_audit(u["id"], u["email"], "patient.create", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"id": pid, "duplicate": False}


class PatientUpdateIn(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=80)
    phone: str | None = Field(default=None, max_length=30)
    lang: Literal["tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he"] | None = None


@app.patch("/app/api/patients/{pid}")
def update_patient(pid: int, b: PatientUpdateIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    p = q1("SELECT * FROM patients WHERE id=? AND clinic_id=?", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    new_name = b.name if b.name is not None else p["display_name"]
    new_lang = b.lang if b.lang is not None else p["lang"]
    if b.phone is not None:
        if len(norm_phone(b.phone)) < 10:
            raise HTTPException(400, "Geçerli telefon girin")
        ph = phone_hmac(b.phone)
        pe = enc(norm_phone(b.phone))
    else:
        ph = p["phone_hmac"]
        pe = p["phone_enc"]
    ex("UPDATE patients SET display_name=?, lang=?, phone_hmac=?, phone_enc=? WHERE id=? AND clinic_id=?",
       new_name, new_lang, ph, pe, pid, cid)
    write_audit(u["id"], u["email"], "patient.update", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"ok": True, "id": pid}


@app.post("/app/api/patients/{pid}/archive")
def archive_patient(pid: int, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    ex("UPDATE patients SET active=0 WHERE id=? AND clinic_id=?", pid, cid)
    write_audit(u["id"], u["email"], "patient.archive", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.post("/app/api/patients/{pid}/unarchive")
def unarchive_patient(pid: int, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    ex("UPDATE patients SET active=1 WHERE id=? AND clinic_id=?", pid, cid)
    write_audit(u["id"], u["email"], "patient.unarchive", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.post("/app/api/patients/{pid}/media")
async def upload_patient_media(pid: int, request: Request, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    if not q1("SELECT id FROM patients WHERE id=? AND clinic_id=?", pid, cid):
        raise HTTPException(404, "hasta yok")
    data = b""
    ctype = request.headers.get("content-type", "")
    if "multipart/form-data" in ctype:
        try:
            form = await request.form()
            up = form.get("file")
            if up and hasattr(up, "read"):
                data = await up.read()
        except Exception:
            raw_body = await request.body()
            idx = raw_body.find(b"\xff\xd8\xff")
            if idx != -1:
                end_idx = raw_body.rfind(b"\xff\xd9")
                data = raw_body[idx:end_idx + 2] if end_idx != -1 else raw_body[idx:]
    else:
        data = await request.body()
    if not data or len(data) > 15 * 1024 * 1024:
        raise HTTPException(400, "Geçersiz dosya boyutu")
    try:
        qc = media.assess_image(data)
    except Exception:
        raise HTTPException(400, "Geçersiz görsel formatı")
    img_dir = ROOT / "encrypted_media"
    img_dir.mkdir(parents=True, exist_ok=True)
    enc_path = img_dir / f"p{pid}_{secrets.token_hex(6)}.jpg.enc"
    enc_path.write_bytes(_FERNET.encrypt(data))
    if qc["verdict"] == "ok":
        ex("INSERT INTO alerts (clinic_id,patient_id,kind,detail,created_at) VALUES (?,?,'gorsel_alindi',?,?)",
           cid, pid, f"Hasta #{pid} değerlendirmeye uygun görsel yükledi ({qc['w']}x{qc['h']}).", iso_now())
    write_audit(u["id"], u["email"], "patient.media_upload", f"patient:{pid}", u["ip_h"], {"verdict": qc["verdict"]}, clinic_id=cid)
    return {**qc, "encrypted_file": enc_path.name}


@app.get("/app/api/patients/{pid}")
def get_patient(pid: int, reveal: bool = False, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    p = q1("SELECT * FROM patients WHERE id=? AND clinic_id=?", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    phone = dec(p["phone_enc"])
    write_audit(u["id"], u["email"], "patient.reveal_phone" if reveal else "patient.view", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    billed = q1("SELECT coalesce(sum(amount_kurus),0) AS k FROM charges WHERE patient_id=? AND voided_at IS NULL", pid)["k"]
    paid = q1("SELECT coalesce(sum(amount_kurus),0) AS k FROM payments WHERE patient_id=? AND voided_at IS NULL", pid)["k"]
    charges = q("SELECT id, description, amount_kurus, created_at, voided_at FROM charges WHERE patient_id=? ORDER BY id DESC", pid)
    pays = q("SELECT id, amount_kurus, method, created_at, voided_at FROM payments WHERE patient_id=? ORDER BY id DESC", pid)
    for c in charges + pays:
        c["amount"] = tl(c.pop("amount_kurus"))
    anam = q("SELECT id, red_flags_json, signed_at FROM anamnesis WHERE patient_id=? ORDER BY id DESC", pid)
    for a in anam:
        a["red_flags"] = json.loads(a.pop("red_flags_json") or "[]")
    return {
        "id": p["id"], "name": p["display_name"], "lang": p["lang"], "channel": p["channel"],
        "active": bool(p.get("active", 1)),
        "phone": phone if reveal else mask_phone(phone), "balance": tl(billed - paid),
        "appointments": q("SELECT id, starts_at, treatment, status, chair FROM appointments WHERE patient_id=? ORDER BY starts_at DESC", pid),
        "charges": charges, "payments": pays, "anamnesis": anam,
        "consents": q("SELECT kind, text_version, granted_at, revoked_at FROM consents WHERE patient_id=?", pid),
        "anamnesis_links": {a["id"]: sign_path(f"/view/anamnez/{a['id']}", 900) for a in anam} if u["role"] != "secretary" else {},
    }


class OdontogramIn(BaseModel):
    tooth_fdi: int
    surface: Literal["M", "D", "O", "B", "L", "FULL"] = "FULL"
    status: Literal["healthy", "caries", "planned", "treated", "implant", "crown", "root_canal", "missing", "extraction"] = "planned"
    procedure_code: str = Field("", max_length=40)
    procedure_name: str = Field(min_length=2, max_length=120)
    amount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
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


class OdontogramUpdateIn(BaseModel):
    surface: Literal["M", "D", "O", "B", "L", "FULL"] | None = None
    status: Literal["healthy", "caries", "planned", "treated", "implant", "crown", "root_canal", "missing", "extraction"] | None = None
    procedure_code: str | None = Field(default=None, max_length=40)
    procedure_name: str | None = Field(default=None, min_length=2, max_length=120)
    amount: Decimal | None = Field(default=None, ge=0, le=10_000_000)
    doctor_id: int | None = None
    note: str | None = Field(default=None, max_length=300)


@app.get("/app/api/patients/{pid}/odontogram")
def get_odontogram(pid: int, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    p = q1("SELECT id, display_name FROM patients WHERE id=? AND clinic_id=?", pid, cid)
    if not p:
        raise HTTPException(404, "hasta yok")
    rows = q(
        """SELECT t.*, s.full_name AS doctor_name
           FROM tooth_records t LEFT JOIN staff_users s ON s.id=t.doctor_id
           WHERE t.clinic_id=? AND t.patient_id=? ORDER BY t.tooth_fdi, t.id DESC""",
        cid, pid,
    )
    for r in rows:
        r["amount_try"] = tl(r["amount_kurus"])
    return {
        "patient_id": pid,
        "clinic_id": cid,
        "records": rows,
        "summary": {
            "total_records": len(rows),
            "treated_count": sum(1 for r in rows if r["status"] in ("treated", "implant", "crown", "root_canal")),
            "planned_count": sum(1 for r in rows if r["status"] in ("planned", "caries", "extraction")),
        },
    }


@app.post("/app/api/patients/{pid}/odontogram")
def add_odontogram_record(pid: int, b: OdontogramIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    amt_k = kurus(b.amount)
    charge_id = None
    with _DB_LOCK:
        c = db()
        _require_active_patient_row(c, pid, cid)
        if b.doctor_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.doctor_id, cid)).fetchone():
            raise HTTPException(404, "hekim yok")
        t_now = iso_now()
        cur_t = c.execute(
            """INSERT INTO tooth_records
               (clinic_id,patient_id,tooth_fdi,surface,status,procedure_code,procedure_name,amount_kurus,doctor_id,note,created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (cid, pid, b.tooth_fdi, b.surface, b.status, b.procedure_code, b.procedure_name, amt_k, b.doctor_id or u["id"], b.note, t_now),
        )
        rid = cur_t.lastrowid
        if b.auto_charge and amt_k > 0:
            if b.idempotency_key:
                dup = c.execute("SELECT id FROM charges WHERE clinic_id=? AND idempotency_key=?", (cid, b.idempotency_key)).fetchone()
                if dup:
                    raise HTTPException(409, "Bu odontogram hizmet borçlandırması zaten işlendi")
            desc = f"Diş #{b.tooth_fdi} ({b.surface}) - {b.procedure_name}"[:120]
            cur_ch = c.execute(
                "INSERT INTO charges (clinic_id,patient_id,description,amount_kurus,doctor_id,created_by,created_at,idempotency_key) VALUES (?,?,?,?,?,?,?,?)",
                (cid, pid, desc, amt_k, b.doctor_id or u["id"], u["id"], t_now, b.idempotency_key),
            )
            charge_id = cur_ch.lastrowid
        c.commit()
    write_audit(u["id"], u["email"], "odontogram.create", f"patient:{pid}:tooth:{b.tooth_fdi}", u["ip_h"],
                {"surface": b.surface, "status": b.status, "charge_id": charge_id}, clinic_id=cid)
    return {"id": rid, "tooth_fdi": b.tooth_fdi, "surface": b.surface, "status": b.status, "charge_id": charge_id}


@app.patch("/app/api/patients/{pid}/odontogram/{rid}")
def update_odontogram_record(pid: int, rid: int, b: OdontogramUpdateIn, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    rec = q1("SELECT * FROM tooth_records WHERE id=? AND patient_id=? AND clinic_id=?", rid, pid, cid)
    if not rec:
        raise HTTPException(404, "diş kaydı yok")
    new_surface = b.surface if b.surface is not None else rec["surface"]
    new_status = b.status if b.status is not None else rec["status"]
    new_code = b.procedure_code if b.procedure_code is not None else rec["procedure_code"]
    new_name = b.procedure_name if b.procedure_name is not None else rec["procedure_name"]
    new_amt = kurus(b.amount) if b.amount is not None else rec["amount_kurus"]
    new_doc = b.doctor_id if b.doctor_id is not None else rec["doctor_id"]
    new_note = b.note if b.note is not None else rec["note"]
    ex(
        """UPDATE tooth_records SET surface=?, status=?, procedure_code=?, procedure_name=?, amount_kurus=?, doctor_id=?, note=?
           WHERE id=? AND patient_id=? AND clinic_id=?""",
        new_surface, new_status, new_code, new_name, new_amt, new_doc, new_note, rid, pid, cid,
    )
    write_audit(u["id"], u["email"], "odontogram.update", f"tooth_record:{rid}", u["ip_h"], {"status": new_status}, clinic_id=cid)
    return {"ok": True, "id": rid}


@app.delete("/app/api/patients/{pid}/odontogram/{rid}")
def delete_odontogram_record(pid: int, rid: int, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    rec = q1("SELECT id FROM tooth_records WHERE id=? AND patient_id=? AND clinic_id=?", rid, pid, cid)
    if not rec:
        raise HTTPException(404, "diş kaydı yok")
    ex("DELETE FROM tooth_records WHERE id=? AND patient_id=? AND clinic_id=?", rid, pid, cid)
    write_audit(u["id"], u["email"], "odontogram.delete", f"tooth_record:{rid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.post("/app/api/patients/{pid}/anamnesis")
def send_anam(pid: int, request: Request, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    with _DB_LOCK:
        _require_active_patient_row(db(), pid, cid)
    tok = secrets.token_urlsafe(24)
    ex("INSERT INTO anamnesis_tokens (token,patient_id,expires_at) VALUES (?,?,?)",
       tok, pid, (now_utc() + timedelta(hours=48)).isoformat())
    write_audit(u["id"], u["email"], "anamnesis.send", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"link": f"{public_base(request)}/form/anamnez/{tok}"}


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
label.f{display:block;font-weight:600;font-size:14.5px;margin:18px 0 6px}input[type=text]{width:100%;min-height:48px;padding:10px 12px;font:inherit;border:1px solid #64748B;border-radius:10px}
.kvkk{display:flex;gap:10px;align-items:flex-start;font-size:13.5px;color:var(--muted);margin-top:14px}.kvkk input{margin-top:3px;width:18px;height:18px;accent-color:var(--teal);flex:none}
button{width:100%;min-height:50px;margin-top:18px;background:var(--teal);color:#fff;border:0;border-radius:10px;font:inherit;font-weight:700;font-size:16px;cursor:pointer;transition:background-color .15s}button:hover{background:var(--teal-h)}
:focus-visible{outline:3px solid #5EEAD4;outline-offset:2px}
.foot{color:var(--muted);font-size:12.5px;text-align:center;margin-top:18px}
table{width:100%;border-collapse:collapse;font-size:14.5px}td{border-top:1px solid var(--line);padding:10px 6px;vertical-align:top}td.a{font-weight:700;white-space:nowrap;text-align:right}
tr.flag td{background:var(--red-bg);color:var(--red)}.ok{color:var(--teal);font-weight:700}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

_SHIELD = ('<svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#0F766E" stroke-width="1.8" stroke-linecap="round" '
           'stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>')


def _patient_page(title: str, clinic: str, inner: str, status: int = 200) -> HTMLResponse:
    page = (f"<!doctype html><html lang=tr><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<meta name=robots content='noindex,nofollow'><title>{html_lib.escape(title)}</title><style>{_PATIENT_CSS}</style></head><body><main>"
            f"<div class=head>{_SHIELD}<div><b>{html_lib.escape(clinic)}</b><small>Güvenli hasta formu</small></div></div>"
            f"<div class=card>{inner}</div><p class=foot>Bilgileriniz şifrelenerek yalnızca hekiminizle paylaşılır.</p></main></body></html>")
    return HTMLResponse(page, status_code=status)


def _anam_token(token: str):
    t = q1("SELECT * FROM anamnesis_tokens WHERE token=? AND used_at IS NULL", token)
    if not t or (t.get("expires_at") and datetime.fromisoformat(t["expires_at"]) < now_utc()):
        return None, None
    c = q1("SELECT c.name FROM patients p JOIN clinics c ON c.id=p.clinic_id WHERE p.id=?", t["patient_id"])
    return t, (c["name"] if c else os.environ.get("CLINIC_NAME", "Kliniğimiz"))


_INVALID_LINK = ("<h1>Bu bağlantı artık geçerli değil</h1><p class=lead>Form daha önce doldurulmuş ya da 48 saatlik süresi dolmuş olabilir. "
                 "Yeni bir bağlantı için lütfen kliniğinizi arayın.</p>")


@app.get("/form/anamnez/{token}", response_class=HTMLResponse)
def anamnez_form(token: str):
    t, clinic = _anam_token(token)
    if not t:
        return _patient_page("Bağlantı geçersiz", os.environ.get("CLINIC_NAME", "Kliniğimiz"), _INVALID_LINK, 400)
    rows = "".join(
        f"<fieldset><legend>{i}. {html_lib.escape(q_text)}</legend><div class=opts>"
        f"<label><input type=radio name={k} value=evet required> Evet</label>"
        f"<label><input type=radio name={k} value=hayir> Hayır</label></div></fieldset>"
        for i, (k, q_text, _) in enumerate(ANAMNEZ_SORULAR, 1))
    inner = ("<h1>Sağlık Bilgi Formu</h1><p class=lead>Tedaviniz güvenle planlansın diye 11 kısa soru. Yaklaşık 2 dakika sürer.</p>"
             "<div class=note>Emin olmadığınız bir soru varsa \"Evet\" işaretleyin; hekiminiz muayenede sizinle birlikte netleştirir.</div>"
             f"<form method=post>{rows}<label class=f for=imza>Adınız ve soyadınız</label>"
             "<input type=text id=imza name=imza required maxlength=80 autocomplete=name>"
             "<label class=kvkk><input type=checkbox name=kvkk value=1 required> Sağlık verilerimin yalnızca tedavim amacıyla, 6698 sayılı KVKK "
             "kapsamında kliniğim tarafından işlenmesine açık rıza veriyorum.</label>"
             "<button type=submit>Onayla ve gönder</button></form>")
    return _patient_page("Sağlık Bilgi Formu", clinic, inner)


@app.post("/form/anamnez/{token}", response_class=HTMLResponse)
async def anamnez_submit(token: str, request: Request):
    t, clinic = _anam_token(token)
    if not t:
        return _patient_page("Bağlantı geçersiz", os.environ.get("CLINIC_NAME", "Kliniğimiz"), _INVALID_LINK, 400)
    form = dict(await request.form())
    if str(form.get("kvkk", "")) != "1":
        return _patient_page("Onay gerekli", clinic, "<h1>Açık rıza onayı gerekli</h1><p class=lead>Formu göndermek için KVKK onay kutusunu işaretleyin. "
                             "Geri dönüp tekrar deneyebilirsiniz.</p>", 400)
    ans = {k: str(form.get(k, "")) for k, _, _ in ANAMNEZ_SORULAR}
    flags = [k for k, _, red in ANAMNEZ_SORULAR if red and ans.get(k) == "evet"]
    imza = str(form.get("imza", "Hasta")).strip()[:80] or "Hasta"
    sig = hashlib.sha256(f"{t['patient_id']}|{imza}".encode()).hexdigest()
    now_s = iso_now()
    ex("INSERT INTO anamnesis (patient_id,answers_enc,red_flags_json,signer_name,signature_sha256,signed_at) VALUES (?,?,?,?,?,?)",
       t["patient_id"], enc(json.dumps(ans)), json.dumps(flags), imza, sig, now_s)
    ex("UPDATE anamnesis_tokens SET used_at=? WHERE token=?", now_s, token)
    kvkk_hash = hashlib.sha256(f"kvkk-2026-11|{clinic}".encode()).hexdigest()
    for c_kind in ("kvkk_aydinlatma", "saglik_verisi_acik_riza"):
        ex("INSERT INTO consents (patient_id,kind,text_version,text_sha256,channel,granted_at) VALUES (?,?,?,?,?,?)",
           t["patient_id"], c_kind, "2026-11", kvkk_hash, "web_form", now_s)
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
        "<form method=post>"
        f"<input type=hidden name=csrf_token value=\"{tok}\">"
        "<label class=f for=mesaj>Mesajınız</label>"
        "<input type=text id=mesaj name=mesaj required maxlength=1500>"
        "<label class=f for=iletisim>Telefon (isteğe bağlı)</label>"
        "<input type=text id=iletisim name=iletisim maxlength=40>"
        "<button type=submit>Gönder</button></form>"
    )
    return _patient_page("Başhekimliğe İlet", clinic, inner)


@app.post("/form/geri-bildirim", response_class=HTMLResponse)
async def feedback_submit(request: Request):
    clinic = os.environ.get("CLINIC_NAME", "Özel DentaCore Merkez Polikliniği")
    f = dict(await request.form())
    from urllib.parse import parse_qs
    tok_p = parse_qs(str(f.get("csrf_token", "")))
    if not verify_sig("/form/geri-bildirim", (tok_p.get("exp") or [""])[0], (tok_p.get("sig") or [""])[0]):
        raise HTTPException(403, "Form oturumu geçersiz veya süresi dolmuş")
    msg = str(f.get("mesaj", "")).strip()[:1500]
    if msg:
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


async def _process_inbound_webhook_msg(sender: str, profile_name: str | None, mtype: str, text: str, channel: str = "wa", clinic_id: int = 1):
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

    with _DB_LOCK:
        c = db()
        row = c.execute("SELECT id, display_name FROM patients WHERE clinic_id=? AND phone_hmac=?", (clinic_id, ph)).fetchone()
        if row:
            pid = row["id"]
            if profile_name and not row["display_name"]:
                c.execute("UPDATE patients SET display_name=?, lang=? WHERE id=?", (profile_name, lang, pid))
        else:
            cur_p = c.execute(
                "INSERT INTO patients (clinic_id,phone_hmac,phone_enc,display_name,lang,channel,active,created_at) VALUES (?,?,?,?,?,?,1,?)",
                (clinic_id, ph, enc(raw_id), profile_name or f"Misafir ({sender[-4:]})", lang, channel, t_now),
            )
            pid = cur_p.lastrowid
        c.execute(
            "INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,'in',NULL,?,0,0,?)",
            (clinic_id, pid, f"{channel}:{mtype}", t_now),
        )
        c.commit()

    if not text:
        return

    c_row = q1("SELECT name, address, phone FROM clinics WHERE id=?", clinic_id)
    all_branches = q("SELECT id, name, city, address, phone FROM clinics WHERE active=1")
    facts: dict = {
        "clinic": (c_row and c_row["name"]) or os.environ.get("CLINIC_NAME", "Özel DentaCore Merkez Polikliniği"),
        "branches": all_branches,
    }
    if c_row and c_row.get("address"):
        facts["adres"] = c_row["address"]
    if c_row and c_row.get("phone"):
        facts["telefon"] = c_row["phone"]

    try:
        res = await asyncio.wait_for(_ROUTER.route(text, lang=lang, clinic_facts=facts, allow_llm=True, patient_id=pid), timeout=10.0)
    except Exception:
        res = await _ROUTER.route(text, lang=lang, clinic_facts=facts, allow_llm=False, patient_id=pid)

    ex(
        "INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,'out',?,?,?,?,?)",
        clinic_id, pid, res.layer, res.intent, res.tokens_in, res.tokens_out, iso_now(),
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


@app.post("/webhook/whatsapp")
async def wa_webhook_local(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    raw = await request.body()
    secret = os.environ.get("WA_APP_SECRET", "")
    if not secret or not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256="):
        raise HTTPException(401, "imza geçersiz")
    good = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, x_hub_signature_256[7:]):
        raise HTTPException(401, "imza geçersiz")
    body = json.loads(raw)
    processed = 0
    dedup = 0
    for entry in body.get("entry", []):
        for ch in entry.get("changes", []):
            v = ch.get("value", {})
            names = {c.get("wa_id"): (c.get("profile") or {}).get("name") for c in v.get("contacts", []) if isinstance(c, dict)}
            for m in v.get("messages", []):
                mid = str(m.get("id") or "")
                if mid in _SEEN_WEBHOOK_IDS:
                    dedup += 1
                    continue
                if mid:
                    _SEEN_WEBHOOK_IDS.add(mid)
                sender = str(m.get("from") or "")
                mtype = str(m.get("type") or "text")
                text = ""
                if mtype == "text":
                    text = str((m.get("text") or {}).get("body") or "")
                elif mtype == "button":
                    text = str((m.get("button") or {}).get("text") or "")
                elif mtype == "interactive":
                    it = m.get("interactive") or {}
                    rep = it.get("button_reply") or it.get("list_reply") or {}
                    text = str(rep.get("title") or "")
                if sender:
                    await _process_inbound_webhook_msg(sender, names.get(sender), mtype, text, channel="wa", clinic_id=1)
                processed += 1
    return {"ok": True, "processed": processed, "dedup": dedup}


@app.post("/webhook/instagram")
async def ig_webhook_local(request: Request, x_hub_signature_256: str | None = Header(default=None)):
    raw = await request.body()
    secret = os.environ.get("IG_APP_SECRET") or os.environ.get("WA_APP_SECRET", "")
    if not secret or not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256="):
        raise HTTPException(401, "imza geçersiz")
    good = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(good, x_hub_signature_256[7:]):
        raise HTTPException(401, "imza geçersiz")
    body = json.loads(raw)
    processed = 0
    for entry in body.get("entry", []):
        for ev in entry.get("messaging", []):
            msg = ev.get("message") or {}
            if msg.get("is_echo") or not msg.get("text"):
                continue
            mid = str(msg.get("mid") or "")
            if mid and mid in _SEEN_WEBHOOK_IDS:
                continue
            if mid:
                _SEEN_WEBHOOK_IDS.add(mid)
            sender = str((ev.get("sender") or {}).get("id") or "")
            if sender:
                await _process_inbound_webhook_msg(sender, None, "text", str(msg["text"]), channel="ig", clinic_id=1)
                processed += 1
    return {"ok": True, "processed": processed}


@app.get("/app/api/alerts")
def alerts(u: dict = Depends(ANY)):
    return q("SELECT id, patient_id, kind, detail, created_at FROM alerts WHERE clinic_id=? AND acknowledged_at IS NULL ORDER BY id DESC", u["clinic_id"])


@app.post("/app/api/alerts/{aid}/ack")
def ack(aid: int, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    if not q1("SELECT id FROM alerts WHERE id=? AND clinic_id=? AND acknowledged_at IS NULL", aid, cid):
        raise HTTPException(404, "uyarı yok")
    ex("UPDATE alerts SET acknowledged_at=? WHERE id=? AND clinic_id=?", iso_now(), aid, cid)
    write_audit(u["id"], u["email"], "alert.ack", f"alert:{aid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


@app.get("/app/api/inventory")
def inventory(u: dict = Depends(ANY)):
    rows = q("SELECT * FROM inventory_items WHERE clinic_id=? AND active=1 ORDER BY id", u["clinic_id"])
    for r in rows:
        r["unit_cost"] = tl(r.pop("unit_cost_kurus"))
        r["value"] = round(r["qty"] * r["unit_cost"], 2)
        r["low"] = bool(r["min_qty"] > 0 and r["qty"] <= r["min_qty"])
    return rows


class ItemIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    sku: str | None = Field(default=None, max_length=40)
    unit: str = Field("adet", max_length=16)
    qty: Decimal = Field(Decimal(0), ge=0, le=1_000_000)
    min_qty: Decimal = Field(Decimal(0), ge=0, le=1_000_000)
    unit_cost: Decimal = Field(Decimal(0), ge=0, le=10_000_000)


@app.post("/app/api/inventory")
def add_item(b: ItemIn, u: dict = Depends(ANY)):
    iid = ex("INSERT INTO inventory_items (clinic_id,name,sku,unit,qty,min_qty,unit_cost_kurus,created_at) VALUES (?,?,?,?,?,?,?,?)",
             u["clinic_id"], b.name, b.sku, b.unit, float(b.qty), float(b.min_qty), kurus(b.unit_cost), iso_now())
    if b.qty > 0:
        ex("INSERT INTO stock_moves (item_id,delta,qty_after,reason,actor_id,created_at) VALUES (?,?,?,'ilk stok',?,?)", iid, float(b.qty), float(b.qty), u["id"], iso_now())
    return {"id": iid}


class MoveIn(BaseModel):
    delta: Decimal = Field(ge=-1_000_000, le=1_000_000)
    reason: str = Field(min_length=2, max_length=120)

    @field_validator("delta")
    @classmethod
    def nonzero(cls, v):
        if v == 0:
            raise ValueError("miktar sıfır olamaz")
        return v


@app.post("/app/api/inventory/{iid}/move")
def move_item(iid: int, b: MoveIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    delta_f = float(b.delta)
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
            "INSERT INTO stock_moves (item_id,delta,qty_after,reason,actor_id,created_at) VALUES (?,?,?,?,?,?)",
            (iid, delta_f, new_qty, b.reason, u["id"], iso_now()),
        )
        if new_qty <= float(it["min_qty"]) and float(it["min_qty"]) > 0:
            c.execute(
                "INSERT INTO alerts (clinic_id,kind,detail,created_at) VALUES (?,'stok_kritik',?,?)",
                (cid, f"Stok kritik: {it['name']} ({new_qty} {it['unit']})", iso_now()),
            )
        c.commit()
    write_audit(u["id"], u["email"], "inventory.move", f"item:{iid}", u["ip_h"], {"delta": str(b.delta)}, clinic_id=cid)
    return {"ok": True, "qty": new_qty}


class StockTransferIn(BaseModel):
    target_clinic_id: int
    qty: Decimal = Field(gt=0, le=1_000_000)
    reason: str = Field("Şubeler arası transfer", min_length=2, max_length=120)


@app.post("/app/api/inventory/{iid}/transfer")
def transfer_item(iid: int, b: StockTransferIn, u: dict = Depends(CLINICAL)):
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
        c.execute("INSERT INTO stock_moves (item_id,delta,qty_after,reason,actor_id,created_at) VALUES (?,?,?,?,?,?)",
                  (iid, -qty_f, new_src_qty, f"Transfer -> Şube #{b.target_clinic_id}: {b.reason}", u["id"], t_now))
        dst = c.execute("SELECT * FROM inventory_items WHERE clinic_id=? AND name=? AND active=1", (b.target_clinic_id, src["name"])).fetchone()
        if dst:
            new_dst_qty = round(float(dst["qty"]) + qty_f, 4)
            c.execute("UPDATE inventory_items SET qty=? WHERE id=?", (new_dst_qty, dst["id"]))
            dst_id = dst["id"]
        else:
            cur_d = c.execute(
                "INSERT INTO inventory_items (clinic_id,name,sku,unit,qty,min_qty,unit_cost_kurus,active,created_at) VALUES (?,?,?,?,?,?,?,1,?)",
                (b.target_clinic_id, src["name"], src["sku"], src["unit"], qty_f, src["min_qty"], src["unit_cost_kurus"], t_now),
            )
            dst_id = cur_d.lastrowid
            new_dst_qty = qty_f
        c.execute("INSERT INTO stock_moves (item_id,delta,qty_after,reason,actor_id,created_at) VALUES (?,?,?,?,?,?)",
                  (dst_id, qty_f, new_dst_qty, f"Transfer <- Şube #{cid}: {b.reason}", u["id"], t_now))
        c.commit()
    write_audit(u["id"], u["email"], "inventory.transfer", f"item:{iid}->clinic:{b.target_clinic_id}", u["ip_h"], {"qty": qty_f}, clinic_id=cid)
    return {"ok": True, "src_qty": new_src_qty, "dst_item_id": dst_id, "dst_qty": new_dst_qty}


@app.get("/app/api/inventory/{iid}/moves")
def item_moves(iid: int, u: dict = Depends(ANY)):
    if not q1("SELECT id FROM inventory_items WHERE id=? AND clinic_id=?", iid, u["clinic_id"]):
        raise HTTPException(404, "ürün yok")
    return q("SELECT m.*, s.full_name AS actor FROM stock_moves m LEFT JOIN staff_users s ON s.id=m.actor_id WHERE m.item_id=? ORDER BY m.id DESC", iid)


class ChargeIn(BaseModel):
    patient_id: int
    description: str = Field(min_length=2, max_length=120)
    amount: Decimal = Field(gt=0, le=10_000_000)
    discount: Decimal = Field(Decimal(0), ge=0, le=10_000_000)
    doctor_id: int | None = None
    idempotency_key: str | None = Field(default=None, max_length=80)
    allow_duplicate: bool = False


@app.post("/app/api/charges")
async def add_charge(b: ChargeIn, u: dict = Depends(ANY)):
    if not await _LIMITER.hit(f"chg:{u['id']}", 60, 60):
        raise HTTPException(429, "Çok fazla hizmet ekleme isteği")
    cid = u["clinic_id"]
    net_amount = b.amount - b.discount
    with _DB_LOCK:
        c = db()
        _require_active_patient_row(c, b.patient_id, cid)
        if b.doctor_id is not None and not c.execute("SELECT id FROM staff_users WHERE id=? AND clinic_id=?", (b.doctor_id, cid)).fetchone():
            raise HTTPException(404, "hekim yok")
        if net_amount <= 0:
            raise HTTPException(400, "İndirim sonrası tutar sıfırdan büyük olmalıdır")
        net_k = kurus(net_amount)
        desc = (f"{b.description} (İndirim: {b.discount} TL)" if b.discount > 0 else b.description)[:120]
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
                "INSERT INTO charges (clinic_id,patient_id,description,amount_kurus,doctor_id,created_by,created_at,idempotency_key) VALUES (?,?,?,?,?,?,?,?)",
                (cid, b.patient_id, desc, net_k, b.doctor_id, u["id"], iso_now(), b.idempotency_key),
            )
            cid_id = cur_ch.lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Mükerrer hizmet borçlandırması engellendi")
    write_audit(u["id"], u["email"], "kasa.charge", f"charge:{cid_id}", u["ip_h"], {"kurus": net_k}, clinic_id=cid)
    return {"id": cid_id, "net_kurus": net_k}


class PaymentIn(BaseModel):
    patient_id: int
    amount: Decimal = Field(gt=0, le=10_000_000)
    method: Literal["nakit", "kart", "havale", "diger"]
    idempotency_key: str | None = Field(default=None, max_length=80)
    allow_advance: bool = False


@app.post("/app/api/payments")
async def add_payment(b: PaymentIn, u: dict = Depends(ANY)):
    if not await _LIMITER.hit(f"pay:{u['id']}", 60, 60):
        raise HTTPException(429, "Çok fazla tahsilat isteği")
    cid = u["clinic_id"]
    amt_k = kurus(b.amount)
    with _DB_LOCK:
        c = db()
        _require_active_patient_row(c, b.patient_id, cid)
        if b.idempotency_key:
            dup = c.execute("SELECT id FROM payments WHERE clinic_id=? AND idempotency_key=?", (cid, b.idempotency_key)).fetchone()
            if dup:
                raise HTTPException(409, "Bu ödeme zaten işlendi (mükerrer işlem engellendi)")
        billed_k = (c.execute("SELECT coalesce(sum(amount_kurus),0) AS s FROM charges WHERE clinic_id=? AND patient_id=? AND voided_at IS NULL", (cid, b.patient_id)).fetchone() or {"s": 0})["s"]
        paid_k = (c.execute("SELECT coalesce(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND patient_id=? AND voided_at IS NULL", (cid, b.patient_id)).fetchone() or {"s": 0})["s"]
        balance_k = int(billed_k or 0) - int(paid_k or 0)
        if amt_k > max(0, balance_k) and not b.allow_advance:
            raise HTTPException(
                422,
                f"Hastanın açık bakiyesi {tl(max(0, balance_k)):.2f} TL; bakiye üstü tahsilat için avans onayı (allow_advance=true) gereklidir",
            )
        try:
            cur_p = c.execute(
                "INSERT INTO payments (clinic_id,patient_id,amount_kurus,method,created_by,created_at,idempotency_key) VALUES (?,?,?,?,?,?,?)",
                (cid, b.patient_id, amt_k, b.method, u["id"], iso_now(), b.idempotency_key),
            )
            pid_id = cur_p.lastrowid
            c.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Mükerrer ödeme engellendi")
    write_audit(u["id"], u["email"], "kasa.payment", f"payment:{pid_id}", u["ip_h"], {"kurus": amt_k}, clinic_id=cid)
    return {"id": pid_id}


class VoidIn(BaseModel):
    reason: str = Field(min_length=3, max_length=200)


@app.post("/app/api/{kind}/{eid}/void")
def void_entry(kind: Literal["charges", "payments"], eid: int, b: VoidIn, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    if not q1(f"SELECT id FROM {kind} WHERE id=? AND clinic_id=? AND voided_at IS NULL", eid, cid):
        raise HTTPException(404, "kayıt yok veya zaten iptal")
    ex(f"UPDATE {kind} SET voided_at=?, void_reason=? WHERE id=? AND clinic_id=? AND voided_at IS NULL", iso_now(), b.reason, eid, cid)
    write_audit(u["id"], u["email"], f"kasa.void_{kind}", f"{kind}:{eid}", u["ip_h"], {"reason": b.reason}, clinic_id=cid)
    return {"ok": True}


@app.get("/app/api/kasa")
def kasa(start: datetime, end: datetime, u: dict = Depends(CLINICAL)):
    cid = u["clinic_id"]
    s_dt = start if start.tzinfo else start.replace(tzinfo=TZ)
    e_dt = end if end.tzinfo else end.replace(tzinfo=TZ)
    ch_all = q("SELECT c.*, p.display_name AS patient FROM charges c JOIN patients p ON p.id=c.patient_id WHERE c.clinic_id=? ORDER BY c.id DESC", cid)
    py_all = q("SELECT y.*, p.display_name AS patient FROM payments y JOIN patients p ON p.id=y.patient_id WHERE y.clinic_id=? ORDER BY y.id DESC", cid)

    def _in_range(iso: str) -> bool:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ)
        return s_dt <= dt < e_dt

    ch = [x for x in ch_all if _in_range(x["created_at"])]
    py = [x for x in py_all if _in_range(x["created_at"])]
    billed = sum(x["amount_kurus"] for x in ch if not x["voided_at"])
    paid = sum(x["amount_kurus"] for x in py if not x["voided_at"])
    total_billed = sum(x["amount_kurus"] for x in ch_all if not x["voided_at"])
    total_paid = sum(x["amount_kurus"] for x in py_all if not x["voided_at"])
    methods: dict[str, int] = {}
    for x in py:
        if not x["voided_at"]:
            methods[x["method"]] = methods.get(x["method"], 0) + x["amount_kurus"]
    entries = [{"type": "hizmet", "id": x["id"], "created_at": x["created_at"], "patient": x["patient"], "info": x["description"], "amount": tl(x["amount_kurus"]), "voided_at": x["voided_at"]} for x in ch]
    entries += [{"type": "tahsilat", "id": x["id"], "created_at": x["created_at"], "patient": x["patient"], "info": x["method"], "amount": tl(x["amount_kurus"]), "voided_at": x["voided_at"]} for x in py]
    entries.sort(key=lambda x: x["created_at"], reverse=True)
    shares = []
    if u["role"] == "owner":
        for d in q("SELECT id, full_name, share_pct FROM staff_users WHERE clinic_id=? AND role IN ('owner','doctor') AND active=1", cid):
            dbilled = sum(x["amount_kurus"] for x in ch if not x["voided_at"] and x["doctor_id"] == d["id"])
            shares.append({"full_name": d["full_name"], "share_pct": d["share_pct"], "billed": tl(dbilled), "share_try": tl(int(dbilled * d["share_pct"] / 100))})
    return {"billed": tl(billed), "paid": tl(paid), "receivable": tl(total_billed - total_paid),
            "methods": [{"method": k, "amount": tl(v)} for k, v in methods.items()], "entries": entries, "shares": shares}


# ---------------- Ekip, Zincir Klinikler, Mesajlar, Şablonlar, Analiz, Ayarlar, Asistan ----------------
@app.get("/app/api/staff")
def staff(u: dict = Depends(ANY)):
    rows = q("SELECT id, email, full_name, role, share_pct, totp_enabled, active, (phone_hmac IS NOT NULL) AS whatsapp FROM staff_users WHERE clinic_id=?", u["clinic_id"])
    for r in rows:
        r["totp_enabled"] = bool(r["totp_enabled"]); r["active"] = bool(r["active"]); r["whatsapp"] = bool(r["whatsapp"])
        if u["role"] != "owner":
            r.pop("email", None); r.pop("share_pct", None)
    return rows


class StaffIn(BaseModel):
    email: str
    full_name: str
    role: Literal["owner", "doctor", "secretary"]
    password: str = Field(min_length=12)
    phone: str | None = None
    share_pct: Decimal = Decimal(0)


@app.post("/app/api/staff")
def add_staff(b: StaffIn, u: dict = Depends(OWNER)):
    email = b.email.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(400, "Geçerli e-posta girin")
    try:
        sid = ex("INSERT INTO staff_users (clinic_id,email,full_name,role,pw_hash,phone_hmac,share_pct,created_at) VALUES (?,?,?,?,?,?,?,?)",
                 u["clinic_id"], email, b.full_name, b.role, _hash_pw(b.password),
                 phone_hmac(b.phone) if b.phone else None, float(b.share_pct), iso_now())
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Bu e-posta veya telefon zaten kayıtlı")
    write_audit(u["id"], u["email"], "staff.create", f"staff:{sid}", u["ip_h"], clinic_id=u["clinic_id"])
    return {"id": sid}


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
        paid_k = (q1("SELECT coalesce(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND voided_at IS NULL", c["id"]) or {})["s"]
        c["paid_try"] = tl(paid_k)
        c["active"] = bool(c["active"])
        tok = cal.calendar_feed_token(c["id"])
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
def list_conversations(u: dict = Depends(ANY)):
    rows = q("SELECT id, display_name, channel, lang FROM patients WHERE clinic_id=? AND active=1 ORDER BY id DESC", u["clinic_id"])
    for r in rows:
        logs = q("SELECT layer, intent, direction, created_at FROM message_log WHERE patient_id=? ORDER BY id DESC", r["id"])
        out_logs = [l for l in logs if l["direction"] == "out"]
        r["last_at"] = logs[0]["created_at"] if logs else None
        r["last_layer"] = out_logs[0]["layer"] if out_logs else None
        r["last_intent"] = logs[0]["intent"] if logs else None
        r["msg_count"] = len(logs)
    return rows


class ReplyIn(BaseModel):
    text: str = Field(min_length=1, max_length=2000)


@app.post("/app/api/conversations/{pid}/send")
def send_conv(pid: int, b: ReplyIn, u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    with _DB_LOCK:
        _require_active_patient_row(db(), pid, cid)
    ex("INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,?,'out','panel-manuel','personel',0,0,?)",
       cid, pid, iso_now())
    write_audit(u["id"], u["email"], "conversation.send", f"patient:{pid}", u["ip_h"], clinic_id=cid)
    return {"ok": True}


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
    c = q1("SELECT name, address, phone FROM clinics WHERE id=?", cid)
    all_branches = q("SELECT id, name, city, address, phone FROM clinics WHERE active=1")
    facts: dict = {
        "clinic": (c and c["name"]) or u["clinic_name"],
        "branches": all_branches,
    }
    if c and c.get("address"):
        facts["adres"] = c["address"]
    if c and c.get("phone"):
        facts["telefon"] = c["phone"]
    try:
        res = await asyncio.wait_for(
            _ROUTER.route(
                b.text,
                lang=b.lang,
                clinic_facts=facts,
                allow_llm=True,
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
    ex("INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,NULL,'in',NULL,'simulator',0,0,?)",
       cid, iso_now())
    ex("INSERT INTO message_log (clinic_id,patient_id,direction,layer,intent,tokens_in,tokens_out,created_at) VALUES (?,NULL,'out',?,?,?, ?,?)",
       cid, res.layer, f"simulator:{res.intent}", res.tokens_in, res.tokens_out, iso_now())
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
        async with httpx.AsyncClient(timeout=0.9) as c:
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
def analytics(u: dict = Depends(ANY)):
    cid = u["clinic_id"]
    appts = q("SELECT starts_at FROM appointments WHERE clinic_id=?", cid)
    off = 0
    for a in appts:
        dt = datetime.fromisoformat(a["starts_at"])
        if dt.hour < 9 or dt.hour >= 19 or dt.weekday() == 6:
            off += 1
    camps = q("SELECT * FROM campaigns WHERE clinic_id=? ORDER BY id DESC", cid)
    for c in camps:
        c["revenue_try"] = tl(c.pop("revenue_kurus"))
    return {"total_appts_30d": len(appts), "off_hours_appts": off,
            "off_hours_pct": round(100 * off / len(appts)) if appts else 0, "campaigns": camps}


class CampaignIn(BaseModel):
    name: str
    source: str = "meta_ads"
    clicks: int = 0
    conversations: int = 0
    appointments_booked: int = 0
    revenue_try: Decimal = Decimal(0)


@app.post("/app/api/campaigns")
def add_campaign(b: CampaignIn, u: dict = Depends(OWNER)):
    cid_id = ex("INSERT INTO campaigns (clinic_id,name,source,clicks,conversations,appointments_booked,revenue_kurus,created_at) VALUES (?,?,?,?,?,?,?,?)",
                u["clinic_id"], b.name, b.source, b.clicks, b.conversations, b.appointments_booked, kurus(b.revenue_try), iso_now())
    return {"id": cid_id}


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


@app.post("/app/api/settings")
def save_settings(b: SettingsIn, u: dict = Depends(OWNER)):
    wh_str = b.working_hours_json or DEFAULT_WORKING_HOURS_JSON
    try:
        parsed_wh = json.loads(wh_str)
        if not isinstance(parsed_wh, dict):
            raise ValueError("dict değil")
    except Exception:
        raise HTTPException(400, "Geçersiz çalışma saatleri JSON formatı")
    ex(
        "UPDATE clinics SET name=?,city=?,address=?,phone=?,autopilot_name=?,default_lang=?,slot_step_min=?,google_review_url=?,working_hours_json=?,buffer_min=? WHERE id=?",
        b.name, b.city, b.address, b.phone, b.autopilot_name, b.default_lang, b.slot_step_min, b.google_review_url, wh_str, b.buffer_min, u["clinic_id"],
    )
    write_audit(u["id"], u["email"], "settings.update", f"clinic:{u['clinic_id']}", u["ip_h"], clinic_id=u["clinic_id"])
    return {"ok": True}


class AskIn(BaseModel):
    question: str


@app.post("/app/api/assistant")
async def assistant(b: AskIn, u: dict = Depends(ANY)):
    if not await _LIMITER.hit(f"asst:{u['id']}", 30, 60):
        raise HTTPException(429, "Çok fazla asistan sorgusu")
    cid = u["clinic_id"]
    txt = b.question.lower()
    if any(k in txt for k in ("kasa", "tahsilat", "ciro")):
        if u["role"] == "secretary":
            return {"answer": "Kasa özeti yalnızca hekim ve yöneticiye açık.", "tokens": 0}
        p = q1("SELECT coalesce(sum(amount_kurus),0) AS s FROM payments WHERE clinic_id=? AND voided_at IS NULL", cid)["s"]
        return {"answer": f"Toplam tahsilat: {tl(p):,.2f} TL (0 LLM tokenı harcandı).", "tokens": 0}
    if any(k in txt for k in ("stok", "envanter")):
        lows = q("SELECT name, qty, min_qty, unit FROM inventory_items WHERE clinic_id=? AND active=1 AND qty <= min_qty AND min_qty > 0", cid)
        ans = "\n".join(f"- {r['name']}: {r['qty']} {r['unit']} (alt sınır {r['min_qty']})" for r in lows) or "Kritik stok yok."
        return {"answer": ans, "tokens": 0}
    if any(k in txt for k in ("uyarı", "uyari", "kırmızı", "kirmizi")):
        als = q("SELECT detail FROM alerts WHERE clinic_id=? AND acknowledged_at IS NULL", cid)
        return {"answer": "\n".join(f"- {a['detail']}" for a in als) or "Açık uyarı yok.", "tokens": 0}
    appts = q("SELECT a.starts_at, a.treatment, a.chair, p.display_name FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id WHERE a.clinic_id=? AND a.status IN ('booked','confirmed') ORDER BY a.starts_at LIMIT 10", cid)
    ans = "\n".join(f"- {a['starts_at'][:16].replace('T',' ')} K{a['chair']} {a['display_name']} ({a['treatment']})" for a in appts) or "Aktif randevu yok."
    return {"answer": f"Yaklaşan Randevular:\n{ans}", "tokens": 0}


@app.post("/app/api/backup/create")
async def create_encrypted_backup(u: dict = Depends(OWNER)):
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
async def restore_encrypted_backup_test(b: RestoreTestIn, u: dict = Depends(OWNER)):
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
    dst_file.write_bytes(raw_db)
    rconn = sqlite3.connect(dst_file)
    rconn.row_factory = sqlite3.Row
    try:
        p_cnt = rconn.execute("SELECT count(*) AS n FROM patients").fetchone()["n"]
        a_cnt = rconn.execute("SELECT count(*) AS n FROM appointments").fetchone()["n"]
        aud_rows = [dict(r) for r in rconn.execute("SELECT id, ts, actor, action, target, meta, prev_hash, hash FROM audit_log ORDER BY id").fetchall()]
        chain_res = sec.verify_chain(aud_rows)
    finally:
        rconn.close()
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
def audit_verify(u: dict = Depends(OWNER)):
    rows = q("SELECT id, ts, actor, action, target, meta, prev_hash, hash FROM audit_log ORDER BY id")
    return sec.verify_chain(rows)


class LeadIn(BaseModel):
    clinic: str = Field(min_length=2, max_length=120)
    contact: str = Field(min_length=5, max_length=120)
    city: str | None = Field(default=None, max_length=40)
    chairs: int | None = Field(default=None, ge=1, le=200)
    website: str | None = Field(default=None, max_length=200)


@app.post("/lead")
async def lead(b: LeadIn, request: Request):
    if b.website:
        return {"ok": True}
    if not await _LIMITER.hit(f"lead:{client_ip(request)}", 5, 3600):
        raise HTTPException(429, "Çok fazla talep")
    ex("INSERT INTO leads (clinic,contact_enc,city,chairs,created_at) VALUES (?,?,?,?,?)", b.clinic, enc(b.contact), b.city, b.chairs, iso_now())
    ex("INSERT INTO alerts (clinic_id,kind,detail,created_at) VALUES (1,'web_talep',?,?)", f"Web sitesinden demo talebi: {b.clinic} ({b.city or '-'})", iso_now())
    return {"ok": True}


if __name__ == "__main__":
    host = os.environ.get("DC_HOST", "127.0.0.1")
    port = int(os.environ.get("DC_PORT", "8000"))
    uvicorn.run(app, host=host, port=port, log_level="warning", server_header=False)
