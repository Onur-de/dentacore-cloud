-- DentaCore platform katmanı: personel girişi, oturum, değiştirilemez denetim kaydı, envanter, kasa, kanal.
-- Idempotent: API her açılışta bu dosyayı çalıştırır; mevcut veriyi bozmaz.

ALTER TABLE patients     ADD COLUMN IF NOT EXISTS channel   TEXT NOT NULL DEFAULT 'wa';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS notes_enc TEXT;
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE patients     DROP CONSTRAINT IF EXISTS patients_phone_hmac_key;
CREATE UNIQUE INDEX IF NOT EXISTS patients_clinic_phone_uq ON patients (clinic_id, phone_hmac);
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS source    TEXT NOT NULL DEFAULT 'panel';
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS doctor_id BIGINT;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS clinics (
  id                BIGSERIAL PRIMARY KEY,
  name              TEXT NOT NULL,
  slug              TEXT UNIQUE NOT NULL,
  city              TEXT NOT NULL DEFAULT 'İstanbul',
  address           TEXT NOT NULL DEFAULT '',
  phone             TEXT NOT NULL DEFAULT '',
  chairs            INT NOT NULL DEFAULT 2,
  work_minutes      INT NOT NULL DEFAULT 600,
  wa_phone_id       TEXT NOT NULL DEFAULT '',
  ig_handle         TEXT NOT NULL DEFAULT '',
  google_review_url TEXT NOT NULL DEFAULT '',
  autopilot_name    TEXT NOT NULL DEFAULT 'DentaCore Asistan',
  default_lang      TEXT NOT NULL DEFAULT 'tr',
  slot_step_min     INT NOT NULL DEFAULT 15,
  active            BOOLEAN NOT NULL DEFAULT true,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS staff_users (
  id              BIGSERIAL PRIMARY KEY,
  clinic_id       BIGINT NOT NULL DEFAULT 1,
  email           TEXT UNIQUE NOT NULL,
  full_name       TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('owner','doctor','secretary')),
  pw_hash         TEXT NOT NULL,
  phone_hmac      TEXT UNIQUE,
  share_pct       NUMERIC(5,2) NOT NULL DEFAULT 0 CHECK (share_pct BETWEEN 0 AND 100),
  totp_secret_enc TEXT,
  totp_enabled    BOOLEAN NOT NULL DEFAULT false,
  totp_last_step  BIGINT NOT NULL DEFAULT 0,
  failed_count    INT NOT NULL DEFAULT 0,
  locked_until    TIMESTAMPTZ,
  active          BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Oturum kimliğinin kendisi değil SHA-256 özeti saklanır: veritabanı sızsa bile oturum çalınamaz.
CREATE TABLE IF NOT EXISTS sessions (
  id_hash          TEXT PRIMARY KEY,
  user_id          BIGINT NOT NULL REFERENCES staff_users(id) ON DELETE CASCADE,
  active_clinic_id BIGINT,
  csrf             TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen        TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,
  revoked          BOOLEAN NOT NULL DEFAULT false,
  ua               TEXT
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_clinic_id BIGINT;
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id) WHERE NOT revoked;

-- Denetim kaydı: her satır bir öncekinin özetini taşır (hash zinciri). Araya ekleme, silme, değiştirme zinciri kırar.
CREATE TABLE IF NOT EXISTS audit_log (
  id          BIGSERIAL PRIMARY KEY,
  clinic_id   BIGINT NOT NULL DEFAULT 1,
  ts          TEXT NOT NULL,
  actor_id    BIGINT,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,
  target      TEXT NOT NULL DEFAULT '',
  ip_hash     TEXT NOT NULL DEFAULT '',
  meta        TEXT NOT NULL DEFAULT '{}',
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL UNIQUE
);
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;

CREATE OR REPLACE FUNCTION dc_audit_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_log yalnizca eklemeye aciktir';
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_no_update ON audit_log;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_log FOR EACH ROW EXECUTE FUNCTION dc_audit_immutable();
DROP TRIGGER IF EXISTS audit_no_truncate ON audit_log;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log FOR EACH STATEMENT EXECUTE FUNCTION dc_audit_immutable();

-- Envanter: stok asla eksiye düşmez (CHECK + atomik UPDATE)
CREATE TABLE IF NOT EXISTS inventory_items (
  id              BIGSERIAL PRIMARY KEY,
  name            TEXT NOT NULL,
  sku             TEXT,
  unit            TEXT NOT NULL DEFAULT 'adet',
  qty             NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (qty >= 0),
  min_qty         NUMERIC(12,2) NOT NULL DEFAULT 0 CHECK (min_qty >= 0),
  unit_cost_kurus BIGINT NOT NULL DEFAULT 0 CHECK (unit_cost_kurus >= 0),
  active          BOOLEAN NOT NULL DEFAULT true,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS stock_moves (
  id          BIGSERIAL PRIMARY KEY,
  item_id     BIGINT NOT NULL REFERENCES inventory_items(id) ON DELETE CASCADE,
  delta       NUMERIC(12,2) NOT NULL CHECK (delta <> 0),
  qty_after   NUMERIC(12,2) NOT NULL,
  reason      TEXT NOT NULL,
  actor_id    BIGINT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS stock_moves_item_idx ON stock_moves (item_id, created_at DESC);

-- Kasa: tutarlar kuruş cinsinden tam sayı (kayan nokta hatası yok). Silme yok, iptal (void) var.
CREATE TABLE IF NOT EXISTS charges (
  id            BIGSERIAL PRIMARY KEY,
  patient_id    BIGINT NOT NULL REFERENCES patients(id) ON DELETE RESTRICT,
  description   TEXT NOT NULL,
  amount_kurus  BIGINT NOT NULL CHECK (amount_kurus > 0),
  doctor_id     BIGINT REFERENCES staff_users(id),
  created_by    BIGINT REFERENCES staff_users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  voided_at     TIMESTAMPTZ,
  void_reason   TEXT
);
CREATE INDEX IF NOT EXISTS charges_created_idx ON charges (created_at);

CREATE TABLE IF NOT EXISTS payments (
  id            BIGSERIAL PRIMARY KEY,
  patient_id    BIGINT NOT NULL REFERENCES patients(id) ON DELETE RESTRICT,
  amount_kurus  BIGINT NOT NULL CHECK (amount_kurus > 0),
  method        TEXT NOT NULL CHECK (method IN ('nakit','kart','havale','diger')),
  created_by    BIGINT REFERENCES staff_users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  voided_at     TIMESTAMPTZ,
  void_reason   TEXT
);
CREATE INDEX IF NOT EXISTS payments_created_idx ON payments (created_at);

-- Web sitesinden gelen demo talepleri
CREATE TABLE IF NOT EXISTS leads (
  id          BIGSERIAL PRIMARY KEY,
  clinic      TEXT NOT NULL,
  contact_enc TEXT NOT NULL,
  city        TEXT,
  chairs      INT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE staff_users     ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE charges         ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE payments        ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE alerts          ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE message_log     ADD COLUMN IF NOT EXISTS clinic_id BIGINT NOT NULL DEFAULT 1;
ALTER TABLE message_log     ADD COLUMN IF NOT EXISTS body TEXT;
ALTER TABLE message_log     ADD COLUMN IF NOT EXISTS delivery_status TEXT;
ALTER TABLE message_log     ADD COLUMN IF NOT EXISTS delivery_error TEXT;
ALTER TABLE slot_offers     ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
CREATE UNIQUE INDEX IF NOT EXISTS clinics_wa_phone_id_uq ON clinics (wa_phone_id) WHERE wa_phone_id <> '';
CREATE UNIQUE INDEX IF NOT EXISTS clinics_ig_handle_uq ON clinics (ig_handle) WHERE ig_handle <> '';

CREATE TABLE IF NOT EXISTS message_templates (
  id         BIGSERIAL PRIMARY KEY,
  clinic_id  BIGINT NOT NULL DEFAULT 1,
  name       TEXT NOT NULL,
  channel    TEXT NOT NULL DEFAULT 'whatsapp',
  lang       TEXT NOT NULL DEFAULT 'tr',
  category   TEXT NOT NULL DEFAULT 'UTILITY',
  body       TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'APPROVED',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE patients     ADD COLUMN IF NOT EXISTS active    BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE charges      ADD COLUMN IF NOT EXISTS discount  NUMERIC(5,2) NOT NULL DEFAULT 0;
ALTER TABLE charges      ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS charges_idem_uq ON charges (clinic_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
ALTER TABLE payments     ADD COLUMN IF NOT EXISTS idempotency_key TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS payments_idem_uq ON payments (clinic_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS working_hours_json TEXT NOT NULL DEFAULT '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}';
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS buffer_min INT NOT NULL DEFAULT 0;
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS ai_custom_rules_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS cal_token_version INT NOT NULL DEFAULT 1;
ALTER TABLE leads        ADD COLUMN IF NOT EXISTS kvkk_version TEXT NOT NULL DEFAULT '';
ALTER TABLE leads        ADD COLUMN IF NOT EXISTS kvkk_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE leads        ADD COLUMN IF NOT EXISTS yurt_disi_riza BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS tooth_records (
  id              BIGSERIAL PRIMARY KEY,
  clinic_id       BIGINT NOT NULL DEFAULT 1,
  patient_id      BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  tooth_fdi       INT NOT NULL CHECK ((tooth_fdi BETWEEN 11 AND 48) OR (tooth_fdi BETWEEN 51 AND 85)),
  surface         TEXT NOT NULL DEFAULT 'FULL' CHECK (surface IN ('M','D','O','B','L','FULL')),
  status          TEXT NOT NULL DEFAULT 'planned' CHECK (status IN ('healthy','caries','planned','treated','implant','crown','root_canal','missing','extraction')),
  procedure_code  TEXT NOT NULL DEFAULT '',
  procedure_name  TEXT NOT NULL DEFAULT '',
  amount_kurus    BIGINT NOT NULL DEFAULT 0 CHECK (amount_kurus >= 0),
  doctor_id       BIGINT REFERENCES staff_users(id),
  note            TEXT NOT NULL DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tooth_records_patient_idx ON tooth_records (clinic_id, patient_id, tooth_fdi);

CREATE TABLE IF NOT EXISTS campaigns (
  id                  BIGSERIAL PRIMARY KEY,
  clinic_id           BIGINT NOT NULL DEFAULT 1,
  name                TEXT NOT NULL,
  source              TEXT NOT NULL DEFAULT 'meta_ads',
  clicks              INT NOT NULL DEFAULT 0,
  conversations       INT NOT NULL DEFAULT 0,
  appointments_booked INT NOT NULL DEFAULT 0,
  revenue_kurus       BIGINT NOT NULL DEFAULT 0,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
