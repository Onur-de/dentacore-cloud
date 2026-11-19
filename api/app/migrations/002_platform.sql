-- DentaCore platform katmanı: personel girişi, oturum, değiştirilemez denetim kaydı, envanter, kasa, kanal.
-- Idempotent: API her açılışta bu dosyayı çalıştırır; mevcut veriyi bozmaz.
-- Sıfırdan (Render / Railway / Bulut PostgreSQL) kurulumlar için çekirdek tablolar önce IF NOT EXISTS ile güvenceye alınır:

CREATE TABLE IF NOT EXISTS patients (
  id            BIGSERIAL PRIMARY KEY,
  clinic_id     BIGINT NOT NULL DEFAULT 1,
  phone_hmac    TEXT NOT NULL,
  phone_enc     TEXT NOT NULL,
  display_name  TEXT,
  lang          TEXT NOT NULL DEFAULT 'tr',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (clinic_id, phone_hmac)
);

CREATE TABLE IF NOT EXISTS consents (
  id           BIGSERIAL PRIMARY KEY,
  patient_id   BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  kind         TEXT NOT NULL CHECK (kind IN ('kvkk_aydinlatma','saglik_verisi_acik_riza','iletisim','yurt_disi_aktarim')),
  text_version TEXT NOT NULL,
  text_sha256  TEXT NOT NULL,
  channel      TEXT NOT NULL,
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS consents_patient_kind_idx ON consents (patient_id, kind);

CREATE TABLE IF NOT EXISTS appointments (
  id               BIGSERIAL PRIMARY KEY,
  patient_id       BIGINT REFERENCES patients(id) ON DELETE SET NULL,
  starts_at        TIMESTAMPTZ NOT NULL,
  duration_min     INT NOT NULL DEFAULT 30,
  treatment        TEXT NOT NULL,
  chair            TEXT NOT NULL DEFAULT '1',
  status           TEXT NOT NULL DEFAULT 'booked' CHECK (status IN ('booked','confirmed','cancelled','done','noshow','open')),
  reminder_sent_at TIMESTAMPTZ,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS appointments_starts_at_idx ON appointments (starts_at);

CREATE TABLE IF NOT EXISTS waitlist (
  id          BIGSERIAL PRIMARY KEY,
  patient_id  BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  treatment   TEXT NOT NULL,
  earliest    TIMESTAMPTZ NOT NULL DEFAULT now(),
  active      BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS slot_offers (
  id             BIGSERIAL PRIMARY KEY,
  appointment_id BIGINT NOT NULL REFERENCES appointments(id) ON DELETE CASCADE,
  waitlist_id    BIGINT NOT NULL REFERENCES waitlist(id) ON DELETE CASCADE,
  wave           INT NOT NULL,
  sent_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  status         TEXT NOT NULL DEFAULT 'sent' CHECK (status IN ('sent','won','lost','expired'))
);

CREATE TABLE IF NOT EXISTS anamnesis (
  id               BIGSERIAL PRIMARY KEY,
  patient_id       BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  answers_enc      TEXT NOT NULL,
  red_flags        TEXT[] NOT NULL DEFAULT '{}',
  signer_name      TEXT NOT NULL,
  signature_sha256 TEXT NOT NULL,
  signed_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS anamnesis_tokens (
  token       TEXT PRIMARY KEY,
  patient_id  BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS postop_checks (
  id          BIGSERIAL PRIMARY KEY,
  patient_id  BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  procedure   TEXT NOT NULL,
  due_at      TIMESTAMPTZ NOT NULL,
  stage       TEXT NOT NULL CHECK (stage IN ('2s','24s','72s')),
  sent_at     TIMESTAMPTZ,
  pain_score  INT,
  answered_at TIMESTAMPTZ,
  alarm       BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS postop_checks_due_idx ON postop_checks (due_at) WHERE sent_at IS NULL;

CREATE TABLE IF NOT EXISTS treatment_plans (
  id              BIGSERIAL PRIMARY KEY,
  patient_id      BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  treatment       TEXT NOT NULL,
  planned_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  status          TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','declined','lost')),
  last_contact_at TIMESTAMPTZ,
  followups_sent  INT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS message_log (
  id          BIGSERIAL PRIMARY KEY,
  clinic_id   BIGINT NOT NULL DEFAULT 1,
  patient_id  BIGINT REFERENCES patients(id) ON DELETE SET NULL,
  direction   TEXT NOT NULL CHECK (direction IN ('in','out')),
  layer       TEXT,
  intent      TEXT,
  tokens_in   INT NOT NULL DEFAULT 0,
  tokens_out  INT NOT NULL DEFAULT 0,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS message_log_created_at_idx ON message_log (created_at);

CREATE TABLE IF NOT EXISTS alerts (
  id              BIGSERIAL PRIMARY KEY,
  clinic_id       BIGINT NOT NULL DEFAULT 1,
  patient_id      BIGINT REFERENCES patients(id) ON DELETE SET NULL,
  kind            TEXT NOT NULL,
  detail          TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ
);

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
  doctor_id       BIGINT,
  note            TEXT NOT NULL DEFAULT '',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tooth_records_patient_idx ON tooth_records (clinic_id, patient_id, tooth_fdi);

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
  role            TEXT NOT NULL CHECK (role IN ('owner','doctor','secretary','accounting','clinical_support','lab_tech','warehouse','no_access')),
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
ALTER TABLE staff_users DROP CONSTRAINT IF EXISTS staff_users_role_check;

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
  code                TEXT NOT NULL DEFAULT '',
  channel             TEXT NOT NULL DEFAULT 'instagram',
  utm_source          TEXT NOT NULL DEFAULT 'instagram',
  utm_medium          TEXT NOT NULL DEFAULT 'cpc',
  utm_campaign        TEXT NOT NULL DEFAULT '',
  target_url          TEXT NOT NULL DEFAULT '/',
  is_sample           BOOLEAN NOT NULL DEFAULT false,
  clicks              INT NOT NULL DEFAULT 0,
  conversations       INT NOT NULL DEFAULT 0,
  appointments_booked INT NOT NULL DEFAULT 0,
  revenue_kurus       BIGINT NOT NULL DEFAULT 0,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Kurumsal genişletmeler (Bölüm 3-25): PostgreSQL ve SQLite şema eşitliği
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS first_source       TEXT NOT NULL DEFAULT 'whatsapp';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS last_source        TEXT NOT NULL DEFAULT 'whatsapp';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS campaign_id        BIGINT;
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS utm_source         TEXT NOT NULL DEFAULT '';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS utm_medium         TEXT NOT NULL DEFAULT '';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS utm_campaign       TEXT NOT NULL DEFAULT '';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS click_id           TEXT NOT NULL DEFAULT '';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS primary_doctor_id  BIGINT;
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS bank_agreement_id  BIGINT;
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS created_by         BIGINT;
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS notes              TEXT NOT NULL DEFAULT '';
ALTER TABLE patients     ADD COLUMN IF NOT EXISTS birth_date         TEXT NOT NULL DEFAULT '';

ALTER TABLE tooth_records ADD COLUMN IF NOT EXISTS gross_amount_kurus BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tooth_records ADD COLUMN IF NOT EXISTS discount_kurus     BIGINT NOT NULL DEFAULT 0;
ALTER TABLE tooth_records ADD COLUMN IF NOT EXISTS bank_agreement_id  BIGINT;
ALTER TABLE tooth_records ADD COLUMN IF NOT EXISTS discount_reason    TEXT NOT NULL DEFAULT '';
ALTER TABLE tooth_records ADD COLUMN IF NOT EXISTS created_by         BIGINT;

ALTER TABLE charges      ADD COLUMN IF NOT EXISTS gross_amount_kurus BIGINT NOT NULL DEFAULT 0;
ALTER TABLE charges      ADD COLUMN IF NOT EXISTS discount_kurus     BIGINT NOT NULL DEFAULT 0;
ALTER TABLE charges      ADD COLUMN IF NOT EXISTS bank_agreement_id  BIGINT;
ALTER TABLE charges      ADD COLUMN IF NOT EXISTS discount_reason    TEXT NOT NULL DEFAULT '';
ALTER TABLE charges      ADD COLUMN IF NOT EXISTS tooth_record_id    BIGINT;

ALTER TABLE payments     ADD COLUMN IF NOT EXISTS status             TEXT NOT NULL DEFAULT 'completed';
ALTER TABLE payments     ADD COLUMN IF NOT EXISTS doctor_id          BIGINT;
ALTER TABLE payments     ADD COLUMN IF NOT EXISTS is_advance         BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE payments     ADD COLUMN IF NOT EXISTS applied_charge_id  BIGINT;
ALTER TABLE payments     ADD COLUMN IF NOT EXISTS refund_of_id       BIGINT;
ALTER TABLE payments     ADD COLUMN IF NOT EXISTS note               TEXT NOT NULL DEFAULT '';

ALTER TABLE appointments ADD COLUMN IF NOT EXISTS confirmed_at           TIMESTAMPTZ;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS cancelled_at           TIMESTAMPTZ;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS cancel_reason          TEXT NOT NULL DEFAULT '';
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS satisfaction_sent_at   TIMESTAMPTZ;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS satisfaction_reply     TEXT;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS satisfaction_replied_at TIMESTAMPTZ;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS satisfaction_status    TEXT NOT NULL DEFAULT '';
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS google_link_sent_at    TIMESTAMPTZ;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS series_id              TEXT;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS sequence               INT NOT NULL DEFAULT 0;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS updated_at             TIMESTAMPTZ;
ALTER TABLE appointments ADD COLUMN IF NOT EXISTS campaign_id            BIGINT;

ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS ai_monthly_token_limit BIGINT NOT NULL DEFAULT 1500000;
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS ai_monthly_budget_try  NUMERIC(12,2) NOT NULL DEFAULT 250.00;
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS ai_hard_stop           BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS max_reminders          INT NOT NULL DEFAULT 1;
ALTER TABLE clinics      ADD COLUMN IF NOT EXISTS reminder_hours_before  INT NOT NULL DEFAULT 24;

ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS category    TEXT NOT NULL DEFAULT 'Sarf Malzeme';
ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS supplier    TEXT NOT NULL DEFAULT '';
ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS expiry_date TEXT NOT NULL DEFAULT '';
ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS lot_number  TEXT NOT NULL DEFAULT '';
ALTER TABLE inventory_items ADD COLUMN IF NOT EXISTS warehouse   TEXT NOT NULL DEFAULT 'Ana Depo';

ALTER TABLE stock_moves  ADD COLUMN IF NOT EXISTS move_type  TEXT NOT NULL DEFAULT 'in';
ALTER TABLE stock_moves  ADD COLUMN IF NOT EXISTS lot_number TEXT NOT NULL DEFAULT '';

ALTER TABLE staff_users  ADD COLUMN IF NOT EXISTS job_title             TEXT NOT NULL DEFAULT '';
ALTER TABLE staff_users  ADD COLUMN IF NOT EXISTS permissions_json      TEXT NOT NULL DEFAULT '{}';
ALTER TABLE staff_users  ADD COLUMN IF NOT EXISTS working_schedule_json TEXT NOT NULL DEFAULT '{}';

ALTER TABLE campaigns    ADD COLUMN IF NOT EXISTS code         TEXT NOT NULL DEFAULT '';
ALTER TABLE campaigns    ADD COLUMN IF NOT EXISTS channel      TEXT NOT NULL DEFAULT 'instagram';
ALTER TABLE campaigns    ADD COLUMN IF NOT EXISTS utm_source   TEXT NOT NULL DEFAULT 'instagram';
ALTER TABLE campaigns    ADD COLUMN IF NOT EXISTS utm_medium   TEXT NOT NULL DEFAULT 'cpc';
ALTER TABLE campaigns    ADD COLUMN IF NOT EXISTS utm_campaign TEXT NOT NULL DEFAULT '';
ALTER TABLE campaigns    ADD COLUMN IF NOT EXISTS target_url   TEXT NOT NULL DEFAULT '/';
ALTER TABLE campaigns    ADD COLUMN IF NOT EXISTS is_sample    INT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS campaign_events (
  id                 BIGSERIAL PRIMARY KEY,
  clinic_id          BIGINT NOT NULL DEFAULT 1,
  campaign_id        BIGINT,
  event_type         TEXT NOT NULL,
  source             TEXT NOT NULL DEFAULT 'website',
  utm_source         TEXT NOT NULL DEFAULT '',
  utm_medium         TEXT NOT NULL DEFAULT '',
  utm_campaign       TEXT NOT NULL DEFAULT '',
  click_id           TEXT NOT NULL DEFAULT '',
  visitor_hash       TEXT NOT NULL DEFAULT '',
  is_bot             INT NOT NULL DEFAULT 0,
  is_unique          INT NOT NULL DEFAULT 0,
  patient_id         BIGINT,
  appointment_id     BIGINT,
  idempotency_key    TEXT,
  user_agent_summary TEXT NOT NULL DEFAULT '',
  created_at         TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS bank_agreements (
  id                    BIGSERIAL PRIMARY KEY,
  clinic_id             BIGINT NOT NULL DEFAULT 1,
  bank_name             TEXT NOT NULL,
  start_date            TEXT NOT NULL DEFAULT '',
  end_date              TEXT NOT NULL DEFAULT '',
  discount_pct          NUMERIC(6,2) NOT NULL DEFAULT 0,
  discount_type         TEXT NOT NULL DEFAULT 'percentage',
  fixed_discount_kurus  BIGINT NOT NULL DEFAULT 0,
  applicable_treatments TEXT NOT NULL DEFAULT 'all',
  max_discount_kurus    BIGINT NOT NULL DEFAULT 0,
  combinable            INT NOT NULL DEFAULT 0,
  eligibility_notes     TEXT NOT NULL DEFAULT '',
  active                INT NOT NULL DEFAULT 1,
  created_by            BIGINT,
  created_at            TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS patient_groups (
  id            BIGSERIAL PRIMARY KEY,
  clinic_id     BIGINT NOT NULL DEFAULT 1,
  name          TEXT NOT NULL,
  color         TEXT NOT NULL DEFAULT 'teal',
  is_restricted INT NOT NULL DEFAULT 0,
  description   TEXT NOT NULL DEFAULT '',
  created_by    BIGINT,
  created_at    TEXT NOT NULL DEFAULT (now()::text),
  UNIQUE(clinic_id, name)
);

CREATE TABLE IF NOT EXISTS patient_group_members (
  id            BIGSERIAL PRIMARY KEY,
  clinic_id     BIGINT NOT NULL DEFAULT 1,
  patient_id    BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  group_id      BIGINT NOT NULL REFERENCES patient_groups(id) ON DELETE CASCADE,
  reason        TEXT NOT NULL DEFAULT '',
  added_by      BIGINT,
  added_by_name TEXT NOT NULL DEFAULT '',
  added_at      TEXT NOT NULL DEFAULT (now()::text),
  created_at    TEXT NOT NULL DEFAULT (now()::text),
  UNIQUE(patient_id, group_id),
  UNIQUE(clinic_id, patient_id, group_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS pgm_patient_group_uq ON patient_group_members(patient_id, group_id);

CREATE TABLE IF NOT EXISTS payment_installments (
  id                 BIGSERIAL PRIMARY KEY,
  clinic_id          BIGINT NOT NULL DEFAULT 1,
  patient_id         BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  charge_id          BIGINT,
  installment_no     INT NOT NULL DEFAULT 1,
  total_installments INT NOT NULL DEFAULT 1,
  title              TEXT NOT NULL DEFAULT 'Taksit',
  due_date           TEXT NOT NULL,
  amount_kurus       BIGINT NOT NULL CHECK (amount_kurus > 0),
  paid_kurus         BIGINT NOT NULL DEFAULT 0,
  status             TEXT NOT NULL DEFAULT 'pending',
  paid_payment_id    BIGINT,
  paid_at            TEXT,
  note               TEXT NOT NULL DEFAULT '',
  created_by         BIGINT,
  created_at         TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS periodontal_exams (
  id                 BIGSERIAL PRIMARY KEY,
  clinic_id          BIGINT NOT NULL DEFAULT 1,
  patient_id         BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  doctor_id          BIGINT,
  exam_date          TEXT NOT NULL DEFAULT '',
  teeth_json         TEXT NOT NULL DEFAULT '{}',
  measurements_json  TEXT NOT NULL DEFAULT '{}',
  bop_pct            NUMERIC(5,2) NOT NULL DEFAULT 0,
  plaque_pct         NUMERIC(5,2) NOT NULL DEFAULT 0,
  plaque_index_pct   NUMERIC(5,2) NOT NULL DEFAULT 0,
  bleeding_index_pct NUMERIC(5,2) NOT NULL DEFAULT 0,
  mean_pd            NUMERIC(5,2) NOT NULL DEFAULT 0,
  max_pd             INT NOT NULL DEFAULT 0,
  doctor_approved    INT NOT NULL DEFAULT 1,
  doctor_note        TEXT NOT NULL DEFAULT '',
  note               TEXT NOT NULL DEFAULT '',
  created_at         TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS treatment_consents (
  id                 BIGSERIAL PRIMARY KEY,
  clinic_id          BIGINT NOT NULL DEFAULT 1,
  patient_id         BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  doctor_id          BIGINT,
  token              TEXT UNIQUE NOT NULL,
  plan_summary_json  TEXT NOT NULL DEFAULT '[]',
  total_amount_kurus BIGINT NOT NULL DEFAULT 0,
  document_version   TEXT NOT NULL DEFAULT '2026-11-v1',
  content_sha256     TEXT NOT NULL DEFAULT '',
  signer_name        TEXT NOT NULL DEFAULT '',
  signature_text     TEXT NOT NULL DEFAULT '',
  signature_svg_enc  TEXT NOT NULL DEFAULT '',
  consent_type       TEXT NOT NULL DEFAULT 'electronic_form_approval',
  status             TEXT NOT NULL DEFAULT 'pending',
  signed_ip_hash     TEXT NOT NULL DEFAULT '',
  signed_user_agent  TEXT NOT NULL DEFAULT '',
  signed_at          TEXT,
  expires_at         TEXT,
  created_by         BIGINT,
  created_at         TEXT NOT NULL DEFAULT (now()::text)
);
ALTER TABLE treatment_consents ADD COLUMN IF NOT EXISTS signature_svg_enc TEXT NOT NULL DEFAULT '';
ALTER TABLE treatment_consents ADD COLUMN IF NOT EXISTS created_by BIGINT;
ALTER TABLE periodontal_exams ADD COLUMN IF NOT EXISTS measurements_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE periodontal_exams ADD COLUMN IF NOT EXISTS bop_pct NUMERIC(5,2) NOT NULL DEFAULT 0;
ALTER TABLE periodontal_exams ADD COLUMN IF NOT EXISTS plaque_pct NUMERIC(5,2) NOT NULL DEFAULT 0;
ALTER TABLE periodontal_exams ADD COLUMN IF NOT EXISTS doctor_note TEXT NOT NULL DEFAULT '';
ALTER TABLE periodontal_exams ADD COLUMN IF NOT EXISTS created_by BIGINT;

CREATE TABLE IF NOT EXISTS lab_orders (
  id              BIGSERIAL PRIMARY KEY,
  clinic_id       BIGINT NOT NULL DEFAULT 1,
  patient_id      BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  doctor_id       BIGINT,
  tooth_fdi       INT,
  lab_name        TEXT NOT NULL,
  procedure_type  TEXT NOT NULL DEFAULT '',
  work_type       TEXT NOT NULL DEFAULT '',
  shade_color     TEXT NOT NULL DEFAULT 'A2',
  shade           TEXT NOT NULL DEFAULT 'A2',
  sent_date       TEXT NOT NULL DEFAULT '',
  sent_at         TEXT NOT NULL DEFAULT '',
  due_date        TEXT NOT NULL,
  delivered_date  TEXT,
  delivered_at    TEXT,
  cost_kurus      BIGINT NOT NULL DEFAULT 0,
  status          TEXT NOT NULL DEFAULT 'sent',
  note            TEXT NOT NULL DEFAULT '',
  created_by      BIGINT,
  created_at      TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS implant_records (
  id                      BIGSERIAL PRIMARY KEY,
  clinic_id               BIGINT NOT NULL DEFAULT 1,
  patient_id              BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  doctor_id               BIGINT,
  tooth_fdi               INT NOT NULL,
  brand                   TEXT NOT NULL,
  model                   TEXT NOT NULL DEFAULT '',
  diameter_mm             NUMERIC(5,2) NOT NULL DEFAULT 4.1,
  length_mm               NUMERIC(5,2) NOT NULL DEFAULT 10.0,
  lot_number              TEXT NOT NULL,
  serial_number           TEXT NOT NULL DEFAULT '',
  expiry_date             TEXT NOT NULL DEFAULT '',
  used_at                 TEXT NOT NULL DEFAULT '',
  placed_at               TEXT NOT NULL DEFAULT '',
  supplier                TEXT NOT NULL DEFAULT '',
  document_ref            TEXT NOT NULL DEFAULT '',
  uts_barcode             TEXT NOT NULL DEFAULT '',
  barcode_udi             TEXT NOT NULL DEFAULT '',
  uts_notification_status TEXT NOT NULL DEFAULT 'not_connected_prepared',
  torque_ncm              NUMERIC(5,2) NOT NULL DEFAULT 35.0,
  note                    TEXT NOT NULL DEFAULT '',
  created_by              BIGINT,
  created_at              TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS patient_media (
  id                BIGSERIAL PRIMARY KEY,
  clinic_id         BIGINT NOT NULL DEFAULT 1,
  patient_id        BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  appointment_id    BIGINT,
  tooth_record_id   BIGINT,
  category          TEXT NOT NULL DEFAULT 'photo',
  stage             TEXT NOT NULL DEFAULT 'general',
  original_filename TEXT NOT NULL DEFAULT '',
  filename          TEXT NOT NULL DEFAULT '',
  mime_type         TEXT NOT NULL DEFAULT 'image/jpeg',
  file_size_bytes   BIGINT NOT NULL DEFAULT 0,
  size_bytes        BIGINT NOT NULL DEFAULT 0,
  sha256_hash       TEXT NOT NULL DEFAULT '',
  sha256            TEXT NOT NULL DEFAULT '',
  encrypted_path    TEXT NOT NULL DEFAULT '',
  encrypted_file    TEXT NOT NULL DEFAULT '',
  is_dicom          INT NOT NULL DEFAULT 0,
  width             INT NOT NULL DEFAULT 0,
  height            INT NOT NULL DEFAULT 0,
  sharpness         NUMERIC(8,2) NOT NULL DEFAULT 0,
  brightness        NUMERIC(8,2) NOT NULL DEFAULT 0,
  qc_verdict        TEXT NOT NULL DEFAULT 'ok',
  note              TEXT NOT NULL DEFAULT '',
  uploaded_by       BIGINT,
  created_at        TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS suppliers (
  id             BIGSERIAL PRIMARY KEY,
  clinic_id      BIGINT NOT NULL DEFAULT 1,
  name           TEXT NOT NULL,
  category       TEXT NOT NULL DEFAULT 'Genel',
  contact_name   TEXT NOT NULL DEFAULT '',
  contact_person TEXT NOT NULL DEFAULT '',
  phone          TEXT NOT NULL DEFAULT '',
  email          TEXT NOT NULL DEFAULT '',
  tax_no         TEXT NOT NULL DEFAULT '',
  note           TEXT NOT NULL DEFAULT '',
  balance_kurus  BIGINT NOT NULL DEFAULT 0,
  active         INT NOT NULL DEFAULT 1,
  created_at     TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS expenses (
  id             BIGSERIAL PRIMARY KEY,
  clinic_id      BIGINT NOT NULL DEFAULT 1,
  supplier_id    BIGINT,
  category       TEXT NOT NULL DEFAULT 'malzeme',
  description    TEXT NOT NULL,
  amount_kurus   BIGINT NOT NULL CHECK (amount_kurus > 0),
  method         TEXT NOT NULL DEFAULT 'havale',
  invoice_no     TEXT NOT NULL DEFAULT '',
  paid_at        TEXT NOT NULL,
  created_by     BIGINT,
  voided_at      TEXT,
  created_at     TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS cash_closings (
  id                     BIGSERIAL PRIMARY KEY,
  clinic_id              BIGINT NOT NULL DEFAULT 1,
  closing_date           TEXT NOT NULL,
  opening_balance_kurus  BIGINT NOT NULL DEFAULT 0,
  total_in_kurus         BIGINT NOT NULL DEFAULT 0,
  total_out_kurus        BIGINT NOT NULL DEFAULT 0,
  cash_in_kurus          BIGINT NOT NULL DEFAULT 0,
  card_in_kurus          BIGINT NOT NULL DEFAULT 0,
  bank_in_kurus          BIGINT NOT NULL DEFAULT 0,
  closing_balance_kurus  BIGINT NOT NULL DEFAULT 0,
  physical_counted_kurus BIGINT NOT NULL DEFAULT 0,
  diff_kurus             BIGINT NOT NULL DEFAULT 0,
  note                   TEXT NOT NULL DEFAULT '',
  closed_by              BIGINT,
  closed_at              TEXT NOT NULL DEFAULT (now()::text)
);

CREATE TABLE IF NOT EXISTS treatment_catalog (
  id                  BIGSERIAL PRIMARY KEY,
  clinic_id           BIGINT NOT NULL DEFAULT 1,
  code                TEXT NOT NULL,
  name                TEXT NOT NULL,
  category            TEXT NOT NULL DEFAULT 'Genel',
  default_price_kurus BIGINT NOT NULL DEFAULT 0,
  default_status      TEXT NOT NULL DEFAULT 'treated',
  active              INT NOT NULL DEFAULT 1,
  created_at          TEXT NOT NULL DEFAULT (now()::text)
);

ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS procedure_type TEXT NOT NULL DEFAULT '';
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS shade_color TEXT NOT NULL DEFAULT 'A2';
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS sent_date TEXT NOT NULL DEFAULT '';
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS delivered_date TEXT;
ALTER TABLE lab_orders ADD COLUMN IF NOT EXISTS created_by BIGINT;
ALTER TABLE implant_records ADD COLUMN IF NOT EXISTS expiry_date TEXT NOT NULL DEFAULT '';
ALTER TABLE implant_records ADD COLUMN IF NOT EXISTS used_at TEXT NOT NULL DEFAULT '';
ALTER TABLE implant_records ADD COLUMN IF NOT EXISTS supplier TEXT NOT NULL DEFAULT '';
ALTER TABLE implant_records ADD COLUMN IF NOT EXISTS document_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE implant_records ADD COLUMN IF NOT EXISTS uts_barcode TEXT NOT NULL DEFAULT '';
ALTER TABLE implant_records ADD COLUMN IF NOT EXISTS created_by BIGINT;
ALTER TABLE patient_media ADD COLUMN IF NOT EXISTS appointment_id BIGINT;
ALTER TABLE patient_media ADD COLUMN IF NOT EXISTS tooth_record_id BIGINT;
ALTER TABLE patient_media ADD COLUMN IF NOT EXISTS original_filename TEXT NOT NULL DEFAULT '';
ALTER TABLE patient_media ADD COLUMN IF NOT EXISTS file_size_bytes BIGINT NOT NULL DEFAULT 0;
ALTER TABLE patient_media ADD COLUMN IF NOT EXISTS sha256_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE patient_media ADD COLUMN IF NOT EXISTS encrypted_path TEXT NOT NULL DEFAULT '';
ALTER TABLE suppliers ADD COLUMN IF NOT EXISTS contact_name TEXT NOT NULL DEFAULT '';
ALTER TABLE suppliers ADD COLUMN IF NOT EXISTS balance_kurus BIGINT NOT NULL DEFAULT 0;
ALTER TABLE treatment_catalog ADD COLUMN IF NOT EXISTS default_price_kurus BIGINT NOT NULL DEFAULT 0;
ALTER TABLE treatment_catalog ADD COLUMN IF NOT EXISTS default_status TEXT NOT NULL DEFAULT 'treated';

-- High-concurrency composite indexes (100+ concurrent users / webhooks / calendar slots)
CREATE INDEX IF NOT EXISTS patients_clinic_phone_idx ON patients(clinic_id, phone_hmac);
CREATE INDEX IF NOT EXISTS patients_clinic_active_idx ON patients(clinic_id, active, id DESC);
CREATE INDEX IF NOT EXISTS appointments_clinic_starts_idx ON appointments(clinic_id, starts_at);
CREATE INDEX IF NOT EXISTS appointments_clinic_doc_starts_idx ON appointments(clinic_id, doctor_id, starts_at);
CREATE INDEX IF NOT EXISTS appointments_clinic_chair_status_idx ON appointments(clinic_id, status, chair, starts_at);
CREATE INDEX IF NOT EXISTS message_log_clinic_patient_idx ON message_log(clinic_id, patient_id, id DESC);
CREATE INDEX IF NOT EXISTS campaign_events_clinic_camp_idx ON campaign_events(clinic_id, campaign_id, event_type);
CREATE INDEX IF NOT EXISTS charges_clinic_patient_idx ON charges(clinic_id, patient_id, voided_at);
CREATE INDEX IF NOT EXISTS payments_clinic_patient_idx ON payments(clinic_id, patient_id, voided_at);

