-- n8n kendi veritabanını kullanır
CREATE DATABASE n8n;

\connect dentacore

CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Hasta: telefon şifreli (Fernet) + aranabilir HMAC. Ad isteğe bağlı, tanı/teşhis bu tabloda tutulmaz.
CREATE TABLE patients (
  id            BIGSERIAL PRIMARY KEY,
  clinic_id     BIGINT NOT NULL DEFAULT 1,
  phone_hmac    TEXT NOT NULL,
  phone_enc     TEXT NOT NULL,
  display_name  TEXT,
  lang          TEXT NOT NULL DEFAULT 'tr',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (clinic_id, phone_hmac)
);

-- KVKK: her onay ayrı satır, metnin özeti (hash) ve sürümü ile. Geri alma revoked_at ile.
CREATE TABLE consents (
  id           BIGSERIAL PRIMARY KEY,
  patient_id   BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  kind         TEXT NOT NULL CHECK (kind IN ('kvkk_aydinlatma','saglik_verisi_acik_riza','iletisim','yurt_disi_aktarim')),
  text_version TEXT NOT NULL,
  text_sha256  TEXT NOT NULL,
  channel      TEXT NOT NULL,
  granted_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at   TIMESTAMPTZ
);
CREATE INDEX ON consents (patient_id, kind);

CREATE TABLE appointments (
  id          BIGSERIAL PRIMARY KEY,
  patient_id  BIGINT REFERENCES patients(id) ON DELETE SET NULL,
  starts_at   TIMESTAMPTZ NOT NULL,
  duration_min INT NOT NULL DEFAULT 30,
  treatment   TEXT NOT NULL,
  chair       TEXT NOT NULL DEFAULT '1',
  status      TEXT NOT NULL DEFAULT 'booked' CHECK (status IN ('booked','confirmed','cancelled','done','noshow','open')),
  reminder_sent_at TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ON appointments (starts_at);

CREATE TABLE waitlist (
  id          BIGSERIAL PRIMARY KEY,
  patient_id  BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  treatment   TEXT NOT NULL,
  earliest    TIMESTAMPTZ NOT NULL DEFAULT now(),
  active      BOOLEAN NOT NULL DEFAULT true,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Boş koltuk teklifleri: aynı slot için dalga dalga gönderim, ilk "EVET" kazanır.
CREATE TABLE slot_offers (
  id             BIGSERIAL PRIMARY KEY,
  appointment_id BIGINT NOT NULL REFERENCES appointments(id) ON DELETE CASCADE,
  waitlist_id    BIGINT NOT NULL REFERENCES waitlist(id) ON DELETE CASCADE,
  wave           INT NOT NULL,
  sent_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  status         TEXT NOT NULL DEFAULT 'sent' CHECK (status IN ('sent','won','lost','expired'))
);

-- Anamnez: cevaplar şifreli JSON; kırmızı bayraklar açık metin (hekim uyarısı için).
CREATE TABLE anamnesis (
  id            BIGSERIAL PRIMARY KEY,
  patient_id    BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  answers_enc   TEXT NOT NULL,
  red_flags     TEXT[] NOT NULL DEFAULT '{}',
  signer_name   TEXT NOT NULL,
  signature_sha256 TEXT NOT NULL,
  signed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE anamnesis_tokens (
  token       TEXT PRIMARY KEY,
  patient_id  BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  expires_at  TIMESTAMPTZ NOT NULL,
  used_at     TIMESTAMPTZ
);

-- İşlem sonrası takip: 2s / 24s / 72s kontrolleri
CREATE TABLE postop_checks (
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
CREATE INDEX ON postop_checks (due_at) WHERE sent_at IS NULL;

-- Tedavi planı / teklif takibi (uyuyan hasta madencisi)
CREATE TABLE treatment_plans (
  id            BIGSERIAL PRIMARY KEY,
  patient_id    BIGINT NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
  treatment     TEXT NOT NULL,
  planned_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','accepted','declined','lost')),
  last_contact_at TIMESTAMPTZ,
  followups_sent INT NOT NULL DEFAULT 0
);

-- Mesaj günlüğü: içerik değil, yalnızca hangi katmanın cevap verdiği ve token sayısı (maliyet takibi)
CREATE TABLE message_log (
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
CREATE INDEX ON message_log (created_at);

CREATE TABLE alerts (
  id          BIGSERIAL PRIMARY KEY,
  clinic_id   BIGINT NOT NULL DEFAULT 1,
  patient_id  BIGINT REFERENCES patients(id) ON DELETE SET NULL,
  kind        TEXT NOT NULL,
  detail      TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ
);
