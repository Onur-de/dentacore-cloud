-- DentaCore Paket 1 (P1): mesaj/webhook ve zamanlayıcı güvenilirliği.
-- Idempotent: migration çalıştırıcı (core.run_migrations) checksum değişince yeniden uygular; her ifade tekrar çalıştırılabilir.
--
-- 1) webhook_inbox  : Meta'dan gelen her mesaj, HTTP 200 dönülmeden ÖNCE kalıcı yazılır (transactional inbox).
--                     UNIQUE (channel, external_id) = küme genelinde, restart'a dayanıklı mükerrer engeli.
--                     Aynı tablo PostgreSQL iş kuyruğudur: FOR UPDATE SKIP LOCKED + lease + exponential backoff + DLQ ('dead').
-- 2) *_claimed_*    : Hatırlatma / post-op için "önce sahiplen, sonra gönder" (Redis'e bağımlı değil).
-- 3) system_heartbeat: Sağlık uçları için küme genelinde "son başarılı çalışma" kaydı.
-- 4) scheduler_runs : Günlük işlerin (sabah özeti vb.) gün başına tam bir kez sahiplenilmesi.

CREATE TABLE IF NOT EXISTS webhook_inbox (
  id               BIGSERIAL PRIMARY KEY,
  channel          TEXT NOT NULL CHECK (channel IN ('wa','ig')),
  external_id      TEXT NOT NULL,
  clinic_id        BIGINT NOT NULL,
  sender_key       TEXT NOT NULL,                 -- HMAC(kanal:klinik:gönderen); ham telefon tutulmaz
  payload_enc      TEXT,                          -- Fernet ile şifreli mesaj (sağlık verisi olabilir); 'done' olunca NULL'lanır
  status           TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','done','dead')),
  attempts         INT NOT NULL DEFAULT 0,
  max_attempts     INT NOT NULL DEFAULT 10,
  next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  locked_by        TEXT,
  lease_expires_at TIMESTAMPTZ,
  last_error       TEXT,                          -- yalnızca hata sınıfı + kısaltılmış/maskelenmiş ileti (PHI yok)
  received_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at     TIMESTAMPTZ,
  UNIQUE (channel, external_id)
);

CREATE INDEX IF NOT EXISTS webhook_inbox_ready_idx  ON webhook_inbox (next_attempt_at, id) WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS webhook_inbox_lease_idx  ON webhook_inbox (lease_expires_at)    WHERE status = 'processing';
CREATE INDEX IF NOT EXISTS webhook_inbox_sender_idx ON webhook_inbox (sender_key, id)      WHERE status IN ('pending','processing');
CREATE INDEX IF NOT EXISTS webhook_inbox_dead_idx   ON webhook_inbox (id)                  WHERE status = 'dead';
CREATE INDEX IF NOT EXISTS webhook_inbox_done_idx   ON webhook_inbox (processed_at)        WHERE status = 'done';

ALTER TABLE appointments  ADD COLUMN IF NOT EXISTS reminder_claimed_at TIMESTAMPTZ;
ALTER TABLE appointments  ADD COLUMN IF NOT EXISTS reminder_claimed_by TEXT;
ALTER TABLE postop_checks ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;
ALTER TABLE postop_checks ADD COLUMN IF NOT EXISTS claimed_by TEXT;

CREATE TABLE IF NOT EXISTS system_heartbeat (
  name          TEXT PRIMARY KEY,
  instance      TEXT,
  last_ok_at    TIMESTAMPTZ,
  last_error    TEXT,
  last_error_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scheduler_runs (
  job        TEXT NOT NULL,
  run_key    TEXT NOT NULL,
  claimed_by TEXT,
  claimed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (job, run_key)
);
