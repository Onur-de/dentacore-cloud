"""Kalıcı webhook gelen kutusu (transactional inbox) + PostgreSQL iş kuyruğu.

Garanti modeli (dürüst tanım): **en az bir kez (at-least-once) işleme + mükerrer girdi engeli**.
- Webhook, mesajı `webhook_inbox`'a kalıcı yazmadan Meta'ya 200 DÖNMEZ. Yazılamazsa 503 döner, Meta yeniden dener.
- `UNIQUE (channel, external_id)`: aynı mesajın tekrar gelmesi (Meta yeniden denemesi, restart, iki worker) tek satıra düşer.
- İşleme: `FOR UPDATE SKIP LOCKED` ile atomik sahiplenme + lease. Worker ölürse lease dolunca başka worker devralır.
- Hata: exponential backoff (+jitter); `max_attempts` aşılırsa 'dead' (DLQ) + panel uyarısı; yönetici yeniden kuyruğa alabilir.
- Aynı gönderenin mesajları sırayla işlenir (daha eski bitmemiş mesajı olan gönderenin yeni mesajı sahiplenilemez).
- Dış etki (WhatsApp cevabı) için "tam bir kez" İDDİA EDİLMEZ: işleyici çökerse cevap tekrar gönderilebilir
  (Meta Cloud API gönderim idempotency anahtarı sunmaz). Dar pencere; bkz. docs/ yedekleme-güvenilirlik notları.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import hmac
import json
import logging
import random
import re
import time
from collections.abc import Awaitable, Callable

from .core import S, add_alert, dec, enc, env, heartbeat_ok, instance_id, q, q1

log = logging.getLogger("inbox")

MAX_ATTEMPTS = int(env("DC_INBOX_MAX_ATTEMPTS", "10"))
LEASE_SECONDS = int(env("DC_INBOX_LEASE_SECONDS", "120"))
BACKOFF_BASE_S = float(env("DC_INBOX_BACKOFF_BASE_S", "5"))
BACKOFF_CAP_S = float(env("DC_INBOX_BACKOFF_CAP_S", "3600"))
POLL_SECONDS = float(env("DC_INBOX_POLL_S", "1.0"))
DONE_RETENTION_DAYS = int(env("DC_INBOX_RETENTION_DAYS", "30"))

# (mesaj, profil_adı, kanal, klinik_id) -> None ; hata durumunda istisna fırlatır
Handler = Callable[[dict, "str | None", str, int], Awaitable[None]]


def backoff_seconds(attempts: int, jitter: bool = True) -> float:
    """Deneme sayısına göre bekleme: base * 2^(n-1), tavan BACKOFF_CAP_S, ±%20 jitter."""
    d = min(BACKOFF_CAP_S, BACKOFF_BASE_S * (2 ** max(0, attempts - 1)))
    return d * (random.uniform(0.8, 1.2) if jitter else 1.0)  # noqa: S311  # nosec B311


def sender_key(channel: str, clinic_id: int, sender: str) -> str:
    """Gönderen sıralaması için anahtarlı özet; ham telefon / IG kimliği bu sütunda tutulmaz."""
    return hmac.new(S.phone_hmac_key, f"inbox:{channel}:{clinic_id}:{sender}".encode(), hashlib.sha256).hexdigest()[:32]


def synthetic_external_id(channel: str, message: dict) -> str:
    """Meta kimlik (id/mid) göndermediyse içerikten deterministik kimlik üretilir (aynı yük -> aynı kimlik)."""
    raw = json.dumps(message, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "syn:" + hashlib.sha256(f"{channel}:{raw}".encode()).hexdigest()


def _safe_err(e: BaseException) -> str:
    """Hata kaydına yalnızca sınıf adı + rakamları maskelenmiş kısa ileti yazılır (telefon/sağlık verisi sızmasın)."""
    return f"{type(e).__name__}: {re.sub(r'[0-9]{6,}', '***', str(e))[:160]}"


async def persist(channel: str, external_id: str, clinic_id: int, sender: str, message: dict,
                  profile_name: str | None = None) -> tuple[int | None, bool]:
    """Mesajı kalıcı yazar. (satır_id, yeni_mi) döner; mükerrerse (None, False). Yazılamazsa istisna YUTULMAZ."""
    payload = enc(json.dumps({"m": message, "profile_name": profile_name}, ensure_ascii=False))
    row = await q1(
        """INSERT INTO webhook_inbox (channel, external_id, clinic_id, sender_key, payload_enc, max_attempts)
           VALUES (%s,%s,%s,%s,%s,%s)
           ON CONFLICT (channel, external_id) DO NOTHING RETURNING id""",
        channel, external_id[:200], clinic_id, sender_key(channel, clinic_id, sender), payload, MAX_ATTEMPTS)
    return (int(row["id"]), True) if row else (None, False)


_CLAIM_SQL = """
WITH cand AS (
  SELECT w.id FROM webhook_inbox w
  WHERE ((w.status = 'pending' AND w.next_attempt_at <= now())
      OR (w.status = 'processing' AND w.lease_expires_at < now()))
    {id_filter}
    AND NOT EXISTS (SELECT 1 FROM webhook_inbox o
                    WHERE o.sender_key = w.sender_key AND o.id < w.id AND o.status IN ('pending','processing'))
  ORDER BY w.id
  FOR UPDATE OF w SKIP LOCKED
  LIMIT %s)
UPDATE webhook_inbox t SET
  status = CASE WHEN t.attempts + 1 > t.max_attempts THEN 'dead' ELSE 'processing' END,
  attempts = t.attempts + 1,
  locked_by = %s,
  lease_expires_at = now() + make_interval(secs => %s),
  last_error = CASE WHEN t.attempts + 1 > t.max_attempts THEN 'max_attempts_exceeded' ELSE t.last_error END
FROM cand
WHERE t.id = cand.id
RETURNING t.id, t.channel, t.clinic_id, t.payload_enc, t.status, t.attempts
"""


async def claim(worker_id: str, limit: int = 1, lease_seconds: float | None = None,
                only_ids: list[int] | None = None) -> list[dict]:
    """Atomik sahiplenme: SKIP LOCKED sayesinde iki worker asla aynı satırı alamaz."""
    lease = float(LEASE_SECONDS if lease_seconds is None else lease_seconds)
    args: list = []
    id_filter = ""
    if only_ids is not None:
        id_filter = "AND w.id = ANY(%s)"
        args.append(list(only_ids))
    args += [limit, worker_id, lease]
    rows = await q(_CLAIM_SQL.format(id_filter=id_filter), *args)  # nosec B608  # noqa: S608
    return sorted(rows, key=lambda r: r["id"])


async def _alert_dead(row: dict, err: str) -> None:
    try:
        await add_alert(
            None, "webhook_dead",
            f"Webhook mesajı kalıcı olarak işlenemedi (DLQ): kanal={row['channel']} inbox#{row['id']} ({err}). "
            "Yönetici panelinden yeniden kuyruğa alınabilir.",
            clinic_id=int(row["clinic_id"]))
    except Exception:
        log.exception("DLQ uyarısı yazılamadı inbox#%s", row.get("id"))


async def _complete(rid: int, worker_id: str) -> None:
    rows = await q(
        """UPDATE webhook_inbox SET status='done', payload_enc=NULL, processed_at=now(),
                  locked_by=NULL, lease_expires_at=NULL, last_error=NULL
           WHERE id=%s AND status='processing' AND locked_by=%s RETURNING id""", rid, worker_id)
    if not rows:
        log.warning("inbox#%s tamamlandı ama lease başka worker'a geçmişti (at-least-once: mükerrer işleme mümkün)", rid)


async def _fail(row: dict, worker_id: str, err: BaseException) -> None:
    text = _safe_err(err)
    delay = backoff_seconds(int(row["attempts"]))
    upd = await q1(
        """UPDATE webhook_inbox SET
             status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'pending' END,
             next_attempt_at = now() + make_interval(secs => %s),
             locked_by = NULL, lease_expires_at = NULL, last_error = %s
           WHERE id=%s AND status='processing' AND locked_by=%s
           RETURNING status""", float(delay), text, row["id"], worker_id)
    log.warning("inbox#%s işlenemedi (deneme %s): %s", row["id"], row["attempts"], text)
    if upd and upd["status"] == "dead":
        await _alert_dead(row, text)


async def _release(rid: int, worker_id: str) -> None:
    """Kapanış (iptal) sırasında satırı deneme hakkı harcamadan geri bırakır."""
    await q(
        """UPDATE webhook_inbox SET status='pending', attempts=GREATEST(attempts-1, 0), next_attempt_at=now(),
                  locked_by=NULL, lease_expires_at=NULL
           WHERE id=%s AND status='processing' AND locked_by=%s""", rid, worker_id)


async def process_row(row: dict, handler: Handler, worker_id: str) -> bool:
    """Sahiplenilmiş tek satırı işler. Başarılıysa True."""
    if row["status"] == "dead":  # claim() max_attempts aşımı (çöken worker döngüsü) nedeniyle öldürdü
        await _alert_dead(row, "max_attempts_exceeded")
        return False
    try:
        payload = json.loads(dec(row["payload_enc"]))
        await handler(payload["m"], payload.get("profile_name"), row["channel"], int(row["clinic_id"]))
    except asyncio.CancelledError:
        with contextlib.suppress(Exception):
            await asyncio.shield(_release(int(row["id"]), worker_id))
        raise
    except Exception as e:  # noqa: BLE001 - her hata yeniden denenir / DLQ'ya gider
        await _fail(row, worker_id, e)
        return False
    await _complete(int(row["id"]), worker_id)
    return True


async def drain_ids(ids: list[int], handler: Handler, worker_id: str, max_rounds: int = 100) -> int:
    """Verilen satırları (uygun olanları) satır içi işler; başarıyla bitenlerin sayısını döner."""
    done = 0
    for _ in range(max_rounds):
        rows = await claim(worker_id, limit=max(1, len(ids)), only_ids=ids)
        if not rows:
            break
        for row in rows:
            if await process_row(row, handler, worker_id):
                done += 1
    return done


async def drain_all(handler: Handler, worker_id: str, budget_s: float = 15.0) -> int:
    """Bekleyen tüm uygun satırları (zaman bütçesi içinde) işler. Yönetici 'kuyruğu boşalt' ucu kullanır."""
    done, t0 = 0, time.monotonic()
    while time.monotonic() - t0 < budget_s:
        rows = await claim(worker_id, limit=10)
        if not rows:
            break
        for row in rows:
            if await process_row(row, handler, worker_id):
                done += 1
    return done


async def worker_loop(handler: Handler, wake: asyncio.Event, worker_no: int = 0) -> None:
    """Sürekli çalışan işleyici. PG kesintisinde çökmez; üstel bekleme ile yeniden dener."""
    wid = f"{instance_id()}#{worker_no}"
    err_delay = 1.0
    while True:
        try:
            wake.clear()
            rows = await claim(wid, limit=1)
            if rows:
                for row in rows:
                    await process_row(row, handler, wid)
                err_delay = 1.0
                continue
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(wake.wait(), POLL_SECONDS)
            err_delay = 1.0
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("inbox worker hatası; %.0fs sonra yeniden denenecek", err_delay)
            await asyncio.sleep(err_delay)
            err_delay = min(30.0, err_delay * 2)


async def heartbeat_loop(interval: float = 15.0) -> None:
    """Bu sürecin inbox işleyicilerinin canlı olduğunu küme genelinde görünür kılar (readiness/health)."""
    name = f"inbox:{instance_id()}"
    n = 0
    while True:
        try:
            await heartbeat_ok(name)
            if n % 240 == 0:  # ~saatte bir ölü örneklerin kayıtlarını temizle
                await q("DELETE FROM system_heartbeat WHERE name LIKE 'inbox:%%' AND last_ok_at < now() - interval '1 day'")
            n += 1
        except asyncio.CancelledError:
            raise
        except Exception:
            log.warning("inbox heartbeat yazılamadı", exc_info=True)
        await asyncio.sleep(interval)


async def stats() -> dict:
    r = await q1(
        """SELECT count(*) FILTER (WHERE status='pending')    AS pending,
                  count(*) FILTER (WHERE status='processing') AS processing,
                  count(*) FILTER (WHERE status='dead')       AS dead,
                  count(*) FILTER (WHERE status='done' AND processed_at > now() - interval '1 hour') AS done_1h,
                  coalesce(extract(epoch FROM now() - min(received_at) FILTER (WHERE status IN ('pending','processing')))::int, 0) AS oldest_age_s
           FROM webhook_inbox""")
    return {k: int(v or 0) for k, v in (r or {}).items()}


async def list_dead(limit: int = 50) -> list[dict]:
    """DLQ özeti (yük/PHI içermez)."""
    return await q(
        """SELECT id, channel, clinic_id, attempts, last_error, received_at
           FROM webhook_inbox WHERE status='dead' ORDER BY id DESC LIMIT %s""", limit)


async def requeue(rid: int) -> bool:
    """DLQ'daki mesajı yeniden kuyruğa alır (yük silinmemişse)."""
    row = await q1(
        """UPDATE webhook_inbox SET status='pending', attempts=0, next_attempt_at=now(), last_error=NULL,
                  locked_by=NULL, lease_expires_at=NULL
           WHERE id=%s AND status='dead' AND payload_enc IS NOT NULL RETURNING id""", rid)
    return bool(row)


async def purge_done(days: int | None = None) -> int:
    """İşlenmiş kayıtları (yükü zaten silinmiş) saklama süresi sonunda temizler."""
    rows = await q(
        "DELETE FROM webhook_inbox WHERE status='done' AND processed_at < now() - make_interval(days => %s) RETURNING id",
        DONE_RETENTION_DAYS if days is None else days)
    return len(rows)
