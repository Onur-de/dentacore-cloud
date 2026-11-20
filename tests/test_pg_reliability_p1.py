"""P1 güvenilirlik testleri — GERÇEK PostgreSQL üzerinde (mock yok).

Çalıştırma önkoşulu: erişilebilir bir test PG (varsayılan: docker `dentacore-pg-test`, 127.0.0.1:55432).
DSN `DC_PG_TEST_DSN` ile değiştirilebilir. PG yoksa testler ATLANIR. Test her başlangıçta `public` şemasını SİLİP yeniden
kurar; bu yüzden DSN veritabanı adı mutlaka `_test` ile bitmelidir (yanlışlıkla gerçek veriyi silmeyi engeller).

Kanıtlananlar:
  1) migrations/ idempotent uygulanır (iki kez çalıştırma güvenli, schema_migrations tekil).
  2) Aynı external_id ile gelen mükerrer webhook 1 kez kaydedilir, 1 kez işlenir.
  3) 20 mesaj + 2 yarışan worker (FOR UPDATE SKIP LOCKED): kayıpsız ve mükerrersiz tam 20 işleme; aynı gönderen sıralı.
  4) Çöken worker'ın süresi dolmuş lease'i devralınır; max_attempts aşımı -> DLQ + uyarı; requeue ile yeniden işlenir.
  5) İki eşzamanlı worker: hatırlatma / post-op / günlük görev tek sefer.
"""
from __future__ import annotations

import asyncio
import functools
import os
import pathlib
import urllib.parse
from collections import Counter
from datetime import timedelta

import pytest

DSN = os.environ.get("DC_PG_TEST_DSN", "postgresql://dentacore:dctest_pw_local_only@127.0.0.1:55432/dentacore_test")
os.environ["DATABASE_URL"] = DSN
os.environ.setdefault("PHONE_HMAC_KEY", "p1-test-phone-hmac-key-0123456789abcdef")
if not os.environ.get("DATA_ENCRYPTION_KEY"):
    from cryptography.fernet import Fernet
    os.environ["DATA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()

psycopg = pytest.importorskip("psycopg")
pytest.importorskip("psycopg_pool")

from api.app import core, inbox, modules  # noqa: E402

MIG_DIR = pathlib.Path(__file__).resolve().parents[1] / "api" / "app" / "migrations"
DB_NAME = urllib.parse.urlparse(DSN).path.lstrip("/")


def _pg_reachable() -> bool:
    try:
        with psycopg.connect(DSN, connect_timeout=3):
            return True
    except Exception:
        return False


async def _exec(sql: str, *args):
    async with core.pool.connection() as conn:
        await conn.execute(sql, args or None)


async def _fresh_db(apply_migrations: bool = True) -> None:
    if not DB_NAME.endswith("_test"):
        pytest.fail(f"Güvenlik: test DB adı '_test' ile bitmeli, gelen: {DB_NAME}")
    if not _pg_reachable():
        pytest.skip("Test PostgreSQL erişilemiyor (docker `dentacore-pg-test`).")
    await core.db_open()
    await _exec("DROP SCHEMA public CASCADE")
    await _exec("CREATE SCHEMA public")
    if apply_migrations:
        await core.run_migrations(str(MIG_DIR))
        await _exec("INSERT INTO clinics (id, name, slug) VALUES (1, 'Test Klinik', 'test') ON CONFLICT DO NOTHING")


def pg_test(fn=None, *, migrations: bool = True):
    def deco(f):
        @functools.wraps(f)
        def wrapper():
            async def main():
                await _fresh_db(migrations)
                try:
                    await asyncio.wait_for(f(), 120)
                finally:
                    await core.db_close()
            asyncio.run(main())
        return wrapper
    return deco(fn) if fn else deco


async def _wait_until(pred, timeout: float = 30.0, step: float = 0.05):
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    while loop.time() - t0 < timeout:
        if await pred():
            return
        await asyncio.sleep(step)
    raise AssertionError("zaman aşımı: koşul gerçekleşmedi")


def _msg(i: int, sender: str | None = None) -> dict:
    return {"id": f"wamid.{i}", "from": sender or f"90555000{i:04d}", "type": "text", "text": {"body": f"mesaj {i}"}}


class Recorder:
    """Inbox işleyicisi: her çağrıyı kaydeder (mesaj kimliği sayacı)."""

    def __init__(self, delay: float = 0.0, fail_ids: set[str] | None = None):
        self.calls: list[str] = []
        self.delay = delay
        self.fail_ids = fail_ids or set()

    async def __call__(self, m: dict, profile_name, channel: str, clinic_id: int) -> None:
        if self.delay:
            await asyncio.sleep(self.delay)
        if m["id"] in self.fail_ids:
            raise RuntimeError("kasıtlı hata")
        self.calls.append(m["id"])


# ---------------------------------------------------------------- 1) migrations
@pg_test(migrations=False)
async def test_migrations_idempotent():
    files = sorted(p.name for p in MIG_DIR.glob("*.sql"))
    assert any(f.startswith("003_reliability") for f in files)
    await core.run_migrations(str(MIG_DIR))
    await core.run_migrations(str(MIG_DIR))  # ikinci çalıştırma hata vermemeli, yeni kayıt eklememeli
    async with core.pool.connection() as conn:
        cur = await conn.execute("SELECT version FROM schema_migrations ORDER BY version")
        versions = [r["version"] for r in await cur.fetchall()]
        cur = await conn.execute("""SELECT table_name FROM information_schema.tables WHERE table_schema='public'""")
        tables = {r["table_name"] for r in await cur.fetchall()}
    assert len(versions) == len(set(versions)) == len(files)
    assert {"webhook_inbox", "system_heartbeat", "scheduler_runs", "appointments", "postop_checks"} <= tables
    # tek dosya biçimi de çalışmalı (geriye dönük uyumluluk)
    await core.run_migrations(str(MIG_DIR / "002_platform.sql"))


# ---------------------------------------------------------------- 2) mükerrer webhook
@pg_test
async def test_duplicate_webhook_persisted_and_processed_once():
    m = _msg(1)
    results = await asyncio.gather(*[inbox.persist("wa", "wamid.dup", 1, m["from"], m) for _ in range(8)])
    new = [r for r in results if r[1]]
    assert len(new) == 1 and sum(1 for r in results if not r[1]) == 7
    row = await core.q1("SELECT count(*) AS n FROM webhook_inbox WHERE channel='wa' AND external_id='wamid.dup'")
    assert row["n"] == 1
    # ham mesaj şifreli saklanır (PHI düz metin olarak diskte durmaz)
    raw = await core.q1("SELECT payload_enc FROM webhook_inbox WHERE id=%s", new[0][0])
    assert "mesaj 1" not in raw["payload_enc"]
    h = Recorder()
    assert await inbox.drain_ids([new[0][0]], h, "w-test") == 1
    # tekrar sürülse de ikinci kez işlenmez
    assert await inbox.drain_all(h, "w-test", budget_s=2) == 0
    assert h.calls == ["wamid.1"]
    # aynı kimlik farklı kanalda ayrı mesajdır
    _, new_ig = await inbox.persist("ig", "wamid.dup", 1, m["from"], m)
    assert new_ig


# ---------------------------------------------------------------- 3) 2 eşzamanlı worker, 20 mesaj
@pg_test
async def test_two_workers_process_20_messages_exactly_once(monkeypatch):
    monkeypatch.setattr(inbox, "POLL_SECONDS", 0.05)
    msgs = [_msg(i) for i in range(20)]  # 20 farklı gönderen
    ids = await asyncio.gather(*[inbox.persist("wa", m["id"], 1, m["from"], m) for m in msgs])
    assert all(new for _, new in ids)
    h = Recorder(delay=0.02)
    wakes = [asyncio.Event(), asyncio.Event()]
    workers = [asyncio.create_task(inbox.worker_loop(h, wakes[i], i)) for i in range(2)]
    try:
        async def done():
            st = await inbox.stats()
            return st["pending"] == 0 and st["processing"] == 0
        await _wait_until(done)
    finally:
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    assert len(h.calls) == 20, "kayıp ya da mükerrer işleme"
    assert Counter(h.calls) == Counter(m["id"] for m in msgs)
    assert max(Counter(h.calls).values()) == 1
    st = await inbox.stats()
    assert st["dead"] == 0
    # işlenen satırlarda yük silinmiş olmalı (veri minimizasyonu)
    left = await core.q1("SELECT count(*) AS n FROM webhook_inbox WHERE status='done' AND payload_enc IS NOT NULL")
    assert left["n"] == 0


@pg_test
async def test_same_sender_messages_processed_in_order_across_workers(monkeypatch):
    monkeypatch.setattr(inbox, "POLL_SECONDS", 0.05)
    sender = "905550009999"
    msgs = [_msg(i, sender) for i in range(6)]
    for m in msgs:
        await inbox.persist("wa", m["id"], 1, sender, m)
    h = Recorder(delay=0.02)
    workers = [asyncio.create_task(inbox.worker_loop(h, asyncio.Event(), i)) for i in range(2)]
    try:
        async def done():
            return len(h.calls) == 6
        await _wait_until(done)
    finally:
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
    assert h.calls == [m["id"] for m in msgs]


# ---------------------------------------------------------------- 4) çöken worker, DLQ, requeue
@pg_test
async def test_expired_lease_is_taken_over_by_other_worker():
    m = _msg(1)
    rid, _ = await inbox.persist("wa", m["id"], 1, m["from"], m)
    crashed = await inbox.claim("crashed-worker", limit=1, lease_seconds=0.1)  # sahiplen, sonra "çök"
    assert [r["id"] for r in crashed] == [rid]
    # lease dolmadan başkası alamaz
    assert await inbox.claim("w2", limit=1) == []
    await asyncio.sleep(0.3)
    h = Recorder()
    assert await inbox.drain_all(h, "w2", budget_s=5) == 1
    assert h.calls == [m["id"]]
    row = await core.q1("SELECT status, attempts FROM webhook_inbox WHERE id=%s", rid)
    assert row["status"] == "done" and row["attempts"] == 2
    # çöken worker'ın geç gelen tamamlama denemesi sonucu bozmaz
    await inbox._complete(rid, "crashed-worker")
    assert (await core.q1("SELECT status FROM webhook_inbox WHERE id=%s", rid))["status"] == "done"


@pg_test
async def test_max_attempts_goes_dead_alert_then_requeue_succeeds():
    m = _msg(7)
    rid, _ = await inbox.persist("wa", m["id"], 1, m["from"], m)
    await _exec("UPDATE webhook_inbox SET max_attempts=2 WHERE id=%s", rid)
    failing = Recorder(fail_ids={m["id"]})
    for _ in range(2):
        rows = await inbox.claim("w1", limit=1)
        assert len(rows) == 1
        assert await inbox.process_row(rows[0], failing, "w1") is False
        await _exec("UPDATE webhook_inbox SET next_attempt_at=now() WHERE id=%s AND status='pending'", rid)
    row = await core.q1("SELECT status, attempts, last_error FROM webhook_inbox WHERE id=%s", rid)
    assert row["status"] == "dead" and row["attempts"] == 2
    assert "RuntimeError" in row["last_error"]
    assert await inbox.claim("w1", limit=1) == []  # ölü satır tekrar sahiplenilmez
    alert = await core.q1("SELECT count(*) AS n FROM alerts WHERE kind='webhook_dead' AND clinic_id=1")
    assert alert["n"] >= 1
    assert [d["id"] for d in await inbox.list_dead()] == [rid]
    # yönetici yeniden kuyruğa alır -> bu kez işlenir
    assert await inbox.requeue(rid) is True
    ok = Recorder()
    assert await inbox.drain_ids([rid], ok, "w1") == 1
    assert ok.calls == [m["id"]]
    assert (await core.q1("SELECT status FROM webhook_inbox WHERE id=%s", rid))["status"] == "done"
    assert await inbox.requeue(rid) is False  # done satır requeue edilemez


@pg_test
async def test_claim_marks_dead_when_attempts_exhausted_by_crash_loop():
    """Sürekli çöken (hiç fail yazamayan) worker döngüsü sonsuza dek devam etmez: claim() satırı 'dead' yapar."""
    m = _msg(9)
    rid, _ = await inbox.persist("wa", m["id"], 1, m["from"], m)
    await _exec("UPDATE webhook_inbox SET max_attempts=2 WHERE id=%s", rid)
    for _ in range(2):
        assert len(await inbox.claim("crashy", limit=1, lease_seconds=0.05)) == 1
        await asyncio.sleep(0.15)
    rows = await inbox.claim("crashy", limit=1, lease_seconds=0.05)
    assert [r["status"] for r in rows] == ["dead"]
    h = Recorder()
    assert await inbox.process_row(rows[0], h, "crashy") is False and h.calls == []
    assert (await core.q1("SELECT count(*) AS n FROM alerts WHERE kind='webhook_dead'"))["n"] >= 1


# ---------------------------------------------------------------- 5) hatırlatma / post-op / günlük görev
async def _seed_patients(n: int) -> list[int]:
    ids = []
    for i in range(n):
        phone = f"90555111{i:04d}"
        row = await core.q1(
            "INSERT INTO patients (clinic_id, phone_hmac, phone_enc, display_name) VALUES (1,%s,%s,%s) RETURNING id",
            core.phone_hmac(phone), core.enc(phone), f"Hasta {i}")
        ids.append(int(row["id"]))
    return ids


@pg_test
async def test_two_workers_send_each_reminder_once(monkeypatch):
    pids = await _seed_patients(10)
    ref = modules.now()
    for pid in pids:
        await core.q("INSERT INTO appointments (patient_id, starts_at, treatment, status) VALUES (%s,%s,'Kontrol','booked')",
                     pid, ref + timedelta(hours=24))
    sent: list[str] = []

    async def fake_send(phone, tpl, params, quick_reply_payloads=None, **kw):
        await asyncio.sleep(0.01)  # yarışma penceresini genişlet
        sent.append(quick_reply_payloads[0])
        return {"messages": [{"id": "ok"}]}

    monkeypatch.setattr(modules.wa, "send_template", fake_send)
    counts = await asyncio.gather(*[modules.send_reminders(now_dt=ref, respect_hours=False) for _ in range(2)])
    assert sum(counts) == 10
    assert len(sent) == 10 and max(Counter(sent).values()) == 1
    left = await core.q1("SELECT count(*) AS n FROM appointments WHERE reminder_sent_at IS NULL")
    assert left["n"] == 0
    # sonraki tur: gönderilecek bir şey kalmamış olmalı
    assert await modules.send_reminders(now_dt=ref, respect_hours=False) == 0
    assert len(sent) == 10


@pg_test
async def test_failed_reminder_keeps_claim_until_lease_expires(monkeypatch):
    (pid,) = await _seed_patients(1)
    ref = modules.now()
    row = await core.q1("INSERT INTO appointments (patient_id, starts_at, treatment) VALUES (%s,%s,'Kontrol') RETURNING id",
                        pid, ref + timedelta(hours=24))
    calls = {"n": 0}

    async def failing(phone, tpl, params, quick_reply_payloads=None, **kw):
        calls["n"] += 1
        return {"error": {"code": 429}}

    monkeypatch.setattr(modules.wa, "send_template", failing)
    assert await modules.send_reminders(now_dt=ref, respect_hours=False) == 0
    assert calls["n"] == 1
    # lease dolmadan hemen tekrar denenmez (Meta 429'a karşı geri çekilme)
    assert await modules.send_reminders(now_dt=ref, respect_hours=False) == 0
    assert calls["n"] == 1
    await _exec("UPDATE appointments SET reminder_claimed_at = now() - interval '1 hour' WHERE id=%s", row["id"])

    async def ok(phone, tpl, params, quick_reply_payloads=None, **kw):
        calls["n"] += 1
        return {"messages": [{"id": "ok"}]}

    monkeypatch.setattr(modules.wa, "send_template", ok)
    assert await modules.send_reminders(now_dt=ref, respect_hours=False) == 1
    assert calls["n"] == 2


@pg_test
async def test_two_workers_send_each_postop_check_once(monkeypatch):
    pids = await _seed_patients(10)
    for i, pid in enumerate(pids):
        await core.q("INSERT INTO postop_checks (patient_id, procedure, due_at, stage) VALUES (%s,%s, now() - interval '1 hour', '2s')",
                     pid, f"islem-{i}")
    sent: list[str] = []

    async def fake_send(phone, tpl, params, **kw):
        await asyncio.sleep(0.01)
        sent.append(params[0])
        return {"messages": [{"id": "ok"}]}

    monkeypatch.setattr(modules.wa, "send_template", fake_send)
    counts = await asyncio.gather(*[modules.send_postop_checks() for _ in range(2)])
    assert sum(counts) == 10
    assert len(sent) == 10 and max(Counter(sent).values()) == 1
    assert (await core.q1("SELECT count(*) AS n FROM postop_checks WHERE sent_at IS NULL"))["n"] == 0
    assert await modules.send_postop_checks() == 0 and len(sent) == 10


@pg_test
async def test_daily_jobs_claimed_exactly_once_and_released_on_failure():
    results = await asyncio.gather(*[modules.claim_daily("morning_brief", "20260101") for _ in range(6)])
    assert results.count(True) == 1
    assert await modules.claim_daily("morning_brief", "20260102") is True  # ertesi gün yeniden sahiplenilir
    assert await modules.claim_daily("mine_sleeping_plans", "20260101") is True  # farklı iş bağımsız

    calls = {"n": 0}

    async def boom():
        calls["n"] += 1
        raise RuntimeError("görev hatası")

    with pytest.raises(RuntimeError):
        await modules._run_daily("morning_brief", "20260103", boom)
    # hata sonrası sahiplenme bırakılır -> sonraki turda yeniden denenir
    with pytest.raises(RuntimeError):
        await modules._run_daily("morning_brief", "20260103", boom)
    assert calls["n"] == 2

    async def fine():
        calls["n"] += 1

    await modules._run_daily("morning_brief", "20260103", fine)
    await modules._run_daily("morning_brief", "20260103", fine)  # ikinci kez çalışmaz
    assert calls["n"] == 3


@pg_test
async def test_scheduler_tick_lock_is_exclusive_across_connections():
    async with core.try_lock("dentacore:scheduler_tick") as a:
        assert a.acquired
        async with core.try_lock("dentacore:scheduler_tick") as b:
            assert not b.acquired  # ikinci worker turu atlar
    async with core.try_lock("dentacore:scheduler_tick") as c:
        assert c.acquired  # blok bitince kilit serbest


@pg_test
async def test_heartbeat_ok_and_error_recorded():
    await core.heartbeat_ok("scheduler")
    await core.heartbeat_error("scheduler", RuntimeError("tel 905551112233 hata"))
    row = await core.q1("SELECT last_ok_at, last_error, last_error_at FROM system_heartbeat WHERE name='scheduler'")
    assert row["last_ok_at"] is not None and row["last_error_at"] is not None
    assert "RuntimeError" in row["last_error"] and "905551112233" not in row["last_error"]
