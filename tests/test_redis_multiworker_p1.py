"""Adım 6b: Redis + çoklu worker paylaşımlı durum, GERÇEK Redis üzerinde.

Kanıtlanan sözler:
  - RateLimiter.hit (async) ve RateLimiter.hit_sync (sync uçlar) sayacı bütün worker'lar arasında paylaşır:
    N bağımsız istemci / N gerçek işletim sistemi süreci birlikte tam `limit` kadar izin verir (limit x N değil).
  - Anahtar her zaman TTL taşır (INCR ile EXPIRE arasında kesilen süreç sonsuz anahtar bırakmaz); pencere bitince sayaç sıfırlanır.
  - Redis kesintisinde istek 500 olmaz, limit atlanmaz (süreç içi sayaca düşülür), Redis dönünce paylaşımlı sayaç sürer.
  - Webhook tekilleştirme (`SET NX EX`) süreçler arasında tam bir kazanan üretir.
  - Gerçek iki uygulama süreci (aynı PostgreSQL + aynı Redis): giriş sınırı ve herkese açık uç nokta sınırı süreçler arası
    paylaşılır. Redis'siz KONTROL çalıştırması sınırın süreç başına kaldığını gösterir (testin ayırt edici olduğunun kanıtı).
Ön koşul: test Redis (docker `dentacore-redis-test`, 127.0.0.1:56379) ve test PG (55432). Erişilemezse ATLANIR;
DC_REQUIRE_REDIS=1 ya da DC_REQUIRE_PG=1 ise BAŞARISIZ olur. Kesinti testleri docker CLI ve konteyner adı ister (yoksa atlanır).
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from cryptography.fernet import Fernet

ROOT = pathlib.Path(__file__).resolve().parents[1]
API_DIR = str(ROOT / "api")
sys.path.insert(0, API_DIR)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from pg_app_harness import _KEEP, _spawn, _wait_ready, free_port, pg_app  # noqa: E402

from app.security import RateLimiter  # noqa: E402

REDIS_URL = os.environ.get("DC_REDIS_TEST_URL", "redis://:dctest_redis_local_only@127.0.0.1:56379/0")
CONTAINER = os.environ.get("DC_REDIS_TEST_CONTAINER", "dentacore-redis-test")
REQUIRE = os.environ.get("DC_REQUIRE_REDIS") == "1" or os.environ.get("DC_REQUIRE_PG") == "1"
PREFIX = "rltest-"


def uniq() -> str:
    return PREFIX + uuid.uuid4().hex[:12]


def _sync_client(timeout: float = 2.0, url: str = REDIS_URL):
    import redis
    return redis.Redis.from_url(url, decode_responses=True, socket_timeout=timeout, socket_connect_timeout=timeout)


def _aclient(url: str = REDIS_URL):
    import redis.asyncio as aioredis
    return aioredis.from_url(url, decode_responses=True)


def _wait_redis_up(timeout: float = 30.0) -> None:
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        try:
            c = _sync_client(1.0)
            c.ping()
            c.close()
            return
        except Exception as ex:  # noqa: BLE001
            last = ex
            time.sleep(0.4)
    raise RuntimeError(f"Redis {timeout:.0f} sn içinde dönmedi: {last}")


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=90, check=check)  # noqa: S603,S607


def _can_control_redis() -> bool:
    if not shutil.which("docker"):
        return False
    r = _docker("ps", "--filter", f"name=^{CONTAINER}$", "--format", "{{.Names}}", check=False)
    return r.returncode == 0 and CONTAINER in r.stdout


def _skip_if_no_docker_control() -> None:
    if not _can_control_redis():
        pytest.skip(f"docker CLI ya da '{CONTAINER}' konteyneri yok: gerçek kesinti testi atlandı")


@pytest.fixture(scope="module")
def rds():
    try:
        c = _sync_client()
        c.ping()
    except Exception as ex:  # noqa: BLE001
        if REQUIRE:
            pytest.fail(f"DC_REQUIRE_REDIS/DC_REQUIRE_PG=1 ama Redis erişilemiyor: {ex}", pytrace=False)
        pytest.skip(f"Test Redis erişilemiyor (docker {CONTAINER}): {ex}")
    yield c
    with contextlib.suppress(Exception):
        for pat in (f"dc:rl:{PREFIX}*", f"dc:rl:em:{PREFIX}*", f"dc:seen:{PREFIX}*", "dc:rl:ip:127.0.0.1", "dc:rl:camp_click:127.0.0.1"):
            for k in c.scan_iter(pat):
                c.delete(k)
    c.close()


# ----------------------------------------------------------------------------------------------------------------------
# 1) Async sayaç: bağımsız istemciler (= worker'lar) arasında kesin paylaşım
# ----------------------------------------------------------------------------------------------------------------------
def test_async_limit_is_exact_across_independent_workers(rds):
    key = uniq()

    async def run():
        clients = [_aclient() for _ in range(4)]
        limiters = [RateLimiter(redis=c) for c in clients]
        res = await asyncio.gather(*[limiters[i % 4].hit(key, 10, 60) for i in range(40)])
        for c in clients:
            await c.aclose()
        return res

    res = asyncio.run(run())
    assert sum(res) == 10 and len(res) - sum(res) == 30, res
    assert rds.get(f"dc:rl:{key}") == "40"
    assert 0 < rds.ttl(f"dc:rl:{key}") <= 60


def test_counter_expires_and_resets_after_window(rds):
    key = uniq()

    async def run():
        c = _aclient()
        rl = RateLimiter(redis=c)
        first, second = await rl.hit(key, 1, 2), await rl.hit(key, 1, 2)
        ttl = await c.ttl(f"dc:rl:{key}")
        await asyncio.sleep(2.6)
        third = await rl.hit(key, 1, 2)
        await c.aclose()
        return first, second, ttl, third

    first, second, ttl, third = asyncio.run(run())
    assert (first, second) == (True, False)
    assert 0 < ttl <= 2
    assert third is True, "pencere bitince sayaç sıfırlanmalı"


def test_orphaned_counter_without_ttl_is_repaired(rds):
    """INCR ile EXPIRE arasında kesilen süreç TTL'siz anahtar bırakır; sonraki istek TTL'yi onarmalı (sonsuz kilit olmaz)."""
    key = uniq()
    rds.incr(f"dc:rl:{key}")
    assert rds.ttl(f"dc:rl:{key}") == -1

    async def run():
        c = _aclient()
        ok = await RateLimiter(redis=c).hit(key, 5, 30)
        await c.aclose()
        return ok

    assert asyncio.run(run()) is True
    assert 0 < rds.ttl(f"dc:rl:{key}") <= 30


def test_reset_clears_the_shared_counter_for_every_worker(rds):
    key = uniq()

    async def run():
        ca, cb = _aclient(), _aclient()
        a, b = RateLimiter(redis=ca), RateLimiter(redis=cb)
        blocked = [await a.hit(key, 2, 60) for _ in range(3)]
        await b.reset(key)
        gone = await ca.exists(f"dc:rl:{key}")
        after = await a.hit(key, 2, 60)
        await ca.aclose()
        await cb.aclose()
        return blocked, gone, after

    blocked, gone, after = asyncio.run(run())
    assert blocked == [True, True, False]
    assert gone == 0
    assert after is True


# ----------------------------------------------------------------------------------------------------------------------
# 2) Sync sayaç (hit_sync: herkese açık uçlar): aynı paylaşım sözü
# ----------------------------------------------------------------------------------------------------------------------
def test_sync_limit_is_exact_across_independent_workers(rds):
    key = uniq()
    limiters = [RateLimiter(sync_redis=_sync_client()) for _ in range(4)]
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda i: limiters[i % 4].hit_sync(key, 10, 60), range(40)))
    assert sum(res) == 10 and len(res) - sum(res) == 30, res
    assert rds.get(f"dc:rl:{key}") == "40"
    assert 0 < rds.ttl(f"dc:rl:{key}") <= 60


def test_sync_and_async_limiters_share_one_counter(rds):
    """Aynı anahtar, bir worker async yoldan, diğeri sync yoldan: tek sayaç."""
    key = uniq()

    async def run():
        c = _aclient()
        a = RateLimiter(redis=c)
        out = [await a.hit(key, 4, 60) for _ in range(2)]
        await c.aclose()
        return out

    first = asyncio.run(run())
    b = RateLimiter(sync_redis=_sync_client())
    second = [b.hit_sync(key, 4, 60) for _ in range(4)]
    assert first == [True, True] and second == [True, True, False, False]


def test_unreachable_redis_never_raises_and_still_limits_locally():
    """Kapalı port: hit/hit_sync istisna atmaz, sınır atlanmaz (süreç içi sayaç), durum `degraded` olarak izlenir."""
    dead = "redis://127.0.0.1:1/0"

    async def run():
        c = _aclient(dead)
        rl = RateLimiter(redis=c)
        out = [await rl.hit("k", 3, 60) for _ in range(5)]
        await c.aclose()
        return out, rl.degraded, rl.redis_errors

    out, degraded, errs = asyncio.run(run())
    assert out == [True, True, True, False, False]
    assert degraded is True and errs >= 1
    sl = RateLimiter(sync_redis=_sync_client(0.3, dead))
    out2 = [sl.hit_sync("k", 3, 60) for _ in range(5)]
    assert out2 == [True, True, True, False, False]
    assert sl.degraded is True and sl.redis_errors >= 1


# ----------------------------------------------------------------------------------------------------------------------
# 3) Gerçek Redis kesintisi (konteyner durdurulur) ve toparlanma
# ----------------------------------------------------------------------------------------------------------------------
@contextlib.contextmanager
def redis_outage():
    """Test Redis konteynerini durdurur; çıkışta MUTLAKA yeniden başlatır ve hazır olmasını bekler."""
    _skip_if_no_docker_control()
    _docker("stop", CONTAINER)
    try:
        yield
    finally:
        _docker("start", CONTAINER, check=False)
        _wait_redis_up()


def test_limiter_degrades_during_real_outage_and_recovers_shared_counting(rds):
    k_out, k_after = uniq(), uniq()

    async def run():
        c = _aclient()
        rl = RateLimiter(redis=c)
        before = [await rl.hit(k_out, 3, 60) for _ in range(2)]
        await asyncio.to_thread(_docker, "stop", CONTAINER)
        try:
            during = [await rl.hit(k_out, 3, 60) for _ in range(5)]
            state_during = (rl.degraded, rl.redis_errors)
        finally:
            await asyncio.to_thread(_docker, "start", CONTAINER, check=False)
            await asyncio.to_thread(_wait_redis_up)
        recovered = False
        for _ in range(20):  # eski bağlantının bir kez hata vermesi normal; sonra yeniden bağlanmalı
            await rl.hit(uniq(), 100, 60)
            if not rl.degraded:
                recovered = True
                break
            await asyncio.sleep(0.5)
        after = [await rl.hit(k_after, 3, 60) for _ in range(5)]
        await c.aclose()
        return before, during, state_during, recovered, after

    _skip_if_no_docker_control()
    before, during, state_during, recovered, after = asyncio.run(run())
    assert before == [True, True]
    assert during == [True, True, True, False, False], "kesintide istek düşmemeli ve sınır atlanmamalı (süreç içi sayaç)"
    assert state_during[0] is True and state_during[1] >= 1
    assert recovered, "Redis dönünce aynı istemci yeniden bağlanıp paylaşımlı sayaca dönmeli"
    assert after == [True, True, True, False, False]
    assert rds.get(f"dc:rl:{k_after}") == "5", "toparlanınca sayaç yeniden Redis'te tutulmalı"


# ----------------------------------------------------------------------------------------------------------------------
# 4) Gerçek işletim sistemi süreçleri: paylaşım ve webhook tekilleştirme
# ----------------------------------------------------------------------------------------------------------------------
_RL_WORKER = r"""
import asyncio, json, sys
sys.path.insert(0, sys.argv[1])
from app.security import RateLimiter
url, key, mode, n, limit = sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6])
allowed = 0
if mode == "sync":
    import redis
    rl = RateLimiter(sync_redis=redis.Redis.from_url(url, decode_responses=True, socket_timeout=2, socket_connect_timeout=2))
    for _ in range(n):
        allowed += bool(rl.hit_sync(key, limit, 60))
else:
    import redis.asyncio as aioredis
    async def go():
        global allowed
        c = aioredis.from_url(url, decode_responses=True)
        rl = RateLimiter(redis=c)
        for _ in range(n):
            allowed += bool(await rl.hit(key, limit, 60))
        await c.aclose()
    asyncio.run(go())
print(json.dumps({"allowed": allowed}))
"""

_DEDUP_WORKER = r"""
import asyncio, json, sys
sys.path.insert(0, sys.argv[1])
import redis.asyncio as aioredis
from app import main
async def go():
    r = aioredis.from_url(sys.argv[2], decode_responses=True)
    main.state["redis"] = r
    out = [await main._is_dup_webhook_msg(m) for m in sys.argv[3:]]
    await r.aclose()
    return out
print(json.dumps(asyncio.run(go())))
"""


def _import_env() -> dict[str, str]:
    """`app.main` içe aktarmak için gereken en az ortam (veritabanına bağlanmaz)."""
    env = {k: v for k, v in os.environ.items() if k in _KEEP}
    env.update({
        "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1", "DC_ENV": "local", "DC_ALLOW_HTTP_LOCAL": "1",
        "DATABASE_URL": "postgresql://x:x@127.0.0.1:1/x", "ADMIN_TOKEN": uuid.uuid4().hex + uuid.uuid4().hex,
        "PHONE_HMAC_KEY": uuid.uuid4().hex + uuid.uuid4().hex, "DATA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "OWNER_EMAIL": "x@klinik.example", "OWNER_PASSWORD": uuid.uuid4().hex + "aZ7q", "PUBLIC_URL": "http://127.0.0.1:0",
    })
    return env


def _run_workers(script: str, arg_lists: list[list[str]], env: dict[str, str] | None = None) -> list:
    """Her argüman listesi için ayrı bir GERÇEK işletim sistemi süreci başlatır; hepsi aynı anda çalışır."""
    procs = [subprocess.Popen([sys.executable, "-X", "utf8", "-c", script, *a], env=env, stdout=subprocess.PIPE,  # noqa: S603
                              stderr=subprocess.PIPE, text=True, encoding="utf-8") for a in arg_lists]
    outs = []
    for p in procs:
        out, err = p.communicate(timeout=180)
        assert p.returncode == 0, f"işçi süreç başarısız (kod {p.returncode}):\n{err[-1200:]}"
        outs.append(json.loads(out.strip().splitlines()[-1]))
    return outs


@pytest.mark.parametrize("mode", ["async", "sync"])
def test_four_real_processes_share_one_limit(rds, mode):
    key = uniq()
    outs = _run_workers(_RL_WORKER, [[API_DIR, REDIS_URL, key, mode, "25", "20"] for _ in range(4)])
    assert sum(o["allowed"] for o in outs) == 20, outs
    assert rds.get(f"dc:rl:{key}") == "100"
    assert 0 < rds.ttl(f"dc:rl:{key}") <= 60


def test_webhook_dedup_has_exactly_one_winner_across_real_processes(rds):
    ids = [f"{PREFIX}{uuid.uuid4().hex[:10]}-{i}" for i in range(5)]
    outs = _run_workers(_DEDUP_WORKER, [[API_DIR, REDIS_URL, *ids] for _ in range(4)], env=_import_env())
    for i, mid in enumerate(ids):
        firsts = [o[i] for o in outs].count(False)  # False: "tekrar değil" = ilk gören
        assert firsts == 1, f"{mid}: tam bir süreç ilk görmeli, {firsts} süreç ilk gördü: {outs}"
        ttl = rds.ttl(f"dc:seen:{mid}")
        assert 86000 < ttl <= 86400, ttl


# ----------------------------------------------------------------------------------------------------------------------
# 5) Tam yığın: aynı PostgreSQL + aynı Redis üzerinde İKİ gerçek uygulama süreci (= iki worker)
# ----------------------------------------------------------------------------------------------------------------------
@contextlib.contextmanager
def two_workers(extra_env: dict[str, str]):
    """Gerçek uygulama + aynı ortamla ikinci bir uygulama süreci (aynı DB, aynı anahtarlar, aynı Redis)."""
    with pg_app(extra_env) as a:
        base2 = f"http://127.0.0.1:{free_port()}"
        p2 = _spawn(base2, a.env)
        try:
            _wait_ready(base2, p2)
            yield a, base2
        finally:
            with contextlib.suppress(Exception):
                p2.kill()
                p2.wait(timeout=15)
            with contextlib.suppress(Exception):
                if p2.stdout:
                    p2.stdout.close()


def _bad_login(base: str, email: str) -> int:
    return httpx.post(base + "/auth/login", json={"email": email, "password": "yanlis-parola-123"}, timeout=30).status_code


def _ready_redis(base: str) -> str:
    return httpx.get(base + "/ready", timeout=15).json()["redis"]  # /ready hazır değilse 503 döner; alan yine de okunur


def test_login_limit_is_shared_by_two_real_worker_processes(rds):
    email = f"{uniq()}@nobody.example"
    rds.delete("dc:rl:ip:127.0.0.1")
    with two_workers({"REDIS_URL": REDIS_URL}) as (a, base2):
        assert _ready_redis(a.base) == "ok" and _ready_redis(base2) == "ok"
        codes = [_bad_login(a.base, email) for _ in range(10)] + [_bad_login(base2, email) for _ in range(10)]
    assert codes[:15] == [401] * 15, codes
    assert codes[15:] == [429] * 5, f"16. istekten itibaren (hangi worker'a gittiğine bakılmaksızın) 429 beklenir: {codes}"
    assert rds.get(f"dc:rl:em:{email}") == "20"


def test_control_without_redis_each_worker_keeps_its_own_counter():
    """KONTROL: Redis yokken aynı akış 429 üretmez (10+10, işçi başına 15 sınırının altında). Yukarıdaki testin ayırt edici olduğunu gösterir."""
    email = f"{uniq()}@nobody.example"
    with two_workers({}) as (a, base2):
        assert _ready_redis(a.base) == "not_configured" and _ready_redis(base2) == "not_configured"
        codes = [_bad_login(a.base, email) for _ in range(10)] + [_bad_login(base2, email) for _ in range(10)]
    assert codes == [401] * 20, codes


def test_public_endpoint_limit_is_shared_by_two_real_worker_processes(rds):
    """/c/{code}: `hit_sync` kullanan herkese açık uç nokta (20/dk/IP). İki worker'a 15'er istek = toplam 30."""
    rds.delete("dc:rl:camp_click:127.0.0.1")
    code = uniq()
    with two_workers({"REDIS_URL": REDIS_URL}) as (a, base2):
        codes = [httpx.get(f"{a.base}/c/{code}", timeout=30, follow_redirects=False).status_code for _ in range(15)]
        codes += [httpx.get(f"{base2}/c/{code}", timeout=30, follow_redirects=False).status_code for _ in range(15)]
    assert codes[:20] == [404] * 20, codes
    assert codes[20:] == [429] * 10, f"limit worker'lar arasında paylaşılmalı: {codes}"


def test_app_survives_real_redis_outage_and_recovers(rds):
    """Uygulama düzeyinde: Redis düşünce istek 500 olmaz, giriş sınırı atlanmaz (süreç içi), /ready 'down' der; Redis dönünce 'ok'."""
    rds.delete("dc:rl:ip:127.0.0.1")
    _skip_if_no_docker_control()
    e_out, e_after = f"{uniq()}@nobody.example", f"{uniq()}@nobody.example"
    with pg_app({"REDIS_URL": REDIS_URL}) as a:
        assert _ready_redis(a.base) == "ok"
        assert _bad_login(a.base, f"{uniq()}@nobody.example") == 401
        with redis_outage():
            assert _ready_redis(a.base) == "down"
            during = [_bad_login(a.base, e_out) for _ in range(16)]
        status = "down"
        for _ in range(40):
            status = _ready_redis(a.base)
            if status == "ok":
                break
            time.sleep(0.5)
        after = [_bad_login(a.base, e_after) for _ in range(3)]
    assert during == [401] * 15 + [429], f"kesintide 500 olmamalı ve süreç içi sınır uygulanmalı: {during}"
    assert status == "ok", "Redis dönünce /ready yeniden 'ok' demeli"
    assert after == [401] * 3
