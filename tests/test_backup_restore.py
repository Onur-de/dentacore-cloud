"""Adım 7: şifreli yedek + gerçek geri yükleme testleri (gerçek Docker, pgvector/pgvector:pg16, sentetik veri).

Her şey tek kullanımlık konteynerlerde döner (scripts/dr_drill.py). Canlı veritabanına ve gerçek hasta verisine dokunulmaz.
Docker yoksa testler ATLANIR; DC_REQUIRE_PG=1 ise atlanmaz, BAŞARISIZ olur.

Kapsam: normal yedek + boş hedefe geri yükleme (fingerprint + app_checks), --verify-only, yanlış anahtar, bozuk
dosya / bozuk .sha256, boş olmayan hedef (çıkış 4), off-host başarı / arıza (çıkış 3) / döngüde yeniden deneme,
uyarı kancası, geçersiz alıcı (çıkış 2), healthcheck, saklama (MIN_KEEP).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import dr_drill as dr  # noqa: E402

REQUIRE = os.environ.get("DC_REQUIRE_PG") == "1"
NO_HOST = "no-such-host.invalid"  # hedefe/kaynağa HİÇ bağlanılmaması gereken durumlar için


@pytest.fixture(scope="module")
def drill():
    if not dr.docker_available():
        msg = "docker erisilemiyor"
        if REQUIRE:
            pytest.fail(f"DC_REQUIRE_PG=1 ama {msg}", pytrace=False)
        pytest.skip(msg)
    with dr.Drill() as d:
        d.build_image()
        d.src = d.start_pg("src", with_init=True)
        d.migrate(d.src)
        d.seeded = d.seed(d.src, 60)
        d.pub, d.key = d.keygen("main")
        b = d.backup(d.pub, d.src)
        assert b.rc == 0, b
        d.fname = d.latest_backup()
        yield d


def _copy_backup(d, name: str, *, with_sha: bool = True) -> Path:
    dst = d.tmp / name
    dst.mkdir()
    shutil.copy(d.tmp / "backups" / d.fname, dst / d.fname)
    if with_sha:
        shutil.copy(d.tmp / "backups" / f"{d.fname}.sha256", dst / f"{d.fname}.sha256")
    return dst


def _flip_middle_byte(p: Path) -> None:
    data = bytearray(p.read_bytes())
    i = len(data) // 2
    data[i] ^= 0xFF
    p.write_bytes(bytes(data))


def _healthcheck(d, bdir: Path) -> int:
    return dr.run(["docker", "run", "--rm", "-v", f"{bdir}:/backups", dr.IMAGE, "/backup.sh", "--healthcheck"], check=False).rc


# ------------------------------------------------------------------ normal yol
def test_backup_is_encrypted_and_checksummed(drill):
    d = drill
    f = d.tmp / "backups" / d.fname
    raw = f.read_bytes()
    assert raw.startswith(b"age-encryption.org/v1")
    # düz metin kırıntısı YOK (şifreli; gzip sihirli baytı ve dökümün başlığı görünmemeli)
    assert b"PostgreSQL database cluster dump" not in raw
    assert "Çağrı".encode() not in raw
    assert (d.tmp / "backups" / f"{d.fname}.sha256").read_text().split()[0] == hashlib.sha256(raw).hexdigest()
    assert not list((d.tmp / "backups").glob("*.partial"))
    ok = (d.tmp / "backups" / ".last_success").read_text().split()
    assert ok[1] == d.fname and int(ok[2]) == len(raw)


def test_restore_into_empty_target_matches_source(drill):
    d = drill
    dst = d.start_pg("dst-ok")
    r = d.restore(d.fname, d.key, dst)
    assert r.rc == 0, r
    assert "RESTORE_OK" in r.out
    fs, fd = d.fingerprint(d.src), d.fingerprint(dst)
    assert fs["tables"] and fs == fd
    chk = d.app_checks(dst)
    assert chk["audit_chain"]["ok"] is True and chk["patients_bad"] == 0 and chk["patients_checked"] == 60
    # negatif kontrol: tek satır değişince parmak izi FARK etmeli (karşılaştırma gerçekten bir şey ölçüyor)
    d.psql(dst, "dentacore", "UPDATE patients SET display_name = display_name || 'x' WHERE id = (SELECT min(id) FROM patients)")
    assert d.fingerprint(dst) != fs


def test_verify_only_does_not_touch_any_target(drill):
    d = drill
    r = d.restore(d.fname, d.key, NO_HOST, "--verify-only")  # hedef YOK; bağlanmaya çalışsaydı exit 7 olurdu
    assert r.rc == 0, r
    assert "VERIFY_OK" in r.out and "tables=40" in r.out


# ------------------------------------------------------------------ reddedilmesi gerekenler
def test_wrong_age_key_is_rejected_before_touching_target(drill):
    d = drill
    _, other = d.keygen("other")
    r = d.restore(d.fname, other, NO_HOST)  # --verify-only YOK: yine de hedefe bağlanmadan exit 3
    assert r.rc == 3, r
    assert "sifre cozme" in r.err


def test_corrupt_file_with_sha_is_rejected(drill):
    d = drill
    bdir = _copy_backup(d, "bad-sha")
    _flip_middle_byte(bdir / d.fname)
    r = d.restore(d.fname, d.key, NO_HOST, "--verify-only", backups_dir=bdir)
    assert r.rc == 3 and "sha256" in r.err, r


def test_corrupt_file_without_sha_is_still_rejected_by_age_integrity(drill):
    d = drill
    bdir = _copy_backup(d, "bad-nosha", with_sha=False)
    _flip_middle_byte(bdir / d.fname)
    r = d.restore(d.fname, d.key, NO_HOST, "--verify-only", backups_dir=bdir)
    assert r.rc == 3, r
    # kesilmiş dosya
    bdir2 = _copy_backup(d, "trunc", with_sha=False)
    p = bdir2 / d.fname
    p.write_bytes(p.read_bytes()[: p.stat().st_size // 2])
    r2 = d.restore(d.fname, d.key, NO_HOST, "--verify-only", backups_dir=bdir2)
    assert r2.rc == 3, r2


def test_garbage_sha_file_is_rejected(drill):
    d = drill
    bdir = _copy_backup(d, "bad-shafile")
    (bdir / f"{d.fname}.sha256").write_text("0" * 64 + f"  {d.fname}\n")
    r = d.restore(d.fname, d.key, NO_HOST, "--verify-only", backups_dir=bdir)
    assert r.rc == 3 and "sha256" in r.err, r


def test_non_empty_target_is_refused_and_left_intact(drill):
    d = drill
    before = d.fingerprint(d.src)
    r = d.restore(d.fname, d.key, d.src)  # kaynak küme DOLU: yanlışlıkla üzerine yazma engellenmeli
    assert r.rc == 4, r
    assert "BOS DEGIL" in r.err
    assert d.fingerprint(d.src) == before


def test_restore_into_freshly_initialised_compose_target(drill):
    """Üretim 'yeni sunucu' senaryosu: compose'un postgres'i init.sql ile şemayı kurar (tablolar var, SATIR yok) -> reddedilmemeli."""
    d = drill
    dst = d.start_pg("dst-init", with_init=True)
    assert d.psql(dst, "dentacore", "select count(*) from pg_tables where schemaname='public'").strip() != "0"
    r = d.restore(d.fname, d.key, dst)
    assert r.rc == 0, r
    assert d.fingerprint(d.src) == d.fingerprint(dst)


def test_initialised_target_with_any_row_is_refused_unless_forced(drill):
    d = drill
    dst = d.start_pg("dst-init-row", with_init=True)
    d.psql(dst, "dentacore", "CREATE TABLE scratch_live(x int); INSERT INTO scratch_live VALUES (1)")
    r = d.restore(d.fname, d.key, dst)
    assert r.rc == 4 and "BOS DEGIL" in r.err, r
    assert d.psql(dst, "dentacore", "select count(*) from scratch_live").strip() == "1"  # dokunulmadı
    forced = d.restore(d.fname, d.key, dst, "--force-nonempty")  # bilinçli ezme yolu
    assert forced.rc == 0, forced
    assert d.fingerprint(d.src) == d.fingerprint(dst)
    assert "scratch_live" not in d.fingerprint(dst)["tables"]


# ------------------------------------------------------------------ off-host
def test_offhost_success_copies_file_and_checksum(drill):
    d = drill
    b, off = d.tmp / "b-off-ok", d.tmp / "off-ok"
    b.mkdir()
    off.mkdir()
    r = d.backup(d.pub, d.src, backups_dir=b, extra=["-v", f"{off}:/offhost"],
                 env={"BACKUP_OFFHOST_CMD": 'cp "$BACKUP_FILE" "$BACKUP_SHA_FILE" /offhost/'})
    assert r.rc == 0, r
    name = d.latest_backup(b)
    assert (off / name).read_bytes() == (b / name).read_bytes()
    assert (off / f"{name}.sha256").exists()
    assert not (b / ".offhost_pending").exists()
    # off-host kopya gerçekten geri yüklenebilir/doğrulanabilir
    v = d.restore(name, d.key, NO_HOST, "--verify-only", backups_dir=off)
    assert v.rc == 0 and "VERIFY_OK" in v.out, v


def test_offhost_failure_exit3_keeps_local_backup_and_alerts(drill):
    d = drill
    b = d.tmp / "b-off-fail"
    b.mkdir()
    r = d.backup(d.pub, d.src, backups_dir=b, env={
        "BACKUP_OFFHOST_CMD": "exit 1",
        "BACKUP_ALERT_CMD": 'echo "$BACKUP_ALERT_MESSAGE" > /backups/alert.out',
    })
    assert r.rc == 3, r
    name = d.latest_backup(b)  # yerel yedek HÂLÂ var
    assert (b / ".offhost_pending").read_text().strip().endswith(name)
    assert "off-host" in (b / "alert.out").read_text()
    v = d.restore(name, d.key, NO_HOST, "--verify-only", backups_dir=b)
    assert v.rc == 0, v


def test_offhost_retry_in_loop_mode_recovers(drill):
    d = drill
    b, off = d.tmp / "b-retry", d.tmp / "off-retry"
    b.mkdir()
    off.mkdir()
    name = f"dcdrill-{d.id}-loop"
    d.containers.append(name)
    cmd = ('if [ -f /backups/flag ]; then cp "$BACKUP_FILE" "$BACKUP_SHA_FILE" /offhost/; '
           'else touch /backups/flag; exit 1; fi')
    dr.run(["docker", "run", "-d", "--name", name, "--network", d.net, "-v", f"{b}:/backups", "-v", f"{off}:/offhost",
            "-e", f"PGHOST={d.src}", "-e", f"PGUSER={dr.PG_USER}", "-e", f"PGPASSWORD={dr.PG_PASS}",
            "-e", f"AGE_RECIPIENT={d.pub}", "-e", "BACKUP_LOOP_SECONDS=1", "-e", f"BACKUP_OFFHOST_CMD={cmd}", dr.IMAGE])
    try:
        deadline = time.time() + 90
        while time.time() < deadline and not (list(off.glob("dentacore-*.sql.gz.age")) and not (b / ".offhost_pending").exists()):
            time.sleep(1)
        copied = list(off.glob("dentacore-*.sql.gz.age"))
        assert copied, dr.run(["docker", "logs", name], check=False)
        assert not (b / ".offhost_pending").exists()
        assert len(list(b.glob("dentacore-*.sql.gz.age"))) == 1  # yeniden deneme YENİ yedek almaz, aynısını gönderir
    finally:
        dr.run(["docker", "rm", "-f", name], check=False)


# ------------------------------------------------------------------ uyarı / hata yolları
def test_db_failure_exit1_fires_alert_and_leaves_no_backup_file(drill):
    d = drill
    b = d.tmp / "b-dbfail"
    b.mkdir()
    r = d.backup(d.pub, NO_HOST, backups_dir=b, env={"BACKUP_ALERT_CMD": 'echo "$BACKUP_ALERT_MESSAGE" > /backups/alert.out'})
    assert r.rc == 1, r
    assert "ALINAMADI" in (b / "alert.out").read_text()
    assert (b / ".last_failure").exists() and not (b / ".last_success").exists()
    assert not list(b.glob("dentacore-*")) and not list(b.glob("*.partial"))


def test_invalid_recipient_exit2(drill):
    d = drill
    b = d.tmp / "b-badkey"
    b.mkdir()
    r = d.backup("age1bozuk", d.src, backups_dir=b)
    assert r.rc == 2, r
    assert not list(b.glob("dentacore-*"))


def test_healthcheck_tracks_last_success(drill):
    d = drill
    b = d.tmp / "b-health"
    b.mkdir()
    assert _healthcheck(d, b) == 1  # hiç başarılı yedek yok
    assert d.backup(d.pub, d.src, backups_dir=b).rc == 0
    assert _healthcheck(d, b) == 0
    (b / ".last_success").write_text("1000000000 x 1 y 1\n")  # 2001 yılı: bayat
    assert _healthcheck(d, b) == 1


def test_retention_keeps_min_keep_newest_even_when_old(drill):
    d = drill
    b = d.tmp / "b-keep"
    b.mkdir()
    old = []
    for i in range(5):
        f = b / f"dentacore-2020010{i + 1}-030000.sql.gz.age"
        f.write_bytes(b"x" * 600)
        (b / f"{f.name}.sha256").write_text("deadbeef  " + f.name + "\n")
        t = 1577836800 + i * 86400  # 2020-01-01 + i gün (hepsi KEEP_DAYS'ten çok eski)
        os.utime(f, (t, t))
        old.append(f)
    r = d.backup(d.pub, d.src, backups_dir=b, env={"BACKUP_KEEP_DAYS": "1", "BACKUP_MIN_KEEP": "3"})
    assert r.rc == 0, r
    left = sorted(p.name for p in b.glob("dentacore-*.sql.gz.age"))
    assert len(left) == 3, left  # yeni yedek + en yeni 2 eski
    assert old[4].name in left and old[3].name in left and old[0].name not in left
    assert not (b / f"{old[0].name}.sha256").exists()  # silinen yedeğin .sha256'sı da gitti
