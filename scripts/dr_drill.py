#!/usr/bin/env python
"""DentaCore yedek -> boş kümeye geri yükleme tatbikatı (DR drill).

Tek kullanımlık Docker kaynakları kurar, gerçek şemaya sentetik veri basar, `backup/backup.sh` ile şifreli yedek alır,
`backup/restore.sh` ile BOŞ bir PostgreSQL kümesine geri yükler ve kaynak ile hedefi karşılaştırır.

  python scripts/dr_drill.py --patients 20000          # ölçüm koşusu (JSON çıktı)
  python scripts/dr_drill.py --patients 2000 --keep    # konteynerleri/dizini silmeden bırak

Gerçek hasta verisi KULLANILMAZ; her şey sentetiktir. Üretim imajıyla aynı ana sürüm: pgvector/pgvector:pg16.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac as hmac_mod
import io
import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

IMAGE = "dentacore-backup-drill"
PG_IMAGE = os.environ.get("DC_DRILL_PG_IMAGE", "pgvector/pgvector:pg16")
PG_USER = "dentacore"
# Yalnızca tek kullanımlık, dışarıya açılmayan test konteyneri parolası (gerçek sır değil).
PG_PASS = "drillpw_local_only"  # noqa: S105  # nosec B105


class R:
    """Alt süreç sonucu."""

    def __init__(self, rc: int, out: str, err: str):
        self.rc, self.out, self.err = rc, out, err

    def __repr__(self) -> str:
        return f"R(rc={self.rc}, out={self.out[-300:]!r}, err={self.err[-300:]!r})"


def run(args: list[str], *, input: bytes | str | None = None, check: bool = True, timeout: int = 900) -> R:
    if isinstance(input, str):
        input = input.encode("utf-8")
    # args yalnızca bu dosyadaki sabit docker/psql komutlarından ve kendi ürettiğimiz adlardan oluşur; kullanıcı girdisi yok.
    p = subprocess.run(args, input=input, capture_output=True, timeout=timeout)  # noqa: S603  # nosec B603
    r = R(p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace"))
    if check and r.rc != 0:
        raise RuntimeError(f"komut basarisiz ({' '.join(args[:4])}...): {r}")
    return r


def docker_available() -> bool:
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=30).returncode == 0  # noqa: S603, S607  # nosec B603 B607
    except (OSError, subprocess.TimeoutExpired):
        return False


class Drill:
    def __init__(self, keep: bool = False):
        self.id = uuid.uuid4().hex[:8]
        self.keep = keep
        self.net = f"dcdrill-{self.id}"
        self.tmp = Path(tempfile.mkdtemp(prefix="dcdrill-"))
        (self.tmp / "backups").mkdir()
        (self.tmp / "keys").mkdir()
        self.containers: list[str] = []
        self.fernet_key = ""
        self.hmac_key = os.urandom(32)

    # ------------------------------------------------------------ yaşam döngüsü
    def __enter__(self) -> "Drill":
        run(["docker", "network", "create", self.net])
        return self

    def __exit__(self, *exc) -> None:
        if self.keep:
            print(f"[drill] --keep: ag={self.net} konteynerler={self.containers} dizin={self.tmp}", file=sys.stderr)
            return
        for c in self.containers:
            run(["docker", "rm", "-f", c], check=False)
        run(["docker", "network", "rm", self.net], check=False)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build_image(self) -> None:
        run(["docker", "build", "-t", IMAGE, str(ROOT / "backup")], timeout=900)

    # ------------------------------------------------------------ PostgreSQL
    def start_pg(self, role: str, with_init: bool = False, image: str | None = None) -> str:
        """Üretim kurulumunu taklit eden (with_init) ya da çıplak, boş bir PG16 kümesi başlatır."""
        name = f"dcdrill-{self.id}-{role}"
        env = ["-e", f"POSTGRES_USER={PG_USER}", "-e", f"POSTGRES_PASSWORD={PG_PASS}"]
        if with_init:
            env += ["-e", "POSTGRES_DB=dentacore"]
        run(["docker", "create", "--name", name, "--network", self.net, *env, image or PG_IMAGE])
        self.containers.append(name)
        if with_init:
            run(["docker", "cp", str(ROOT / "db" / "init.sql"), f"{name}:/docker-entrypoint-initdb.d/01-init.sql"])
        run(["docker", "start", name])
        deadline = time.time() + 120
        while time.time() < deadline:
            logs = run(["docker", "logs", name], check=False)
            ready = (logs.out + logs.err).count("database system is ready to accept connections")
            if ready >= 2 and run(["docker", "exec", name, "pg_isready", "-U", PG_USER], check=False).rc == 0:
                return name
            time.sleep(1)
        raise RuntimeError(f"{name} hazir olmadi")

    def psql(self, name: str, db: str, sql: str, *, copy_input: str | None = None) -> str:
        args = ["docker", "exec", "-i", name, "psql", "-U", PG_USER, "-d", db, "-X", "-q", "-At", "-F", "\t", "-v", "ON_ERROR_STOP=1"]
        if copy_input is not None:
            args += ["-c", sql]
            return run(args, input=copy_input).out
        return run(args + ["-f", "-"], input=sql).out

    def migrate(self, name: str) -> None:
        for f in sorted((ROOT / "api" / "app" / "migrations").glob("*.sql")):
            run(["docker", "cp", str(f), f"{name}:/tmp/{f.name}"])
            # /tmp tek kullanımlık KONTEYNERİN içindedir (ana makinenin /tmp'si değil).
            run(["docker", "exec", name, "psql", "-U", PG_USER, "-d", "dentacore", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-f", f"/tmp/{f.name}"])  # noqa: S108  # nosec B108

    # ------------------------------------------------------------ sentetik veri
    def seed(self, name: str, patients: int) -> dict:
        from cryptography.fernet import Fernet
        from app import security as sec

        self.fernet_key = Fernet.generate_key().decode()
        f = Fernet(self.fernet_key.encode())
        buf = io.StringIO()
        w = csv.writer(buf)
        for i in range(1, patients + 1):
            phone = f"+90532{i:07d}"
            w.writerow([1, hmac_mod.new(self.hmac_key, phone.encode(), hashlib.sha256).hexdigest(), f.encrypt(phone.encode()).decode(),
                        f"Hasta Çağrı Şükrü İğne {i}"])
        self.psql(name, "dentacore", "COPY patients(clinic_id, phone_hmac, phone_enc, display_name) FROM STDIN WITH (FORMAT csv)",
                  copy_input=buf.getvalue())
        # Hash zincirli denetim kaydı (gerçek security.audit_digest ile)
        n_audit = max(10, patients // 2)
        buf = io.StringIO()
        w = csv.writer(buf)
        prev = sec.GENESIS
        for i in range(1, n_audit + 1):
            ts = f"2026-11-21T10:{(i // 60) % 60:02d}:{i % 60:02d}.000000+00:00"
            actor, action, target = "seed", f"seed.{i % 7}", f"obj:{i}"
            meta = json.dumps({"i": i, "not": "ğüşiöç"}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            h = sec.audit_digest(prev, ts, actor, action, target, meta)
            w.writerow([1, ts, "", actor, action, target, "", meta, prev, h])
            prev = h
        self.psql(name, "dentacore", "COPY audit_log(clinic_id, ts, actor_id, actor, action, target, ip_hash, meta, prev_hash, hash) FROM STDIN WITH (FORMAT csv, FORCE_NOT_NULL (ip_hash))",
                  copy_input=buf.getvalue())
        self.psql(name, "dentacore", """
INSERT INTO consents(patient_id, kind, text_version, text_sha256, channel)
  SELECT id, 'kvkk_aydinlatma', 'v1', md5(id::text), 'web' FROM patients;
INSERT INTO consents(patient_id, kind, text_version, text_sha256, channel)
  SELECT id, 'iletisim', 'v1', md5(id::text), 'web' FROM patients;
INSERT INTO appointments(patient_id, starts_at, treatment)
  SELECT p.id, now() + ((p.id * 3 + k) || ' hours')::interval, 'Dolgu' FROM patients p, generate_series(1,3) k;
INSERT INTO message_log(patient_id, direction, layer, intent, tokens_in, tokens_out)
  SELECT p.id, CASE WHEN k % 2 = 0 THEN 'in' ELSE 'out' END, 'faq', 'randevu', 10 + k, 5 + k FROM patients p, generate_series(1,5) k;
INSERT INTO tooth_records(patient_id, tooth_fdi, status, procedure_name, amount_kurus, note)
  SELECT p.id, 11 + ((p.id + k) % 8), 'planned', 'Kanal tedavisi', 150000 + k, 'not ğüşiöç ' || k FROM patients p, generate_series(1,4) k;
ANALYZE;
""")
        return {"patients": patients, "audit_rows": n_audit}

    # ------------------------------------------------------------ yedek / geri yükleme
    def keygen(self, label: str = "key") -> tuple[str, Path]:
        out = run(["docker", "run", "--rm", IMAGE, "age-keygen"]).out
        pub = re.search(r"public key: (age1[a-z0-9]+)", out).group(1)
        path = self.tmp / "keys" / f"{label}.txt"
        path.write_text(out, encoding="ascii")
        return pub, path

    def backup(self, recipient: str, host: str, *, env: dict[str, str] | None = None, backups_dir: Path | None = None,
               extra: list[str] | None = None) -> R:
        """Tek seferlik yedek (BACKUP_ONCE=1). `extra`: docker run'a eklenecek bağımsız değişkenler (ör. ["-v", "a:/offhost"])."""
        b = backups_dir or (self.tmp / "backups")
        cmd = ["docker", "run", "--rm", "--network", self.net, "-v", f"{b}:/backups",
               "-e", f"PGHOST={host}", "-e", f"PGUSER={PG_USER}", "-e", f"PGPASSWORD={PG_PASS}",
               "-e", f"AGE_RECIPIENT={recipient}", "-e", "BACKUP_ONCE=1", *(extra or [])]
        for k, v in (env or {}).items():
            cmd += ["-e", f"{k}={v}"]
        return run([*cmd, IMAGE], check=False)

    def latest_backup(self, backups_dir: Path | None = None) -> str:
        files = sorted((backups_dir or self.tmp / "backups").glob("dentacore-*.sql.gz.age"), key=lambda p: p.stat().st_mtime)
        return files[-1].name

    def restore(self, fname: str, key: Path, host: str, *extra: str, backups_dir: Path | None = None) -> R:
        b = backups_dir or (self.tmp / "backups")
        return run(["docker", "run", "--rm", "--network", self.net, "-v", f"{b}:/backups:ro", "-v", f"{key.parent}:/keys:ro",
                    "-e", f"PGHOST={host}", "-e", f"PGUSER={PG_USER}", "-e", f"PGPASSWORD={PG_PASS}",
                    IMAGE, "/restore.sh", "--file", f"/backups/{fname}", "--identity", f"/keys/{key.name}", *extra], check=False)

    # ------------------------------------------------------------ karşılaştırma
    def fingerprint(self, name: str) -> dict:
        """public şemadaki her tablo için (satır sayısı, içerik md5) + sekans değerleri. Kaynağın durağan olması gerekir."""
        tables = self.psql(name, "dentacore", "select tablename from pg_tables where schemaname='public' order by 1").split()
        # Tablo adları tatbikatın KENDİ geçici veritabanının kataloğundan gelir; yine de açıkça doğrula (Adım 5'teki gibi).
        bad = [t for t in tables if not re.fullmatch(r"[a-z_][a-z0-9_]*", t)]
        if bad:
            raise RuntimeError(f"beklenmeyen tablo adi: {bad}")
        sql = " union all ".join(
            f"select '{t}', count(*)::text, md5(coalesce(string_agg(x::text, '|' order by x::text), '')) from public.{t} x"  # noqa: S608  # nosec B608
            for t in tables)
        fp = {}
        for line in self.psql(name, "dentacore", sql).strip().splitlines():
            t, n, h = line.split("\t")
            fp[t] = (int(n), h)
        seqs = self.psql(name, "dentacore", "select sequencename || '=' || coalesce(last_value::text,'null') from pg_sequences order by 1").split()
        return {"tables": fp, "sequences": seqs}

    def app_checks(self, name: str) -> dict:
        """Uygulama düzeyi: denetim hash zinciri sağlam mı, şifreli telefonlar çözülüyor ve HMAC'leri tutuyor mu?"""
        from cryptography.fernet import Fernet
        from app import security as sec

        rows = json.loads(self.psql(name, "dentacore", "select coalesce(json_agg(a order by id), '[]'::json) from audit_log a"))
        chain = sec.verify_chain(rows)
        pats = json.loads(self.psql(name, "dentacore", "select coalesce(json_agg(json_build_object('h',phone_hmac,'e',phone_enc,'n',display_name) order by id), '[]'::json) from patients"))
        f = Fernet(self.fernet_key.encode())
        bad = 0
        for p in pats:
            phone = f.decrypt(p["e"].encode())
            if hmac_mod.new(self.hmac_key, phone, hashlib.sha256).hexdigest() != p["h"] or "Çağrı Şükrü İğne" not in p["n"]:
                bad += 1
        return {"audit_chain": chain, "patients_checked": len(pats), "patients_bad": bad}


def run_drill(patients: int, keep: bool = False) -> dict:
    m: dict = {"patients_seeded": patients}
    with Drill(keep=keep) as d:
        d.build_image()
        src = d.start_pg("src", with_init=True)
        dst = d.start_pg("dst", with_init=False)
        d.migrate(src)
        m["seed"] = d.seed(src, patients)
        m["source_db_size"] = d.psql(src, "dentacore", "select pg_size_pretty(pg_database_size('dentacore'))").strip()
        pub, key = d.keygen()
        t = time.time()
        b = d.backup(pub, src)
        m["backup_wall_s"] = round(time.time() - t, 1)
        m["backup_rc"] = b.rc
        fname = d.latest_backup()
        m["backup_bytes"] = (d.tmp / "backups" / fname).stat().st_size
        t = time.time()
        r = d.restore(fname, key, dst)
        m["restore_wall_s"] = round(time.time() - t, 1)
        m["restore_rc"] = r.rc
        m["restore_summary"] = (r.out.strip().splitlines() or [""])[-1]
        fs, fd = d.fingerprint(src), d.fingerprint(dst)
        m["tables_compared"] = len(fs["tables"])
        m["fingerprint_equal"] = fs == fd
        m["total_rows"] = sum(n for n, _ in fs["tables"].values())
        m["app_checks"] = d.app_checks(dst)
    return m


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--patients", type=int, default=2000)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args()
    if not docker_available():
        sys.exit("docker erisilemiyor")
    print(json.dumps(run_drill(a.patients, a.keep), indent=2, ensure_ascii=False))
