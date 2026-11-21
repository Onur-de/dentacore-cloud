"""Hasta dosyaları kalıcı depolama testleri (Adım 4): api/app/media.py + panel.py dosya uç noktaları.

Üç katman:
  1) Birim: LocalStore / S3Store, Fernet şifreleme, SHA-256 bütünlüğü, imzalı bağlantı, yükleme doğrulaması, taşıma.
  2) Gerçek HTTP + gerçek PostgreSQL (tests/pg_app_harness.py): yükle -> süreci yeniden başlat -> indir, çapraz klinik
     erişim engeli, silmede DB + depo temizliği, bozulmuş/eksik nesne, imzalı bağlantı akışı.
  3) S3 uyumlu depo (docker `dentacore-s3-test`: motoserver/moto, 127.0.0.1:55000): aynı yaşam döngüsü nesne deposunda.

Ön koşul: test PG (55432) ve S3 uyumlu sunucu (DC_S3_TEST_ENDPOINT, varsayılan http://127.0.0.1:55000).
Erişilemezse testler ATLANIR; DC_REQUIRE_PG=1 ise atlanmaz, BAŞARISIZ olur.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import pathlib
import secrets
import sys
import time

import httpx
import pytest
from cryptography.fernet import Fernet

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from app import media  # noqa: E402
from pg_app_harness import REQUIRE_PG, make_jpeg, pg_app  # noqa: E402

S3_ENDPOINT = os.environ.get("DC_S3_TEST_ENDPOINT", "http://127.0.0.1:55000")
S3_KEY, S3_SECRET = "dctest-access", "dctest-secret-0123456789"


def _s3_unavailable(reason: str):
    if REQUIRE_PG:
        pytest.fail(f"DC_REQUIRE_PG=1 ama S3 uyumlu test sunucusu yok: {reason}", pytrace=False)
    pytest.skip(f"S3 uyumlu test sunucusu erişilemiyor: {reason}")


def _raw_s3():
    import botocore.session
    from botocore.config import Config
    return botocore.session.get_session().create_client(
        "s3", region_name="us-east-1", endpoint_url=S3_ENDPOINT, aws_access_key_id=S3_KEY,
        aws_secret_access_key=S3_SECRET, config=Config(s3={"addressing_style": "path"}, connect_timeout=3, read_timeout=10,
                                                      retries={"max_attempts": 1}))


@pytest.fixture(scope="module")
def s3_bucket():
    c = _raw_s3()
    name = "dc-test-" + secrets.token_hex(6)
    try:
        c.create_bucket(Bucket=name)
    except Exception as ex:  # noqa: BLE001
        _s3_unavailable(f"{type(ex).__name__}")
    yield name
    try:
        for o in c.list_objects_v2(Bucket=name).get("Contents", []):
            c.delete_object(Bucket=name, Key=o["Key"])
        c.delete_bucket(Bucket=name)
    except Exception:  # noqa: BLE001, S110
        pass


def _s3_env(bucket: str, prefix: str = "pm") -> dict[str, str]:
    return {"MEDIA_BACKEND": "s3", "S3_BUCKET": bucket, "S3_ENDPOINT_URL": S3_ENDPOINT, "S3_REGION": "us-east-1",
            "S3_ACCESS_KEY_ID": S3_KEY, "S3_SECRET_ACCESS_KEY": S3_SECRET, "S3_PREFIX": prefix}


@pytest.fixture(autouse=True)
def _fresh_store_cache():
    media.reset_store_cache()
    yield
    media.reset_store_cache()


@pytest.fixture
def fern(monkeypatch):
    f = Fernet(Fernet.generate_key())
    monkeypatch.setattr("app.core.fernet", lambda: f)
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", Fernet.generate_key().decode())
    return f


@pytest.fixture
def local_env(monkeypatch, tmp_path):
    monkeypatch.setenv("MEDIA_BACKEND", "local")
    monkeypatch.setenv("IMAGE_DIR", str(tmp_path / "images"))
    return tmp_path / "images"


# ====================================================================================== 1) BİRİM
class TestLocalStore:
    def test_roundtrip_overwrite_and_delete(self, tmp_path):
        st = media.LocalStore(tmp_path)
        st.put("c1/p2/a.enc", b"bir")
        st.put("c1/p2/a.enc", b"iki")
        assert st.get("c1/p2/a.enc") == b"iki" and st.exists("c1/p2/a.enc")
        assert not list(tmp_path.rglob("*.tmp")), "atomik yazımdan artık geçici dosya kalmamalı"
        assert st.delete("c1/p2/a.enc") is True
        assert st.delete("c1/p2/a.enc") is False, "ikinci silme güvenli (False)"
        with pytest.raises(media.MediaNotFound):
            st.get("c1/p2/a.enc")

    @pytest.mark.parametrize("key", ["../disari.enc", "/mutlak.enc", "c1/../../x", "a\\b.enc", "c1//x.enc", "", ".", "c1/./x",
                                     "a b.enc", "x" * 300, "c1/x.enc/", "c:/windows/x"])
    def test_rejects_unsafe_keys(self, tmp_path, key):
        st = media.LocalStore(tmp_path)
        with pytest.raises(media.MediaError):
            st.put(key, b"x")
        with pytest.raises(media.MediaError):
            st.get(key)
        with pytest.raises(media.MediaError):
            st.delete(key)
        assert not any(p for p in tmp_path.parent.glob("disari.enc"))


def test_get_store_configuration_errors(monkeypatch):
    monkeypatch.setenv("MEDIA_BACKEND", "ftp")
    with pytest.raises(media.MediaStorageError):
        media.get_store()
    monkeypatch.setenv("MEDIA_BACKEND", "s3")
    for k in ("S3_BUCKET", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY"):
        monkeypatch.delenv(k, raising=False)
    with pytest.raises(media.MediaStorageError, match="zorunlu"):
        media.get_store()


def test_encrypted_roundtrip_hides_plaintext_and_verifies_sha256(fern, local_env):
    data = make_jpeg(size=640)
    sha = hashlib.sha256(data).hexdigest()
    key = media.save_encrypted(3, 9, data)
    assert key.startswith("c3/p9/") and key.endswith(".enc")
    on_disk = (local_env / key).read_bytes()
    assert data[:200] not in on_disk and on_disk != data, "diskteki nesne düz veri olmamalı"
    assert media.load_decrypted(key, sha) == data
    assert media.load_decrypted(key) == data
    with pytest.raises(media.MediaIntegrityError):
        media.load_decrypted(key, hashlib.sha256(b"baska").hexdigest())


def test_tampered_object_and_wrong_key_are_integrity_errors(fern, local_env, monkeypatch):
    data = b"hasta-verisi" * 500
    key = media.save_encrypted(1, 1, data)
    p = local_env / key
    blob = bytearray(p.read_bytes())
    blob[len(blob) // 2] ^= 0x01
    p.write_bytes(bytes(blob))
    with pytest.raises(media.MediaIntegrityError):
        media.load_decrypted(key)
    key2 = media.save_encrypted(1, 1, data)
    other = Fernet(Fernet.generate_key())
    monkeypatch.setattr("app.core.fernet", lambda: other)
    with pytest.raises(media.MediaIntegrityError):
        media.load_decrypted(key2)


class TestSignedLink:
    def test_roundtrip_and_claims(self, fern):
        tok, exp = media.sign_link(7, 2, 5, ttl=120)
        c = media.verify_link(tok)
        assert (c["media_id"], c["clinic_id"], c["user_id"], c["exp"]) == (7, 2, 5, exp)

    def test_any_tampering_is_rejected(self, fern):
        tok, _ = media.sign_link(7, 2, 5)
        mid, cid, uid, exp, sig = tok.split(".")
        for bad in (f"8.{cid}.{uid}.{exp}.{sig}", f"{mid}.3.{uid}.{exp}.{sig}", f"{mid}.{cid}.6.{exp}.{sig}",
                    f"{mid}.{cid}.{uid}.{int(exp) + 999}.{sig}", f"{mid}.{cid}.{uid}.{exp}.{sig[:-2]}AA"):
            with pytest.raises(media.MediaLinkError) as ei:
                media.verify_link(bad)
            assert ei.value.reason == "signature"
        for junk in ("", "abc", "1.2.3", "1.2.3.4.5.6", "a.b.c.d.e", "x" * 400):
            with pytest.raises(media.MediaLinkError):
                media.verify_link(junk)

    def test_expiry_and_ttl_clamp(self, fern):
        now = 1_000_000.0
        tok, exp = media.sign_link(1, 1, 1, ttl=60, now=now)
        assert exp == int(now) + 60
        assert media.verify_link(tok, now=now + 60)["media_id"] == 1
        with pytest.raises(media.MediaLinkError) as ei:
            media.verify_link(tok, now=now + 61)
        assert ei.value.reason == "expired"
        assert media.sign_link(1, 1, 1, ttl=1, now=now)[1] == int(now) + media.LINK_MIN_TTL
        assert media.sign_link(1, 1, 1, ttl=10**9, now=now)[1] == int(now) + media.LINK_MAX_TTL

    def test_link_from_another_key_is_invalid(self, fern, monkeypatch):
        tok, _ = media.sign_link(1, 1, 1)
        monkeypatch.setenv("DATA_ENCRYPTION_KEY", Fernet.generate_key().decode())
        with pytest.raises(media.MediaLinkError):
            media.verify_link(tok)


class TestUploadValidation:
    @pytest.mark.parametrize("data,name", [
        (b"MZ\x90\x00" + b"\x00" * 600, "foto.jpg"),                                  # PE, jpg gibi giyinmiş
        (b"\x7fELF" + b"\x00" * 600, "foto.png"),                                      # ELF
        (b"<!DOCTYPE html><script>alert(1)</script>", "foto.jpg"),                     # HTML
        (b"<svg xmlns='http://www.w3.org/2000/svg'><script>1</script></svg>", "x.png"),
        (b"#!/bin/sh\nrm -rf /", "x.jpg"),
        (make_jpeg(size=620), "evil.php.jpg"),                                         # çift uzantı
        (make_jpeg(size=620), "x.exe"),
        (make_jpeg(size=620), "x.svg"),
        (make_jpeg(size=620), "x.txt"),                                                # izinli olmayan uzantı
        (b"%PDF-1.4\n1 0 obj<</S/JavaScript/JS(app.alert(1))>>endobj\n%%EOF", "x.pdf"),
        (b"%PDF-1.4\n1 0 obj<</OpenAction 2 0 R>>endobj\n%%EOF", "x.pdf"),
        (b"yalnizca duz metin, hicbir imza yok", "x.jpg"),
        (b"", "x.jpg"),
    ], ids=["pe-jpg", "elf-png", "html-jpg", "svg-png", "shebang-jpg", "cift-uzanti", "exe", "svg", "txt",
            "pdf-javascript", "pdf-openaction", "duz-metin", "bos"])
    def test_dangerous_or_fake_files_are_rejected(self, data, name):
        with pytest.raises(ValueError):
            media.assess_media_file(data, filename=name)

    def test_truncated_image_with_valid_magic_is_rejected(self):
        with pytest.raises((ValueError, OSError)):
            media.assess_media_file(b"\xff\xd8\xff\xe0" + b"bozuk" * 50, filename="x.jpg")

    def test_oversize_is_rejected(self):
        with pytest.raises(ValueError, match="çok büyük"):
            media.assess_media_file(b"\xff\xd8\xff" + b"\x00" * (media.MAX_UPLOAD_BYTES + 1), filename="x.jpg")

    def test_genuine_files_pass_with_detected_mime(self):
        jpg = media.assess_media_file(make_jpeg(size=640), filename="a.jpg")
        assert jpg["mime_type"] == "image/jpeg" and jpg["sha256"]
        assert media.assess_media_file(b"%PDF-1.4\n%%EOF", filename="a.pdf")["mime_type"] == "application/pdf"
        dcm = media.assess_media_file(b"\x00" * 128 + b"DICM" + b"\x00" * 64, filename="a.dcm")
        assert dcm["is_dicom"] is True


def test_persist_removes_stored_object_when_db_insert_fails(fern, local_env, monkeypatch):
    data = make_jpeg(size=640)
    qc = media.assess_media_file(data, filename="a.jpg")

    async def boom(*a, **k):
        raise RuntimeError("veritabanı kapalı")

    monkeypatch.setattr("app.core.q1", boom)
    with pytest.raises(RuntimeError):
        asyncio.run(media.persist_patient_media(1, 5, data, filename="a.jpg", qc=qc))
    assert not list(local_env.rglob("*.enc")), "satır eklenemezse depoda sahipsiz şifreli dosya kalmamalı"


# ---------------------------------------------------------------- S3 uyumlu depo (birim)
class TestS3Store:
    def _store(self, bucket, prefix="pm"):
        return media.S3Store(bucket, prefix, endpoint_url=S3_ENDPOINT, region="us-east-1", access_key=S3_KEY, secret_key=S3_SECRET)

    def test_put_get_exists_delete_and_prefix_layout(self, s3_bucket):
        st = self._store(s3_bucket)
        st.put("c1/p1/x.enc", b"sifreli-icerik", hashlib.sha256(b"x").hexdigest())
        assert st.exists("c1/p1/x.enc") and st.get("c1/p1/x.enc") == b"sifreli-icerik"
        keys = [o["Key"] for o in _raw_s3().list_objects_v2(Bucket=s3_bucket, Prefix="pm/").get("Contents", [])]
        assert "pm/c1/p1/x.enc" in keys
        head = _raw_s3().head_object(Bucket=s3_bucket, Key="pm/c1/p1/x.enc")
        assert head["Metadata"].get("sha256") == hashlib.sha256(b"x").hexdigest()
        assert st.delete("c1/p1/x.enc") is True
        assert st.delete("c1/p1/x.enc") is False
        assert not st.exists("c1/p1/x.enc")
        with pytest.raises(media.MediaNotFound):
            st.get("c1/p1/x.enc")

    def test_unsafe_keys_rejected_before_any_request(self, s3_bucket):
        with pytest.raises(media.MediaError):
            self._store(s3_bucket).put("../x", b"1")

    def test_missing_bucket_is_storage_error(self):
        st = self._store("dc-yok-" + secrets.token_hex(5))
        with pytest.raises(media.MediaStorageError):
            st.put("c1/p1/x.enc", b"1")
        with pytest.raises(media.MediaStorageError):
            st.get("c1/p1/x.enc")

    def test_unreachable_endpoint_is_storage_error(self):
        st = media.S3Store("b", "", endpoint_url="http://127.0.0.1:9", region="us-east-1", access_key="a", secret_key="b")
        with pytest.raises(media.MediaStorageError):
            st.put("c1/p1/x.enc", b"1")

    def test_selfcheck_via_env(self, s3_bucket, monkeypatch):
        for k, v in _s3_env(s3_bucket).items():
            monkeypatch.setenv(k, v)
        assert media.selfcheck() == {"backend": "s3", "ok": True}
        assert not _raw_s3().list_objects_v2(Bucket=s3_bucket, Prefix="pm/_selfcheck").get("Contents"), "sonda nesnesi silinmiş olmalı"


# ---------------------------------------------------------------- taşıma
class TestMigration:
    def _seed(self, src, n=3):
        f = Fernet(Fernet.generate_key())
        rows, plains = [], {}
        for i in range(n):
            plain = secrets.token_bytes(2000 + i)
            key = f"c1/p{i}/{secrets.token_hex(8)}.enc"
            src.put(key, f.encrypt(plain))
            rows.append({"id": i + 1, "encrypted_path": key, "sha256_hash": hashlib.sha256(plain).hexdigest()})
            plains[key] = plain
        return f, rows, plains

    def test_local_to_local_copies_and_keeps_source_by_default(self, tmp_path, monkeypatch):
        src, dst = media.LocalStore(tmp_path / "a"), media.LocalStore(tmp_path / "b")
        f, rows, _ = self._seed(src)
        monkeypatch.setattr("app.core.fernet", lambda: f)
        rep = media.migrate_rows(src, dst, rows)
        assert rep["copied"] == 3 and rep["source_deleted"] == 0 and not rep["missing"] and not rep["corrupt"]
        for r in rows:
            assert dst.get(r["encrypted_path"]) == src.get(r["encrypted_path"])

    def test_source_deleted_only_after_verified_copy(self, tmp_path, monkeypatch):
        src, dst = media.LocalStore(tmp_path / "a"), media.LocalStore(tmp_path / "b")
        f, rows, _ = self._seed(src)
        monkeypatch.setattr("app.core.fernet", lambda: f)
        # 1. satırın kaynağını boz, 2. satırı kaynaktan kaldır: bunlara dokunulmamalı/silinmemeli
        bad = tmp_path / "a" / rows[0]["encrypted_path"]
        b = bytearray(bad.read_bytes())
        b[10] ^= 0xFF
        bad.write_bytes(bytes(b))
        src.delete(rows[1]["encrypted_path"])
        rep = media.migrate_rows(src, dst, rows, delete_source=True)
        assert rep["corrupt"] == [1] and rep["missing"] == [2] and rep["copied"] == 1 and rep["source_deleted"] == 1
        assert src.exists(rows[0]["encrypted_path"]), "doğrulanamayan kaynak asla silinmez"
        assert not dst.exists(rows[0]["encrypted_path"]), "bozuk nesne hedefe taşınmaz"
        assert not src.exists(rows[2]["encrypted_path"]) and dst.exists(rows[2]["encrypted_path"])

    def test_wrong_sha_in_db_blocks_copy(self, tmp_path, monkeypatch):
        src, dst = media.LocalStore(tmp_path / "a"), media.LocalStore(tmp_path / "b")
        f, rows, _ = self._seed(src, 1)
        monkeypatch.setattr("app.core.fernet", lambda: f)
        rows[0]["sha256_hash"] = hashlib.sha256(b"x").hexdigest()
        rep = media.migrate_rows(src, dst, rows, delete_source=True)
        assert rep["corrupt"] == [1] and src.exists(rows[0]["encrypted_path"]) and not dst.exists(rows[0]["encrypted_path"])

    def test_local_to_s3_roundtrip(self, tmp_path, s3_bucket, monkeypatch):
        src = media.LocalStore(tmp_path / "a")
        dst = media.S3Store(s3_bucket, "mig", endpoint_url=S3_ENDPOINT, region="us-east-1", access_key=S3_KEY, secret_key=S3_SECRET)
        f, rows, plains = self._seed(src)
        monkeypatch.setattr("app.core.fernet", lambda: f)
        rep = media.migrate_rows(src, dst, rows, delete_source=True)
        assert rep["copied"] == 3 and rep["source_deleted"] == 3 and not rep["errors"]
        for r in rows:
            assert f.decrypt(dst.get(r["encrypted_path"])) == plains[r["encrypted_path"]]
            assert not src.exists(r["encrypted_path"])


# ================================================================ 2) GERÇEK HTTP + PostgreSQL (yerel disk)
def _db(app, sql, *args):
    import psycopg
    with psycopg.connect(app.dsn, autocommit=True) as c:
        return c.execute(sql, args).fetchall()


def _enc_files(app):
    return [p for p in app.media_dir.rglob("*.enc")] if app.media_dir.exists() else []


@pytest.fixture(scope="module")
def app_local():
    with pg_app() as a:
        yield a


@pytest.fixture(scope="module")
def clinics(app_local):
    hq = app_local.hq()
    a = app_local.new_clinic(hq, "Klinik A")
    b = app_local.new_clinic(hq, "Klinik B")
    return a, b


def _upload_ok(app, s, pid, data=None, **kw):
    data = data or make_jpeg(size=640)
    r = app.upload(s, pid, data, **kw)
    assert r.status_code == 200, r.text[:300]
    return data, r.json()


def test_upload_restart_download_same_file_and_sha256(app_local):
    hq = app_local.hq()
    pid = app_local.new_patient(hq, "Kalıcılık Hastası")
    data, up = _upload_ok(app_local, hq, pid, filename="panoramik.jpg", category="xray", stage="before")
    mid, sha = up["id"], hashlib.sha256(data).hexdigest()
    assert up["sha256"] == sha and "encrypted_file" not in up and "encrypted_path" not in up
    files = _enc_files(app_local)
    assert len(files) >= 1 and all(data[:200] not in p.read_bytes() for p in files), "diskteki dosya şifreli olmalı"
    assert any(p.relative_to(app_local.media_dir).parts[0].startswith("c1") for p in files), "anahtar klinik/hasta dizinli olmalı"

    app_local.restart()
    hq2 = app_local.hq()
    r = hq2.get(f"/app/api/patients/{pid}/media/{mid}")
    assert r.status_code == 200
    assert r.content == data and hashlib.sha256(r.content).hexdigest() == sha
    assert r.headers["x-dentacore-sha256"] == sha and r.headers["content-type"].startswith("image/jpeg")
    assert r.headers["x-content-type-options"] == "nosniff" and "no-store" in r.headers["cache-control"]
    assert r.headers["content-disposition"].startswith("inline")


def test_list_and_patient_detail_expose_files_without_storage_key(app_local):
    hq = app_local.hq()
    pid = app_local.new_patient(hq, "Liste Hastası")
    data, up = _upload_ok(app_local, hq, pid, filename="oncesi.jpg", category="photo", stage="before")
    lst = hq.get(f"/app/api/patients/{pid}/media")
    assert lst.status_code == 200
    j = lst.json()
    assert j["before_after_summary"] == {"before_count": 1, "after_count": 0} and j["disclaimer"]
    f = j["files"][0]
    assert f["id"] == up["id"] and f["filename"] == "oncesi.jpg" and f["size_bytes"] == len(data)
    assert f["sha256"] == hashlib.sha256(data).hexdigest() and f["stage"] == "before"
    det = hq.get(f"/app/api/patients/{pid}").json()
    assert det["media_files"] and det["media_files"][0]["filename"] == "oncesi.jpg"
    for blob in (lst.text, hq.get(f"/app/api/patients/{pid}").text):
        assert "encrypted_path" not in blob and "encrypted_file" not in blob and ".enc" not in blob


def test_other_clinic_cannot_read_list_link_or_delete(app_local, clinics):
    a, b = clinics
    pid_a = app_local.new_patient(a, "A Hastası")
    data, up = _upload_ok(app_local, a, pid_a, filename="gizli.jpg")
    mid = up["id"]
    assert a.get(f"/app/api/patients/{pid_a}/media/{mid}").content == data
    # Klinik B: aynı kimlikleri doğrudan dener
    for r in (b.get(f"/app/api/patients/{pid_a}/media/{mid}"),
              b.get(f"/app/api/patients/{pid_a}/media"),
              b.post(f"/app/api/patients/{pid_a}/media/{mid}/link"),
              b.delete(f"/app/api/patients/{pid_a}/media/{mid}"),
              b.get(f"/app/api/patients/{pid_a}")):
        assert r.status_code in (403, 404), (r.status_code, r.text[:120])
    up_b = app_local.upload(b, pid_a, make_jpeg(size=640))
    assert up_b.status_code in (403, 404), "B, A'nın hastasına dosya yükleyememeli"
    # B kendi hastasının kimliğiyle A'nın dosya kimliğini dener
    pid_b = app_local.new_patient(b, "B Hastası")
    for r in (b.get(f"/app/api/patients/{pid_b}/media/{mid}"), b.delete(f"/app/api/patients/{pid_b}/media/{mid}")):
        assert r.status_code == 404
    # A'nın dosyası hâlâ sağlam
    assert a.get(f"/app/api/patients/{pid_a}/media/{mid}").content == data
    assert _db(app_local, "SELECT count(*) FROM patient_media WHERE patient_id=%s", pid_a)[0][0] == 1


def test_signed_link_flow_and_cross_clinic_link_is_refused(app_local, clinics, monkeypatch):
    a, b = clinics
    pid = app_local.new_patient(a, "Link Hastası")
    data, up = _upload_ok(app_local, a, pid)
    mid = up["id"]
    lk = a.post(f"/app/api/patients/{pid}/media/{mid}/link", params={"ttl": 120})
    assert lk.status_code == 200 and lk.json()["expires_in"] == 120
    url = lk.json()["url"]
    ok = a.get(url)
    assert ok.status_code == 200 and ok.content == data
    # Klinik B imzalı linki ele geçirse bile açamaz (kullanıcı/klinik bağlı)
    assert b.get(url).status_code == 403
    # Oturumsuz
    assert httpx.get(app_local.base + url, timeout=15).status_code == 401
    # Kurcalanmış imza / alan
    tok = url.rsplit("/", 1)[1]
    m, c, u, e, s = tok.split(".")
    for bad in (f"{m}.{c}.{u}.{int(e) + 500}.{s}", f"{m}.{c}.{u}.{e}.{s[:-2]}AA", f"{int(m) + 1}.{c}.{u}.{e}.{s}", "kotu"):
        assert a.get(f"/app/api/media/dl/{bad}").status_code == 403
    # Geçerli imzalı ama süresi geçmiş (uygulamanın kendi anahtarıyla üretilir)
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", app_local.env["DATA_ENCRYPTION_KEY"])
    uid = _db(app_local, "SELECT id FROM staff_users WHERE email=%s", a.email)[0][0]
    expired, _ = media.sign_link(mid, a.clinic_id, uid, ttl=30, now=time.time() - 3600)
    assert a.get(f"/app/api/media/dl/{expired}").status_code == 410
    live, _ = media.sign_link(mid, a.clinic_id, uid, ttl=60)
    assert a.get(f"/app/api/media/dl/{live}").content == data, "kendi anahtarımızla üretilen geçerli bağlantı çalışmalı (test kendini doğrular)"
    # B'nin kimliğine ait ama A'nın dosyasını gösteren bağlantı: klinik uyuşmuyor
    uid_b = _db(app_local, "SELECT id FROM staff_users WHERE email=%s", b.email)[0][0]
    forged, _ = media.sign_link(mid, b.clinic_id, uid_b, ttl=60)
    assert b.get(f"/app/api/media/dl/{forged}").status_code == 404
    # TTL sınırları
    assert a.post(f"/app/api/patients/{pid}/media/{mid}/link", params={"ttl": 5}).status_code == 422
    assert a.post(f"/app/api/patients/{pid}/media/{mid}/link", params={"ttl": 999999}).status_code == 422


def test_delete_removes_db_row_and_stored_file(app_local, clinics):
    a, _ = clinics
    pid = app_local.new_patient(a, "Silinecek")
    d1, u1 = _upload_ok(app_local, a, pid, filename="bir.jpg")
    d2, u2 = _upload_ok(app_local, a, pid, filename="iki.jpg")
    before = len(_enc_files(app_local))
    keys = {r[0] for r in _db(app_local, "SELECT encrypted_path FROM patient_media WHERE patient_id=%s", pid)}
    assert len(keys) == 2 and all((app_local.media_dir / k).is_file() for k in keys)
    k1 = _db(app_local, "SELECT encrypted_path FROM patient_media WHERE id=%s", u1["id"])[0][0]
    r = a.delete(f"/app/api/patients/{pid}/media/{u1['id']}")
    assert r.status_code == 200 and r.json() == {"ok": True, "storage_deleted": True}
    assert _db(app_local, "SELECT count(*) FROM patient_media WHERE id=%s", u1["id"])[0][0] == 0
    assert not (app_local.media_dir / k1).exists() and len(_enc_files(app_local)) == before - 1
    assert a.get(f"/app/api/patients/{pid}/media/{u1['id']}").status_code == 404
    assert a.delete(f"/app/api/patients/{pid}/media/{u1['id']}").status_code == 404
    assert a.get(f"/app/api/patients/{pid}/media/{u2['id']}").content == d2, "diğer dosya etkilenmemeli"


def test_delete_keeps_record_when_storage_delete_fails(app_local, clinics):
    a, _ = clinics
    pid = app_local.new_patient(a, "Depo Hatası")
    _, up = _upload_ok(app_local, a, pid)
    k = _db(app_local, "SELECT encrypted_path FROM patient_media WHERE id=%s", up["id"])[0][0]
    # geçersiz bir anahtar -> depo silme hatası -> kayıt KORUNUR (sahipsiz dosya/kayıt oluşmaz)
    import psycopg
    with psycopg.connect(app_local.dsn, autocommit=True) as c:
        c.execute("UPDATE patient_media SET encrypted_path=%s WHERE id=%s", ("../../kacis.enc", up["id"]))
    r = a.delete(f"/app/api/patients/{pid}/media/{up['id']}")
    assert r.status_code == 502
    assert _db(app_local, "SELECT count(*) FROM patient_media WHERE id=%s", up["id"])[0][0] == 1
    with psycopg.connect(app_local.dsn, autocommit=True) as c:
        c.execute("UPDATE patient_media SET encrypted_path=%s WHERE id=%s", (k, up["id"]))
    assert a.delete(f"/app/api/patients/{pid}/media/{up['id']}").status_code == 200


def test_rejected_uploads_store_nothing(app_local, clinics):
    a, _ = clinics
    pid = app_local.new_patient(a, "Reddedilen")
    files_before = len(_enc_files(app_local))
    rows_before = _db(app_local, "SELECT count(*) FROM patient_media WHERE patient_id=%s", pid)[0][0]
    exe = b"MZ\x90\x00" + secrets.token_bytes(4000)
    cases = [
        (exe, "foto.jpg", 400), (exe, "zararli.exe", 400),
        (b"<html><script>alert(1)</script></html>", "x.jpg", 400),
        (make_jpeg(size=620), "evil.php.jpg", 400),
        (b"%PDF-1.4\n1 0 obj<</S/JavaScript/JS(1)>>endobj", "x.pdf", 400),
        (b"", "bos.jpg", 400),
    ]
    for data, name, want in cases:
        r = app_local.upload(a, pid, data, filename=name)
        assert r.status_code == want, (name, r.status_code, r.text[:150])
    big = a.post(f"/app/api/patients/{pid}/media", params={"filename": "dev.jpg"}, content=b"\xff\xd8\xff" + secrets.token_bytes(media.MAX_UPLOAD_BYTES))
    assert big.status_code == 413
    def chunks():
        for _ in range(17):
            yield b"\xff" * (1024 * 1024)
    streamed = a.post(f"/app/api/patients/{pid}/media", params={"filename": "akis.jpg"}, content=chunks())
    assert streamed.status_code == 413, "Content-Length olmadan (chunked) gelen büyük gövde de kesilmeli"
    anon = httpx.post(app_local.base + f"/app/api/patients/{pid}/media", params={"filename": "a.jpg"}, content=make_jpeg(size=620), timeout=30)
    assert anon.status_code in (401, 403)
    assert len(_enc_files(app_local)) == files_before
    assert _db(app_local, "SELECT count(*) FROM patient_media WHERE patient_id=%s", pid)[0][0] == rows_before


def test_pdf_and_dicom_are_attachments_with_integrity_ok(app_local, clinics):
    a, _ = clinics
    pid = app_local.new_patient(a, "Belgeler")
    pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF"
    dcm = b"\x00" * 128 + b"DICM" + secrets.token_bytes(500)
    _, up_pdf = _upload_ok(app_local, a, pid, pdf, filename="rapor.pdf", category="document")
    _, up_dcm = _upload_ok(app_local, a, pid, dcm, filename="kesit.dcm", category="xray")
    r1 = a.get(f"/app/api/patients/{pid}/media/{up_pdf['id']}")
    r2 = a.get(f"/app/api/patients/{pid}/media/{up_dcm['id']}")
    assert r1.content == pdf and r1.headers["content-disposition"].startswith("attachment")
    assert r2.content == dcm and r2.headers["content-disposition"].startswith("attachment")
    assert r2.headers["content-type"].startswith("application/dicom")


def test_tampered_or_missing_stored_file_is_reported_not_served(app_local, clinics):
    a, _ = clinics
    pid = app_local.new_patient(a, "Bozulan")
    data, up = _upload_ok(app_local, a, pid)
    k = _db(app_local, "SELECT encrypted_path FROM patient_media WHERE id=%s", up["id"])[0][0]
    p = app_local.media_dir / k
    original = p.read_bytes()
    b = bytearray(original)
    b[len(b) // 2] ^= 0x01
    p.write_bytes(bytes(b))
    r = a.get(f"/app/api/patients/{pid}/media/{up['id']}")
    assert r.status_code == 500 and data[:100] not in r.content and "bütünlük" in r.text
    assert _db(app_local, "SELECT count(*) FROM audit_log WHERE action='patient.media_integrity_fail' AND target=%s",
               f"patient:{pid}:media:{up['id']}")[0][0] == 1
    p.unlink()
    assert a.get(f"/app/api/patients/{pid}/media/{up['id']}").status_code == 404
    p.write_bytes(original)
    assert a.get(f"/app/api/patients/{pid}/media/{up['id']}").content == data


def test_uploads_and_downloads_are_audited(app_local, clinics):
    a, _ = clinics
    pid = app_local.new_patient(a, "Denetim")
    _, up = _upload_ok(app_local, a, pid)
    a.get(f"/app/api/patients/{pid}/media/{up['id']}")
    a.delete(f"/app/api/patients/{pid}/media/{up['id']}")
    acts = {r[0] for r in _db(app_local, "SELECT action FROM audit_log WHERE target=%s", f"patient:{pid}:media:{up['id']}")}
    assert {"patient.media_upload", "patient.media_download", "patient.media_delete"} <= acts


# ================================================================ 3) GERÇEK HTTP + PostgreSQL + S3 uyumlu depo
@pytest.fixture(scope="module")
def app_s3(s3_bucket):
    with pg_app(_s3_env(s3_bucket, "pm")) as a:
        yield a


def _objs(bucket, prefix="pm/"):
    return [o["Key"] for o in _raw_s3().list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])]


def test_s3_lifecycle_upload_restart_download_delete(app_s3, s3_bucket):
    hq = app_s3.hq()
    pid = app_s3.new_patient(hq, "S3 Hastası")
    data, up = _upload_ok(app_s3, hq, pid, filename="s3.jpg", category="xray")
    mid, sha = up["id"], hashlib.sha256(data).hexdigest()
    key = _db(app_s3, "SELECT encrypted_path FROM patient_media WHERE id=%s", mid)[0][0]
    assert f"pm/{key}" in _objs(s3_bucket), "nesne bucket'ta prefix altında olmalı"
    raw = _raw_s3().get_object(Bucket=s3_bucket, Key=f"pm/{key}")["Body"].read()
    assert data[:200] not in raw and raw != data, "nesne deposu düz görüntüyü görmemeli (istemci tarafı şifreleme)"
    assert not _enc_files(app_s3), "S3 modunda yerel diske dosya yazılmamalı"

    app_s3.restart()
    hq2 = app_s3.hq()
    r = hq2.get(f"/app/api/patients/{pid}/media/{mid}")
    assert r.status_code == 200 and r.content == data and hashlib.sha256(r.content).hexdigest() == sha

    d = hq2.delete(f"/app/api/patients/{pid}/media/{mid}")
    assert d.status_code == 200 and d.json()["storage_deleted"] is True
    assert f"pm/{key}" not in _objs(s3_bucket), "silmede nesne deposundan da kalkmalı"
    assert _db(app_s3, "SELECT count(*) FROM patient_media WHERE id=%s", mid)[0][0] == 0
    assert hq2.get(f"/app/api/patients/{pid}/media/{mid}").status_code == 404


def test_s3_cross_clinic_and_signed_link(app_s3, s3_bucket):
    hq = app_s3.hq()
    a = app_s3.new_clinic(hq, "S3 Klinik A")
    b = app_s3.new_clinic(hq, "S3 Klinik B")
    pid = app_s3.new_patient(a, "S3 A Hastası")
    data, up = _upload_ok(app_s3, a, pid)
    mid = up["id"]
    assert b.get(f"/app/api/patients/{pid}/media/{mid}").status_code in (403, 404)
    assert b.delete(f"/app/api/patients/{pid}/media/{mid}").status_code in (403, 404)
    url = a.post(f"/app/api/patients/{pid}/media/{mid}/link").json()["url"]
    assert a.get(url).content == data
    assert b.get(url).status_code == 403
    assert len(_objs(s3_bucket)) >= 1, "B'nin başarısız silme denemesi nesneyi silmemiş olmalı"
    assert a.get(f"/app/api/patients/{pid}/media/{mid}").content == data


def test_s3_object_missing_or_corrupt_is_reported(app_s3, s3_bucket):
    hq = app_s3.hq()
    pid = app_s3.new_patient(hq, "S3 Bozuk")
    data, up = _upload_ok(app_s3, hq, pid)
    key = _db(app_s3, "SELECT encrypted_path FROM patient_media WHERE id=%s", up["id"])[0][0]
    c = _raw_s3()
    good = c.get_object(Bucket=s3_bucket, Key=f"pm/{key}")["Body"].read()
    bad = bytearray(good)
    bad[len(bad) // 2] ^= 0x01
    c.put_object(Bucket=s3_bucket, Key=f"pm/{key}", Body=bytes(bad))
    assert hq.get(f"/app/api/patients/{pid}/media/{up['id']}").status_code == 500
    c.delete_object(Bucket=s3_bucket, Key=f"pm/{key}")
    assert hq.get(f"/app/api/patients/{pid}/media/{up['id']}").status_code == 404
    # nesne yokken silme: kayıt temizlenir, storage_deleted=False
    d = hq.delete(f"/app/api/patients/{pid}/media/{up['id']}")
    assert d.status_code == 200 and d.json()["storage_deleted"] is False


def test_s3_app_refuses_to_start_when_bucket_is_missing():
    env = _s3_env("dc-yok-" + secrets.token_hex(6))
    with pytest.raises(RuntimeError, match="kapandı"):
        with pg_app(env):
            pass


def test_s3_app_refuses_to_start_without_credentials(s3_bucket):
    env = _s3_env(s3_bucket)
    env["S3_SECRET_ACCESS_KEY"] = ""
    with pytest.raises(RuntimeError, match="kapandı"):
        with pg_app(env):
            pass
