"""KVKK dışa aktarma / anonimleştirme testleri (Adım 5): api/app/privacy.py + panel.py.

Yöntem: GERÇEK uygulama süreci + GERÇEK PostgreSQL (tests/pg_app_harness.py). Sentetik hastanın bağlı HER kayıt türüne
benzersiz "kanarya" metinler (KNRY<hex>-<tablo>-<sütun>) yazılır; şifreli sütunlara Fernet ile şifrelenmiş kanarya yazılır.
  - Dışa aktarma: kanaryaların beklenen bölümlerde görünmesi, gizli alanların (belirteç, dosya yolu) sızmaması.
  - Anonimleştirme: TÜM veritabanı (her tablo, her sütun, şifreli olanlar çözülerek) taranır; yalnız belgelenmiş korunan
    mali serbest metin sütunları kalabilir. Aynı klinikteki ve başka klinikteki hastalar etkilenmemelidir.
  - Politika kaydı: patient_id taşıyan her tablo privacy.POLICY'de sınıflandırılmış olmalıdır (şema-karşı testi).
Ön koşul: test PG (55432). Erişilemezse ATLANIR; DC_REQUIRE_PG=1 ise BAŞARISIZ olur.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import secrets
import sys
import uuid

import psycopg
import pytest
from cryptography.fernet import Fernet
from psycopg.rows import dict_row

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from pg_app_harness import make_jpeg, pg_app  # noqa: E402
from test_media_storage import S3_ENDPOINT, _raw_s3, _s3_env, _s3_unavailable  # noqa: E402,F401

from app import media, privacy  # noqa: E402

TEXT_TYPES = ("text", "character varying", "json", "jsonb", "ARRAY")


def can() -> str:
    return "KNRY" + secrets.token_hex(5)


def C(cn: str, table: str, col: str) -> str:
    return f"{cn}-{table}-{col}"


class Db:
    """Test tarafı doğrudan SQL erişimi (uygulama dışı): tohumlama ve kalıntı taraması."""

    def __init__(self, app):
        self.app = app
        self.fernet = Fernet(app.env["DATA_ENCRYPTION_KEY"].encode())
        self.conn = psycopg.connect(app.dsn, autocommit=True, row_factory=dict_row)

    def close(self):
        self.conn.close()

    def enc(self, s: str) -> str:
        return self.fernet.encrypt(s.encode()).decode()

    def ins(self, table: str, **vals) -> int:
        """Satır ekler; belirtilmeyen NOT NULL + varsayılansız sütunlara tip-uyumlu sahte değer koyar."""
        cols = self.conn.execute(
            "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=%s", (table,)).fetchall()
        row = dict(vals)
        for c in cols:
            n = c["column_name"]
            if n in row or c["is_nullable"] == "YES" or c["column_default"] is not None:
                continue
            dt = c["data_type"]
            row[n] = ("x" if dt in ("text", "character varying") else 1 if "int" in dt else 0 if dt == "numeric"
                      else False if dt == "boolean" else "now" if dt.startswith("timestamp") else None)
            if row[n] == "now":
                row[n] = None
                row[n] = self.conn.execute("SELECT now() AS n").fetchone()["n"]
        names = ", ".join(row)
        ph = ", ".join(["%s"] * len(row))
        return self.conn.execute(f"INSERT INTO {table} ({names}) VALUES ({ph}) RETURNING id", list(row.values())).fetchone()["id"]

    def one(self, sql: str, *a):
        return self.conn.execute(sql, a).fetchone()

    def all(self, sql: str, *a):
        return self.conn.execute(sql, a).fetchall()

    def tables(self) -> list[str]:
        return [r["table_name"] for r in self.all(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")]

    def scan(self, cn: str) -> set[tuple[str, str]]:
        """Tüm tablolar/sütunlar: ham ya da (Fernet ise) çözülmüş değerde kanarya geçen (tablo, sütun) kümesi."""
        found: set[tuple[str, str]] = set()
        for t in self.tables():
            for r in self.all(f"SELECT * FROM {t}"):
                for k, v in r.items():
                    if v is None:
                        continue
                    s = json.dumps(v, default=str) if not isinstance(v, str) else v
                    if cn in s:
                        found.add((t, k))
                    elif isinstance(v, str) and v.startswith("gAAAA"):
                        try:
                            if cn in self.fernet.decrypt(v.encode()).decode():
                                found.add((t, k))
                        except Exception:  # noqa: BLE001, S110
                            pass
        return found


def sender_key(app, cid: int, phone: str, channel: str = "wa") -> str:
    key = app.env["PHONE_HMAC_KEY"].encode()
    return hmac.new(key, f"inbox:{channel}:{cid}:{phone}".encode(), hashlib.sha256).hexdigest()[:32]


def seed(db: Db, app, s, pid: int, cn: str) -> dict:
    """Hastaya HER bağlı kayıt türünden en az bir satır + kanarya yazar. Dönen sözlük testlerin referans değerleridir."""
    cid = s.clinic_id
    c = lambda t, col: C(cn, t, col)  # noqa: E731
    phone = db.fernet.decrypt(db.one("SELECT phone_enc FROM patients WHERE id=%s", pid)["phone_enc"].encode()).decode()
    db.conn.execute(
        "UPDATE patients SET notes=%s, notes_enc=%s, birth_date='1990-05-17', click_id=%s, utm_source=%s, utm_medium=%s, "
        "utm_campaign=%s WHERE id=%s",
        (c("patients", "notes"), db.enc(c("patients", "notes_enc")), c("patients", "click_id"), c("patients", "utm_source"),
         c("patients", "utm_medium"), c("patients", "utm_campaign"), pid))
    ids: dict[str, int] = {}
    ids["consents"] = db.ins("consents", patient_id=pid, kind="saglik_verisi_acik_riza", text_version="v1", text_sha256="ab" * 32, channel="web")
    ids["anamnesis"] = db.ins("anamnesis", patient_id=pid, answers_enc=db.enc(json.dumps({"alerji": c("anamnesis", "answers_enc")})),
                              red_flags=[], signer_name=c("anamnesis", "signer_name"), signature_sha256="cd" * 32)
    ids["anamnesis_tokens"] = 0
    db.conn.execute("INSERT INTO anamnesis_tokens (token, patient_id, expires_at) VALUES (%s,%s, now() + interval '1 day')",
                    (c("anamnesis_tokens", "token"), pid))
    ids["appointments"] = db.ins("appointments", patient_id=pid, clinic_id=cid, treatment="Kontrol", cancel_reason=c("appointments", "cancel_reason"),
                                 satisfaction_reply=c("appointments", "satisfaction_reply"))
    ids["waitlist"] = db.ins("waitlist", patient_id=pid, treatment="Dolgu", active=True)
    ids["postop_checks"] = db.ins("postop_checks", patient_id=pid, procedure="Kanal", stage="24s")
    ids["treatment_plans"] = db.ins("treatment_plans", patient_id=pid, treatment="İmplant")
    ids["message_log"] = db.ins("message_log", clinic_id=cid, patient_id=pid, direction="in", body=db.enc(c("message_log", "body")))
    ids["alerts"] = db.ins("alerts", clinic_id=cid, patient_id=pid, kind="test", detail=c("alerts", "detail"))
    ids["tooth_records"] = db.ins("tooth_records", clinic_id=cid, patient_id=pid, tooth_fdi=11, note=c("tooth_records", "note"),
                                  discount_reason="")
    ids["charges"] = db.ins("charges", clinic_id=cid, patient_id=pid, description=c("charges", "description"), amount_kurus=250000)
    ids["payments"] = db.ins("payments", clinic_id=cid, patient_id=pid, amount_kurus=100000, method="nakit", note=c("payments", "note"))
    ids["payment_installments"] = db.ins("payment_installments", clinic_id=cid, patient_id=pid, charge_id=ids["charges"], installment_no=1,
                                         total_installments=2, title="Taksit 1", amount_kurus=125000, note=c("payment_installments", "note"))
    ids["periodontal_exams"] = db.ins("periodontal_exams", clinic_id=cid, patient_id=pid, doctor_note=c("periodontal_exams", "doctor_note"),
                                      note=c("periodontal_exams", "note"))
    ids["treatment_consents"] = db.ins(
        "treatment_consents", clinic_id=cid, patient_id=pid, token=c("treatment_consents", "token"),
        signer_name=c("treatment_consents", "signer_name"), signature_text=c("treatment_consents", "signature_text"),
        signature_svg_enc=db.enc(c("treatment_consents", "signature_svg_enc")), signed_user_agent=c("treatment_consents", "signed_user_agent"),
        status="signed")
    ids["lab_orders"] = db.ins("lab_orders", clinic_id=cid, patient_id=pid, lab_name="Lab Test", note=c("lab_orders", "note"))
    ids["implant_records"] = db.ins("implant_records", clinic_id=cid, patient_id=pid, brand="Marka", lot_number="LOT-" + cn[4:],
                                    serial_number="SER-" + cn[4:], note=c("implant_records", "note"))
    gid = db.ins("patient_groups", clinic_id=cid, name="Grup-" + cn[4:])
    ids["patient_group_members"] = db.ins("patient_group_members", clinic_id=cid, patient_id=pid, group_id=gid,
                                          reason=c("patient_group_members", "reason"))
    ids["campaign_events"] = db.ins("campaign_events", clinic_id=cid, event_type="lead", patient_id=pid, visitor_hash=c("campaign_events", "visitor_hash"),
                                    user_agent_summary=c("campaign_events", "user_agent_summary"), click_id=c("campaign_events", "click_id"))
    ids["webhook_inbox"] = db.ins("webhook_inbox", channel="wa", external_id="wamid." + cn[4:], clinic_id=cid,
                                  sender_key=sender_key(app, cid, phone), payload_enc=db.enc(c("webhook_inbox", "payload_enc")), status="pending")
    r = app.upload(s, pid, make_jpeg(seed=int(cn[4:8], 16)), filename=f"{cn}-grafi.jpg")
    assert r.status_code == 200, r.text[:300]
    ids["patient_media"] = r.json().get("id") or db.one("SELECT max(id) AS i FROM patient_media WHERE patient_id=%s", pid)["i"]
    ids["_phone"] = phone
    return ids


def files_on_disk(app) -> int:
    return sum(1 for p in app.media_dir.rglob("*") if p.is_file())


@pytest.fixture(scope="module")
def world():
    """Bir uygulama + iki klinik. A kliniğinde hedef (P1) ve komşu (P2) hasta, B kliniğinde komşu (P3)."""
    with pg_app() as app:
        db = Db(app)
        hq = app.hq()
        a = app.new_clinic(hq, "Klinik A")
        b = app.new_clinic(hq, "Klinik B")
        pids = {"p1": app.new_patient(a, "Hedef Hasta"), "p2": app.new_patient(a, "Komşu Hasta"), "p3": app.new_patient(b, "Diğer Klinik Hastası")}
        cans = {k: can() for k in pids}
        seeds = {"p1": seed(db, app, a, pids["p1"], cans["p1"]), "p2": seed(db, app, a, pids["p2"], cans["p2"]),
                 "p3": seed(db, app, b, pids["p3"], cans["p3"])}
        yield {"app": app, "db": db, "a": a, "b": b, "pids": pids, "cans": cans, "seeds": seeds}
        db.close()


# ----------------------------------------------------------------------------------------------------------------------
# 1) Politika kaydı canlı şemayla uyumlu mu
# ----------------------------------------------------------------------------------------------------------------------
EXPORT_KEY = {"patients": "patient", "consents": "consents", "anamnesis": "anamnesis", "appointments": "appointments",
              "waitlist": "waitlist", "postop_checks": "postop_checks", "tooth_records": "tooth_records",
              "charges": "charges", "payments": "payments"}
EXPORT_KEY.update({t: k for k, (t, _c, _s) in privacy.EXPORT_SECTIONS.items()})
# Dışa aktarmada bilerek yer almayanlar: tek kullanımlık belirteçler (veri içermez).
NOT_EXPORTED = {"anamnesis_tokens"}


def test_policy_classifies_every_patient_table_in_live_schema(world):
    db = world["db"]
    linked = {r["table_name"] for r in db.all(
        "SELECT DISTINCT table_name FROM information_schema.columns WHERE table_schema='public' AND column_name='patient_id'")}
    unclassified = linked - set(privacy.POLICY)
    assert not unclassified, f"patient_id taşıyan ama privacy.POLICY'de OLMAYAN tablo(lar): {sorted(unclassified)}"
    stale = set(privacy.POLICY) - linked - {"patients"}
    assert not stale, f"POLICY'de olup şemada patient_id taşımayan tablo(lar): {sorted(stale)}"
    assert set(privacy.POLICY) - NOT_EXPORTED <= set(EXPORT_KEY), "dışa aktarmada karşılığı olmayan politika tablosu"
    for t, cols in privacy.SCRUB.items():
        assert privacy.POLICY[t]["anonymize"] == "scrub", t
        have = {r["column_name"] for r in db.all("SELECT column_name FROM information_schema.columns WHERE table_name=%s", t)}
        assert set(cols) <= have, (t, set(cols) - have)
    for key, (t, cols, _s) in privacy.EXPORT_SECTIONS.items():
        db.all(f"SELECT {cols} FROM {t} LIMIT 0")  # sütun adları şemada var mı
    for t, v in privacy.POLICY.items():
        assert v["anonymize"] in ("special", "scrub", "delete", "purge", "keep") and v["why"].strip(), t


# ----------------------------------------------------------------------------------------------------------------------
# 2) Dışa aktarma
# ----------------------------------------------------------------------------------------------------------------------
EXPECT_IN_EXPORT = [("patients", "notes"), ("patients", "notes_enc"), ("anamnesis", "answers_enc"), ("anamnesis", "signer_name"),
                    ("message_log", "body"), ("alerts", "detail"), ("tooth_records", "note"), ("charges", "description"),
                    ("periodontal_exams", "doctor_note"), ("periodontal_exams", "note"), ("treatment_consents", "signer_name"),
                    ("treatment_consents", "signature_text"), ("lab_orders", "note"), ("implant_records", "note"),
                    ("payment_installments", "note"), ("patient_group_members", "reason")]


def test_export_contains_every_linked_record_type_and_never_leaks_secrets(world):
    a, p1, cn = world["a"], world["pids"]["p1"], world["cans"]["p1"]
    r = a.get(f"/app/api/patients/{p1}/export")
    assert r.status_code == 200, r.text[:300]
    data = r.json()
    dump = json.dumps(data, ensure_ascii=False)
    for table, key in EXPORT_KEY.items():
        assert key in data, f"{table}: dışa aktarmada '{key}' bölümü yok"
        if key != "patient":
            assert len(data[key]) >= 1, f"{table}: '{key}' bölümü boş (tohum satırı beklenirdi)"
    for table, col in EXPECT_IN_EXPORT:
        assert C(cn, table, col) in dump, f"dışa aktarmada eksik: {table}.{col}"
    assert any(cn in (m.get("original_filename") or "") for m in data["media_files"])
    assert data["patient"]["birth_date"] == "1990-05-17"
    # Sızmaması gerekenler: tek kullanımlık belirteçler, imza çizimi, depo yolu, ham şifreli değerler.
    assert C(cn, "treatment_consents", "token") not in dump and C(cn, "anamnesis_tokens", "token") not in dump
    assert C(cn, "treatment_consents", "signature_svg_enc") not in dump
    stored = world["db"].one("SELECT encrypted_path FROM patient_media WHERE patient_id=%s", p1)["encrypted_path"]
    assert stored not in dump and "encrypted_path" not in dump and "gAAAA" not in dump
    # Başka hastaların verisi karışmaz.
    assert world["cans"]["p2"] not in dump and world["cans"]["p3"] not in dump


def test_export_of_another_clinics_patient_is_404(world):
    assert world["b"].get(f"/app/api/patients/{world['pids']['p1']}/export").status_code == 404


# ----------------------------------------------------------------------------------------------------------------------
# 3) Anonimleştirme
# ----------------------------------------------------------------------------------------------------------------------
ALLOWED_LEFTOVER = {("charges", "description"), ("payments", "note")}  # mali kayıt serbest metni: POLICY'de gerekçeli 'keep'


def test_anonymize_of_another_clinics_patient_is_404_and_changes_nothing(world):
    db, cn2 = world["db"], world["cans"]["p2"]
    before = db.scan(cn2)
    r = world["b"].post(f"/app/api/patients/{world['pids']['p2']}/anonymize")
    assert r.status_code == 404
    assert db.scan(cn2) == before


def test_anonymize_scrubs_whole_database_but_keeps_financials_and_bystanders(world):
    app, db, a = world["app"], world["db"], world["a"]
    p1, p2, p3 = world["pids"]["p1"], world["pids"]["p2"], world["pids"]["p3"]
    cn1, cn2, cn3 = world["cans"]["p1"], world["cans"]["p2"], world["cans"]["p3"]
    s1 = world["seeds"]["p1"]

    before1, before2, before3 = db.scan(cn1), db.scan(cn2), db.scan(cn3)
    assert {t for t, _ in before1} >= {
        "patients", "anamnesis", "anamnesis_tokens", "appointments", "message_log", "alerts", "tooth_records", "charges", "payments",
        "payment_installments", "periodontal_exams", "treatment_consents", "lab_orders", "implant_records", "patient_group_members",
        "campaign_events", "webhook_inbox", "patient_media"}, "tohumlama eksik: kanarya her bağlı tabloda olmalı"
    old_hmac = db.one("SELECT phone_hmac FROM patients WHERE id=%s", p1)["phone_hmac"]
    old_token = db.one("SELECT token FROM treatment_consents WHERE patient_id=%s", p1)["token"]
    fin_before = (db.one("SELECT count(*) n, sum(amount_kurus) s FROM charges WHERE patient_id=%s", p1),
                  db.one("SELECT count(*) n, sum(amount_kurus) s FROM payments WHERE patient_id=%s", p1),
                  db.one("SELECT count(*) n, sum(amount_kurus) s FROM payment_installments WHERE patient_id=%s", p1))
    disk_before = files_on_disk(app)
    assert disk_before >= 3 and db.one("SELECT count(*) n FROM patient_media WHERE patient_id=%s", p1)["n"] == 1

    r = a.post(f"/app/api/patients/{p1}/anonymize")
    assert r.status_code == 200, r.text[:400]
    body = r.json()
    assert body["anonymized"] is True and body["financial_records_preserved"] is True and body["media_files_deleted"] == 1
    assert body["scrubbed"]["webhook_inbox"] == 1 and body["scrubbed"]["patient_group_members"] == 1

    # Tüm veritabanı: yalnız belgelenmiş mali serbest metin kalabilir.
    after1 = db.scan(cn1)
    assert after1 - ALLOWED_LEFTOVER == set(), f"anonimleştirme sonrası kalıntı: {sorted(after1 - ALLOWED_LEFTOVER)}"
    assert after1 == ALLOWED_LEFTOVER, "korunduğu belgelenen mali sütunlar beklenmedik biçimde değişti"

    pat = db.one("SELECT * FROM patients WHERE id=%s", p1)
    assert pat["display_name"] == f"Anonim Hasta #{p1}" and pat["active"] is False
    assert pat["birth_date"] == "" and pat["notes"] == "" and pat["notes_enc"] is None
    assert pat["phone_hmac"] != old_hmac and db.fernet.decrypt(pat["phone_enc"].encode()).decode() == f"anon-{p1}"
    assert db.one("SELECT count(*) n FROM consents WHERE patient_id=%s AND revoked_at IS NULL", p1)["n"] == 0
    new_token = db.one("SELECT token FROM treatment_consents WHERE patient_id=%s", p1)["token"]
    assert new_token.startswith("anon-") and new_token != old_token

    # Mali kayıtlar ve izlenebilirlik alanları korunur.
    fin_after = (db.one("SELECT count(*) n, sum(amount_kurus) s FROM charges WHERE patient_id=%s", p1),
                 db.one("SELECT count(*) n, sum(amount_kurus) s FROM payments WHERE patient_id=%s", p1),
                 db.one("SELECT count(*) n, sum(amount_kurus) s FROM payment_installments WHERE patient_id=%s", p1))
    assert fin_after == fin_before
    imp = db.one("SELECT lot_number, serial_number, note FROM implant_records WHERE patient_id=%s", p1)
    assert imp["lot_number"] == "LOT-" + cn1[4:] and imp["serial_number"] == "SER-" + cn1[4:] and imp["note"] == ""

    # Dosyalar: satır + depo nesnesi gitti; indirme 404.
    assert db.one("SELECT count(*) n FROM patient_media WHERE patient_id=%s", p1)["n"] == 0
    assert files_on_disk(app) == disk_before - 1
    assert a.get(f"/app/api/patients/{p1}/media/{s1['patient_media']}").status_code == 404

    # Webhook kuyruğu: hastanın bekleyen yükü temizlendi; komşunun yükü durur.
    wh = db.one("SELECT status, payload_enc FROM webhook_inbox WHERE external_id=%s", "wamid." + cn1[4:])
    assert wh["payload_enc"] is None and wh["status"] == "done"
    wh2 = db.one("SELECT status, payload_enc FROM webhook_inbox WHERE external_id=%s", "wamid." + cn2[4:])
    assert wh2["status"] == "pending" and wh2["payload_enc"] is not None

    # Komşu hasta (aynı klinik) ve başka klinikteki hasta: bit-bit aynı kalıntı kümesi, dosyalar erişilebilir.
    assert db.scan(cn2) == before2 and db.scan(cn3) == before3
    assert a.get(f"/app/api/patients/{p2}/media/{world['seeds']['p2']['patient_media']}").status_code == 200
    assert db.one("SELECT display_name FROM patients WHERE id=%s", p3)["display_name"] == "Diğer Klinik Hastası"

    audit = db.one("SELECT action, target FROM audit_log WHERE action='patient.anonymize' AND target=%s", f"patient:{p1}")
    assert audit is not None


def test_anonymize_is_idempotent(world):
    a, db, p1, cn1 = world["a"], world["db"], world["pids"]["p1"], world["cans"]["p1"]
    r = a.post(f"/app/api/patients/{p1}/anonymize")
    assert r.status_code == 200 and r.json()["media_files_deleted"] == 0
    assert db.scan(cn1) == ALLOWED_LEFTOVER


# ----------------------------------------------------------------------------------------------------------------------
# 4) Depo silme hatasında anonimleştirme DURUR (hasta kaydına dokunulmaz); düzelince yeniden denenebilir
# ----------------------------------------------------------------------------------------------------------------------
def test_anonymize_aborts_untouched_when_storage_delete_fails_then_succeeds_on_retry(world):
    app, db, a = world["app"], world["db"], world["a"]
    p4, cn4 = app.new_patient(a, "Silinemeyen Dosyalı Hasta"), can()
    seed(db, app, a, p4, cn4)
    db.conn.execute("UPDATE patient_media SET encrypted_path='../../kacak' WHERE patient_id=%s", (p4,))  # depo anahtarı geçersiz -> silme hata verir
    before = db.scan(cn4)
    r = a.post(f"/app/api/patients/{p4}/anonymize")
    assert r.status_code == 502, r.text[:300]
    assert "anonimleştirilmedi" in r.text
    assert db.scan(cn4) == before, "depo hatasında hasta verisi değişmemeli"
    assert db.one("SELECT display_name FROM patients WHERE id=%s", p4)["display_name"] == "Silinemeyen Dosyalı Hasta"
    assert db.one("SELECT count(*) n FROM patient_media WHERE patient_id=%s", p4)["n"] == 1
    db.conn.execute("UPDATE patient_media SET encrypted_path='' WHERE patient_id=%s", (p4,))  # sorun giderildi
    r = a.post(f"/app/api/patients/{p4}/anonymize")
    assert r.status_code == 200, r.text[:300]
    assert db.scan(cn4) - ALLOWED_LEFTOVER == set()


# ----------------------------------------------------------------------------------------------------------------------
# 5) Aynı yaşam döngüsü S3 uyumlu nesne deposunda (docker: motoserver/moto, 127.0.0.1:55000)
# ----------------------------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def s3_bucket_privacy():
    c = _raw_s3()
    name = "dc-priv-" + secrets.token_hex(6)
    try:
        c.create_bucket(Bucket=name)
    except Exception as ex:  # noqa: BLE001
        _s3_unavailable(type(ex).__name__)
    yield name
    try:
        for o in c.list_objects_v2(Bucket=name).get("Contents", []):
            c.delete_object(Bucket=name, Key=o["Key"])
        c.delete_bucket(Bucket=name)
    except Exception:  # noqa: BLE001, S110
        pass


def test_anonymize_deletes_objects_from_s3_and_leaves_other_patients_files(s3_bucket_privacy):
    bucket = s3_bucket_privacy
    c = _raw_s3()
    with pg_app(_s3_env(bucket, prefix="priv")) as app:
        db = Db(app)
        try:
            a = app.new_clinic(app.hq(), "S3 Klinik")
            p1, p2 = app.new_patient(a, "S3 Hedef"), app.new_patient(a, "S3 Komşu")
            for pid, n in ((p1, 1), (p1, 2), (p2, 3)):
                assert app.upload(a, pid, make_jpeg(seed=n), filename=f"s3-{n}.jpg").status_code == 200

            def keys() -> set[str]:
                return {o["Key"] for o in c.list_objects_v2(Bucket=bucket, Prefix="priv/").get("Contents", [])}

            def stored(pid: int) -> set[str]:
                return {"priv/" + r["encrypted_path"] if not r["encrypted_path"].startswith("priv/") else r["encrypted_path"]
                        for r in db.all("SELECT encrypted_path FROM patient_media WHERE patient_id=%s", pid)}

            k1, k2 = stored(p1), stored(p2)
            assert len(k1) == 2 and len(k2) == 1 and (k1 | k2) <= keys(), (k1, k2, keys())
            r = a.post(f"/app/api/patients/{p1}/anonymize")
            assert r.status_code == 200 and r.json()["media_files_deleted"] == 2, r.text[:300]
            left = keys()
            assert not (k1 & left), "S3'te hasta nesneleri kaldı"
            assert k2 <= left, "komşu hastanın nesnesi silinmemeli"
            assert db.one("SELECT count(*) n FROM patient_media WHERE patient_id=%s", p1)["n"] == 0
            assert a.get(f"/app/api/patients/{p2}/media/{db.one('SELECT id FROM patient_media WHERE patient_id=%s', p2)['id']}").status_code == 200
        finally:
            db.close()
