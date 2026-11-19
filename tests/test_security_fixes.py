"""Güvenlik ve KVKK düzeltmeleri için canlı (:8791) + birim doğrulama testleri (SEC-01..SEC-07)."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))

BASE = os.environ.get("DENTACORE_URL", "http://127.0.0.1:8791")
HQ_CREDS = ("yonetici@dentacore.com", "DentaCore2026!")
BURSA_CREDS = ("klinik@bursadis.com", "BursaDis2026!")


def _login(email: str, password: str) -> tuple[httpx.Client, dict, dict]:
    c = httpx.Client(base_url=BASE, timeout=25.0)
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"Login başarısız ({email}): {r.status_code} {r.text}"
    me = c.get("/auth/me").json()
    return c, me, {"X-CSRF-Token": me["csrf"]}


def test_sec01_backup_and_audit_hq_only():
    hq, _, hq_hdr = _login(*HQ_CREDS)
    bursa, _, b_hdr = _login(*BURSA_CREDS)
    created_bak: Path | None = None
    try:
        # Şube owner'ı backup ve global audit/verify uçlarında 403 almalı
        assert bursa.post("/app/api/backup/create", headers=b_hdr).status_code == 403
        assert bursa.post(
            "/app/api/backup/restore-test",
            json={"backup_path": str(ROOT / "backups" / "none.db.gz.fernet"), "target_db_path": str(ROOT / "backups" / "x.db")},
            headers=b_hdr,
        ).status_code == 403
        assert bursa.get("/app/api/audit/verify").status_code == 403

        # HQ owner yedek oluşturup restore-test yapabilmeli; açık metin .db diskte kalmamalı
        r_bak = hq.post("/app/api/backup/create", headers=hq_hdr)
        assert r_bak.status_code == 200, r_bak.text
        bak_path = r_bak.json()["backup_path"]
        created_bak = Path(bak_path)
        assert created_bak.is_file() and bak_path.endswith(".db.gz.fernet")

        restore_target = ROOT / "backups" / "sec01_verify_tmp.db"
        r_res = hq.post(
            "/app/api/backup/restore-test",
            json={"backup_path": bak_path, "target_db_path": str(restore_target)},
            headers=hq_hdr,
        )
        assert r_res.status_code == 200, r_res.text
        assert r_res.json()["ok"] is True
        assert not restore_target.exists(), "Geçici şifresiz .db dosyası diskte kalmamalı"

        r_av = hq.get("/app/api/audit/verify")
        assert r_av.status_code == 200 and r_av.json()["ok"] is True
    finally:
        if created_bak and created_bak.exists():
            created_bak.unlink(missing_ok=True)
        hq.close()
        bursa.close()
    print("OK  SEC-01: Şube owner backup/audit-verify 403, HQ OK, diskte şifresiz .db bırakılmıyor")


def test_sec03_sec04_kvkk_consents_export_anonymize():
    bursa, _, b_hdr = _login(*BURSA_CREDS)
    with httpx.Client(base_url=BASE, timeout=15.0) as anon:
        # /lead onaysız 400 dönmeli
        r_lead_bad = anon.post("/lead", json={"clinic": "KVKK Test Kliniği", "contact": "05321112233", "kvkk_aydinlatma": False})
        assert r_lead_bad.status_code == 400, f"Onaysız /lead 400 dönmeli: {r_lead_bad.status_code}"
        r_lead_ok = anon.post("/lead", json={"clinic": "KVKK Test Kliniği", "contact": "05321112233", "kvkk_aydinlatma": True, "yurt_disi_riza": False})
        assert r_lead_ok.status_code == 200, r_lead_ok.text

    try:
        # Bursa kliniğinde test hastası + kasa kaydı + anamnez linki oluştur
        p_res = bursa.post("/app/api/patients", json={"phone": "+905388887766", "name": "Zeynep Demirci", "lang": "tr"}, headers=b_hdr)
        assert p_res.status_code == 200
        pid = p_res.json()["id"]

        chg = bursa.post("/app/api/charges", json={"patient_id": pid, "description": "KVKK Test Muayene", "amount": "500"}, headers=b_hdr)
        assert chg.status_code == 200

        lnk = bursa.post(f"/app/api/patients/{pid}/anamnesis", headers=b_hdr)
        assert lnk.status_code == 200
        form_path = "/" + lnk.json()["link"].split("/", 3)[-1]

        with httpx.Client(base_url=BASE, timeout=15.0) as pat:
            g = pat.get(form_path)
            assert g.status_code == 200
            assert "KVKK Aydınlatma Metni" in g.text
            assert 'name=kvkk_aydinlatma' in g.text and 'name=saglik_riza' in g.text and 'name=yurt_disi_riza' in g.text

            # Onay kutuları olmadan POST -> 400
            payload_base = {
                "kan_sulandirici": "evet", "kanama_bozuklugu": "hayir", "penisilin_alerji": "hayir",
                "anestezi_alerji": "hayir", "diyabet": "hayir", "kalp": "hayir", "tansiyon": "hayir",
                "bifosfonat": "hayir", "radyoterapi": "hayir", "hamilelik": "hayir", "sigara": "hayir",
                "imza": "Zeynep Demirci",
            }
            bad_post = pat.post(form_path, data=payload_base)
            assert bad_post.status_code == 400, f"Onaysız anamnez 400 dönmeli: {bad_post.status_code}"

            # Yalnız eski tek kutuyla POST -> 400
            bad_old = pat.post(form_path, data={**payload_base, "kvkk": "1"})
            assert bad_old.status_code == 400

            # Zorunlu iki onay kutusuyla POST -> 200 (isteğe bağlı yurt dışı işaretsiz)
            ok_post = pat.post(form_path, data={**payload_base, "kvkk_aydinlatma": "1", "saglik_riza": "1"})
            assert ok_post.status_code == 200

        # Gerçek SHA-256 hash ve consents kontrolü
        p_detail = bursa.get(f"/app/api/patients/{pid}").json()
        kinds = {c["kind"]: c for c in p_detail["consents"]}
        assert "kvkk_aydinlatma" in kinds and "saglik_verisi_acik_riza" in kinds
        assert "yurt_disi_aktarim" not in kinds
        assert len(kinds["saglik_verisi_acik_riza"]["text_sha256"]) == 64

        # Rıza geri alma (CSRF zorunlu)
        assert bursa.post(f"/app/api/patients/{pid}/consents/revoke", json={"kind": "saglik_verisi_acik_riza"}).status_code == 403
        rev = bursa.post(f"/app/api/patients/{pid}/consents/revoke", json={"kind": "saglik_verisi_acik_riza"}, headers=b_hdr)
        assert rev.status_code == 200 and rev.json()["revoked_count"] >= 1
        p_after_rev = bursa.get(f"/app/api/patients/{pid}").json()
        rev_row = next(c for c in p_after_rev["consents"] if c["kind"] == "saglik_verisi_acik_riza")
        assert rev_row["revoked_at"] is not None

        # Veri dışa aktarma (JSON)
        exp = bursa.get(f"/app/api/patients/{pid}/export")
        assert exp.status_code == 200
        exp_data = exp.json()
        assert exp_data["patient"]["display_name"] == "Zeynep Demirci"
        assert len(exp_data["charges"]) >= 1 and len(exp_data["anamnesis"]) >= 1

        # Anonimleştirme (finansal kayıt korunur, kişisel veri okunamaz)
        anon_res = bursa.post(f"/app/api/patients/{pid}/anonymize", headers=b_hdr)
        assert anon_res.status_code == 200 and anon_res.json()["financial_records_preserved"] is True

        p_anon = bursa.get(f"/app/api/patients/{pid}?reveal=true").json()
        assert "Zeynep" not in (p_anon["name"] or "")
        assert "5388887766" not in (p_anon["phone"] or "")
        assert len(p_anon["charges"]) >= 1, "Finansal kayıtlar korunmalı"

        aud = bursa.get("/app/api/audit").json()
        actions = {row["action"] for row in aud}
        assert {"patient.consent_revoke", "patient.export", "patient.anonymize"}.issubset(actions)
    finally:
        bursa.close()
    print("OK  SEC-03/04: KVKK aydınlatma+açık rıza, /lead onayı, rıza geri alma, export ve anonimleştirme")


def test_sec05_xff_and_lockout_before_scrypt():
    # 1. Güvenilmeyen modda (TRUSTED_PROXY yok) X-Forwarded-For sahteciliği /lead hız sınırını aşamamalı
    with httpx.Client(base_url=BASE, timeout=15.0) as c:
        statuses = []
        for i in range(6):
            r = c.post(
                "/lead",
                json={"clinic": f"XFF Test {i}", "contact": "05320001122", "kvkk_aydinlatma": True},
                headers={"X-Forwarded-For": f"198.51.100.{10 + i}"},
            )
            statuses.append(r.status_code)
        assert 429 in statuses, f"TRUSTED_PROXY=0 iken XFF sahteciliği 429'u atlayamamalı: {statuses}"

    # 2. Kilitli hesap kontrolü scrypt'ten önce hızlıca 423 dönmeli
    hq, _, hq_hdr = _login(*HQ_CREDS)
    test_email = f"locktest_{int(time.time())}@dentacore.com"
    try:
        st_r = hq.post(
            "/app/api/staff",
            json={"email": test_email, "full_name": "Kilit Test", "role": "secretary", "password": "StrongLockTest2026!"},
            headers=hq_hdr,
        )
        assert st_r.status_code == 200, st_r.text
        with httpx.Client(base_url=BASE, timeout=15.0) as lc:
            for _ in range(10):
                r_fail = lc.post("/auth/login", json={"email": test_email, "password": "WrongPassword123!"})
                assert r_fail.status_code == 401
            # 11. deneme (doğru parolayla bile!) 423 ve scrypt'e girmeden çok hızlı dönmeli
            t0 = time.monotonic()
            r_locked = lc.post("/auth/login", json={"email": test_email, "password": "StrongLockTest2026!"})
            elapsed = time.monotonic() - t0
            assert r_locked.status_code == 423, f"Kilitli hesap 423 dönmeli: {r_locked.status_code}"
            assert elapsed < 0.25, f"Kilitli hesap scrypt çalıştırmamalı ({elapsed:.3f}s)"
    finally:
        hq.close()
    print("OK  SEC-05: Güvenilmeyen modda XFF etkisiz, kilitli hesap scrypt öncesi 423")


def test_sec06_calendar_security():
    from app import cal

    hq, _, hq_hdr = _login(*HQ_CREDS)
    try:
        links1 = hq.get("/app/api/calendar-links").json()
        ics_path1 = "/" + links1["ics_url"].split("/", 3)[-1]
        with httpx.Client(base_url=BASE, timeout=15.0) as anon:
            feed = anon.get(ics_path1)
            assert feed.status_code == 200
            body_l = feed.text.lower()
            assert "kırmızı bayrak" not in body_l and "kirmizi bayrak" not in body_l
            assert "ayşe kaya" not in body_l and "ahmet yılmaz" not in body_l
            assert "A. K." in feed.text or "A. Y." in feed.text

        all_ics = hq.get("/app/api/calendar/all.ics")
        assert all_ics.status_code == 200
        assert "kırmızı bayrak" not in all_ics.text.lower()
        assert "ayşe kaya" not in all_ics.text.lower()

        # Token yenileme: eski token 403, yeni token 200
        rot = hq.post("/app/api/calendar-links/rotate", headers=hq_hdr)
        assert rot.status_code == 200
        ics_path2 = "/" + rot.json()["ics_url"].split("/", 3)[-1]
        assert ics_path2 != ics_path1
        with httpx.Client(base_url=BASE, timeout=15.0) as anon:
            assert anon.get(ics_path1).status_code == 403, "İptal edilen eski takvim bağlantısı 403 dönmeli"
            assert anon.get(ics_path2).status_code == 200

        # Süresi dolmuş token ve dev sabit anahtar yokluğu doğrulaması
        expired_tok = cal.calendar_feed_token(1, version=1, ttl_seconds=-120)
        assert cal.verify_feed_token(expired_tok) is None
        saved_admin = os.environ.pop("ADMIN_TOKEN", None)
        saved_cal = os.environ.pop("CALENDAR_SECRET", None)
        try:
            assert cal._feed_key() != b"dentacore-dev-cal-key"
        finally:
            if saved_admin is not None:
                os.environ["ADMIN_TOKEN"] = saved_admin
            if saved_cal is not None:
                os.environ["CALENDAR_SECRET"] = saved_cal
    finally:
        hq.close()
    print("OK  SEC-06: .ics kırmızı bayrak/tam ad içermez, token süreli+yenilenebilir, sabit dev anahtar yok")


def test_sec07_webhook_clinic_mapping_and_dedup():
    from app import security as sec

    # Dedup cache birim testi (OrderedDict + max_size + TTL)
    cache = sec.WebhookDedupCache(max_size=2, ttl_seconds=10)
    assert cache.seen_or_add("m1", now=100.0) is False
    assert cache.seen_or_add("m1", now=105.0) is True
    assert cache.seen_or_add("m2", now=106.0) is False
    assert cache.seen_or_add("m3", now=107.0) is False  # m1 evict edilmiş olmalı
    assert cache.seen_or_add("m1", now=108.0) is False
    assert cache.seen_or_add("m3", now=120.0) is False  # TTL dolmuş olmalı

    # Canlı webhook testi (yalnız WA_APP_SECRET ortamda varsa canlı HTTP, yoksa unit+settings kontrolü)
    bursa, _, b_hdr = _login(*BURSA_CREDS)
    try:
        cur_set = bursa.get("/app/api/settings").json()
        upd = bursa.post(
            "/app/api/settings",
            json={
                "name": cur_set["name"],
                "city": cur_set["city"],
                "address": cur_set["address"],
                "phone": cur_set["phone"],
                "wa_phone_id": "wa-phone-bursa-8791",
                "ig_handle": "ig-bursa-8791",
            },
            headers=b_hdr,
        )
        assert upd.status_code == 200, upd.text

        wa_secret = os.environ.get("DENTACORE_WA_SECRET", "")  # sunucunun gerçek WA_APP_SECRET'i; test_offline env sızıntısından etkilenmez
        if wa_secret:
            with httpx.Client(base_url=BASE, timeout=15.0) as wc:
                def _sign(payload: dict) -> tuple[bytes, dict]:
                    raw = json.dumps(payload).encode()
                    sig = "sha256=" + hmac.new(wa_secret.encode(), raw, hashlib.sha256).hexdigest()
                    return raw, {"X-Hub-Signature-256": sig, "Content-Type": "application/json"}

                # Eşleşmeyen phone_number_id -> unmapped>=1, processed=0
                raw_bad, hdr_bad = _sign({
                    "entry": [{"changes": [{"value": {
                        "metadata": {"phone_number_id": "unknown-phone-999"},
                        "messages": [{"id": f"wamid.unmapped.{time.time_ns()}", "from": "905310009988", "type": "text", "text": {"body": "Merhaba"}}],
                    }}]}]
                })
                r_bad = wc.post("/webhook/whatsapp", content=raw_bad, headers=hdr_bad)
                assert r_bad.status_code == 200 and r_bad.json()["unmapped"] >= 1 and r_bad.json()["processed"] == 0

                # Bursa'ya eşleşen phone_number_id -> processed=1, Bursa hastalarına düşer
                raw_ok, hdr_ok = _sign({
                    "entry": [{"changes": [{"value": {
                        "metadata": {"phone_number_id": "wa-phone-bursa-8791"},
                        "contacts": [{"wa_id": "905310007755", "profile": {"name": "Bursa Webhook Test"}}],
                        "messages": [{"id": f"wamid.bursa.{time.time_ns()}", "from": "905310007755", "type": "text", "text": {"body": "Adresiniz nerede?"}}],
                    }}]}]
                })
                r_ok = wc.post("/webhook/whatsapp", content=raw_ok, headers=hdr_ok)
                assert r_ok.status_code == 200 and r_ok.json()["processed"] == 1

                # Aynı message id tekrar gelirse dedup=1
                r_dup = wc.post("/webhook/whatsapp", content=raw_ok, headers=hdr_ok)
                assert r_dup.status_code == 200 and r_dup.json()["dedup"] == 1 and r_dup.json()["processed"] == 0

                b_patients = bursa.get("/app/api/patients?search=Bursa+Webhook+Test").json()
                assert len(b_patients) >= 1, "Webhook mesajı Bursa kliniğine düşmeli"
    finally:
        bursa.close()
    print("OK  SEC-07: Webhook kanal->klinik eşlemesi ve sınırlı TTL dedup önbelleği")


if __name__ == "__main__":
    test_sec01_backup_and_audit_hq_only()
    test_sec03_sec04_kvkk_consents_export_anonymize()
    test_sec05_xff_and_lockout_before_scrypt()
    test_sec06_calendar_security()
    test_sec07_webhook_clinic_mapping_and_dedup()
    print("SONUÇ: TÜM GÜVENLİK VE KVKK TESTLERİ GEÇTİ")
