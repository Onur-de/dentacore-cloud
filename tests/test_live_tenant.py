"""Canlı yerel sunucu (http://127.0.0.1:8000) çok kiracılı izolasyon, HQ geçiş, takvim ve güvenlik testleri.
Çalıştırmadan önce `run_local.py` sunucusunun 8000 portunda açık olması gerekir.
"""
from __future__ import annotations

import os
import time

import httpx

BASE = os.environ.get("DENTACORE_URL", "http://127.0.0.1:8000")

CLINICS = [
    (1, "yonetici@dentacore.com", "DentaCore2026!", True),
    (2, "klinik@bursadis.com", "BursaDis2026!", False),
    (3, "klinik@ankaradis.com", "AnkaraDis2026!", False),
]

REQUIRED_12_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
    "cross-origin-embedder-policy",
    "x-permitted-cross-domain-policies",
    "cache-control",
]


def login_client(email: str, password: str) -> tuple[httpx.Client, dict]:
    c = httpx.Client(base_url=BASE, timeout=25.0)
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"Login başarısız ({email}): {r.status_code} {r.text}"
    data = r.json()
    assert data["ok"] is True
    me = c.get("/auth/me")
    assert me.status_code == 200
    return c, me.json()


def test_security_headers_and_static():
    with httpx.Client(base_url=BASE, timeout=10.0) as c:
        r = c.get("/health")
        assert r.status_code == 200 and r.json()["ok"] is True

        # PWA, sw.js, sitemap, robots, static regex
        m = c.get("/manifest.webmanifest")
        assert m.status_code == 200
        sw = c.get("/sw.js")
        assert sw.status_code == 200 and sw.headers.get("service-worker-allowed") == "/"
        sm = c.get("/sitemap.xml")
        assert sm.status_code == 200 and "<urlset" in sm.text
        rb = c.get("/robots.txt")
        assert rb.status_code == 200

        # Path traversal & disallowed extension checks
        for bad in ("../run_local.py", "app.py", "..%2F..%2Frun_local.py", ".hidden.js", "BAD.js"):
            rs = c.get(f"/static/{bad}")
            assert rs.status_code in (400, 404), f"Static traversal/red başarısız ({bad}): {rs.status_code}"

        # 12 güvenlik başlığı (/auth/me veya /app/api/* üzerinde no-store ile 12 başlık)
        c1, _ = login_client(CLINICS[0][1], CLINICS[0][2])
        try:
            r_me = c1.get("/auth/me")
            assert r_me.status_code == 200
            lower_hdrs = {k.lower(): v for k, v in r_me.headers.items()}
            for h in REQUIRED_12_HEADERS:
                assert h in lower_hdrs, f"Eksik güvenlik başlığı: {h}"
            assert "server" not in lower_hdrs and "x-powered-by" not in lower_hdrs
            assert lower_hdrs["cache-control"] == "no-store"
            assert "manifest-src 'self'" in lower_hdrs["content-security-policy"]
            assert "worker-src 'self'" in lower_hdrs["content-security-policy"]
        finally:
            c1.close()
    print("OK  12 güvenlik başlığı, manifest/sw.js/sitemap/robots ve static traversal koruması")


def test_three_clinics_and_csrf_and_isolation():
    clients = {}
    try:
        for cid, email, pw, exp_hq in CLINICS:
            cli, me = login_client(email, pw)
            assert me["clinic_id"] == cid, f"{email} clinic_id={me['clinic_id']} != {cid}"
            assert me["home_clinic_id"] == cid
            assert me["user"]["is_hq"] is exp_hq
            clients[cid] = (cli, me)

        # CSRF reddi testi (X-CSRF-Token olmadan POST 403 dönmeli)
        c2, me2 = clients[2]
        r_nocsrf = c2.post("/app/api/waitlist", json={"patient_id": 1, "treatment": "dolgu"})
        assert r_nocsrf.status_code == 403, f"CSRF olmadan 403 bekleniyordu: {r_nocsrf.status_code}"
        r_badcsrf = c2.post("/app/api/waitlist", json={"patient_id": 1, "treatment": "dolgu"},
                            headers={"X-CSRF-Token": "wrong-token"})
        assert r_badcsrf.status_code == 403

        # Klinik 1'in kayıtları (hasta #1, randevu #1, envanter #1, uyarı #1, kasa #1)
        c1, me1 = clients[1]
        h1 = {"X-CSRF-Token": me1["csrf"]}
        h2 = {"X-CSRF-Token": me2["csrf"]}
        c3, me3 = clients[3]
        h3 = {"X-CSRF-Token": me3["csrf"]}

        # Klinik 1 hastası ve randevusu oluştur / al
        p1_list = c1.get("/app/api/patients").json()
        assert len(p1_list) >= 1
        p1_id = p1_list[0]["id"]

        inv1 = c1.get("/app/api/inventory").json()
        inv1_id = inv1[0]["id"]

        w1 = c1.post("/app/api/waitlist", json={"patient_id": p1_id, "treatment": "test_izolasyon"}, headers=h1)
        assert w1.status_code == 200
        w1_id = w1.json()["id"]

        # Klinik 2 oturumuyla Klinik 1 kayıtlarına erişim -> 404
        assert c2.get(f"/app/api/patients/{p1_id}").status_code == 404
        assert c2.post(f"/app/api/patients/{p1_id}/anamnesis", headers=h2).status_code == 404
        assert c2.post("/app/api/waitlist", json={"patient_id": p1_id, "treatment": "x"}, headers=h2).status_code == 404
        assert c2.post(f"/app/api/waitlist/{w1_id}/remove", headers=h2).status_code == 404
        assert c2.get(f"/app/api/inventory/{inv1_id}/moves").status_code == 404
        assert c2.post(f"/app/api/inventory/{inv1_id}/move", json={"delta": "-1", "reason": "test"}, headers=h2).status_code == 404
        assert c2.post("/app/api/charges", json={"patient_id": p1_id, "description": "test islem", "amount": "100"}, headers=h2).status_code == 404
        assert c2.post("/app/api/payments", json={"patient_id": p1_id, "amount": "100", "method": "nakit"}, headers=h2).status_code == 404
        assert c2.post(f"/app/api/conversations/{p1_id}/send", json={"text": "merhaba"}, headers=h2).status_code == 404
        assert c2.post("/app/api/appointments/1/status", json={"status": "confirmed"}, headers=h2).status_code == 404
        assert c2.get("/app/api/appointments/1/ics").status_code == 404
        assert c2.post("/app/api/charges/1/void", json={"reason": "test"}, headers=h2).status_code == 404

        # Temizlik: w1_id kapat
        assert c1.post(f"/app/api/waitlist/{w1_id}/remove", headers=h1).status_code == 200

        # Aynı telefon numarasını Klinik 2 ve Klinik 3 kendi kliniklerine ayrı hasta olarak ekleyebilmeli (UNIQUE(clinic_id, phone_hmac))
        shared_phone = "+905399998877"
        cp2 = c2.post("/app/api/patients", json={"phone": shared_phone, "name": "Bursa Ortak Tel", "lang": "fr"}, headers=h2)
        cp3 = c3.post("/app/api/patients", json={"phone": shared_phone, "name": "Ankara Ortak Tel", "lang": "he"}, headers=h3)
        assert cp2.status_code == 200 and cp3.status_code == 200
        assert cp2.json()["id"] != cp3.json()["id"]

        # Audit izolasyonu: Klinik 2 denetim listesinde Klinik 1 veya Klinik 3 e-postası/aksiyonu görünmemeli
        aud2 = c2.get("/app/api/audit").json()
        assert all("yonetici@dentacore.com" not in str(row.get("actor", "")) for row in aud2)
        assert all("klinik@ankaradis.com" not in str(row.get("actor", "")) for row in aud2)

        # Non-HQ owner clinic listesinde yalnız kendi kliniğini görür, switch ve yeni klinik açma 403 döner
        cl2 = c2.get("/app/api/clinics").json()
        assert len(cl2) == 1 and cl2[0]["id"] == 2
        assert c2.post("/app/api/clinics/1/switch", headers=h2).status_code == 403
        assert c2.post("/app/api/clinics", json={
            "clinic_name": "Yetkisiz", "owner_name": "X Y", "owner_email": "x@y.com", "owner_password": "StrongPassword123!"
        }, headers=h2).status_code == 403
    finally:
        for cli, _ in clients.values():
            cli.close()
    print("OK  3 klinik girişi, CSRF reddi, çapraz kiracı 404 izolasyonu ve UNIQUE(clinic_id, phone_hmac)")


def test_hq_switch_calendar_simulate_ecosystem():
    c1, me1 = login_client(CLINICS[0][1], CLINICS[0][2])
    h1 = {"X-CSRF-Token": me1["csrf"]}
    try:
        # HQ tüm 3 kliniği görür
        all_cl = c1.get("/app/api/clinics").json()
        assert len(all_cl) >= 3
        for item in all_cl:
            assert "owner_email" in item and "ics_url" in item and "webcal_url" in item and "paid_try" in item

        # HQ switch -> Klinik 3 (Ankara)
        sw3 = c1.post("/app/api/clinics/3/switch", headers=h1)
        assert sw3.status_code == 200 and sw3.json()["clinic_id"] == 3
        me_after = c1.get("/auth/me").json()
        assert me_after["clinic_id"] == 3 and me_after["home_clinic_id"] == 1 and me_after["user"]["is_hq"] is True

        # Ankara takvim all.ics ve calendar-links
        clinks = c1.get("/app/api/calendar-links").json()
        assert clinks["ics_url"].endswith(".ics")
        assert clinks["webcal_url"].startswith("webcal://")
        assert clinks["google_subscribe_url"].startswith("https://calendar.google.com/calendar/r?cid=")

        all_ics = c1.get("/app/api/calendar/all.ics")
        assert all_ics.status_code == 200
        assert "text/calendar" in all_ics.headers.get("content-type", "")
        assert "BEGIN:VCALENDAR" in all_ics.text and "Ankara" in all_ics.text

        # Simulate endpoint (<20s garanti, Ankara klinik bilgisiyle)
        t0 = time.monotonic()
        sim = c1.post("/app/api/conversations/simulate", json={"text": "Adresiniz nerede?"}, headers=h1)
        elapsed = time.monotonic() - t0
        assert sim.status_code == 200, sim.text
        assert elapsed < 20.0
        sdata = sim.json()
        assert sdata["lang"] == "tr" and sdata["intent"] == "konum" and "Tunalı" in sdata["answer"]

        # HQ geri dönüş -> Klinik 1
        sw1 = c1.post("/app/api/clinics/1/switch", headers=h1)
        assert sw1.status_code == 200 and sw1.json()["clinic_id"] == 1

        # Ecosystem status
        eco = c1.get("/app/api/ecosystem-status")
        assert eco.status_code == 200
        edata = eco.json()
        assert edata["langs"] == 16 and edata["security_headers"] == 12
        assert len(edata["apps"]) == 9

        # Audit chain integrity
        av = c1.get("/app/api/audit/verify")
        assert av.status_code == 200 and av.json()["ok"] is True

        # Sınır durumlar: naive datetime, setup'sız totp enable (400), negatif stok (422) -> asla 500 değil
        ap_naive = c1.get("/app/api/appointments?start=2026-11-18T00:00:00&end=2026-11-25T00:00:00")
        assert ap_naive.status_code == 200, f"Naive datetime 500 dönmemeli: {ap_naive.status_code}"
        t_no_setup = c1.post("/auth/totp/enable", json={"code": "123456"}, headers=h1)
        assert t_no_setup.status_code == 400, f"Setup'sız totp 400 dönmeli: {t_no_setup.status_code}"
        neg_inv = c1.post("/app/api/inventory", json={"name": "NegTest", "qty": "-5"}, headers=h1)
        assert neg_inv.status_code == 422, f"Negatif stok 422 dönmeli: {neg_inv.status_code}"
    finally:
        c1.close()
    print("OK  HQ switch, calendar all.ics + google_subscribe_url, simulate (<20s), ecosystem-status")


if __name__ == "__main__":
    test_security_headers_and_static()
    test_three_clinics_and_csrf_and_isolation()
    test_hq_switch_calendar_simulate_ecosystem()
    print("SONUÇ: TÜM CANLI ÇOK-KİRACILI TESTLER GEÇTİ")
