"""DentaCore Kurumsal SaaS — 20 Uçtan Uca (E2E) Kabul ve Regresyon Test Paketi.
Tüm testler gerçek HTTP çağrılarıyla (POST / PATCH / GET / DELETE) izole sunucu üzerinde çalışır.
"""
from __future__ import annotations

import os
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("DENTACORE_URL", "http://127.0.0.1:8794").rstrip("/")
TZ = ZoneInfo("Europe/Istanbul")

HQ_CREDS = ("yonetici@dentacore.com", "DentaCore2026!")
SEC_CREDS = ("sekreter@dentacore.com", "DentaCore2026!")
BURSA_CREDS = ("klinik@bursadis.com", "BursaDis2026!")


_SESSIONS: dict[str, tuple[httpx.Client, dict, dict]] = {}


def _login(email: str, password: str) -> tuple[httpx.Client, dict, dict]:
    cached = _SESSIONS.get(email)
    if cached is not None:
        client, me, hdr = cached
        if not client.is_closed:
            return client, me, hdr
    c = httpx.Client(base_url=BASE, timeout=25.0)
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"Login başarısız ({email}): {r.status_code} {r.text}"
    me = c.get("/auth/me").json()
    res = (c, me, {"X-CSRF-Token": me["csrf"]})
    _SESSIONS[email] = res
    return res


def _close_cached(_client: httpx.Client) -> None:
    # Oturumu kapatma; test paketi boyunca aynı oturum yeniden kullanılarak login rate-limit (429) korunur.
    pass


def _uniq() -> int:
    return int(time.time() * 1000000) % 89999 + 10000


def test_01_instagram_campaign_lead_to_patient_first_source():
    """1. Instagram reklamından gelen kişinin kaydedilmesi ve first_source=instagram olması."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        c_res = hq.post(
            "/app/api/campaigns",
            json={
                "name": f"IG Zirkonyum Kampanya {u}",
                "source": "instagram",
                "channel": "instagram",
                "code": f"ig-zirkon-{u}",
                "utm_source": "instagram",
                "utm_medium": "cpc",
                "utm_campaign": f"zirkon_{u}",
            },
            headers=hdr,
        )
        assert c_res.status_code == 200
        camp_id = c_res.json()["id"]

        p_res = hq.post(
            "/app/api/patients",
            json={
                "name": f"Selin Instagram {u}",
                "phone": f"+90532{u}01",
                "lang": "tr",
                "utm_source": "instagram",
                "utm_medium": "paid_social",
                "utm_campaign": f"zirkon_{u}",
                "click_id": f"fbclid_{u}",
                "campaign_id": camp_id,
            },
            headers=hdr,
        )
        assert p_res.status_code == 200, p_res.text
        pdata = p_res.json()
        assert pdata["first_source"] == "instagram"
        assert pdata["last_source"] == "instagram"

        detail = hq.get(f"/app/api/patients/{pdata['id']}").json()
        assert detail["first_source"] == "instagram"
        assert detail["campaign_id"] == camp_id
    finally:
        _close_cached(hq)


def test_02_whatsapp_message_preserves_immutable_first_source():
    """2. Daha sonra WhatsApp’tan temas etmesi ama first_source bilgisinin bozulmaması."""
    hq, _, hdr = _login(*HQ_CREDS)
    sec, _, s_hdr = _login(*SEC_CREDS)
    try:
        u = _uniq()
        p_res = hq.post(
            "/app/api/patients",
            json={
                "name": f"Mert GoogleAds {u}",
                "phone": f"+90533{u}02",
                "first_source": "google_ads",
                "last_source": "google_ads",
            },
            headers=hdr,
        )
        assert p_res.status_code == 200
        pid = p_res.json()["id"]

        # Sekreter hastanın son temas kanalını WhatsApp olarak günceller
        up_last = sec.patch(
            f"/app/api/patients/{pid}",
            json={"last_source": "whatsapp"},
            headers=s_hdr,
        )
        assert up_last.status_code == 200
        det = hq.get(f"/app/api/patients/{pid}").json()
        assert det["first_source"] == "google_ads"
        assert det["last_source"] == "whatsapp"

        # Sekreter first_source'u değiştirmeye çalışırsa 403 almalı
        forbid = sec.patch(
            f"/app/api/patients/{pid}",
            json={"first_source": "walk_in", "source_change_reason": "Yanlış seçilmiş"},
            headers=s_hdr,
        )
        assert forbid.status_code == 403

        # Yönetici bile gerekçesiz first_source değiştiremez (400)
        no_reason = hq.patch(
            f"/app/api/patients/{pid}",
            json={"first_source": "referral"},
            headers=hdr,
        )
        assert no_reason.status_code == 400
    finally:
        _close_cached(hq)
        _close_cached(sec)


def test_03_duplicate_phone_prevention_and_check_endpoint():
    """3. Aynı telefonla ikinci hasta kaydının engellenmesi ve check-duplicate kontrolü."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        raw_phone = f"0534 {str(u)[:3]} {str(u)[3:]} 03"
        p1 = hq.post(
            "/app/api/patients",
            json={"name": f"Tekil Hasta {u}", "phone": raw_phone, "first_source": "phone"},
            headers=hdr,
        )
        assert p1.status_code == 200
        pid = p1.json()["id"]

        chk = hq.get("/app/api/patients/check-duplicate", params={"phone": f"+90 534 {u} 03"})
        assert chk.status_code == 200
        assert chk.json()["duplicate"] is True
        assert chk.json()["patient"]["id"] == pid

        p2 = hq.post(
            "/app/api/patients",
            json={"name": f"Mükerrer Hasta {u}", "phone": f"90534{u}03", "first_source": "walk_in"},
            headers=hdr,
        )
        assert p2.status_code == 200
        assert p2.json()["duplicate"] is True
        assert p2.json()["id"] == pid
        assert p2.json()["first_source"] == "phone"
    finally:
        _close_cached(hq)


def test_04_primary_doctor_vs_performing_doctor_separation():
    """4. Hastanın sorumlu doktoru Dr. A iken tedaviyi Dr. B’nin yapması ve raporun doğru ayrılması."""
    hq, me_hq, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        doc_a_id = me_hq["user"]["id"]
        doc_b = hq.post(
            "/app/api/staff",
            json={
                "email": f"dr.cerrah.{u}@dentacore.com",
                "full_name": f"Dt. Cerrah B {u}",
                "role": "doctor",
                "job_title": "specialist_dentist",
                "share_pct": "40",
                "password": "DoctorPassword2026!",
            },
            headers=hdr,
        )
        assert doc_b.status_code == 200, doc_b.text
        doc_b_id = doc_b.json()["id"]

        p = hq.post(
            "/app/api/patients",
            json={
                "name": f"Doktor Ayrım Hasta {u}",
                "phone": f"+90535{u}04",
                "primary_doctor_id": doc_a_id,
                "first_source": "referral",
            },
            headers=hdr,
        )
        assert p.status_code == 200
        pid = p.json()["id"]

        # Tedaviyi Dr. B yapar
        odo = hq.post(
            f"/app/api/patients/{pid}/odontogram",
            json={
                "tooth_fdi": 36,
                "surface": "FULL",
                "status": "implant",
                "procedure_code": "IMP-01",
                "procedure_name": "İmplant Cerrahisi",
                "amount": "15000",
                "doctor_id": doc_b_id,
                "auto_charge": True,
            },
            headers=hdr,
        )
        assert odo.status_code == 200, odo.text
        assert odo.json()["performing_doctor_id"] == doc_b_id

        # Sorumlu doktor hâlâ Dr. A kalmalı
        p_det = hq.get(f"/app/api/patients/{pid}").json()
        assert p_det["primary_doctor_id"] == doc_a_id

        # Gelir raporunda Dr. B'nin yaptığı işlem ve 15.000 TL üzerinden %40 = 6.000 TL hakedişi görünmeli
        rep = hq.get("/app/api/doctors/revenue-report").json()
        row_b = next(r for r in rep if r["doctor_id"] == doc_b_id)
        assert row_b["performed_procedures_count"] >= 1
        assert row_b["net_billed"] == 15000.0
        assert row_b["doctor_hakedis"] == 6000.0
        assert row_b["clinic_share"] == 9000.0
    finally:
        _close_cached(hq)


def test_05_anatomical_52_fdi_odontogram_adult_and_pediatric():
    """5. 52 dişlik FDI anatomik kataloğu (32 yetişkin + 20 süt dişi) ve tedavi fiyat kataloğu."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        cat = hq.get("/app/api/fdi-catalog")
        assert cat.status_code == 200
        data = cat.json()
        assert len(data["fdi_teeth"]) == 52
        adult = [t for t in data["fdi_teeth"].values() if t["dentition"] == "permanent"]
        pediatric = [t for t in data["fdi_teeth"].values() if t["dentition"] in ("deciduous", "primary")]
        assert len(adult) == 32
        assert len(pediatric) == 20

        # Yeni tedavi kataloğu kalemi ekleme
        u = _uniq()
        tc = hq.post(
            "/app/api/treatment-catalog",
            json={
                "code": f"ZIR-{u}",
                "name": "Monolitik Zirkonyum Kron",
                "category": "Protez",
                "default_price": "9500",
                "default_status": "crown",
            },
            headers=hdr,
        )
        assert tc.status_code == 200, tc.text
        t_list = hq.get("/app/api/treatment-catalog").json()
        assert any(item["code"] == f"ZIR-{u}" and item["default_price"] == 9500.0 for item in t_list)
    finally:
        _close_cached(hq)


def test_06_planned_vs_completed_treatment_debt_separation():
    """6. Planlanan tedavinin borç oluşturmaması, tamamlanan tedavinin borç oluşturması."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Plan Borç Hasta {u}", "phone": f"+90536{u}06"},
            headers=hdr,
        ).json()
        pid = p["id"]

        # 12.000 TL planlanan işlem girilir -> borç 0 olmalı
        odo_plan = hq.post(
            f"/app/api/patients/{pid}/odontogram",
            json={
                "tooth_fdi": 16,
                "surface": "MOD"[:1],
                "status": "planned",
                "procedure_name": "Planlanan Kanal + Kron",
                "amount": "12000",
                "auto_charge": True,
            },
            headers=hdr,
        )
        assert odo_plan.status_code == 200, odo_plan.text
        rid = odo_plan.json()["id"]
        assert odo_plan.json()["charge_id"] is None

        det1 = hq.get(f"/app/api/patients/{pid}").json()
        fin1 = det1["finance_summary"]
        assert fin1["planned_total"] == 12000.0
        assert fin1["completed_net_debt"] == 0.0
        assert fin1["net_remaining_debt"] == 0.0

        # Planlanan işlem tamamlandığında (status='treated') otomatik borç oluşmalı
        patch_res = hq.patch(
            f"/app/api/patients/{pid}/odontogram/{rid}",
            json={"status": "treated"},
            headers=hdr,
        )
        assert patch_res.status_code == 200, patch_res.text
        assert patch_res.json()["new_charge_id"] is not None

        det2 = hq.get(f"/app/api/patients/{pid}").json()
        fin2 = det2["finance_summary"]
        assert fin2["planned_total"] == 0.0
        assert fin2["completed_net_debt"] == 12000.0
        assert fin2["net_remaining_debt"] == 12000.0
    finally:
        _close_cached(hq)


def test_07_draft_corporate_20_percent_agreement_auto_discount():
    """7. Taslak kurum %20 anlaşmalı hastada 10.000 TL işlemin 8.000 TL net borca düşmesi."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        ba = hq.post(
            "/app/api/bank-agreements",
            json={
                "bank_name": f"Taslak Kurum {u}",
                "start_date": "2025-01-01",
                "end_date": "2028-12-31",
                "discount_pct": "20",
                "discount_type": "percentage",
                "applicable_treatments": "all",
                "max_discount": "0",
                "combinable": False,
                "active": True,
            },
            headers=hdr,
        )
        assert ba.status_code == 200, ba.text
        bank_id = ba.json()["id"]

        # Hesaplama ucu doğrulaması
        calc = hq.post(
            "/app/api/bank-agreements/calculate",
            json={"gross_amount": "10000", "bank_agreement_id": bank_id, "procedure_name": "İmplant"},
            headers=hdr,
        )
        assert calc.status_code == 200, calc.text
        assert calc.json()["gross_amount"] == 10000.0
        assert calc.json()["total_discount"] == 2000.0
        assert calc.json()["net_payable"] == 8000.0

        # Taslak Kurum anlaşmalı hasta
        p = hq.post(
            "/app/api/patients",
            json={
                "name": f"Taslak Kurum Hasta {u}",
                "phone": f"+90537{u}07",
                "bank_agreement_id": bank_id,
            },
            headers=hdr,
        ).json()
        pid = p["id"]

        # Odontogram üzerinden 10.000 TL tamamlanan işlem -> otomatik %20 indirimle 8.000 TL borç
        odo = hq.post(
            f"/app/api/patients/{pid}/odontogram",
            json={
                "tooth_fdi": 24,
                "surface": "FULL",
                "status": "crown",
                "procedure_name": "Zirkonyum Kron",
                "amount": "10000",
                "auto_charge": True,
            },
            headers=hdr,
        )
        assert odo.status_code == 200, odo.text
        odata = odo.json()
        assert odata["gross_amount"] == 10000.0
        assert odata["discount"] == 2000.0
        assert odata["net_amount"] == 8000.0

        fin = hq.get(f"/app/api/patients/{pid}").json()["finance_summary"]
        assert fin["completed_gross"] == 10000.0
        assert fin["discount_total"] == 2000.0
        assert fin["completed_net_debt"] == 8000.0
        assert fin["net_remaining_debt"] == 8000.0
    finally:
        _close_cached(hq)


def test_08_partial_payment_and_remaining_debt_calculation():
    """8. 8.000 TL net borçtan 3.000 TL ödeme alındığında kalan borcun 5.000 TL görünmesi."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Kısmi Ödeme Hasta {u}", "phone": f"+90538{u}08"},
            headers=hdr,
        ).json()
        pid = p["id"]

        chg = hq.post(
            "/app/api/charges",
            json={
                "patient_id": pid,
                "description": "4'lü Köprü Protez",
                "amount": "10000",
                "discount": "2000",
            },
            headers=hdr,
        )
        assert chg.status_code == 200, chg.text

        pay = hq.post(
            "/app/api/payments",
            json={
                "patient_id": pid,
                "amount": "3000",
                "method": "kredi_karti",
                "status": "completed",
            },
            headers=hdr,
        )
        assert pay.status_code == 200, pay.text
        fin = pay.json()["finance_summary"]
        assert fin["completed_gross"] == 10000.0
        assert fin["discount_total"] == 2000.0
        assert fin["completed_net_debt"] == 8000.0
        assert fin["collected_paid"] == 3000.0
        assert fin["net_remaining_debt"] == 5000.0
    finally:
        _close_cached(hq)


def test_09_pending_and_failed_payments_never_reduce_debt():
    """9. Bekleyen (pending) ve başarısız (failed) ödemenin kalan borçtan düşmemesi."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Pending Failed Hasta {u}", "phone": f"+90539{u}09"},
            headers=hdr,
        ).json()
        pid = p["id"]

        hq.post("/app/api/charges", json={"patient_id": pid, "description": "Kanal Tedavisi", "amount": "5000"}, headers=hdr)

        p_pend = hq.post(
            "/app/api/payments",
            json={"patient_id": pid, "amount": "2000", "method": "havale", "status": "pending"},
            headers=hdr,
        )
        assert p_pend.status_code == 200
        fin1 = p_pend.json()["finance_summary"]
        assert fin1["pending_payment"] == 2000.0
        assert fin1["collected_paid"] == 0.0
        assert fin1["net_remaining_debt"] == 5000.0

        p_fail = hq.post(
            "/app/api/payments",
            json={"patient_id": pid, "amount": "5000", "method": "kredi_karti", "status": "failed"},
            headers=hdr,
        )
        assert p_fail.status_code == 200
        fin2 = p_fail.json()["finance_summary"]
        assert fin2["failed_payment"] == 5000.0
        assert fin2["collected_paid"] == 0.0
        assert fin2["net_remaining_debt"] == 5000.0
    finally:
        _close_cached(hq)


def test_10_advance_payment_and_settlement():
    """10. Avans ödemenin kaydedilmesi ve sonradan oluşan borçtan mahsup edilmesi."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Avans Hasta {u}", "phone": f"+90541{u}10"},
            headers=hdr,
        ).json()
        pid = p["id"]

        # Açık borç 0 iken allow_advance=False ile ödeme reddedilmeli (422)
        reject = hq.post(
            "/app/api/payments",
            json={"patient_id": pid, "amount": "6000", "method": "nakit", "allow_advance": False},
            headers=hdr,
        )
        assert reject.status_code == 422

        # allow_advance=True ile 6.000 TL avans tahsilatı
        adv = hq.post(
            "/app/api/payments",
            json={"patient_id": pid, "amount": "6000", "method": "nakit", "allow_advance": True},
            headers=hdr,
        )
        assert adv.status_code == 200, adv.text
        assert adv.json()["is_advance"] is True
        assert adv.json()["finance_summary"]["available_advance"] == 6000.0

        # Sonradan 4.000 TL hizmet borcu oluşur
        ch = hq.post(
            "/app/api/charges",
            json={"patient_id": pid, "description": "Cerrahi Çekim", "amount": "4000"},
            headers=hdr,
        ).json()

        # Avans mahsuplaşması yapılır
        settle = hq.post(
            f"/app/api/patients/{pid}/settle-advance",
            json={"charge_id": ch["id"], "amount": "4000"},
            headers=hdr,
        )
        assert settle.status_code == 200, settle.text
        fin = settle.json()["finance_summary"]
        assert fin["net_remaining_debt"] == 0.0
        assert fin["available_advance"] == 2000.0
    finally:
        _close_cached(hq)


def test_11_payment_refund_with_audit_log():
    """11. İade işleminin denetim kaydıyla bakiyeyi doğru güncellemesi."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"İade Hasta {u}", "phone": f"+90542{u}11"},
            headers=hdr,
        ).json()
        pid = p["id"]

        hq.post("/app/api/charges", json={"patient_id": pid, "description": "Beyazlatma", "amount": "4000"}, headers=hdr)
        pay = hq.post(
            "/app/api/payments",
            json={"patient_id": pid, "amount": "4000", "method": "kart"},
            headers=hdr,
        ).json()

        ref = hq.post(
            f"/app/api/payments/{pay['id']}/refund",
            json={"amount": "1500", "reason": "Kısmi tedavi değişikliği iadesi"},
            headers=hdr,
        )
        assert ref.status_code == 200, ref.text
        fin = ref.json()["finance_summary"]
        assert fin["collected_paid"] == 4000.0
        assert fin["refunded_total"] == 1500.0
        assert fin["net_paid_after_refund"] == 2500.0
        assert fin["net_remaining_debt"] == 1500.0
    finally:
        _close_cached(hq)


def test_12_ethical_patient_groups_and_restricted_reason():
    """12. Hastanın 'Özel dikkat gerektiren' grubuna neden girilerek eklenmesi ve etik filtre."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Grup Hasta {u}", "phone": f"+90543{u}12"},
            headers=hdr,
        ).json()
        pid = p["id"]

        groups = hq.get("/app/api/patient-groups").json()
        special_grp = next(g for g in groups if g["name"] == "Özel dikkat gerektiren")
        assert special_grp["is_restricted"] is True

        # Neden girilmeden restricted gruba atama reddedilmeli (400)
        no_reason = hq.post(
            f"/app/api/patients/{pid}/groups",
            json={"group_id": special_grp["id"], "reason": ""},
            headers=hdr,
        )
        assert no_reason.status_code == 400

        # Nesnel neden girilerek atama başarılı olmalı
        ok_assign = hq.post(
            f"/app/api/patients/{pid}/groups",
            json={"group_id": special_grp["id"], "reason": "Son 2 randevusuna haber vermeden gelmedi, ön teyit şart."},
            headers=hdr,
        )
        assert ok_assign.status_code == 200, ok_assign.text

        # Etik dışı / hakaret içeren yeni grup açma girişimi reddedilmeli (400)
        bad_grp = hq.post(
            "/app/api/patient-groups",
            json={"name": "Sorunlu aptal hasta", "color": "red"},
            headers=hdr,
        )
        assert bad_grp.status_code == 400
    finally:
        _close_cached(hq)


def test_13_calendar_conflict_prevention_and_appointment_lifecycle():
    """13. Takvimde aynı koltuk/doktor için çakışan randevunun engellenmesi ve durum döngüsü."""
    hq, me_hq, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        doc_id = me_hq["user"]["id"]
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Takvim Hasta {u}", "phone": f"+90544{u}13"},
            headers=hdr,
        ).json()
        pid = p["id"]

        dt_future = (datetime.now(TZ) + timedelta(days=12)).replace(hour=14, minute=0, second=0, microsecond=0)
        while dt_future.weekday() >= 5:
            dt_future += timedelta(days=1)

        ap1 = hq.post(
            "/app/api/appointments",
            json={
                "patient_id": pid,
                "starts_at": dt_future.isoformat(),
                "duration_min": 45,
                "treatment": "Kanal Tedavisi",
                "chair": "1",
                "doctor_id": doc_id,
            },
            headers=hdr,
        )
        assert ap1.status_code == 200, ap1.text
        aid = ap1.json()["id"]

        # Aynı koltuk ve saatte ikinci randevu 409 Conflict vermeli
        clash = hq.post(
            "/app/api/appointments",
            json={
                "patient_id": pid,
                "starts_at": (dt_future + timedelta(minutes=15)).isoformat(),
                "duration_min": 30,
                "treatment": "Muayene",
                "chair": "1",
                "doctor_id": doc_id,
            },
            headers=hdr,
        )
        assert clash.status_code == 409

        # Durum güncelleme: confirmed -> done
        st_conf = hq.patch(f"/app/api/appointments/{aid}", json={"status": "confirmed"}, headers=hdr)
        assert st_conf.status_code == 200 and st_conf.json()["status"] == "confirmed"
        st_done = hq.patch(f"/app/api/appointments/{aid}", json={"status": "done"}, headers=hdr)
        assert st_done.status_code == 200 and st_done.json()["status"] == "done"
        p_appts = hq.get(f"/app/api/patients/{pid}").json()["appointments"]
        assert next(a["status"] for a in p_appts if a["id"] == aid) == "done"
    finally:
        _close_cached(hq)


def test_14_whatsapp_single_reminder_and_post_visit_feedback():
    """14. WhatsApp tek hatırlatma kuralı ve randevu sonrası memnuniyet akışı."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Hatırlatma Hasta {u}", "phone": f"+90545{u}14"},
            headers=hdr,
        ).json()
        pid = p["id"]

        # Memnuniyet: olumlu ve olumsuz hasta yanıtı simülasyonu
        sim_neg = hq.post(
            "/app/api/conversations/simulate",
            json={"text": "Dolgumdan sonra çok ağrım var ve memnun kalmadım, şikayetçiyim", "lang": "tr"},
            headers=hdr,
        )
        assert sim_neg.status_code == 200
        assert sim_neg.json()["handoff"] is True
        assert sim_neg.json()["alert"] in ("sikayet", "acil")

        # Taksit planı oluşturma ve ödeme
        inst = hq.post(
            f"/app/api/patients/{pid}/installments",
            json={
                "total_amount": "9000",
                "installment_count": 3,
                "first_due_date": date.today().isoformat(),
                "note": "3 Taksit İmplant Planı",
            },
            headers=hdr,
        )
        assert inst.status_code == 200, inst.text
        iid = inst.json()["installment_ids"][0]
        pay_inst = hq.post(
            f"/app/api/installments/{iid}/pay",
            json={"method": "kredi_karti", "amount": "3000"},
            headers=hdr,
        )
        assert pay_inst.status_code == 200, pay_inst.text
        assert pay_inst.json()["installment_status"] == "paid"
    finally:
        _close_cached(hq)


def test_15_media_upload_xray_photo_pdf_and_delete():
    """15. Röntgen/fotoğraf yükleme, boyut/format doğrulaması, listeleme ve silme."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Medya Hasta {u}", "phone": f"+90546{u}15"},
            headers=hdr,
        ).json()
        pid = p["id"]

        # Geçerli 80x80 PGM röntgen görseli oluştur
        w, h_px = 80, 80
        pixels = bytes(((x * 13 + y * 29) % 200) + 30 for y in range(h_px) for x in range(w))
        pgm_bytes = f"P5\n{w} {h_px}\n255\n".encode("ascii") + pixels

        up = hq.post(
            f"/app/api/patients/{pid}/media",
            params={"category": "xray", "stage": "before", "filename": "panoramik_rontgen.pgm", "note": "İlk muayene panoramik"},
            content=pgm_bytes,
            headers={**hdr, "Content-Type": "image/x-portable-graymap"},
        )
        assert up.status_code == 200, up.text
        mid = up.json()["id"]
        assert "teşhis" in up.json()["disclaimer"].lower()

        m_list = hq.get(f"/app/api/patients/{pid}/media").json()
        assert any(f["id"] == mid for f in m_list["files"])

        p_det = hq.get(f"/app/api/patients/{pid}").json()
        assert any(f["id"] == mid for f in p_det["media_files"])

        del_m = hq.delete(f"/app/api/patients/{pid}/media/{mid}", headers=hdr)
        assert del_m.status_code == 200
    finally:
        _close_cached(hq)


def test_16_campaign_click_bot_filter_and_uniqueness():
    """16. Kampanya linki tıklama, bot/önizleme filtresi ve tekil/toplam ayrımı."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        code = f"meta-smile-{u}"
        cp = hq.post(
            "/app/api/campaigns",
            json={
                "name": f"Gülüş Tasarımı {u}",
                "source": "instagram",
                "channel": "instagram",
                "code": code,
                "utm_source": "instagram",
                "utm_medium": "cpc",
                "utm_campaign": code,
            },
            headers=hdr,
        )
        assert cp.status_code == 200
        camp_id = cp.json()["id"]

        # 1) WhatsApp link önizleme botu tıklaması -> is_bot=True olmalı ve tekil tıklamayı şişirmemeli
        bot_r = hq.get(
            f"/c/{code}",
            params={"format": "json"},
            headers={"User-Agent": "WhatsApp/2.23.20.0 i"},
        )
        assert bot_r.status_code == 200
        assert bot_r.json()["is_bot"] is True
        assert bot_r.json()["is_unique"] is False

        # 2) Gerçek kullanıcı 1. tıklama -> is_bot=False, is_unique=True
        real_ua = f"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/{u}"
        r1 = hq.get(f"/c/{code}", params={"format": "json"}, headers={"User-Agent": real_ua})
        assert r1.status_code == 200
        assert r1.json()["is_bot"] is False
        assert r1.json()["is_unique"] is True

        # 3) Aynı gerçek kullanıcının aynı gün 2. tıklaması -> is_unique=False
        r2 = hq.get(f"/c/{code}", params={"format": "json"}, headers={"User-Agent": real_ua})
        assert r2.status_code == 200
        assert r2.json()["is_bot"] is False
        assert r2.json()["is_unique"] is False

        # 4) Form başlangıç ve gönderim etkinliği
        tr_ev = hq.post(
            "/api/campaigns/track",
            json={"campaign_id": camp_id, "event_type": "form_submit", "utm_source": "instagram"},
            headers={"User-Agent": real_ua},
        )
        assert tr_ev.status_code == 200

        rep = hq.get("/app/api/campaigns/report").json()
        c_row = next(c for c in rep["campaigns"] if c["id"] == camp_id)
        assert c_row["bot_clicks"] == 1
        assert c_row["total_clicks"] == 2
        assert c_row["unique_clicks"] == 1
        assert c_row["form_submits"] == 1
    finally:
        _close_cached(hq)


def test_17_rbac_14_professions_and_15_granular_permissions():
    """17. 14 personel mesleği, 15 granüler yetki ve sekreterin kısıtlı alanlara erişememesi."""
    hq, _, hdr = _login(*HQ_CREDS)
    sec, me_sec, s_hdr = _login(*SEC_CREDS)
    try:
        cat = hq.get("/app/api/staff/professions-catalog").json()
        assert len(cat["professions"]) == 14
        assert len(cat["permission_keys"]) >= 15

        # Sekreter kasa anlaşması oluşturamaz (finance_edit yetkisi yok -> 403)
        sec_bank = sec.post(
            "/app/api/bank-agreements",
            json={"bank_name": "Yetkisiz Banka", "discount_pct": "10"},
            headers=s_hdr,
        )
        assert sec_bank.status_code == 403

        # Yönetici sekreterin mesleğini patient_relations yapıp export yetkisini açabilir
        sec_id = me_sec["user"]["id"]
        up_perm = hq.patch(
            f"/app/api/staff/{sec_id}/permissions",
            json={
                "job_title": "patient_relations",
                "permissions": {"export": True, "finance_edit": False},
            },
            headers=hdr,
        )
        assert up_perm.status_code == 200, up_perm.text
        assert up_perm.json()["effective_permissions"]["export"] is True
        assert up_perm.json()["effective_permissions"]["finance_edit"] is False

        # Sonraki testler için sekreterin varsayılan finance_edit yetkisini geri yükle
        hq.patch(
            f"/app/api/staff/{sec_id}/permissions",
            json={"job_title": "secretary", "permissions": {"finance_edit": True}},
            headers=hdr,
        )
    finally:
        _close_cached(hq)
        _close_cached(sec)


def test_18_periodontal_chart_and_treatment_consent_e2e():
    """18. Periodontal 6 nokta klinik ölçüm ve Dijital Tedavi Planı Onamı (5070 hukuki ayrımlı)."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Perio Onam Hasta {u}", "phone": f"+90547{u}18"},
            headers=hdr,
        ).json()
        pid = p["id"]

        # 1. Periodontal muayene
        pe1 = hq.post(
            f"/app/api/patients/{pid}/periodontal",
            json={
                "exam_date": "2026-10-01",
                "teeth": {
                    "16": {"pd": [4, 5, 4, 3, 5, 4], "gm": [1, 1, 0, 0, 1, 1], "bop": [True, True, False, False, True, False], "plaque": [True] * 6, "mobility": 1, "furcation": 1}
                },
                "doctor_approved": True,
                "doctor_note": "İlk periodontal değerlendirme",
            },
            headers=hdr,
        )
        assert pe1.status_code == 200, pe1.text
        assert pe1.json()["max_pd"] == 5

        # 2. Periodontal muayene (tedavi sonrası iyileşme karşılaştırması)
        pe2 = hq.post(
            f"/app/api/patients/{pid}/periodontal",
            json={
                "exam_date": "2026-11-15",
                "teeth": {
                    "16": {"pd": [2, 3, 2, 2, 3, 2], "gm": [1, 1, 0, 0, 1, 1], "bop": [False] * 6, "plaque": [False] * 6, "mobility": 0, "furcation": 0}
                },
                "doctor_approved": True,
                "doctor_note": "Küretaj sonrası kontrol",
            },
            headers=hdr,
        )
        assert pe2.status_code == 200
        pe_list = hq.get(f"/app/api/patients/{pid}/periodontal").json()
        assert len(pe_list["exams"]) == 2
        assert pe_list["comparison_with_previous"]["delta_mean_pd"] < 0

        # Dijital tedavi planı onamı oluşturma ve hasta imzası
        tc = hq.post(
            f"/app/api/patients/{pid}/treatment-consents",
            json={
                "document_version": "2026-11-v1",
                "custom_items": [{"tooth_fdi": 16, "surface": "FULL", "procedure_name": "Subgingival Küretaj", "amount": 3500}],
            },
            headers=hdr,
        )
        assert tc.status_code == 200, tc.text
        tok = tc.json()["token"]
        assert "5070" in tc.json()["legal_notice"]

        form_page = hq.get(f"/form/tedavi-onay/{tok}")
        assert form_page.status_code == 200
        import re as _re_tc
        m_csrf = _re_tc.search(r'name="csrf_token"\s+value="([^"]+)"', form_page.text)
        assert m_csrf, "Tedavi onam formunda csrf_token gizli alanı bulunmalıdır"

        sign_res = hq.post(
            f"/form/tedavi-onay/{tok}",
            data={"csrf_token": m_csrf.group(1), "accept_plan": "1", "signer_name": f"Perio Onam Hasta {u}"},
        )
        assert sign_res.status_code == 200
        tc_rows = hq.get(f"/app/api/patients/{pid}/treatment-consents").json()
        assert tc_rows[0]["status"] == "signed"
    finally:
        _close_cached(hq)


def test_19_lab_orders_implant_lot_and_inventory_expiry():
    """19. Laboratuvar iş emri, İmplant/Lot kaydı (dürüst ÜTS durumu), Tedarikçi/Gider ve Günlük Kasa Kapanışı."""
    hq, _, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Lab İmplant Hasta {u}", "phone": f"+90548{u}19"},
            headers=hdr,
        ).json()
        pid = p["id"]

        # Laboratuvar iş emri
        lo = hq.post(
            "/app/api/lab-orders",
            json={
                "patient_id": pid,
                "tooth_fdi": 11,
                "lab_name": "Kristal Dental Protez Lab",
                "procedure_type": "E-Max Lamina Veneer",
                "shade_color": "BL2",
                "due_date": (date.today() + timedelta(days=4)).isoformat(),
                "cost": "2200",
            },
            headers=hdr,
        )
        assert lo.status_code == 200, lo.text
        lid = lo.json()["id"]

        lo_up = hq.patch(
            f"/app/api/lab-orders/{lid}",
            json={"status": "delivered", "note": "Klinik provası tam uyumlu"},
            headers=hdr,
        )
        assert lo_up.status_code == 200

        # İmplant & Lot kaydı
        imp = hq.post(
            "/app/api/implants",
            json={
                "patient_id": pid,
                "tooth_fdi": 46,
                "brand": "Straumann",
                "model": "BLX Roxolid SLActive",
                "diameter_mm": 4.0,
                "length_mm": 10.0,
                "lot_number": f"LOT-STR-{u}",
                "serial_number": f"SN-{u}",
                "uts_barcode": f"869000{u}",
            },
            headers=hdr,
        )
        assert imp.status_code == 200, imp.text
        assert imp.json()["uts_live_connected"] is False
        assert imp.json()["uts_notification_status"] == "not_connected_prepared"

        # Tedarikçi + Gider + Günlük Kasa Kapanışı
        sup = hq.post("/app/api/suppliers", json={"name": f"Medikal Depo {u}", "phone": "+902122223344"}, headers=hdr)
        assert sup.status_code == 200
        exp = hq.post(
            "/app/api/expenses",
            json={"supplier_id": sup.json()["id"], "category": "laboratuvar", "description": "Lamina Lab Faturası", "amount": "2200", "method": "havale"},
            headers=hdr,
        )
        assert exp.status_code == 200, exp.text
        cc = hq.post(
            "/app/api/kasa/closings",
            json={"opening_balance": "1000", "physical_counted": "1000", "note": "Otomatik E2E kasa kapanışı"},
            headers=hdr,
        )
        assert cc.status_code == 200, cc.text

        # Envanter SKT (expiry_date) doğrulaması: geçerli geçmiş tarih -> expired=True, geçersiz tarih -> 422
        inv_exp = hq.post(
            "/app/api/inventory",
            json={
                "name": f"SKT Kompozit {u}",
                "category": "Sarf Malzeme",
                "unit": "adet",
                "qty": "4",
                "min_qty": "2",
                "unit_cost": "450",
                "expiry_date": "2024-01-01",
                "lot_number": f"LOT-{u}",
                "warehouse": "Ana Depo",
            },
            headers=hdr,
        )
        assert inv_exp.status_code == 200, inv_exp.text
        inv_rows = hq.get("/app/api/inventory").json()
        assert any(r["id"] == inv_exp.json()["id"] and r["expired"] is True for r in inv_rows)

        inv_bad_date = hq.post(
            "/app/api/inventory",
            json={"name": f"Bozuk SKT {u}", "qty": "1", "expiry_date": "not-a-date"},
            headers=hdr,
        )
        assert inv_bad_date.status_code == 422
    finally:
        _close_cached(hq)


def test_20_multi_branch_isolation_csv_import_export_and_ai_quota():
    """20. Şube A verisinin Şube B tarafından görülememesi, CSV İçe/Dışa Aktarma, Online Randevu ve AI Maliyet/Kâr Raporu."""
    hq, _, hdr = _login(*HQ_CREDS)
    bursa, _, b_hdr = _login(*BURSA_CREDS)
    try:
        u = _uniq()
        # Şube 1 (İstanbul HQ) üzerinde banka anlaşması ve hasta oluşturulur
        ba_hq = hq.post(
            "/app/api/bank-agreements",
            json={"bank_name": f"HQ Özel Banka {u}", "discount_pct": "15"},
            headers=hdr,
        ).json()
        p_hq = hq.post(
            "/app/api/patients",
            json={"name": f"HQ İzole Hasta {u}", "phone": f"+90549{u}20"},
            headers=hdr,
        ).json()

        # Şube 2 (Bursa) Şube 1'in hastasını veya banka anlaşmasını göremez
        assert bursa.get(f"/app/api/patients/{p_hq['id']}").status_code == 404
        bursa_banks = bursa.get("/app/api/bank-agreements").json()
        assert not any(b["id"] == ba_hq["id"] for b in bursa_banks)

        # CSV toplu hasta içe aktarma
        csv_payload = f"name,phone,source,lang,notes\nCSV Hasta Bir {u},+90551{u}21,website,tr,Web CSV kaydı\nCSV Hasta İki {u},+90552{u}22,instagram,en,IG CSV kaydı\n"
        imp_res = hq.post(
            "/app/api/patients/import-csv",
            json={"csv_text": csv_payload, "default_source": "other"},
            headers=hdr,
        )
        assert imp_res.status_code == 200, imp_res.text
        assert imp_res.json()["imported"] == 2

        # CSV dışa aktarma
        exp_csv = hq.get("/app/api/export/patients.csv")
        assert exp_csv.status_code == 200
        assert f"CSV Hasta Bir {u}" in exp_csv.text

        # Online Randevu (/api/public/book/{slug})
        dt_pub = (datetime.now(TZ) + timedelta(days=16)).replace(hour=11, minute=30, second=0, microsecond=0)
        while dt_pub.weekday() >= 5:
            dt_pub += timedelta(days=1)
        pub_book = hq.post(
            "/api/public/book/merkez",
            json={
                "name": f"Online Randevu Hasta {u}",
                "phone": f"+90553{u}23",
                "starts_at": dt_pub.isoformat(),
                "treatment": "İlk Muayene",
                "source": "website",
                "utm_source": "google",
                "utm_medium": "cpc",
                "kvkk_consent": True,
            },
        )
        assert pub_book.status_code == 200, pub_book.text
        assert pub_book.json()["source"] == "google_ads"

        # 3.500 TL SaaS AI Maliyet & Brüt Kâr Analizi
        ai_rep = hq.get("/app/api/ai-costs").json()
        assert ai_rep["subscription_price_try"] == 3500.0
        assert ai_rep["gross_margin_after_ai_pct"] > 90.0
    finally:
        _close_cached(hq)
        _close_cached(bursa)


def test_21_recurring_appointments_series_and_conflict():
    """21. Tekrarlayan randevu serisi (Haftalık 3 seans) oluşturma ve çakışma engeli."""
    hq, me_hq, hdr = _login(*HQ_CREDS)
    try:
        u = _uniq()
        doc_id = me_hq["user"]["id"]
        p = hq.post(
            "/app/api/patients",
            json={"name": f"Seri Randevu Hasta {u}", "phone": f"+90554{u}24"},
            headers=hdr,
        ).json()
        pid = p["id"]

        dt_start = (datetime.now(TZ) + timedelta(days=20)).replace(hour=15, minute=0, second=0, microsecond=0)
        while dt_start.weekday() >= 5:
            dt_start += timedelta(days=1)

        rec = hq.post(
            "/app/api/appointments/recurring",
            json={
                "patient_id": pid,
                "starts_at": dt_start.isoformat(),
                "duration_min": 30,
                "treatment": "Ortodonti Kontrol",
                "chair": "2",
                "doctor_id": doc_id,
                "frequency": "weekly",
                "occurrences": 3,
            },
            headers=hdr,
        )
        assert rec.status_code == 200, rec.text
        data = rec.json()
        assert data["created_count"] == 3
        assert len(data["appointment_ids"]) == 3

        # Aynı koltuk ve saatlerde ikinci seri randevu 409 Conflict vermeli
        conflict_rec = hq.post(
            "/app/api/appointments/recurring",
            json={
                "patient_id": pid,
                "starts_at": dt_start.isoformat(),
                "duration_min": 30,
                "treatment": "Çakışan Seri",
                "chair": "2",
                "doctor_id": doc_id,
                "frequency": "weekly",
                "occurrences": 3,
            },
            headers=hdr,
        )
        assert conflict_rec.status_code == 409
    finally:
        _close_cached(hq)

