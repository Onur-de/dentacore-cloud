"""Tur 3 düzeltmeleri için kapsamlı doğrulama testleri (SEC-03/04/06/08/10/11/12/13, TECH-01..05, KOP-02/04, UX-12)."""
from __future__ import annotations

import asyncio
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "api"))

BASE = os.environ.get("DENTACORE_URL", "http://127.0.0.1:8794").rstrip("/")
DB_PATH = Path(os.environ.get("DC_DB_PATH") or (ROOT / "dentacore_local.db"))
TZ = ZoneInfo("Europe/Istanbul")

HQ_CREDS = ("yonetici@dentacore.com", "DentaCore2026!")
SEC_CREDS = ("sekreter@dentacore.com", "DentaCore2026!")
BURSA_CREDS = ("klinik@bursadis.com", "BursaDis2026!")


def _login(email: str, password: str) -> tuple[httpx.Client, dict, dict]:
    c = httpx.Client(base_url=BASE, timeout=25.0)
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"Login başarısız ({email}): {r.status_code} {r.text}"
    me = c.get("/auth/me").json()
    return c, me, {"X-CSRF-Token": me["csrf"]}


def _next_weekday_slot(c: httpx.Client, days_ahead: int = 4) -> dict:
    cur = (datetime.now(TZ) + timedelta(days=days_ahead)).replace(hour=10, minute=0, second=0, microsecond=0)
    for _ in range(20):
        while cur.weekday() >= 5:
            cur += timedelta(days=1)
        r = c.get("/app/api/appointments/available", params={"date": cur.strftime("%Y-%m-%d"), "duration": 30})
        if r.status_code == 200 and not r.json().get("closed") and r.json().get("slots"):
            return r.json()["slots"][0]
        cur += timedelta(days=1)
    raise AssertionError("Boş slot bulunamadı")


def test_sec11_sec04_message_encryption_and_delete_cleanup():
    bursa, _, b_hdr = _login(*BURSA_CREDS)
    try:
        uniq = int(time.time() * 1000) % 100000
        p = bursa.post(
            "/app/api/patients",
            json={"phone": f"+90538{uniq:05d}11", "name": f"Kripto Silme {uniq}", "lang": "tr"},
            headers=b_hdr,
        )
        assert p.status_code == 200
        pid = p.json()["id"]

        secret_msg = f"Sayın Kripto Hasta {uniq}, Coumadin ve penisilin alerjiniz kontrol edildi."
        s_res = bursa.post(f"/app/api/conversations/{pid}/send", json={"text": secret_msg}, headers=b_hdr)
        assert s_res.status_code == 200 and s_res.json()["ok"] is True

        # Diskteki sqlite3 satırında düz metin olmamalı (Fernet şifreli)
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT body FROM message_log WHERE patient_id=?", (pid,)).fetchall()
        assert len(rows) >= 1
        for row in rows:
            body_disk = row["body"] or ""
            assert "Coumadin" not in body_disk and "penisilin" not in body_disk
            assert body_disk.startswith("gAAAAA"), f"message_log.body Fernet şifreli olmalı: {body_disk[:30]}"
        conn.close()

        # API üzerinden çözülmüş metin ve son yön okunmalı (SEC-11 + KOP-04)
        msgs = bursa.get(f"/app/api/conversations/{pid}/messages").json()
        assert any(m["body"] == secret_msg for m in msgs)
        convs = bursa.get("/app/api/conversations").json()
        conv_row = next(c for c in convs if c["id"] == pid)
        assert conv_row["last_body"] == secret_msg
        assert conv_row["last_dir"] == "out"

        # Waitlist + slot_offer + postop_checks oluştur, sonra DELETE /patients/{pid} çağır
        wl = bursa.post("/app/api/waitlist", json={"patient_id": pid, "treatment": "Kanal"}, headers=b_hdr)
        assert wl.status_code == 200
        wid = wl.json()["id"]
        po = bursa.post("/app/api/postop/schedule", json={"patient_id": pid, "procedure": "Diş Çekimi"}, headers=b_hdr)
        assert po.status_code == 200

        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO slot_offers (appointment_id, waitlist_id, wave, sent_at, status) VALUES (1, ?, 1, ?, 'sent')",
            (wid, datetime.now(TZ).isoformat()),
        )
        conn.commit()
        conn.close()

        del_res = bursa.delete(f"/app/api/patients/{pid}", headers=b_hdr)
        assert del_res.status_code == 200 and del_res.json()["anonymized"] is True

        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        m_after = conn.execute("SELECT body FROM message_log WHERE patient_id=?", (pid,)).fetchall()
        assert all((r["body"] or "") == "" for r in m_after), "Silinen hastanın message_log.body alanı temizlenmeli"
        so_cnt = conn.execute("SELECT count(*) FROM slot_offers WHERE waitlist_id=?", (wid,)).fetchone()[0]
        po_cnt = conn.execute("SELECT count(*) FROM postop_checks WHERE patient_id=?", (pid,)).fetchone()[0]
        tok_cnt = conn.execute("SELECT count(*) FROM anamnesis_tokens WHERE patient_id=?", (pid,)).fetchone()[0]
        conn.close()
        assert so_cnt == 0 and po_cnt == 0 and tok_cnt == 0
    finally:
        bursa.close()


def test_tech02_create_appt_no_phantom_patient_on_conflict():
    hq, _, hq_hdr = _login(*HQ_CREDS)
    try:
        slot = _next_weekday_slot(hq, days_ahead=6)
        chair = slot["available_chairs"][0]
        p_ok = hq.post("/app/api/patients", json={"phone": "+905319991101", "name": "Dolu Koltuk Sahibi"}, headers=hq_hdr)
        assert p_ok.status_code == 200
        a_ok = hq.post(
            "/app/api/appointments",
            json={"patient_id": p_ok.json()["id"], "starts_at": slot["starts_at"], "duration_min": 30, "treatment": "Dolgu", "chair": chair},
            headers=hq_hdr,
        )
        assert a_ok.status_code == 200

        phantom_phone = "+905319998877"
        phantom_name = "Hayalet Hasta Tech02"
        r_clash = hq.post(
            "/app/api/appointments",
            json={"phone": phantom_phone, "name": phantom_name, "starts_at": slot["starts_at"], "duration_min": 30, "treatment": "Muayene", "chair": chair},
            headers=hq_hdr,
        )
        assert r_clash.status_code == 409

        # Ardından başka bir yazma işlemi yap (sızıntı olsaydı commitlenirdi)
        hq.post("/app/api/patients", json={"phone": "+905319991102", "name": "Commit Tetikleyici"}, headers=hq_hdr)

        pts = hq.get("/app/api/patients", params={"include_archived": "true"}).json()
        assert not any(p["display_name"] == phantom_name for p in pts), "409 sonrası hayalet hasta oluşmamalı"
    finally:
        hq.close()


def test_tech03_postop_pain_score_never_cancels_or_confirms_appt():
    hq, _, hq_hdr = _login(*HQ_CREDS)
    try:
        uniq = int(time.time() * 1000) % 100000
        p = hq.post("/app/api/patients", json={"phone": f"+90534{uniq:05d}22", "name": f"Postop Hasta {uniq}"}, headers=hq_hdr)
        pid = p.json()["id"]
        slot = _next_weekday_slot(hq, days_ahead=7)
        a_res = hq.post(
            "/app/api/appointments",
            json={"patient_id": pid, "starts_at": slot["starts_at"], "duration_min": 30, "treatment": "Kontrol", "chair": slot["available_chairs"][0]},
            headers=hq_hdr,
        )
        assert a_res.status_code == 200
        aid = a_res.json()["id"]

        # Aktif post-op kontrolü varken "2" yanıtı randevuyu iptal etmemeli, ağrı skoru olarak kaydedilmeli
        po = hq.post("/app/api/postop/schedule", json={"patient_id": pid, "procedure": "20 Yaş Çekim"}, headers=hq_hdr)
        assert po.status_code == 200
        _po_id = po.json()["ids"][0]

        rep2 = hq.post("/app/api/conversations/simulate", json={"patient_id": pid, "text": "2"}, headers=hq_hdr)
        assert rep2.status_code == 200
        assert rep2.json()["intent"] == "postop", f"Beklenen postop, gelen: {rep2.json()}"

        pat_detail = hq.get(f"/app/api/patients/{pid}").json()
        st = next(a["status"] for a in pat_detail["appointments"] if a["id"] == aid)
        assert st == "booked", f"Post-op '2' yanıtı randevuyu iptal/teyit etmemeli: {st}"

        conn = sqlite3.connect(DB_PATH)
        pains = [r[0] for r in conn.execute("SELECT pain_score FROM postop_checks WHERE patient_id=? AND pain_score IS NOT NULL", (pid,)).fetchall()]
        conn.close()
        assert pains == [2]

        # Post-op kapalıyken bile "1" veya "2" tek başına randevu teyit/iptal olmamalı
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM postop_checks WHERE patient_id=?", (pid,))
        conn.commit()
        conn.close()
        rep1 = hq.post("/app/api/conversations/simulate", json={"patient_id": pid, "text": "1"}, headers=hq_hdr)
        assert rep1.json()["intent"] != "teyit"
        pat_detail2 = hq.get(f"/app/api/patients/{pid}").json()
        assert next(a["status"] for a in pat_detail2["appointments"] if a["id"] == aid) == "booked"

        # Tam kelime "EVET" teyit etmeli
        rep_yes = hq.post("/app/api/conversations/simulate", json={"patient_id": pid, "text": "EVET"}, headers=hq_hdr)
        assert rep_yes.json()["intent"] == "teyit"
    finally:
        hq.close()


def test_tech04_expired_slot_offer_does_not_hijack_confirm():
    hq, _, hq_hdr = _login(*HQ_CREDS)
    try:
        uniq = int(time.time() * 1000) % 100000
        p = hq.post("/app/api/patients", json={"phone": f"+90535{uniq:05d}33", "name": f"Teklif Hasta {uniq}"}, headers=hq_hdr)
        pid = p.json()["id"]

        slot1 = _next_weekday_slot(hq, days_ahead=8)
        a_fut = hq.post(
            "/app/api/appointments",
            json={"patient_id": pid, "starts_at": slot1["starts_at"], "duration_min": 30, "treatment": "Kendi Randevusu", "chair": slot1["available_chairs"][0]},
            headers=hq_hdr,
        ).json()["id"]

        # Başka bir iptal edilmiş randevu ve süresi dolmuş (expires_at geçmişte) ama status='sent' kalmış teklif
        slot2 = _next_weekday_slot(hq, days_ahead=9)
        p_other = hq.post("/app/api/patients", json={"phone": f"+90535{uniq:05d}34", "name": f"Diğer {uniq}"}, headers=hq_hdr).json()["id"]
        a_can = hq.post(
            "/app/api/appointments",
            json={"patient_id": p_other, "starts_at": slot2["starts_at"], "duration_min": 30, "treatment": "İptal Slotu", "chair": slot2["available_chairs"][0]},
            headers=hq_hdr,
        ).json()["id"]
        hq.post(f"/app/api/appointments/{a_can}/status", json={"status": "cancelled"}, headers=hq_hdr)
        wid = hq.post("/app/api/waitlist", json={"patient_id": pid, "treatment": "herhangi"}, headers=hq_hdr).json()["id"]

        past_iso = (datetime.now(TZ) - timedelta(minutes=10)).isoformat()
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO slot_offers (appointment_id, waitlist_id, wave, sent_at, expires_at, status) VALUES (?, ?, 1, ?, ?, 'sent')",
            (a_can, wid, datetime.now(TZ).isoformat(), past_iso),
        )
        conn.commit()
        conn.close()

        res = hq.post("/app/api/conversations/simulate", json={"patient_id": pid, "text": "EVET"}, headers=hq_hdr)
        assert res.status_code == 200
        assert res.json()["intent"] == "teyit", f"Süresi dolmuş teklif randevu teyidini gasp etmemeli: {res.json()}"
        pat_d = hq.get(f"/app/api/patients/{pid}").json()
        assert next(a["status"] for a in pat_d["appointments"] if a["id"] == a_fut) == "confirmed"
    finally:
        hq.close()


def test_tech05_scheduler_lock_and_failed_delivery_retry(tmp_path):
    # İzole geçici SQLite DB ile modül içi _SCHED_LOCK ve failed -> retry davranışını doğrula
    import run_local as rl

    assert isinstance(rl._SCHED_LOCK, asyncio.Lock)
    saved_db_path = rl.DB_PATH
    saved_conn = rl._CONN
    tmp_db = tmp_path / "sched_tech05.db"
    rl.DB_PATH = tmp_db
    rl._CONN = None
    orig_deliver = rl._deliver_wa
    try:
        rl.init_and_seed()
        rl.ex("UPDATE appointments SET reminder_sent_at=?", rl.iso_now())
        # 24 saat sonrasına bir booked randevu ekle (hafta içi öğlen)
        now_loc = datetime.now(TZ).replace(hour=12, minute=0, second=0, microsecond=0)
        while now_loc.weekday() >= 5:
            now_loc += timedelta(days=1)
        appt_dt = now_loc + timedelta(hours=24)
        aid = rl.ex(
            "INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,status,source,created_at) VALUES (1,1,?,30,'Tech05 Test','1','booked','panel',?)",
            appt_dt.isoformat(), rl.iso_now(),
        )

        # 1) failed teslimatta reminder_sent_at işaretlenmemeli
        async def fail_deliver(*args, **kwargs):
            return {"ok": False, "status": "failed", "dry_run": False, "error": "net_err", "raw": {}}

        rl._deliver_wa = fail_deliver
        res_fail = asyncio.run(rl._run_scheduler_tick(clinic_id=1, now_dt=now_loc, respect_hours=False))
        assert res_fail["reminders_sent"] == 0
        row_a = rl.q1("SELECT reminder_sent_at FROM appointments WHERE id=?", aid)
        assert row_a["reminder_sent_at"] is None, "failed teslimatta reminder_sent_at işaretlenmemeli"

        # 2) İki eşzamanlı tick çalıştırıldığında yalnız 1 kez göndermeli
        calls = 0

        async def slow_ok_deliver(*args, **kwargs):
            nonlocal calls
            if kwargs.get("intent") == "hatirlatma":
                calls += 1
            await asyncio.sleep(0.05)
            return {"ok": True, "status": "dry_run", "dry_run": True, "error": None, "raw": {}}

        rl._deliver_wa = slow_ok_deliver

        async def run_two():
            return await asyncio.gather(
                rl._run_scheduler_tick(clinic_id=1, now_dt=now_loc, respect_hours=False),
                rl._run_scheduler_tick(clinic_id=1, now_dt=now_loc, respect_hours=False),
            )

        r1, r2 = asyncio.run(run_two())
        assert r1["reminders_sent"] + r2["reminders_sent"] == 1
        assert calls == 1
        row_a2 = rl.q1("SELECT reminder_sent_at FROM appointments WHERE id=?", aid)
        assert row_a2["reminder_sent_at"] is not None
    finally:
        rl._deliver_wa = orig_deliver
        if rl._CONN is not None:
            rl._CONN.close()
        rl._CONN = saved_conn
        rl.DB_PATH = saved_db_path


def test_kop02_date_filters_in_overview_and_analytics():
    bursa, _, _ = _login(*BURSA_CREDS)
    try:
        ov_before = bursa.get("/app/api/overview").json()
        an_before = bursa.get("/app/api/analytics").json()

        old_45d = (datetime.now(TZ) - timedelta(days=45)).isoformat()
        old_15d = (datetime.now(TZ) - timedelta(days=15)).isoformat()
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO charges (clinic_id,patient_id,description,amount_kurus,created_at) VALUES (2,5,'Eski Hizmet',9990000,?)",
            (old_45d,),
        )
        conn.execute(
            "INSERT INTO payments (clinic_id,patient_id,amount_kurus,method,created_at) VALUES (2,5,8880000,'nakit',?)",
            (old_45d,),
        )
        conn.execute(
            "INSERT INTO appointments (clinic_id,patient_id,starts_at,duration_min,treatment,chair,status,source,created_at) VALUES (2,5,?,30,'Eski Noshow','1','noshow','panel',?)",
            (old_45d, old_45d),
        )
        conn.execute(
            "INSERT INTO postop_checks (patient_id,procedure,due_at,stage,sent_at,pain_score,answered_at,alarm) VALUES (5,'Eski Alarm',?,'2s',?,9,?,1)",
            (old_15d, old_15d, old_15d),
        )
        conn.commit()
        conn.close()

        ov_after = bursa.get("/app/api/overview").json()
        an_after = bursa.get("/app/api/analytics").json()
        assert ov_after["month"]["billed_try"] == ov_before["month"]["billed_try"]
        assert ov_after["month"]["paid_try"] == ov_before["month"]["paid_try"]
        assert ov_after["attendance_30d"]["noshow"] == ov_before["attendance_30d"]["noshow"]
        assert ov_after["counts"]["postop_alarms"] == ov_before["counts"]["postop_alarms"]
        assert an_after["total_appts_30d"] == an_before["total_appts_30d"]
    finally:
        bursa.close()


def test_sec03_sec06_sec08_sec10_sec12_sec13_and_ux12():
    from app import cal

    # SEC-06: .ics ve google_calendar_url tıbbi işlem adı (treatment) içermemeli
    sample_appt = {
        "id": 99,
        "starts_at": "2026-11-20T14:30:00+03:00",
        "duration_min": 45,
        "treatment": "Yirmi Yaş Cerrahi Çekim",
        "chair": "1",
        "patient": "Ayşe Kaya",
        "doctor": "Dt. Onur",
        "status": "booked",
    }
    ics_txt = cal.appointment_ics(sample_appt, "Klinik", "Adres")
    g_url = cal.google_calendar_url(sample_appt, "Klinik", "Adres")
    assert "Yirmi Yaş" not in ics_txt and "Cerrahi" not in ics_txt and "Diş Randevusu" in ics_txt
    assert "Yirmi" not in g_url and "Di%C5%9F+Randevusu" in g_url

    hq, _, hq_hdr = _login(*HQ_CREDS)
    sec_c, _, sec_hdr = _login(*SEC_CREDS)
    bursa, _, b_hdr = _login(*BURSA_CREDS)
    try:
        # SEC-08: Sekreter alerts ve hasta detayında tıbbi detay maskeli olmalı
        al_sec = sec_c.get("/app/api/alerts").json()
        for a in al_sec:
            if a.get("kind") in ("anamnez_kirmizi", "postop_alarm", "acil"):
                assert "kan_sulandirici" not in a["detail"] and "penisilin" not in a["detail"]
                assert "Klinik Uyarı (Hekim Kontrolü)" in a["detail"]
        p1_sec = sec_c.get("/app/api/patients/1").json()
        assert p1_sec["anamnesis"] and p1_sec["anamnesis"][0]["red_flags"] == ["Klinik Uyarı (Hekim Kontrolü)"]
        p1_hq = hq.get("/app/api/patients/1").json()
        assert "kan_sulandirici" in p1_hq["anamnesis"][0]["red_flags"]

        # SEC-10: google_review_url şema doğrulaması
        cur_b = bursa.get("/app/api/settings").json()
        bad_url = bursa.post(
            "/app/api/settings",
            json={"name": cur_b["name"], "city": cur_b["city"], "google_review_url": "javascript:alert(1)"},
            headers=b_hdr,
        )
        assert bad_url.status_code == 400

        # SEC-12: Aynı wa_phone_id başka klinikte 409 dönmeli
        cur_hq = hq.get("/app/api/settings").json()
        hq.post(
            "/app/api/settings",
            json={"name": cur_hq["name"], "city": cur_hq["city"], "wa_phone_id": "wa-hq-unique-8794", "ig_handle": "ig-hq-unique-8794"},
            headers=hq_hdr,
        )
        dup_wa = bursa.post(
            "/app/api/settings",
            json={"name": cur_b["name"], "city": cur_b["city"], "wa_phone_id": "wa-hq-unique-8794"},
            headers=b_hdr,
        )
        assert dup_wa.status_code == 409
        dup_ig = bursa.post(
            "/app/api/settings",
            json={"name": cur_b["name"], "city": cur_b["city"], "ig_handle": "ig-hq-unique-8794"},
            headers=b_hdr,
        )
        assert dup_ig.status_code == 409

        # SEC-03: yurt_disi_aktarim rızası yokken allow_llm=False olmalı
        import run_local as rl
        assert rl._has_consent(1, "yurt_disi_aktarim") is False

        # UX-12: /form/anamnez/{token} ve /form/geri-bildirim novalidate + validate.js + 400 ana sayfaya dönüş butonu
        lnk = hq.post("/app/api/patients/1/anamnesis", headers=hq_hdr).json()["link"]
        form_path = "/" + lnk.split("/", 3)[-1]
        with httpx.Client(base_url=BASE, timeout=15.0) as anon:
            g_anam = anon.get(form_path)
            assert g_anam.status_code == 200
            assert "novalidate" in g_anam.text and "/form/validate.js" in g_anam.text
            bad_anam = anon.post(form_path, data={"imza": "X"})
            assert bad_anam.status_code == 400 and 'href="/"' in bad_anam.text and "Ana Sayfaya Dön" in bad_anam.text

            g_fb = anon.get("/form/geri-bildirim")
            assert g_fb.status_code == 200 and "novalidate" in g_fb.text and "<textarea" in g_fb.text and "/form/validate.js" in g_fb.text
            js_r = anon.get("/form/validate.js")
            assert js_r.status_code == 200 and "Lütfen bu soruyu yanıtlayın" in js_r.text

        # SEC-13: Rate limiter kontrolü (/app/api/reminders/send 20/60s sınırı sonrası 429)
        statuses_rem = []
        for _ in range(22):
            rr = bursa.post("/app/api/reminders/send", json={"force": False}, headers=b_hdr)
            statuses_rem.append(rr.status_code)
            if rr.status_code == 429:
                break
        assert 429 in statuses_rem, f"SEC-13: /reminders/send hız sınırı 429 dönmeli: {statuses_rem}"
    finally:
        hq.close()
        sec_c.close()
        bursa.close()


def test_tech01_postgres_parity_and_modules_work_hours():
    from app import modules, panel

    # StatusIn 'booked' içermeli; SettingsIn wa_phone_id & ig_handle içermeli
    assert panel.StatusIn(status="booked").status == "booked"
    s_in = panel.SettingsIn(name="Test Klinik", wa_phone_id="wa-123", ig_handle="ig-123")
    assert s_in.wa_phone_id == "wa-123" and s_in.ig_handle == "ig-123"

    # panel.router içinde 5 yeni endpoint bulunmalı
    paths = {getattr(r, "path", "") for r in panel.router.routes}
    for req_p in (
        "/app/api/waitlist/offers",
        "/app/api/appointments/available",
        "/app/api/reminders/send",
        "/app/api/admin/scheduler/tick",
        "/app/api/conversations/{pid}/messages",
    ):
        assert req_p in paths, f"panel.py içinde eksik uç: {req_p}"

    # modules.is_within_work_hours kontrolü
    mon_open = datetime(2026, 11, 23, 11, 0, tzinfo=TZ)   # Pazartesi 11:00
    mon_night = datetime(2026, 11, 23, 22, 30, tzinfo=TZ)  # Pazartesi 22:30
    sun_noon = datetime(2026, 11, 22, 12, 0, tzinfo=TZ)   # Pazar 12:00
    assert modules.is_within_work_hours(mon_open) is True
    assert modules.is_within_work_hours(mon_night) is False
    assert modules.is_within_work_hours(sun_noon) is False
