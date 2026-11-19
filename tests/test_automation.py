"""Otomasyon uçtan uca doğrulama testleri (F-01..F-07 + Envanter F-01).
DENTACORE_URL (varsayılan: http://127.0.0.1:8792) ile çalışan run_local.py sunucusuna karşı çalışır.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import random
import sys
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import httpx

BASE = os.environ.get("DENTACORE_URL", "http://127.0.0.1:8792").rstrip("/")
TZ = ZoneInfo("Europe/Istanbul")

HQ_EMAIL = "yonetici@dentacore.com"
HQ_PASS = "DentaCore2026!"
SEC_EMAIL = "sekreter@dentacore.com"
SEC_PASS = "DentaCore2026!"
BURSA_EMAIL = "klinik@bursadis.com"
BURSA_PASS = "BursaDis2026!"


def login_client(email: str, password: str) -> tuple[httpx.Client, dict, dict]:
    c = httpx.Client(base_url=BASE, timeout=25.0)
    r = c.post("/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, f"Login başarısız ({email}): {r.status_code} {r.text}"
    data = r.json()
    return c, data, {"X-CSRF-Token": data["csrf"]}


def next_weekday(days_ahead: int = 3) -> datetime:
    d = (datetime.now(TZ) + timedelta(days=days_ahead)).replace(hour=10, minute=0, second=0, microsecond=0)
    while d.weekday() >= 5:
        d += timedelta(days=1)
    return d


def find_free_slot(c: httpx.Client, date_dt: datetime, duration: int = 30) -> dict:
    cur = date_dt
    for _ in range(14):
        while cur.weekday() >= 5:
            cur += timedelta(days=1)
        r = c.get("/app/api/appointments/available", params={"date": cur.strftime("%Y-%m-%d"), "duration": duration})
        assert r.status_code == 200, r.text
        body = r.json()
        if not body.get("closed") and body.get("slots"):
            return body["slots"][0]
        cur += timedelta(days=1)
    raise AssertionError("Boş slot bulunamadı")


def test_automation_end_to_end():
    c1, _, h1 = login_client(HQ_EMAIL, HQ_PASS)
    c_sec, _, h_sec = login_client(SEC_EMAIL, SEC_PASS)
    c2, _, h2 = login_client(BURSA_EMAIL, BURSA_PASS)
    tag = random.randint(100, 899)

    try:
        # 1) Available slots endpoint (F-05) - Sunday closed + weekday free slots
        sun = datetime.now(TZ) + timedelta(days=1)
        while sun.weekday() != 6:
            sun += timedelta(days=1)
        r_sun = c1.get("/app/api/appointments/available", params={"date": sun.strftime("%Y-%m-%d"), "duration": 30})
        assert r_sun.status_code == 200 and r_sun.json()["closed"] is True and r_sun.json()["slots"] == []

        slot_a = find_free_slot(c1, next_weekday(3), 30)
        day_str = slot_a["starts_at"][:10]
        chair_a = slot_a["available_chairs"][0]

        # 2) Create appointment -> automatic dry_run confirmation message stored (F-01)
        p_phone = f"+90 555 {tag} 01 01"
        r_cr = c1.post(
            "/app/api/appointments",
            json={
                "phone": p_phone,
                "name": f"Otomasyon Hasta {tag}",
                "starts_at": slot_a["starts_at"],
                "duration_min": 30,
                "treatment": "İmplant Muayene",
                "chair": chair_a,
            },
            headers=h1,
        )
        assert r_cr.status_code == 200, r_cr.text
        cr_data = r_cr.json()
        aid1 = cr_data["id"]
        pid1 = cr_data["patient_id"]
        assert cr_data["delivery"]["status"] == "dry_run" and cr_data["delivery"]["dry_run"] is True

        msgs = c1.get(f"/app/api/conversations/{pid1}/messages").json()
        assert len(msgs) >= 1
        assert msgs[0]["direction"] == "out"
        assert msgs[0]["delivery_status"] == "dry_run"
        assert "randevunuz oluşturulmuştur" in (msgs[0]["body"] or "")

        # Verify occupied chair/time disappears or loses that chair in /available (F-05)
        avail_after = c1.get("/app/api/appointments/available", params={"date": day_str, "duration": 30}).json()
        matching = [s for s in avail_after["slots"] if s["time"] == slot_a["time"]]
        if matching:
            assert chair_a not in matching[0]["available_chairs"], "Dolu koltuk available içinde dönmemeli"

        # 3) Manual /conversations/{pid}/send stores body + returns dry_run/status (F-01 + F-06)
        manual_txt = f"Kontrol mesajı {tag}"
        r_send = c1.post(f"/app/api/conversations/{pid1}/send", json={"text": manual_txt}, headers=h1)
        assert r_send.status_code == 200
        sd = r_send.json()
        assert sd["ok"] is True and sd["dry_run"] is True and sd["status"] == "dry_run"
        msgs2 = c1.get(f"/app/api/conversations/{pid1}/messages").json()
        assert any(m["body"] == manual_txt and m["delivery_status"] == "dry_run" for m in msgs2)

        # 4) Patient "EVET" reply -> booked becomes confirmed (F-02)
        r_yes = c1.post(
            "/app/api/conversations/simulate",
            json={"text": "EVET", "patient_id": pid1, "context_previous_turn": "Randevu onayı için EVET yazınız."},
            headers=h1,
        )
        assert r_yes.status_code == 200
        assert r_yes.json()["intent"] == "teyit"
        pat1 = c1.get(f"/app/api/patients/{pid1}").json()
        st1 = next(a["status"] for a in pat1["appointments"] if a["id"] == aid1)
        assert st1 == "confirmed", f"EVET sonrası confirmed bekleniyordu, {st1} geldi"

        # Test "tamam" / "onaylıyorum" / "yes" + "HAYIR" -> cancel + waitlist (F-02 + F-03)
        slot_b = find_free_slot(c1, next_weekday(5), 30)
        r_wl_p = c1.post("/app/api/patients", json={"phone": f"+90 555 {tag} 02 02", "name": f"Bekleyen {tag}"}, headers=h1)
        pid_wl = r_wl_p.json()["id"]
        r_wl = c1.post("/app/api/waitlist", json={"patient_id": pid_wl, "treatment": "herhangi"}, headers=h1)
        wid_wl = r_wl.json()["id"]

        r_cr2 = c1.post(
            "/app/api/appointments",
            json={
                "patient_id": pid1,
                "starts_at": slot_b["starts_at"],
                "duration_min": 30,
                "treatment": "Dolgu Kontrol",
                "chair": slot_b["available_chairs"][0],
            },
            headers=h1,
        )
        assert r_cr2.status_code == 200
        aid2 = r_cr2.json()["id"]

        # Reply "HAYIR" -> cancels aid2 and generates waitlist offers
        r_no = c1.post("/app/api/conversations/simulate", json={"text": "HAYIR", "patient_id": pid1}, headers=h1)
        assert r_no.status_code == 200 and r_no.json()["intent"] == "iptal"
        pat1_after_no = c1.get(f"/app/api/patients/{pid1}").json()
        st2 = next(a["status"] for a in pat1_after_no["appointments"] if a["id"] == aid2)
        assert st2 == "cancelled"

        # 5) Waitlist offers API + tenant isolation (F-03)
        offers_c1 = c1.get("/app/api/waitlist/offers").json()
        assert any(o["appointment_id"] == aid2 and o["status"] == "sent" for o in offers_c1)
        offers_c2 = c2.get("/app/api/waitlist/offers").json()
        assert not any(o["appointment_id"] == aid2 for o in offers_c2), "Bursa şubesi İstanbul teklifini görmemeli"

        # 6) Undo cancel -> booked when free, 409 when taken (F-07)
        r_undo = c1.post(f"/app/api/appointments/{aid2}/status", json={"status": "booked"}, headers=h1)
        assert r_undo.status_code == 200, r_undo.text
        audits = c1.get("/app/api/audit").json()
        assert any(a["action"] == "appointment.undo_cancel" and a["target"] == f"appointment:{aid2}" for a in audits)

        # Cancel again, book another patient on same slot, then undo must return 409
        c1.post(f"/app/api/appointments/{aid2}/status", json={"status": "cancelled"}, headers=h1)
        r_block = c1.post(
            "/app/api/appointments",
            json={
                "patient_id": pid_wl,
                "starts_at": slot_b["starts_at"],
                "duration_min": 30,
                "treatment": "Dolgu Yerine",
                "chair": slot_b["available_chairs"][0],
            },
            headers=h1,
        )
        assert r_block.status_code == 200
        r_undo_conflict = c1.post(f"/app/api/appointments/{aid2}/status", json={"status": "booked"}, headers=h1)
        assert r_undo_conflict.status_code == 409

        # Cleanup waitlist
        c1.post(f"/app/api/waitlist/{wid_wl}/remove", headers=h1)

        # 7) Scheduler tick auth/CSRF/working hours + 24h reminder sent once (F-04)
        assert c_sec.post("/app/api/admin/scheduler/tick", headers=h_sec).status_code == 403
        assert c1.post("/app/api/admin/scheduler/tick").status_code == 403

        # Create an appointment ~24 hours from a free weekday slot (so both appt_24h_dt and tick_day are weekdays)
        slot_rmd = None
        for day_try in range(7, 21):
            cand_day = next_weekday(day_try)
            if cand_day.weekday() == 0:
                continue  # day before Monday is Sunday
            r_av = c1.get("/app/api/appointments/available", params={"date": cand_day.strftime("%Y-%m-%d"), "duration": 30}).json()
            cands_rmd = [s for s in r_av.get("slots", []) if "10:00" <= s["time"] <= "16:00"]
            if cands_rmd:
                slot_rmd = cands_rmd[0]
                break
        assert slot_rmd is not None, "24s hatırlatma testi için uygun slot bulunamadı"
        appt_24h_dt = datetime.fromisoformat(slot_rmd["starts_at"])
        tick_day = appt_24h_dt - timedelta(hours=24)

        r_cr_rmd = c1.post(
            "/app/api/appointments",
            json={
                "patient_id": pid_wl,
                "starts_at": appt_24h_dt.isoformat(),
                "duration_min": 30,
                "treatment": "24s Hatırlatma Test",
                "chair": slot_rmd["available_chairs"][0],
            },
            headers=h1,
        )
        assert r_cr_rmd.status_code == 200, r_cr_rmd.text

        # Outside working hours (22:30) -> skipped!
        off_hours = tick_day.replace(hour=22, minute=30)
        r_tick_off = c1.post("/app/api/admin/scheduler/tick", json={"at": off_hours.isoformat()}, headers=h1)
        assert r_tick_off.status_code == 200
        assert r_tick_off.json()["skipped_outside_hours"] is True
        assert r_tick_off.json()["reminders_sent"] == 0

        # Inside working hours (11:00) -> reminder sent ONCE
        r_tick1 = c1.post("/app/api/admin/scheduler/tick", json={"at": tick_day.isoformat()}, headers=h1)
        assert r_tick1.status_code == 200
        assert r_tick1.json()["skipped_outside_hours"] is False
        assert r_tick1.json()["reminders_sent"] >= 1

        # Second tick at same time -> must NOT re-send for same appointment
        r_tick2 = c1.post("/app/api/admin/scheduler/tick", json={"at": tick_day.isoformat()}, headers=h1)
        assert r_tick2.status_code == 200
        assert r_tick2.json()["reminders_sent"] == 0

        # Unanswered follow-up: 5 hours later (16:00), still booked -> follow-up sent once
        followup_dt = tick_day.replace(hour=16, minute=0)
        r_tick_fu1 = c1.post("/app/api/admin/scheduler/tick", json={"at": followup_dt.isoformat()}, headers=h1)
        assert r_tick_fu1.status_code == 200
        assert r_tick_fu1.json()["followups_sent"] >= 1
        r_tick_fu2 = c1.post("/app/api/admin/scheduler/tick", json={"at": followup_dt.isoformat()}, headers=h1)
        assert r_tick_fu2.status_code == 200
        assert r_tick_fu2.json()["followups_sent"] == 0

        # Waitlist wave advancement: cancel future appointment with >5 waitlist patients -> wave 1 -> after 4 min tick -> wave 2
        wl_pids = []
        wl_wids = []
        for idx in range(7):
            rp = c1.post("/app/api/patients", json={"phone": f"+90 555 {tag} 7{idx} 00", "name": f"Dalga {idx} {tag}"}, headers=h1)
            p_w = rp.json()["id"]
            rw = c1.post("/app/api/waitlist", json={"patient_id": p_w, "treatment": "herhangi"}, headers=h1)
            wl_pids.append(p_w)
            wl_wids.append(rw.json()["id"])

        slot_w = find_free_slot(c1, next_weekday(9), 30)
        r_cw = c1.post(
            "/app/api/appointments",
            json={"patient_id": pid1, "starts_at": slot_w["starts_at"], "duration_min": 30, "treatment": "Dalga Test", "chair": slot_w["available_chairs"][0]},
            headers=h1,
        )
        aid_w = r_cw.json()["id"]
        rcan_w = c1.post(f"/app/api/appointments/{aid_w}/status", json={"status": "cancelled"}, headers=h1)
        assert rcan_w.status_code == 200 and rcan_w.json()["waitlist_offers"] == 5

        wave_tick_dt = next_weekday(0).replace(hour=11, minute=10)
        while wave_tick_dt <= datetime.now(TZ) + timedelta(minutes=5):
            wave_tick_dt = (wave_tick_dt + timedelta(days=1)).replace(hour=11, minute=10)
            while wave_tick_dt.weekday() >= 5:
                wave_tick_dt += timedelta(days=1)
        # Ensure wave_tick_dt is at least 4 min in future and weekday 11:10
        r_wave = c1.post("/app/api/admin/scheduler/tick", json={"at": wave_tick_dt.isoformat()}, headers=h1)
        assert r_wave.status_code == 200 and r_wave.json()["waves_advanced"] >= 1
        w_offers = [o for o in c1.get("/app/api/waitlist/offers").json() if o["appointment_id"] == aid_w]
        assert any(o["wave"] == 2 and o["status"] == "sent" for o in w_offers)
        assert any(o["wave"] == 1 and o["status"] == "expired" for o in w_offers)
        for wid_clean in wl_wids:
            c1.post(f"/app/api/waitlist/{wid_clean}/remove", headers=h1)

        # Confirm variants ("tamam", "onaylıyorum", "yes") on fresh patients -> nearest future booked -> confirmed
        for idx, word in enumerate(("tamam", "onaylıyorum", "yes")):
            rp_v = c1.post("/app/api/patients", json={"phone": f"+90 555 {tag} 8{idx} 00", "name": f"Onay Hasta {word} {tag}"}, headers=h1)
            pid_v = rp_v.json()["id"]
            sl = find_free_slot(c1, next_weekday(11 + idx), 30)
            rc = c1.post("/app/api/appointments", json={"patient_id": pid_v, "starts_at": sl["starts_at"], "duration_min": 30, "treatment": f"Onay {word}", "chair": sl["available_chairs"][0]}, headers=h1)
            aid_v = rc.json()["id"]
            rs = c1.post("/app/api/conversations/simulate", json={"text": word, "patient_id": pid_v}, headers=h1)
            assert rs.status_code == 200 and rs.json()["intent"] == "teyit"
            pv = c1.get(f"/app/api/patients/{pid_v}").json()
            assert next(a["status"] for a in pv["appointments"] if a["id"] == aid_v) == "confirmed"

        # 8) Anamnesis send -> returns link + dry_run + stores in patient messages (Envanter F-01)
        r_anam = c1.post(f"/app/api/patients/{pid1}/anamnesis", headers=h1)
        assert r_anam.status_code == 200
        ad = r_anam.json()
        assert "/form/anamnez/" in ad["link"] and ad["dry_run"] is True and ad["delivery"] == "dry_run"
        msgs_anam = c1.get(f"/app/api/conversations/{pid1}/messages").json()
        assert any(ad["link"] in (m["body"] or "") and m["delivery_status"] == "dry_run" for m in msgs_anam)

        print("OK  Tüm otomasyon testleri (F-01..F-07 + Envanter F-01) geçti!")
    finally:
        c1.close()
        c_sec.close()
        c2.close()


if __name__ == "__main__":
    test_automation_end_to_end()
