"""Klinik modülleri: hatırlatma, boş koltuk doldurucu, anamnez, işlem sonrası radar, uyuyan plan, deneyim talebi, sabah özeti."""
from __future__ import annotations

import asyncio
import hashlib
import html
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from . import wa
from .core import S, add_alert, add_consent, enc, env, patient, q, q1, sign

log = logging.getLogger("modules")
TZ = ZoneInfo("Europe/Istanbul")
TPL = {k: env(f"WA_TPL_{k.upper()}") for k in ("waitlist", "postop", "reminder", "plan_followup", "feedback", "anamnesis", "brief")}
YES = {"evet", "e", "yes", "y", "ja", "نعم", "да", "ok", "tamam", "1"}


def now() -> datetime:
    return datetime.now(timezone.utc)


def fmt_dt(dt: datetime) -> tuple[str, str]:
    l = dt.astimezone(TZ)
    return l.strftime("%d.%m.%Y"), l.strftime("%H:%M")


async def alert_doctor(phone: str, text: str, pid: int | None, kind: str, clinic_id: int | None = None):
    await add_alert(pid, kind, text, clinic_id=clinic_id)
    if phone:
        await wa.send_text_or_template(phone, text, TPL["brief"], [text[:900].replace("\n", " ")])


# ================= 1) Randevu hatırlatma (no-show önleme) =================
async def send_reminders():
    rows = await q("""SELECT a.id, a.starts_at, a.patient_id FROM appointments a
                      WHERE a.status='booked' AND a.reminder_sent_at IS NULL AND a.patient_id IS NOT NULL
                        AND a.starts_at BETWEEN now() + interval '20 hours' AND now() + interval '28 hours'""")
    for r in rows:
        p = await patient(r["patient_id"])
        d, t = fmt_dt(r["starts_at"])
        await wa.send_template(p["phone"], TPL["reminder"], [d, t], quick_reply_payloads=[f"RMD_OK_{r['id']}", f"RMD_CHG_{r['id']}"])
        await q("UPDATE appointments SET reminder_sent_at=now() WHERE id=%s", r["id"])


async def handle_reminder_reply(pid: int, payload: str, text: str) -> str | None:
    appt = None
    if payload.startswith("RMD_"):
        appt = await q1("SELECT * FROM appointments WHERE id=%s AND patient_id=%s", int(payload.rsplit("_", 1)[1]), pid)
        choice = "1" if "_OK_" in payload else "2"
    else:
        choice = text.strip()
        if choice not in ("1", "2"):
            return None
        appt = await q1("""SELECT * FROM appointments WHERE patient_id=%s AND status='booked'
                           AND reminder_sent_at > now() - interval '36 hours' ORDER BY starts_at LIMIT 1""", pid)
    if not appt:
        return None
    if choice == "1":
        await q("UPDATE appointments SET status='confirmed' WHERE id=%s", appt["id"])
        return "Teşekkürler, randevunuz teyit edildi."
    await cancel_and_refill(appt["id"], reason="hasta_degisiklik")
    return "Randevunuz serbest bırakıldı. Ekibimiz yeni saat için sizinle iletişime geçecek."


# ================= 2) Boş koltuk doldurucu =================
WAVE_SIZE, WAVE_MINUTES, MAX_WAVES = 5, 3, 4


async def cancel_and_refill(appt_id: int, reason: str = "iptal", clinic_id: int | None = None):
    if clinic_id is not None:
        a = await q1("UPDATE appointments SET status='cancelled' WHERE id=%s AND clinic_id=%s AND status IN ('booked','confirmed') RETURNING *", appt_id, clinic_id)
    else:
        a = await q1("UPDATE appointments SET status='cancelled' WHERE id=%s AND status IN ('booked','confirmed') RETURNING *", appt_id)
    if a and a["starts_at"] > now() + timedelta(hours=1):
        await _send_wave(a, 1)


async def _send_wave(a: dict, wave: int) -> int:
    cid = int(a.get("clinic_id") or 1)
    cands = await q("""SELECT w.id, w.patient_id FROM waitlist w
                       JOIN patients p ON p.id = w.patient_id
                       WHERE w.active AND p.clinic_id = %s AND w.earliest <= %s
                         AND (w.treatment ILIKE %s OR w.treatment = 'herhangi')
                         AND (%s::bigint IS NULL OR w.patient_id <> %s::bigint)
                         AND NOT EXISTS (SELECT 1 FROM slot_offers o WHERE o.appointment_id=%s AND o.waitlist_id=w.id)
                       ORDER BY w.created_at LIMIT %s""",
                    cid, a["starts_at"], f"%{a['treatment']}%", a["patient_id"], a["patient_id"], a["id"], WAVE_SIZE)
    d, t = fmt_dt(a["starts_at"])
    for c in cands:
        o = await q1("INSERT INTO slot_offers (appointment_id, waitlist_id, wave) VALUES (%s,%s,%s) RETURNING id", a["id"], c["id"], wave)
        p = await patient(c["patient_id"])
        await wa.send_template(p["phone"], TPL["waitlist"], [d, t, a["treatment"]], quick_reply_payloads=[f"SLOT_{o['id']}"])
    return len(cands)


async def advance_waves():
    rows = await q("""SELECT a.*, max(o.wave) AS wave, max(o.sent_at) AS last_sent FROM appointments a
                      JOIN slot_offers o ON o.appointment_id=a.id
                      WHERE a.status='cancelled' AND a.starts_at > now() + interval '1 hour'
                      GROUP BY a.id
                      HAVING bool_and(o.status <> 'won') AND max(o.sent_at) < now() - make_interval(mins => %s)""", WAVE_MINUTES)
    for a in rows:
        await q("UPDATE slot_offers SET status='expired' WHERE appointment_id=%s AND status='sent'", a["id"])
        if a["wave"] < MAX_WAVES:
            await _send_wave(a, a["wave"] + 1)


async def claim_slot(pid: int, offer_id: int | None) -> str | None:
    if offer_id is None:
        o = await q1("""SELECT o.* FROM slot_offers o JOIN waitlist w ON w.id=o.waitlist_id
                        WHERE w.patient_id=%s AND o.status='sent' AND o.sent_at > now() - interval '2 hours'
                        ORDER BY o.sent_at DESC LIMIT 1""", pid)
    else:
        o = await q1("""SELECT o.* FROM slot_offers o JOIN waitlist w ON w.id=o.waitlist_id
                        WHERE o.id=%s AND w.patient_id=%s""", offer_id, pid)
    if not o:
        return None
    won = await q1("""UPDATE appointments SET status='booked', patient_id=%s, reminder_sent_at=NULL
                      WHERE id=%s AND status='cancelled' RETURNING *""", pid, o["appointment_id"])
    if not won:
        await q("UPDATE slot_offers SET status='lost' WHERE id=%s", o["id"])
        return "Teşekkürler; bu saat az önce doldu. Bekleme listesindeki yeriniz korunuyor, yeni bir saat açıldığında tekrar haber vereceğiz."
    await q("UPDATE slot_offers SET status='won' WHERE id=%s", o["id"])
    await q("UPDATE slot_offers SET status='lost' WHERE appointment_id=%s AND id<>%s AND status='sent'", o["appointment_id"], o["id"])
    await q("UPDATE waitlist SET active=false WHERE id=%s", o["waitlist_id"])
    d, t = fmt_dt(won["starts_at"])
    await add_alert(pid, "koltuk_dolduruldu", f"İptal edilen {d} {t} ({won['treatment']}) koltuğu bekleme listesinden dolduruldu.", clinic_id=int(won.get("clinic_id") or 1))
    return f"Randevunuz oluşturuldu: {d} saat {t}. Görüşmek üzere."


# ================= 3) Anamnez + KVKK onamı =================
ANAMNEZ_SORULAR = [
    ("kan_sulandirici", "Kan sulandırıcı kullanıyor musunuz? (Coumadin/warfarin, aspirin, Xarelto, Eliquis vb.)", True),
    ("kanama_bozuklugu", "Kanama/pıhtılaşma bozukluğunuz var mı?", True),
    ("penisilin_alerji", "Penisilin veya başka bir antibiyotiğe alerjiniz var mı?", True),
    ("anestezi_alerji", "Lokal anesteziye (uyuşturma) karşı alerji veya kötü deneyim yaşadınız mı?", True),
    ("diyabet", "Diyabet (şeker hastalığı) var mı?", True),
    ("kalp", "Kalp hastalığı, kalp kapak sorunu, pil (pacemaker) veya son 6 ayda kalp krizi/inme öykünüz var mı?", True),
    ("tansiyon", "Yüksek tansiyon tedavisi görüyor musunuz?", False),
    ("bifosfonat", "Kemik erimesi veya kanser tedavisi için bifosfonat/denosumab (Fosamax, Zometa, Prolia vb.) kullandınız mı?", True),
    ("radyoterapi", "Baş-boyun bölgesine radyoterapi aldınız mı?", True),
    ("hamilelik", "Hamile misiniz veya hamilelik ihtimali var mı?", True),
    ("sigara", "Sigara kullanıyor musunuz?", False),
]
KVKK_METIN_VER = "2026-11"
KVKK_ACIK_RIZA = ("Sağlık verilerimin (anamnez cevapları, ağız içi fotoğraf ve röntgenler) yalnızca muayene ve tedavi planlaması "
                  "amacıyla, {clinic} tarafından işlenmesine ve hizmet sağlayıcıların yurt dışındaki sunucularında (WhatsApp/Meta) "
                  "iletilmesine açık rıza veriyorum. Rızamı her zaman geri alabileceğimi biliyorum.")


async def create_anamnesis_link(pid: int) -> str:
    token = secrets.token_urlsafe(24)
    await q("INSERT INTO anamnesis_tokens (token, patient_id, expires_at) VALUES (%s,%s, now() + interval '48 hours')", token, pid)
    return f"{S.public_url}/form/anamnez/{token}"


async def send_anamnesis(pid: int):
    p = await patient(pid)
    link = await create_anamnesis_link(pid)
    await wa.send_template(p["phone"], TPL["anamnesis"], [link])
    return link


def anamnesis_form_html(token: str, error: str = "") -> str:
    rows = "".join(
        f"""<fieldset><legend>{html.escape(t)}</legend>
        <label><input type="radio" name="{k}" value="evet" required> Evet</label>
        <label><input type="radio" name="{k}" value="hayir"> Hayır</label></fieldset>""" for k, t, _ in ANAMNEZ_SORULAR)
    riza = html.escape(KVKK_ACIK_RIZA.replace("{clinic}", S.clinic))
    err = f'<p class="err">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sağlık Bilgi Formu</title><style>
body{{font-family:system-ui,Segoe UI,Arial;background:#F8FAFC;color:#0A2540;margin:0;padding:16px;line-height:1.5}}
main{{max-width:560px;margin:auto;background:#fff;border-radius:12px;padding:18px;border:1px solid #e2e8f0}}
h1{{font-size:19px;margin:0 0 6px}}p.s{{color:#475569;font-size:14px}}
fieldset{{border:1px solid #e2e8f0;border-radius:8px;margin:10px 0;padding:10px}}legend{{font-weight:600;font-size:14.5px}}
label{{display:inline-flex;gap:6px;margin-right:18px;font-size:15px;padding:6px 0}}
textarea,input[type=text]{{width:100%;box-sizing:border-box;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font:inherit}}
.riza{{background:#f1f5f9;border-radius:8px;padding:10px;font-size:13.5px}}
button{{width:100%;background:#0F766E;color:#fff;border:0;border-radius:10px;padding:14px;font-size:16px;font-weight:700;margin-top:14px}}
.err{{color:#b91c1c;font-weight:600}}</style></head><body><main>
<h1>{html.escape(S.clinic)} - Randevu Öncesi Sağlık Bilgi Formu</h1>
<p class="s">Yaklaşık 1 dakika sürer. Cevaplarınız şifrelenerek saklanır ve yalnızca hekiminiz görür.</p>{err}
<form method="post">{rows}
<fieldset><legend>Düzenli kullandığınız ilaçlar (varsa)</legend><textarea name="ilaclar" rows="2" maxlength="500"></textarea></fieldset>
<div class="riza"><label style="display:flex"><input type="checkbox" name="kvkk_aydinlatma" required> KVKK Aydınlatma Metni'ni okudum.</label>
<label style="display:flex"><input type="checkbox" name="acik_riza" required> {riza}</label></div>
<fieldset><legend>Ad Soyad (imza yerine geçer)</legend><input type="text" name="imza" required minlength="5" maxlength="80"></fieldset>
<button type="submit">Formu Onayla ve Gönder</button></form></main></body></html>"""


async def submit_anamnesis(token: str, form: dict) -> tuple[bool, str]:
    t = await q1("SELECT * FROM anamnesis_tokens WHERE token=%s AND used_at IS NULL AND expires_at > now()", token)
    if not t:
        return False, "Bu bağlantının süresi dolmuş veya daha önce kullanılmış."
    if not (form.get("kvkk_aydinlatma") and form.get("acik_riza") and len((form.get("imza") or "").strip()) >= 5):
        return False, "Lütfen onay kutularını işaretleyin ve adınızı soyadınızı yazın."
    answers = {k: form.get(k, "") for k, _, _ in ANAMNEZ_SORULAR}
    answers["ilaclar"] = (form.get("ilaclar") or "")[:500]
    flags = [k for k, _, red in ANAMNEZ_SORULAR if red and answers.get(k) == "evet"]
    imza = form["imza"].strip()
    pid = t["patient_id"]
    signature = hashlib.sha256(f"{pid}|{imza}|{json.dumps(answers, sort_keys=True)}|{now().isoformat()}".encode()).hexdigest()
    row = await q1("""INSERT INTO anamnesis (patient_id, answers_enc, red_flags, signer_name, signature_sha256)
                      VALUES (%s,%s,%s,%s,%s) RETURNING id""", pid, enc(json.dumps(answers, ensure_ascii=False)), flags, imza, signature)
    await q("UPDATE anamnesis_tokens SET used_at=now() WHERE token=%s", token)
    await add_consent(pid, "kvkk_aydinlatma", KVKK_METIN_VER, "aydinlatma", "web_form")
    riza = KVKK_ACIK_RIZA.replace("{clinic}", S.clinic)
    await add_consent(pid, "saglik_verisi_acik_riza", KVKK_METIN_VER, riza, "web_form")
    await add_consent(pid, "yurt_disi_aktarim", KVKK_METIN_VER, riza, "web_form")
    if flags:
        p_row = await q1("SELECT clinic_id FROM patients WHERE id=%s", pid)
        cid_p = int(p_row["clinic_id"]) if p_row and p_row.get("clinic_id") else 1
        link = sign(f"/view/anamnez/{row['id']}", ttl=72 * 3600)
        await alert_doctor(S.doctor_on_call or S.doctor_owner,
                           f"KIRMIZI BAYRAK: Hasta #{pid} anamnezinde {len(flags)} risk işareti var. Detay (72 saat geçerli): {link}",
                           pid, "anamnez_kirmizi", clinic_id=cid_p)
    return True, "Formunuz alındı. Teşekkür ederiz."


async def anamnesis_view_html(aid: int) -> str:
    from .core import dec
    a = await q1("SELECT * FROM anamnesis WHERE id=%s", aid)
    if not a:
        return "<p>Bulunamadı</p>"
    ans = json.loads(dec(a["answers_enc"]))
    labels = {k: t for k, t, _ in ANAMNEZ_SORULAR}
    rows = "".join(
        f"<tr style='background:{'#fee2e2' if k in a['red_flags'] else '#fff'}'><td>{html.escape(labels.get(k, k))}</td><td><b>{html.escape(str(v))}</b></td></tr>"
        for k, v in ans.items())
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Anamnez #{aid}</title></head>
<body style="font-family:system-ui;color:#0A2540;padding:14px"><h2>Hasta #{a['patient_id']} anamnez</h2>
<p>İmza: {html.escape(a['signer_name'])} | {a['signed_at'].astimezone(TZ):%d.%m.%Y %H:%M} | Kırmızı bayrak: <b style="color:#b91c1c">{', '.join(a['red_flags']) or 'yok'}</b></p>
<table border="1" cellpadding="6" style="border-collapse:collapse;font-size:14px">{rows}</table></body></html>"""


# ================= 4) İşlem sonrası komplikasyon radarı =================
POSTOP_STAGES = (("2s", timedelta(hours=2)), ("24s", timedelta(hours=24)), ("72s", timedelta(hours=72)))


async def schedule_postop(pid: int, procedure: str, done_at: datetime):
    for stage, delta in POSTOP_STAGES:
        await q("INSERT INTO postop_checks (patient_id, procedure, due_at, stage) VALUES (%s,%s,%s,%s)", pid, procedure, done_at + delta, stage)


async def send_postop_checks():
    rows = await q("SELECT * FROM postop_checks WHERE sent_at IS NULL AND due_at <= now() AND due_at > now() - interval '6 hours'")
    for r in rows:
        p = await patient(r["patient_id"])
        await wa.send_template(p["phone"], TPL["postop"], [r["procedure"]])
        await q("UPDATE postop_checks SET sent_at=now() WHERE id=%s", r["id"])


async def handle_postop_reply(pid: int, text: str, emergency: bool) -> str | None:
    c = await q1("""SELECT * FROM postop_checks WHERE patient_id=%s AND sent_at > now() - interval '12 hours'
                    AND answered_at IS NULL ORDER BY sent_at DESC LIMIT 1""", pid)
    if not c:
        return None
    import re
    m = re.search(r"\b(10|[1-9])\b", text)
    if not m and not emergency:
        return None
    score = int(m.group(1)) if m else None
    alarm = emergency or (score is not None and score >= 8)
    await q("UPDATE postop_checks SET pain_score=%s, answered_at=now(), alarm=%s WHERE id=%s", score, alarm, c["id"])
    if alarm:
        p = await patient(pid)
        cid_p = int(p.get("clinic_id") or 1)
        await alert_doctor(S.doctor_on_call or S.doctor_owner,
                           f"İŞLEM SONRASI ALARM: {p.get('display_name') or 'Hasta'} (#{pid}), {c['procedure']}, {c['stage']} kontrolü, "
                           f"ağrı {score if score is not None else '?'}/10{', acil belirti bildirdi' if emergency else ''}. Geri arama: +{p['phone']}",
                           pid, "postop_alarm", clinic_id=cid_p)
        return "Bilginiz nöbetçi hekimimize iletildi, sizi en kısa sürede arayacak. Nefes alma güçlüğü, durmayan kanama veya hızla artan şişlik varsa lütfen 112'yi arayın."
    if score is not None and score >= 5:
        return "Teşekkürler. Bu düzeyde ağrı ilk günlerde görülebilir; hekiminizin verdiği talimatlara uyun. Ağrı artarsa veya 8 ve üzerine çıkarsa bize hemen yazın."
    return "Teşekkürler, iyileşmeniz beklenen şekilde ilerliyor görünüyor. Sorunuz olursa buradan yazabilirsiniz."


# ================= 5) Uyuyan tedavi planları =================
async def mine_sleeping_plans(limit: int = 30):
    rows = await q("""SELECT tp.* FROM treatment_plans tp
                      WHERE tp.status='open' AND tp.followups_sent < 2
                        AND tp.planned_at BETWEEN now() - interval '180 days' AND now() - interval '90 days'
                        AND (tp.last_contact_at IS NULL OR tp.last_contact_at < now() - interval '30 days')
                        AND EXISTS (SELECT 1 FROM consents c WHERE c.patient_id=tp.patient_id AND c.kind='iletisim' AND c.revoked_at IS NULL)
                      ORDER BY tp.planned_at LIMIT %s""", limit)
    for r in rows:
        p = await patient(r["patient_id"])
        await wa.send_template(p["phone"], TPL["plan_followup"], [r["treatment"]])
        await q("UPDATE treatment_plans SET followups_sent=followups_sent+1, last_contact_at=now() WHERE id=%s", r["id"])
    return len(rows)


# ================= 6) Deneyim talebi (filtresiz, herkese eşit) =================
async def request_feedback(pid: int):
    p = await patient(pid)
    private = f"{S.public_url}/form/geri-bildirim"
    await wa.send_template(p["phone"], TPL["feedback"], [S.google_review_url, private])


# ================= 7) Sabah 08:30 hekim özeti =================
async def morning_brief(clinic_id: int = 1) -> str:
    text = await morning_brief_text(clinic_id)
    if S.doctor_owner:
        lines = text.split("\n")
        await wa.send_text_or_template(S.doctor_owner, text, TPL["brief"], [" | ".join(lines[1:])[:900]])
    return text


async def morning_brief_text(clinic_id: int = 1) -> str:
    start = datetime.now(TZ).replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    cinfo = await q1("SELECT chairs, work_minutes FROM clinics WHERE id=%s", clinic_id)
    chairs = (cinfo and cinfo["chairs"]) or S.chairs
    work_min = (cinfo and cinfo["work_minutes"]) or S.work_minutes
    appts = await q("SELECT status, duration_min, patient_id FROM appointments WHERE clinic_id=%s AND starts_at >= %s AND starts_at < %s",
                    clinic_id, start, end)
    active = [a for a in appts if a["status"] in ("booked", "confirmed")]
    minutes = sum(a["duration_min"] for a in active)
    occ = round(100 * minutes / max(1, chairs * work_min))
    confirmed = sum(1 for a in active if a["status"] == "confirmed")
    night = await q1("""SELECT count(DISTINCT m.patient_id) AS n FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id
                        WHERE m.direction='in' AND COALESCE(p.clinic_id, m.clinic_id, 1)=%s AND m.created_at >= %s AND m.created_at < %s""",
                     clinic_id, start - timedelta(hours=5), start + timedelta(hours=8, minutes=30))
    pids = [a["patient_id"] for a in active if a["patient_id"]]
    flagged = await q("""SELECT DISTINCT ON (a.patient_id) a.patient_id, a.red_flags FROM anamnesis a
                         JOIN patients p ON p.id=a.patient_id
                         WHERE p.clinic_id=%s AND a.patient_id = ANY(%s) AND cardinality(a.red_flags) > 0
                         ORDER BY a.patient_id, a.signed_at DESC""", clinic_id, pids) if pids else []
    alarms = await q1("""SELECT count(*) AS n FROM postop_checks pc JOIN patients p ON p.id=pc.patient_id
                         WHERE p.clinic_id=%s AND pc.alarm AND pc.answered_at > now() - interval '24 hours'""", clinic_id)
    refills = await q1("SELECT count(*) AS n FROM alerts WHERE clinic_id=%s AND kind='koltuk_dolduruldu' AND created_at > now() - interval '24 hours'", clinic_id)
    layers = await q("""SELECT m.layer, count(*) AS n, sum(m.tokens_in+m.tokens_out) AS tok
                        FROM message_log m LEFT JOIN patients p ON p.id=m.patient_id
                        WHERE m.direction='out' AND COALESCE(p.clinic_id, m.clinic_id, 1)=%s AND m.created_at > now() - interval '24 hours'
                        GROUP BY m.layer""", clinic_id)
    total = sum(l["n"] for l in layers) or 0
    free = sum(l["n"] for l in layers if (l["layer"] or "").startswith("L1"))
    lines = [
        f"Günaydın. {start:%d.%m.%Y} özeti:",
        f"Koltuk doluluğu: %{occ} ({len(active)} randevu, {confirmed} teyitli)",
        f"Gece gelen yeni konuşma: {night['n'] if night else 0}",
        f"Bugünkü hastalarda kırmızı bayraklı anamnez: {len(flagged)}" + (" -> " + "; ".join(f"#{f['patient_id']}: {', '.join(f['red_flags'])}" for f in flagged[:5]) if flagged else ""),
        f"Son 24 saat işlem sonrası alarm: {alarms['n'] if alarms else 0}",
        f"Bekleme listesinden doldurulan koltuk: {refills['n'] if refills else 0}",
        f"Mesajların %{round(100 * free / total) if total else 0}'i LLM'siz cevaplandı ({total} cevap).",
    ]
    low = await q1("SELECT count(*) AS n FROM inventory_items WHERE clinic_id=%s AND active AND min_qty > 0 AND qty <= min_qty", clinic_id)
    if low and low["n"]:
        lines.append(f"Kritik stok: {low['n']} ürün")
    return "\n".join(lines)


# ================= Zamanlayıcı =================
async def scheduler_loop(redis):
    last_daily: dict[str, str] = {}
    while True:
        try:
            got = await redis.set("dc:sched:lock", "1", nx=True, ex=55) if redis else True
            if got:
                await send_reminders()
                await advance_waves()
                await send_postop_checks()
                local = datetime.now(TZ)
                today = local.strftime("%Y%m%d")
                if local.strftime("%H:%M") >= "08:30" and last_daily.get("brief") != today:
                    if not redis or await redis.set(f"dc:brief:{today}", "1", nx=True, ex=86400):
                        await morning_brief()
                    last_daily["brief"] = today
                if local.hour == 11 and last_daily.get("sleep") != today:
                    if not redis or await redis.set(f"dc:sleep:{today}", "1", nx=True, ex=86400):
                        await mine_sleeping_plans()
                    last_daily["sleep"] = today
        except Exception as e:
            log.exception("zamanlayıcı hatası: %s", e)
        await asyncio.sleep(60)
