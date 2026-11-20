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

from . import inbox, wa
from .core import S, add_alert, add_consent, enc, env, heartbeat_error, heartbeat_ok, instance_id, mask_phone, patient, q, q1, sign, try_lock
from .router import normalize

log = logging.getLogger("modules")
TZ = ZoneInfo("Europe/Istanbul")
TPL = {k: env(f"WA_TPL_{k.upper()}") for k in ("waitlist", "postop", "reminder", "plan_followup", "feedback", "anamnesis", "brief")}
YES = {"evet", "yes", "ja", "نعم", "да", "ok", "tamam", "onayliyorum"}
_CONFIRM_WORDS = {"evet", "tamam", "onayliyorum", "yes"}
_CANCEL_WORDS = {"hayir", "iptal", "no"}
_SCHED_LOCK = asyncio.Lock()
DEFAULT_WORKING_HOURS_JSON = '{"mon_fri":["09:00","19:00"],"sat":["09:00","15:00"],"sun":null}'


def _parse_hhmm(val: str) -> int:
    parts = str(val or "00:00").strip().split(":")
    return int(parts[0]) * 60 + (int(parts[1]) if len(parts) > 1 else 0)


def is_within_work_hours(now_dt: datetime | None = None, working_hours_json: str | None = None) -> bool:
    dt_loc = ((now_dt or now()) if (now_dt is None or now_dt.tzinfo) else now_dt.replace(tzinfo=TZ)).astimezone(TZ)
    try:
        wh = json.loads(working_hours_json or DEFAULT_WORKING_HOURS_JSON)
        if not isinstance(wh, dict):
            wh = json.loads(DEFAULT_WORKING_HOURS_JSON)
    except Exception:
        wh = json.loads(DEFAULT_WORKING_HOURS_JSON)
    wd = dt_loc.weekday()
    day_keys = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    dkey = day_keys[wd]
    if dkey in wh:
        hrs = wh[dkey]
    elif wd < 5:
        hrs = wh.get("mon_fri", ["09:00", "19:00"])
    elif wd == 5:
        hrs = wh.get("sat", ["09:00", "15:00"])
    else:
        hrs = wh.get("sun", None)
    if not hrs or not isinstance(hrs, (list, tuple)) or len(hrs) < 2 or not hrs[0] or not hrs[1]:
        return False
    open_m, close_m = _parse_hhmm(hrs[0]), _parse_hhmm(hrs[1])
    cur_m = dt_loc.hour * 60 + dt_loc.minute
    return open_m <= cur_m < close_m


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
CLAIM_LEASE_MIN = int(env("DC_CLAIM_LEASE_MINUTES", "10"))  # gönderim sahiplenme süresi = başarısız gönderimde yeniden deneme bekleme süresi
CLAIM_BATCH = int(env("DC_CLAIM_BATCH", "20"))              # tek seferde sahiplenilen satır (lease'in batch sürerken dolmaması için küçük)

_REMINDER_CLAIM_SQL = """
WITH due AS (
  SELECT a.id FROM appointments a
  WHERE a.status='booked' AND a.reminder_sent_at IS NULL AND a.patient_id IS NOT NULL
    AND a.starts_at BETWEEN %s + interval '20 hours' AND %s + interval '28 hours'
    AND (a.reminder_claimed_at IS NULL OR a.reminder_claimed_at < now() - make_interval(mins => %s))
    AND a.id <> ALL(%s::bigint[])
    {clinic_filter}
  ORDER BY a.starts_at
  FOR UPDATE OF a SKIP LOCKED
  LIMIT %s)
UPDATE appointments a SET reminder_claimed_at=now(), reminder_claimed_by=%s
FROM due, clinics c
WHERE a.id = due.id AND c.id = a.clinic_id
RETURNING a.id, a.clinic_id, a.starts_at, a.patient_id, c.working_hours_json
"""


async def _claim_reminders(ref_now: datetime, clinic_id: int | None, wid: str, exclude: list[int]) -> list[dict]:
    args: list = [ref_now, ref_now, CLAIM_LEASE_MIN, exclude]
    clinic_filter = ""
    if clinic_id is not None:
        clinic_filter = "AND a.clinic_id=%s"
        args.append(clinic_id)
    args += [CLAIM_BATCH, wid]
    return await q(_REMINDER_CLAIM_SQL.format(clinic_filter=clinic_filter), *args)  # nosec B608  # noqa: S608


async def send_reminders(clinic_id: int | None = None, now_dt: datetime | None = None, respect_hours: bool = True) -> int:
    """Randevu hatırlatması. "Önce sahiplen, sonra gönder": iki worker aynı randevuya aynı anda gönderemez.

    - Sahiplenme (reminder_claimed_*) tek SQL'de, FOR UPDATE SKIP LOCKED ile yapılır; Redis gerekmez.
    - Gönderim başarılıysa reminder_sent_at yazılır. Başarısızsa sahiplenme KALIR: lease (CLAIM_LEASE_MIN dk) dolunca
      yeniden denenir (Meta 429/5xx'e karşı doğal geri çekilme). Çalışma saati dışındakiler hemen serbest bırakılır.
    - Çöken worker: lease dolunca başka worker devralır. Gönderimden sonra, işaretlemeden önce çökerse dar bir pencerede
      mükerrer gönderim mümkündür (at-least-once; Meta gönderim idempotency anahtarı sunmaz).
    """
    ref_now = (now_dt if now_dt.tzinfo else now_dt.replace(tzinfo=TZ)) if now_dt else now()
    wid = instance_id()
    sent_cnt = 0
    skip: list[int] = []
    while True:
        rows = await _claim_reminders(ref_now, clinic_id, wid, skip)
        if not rows:
            break
        for r in rows:
            skip.append(int(r["id"]))
            if respect_hours and not is_within_work_hours(ref_now, r.get("working_hours_json")):
                await q("UPDATE appointments SET reminder_claimed_at=NULL, reminder_claimed_by=NULL WHERE id=%s AND reminder_claimed_by=%s",
                        r["id"], wid)
                continue
            ok = False
            try:
                p = await patient(r["patient_id"])
                d, t = fmt_dt(r["starts_at"])
                res = await wa.send_template(p["phone"], TPL["reminder"], [d, t], quick_reply_payloads=[f"RMD_OK_{r['id']}", f"RMD_CHG_{r['id']}"])
                ok = not (isinstance(res, dict) and res.get("error"))
            except Exception:
                log.exception("hatırlatma gönderilemedi appt=%s", r["id"])
            if ok:
                await q("""UPDATE appointments SET reminder_sent_at=%s, reminder_claimed_at=NULL, reminder_claimed_by=NULL
                           WHERE id=%s AND reminder_sent_at IS NULL""", ref_now, r["id"])
                sent_cnt += 1
    return sent_cnt


async def handle_reminder_reply(pid: int, payload: str, text: str) -> str | None:
    appt = None
    if payload.startswith("RMD_"):
        appt = await q1("SELECT * FROM appointments WHERE id=%s AND patient_id=%s", int(payload.rsplit("_", 1)[1]), pid)
        choice = "1" if "_OK_" in payload else "2"
    else:
        cleaned = normalize(text or "").strip()
        if cleaned in _CONFIRM_WORDS:
            choice = "1"
        elif cleaned in _CANCEL_WORDS:
            choice = "2"
        else:
            return None
        allowed = ("booked",) if choice == "1" else ("booked", "confirmed")
        appt = await q1("""SELECT * FROM appointments WHERE patient_id=%s AND status = ANY(%s)
                           AND starts_at >= now() - interval '15 minutes' ORDER BY starts_at LIMIT 1""", pid, list(allowed))
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
        o = await q1(
            "INSERT INTO slot_offers (appointment_id, waitlist_id, wave, expires_at) VALUES (%s,%s,%s, now() + interval '2 hours') RETURNING id",
            a["id"], c["id"], wave,
        )
        p = await patient(c["patient_id"])
        await wa.send_template(p["phone"], TPL["waitlist"], [d, t, a["treatment"]], quick_reply_payloads=[f"SLOT_{o['id']}"])
    return len(cands)


async def advance_waves(clinic_id: int | None = None) -> int:
    sql = """SELECT a.*, max(o.wave) AS wave, max(o.sent_at) AS last_sent FROM appointments a
             JOIN slot_offers o ON o.appointment_id=a.id
             WHERE a.status='cancelled' AND a.starts_at > now() + interval '1 hour'"""
    args: list = []
    if clinic_id is not None:
        sql += " AND a.clinic_id=%s"
        args.append(clinic_id)
    sql += """ GROUP BY a.id
               HAVING bool_and(o.status <> 'won') AND max(o.sent_at) < now() - make_interval(mins => %s)"""
    args.append(WAVE_MINUTES)
    rows = await q(sql, *args)
    adv = 0
    for a in rows:
        await q("UPDATE slot_offers SET status='expired' WHERE appointment_id=%s AND status='sent'", a["id"])
        if a["wave"] < MAX_WAVES:
            await _send_wave(a, a["wave"] + 1)
            adv += 1
    return adv


async def claim_slot(pid: int, offer_id: int | None) -> str | None:
    if offer_id is None:
        o = await q1("""SELECT o.* FROM slot_offers o JOIN waitlist w ON w.id=o.waitlist_id
                        WHERE w.patient_id=%s AND o.status='sent'
                          AND (o.expires_at IS NULL OR o.expires_at >= now())
                          AND o.sent_at > now() - interval '2 hours'
                        ORDER BY o.sent_at DESC LIMIT 1""", pid)
    else:
        o = await q1("""SELECT o.* FROM slot_offers o JOIN waitlist w ON w.id=o.waitlist_id
                        WHERE o.id=%s AND w.patient_id=%s
                          AND o.status='sent' AND (o.expires_at IS NULL OR o.expires_at >= now())""", offer_id, pid)
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
KVKK_METIN_VER = "2026-11-v2"


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
    from .security import KVKK_METIN_VER as _VER, kvkk_texts
    texts = kvkk_texts(S.clinic)
    rows = "".join(
        f"""<fieldset><legend>{html.escape(t)}</legend>
        <label><input type="radio" name="{k}" value="evet" required> Evet</label>
        <label><input type="radio" name="{k}" value="hayir"> Hayır</label></fieldset>""" for k, t, _ in ANAMNEZ_SORULAR)
    aydinlatma_html = html.escape(texts["aydinlatma"])
    saglik_html = html.escape(texts["saglik"])
    yurt_disi_html = html.escape(texts["yurt_disi"])
    err = (
        f'<p class="err" role="alert">{html.escape(error)}</p>'
        '<p><a class="btn-back" href="/">Kliniğe / Ana Sayfaya Dön</a></p>'
    ) if error else ""
    return f"""<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sağlık Bilgi Formu</title><style>
body{{font-family:system-ui,Segoe UI,Arial;background:#F8FAFC;color:#0A2540;margin:0;padding:16px;line-height:1.5}}
main{{max-width:560px;margin:auto;background:#fff;border-radius:12px;padding:18px;border:1px solid #e2e8f0}}
h1{{font-size:19px;margin:0 0 6px}}p.s{{color:#475569;font-size:14px}}
fieldset{{border:1px solid #e2e8f0;border-radius:8px;margin:10px 0;padding:10px}}legend{{font-weight:600;font-size:14.5px}}
label{{display:inline-flex;gap:6px;margin-right:18px;font-size:15px;padding:6px 0}}
textarea,input[type=text]{{width:100%;box-sizing:border-box;padding:10px;border:1px solid #cbd5e1;border-radius:8px;font:inherit}}
.riza{{background:#f1f5f9;border-radius:8px;padding:12px;font-size:13.5px}}
.riza .ayd{{margin:0 0 8px;color:#334155;font-size:13px}}
button{{width:100%;background:#0F766E;color:#fff;border:0;border-radius:10px;padding:14px;font-size:16px;font-weight:700;margin-top:14px}}
.err{{color:#b91c1c;font-weight:600;background:#FEF2F2;border:1px solid #FECACA;border-radius:8px;padding:10px 12px}}
.f-err{{color:#b91c1c;font-size:13px;font-weight:600;margin:6px 0 0}}
.btn-back{{display:inline-block;padding:10px 16px;border-radius:8px;background:#0A2540;color:#fff;text-decoration:none;font-weight:600;font-size:14px}}</style></head><body><main>
<h1>{html.escape(S.clinic)} - Randevu Öncesi Sağlık Bilgi Formu</h1>
<p class="s">Yaklaşık 1 dakika sürer. Cevaplarınız şifrelenerek saklanır ve yalnızca hekiminiz görür.</p>{err}
<div id="form-err" class="err" role="alert" style="display:none"></div>
<form method="post" novalidate>{rows}
<fieldset><legend>Düzenli kullandığınız ilaçlar (varsa)</legend><textarea name="ilaclar" rows="2" maxlength="500"></textarea></fieldset>
<div class="riza" data-kvkk-ver="{html.escape(_VER)}">
<p class="ayd"><strong>KVKK Aydınlatma Metni:</strong> {aydinlatma_html}</p>
<label style="display:flex"><input type="checkbox" name="kvkk_aydinlatma" value="1" required> Aydınlatma Metni'ni okudum ve anladım.</label>
<label style="display:flex"><input type="checkbox" name="saglik_riza" value="1" required> {saglik_html}</label>
<label style="display:flex"><input type="checkbox" name="yurt_disi_riza" value="1"> {yurt_disi_html}</label>
</div>
<fieldset><legend>Ad Soyad (imza yerine geçer)</legend><input type="text" name="imza" required minlength="2" maxlength="80"></fieldset>
<button type="submit">Formu Onayla ve Gönder</button></form>
<script src="/form/validate.js" defer></script></main></body></html>"""


async def submit_anamnesis(token: str, form: dict) -> tuple[bool, str]:
    from .security import KVKK_METIN_VER as _VER, is_checked, kvkk_texts
    t = await q1("SELECT * FROM anamnesis_tokens WHERE token=%s AND used_at IS NULL AND expires_at > now()", token)
    if not t:
        return False, "Bu bağlantının süresi dolmuş veya daha önce kullanılmış."
    has_ayd = is_checked(form.get("kvkk_aydinlatma"))
    has_saglik = is_checked(form.get("saglik_riza")) or is_checked(form.get("acik_riza"))
    imza = (form.get("imza") or "").strip()[:80]
    if not (has_ayd and has_saglik and len(imza) >= 2):
        return False, "Lütfen aydınlatma metni ve sağlık verisi açık rıza onay kutularını işaretleyin ve adınızı soyadınızı yazın."
    claimed = await q1("UPDATE anamnesis_tokens SET used_at=now() WHERE token=%s AND used_at IS NULL AND expires_at > now() RETURNING patient_id", token)
    if not claimed:
        return False, "Bu bağlantının süresi dolmuş veya daha önce kullanılmış."
    answers = {k: form.get(k, "") for k, _, _ in ANAMNEZ_SORULAR}
    answers["ilaclar"] = (form.get("ilaclar") or "")[:500]
    flags = [k for k, _, red in ANAMNEZ_SORULAR if red and answers.get(k) == "evet"]
    pid = t["patient_id"]
    signature = hashlib.sha256(f"{pid}|{imza}|{json.dumps(answers, sort_keys=True)}|{now().isoformat()}".encode()).hexdigest()
    row = await q1("""INSERT INTO anamnesis (patient_id, answers_enc, red_flags, signer_name, signature_sha256)
                      VALUES (%s,%s,%s,%s,%s) RETURNING id""", pid, enc(json.dumps(answers, ensure_ascii=False)), flags, imza, signature)
    texts = kvkk_texts(S.clinic)
    await add_consent(pid, "kvkk_aydinlatma", _VER, texts["aydinlatma"], "web_form")
    await add_consent(pid, "saglik_verisi_acik_riza", _VER, texts["saglik"], "web_form")
    if is_checked(form.get("yurt_disi_riza")):
        await add_consent(pid, "yurt_disi_aktarim", _VER, texts["yurt_disi"], "web_form")
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


_POSTOP_CLAIM_SQL = """
WITH due AS (
  SELECT pc.id FROM postop_checks pc
  JOIN patients p ON p.id = pc.patient_id
  WHERE pc.sent_at IS NULL AND pc.due_at <= now() AND pc.due_at > now() - interval '6 hours'
    AND (pc.claimed_at IS NULL OR pc.claimed_at < now() - make_interval(mins => %s))
    AND pc.id <> ALL(%s::bigint[])
    {clinic_filter}
  ORDER BY pc.due_at
  FOR UPDATE OF pc SKIP LOCKED
  LIMIT %s)
UPDATE postop_checks pc SET claimed_at=now(), claimed_by=%s
FROM due
WHERE pc.id = due.id
RETURNING pc.id, pc.patient_id, pc.procedure
"""


async def _claim_postop(clinic_id: int | None, wid: str, exclude: list[int]) -> list[dict]:
    args: list = [CLAIM_LEASE_MIN, exclude]
    clinic_filter = ""
    if clinic_id is not None:
        clinic_filter = "AND p.clinic_id=%s"
        args.append(clinic_id)
    args += [CLAIM_BATCH, wid]
    return await q(_POSTOP_CLAIM_SQL.format(clinic_filter=clinic_filter), *args)  # nosec B608  # noqa: S608


async def send_postop_checks(clinic_id: int | None = None) -> int:
    """Post-op kontrol mesajı. Önce sahiplen (claimed_at/by, FOR UPDATE SKIP LOCKED), sonra gönder; başarısızsa lease dolunca yeniden denenir."""
    wid = instance_id()
    sent_cnt = 0
    skip: list[int] = []
    while True:
        rows = await _claim_postop(clinic_id, wid, skip)
        if not rows:
            break
        for r in rows:
            skip.append(int(r["id"]))
            ok = False
            try:
                p = await patient(r["patient_id"])
                res = await wa.send_template(p["phone"], TPL["postop"], [r["procedure"]])
                ok = not (isinstance(res, dict) and res.get("error"))
            except Exception:
                log.exception("post-op gönderilemedi id=%s", r["id"])
            if ok:
                await q("UPDATE postop_checks SET sent_at=now(), claimed_at=NULL, claimed_by=NULL WHERE id=%s AND sent_at IS NULL", r["id"])
                sent_cnt += 1
    return sent_cnt


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
                           f"ağrı {score if score is not None else '?'}/10{', acil belirti bildirdi' if emergency else ''}. Geri arama: {mask_phone(p['phone'])}",
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


# ================= 6) İki aşamalı memnuniyet ve Google değerlendirme akışı (Podium / Weave standardı) =================
async def request_feedback(pid: int, appt_id: int | None = None, clinic_id: int = 1, treatment: str = "tedavi"):
    p = await patient(pid)
    fb_link = sign("/form/geri-bildirim", ttl=7 * 86400)
    p_name = p.get("display_name") or "Sayın Hastamız"
    sat_msg = (
        f"Merhaba {p_name}, bugün kliniğimizi ziyaret ettiğiniz için teşekkür ederiz. "
        f"Aldığınız {treatment} hizmetimizden memnun kaldınız mı? "
        f"Yanıt olarak 'Memnun kaldım' veya 'Şikayetim var' yazabilir ya da 1-10 arası puan verebilirsiniz. "
        f"(Kliniğimize doğrudan özel geri bildirim iletmek için: {fb_link})"
    )
    await wa.send_text_or_template(p["phone"], sat_msg, TPL["feedback"], [fb_link])
    if appt_id is not None:
        await q("UPDATE appointments SET satisfaction_sent_at=now(), satisfaction_status='asked' WHERE id=%s", appt_id)
    else:
        await q(
            """UPDATE appointments SET satisfaction_sent_at=now(), satisfaction_status='asked'
               WHERE id=(SELECT id FROM appointments WHERE patient_id=%s AND status='done' ORDER BY starts_at DESC LIMIT 1)""",
            pid,
        )


async def handle_satisfaction_reply(pid: int, text: str, clinic_id: int = 1) -> tuple[str, str] | None:
    import re
    raw_txt = text or ""
    cleaned = re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", normalize(raw_txt))).strip()
    sat_appt = await q1(
        """SELECT id, treatment FROM appointments
           WHERE clinic_id=%s AND patient_id=%s AND status='done'
             AND satisfaction_sent_at IS NOT NULL AND satisfaction_reply IS NULL
           ORDER BY id DESC LIMIT 1""",
        clinic_id, pid,
    )
    if not sat_appt:
        return None
    neg_phrases = ("memnun degilim", "memnun kalmadim", "sikayet", "kotu", "berbat", "agrim var", "cok agri", "rezalet", "hic memnun", "uzgun", "pisman")
    pos_phrases = ("memnun kaldim", "cok memnun", "memnunum", "memnun", "cok iyi", "harika", "tesekkur", "super", "mukemmel", "gayet iyi", "elinize saglik")
    has_neg = any(w in cleaned for w in neg_phrases) or cleaned in {"hayir", "no"}
    has_pos = not has_neg and (any(w in cleaned for w in pos_phrases) or cleaned in {"evet", "yes", "tamam"})
    is_num = bool(re.fullmatch(r"\s*(10|[1-9])\s*", raw_txt))
    active_postop = await q1(
        "SELECT id FROM postop_checks WHERE patient_id=%s AND sent_at IS NOT NULL AND answered_at IS NULL ORDER BY id DESC LIMIT 1",
        pid,
    )
    num_val = int(raw_txt.strip()) if (is_num and not active_postop) else None
    is_sat_neg = has_neg or (num_val is not None and 1 <= num_val <= 4)
    is_sat_pos = has_pos or (num_val is not None and 8 <= num_val <= 10)
    if not (is_sat_neg or is_sat_pos):
        return None
    if is_sat_neg:
        await q(
            "UPDATE appointments SET satisfaction_reply=%s, satisfaction_replied_at=now(), satisfaction_status='negative' WHERE id=%s",
            raw_txt[:400], sat_appt["id"],
        )
        p_row = await q1("SELECT display_name FROM patients WHERE id=%s", pid)
        pname = (p_row and p_row.get("display_name")) or f"Hasta #{pid}"
        await add_alert(pid, "memnuniyetsiz_hasta", f"MEMNUNİYETSİZ HASTA UYARISI: {pname} (#{pid}) randevu sonrası olumsuz geri bildirim iletti: {raw_txt[:200]}", clinic_id=clinic_id)
        await add_alert(pid, "sekreter_gorev", f"ACİL YÖNETİCİ / SEKRETER GÖREVİ: Memnuniyetsiz hasta {pname} (#{pid}) ile hemen iletişime geçin.", clinic_id=clinic_id)
        return (
            "Yaşadığınız olumsuz deneyim için çok özür dileriz. Bildiriminiz başhekimliğimize ve klinik yöneticimize acil öncelikle iletildi; klinik yöneticimiz sizinle hemen ilgilenecektir.",
            "memnuniyet_olumsuz",
        )
    cl_row = await q1("SELECT google_review_url FROM clinics WHERE id=%s", clinic_id) or {}
    g_url = (cl_row.get("google_review_url") or S.google_review_url or "https://search.google.com/local/writereview").strip()
    await q(
        "UPDATE appointments SET satisfaction_reply=%s, satisfaction_replied_at=now(), satisfaction_status='positive', google_link_sent_at=now() WHERE id=%s",
        raw_txt[:400], sat_appt["id"],
    )
    return (
        f"Memnuniyetiniz bizi çok mutlu etti, değerli geri bildiriminiz için çok teşekkür ederiz! Deneyiminizi Google Haritalar üzerinde paylaşmanız kliniğimiz için çok değerli: {g_url}",
        "memnuniyet_olumlu",
    )


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
async def run_scheduler_tick(clinic_id: int | None = None, now_dt: datetime | None = None, respect_hours: bool = True) -> dict:
    async with _SCHED_LOCK:
        ref_now = (now_dt if now_dt.tzinfo else now_dt.replace(tzinfo=TZ)) if now_dt else now()
        skipped_outside = False
        if respect_hours and clinic_id is not None:
            cinfo = await q1("SELECT working_hours_json FROM clinics WHERE id=%s", clinic_id)
            if not is_within_work_hours(ref_now, cinfo.get("working_hours_json") if cinfo else None):
                return {
                    "ok": True,
                    "at": ref_now.isoformat(),
                    "skipped_outside_hours": True,
                    "reminders_sent": 0,
                    "waves_advanced": 0,
                    "postop_sent": 0,
                }
        rmd_sent = await send_reminders(clinic_id=clinic_id, now_dt=ref_now, respect_hours=respect_hours)
        waves_adv = await advance_waves(clinic_id=clinic_id)
        postop_sent = await send_postop_checks(clinic_id=clinic_id)
        return {
            "ok": True,
            "at": ref_now.isoformat(),
            "skipped_outside_hours": skipped_outside,
            "reminders_sent": rmd_sent,
            "waves_advanced": waves_adv,
            "postop_sent": postop_sent,
        }


async def claim_daily(job: str, run_key: str) -> bool:
    """Günlük tekil görevi küme genelinde tam 1 kez sahiplenir (scheduler_runs PK = (job, run_key))."""
    row = await q1(
        "INSERT INTO scheduler_runs (job, run_key, claimed_by) VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING job",
        job, run_key, instance_id())
    return bool(row)


async def release_daily(job: str, run_key: str) -> None:
    """Görev hata verirse sahiplenmeyi geri bırakır; bir sonraki turda yeniden denenir."""
    await q("DELETE FROM scheduler_runs WHERE job=%s AND run_key=%s", job, run_key)


async def _run_daily(job: str, run_key: str, fn) -> None:
    if not await claim_daily(job, run_key):
        return
    try:
        await fn()
    except Exception:
        await release_daily(job, run_key)
        raise


async def scheduler_tick_once() -> bool:
    """Tek zamanlayıcı turu. Redis gerekmez: PG advisory kilidi + scheduler_runs. Kilidi başka worker tutuyorsa False döner."""
    async with try_lock("dentacore:scheduler_tick") as lk:
        if not lk.acquired:
            return False
        await run_scheduler_tick(respect_hours=True)
        local = datetime.now(TZ)
        today = local.strftime("%Y%m%d")
        if local.strftime("%H:%M") >= "08:30":
            await _run_daily("morning_brief", today, morning_brief)
        if local.hour >= 11:
            await _run_daily("mine_sleeping_plans", today, mine_sleeping_plans)
        if local.hour >= 3:
            await _run_daily("inbox_purge_done", today, inbox.purge_done)
    return True


async def scheduler_loop(redis=None):
    """`redis` parametresi geriye dönük uyumluluk için durur; kullanılmaz."""
    while True:
        try:
            await scheduler_tick_once()
            await heartbeat_ok("scheduler")
        except Exception as e:
            log.exception("zamanlayıcı hatası: %s", e)
            try:
                await heartbeat_error("scheduler", e)
            except Exception:
                log.exception("heartbeat_error yazılamadı")
        await asyncio.sleep(60)
