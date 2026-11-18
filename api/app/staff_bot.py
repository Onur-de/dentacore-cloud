"""Personel asistanı: kayıtlı hekim/sekreter numarasından gelen WhatsApp komutlarını LLM kullanmadan (0 token) yanıtlar."""
from __future__ import annotations

from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from .core import q

TZ = ZoneInfo("Europe/Istanbul")
HELP = ("Personel komutları:\n"
        "bugün / yarın - randevu listesi\n"
        "özet - günün özeti\n"
        "uyarılar - okunmamış uyarılar\n"
        "stok - kritik stoklar\n"
        "kasa - bugünkü tahsilat")
TR = str.maketrans("çğıöşüÇĞİÖŞÜ", "cgiosuCGIOSU")


def _norm(t: str) -> str:
    return t.strip().translate(TR).lower()


async def _day(offset: int, cid: int = 1) -> str:
    s = datetime.now(TZ).replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=offset)
    rows = await q("""SELECT a.starts_at, a.treatment, a.chair, a.status, p.display_name,
                             EXISTS (SELECT 1 FROM anamnesis x WHERE x.patient_id=a.patient_id AND cardinality(x.red_flags) > 0) AS rf
                      FROM appointments a LEFT JOIN patients p ON p.id=a.patient_id
                      WHERE a.clinic_id=%s AND a.starts_at >= %s AND a.starts_at < %s AND a.status IN ('booked','confirmed','done')
                      ORDER BY a.starts_at""", cid, s, s + timedelta(days=1))
    if not rows:
        return f"{s:%d.%m.%Y}: randevu yok."
    lines = [f"{s:%d.%m.%Y} - {len(rows)} randevu:"]
    for r in rows:
        mark = " [KIRMIZI BAYRAK]" if r["rf"] else ""
        ok = "teyitli" if r["status"] == "confirmed" else r["status"]
        lines.append(f"{r['starts_at'].astimezone(TZ):%H:%M} K{r['chair']} {r['display_name'] or 'Hasta'} - {r['treatment']} ({ok}){mark}")
    return "\n".join(lines[:40])


async def handle(staff: dict, text: str) -> str | None:
    t = _norm(text)
    cid = int(staff.get("clinic_id") or 1)
    if t in ("bugun", "randevular"):
        return await _day(0, cid)
    if t == "yarin":
        return await _day(1, cid)
    if t in ("ozet", "brief"):
        from .modules import morning_brief_text
        return await morning_brief_text(cid)
    if t in ("uyarilar", "uyari", "alarm"):
        rows = await q("SELECT kind, detail, created_at FROM alerts WHERE clinic_id=%s AND acknowledged_at IS NULL ORDER BY created_at DESC LIMIT 10", cid)
        return "\n".join(f"- {r['created_at'].astimezone(TZ):%d.%m %H:%M} {r['detail'][:160]}" for r in rows) or "Okunmamış uyarı yok."
    if t == "stok":
        rows = await q("SELECT name, qty, min_qty, unit FROM inventory_items WHERE clinic_id=%s AND active AND min_qty > 0 AND qty <= min_qty ORDER BY name", cid)
        return "\n".join(f"- {r['name']}: {r['qty']} {r['unit']} (alt sınır {r['min_qty']})" for r in rows) or "Kritik stok yok."
    if t == "kasa":
        if staff["role"] == "secretary":
            return "Kasa özeti yalnızca hekim ve yöneticiye açık."
        s = datetime.now(TZ).replace(hour=0, minute=0, second=0, microsecond=0)
        r = await q("""SELECT method, coalesce(sum(amount_kurus),0) AS k FROM payments
                       WHERE clinic_id=%s AND voided_at IS NULL AND created_at >= %s GROUP BY method""", cid, s)
        total = sum(x["k"] for x in r)
        return f"Bugünkü tahsilat: {total / 100:,.2f} TL" + "".join(f"\n- {x['method']}: {x['k'] / 100:,.2f} TL" for x in r)
    if t in ("yardim", "help", "?", "menu"):
        return HELP
    return None
