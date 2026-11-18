"""Android (Google Takvim) ve iPhone (Apple Takvim / webcal://) RFC 5545 takvim motoru."""
from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode


def _dt_utc(v: datetime | str) -> datetime:
    if isinstance(v, str):
        s = v.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
    else:
        dt = v
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone(timedelta(hours=3)))
    return dt.astimezone(timezone.utc)


def _fmt_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ics_escape(s: str) -> str:
    return (
        str(s or "")
        .replace("\\", "\\\\")
        .replace("\r\n", "\\n")
        .replace("\n", "\\n")
        .replace(";", "\\;")
        .replace(",", "\\,")
    )


def _event_lines(appt: dict, clinic_name: str, address: str = "") -> list[str]:
    start = _dt_utc(appt["starts_at"])
    dur = int(appt.get("duration_min") or 30)
    end = start + timedelta(minutes=dur)
    patient = appt.get("patient") or appt.get("patient_name") or "Hasta"
    treatment = appt.get("treatment") or "Muayene"
    chair = appt.get("chair") or "1"
    doctor = appt.get("doctor") or ""
    status = "CANCELLED" if appt.get("status") == "cancelled" else "CONFIRMED"
    summary = f"{patient} - {treatment} (Koltuk {chair})"
    desc_parts = [f"Klinik: {clinic_name}", f"Hasta: {patient}", f"İşlem: {treatment}", f"Koltuk: {chair}"]
    if doctor:
        desc_parts.append(f"Hekim: {doctor}")
    if appt.get("red_flag"):
        desc_parts.append("UYARI: KIRMIZI BAYRAKLI ANAMNEZ")
    lines = [
        "BEGIN:VEVENT",
        f"UID:dentacore-{appt.get('id', 0)}@dentacore.local",
        f"DTSTAMP:{_fmt_utc(datetime.now(timezone.utc))}",
        f"DTSTART:{_fmt_utc(start)}",
        f"DTEND:{_fmt_utc(end)}",
        f"SUMMARY:{ics_escape(summary)}",
        f"DESCRIPTION:{ics_escape(' | '.join(desc_parts))}",
        f"STATUS:{status}",
    ]
    if address or clinic_name:
        lines.append(f"LOCATION:{ics_escape(address or clinic_name)}")
    lines.extend([
        "BEGIN:VALARM",
        "TRIGGER:-PT60M",
        "ACTION:DISPLAY",
        f"DESCRIPTION:{ics_escape('1 saat sonra randevu: ' + summary)}",
        "END:VALARM",
        "BEGIN:VALARM",
        "TRIGGER:-PT15M",
        "ACTION:DISPLAY",
        f"DESCRIPTION:{ics_escape('15 dk sonra randevu: ' + summary)}",
        "END:VALARM",
        "END:VEVENT",
    ])
    return lines


def appointment_ics(appt: dict, clinic_name: str, address: str = "") -> str:
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//DentaCore//Klinik Takvim v5.0//TR",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{ics_escape(clinic_name + ' Randevu')}",
    ]
    lines.extend(_event_lines(appt, clinic_name, address))
    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"


def feed_ics(appts: list[dict], clinic_name: str, address: str = "") -> str:
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//DentaCore//Klinik Canli Takvim v5.0//TR",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{ics_escape(clinic_name + ' Randevu Takvimi')}",
        "REFRESH-INTERVAL;VALUE=DURATION:PT15M",
        "X-PUBLISHED-TTL:PT15M",
    ]
    for a in appts:
        if a.get("status") in ("booked", "confirmed", "done", None):
            lines.extend(_event_lines(a, clinic_name, address))
    lines.append("END:VCALENDAR")
    return "\r\n".join(lines) + "\r\n"


def google_calendar_url(appt: dict, clinic_name: str, address: str = "") -> str:
    start = _dt_utc(appt["starts_at"])
    dur = int(appt.get("duration_min") or 30)
    end = start + timedelta(minutes=dur)
    patient = appt.get("patient") or appt.get("patient_name") or "Hasta"
    treatment = appt.get("treatment") or "Muayene"
    chair = appt.get("chair") or "1"
    doctor = appt.get("doctor") or ""
    details = f"Klinik: {clinic_name}\nHasta: {patient}\nİşlem: {treatment}\nKoltuk: {chair}"
    if doctor:
        details += f"\nHekim: {doctor}"
    if appt.get("red_flag"):
        details += "\nUYARI: Kırmızı Bayraklı Anamnez"
    q = urlencode({
        "action": "TEMPLATE",
        "text": f"{patient} - {treatment} (K{chair})",
        "dates": f"{_fmt_utc(start)}/{_fmt_utc(end)}",
        "details": details,
        "location": address or clinic_name,
    })
    return f"https://calendar.google.com/calendar/render?{q}"


def _feed_key(secret: str | None = None) -> bytes:
    return (secret or os.environ.get("ADMIN_TOKEN") or "dentacore-dev-cal-key").encode()


def calendar_feed_token(clinic_id: int, secret: str | None = None) -> str:
    cid = int(clinic_id)
    sig = hmac.new(_feed_key(secret), f"cal:{cid}".encode(), hashlib.sha256).hexdigest()[:24]
    return f"{cid}.{sig}"


def verify_feed_token(token: str, secret: str | None = None) -> int | None:
    if not token or "." not in token:
        return None
    raw_cid, sig = token.split(".", 1)
    try:
        cid = int(raw_cid)
    except ValueError:
        return None
    good = hmac.new(_feed_key(secret), f"cal:{cid}".encode(), hashlib.sha256).hexdigest()[:24]
    return cid if hmac.compare_digest(good, sig) else None
