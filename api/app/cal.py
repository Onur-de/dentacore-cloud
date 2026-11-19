"""Android (Google Takvim) ve iPhone (Apple Takvim / webcal://) RFC 5545 takvim motoru."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

_EPHEMERAL_FEED_KEY: bytes | None = None
_SECRETS_FILE = Path(__file__).resolve().parents[2] / ".local_secrets.json"


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


def _initials(name: str | None) -> str:
    """Takvim akışında hasta mahremiyeti için tam ad yerine baş harf döndürür (örn. 'A. Y.')."""
    cleaned = re.sub(r"\([^)]*\)", "", str(name or "")).strip()
    parts = [p for p in cleaned.split() if p]
    if not parts:
        return "Hasta"
    return " ".join(f"{p[0].upper()}." for p in parts[:4])


def _event_lines(appt: dict, clinic_name: str, address: str = "") -> list[str]:
    start = _dt_utc(appt["starts_at"])
    dur = int(appt.get("duration_min") or 30)
    end = start + timedelta(minutes=dur)
    patient_label = _initials(appt.get("patient") or appt.get("patient_name"))
    chair = appt.get("chair") or "1"
    doctor = appt.get("doctor") or ""
    status = "CANCELLED" if appt.get("status") == "cancelled" else "CONFIRMED"
    summary = f"{patient_label} - Diş Randevusu (Koltuk {chair})"
    desc_parts = [f"Klinik: {clinic_name}", f"Hasta: {patient_label}", "İşlem: Diş Randevusu", f"Koltuk: {chair}"]
    if doctor:
        desc_parts.append(f"Hekim: {doctor}")
    seq = int(appt.get("sequence") or 0)
    last_mod_raw = appt.get("updated_at") or appt.get("created_at")
    last_mod = _dt_utc(last_mod_raw) if last_mod_raw else datetime.now(timezone.utc)
    lines = [
        "BEGIN:VEVENT",
        f"UID:dentacore-{appt.get('id', 0)}@dentacore.local",
        f"SEQUENCE:{seq}",
        f"DTSTAMP:{_fmt_utc(datetime.now(timezone.utc))}",
        f"LAST-MODIFIED:{_fmt_utc(last_mod)}",
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
    patient_label = _initials(appt.get("patient") or appt.get("patient_name"))
    chair = appt.get("chair") or "1"
    doctor = appt.get("doctor") or ""
    details = f"Klinik: {clinic_name}\nHasta: {patient_label}\nİşlem: Diş Randevusu\nKoltuk: {chair}"
    if doctor:
        details += f"\nHekim: {doctor}"
    q = urlencode({
        "action": "TEMPLATE",
        "text": f"{patient_label} - Diş Randevusu (K{chair})",
        "dates": f"{_fmt_utc(start)}/{_fmt_utc(end)}",
        "details": details,
        "location": address or clinic_name,
    })
    return f"https://calendar.google.com/calendar/render?{q}"


def _feed_key(secret: str | None = None) -> bytes:
    global _EPHEMERAL_FEED_KEY
    if secret:
        return secret.encode()
    env_val = os.environ.get("CALENDAR_SECRET") or os.environ.get("ADMIN_TOKEN")
    if env_val:
        return env_val.encode()
    if _SECRETS_FILE.is_file():
        try:
            data = json.loads(_SECRETS_FILE.read_text(encoding="utf-8"))
            file_val = data.get("CALENDAR_SECRET") or data.get("ADMIN_TOKEN")
            if file_val:
                return str(file_val).encode()
        except Exception:
            pass
    if _EPHEMERAL_FEED_KEY is None:
        _EPHEMERAL_FEED_KEY = secrets.token_bytes(32)
    return _EPHEMERAL_FEED_KEY


def calendar_feed_token(
    clinic_id: int,
    version: int = 1,
    ttl_seconds: int = 90 * 86400,
    secret: str | None = None,
) -> str:
    cid = int(clinic_id)
    ver = max(1, int(version))
    exp = int(time.time()) + int(ttl_seconds)
    sig = hmac.new(_feed_key(secret), f"cal:{cid}:{ver}:{exp}".encode(), hashlib.sha256).hexdigest()[:24]
    return f"{cid}.{ver}.{exp}.{sig}"


def verify_feed_token_parts(token: str, secret: str | None = None) -> tuple[int, int] | None:
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 4:
        return None
    raw_cid, raw_ver, raw_exp, sig = parts
    try:
        cid = int(raw_cid)
        ver = int(raw_ver)
        exp = int(raw_exp)
    except ValueError:
        return None
    if cid < 1 or ver < 1 or exp < int(time.time()):
        return None
    good = hmac.new(_feed_key(secret), f"cal:{cid}:{ver}:{exp}".encode(), hashlib.sha256).hexdigest()[:24]
    if not hmac.compare_digest(good, sig):
        return None
    return cid, ver


def verify_feed_token(token: str, expected_version: int | None = None, secret: str | None = None) -> int | None:
    parsed = verify_feed_token_parts(token, secret=secret)
    if not parsed:
        return None
    cid, ver = parsed
    if expected_version is not None and ver != int(expected_version):
        return None
    return cid
