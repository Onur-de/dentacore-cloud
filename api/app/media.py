"""
Görsel kalite denetimi (0 LLM tokenı) ve hekim sesi.

Görsel: Pillow ile çözünürlük, netlik (kenar haritası varyansı) ve pozlama ölçülür. Tanı KONULMAZ;
yalnızca "hekimin değerlendirebileceği netlikte mi" sorusuna cevap verilir.

Ses: iki mod.
  - recorded: Hekimin kendi kaydettiği .ogg (opus) dosyaları /data/voice/<senaryo>.ogg altında. Önerilen mod.
  - elevenlabs: Hekimin YAZILI onayıyla oluşturulmuş ses modeli. Metin serbest değildir; yalnızca
    VOICE_SCRIPTS içindeki onaylı cümleler seslendirilir ve hastaya yapay zekâ ile üretildiği yazılı olarak bildirilir.
"""
from __future__ import annotations

import asyncio
import io
import os
import tempfile
from pathlib import Path

import hashlib
import httpx
from PIL import Image, ImageFilter, ImageOps, ImageStat

# Decompression bomb saldırılarına karşı piksel üst sınırı (25 MP)
Image.MAX_IMAGE_PIXELS = 25_000_000
MAX_UPLOAD_BYTES = 15 * 1024 * 1024
QC_DISCLAIMER_TR = "Bu sistem yalnızca teknik görüntü ve dosya kalitesini (netlik, pozlama, çözünürlük, bütünlük) kontrol eder; tıbbi teşhis koymaz."


def env(k: str, d: str = "") -> str:
    return os.environ.get(k, d)


IMG_DIR = Path(env("IMAGE_DIR", "/data/images"))
VOICE_DIR = Path(env("VOICE_DIR", "/data/voice"))

QC_MSG = {
    "tr": {
        "ok": "Görseliniz net ve hekim dosyanıza eklendi. Değerlendirme sonrası ekibimiz size dönüş yapacaktır.",
        "low_res": "Görselin çözünürlüğü düşük. Lütfen fotoğrafı sıkıştırmadan, 'belge' olarak veya daha yakından tekrar gönderin.",
        "blur": "Görsel bulanık görünüyor. Telefonu sabit tutup, iyi ışıkta ve odaklanarak tekrar çeker misiniz?",
        "dark": "Görsel çok karanlık. Lütfen aydınlık bir ortamda, flaş açıkken tekrar çekin.",
        "bright": "Görselde aşırı parlama var. Lütfen doğrudan ışık kaynağına karşı çekmeden tekrar gönderin.",
        "opg_tip": "Panoramik röntgen gönderiyorsanız filmin tamamı kadrajda olacak şekilde, düz bir ışık kaynağı önünde çekin.",
    },
    "en": {
        "ok": "Your image is clear and has been added to your file. Our team will get back to you after review.",
        "low_res": "The image resolution is low. Please resend it uncompressed (as a document) or from closer.",
        "blur": "The image looks blurry. Please hold the phone steady, use good light and focus before taking it again.",
        "dark": "The image is too dark. Please retake it in a bright place with the flash on.",
        "bright": "The image is overexposed. Please avoid shooting directly against a light source.",
        "opg_tip": "If you are sending a panoramic X-ray, keep the whole film in frame against an even light source.",
    },
}


def _msg(lang: str, key: str) -> str:
    return (QC_MSG.get(lang) or QC_MSG["en"])[key]


def assess_image(data: bytes) -> dict:
    img = Image.open(io.BytesIO(data))
    img = ImageOps.exif_transpose(img)
    w, h = img.size
    g = img.convert("L")
    small = g.copy()
    small.thumbnail((1024, 1024))
    edges = small.filter(ImageFilter.FIND_EDGES)
    sharp = ImageStat.Stat(edges).var[0]
    bright = ImageStat.Stat(small).mean[0]
    wide = w / max(1, h) > 1.6
    verdict = "ok"
    if min(w, h) < 600:
        verdict = "low_res"
    elif sharp < 120:
        verdict = "blur"
    elif bright < 40:
        verdict = "dark"
    elif bright > 225:
        verdict = "bright"
    return {
        "verdict": verdict,
        "w": w,
        "h": h,
        "sharpness": round(sharp, 1),
        "brightness": round(bright, 1),
        "possible_opg": wide,
        "sha256": hashlib.sha256(data).hexdigest(),
        "file_size_bytes": len(data),
        "is_dicom": False,
        "disclaimer": QC_DISCLAIMER_TR,
    }


_FORBIDDEN_EXTS = {
    ".exe", ".dll", ".bat", ".cmd", ".sh", ".php", ".phtml", ".jsp", ".asp", ".aspx",
    ".html", ".htm", ".xhtml", ".svg", ".js", ".mjs", ".py", ".vbs", ".ps1", ".scr",
    ".com", ".jar", ".war", ".cgi", ".pl", ".msi", ".hta", ".swf",
}
_ALLOWED_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".pgm", ".ppm", ".pdf", ".dcm", ".dicom"}


def assess_media_file(data: bytes, filename: str = "", mime: str = "") -> dict:
    """Röntgen (JPEG/PNG/WebP/DICOM), ağız içi fotoğraf ve PDF belge bütünlük + kalite kontrolü.
    Tıbbi teşhis koymaz; yalnızca dosya bütünlüğünü ve teknik görüntü kalitesini denetler.
    """
    if not data:
        raise ValueError("Boş dosya yüklenemez")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Dosya boyutu çok büyük (maksimum {MAX_UPLOAD_BYTES // (1024 * 1024)} MB)")
    sha = hashlib.sha256(data).hexdigest()
    raw_fn = (filename or "").strip()
    clean_fn = Path(raw_fn.replace("\\", "/")).name
    fn_low = clean_fn.lower()
    mime_low = (mime or "").strip().lower()

    # Güvenlik: Yasaklı uzantı, çift uzantı (örn. evil.php.jpg) veya HTML/PE/ELF/Script magic byte kontrolü
    if clean_fn:
        suffixes = [s.lower() for s in Path(clean_fn).suffixes]
        if any(s in _FORBIDDEN_EXTS for s in suffixes):
            raise ValueError("Güvenlik engeli: Çalıştırılabilir veya betik uzantılı dosya yüklenemez")
        if suffixes and suffixes[-1] not in _ALLOWED_EXTS:
            raise ValueError("Güvenlik engeli: Yalnızca JPEG, PNG, WebP, PDF ve DICOM uzantıları kabul edilir")
    head_low = data[:256].lstrip().lower()
    if (
        data[:2] == b"MZ"
        or data[:4] == b"\x7fELF"
        or head_low.startswith((b"<!doctype", b"<html", b"<script", b"<?php", b"<svg", b"#!"))
    ):
        raise ValueError("Güvenlik engeli: Zararlı veya çalıştırılabilir dosya imzası tespit edildi")

    # 1) DICOM Part 10 kontrolü (128-byte preamble + 'DICM' magic header veya .dcm uzantısı)
    is_dcm = (len(data) >= 132 and data[128:132] == b"DICM") or fn_low.endswith((".dcm", ".dicom")) or "dicom" in mime_low
    if is_dcm:
        if len(data) < 132 or data[128:132] != b"DICM":
            raise ValueError("Bozuk veya geçersiz DICOM (.dcm) dosya başlığı (DICM imzası bulunamadı)")
        return {
            "verdict": "dicom_ok",
            "w": 0,
            "h": 0,
            "sharpness": 0.0,
            "brightness": 0.0,
            "possible_opg": True,
            "sha256": sha,
            "file_size_bytes": len(data),
            "is_dicom": True,
            "mime_type": "application/dicom",
            "disclaimer": QC_DISCLAIMER_TR,
        }

    # 2) PDF Belge kontrolü (%PDF- magic header ve tam dosya aktif içerik / hex-escape taraması)
    if data[:5] == b"%PDF-" or fn_low.endswith(".pdf") or mime_low == "application/pdf":
        if data[:5] != b"%PDF-":
            raise ValueError("Bozuk veya geçersiz PDF dosya başlığı")
        import re as _re
        pdf_norm = _re.sub(
            rb"#([0-9a-fA-F]{2})",
            lambda m: bytes([int(m.group(1), 16)]),
            data,
        ).lower()
        if any(
            tok in pdf_norm
            for tok in (
                b"/javascript",
                b"/js ",
                b"/js(",
                b"/js<",
                b"/js/",
                b"/js\n",
                b"/js\r",
                b"/launch",
                b"/openaction",
                b"/aa",
                b"/richmedia",
                b"/embeddedfiles",
                b"<script",
            )
        ):
            raise ValueError("Güvenlik engeli: PDF içinde gömülü betik veya aktif eylem (/JavaScript /OpenAction) tespit edildi")
        return {
            "verdict": "document_ok",
            "w": 0,
            "h": 0,
            "sharpness": 0.0,
            "brightness": 0.0,
            "possible_opg": False,
            "sha256": sha,
            "file_size_bytes": len(data),
            "is_dicom": False,
            "mime_type": "application/pdf",
            "disclaimer": QC_DISCLAIMER_TR,
        }

    # 3) Standart görsel (JPEG/PNG/WebP/PGM) magic-byte ve kalite kontrolü
    is_jpeg = data[:3] == b"\xff\xd8\xff"
    is_png = data[:8] == b"\x89PNG\r\n\x1a\n"
    is_webp = len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    is_pnm = len(data) >= 10 and data[:2] in (b"P5", b"P6") and data[2:3] in (b"\n", b" ", b"\r", b"\t")
    if not (is_jpeg or is_png or is_webp or is_pnm):
        raise ValueError("Geçersiz görsel dosya başlığı (yalnız gerçek JPEG, PNG, WebP, PGM, PDF ve DICOM kabul edilir)")
    res = assess_image(data)
    det_mime = "image/jpeg" if is_jpeg else ("image/png" if is_png else ("image/x-portable-graymap" if is_pnm else "image/webp"))
    res["mime_type"] = det_mime
    return res


def qc_reply(result: dict, lang: str) -> str:
    text = _msg(lang, result["verdict"])
    if result["verdict"] != "ok" and result["possible_opg"]:
        text += " " + _msg(lang, "opg_tip")
    return text


def store_encrypted(pid: int, data: bytes, mime: str) -> str:
    from .core import fernet
    IMG_DIR.mkdir(parents=True, exist_ok=True)
    ext = ".jpg" if "jpeg" in mime else ".png" if "png" in mime else ".bin"
    f = IMG_DIR / f"p{pid}_{os.urandom(6).hex()}{ext}.enc"
    f.write_bytes(fernet().encrypt(data))
    return str(f)


# ---------------- Hekim sesi ----------------
VOICE_SCRIPTS = {
    "yuksek_deger_tr": "Merhaba, ben {doktor}. Mesajınızı aldık. Sizin için en doğru planı muayenede birlikte, acele etmeden çıkaracağız. Ekibim size uygun bir saat için dönüş yapacak.",
    "yuksek_deger_en": "Hello, this is {doktor}. We have received your message. We will work out the right plan together during your consultation, without any rush. My team will contact you to arrange a convenient time.",
    "yuksek_deger_de": "Hallo, hier ist {doktor}. Wir haben Ihre Nachricht erhalten. Den passenden Plan erarbeiten wir in Ruhe gemeinsam bei der Untersuchung. Mein Team meldet sich für einen Termin.",
}
VOICE_DISCLOSURE = {
    "tr": "Bu sesli mesaj, hekimimizin onayıyla onun ses modeli kullanılarak üretilmiştir.",
    "en": "This voice message was generated with our dentist's approved voice model.",
    "de": "Diese Sprachnachricht wurde mit dem genehmigten Stimmmodell unseres Zahnarztes erzeugt.",
}


async def _to_ogg_opus(mp3: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as d:
        src, dst = Path(d) / "in.mp3", Path(d) / "out.ogg"
        src.write_bytes(mp3)
        p = await asyncio.create_subprocess_exec("ffmpeg", "-y", "-loglevel", "error", "-i", str(src),
                                                 "-ac", "1", "-c:a", "libopus", "-b:a", "32k", str(dst))
        await p.wait()
        if p.returncode != 0:
            raise RuntimeError("ffmpeg dönüştürme hatası")
        return dst.read_bytes()


async def voice_note(scenario: str, lang: str) -> tuple[bytes, bool] | None:
    """(ogg_bytes, yapay_mi) döner. Uygun ses yoksa None."""
    key = f"{scenario}_{lang}"
    rec = VOICE_DIR / f"{key}.ogg"
    if rec.exists():
        return rec.read_bytes(), False
    if env("VOICE_PROVIDER", "off") != "elevenlabs" or key not in VOICE_SCRIPTS:
        return None
    text = VOICE_SCRIPTS[key].replace("{doktor}", env("DOCTOR_DISPLAY_NAME", "hekiminiz"))
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(f"https://api.elevenlabs.io/v1/text-to-speech/{env('ELEVENLABS_VOICE_ID')}",
                         params={"output_format": "mp3_44100_128"},
                         headers={"xi-api-key": env("ELEVENLABS_API_KEY")},
                         json={"text": text, "model_id": "eleven_multilingual_v2"})
        r.raise_for_status()
    return await _to_ogg_opus(r.content), True
