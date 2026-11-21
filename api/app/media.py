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
import base64
import contextlib
import hashlib
import hmac
import io
import os
import re
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

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
        "invalid": "Bu dosya okunamadı ya da desteklenmiyor. Lütfen fotoğrafı JPEG veya PNG olarak yeniden gönderin.",
    },
    "en": {
        "ok": "Your image is clear and has been added to your file. Our team will get back to you after review.",
        "low_res": "The image resolution is low. Please resend it uncompressed (as a document) or from closer.",
        "blur": "The image looks blurry. Please hold the phone steady, use good light and focus before taking it again.",
        "dark": "The image is too dark. Please retake it in a bright place with the flash on.",
        "bright": "The image is overexposed. Please avoid shooting directly against a light source.",
        "opg_tip": "If you are sending a panoramic X-ray, keep the whole film in frame against an even light source.",
        "invalid": "This file could not be read or is not supported. Please resend the photo as JPEG or PNG.",
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


# ======================================================================================
# Kalıcı hasta dosyası deposu: MEDIA_BACKEND=local (kalıcı disk) | s3 (S3/R2/MinIO uyumlu)
#
# Depoya giden her nesne önce Fernet ile şifrelenir (istemci tarafı şifreleme: nesne deposu
# sağlayıcısı düz veriyi hiç görmez). Veritabanında yalnızca depo anahtarı ve düz verinin SHA-256 özeti
# tutulur; okurken özet yeniden hesaplanır, uyuşmazlık "bütünlük hatası" sayılır.
# Anahtar biçimi: c<klinik>/p<hasta>/<32 hex>.enc  (eski satırlardaki çıplak dosya adları da çözülür).
# ======================================================================================
class MediaError(Exception):
    """Dosya deposu hatalarının üst sınıfı."""


class MediaNotFound(MediaError):
    """Depoda böyle bir nesne yok."""


class MediaIntegrityError(MediaError):
    """Şifre çözme ya da SHA-256 doğrulaması başarısız: dosya bozulmuş veya değiştirilmiş."""


class MediaStorageError(MediaError):
    """Depoya ulaşılamadı / yapılandırma hatalı."""


class MediaLinkError(MediaError):
    """İmzalı indirme bağlantısı geçersiz. reason: format | signature | expired | key"""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _check_key(key: str) -> str:
    segs = (key or "").split("/")
    if (
        not key
        or len(key) > 255
        or not re.fullmatch(r"[A-Za-z0-9._/-]+", key)
        or any(s in ("", ".", "..") for s in segs)
    ):
        raise MediaError("Geçersiz depo anahtarı")
    return key


class LocalStore:
    """Kalıcı diske (Compose volume / Render diski) yazar. Anahtar kök klasörün dışına çıkamaz."""

    backend = "local"

    def __init__(self, root: Path):
        self.root = Path(root)

    def _path(self, key: str) -> Path:
        _check_key(key)
        root = self.root.resolve()
        p = (root / key).resolve()
        if root not in p.parents:
            raise MediaError("Anahtar depo klasörünün dışına çıkıyor")
        return p

    def put(self, key: str, blob: bytes, sha256: str = "") -> None:
        p = self._path(key)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(p.name + "." + secrets.token_hex(4) + ".tmp")
            try:
                with open(tmp, "wb") as f:
                    f.write(blob)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp, p)  # yarım yazılmış dosya asla görünmez
            finally:
                with contextlib.suppress(OSError):
                    tmp.unlink()
        except OSError as ex:
            raise MediaStorageError(f"Diske yazılamadı: {type(ex).__name__}") from ex

    def get(self, key: str) -> bytes:
        try:
            return self._path(key).read_bytes()
        except FileNotFoundError:
            raise MediaNotFound(key) from None
        except OSError as ex:
            raise MediaStorageError(f"Diskten okunamadı: {type(ex).__name__}") from ex

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def delete(self, key: str) -> bool:
        """Silinen nesne vardıysa True; zaten yoksa False (tekrar silme güvenlidir)."""
        try:
            self._path(key).unlink()
            return True
        except FileNotFoundError:
            return False
        except OSError as ex:
            raise MediaStorageError(f"Diskten silinemedi: {type(ex).__name__}") from ex


class S3Store:
    """S3 uyumlu nesne deposu (AWS S3, Cloudflare R2, MinIO, Hetzner Object Storage...). botocore ile konuşur."""

    backend = "s3"

    def __init__(self, bucket: str, prefix: str = "", *, endpoint_url: str = "", region: str = "",
                 access_key: str = "", secret_key: str = ""):
        import botocore.session
        from botocore.config import Config

        self.bucket = bucket
        self.prefix = (prefix.strip("/") + "/") if prefix.strip("/") else ""
        cfg = Config(
            signature_version="s3v4",
            retries={"max_attempts": 3, "mode": "standard"},
            connect_timeout=5,
            read_timeout=30,
            s3={"addressing_style": "path" if endpoint_url else "auto"},
        )
        self.client = botocore.session.get_session().create_client(
            "s3",
            region_name=region or ("auto" if endpoint_url else "us-east-1"),
            endpoint_url=endpoint_url or None,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=cfg,
        )

    def _k(self, key: str) -> str:
        return self.prefix + _check_key(key)

    @staticmethod
    def _code(ex: Exception) -> str:
        return str(getattr(ex, "response", {}).get("Error", {}).get("Code", ""))

    def put(self, key: str, blob: bytes, sha256: str = "") -> None:
        from botocore.exceptions import BotoCoreError, ClientError
        try:
            self.client.put_object(Bucket=self.bucket, Key=self._k(key), Body=blob,
                                   ContentType="application/octet-stream",
                                   Metadata={"sha256": sha256} if sha256 else {})
        except (ClientError, BotoCoreError) as ex:
            raise MediaStorageError(f"S3 yazma hatası: {self._code(ex) or type(ex).__name__}") from ex

    def get(self, key: str) -> bytes:
        from botocore.exceptions import BotoCoreError, ClientError
        try:
            return self.client.get_object(Bucket=self.bucket, Key=self._k(key))["Body"].read()
        except ClientError as ex:
            if self._code(ex) in ("NoSuchKey", "404", "NotFound"):
                raise MediaNotFound(key) from None
            raise MediaStorageError(f"S3 okuma hatası: {self._code(ex) or type(ex).__name__}") from ex
        except BotoCoreError as ex:
            raise MediaStorageError(f"S3 okuma hatası: {type(ex).__name__}") from ex

    def exists(self, key: str) -> bool:
        from botocore.exceptions import BotoCoreError, ClientError
        try:
            self.client.head_object(Bucket=self.bucket, Key=self._k(key))
            return True
        except ClientError as ex:
            if self._code(ex) in ("404", "NoSuchKey", "NotFound"):
                return False
            raise MediaStorageError(f"S3 sorgu hatası: {self._code(ex) or type(ex).__name__}") from ex
        except BotoCoreError as ex:
            raise MediaStorageError(f"S3 sorgu hatası: {type(ex).__name__}") from ex

    def delete(self, key: str) -> bool:
        from botocore.exceptions import BotoCoreError, ClientError
        existed = self.exists(key)
        try:
            self.client.delete_object(Bucket=self.bucket, Key=self._k(key))
        except (ClientError, BotoCoreError) as ex:
            raise MediaStorageError(f"S3 silme hatası: {self._code(ex) or type(ex).__name__}") from ex
        return existed


_STORES: dict[tuple, object] = {}
_STORES_LOCK = threading.Lock()


def backend_name() -> str:
    return (env("MEDIA_BACKEND", "local") or "local").strip().lower()


def get_store():
    """Ortam değişkenlerine göre depoyu (önbellekli) döndürür. Ayar değişirse yeni depo kurulur."""
    be = backend_name()
    if be == "local":
        sig: tuple = ("local", env("IMAGE_DIR", "/data/images").strip())
    elif be == "s3":
        sig = ("s3", *(env(k).strip() for k in (
            "S3_BUCKET", "S3_PREFIX", "S3_ENDPOINT_URL", "S3_REGION", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY")))
        if not (sig[1] and sig[5] and sig[6]):
            raise MediaStorageError("MEDIA_BACKEND=s3 iken S3_BUCKET, S3_ACCESS_KEY_ID ve S3_SECRET_ACCESS_KEY zorunlu")
    else:
        raise MediaStorageError("MEDIA_BACKEND 'local' ya da 's3' olmalı")
    with _STORES_LOCK:
        st = _STORES.get(sig)
        if st is None:
            if be == "local":
                st = LocalStore(Path(sig[1]))
            else:
                st = S3Store(sig[1], sig[2], endpoint_url=sig[3], region=sig[4], access_key=sig[5], secret_key=sig[6])
            _STORES[sig] = st
        return st


def reset_store_cache() -> None:
    with _STORES_LOCK:
        _STORES.clear()


def selfcheck() -> dict:
    """Yaz → oku → sil sondası. Yanlış S3 anahtarı/bucket ya da yazılamayan disk açılışta yakalanır."""
    st = get_store()
    probe = f"_selfcheck/{secrets.token_hex(8)}.bin"
    payload = secrets.token_bytes(32)
    st.put(probe, payload, hashlib.sha256(payload).hexdigest())
    try:
        ok = st.get(probe) == payload
    finally:
        st.delete(probe)
    if not ok:
        raise MediaStorageError("Depo sondası: okunan veri yazılanla aynı değil")
    return {"backend": st.backend, "ok": True}


def new_key(clinic_id: int, pid: int) -> str:
    return f"c{int(clinic_id)}/p{int(pid)}/{secrets.token_hex(16)}.enc"


def _decrypt_checked(blob: bytes, expected_sha256: str = "") -> bytes:
    from cryptography.fernet import InvalidToken

    from .core import fernet
    try:
        data = fernet().decrypt(blob)
    except InvalidToken:
        raise MediaIntegrityError("Şifre çözülemedi: dosya bozulmuş ya da farklı anahtarla şifrelenmiş") from None
    if expected_sha256 and not hmac.compare_digest(hashlib.sha256(data).hexdigest(), expected_sha256.strip().lower()):
        raise MediaIntegrityError("SHA-256 özeti kayıttakiyle uyuşmuyor")
    return data


def save_encrypted(clinic_id: int, pid: int, data: bytes, sha256: str = "") -> str:
    """Şifreleyip depoya yazar, depo anahtarını döndürür."""
    from .core import fernet
    sha = sha256 or hashlib.sha256(data).hexdigest()
    key = new_key(clinic_id, pid)
    get_store().put(key, fernet().encrypt(data), sha)
    return key


def load_decrypted(key: str, expected_sha256: str = "") -> bytes:
    """Depodan okuyup çözer; kayıtlı SHA-256 verilmişse doğrular (uyuşmazlıkta MediaIntegrityError)."""
    return _decrypt_checked(get_store().get(key), expected_sha256)


def delete_stored(key: str) -> bool:
    return get_store().delete(key)


def store_encrypted(pid: int, data: bytes, mime: str = "", clinic_id: int = 0) -> str:
    """Geriye dönük uyumluluk: yeni kod save_encrypted / persist_patient_media kullanır."""
    return save_encrypted(clinic_id, pid, data)


async def persist_patient_media(clinic_id: int, pid: int, data: bytes, *, filename: str, category: str = "photo",
                                stage: str = "general", uploaded_by: int | None = None, qc: dict) -> tuple[int, str]:
    """Dosyayı depoya yazar, sonra patient_media satırını ekler. Satır eklenemezse nesneyi geri siler
    (depoda sahipsiz şifreli dosya kalmaz). (media_id, depo_anahtarı) döndürür."""
    from .core import q1
    sha = str(qc.get("sha256") or hashlib.sha256(data).hexdigest())
    is_dcm = bool(qc.get("is_dicom"))
    mime = str(qc.get("mime_type") or "image/jpeg")
    key = await asyncio.to_thread(save_encrypted, clinic_id, pid, data, sha)
    try:
        row = await q1(
            """INSERT INTO patient_media
               (clinic_id,patient_id,category,stage,original_filename,filename,mime_type,file_size_bytes,size_bytes,
                sha256_hash,sha256,encrypted_path,encrypted_file,is_dicom,width,height,sharpness,brightness,qc_verdict,
                uploaded_by,created_at)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            clinic_id, pid, "xray" if is_dcm else category, stage, filename, filename, mime, len(data), len(data),
            sha, sha, key, key, 1 if is_dcm else 0, int(qc.get("w") or 0), int(qc.get("h") or 0),
            float(qc.get("sharpness") or 0), float(qc.get("brightness") or 0), str(qc.get("verdict") or "ok"),
            uploaded_by, datetime.now(timezone.utc).isoformat(),
        )
        if not row:
            raise MediaStorageError("Dosya kaydı oluşturulamadı")
    except BaseException:
        with contextlib.suppress(Exception):
            await asyncio.to_thread(delete_stored, key)
        raise
    return int(row["id"]), key


# ---------------- Süreli, imzalı indirme bağlantısı ----------------
LINK_DEFAULT_TTL = 300
LINK_MIN_TTL = 30
LINK_MAX_TTL = 3600


def _link_secret() -> bytes:
    base = env("DATA_ENCRYPTION_KEY") or env("ADMIN_TOKEN")
    if not base:
        raise MediaLinkError("key")
    return hmac.new(base.encode(), b"dentacore/patient-media-link/v1", hashlib.sha256).digest()


def _sig(body: str) -> str:
    return base64.urlsafe_b64encode(hmac.new(_link_secret(), body.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()


def sign_link(media_id: int, clinic_id: int, user_id: int, ttl: int = LINK_DEFAULT_TTL,
              now: float | None = None) -> tuple[str, int]:
    """(belirteç, bitiş_unix) döndürür. Belirteç dosyaya, kliniğe ve isteyen kullanıcıya bağlıdır."""
    ttl = max(LINK_MIN_TTL, min(int(ttl), LINK_MAX_TTL))
    exp = int(time.time() if now is None else now) + ttl
    body = f"{int(media_id)}.{int(clinic_id)}.{int(user_id)}.{exp}"
    return f"{body}.{_sig(body)}", exp


def verify_link(token: str, now: float | None = None) -> dict:
    parts = (token or "").split(".")
    if len(parts) != 5 or len(token) > 300:
        raise MediaLinkError("format")
    body = ".".join(parts[:4])
    if not hmac.compare_digest(parts[4], _sig(body)):
        raise MediaLinkError("signature")
    try:
        mid, cid, uid, exp = (int(x) for x in parts[:4])
    except ValueError:
        raise MediaLinkError("format") from None
    if (time.time() if now is None else now) > exp:
        raise MediaLinkError("expired")
    return {"media_id": mid, "clinic_id": cid, "user_id": uid, "exp": exp}


# ---------------- Depolar arası güvenli taşıma (örn. local → s3) ----------------
def migrate_object(src, dst, key: str, expected_sha256: str = "", *, delete_source: bool = False) -> str:
    """Nesneyi kaynaktan hedefe kopyalar. Sırayla: kaynaktan oku → şifreyi çöz + SHA-256 doğrula → hedefe yaz →
    hedeften geri oku, birebir aynı mı bak → ancak hepsi geçerse VE delete_source=True ise kaynağı sil.
    Doğrulanamayan nesneye asla dokunulmaz. Dönüş: 'copied' | 'copied_source_deleted'."""
    blob = src.get(key)                                  # yoksa MediaNotFound
    _decrypt_checked(blob, expected_sha256)              # bozuksa MediaIntegrityError
    dst.put(key, blob, expected_sha256)
    if dst.get(key) != blob:
        raise MediaIntegrityError("Hedefte okunan nesne kaynakla aynı değil")
    if delete_source:
        src.delete(key)
        return "copied_source_deleted"
    return "copied"


def migrate_rows(src, dst, rows: list[dict], *, delete_source: bool = False) -> dict:
    """rows: [{'id', 'encrypted_path', 'sha256_hash'}]. Hata veren satır diğerlerini durdurmaz; rapor döner."""
    rep: dict = {"copied": 0, "source_deleted": 0, "missing": [], "corrupt": [], "errors": []}
    for r in rows:
        key = str(r.get("encrypted_path") or "")
        if not key:
            continue
        try:
            res = migrate_object(src, dst, key, str(r.get("sha256_hash") or ""), delete_source=delete_source)
            rep["copied"] += 1
            rep["source_deleted"] += int(res == "copied_source_deleted")
        except MediaNotFound:
            rep["missing"].append(r.get("id"))
        except MediaIntegrityError:
            rep["corrupt"].append(r.get("id"))
        except MediaError as ex:
            rep["errors"].append({"id": r.get("id"), "error": str(ex)})
    return rep


async def migrate_all_media(src, dst, *, delete_source: bool = False) -> dict:
    """patient_media tablosundaki tüm dosyaları src → dst taşır (varsayılan: kaynak silinmez)."""
    from .core import q
    rows = await q("SELECT id, encrypted_path, sha256_hash FROM patient_media WHERE encrypted_path <> '' ORDER BY id")
    return await asyncio.to_thread(migrate_rows, src, dst, rows, delete_source=delete_source)


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
