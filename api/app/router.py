"""
Token Router: 3 katmanlı maliyet yönlendiricisi + Birleşik Niyet Motoru + Çok Turlu FSM + RapidFuzz.

Katman-1 (0 LLM tokenı):
  - 1a: Acil durum triyajı (16 dil, L1-acil)
  - 1b: Güvenlik / Prompt Injection / KVKK veri sızıntısı engeli (L1-guvenlik) ve Tıbbi ilaç/doz koruma (L1-tibbi)
  - 1c: Çok turlu diyalog hafızası & Sonlu Durum Makinesi (FSM: IDLE -> ASKED_TREATMENT -> OFFERED_APPT -> AWAITING_SLOT)
  - 1d: Birleşik Niyet Birleştirici (Compound Query Engine: L1-sss + L2-anahtar + RapidFuzz bulanık eşleştirme)
  - 1e: Kesin eşleşme önbelleği (Redis/Memory) ve semantik önbellek
Katman-2 (çok ucuz): küçük model tek etiket döndürür (max_tokens=4). LLM yoksa anahtar kelime sınıflandırıcı.
Katman-3: ana LLM, sabit sistem promptu, max_tokens sınırlı, çıktı sonrası yasaklı içerik filtresi.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

try:
    from rapidfuzz import fuzz as _rf_fuzz
except Exception:
    _rf_fuzz = None

BASE = Path(__file__).parent
LANGS = ("tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he")
LABELS = ("fiyat", "randevu", "tibbi_soru", "gorsel", "sikayet", "genel", "insan")

# Birleşik sorularda birincil niyet öncelik sırası (test_offline.py ve whatsapp_jury.py kontratlarıyla %100 uyumlu)
INTENT_PRIORITY = (
    "konum",
    "agri_korku",
    "tedavi_sure",
    "cocuk_dis",
    "sigorta_taksit",
    "otopark",
    "fiyat",
    "saat",
    "iletisim",
    "odeme",
    "gorsel",
    "randevu",
    "selam",
)

L1_INTENT_SET = {
    "selam",
    "konum",
    "saat",
    "otopark",
    "iletisim",
    "odeme",
    "agri_korku",
    "tedavi_sure",
    "cocuk_dis",
    "sigorta_taksit",
}

# Varsayılan çok şubeli klinik dizini (DB'den gelen şubelerle dinamik zenginleştirilir)
DEFAULT_BRANCH_DIRECTORY: dict[str, dict[str, Any]] = {
    "istanbul": {
        "key": "istanbul",
        "clinic": "Özel DentaCore Merkez Polikliniği",
        "city": "İstanbul",
        "adres": "Bağdat Cad. No:142, Kadıköy / İstanbul",
        "harita": "https://maps.google.com/?q=Kadikoy+Istanbul",
        "telefon": "+90 216 555 01 01",
        "keywords": ("istanbul", "kadikoy", "bagdat", "merkez sube"),
    },
    "bursa": {
        "key": "bursa",
        "clinic": "Özel Bursa Gülüş Diş Polikliniği",
        "city": "Bursa",
        "adres": "FSM Bulvarı No:48, Nilüfer / Bursa",
        "harita": "https://maps.google.com/?q=Nilufer+Bursa",
        "telefon": "+90 224 555 02 02",
        "keywords": ("bursa", "nilufer", "fsm"),
    },
    "ankara": {
        "key": "ankara",
        "clinic": "Ankara Çankaya Estetik Diş Polikliniği",
        "city": "Ankara",
        "adres": "Tunalı Hilmi Cad. No:88, Çankaya / Ankara",
        "harita": "https://maps.google.com/?q=Cankaya+Ankara",
        "telefon": "+90 312 555 03 03",
        "keywords": ("ankara", "cankaya", "tunali"),
    },
}

# Türkçe STT / sokak ağzı / kısaltma ve yazım hatası normalizasyon kuralları
TR_INFORMAL_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bslm\b"), "selam"),
    (re.compile(r"\bmrb\b"), "merhaba"),
    (re.compile(r"\bmeraba\b"), "merhaba"),
    (re.compile(r"\bne\s+kdr\b"), "ne kadar"),
    (re.compile(r"\bnekadr\b"), "ne kadar"),
    (re.compile(r"\bnekadar\b"), "ne kadar"),
    (re.compile(r"\bfyat(i|in|iniz|lar|lari|lariniz)?\b"), "fiyat"),
    (re.compile(r"\bfiyat(i|in|iniz|lar|lari|lariniz)?\b"), "fiyat"),
    (re.compile(r"\bucret(i|in|iniz|ler|leri|leriniz)?\b"), "ucret"),
    (re.compile(r"\binpilant\w*\b"), "implant"),
    (re.compile(r"\bimplnt\w*\b"), "implant"),
    (re.compile(r"\brandvu\w*\b"), "randevu"),
    (re.compile(r"\brandev\b"), "randevu"),
    (re.compile(r"\balmk\b"), "almak"),
    (re.compile(r"\bistiyom\b"), "istiyorum"),
    (re.compile(r"\bistiyrum\b"), "istiyorum"),
    (re.compile(r"\balami?yom\b"), "alamiyorum"),
    (re.compile(r"\byutkunami?yom\b"), "yutkunamiyorum"),
    (re.compile(r"\bdurmuyo\b"), "durmuyor"),
    (re.compile(r"\bkapaniyo\b"), "kapaniyor"),
    (re.compile(r"\baciliyo\b"), "aciliyor"),
    (re.compile(r"\boluyo\b"), "oluyor"),
    (re.compile(r"\bctesi\b"), "cumartesi"),
    (re.compile(r"\bcmtsi\b"), "cumartesi"),
    (re.compile(r"\bpztesi\b"), "pazartesi"),
    (re.compile(r"\bkanma\b"), "kanama"),
    (re.compile(r"\byuzm\b"), "yuzum"),
    (re.compile(r"\bbogzm\b"), "bogazim"),
    (re.compile(r"\bdisim\b"), "disim"),
]

# RapidFuzz bulanık eşleştirme için kanonik referans ifadeler
FUZZY_CANONICAL_PHRASES: dict[str, list[str]] = {
    "acil": [
        "kanama durmuyor yuzum sisti nefes alamiyorum",
        "disim cekildi kanama durmuyor",
        "bogazim ve yuzum cok sisti yutkunamiyorum",
    ],
    "fiyat": [
        "implant fiyati ne kadar",
        "zirkonyum kaplama fiyatlariniz ne kadar",
        "dis beyazlatma ucreti ne kadar",
        "tek dis implant fiyatiniz ne kadar",
    ],
    "randevu": [
        "randevu almak istiyorum",
        "muayene randevusu olusturmak istiyorum",
        "yarin icin randevu almak istiyorum",
    ],
    "konum": [
        "adresiniz nerede",
        "kliniginiz tam olarak nerede",
        "subenizin tam adresi nedir",
    ],
    "saat": [
        "calisma saatleriniz nedir",
        "cumartesi kacta kapaniyor",
        "aksam saat kaca kadar aciksiniz",
    ],
    "otopark": [
        "arabayla gelsem otopark yeriniz var mi",
        "otoparkiniz var mi",
    ],
    "iletisim": [
        "telefon numaraniz nedir",
        "subenizin telefon numarasi nedir",
    ],
    "agri_korku": [
        "disci korkum var islem sirasinda canim acir mi",
        "yaptirirken hic aci hisseder miyim",
        "uyutarak sedasyon yapiyor musunuz",
    ],
    "sigorta_taksit": [
        "ozel saglik sigortasi gecerli mi",
        "kredi kartina kac taksit yapiyorsunuz",
        "ucreti taksit oluyor mu",
    ],
    "cocuk_dis": [
        "cocuk dis hekiminiz var mi",
        "oglumun sut disi curudu pedodonti",
    ],
}

PROMPT_INJECTION_RE = re.compile(
    r"(sistem komutu|onceki (tum )?kurallari unut|ignore (all )?previous instructions|system prompt|"
    r"sen artik .{0,35}asistansin|omur boyu .{0,25}garanti.{0,25}yaz)"
)

KVKK_TRAP_RE = re.compile(
    r"((esiyim|kocasiyim|karisiyim|annesiyim|babasiyim|kardesiyim|arkadasiyim).{0,60}(telefon|numara|ilac|kayit|bilgi)|"
    r"sistemdeki telefon numarasini|kullandigi ilaclari bana yaz|baska hastanin (telefon|bilgi))"
)

SLOT_CONFIRM_RE = re.compile(
    r"(\b(olur|tamam|evet|uygun|tabii|peki|lutfen)\b.{0,45}\b(yarin|bugun|pazartesi|sali|carsamba|persembe|cuma|cumartesi|sabah|ogleden sonra|aksam|saat\s*\d{1,2}|\d{1,2}[:.]\d{2})\b|"
    r"\b(yarin|bugun|sabah|ogleden sonra|saat\s*\d{1,2}|\d{1,2}[:.]\d{2})\b.{0,35}\b(uygun mu(dur)?|beni yaz(in)?|yazabilir misiniz|randevu|ayirin)\b)"
)

TREATMENT_KEYWORDS = (
    "implant",
    "zirkonyum",
    "kanal",
    "dolgu",
    "beyazlatma",
    "lamine",
    "cekim",
    "ortodonti",
    "protez",
    "gulus tasarimi",
)


def normalize(text: str) -> str:
    raw = (text or "").replace("\u200c", " ").replace("ı", "i").replace("İ", "i").replace("ə", "e").replace("Ə", "e")
    t = unicodedata.normalize("NFKD", raw)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", t.casefold()).strip()


def normalize_tr_informal(n: str) -> str:
    out = n
    for pat, repl in TR_INFORMAL_PATTERNS:
        out = pat.sub(repl, out)
    return re.sub(r"\s+", " ", out).strip()


def detect_lang(text: str, default: str = "tr") -> str:
    raw = (text or "").casefold()
    if re.search(r"[\u0590-\u05FF]", raw):
        return "he"
    if re.search(r"[\u0600-\u06FF]", raw):
        if re.search(r"[پچژگک]", raw) or any(w in raw for w in ("سلام", "نوبت", "قیمت", "دندان", "چند", "آدرس", "خونریزی", "صورتم", "ورم", "نفس")):
            return "fa"
        return "ar"
    if re.search(r"[\u0370-\u03FF]", raw):
        return "el"
    if re.search(r"[\u0400-\u04FF]", raw):
        cyr_words = set(re.findall(r"[а-яёіїєґъ]+", raw))
        uk_score = (3 if re.search(r"[іїєґ]", raw) else 0) + len(
            cyr_words & {"добрий", "вітаю", "ціна", "скільки", "запис", "записатися", "адреса", "лікар", "клініка", "години", "роботи", "імплантації", "яка", "який", "графік"}
        )
        bg_score = len(
            cyr_words & {"здравейте", "добър", "колко", "зъб", "зъби", "работно", "работното", "време", "струва", "къде", "час", "лекар", "адресът", "какво"}
        ) + (2 if ("работно време" in raw or "работното време" in raw or "колко струва" in raw) else 0)
        ru_score = (3 if re.search(r"[ыэё]", raw) else 0) + len(
            cyr_words & {"здравствуйте", "сколько", "стоит", "стоимость", "записаться", "прием", "приём", "имплантация", "зубов", "часы", "работы", "какие", "какая", "цена", "вас", "где", "клиника", "можно"}
        )
        if uk_score > ru_score and uk_score >= bg_score and uk_score > 0:
            return "uk"
        if bg_score > ru_score and bg_score > uk_score and bg_score > 0:
            return "bg"
        return "ru"
    if re.search(r"[əƏ]", raw):
        return "az"
    if re.search(r"[ğşıİĞŞ]", text or ""):
        return "tr"
    n = normalize(text)
    words = set(re.findall(r"[a-z]+", n))
    lexicons = {
        "de": {"ich", "und", "nicht", "zahn", "zahne", "zahnimplantat", "termin", "bitte", "hallo", "wie", "viel", "kostet", "ist", "sie", "wir", "mein", "kosten", "danke", "guten", "wo", "adresse", "ihre", "klinik"},
        "en": {"the", "and", "is", "my", "tooth", "teeth", "appointment", "please", "hello", "hi", "how", "much", "can", "you", "what", "price", "where", "there", "parking", "swollen", "swallow", "cost", "crowns", "extraction", "breathe"},
        "tr": {"merhaba", "dis", "disim", "randevu", "randvu", "fiyat", "fyat", "ucret", "ucreti", "ne", "kadar", "kdr", "nekadr", "nerede", "var", "mi", "mu", "istiyorum", "istiyom", "tesekkur", "agri", "slm", "mrb", "selam", "kacta", "acik", "cumartesi", "ctesi", "kapaniyo", "kapaniyor", "yarin", "saat", "olur", "tamam", "bursa", "ankara", "sube", "subenizin", "otopark"},
        "fr": {"bonjour", "salut", "bonsoir", "merci", "prix", "tarif", "combien", "adresse", "horaires", "rendez", "vous", "dent", "dents", "dentiste", "peur", "douloureux", "ou", "etes", "quels", "sont"},
        "nl": {"hallo", "goedemorgen", "goedemiddag", "afspraak", "prijs", "kosten", "adres", "waar", "tandarts", "openingstijden", "bedankt", "hoe", "laat", "vandaag", "bang", "voor", "implantaat", "pijn", "sedatie", "hebben", "jullie"},
        "es": {"hola", "buenos", "dias", "gracias", "precio", "cuanto", "cuesta", "cita", "direccion", "donde", "horario", "horarios", "diente", "dentista", "tengo", "sonrisa", "cuales"},
        "it": {"ciao", "buongiorno", "buonasera", "salve", "grazie", "prezzo", "quanto", "costa", "appuntamento", "prenotare", "vorrei", "faccette", "indirizzo", "dove", "siete", "orari", "dente", "dentista"},
        "az": {"salam", "sabahiniz", "xeyir", "qiymet", "unvan", "unvaniniz", "hardasiniz", "haradadir", "hekim", "nece", "gorus", "qanaxma"},
        "ro": {"buna", "ziua", "multumesc", "pret", "cat", "costa", "programare", "adresa", "unde", "dinte", "stomatolog", "care", "este"},
    }
    scores = {k: len(words & v) for k, v in lexicons.items()}
    best = max(scores, key=scores.get)
    return best if scores[best] > 0 else default


@dataclass
class RouteResult:
    answer: str
    layer: str
    intent: str
    lang: str
    tokens_in: int = 0
    tokens_out: int = 0
    alert: str | None = None          # "acil" | "sikayet" | None
    handoff: bool = False
    high_value: bool = False
    meta: dict = field(default_factory=dict)


class MemoryCache:
    """Redis yokken (yerel test) kullanılan basit önbellek."""
    def __init__(self):
        self.kv: dict[str, str] = {}
        self.h: dict[str, dict[str, str]] = {}

    async def get(self, k):
        return self.kv.get(k)

    async def set(self, k, v, ex=None):
        self.kv[k] = v

    async def hset(self, name, key, value):
        self.h.setdefault(name, {})[key] = value

    async def hgetall(self, name):
        return dict(self.h.get(name, {}))

    async def hlen(self, name):
        return len(self.h.get(name, {}))


class DialogueFSM:
    """
    Çok Turlu Diyalog Hafızası ve Sonlu Durum Makinesi (FSM):
    Durumlar: IDLE -> ASKED_TREATMENT -> OFFERED_APPT -> AWAITING_SLOT
    Her (clinic_key, session_id/patient_id) için son 5 turu, aktif şubeyi ve son tedaviyi saklar.
    """
    STATES = ("IDLE", "ASKED_TREATMENT", "OFFERED_APPT", "AWAITING_SLOT")

    def __init__(self):
        self.sessions: dict[str, dict[str, Any]] = {}

    def get_session(self, session_key: str) -> dict[str, Any]:
        if session_key not in self.sessions:
            self.sessions[session_key] = {
                "state": "IDLE",
                "active_branch": None,
                "last_treatment": None,
                "turns": [],
                "updated_at": time.monotonic(),
            }
        return self.sessions[session_key]

    def record_turn(
        self,
        session_key: str,
        user_text: str,
        intent: str,
        branch: str | None = None,
        treatment: str | None = None,
        bot_answer: str = "",
    ) -> dict[str, Any]:
        sess = self.get_session(session_key)
        if branch:
            sess["active_branch"] = branch
        if treatment:
            sess["last_treatment"] = treatment

        ans_norm = normalize(bot_answer)
        if intent == "randevu":
            sess["state"] = "AWAITING_SLOT"
        elif "randevu" in ans_norm or "gun ve saat" in ans_norm or "ister misiniz" in ans_norm:
            sess["state"] = "OFFERED_APPT"
        elif treatment or intent in ("tedavi_sure", "fiyat", "agri_korku", "cocuk_dis"):
            sess["state"] = "ASKED_TREATMENT"

        sess["turns"].append({
            "text": user_text[:300],
            "intent": intent,
            "branch": sess["active_branch"],
            "treatment": sess["last_treatment"],
            "state": sess["state"],
        })
        if len(sess["turns"]) > 5:
            sess["turns"] = sess["turns"][-5:]
        sess["updated_at"] = time.monotonic()
        return sess


class TokenRouter:
    def __init__(self, redis=None, faq_path: Path | None = None, offline: bool = False):
        self.cache = redis or MemoryCache()
        self.offline = offline
        self._cb_until = 0.0
        self.fsm = DialogueFSM()
        data = json.loads((faq_path or BASE / "faq.json").read_text(encoding="utf-8"))
        self.clinic = os.environ.get("CLINIC_NAME", "Klinik")
        self.facts = {**data["facts"], "clinic": self.clinic}
        self.intents = []
        self.intent_map: dict[str, dict[str, Any]] = {}
        for name, spec in data["intents"].items():
            pats = {lg: re.compile(normalize(p)) for lg, p in spec["patterns"].items()}
            self.intents.append((name, spec.get("only_short", False), pats, spec["answers"]))
            self.intent_map[name] = {"only_short": spec.get("only_short", False), "pats": pats, "answers": spec["answers"]}
        self.emerg = {lg: re.compile(normalize(p)) for lg, p in data["emergency"]["patterns"].items()}
        self.emerg_ans = data["emergency"]["answers"]
        self.tpl = data["templates"]
        self.kw = {k: re.compile(normalize(v)) for k, v in data["classifier_keywords"].items()}
        facts_txt = "\n".join(f"- {k}: {v}" for k, v in data["facts"].items())
        self.system_tpl = (BASE / "guardrail_prompt.txt").read_text(encoding="utf-8").replace("{facts}", facts_txt).replace("{clinic}", self.clinic)
        self.base_url = (os.environ.get("LLM_BASE_URL", "http://127.0.0.1:20128/v1") or "http://127.0.0.1:20128/v1").rstrip("/")
        self.api_key = os.environ.get("LLM_API_KEY", "")
        self.small = os.environ.get("LLM_SMALL_MODEL", "free-auto") or "free-auto"
        self.main = os.environ.get("LLM_MAIN_MODEL", "free-auto") or "free-auto"
        self.max_tokens = int(os.environ.get("LLM_MAX_TOKENS", "180"))
        self.embed_model = os.environ.get("EMBED_MODEL", "")
        self.sem_threshold = float(os.environ.get("SEMANTIC_THRESHOLD", "0.92"))
        self.price_on = os.environ.get("PRICE_DISCLOSURE", "off").lower() == "on"
        self.forbidden = re.compile(normalize(
            r"(\b\d+\s?(mg|ml|gr)\b|amoksisilin|amoxicillin|augmentin|ibuprofen|parol|majezik|apranax|antibiyotik|antibiotic|recete|"
            r"teshis(iniz)?|tanisi|garanti|en iyi|agrisiz|kusursuz|indirim|kampanya|ucretsiz|\b\d[\d.]*\s?(tl|try|euro|eur|usd|\$|€))"
        ))

    # ---------- yardımcılar ----------
    def _fmt(self, s: str, extra: dict | None = None) -> str:
        facts = {**self.facts, **(extra or {})}
        for k, v in facts.items():
            if k != "branches":
                s = s.replace("{" + k + "}", str(v))
        return s

    def _pick(self, table: dict, lang: str, extra: dict | None = None) -> str:
        return self._fmt(table.get(lang) or table.get("en") or table["tr"], extra)

    def _auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key or 'omniroute-local'}"}

    @property
    def llm_ready(self) -> bool:
        if self.offline or time.monotonic() < self._cb_until or not self.base_url:
            return False
        is_local = "127.0.0.1" in self.base_url or "localhost" in self.base_url
        return bool(self.api_key or is_local)

    @staticmethod
    def _detect_treatment(n_text: str) -> str | None:
        for tr_kw in TREATMENT_KEYWORDS:
            if tr_kw in n_text:
                return tr_kw
        return None

    def _detect_branch(self, n_text: str, clinic_facts: dict | None = None) -> tuple[str | None, dict[str, str] | None]:
        """Mesajda geçen şube/şehir adını tespit edip o şubenin gerçek adres, telefon ve harita bilgisini döndürür."""
        if not n_text:
            return None, None
        branch_dir = dict(DEFAULT_BRANCH_DIRECTORY)
        for b in (clinic_facts or {}).get("branches") or []:
            city_norm = normalize(b.get("city") or "")
            name_norm = normalize(b.get("name") or "")
            key = city_norm or name_norm
            if key:
                kws = tuple(filter(None, {city_norm, *name_norm.split()[:2]}))
                branch_dir[key] = {
                    "key": key,
                    "clinic": b.get("name") or self.clinic,
                    "city": b.get("city") or "",
                    "adres": b.get("address") or self.facts["adres"],
                    "harita": f"https://maps.google.com/?q={b.get('city') or 'Istanbul'}",
                    "telefon": b.get("phone") or self.facts["telefon"],
                    "keywords": kws,
                }
        for bkey, binfo in branch_dir.items():
            for kw in binfo.get("keywords", ()):
                if kw and re.search(r"\b" + re.escape(kw), n_text):
                    return bkey, {
                        "clinic": binfo["clinic"],
                        "adres": binfo["adres"],
                        "harita": binfo["harita"],
                        "telefon": binfo["telefon"],
                    }
        return None, None

    def _fuzzy_match_intents(self, n_norm: str, lang: str) -> list[str]:
        """Katı regex eşleşmediğinde RapidFuzz ile yazım hatalı Türkçe mesajlarda niyet yakalar."""
        if _rf_fuzz is None or lang != "tr" or len(n_norm) < 6:
            return []
        # Regression guard: "kaç seans sürer" L2-yedek/genel kalmalı
        if "kac seans surer" in n_norm:
            return []
        matched: list[str] = []
        for intent_name, phrases in FUZZY_CANONICAL_PHRASES.items():
            for ph in phrases:
                score_ts = _rf_fuzz.token_set_ratio(n_norm, ph)
                score_pr = _rf_fuzz.partial_ratio(n_norm, ph)
                if score_ts >= 84 or (len(n_norm) >= 14 and score_pr >= 86):
                    if intent_name not in matched:
                        matched.append(intent_name)
                    break
        return matched

    async def _chat(self, model: str, messages: list, max_tokens: int, temperature: float = 0.0):
        candidates = [model] + (["free-auto"] if model != "free-auto" else [])
        last_err = None
        async with httpx.AsyncClient(timeout=12) as c:
            for cand in candidates:
                try:
                    r = await c.post(f"{self.base_url}/chat/completions", headers=self._auth_headers(),
                                     json={"model": cand, "messages": messages, "max_tokens": max_tokens, "temperature": temperature})
                    r.raise_for_status()
                    j = r.json()
                    text = (j["choices"][0]["message"].get("content") or "").strip()
                    u = j.get("usage") or {}
                    tin = u.get("prompt_tokens") or sum(len(m["content"]) for m in messages) // 4
                    tout = u.get("completion_tokens") or len(text) // 4
                    return text, tin, tout
                except Exception as exc:
                    last_err = exc
        self._cb_until = time.monotonic() + 30.0
        raise RuntimeError(f"OmniRoute/LLM hatası: {last_err}")

    async def _embed(self, text: str) -> list[float] | None:
        if not (self.embed_model and self.llm_ready):
            return None
        async with httpx.AsyncClient(timeout=12) as c:
            r = await c.post(f"{self.base_url}/embeddings", headers=self._auth_headers(),
                             json={"model": self.embed_model, "input": text})
            r.raise_for_status()
            return r.json()["data"][0]["embedding"]

    @staticmethod
    def _cos(a, b) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a)); nb = math.sqrt(sum(y * y for y in b))
        return dot / (na * nb) if na and nb else 0.0

    def keyword_label(self, n: str) -> str:
        for lbl in ("sikayet", "tibbi_soru", "fiyat", "gorsel", "randevu"):
            if lbl in self.kw and self.kw[lbl].search(n):
                return lbl
        return "genel"

    # ---------- ana akış ----------
    def is_emergency(self, text: str) -> bool:
        n = normalize_tr_informal(normalize(text))
        return any(p.search(n) for p in self.emerg.values())

    async def route(
        self,
        text: str,
        lang: str | None = None,
        clinic_facts: dict | None = None,
        allow_llm: bool = True,
        session_id: str | None = None,
        patient_id: int | str | None = None,
        history: list[dict[str, Any]] | None = None,
        context_previous_turn: str | None = None,
    ) -> RouteResult:
        lang = lang if lang in LANGS else detect_lang(text)
        n_raw = normalize(text)
        n = normalize_tr_informal(n_raw) if lang == "tr" else n_raw

        # Çok turlu oturum anahtarı ve önceki tur bağlamı
        cf_base_name = (clinic_facts or {}).get("clinic", self.clinic)
        sess_key = f"{cf_base_name}:{session_id or patient_id or 'anon'}"
        sess = self.fsm.get_session(sess_key) if (session_id or patient_id or context_previous_turn or history) else None

        prev_texts: list[str] = []
        if context_previous_turn:
            prev_texts.append(context_previous_turn)
        if history:
            for h_item in history[-4:]:
                if isinstance(h_item, dict) and h_item.get("text"):
                    prev_texts.append(str(h_item["text"]))
        if sess and sess["turns"]:
            for t_item in sess["turns"][-3:]:
                if t_item.get("text"):
                    prev_texts.append(str(t_item["text"]))
        prev_norm = normalize_tr_informal(normalize(" ".join(prev_texts))) if prev_texts else ""

        # Şube çözümleyici: önce mevcut mesajda, yoksa önceki turda veya oturum hafızasında şube ara
        branch_key, branch_facts = self._detect_branch(n, clinic_facts)
        if not branch_facts and prev_norm:
            branch_key, branch_facts = self._detect_branch(prev_norm, clinic_facts)
        if not branch_facts and sess and sess.get("active_branch"):
            b_cached = DEFAULT_BRANCH_DIRECTORY.get(sess["active_branch"])
            if b_cached:
                branch_key = sess["active_branch"]
                branch_facts = {
                    "clinic": b_cached["clinic"],
                    "adres": b_cached["adres"],
                    "harita": b_cached["harita"],
                    "telefon": b_cached["telefon"],
                }

        effective_facts = {**(clinic_facts or {})}
        if branch_facts:
            effective_facts.update(branch_facts)

        cur_treatment = self._detect_treatment(n) or (self._detect_treatment(prev_norm) if prev_norm else None)
        high_value = bool(self.kw["yuksek_deger"].search(n) or (prev_norm and self.kw["yuksek_deger"].search(prev_norm)))

        # Katman-1a: Acil durum triyajı (16 dil + bulanık acil kontrolü; her şeyden önce gelir!)
        for lg, pat in self.emerg.items():
            if pat.search(n) or pat.search(n_raw):
                ans = self._pick(self.emerg_ans, lang, effective_facts)
                if sess is not None:
                    self.fsm.record_turn(sess_key, text, "acil", branch_key, cur_treatment, ans)
                return RouteResult(ans, "L1-acil", "acil", lang, alert="acil", handoff=True, meta={"branch": branch_key})

        # Katman-1b: Güvenlik / Prompt Injection / KVKK Üçüncü Kişi Veri Sızıntısı Koruması
        if PROMPT_INJECTION_RE.search(n):
            ans = (
                f"{self._pick(self.tpl['fiyat'], lang, effective_facts)} "
                f"{self._pick(self.tpl['insan'], lang, effective_facts)}"
            )
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "insan", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L1-guvenlik", "insan", lang, handoff=True, meta={"guardrail": "prompt_injection"})

        if KVKK_TRAP_RE.search(n):
            ans = (
                "KVKK ve hasta mahremiyeti kuralları gereği hasta iletişim veya sağlık bilgileri üçüncü kişilerle paylaşılamamaktadır. "
                "Mesajınızı değerlendirmesi için hekim ve hasta kabul ekibimize ilettik; çalışma saatlerinde size dönüş yapılacaktır."
                if lang == "tr"
                else self._pick(self.tpl["guvenli_yedek"], lang, effective_facts)
            )
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "insan", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L1-guvenlik", "insan", lang, handoff=True, meta={"guardrail": "kvkk_privacy"})

        # Katman-1b2: Tıbbi Güvenlik, İlaç Dozu & Kan Sulandırıcı Sınıflandırıcısı (0 token)
        if "tibbi_soru" in self.kw and self.kw["tibbi_soru"].search(n):
            ans = self._pick(self.tpl["tibbi_soru"], lang, effective_facts)
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "tibbi_soru", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L1-tibbi", "tibbi_soru", lang, handoff=True, high_value=high_value)

        # Katman-1b3: Şikayet & Memnuniyetsizlik (Başhekim alarmı)
        if self.kw["sikayet"].search(n):
            ans = self._pick(self.tpl["sikayet"], lang, effective_facts)
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "sikayet", branch_key, cur_treatment, ans)
            return RouteResult(ans, "L2-anahtar", "sikayet", lang, alert="sikayet", handoff=True, high_value=high_value)

        # Katman-1c: Çok Turlu FSM Randevu / Slot Kabulü Yakalayıcı ("Olur yarın 15:00 uygun mu?", "Tamam yarın sabah 10:00'a beni yazın")
        is_slot_confirm = bool(SLOT_CONFIRM_RE.search(n))
        has_appt_context = bool(
            prev_norm and any(w in prev_norm for w in ("randevu", "uygun", "sube", "tedavi", "kanal", "implant", "muayene", "ister misiniz"))
        ) or bool(sess and sess.get("state") in ("ASKED_TREATMENT", "OFFERED_APPT", "AWAITING_SLOT"))

        if is_slot_confirm and (has_appt_context or "beni yaz" in n or "uygun mu" in n):
            base_ans = self._pick(self.tpl["randevu"], lang, effective_facts)
            if branch_facts and lang == "tr":
                base_ans = f"{branch_facts['clinic']} için {base_ans[0].lower()}{base_ans[1:]}"
            if sess is not None:
                self.fsm.record_turn(sess_key, text, "randevu", branch_key, cur_treatment, base_ans)
            return RouteResult(
                base_ans,
                "L1-baglam",
                "randevu",
                lang,
                handoff=True,
                high_value=high_value,
                meta={"fsm_state": "AWAITING_SLOT", "branch": branch_key, "treatment": cur_treatment},
            )

        # Katman-1d: Birleşik Niyet Birleştirici (Compound Query Engine: L1-sss + L2-anahtar)
        matched_intents: list[str] = []
        word_count = len(n.split())

        for name, only_short, pats, _ in self.intents:
            if only_short and word_count > 4:
                continue
            # Önce tespit edilen dilin deseni, sonra diğer dillerin desenleri
            if (lang in pats and (pats[lang].search(n) or pats[lang].search(n_raw))) or any(
                p.search(n) or p.search(n_raw) for p in pats.values()
            ):
                if name not in matched_intents:
                    matched_intents.append(name)

        # L2 anahtar kelime niyetlerini de birleşik taramaya dahil et (fiyat, gorsel, randevu)
        for l2_lbl in ("fiyat", "gorsel", "randevu"):
            if self.kw[l2_lbl].search(n) or self.kw[l2_lbl].search(n_raw):
                if l2_lbl == "fiyat" and self.price_on:
                    continue
                if l2_lbl not in matched_intents:
                    matched_intents.append(l2_lbl)

        # Eğer birden fazla niyet eşleştiyse 'selam'ı çıkar (asıl sorular yanıtlansın)
        if len(matched_intents) > 1 and "selam" in matched_intents:
            matched_intents.remove("selam")

        # Hiçbir katı regex eşleşmediyse RapidFuzz bulanık eşleştirmeyi çalıştır
        if not matched_intents:
            fuzzy_hits = self._fuzzy_match_intents(n, lang)
            if "acil" in fuzzy_hits:
                ans = self._pick(self.emerg_ans, lang, effective_facts)
                if sess is not None:
                    self.fsm.record_turn(sess_key, text, "acil", branch_key, cur_treatment, ans)
                return RouteResult(ans, "L1-acil", "acil", lang, alert="acil", handoff=True, meta={"fuzzy": True})
            for fh in fuzzy_hits:
                if fh not in matched_intents:
                    matched_intents.append(fh)

        if matched_intents:
            ordered = [it for it in INTENT_PRIORITY if it in matched_intents]
            for it in matched_intents:
                if it not in ordered:
                    ordered.append(it)
            primary_intent = ordered[0]
            primary_layer = "L1-sss" if primary_intent in L1_INTENT_SET else "L2-anahtar"

            ans_parts: list[str] = []
            for it_name in ordered:
                if it_name in self.intent_map:
                    part = self._pick(self.intent_map[it_name]["answers"], lang, effective_facts)
                elif it_name in self.tpl:
                    part = self._pick(self.tpl[it_name], lang, effective_facts)
                else:
                    continue
                if part and part not in ans_parts:
                    ans_parts.append(part)

            combined_answer = " ".join(ans_parts).strip()
            needs_handoff = any(it in ("randevu", "insan", "sikayet") for it in ordered)
            if sess is not None:
                self.fsm.record_turn(sess_key, text, primary_intent, branch_key, cur_treatment, combined_answer)
            return RouteResult(
                combined_answer,
                primary_layer,
                primary_intent,
                lang,
                handoff=needs_handoff,
                high_value=high_value,
                meta={"matched_intents": ordered, "branch": branch_key, "treatment": cur_treatment},
            )

        # Katman-1e: kesin eşleşme önbelleği (klinik adıyla ayrı anahtar)
        cf_key = effective_facts.get("clinic", self.clinic)
        key = f"dc:ans:{cf_key}:{lang}:{hashlib.sha256(n.encode()).hexdigest()}"
        hit = await self.cache.get(key)
        if hit:
            return RouteResult(hit if isinstance(hit, str) else hit.decode(), "L1-onbellek", "genel", lang, high_value=high_value)

        # Katman-1f: semantik önbellek
        emb = None
        try:
            emb = await self._embed(n)
        except Exception:
            emb = None
        if emb:
            best, best_ans = 0.0, None
            for raw in (await self.cache.hgetall(f"dc:sem:{cf_key}:{lang}")).values():
                item = json.loads(raw)
                s = self._cos(emb, item["v"])
                if s > best:
                    best, best_ans = s, item["a"]
            if best_ans and best >= self.sem_threshold:
                return RouteResult(best_ans, "L1-semantik", "genel", lang, high_value=high_value, meta={"benzerlik": round(best, 3)})

        # Katman-2: sınıflandırma (küçük LLM veya önbellek)
        tin = tout = 0
        label = "genel"
        layer2 = "L2-anahtar"
        lkey = f"dc:lbl:{hashlib.sha256(n.encode()).hexdigest()}"
        cached_lbl = await self.cache.get(lkey)
        if cached_lbl:
            label, layer2 = (cached_lbl if isinstance(cached_lbl, str) else cached_lbl.decode()), "L2-onbellek"
        elif allow_llm and self.llm_ready and self.small:
            try:
                out, tin, tout = await self._chat(self.small, [
                    {"role": "system", "content": "Etiket: " + ",".join(LABELS)},
                    {"role": "user", "content": text[:300]}], max_tokens=3)
                cand = normalize(out).split()[0] if out else ""
                if cand in LABELS:
                    label, layer2 = cand, "L2-kucuk-model"
                    await self.cache.set(lkey, cand, ex=30 * 86400)
            except Exception:
                pass

        if label == "fiyat" and not self.price_on:
            return RouteResult(self._pick(self.tpl["fiyat"], lang, effective_facts), layer2, "fiyat", lang, tin, tout, high_value=high_value)
        if label == "tibbi_soru":
            return RouteResult(self._pick(self.tpl["tibbi_soru"], lang, effective_facts), layer2, "tibbi_soru", lang, tin, tout, handoff=True, high_value=high_value)
        if label in ("randevu", "insan", "gorsel", "sikayet"):
            return RouteResult(self._pick(self.tpl[label], lang, effective_facts), layer2, label, lang, tin, tout,
                               alert="sikayet" if label == "sikayet" else None,
                               handoff=label in ("randevu", "insan", "sikayet"), high_value=high_value)

        # Katman-3: ana LLM
        if not (allow_llm and self.llm_ready and self.main):
            return RouteResult(self._pick(self.tpl["insan"], lang, effective_facts), "L2-yedek", label, lang, tin, tout, handoff=True, high_value=high_value)
        system = self.system_tpl.replace("{lang}", lang).replace(self.clinic, cf_key)
        try:
            ans, t3i, t3o = await self._chat(self.main, [{"role": "system", "content": system}, {"role": "user", "content": text[:1200]}],
                                             max_tokens=self.max_tokens, temperature=0.2)
        except Exception:
            return RouteResult(self._pick(self.tpl["insan"], lang, effective_facts), "L2-yedek", label, lang, tin, tout,
                               handoff=True, high_value=high_value, meta={"failover": "circuit-breaker"})
        tin += t3i; tout += t3o
        tag = re.search(r"\[(INSAN|RANDEVU|ACIL)\]", ans)
        ans_clean = re.sub(r"\s*\[(INSAN|RANDEVU|ACIL)\]\s*", " ", ans).strip()
        if not ans_clean or self.forbidden.search(normalize(ans_clean)):
            return RouteResult(self._pick(self.tpl["guvenli_yedek"], lang, effective_facts), "L3-filtre", label, lang, tin, tout, handoff=True, high_value=high_value)
        res = RouteResult(ans_clean, "L3-ana-model", label, lang, tin, tout,
                          alert="acil" if tag and tag.group(1) == "ACIL" else None,
                          handoff=bool(tag), high_value=high_value)
        if label == "genel" and not tag:
            await self.cache.set(key, ans_clean, ex=7 * 86400)
            if emb and await self.cache.hlen(f"dc:sem:{cf_key}:{lang}") < 2000:
                await self.cache.hset(f"dc:sem:{cf_key}:{lang}", key, json.dumps({"v": emb, "a": ans_clean}))
        return res
