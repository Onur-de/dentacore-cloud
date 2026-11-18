"""
Token Router: 3 katmanlı maliyet yönlendiricisi.

Katman-1 (0 LLM tokenı): acil durum desenleri -> SSS desenleri -> kesin eşleşme önbelleği (Redis)
           -> semantik önbellek (yalnızca embedding maliyeti; EMBED_MODEL boşsa kapalı).
Katman-2 (çok ucuz): küçük model tek etiket döndürür (max_tokens=4). LLM yoksa anahtar kelime sınıflandırıcı.
           Etiketlerin çoğu (fiyat, randevu, şikayet, görsel, insan) hazır şablonla cevaplanır, ana LLM çağrılmaz.
Katman-3: ana LLM, sabit sistem promptu en başta (sağlayıcı tarafı prompt caching için aynı önek),
           max_tokens sınırlı, çıktı sonrası yasaklı içerik filtresi.
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

import httpx

BASE = Path(__file__).parent
LANGS = ("tr", "en", "de", "ar", "ru", "fr", "nl", "es", "it", "fa", "az", "uk", "bg", "ro", "el", "he")
LABELS = ("fiyat", "randevu", "tibbi_soru", "gorsel", "sikayet", "genel", "insan")


def normalize(text: str) -> str:
    t = unicodedata.normalize("NFKD", (text or "").replace("ı", "i").replace("İ", "i").replace("ə", "e").replace("Ə", "e"))
    t = "".join(c for c in t if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", t.casefold()).strip()


def detect_lang(text: str, default: str = "tr") -> str:
    raw = (text or "").casefold()
    if re.search(r"[\u0590-\u05FF]", raw):
        return "he"
    if re.search(r"[\u0600-\u06FF]", raw):
        if re.search(r"[پچژگک]", raw) or any(w in raw for w in ("سلام", "نوبت", "قیمت", "دندان", "چند", "آدرس")):
            return "fa"
        return "ar"
    if re.search(r"[\u0370-\u03FF]", raw):
        return "el"
    if re.search(r"[\u0400-\u04FF]", raw):
        if re.search(r"[іїєґ]", raw) or any(w in raw for w in ("добрий", "вітаю", "ціна", "скільки", "запис", "адреса")):
            return "uk"
        if any(w in raw for w in ("здравейте", "добър", "колко", "зъб", "работно време", "струва", "къде")):
            return "bg"
        return "ru"
    if re.search(r"[əƏ]", raw):
        return "az"
    if re.search(r"[ğşıİĞŞ]", text):
        return "tr"
    n = normalize(text)
    words = set(re.findall(r"[a-z]+", n))
    lexicons = {
        "de": {"ich", "und", "nicht", "zahn", "zahne", "termin", "bitte", "hallo", "wie", "ist", "sie", "wir", "mein", "kosten", "danke", "guten", "wo", "adresse", "ihre"},
        "en": {"the", "and", "is", "my", "tooth", "teeth", "appointment", "please", "hello", "hi", "how", "much", "can", "you", "what", "price", "where", "there", "parking", "swollen", "swallow", "cost", "crowns"},
        "tr": {"merhaba", "dis", "disim", "randevu", "fiyat", "ne", "kadar", "nerede", "var", "mi", "mu", "istiyorum", "tesekkur", "agri", "slm", "mrb", "selam", "kacta", "acik"},
        "fr": {"bonjour", "salut", "bonsoir", "merci", "prix", "tarif", "combien", "adresse", "horaires", "rendez", "vous", "dent", "dents", "ou", "etes"},
        "nl": {"hallo", "goedemorgen", "goedemiddag", "afspraak", "prijs", "kosten", "adres", "waar", "tandarts", "openingstijden", "bedankt", "hoe", "laat", "vandaag"},
        "es": {"hola", "buenos", "dias", "gracias", "precio", "cuanto", "cita", "direccion", "donde", "horario", "diente", "dentista", "tengo"},
        "it": {"ciao", "buongiorno", "buonasera", "salve", "grazie", "prezzo", "quanto", "appuntamento", "indirizzo", "dove", "orari", "dente", "dentista"},
        "az": {"salam", "sabahiniz", "xeyir", "qiymet", "unvan", "hardasiniz", "hekim", "nece", "gorus"},
        "ro": {"buna", "ziua", "multumesc", "pret", "cat", "costa", "programare", "adresa", "unde", "dinte", "stomatolog"},
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


class TokenRouter:
    def __init__(self, redis=None, faq_path: Path | None = None, offline: bool = False):
        self.cache = redis or MemoryCache()
        self.offline = offline
        self._cb_until = 0.0
        data = json.loads((faq_path or BASE / "faq.json").read_text(encoding="utf-8"))
        self.clinic = os.environ.get("CLINIC_NAME", "Klinik")
        self.facts = {**data["facts"], "clinic": self.clinic}
        self.intents = []
        for name, spec in data["intents"].items():
            pats = {lg: re.compile(normalize(p)) for lg, p in spec["patterns"].items()}
            self.intents.append((name, spec.get("only_short", False), pats, spec["answers"]))
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
            r"(\b\d+\s?(mg|ml|gr)\b|amoksisilin|amoxicillin|augmentin|ibuprofen|parol|majezik|apranax|antibiyotik kullan|"
            r"teshis(iniz)?|tanisi|garanti|en iyi|agrisiz|kusursuz|indirim|kampanya|ucretsiz|\b\d[\d.]*\s?(tl|try|euro|eur|usd|\$|€))"
        ))

    # ---------- yardımcılar ----------
    def _fmt(self, s: str, extra: dict | None = None) -> str:
        facts = {**self.facts, **(extra or {})}
        for k, v in facts.items():
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
        for lbl in ("sikayet", "fiyat", "gorsel", "randevu"):
            if self.kw[lbl].search(n):
                return lbl
        return "genel"

    # ---------- ana akış ----------
    def is_emergency(self, text: str) -> bool:
        n = normalize(text)
        return any(p.search(n) for p in self.emerg.values())

    async def route(self, text: str, lang: str | None = None, clinic_facts: dict | None = None, allow_llm: bool = True) -> RouteResult:
        lang = lang if lang in LANGS else detect_lang(text)
        n = normalize(text)
        high_value = bool(self.kw["yuksek_deger"].search(n))

        # Katman-1a: acil durum (her dilin deseni denenir; hasta karışık dil yazabilir)
        for lg, pat in self.emerg.items():
            if pat.search(n):
                return RouteResult(self._pick(self.emerg_ans, lang, clinic_facts), "L1-acil", "acil", lang, alert="acil", handoff=True)

        # Katman-1b: SSS
        for name, only_short, pats, answers in self.intents:
            if only_short and len(n.split()) > 4:
                continue
            for lg, pat in pats.items():
                if pat.search(n):
                    return RouteResult(self._pick(answers, lang, clinic_facts), "L1-sss", name, lang, high_value=high_value)

        # Katman-1c: kesin eşleşme önbelleği (klinik adıyla ayrı anahtar)
        cf_key = (clinic_facts or {}).get("clinic", self.clinic)
        key = f"dc:ans:{cf_key}:{lang}:{hashlib.sha256(n.encode()).hexdigest()}"
        hit = await self.cache.get(key)
        if hit:
            return RouteResult(hit if isinstance(hit, str) else hit.decode(), "L1-onbellek", "genel", lang, high_value=high_value)

        # Katman-1d: semantik önbellek (yalnızca "genel" bilgi cevapları saklanır, klinik izolasyonlu)
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

        # Katman-2: sınıflandırma
        tin = tout = 0
        label = self.keyword_label(n)
        layer2 = "L2-anahtar"
        lkey = f"dc:lbl:{hashlib.sha256(n.encode()).hexdigest()}"
        cached_lbl = await self.cache.get(lkey) if label == "genel" else None
        if cached_lbl:
            label, layer2 = (cached_lbl if isinstance(cached_lbl, str) else cached_lbl.decode()), "L2-onbellek"
        elif allow_llm and label == "genel" and self.llm_ready and self.small:
            # Anahtar kelime zaten net etiket verdiyse küçük model hiç çağrılmaz.
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
            return RouteResult(self._pick(self.tpl["fiyat"], lang, clinic_facts), layer2, "fiyat", lang, tin, tout, high_value=high_value)
        if label in ("randevu", "insan", "gorsel", "sikayet"):
            return RouteResult(self._pick(self.tpl[label], lang, clinic_facts), layer2, label, lang, tin, tout,
                               alert="sikayet" if label == "sikayet" else None,
                               handoff=label in ("randevu", "insan", "sikayet"), high_value=high_value)

        # Katman-3: ana LLM
        if not (allow_llm and self.llm_ready and self.main):
            return RouteResult(self._pick(self.tpl["insan"], lang, clinic_facts), "L2-yedek", label, lang, tin, tout, handoff=True, high_value=high_value)
        system = self.system_tpl.replace("{lang}", lang).replace(self.clinic, (clinic_facts or {}).get("clinic", self.clinic))
        try:
            ans, t3i, t3o = await self._chat(self.main, [{"role": "system", "content": system}, {"role": "user", "content": text[:1200]}],
                                             max_tokens=self.max_tokens, temperature=0.2)
        except Exception:
            return RouteResult(self._pick(self.tpl["insan"], lang, clinic_facts), "L2-yedek", label, lang, tin, tout,
                               handoff=True, high_value=high_value, meta={"failover": "circuit-breaker"})
        tin += t3i; tout += t3o
        tag = re.search(r"\[(INSAN|RANDEVU|ACIL)\]", ans)
        ans_clean = re.sub(r"\s*\[(INSAN|RANDEVU|ACIL)\]\s*", " ", ans).strip()
        if not ans_clean or self.forbidden.search(normalize(ans_clean)):
            return RouteResult(self._pick(self.tpl["guvenli_yedek"], lang, clinic_facts), "L3-filtre", label, lang, tin, tout, handoff=True, high_value=high_value)
        res = RouteResult(ans_clean, "L3-ana-model", label, lang, tin, tout,
                          alert="acil" if tag and tag.group(1) == "ACIL" else None,
                          handoff=bool(tag), high_value=high_value)
        if label == "genel" and not tag:
            await self.cache.set(key, ans_clean, ex=7 * 86400)
            if emb and await self.cache.hlen(f"dc:sem:{cf_key}:{lang}") < 2000:
                await self.cache.hset(f"dc:sem:{cf_key}:{lang}", key, json.dumps({"v": emb, "a": ans_clean}))
        return res
