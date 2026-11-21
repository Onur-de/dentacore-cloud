"""KVKK dışa aktarma / anonimleştirme testleri (Adım 5): api/app/privacy.py + panel.py.

Yöntem: GERÇEK uygulama süreci + GERÇEK PostgreSQL (tests/pg_app_harness.py). Sentetik hastanın bağlı HER kayıt türüne
benzersiz "kanarya" metinler (KNRY<hex>-<tablo>-<sütun>) yazılır; şifreli sütunlara Fernet ile şifrelenmiş kanarya yazılır.
  - Dışa aktarma: kanaryaların beklenen bölümlerde görünmesi, gizli alanların (belirteç, dosya yolu) sızmaması.
  - Anonimleştirme: TÜM veritabanı (her tablo, her sütun, şifreli olanlar çözülerek) taranır; yalnız belgelenmiş korunan
    mali serbest metin sütunları kalabilir. Aynı klinikteki ve başka klinikteki hastalar etkilenmemelidir.
  - Politika kaydı: patient_id taşıyan her tablo privacy.POLICY'de sınıflandırılmış olmalıdır (şema-karşı testi).
Ön koşul: test PG (55432). Erişilemezse ATLANIR; DC_REQUIRE_PG=1 ise BAŞARISIZ olur.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import secrets
import sys
import uuid

import psycopg
import pytest
from cryptography.fernet import Fernet
from psycopg.rows import dict_row

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "api"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from pg_app_harness import make_jpeg, pg_app  # noqa: E402
from test_media_storage import S3_ENDPOINT, _raw_s3, _s3_env, _s3_unavailable  # noqa: E402,F401

from app import media, privacy  # noqa: E402

TEXT_TYPES = ("text", "character varying", "json", "jsonb", "ARRAY")


def can() -> str:
    return "KNRY" + secrets.token_hex(5)


def C(cn: str, table: str, col: str) -> str:
    return f"{cn}-{table}-{col}"


class Db:
    """Test tarafı doğrudan SQL erişimi (uygulama dışı): tohumlama ve kalıntı taraması."""

    def __init__(self, app):
        self.app = app
        self.fernet = Fernet(app.env["DATA_ENCRYPTION_KEY"].encode())
        self.conn = psycopg.connect(app.dsn, autocommit=True, row_factory=dict_row)

    def close(self):
        self.conn.close()

    def enc(self, s: str) -> str:
        return self.fernet.encrypt(s.encode()).decode()

    def ins(self, table: str, **vals) -> int:
        """Satır ekler; belirtilmeyen NOT NULL + varsayılansız sütunlara tip-uyumlu sahte değer koyar."""
        cols = self.conn.execute(
            "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_schema='public' AND table_name=%s", (table,)).fetchall()
        row = dict(vals)
        for c in cols:
            n = c["column_name"]
            if n in row or c["is_nullable"] == "YES" or c["column_default"] is not None:
                continue
            dt = c["data_type"]
            row[n] = ("x" if dt in ("text", "character varying") else 1 if "int" in dt else 0 if dt == "numeric"
                      else False if dt == "boolean" else "now" if dt.startswith("timestamp") else None)
            if row[n] == "now":
                row[n] = None
                row[n] = self.conn.execute("SELECT now() AS n").fetchone()["n"]
        names = ", ".join(row)
        ph = ", ".join(["%s"] * len(row))
        return self.conn.execute(f"INSERT INTO {table} ({names}) VALUES ({ph}) RETURNING id", list(row.values())).fetchone()["id"]

    def one(self, sql: str, *a):
        return self.conn.execute(sql, a).fetchone()

    def all(self, sql: str, *a):
        return self.conn.execute(sql, a).fetchall()

    def tables(self) -> list[str]:
        return [r["table_name"] for r in self.all(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public' AND table_type='BASE TABLE'")]

    def scan(self, cn: str) -> set[tuple[str, str]]:
        """Tüm tablolar/sütunlar: ham ya da (Fernet ise) çözülmüş değerde kanarya geçen (tablo, sütun) kümesi."""
        found: set[tuple[str, str]] = set()
        for t in self.tables():
            for r in self.all(f"SELECT * FROM {t}"):
                for k, v in r.items():
                    if v is None:
                        continue
                    s = json.dumps(v, default=str) if not isinstance(v, str) else v
                    if cn in s:
                        found.add((t, k))
                    elif isinstance(v, str) and v.startswith("gAAAA"):
                        try:
                            if cn in self.fernet.decrypt(v.encode()).decode():
                                found.add((t, k))
                        except Exception:  # noqa: BLE001, S110
                            pass
        return found
