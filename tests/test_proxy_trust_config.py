"""Adım 9 (kapanış): proxy güven sınırı yapılandırma denetimi (Docker Compose + Render) ve uvicorn davranışı.

Bulgu: `FORWARDED_ALLOW_IPS=127.0.0.1` iken Traefik ayrı bir konteyner olduğundan uvicorn `X-Forwarded-Proto: https`
başlığını yok sayıyor ve `request.base_url` ile üretilen takvim/izleme bağlantıları `http://` çıkıyordu. Düzeltme:
Traefik sabit IP alır, api yalnızca o adrese güvenir. Test, değerin geri `127.0.0.1` veya `*` olmasını engeller.
"""
from __future__ import annotations

import asyncio
import ipaddress
import pathlib

import pytest
import yaml
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def _env(svc: dict) -> dict:
    e = svc.get("environment") or {}
    if isinstance(e, list):
        e = dict(x.split("=", 1) for x in e)
    return {k: str(v) for k, v in e.items()}


def test_only_traefik_publishes_ports(compose):
    published = [n for n, s in compose["services"].items() if s.get("ports")]
    assert published == ["traefik"], f"internete açılan servisler: {published}"


def test_core_network_is_internal(compose):
    assert compose["networks"]["core"].get("internal") is True


def test_api_trusts_only_the_traefik_address(compose):
    env = _env(compose["services"]["api"])
    allow = env.get("FORWARDED_ALLOW_IPS", "")
    assert allow not in ("", "*", "127.0.0.1"), f"FORWARDED_ALLOW_IPS güvensiz/etkisiz: {allow!r}"
    traefik_ip = compose["services"]["traefik"]["networks"]["edge"]["ipv4_address"]
    assert allow == traefik_ip, "api yalnızca Traefik'in sabit adresine güvenmeli"
    subnet = compose["networks"]["edge"]["ipam"]["config"][0]["subnet"]
    assert ipaddress.ip_address(traefik_ip) in ipaddress.ip_network(subnet)
    assert env.get("TRUSTED_PROXY") == "1" and env.get("TRUSTED_PROXY_HOPS") == "1"


def test_render_declares_proxy_trust_knobs():
    r = yaml.safe_load((ROOT / "render.yaml").read_text(encoding="utf-8"))
    env = {e["key"]: e.get("value") for e in r["services"][0]["envVars"]}
    assert env.get("TRUSTED_PROXY") == "1"
    assert env.get("TRUSTED_PROXY_HOPS") == "1"
    assert env.get("FORWARDED_ALLOW_IPS") != "", "FORWARDED_ALLOW_IPS boş bırakılamaz"


def _scheme_for(peer: str, trusted: str) -> str:
    seen: dict = {}

    async def inner(scope, receive, send):
        seen["scheme"] = scope["scheme"]

    mw = ProxyHeadersMiddleware(inner, trusted_hosts=trusted)
    scope = {"type": "http", "scheme": "http", "client": (peer, 5555),
             "headers": [(b"x-forwarded-proto", b"https"), (b"x-forwarded-for", b"203.0.113.9")]}
    asyncio.run(mw(scope, None, None))
    return seen["scheme"]


def test_uvicorn_honours_https_only_from_trusted_peer():
    assert _scheme_for("172.30.40.2", "172.30.40.2") == "https"
    assert _scheme_for("172.30.40.9", "172.30.40.2") == "http", "güvenilmeyen eş şemayı değiştirememeli"
    # Eski yapılandırmanın hatası: Traefik başka bir IP'den bağlandığı için https kayboluyordu
    assert _scheme_for("172.30.40.2", "127.0.0.1") == "http"
