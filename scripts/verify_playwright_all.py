"""DentaCore v6.3 — Canlı FastAPI Sunucusu + Statik Bulut Demo (docs/) Tam Kapsamlı Playwright (1440x900 & 390x844) Doğrulayıcısı."""
from __future__ import annotations

import functools
import http.server
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
DENTACORE_DIR = HERE.parent
CLOUD_DOCS_DIR = DENTACORE_DIR.parent.parent / "5_KALICI_GITHUB_VE_BULUT_KURULUMU" / "docs"

ALL_15_TABS = [
    "overview",
    "calendar",
    "messages",
    "patients",
    "waitlist",
    "alerts",
    "inventory",
    "templates",
    "kasa",
    "analytics",
    "costs",
    "team",
    "clinics",
    "settings",
    "security",
]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 15.0) -> None:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"Server did not start in time: {url}")


def _verify_surface(page, base_url: str, panel_path: str, is_static: bool) -> dict:
    console_errors: list[str] = []
    page_errors: list[str] = []
    http_errors: list[str] = []

    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
    page.on("pageerror", lambda err: page_errors.append(str(err)))
    page.on(
        "response",
        lambda resp: http_errors.append(f"{resp.status} {resp.url}")
        if resp.status >= 400 and "favicon" not in resp.url
        else None,
    )

    for vp_name, vp in (("desktop", {"width": 1440, "height": 900}), ("mobile", {"width": 390, "height": 844})):
        page.set_viewport_size(vp)

        # 1) Landing page
        landing_url = f"{base_url}/index.html" if is_static else f"{base_url}/"
        page.goto(landing_url, wait_until="networkidle")
        overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
        assert not overflow, f"Landing overflow on {vp_name} (static={is_static})"

        # 2) Panel page
        p_url = f"{base_url}/{panel_path}"
        page.goto(p_url, wait_until="networkidle")
        page.wait_for_selector("input[name='email'], .shell", timeout=8000)

        # If on login screen, log in as owner
        if page.locator("input[name='email']").count() > 0:
            demo_owner_btn = page.locator(".demo-btn").first
            if demo_owner_btn.count() > 0:
                demo_owner_btn.click()
            else:
                page.fill("input[name='email']", "yonetici@dentacore.com")
                page.fill("input[name='password']", "DentaCore2026!")
            page.click("button[type='submit']")
            page.wait_for_selector(".shell", timeout=8000)
            page.wait_for_timeout(400)

        # Visit all 15 tabs on desktop (and key tabs on mobile)
        tabs_to_visit = ALL_15_TABS if vp_name == "desktop" else ["overview", "calendar", "patients", "analytics", "kasa"]
        for tk in tabs_to_visit:
            page.evaluate(f"location.hash = '#/{tk}'")
            page.wait_for_timeout(350)
            body_txt = page.inner_text("body")
            assert "Yükleme hatası" not in body_txt, f"UI error on #/{tk} ({vp_name}, static={is_static}): {body_txt[:300]}"
            assert "is not defined" not in body_txt, f"ReferenceError on #/{tk} ({vp_name}, static={is_static})"
            assert "NaN" not in body_txt, f"NaN displayed on #/{tk} ({vp_name}, static={is_static})"
            ov_tab = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
            assert not ov_tab, f"Horizontal overflow on #/{tk} ({vp_name}, static={is_static})"

        if vp_name == "desktop":
            # Verify Global Quick Search (Ctrl+K)
            page.evaluate("location.hash = '#/overview'")
            page.wait_for_timeout(300)
            q_btn = page.locator("button:has-text('Hızlı Hasta Ara')").first
            assert q_btn.count() > 0, "Missing Hızlı Hasta Ara button on #/overview"
            q_btn.click()
            page.wait_for_timeout(300)
            assert page.locator(".modal").count() > 0, "Quick search modal did not open"
            page.keyboard.press("Escape")
            page.wait_for_timeout(200)

            # Open patient drawer on #/patients and test 4 drawer tabs
            page.evaluate("location.hash = '#/patients'")
            page.wait_for_timeout(450)
            open_btn = page.locator("button:has-text('Aç')").first
            assert open_btn.count() > 0, "No patient 'Aç' button found on #/patients"
            open_btn.click()
            page.wait_for_timeout(450)
            assert page.locator(".drawer").count() > 0, "Patient drawer did not open"
            for d_tk in ("summary", "odo", "finance", "clinical", "all"):
                tab_btn = page.locator(f".drawer-tab[data-tk='{d_tk}']")
                assert tab_btn.count() > 0, f"Missing drawer tab {d_tk}"
                tab_btn.click()
                page.wait_for_timeout(120)
            drawer_txt = page.inner_text(".drawer")
            assert "Yükleme hatası" not in drawer_txt
            assert "is not defined" not in drawer_txt
            page.keyboard.press("Escape")
            page.wait_for_timeout(200)

    assert not console_errors, f"Console errors (static={is_static}): {console_errors}"
    assert not page_errors, f"Page errors (static={is_static}): {page_errors}"
    assert not http_errors, f"HTTP >=400 errors (static={is_static}): {http_errors}"
    return {"ok": True, "tabs_checked": len(ALL_15_TABS), "console_errors": 0, "http_errors": 0}


def main() -> None:
    tmp_dir = tempfile.mkdtemp(prefix="dc_pw_")
    live_port = _free_port()
    env = os.environ.copy()
    env["DC_DB_PATH"] = str(Path(tmp_dir) / "pw_live.db")
    env["DC_MEDIA_DIR"] = str(Path(tmp_dir) / "pw_media")
    env["DC_PORT"] = str(live_port)
    env["DC_ALLOW_HTTP_LOCAL"] = "1"

    proc = subprocess.Popen(
        [sys.executable, "-X", "utf8", "run_local.py"],
        cwd=str(DENTACORE_DIR),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    static_port = _free_port()
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(CLOUD_DOCS_DIR))
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", static_port), handler)
    t_static = threading.Thread(target=httpd.serve_forever, daemon=True)
    t_static.start()

    try:
        _wait_http(f"http://127.0.0.1:{live_port}/health")
        _wait_http(f"http://127.0.0.1:{static_port}/panel.html")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx1 = browser.new_context()
            res_live = _verify_surface(ctx1.new_page(), f"http://127.0.0.1:{live_port}", "app", is_static=False)
            ctx1.close()

            ctx2 = browser.new_context()
            res_static = _verify_surface(ctx2.new_page(), f"http://127.0.0.1:{static_port}", "panel.html", is_static=True)
            ctx2.close()
            browser.close()
        print("PLAYWRIGHT_VERIFICATION_PASS", {"live_server": res_live, "static_cloud_docs": res_static})
    finally:
        httpd.shutdown()
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()


if __name__ == "__main__":
    main()
