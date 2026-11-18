"""
DentaCore v6.2 — Tam Otomatik Arka Plan GitHub Senkronizasyon Servisi.
Dosyalarda bir değişiklik olduğunda hiçbir tuşa basmaya gerek kalmadan
otomatik olarak GitHub ve GitHub Pages canlı sitelerini günceller.
"""
from __future__ import annotations

import hashlib
import pathlib
import shutil
import subprocess
import time

ROOT = pathlib.Path(r"C:\Users\onura\OneDrive\Masaüstü\Kurumsal-Otomasyon-Sistemi")
SRC_WEB = ROOT / "4_SISTEM_MOTORU_DOKUNMA" / "dentacore" / "api" / "app" / "web"
SRC_WA = ROOT / "WhatsApp_Gonderim"
TARGET = ROOT / "5_KALICI_GITHUB_VE_BULUT_KURULUMU"
GIT_EXE = r"C:\Users\onura\AppData\Local\Programs\Git\cmd\git.exe"
PYTHON_EXE = r"C:\Users\onura\anaconda3\python.exe"

REPOS = [
    "https://github.com/Onur-de/Kurumsal-Otomasyon-Sistemi.git",
    "https://github.com/Onur-de/Kurumsal-Otomasyon-Sistemii.git",
    "https://github.com/Onur-de/dentacore-cloud.git",
]


def compute_fingerprint() -> str:
    h = hashlib.sha256()
    for folder in (SRC_WEB, SRC_WA):
        if not folder.exists():
            continue
        for p in sorted(folder.glob("*.html")) + sorted(folder.glob("*.css")) + sorted(folder.glob("*.js")):
            try:
                st = p.stat()
                h.update(f"{p.name}:{st.st_size}:{int(st.st_mtime)}".encode("utf-8"))
            except Exception:
                pass
    return h.hexdigest()


def sync_once() -> None:
    # Rebuild 1:1 standalone bundles if deploy_pure_1to1.py exists
    pure_script = SRC_WA / "deploy_pure_1to1.py"
    if pure_script.exists():
        subprocess.run([PYTHON_EXE, "-X", "utf8", str(pure_script)], cwd=str(SRC_WA), capture_output=True)

    docs_dir = TARGET / "docs"
    app_subdir = docs_dir / "app"
    docs_dir.mkdir(parents=True, exist_ok=True)
    app_subdir.mkdir(parents=True, exist_ok=True)

    birebir_tanitim = SRC_WA / "1_Birebir_Tanitim_Sitesi.html"
    birebir_panel = SRC_WA / "2_Birebir_Yonetim_Paneli.html"
    if birebir_tanitim.exists():
        html_t = birebir_tanitim.read_text(encoding="utf-8").replace('href="/app"', 'href="panel.html"')
        (docs_dir / "index.html").write_text(html_t, encoding="utf-8")
        (docs_dir / "tanitim.html").write_text(html_t, encoding="utf-8")
    if birebir_panel.exists():
        html_p = birebir_panel.read_text(encoding="utf-8")
        (docs_dir / "panel.html").write_text(html_p, encoding="utf-8")
        (docs_dir / "app.html").write_text(html_p, encoding="utf-8")
        (app_subdir / "index.html").write_text(html_p, encoding="utf-8")

    subprocess.run([GIT_EXE, "add", "."], cwd=str(TARGET), capture_output=True)
    st = subprocess.run([GIT_EXE, "status", "--porcelain"], cwd=str(TARGET), capture_output=True, text=True)
    if st.stdout.strip():
        subprocess.run(
            [GIT_EXE, "commit", "-m", "chore(auto-sync): automatic background update"],
            cwd=str(TARGET),
            capture_output=True,
        )
        for remote in REPOS:
            subprocess.run([GIT_EXE, "push", remote, "main:main", "--force"], cwd=str(TARGET), capture_output=True)


def main() -> None:
    last_fp = compute_fingerprint()
    while True:
        time.sleep(25)
        try:
            curr_fp = compute_fingerprint()
            if curr_fp != last_fp:
                time.sleep(3)
                sync_once()
                last_fp = compute_fingerprint()
        except Exception:
            pass


if __name__ == "__main__":
    main()
