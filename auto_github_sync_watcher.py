"""
DentaCore v6.2 — Tam Otomatik Arka Plan GitHub Senkronizasyon Servisi.
Dosyalarda bir değişiklik olduğunda hiçbir tuşa basmaya gerek kalmadan
otomatik olarak GitHub ve GitHub Pages canlı sitelerini günceller.
"""
from __future__ import annotations

import ctypes
import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(r"C:\Users\onura\OneDrive\Masaüstü\Kurumsal-Otomasyon-Sistemi")
SRC_WEB = ROOT / "4_SISTEM_MOTORU_DOKUNMA" / "dentacore" / "api" / "app" / "web"
SRC_WA = ROOT / "WhatsApp_Gonderim"
TARGET = ROOT / "5_KALICI_GITHUB_VE_BULUT_KURULUMU"
GIT_EXE = r"C:\Users\onura\AppData\Local\Programs\Git\cmd\git.exe"
if not pathlib.Path(GIT_EXE).exists():
    GIT_EXE = "git"
PYTHON_EXE = r"C:\Users\onura\anaconda3\python.exe"
LOG_FILE = pathlib.Path(tempfile.gettempdir()) / "dentacore_github_autosync.log"

REPOS = [
    "https://github.com/Onur-de/Kurumsal-Otomasyon-Sistemi.git",
    "https://github.com/Onur-de/Kurumsal-Otomasyon-Sistemii.git",
    "https://github.com/Onur-de/dentacore-cloud.git",
]

EDGEONE_HREF_RE = re.compile(r'href="https://mcp\.edgeone\.site/share/[^"]+"')


def _log(msg: str) -> None:
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def _acquire_single_instance() -> object | None:
    """Ensure only one watcher instance runs on Windows even if multiple Startup entries launch."""
    if sys.platform != "win32":
        return True
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, "Global\\DentaCoreGitHubAutoSyncWatcher")
    if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        return None
    return mutex


def compute_fingerprint() -> str:
    """Hash source web and WhatsApp bundle files excluding volatile EdgeOne share URLs."""
    h = hashlib.sha256()
    for folder in (SRC_WEB, SRC_WA):
        if not folder.exists():
            continue
        for p in sorted(folder.glob("*.html")) + sorted(folder.glob("*.css")) + sorted(folder.glob("*.js")):
            try:
                if folder == SRC_WA and p.suffix == ".html":
                    content = EDGEONE_HREF_RE.sub('href="panel.html"', p.read_text(encoding="utf-8", errors="replace"))
                    h.update(f"{p.name}:".encode("utf-8"))
                    h.update(hashlib.sha256(content.encode("utf-8")).digest())
                else:
                    st = p.stat()
                    h.update(f"{p.name}:{st.st_size}:{int(st.st_mtime)}".encode("utf-8"))
            except Exception as exc:
                _log(f"fingerprint warning for {p}: {exc}")
    return h.hexdigest()


def normalize_pages_landing(html: str) -> str:
    """Keep GitHub Pages landing links pointing to permanent panel.html instead of ephemeral EdgeOne shares."""
    html = html.replace('href="/app"', 'href="panel.html"')
    html = EDGEONE_HREF_RE.sub('href="panel.html"', html)
    return html


def _push_remote(remote: str) -> None:
    res = subprocess.run([GIT_EXE, "push", remote, "main:main"], cwd=str(TARGET), capture_output=True, text=True)
    if res.returncode != 0:
        _log(f"push fast-forward failed for {remote}: {res.stderr.strip()}; retrying with --force-with-lease")
        res2 = subprocess.run(
            [GIT_EXE, "push", remote, "main:main", "--force-with-lease"],
            cwd=str(TARGET),
            capture_output=True,
            text=True,
        )
        if res2.returncode != 0:
            _log(f"push error for {remote}: {res2.stderr.strip()}")


def sync_once() -> None:
    """Rebuild standalone bundles if needed, normalize docs/ links, commit diffs, and push serially."""
    pure_script = SRC_WA / "deploy_pure_1to1.py"
    if pure_script.exists():
        res = subprocess.run([PYTHON_EXE, "-X", "utf8", str(pure_script)], cwd=str(SRC_WA), capture_output=True, text=True)
        if res.returncode != 0:
            _log(f"deploy_pure_1to1 failed: {res.stderr.strip()}")

    docs_dir = TARGET / "docs"
    app_subdir = docs_dir / "app"
    docs_dir.mkdir(parents=True, exist_ok=True)
    app_subdir.mkdir(parents=True, exist_ok=True)

    birebir_tanitim = SRC_WA / "1_Birebir_Tanitim_Sitesi.html"
    birebir_panel = SRC_WA / "2_Birebir_Yonetim_Paneli.html"
    if birebir_tanitim.exists():
        html_t = normalize_pages_landing(birebir_tanitim.read_text(encoding="utf-8"))
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
        cm = subprocess.run(
            [GIT_EXE, "commit", "-m", "chore(auto-sync): automatic background update"],
            cwd=str(TARGET),
            capture_output=True,
            text=True,
        )
        if cm.returncode == 0:
            for remote in REPOS:
                _push_remote(remote)


def main() -> None:
    _mutex = _acquire_single_instance()
    if _mutex is None:
        _log("Duplicate watcher instance exited cleanly.")
        return

    last_fp = compute_fingerprint()
    while True:
        time.sleep(25)
        try:
            curr_fp = compute_fingerprint()
            if curr_fp != last_fp:
                # Cooldown debounce so rapid edits batch into one push instead of racing Pages deploys
                time.sleep(10)
                sync_once()
                last_fp = compute_fingerprint()
        except Exception as exc:
            _log(f"watcher loop error: {exc}")


if __name__ == "__main__":
    main()
