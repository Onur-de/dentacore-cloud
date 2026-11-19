"""DentaCore v6.2 — Tek Tıkla GitHub'a Yükleme ve Kalıcı Link Oluşturma Sihirbazı."""
from __future__ import annotations

import subprocess
import sys
import webbrowser
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
GIT_EXE = r"C:\Users\onura\AppData\Local\Programs\Git\cmd\git.exe"
if not Path(GIT_EXE).exists():
    GIT_EXE = "git"


def run_git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([GIT_EXE, *args], cwd=str(REPO_DIR), text=True, capture_output=True, encoding="utf-8")


def main() -> None:
    print("=" * 72)
    print("  DENTACORE v6.2 — KALICI GITHUB & BULUT YUKLEME SIHIRBAZI")
    print("=" * 72)
    print()

    # Check current remote
    res = run_git("remote", "get-url", "origin")
    remote_url = res.stdout.strip() if res.returncode == 0 else ""

    if remote_url:
        print(f"[✓] Mevcut GitHub Depo Adresi: {remote_url}")
        degistir = input("Ayni adrese yuklensin mi? (E/h, Enter=Evet): ").strip().lower()
        if degistir == "h":
            remote_url = ""

    if not remote_url:
        print("1) Simdi tarayicida GitHub yeni depo olusturma sayfasi acilacak.")
        print("2) Depo adina 'dentacore-cloud' yazip 'Create repository' butonuna tiklayin.")
        print("3) Olusan sayfadaki 'https://github.com/...' adresini kopyalayip asagiya yapistirin.")
        print()
        ac = input("GitHub yeni depo sayfasi tarayicida acilsin mi? (E/h, Enter=Evet): ").strip().lower()
        if ac != "h":
            webbrowser.open("https://github.com/new")
        print()
        remote_url = input("GitHub Depo Linkini Yapistirin (ornek: https://github.com/adiniz/dentacore-cloud.git): ").strip()
        if not remote_url:
            print("[!] Link girilmedi. Istediginiz zaman bu dosyayi tekrar calistirabilirsiniz.")
            input("\nCikmak icin Enter'a basin...")
            return

        if not remote_url.endswith(".git") and "github.com/" in remote_url:
            remote_url = remote_url.rstrip("/") + ".git"

        run_git("remote", "remove", "origin")
        run_git("remote", "add", "origin", remote_url)

    print("\n[*] Dosyalar GitHub'a yukleniyor (Tarayicida giris penceresi acilirsa onaylayin)...")
    run_git("add", ".")
    run_git("commit", "-m", "chore: update DentaCore v6.2 cloud bundle")
    push_proc = subprocess.run([GIT_EXE, "push", "-u", "origin", "main"], cwd=str(REPO_DIR))
    if push_proc.returncode != 0:
        subprocess.run([GIT_EXE, "pull", "--rebase", "origin", "main"], cwd=str(REPO_DIR))
        push_proc = subprocess.run([GIT_EXE, "push", "-u", "origin", "main"], cwd=str(REPO_DIR))

    if push_proc.returncode == 0:
        clean_url = remote_url[:-4] if remote_url.endswith(".git") else remote_url
        parts = clean_url.rstrip("/").split("/")
        user_name = parts[-2] if len(parts) >= 2 else "kullanici"
        repo_name = parts[-1] if len(parts) >= 1 else "dentacore-cloud"
        pages_url = f"https://{user_name}.github.io/{repo_name}/"
        settings_pages_url = f"{clean_url}/settings/pages"

        print("\n" + "=" * 72)
        print("  [BASARILI] SISTEM %100 GITHUB'A YUKLENDI!")
        print("=" * 72)
        print(f"  • GitHub Depo Adresi : {clean_url}")
        print(f"  • Kalici Tam Sistem  : {pages_url}")
        print(f"  • Kalici Tanitim     : {pages_url}tanitim.html")
        print(f"  • Kalici Panel       : {pages_url}panel.html")
        print("=" * 72)
        print("\n[*] Simdi GitHub Pages ayarlar sayfasi aciliyor ('Source: GitHub Actions' secin — Branch secerseniz cift dagitim cakismasi olur)...")
        webbrowser.open(settings_pages_url)
    else:
        print("\n[!] Yukleme sirasinda GitHub girisi tamamlanmadi veya baglanti hatasi olustu.")
        print("    Tekrar denemek icin bu araci yeniden calistirabilirsiniz.")

    input("\nKapatmak icin Enter'a basin...")


if __name__ == "__main__":
    main()
