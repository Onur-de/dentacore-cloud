@echo off
chcp 65001 >nul
title DentaCore v6.2 - Tek Tikla GitHub ve Kalici Bulut Yukleyici
cd /d "%~dp0"
"C:\Users\onura\anaconda3\python.exe" -X utf8 github_auto_deployer.py
