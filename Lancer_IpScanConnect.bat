@echo off
setlocal
title IpScanConnect - Demarrage...
cd /d "%~dp0"

:: Verification des privileges administrateur
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Demande d'elevation administrateur pour le controle reseau...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: Lancement de l'application
if exist "bin\IpScanConnect.exe" (
    start "" "bin\IpScanConnect.exe"
) else if exist "IpScanConnect.exe" (
    start "" "IpScanConnect.exe"
) else (
    echo [ERREUR] Impossible de trouver IpScanConnect.exe
    pause
)
