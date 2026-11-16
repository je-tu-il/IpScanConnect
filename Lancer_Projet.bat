@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "APP_TITLE=IpScanConnect"
title %APP_TITLE%

echo ========================================================
echo   %APP_TITLE%
echo ========================================================
echo.

set "PROJ_ROOT=%~dp0"
set "EXE_PATH=%PROJ_ROOT%IpScanConnect.exe"
set "BIN_EXE=%PROJ_ROOT%bin\IpScanConnect.exe"
set "CSPROJ_PATH=%PROJ_ROOT%App\IpScanConnect.csproj"
set "MSBUILD_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
set "NEED_BUILD=0"

if not exist "%EXE_PATH%" set "NEED_BUILD=1"
if "%NEED_BUILD%"=="1" goto DO_BUILD

powershell -NoProfile -Command "try { $e = (Get-Item -LiteralPath $env:EXE_PATH).LastWriteTimeUtc; $appDir = Join-Path $env:PROJ_ROOT 'App'; $latest = Get-ChildItem -LiteralPath $appDir -Recurse -File | Where-Object { $_.Extension -in '.cs','.xaml','.csproj','.manifest' } | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1; if ($latest -and $latest.LastWriteTimeUtc -gt $e) { exit 1 } else { exit 0 } } catch { exit 1 }" >nul 2>&1
if errorlevel 1 set "NEED_BUILD=1"

if "%NEED_BUILD%"=="1" goto DO_BUILD

echo [OK] IpScanConnect.exe est deja a jour.
goto LAUNCH

:DO_BUILD
echo [*] Modifications detectees ou executable manquant.
echo [*] Recompilation automatique en cours...
echo.

taskkill /f /im IpScanConnect.exe >nul 2>&1

if exist "%MSBUILD_PATH%" goto BUILD_FRAMEWORK
where msbuild >nul 2>&1
if errorlevel 1 goto NO_MSBUILD
msbuild "%CSPROJ_PATH%" /p:Configuration=Release /p:Platform=x64 /v:m
if errorlevel 1 goto BUILD_FAIL
goto COPY_EXE

:BUILD_FRAMEWORK
"%MSBUILD_PATH%" "%CSPROJ_PATH%" /p:Configuration=Release /p:Platform=x64 /v:m
if errorlevel 1 goto BUILD_FAIL

:COPY_EXE
if not exist "%BIN_EXE%" goto MISSING_BIN
copy /y "%BIN_EXE%" "%EXE_PATH%" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Binaire racine mis a jour avec succes.
    echo.
    goto LAUNCH
)
echo [ATTENTION] Impossible d'ecraser "%EXE_PATH%" (application deja active).
echo [INFO] Pour remplacer la copie racine, fermez IpScanConnect depuis les icones cachees (Clic droit - Quitter).
echo [*] Lancement direct de la version fraichement compilee ("%BIN_EXE%")...
echo.
set "EXE_PATH=%BIN_EXE%"
goto LAUNCH

:LAUNCH
if /i "%~1"=="--build-only" exit /b 0
echo [*] Lancement de IpScanConnect.exe...
start "" "%EXE_PATH%"
exit /b 0

:NO_MSBUILD
echo [!] MSBuild introuvable sur cet ordinateur.
pause
exit /b 1

:BUILD_FAIL
echo.
echo [ERREUR] Echec de la recompilation MSBuild.
pause
exit /b 1

:MISSING_BIN
echo [ERREUR] Binaire compile introuvable : "%BIN_EXE%"
pause
exit /b 1

:COPY_FAIL
echo [ERREUR] Impossible de copier "%BIN_EXE%" vers "%EXE_PATH%".
echo [!] Si IpScanConnect est ouvert en arriere-plan dans les icones cachees, quittez-le puis relancez.
pause
exit /b 1
