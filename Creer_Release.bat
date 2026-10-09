@echo off
setlocal enabledelayedexpansion
title Generation de la Release - IpScanConnect
cd /d "%~dp0"

echo =========================================================
echo       GENERATION DE LA RELEASE IPSCANCONNECT v1.0
echo =========================================================
echo.

set MSBUILD="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
set CSC="C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if not exist %MSBUILD% (
    echo [ERREUR] MSBuild non trouve dans .NET Framework 4.8.
    pause
    exit /b 1
)

:: 1. Compilation de l'application principale
echo [1/4] Compilation de IpScanConnect.exe...
%MSBUILD% App\IpScanConnect.csproj /p:Configuration=Release /p:Platform=x64 /v:minimal
if %errorlevel% neq 0 (
    echo [ERREUR] Echec compilation IpScanConnect.
    pause
    exit /b 1
)
copy /y "bin\IpScanConnect.exe" "IpScanConnect.exe" >nul

:: 2. Compilation du Desinstalleur
echo [2/4] Compilation du Desinstalleur Uninstall.exe...
%CSC% /nologo /target:winexe /r:System.Windows.Forms.dll /r:System.Drawing.dll /out:Installer\Uninstall.exe Installer\UninstallProgram.cs
if %errorlevel% neq 0 (
    echo [ERREUR] Echec compilation Uninstall.exe.
    pause
    exit /b 1
)

:: 3. Compilation du Programme d'Installation Setup
echo [3/4] Compilation du Programme d'Installation IpScanConnect_Setup.exe...
%MSBUILD% Installer\IpScanConnect_Setup.csproj /p:Configuration=Release /p:Platform=x64 /v:minimal
if %errorlevel% neq 0 (
    echo [ERREUR] Echec compilation Setup.
    pause
    exit /b 1
)

:: 4. Creation des packages Release
echo [4/4] Creation des packages d'installation et portable...
if not exist "Release" mkdir "Release"

:: Copie de l'Installeur Setup
copy /y "bin\IpScanConnect_Setup.exe" "Release\IpScanConnect_Setup_v1.0.exe" >nul

:: Creation de la version Portable ZIP
if exist "dist_temp" rmdir /s /q "dist_temp"
mkdir "dist_temp\IpScanConnect_v1.0_Portable"
copy /y "IpScanConnect.exe" "dist_temp\IpScanConnect_v1.0_Portable\" >nul
copy /y "Lancer_IpScanConnect.bat" "dist_temp\IpScanConnect_v1.0_Portable\" >nul
copy /y "README.md" "dist_temp\IpScanConnect_v1.0_Portable\" >nul
copy /y "LICENSE" "dist_temp\IpScanConnect_v1.0_Portable\" >nul

powershell -Command "Compress-Archive -Path 'dist_temp\IpScanConnect_v1.0_Portable' -DestinationPath 'Release\IpScanConnect_v1.0_Portable.zip' -Force"
rmdir /s /q "dist_temp"

echo.
echo =========================================================
echo       PACKAGES DE RELEASE GENERES AVEC SUCCES !
echo =========================================================
echo.
echo Fichiers prets dans le dossier 'Release\' :
echo   - Release\IpScanConnect_Setup_v1.0.exe  (Installeur Windows)
echo   - Release\IpScanConnect_v1.0_Portable.zip (Version Portable)
echo.
pause
