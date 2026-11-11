@echo off
chcp 65001 >nul
cd /d "%~dp0"

set "MSBUILD_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
set "CSC_PATH=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

echo [*] Compilation IpScanConnect (Release x64)...
"%MSBUILD_PATH%" "%~dp0App\IpScanConnect.csproj" /p:Configuration=Release /p:Platform=x64 /v:m
if errorlevel 1 exit /b 1

echo [*] Compilation des tests unitaires C#...
"%CSC_PATH%" /nologo /platform:x64 /target:exe /lib:"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF" /out:"%~dp0bin\IpScanConnect.Tests.exe" /r:"%~dp0bin\IpScanConnect.exe" /r:System.Core.dll /r:PresentationFramework.dll /r:PresentationCore.dll /r:WindowsBase.dll /r:System.Xaml.dll "%~dp0tests\IpScanConnect.Tests.cs"
if errorlevel 1 exit /b 1

echo [*] Execution des tests...
"%~dp0bin\IpScanConnect.Tests.exe"
exit /b %ERRORLEVEL%
