@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Rust Test Client (no EAC, localhost)

set GAME_DIR=D:\steam\steamapps\common\Rust
set CLIENT_EXE=%GAME_DIR%\RustClient.exe
set TARGET=localhost:28015

echo ============================================
echo   Rust Client (no EAC) -^> %TARGET%
echo ============================================
echo.

if not exist "%CLIENT_EXE%" (
    echo [-] RustClient.exe not found: "%CLIENT_EXE%"
    echo     Verify Steam Rust install path.
    pause
    exit /b 1
)

echo [*] Checking for local server on port 28015...
netstat -an | findstr /R /C:"0.0.0.0:28015 .*LISTENING" >nul 2>&1
if errorlevel 1 (
    netstat -an | findstr /R /C:"127.0.0.1:28015 .*LISTENING" >nul 2>&1
    if errorlevel 1 (
        echo [!] No listener on 28015. Start start_test_server.bat first
        echo     and wait for "Server startup complete" before running this.
        echo.
        choice /C YN /N /M "Continue anyway? (Y/N) "
        if errorlevel 2 exit /b 2
    )
)

echo [*] Launching RustClient -^> %TARGET% (offline mode)...
echo.

cd /d "%GAME_DIR%"

start "" "%CLIENT_EXE%" -connect %TARGET% +app.forceoffline

echo [+] Launched. This window will close in 3s.
timeout /t 3 /nobreak >nul
endlocal
