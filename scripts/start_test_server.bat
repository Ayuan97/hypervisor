@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Rust Test Server (no EAC)

set SERVER_DIR=D:\rust-cheat\server
set SERVER_EXE=%SERVER_DIR%\RustDedicated.exe
set SERVER_CFG=%SERVER_DIR%\server\test\cfg\serverauto.cfg

echo ============================================
echo   Rust Local Test Server (no EAC)
echo ============================================
echo.

if not exist "%SERVER_EXE%" (
    echo [-] RustDedicated.exe not found: "%SERVER_EXE%"
    echo     Install via: D:\rust-cheat\tools\steamcmd\steamcmd.exe +force_install_dir %SERVER_DIR% +login anonymous +app_update 258550 validate +quit
    pause
    exit /b 1
)

if not exist "%SERVER_CFG%" (
    echo [!] serverauto.cfg not found: "%SERVER_CFG%"
    echo     First launch will create it. After "Server startup complete" appears,
    echo     close this window, then run:
    echo         Add-Content -Path "%SERVER_CFG%" -Value "`nserver.secure `"0`"`nserver.encryption `"0`""
    echo     Then rerun this script.
    echo.
) else (
    findstr /I /C:"server.secure \"0\"" "%SERVER_CFG%" >nul 2>&1
    if errorlevel 1 (
        echo [!] serverauto.cfg is missing 'server.secure "0"'.
        echo     EAC will be enabled - client will refuse to connect without EAC.
        echo     Fix with:
        echo         Add-Content -Path "%SERVER_CFG%" -Value "`nserver.secure `"0`"`nserver.encryption `"0`""
        echo.
        pause
    ) else (
        echo [+] server.secure = 0 detected in serverauto.cfg
    )
)

echo [*] Launching RustDedicated on port 28015...
echo.

cd /d "%SERVER_DIR%"

"%SERVER_EXE%" ^
    -batchmode ^
    +server.port 28015 ^
    +server.level "Procedural Map" ^
    +server.seed 12345 ^
    +server.worldsize 1000 ^
    +server.maxplayers 10 ^
    +server.hostname "test" ^
    +server.identity "test"

echo.
echo [*] Server exited. Press any key to close.
pause >nul
endlocal
