@echo off
setlocal

if "%~1"=="" (
    echo Usage: scripts\debug_stage.bat STAGE
    echo Example: scripts\debug_stage.bat 600
    exit /b 2
)

set "ROOT=%~dp0.."
set "KDMAPPER=D:\rust-cheat\tools\kdmapper\x64\Release\kdmapper_Release.exe"
set "DRIVER=%ROOT%\target\release\matrix_stage_%~1.sys"

if not exist "%KDMAPPER%" (
    echo [-] kdmapper not found: "%KDMAPPER%"
    exit /b 4
)

call "%~dp0build_stage.bat" %~1
if %errorlevel% neq 0 (
    exit /b %errorlevel%
)

echo [*] Mapping stage-gated driver. Expected stop stage: %~1
echo     COM2 should show the last hv stage reached.
"%KDMAPPER%" "%DRIVER%"
echo [*] kdmapper exit=%errorlevel%
echo [*] If the machine did not freeze, this stage survived.
exit /b 0
