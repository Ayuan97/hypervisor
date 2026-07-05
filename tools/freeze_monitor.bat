@echo off
set LOG=D:\hello\code\hypervisor\logs\freeze_monitor.log
set PING=D:\hello\code\hypervisor\tools\cpuid_ping.exe
set N=0

echo [%date% %time%] freeze_monitor started > %LOG%

:loop
set /a N+=1
%PING% > %LOG%.tmp 2>&1

for /f "tokens=3 delims== " %%a in ('findstr /c:"Total" %LOG%.tmp') do set TOTAL=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"CPUID         =" %LOG%.tmp') do set CPUID=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"EPT Viol" %LOG%.tmp') do set EPT=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"CR Access" %LOG%.tmp') do set CR=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"MSR           =" %LOG%.tmp') do set MSR=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"VMX Instr" %LOG%.tmp') do set VMX=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"Other" %LOG%.tmp') do set OTHER=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"Host #GP      =" %LOG%.tmp') do set GP=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"LastHandlerID" %LOG%.tmp') do set HID=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"LastExitReason" %LOG%.tmp') do set LER=%%a
for /f "tokens=3 delims== " %%a in ('findstr /c:"Write index" %LOG%.tmp') do set RI=%%a

echo [%time%] p=%N% T=%TOTAL% C=%CPUID% EPT=%EPT% CR=%CR% MSR=%MSR% VMX=%VMX% O=%OTHER% GP=%GP% hid=%HID% lr=%LER% ri=%RI% >> %LOG%

timeout /t 2 /nobreak > nul
goto loop
