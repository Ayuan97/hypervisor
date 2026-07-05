@echo off
start /b powershell -NoProfile -ExecutionPolicy Bypass -File "D:\hello\code\hypervisor\tools\freeze_monitor.ps1" > nul 2>&1
echo Monitor started
