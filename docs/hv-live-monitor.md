# HV live monitor

`scripts\hv_live_monitor.bat` now starts in passive local mode. It clears
`logs\hv_monitor_live` and records Windows System/Application events, process
presence, uptime, and memory state. It does not call `cpuid_ping` or
`hv_breadcrumb`, so the monitor itself does not create diagnostic CPUID
VM-exits.

Double-click `scripts\hv_live_monitor.bat`, or run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\hv_live_monitor.ps1
```

Local passive files:

- `windows_events.jsonl`: new System and Application event records.
- `heartbeat.csv`: OS, game-process, and event-log heartbeat.
- `state.json`, `context.json`, and `monitor.log`: monitor state and settings.
- `cpuid_status.log`: explicitly states that no probes ran.

The old active behavior remains available only when explicitly requested:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\hv_live_monitor.ps1 -ActiveHvProbes
```

Active mode calls `cpuid_ping` once per interval and starts
`hv_breadcrumb.exe`; those queries generate additional VM-exits and affect
timing/counters. Do not use active mode when reproducing the freeze unless the
extra interference is intentional.

For HV state without diagnostic CPUID polling, use the second-PC COM2 receiver
described in `docs\hv-serial-monitor.md`.
