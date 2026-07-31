# Local-file HV monitor

The local diagnostic build writes HV telemetry directly to:

```text
D:\rust-cheat\hv_diag_live.log
```

The file is overwritten whenever the diagnostic driver is loaded, so every
reboot/test session starts without data from the previous run. VM-exit handlers
only update the existing lock-free per-CPU ring. A kernel system thread running
outside VM-exit context collects the latest completed slots every 100 ms,
writes one bounded batch, and calls `ZwFlushBuffersFile` immediately.

The file is opened and its `HVL1 START` record is flushed before per-CPU VMX
initialization begins. Both the start record and periodic `HVL1 C` records
include `boot_stage`, so an initialization failure still leaves the last
reached startup phase on disk.

All logical processors remain enabled. Their persistent, affinity-pinned SMP
workers initialize VMX in CPU-index order, handing the launch turn to the next
CPU only after the current CPU has entered the guest successfully. The CPUs
share one immutable 0x202000-byte identity page-table allocation instead of
allocating the same paging hierarchy once per VCPU.

This avoids diagnostic CPUID polling, but it is not completely passive. The
kernel worker and filesystem flushes add some I/O. A total machine freeze can
also lose the final batch that had not run or reached stable storage. Earlier
flushed records remain available after reboot.

## Build and load

Do this before starting the game/EAC:

1. Reboot so no old HV instance remains.
2. Double-click `D:\rust-cheat\scripts\build_local_diag.bat` once after a code
   change.
3. Double-click `D:\rust-cheat\scripts\start_local_diag.bat`. It requests
   Administrator privileges through UAC, starts both monitors, loads the
   diagnostic HV, and opens the live kernel-log viewer.

For normal testing, `start_local_diag.bat` is the only runtime entry point.
Do not start a second monitor or load script alongside it.

The build creates:

```text
D:\rust-cheat\output\hv\matrix_local_diag.sys
```

It enables the normal client-read and concealment settings plus the build-time
flag `HV_LOCAL_DIAG=1`. One release codegen unit is used to avoid the thin-LTO
ICE in the currently installed nightly compiler.

Do not hot-load or replace the HV while the game/EAC is running.

## Watch the log

`start_local_diag.bat` opens the local viewer automatically. The viewer waits
for the file to appear and then follows new records. Closing the viewer does
not stop kernel logging.

## Passive Windows event monitor

The same launcher starts `D:\rust-cheat\scripts\hv_live_monitor.ps1` before HV
loading. On every run it clears `D:\rust-cheat\hv_monitor_live`, then records
new Windows System/Application events, process presence, uptime, and memory
state. Default mode does not call `cpuid_ping` or `hv_breadcrumb`, so the
companion monitor does not create diagnostic CPUID VM-exits.

Files written under `hv_monitor_live`:

- `windows_events.jsonl`: new System and Application event records.
- `heartbeat.csv`: OS, game-process, and event-log heartbeat.
- `state.json`, `context.json`, and `monitor.log`: monitor state and settings.
- `cpuid_status.log`: explicitly states that no active probes ran.

Active probing remains available only for focused diagnostics:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File D:\rust-cheat\scripts\hv_live_monitor.ps1 -ActiveHvProbes
```

Active mode calls `cpuid_ping` once per interval and starts
`hv_breadcrumb.exe`. Those queries generate additional VM-exits and affect
timing/counters, so do not use active mode when reproducing a freeze unless
that interference is intentional.

## Record format

`HVL1 R` is the newest completed ring record for a CPU:

```text
HVL1 R seq=42 cpu=7 ring_seq=9182 overwritten=31 reason=0xa rip=0xffff... qual=0x0 rax=0x...
```

`overwritten` is the number of VM-exits on that CPU between file snapshots.
Those intermediate exits no longer fit in the fixed 16-entry ring; the newest
completed entry is still preserved.

`HVL1 C` is emitted about once per second. It contains total/CPUID/MSR/VMX/EPT
counts, host faults, MSR `#GP` injections, EFER/APERF/MPERF/DEBUGCTL/LBR probe
counters, bugcheck evidence, freeze state, file-write failures, and dropped
record count.

Important fields:

- `eptm`, `hostfault`, `gp`, `pf`, `mc`, `bughit`, `bugcb`, or `freeze` nonzero:
  abnormal and high priority.
- `vmx`, `msrgp`, `efer_r`, `aperf`, `mperf`, `dbg_r`, `dbg_w`, or `lbr`
  changing: that capability/probe path was exercised. Context is still needed
  to distinguish normal OS behavior from detection activity.
- `write_failures` increasing: the local file write or flush failed.
- `dropped_records` increasing: a bounded in-memory output batch filled before
  another formatted record could be appended.

The log cannot contain literally every high-rate VM-exit. It records each CPU's
newest state and reports the exact coverage gap through `overwritten`.
