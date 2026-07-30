# Local-file HV monitor

The local diagnostic build writes HV telemetry directly to:

```text
C:\hv_diag_live.log
```

The file is overwritten whenever the diagnostic driver is loaded, so every
reboot/test session starts without data from the previous run. VM-exit handlers
only update the existing lock-free per-CPU ring. A kernel system thread running
outside VM-exit context collects the latest completed slots every 100 ms,
writes one bounded batch, and calls `ZwFlushBuffersFile` immediately.

This avoids diagnostic CPUID polling, but it is not completely passive. The
kernel worker and filesystem flushes add some I/O. A total machine freeze can
also lose the final batch that had not run or reached stable storage. Earlier
flushed records remain available after reboot.

## Build and load

Do this before starting the game/EAC:

1. Reboot so no old HV instance remains.
2. Double-click `scripts\build_local_diag.bat` once after a code change.
3. Run `scripts\start_local_diag.bat` as Administrator. This single script
   loads the diagnostic HV and automatically opens both passive monitors.

The build creates:

```text
target\release\matrix_local_diag.sys
```

It enables the normal client-read and concealment settings plus the build-time
flag `HV_LOCAL_DIAG=1`. One release codegen unit is used to avoid the thin-LTO
ICE in the currently installed nightly compiler.

Do not hot-load or replace the HV while the game/EAC is running.

## Watch the log

`start_local_diag.bat` opens the local viewer automatically. The standalone
`scripts\hv_local_log_viewer.bat` is available when the driver is already
loaded. The viewer waits for the file to appear and then follows new records.
Closing the viewer does not stop kernel logging.

The existing `scripts\hv_live_monitor.bat` may run at the same time to capture
Windows System/Application events and process/OS state. Its default mode does
not issue diagnostic CPUID requests.

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
