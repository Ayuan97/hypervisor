# HV live monitor

Run this after the hypervisor is loaded:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\hv_live_monitor.ps1
```

The script clears `logs\hv_monitor_live` at startup. It then runs the per-CPU
breadcrumb sampler and periodically captures the complete `cpuid_ping` report.
Each sample is flushed immediately so the last data remains available after a
freeze or forced reboot.

Useful options:

```powershell
# Faster sampling
powershell -NoProfile -File scripts\hv_live_monitor.ps1 -IntervalMs 250

# Run for one minute
powershell -NoProfile -File scripts\hv_live_monitor.ps1 -DurationSeconds 60

# Only collect CPUID/System/Application telemetry
powershell -NoProfile -File scripts\hv_live_monitor.ps1 -NoBreadcrumb
```

Files in the live directory:

- `cpuid_status.log`: timestamped full diagnostic output, including counters,
  VMCS controls, watchdog, host faults, freeze/CMOS fields, and probe-related
  observations exposed by the HV.
- `hv_breadcrumb.csv`: flushed per-CPU VM-exit breadcrumb samples and counters.
- `windows_events.jsonl`: new System and Application event records.
- `heartbeat.csv`: compact time series for scripts/Excel analysis.
- `state.json` and `monitor.log`: current sampler state and lifecycle events.

For full counters and freeze diagnostics, the HV must be loaded with
`HV_NO_SEAL=1`. A sealed diagnostics channel can still report limited status,
but it cannot expose all counters and control fields.

The monitor records the telemetry exposed by the current user-mode diagnostic
protocol. It cannot reconstruct VM-exits that the driver does not retain in its
breadcrumb/ring buffers.
