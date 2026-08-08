# HV terminal capture and legacy local-file format

Workflow: `D:\cheat\DEV.md` §5-B. Project layout: `../CLAUDE.md`.

## Default freeze workflow: terminal capture

The default diagnostic scripts now build and load a reboot-persistent terminal
flight recorder:

```text
D:\cheat\scripts\build_local_diag.bat
D:\cheat\scripts\start_local_diag.bat
D:\cheat\output\hv\matrix_terminal_capture.sys
```

After a hard reset, use the collector before starting another terminal
session:

```text
D:\cheat\scripts\build_cmos_capture.bat
D:\cheat\scripts\start_cmos_capture.bat
D:\cheat\hv_cmos_capture.txt
```

The collector maps a separate read-only build, copies all 128 extended CMOS
bytes to stable storage, flushes and closes the file, and exits. It never
initializes VMX, creates a worker, or clears/writes CMOS. The offline decoder
is `tools\decode_terminal_cmos.rs`; archive the raw capture before another
HV load.

The build sets `HV_TERMINAL_CAPTURE=1` and explicitly sets
`HV_LOCAL_DIAG=0`. During the game there is no `hv_diag_live.log` worker and no
periodic filesystem flush from the recorder. Terminal mode also leaves the
COM2 logger disabled, so there is no `hv_live_monitor.ps1` or log viewer. The
terminal build sets `HV_USER_CLIENT_READS=0`, so it creates no client-read
system thread. After all CPUs enter non-root and the settle delay completes,
the only runtime worker action is a once-per-second CMOS checkpoint. The
loader maps the driver directly and then exits. It never calls `cpuid_ping`,
`probe_test`, `hv_breadcrumb`, seal, or an HV readiness query.

The loader creates an atomic boot-specific marker under
`D:\cheat\output\hv\load_guards\` immediately before kdmapper. A mapping
attempt, including a failed or partial attempt, consumes that Windows boot.
Reboot before retrying; never hot-map or replace a live instance.

## Collector-first invariant

Extended CMOS is the evidence, not the viewer. On the first diagnostic load
after a hard reset, the collector must read and preserve the complete previous
`0x00..0x7f` image **before** a new terminal session clears or writes any byte.
The previous image must reach stable storage before it is treated as archived.
Only after that succeeds may the recorder initialize the next session.
The collector output is:

```text
D:\cheat\hv_cmos_capture.txt
```

It contains an `HVCMOS1` header and one `raw_hex=` line with all 128 bytes;
the write is flushed synchronously before session initialization.

This ordering is mandatory:

1. Freeze, then hard reset.
2. Collect and verify the previous 128-byte image in `hv_cmos_capture.txt`.
3. Archive the decoded record together with the raw image.
4. Only then initialize or load a new test session.

Do not load a second HV merely to “see whether the first one is alive.” A
second map can overwrite the only terminal evidence and is prohibited by the
one-map-per-boot guard.

## Terminal CMOS format

The terminal profile owns the complete extended CMOS `0x00..0x7f` region. It
does not share the legacy Layer3/Layer6/retention layouts.

| Range | Meaning |
|---|---|
| `0x00..0x1f` | committed terminal slot A |
| `0x20..0x3f` | committed terminal slot B |
| `0x40..0x57` | latest reason and active bit for CPUs 0..23 |
| `0x58..0x6f` | checkpoint epoch and phase for CPUs 0..23 |
| `0x70..0x7f` | emergency host-fault capsule |

Each 32-byte terminal slot contains format/kind, sequence, CPU, phase, exit
reason, flags, VM-instruction error, session, full RIP, full exit
qualification, detail, active bitmap, CRC-8, and a commit byte. Writes alternate
between A and B. The target commit byte is invalidated first and written last;
a torn or corrupt target is rejected while the other committed slot remains
usable. Sequence comparison selects the newest valid slot.

Normal VM-exit progress updates RAM only. Approximately once per second the
recorder copies all 24 CPUs' reason/active and phase state to CMOS and commits a
terminal record. Rare exits, detected stalled handlers, VM-entry/VMRESUME
failures, host faults, and bugcheck evidence may force an earlier commit.

The one-second checkpoint is also the hard observation boundary. If every CPU
stops before the next checkpoint and no rare/fatal commit completes, CMOS can
only contain the last successful checkpoint. Nothing can write after the
machine has frozen. If another CPU continues running long enough to observe a
stalled handler, its forced record may narrow that window, but this is not
guaranteed. Terminal capture is a bounded terminal capsule, not a complete
trace of every high-rate VM-exit.

## Forbidden legacy reader

Do **not** run `tools\read_cmos_freeze.exe`. It uses the old standard-CMOS
`0x70/0x71` layout, does not decode terminal slots, performs privileged port I/O
from user mode, and can clear old magic. It is neither a collector nor a valid
terminal-capture reader. Do not use `cpuid_ping`, breadcrumb, probe, or seal as
a substitute for collector-first recovery.

## Test sequence

1. Build after a code change with `build_local_diag.bat`.
2. Reboot so no prior HV is live.
3. Run `start_local_diag.bat` once, before the game/EAC.
4. Expect no runtime file, viewer, monitor, heartbeat, or readiness query. The
   terminal worker writes only the reboot-persistent CMOS checkpoint.
5. Start the game and reproduce the freeze.
6. Hard reset and perform collector-first recovery before another HV session.

## Legacy HVL1 record format

The remainder of this document describes existing `hv_diag_live.log` archives
from older `HV_LOCAL_DIAG=1` runs. The default terminal build does not emit
these records and the default loader does not start the legacy monitor.

`HVL1 R` is the newest completed ring record for a CPU:

```text
HVL1 R seq=42 cpu=7 ring_seq=9182 overwritten=31 reason=0xa rip=0xffff... qual=0x0 rax=0x...
```

`overwritten` is the number of VM-exits on that CPU between file snapshots.
Those intermediate exits no longer fit in the fixed 16-entry ring; the newest
completed entry is still preserved.

`HVL1 C` is emitted about once per second. It contains total/CPUID/MSR/XSETBV/
VMX/EPT counts, effective pin-based VM-execution controls, host faults, raw
exception and IDT-vectoring context, MSR `#GP` injections,
EFER/APERF/MPERF/DEBUGCTL/LBR probe counters, bugcheck evidence, freeze state,
active VM-exit context, client-read worker state, file-write failures, and
dropped record count.

Important fields:

- `eptm`, `hostfault`, `gp`, `pf`, `mc`, `bughit`, `bugcb`, or `freeze` nonzero:
  abnormal and high priority.
- `vmx`, `xsetbv`, `msrgp`, `efer_r`, `aperf`, `mperf`, `dbg_r`, `dbg_w`, or `lbr`
  changing: that capability/probe path was exercised. Context is still needed
  to distinguish normal OS behavior from detection activity.
- `msr_r` / `msr_w` split the total `msr` exits by direction. `last_msr` is
  the most recently handled MSR address; `msr_action=0` means read and
  `msr_action=1` means write.
- `pin` is the effective pin-based execution-control value written to the
  VMCS. In particular, bit 3 is NMI exiting and bit 6 is the VMX preemption
  timer.
- `exc_cpu`, `exc_info`, and `exc_error` preserve the CPU and raw
  `VMEXIT_INTERRUPTION_INFO` / interruption error code from the latest
  Exception-or-NMI exit. Treat `exc_error` as meaningful only when bit 11 of
  `exc_info` is set. The event-context fields are read from one committed
  double-buffer snapshot, so concurrent CPUs cannot splice these values.
- `idt_info` / `idt_error` preserve the latest raw IDT-vectoring event seen at
  VM-exit entry; `idt_events` counts valid vectoring events. `entry_conflict_info`
  is the already-pending `VMENTRY_INTERRUPTION_INFO` observed when vectoring
  reinjection would collide with it, and `entry_conflicts` counts those
  collisions. `event_context_dropped` counts event-context updates skipped
  because another CPU was publishing a snapshot; writers never wait in
  VMX-root.
- `write_failures` increasing: the local file write or flush failed.
- `dropped_records` increasing: a bounded in-memory output batch filled before
  another formatted record could be appended.
- `cmos_io_contention` increasing: two CPUs tried to use the shared extended
  CMOS index/data ports at the same time. The losing diagnostic byte was
  skipped instead of waiting in VMX-root or interleaving the port pair.
- `init` / `sipi` / `awaiting_sipi` / `init_stage` / `init_stage_count`:
  passive INIT/SIPI telemetry. Runtime INIT and SIPI exits are discarded
  without changing guest state. Stages `6`/`14` mean INIT/SIPI selected the
  discard path; stages `7`/`15` mean all common VM-exit cleanup completed and
  the handler reached its return point. `awaiting_sipi` therefore remains zero.
  `init_last_cpu` and `sipi_vector` identify the most recent event
  (`sipi_vector=18446744073709551615` means no SIPI yet).
- `active` / `active_count`: bitmap and count of CPUs currently inside a
  VM-exit handler. `active_cpu` is the lowest active CPU represented by the
  following `phase`, `leaf`, and `command` fields; it is `u64::MAX` when no
  handler is active.
- `phase`: selected active CPU's VM-exit phase (`0x10` handler entry, `0x20`
  slow-path dispatch, `0x30` slow handler, `0x40` CPUID entry, `0x50` CPUID
  handled, `0x60` RIP advance, `0x68` IDT-vectoring reinjection, `0x70`
  pending-NMI check, `0x80` pre-VMRESUME). `leaf` and `command` are that CPU's
  last CPUID `RAX` and `RCX` inputs.
- `cr_worker` / `cr_phase`: client-read worker started flag and current phase.
  Phases are `1` start, `2` unarmed delay, `3` batch registration, `4` batch
  unregister, `5` batch processing, `6` physical read, `7` virtual read, `8`
  completion, `9` idle spin, `10` armed delay, `11` exit cleanup, and `12`
  exited.
- `cr_slot`, `cr_req`, `cr_done`, `cr_status`, `cr_kind`, and `cr_size`:
  single-read request slot, submitted/completed sequence, result status,
  request kind (`0` physical, `1` virtual), and byte count.
- `batch_state`, `batch_processed`, `batch_failures`, and `batch_processing`:
  registered batch state, lifetime processed/failure counters, and whether a
  batch callback currently owns the processing guard.

Layer 3 CMOS uses two checksummed 15-byte slots in the stable profile. This
keeps the original VM-exit write cost: magic, sequence, port80, active bitmap,
last exit, active count, and checksum. The reader accepts both the stable v1
magic (`0x4C`) and the extended v2 magic (`0x4D`) from earlier diagnostic
builds. Stable-profile snapshots therefore report `l3_phase=0`,
`l3_cr_phase=0`, and `l3_command=0`; an explicitly enabled extended profile
can capture those extra context fields.
On the next diagnostic load, `HVL1 PREV_FATAL` archives that previous-boot slot
before new VM-exits can overwrite it. Its `l3_phase`, `l3_cr_phase`, and
`l3_command` fields are the durable counterparts of the live phase/command
fields.

The same record includes each previous-boot rare-exit slot as:

```text
rareN=cpu:reason:rip:vector:meta
```

`reason`, `rip`, `vector`, and `meta` are hexadecimal. A committed context
record uses magic `0xD7`; legacy `0xD6` records are still accepted but report
`meta=0`. The packed `meta` byte is:

- bit 7: `VMEXIT_INTERRUPTION_INFO.valid`;
- bits 6:4: interruption type from `VMEXIT_INTERRUPTION_INFO`;
- bit 3: interruption error-code valid;
- bit 2: NMI unblocking due to IRET;
- bit 1: `IDT_VECTORING_INFO.valid` at handler entry;
- bit 0: raw `EXIT_REASON` VM-entry-failure flag.

This metadata disambiguates a valid vector 0 (`#DE`, bit 7 set) from an absent
or invalid interruption-info value. If bit 0 is set, the low basic exit reason
must not be interpreted as an ordinary Exception-or-NMI exit. `vector=0xfe`
means reading `VMEXIT_INTERRUPTION_INFO` failed while recording the slot.

The log cannot contain literally every high-rate VM-exit. It records each CPU's
newest state and reports the exact coverage gap through `overwritten`.
