# Passive COM2 HV monitor

This path moves freeze evidence off the test machine before it locks up. The HV
still writes its existing per-CPU ring in the VM-exit path. A kernel worker,
outside the VM-exit handler, samples completed ring slots and sends compact
ASCII records through the UART at I/O base `0x2f8` (COM2). The receiving PC
writes incoming bytes to disk immediately.

It is low-interference, not mathematically passive: the test PC still runs one
small worker every 100 ms and performs UART output. It does not generate
diagnostic CPUID VM-exits.

## Hardware

The test PC must have a real legacy UART mapped to `0x2f8`, normally a
motherboard COM header or a VM serial-port mapping. A USB serial adapter plugged
into the test PC is not directly writable through raw port `0x2f8`.

The receiving PC may use a USB-to-serial adapter. Match the electrical standard
on both sides. Do not connect TTL UART pins directly to RS-232 voltage levels.
For DB9 RS-232 null-modem wiring, connect test TX to receiver RX and connect
ground (commonly pin 3 to pin 2, and pin 5 to pin 5).

Settings: `115200` baud, 8 data bits, no parity, 1 stop bit, no flow control.

## Build and load on the test PC

Before starting the game/EAC:

1. Reboot so no old HV instance remains.
2. Double-click `scripts\build_serial_diag.bat`.
3. Double-click `scripts\start_serial_diag.bat` as Administrator.

The build script uses the normal client-read/concealment settings, adds the
build-time flag `HV_SERIAL_DIAG=1`, and uses one release codegen unit to avoid a
known thin-LTO ICE in the currently installed nightly compiler. It creates:

```text
target\release\matrix_serial_diag.sys
```

Do not hot-load or replace the HV while the game/EAC is running.

## Receive on the second PC

Place the repository/scripts on the receiving PC and double-click:

```text
scripts\hv_serial_receiver.bat
```

If exactly one COM port exists, it is selected automatically. Otherwise the
script asks for the receiver port. It can also be specified directly:

```powershell
scripts\hv_serial_receiver.bat -PortName COM3
```

Every run clears `logs\hv_serial_live`. Output files are:

- `hv_serial_raw.log`: exact received bytes, flushed with write-through.
- `hv_serial_timestamped.log`: complete records with receiver timestamps.
- `context.json`: port, baud rate, receiver host, and start time.

Run the receiver before loading the diagnostic HV so the `HVS1 START` record is
captured.

## Record format

`HVS1 R` is a per-CPU latest-ring record:

```text
HVS1 R seq=42 cpu=7 ring_seq=9182 overwritten=31 reason=0xa rip=0xffff... qual=0x0 rax=0x...
```

`overwritten` is the number of VM-exits that occurred on that CPU between
serial snapshots and could not be transmitted individually. This is required
because a 115200-baud line carries only about 11 KB/s, far below the possible
VM-exit rate.

`HVS1 C` is emitted about once per second and contains total/CPUID/MSR/VMX/EPT
counts, host faults, MSR `#GP` injections, EFER/APERF/MPERF/DEBUGCTL/LBR probe
counters, bugcheck evidence, freeze state, and serial dropped-line count.

Important fields:

- `eptm`, `hostfault`, `gp`, `pf`, `mc`, `bughit`, `bugcb`, or `freeze` nonzero:
  abnormal and high priority.
- `vmx`, `msrgp`, `efer_r`, `aperf`, `mperf`, `dbg_r`, `dbg_w`, `lbr` changing:
  the corresponding capability/probe path was exercised; context is needed to
  decide whether it was normal OS activity or detection.
- `dropped` increasing: UART was absent, busy, or could not accept a complete
  line within the bounded wait.
- `overwritten` increasing: events occurred faster than the serial bandwidth;
  the record still contains the newest completed ring slot for that CPU.

No implementation can transmit every high-rate VM-exit over 115200 baud. This
monitor preserves the newest per-CPU state, reports the exact coverage gap, and
sends the probe/fault counters needed for freeze triage.
