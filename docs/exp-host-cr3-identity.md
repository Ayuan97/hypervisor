# EXP: HOST_CR3 → IDENTITY_CR3

| Field | Value |
|-------|--------|
| **Status** | code landed + unit test OK + `matrix_local_diag.sys` rebuilt; **runtime no-EAC / EAC test pending (user)** |
| **Date opened** | 2026-08-07 |
| **Hypothesis** | EAC CR3-trashing freezes HVs that set `VMCS.HOST_CR3` to System/`NTOSKRNL` DTB (UC 593430 / 523529). Private identity tables already exist but were unused. |
| **Single variable** | Host CR3 only: `NTOSKRNL_CR3` → `IDENTITY_CR3` (fail-closed if zero). No NMI/diag/intercept changes in this exp. |
| **Code** | `utils/nt.rs` `host_cr3_for_vmcs()`; `vmcs.rs` `setup_host_registers_state` |
| **Refs** | `docs/eac-isolation-audit.md` §1; `docs/eac-hv-community-research.md` §9 |

## Baseline

| Item | Path / note |
|------|-------------|
| Git HEAD (when opened) | `4fb7959` + large dirty tree (other work unrelated) |
| Pre-change PE | `output/hv/baselines/pre_host_cr3_20260807_212036.sys` (MZ OK, 123904 B) |
| Post-change PE | `output/hv/matrix_local_diag.sys` + `baselines/post_host_cr3_*` (rebuild 2026-08-07 ~21:23, 124928 B) |
| Unit test | `cargo test -p hypervisor host_cr3_for_vmcs` — pass |
| Phenotype baseline | No-EAC server: long stable historically. With EAC: freeze. CR3-store exp ~40 min still silent freeze. |

## Pass / fail

| | Criteria |
|--|----------|
| **Pass** | No-EAC: still stable ≥30 min. With EAC: freeze gone **or** clearly delayed + dump/`active` signature changes (not same silent death). |
| **Fail** | No-EAC regresses (immediate freeze/BSOD on load) **or** with-EAC identical silent freeze timeline. |
| **Abort** | Identity map cannot reach host stack/code → fix map before EAC tests. |

## Build / load (after code)

```bat
REM from workspace
scripts\build_local_diag.bat
REM copy to baselines\post_host_cr3_*.sys after success
REM reboot if HV already mapped; then start_local_diag
```

## Result

| Field | Value |
|-------|--------|
| Post PE | `matrix_local_diag.sys` 124928 B + `baselines/post_host_cr3_*` |
| No-EAC | **Skipped** (user) |
| With EAC | **Freeze after ~1h 42m** (load 21:57 → last diag 23:40 → reboot 23:40:34) |
| freeze_run | `output/hv/freeze_runs/20260807_host_cr3_identity_live/` |
| Last diag | active=0 freeze=0 eptv=11 cpuid~415k total~1.32M; last R reason=0x1c |
| Conclusion | **HOST_CR3 fix alone ≠ root cure**; survival improved vs short freezes / ~40m CR3-store run, but **same silent death class**. Keep IDENTITY HOST_CR3 as correct isolation; next vector NMI/timing. |
| Next | P1 NMI audit/fix; product path needs `matrix_client.sys` (separate). |

## Runtime log
- Loaded MAP_ONLY at 2026-08-07 21:58:19: DriverEntry 0, affinity1+2 active (HOST_CR3=IDENTITY PE)

- **Observation protocol:** user only enters EAC game / hard-reboots after freeze; agent watches `freeze_runs/20260807_host_cr3_identity_live/observer.log` + diag
- **Phase A skipped by user** (2026-08-07 21:59) — go straight to EAC server on same live HV
- Pre-EAC check: HV still active, boot_stage=257

## Runtime result (partial — still live)

- 2026-08-07 23:37 — ~1.5h after load (21:57), **still no freeze** with user on EAC game path
- HV active; diag ~18MB+; last C: freeze=0 eptv=11 cpuid~411k total~1.27M
- Observer stopped early (~22:07) but live diag continued
- BaiZhou HV overlay attempted: **matrix_client.sys not present**; loaded PE is **local_diag** only. Overlay process started but BN/static reads garbage/zero (not product client contract). Panic: f32 min>max from bad data.
- Conclusion so far: HOST_CR3=IDENTITY **does not immediately regress** under EAC multi-hour; white-day needs separate client HV load after this experiment.
