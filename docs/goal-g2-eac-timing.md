# G2 — EAC exit-path timing (CPUID / CR / CMOS tax)

| Field | Value |
|-------|--------|
| **ID** | G2 |
| **Status** | **IN PROGRESS** (2026-08-08) |
| **Trigger** | G1 round 2 FAIL: `matrix_client` + EAC silent freeze **~81 min** |
| **Prior** | HOST_CR3 identity ~102 min same class; G1 M1/M2 code shipped |

## Why G2

G1 did not clear the 3h bar. CMOS on the freeze boot:

- first host fault **#NMI** CPU **14**
- last exit **0x1c** (CR access), `active_count≈21`
- silent hang (Event 41), not clean BSOD

Freeze review (`eac-runtime-freeze-review.md`): multi-core CPUID/CR pressure × **every-exit `handler_entry_persist` CMOS** → CPUs stuck in VMX-root → guest clocks die.

## Root tax found in tree

| Bug | Detail |
|-----|--------|
| **Inverted flush cadence** | Prod `LAYER3` / Layer6 interval was **64**; `HV_LOCAL_DIAG` was **1024** |
| Seal ignored | After `diagnostics_sealed()`, periodic Layer3/6 still ran |

## G2 code changes (this pass)

1. Prod Layer3 / Layer6 interval → **8192** (local_diag **512**)
2. After seal: **no periodic** Layer3; Layer6 **rare only** (NMI/exception/…)
3. Force-flush / fatal paths unchanged (forensics still available)

## Not in this pass

- TSC spoof after CPUID (still rejected: APERF/MPERF native → worse ratio)
- Full APERF intercept redesign
- NMI inject rewrite (G1 P1 kept)

## Test plan

```text
冷启动 → start_hv_client.bat → EAC
计时; 冻了硬重启 → CMOS collector → 对比 81m
```

| Result | Condition |
|--------|-----------|
| **PASS** | ≥3h no hard freeze |
| **PARTIAL** | clearly >81–102m or table type change |
| **FAIL** | ≤~90m same silent death → next: CR3-load path / NMI edge / EPT lock |

## Artifacts

- Freeze that opened G2: `output/hv/freeze_runs/20260808_g1_round2_matrix_client_eac_freeze`
- PE after rebuild: `output/hv/matrix_client.sys`
