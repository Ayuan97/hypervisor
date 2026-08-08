# Matrix HV: EAC probe → whole-system freeze review

**Scope:** `D:\cheat\backends\hypervisor` working tree (dirty vs HEAD includes local_diag, SMP settle, late-capture, launch_stage_band — noted where relevant).  
**Non-goals:** no fixes, no live map/EAC repro.  
**Evidence map:** `{SCRATCH}/hv_eac_freeze_review_notes.txt` (file inventory + Select-String hits).

---

## 1. Load-time vs EAC-runtime freeze (separate classes)

| Class | When | Typical signature | Primary code surface |
|-------|------|-------------------|----------------------|
| **A. Load-time / bring-up** | DriverEntry → multi-LP VMLAUNCH / settle / first worker | Hard hang during kdmap; CMOS peak mid-launch (700 / 770 / stage bands); little or no `HVL1 C` after START | `vmm.rs` SMP workers, `vcpu` late-capture, EPT identity, `local_diag` launch I/O quiesce |
| **B. EAC-runtime / in-game** | HV already non-root; EAC/game polls CPUID/MSR/timing/memory; whole machine freezes in seconds | `HVL1 C` was climbing then stops; post-RST Layer3/6 show many CPUs with `HANDLER_ACTIVE` or large seq gaps; or bitmap=0 if frozen outside host handler | `vmexit/*`, `diag` entry CMOS, `lbr`, `ept` + `bugcheck_hook`, `shared_data` EPT lock, optional `client_read` |

**Objective focus: class B.** Class A is adjacent (today multi-LP load is fragile) but is *not* the “EAC discovered us → instant lockup” story.

**Dirty-tree note:** Week-ago load used sequential `switch_to_processor` + early `RtlCaptureContext` (`7ed2a41`/`f2c5800`). From `81bffa3`, load uses per-CPU parked workers; dirty adds sequential spawn, settle, late-capture. **Runtime exit handlers (class B) largely share the same `handle_vmexit` path** across those eras; stealth deltas (CPUID/MSR/LBR/EPT) matter more for EAC freezes than SMP spawn order.

---

## 2. EAC-reachable paths (concrete sources)

Every VM-exit still runs this **prologue** (all CPUs):

| Step | Location | What EAC feels |
|------|----------|----------------|
| `handler_enter` → `HANDLER_ACTIVE[cpu]=1` | `diag.rs` ~537–542 | Host time before guest advances |
| LBR save (if `HV_LBR_SHADOW=1` and guest DEBUGCTL.LBR) | `lbr.rs` `save_and_disable_lbr` ~154–186; called from `vmexit/mod.rs` ~154 | Up to **32×2 RDMSR** + TOS per exit |
| `handler_entry_persist` | `diag.rs` ~1006–1014; `vmexit/mod.rs` ~167 | `LAST_EXIT_REASON`; Step4 CMOS on change; **Layer3 every 64 exits**; **Layer6 `snap_flush` every 64** (with **global `SNAP_FLUSH_LOCK`**) |
| Dispatch | `vmexit/mod.rs` fast path CPUID/RDTSC/RDTSCP ~222–313; slow match ~368+ | Per-reason handlers |

### 2.1 CPUID / HV leaves

| Item | Location |
|------|----------|
| Handler | `vmexit/cpuid.rs` `handle_cpuid` ~98–118 |
| Zero hypervisor leaves `0x40000000..=0x4FFFFFFF` without host CPUID | `cpuid_leaf_is_zeroed_without_host` ~161–166 |
| Mask leaf 1 ECX hypervisor bit | `mask_cpuid_result` ~186+ |
| Zero SGX / PT / Arch LBR capability leaves | same |
| Diag leaf only if dual-token authorized | `CPUID_COMM_LEAF` + `cpuid_comm_authorized` ~100–108 |
| Fast path | `vmexit/mod.rs` basic_reason==10 ~228–272 |

**EAC use:** scan HV vendor leaves, hypervisor present bit, SGX/PT/LBR caps.  
**Note:** comments explicitly avoid TSC spoof after CPUID because **APERF/MPERF stay native** (`cpuid.rs` ~115–117) — timing-ratio detectors still get a clean “slow CPUID vs raw APERF” signal without RDTSC exiting.

### 2.2 MSR detect surface

| Item | Location |
|------|----------|
| Handler | `vmexit/msr.rs` `handle_msr_access` / `handle_msr_access_with` ~44–133 |
| Bitmap policy (comment) | only FEATURE_CONTROL, VMX cap `0x480–0x491`, SGX keyhash, Intel PT MSRs |
| VMX cap → **#GP both R/W** for CPUID “no VMX” story | ~107–118 (cites secret.club EAC vector) |
| FEATURE_CONTROL read masks VMX/SENTER/SGX bits | ~95–105 |
| PT / SGX keyhash → #GP | ~90–93 |
| Fail-closed #GP for unexpected intercept | ~129–132 |
| Counters for EAC-style polls | `diag.rs` `EFER_*`, `APERF_READ_COUNT`, `MPERF_READ_COUNT`, `DEBUGCTL_*`, `LBR_STACK_READ_COUNT` ~50–64 |

**EAC use:** RDMSR VMX caps, FEATURE_CONTROL, LBR/DEBUGCTL, APERF/MPERF ratios.  
**Critical product choice:** production **does not** intercept APERF/MPERF/EFER as general exits (bitmap limited); those MSRs run **native** → no exit storm, but **no** opportunity to fake consistency with HV overhead. Diag counters for APERF/MPERF only increment if those MSRs *are* intercepted in a given build.

### 2.3 Timing / RDTSC / timers

| Item | Location |
|------|----------|
| RDTSC/RDTSCP handlers | `vmexit/rdtsc.rs` (offset + guest TSC_AUX) |
| Production VMCS: **RDTSC exiting off**, HLT/MWAIT/MONITOR exiting **off** | `vmcs.rs` ~639–666 unsupported bits clear HLT/MWAIT/MONITOR |
| TSC offsetting may still be on | `USE_TSC_OFFSETTING` in primary controls ~518–520 |
| Preempt timer: not armed for auto-NMI freeze detector path by default | `diag.rs` comments ~1073–1081, ~1094–1119; `cpu_record_timer_rip` always returns false |

**EAC use:** TSC vs wall / vs APERF; short loops around CPUID.  
**Freeze angle:** not “RDTSC exit storm” in default config. Risk is **host time on other exits** (LBR+CMOS) making CPUID appear slow while counters disagree.

### 2.4 EPT / promote / (dead) bugcheck cloak

| Item | Location | Live now? |
|------|----------|-----------|
| EPT violation | `vmexit/ept.rs` `handle_ept_violation` ~41+ | **Yes** |
| Promote non-X page on execute | ~71–87 + `invept_all_contexts()` | **Yes** (identity holes / non-X PDE) |
| **Serialized EPT updates** | `shared_data.rs` `with_primary_ept_mut` ~126–140, **`EPT_UPDATE_RETRIES = 100_000`** spin | **Yes** (any concurrent mutator) |
| On lock timeout | returns `None`; ept path logs and `Continue` without update | **Yes** |
| KeBugCheckEx EPT cloak + MTF recloak | `bugcheck_hook.rs` + ept.rs ~90–120 call sites | **No — permanently disabled** |

**Bugcheck hook (current tree — not a live freeze surface):**

- `bugcheck_hook::install` is an intentional **no-op** (`bugcheck_hook.rs` ~67–75): logs `install skipped (permanently disabled)` and never sets `HOOK_PAGE_PA`.
- Driver still *calls* `install` (`driver/src/lib.rs`), but that does not cloak any page.
- `matches(guest_pa)` is false while `HOOK_PAGE_PA == 0` (~81–87), so the ept.rs cloak/MTF branch **never runs**.
- Comment in-source: cloaking whole 4 KiB + MTF neighbour step-through scaled to ~1.5M spurious steps/session and was a **former** freeze suspect; re-enable only by restoring install in source (not a runtime flag).
- CTL 70–76 / CMOS `0xE1` stay at zero while disabled.

**EAC use (live):** identity EPT execute-on-non-X promote, general EPT pressure under integrity scans — **not** KeBugCheckEx cloak.  
**Freeze angle (live):** multi-CPU concurrent **promote / other EPT mutators** → long **busy-wait in VMX-root** on `ept_update_lock` → **CLOCK_WATCHDOG**. INVEPT-all amplifies TLB shootdown. **Do not attribute this contention to bugcheck cloak on current builds.**

### 2.5 Host-handler long paths (always-on tax)

| Item | Location | Cost pattern |
|------|----------|--------------|
| LBR shadow (gated) | `lbr.rs` | 65 RDMSR/WRMSR worst case when guest LBR on + `HV_LBR_SHADOW=1` |
| Layer3 flush every 64 exits | `diag.rs` `LAYER3_FLUSH_INTERVAL=64`, `layer3_flush` | Ext CMOS port I/O under `handler_entry_persist` |
| Layer6 `snap_flush` every 64 + **SNAP_FLUSH_LOCK** | `diag.rs` ~1194–1468 | One CPU holds lock; others skip/race — still CMOS I/O |
| `SNAP_MAX_CPUS=24` | `diag.rs` ~1188 | Extra LPs not in snapshot |

**EAC use:** high-rate CPUID/MSR loops on many cores **multiply** entry persist + optional LBR.

### 2.6 Idle / C-state (historical self-own)

| Item | Location |
|------|----------|
| MWAIT/HLT handlers (no host HLT anymore) | `vmexit/idle.rs` — docs say host `sti;hlt` **hung all CPUs**; now RIP advance only |
| Default VMCS disables MWAIT/HLT exiting | `vmcs.rs` |

**EAC relevance:** low if exits disabled; deep C-state **WHEA** under game+EAC was a prior class (errata RPL038/044 comments). That is **hardware PMC**, not “detected HV” per se, but co-occurs with game load.

### 2.7 client_read / product VMCALL

| Item | Location |
|------|----------|
| User physical/virtual read worker | `client_read.rs` (build `HV_USER_CLIENT_READS`) |
| Completions outside pure exit if worker | system thread + MDL probe |

**EAC relevance:** if overlay/client reads heavy during EAC scan, can contend memory/locks; **freeze** more likely from **IRQL-safe path mistakes** or guest waits than from EAC itself — still list as secondary under load.

### 2.8 local_diag disk worker (runtime adjacent)

| Item | Location |
|------|----------|
| 100 ms file write + `ZwFlushBuffersFile` | `driver/src/local_diag.rs` |

**Not in VM-exit context**, but flushes can cause **IPI/TLB** pressure while EAC is thrashing exits → can **amplify** class-B freezes in diag builds. Production sealed client may differ.

### 2.9 Self-inflicted freeze detector (disabled behavior)

| Item | Location |
|------|----------|
| Old same-RIP NMI → BSOD 0x80 | `diag.rs` `cpu_record_timer_rip` always `false` ~1083–1091 |
| Smart freeze NMI path | documented ~1094+; requires preempt timer + stuck CR8/IF criteria |

If preempt timer **not** in VMCS, detector does not run. If re-enabled wrongly under EAC idle, can look like “instant death after probe.”

---

## 3. High-risk paths: mechanism + telemetry coverage

| # | Path | Freeze mechanism (plausible) | Telemetry covers? |
|---|------|------------------------------|-------------------|
| 1 | **Multi-CPU EPT lock spin** (`with_primary_ept_mut`, 1e5 spins) under concurrent **X-promote / other live EPT mutators** (not bugcheck cloak — disabled) | All contenders spin in VMX-root → no guest progress → **0x101 CLOCK_WATCHDOG** | **Partial:** `HANDLER_ACTIVE` stays 1 mid-spin; Layer3 bitmap may show many actives if flush happened ≤63 exits earlier; EPT stage `0xEE10` only on promote path; **no dedicated “EPT lock timeout count” in CMOS** |
| 2 | **handler_entry_persist CMOS + SNAP_FLUSH_LOCK** under multi-core CPUID storm | Port I/O + lock contention lengthens **every** exit; synchronized multi-core storms → watchdog | **Yes entry-time:** Layer3 dual-buffer, Layer6 seq/reason if flush completed; **gap:** finish-only watchdog duration **not** CMOS (`watchdog_handler_finish`) |
| 3 | **LBR full stack save/restore** if `HV_LBR_SHADOW=1` and guest enables LBR (EAC does) | 64+ MSR R/W per exit × N CPUs → host time spike / apparent hang | **Partial:** `LBR_SAVE_COUNT` / `LBR_RESTORE_COUNT` RAM; Layer3 last exit reason; **not** freeze-safe unless mirrored |
| 4 | **Stealth inconsistency under load** (CPUID slow, APERF/MPERF native, no RDTSC exit) | Not always freeze — more **detect** then EAC **escalates** (aggressive threads, more exits) → secondary freeze via 1–3 | Detect itself leaves little CMOS; post-escalation same as 1–3 |
| 5 | **INVEPT-all after live EPT flag change** (`ept.rs` promote path) | Cross-CPU TLB invalidation storms during EAC | HANDLER_ACTIVE during handler; hard to distinguish from 1 |
| 6 | **Deep C-state / WHEA** (if MWAIT ever re-enabled or package C not limited) | PMC MCE, not HV handler stall | WHEA logs; HANDLER_ACTIVE often **0** |
| 7 | **Load-time SMP** (adjacent) | Sequential VMLAUNCH / settle / early capture | CMOS boot stage peak / s130 `prev_boot_stage` |
| — | ~~bugcheck_hook MTF recloak~~ | **Not live:** `install` no-op; `HOOK_PAGE_PA=0`; `matches()` false | CTL 70–76 / CMOS `0xE1` stay zero; historical only |

---

## 4. Ranked suspects (EAC-runtime priority)

1. **EPT update lock contention + INVEPT** under multi-core EAC / execute-on-non-X **promote** (and any other live EPT mutators — **not** KeBugCheckEx cloak, which is install-disabled)  
   - **Confirm:** post-RST Layer3 `HANDLER_ACTIVE` bitmap multi-bit; last exit reason EPT violation (48); local_diag last `HVL1 C` with rising `eptv`; optional stage `0xEE**` on promote; **MTF / bugcheck CTL should stay idle** on current builds  
   - **Refute:** bitmap all 0, last reasons only CPUID, no EPT counters growth before freeze  

2. **Entry-path CMOS / snap_flush tax × CPUID storm**  
   - **Confirm:** huge `EXIT_CPUID` in last flushed `HVL1 C`; Layer6 prev-boot large **seq gaps** on many CPUs (stuck mid-handler or stopped exiting); Layer3 last exit = CPUID (10)  
   - **Refute:** low CPUID counts; freezes with idle counters only  

3. **LBR shadow enabled build under EAC LBR enable**  
   - **Confirm:** build has `HV_LBR_SHADOW=1`; RAM/CTL LBR save counts high pre-freeze; guest DEBUGCTL LBR on  
   - **Refute:** shadow off / save count 0  

4. **Amplification from local_diag flushes** (diag builds only)  
   - **Confirm:** freeze correlates with `hv_diag_live` flush cadence; prod without worker does not  
   - **Refute:** sealed non-diag client still freezes  

5. **C-state / WHEA** (not “detection” but co-timed with EAC+game)  
   - **Confirm:** WHEA/MCE records; HANDLER_ACTIVE clear  
   - **Refute:** clean WHEA, multi-CPU HANDLER_ACTIVE set  

6. **Self-NMI freeze detector** (if controls re-armed)  
   - **Confirm:** Ext CMOS freeze mark `0xFD`; BSOD 0x80  
   - **Refute:** mark 0x00; no 0x80  

---

## 5. Post-hard-reset evidence checklist (class B)

Aligned with `docs/freeze-postmortem.md`:

1. **Do not** try live tools mid-freeze. RST only.  
2. **Disk:** last `D:\cheat\hv_diag_live.log` `HVL1 C` / `R` lines (cpuid/msr/eptv/eptm/freeze fields, `boot_stage`).  
3. **Reload HV_NO_SEAL local_diag or use `cpuid_ping` after map** and read:  
   - Layer 3: slot validity, **HANDLER_ACTIVE bitmap**, last exit reason  
   - Layer 6 prev-boot: per-CPU seq + reason; **max gap** = first death  
   - Step4 / bugcheck CMOS (`0xB1` / `0xE1`)  
   - Freeze detector CMOS `0x2D`/`0x2E`  
4. **s130 / boot stage** only for class A load peaks.  
5. **Judgment table** (postmortem §复位后判决): multi-active bitmap → host handler stall; HITS>0 → bugcheck path; WHEA → hardware/C-state.

---

## 6. Open questions / gaps (code alone cannot close)

1. **Exact EAC leaf/MSR schedule** on this game build (black box) — which path fires first after “detect.”  
2. Whether **production** `matrix_client` enables `HV_LBR_SHADOW`, `HV_USER_CLIENT_READS`, local_diag worker (flags change ranking).  
3. Whether freezes are **0x101** vs **true hard hang** (no dump) — changes confirmation fields.  
4. **APERF/MPERF** native vs any experimental bitmap intercept in the binary that was loaded in the field (source default vs shipped PE).  
5. Dirty **SMP worker park** + Windows scheduling under EAC IPI load: theoretical cross-talk with exit storms not fully modeled here.  
6. No single root cause claim without a freeze capture matching §5.

---

## 7. Adjacent: load-time (not primary)

- Multi-LP 0x101 during map; peaks 700/770 historically; late-capture + settle dirty mitigations.  
- Do **not** conflate with EAC post-probe freezes: different stage of life, different evidence (CMOS boot stage vs HANDLER_ACTIVE/Layer6).

---

## 8. Summary judgment

**Most credible “EAC probes → whole machine dies” code story in this tree:**  
EAC multi-core pressure hits **CPUID/MSR/EPT promote** → every exit pays **`handler_entry_persist` (CMOS)** and optionally **LBR MSR storms** → concurrent **EPT lock spins + INVEPT** (from **live** mutators, not bugcheck cloak) pin multiple LPs in VMX-root → **guest clocks stop → CLOCK_WATCHDOG / hard freeze**.  

**Detection inconsistency** (slow CPUID vs raw APERF/MPERF, HV leaves zeroed) is more likely **why EAC escalates** than the freeze primitive itself.

**Not live on current tree:** KeBugCheckEx EPT cloak/MTF (`bugcheck_hook::install` permanently skipped). Do not rank it as an active freeze path until install is restored in source.

Telemetry that already matches this story is **entry-time** Layer3/6 + `HANDLER_ACTIVE`, not finish-path watchdog duration.
