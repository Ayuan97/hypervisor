# HV isolation audit vs UC EAC freeze vectors

**Date:** 2026-08-07  
**Tree:** `D:\cheat\backends\hypervisor` (dirty working tree)  
**Goal:** Check whether matrix falls into UC-described **naive HV** traps that EAC uses to freeze/BSOD after load (esp. CR3 trashing, NMI, CR0/CR4).

**Community anchors:** UC 495591 / 523529 / 577702 / 593430 (see `eac-hv-community-research.md` §9).

---

## Executive verdict

| Vector (UC) | This tree | Risk |
|-------------|-----------|------|
| **HOST_CR3 shared with guest System DTB** (CR3 trash → freeze) | **FAIL** — `HOST_CR3 = NTOSKRNL_CR3`; private `IDENTITY_CR3` is **built but not installed as host CR3** | **P0 — primary suspect for EAC freeze** |
| **Host IDT / NMI not guest’s** | **PARTIAL PASS** — private host IDT + custom NMI stub; inject deferred via `check_pending_nmi` | **P1** — better than Bluepill-style window; edge cases remain |
| **CR0/CR4 guest writes need proper emulate** | **PARTIAL** — CR access handler sanitizes CR0/CR4 writes when they exit | **P1** — depends on which CR exits are armed |
| **CR3 load/store** | **STORE only** (MOV-from-CR3); **MOV-to-CR3 does not exit** | By design; does **not** stop trashing; only HOST_CR3 isolation does |
| **EPT hooks / bugcheck cloak** | Cloak **disabled** | Not live freeze path |
| Empty pin-based / no preemption timer | **PASS** for that class of 0x101 | — |

**Bottom line:** The code **has** a private identity host page-table (`PageTables` + `IDENTITY_CR3`), but **VMCS host state still points at the System process CR3 snapshot**. That matches UC’s definition of a naïve HV that **CR3 trashing is designed to kill**. This is the highest-priority fix to validate against EAC freezes—not more CR3-store experiments alone.

---

## 1. HOST_CR3 / page tables (P0)

### What the code does

```259:259:backends/hypervisor/hypervisor/src/intel/vmcs.rs
        vmwrite_checked(vmcs::host::CR3, unsafe { crate::utils::nt::NTOSKRNL_CR3 })?;
```

```92:106:backends/hypervisor/hypervisor/src/utils/nt.rs
// update_ntoskrnl_cr3():
// NTOSKRNL_CR3 = cr3() at DriverEntry (system process context)
```

```335:383:backends/hypervisor/hypervisor/src/intel/vmm.rs
// build():
// identity_paging.init_hypervisor_paging(system_cr3);
// identity_paging.build_identity();
// IDENTITY_CR3.store(identity_cr3, ...);
// // but setup_host_registers_state never uses identity_cr3
```

`init_hypervisor_paging` copies **high half** of System PML4 and builds a **private identity low half** — suitable as a host CR3. **It is never written to `vmcs::host::CR3`.**

`IDENTITY_CR3` is only exposed via diag CTL (`diag.rs` ~3284), not used for VM-exit host translation.

### Why UC says this freezes under EAC

CR3 trashing (593430):

1. Copy current System PML4 → new allocation  
2. Point System `DirectoryTableBase` at the copy; IPI cores onto it  
3. **Overwrite the old PML4 page(s)**  
4. Force VMEXIT (e.g. CPUID)  

If `HOST_CR3` is the **physical address of those old System tables**, host code after exit cannot translate → **silent freeze / fault**.  

`NTOSKRNL_CR3` is exactly “System DTB at init time” (or whatever CR3 was at `update_ntoskrnl_cr3`). That physical page is **guest-controlled memory** from EAC’s perspective—not a HV-private allocation.

### What would be correct (community + architecture)

| Requirement | Status |
|-------------|--------|
| Host uses **HV-owned** page tables for all VMX-root execution | **No** — uses System CR3 |
| Tables not reachable as “System DTB” for trash-then-exit | **No** |
| Private identity map exists | **Yes** — unused for HOST_CR3 |

**Recommended fix direction (analysis only; not implemented here):**  
`vmwrite(host::CR3, IDENTITY_CR3)` (or per-CPU host tables), ensure host stacks/code/data reachable under that map, never use live guest/System CR3 as HOST_CR3. Re-test EAC after that **single** change.

### CR3 exit policy (related but secondary)

```525:532:backends/hypervisor/hypervisor/src/intel/vmcs.rs
// CR3_STORE_EXITING only — comment: EAC freezes if both CR3 exits disabled
// CR3_LOAD_EXITING deliberately off
```

`handle_cr_access` only fully handles **MOV from CR3** (store to GPR). **MOV to CR3 does not exit**, so HV does **not** “see” trashing CR3 switches—by design. Intercepting CR3-store only **cannot** fix trashing; **HOST_CR3 isolation can**.

---

## 2. NMI path (P1)

### What the code does

| Piece | Location | Behavior |
|-------|----------|----------|
| Pin-based controls | `requested_pinbased_controls() → 0` | **No** NMI_EXITING / virtual NMIs / preemption timer forced from request surface |
| Host NMI vector | `host_idt.rs` `patch_host_idt` → custom asm | Sets **per-CPU pending flag**, IRET (does not run Windows NMI in root) |
| Guest delivery | `check_pending_nmi()` end of every exit | Injects NMI if flag set and interruptibility allows; else keeps pending |

This is **closer** to bombobombone’s fix (inject NMI, avoid broken NmiWindowExiting window) than to Bluepill’s failed window path. Good.

### Residual risk

- If guest stays **NMI-blocked** for long stretches, pending NMI defers; EAC “5–10 min NMI attack” may still stress this.  
- Host NMI on VMX-root does **not** use guest IDT (good).  
- `check_pending_nmi` returns early if another event already queued in entry interruption info.

**Not P0 vs CR3**, but worth a dedicated EAC timing test after HOST_CR3 fix.

---

## 3. Host IDT / GDT (P1 partial pass)

| Piece | Status |
|-------|--------|
| Host IDT | **Private** buffer; all vectors patched to HV handlers (default halt / NMI / #DF / #PF / #MC) — avoids Windows handlers in root |
| Host GDT | Copied into host descriptor tables; GDTR points at HV-owned storage |
| Guest GDT/IDT | Captured from live tables at launch |

Aligned with UC “don’t run guest IDT in root.” Stronger than shared IDT.

---

## 4. CR0 / CR4 (P1)

`handle_cr_access` sanitizes **CR0/CR4 writes** against FIXED0/FIXED1 and updates read shadows (matches alackbar7 “emulate CR0 bit games or inject”).  

Need pin/primary control surface to actually **exit** on those CR writes (mask/shadow configuration elsewhere in `setup_vmcs_control_fields`). If guest CR0/CR4 writes are **not** exiting, sanitizer never runs—worth verifying control fields in a follow-up, but secondary to HOST_CR3.

---

## 5. Mapping to your freezes

| Observation | Fit with HOST_CR3 FAIL |
|-------------|-------------------------|
| No EAC → long stable | EAC not trashing / not running HV attack chain |
| EAC → freeze after init or in game | Classic window for CR3 trash + forced exit |
| Silent freeze, no neat HV fault log | Trash then exit can hard-fault host **before** diagnostic paths complete |
| `active=0` on last disk sample | Consistent with death **as host starts** or outside long handler (not multi-handler spin) |
| CR3-store intercept “helps a bit” | Adds noise/exits; **does not** protect HOST_CR3 from trash |

Does **not** prove CR3 trash is the only mechanism (CPUID timing, intentional freeze, NMI remain). It **does** show a **confirmed architectural hole** that UC treats as a known EAC freeze class.

---

## 6. Recommended investigation order (actionable)

1. **P0 — Wire `HOST_CR3` to private identity (or dedicated host) tables**  
   - Single-variable experiment  
   - Pass: no EAC still stable; with EAC, freeze delayed/gone  
2. **P0 verify** — After exit, dump host CR3 PA and confirm it is **not** System `DirectoryTableBase` and not guest process CR3  
3. **P1** — NMI path under EAC (pending vs inject); serial log if disk dies mid-freeze  
4. **P1** — Confirm CR0/CR4 exit masks match sanitize handlers  
5. **P2** — CPUID/MSR timing (community + your high CPUID counts)  
6. **Do not** prioritize more CR3-store-only or random intercepts before P0

---

## 7. Code citations (quick)

| Item | File:line |
|------|-----------|
| HOST_CR3 ← NTOSKRNL_CR3 | `vmcs.rs:259` |
| NTOSKRNL_CR3 ← `cr3()` at init | `nt.rs:92–106` |
| Identity tables built | `vmm.rs:343–383`, `paging.rs:59–121` |
| IDENTITY_CR3 only diag | `diag.rs` CTL ~3284 |
| CR3_STORE only | `vmcs.rs:525–532` |
| NMI pending + inject | `host_idt.rs:744–782` |
| Host IDT patch all vectors | `host_idt.rs:796+` |
| CR0/CR4 sanitize | `vmexit/cr.rs:34+` |

---

## 8. Open questions

- Does runtime ever rewrite `host::CR3` after setup? (grep: only setup path found.)  
- Is `NTOSKRNL_CR3` refreshed if System DTB changes? (static once → stale **or** still the trash target if EAC hits that PA.)  
- Identity map: host stack / pool / driver image all covered under identity + high-half copy? Must be validated when switching HOST_CR3.

---

## 9. One-line answer

**Yes: this HV still looks “naive” on the UC CR3-trashing axis—private host page tables exist but HOST_CR3 still uses System `NTOSKRNL_CR3`. That is the #1 code-level finding for EAC freezes; next step is wire HOST_CR3 to IDENTITY and re-test EAC, not more experiment intercepts.**
