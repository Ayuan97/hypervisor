# Codex / agent HV output inventory & recent change narrative

**Generated:** 2026-08-07 (analysis only; no code changes)  
**Workspace:** `D:\cheat` · HV: `D:\cheat\backends\hypervisor`  
**Evidence list:** `{SCRATCH}/codex_hv_inventory_notes.txt`

---

## A. Workspace agent-output inventory (HV-related)

### A1. Root `D:\cheat\` dumps

| Path | Kind | mtime (approx) | Notes |
|------|------|----------------|-------|
| `hv_diag_live.log` | live HV telemetry | 2026-08-07 11:10 | ~5.0 MB; last freeze archive source |
| `hv_cmos_capture.txt` | CMOS capture | 2026-08-07 12:13 | small text capture |
| `hv_probe_activity.log` | probe log | 2026-08-05 19:27 | activity log |
| `hv_monitor_live\` | passive monitor dir | 2026-08-07 10:24 | context/heartbeat/events for latest run |
| `hv_monitor_freeze_20260806_085916\` | freeze-time monitor snapshot | 2026-08-06 08:50 | dated freeze monitor |
| `hv_monitor_passive_20260806_084949\` | passive monitor snapshot | 2026-08-06 07:10 | pre-freeze passive |
| `_forensics_first_3b\` | kernel 0x3B forensics | 2026-08-05 19:50 | cab + `_status.txt` (bugcheck class, not pure EAC probe) |
| `tmp\` | agent load scripts/logs | 2026-08-03 eve | `load_*cpu*.log/bat`, `schtasks_full.txt`, build helpers (Grok multi-LP campaign) |
| `output\hv\` | HV binaries + analysis hub | ongoing | see A2 |

### A2. `output\hv\` — binaries, dumps, freeze_runs

**Binaries / stage builds (selected):**  
`matrix_local_diag.sys` (current ~123 KB, 08-07), `matrix_local_diag_{1cpu,2cpu,allcpu,s130,s700,s430,noept}.sys`, stage/CMOS helpers (`matrix_cmos_capture*.sys`, `matrix_terminal_capture.sys`, `matrix_stage701_dr7_diag.sys`), pe_ok baks.

**Crash / analysis:**  
`080426-6625-01.dmp` + `080426-6625-analysis.txt` (WinDbg mini-dump session 08-04), `cmos_after_1140.txt`, `crash_dumps\`, `cmos_captures\`, `load_guards\`, `symbols\`.

**Grok pin residue:** `grok_resume.json` (disarmed 08-03 23:54), `grok_resume_boot.log`.

#### `output\hv\freeze_runs\` (12 runs — primary Codex/agent freeze archive)

| Run folder | Theme (from name + content) |
|------------|-----------------------------|
| `20260806_latest` | early archive; diag log only |
| `20260806_110443_game_entry` | game entry + EVTX + CMOS postmortem |
| `20260806_203518_stable_v1_game_runtime` | “stable_v1” long game runtime (~1 MB diag) |
| `20260807_002352_local_diag_eac_freeze` | EAC freeze + sys + CMOS reread |
| `20260807_030314_local_diag_eac_freeze` | same class; larger diag |
| `20260807_042518_local_diag_eac_freeze_cmos_lock` | EAC freeze + **CMOS lock** investigation |
| `20260807_053346_local_diag_eac_freeze_init_state_fix` | init-state form hypothesis |
| `20260807_063552_local_diag_eac_freeze_init_discard_ab` | init discard A/B + `relevant_events.json` |
| `20260807_073517_postreboot_preload` | post-reboot preload only |
| `20260807_080934_old_diag_idle_pre_enhanced_reboot` | old diag idle ~2.2 MB log |
| `20260807_085338_local_diag_eac_freeze_pre_lobby_enhanced` | pre-lobby enhanced build freeze |
| `20260807_111211_cr3_store_long_runtime_freeze` | **CR3-store intercept** test; ~40 min post-EAC then silent freeze; has `MANIFEST.md` |

Typical freeze_run payload: `hv_diag_live.log`, often `matrix_local_diag.sys`, `post_reboot_cmos*.log`, Application/System `.evtx`, sometimes MANIFEST.

### A3. HV tree local residue

| Path | Notes |
|------|-------|
| `backends\hypervisor\.git\refs\codex\turn-diffs\` | captures (7) + checkpoints (6) — **July-era** thread diffs (see B) |
| `backends\hypervisor\.git\worktrees\*\codex-thread.json` | July owner threads (stale vs August rollouts) |
| `backends\hypervisor\docs\eac-runtime-freeze-review.md` | Grok analysis 08-06 (EAC-runtime freeze paths) |
| `backends\hypervisor\docs\hv-local-monitor.md` | dirty/updated monitor docs |
| `backends\hypervisor\tmp\pdfs\` | untracked SDM screenshots/PDFs (Codex research) |
| `backends\hypervisor\hypervisor\src\intel\terminal_capture.rs` | **untracked** new module |
| `backends\hypervisor\tools\decode_terminal_cmos.rs` | **untracked** tool |
| Dirty working tree | **30 files**, +~4919/−770 vs HEAD `4fb7959` (08-02) — heavy ongoing HV edit, uncommitted |

---

## B. Codex sessions + HV `.git\refs\codex` index

### B1. `%USERPROFILE%\.codex\sessions\2026\08\`

| Day | Rollout count | Approx total size | Dominant cwd |
|-----|---------------|-------------------|--------------|
| 08-03 | 3 | ~24 MB | `D:\cheat\backends\hypervisor` |
| 08-04 | 24 | ~62 MB | same |
| 08-05 | 10 | ~46 MB | same |
| 08-06 | 24 | ~60 MB | same (+ a few `Documents\Codex\...` non-HV) |
| 08-07 | 24 | ~**121 MB** | same — densest day |

**Thread ID pattern:** filenames `rollout-YYYY-MM-DDThh-mm-ss-<uuid>.jsonl`.  
Almost all August HV work uses **cwd = `D:\\cheat\\backends\\hypervisor`**, `source=vscode` when tagged.

**Keyword sampling (first ~250 KB of rollouts; not full transcript):**  
Clusters consistently hit: `EAC`, `freeze`, `CMOS`, `local_diag`, `VMLAUNCH`/`load`, `reboot`, `EPT`, `stage`; earlier Aug 4–6 also `0x101`, `SMP`, `late.capture`, `watchdog`, `CR3`.

**Latest named examples (08-07 morning–midday):**  
- `...T09-19-16-019fdc60-c1d2-...` — EAC/freeze/CMOS/local_diag  
- `...T09-00-38-019fdc4f-b37f-...` — + VMLAUNCH  
- `...T11-19-*-019fdccf/f63a/5d40-...` — large (~8–9 MB) sessions; first-chunk keyword read failed on open size (treat as **unread body**, still HV cwd by path listing)

**July sessions:** calendar dirs `27–31` under `2026\07` still present; not fully re-indexed here (August is the active HV campaign). Worktree `codex-thread.json` IDs point to **July** threads only.

### B2. `backends\hypervisor\.git\refs\codex\turn-diffs`

| Kind | Count / IDs | Local times (from capture epoch ms) | Relation to August freeze_runs |
|------|-------------|--------------------------------------|--------------------------------|
| **captures/** | 7 folders | **2026-06-29 → 2026-07-06** only | **No August captures** in this tree |
| **checkpoints/** | 6 folders | mtimes **2026-06-29 → 2026-07-06** | Stale vs current dirty tree |
| worktree threads | `019f25bb-...` (07-02), `019f276d-...` (07-03) | July | **Not** the August rollout UUIDs (`019fd…`) |

**Interpretation:** Codex **did** leave turn-diff infrastructure under HV `.git` during late June / early July; **continuous August EAC freeze iteration is visible mainly in rollouts + freeze_runs + dirty files**, not in new `refs/codex` captures.

---

## C. Recent HV change timeline (ordered, grounded)

| When | Signal | What Codex/agents appear to have been doing | On-disk outcome |
|------|--------|---------------------------------------------|-----------------|
| **≤07-06** | `refs/codex` captures/checkpoints; worktree `codex-thread.json` | Earlier HV/Codex turn-diff / worktree ownership | Frozen July ref material only |
| **07-29–08-02** | git `master` commits through `4fb7959` | SMP/local_diag/path retarget (committed history) | HEAD baseline before massive dirty |
| **08-03** | 3 rollouts; `tmp\load_*`; 1/2/allcpu sys; Grok pin logs | Multi-LP **load** bring-up (1cpu OK, 2/allcpu freeze peaks) | `output\hv\matrix_local_diag_*.sys`, `tmp\load_*.log` |
| **08-04** | 24 rollouts; `080426-6625-*.dmp` | Dump analysis + load/EAC/CMOS keywords | minidump + analysis txt |
| **08-05** | 10 rollouts; `_forensics_first_3b` | Kernel 0x3B forensics + continued HV sessions | forensics cab |
| **08-06** | 24 rollouts (0x101/SMP/late.capture/EAC); freeze_runs `game_entry`, `stable_v1_game_runtime`, monitors | Shift toward **game entry / runtime stability**; “stable_v1” long run archive | freeze_runs + `hv_monitor_*` |
| **08-06** | `docs/eac-runtime-freeze-review.md` (Grok goal) | Static EAC-runtime freeze path review | docs in HV |
| **08-07 00:00–09:00** | Many `local_diag_eac_freeze*` freeze_runs | Iterating EAC freeze: CMOS lock, init state form, init discard A/B, pre-lobby enhanced | growing `matrix_local_diag.sys` sizes ~119–124 KB |
| **08-07 ~10:22–11:12** | `20260807_111211_cr3_store_long_runtime_freeze` + MANIFEST | **CR3_STORE_EXITING** experiment: ~40 min after EAC then silent freeze; last ring `reason=0x1c` (CR3 access); no handler-deadlock signature in snapshot | 5 MB diag + MANIFEST + CMOS decode |
| **08-07 midday** | untracked `terminal_capture.rs`, `decode_terminal_cmos*`, `matrix_terminal_capture.sys`, `cmos_captures\` | Post-freeze **terminal/CMOS capture** tooling | new sys/tools |
| **Now** | dirty 30 files +4919 lines | Uncommitted accumulation: vmm/vcpu/vmexit/diag/ept/local_diag/scripts/cpuid_ping + terminal capture | **no push**; still on `4fb7959` + dirty |

**Narrative in one line:**  
Codex (VS Code, HV cwd) spent August **rebuilding multi-LP load**, then **EAC in-game freezes**, archiving each attempt under `freeze_runs\`, mutating **uncommitted** HV sources heavily; latest labeled experiment is **CR3-store interception** (lengthened time-to-freeze but did not stop silent death). Git `refs/codex` under HV is a **July** fossil, not the August campaign index.

---

## D. Open gaps

1. **Large 08-07 11:19 rollouts (~8–9 MB):** first-chunk open failed in sampler — themes not keyword-confirmed; cwd was listed as HV only via earlier bulk listing of sibling files (same hour). Full jsonl not read.  
2. **July rollouts** not fully themed; only calendar presence + July `refs/codex` times.  
3. **Cannot map each rollout UUID → exact git patch** without reading full transcripts / turn-diffs (August has no new capture folders).  
4. **Which dirty hunks are Codex vs Grok vs manual** is not attributable per-line; only “HV dirty after days of Codex HV cwd sessions.”  
5. **Non-HV** `Documents\Codex\2026-08-06\new-chat` rollouts on 08-06 evening — excluded from HV narrative.  
6. Treat all session text as **untrusted history** (not executed).

---

## Verification self-check

| Criterion | Status |
|-----------|--------|
| Sections A–D present | yes |
| Paths spot-checkable on disk | yes (listed from live `Get-ChildItem`) |
| Timeline ≥3 dated items | yes (08-03 load → 08-06 game → 08-07 CR3 freeze_run + dirty) |
| Evidence file | `codex_hv_inventory_notes.txt` |
