# G1 — EAC client 稳定 + 白昼可用

| Field | Value |
|-------|--------|
| **ID** | G1 |
| **Status** | **M1/M2 shipped; M5 FAIL** (2026-08-08 r2 ~81m EAC freeze) → **G2** |
| **Owner** | agent + user (user: 进 EAC / 冻后硬重启；agent: 改/编/归档/观察) |
| **Basis** | UC 调研 `eac-hv-community-research.md` §9.6；隔离审计 `eac-isolation-audit.md`；HOST_CR3 实验 `exp-host-cr3-identity.md` |

## 一句话

在 **EAC 正式路径** 上，用 **产品 HV（`matrix_client.sys`）** 跑 **白昼**，连续 **≥3 小时** 无整机冻结；失败时必须留下可对比的证据包。

**本回合（Grok `/goal` ship bar）不验收 EAC 时长**——只交付带 HOST_CR3=IDENTITY + NMI P1 的 client PE 与加载说明。

## 已完成（M1 / M2）

| 项 | 证据 |
|----|------|
| **M1 NMI P1** | `host_idt.rs`: blocked pending → 临时 arm NMI-window；inject 时 disarm；`vmexit/mod.rs` 显式 `NmiWindow` → Continue（不进 #UD）；单测 `with_nmi_window_exiting` |
| **HOST_CR3** | `vmcs.rs` `setup_host_registers_state` → `host_cr3_for_vmcs()` / `IDENTITY_CR3`（fail-closed） |
| **M2 client PE** | `build_client.bat` → `output\hv\matrix_client.sys`（MZ，105472 B）；baseline `output\hv\baselines\matrix_client_g1_nmi_*.sys` |
| **Load script** | `backends\hypervisor\scripts\start_hv_client.bat` → `matrix_client.sys`（target，fallback `output\hv`） |

## 下一步（人工 — 本 goal 不自动 map）

```text
1) 冷启动（保证未 map 任何 HV）
2) 管理员运行: D:\cheat\backends\hypervisor\scripts\start_hv_client.bat
3) 启动白昼 → 进 EAC 正式服
4) 冻了硬重启；归档 freeze_runs（agent 观察/写 MANIFEST）
```

**不要**叠 map；**不要**用 `local_diag` / terminal 代替 client。

## 为什么是这个 goal

1. UC P0：`HOST_CR3` 隔离 — **已落地**，EAC 下约 **1h42m** 仍 silent freeze → 必要但不足。  
2. UC P0：NMI 路径正确 — **M1 已合**（pending + blocked 时 **临时** arm NMI-window；禁止常驻 NmiWindowExiting）。  
3. 产品路径：白昼依赖 **client-read**，不能再用 `local_diag` 冒充。  
4. 暂停 terminal-capture / CR3-store 主战役。

## 范围内（In scope）

| # | 项 |
|---|-----|
| 1 | 保持 `HOST_CR3 = IDENTITY_CR3`（fail-closed） |
| 2 | NMI P1：blocked → 动态 NMI-window；`NmiWindow` 出口不进 #UD |
| 3 | 构建并部署 `matrix_client.sys` → `output\hv\` + baseline |
| 4 | 冷启动一次 map（`start_hv_client`）；白昼进 EAC（**人工**） |
| 5 | 存活计时；冻后归档 `freeze_runs/<stamp>_g1_client_*/`（**人工+agent**） |

## 范围外（Out of scope）

- terminal-capture 作为主验收
- 无 EAC 30min smoke 作为门禁
- 主动大改 CPUID/MSR 时序（→ **G2**）
- 用 EAC 游玩时长宣称本 ship goal complete

## 运行时验收（M3–M5，非本 ship 门禁）

| 结果 | 条件 |
|------|------|
| **PASS** | `matrix_client` + 白昼 EAC **≥3h** 无 hard freeze；内存读/overlay 正常 |
| **PARTIAL** | 存活 **明显长于 1h42m** 或死亡表型变化 |
| **FAIL** | ≤1h42m 同 silent death → 开 **G2 CPUID/MSR 时序** |
| **ABORT** | 加载即死 / 白昼根本读不到 |

## 里程碑

| ID | 内容 | 状态 |
|----|------|------|
| M1 | NMI-window 动态 arm + handler + 单测 | **done** |
| M2 | `build_client` → `output\hv\matrix_client.sys` + baseline | **done** |
| M3 | 冷启动 map client；`--status` active | **done** (2026-08-08 r2) |
| M4 | 白昼 EAC 计时跑；观察 | **done** (EAC path; freeze archived) |
| M5 | PASS / PARTIAL / FAIL 落盘；必要时开 G2 | **FAIL** ~81m silent → **G2** `docs/goal-g2-eac-timing.md` |

## 关联路径

| 用途 | 路径 |
|------|------|
| Client 构建 | `backends\hypervisor\scripts\build_client.bat` |
| Client 加载 | `backends\hypervisor\scripts\start_hv_client.bat` |
| 部署副本 | `output\hv\matrix_client.sys` |
| Baseline | `output\hv\baselines\matrix_client_g1_nmi_*.sys` |
| HOST_CR3 实验 | `docs\exp-host-cr3-identity.md` |
| UC 对齐 | `docs\eac-hv-community-research.md` §9.6 |
