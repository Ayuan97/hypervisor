# Hypervisor

Windows x64 Intel VT-x type-2 hypervisor（crate 名 `matrix`）。当前目标是稳定加载、降低 guest 可见 VMX 痕迹、在启动游戏/EAC 前完成自检，并在冻结场景下留下可回读的诊断线索。

Codex/GPT 规则同步见 `AGENTS.md`；Claude 及开发工作流细节见 `CLAUDE.md`。

## 目录

```text
driver/          WDK driver entry，负责创建并启动 hypervisor（产物 matrix.sys）
hypervisor/      VT-x 核心逻辑
  src/intel/
    ept/         EPT 页表与 hook 支撑
    vmexit/      cpuid/msr/cr/rdtsc/vmcall/xsetbv/invd/ept/invept/invvpid/exception handler
    diag.rs      诊断计数、breadcrumb、per-CPU ring、watchdog、CMOS freeze snapshot、KeBugCheckEx sentinel
    vmcs.rs      VMCS guest/host/control 字段初始化
    vcpu.rs      per-CPU 虚拟化/反虚拟化
    vmlaunch.rs  VM-entry/VM-exit 汇编入口
    host_idt.rs  host IDT patch（NMI/#DF/#GP/#PF/#MC/default handler）+ first-fault breadcrumb
    client_read.rs 物理读快路径
scripts/         构建、签名、加载、监控脚本
tools/           用户态诊断与探针工具
docs/            调研报告、EAC 检测清单
```

## 通信模型

用户态诊断走隐藏 CPUID leaf `0x4000_0000`，要求 `r10/r11` 双 token。未授权访问返回全 0；普通 hypervisor leaves 也保持全 0。`VMCALL` 只给 CPL0，用户态执行即使带 token 也应表现为 `#UD`。

| CMD | 用途 | 用户态 |
|---|---|---|
| `0x01` PING | 存活检查 | 允许 |
| `0x10` READ_PHYS | 物理读 | CPL0 only |
| `0x11` WRITE_PHYS | 物理写 | **禁用** |
| `0x12` TRANSLATE_VA | VA→PA | CPL0 only |
| `0x13` GET_GUEST_CR3 | guest CR3 | CPL0 only |
| `0x14` GET_COUNTER | 退出计数 | 允许 |
| `0x15` GET_CTL | 控制位/诊断字段 | 部分允许；`arg1 ∈ {5, 7}` CPL0 only |
| `0x16` SEAL_DIAGNOSTICS | seal 诊断通道 | 允许（幂等） |
| `0x19` GET_BREADCRUMB | 每 CPU 最后一次 VM-exit 现场 | 允许 |
| `0x20` CLOAK_PAGE | EPT page cloak | CPL0 only |
| `0x25` GET_RING | 全局 VM-exit ring | 允许 |
| `0x28` GET_CPU_DIAG | 每 CPU heartbeat/phase/timer_rip | 允许 |
| `0x29` READ_CMOS_FREEZE | 读 CMOS freeze snapshot | 允许 |
| `0x2A` GET_PER_CPU_RING | 每 CPU VM-exit ring | 允许 |
| `0x2B` GET_PER_CPU_RING_IDX | 每 CPU ring 写入总数 | 允许 |
| `0x2C` GET_WATCHDOG | handler duration watchdog | 允许 |
| `0xFF` DEVIRTUALIZE | 反虚拟化卸载 | CPL0 only |

## 构建

```powershell
# driver
cargo build -p matrix --release
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\finalize_driver.ps1

# 用户态工具（按需）
rustc tools\cpuid_ping.rs      -o tools\cpuid_ping.exe
rustc tools\probe_test.rs      -o tools\probe_test.exe
rustc tools\phys_test.rs       -o tools\phys_test.exe
rustc tools\ping_test.rs       -o tools\ping_test.exe
rustc tools\hv_breadcrumb.rs   -o tools\hv_breadcrumb.exe
rustc tools\freeze_watchdog.rs -o tools\freeze_watchdog.exe
rustc tools\read_cmos_freeze.rs -o tools\read_cmos_freeze.exe
```

分阶段构建（在 boot stage N 提前停下，用于隔离启动失败点）：

```powershell
scripts\build_stage.bat 600   # 产物 target\release\matrix_stage_600.sys
```

## 启动顺序

1. 重启，确保没有旧 HV 实例残留。
2. 确保 EAC/游戏未启动。
3. 运行 `scripts\start_hv.bat`（kdmapper 映射 + 自检 + 默认 seal），或 `scripts\load.bat`（走 kernel service）。
4. 等 `cpuid_ping.exe` 与 `probe_test.exe` 均通过。
5. 默认 seal 后：用户态 PING 不再返回 magic，只允许重复 seal 和 CPL0 `DEVIRTUALIZE`。
6. 再启动 EAC/游戏。

如果 `start_hv.bat` 提示 HV 已 active，**不要**重复映射新 build，必须重启后再加载。

### 环境变量

- `HV_NO_SEAL=1`：启动前设置，跳过 seal，保留完整 diag/counters/monitor 能力（用于 `phys_test monitor`、`udp_hv_monitor` 等）。
- `HV_BOOT_STOP_STAGE=N`：**构建时**变量，driver 在 boot stage N 停下（配合 `scripts\build_stage.bat`）。
- `HV_TRANSPARENT=1`：**构建时**，CPUID 完全透传，无 masking，只用于隔离测试。
- `HV_USER_CLIENT_READS=1`：允许用户态 client-read 通道；生产环境保持 0。
- `HV_DRIVER=<path>`：覆盖 `start_hv.bat` 默认的 driver 路径。

## 自检要求

```powershell
cargo fmt --check
cargo test -p hypervisor --lib -- --nocapture
cargo check -p matrix
cargo build -p matrix --release
tools\cpuid_ping.exe
tools\probe_test.exe
tools\phys_test.exe
```

当前机器如果已有旧 HV 在内存中，只能验证用户态状态和热加载保护；新版 runtime 行为必须**重启加载后**再测。

默认启动流程 seal 后：
- `cpuid_ping.exe` 降级为 limited check：把 PING access denied 识别为 sealed active，继续验证 CPUID masking，但跳过 VMCS controls 和 counters。CPL0 `DEVIRTUALIZE` 仍保留给卸载/故障恢复。
- 需要完整 controls/counters 输出：用 `HV_NO_SEAL=1` 启动。
- `phys_test.exe monitor` 遇到 sealed 状态直接退出并提示。

## 冻结后诊断字段（2026-07-09 新增）

冻结时**别立刻硬重启**。通过 `CMD_GET_CTL`（arg1 = field ID）可读：

| ID | 字段 | 判读 |
|---|---|---|
| 30 | HOST_FAULT_TOTAL | 所有 host fault 累计 |
| 31 | HOST_FIRST_FAULT_VECTOR | 最先触发的 vector（0=无 / 2=NMI / 8=#DF / 13=#GP / 14=#PF / 18=#MC） |
| 32-35 | HOST_FIRST_FAULT_RIP/RSP/ERR/CPU | 第一 fault 现场 |
| 36-42 | 各 vector 的 RSP/ERR 补充 | 已有 GP_FAULT_RIP(7)、PF_FAULT_RIP(28)、PF_FAULT_CR2(29) |
| 43-45 | HOST_DF_COUNT/RIP/RSP | #DF（级联 fault）指标 |
| 46-47 | HOST_DEFAULT_RIP/RSP | 未知 vector 触发 default handler |
| 48-49 | PER_CPU_RING_SIZE / MAX_TRACKED_CPUS | 常量，给工具用 |
| 50-56 | KEBUGCHECKEX_ADDR/SENTINEL/HITS/CPU/RIP/TSC/ARG0 | HITS>0 = KeBugCheckEx 被调用；ARG0 = bugcheck 号 |

判读模式：

- `KEBUGCHECKEX_HITS > 0` 且 `ARG0 = 0x139` → EAC 触发了 bugcheck。
- `KEBUGCHECKEX_HITS = 0` 但冻结 → bugcheck **没跑**，根因不在 bugcheck 路径。
- `HOST_FIRST_FAULT_VECTOR = 14 / 13` → handler 里触发次生 fault；查 `HOST_FIRST_FAULT_RIP/CPU` 找肇事者。
- `HOST_FIRST_FAULT_VECTOR = 8` → 级联 #DF。
- watchdog `slow_count > 0` → 有 handler 跑了 ≥14ms（正常 <1ms），`last_slow_reason` 是嫌疑。

CMOS freeze snapshot（`CMD_READ_CMOS_FREEZE`，扩展 CMOS 0x00-0x0B + 传统 CMOS 0x40-0x55）在硬重启后仍可读，记录最后 stuck CPU + RIP + count。

## 隐藏与稳定性状态

| 项目 | 当前状态 |
|---|---|
| CPUID hypervisor bit（ECX[31]） | 隐藏 |
| CPUID VMX/SMX bit | 隐藏 |
| CPUID SGX/SGX_LC/WAITPKG | 隐藏 |
| CPUID hypervisor leaves 0x4000_00xx | 未授权全 0 |
| IA32_FEATURE_CONTROL | 隐藏 VMX/SENTER/SGX enable 位 |
| VMX 能力 MSR (0x480-0x491) | **RDMSR pass-through 到硬件**、WRMSR 注入 `#GP`（与 CPUID VMX bit=0 存在一致性冲突，见 `docs/research-report-2026-07-09.md`） |
| 合成 MSR 0x40000000+ | 注入 `#GP` |
| CR4.VMXE | guest read shadow 隐藏 + guest/host mask |
| VMX 指令探针 | 用户态注入 `#UD`；CPL0 shadow VMXE=0 时 `#UD`；shadow VMXE=1 时 VMfailInvalid |
| SGX ENCLS/ENCLV | 可用时退出并注入 `#UD`；无法安全隐藏 SGX host 时拒绝加载 |
| Intel PT VMX 痕迹 | 支持时启用 VMX concealment；不完整则拒绝 Intel PT host |
| RDTSC/RDTSCP | trap-next-RDTSC 补偿 CPUID exit 开销（TSC_OFFSET 保持 0） |
| XSETBV/INVD/WBINVD | 按 CPL 注入原生一致异常 |
| EPT/VPID invalidation | VMXON 后、VMXOFF 前执行 |
| 首次 VMLAUNCH 失败 | 恢复调用栈与非易失寄存器后返回错误 |
| host IDT patch | 全表覆盖为 default handler，vector 2/8/13/14/18 单独 patch，first-fault breadcrumb 记录第一位 fault 现场 |
| 游戏前诊断通道 | 默认 seal；用户态 PING 不返回 magic，拒绝 counters/controls，只允许重复 seal 与 CPL0 DEVIRTUALIZE |
| **LBR 一致性** | **未防**（`docs/eac-hv-research-2026-07.md` 检测清单第 12 项） |
| **APERF/MPERF 补偿** | **未防**（清单第 10 项，BattlEye 已知使用） |
| **IA32_EFER SCE 虚拟化** | **未防**（清单第 13 项，延迟检测） |
| **devirtualize 路径** | 完整 teardown（invept+invvpid+vmxoff+恢复 FS/GS/GDT/IDT/CR3）；**无 KeRegisterBugCheckCallback** |

## 仍需实机重启验证

- 新 build 加载后 `tools\probe_test.exe` 必须通过，特别是用户态 token `VMCALL` 应为 `#UD`。
- `tools\cpuid_ping.exe` 必须显示 masking OK、TSC offsetting enabled。
- 启动游戏前建议先跑 `tools\phys_test.exe monitor` 观察最后 VM-exit 计数。
- 冻结场景后，用 `HV_NO_SEAL=1` 重启加载，读上表 CTL id 30-56 判断根因。

## 文档索引

- `CLAUDE.md`：完整开发工作流（Mac↔Windows 同步、构建、加载、诊断字段判读、隔离测试）。
- `AGENTS.md`：Codex/GPT 版本的开发规则。
- `docs/eac-hv-research-2026-07.md`：EAC 已知检测清单（13 项）+ 参考项目对比。
- `docs/research-report-2026-07-09.md`：4 项调研综合报告（当前代码审计、参考项目真实兼容性、Windows bugcheck IPI 机制、UC 论坛情报），含根因假设修正和方向决策。
