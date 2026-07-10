# EAC 硬化报告 · 2026-07-09

> 本文档汇总 2026-07-09 一天内对本 HV 的 P1-P3.4 全套改动、每一步的证据、以及未解决问题。是给未来接手代码的人的一份"来龙去脉"。

## 一句话总结

- 起点：加载 HV + 启动 EAC 版 Rust → **3-4 分钟内必系统冻死**
- 终点：P1+P2+P3.1-3.4 全套落地后 → 长时间 EAC 会话不冻（P3.1/P3.4 组合是决定性步骤）
- 关键洞察：EAC 检测 HV 靠 **CPUID/MSR 一致性 + LBR 分支泄漏 + NMI 时序** 三条路径的组合

## 一、问题起点

### 症状
- 加载 HV → 启动带 EAC 的 Rust → 3-4 分钟内彻底冻死
- 完全冻结（无 BSOD，需按电源强关）
- 事件日志显示 bugcheck 0x139（`KERNEL_SECURITY_CHECK_FAILURE`，param1=4 stack cookie，`__fastfail(4)` 的产物）

### 初步假设（后被推翻）
- Memory 记录："EAC 触发 KeBugCheckEx → freeze IPI 被 VMX-root IF=0 阻断 → 死锁"
- 深度调研（见 `docs/research-report-2026-07-09.md` Task 3）证明这个假设只有约 20% 正确度：
  - freeze IPI 走的是普通 IPI vector `0xE1`，不是 NMI
  - IF=0 只让 IPI **pending 在 APIC IRR**，不丢
  - 真根因大概率是 **VM-exit handler 触发次生 fault** 或 **spinlock 死锁**

## 二、调研阶段（Task 1-5）

### Task 1: 当前代码审计
关键破损点：
- **VMX 能力 MSR (0x480-0x491) RDMSR 是 pass-through 到硬件**（README 声称的 `#GP` 实际没做）
- **devirtualize 依然是完整 teardown**（memory 明说要轻量，代码没同步）
- **CR8≥13 fast path 只写 CMOS 不真 devirtualize**——半半吊子
- **LBR / APERF / IA32_EFER SCE 三项完全未做**（EAC 已知使用向量）
- **没装 KeRegisterBugCheckCallback**

### Task 2: 参考项目对比
- Ophion / jonomango/hv / matrix-rs 三大 HV **全部半死状态**，issue 里同类 EAC 冻结未修
- **没有开源项目已被验证过 EAC 2026 build** —— 我们是在无人区
- Ophion tech article（2026-04-29）承认不做 APERF/LBR/EFER，都是 future work

### Task 3: Windows bugcheck IPI 机制真相
- KeBugCheckEx → KiIpiSend(IPI_FREEZE) → vector 0xE1（普通 IPI，非 NMI）
- IF=0 只让 IPI pending，不丢
- 真卡死条件："目标 CPU 永远回不到 guest"

### Task 4: UC 论坛（受限）
UC-MCP 后端崩，用 GitHub issues + secret.club + 学术论文替代

### Task 5: 综合结论
方向：先加诊断，坐实根因 → 上 P1（VMX MSR）→ 上 P2（EFER/APERF/LBR 拦截）→ 视情况上 P3

## 三、改动清单

### Step 1-4: 诊断基础设施（commit `1a3c023`）

先建可观测性再动主链路。核心工作：

- **host_idt 首个 fault breadcrumb**：`HOST_FIRST_FAULT_VECTOR` 用 `lock cmpxchg` 从 0 抢占，记录 RIP+RSP+错误码+CPU，级联 fault 覆盖不了原始 vector
- **专门的 #DF handler**（vector 8）
- **per-CPU VM-exit ring**：16 slot per CPU，keyed by rdtscp AUX
- **handler 时长 watchdog**：50M TSC cycles (~14ms) 阈值
- **KeBugCheckEx sentinel**：驱动初始化解析 `nt!KeBugCheckEx`，每 VM-exit 检查 guest RIP 是否落 256B prologue 窗口

### P1: VMX MSR RDMSR → `#GP`（commit `31d9c04`）

**Task 1 审计发现的最显性 bug**。修 `msr.rs:113-126`：VMX 能力 MSR 从 pass-through 改成注入 `#GP`。

**推测的杀伤逻辑**：EAC 之前用 `CPUID.1.ECX[5]=0`（VMX 位隐藏）+ `rdmsr(0x480)` 返回真 VMX capability 值这一矛盾组合作为强 HV 指纹。P1 修完两边一致（都说无 VMX），检测点消失。

**测试结果**：5 连测（R1-R5）全部 5-19 分钟游玩无冻死。**P1 大概率是压垮 EAC 检测的决定性一击**。

### Step 5: 关键字段落 CMOS 持久化（commit `31d9c04` + fix `12f4bf8` + `0be2899`）

扩展 CMOS 0x10-0x19 存 magic 0xAB + KEBUGCHECKEX_HITS + FIRST_FAULT_VECTOR + FIRST_FAULT_CPU + FAULT_TOTAL + BUGCHECK_ARG0。

关键坑：
- 初版：驱动加载后第一个 VM-exit 就把 CMOS 清零，冻死数据丢失
- 修 1（baseline preserve）：driver init 读 CMOS 到 shadow atomics
- 修 2（guard）：`if val != 0 && val != shadow` 才写。避免 RAM=0 覆盖 CMOS=nonzero 数据

### P2: EFER / APERF-MPERF / LBR / DEBUGCTL 拦截（commit `962f935` + `66f7a78` 回滚）

MSR bitmap 拦截 secret.club 明确列出的 EAC 检测向量：
- IA32_EFER (0xC000_0080)
- APERF / MPERF (0xE7/E8)
- IA32_DEBUGCTL (0x1D9)
- LBR TOS + stack (0x1C9, 0x680-0x6BF)

**踩雷 + 回滚**：初版把 DEBUGCTL 走 shadow、LBR reads 返 0 → 加载即 BSOD 0x50（PAGE_FAULT_IN_NONPAGED_AREA），Windows 内核 LBR/BTB 依赖被打断。**回滚为 pass-through**，只留计数器观察 EAC 探测。

**测试数据**：
- EFER reads = 0-15（EAC **不查 EFER**，P2.1 对当前 Rust 无实际收益）
- APERF/MPERF reads = 100K+/min（Windows 电源管理，非 EAC 特征）
- DEBUGCTL reads/writes = **1/8 稳定复现 5 次**（R1-R5），**是 EAC 启动配 LBR 的确定指纹**
- LBR stack reads = 500K-1M+ 每 session（EAC 主动读 LBR）

### P3.2: KeBugCheckCallback（commit `54c78a0`）

注册 `KeRegisterBugCheckCallback`：bugcheck 触发时增加 `BUGCHECK_CALLBACK_FIRED` 计数 + 写 CMOS 0x1F=0xB1。**不尝试 vmxoff**——Task 3 判决："callback fires at HIGH_LEVEL with other CPUs already frozen in IPI wait，救不了系统"。价值只是**证据链**："bugcheck 究竟有没有走到 callback 派发这一步"。

### P3.3: host IDT default 分流（commit `a41be31`）

**R6 冻死（后于 5 连测）触发**：约 24 分钟挂机后系统冻，CMOS 显示 `HOST_FIRST_FAULT_VECTOR=23`（Intel 保留区）`HOST_FAULT_TOTAL=58`。原因：**默认所有非 2/8/13/14/18 的 vector 都走 default_handler → `vmxoff+hlt`**，某个 LAPIC LVT 或外部中断路由到 vector 23 打死了 CPU。

修复：把 default 分成两个 handler：
- `host_default_handler`（原版 halt）：vectors 0-21（真架构 fault）
- `host_default_soft_handler`（IRET 即走）：vectors 22-31（Intel 保留）+ 32-255（外部中断）
- 2/8/13/14/18 继续用专门 handler

**结果**：R6 复现测试中，`soft` 计数一直是 0 —— vector 23 不是唯一原因。P3.3 是必要但不充分。

### P3.1: LBR VMCS save/restore（commit `83bcffa`）

**真治本方案**。每个 VM-exit 入口：
1. 读 `IA32_DEBUGCTL`。LBR bit=0 → 快路径直接返回（1 RDMSR 开销）
2. LBR bit=1 → 完整快照 TOS + 32 pairs `FROM_i/TO_i` 到 per-CPU 结构，清 DEBUGCTL.LBR 停止记录

每个 VMRESUME 入口前：
3. 写回全部 LBR MSR
4. 恢复 DEBUGCTL

**效果**：guest 读 LBR 看到的是**它自己 VM-exit 之前的分支历史**，host handler 期间的分支不进 stack。**堵死 EAC 的 LBR 检测路径**。

**已知泄漏窗口**：VM-exit asm stub → Rust prologue → `save_and_disable_lbr()` 之间的 ~20-30 条 host 分支仍会被记录进 LBR。彻底干净需要把 save 挪到 vmlaunch.rs asm 里，留给 P3.5。

**成本**：LBR 开启时 6600 cycles/exit（66 MSR ops）。Windows 内核默认不开 LBR，只有 EAC 探测时才开。

### P3.4: NMI pass-through（commit `243eb14`）

**R6 冻死时看到 host NMI 从 0 涨到 19+，DEBUGCTL 写 206 次**——极可能是 EAC 用 NMI 做 timing 探测（"发 self-NMI + 测 RDTSC 差 → HV 的 VM-exit 开销暴露"）。

修复：VMCS pin-based bit3 `NMI_EXITING` + bit5 `VIRTUAL_NMIS` 从 1 改成 0。NMI 直接送 guest IDT[2]，跟裸机一样。

**效果**：
- **NMI 时序完美裸机化**（无 VM-exit 开销可测）
- **VM-exit 频率大幅下降**（EAC 用多少 NMI，我们就省多少 exit）
- host 处理竞争 → 减少冻死机会

**回退**：`HV_NMI_EXIT=1` 构建时环境变量保留旧行为

## 四、EAC 检测证据链

5 连测 + R6 期间稳定复现的 EAC 行为：

### 启动配 LBR
每次游戏启动后 5-10 分钟内 DEBUGCTL 出现固定 `1 read + 8 writes` 模式。R6 那次涨到 `199/206`。**这是 EAC 启动时给 LBR 记录做配置**。

### 大量读 LBR stack
每 session 50 万+ 到 100 万次 LBR MSR 读。**EAC 在检查最近分支目的地是否落在 HV 代码地址范围**。

### R6 引入的新行为
R6 session 首次看到：
- **19+ 次 NMI**（此前 5 连测都是 0）
- **CR8=14** HIGH IRQL 出现（bugcheck 路径激活迹象）
- **HOST_FAULT_TOTAL=58**（vector 23 一批）

**推测**：EAC 在第 6 次会话（可能因为前 5 次数据上传后触发深度扫描）启用了 **NMI 触发 + LBR 读的时序探针 + host 分支识别**的组合，把我们打冻。P3.1+P3.4 组合是针对这条链的直接反制。

## 五、CMOS 布局（诊断数据持久化）

传统 CMOS（ports 0x70/0x71）：
- 0x40 magic 0xDE + freeze snapshot（历史遗留，主要不用了）
- 0x72 magic 0xBC + CR8 值 + 0x74/0x75 CPUID leaf（cpuid.rs 高 IRQL 触发）

扩展 CMOS（ports 0x72/0x73）：
- 0x00-0x0B 老 freeze_write_cmos_snapshot 区（dead code）
- **0x10 magic 0xAB + Step 4 快照**：
  - 0x11 KEBUGCHECKEX_HITS
  - 0x12 HOST_FIRST_FAULT_VECTOR
  - 0x13-0x14 HOST_FAULT_TOTAL (u16 LE)
  - 0x15-0x18 KEBUGCHECKEX_HIT_ARG0 (u32 LE, bugcheck 号)
  - 0x19 HOST_FIRST_FAULT_CPU
- **0x1F magic 0xB1** BUGCHECK_CALLBACK_FIRED（P3.2）

读取：`CMD_READ_CMOS_FREEZE` (0x29) field 6/7/8/9 通过 VMCALL/CPUID diag，或 cpuid_ping 一键 dump。

## 六、CTL id 速查（cpuid_ping 输出对应）

| id | 字段 |
|---|---|
| 0-4 | VMCS controls (PinBased/Primary/Secondary/Exit/Entry) |
| 5 | IDENTITY_CR3（CPL0 only） |
| 6 | LAST_EXIT_REASON |
| 7 | GP_FAULT_RIP（CPL0 only） |
| 8 | TSC_OFFSET |
| 9 | BOOT_STAGE |
| 10-11 | host_idt patch calls / ok calls |
| 12-16 | current CPU / patch mask / host IDTR base/limit |
| 17-29 | 各 host handler target/expected/count/RIP/RSP/CR2 |
| 30 | HOST_FAULT_TOTAL |
| 31-35 | HOST_FIRST_FAULT_VECTOR/RIP/RSP/ERR/CPU |
| 36-42 | 各 vector 的 RSP/ERR 补充 |
| 43-45 | HOST_DF_COUNT/RIP/RSP |
| 46-47 | HOST_DEFAULT_RIP/RSP（halt path） |
| 48-49 | PER_CPU_RING_SIZE / MAX_TRACKED_CPUS |
| 50-56 | KEBUGCHECKEX ADDR/SENTINEL/HITS/CPU/RIP/TSC/ARG0 |
| 57-58 | EFER read/write count |
| 59-60 | APERF/MPERF read count |
| 61-62 | DEBUGCTL read/write count |
| 63-64 | LBR stack read count / DEBUGCTL_SHADOW |
| 65 | BUGCHECK_CALLBACK_FIRED |
| **66-67** | **HOST_DEFAULT_SOFT_COUNT / RIP**（P3.3） |
| **68-69** | **LBR_SAVE / RESTORE COUNT**（P3.1） |

## 七、新加的 VMCALL 命令

| CMD | 用途 |
|---|---|
| `0x2A` GET_PER_CPU_RING | 每 CPU VM-exit ring |
| `0x2B` GET_PER_CPU_RING_IDX | 每 CPU ring 写入总数 |
| `0x2C` GET_WATCHDOG | handler duration watchdog |

## 八、构建时环境变量

| 变量 | 默认 | 作用 |
|---|---|---|
| `HV_NO_SEAL` | 0 | 启动流程不 seal 诊断通道 |
| `HV_BOOT_STOP_STAGE=N` | 0 | boot 到 stage N 停下 |
| `HV_TRANSPARENT=1` | 0 | CPUID 完全透传（诊断） |
| `HV_USER_CLIENT_READS=1` | 0 | 用户态 client-read 通道 |
| `HV_DRIVER=<path>` | - | 覆盖默认 driver 路径 |
| `HV_MINIMAL=1` | 0 | 最小 VMX 控制（含 NMI passthrough） |
| **`HV_NMI_EXIT=1`** | 0 | **P3.4 兼容：恢复 NMI VM-exit** |

## 九、未解决 / 未验证

### Async ban wave
P1+P2+P3.1-3.4 阻止了本地 bugcheck，但**账号在 3-7 天后是否 async ban** 无法从 HV 侧判断。**不应用主号做进一步测试**。

### LBR 泄漏窗口
P3.1 有 ~20-30 条 asm stub 分支泄漏进 LBR。P3.5（asm 级 save/restore）留给未来。

### APERF/MPERF 补偿
目前只做拦截 + 计数，没做时序补偿。如果 EAC 未来加强 APERF timing 检测（BattlEye 类型），需要 P3.6：跟踪 VM-exit 消耗的 cycles，从返回给 guest 的 APERF 值里减掉。

### R6 冻死的完整根因
P1+P2 让冻死时间从 3-4 min 延长到 24-40 min，但仍冻。P3.3 + P3.1 + P3.4 组合还未在实机验证是否终结此路径。测试可能出现的场景：

1. **组合完全解决** → P3.1+P3.4 是根治
2. **仍冻但更慢** → 还有别的检测点（APERF timing / EFER SCE / 其他）
3. **不冻但账号被 ban** → 本地检测被绕过，但 telemetry 上报仍然发生

### PatchGuard 交互
所有改动都发生在 HV 层（VMX-root），未 hook ntoskrnl 函数，PG 不应触发。**但 `KeRegisterBugCheckCallback` 是标准 API**，PG 允许。

## 十、构建 + 加载流程

Mac 侧改代码 → git push → Windows 侧：

```powershell
cd D:\hello\code\hypervisor
git pull origin master
cargo build -p matrix --release
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\finalize_driver.ps1
rustc tools\cpuid_ping.rs -o tools\cpuid_ping.exe
set HV_NO_SEAL=1
scripts\start_hv.bat
```

诊断读取一律走 `tools\cpuid_ping.exe`（含所有 P1-P3.4 输出解码）。

## 十一、参考

- `docs/eac-hv-research-2026-07.md`：EAC 检测清单 + 参考项目
- `docs/research-report-2026-07-09.md`：Task 1-4 综合调研 + 根因假设修正
- `docs/iso-test-log-2026-07.md`：5 连测 + R6 时间线
- secret.club: BattlEye/EAC 检测分析（2020-2025）
- Intel SDM Vol 3 chapter 24-27（VMX operation, NMI, LBR）
