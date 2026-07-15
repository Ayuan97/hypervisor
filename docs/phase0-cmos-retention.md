# Phase 0-2: CMOS 保留实验（2026-07-12）

## 目的

一次实验回答 3 个物理问题，为 Phase 1 数据格式设计定基础：

1. **Extended CMOS（ports 0x72/0x73）0x20-0x2C 是否跨重启保留？**
2. **BIOS 会不会在 boot 时清我们写的字节？**（warm reset vs cold boot 分别测）
3. **能不能可靠地存 32-bit session ID 和递增 boot counter？**（用 checksum + completion marker 验证）

## 背景

方法论审查（2026-07-12）发现：
- 现有 `read_cmos_freeze.rs` 工具读 CMOS 0x40-0x55，但 HV 从**不往这里写**（`freeze_write_cmos_snapshot` 是死代码）
- Memory 里"CMOS 无异常"的历史结论**可能是"BIOS 清了"或"根本没写"**，不是"实际没数据"
- 必须**实测**才能确认 CMOS 作为持久化载体的可靠性

## 实现位置

**HV 侧**：
- `hypervisor/src/intel/diag.rs`
  - `cmos_retention_experiment()` — 实验主函数
  - Const: `CMOS_RET_OFF_MAGIC` (0x20) 到 `CMOS_RET_OFF_CHECKSUM` (0x2C)
  - Static: `CMOS_RET_PREV_*`, `CMOS_RET_NEW_*`, `CMOS_RET_EXPERIMENT_RAN`
- `driver/src/lib.rs::driver_entry` — 在 `boot_stage(100)` 之前调用一次

**工具侧**：
- `tools/cpuid_ping.rs` — 输出 "=== CMOS Retention Experiment ===" 段

## CMOS 布局

| 偏移 | 字段 | 大小 | 说明 |
|---|---|---|---|
| 0x20 | magic | u8 | 固定 0xC3，表明本实验数据存在 |
| 0x21-0x22 | boot_counter | u16 LE | 每次 HV 加载递增 |
| 0x23-0x26 | last_session_id | u32 LE | 上次 HV 加载时的 this_session_id |
| 0x27-0x2A | this_session_id | u32 LE | 本次 HV 加载时的 session ID（RDTSC 低 32）|
| 0x2B | completion_marker | u8 | 0x00=写入进行中，0x01=完成 |
| 0x2C | checksum | u8 | XOR(0x20..0x2B)，`completion` 按 0x01 计算 |

## Torn-write 保护协议

```
1. 写 completion_marker = 0x00        （标记"正在写入"）
2. 写 magic, counter, sessions        （payload）
3. 计算 checksum（假设 completion=0x01）
4. 写 checksum
5. 写 completion_marker = 0x01        （标记"完成"）
```

读端判读：
- `magic != 0xC3` → 无实验数据（未初始化 / BIOS 清 / 别的东西写了）
- `completion != 0x01` → 上次写入中途死了（torn write）
- `checksum` 不匹配 → 部分损坏

## 用户测试步骤

### 步骤 0：构建（Windows-first，全部本机跑）

```powershell
cd D:\rust-cheat\hypervisor
git pull origin master
cargo build -p matrix --release
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\finalize_driver.ps1 -Source .\target\release\matrix.dll -Destination .\target\release\matrix.sys
rustc tools\cpuid_ping.rs -o tools\cpuid_ping.exe
```

### 步骤 1：干净首次加载

**目的**：确认实验函数正确执行，看第一次 boot 时 CMOS 状态。

```powershell
shutdown /r /t 0
# 等重启完成，登回来本机

cd D:\rust-cheat\hypervisor
set HV_NO_SEAL=1
scripts\start_hv.bat
tools\cpuid_ping.exe > logs\cmos-ret-step1.txt
```

**期望值**：
- `Experiment did NOT run` = 未运行（如果出现→说明代码有问题）
- `prev magic = 0xFF` 或 `0x00` = 首次运行，CMOS 无历史数据
- `new counter = 1`
- `new this_session = 某个随机数`

### 步骤 2：warm reset（RST 按钮）

**目的**：验证 CMOS 跨 warm reset 保留。

```powershell
# 主机机箱上按物理 RESET 按钮（不是 shutdown /r，不是软重启）
```

```powershell
# 重启后（本机操作）：
cd D:\rust-cheat\hypervisor
set HV_NO_SEAL=1
scripts\start_hv.bat
tools\cpuid_ping.exe > logs\cmos-ret-step2.txt
```

**期望值**（**这是核心证据**）：
- `prev magic = 0xC3` ← 数据保留了
- `prev counter = 1`
- `prev this_session = step1 的 new_this_session`
- `prev completion = 0x01`（step1 正常写完）
- `prev checksum_ok = true`
- `new counter = 2`

**若失败**：
- `prev magic = 0xFF/0x00` → 主板某种机制在 warm reset 时清 ext CMOS 0x20-0x2C
- `prev checksum_ok = false` → 数据存了但被损坏

### 步骤 3：cold boot（完全关机再开）

**目的**：验证 CMOS 电池能撑住冷启动。

```powershell
shutdown /s /t 0
# 等 10 秒完全断电，按主机开机键
```

```powershell
# 开机后（本机操作）：
cd D:\rust-cheat\hypervisor
set HV_NO_SEAL=1
scripts\start_hv.bat
tools\cpuid_ping.exe > logs\cmos-ret-step3.txt
```

**期望值**：
- `prev magic = 0xC3`
- `prev counter = 2`
- `prev this_session = step2 的 new_this_session`
- `new counter = 3`

**若失败**：
- `prev magic = 0xFF/0x00` → **BIOS 冷启清 CMOS** 或 **CMOS 电池弱**
- 这条决定 CMOS 能不能作为**跨冷启动**的持久层

### 步骤 4：freeze 后 RST

**目的**：验证 freeze 场景下 CMOS 数据能不能读回，检测 torn write 风险。

```powershell
# 触发一次实际 freeze
# 用 CLAUDE.md 里的隔离测试方法：起本地服（无 EAC）或 EAC 环境等冻死

# 冻死后按 RST
```

```powershell
# 重启后（本机操作）：
cd D:\rust-cheat\hypervisor
set HV_NO_SEAL=1
scripts\start_hv.bat
tools\cpuid_ping.exe > logs\cmos-ret-step4.txt
```

**期望值**：
- `prev magic = 0xC3`
- `prev counter = 3`
- `new counter = 4`

**关键关注**：
- `prev completion = 0x01` → 上次实验正常写完，freeze 是在写完后发生的
- `prev completion = 0x00` → 上次实验在写 CMOS 的中间就冻死了 → **race 风险**，Phase 1 必须用双缓冲或 per-CPU slot 修

## 判读矩阵

| step1 | step2 warm | step3 cold | step4 freeze | 结论 |
|---|---|---|---|---|
| ran=1, magic≠C3 | magic=C3, counter=2 | magic=C3, counter=3 | magic=C3, counter=4 | **CMOS 全场景可靠** → Phase 1 用 CMOS 做主战场 |
| ran=1, magic≠C3 | magic=C3, counter=2 | magic≠C3 | - | **只支持 warm reset** → Phase 1 用 CMOS 但不指望冷启后可读 |
| ran=1, magic≠C3 | magic≠C3 | - | - | **CMOS 不跨重启** → 弃用 CMOS，用别的持久化（UEFI NVRAM / 保留 DRAM） |
| ran=0 | - | - | - | **实验函数没运行** → 检查 driver_entry 调用路径 |
| 任何 step: completion=0x00 | - | - | - | **上次冻死时正在 CMOS 写入中间** → Phase 1 必须用 torn-write-safe 双缓冲设计 |

## 结果记录

跑完 4 步后，把 4 个 log 文件的 "=== CMOS Retention Experiment ===" 段贴回来。老子据此决定：

1. Phase 1 数据格式设计是否用 CMOS 做主持久层
2. 如果不能用，下一步走 UEFI NVRAM 还是保留 DRAM
3. 是否需要 per-CPU CMOS slot 避免 race
4. 是否需要额外的 torn-write 保护机制

## 后续实验（Phase 0 剩余）

- **实验 1**：Port 0x80 runtime 生效？（写 0x00-0xFF 到 port 0x80，看主板 Q-CODE 数码管是否响应）
- **实验 3**：保留 DRAM 页跨硬 reset 保留？（分配物理页 → 写 pattern → RST → 读回）
- **实验 4**：串口 THR 到 UART FIFO 逃逸？（需要物理串口硬件，条件成熟再做）

## 相关章节

- `CLAUDE.md` "本项目 freeze 的具体 signature"（判读参考）
- `CLAUDE.md` "观测方法论铁则"（Phase 0 定稿）
- `CLAUDE.md` "CMOS 偏移量分配表"（改前必读）
- `CLAUDE.md` "GET_CTL 字段扩展"（90-98）
