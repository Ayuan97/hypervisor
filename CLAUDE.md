# Hypervisor

Windows x64 Intel VT-x type-2 hypervisor（crate 名 `matrix`）。为 `game_overlay` 提供底层 driver、物理内存读、诊断通道、EPT/VM-exit 隐藏。Codex/GPT 规则同步见 `AGENTS.md`。

## 回复偏好

默认使用简体中文。结果优先、执行导向、少废话。遇到“继续”直接继续做。

## 项目关系


- **本项目**：Windows x64 Intel VT-x type-2 hypervisor、物理内存读、诊断通道、EPT/VM-exit 隐藏、启动前自检。


## 开发工作流

在 Windows 本机直接用 Claude Code 改，全流程都在这台机器上：

```text
步骤 1: 同步         →  cd D:\rust-cheat\hypervisor ; git pull origin master
步骤 2: 编辑          →  Claude Code 的 Edit/Write 工具（UTF-8 安全）
步骤 3: 提交推送     →  git add ... ; git commit ; git push origin master
步骤 4: 构建         →  cargo build -p matrix --release
步骤 5: 收尾         →  powershell -File scripts\finalize_driver.ps1
步骤 6: 重启（干净 slot） → shutdown /r /t 0
步骤 7: 加载 HV      →  scripts\start_hv.bat        (kdmapper 映射 + 自检)
```

**约束**：别用原生 PowerShell 命令改中文源文件（会破 UTF-8）—— Claude Code Edit/Write、VSCode、git 客户端都 OK。**游戏运行中不要热加载/替换 HV**。

如果 pull 被未 commit 的改动挡住：`git stash` 或 `git checkout -- .` 丢弃再 pull。

### 仓库信息

- 远程仓库：`git@github.com:Ayuan97/hypervisor.git`
- 分支：`master`
- Mac 本地目录：`/Users/administer/Desktop/go/hypervisor/`
- Windows 本地目录：`D:\rust-cheat\hypervisor`

### 连接 Windows

```bash
ssh alex@100.117.110.38          # zsh alias: win / winssh
```

- 主机: `DESKTOP-DU71ON9`
- 用户: `alex`
- IP: `100.117.110.38`（Tailscale，已配 SSH key）

SSH 无法启动 GUI，需要 IDA/CE 交互改用 `mstsc` RDP 或本机操作。

### 构建

在 Windows 上执行（通过 SSH）：

```powershell
cd D:\rust-cheat\hypervisor
git pull origin master

# 常规发布构建
cargo build -p matrix --release

# 驱动收尾：把 matrix.dll 复制成 matrix.sys 并把 PE 里的 "matrix.dll" 字符串改成 "disk.sys" 减少特征
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\finalize_driver.ps1
```

用户态工具重建：

```powershell
rustc tools\cpuid_ping.rs      -o tools\cpuid_ping.exe
rustc tools\probe_test.rs      -o tools\probe_test.exe
rustc tools\phys_test.rs       -o tools\phys_test.exe
rustc tools\ping_test.rs       -o tools\ping_test.exe
rustc tools\hv_breadcrumb.rs   -o tools\hv_breadcrumb.exe
rustc tools\freeze_watchdog.rs -o tools\freeze_watchdog.exe
rustc tools\read_cmos_freeze.rs -o tools\read_cmos_freeze.exe
rustc tools\hv_mem_diag.rs     -o tools\hv_mem_diag.exe
```

### 加载 & 卸载 HV

**默认加载**（用 kdmapper 映射到内存，无 service 记录）：

```powershell
scripts\start_hv.bat
```

流程：预检 EAC 未跑 → kdmapper 映射 `target\release\matrix.sys` → 跑 `cpuid_ping.exe` + `probe_test.exe` 自检 → 默认 seal 诊断通道。

**service 方式加载**（有 service 记录，可 `sc stop` 卸载，适合调试）：

```powershell
scripts\load.bat     # 创建 kernel service + 启动
scripts\unload.bat   # 停止 + 删除 service
```

kdmapper 映射的实例**不能通过 unload.bat 卸载**，只能重启。

**重要提醒**：

- 如果 `start_hv.bat` 提示"HV 已 active"，不要重复映射；必须重启后再加载新 build。
- 游戏/EAC 启动前完成 HV 自检；游戏运行中禁止热加载/替换 HV。
- CPU 是 i7-13700KF（Raptor Lake），BIOS 微码 0x115 已排除硬件问题（用户无 HV 玩游戏一天一夜无事）。

### 环境变量

启动前 `set VAR=value` 或在脚本前赋值：

| 变量 | 作用 |
|---|---|
| `HV_NO_SEAL=1` | 启动流程不 seal 诊断通道；`cpuid_ping` 保留 counters/controls 输出，`phys_test monitor` 能工作 |
| `HV_BOOT_STOP_STAGE=N` | **构建时** 变量：让 driver 在 boot stage N 提前停下，便于隔离启动流程失败点。用 `scripts\build_stage.bat N` 重建，产物 `matrix_stage_N.sys` |
| `HV_USER_CLIENT_READS=1` | 允许用户态 client-read 通道（普通生产环境保持 0，即禁用） |
| `HV_DRIVER=<path>` | 覆盖 `start_hv.bat` 默认的 driver 路径 |
| `HV_TRANSPARENT=1` | **构建时**：CPUID 完全透传（诊断模式，无 masking），只用于隔离测试 |

### 日志与监控

- **COM2 串口**：driver 内 `com_logger` 输出到 0x2f8。用串口线接另一台机，或 VM 转发。
- **CMOS freeze snapshot**：freeze 时会写扩展 CMOS 0x00-0x0B 与传统 CMOS 0x40-0x55，硬重启后可读。工具：`tools\read_cmos_freeze.exe`。
- **UDP 实时监控**：`tools\udp_hv_monitor.ps1` 循环调 `cpuid_ping` 把 counters 通过 UDP 打到 Mac：

  ```powershell
  # Windows 侧发送
  powershell -NoProfile -File D:\rust-cheat\hypervisor\tools\udp_hv_monitor.ps1 -RemoteIP 100.91.62.12 -Port 9999 -IntervalMs 100

  # Mac 侧接收
  nc -u -l 9999
  ```

- **freeze watchdog**：`tools\freeze_watchdog.exe` 检测 CPUID 通道停止响应的情况。
- **breadcrumb**：`tools\hv_breadcrumb.exe` 从 `CMD_GET_BREADCRUMB` (0x19) 读每 CPU 最后一条 VM-exit 现场。

## 冻结后诊断字段

**冻结不要立刻硬重启**。老子 2026-07-09 补了一批诊断字段（见 `docs/research-report-2026-07-09.md`）。走 `CMD_GET_CTL`（VMCALL 0x15 / CPUID diag arg1=field_id）：

| ID | 字段 | 判读 |
|---|---|---|
| 30 | HOST_FAULT_TOTAL | 所有 host fault 累计次数 |
| 31 | HOST_FIRST_FAULT_VECTOR | **最先触发的 vector**：0=无，2=NMI，8=#DF，13=#GP，14=#PF，18=#MC |
| 32-35 | HOST_FIRST_FAULT_RIP/RSP/ERR/CPU | 第一 fault 现场 |
| 36-42 | 各 vector 的 RIP/RSP/ERR 补充 | 已有 GP_FAULT_RIP(id=7)、PF_FAULT_RIP(28)、PF_FAULT_CR2(29) |
| 43-45 | HOST_DF_COUNT/RIP/RSP | #DF 出现次数（>0 说明级联） |
| 46-47 | HOST_DEFAULT_RIP/RSP | 未知 vector 触发 default handler |
| 48-49 | PER_CPU_RING_SIZE / MAX_TRACKED_CPUS | 常量，给工具用 |
| 50-56 | KEBUGCHECKEX_ADDR/SENTINEL/HITS/CPU/RIP/TSC/ARG0 | HITS>0 = **确认 KeBugCheckEx 被调用**；ARG0 = bugcheck 号（0x139=KERNEL_SECURITY_CHECK_FAILURE） |

新 VMCALL 命令：

| CMD | 参数 | 返回 |
|---|---|---|
| `0x2A` GET_PER_CPU_RING | cpu, slot, field(0-3) | 该 CPU 该槽的 exit_reason/rip/qual/rax |
| `0x2B` GET_PER_CPU_RING_IDX | cpu | 该 CPU 写入总数（`(idx-1) % PER_CPU_RING_SIZE` 是最新槽） |
| `0x2C` GET_WATCHDOG | cpu, field | 0=max_delta 1=max_reason 2=slow_count 3=last_slow_reason 4=last_slow_rip 5=last_slow_delta 6=in_handler 7=last_exit |

判读思路：

- `KEBUGCHECKEX_HITS > 0` + `ARG0=0x139` → EAC 触发了 bugcheck；freeze 根因在 bugcheck 路径。
- `KEBUGCHECKEX_HITS = 0` 但 freeze → bugcheck **没跑**，问题不在 bugcheck 链。
- `HOST_FIRST_FAULT_VECTOR = 14/13` → handler 内触发次生 fault；对照 `HOST_FIRST_FAULT_RIP/CPU` 找到肇事 handler。
- `HOST_FIRST_FAULT_VECTOR = 8` → 级联 #DF；查 `HOST_DF_COUNT` 和 `PF/GP/MC` 计数看第一个 fault 是谁。
- watchdog `slow_count > 0` → 有 handler 跑得 ≥14ms，`last_slow_reason` 是嫌疑；正常 handler 应 <1ms。

## 本项目 freeze 的具体 signature（2026-07-12 用户实测确认）

**必读**：判读前先确认 freeze 特征是否匹配本项目。

用户实测本项目 freeze 都符合这些特征：
- **屏幕定格最后一帧**（GPU 还在输出，CPU 停送命令）
- **任何键盘按键无反应**（CAPS LOCK / NumLock LED 都不亮）
- **电源键短按无反应**（ACPI SCI 死）
- **SSH / 网络全断**（网络中断 handler 死）
- **无自动重启**（无 hardware watchdog 触发，无 triple fault）
- **直接卡死无渐进**（discrete event 触发，非累积）
- **持续无限**（除非按 RST 硬复位）

**判决**：**全 CPU 卡在稳定循环**，中断服务链全死。最可能是：
- CPU 卡在 VMX-root handler 死循环
- 或全 CPU IPI 死锁互等
- 或 guest kernel spinlock 死锁

**排除**：BSOD（会显示蓝屏）、Triple fault（会自动重启）、GPU driver hang（键盘会响应）、渐进型资源耗尽。

**Boot freeze 触发时机**：游戏全屏画面**马上要出的一瞬间**（Rust DXGI fullscreen 切换 + EAC 首次深度扫描同时发生）。
**Runtime freeze 触发时机**：挂机状态**无明显特征**（推测是 EAC 周期性扫描触发同一 bug）。

## 观测方法论铁则（Phase 0 定稿）

对本项目 freeze signature，观测必须遵守：

1. **数据必须"死前"就在持久层里** —— 不能靠"死时紧急写"。CPU 卡死了根本执行不了写入。**"平时高频写"** 才是唯一可靠模式。
2. **CMOS sync 时机 = handler entry**，**不是 finish** —— 本项目 freeze 里 handler 卡在中间，finish 时机永远到不了。`cmos_sync_step4_state` 走 `watchdog_handler_finish` 是错的（Phase 1 要修）。
3. **必须区分 "HV 卡了" vs "Guest 卡了"** —— 现有诊断无字段回答此问题。Phase 1 加。
4. **观测代码不能自我污染** —— HV 内诊断字段可能被 handler bug 覆盖或漏写；必须有独立 out-of-band 通道（CMOS + Port 0x80 + 串口 FIFO）交叉验证。
5. **依赖 handler 完成的诊断字段一律不可信** —— 只信 handler entry 就写完的字段。

## CMOS 偏移量分配表（**改前必读，避免占用冲突**）

| CMOS 类型 | 偏移 | 用途 | 状态 |
|---|---|---|---|
| Std CMOS (0x70/0x71) | 0x00-0x0D | RTC + BIOS 用 | ❌ 禁用 |
| Std CMOS (0x70/0x71) | 0x0E-0x3F | BIOS 校验/config | ⚠️ BIOS 可能改 |
| Std CMOS (0x70/0x71) | 0x40-0x55 | `freeze_write_cmos_snapshot` 预留 | ⚠️ **死代码 + BIOS 会清**（试过存 ring 挂了）|
| Std CMOS (0x70/0x71) | 0x72-0x75 | CR8 bugcheck marker（`vmexit/cpuid.rs`）| ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x00-0x0F | Layer 6+ rare-exit RING (2 槽 × 6 字节 + 4 字节头) | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x10-0x19 | Step 1-4 CMOS 持久化（KEBUGCHECKEX/first-fault/total） | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x1E | bugcheck entry hook marker (0xE1) | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x1F | bugcheck callback marker (0xB1) | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x20-0x2C | Phase 0-2 CMOS 保留实验（`cmos_retention_experiment`）| ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x2D-0x2F | Layer 6 snap magic + global seq (⚠️ 0x2D/2E 与 FREEZE_DETECTED/PEAK 冲突) | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x30-0x3E | Layer 3 CMOS mirror slot A (magic 0x4C) | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x40-0x4E | Layer 3 CMOS mirror slot B | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x50-0x67 | Layer 6 per-CPU last flush seq (24 CPUs) | ✅ 使用中 |
| Ext CMOS (0x72/0x73) | 0x68-0x7F | Layer 6 per-CPU last exit reason (24 CPUs) | ✅ 使用中 |

## GET_CTL 字段扩展（Phase 0，2026-07-12）

在原表（0-85）基础上新增 90-98，专用于 Phase 0 CMOS 保留实验：

| ID | 字段 | 说明 |
|---|---|---|
| 90 | CMOS_RET_PREV_MAGIC | 上次 CMOS 里的 magic byte（0xC3=有效数据）|
| 91 | CMOS_RET_PREV_COUNTER | 上次 boot counter |
| 92 | CMOS_RET_PREV_LAST_SESSION | 上次的 last_session_id |
| 93 | CMOS_RET_PREV_THIS_SESSION | 上次的 this_session_id |
| 94 | CMOS_RET_PREV_COMPLETION | 上次 completion marker (0x01=正常, 0x00=torn write) |
| 95 | CMOS_RET_PREV_CHECKSUM_OK | 上次 checksum 校验结果 (1=通过) |
| 96 | CMOS_RET_NEW_COUNTER | 本次 boot counter |
| 97 | CMOS_RET_NEW_THIS_SESSION | 本次 session id |
| 98 | CMOS_RET_EXPERIMENT_RAN | 本次是否成功运行 (1=是) |

## Phase 0 CMOS 保留实验

**目的**：验证 Ext CMOS 0x20-0x2C 跨 warm reset / cold boot / freeze-then-RST 是否保留。

**位置**：`hypervisor/src/intel/diag.rs::cmos_retention_experiment()`，从 `driver_entry` 调用一次。

**详细测试协议**：见 `docs/phase0-cmos-retention.md`（4 步测试 + 判读矩阵）。

**读回**：`tools\cpuid_ping.exe` 输出 "=== CMOS Retention Experiment ===" 段。

**判决**：
- `prev magic = 0xC3` + `prev_checksum_ok = 1` + `prev_counter` 正确递增 → **CMOS 可作 Layer 3 主战场**
- `prev magic = 0xFF/0x00` → **BIOS 清了**（下一步查扩展 CMOS 是否被清 vs 主板 CMOS 电池）
- `prev completion = 0x00` → **上次冻死时正在 CMOS 写入中间**（有 race，Phase 1 用双缓冲或 per-CPU slot 修）

## 自检命令

```powershell
cargo fmt --check
cargo test -p hypervisor --lib -- --nocapture
cargo check -p matrix
cargo build -p matrix --release
tools\cpuid_ping.exe
tools\probe_test.exe
tools\phys_test.exe
```

实机 runtime 行为以**重启后新 build 加载**为准；旧 HV 已在内存中时只能验证用户态状态和热加载保护。

默认 seal 后：
- `cpuid_ping.exe` 降级为 limited check（识别 sealed active + CPUID masking，跳过 controls/counters）
- `phys_test.exe monitor` 直接退出提示重启并 `HV_NO_SEAL=1`

## 项目结构

```text
driver/          WDK driver entry；crate 名 matrix，产物 matrix.sys
hypervisor/      VT-x 核心逻辑
  src/intel/
    ept/         EPT 页表、page cloak、MTRR、EPT violation 处理
    vmexit/      cpuid/msr/cr/rdtsc/vmcall/xsetbv/invd/ept/invept/invvpid/exception 各 handler
    diag.rs      诊断计数、seal、breadcrumb、per-CPU ring、watchdog、CMOS freeze snapshot、KeBugCheckEx sentinel
    vmcs.rs      VMCS guest/host/control 初始化
    vcpu.rs      per-CPU 虚拟化/反虚拟化
    vmlaunch.rs  VM-entry/VM-exit 汇编入口
    host_idt.rs  host IDT patch（NMI/#DF/#GP/#PF/#MC/default handlers）+ first-fault breadcrumb
    client_read.rs 物理读快路径
scripts/         构建、签名、加载、监控（.bat + .ps1）
tools/           用户态诊断/探针工具（.rs 源 + 编译产物 .exe）
docs/            eac-hv-research-2026-07.md、research-report-2026-07-09.md
```

## 核心契约

- 用户态诊断走隐藏 CPUID leaf `0x4000_0000`，要求 `r10/r11` 双 token。
- 未授权 CPUID 访问必须返回全 0；普通 hypervisor leaves 也必须保持全 0。
- `VMCALL` 路径只给 CPL0；用户态执行 `VMCALL` 即使带 token 也应表现为 `#UD`。
- 默认 seal 后，用户态 PING 不再返回 magic；只允许重复 seal 和 CPL0 `CMD_DEVIRTUALIZE` (0xFF)。
- `CMD_WRITE_PHYS` (0x11) 默认禁用；不要为了"先跑通"临时打开危险写路径。
- 物理读/翻译失败不要盲目自动重试；失败应暴露状态或禁用对应功能，避免把 guest/目标进程拖崩。

### 命令号速查

| CMD | 用途 | 用户态可用 |
|---|---|---|
| `0x01` PING | 存活检查 | 允许（CPUID diag） |
| `0x10` READ_PHYS | 物理读 | CPL0 only（client-read 变体可开） |
| `0x11` WRITE_PHYS | 物理写 | **禁用** |
| `0x12` TRANSLATE_VA | VA→PA | CPL0 only |
| `0x13` GET_GUEST_CR3 | guest CR3 | CPL0 only |
| `0x14` GET_COUNTER | 退出计数 | 允许 |
| `0x15` GET_CTL | 控制位/诊断字段 | 部分允许；`arg1 ∈ {5, 7}` CPL0 only |
| `0x16` SEAL_DIAGNOSTICS | seal 诊断 | 允许（幂等） |
| `0x19` GET_BREADCRUMB | 每 CPU 最后一次 VM-exit 现场 | 允许 |
| `0x20` CLOAK_PAGE | EPT page cloak | CPL0 only |
| `0x25` GET_RING | 全局 VM-exit ring | 允许 |
| `0x28` GET_CPU_DIAG | 每 CPU heartbeat/phase/timer_rip | 允许 |
| `0x29` READ_CMOS_FREEZE | 读 CMOS freeze snapshot | 允许 |
| `0x2A` GET_PER_CPU_RING | 每 CPU VM-exit ring | 允许（2026-07-09 新增） |
| `0x2B` GET_PER_CPU_RING_IDX | 每 CPU ring 写入总数 | 允许 |
| `0x2C` GET_WATCHDOG | handler duration watchdog | 允许 |
| `0xFF` DEVIRTUALIZE | 反虚拟化卸载 | CPL0 only |

## game_overlay 联动

- `game_overlay` 的内存读依赖本项目稳定加载和物理读路径。
- 修改命令号、返回状态、token、seal 规则、client channel、read result 缓冲区或脚本输出时，同步检查：
  - `game_overlay/core/src/mem.rs`（Mac 侧 `~/Desktop/go/rust-cheating/core/src/mem.rs`）
  - 相关 VMCALL/CPUID 调用点
- 游戏/EAC 启动前先完成 HV 自检；游戏运行后不要热加载/替换 HV。
- 如果 overlay 异常但 HV 自检失败，先修 HV 根因，不要在 overlay 侧堆 fallback 掩盖问题。

## 隔离测试（无 EAC 环境）

**切分 "HV 自己有 bug" vs "EAC 触发 bugcheck" 的关键测试。** 加载 HV 后连本地服玩，冻死 = HV 内因；不冻 = EAC 触发。

### 服务端

服务端已装在 `D:\rust-cheat\server\`。

**更新服务端**（游戏更新后需同步）：

```powershell
D:\rust-cheat\tools\steamcmd\steamcmd.exe +force_install_dir D:\rust-cheat\server +login anonymous +app_update 258550 validate +quit
```

**首次启动**（生成默认配置后关闭）：

```powershell
cd D:\rust-cheat\server
.\RustDedicated.exe -batchmode +server.port 28015 +server.level "Procedural Map" +server.seed 12345 +server.worldsize 1000 +server.maxplayers 10 +server.hostname "test" +server.identity "test"
```

等看到 `Server startup complete` 后关闭进程。

**追加禁用 EAC 的配置**：

```powershell
Add-Content -Path "server\test\cfg\serverauto.cfg" -Value "`nserver.secure `"0`"`nserver.encryption `"0`""
```

关键项：
- `server.secure "0"` + `server.encryption "0"` — 在 `serverauto.cfg` 里设置，禁用 EAC。
- `+server.worldsize 1000` — 最小地图，加载快。
- `+server.identity "test"` — 存档目录 `server/test/`。
- **注意**：`server.eac 0` 这个 convar **不存在**，别用。

**后续启动**：跟首次启动同一命令，`serverauto.cfg` 里的 EAC 关闭配置会生效。

### 客户端

无 EAC 启动 Rust 客户端（Steam 安装路径 `D:\steam\steamapps\common\Rust`）：

```powershell
cd D:\steam\steamapps\common\Rust
.\RustClient.exe -connect localhost:28015 +app.forceoffline
```

### 进服后生成测试内容

先给自己管理员权限（在**服务端控制台**执行，`<steamid64>` 换成自己的 Steam ID）：

```
ownerid <steamid64> "test" "admin"
server.writecfg
```

然后进游戏按 F1 打开**客户端控制台**执行：

```
# — 基本设置 —
god true                              # 无敌
noclip                                # 飞行模式

# — 生成 NPC（验证实体扫描 / 血量 / 位置偏移） —
spawn scientist 5                     # 科学家 x5
spawn scarecrow 3                     # 稻草人 x3
spawn bear 3
spawn boar 2

# — 给武器物品（验证 active_item / inventory 偏移） —
inventory.give rifle.ak 1
inventory.give weapon.bolt 1
inventory.give rocket.launcher 1
inventory.give ammo.rifle 100
inventory.give syringe.medical 5

# — 放置建筑（验证 ToolCupboard / 建筑实体） —
spawn cupboard.tool
spawn box.wooden.large

# — 生成 bot 玩家（验证玩家名 / 队伍 / playerModel，需要 2026-04 后的 Rust 版本） —
spawn player 5
inventory.giveall
spawn testridablehorse 1
```

### HV 侧配合流程

```powershell
# 1. 干净 slot：重启，确保没有旧 HV
shutdown /r /t 0

# 2. 用 HV_NO_SEAL 加载（不 seal 才能读诊断字段）
set HV_NO_SEAL=1
scripts\start_hv.bat

# 3. 起本地服（另一 PowerShell 窗口）
cd D:\rust-cheat\server
.\RustDedicated.exe -batchmode +server.port 28015 +server.level "Procedural Map" +server.seed 12345 +server.worldsize 1000 +server.maxplayers 10 +server.hostname "test" +server.identity "test"

# 4. 起 UDP monitor 观察冻结前状态（可选，另一 PowerShell 窗口）
powershell -NoProfile -File tools\udp_hv_monitor.ps1 -RemoteIP 100.91.62.12 -Port 9999 -IntervalMs 100

# 5. 起客户端（第三个 PowerShell 窗口）
cd D:\steam\steamapps\common\Rust
.\RustClient.exe -connect localhost:28015 +app.forceoffline

# 6. 进游戏、生成 NPC/物品、玩 10-15 分钟观察是否冻结
```

### 判读

| 结果 | 结论 | 下一步 |
|---|---|---|
| A 场景（无 EAC 冻死） | HV 内因，跟 EAC 无关 | 读 `HOST_FIRST_FAULT_VECTOR` (id 31) 定位 handler bug，修根因 |
| B 场景（无 EAC 不冻，有 EAC 冻） | 确认 EAC 触发 | 上隐身路线，堵 LBR / APERF / EFER / VMX MSR 一致性 |

### 硬约束

- CE / IDA 运行时附加**只能在这套无 EAC 环境用**；线上服务器绝对禁止。
- 服务端首次生成配置文件时的启动会盖掉手改的 `serverauto.cfg`，所以必须先启动一次让它生成默认，再追加 EAC 关闭配置。

## 可用工具

### MCP 工具（Mac + Windows 侧混合）

- **`uc-mcp`**（UC 论坛）：搜索技术论坛。常用 `search_forum`、`get_thread`、`check_login`。搜索结果 URL 缺 `/forum/` 时手动补。
- **`ida-pro-mcp`**（Windows 上跑 IDA）：静态逆向。`decompile`、`disasm`、`find_bytes`、`find_regex`、`xrefs_to`、`rename`、`set_type`、`analyze_function`。
- **`cheatengine`**（Windows 上跑 CE）：**仅无 EAC 环境**。游戏或保护模块运行时禁止附加。
- **`pyautogui`**：控制 Windows GUI 工具。优先命令行，GUI 只作最后手段。

## 硬性约束

1. **改 HV 前先读当前实现和 README.md**，不按旧经验猜。memory 里的结论也可能过时（例如 2026-07-09 已推翻"IF=0 阻断 IPI"根因假设）。
2. **保持小 diff**；不要回退用户已有改动。
3. **不做降级/回退掩盖问题**，优先修根因。
4. **涉及加载、seal、VMCALL/CPUID、EPT、物理读的改动必须跑对应单测**或明确说明无法实测原因。
5. **游戏运行时禁止附加调试工具**（CE/IDA runtime attach 等）。
6. **Mac 侧无法编译 driver**（wdk-build 需 Windows host）；正确性靠人工审查 + 推送后 Windows 侧 `cargo build -p matrix --release`。
