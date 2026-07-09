# Hypervisor

Windows x64 Intel VT-x type-2 hypervisor（crate 名 `matrix`）。为 `game_overlay` 提供底层 driver、物理内存读、诊断通道、EPT/VM-exit 隐藏。Codex/GPT 规则同步见 `AGENTS.md`。

## 回复偏好

默认使用简体中文。结果优先、执行导向、少废话。遇到“继续”直接继续做。

## 项目关系

`D:\hello\code\hypervisor`（本项目）是 `D:\hello\code\game_overlay`（Mac 侧 `~/Desktop/go/rust-cheating`）的底层 HV/driver。分工：

- **本项目**：Windows x64 Intel VT-x type-2 hypervisor、物理内存读、诊断通道、EPT/VM-exit 隐藏、启动前自检。
- **game_overlay**：overlay 渲染、实体扫描，通过本项目暴露的 CPUID / VMCALL 通道读物理内存。

改本项目时必须同时考虑两边契约：命令号、返回值、seal 状态、client-read 变体、加载脚本变化，都可能直接影响 `game_overlay/core/src/mem.rs`。

## 开发工作流

### ⚠️ 重要：单向代码流

**所有代码修改只在 Mac 上进行，严禁在 Windows 上直接编辑源代码。**

原因：
1. Windows PowerShell 的文件操作会破坏 UTF-8 编码（中文字符变乱码）。
2. 两边同时改会产生合并冲突，且难以追踪最新版本。
3. Mac 上有完整的编辑工具链和 Claude，Windows 只是构建运行环境。
4. Mac 侧无 WDK，无法本地编译（`wdk-build` 需 Windows host），代码正确性靠人工审查 + 推送后 Windows 侧编译验证。

完整流程：

```text
步骤 1: Mac 上编辑代码（/Users/administer/Desktop/go/hypervisor/）
步骤 2: Mac 上提交并推送  →  git add / git commit / git push origin master
步骤 3: SSH 到 Windows   →  sshpass -p '0223' ssh administrator@100.116.207.106
步骤 4: Windows 拉取代码  →  cd D:\hello\code\hypervisor && git pull origin master
步骤 5: Windows 构建      →  cargo build -p matrix --release
步骤 6: Windows 收尾      →  powershell -File scripts\finalize_driver.ps1
步骤 7: 重启（干净 slot） →  shutdown /r /t 0
步骤 8: Windows 加载 HV  →  scripts\start_hv.bat
```

如果 Windows 上有未提交的改动（`git status` 显示 modified），先 `git stash` 或 `git checkout -- .` 丢弃，再 pull。不要在 Windows 上 commit。

### 仓库信息

- 远程仓库：`git@github.com:Ayuan97/hypervisor.git`
- 分支：`master`
- Mac 本地目录：`/Users/administer/Desktop/go/hypervisor/`
- Windows 本地目录：`D:\hello\code\hypervisor`

### 连接 Windows

```bash
sshpass -p '0223' ssh administrator@100.116.207.106
```

密码 `0223` 是本地环境固定；SSH 时如需交互 GUI（IDA/CE 等）改用 `mstsc` RDP。

### 构建

在 Windows 上执行（通过 SSH）：

```powershell
cd D:\hello\code\hypervisor
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
  powershell -NoProfile -File D:\hello\code\hypervisor\tools\udp_hv_monitor.ps1 -RemoteIP 100.91.62.12 -Port 9999 -IntervalMs 100

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

## 隔离测试

用 `/setup-test-env` skill 起本地无 EAC Rust 服务端 + 客户端。用途：

- **A 场景**：加载 HV + 无 EAC 客户端连本地服 → 冻死 = HV 内因，不是 EAC。
- **B 场景**：加载 HV + 无 EAC 客户端连本地服 → 不冻 = EAC 触发。

这是切分 "HV 自己有 bug" vs "EAC 触发 bugcheck" 的关键测试。执行细节和 spawn 命令看 rust-cheating 的 CLAUDE.md 或直接跑 skill。

## 可用工具

### MCP 工具（Mac + Windows 侧混合）

- **`uc-mcp`**（UC 论坛）：搜索技术论坛。常用 `search_forum`、`get_thread`、`check_login`。搜索结果 URL 缺 `/forum/` 时手动补。
- **`ida-pro-mcp`**（Windows 上跑 IDA）：静态逆向。`decompile`、`disasm`、`find_bytes`、`find_regex`、`xrefs_to`、`rename`、`set_type`、`analyze_function`。
- **`cheatengine`**（Windows 上跑 CE）：**仅无 EAC 环境**。游戏或保护模块运行时禁止附加。
- **`pyautogui`**：控制 Windows GUI 工具。优先命令行，GUI 只作最后手段。

### Skills

- `/fix-game-update`：游戏更新后恢复解密常量、偏移、RVA、实体链（`game_overlay` 侧用）。
- `/setup-test-env`：搭建本地无 EAC Rust 测试环境。

## 硬性约束

1. **改 HV 前先读当前实现和 README.md**，不按旧经验猜。memory 里的结论也可能过时（例如 2026-07-09 已推翻"IF=0 阻断 IPI"根因假设）。
2. **保持小 diff**；不要回退用户已有改动。
3. **不做降级/回退掩盖问题**，优先修根因。
4. **涉及加载、seal、VMCALL/CPUID、EPT、物理读的改动必须跑对应单测**或明确说明无法实测原因。
5. **游戏运行时禁止附加调试工具**（CE/IDA runtime attach 等）。
6. **Mac 侧无法编译 driver**（wdk-build 需 Windows host）；正确性靠人工审查 + 推送后 Windows 侧 `cargo build -p matrix --release`。
