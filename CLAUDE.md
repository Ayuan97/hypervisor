# Hypervisor Claude Notes

本文件保留给 Claude 使用；Codex/GPT 规则同步见 `AGENTS.md`。

## 回复偏好

默认使用简体中文。结果优先、执行导向、少废话。遇到“继续”直接继续做。

## 项目关系

`D:\hello\code\hypervisor` 是 `D:\hello\code\game_overlay` 的底层 HV/driver 项目。`game_overlay` 负责 overlay、实体扫描和渲染；本项目负责 Windows x64 Intel VT-x type-2 hypervisor、物理内存读、诊断通道、EPT/VM-exit 隐藏与启动前自检。

开发时同时考虑两边契约：HV 的命令号、返回值、seal 状态、client-read 变体和加载脚本变化，可能直接影响 `game_overlay` 的内存接口。

## 项目结构

```text
driver/          WDK driver entry，创建并启动 hypervisor，crate 名称 matrix
hypervisor/      VT-x 核心逻辑
  src/intel/
    ept/         EPT 页表、page cloak、EPT violation 处理支撑
    vmexit/      CPUID、MSR、CR、RDTSC、VMCALL、EPT、XSETBV 等 VM-exit
    diag.rs      诊断计数、seal 状态、breadcrumb/monitor 支撑
    vmcs.rs      VMCS guest/host/control 初始化
    vcpu.rs      per-CPU 虚拟化/反虚拟化
    vmlaunch.rs  VM-entry/VM-exit 汇编入口
scripts/         构建、签名、加载、监控脚本
tools/           用户态诊断与探针工具
artifacts/       构建/运行产物
logs/            运行日志
```

## 构建与启动

- 常规构建：`cargo build -p matrix --release`
- 驱动收尾：`powershell -NoProfile -ExecutionPolicy Bypass -File scripts\finalize_driver.ps1`
- 默认启动：`scripts\start_hv.bat`
- client-read 变体：先检查 `scripts\build_client.bat`、`scripts\start_hv_client.bat` 与当前实现是否匹配
- 如果提示 HV 已 active，不要重复映射新 build；重启后再加载
- 需要完整诊断/monitor：启动前设置 `HV_NO_SEAL=1`；默认流程会 seal 诊断通道

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

实机 runtime 行为以重启后新 build 加载为准；旧 HV 已在内存中时，只能验证用户态状态和热加载保护。

## 核心契约

- 用户态诊断走隐藏 CPUID leaf `0x40000000`，要求 `r10/r11` 双 token。
- 未授权 CPUID 访问必须返回全 0；普通 hypervisor leaves 也必须保持全 0。
- `VMCALL` 路径只给 CPL0；用户态执行 `VMCALL` 即使带 token 也应表现为 `#UD`。
- 默认 seal 后，用户态 PING 不再返回 magic；只允许重复 seal 和 CPL0 DEVIRTUALIZE。
- `WRITE_PHYS` 默认禁用；不要为了“先跑通”临时打开危险写路径。
- 物理读/翻译失败不要盲目自动重试；失败应暴露状态或禁用对应功能，避免把 guest/目标进程拖崩。

## game_overlay 联动

- `game_overlay` 的内存读取依赖本项目稳定加载和物理读路径。
- 修改命令号、返回状态、token、seal 规则、client channel、read result 缓冲区或脚本输出时，同步检查 `D:\hello\code\game_overlay` 的 `core/src/mem.rs` 及相关调用。
- 游戏/EAC 启动前先完成 HV 自检；游戏运行后不要再热加载/替换 HV。
- 如果 overlay 异常但 HV 自检失败，先修 HV 根因，不要在 overlay 侧堆 fallback 掩盖问题。

## 可用 MCP 工具

### UC 论坛 (`uc-mcp`)
必须迁入并优先可用。用于搜索/读取技术论坛信息。常用：`search_forum`、`get_thread`、`check_login`。搜索结果 URL 如缺少 `/forum/` 路径段，读取帖子时手动补上。

### IDA Pro (`ida-pro-mcp`)
用于静态逆向和二进制确认。常用：`decompile`、`disasm`、`find_bytes`、`find_regex`、`xrefs_to`、`rename`、`set_type`、`analyze_function`。

### CheatEngine (`cheatengine`)
仅用于无保护/离线分析。游戏或保护模块运行时不要附加 CE/ReClass 等调试工具。

### PyAutoGUI (`pyautogui`)
用于必要时控制本机 GUI 工具，例如 IDA/CE 辅助操作。优先使用可复现命令行；GUI 操作只在确实需要时使用。

## Skills

- `/fix-game-update`：游戏更新后恢复解密常量、偏移、RVA、实体链。
- `/setup-test-env`：搭建本地无 EAC Rust 测试环境。

## 硬性约束

1. 改 HV 行为前先读当前实现与 `README.md`，不按旧经验猜。
2. 保持小 diff；不要回退用户已有改动。
3. 不做降级/回退路径掩盖问题，优先修根因。
4. 涉及加载、seal、VMCALL/CPUID、EPT、物理读的改动必须跑对应单测或说明无法实测原因。
