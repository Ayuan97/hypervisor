# Hypervisor

Windows x64 Intel VT-x type-2 hypervisor. 当前目标是稳定加载、降低 guest 可见 VMX 痕迹，并在启动游戏/EAC 前完成自检。

## 目录

```text
driver/          WDK driver entry，负责创建并启动 hypervisor
hypervisor/      VT-x 核心逻辑
  src/intel/
    ept/         EPT 页表与 hook 支撑
    vmexit/      CPUID、MSR、CR、RDTSC、VMCALL、EPT 等 VM-exit 处理
    vmcs.rs      VMCS guest/host/control 字段初始化
    vcpu.rs      per-CPU 虚拟化/反虚拟化
    vmlaunch.rs  VM-entry/VM-exit 汇编入口
scripts/         启动脚本
tools/           诊断与探针工具
```

## 当前通信模型

用户态诊断工具使用隐藏 CPUID leaf `0x40000000`，并要求 `r10/r11` 双 token。未授权访问必须返回全 0，普通 hypervisor leaves 也必须保持全 0。

`VMCALL` 路径只给 CPL0 使用。用户态执行 `VMCALL`，即使带 token，也应表现为 `#UD`。

| 命令 | 用途 | 用户态 |
|---|---|---|
| `0x01` PING | 存活检查 | 允许，经 CPUID 诊断 leaf |
| `0x14` GET_COUNTER | 退出计数 | 允许，经 CPUID 诊断 leaf |
| `0x15` GET_CTL | 控制位/诊断状态 | 部分允许；敏感项 CPL0 |
| `0x10` READ_PHYS | 物理读 | CPL0 only |
| `0x11` WRITE_PHYS | 物理写 | 禁用 |
| `0x12` TRANSLATE_VA | VA->PA | CPL0 only |
| `0x13` GET_GUEST_CR3 | guest CR3 | CPL0 only |
| `0x20` CLOAK_PAGE | EPT page cloak | CPL0 only |
| `0xFF` DEVIRTUALIZE | 反虚拟化 | CPL0 only |

## 构建

```powershell
cargo build -p matrix --release
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\finalize_driver.ps1
rustc tools\cpuid_ping.rs -o tools\cpuid_ping.exe
rustc tools\probe_test.rs -o tools\probe_test.exe
rustc tools\phys_test.rs -o tools\phys_test.exe
rustc tools\ping_test.rs -o tools\ping_test.exe
```

## 启动顺序

1. 重启，确保没有旧 HV 实例残留。
2. 确保 EAC/游戏未启动。
3. 运行 `scripts\start_hv.bat`。
4. 等待 `cpuid_ping.exe` 与 `probe_test.exe` 均通过。
5. 脚本默认 seal 诊断通道；seal 后用户态 PING 不再返回 magic，只允许重复 seal 和 CPL0 DEVIRTUALIZE。
6. 再启动 EAC/游戏。

如果 `start_hv.bat` 提示 HV 已 active，不要重复映射新 build；必须重启后再加载。

需要运行 `tools\phys_test.exe monitor` 时，可以先设置 `HV_NO_SEAL=1` 再启动脚本；监控结束后重启并按默认流程重新加载。

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

当前机器如果已有旧 HV 在内存中，只能验证用户态状态和热加载保护；新版 runtime 行为必须重启加载后再测。

默认启动流程 seal 后，`tools\cpuid_ping.exe` 会降级为 limited check：把 PING access denied 识别为 sealed active，继续验证 CPUID masking，但跳过 VMCS controls 和 counters。CPL0 DEVIRTUALIZE 仍保留给卸载/故障恢复。需要完整 controls/counters 输出时，用 `HV_NO_SEAL=1` 启动。
`tools\phys_test.exe monitor` 遇到 sealed 状态会直接退出并提示重新以 `HV_NO_SEAL=1` 启动。

## 隐藏与稳定性状态

| 项目 | 当前状态 |
|---|---|
| CPUID hypervisor bit | 隐藏 |
| CPUID VMX/SMX bit | 隐藏 |
| CPUID SGX/SGX_LC/WAITPKG | 隐藏 |
| CPUID hypervisor leaves | 未授权全 0 |
| IA32_FEATURE_CONTROL | 隐藏 VMX/SENTER/SGX enable 位 |
| VMX MSR range | RDMSR/WRMSR 拦截并注入 `#GP` |
| CR4.VMXE | guest read shadow 隐藏 |
| VMX 指令探针 | guest 注入 `#UD` |
| SGX ENCLS/ENCLV | 可用时退出并注入 `#UD`；无法安全隐藏 SGX host 时拒绝加载 |
| Intel PT VMX 痕迹 | 支持时启用 VMX concealment；不完整则拒绝 Intel PT host |
| RDTSC/RDTSCP | TSC offset 补偿 CPUID exit 开销 |
| XSETBV/INVD/WBINVD | 按 CPL 注入原生一致异常 |
| EPT/VPID invalidation | VMXON 后、VMXOFF 前执行 |
| 首次 VMLAUNCH 失败 | 恢复调用栈与非易失寄存器后返回错误 |
| 游戏前诊断通道 | 默认 seal；用户态 PING 不再返回 magic，拒绝 counters/controls，只允许重复 seal 与 CPL0 DEVIRTUALIZE |

## 仍需实机重启验证

- 新 build 加载后 `tools\probe_test.exe` 必须通过，尤其是用户态 token `VMCALL` 应为 `#UD`。
- `tools\cpuid_ping.exe` 必须显示 masking OK、TSC offsetting enabled。
- 启动游戏前建议运行 `tools\phys_test.exe monitor` 观察最后 VM-exit 计数。
