# Hypervisor

Type-2 Windows 内核 hypervisor (Intel VT-x)，为 game_overlay 提供 EPT 级物理内存访问，替代 BYOVD 驱动方案。

## 架构

```
game_overlay (Ring 3)
    │ VMCALL(READ_PHYS, addr, len)
    ▼
Hypervisor (Ring -1)
    │ EPT direct mapping
    ▼
Physical Memory
```

## 项目结构

```
driver/          WDK 驱动壳 — DriverEntry 加载并虚拟化所有 CPU 核心
hypervisor/      VT-x 核心逻辑
  src/
    intel/
      ept/         EPT 页表管理 + hook 机制
      vmexit/      VM-exit 处理（CPUID/RDTSC/VMCALL/EPT violation）
      vmx.rs       VMX 生命周期
      vmcs.rs      VMCS 初始化
      vcpu.rs      Per-CPU 虚拟处理器
      vmlaunch.rs  VMLAUNCH 入口 (asm)
      vmm.rs       VM-exit 分发主循环
    utils/         地址转换、内存分配、NT 绑定
```

## VMCALL 通信协议

| RAX (magic) | RCX (cmd) | RDX | R8 | R9 | 返回 |
|---|---|---|---|---|---|
| `0xA3B7E2914F6D8C15` | `0x01` PING | - | - | - | RAX = magic |
| | `0x10` READ_PHYS | phys addr | len | out buf | RAX = 0 (ok) |
| | `0x11` WRITE_PHYS | phys addr | len | in buf | RAX = 0 (ok) |
| | `0x12` TRANSLATE_VA | CR3 | VA | - | RAX = PA |

## 构建前置

- Rust nightly (`rustup default nightly`)
- cargo-make (`cargo install cargo-make`)
- Windows WDK/SDK (设置 `WDKContentRoot` 环境变量)
- LLVM (`winget install LLVM.LLVM`)
- Test signing: `bcdedit /set testsigning on`

## 构建

```bash
cargo make --profile development   # debug
cargo make --profile release       # release
```

## 测试环境

1. VMware Workstation，开启 VT-x 直通
2. Windows 10/11 x64 虚拟机
3. 关闭 VBS/HVCI
4. 加载驱动: `sc create matrix binPath= <path>\matrix.sys type= kernel && sc start matrix`
5. 验证: VMCALL PING 返回 magic

## 反检测

| 威胁 | 对策 | 状态 |
|------|------|------|
| CPUID bit 31 | 伪造返回值 | TODO |
| VMREAD 指令 | 注入 #UD | TODO |
| RDTSC 时序 | 补偿 VM-exit cycles | TODO |
| IA32_EFER MSR | 不修改 EFER | N/A |

## 参考

- [matrix-rs](https://github.com/memN0ps/matrix-rs) — Type-2 Rust hypervisor (本项目基础)
- [illusion-rs](https://github.com/memN0ps/illusion-rs) — Type-1 UEFI Rust hypervisor (长期目标)
- [Intel SDM Vol.3](https://www.intel.com/) — Chapter 23-33 VMX
- [Secret Club](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html) — Anti-cheat 检测方法实录
- [Detecting Hypervisor-Assisted Hooking](https://momo5502.com/posts/2022-05-02-detecting-hypervisor-assisted-hooking/) — EPT hook 检测研究
