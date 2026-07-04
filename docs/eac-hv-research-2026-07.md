# Type-2 Hypervisor 对抗 EAC 深度调研报告

> 2026-07-04 · 基于 UC 论坛、GitHub、secret.club、学术论文等 8 个并行研究方向

## 核心发现

### 1. 系统冻结不是 EAC 的检测响应

EAC 检测到 hypervisor 后的正常行为：
- 阻止游戏启动
- 崩溃游戏进程（异常码 0xC0000409 + 子码 0xEAC）
- BSOD（KERNEL_SECURITY_CHECK_FAILURE）
- 上报服务器异步 ban

**从不冻结整个系统。** 完全冻结（鼠标不动、无 BSOD、必须强制关机）是 HV 自身的 VM-exit handler bug：
- EPT violation 无限循环
- 未处理的 VM-exit reason
- VMX-root 下与 EAC 内核驱动的 spin lock 死锁（高 IRQL 下连 bug check 都无法执行）

### 2. Type-2 HV 方案可行

多个来源确认：
- **Ophion** (362 stars) — 声称开箱兼容 EAC/BE，Recon 2025 演讲
- **jonomango/hv** (705 stars) — 最完善的时序补偿
- **secret.club** — "反作弊在 HV 检测方面已经停滞"
- **VIC 论文** (2025.02) — QEMU/KVM 方案在 EAC 游戏上测试数周未被 ban
- 商业提供商（Ring-1.io 等）仍在运营

---

## EAC 已知检测手段

### 驱动初始化阶段

| # | 检测向量 | 原理 | 对策 |
|---|---------|------|------|
| 1 | vmread 指令探测 | SEH 包裹 vmread，成功执行→在 VM 内 | 注入 #UD |
| 2 | CPUID leaf 0x40000000 | 返回 vendor string→暴露 HV | 返回全 0 |
| 3 | CPUID ECX[31] | Hypervisor Present bit | 清零 |
| 4 | NtQuerySystemInformation 0xC4 | 查询 hypervisor 信息 | CPUID leaves 返回全 0 |

### 运行时检测

| # | 检测向量 | 原理 | 难度 |
|---|---------|------|------|
| 5 | rdtsc;cpuid;rdtsc 时序 | 裸机 ~200 cycles vs HV ~2000+ | 中-高 |
| 6 | CR4.VMXE 位 | 读 CR4 检查 VMX 是否激活 | 中 |
| 7 | 合成 MSR 0x40000000+ | HV 保留范围，裸机应 #GP | 低 |
| 8 | VMCALL 自完整性校验 | 驱动代码段哈希对比 | 低 |
| 9 | XSETBV 异常行为 | 无条件 VM-exit，验证 XCR0 约束 | 中 |
| 10 | IA32_APERF IET 分歧 | APERF 计时比 TSC 更难伪造 | 高 |
| 11 | WBINVD/INVD 缓存行为 | INVD→WBINVD 替换暴露 HV | 高 |
| 12 | LBR 堆栈一致性 | VM-exit 后 LBR 暴露 VMX-root 分支 | 中 |

### 延迟检测

| # | 检测向量 | 原理 | 触发时机 |
|---|---------|------|---------|
| 13 | IA32_EFER SCE 位 | 检测 syscall hook | 游戏运行 ~30 分钟后 |

---

## 参考项目

### Ophion (zer0condition/Ophion) — 首选参考
- 362 stars, C, Intel VT-x Type-2
- TSC: trap-next-RDTSC（不改 TSC_OFFSET）
  - VMXON 前预校准 200 次取最小值
  - CPUID exit 后开 RDTSC_EXITING
  - 仅拦截紧随 CPUID 之后的一次 RDTSC
  - 返回 tsc_cpuid_entry + bare_metal_cost + offset
- 已知弱点: APERF/MPERF 未补偿, CR4.VMXE 写-读不一致

### jonomango/hv — 时序补偿最完善
- 705 stars, C++, 有 timing.cpp
- 三重补偿: RDTSC + REF_TSC + MPERF
- 作者同时维护 nohv（检测 HV 的驱动）

### secret.club 文章
- 2020.04: How anti-cheats detect system emulation
- 2020.01: BattlEye hypervisor detection
- 2025.06: Hypervisors for Memory Introspection

### VIC 论文 (arXiv 2502.12322, 2025.02)
- QEMU/KVM + LibVMI, 在 Fortnite/BlackSquad/TF2 上成功

---

## 我们之前做错了什么

| 做法 | 问题 | 正确做法 |
|------|------|---------|
| 假设 freeze 是 EAC 时序检测 | EAC 不会冻结系统 | 先排查 HV 自身 bug |
| 每次 CPUID 修改 TSC_OFFSET | 正常 CPUID 也被补偿→时钟漂移 | 不改 TSC_OFFSET |
| RDTSC trap 返回 spoofed 值 | 第三次 RDTSC 暴露跳变 | Ophion 方案 |
| 硬编码 VMEXIT_ENTRY_OVERHEAD=600 | 不同 CPU 差异大 | VMXON 前预校准 |
| 没有 EAC 加载时的诊断输出 | 不知道 freeze 时最后的 exit reason | COM2/UDP 记录 |

---

## 行动计划

### 阶段一：诊断冻结根因
1. 撤销所有 TSC 补偿代码，回到纯净 HV
2. VM-exit handler 加诊断：COM2/UDP 记录最后 N 个 exit reason
3. default/fallthrough 分支记录未处理的 exit reason
4. EAC 环境下测试，捕获 freeze 前最后状态

### 阶段二：修复 HV 稳定性
1. 根据诊断修复具体 bug
2. 确保所有 VM-exit reason 都有处理路径
3. 验证 EAC 驱动加载后不冻结

### 阶段三：隐蔽性
1. CR4.VMXE shadow
2. 合成 MSR 0x40000000+ 注入 #GP
3. TSC 补偿（Ophion trap-next-RDTSC + 预校准）
4. IA32_EFER 虚拟化
5. LBR 保存/恢复
6. APERF/MPERF 补偿

---

## 替代方案对比

| 方案 | 成本 | 可行性 | 风险 |
|------|------|--------|------|
| Type-2 HV（本项目） | $0 | 可行 | 时序检测、实现复杂度 |
| Type-1 UEFI HV | $0 | 可行 | 需关 Secure Boot |
| DMA/FPGA | $400-1500+ | 风险中 | PUBG 封了 26 万账号 |
| QEMU/KVM VMI | 需第二台机 | 可行 | 性能损失 |
| Hyper-V Hijack | $0 | 部分 | 需禁 IOMMU |
