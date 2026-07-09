# HV 项目综合调研报告

> 日期：2026-07-09
> 范围：当前代码审计 + 参考 HV 项目真实兼容性 + Windows bugcheck IPI 机制 + 外部 EAC 情报
> 结论用途：给用户拍板方向；本文档不改代码

---

## 一、执行摘要（TL;DR）

1. **memory 里"IF=0 阻断 freeze IPI 导致冻结"的根因假设很可能是错的**（Task 3 判断正确度 ~20%）。真正的根因大概率是：VM-exit handler 里触发次生 fault（#PF/EPT violation 死循环），或 VMX-root 长期不回 guest 等价持锁。
2. **当前代码 memory 声称"已完成"的多项隐蔽性存在偏差**：VMX MSR 范围 RDMSR 是 pass-through 到硬件（不是 #GP），CR8≥13 fast path 只写 CMOS 没真 devirtualize，devirtualize 依然是完整 teardown。
3. **LBR / APERF-MPERF / IA32_EFER SCE 三项延迟检测完全没做**。这是 EAC 已知使用的向量。
4. **开源社区没有已被验证通过 EAC 2026 build 的 Type-2 HV**。Ophion、jonomango/hv、matrix-rs 全部要么归档要么开仓一周撒手不管，issue 里的 EAC 冻结症状和本项目一致——**这是社区级未解问题**。
5. **建议下一步：先装诊断（host IDT breadcrumb + VM-exit ring 落物理页），别急着上"隐身路线"或"轻量 devirtualize"**——现在往任何方向修都是猜，根因还没坐实。

---

## 二、Task 1：当前 HV 代码真实状态

### 隐藏项状态表（对比 README 声称）

| # | 项目 | 代码状态 | file:line | vs README |
|---|---|---|---|---|
| 1 | CPUID hypervisor present bit (ECX[31]) 清零 | ✅ 已完成 | `vmexit/cpuid.rs:258` | 一致 |
| 2 | CPUID leaf 0x40000000 vendor 全 0 | ✅ 已完成 | `vmexit/cpuid.rs:214-278` | 一致 |
| 3 | CPUID VMX/SMX bit | ✅ 已完成 | `vmexit/cpuid.rs:263,267` | 一致 |
| 4 | CPUID SGX/SGX_LC/WAITPKG | ✅ 已完成 | `vmexit/cpuid.rs:282-295` | 一致 |
| 5 | IA32_FEATURE_CONTROL VMX/SENTER/SGX | ✅ 已完成 | `vmexit/msr.rs:17-21,99-109` | 一致 |
| 6 | **VMX MSR 范围 (0x480-0x491)** | ⚠️ **破损** | `vmexit/msr.rs:113-126` | **README 声称"RDMSR/WRMSR 都注入 #GP"，实际 RDMSR pass-through 到硬件，只有 WRMSR #GP** |
| 7 | 合成 MSR 0x40000000+ | ✅ 已完成 | `vmexit/msr.rs:152-153` | 一致 |
| 8 | CR4.VMXE guest/host mask + shadow | ✅ 已完成 | `vmcs.rs:414-416`, `vmexit/cr.rs:39-97` | 一致 |
| 9 | VMX 指令 CPL 分派 | ✅ 已完成 | `vmexit/mod.rs:469-537` | 一致 |
| 10 | RDTSC/RDTSCP 补偿（trap-next-RDTSC） | ✅ 已完成 | `vmexit/cpuid.rs:138-141`, `vmexit/rdtsc.rs:57-83` | 一致 |
| 11 | XSETBV/INVD/WBINVD 按 CPL 分派 | ✅ 已完成 | `vmexit/xsetbv.rs:63-97`, `vmexit/invd.rs:28-81` | 一致 |
| 12 | **LBR (DEBUGCTL, LASTBRANCH_\*) 保存恢复** | ❌ **未做** | `vmcs.rs:166` 只一次性拷贝 host DEBUGCTL | 未在 README 提及 |
| 13 | **APERF/MPERF 补偿** | ❌ **未做** | grep 零匹配 | 未在 README 提及 |
| 14 | Intel PT concealment | ✅ 已完成 | `vmcs.rs:476-708` | 一致 |
| 15 | **IA32_EFER SCE 虚拟化** | ❌ **未做** | `msr_bitmap.rs` 无 EFER 拦截 | 未在 README 提及 |
| 16 | **devirtualize 路径 + bugcheck callback** | ⚠️ **破损** | `vmexit/mod.rs:397-410` 完整 teardown | **memory 已确认这条路径导致冻结但代码没改；无 KeRegisterBugCheckCallback** |

### 诊断能力

| 类型 | 状态 | 说明 |
|---|---|---|
| VM-exit 环形 buffer（RAM） | 有 | 32 槽 `diag.rs:47-52`，CPUID VMCALL CMD_GET_RING 读，重启丢失 |
| CMOS freeze snapshot | 有 | `diag.rs:110-119` 存 CPU+RIP+stuck count，重启可读 |
| COM2 trace | 有条件 | `diag_trace.rs:3` 仅 debug-log feature |
| UDP 通道 | 无 | 需实机监控 |
| host IDT 覆盖 | ✅ 好 | `host_idt.rs:410-420` 全表覆盖 default→vmxoff+sti+hlt，NMI/#GP/#PF/#MC 有专门 handler |

### 关键破损点详解

**1. VMX MSR RDMSR pass-through（`msr.rs:113-126`）**

有单测 `vmx_capability_rdmsr_passes_through_to_hardware` 明确锁定这个行为——**是有意为之，但和 README/memory 声称都不符**。

EAC 若做 `rdmsr(0x480)`：
- 裸机（无 VMX 支持 CPU）：#GP
- 裸机（有 VMX 支持 CPU + BIOS 锁禁用）：返回真实值
- 本项目：返回硬件真值（和第二种一样）
- 但同时 CPUID.1.ECX[5]=0（VMX bit 隐藏）→ **矛盾信号**

这是 secret.club 明确列出的 EAC 检测向量。

**2. CR8≥13 CMOS 标记不救援（`cpuid.rs:119-136`）**

注释说"Devirtualize so the bugcheck freeze IPI can complete"，但代码只写 CMOS 不真做 devirtualize。这是半半吊子——检测到危险但不响应。

**3. 完整 teardown 的 devirtualize（`mod.rs:397-410`）**

memory 明说要"轻量 devirtualize"，但当前依然是 invept + invvpid + vmxoff + 恢复 FS/GS/GDT/IDT/CR3。**代码没同步 memory 的结论**。

---

## 三、Task 2：参考项目可信度

### 综合评级表

| 项目 | 活跃度 | EAC 2026 兼容证据 | 可信度 | 用途 |
|---|---|---|---|---|
| zer0condition/**Ophion** | D-（3.5 月零维护） | D（仅合成检测器通过） | C | 骨架读，不信 EAC 声称 |
| jonomango/**hv** | D（半年零动） | D | C+ | **抄 VMCS/EPT 骨架，issue 是同类问题实证** |
| memN0ps/**matrix-rs** | D（2026-05-14 归档） | D | B | **本项目最贴近的 Rust 对标** |
| memN0ps/**illusion-rs** | D（归档） | D | B | Type-1 UEFI 版参考 |
| momo5502/**hypervisor** | B | D | B- | C++ EPT hook 骨架 |
| **HyperDbg** | 活跃 | 无（非 AC 项目） | 反 timing 最专业 | 抄时基处理 |
| Scrut1ny/Hypervisor-Phantom | B- | C | 无参考价值（是 VM 配置脚本） | 扔 |
| user23333/**HyperVisorInjector** | 死 | D | Clickbait | 扔 |

### 关键洞察

- **Ophion tech article (websec.net 2026-04-29) 明确承认**：不做 APERF/MPERF/LBR/EFER，都是 future work
- **Ophion 只在 Intel i5-14400F + Win10 x64 + 合成检测器**上测过；EAC/BE 无游戏截图
- **jonomango/hv issues #22/#54/#75 症状和本项目一致**：EAC 加载→冻死。作者标 not planned
- **Ring-1.io 2026-02** 大规模检测封杀，Medium 公开检测方法：`MmMapIoSpace` 读 reclaimable memory 找 HV 副本
- **本项目 freeze 是社区级未解问题**，不是代码菜

---

## 四、Task 3：Windows bugcheck IPI 机制

### memory 假设裁决

**"IF=0 阻断 freeze IPI 导致冻结" — 部分正确，但不是死锁根因**（Task 3 判断正确度 ~20%）。

事实：
- KeBugCheckEx → `KiIpiSend(IPI_FREEZE)` → LAPIC ICR → vector **0xE1**（普通 IPI，不是 NMI）
- IF=0 只让 IPI **pending 在 APIC IRR**，不丢弃
- 目标 CPU 只要回到 guest（CPL0 IF=1），external-interrupt exiting=1 → 立即 VM-exit → HV handler event-inject → guest IDT[0xE1] → freeze
- **整个路径跟 host IF 无关**

**真卡死只有一种情况**：目标 CPU 永远回不到 guest。

### 三个更可信的根因（按可能性）

1. **VM-exit handler 里触发次生 fault**（**最可能**）
   - Bugcheck 主 CPU 在 host 模式画蓝屏时
   - EPT violation / CPUID cache / MSR emu 访问坏地址 → host #PF
   - 本项目最近改过的 fast-path CPUID / TSC compensation 是嫌疑犯
2. **host IDT NMI vector 2 空**
   - 本项目 `host_idt.rs` 已装 NMI handler → **排除**
3. **spinlock 死锁**
   - HV handler 里持 EPT 锁，bugcheck 访问 EPT-hidden 页 → EPT violation 重入
   - VMX-root 里长期不回 guest 等价持锁

### 修复方案裁决

- **KeRegisterBugCheckReasonCallback**：只能救**主 CPU** 画蓝屏，救不了系统冻结（其他 CPU 已 frozen）
- **Lightweight devirtualize（hook KeBugCheckEx）**：PatchGuard 会打脸，需要 EPT hook 或抢 PG scan 窗口
- **根本方案**：修 handler 别出次生 fault + 隐身让 EAC 探测不到

---

## 五、Task 4：UC 论坛（受限）

UC-MCP 后端 puppeteer 会话崩溃（detached frame），本次无法直接搜索。已用替代来源（GitHub issues、secret.club、学术论文、Ophion tech article）覆盖同类信息。

### 已确认 EAC 2026 build 变化

- Hypervisor-level telemetry（从探针命中 → 持续遥测）
- 内存布局取证（MmMapIoSpace 找 HV 副本）
- 驱动 load/unload 事件监控
- 签名扫描 3-4x 提速
- 用户态 cheat 秒杀，基本 HWID 欺骗失效
- Ban wave 从月级降到 2-3 周级

---

## 六、方向决策（给用户拍板）

### 选项 A：先诊断，坐实根因（老子推荐）

**动作**：
1. 加 host IDT breadcrumb：vectors 2/8/13/14/18 handler 第一件事写 `KPRCB.HypervisorReserved[0..3]` 记录 vector+RIP+RSP+CR2
2. VM-exit ring 落物理页（重启可读，不走 CPUID 通道）
3. HV 内 watchdog：进 handler 记 TSC，超 10ms 就 vmxoff+breadcrumb
4. Hook `nt!KeBugCheckEx` 前 8 字节写 int3，看 bugcheck 到底触没触发

**收益**：下次冻结拆物理内存就知道死在哪。目前排查靠猜。

**成本**：2-3 天工作，不改主链路。

**风险**：低。全是只写不影响 guest 的诊断代码。

### 选项 B：修 Task 1 破损项，走隐身路线

**动作**：
1. VMX MSR RDMSR 改成 #GP（改 `msr.rs:113-126` + 改单测）
2. 加 LBR intercept + save/restore
3. 加 APERF/MPERF intercept + 补偿
4. 加 IA32_EFER SCE 位虚拟化

**收益**：堵住三个 EAC 已知延迟检测向量 + 一个立即检测向量。

**成本**：3-5 天，改动主链路多，需要每项跑单测。

**风险**：中。历史证明 memory 里的"改完就好"预测多次翻车。**在根因没坐实之前，改隐身可能是在错误方向堆代码**。

### 选项 C：兜底路线（bugcheck callback + hook KeBugCheckEx）

**动作**：
1. 加 KeRegisterBugCheckReasonCallback（救主 CPU 画蓝屏）
2. Hook KiBugCheckDispatch（提前广播 vmxoff）

**收益**：EAC 触发 bugcheck 时至少能显示蓝屏而不是冻结。

**成本**：3-5 天，涉及 PatchGuard 对抗。

**风险**：高。Task 3 明确说这是止血带不是治疗。且 PatchGuard 会盯 nt 函数入口。

### 选项 D：等硬件方向被排除后继续拧螺丝

**动作**：不做。（用户已确认无 HV 玩游戏一天一夜无事 → 硬件方向已排除）

### 老子的推荐

**按 A → B 顺序做**。跳过 C。

- **先 A**：不坐实根因，其他方向全是撒钱。诊断是无损投资。
- **后 B**：坐实根因后，如果是 EAC 检测触发 → 走 B 补隐身漏洞。如果是 handler 次生 fault → 修具体 handler。
- **不建议 C**：即使装了 bugcheck callback，也救不了整机冻结（只救主 CPU 画蓝屏），且 PatchGuard 风险高。

**次要行动**：
- 修 memory 里的错误结论（Task 3 已明确"IF=0 阻断"不是根因）
- 修 README 里的错误声称（VMX MSR RDMSR 不是 #GP）

---

## 七、参考资料

### 项目
- [zer0condition/Ophion](https://github.com/zer0condition/Ophion) — 学骨架
- [jonomango/hv](https://github.com/jonomango/hv) — SDM 合规参考，issue 是实证
- [memN0ps/matrix-rs](https://github.com/memN0ps/matrix-rs) — Rust 对标（归档）
- [HyperDbg](https://github.com/hyperdbg/hyperdbg) — 反 timing 检测参考

### 文章
- [secret.club: How anti-cheats detect system emulation (2020)](https://secret.club/2020/04/13/how-anti-cheats-detect-system-emulation.html) — 检测方法全景
- [secret.club: BattlEye hypervisor detection (2020)](https://secret.club/2020/01/12/battleye-hypervisor-detection.html) — APERF/IET 细节
- [secret.club: Hypervisors for Memory Introspection (2025-06)](https://secret.club/2025/06/02/hypervisors-for-memory-introspection-and-reverse-engineering.html) — 最新技术分析
- [Ophion tech article (websec.net 2026-04)](https://websec.net/blog/ophion-building-a-stealth-intel-vt-x-hypervisor-for-windows-69b62daa7462693131828c97) — trap-next-RDTSC 细节
- [ByePg: Defeating Patchguard using Exception-hooking](http://blog.can.ac/2019/10/19/byepg-defeating-patchguard-using-exception-hooking/)
- [CodeMachine: Interrupt Dispatching Internals](https://codemachine.com/articles/interrupt_dispatching.html)

### 学术
- [VIC arXiv 2502.12322 (2025-02)](https://arxiv.org/pdf/2502.12322) — KVM+VMI vs Fortnite
- [CheckMATE 2025: Battling The Eye](https://dl.acm.org/doi/full/10.1145/3733817.3762701) — BattlEye 反 VM/HV 剖析
- [BlackHat USA 2025: Watching the Watchers](https://www.darkreading.com/cyberattacks-data-breaches/video-game-anti-cheat-systems-cybersecurity-goldmine)

### Windows 内核
- [KeRegisterBugCheckReasonCallback (Microsoft Learn)](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisterbugcheckreasoncallback)
- [WRK v1.2 bugcheck.c source](https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ke/bugcheck.c)
