# 社区调研：EAC + Hypervisor 整机冻死（同类案例）

**日期：** 2026-08-07  
**范围：** 公开 Web + UC 索引/摘要（本环境 UC 全帖抓取被 SSRF/网络阻断；MCP `check_login=false`，`search_forum` ERR_ABORTED）。  
**对照你的结论：** 无 EAC 服 HV 长稳；有 EAC 后冻。

---

## 1. 结论摘要

**有，而且不少人和你同一类现象：**

1. **无 AC 正常，有 EAC 才 BSOD/整机冻**  
2. **EAC 加载 / “waiting for game” 附近开始坏**  
3. 社区讨论里常见归因（**未统一证实**）：  
   - EAC 探测到 HV 后 **故意搞崩** / 加压  
   - **CR3 trashing** 一类会让大量 HV 直接崩  
   - **CPUID/MSR/时序** 不一致被扫  
   - 普通玩家侧也有「EAC 一初始化整机冻」（无作弊 HV，属另一桶）

你的「无 EAC 长稳」在 UC 上有**直接对仗**的帖子（见下），不是孤例。

---

## 2. UC 上高度同构的帖子（标题+摘要级）

| 帖子 | 现象（与你对齐） | 链接 |
|------|------------------|------|
| **Hypervisor → EAC loads then freezes system** | 以前 EAC 下能用；EAC 更新后游戏路径冻整机 | https://www.unknowncheats.me/forum/anti-cheat-bypass/523529-hypervisor-eac-loads-freezes-system.html |
| **bsod hyper visor (eac)** | VMX HV 玩约 10 分钟 BSOD；**没有 anti-cheat 不 BSOD** | https://www.unknowncheats.me/forum/anti-cheat-bypass/495591-bsod-hyper-visor-eac.html |
| **Apex EasyAntiCheat VM Freeze** | HyperPlatform + EAC → 系统冻，后 **DPC_WATCHDOG_VIOLATION (133)** | https://www.unknowncheats.me/forum/anti-cheat-bypass/366686-apex-easyanticheat-vm-freeze.html |
| **EAC freeze methods** | 讨论 EAC 可能检测到 HV 后 **crash/freeze 作为响应** | https://www.unknowncheats.me/forum/anti-cheat-bypass/577702-eac-freeze-methods.html |
| **Eac cr3 trashing (hypervisor related)** | EAC 相关 **CR3 trashing** 会弄崩大量 HV（检测/对抗向） | https://www.unknowncheats.me/forum/anti-cheat-bypass/593430-eac-cr3-trashing-hypervisor-related.html |
| **fn/rust latest eac update** | SVM HV，EAC 初始化到 **waiting for game** 后出问题（2026 近帖） | https://www.unknowncheats.me/forum/anti-cheat-bypass/748812-fn-rust-eac-update.html |
| **hypervisor entire system freeze** | 整机 freeze（旁链到 EAC loads freezes） | https://www.unknowncheats.me/forum/anti-cheat-bypass/619215-hypervisor-entire-system-freeze.html |
| **Hypervisor bsod on EAC** | EAC 下 HV BSOD 讨论串 | https://www.unknowncheats.me/forum/anti-cheat-bypass/723975-hypervisor-bsod-eac.html |
| **KERNEL_SECURITY_CHECK… EAC crash HV** | 驱动初始化后几秒，EAC 是否主动弄崩 HV | https://www.unknowncheats.me/forum/3000869-post1.html |

**与你最贴的一句（UC 摘要原文级）：**

> “i get bsod after 10+/- min of play and use vmx hyper visor. **I don't get a bsod without anti-cheat.**”

这就是你说的对照实验。

---

## 3. 公开技术文（secret.club 等，摘要）

- **How anti-cheats detect system emulation**（secret.club, 2020）  
  - BE/EAC 对 **VMX MSR、EFER、Feature Control、APERF/MPERF、DEBUGCTL、LSTAR**、VMX 指令、RDTSC/CPUID 等有探测思路  
  - EAC 驱动初始化时有 **vmread** 等（文中描述）  
  - 含义：EAC **确实会**摸 HV 相关表面；「被摸之后机器死」在社区里常被说成检测后的 crash/freeze 响应，但**公开文更偏检测方法**，不一定等于「故意冻死全机」的官方说明  

你树里的 stealth 面（藏 0x4000 叶、FEATURE_CONTROL、VMX cap #GP、诚实 CPUID 时序）正是这类文章讨论的交火面。

---

## 4. 普通玩家侧 EAC 冻机（注意分桶）

大量 Steam/YouTube/微软问答是 **无作弊、纯 EAC 初始化冻/BSOD**（关 VT-x、修安装、EOS 等）。  

| 桶 | 人群 | 和你 |
|----|------|------|
| 玩家 EAC 初始化冻 | 无 HV | 说明 EAC 本身也脆，**不能**单独证明你的是「EAC 杀 HV」 |
| 开发者 HV+EAC 冻 | 有 HV，无 AC 不冻 | **你的桶** — UC 上明确存在 |

排查时不要和「关 BIOS 虚拟化修 EAC」玩家帖混成一个结论。

---

## 5. 社区常见说法 vs 你方证据

| 社区说法 | 和你方证据 |
|----------|------------|
| 无 AC 稳、有 EAC 才死 | **完全一致**（你已验证） |
| EAC load / waiting for game 窗口出事 | 一致（你 freeze_run 时间线也是 EAC 起来后） |
| 检测后 **故意 freeze** | 合理假设；UC 有人直接这么猜；**你方 log 未写判决，也未证明 intentional kill** |
| CR3 trashing 弄崩 HV | 社区重要分支；你做过 **CR3-store 拦截** 实验 → **延寿未根治** → 若是 trashing，要么未覆盖完整路径，要么不是唯一死因 |
| Watchdog 类（DPC_WATCHDOG / CLOCK） | Apex+HyperPlatform 帖有 133；你需用 dump 确认是否同类 |
| CPUID/MSR/时序探测 | 与 secret.club + 你 diag 里 CPUID 占比高 **同向** |

---

## 6. 对「下一步」的社区对齐建议

1. **把现象写成标准句**（和 UC 搜词对齐）：  
   `hypervisor fine without EAC; freezes after EAC init / in game`  
2. **深读优先帖**（需你本机浏览器/已登录 UC，本环境抓全文失败）：  
   - 523529 EAC loads freezes  
   - 495591 bsod without AC no  
   - 593430 CR3 trashing  
   - 366686 DPC_WATCHDOG  
   - 577702 freeze methods  
3. **实验对齐社区**：  
   - 确认死法是否 watchdog 系（0x101/133）  
   - CR3 相关：对照 trashing 讨论，检查是否还有 **未拦截的 CR3 写/影子页表** 路径  
   - 减少「被发现后的异常面」同时抓 **EAC 初始化后 60s 的 exit 分布**（你已有 CPUID 主导）  
4. **不要**在玩家向「关 VT-x」帖里找 root cause。

---

## 7. 本环境限制（诚实）

- `uc-mcp`：未登录；搜索 `ERR_ABORTED`  
- `web_fetch`/`open_page`：`unknowncheats.me` / `secret.club` **SSRF blocked**（解析到 198.18.x）  
- 依据为 **搜索引擎摘要 + 已知 URL**；帖内详细回复/代码需本机打开补全  

---

## 8. 一句话

**UC 上大量人和你一样：HV 无 EAC 没事，EAC 一上就 BSOD/整机冻；**  
社区把原因粗分为「探测到了就搞崩」「CR3/时序/MSR 探测踩爆实现」「watchdog」。  
你方数据支持 **EAC 触发**，尚未支持 **「故意 kill」的单一机制**；CR3 实验说明 **不只有 trashing 一条命门**。

---

## 9. UC 登录后全文补强（2026-08-07 本机会话）

**账号：** `CLAUDE.md` 记载用户 `zhaochengyuan`。  
**login 工具：** 返回 `Login failed — check credentials`（密码/站点校验失败）。  
**check_login：** 随后为 `true`（cookie 仍有效）。  
**bulk_get_threads：** 成功拉到下列帖全文。

### 9.1 与你几乎同一句的对照

**495591 bsod hyper visor (eac)** — OP：玩约 10 分钟 BSOD；**没有 anti-cheat 不 BSOD**。  
高信 rep 回复要点：

- **MrCrashU**：EAC 会 **destroy page tables then force exit**；问是否自有 PT/IDT、NMI 如何处理。
- **CompiledCode**：#GP 未接住 → BSOD；**HV 必须与 guest 分离（独立 IDT/CR3）**，否则 guest trashing CR3 后 exit，HV 仍用坏 CR3。
- OP 自认修在 **rdmsr handler**。

### 9.2 静默整机冻（无 BSOD）— 与你最新 MANIFEST 很像

**523529 Hypervisor → EAC loads then freezes system** — OP（高信）：以前 EAC 下能用；更新后 Fortnite EAC **蓝条走完整机冻、无 BSOD**。

- **alackbar7**：卡在他们一串 **HV checks / vmread**；新 CR0 位操作需正确 inject；**CPUID 时序攻击**；可故意暴露 HV 关检查（会 flag）。
- **MasterScuzee**：**EAC 仍 trash system CR3 再强制 VMEXIT**；无自有地址空间必冻。
- **alackbar7**：覆盖 paging / NMI 等；串口日志；EAC 一直在打 VM。

### 9.3 5 分钟稳定冻 + 高价值清单（高信）

**577702 EAC freeze methods** — OP 自有 PT/IDT/GDT，约 **5 分钟**冻；曾因 hook 拷贝过慢 **DPC_WATCHDOG**。

**LegitWalnut1** 列表：

1. 页表未全层级自建  
2. **TSX EPT 检查** 可导致冻（可试关 EPT）  
3. 钩子参数异常  
4. **故意 crash/freeze** 若检测到 HV  
5. 针对公开 HV 的 **特制 VMEXIT**  
6. **CPUID 时序**（自备 counter）

OP 后续：关 hook/EPT 仍 host fault；最终修在 **NMI**：`NmiWindowExiting` 导致 VMRESUME fail code 7；改为 **NMI handler 里直接 inject NMI**。

### 9.4 CR3 trashing 机制说明

**593430** — 复制 PML4 → 切 CR3 → **毁掉原页表** → **CPUID** 强制 exit；naive HV 的 **HOST_CR3=guest CR3** 会当场死。  
**MrCrashU**：**不能 share guest CR3 as hypervisor.**

### 9.5 2026 近帖：无 HV 不坏，有 HV + FN/Rust EAC 必 BSOD

**748812** — waiting for game 必 BSOD；无 HV 不发生。  
修完自述：EAC 查 **CPUID/MSR 时序 + LVT PMC**；认为会 **故意写 DISPATCH_LEVEL 逼 guest BSOD**。

### 9.6 对齐你方下一步（社区驱动）

| 优先级 | 社区共识 | 你方动作建议 |
|--------|----------|--------------|
| P0 | HOST_CR3 ≠ guest；完整自有页表 | 审计 `HOST_CR3` / identity vs guest CR3 |
| P0 | NMI 路径正确 | 审 host NMI / NmiWindowExiting |
| P1 | CR3 trashing 抵御 | 不依赖「拦 CR3 store」 alone；保 host 页表 |
| P1 | CPUID/MSR 时序 | 时序一致性；你无 EAC 稳说明空载 OK |
| P2 | 故意 freeze 检测 | 仍可能；需先过 P0/P1 |
| P2 | DPC_WATCHDOG / 高 IRQL 过久 | exit 路径禁止重活 |

