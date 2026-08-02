# matrix hypervisor

简体中文。结果优先。

| 文档 | 职责 |
|---|---|
| **本文件** | 本仓目录、构建加载、VMCALL、freeze 诊断 |
| `D:\cheat\DEV.md` | 工作区流程（含本地诊断入口） |
| `docs/hv-local-monitor.md` | `hv_diag_live.log` 格式 |
| `AGENTS.md` | 指向本文件 |

---

## 1. 目录约定

```
hypervisor/
├── hypervisor/src/          VT-x 核心 crate
│   └── intel/
│       ├── ept/             EPT / cloak
│       ├── vmexit/          各 exit handler
│       ├── diag.rs          诊断 / ring / watchdog
│       ├── vmcs.rs vcpu.rs vmlaunch.rs …
│       ├── client_read.rs   物理读快路径
│       └── host_idt.rs      host IDT
├── driver/                  WDK 入口（产物 matrix*.sys）
├── scripts/                 构建与加载（见下表）
├── tools/                   用户态探针 .rs（.exe 不入库）
└── docs/
    └── hv-local-monitor.md  现行诊断格式
```

| 规则 | |
|---|---|
| 日常「本地诊断」入口 | 工作区 `D:\cheat\scripts\build_local_diag.bat` / `start_local_diag.bat` |
| 本仓加载脚本 | `scripts\start_hv.bat` / `start_hv_client.bat` |
| 产物 | `target\release\matrix.sys` / `matrix_client.sys`；diag 另存 `D:\cheat\output\hv\` |
| 禁止 | 根目录丢运行日志（如 esP.lom.trt）；热替换已加载 HV |

### scripts/

| 脚本 | 用途 |
|---|---|
| `build_client.bat` | client 读通道构建 |
| `build_release.bat` / `finalize_driver.ps1` | 发布构建收尾 |
| `build_stage.bat N` | `HV_BOOT_STOP_STAGE=N` 隔离 |
| `start_hv.bat` | kdmapper 映射 `HV_DRIVER` 或默认 matrix.sys + 自检 + seal |
| `start_hv_client.bat` | 映射 matrix_client.sys |
| `load.bat` / `unload.bat` | service 方式（少用；kdmapper 实例只能重启卸） |
| `scan_release_strings.ps1` | 发布串扫描 |
| `enable_testsign.bat` / `build_sign.bat` / `map_driver.bat` | 签名/映射辅助 |

### tools/（探针）

| 常用 | 用途 |
|---|---|
| `cpuid_ping` | 存活 / seal / status（`start_hv` 调用） |
| `probe_test` | 加载后自检 |
| `hv_breadcrumb` | 每 CPU 最后 VM-exit |
| `read_cmos_freeze` | 冻死后硬重启读 CMOS |
| `phys_test` / `hv_mem_diag` | 物理读诊断 |
| `freeze_watchdog` | 通道卡死监视 |
| 其它 `*_bench` / `eac_sim` / `*_monitor` | 专项，非日常 |

```powershell
rustc tools\cpuid_ping.rs -o tools\cpuid_ping.exe
```

---

## 2. 构建与加载

工作区总流程见 **DEV.md**（场景 B/C）。本仓最短路径：

```powershell
cd D:\cheat\backends\hypervisor
cargo build -p matrix --release
powershell -File scripts\finalize_driver.ps1

# 重启后
scripts\start_hv.bat
# 或 client：
scripts\build_client.bat   # 然后重启
scripts\start_hv_client.bat
```

- 已 active → **不要**再 map，先重启  
- 游戏/EAC 前完成加载与自检  
- kdmapper 实例不能 `unload.bat`，只能重启  

### 环境变量

| 变量 | 何时 | 作用 |
|---|---|---|
| `HV_NO_SEAL=1` | 加载前 | 不 seal，保留用户态 diag |
| `HV_DRIVER=path` | 加载前 | 覆盖驱动路径 |
| `HV_BOOT_STOP_STAGE=N` | **构建** | 启动阶段隔离 |
| `HV_USER_CLIENT_READS=1` | **构建** | 用户态 client 读（svcmon / local_diag） |
| `HV_LOCAL_DIAG=1` | **构建** | 写 `D:\cheat\hv_diag_live.log` |
| `HV_TRANSPARENT=1` | **构建** | 测试用 CPUID 透传 |
| `HV_PT_CONCEAL_MASK` | **构建** | 隐蔽掩码（local_diag 脚本会设） |

### 日志通道

| 通道 | 说明 |
|---|---|
| 本地文件 | `HV_LOCAL_DIAG` → `hv_diag_live.log`（见 hv-local-monitor.md） |
| CMOS | freeze 快照；`tools\read_cmos_freeze.exe` |
| COM2 | `0x2f8` 串口 |
| CPUID/VMCALL diag | seal 前；`cpuid_ping` / breadcrumb |

---

## 3. 通信（摘要）

用户态诊断：隐藏 CPUID leaf `0x4000_0000`，`r10/r11` token。VMCALL 仅 CPL0。

| CMD | 用途 | 用户态 |
|---|---|---|
| `0x01` PING | 存活 | 允许 |
| `0x10` READ_PHYS | 物理读 | CPL0 |
| `0x11` WRITE_PHYS | 物理写 | **禁用** |
| `0x12` TRANSLATE_VA | VA→PA | CPL0 |
| `0x14` GET_COUNTER | 计数 | 允许 |
| `0x15` GET_CTL | 诊断字段 | 部分 |
| `0x16` SEAL_DIAGNOSTICS | seal | 允许 |
| `0x19` GET_BREADCRUMB | 最后 exit | 允许 |
| `0x20` CLOAK_PAGE | EPT cloak | CPL0 |
| `0x25`/`0x2A`/`0x2B` | ring | 允许 |
| `0x28` GET_CPU_DIAG | heartbeat | 允许 |
| `0x29` READ_CMOS_FREEZE | CMOS | 允许 |
| `0x2C` GET_WATCHDOG | watchdog | 允许 |
| `0xFF` DEVIRTUALIZE | 卸载 | CPL0 |

---

## 4. Freeze 诊断（本项目特征）

实测 signature：整机死锁式卡死（键鼠/电源短按/网络均无响应，无蓝屏、无自动重启）。细节与字段表：

- 常用：`HOST_FAULT_*`、`KEBUGCHECKEX_*`、`GET_WATCHDOG`、per-CPU ring（`GET_CTL` / VMCALL）  
- 本地文件：`HVL1 R` / `HVL1 C`（`docs/hv-local-monitor.md`）  
- 硬重启后：`read_cmos_freeze.exe`  

观测原则：数据须在卡死前写入持久层；handler entry 写优先于 finish。CMOS 布局以源码 `diag.rs` 为准。

---

## 5. 仓库

```
远程     git@github.com:Ayuan97/hypervisor.git  (master)
Windows  D:\cheat\backends\hypervisor
```

改代码用 Edit/Write（UTF-8）。与 `code/`（svcmon）契约：命令号、seal、client-read、加载脚本。
