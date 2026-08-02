# matrix (hypervisor)

Windows x64 Intel VT-x type-2。工作区流程：**`D:\cheat\DEV.md`**。  
本仓说明：**`CLAUDE.md`**。

## 目录

```
hypervisor/
├── hypervisor/     VT-x 核心（EPT / VM-exit / VMCALL …）
├── driver/         WDK 入口 → matrix.sys
├── scripts/        构建 / 加载 / 收尾
├── tools/          用户态探针（.rs 源；.exe 本地生成、gitignore）
├── docs/hv-local-monitor.md  ★ 本地诊断日志格式
├── CLAUDE.md       ★ 本仓唯一项目说明
└── AGENTS.md       指向 CLAUDE.md
```

## 常用

| 目的 | 命令 |
|---|---|
| 编 client（给 svcmon） | `scripts\build_client.bat` |
| 加载 client | 重启后 `scripts\start_hv_client.bat` |
| 本地诊断 | 工作区 `scripts\build_local_diag.bat` → 重启 → `start_local_diag.bat` |
| 生产 matrix | `cargo build -p matrix --release` + `scripts\finalize_driver.ps1` |
| 加载 | `scripts\start_hv.bat`（须重启后、游戏前） |

日志：`D:\cheat\hv_diag_live.log`（仅 local_diag 构建）。
