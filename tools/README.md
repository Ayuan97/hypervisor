# tools

用户态探针。**源码入库（.rs）**；**可执行文件本地生成（.exe gitignore）**。

| 优先级 | 工具 | 用途 |
|---|---|---|
| 日常 | `cpuid_ping` `probe_test` | 加载自检 / seal |
| 诊断 | `hv_breadcrumb` `read_cmos_freeze` `phys_test` `hv_mem_diag` `freeze_watchdog` | freeze / 读通路 |
| 专项 | `*_bench` `eac_sim` `*_monitor` `test_*` | 非默认路径 |

构建示例：`rustc tools\cpuid_ping.rs -o tools\cpuid_ping.exe`  
工作流见上级 `CLAUDE.md` 与 `D:\rust-cheat\DEV.md`。
