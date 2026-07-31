# Freeze post-mortem（死前落稳 / 硬复位后读）

## 铁则

整机卡死是**一瞬间**。卡死后：

- CPU 不再执行任何 guest/host 路径
- **写不了** CMOS、磁盘、串口、网络
- **跑不了** SSH / `cpuid_ping` / 任何“冻时补救”

因此：

| 可信 | 不可信 |
|---|---|
| 死前已 flush 的 local_diag 文件 | 冻后再开工具抢救 |
| Ext CMOS 双缓冲 / Step4（entry 或事件当下写完） | 依赖 handler **finish** 才写的字段 |
| `HANDLER_ACTIVE=1` 卡死时仍为 1 | “检测到冻再写一次” |

## 当前写入时机（A1）

| 数据 | 何时写 |
|---|---|
| `HANDLER_ACTIVE` | entry 置 1；正常返回 Drop 清 0；冻在中间则保持 1 |
| `LAST_EXIT_REASON` + Layer3 双缓冲 | **entry** `handler_entry_persist`（每 64 exit 刷 CMOS） |
| Layer6 per-CPU last reason / rare ring | **entry** `snap_flush`（周期 / 稀有 exit） |
| Step4（KEBUGCHECKEX_HITS / first-fault / total） | **entry** change-detect；**bugcheck 首 hit 当场**再 sync |
| Watchdog 时长 | finish 仅更新 RAM 计数，**不写 CMOS** |

已知上限：Layer3 双缓冲默认每 64 次 exit 刷一次。若**所有核同时**卡在 entry 之后、下一次周期刷之前，bitmap 可能最多偏旧几十次 exit；Layer6 rare exit 仍会当场刷。local_diag 另有 100ms 盘文件（最后一批可能丢）。

## 实机协议

```text
1. 干净重启
2. local_diag 构建并加载（见 docs/hv-local-monitor.md）
   确认 D:\rust-cheat\hv_diag_live.log 有 HVL1 START
3. 启动游戏/EAC，玩到冻
4. 硬复位（RST）—— 不要指望冻后还能操作
5. 启动后读：
   - hv_diag_live.log（最后已 flush 的 HVL1 C / R）
   - cpuid_ping（HV_NO_SEAL 加载后）Layer3/6 prev-boot、Step4 CMOS
```

## 复位后判决（填一次）

| 证据 | 判型 |
|---|---|
| 多核 `HANDLER_ACTIVE` / Layer3 bitmap 非 0 + last exit 明确 | 卡在 HV handler |
| bitmap 全 0 + KEBUGCHECKEX_HITS>0 | 进过 bugcheck / 处置链 |
| HITS=0 + WHEA/MCE | 硬件 / C-state |
| 日志很久不涨 | 更早已死或 worker 未跑 |

## 不要做的

- 冻后 SSH / 冻后写诊断
- 为“功能”再加默认危险拦截（APERF/MWAIT/bugcheck EPT hook）
- 无上述判决就大改时序隐蔽
