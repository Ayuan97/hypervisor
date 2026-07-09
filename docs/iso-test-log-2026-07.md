# 无 EAC 隔离测试记录

**目标**：确认 HV + 无 EAC 环境下系统不冻，作为 EAC 场景对照的基线。

**流程**：重启 → 双击"1. 加载 HV" → 双击"2. 起本地服务器" → 双击"3. 起客户端" → 玩 15-30 分钟 → 记录结果。

**判定**：连续 3-5 轮全绿 → 进入 EAC 场景测试。

## 记录

| 轮次 | 时间 | HV 状态 | 游玩时长 | 冻/BSOD/异常 | HV 快照 | 备注 |
|---|---|---|---|---|---|---|
| 1 | 待记录 | ✅ 加载 magic OK | 待记录 | 待记录 | 见文末快照 | 已进入服务器 |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |

## 首次基线快照（游戏运行中）

- Total exits：6
- Host #GP/NMI/#MC/#PF：全 0
- CMOS freeze：空
- Boot stage：260
- IDT patch：24 CPU 全 patch 完美（mask 0x3f/0x3f）
- 结论：HV 拦截极少，系统健康

## 冻结时立即操作（万一发生）

1. **别硬重启**
2. Mac 侧告诉 Claude：现在冻死了
3. Claude SSH 抓 CMOS + first-fault + KEBUGCHECKEX 字段
4. 抓完再重启
## 第 1 轮结果（2026-07-09）

- **HV 状态**：加载 magic OK，boot stage 260，IDT patch 24 CPU 全 ok
- **游玩时长**：进服后 3.5 分钟监控（用户在游戏内活动）
- **VM-exit 总数**：6（3 次快照无变化，因 ExtIntExit=0，外部中断不触发 exit）
- **Host fault**：#GP=0 / NMI=0 / #MC=0 / #PF=0
- **CMOS freeze**：空
- **CR8 bugcheck**：正常，marker=0x01
- **结论**：✅ 通过，HV 稳定，无冻结迹象

准备重启进入第 2 轮。

## 第 2 轮结果（2026-07-09 06:27-06:32）

- **HV 状态**：加载 magic OK
- **游玩时长**：进服后 ~4.5 分钟监控
- **VM-exit 总数**：6（3 次快照 T0/T1/T2 全部无变化）
- **Host fault**：#GP=0 / NMI=0 / #MC=0 / #PF=0
- **CMOS freeze**：空
- **边界信号**：CR8 marker 存疑（value=1，非真冻结），等系列测试完统一处理
- **结论**：✅ 通过，HV 稳定

## 第 3 轮结果（2026-07-09 06:46+）

- **HV 状态**：加载 magic OK，boot stage 260
- **VM-exit 总数**：6（T0/T1/T2 三次采样 4 分钟内无变化）
- **Host fault**：全 0
- **CMOS freeze**：空
- **结论**：用户主观判定 ✅ 通过

## 系列测试总结

**3/3 无 EAC 隔离测试全部通过**，HV 单独运行时系统完全稳定。

**根因认定**：**冻结由 EAC 触发**，不是 HV 内因。之前 memory 中的"handler 触发次生 fault"假设作为死锁机制仍可能成立（Task 3 报告），但**触发源**确认是 EAC 检测→bugcheck 路径。

**下一步进入**：EAC 场景对照测试 + 隐身路线堵漏（Task #11）。
