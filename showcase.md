# 从一个网页到沙箱外的计算器
### CVE-2026-87491 ⊕ CVE-2026-85046 ⊕ CVE-2026-78952 · Chrome 三 CVE 全链研究展示

> **靶标**：Chrome for Testing 152.0.7977.54 x64 · Windows 10 19045 / Win11 26300 · Defender 实时防护 + 行为监控全开
> **性质**：授权隔离研究环境下的公开 n-day 复现研究，所有目标均为本地测试构建
> **伴侣文档**：本文件为 [`showcase.html`](showcase.html) 展示页的 Markdown 版；技术全量见 [`report.md`](report.md)

**最终形态**：受害者只需访问一个网页。约 2 分钟内，计算器从**非沙箱的 crashpad-handler 进程**中弹出。stage-2（竞态器 + 恶意 DLL）由 payload 用系统 curl **从页面同源服务器自动拉取**——目标机零预置、零硬编码路径。

| 指标 | 数值 | 口径 |
|---|---|---|
| 整链胜率 | **43%** / 轮 | 30 轮终测（13/30） |
| 到达部署 | **83%** | 25/30 轮 |
| 期望取胜 | **~2.3 轮** | 概率结构：stage1 × 竞态两处固有随机 |
| 硬编码路径 | **0** | origin / chrome 路径 / TEMP 全部运行期自取 |
| 最近复跑 | **round4 / 109s** | 2026-11-11 本机复现取胜 |

---

## 1. 三块拼图

每个漏洞只贡献一段原语，单独都不足以越界——拼接后才构成「网页 → OS 沙箱外代码执行」的完整通路。

### ① CVE-2026-87491 · V8（ITW / KEV）— sort 比较器混淆 + 私有异常符号伪造

- **形态一（addrof）**：比较器在排序中途 `fill(0)` 清空数组，V8 内联 sort 缓存的元素指针与写回类型失配，HeapObject 指针被按 Smi 解出。
- **形态二（RX 别名之钥）**：伪造 wasm 私有异常符号 getter，在 optimized 无副作用窗口换共享跳表 → mixed dispatch 用过期 trusted instance 执行 → memory index 6 越界槽位解析为跳表指针，wasm 代码区形成可读可写别名。
- **产出**：`addrof` → `wasm 代码区读写别名`
- Windows 适配：必须内联脚本结构；V8 map 常量（`DOUBLE_MAP=0x01032879`）由 addrof 探针实测、随 build 锁定。

### ② CVE-2026-85046 · V8（ITW / KEV 2026-09）— 写屏障跳过 → 假对象回收

- **根因**：内联 sort 对多态反馈求 elements-kind **并集**（= PACKED）。并集对「读」是安全上界、对「写回」是危险窄化——回调窄化回 PACKED_SMI 后 CheckMaps 照过，HeapObject 指针被写进 Smi 数组且**跳过写屏障**。
- **利用**：年轻代 GC 一瞬的窗口——GC 移动对象后旧指针滞留新空间，在旧指针位置喷射假 JSArray 头（map=PACKED_DOUBLE），回收内存被当 double 数组复用 → 与 victim 共享 elements 的 **cage 任意读写**。
- **引入/修复**：`v8@66a3f1e9`（2026-04-27）→ `v8@e0562d87`（152.0.7977.82，2026-09-03）。
- **概率特征**：必须 fresh renderer（脏堆 reload 仅 ~3%）；30 轮终测 stage1 失败仅 2 轮。
- Linux 侧同根因独立验证：cage 读写 6/6 · cage 逃逸 3/3 · 渲染器 ACE 10/10。

### ③ CVE-2026-78952 · crashpad（信任边界）— ReadUpTo 无钳位重试溢出

- **错误本质**：① 非沙箱的 crashpad-handler 无条件信任客户端 PE 节 "CPADinfo" 声明的 `extra_memory_ranges`；② `ProcessMemoryWin::ReadUpTo` 撞页重试时**不把长度钳位回调用方 size**。
- **产出**：`SMMW 模板劫持` → `handler 内 LoadLibraryW` = OS 沙箱逃逸。

---

## 2. 全链路：渲染层 ACE → 沙箱逃逸

四条泳道、两次边界穿越（第一次：进程创建离开渲染器；第二次：crashpad 信任进入非沙箱进程——后者才是 OS 沙箱逃逸）：

```
恶意网页（同源服务器）
  ① CVE-2026-87491  sort() 比较器混淆 ─────────► addrof
  ② CVE-2026-85046  写屏障跳过/假对象回收 ─────► V8 cage 任意读写
  ③ wasm 私有异常符号伪造 ────────────────────► 跳表别名 → RX 代码区可写
        │  部署 2.6KB 机器码（字节级校验 bad4=0）+ 注入 location.origin
        ▼  渲染进程 ACE ✔
  ④ payload：PEB→IAT 自取 kernel32 → 5 个已加载导出
        curl.exe 同源拉取 poc.exe+evil.dll 到 %TEMP%（Defender 放行）
        CreateProcessA 启动竞态器 → 自旋 1s → 主动崩溃（0xDEAD0021）
        ▼
  ⑤ CVE-2026-78952  ReadUpTo 无钳位重试溢出
        翻页微脉冲 × 0x168/0xB8 溢出 → SMMW 模板劫持
        → Flush 派发 LoadLibraryW(ev64.dll) → calc 弹出
        ▼  OS 沙箱逃逸 ✔
```

**Console 判据链**（每级有独立验收标记）：

```
GCDBG sane=true → ST1 cage_rw ready · proof 13.37=13.37
→ ALIAS OK body=0x1980 → WROTE blob → VERIFY bad4=0
→ ORIGIN-OK=true · DEPLOYED →（渲染器主动崩溃）
→ [dbgwrap] WAW#0 cs_=plant+0x10 → Flush → LoadLibraryW → calc ✔
```

---

## 3. 研究过程：四个阶段

### 3.1 漏洞探测 · 候选矩阵与版本窗口

同窗口期 n-day 逐个排雷（触发面可达 / 与链内零交集 / 修复版本锁定）：

| 候选 | 一句话甄别结论 | 裁决 |
|---|---|---|
| CVE-2026-85046 ⊕ 87491 | sort 归约 M149+，与 5281 零交集；一个供 cage R/W、一个供 native 执行，结构互补 | ✅ 入选 · 本链 |
| CVE-2026-5281 | Dawn AsyncTask UAF → GPU 进程执行（UNTRUSTED→LOW），零交集 | 🔵 独立成链 |
| CVE-2026-11645 | TryFastAddDataProperty 元表越界写，窗口 A'（M144–149.0.7827.x）错开 | 🔵 独立成链 |
| CVE-2026-5279 | 同批带病，Windows 发布版触发面被 parser 遮蔽（6 构建实测） | ❌ 弃用 |
| CVE-2025-6554 | TurboFan 混淆（ITW 2025-06）Linux/Android 完整复现；Windows 侧退化 libpcap DoS | ❌ 本链弃用 |
| CVE-2026-78952 | crashpad 溢出，唯一「跨进程信任边界」类错误——天然收尾件 | ✅ 入选 · 收尾 |

### 3.2 链路梳理 · 原语阶梯与依赖图

- 原语阶梯：`addrof ⊕ cage R/W ⊕ RX 别名 → 渲染层 ACE → curl 桥接 → 竞态 → OS 逃逸`，每级独立验收。
- bagel 双 bug 结构（上游两报 $1,000 + $2,500，均 ITW/KEV）：**87491 需要 cage 读写才有意义，85046 恰好是它的供应商**。
- Linux 侧先用 152.0.7977.75 验证双 bug 链（`PWNED 2026` · `restored:true` · 首试即中），再移植 Windows 收官。

### 3.3 漏洞定位 · 三个根因，三种下钻法

| 漏洞 | 下钻法 | 结论 |
|---|---|---|
| 85046 | patch-diff 对读 | 引入 `v8@66a3f1e9` → 修复 `e0562d87`；并集 kind 对写回是危险窄化 |
| 87491 | IR 对比 | 私有异常符号 mixed dispatch → `A.tiering_budgets[2]` OOB → mi=6 槽位=跳表指针 |
| 78952 | 信标尸检法 | payload 每个早退点写 `0xDEAD00xx` 故意崩溃，自写 `mdmp.c` 解析 minidump——**崩溃地址=进度报告** |

### 3.4 利用链路研究 · 从「能打通」到 43%

- **部署三重门禁**：marker 回读 → body ∈ [0x1300, 0xE000] → 整 blob 字节校验 `VERIFY bad4=0`。
- **payload 三原则**：零常量（PEB→IAT 自取，重启免疫）· 零遍历（页对齐向下扫 MZ）· 零新 DLL（只用已加载导出，逐个 expchk 验证非转发器）。
- **关键修复「主动崩溃」**：payload 返回≠渲染器死——原生自旋 1s 后写 `0xDEAD0021` 主动崩溃送出竞态起跑信号，此项直接把胜率拉回并反超。
- **30 轮归因**：`WIN=13 DEPLOY=25 stage1=2 getter=0 alias=0`——桥接环节 100% 化，剩余漏损全在两处固有随机。

---

## 4. AI 自主工作流

研究由一条六阶段自治流水线推进：Orchestrator 分解目标 DAG → 四路侦察并行扇出 → 情报汇总收敛选型（6 候选 → 1 组合）→ 根因下钻 → 链路规划 → 三路并行构建（stage1 / 别名部署 / 武器化）→ 稳定性归因 → Verifier 三重门禁；未过门禁自动回环（重新规划 / 修复迭代）——人类只审证据：

```
研究目标（网页 → 渲染层 ACE → OS 沙箱逃逸）
        │
┌───────▼────────────────────────────────────┐
│ ORCHESTRATOR · 任务分解 / DAG 编排 / 回环调度 │
└──┬─────────┬─────────┬─────────┬───────────┘
   ▼         ▼         ▼         ▼        Ⅰ 侦察扇出
 RECON-1   RECON-2   RECON-3   ENV-PROBE
 候选矩阵   版本窗口   CL 挖矿   Defender 实测
   └─────────┴────┬────┴─────────┘
                  ▼                       Ⅱ 情报汇总
 ══════════ INTEL MERGE · 选型收敛 ══════════
        6 候选 → 85046⊕87491 ⊕ 78952
                  ▼                       Ⅲ 根因下钻
          ROOT-CAUSE（patch-diff · IR/gdb · 信标尸检）
                  ▼                       Ⅳ 链路规划
          CHAIN-PLANNER（原语阶梯 · 零交集 · 里程碑门禁）
     ┌────────────┼────────────┐
     ▼            ▼            ▼            Ⅴ 并行构建
 BUILDER·STAGE1  BUILDER·别名部署  WEAPONIZER
 85046→cage RW ─► 87491 别名+部署 ─► v1→v4 · curl 落地
 proof 13.37      VERIFY bad4=0    AV 矩阵选型
     └─────────┬──┴────────┬─────┘
               ▼           │                Ⅵ 归因验收
        STABILITY ─────────┘
        30 轮 A/B 归因 · 竞态调优
               ▼
        VERIFIER · JUDGE（bad4=0 · 字节一致 · WIN 签名）
          │                        │
          │ 未过门禁：↺ 重新规划 / ↺ 修复迭代
          │                        │ 通过 → EVIDENCE VAULT
          │                        ▼（evidence/ · report.md · 统计）
```

**运行轨迹摘录**（agent 消息 × 真实 console 标记）：

```
[orch]    目标分解 → 侦察扇出 ×3（CVE 矩阵 / 版本窗口 / 上游 CL）
[recon-2] 85046+87491 与 5281 零交集 · sort 归约 M149+ → 可组链 ✓
[root]    85046 根因：union-kind 写回——并集对读安全、对写危险 ▲
[chain]   原语阶梯：addrof ⊕ cage R/W ⊕ RX 别名 → ACE → 桥接 → 竞态
[build]   ST1 cage_rw ready · proof 13.37=13.37 ✓
[build]   ALIAS OK body=0x1980 → WROTE blob → VERIFY bad4=0 ✓
[stab]    30 轮归因：WIN=13 DEPLOY=25 · stage1 失败仅 2
[judge]   门禁通过 → 证据归档 · FULL-CHAIN WIN ✓
```

工作流四原则：**扇出侦察**（并行不阻塞）· **证据优先**（推测不进链）· **自校验门禁**（过不了不进下一阶段）· **失败即数据**（死路转护栏）。

---

## 5. 武器化演进：四代生死簿

| 代 | 方案 | 结局 | 胜率 |
|---|---|---|---|
| v1 | 渲染器内 `LoadLibraryW("C:\pwn\launch64.dll")` | ✅ 可跑，但 3 处硬编码本地路径 | 29% |
| v2 | certutil 链式下载 | ❌ Defender **进程创建层**拦截（gle=5）——拦命令行模式，不拦映像 | ✗ |
| v3 | 页面内嵌 64KB 逐 4 字节写 RX | ⚠️ 功能全通（%TEMP% 字节级一致）但垫函数 10→130 扰动 V8 堆布局 | 3% |
| v4 ★ | 系统 curl.exe 一次拉双文件 | ✅ blob 仅 2.6KB · 原版模块一字不动 · 零硬编码零预置 | **43%** |

AV 拦截矩阵（同一台机器同一分钟实测）：certutil ❌ 进程创建层拦截 · curl ✔ 三变体全放行 · 渲染器内 LoadLibraryW 新 DLL = 自杀（损坏堆上初始化即崩）。

---

## 6. 终局竞态：78952 三拍

1. **微脉冲**：6 个内核线程把目标页在 `PAGE_NOACCESS ↔ PAGE_READWRITE` 间翻转。
2. **ReadUpTo 无钳位**：请求 0xB8，撞页重试读出 **0x168** → 溢出 0xB0 盖到相邻 SMMW 对象。
3. **派发**：模板劫持 → `Next()` 把 victim 页 memcpy 进 handler `.data`（plant 区 `[Q]=DLL名 / [Q+8]=LoadLibraryW`）→ `Flush()` 尾部 CFG 派发 **LoadLibraryW** ✓。

命中签名：`[dbgwrap] WAW#0 cs_=plant+0x10`；部署后胜率 13/25（剩余漏损=iters=8 固有窗口）。

---

## 7. 战果与证据

**30 轮分阶段归因**：`WIN=13 DEPLOY=25 stage1=2 getter=0 alias=0 total=1451s`（平均 48s/轮）。2026-10-20 与 2026-11-11 两次本机复跑均取胜（最近一次 round4 / 109s）。

### 实拍证据

| 证据 | 说明 | 文件 |
|---|---|---|
| 全链取胜实拍 | 渲染器按计划崩溃页 + calc 从非沙箱 handler 弹出（2026-11-11 复跑 round4/109s） | [POC_ONECLICK_WIN.png](evidence/POC_ONECLICK_WIN.png) |
| 全链胜（10-20 归档） | 2026-10-20 复现取胜现场 | [POC_FULLCHAIN_WIN_REPRO_20261020.png](evidence/POC_FULLCHAIN_WIN_REPRO_20261020.png) |
| 架构图 ×5 · AI 绘制 | 总架构 / RX 别名 / IAT 自解析 / 武器化矩阵 / 78952 竞态 | [evidence/figs/](evidence/figs/) |
| 胜轮日志 + 30 轮统计 | console trail 与分阶段归因 | [console_win_round23.txt](evidence/console_win_round23.txt) · [rate_w4_30rounds.txt](evidence/rate_w4_30rounds.txt) |

### 防御视角

1. `ReadUpTo` 重试长度**必须钳位**到调用方 size；handler 不应无条件信任 `extra_memory_ranges`。
2. 87491/85046 侧：比较器重入后重校验元素类型；写屏障不可跳过（上游已修）。
3. 检测本质：**命令行特征是补丁式的**（certutil 被拦而 curl 放行）——进程创建审计（渲染器→curl→exe→handler 链）更可靠。
4. IOC：崩溃地址 `0xDEAD00xx` 即信标 · 渲染器子进程出现 curl + 同源下载 · `%TEMP%` 出现 ms64/ev64/msdb 组合 · crashpad WAW 竞态痕迹。

### 复现

```bash
cd poc
./run_chain.sh        # 一键到胜（默认 60 轮；runner 自动拉起）
./rate_w4.sh 30       # 可选：分阶段成功率统计
```

---

*本工作为授权隔离研究环境下的公开研究复现，所有目标均为本地测试构建（Chrome for Testing）。上游致谢：85046 — Salvatore Gulizia（Serotav）· 87491 — Jihyeon Jeong（Compsec Lab, SNU）。*
