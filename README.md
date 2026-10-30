# 链内导航 — 网页 → 渲染层 ACE → crashpad handler OS 沙箱逃逸（chain-87491-85046-78952）

**一句话原理**：恶意网页用 CVE-2026-87491（sort 比较器混淆→addrof）+ CVE-2026-85046
（写屏障跳过→V8 cage 任意读写）+ wasm 私有异常符号伪造（跳表别名→RX 可写）拿到渲染
进程 ACE，部署 2.6KB payload 用 curl 同源拉起竞态器；竞态器以 CVE-2026-78952
（crashpad `ReadUpTo` 无钳位重试溢出）翻页微脉冲 × 0x168/0xB8 溢出劫持 SMMW 模板，
让**非沙箱的 crashpad-handler 进程**派发 `LoadLibraryW(evil.dll)` → calc+notepad 弹出
= OS 沙箱逃逸（沙箱外任意代码执行）。

## 状态

| 目标 | 结果 |
|---|---|
| Chrome for Testing **152.0.7977.54** x64（本链全部 V8/chrome 常量按此 build 锁定） | ✅ **CALC_POPPED**（calc+notepad 双开花，从 crashpad-handler 弹出） |
| 成功率（30 轮实测，原环境） | 整链 43%/轮（13/30）、到达部署 83%（25/30），期望 ~2.3 轮出 calc |

> 该链为**已完整完成**的链路（另一台机器收官），本仓整理 + 复现归档。
> 目标版本 152.0.7977.54 属窗口 B 后段（M152），涉及 CVE-2026-87491 / 85046 / 78952。

## 复现（自包含，零硬编码本地路径）

```bash
cd windows/chain-87491-85046-78952-WIN/poc

# 一键到胜：自动拉起 runner(本地 HTTP) + 循环直到 calc/notepad 弹出
./run_chain.sh              # 默认 60 轮；./run_chain.sh 30 限定轮数
./rate_w4.sh 30             # 可选：分阶段成功率统计
```

- 目标 chrome 解析顺序：`CHROME_EXE` 环境变量 → 仓库
  `windows/shared/chrome/chrome-win64-152.0.7977.54/chrome-win64/chrome.exe`（自动）；
- stage-2（poc.exe+evil.dll）由 payload 用系统 curl 从页面同源服务器拉到 `%TEMP%`，
  目标机零预置；origin/chrome 路径/TEMP 全部运行期自取；
- 运行残留（chrome profile、runner 日志、端口文件）落
  `logs/lab-residue/run/`，过程日志落 `logs/cl_W_*.log`。

**预期输出**：`round1 fail-fast`（概率阶段未中，正常）→ … →
`=== FULL-CHAIN WIN roundN — calc/notepad 已弹出 ===`，桌面弹出 Calculator + Notepad
（双开花用于与手工窗口区分；驱动脚本每轮开跑前清场防误报）。

## 目录结构（仓库五件套）

```
chain-87491-85046-78952-WIN/
├─ README.md            # 本文件（链内导航）
├─ report.md            # 技术报告（三 CVE 原理/武器化四代演进/19 坑博物馆/防御视角）
├─ poc/                 # 自包含复现包
│   ├─ run_chain.sh     # ★ 一键驱动（主链 run_w4.html）
│   ├─ rate_w4.sh       # 成功率统计（分阶段归因）
│   ├─ run_w4.html      # 入口页（stage1w + payload_embed_w4 + pocwin_full_w4）
│   ├─ stage1w.js       # CVE-2026-87491 + 85046 → cage 任意读写
│   ├─ pocwin_full_w4.js# wasm 跳表别名发现 + blob 部署校验(VERIFY bad4=0) + origin 注入
│   ├─ payload_src_w4.c → payload_embed_w4.js / payload_w4.bin
│   │                    # 渲染器 shellcode（curl 落地版 2.6KB；embed 自动生成）
│   ├─ poc.exe / evil.dll# stage-2 竞态器 + 终局 DLL（同源提供，curl 自动拉取）
│   ├─ runner.c / runner.exe  # 本地 HTTP 服务（已去硬编码：路径全 exe/CWD 相对）
│   ├─ mdmp.c / expchk.c / w4test.c  # minidump 解析 / 导出转发器检查 / payload 宿主回归
│   ├─ build_w3.sh      # payload 构建+embed 生成流水线参考
│   └─ archive/         # 研究存档（v1 本地 DLL / v2 certutil / v3 页面内嵌 / RX 探测页）
├─ report.md
├─ evidence/            # 取证归档
│   ├─ POC_*.png        # 实拍证据截图 ×4（一键包/全链胜/渲染层 ACE/重启复胜）
│   ├─ console_win_round23.txt + rate_w4_30rounds.txt  # 胜轮日志 + 30 轮统计
│   └─ figs/            # 架构图 ×5（总架构/别名/IAT/武器化演进/78952 竞态）
└─ logs/                # 过程日志 + lab-residue/（历次运行残留）
```

## 排障

| 症状 | 原因/解法 |
|---|---|
| 每轮都 `fail-fast` | stage1 概率低谷。确认 runner 存活：`curl http://127.0.0.1:<port>/run_w4.html` 应 200 |
| `dep-miss` 连刷 | 概率性竞态未中，属正常；看 `%TEMP%\ms64.exe/ev64.dll` 是否落盘（在=curl 链正常） |
| Chrome 起不来 | 残留僵尸：先 `taskkill /IM ms64.exe /F` 再 `taskkill /IM chrome.exe /F`（顺序反了会卡） |
| 想看链路每步 | 打开 `logs/cl_W_*.log`，按 GCDBG→ST1→BOOT→ALIAS OK→PRE-DEPLOY→WROTE→VERIFY→ORIGIN-OK→DEPLOYED 顺序看 |
| 分析崩溃 dump | `poc/mdmp.exe <profile>/Crashpad/reports/*.dmp`（0xDEAD00xx=payload 信标） |

## 免责

授权隔离研究环境专用；所有目标为本地测试构建。
