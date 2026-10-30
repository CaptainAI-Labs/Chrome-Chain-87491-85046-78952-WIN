#!/bin/bash
# rate_w4.sh N — 统计 v4 各阶段成功率与胜负
PKG="$(cd "$(dirname "$0")" && pwd)"; cd "$PKG"
N=${1:-30}
PORT=$(cat port.txt 2>/dev/null || echo 8765)
WPKG=$(cygpath -w "$PKG")
CHROME=$(cygpath -w "${CHROME_EXE:-C:\\pwn\\chrome54\\chrome-win64\\chrome.exe}")
S1=0; GET=0; AL=0; DEP=0; WIN=0; T0=$(date +%s)
PAT='young GC not observed|85046 bootstrap failed|descriptor discovery failed|private key discovery failed|code alias discovery failed|table entry|stale instance|instance isolation'
for i in $(seq 1 $N); do
  taskkill //IM ms64.exe //F >/dev/null 2>&1; taskkill //IM chrome.exe //F >/dev/null 2>&1
  taskkill //IM CalculatorApp.exe //F >/dev/null 2>&1; taskkill //IM notepad.exe //F >/dev/null 2>&1; sleep 1
  L=tmp/cl_W4_$i.log; rm -f "$L"; LOGF="$WPKG\\tmp\\cl_W4_$i.log"
  powershell.exe -NoProfile -Command "Start-Process '$CHROME' -ArgumentList ('--user-data-dir=$WPKG\\tmp\\tCH4$i','--no-first-run','--no-default-browser-check','--no-sandbox','--disable-features=RendererCodeIntegrity','--enable-logging','--log-file=$LOGF','http://127.0.0.1:$PORT/run_w4.html')" 2>/dev/null
  DEPLOYED=0
  for w in $(seq 1 10); do
    sleep 2
    grep -aq "DEPLOYED" "$L" 2>/dev/null && { DEPLOYED=1; break; }
    grep -aq "FAIL " "$L" 2>/dev/null && break
    tasklist 2>/dev/null | grep -qiE "CalculatorApp|notepad" && break
  done
  if tasklist 2>/dev/null | grep -qiE "CalculatorApp|notepad"; then
    WIN=$((WIN+1)); DEP=$((DEP+1)); echo "round$i WIN ($(( $(date +%s)-T0 ))s)"
    taskkill //IM CalculatorApp.exe //F >/dev/null 2>&1; taskkill //IM notepad.exe //F >/dev/null 2>&1
    continue
  fi
  if [ "$DEPLOYED" = "1" ]; then
    DEP=$((DEP+1))
    for t in $(seq 1 15); do sleep 2; tasklist 2>/dev/null | grep -qiE "CalculatorApp|notepad" && break; done
    if tasklist 2>/dev/null | grep -qiE "CalculatorApp|notepad"; then
      WIN=$((WIN+1)); echo "round$i WIN-late ($(( $(date +%s)-T0 ))s)"
      taskkill //IM CalculatorApp.exe //F >/dev/null 2>&1; taskkill //IM notepad.exe //F >/dev/null 2>&1
    else echo "round$i dep-miss"; fi
    continue
  fi
  R=$(grep -a "FAIL" "$L" 2>/dev/null | head -1 | grep -aoE "$PAT" | head -1)
  [ -z "$R" ] && R="other/$(grep -a FAIL "$L" 2>/dev/null | head -1 | cut -c1-50)"
  case "$R" in
    "young GC not observed"|"85046 bootstrap failed") S1=$((S1+1));;
    descriptor*|private*|table*|stale*|instance*) GET=$((GET+1));;
    code*) AL=$((AL+1));;
  esac
  echo "round$i fail: $R"
done
echo "=== $N rounds: WIN=$WIN DEPLOY=$DEP stage1=$S1 getter=$GET alias=$AL total=$(( $(date +%s)-T0 ))s ==="
