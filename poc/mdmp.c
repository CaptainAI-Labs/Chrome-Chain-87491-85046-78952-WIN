/* mdmp.c — 极简 minidump 异常解析：ExceptionStream(6) + ModuleList(4) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
typedef unsigned char u8; typedef unsigned short u16; typedef unsigned int u32; typedef unsigned long long u64;

int main(int argc, char** argv) {
  if (argc < 2) { printf("usage: mdmp <file.dmp>\n"); return 1; }
  FILE* f = fopen(argv[1], "rb");
  if (!f) { printf("open fail\n"); return 1; }
  u8* buf = (u8*)malloc(32 << 20); if (!buf) return 1;
  size_t n = fread(buf, 1, (32u << 20), f); fclose(f);
  if (memcmp(buf, "MDMP", 4)) { printf("not mdmp\n"); return 1; }
  u32 nStreams = *(u32*)(buf + 8), dirRva = *(u32*)(buf + 12);
  printf("streams=%u size=%zu\n", nStreams, n);
  u32 excRva = 0, modRva = 0, thrRva = 0;
  for (u32 i = 0; i < nStreams; i++) {
    u8* e = buf + dirRva + i * 12;
    u32 type = *(u32*)e, rva = *(u32*)(e + 8);
    if (type == 6) excRva = rva;
    if (type == 4) modRva = rva;
    if (type == 3) thrRva = rva;
  }
  if (!excRva) { printf("no exception stream\n"); return 1; }
  u8* ex = buf + excRva;
  u32 tid = *(u32*)ex;
  u32 code = *(u32*)(ex + 8);
  u64 addr = *(u64*)(ex + 24);
  u32 nParams = *(u32*)(ex + 32);
  printf("Exception tid=%u code=0x%08x addr=0x%llx nParams=%u\n", tid, code, addr, nParams);
  for (u32 i = 0; i < nParams && i < 6; i++)
    printf("  param[%u]=0x%llx\n", i, *(u64*)(ex + 40 + i * 8));
  u32 ctxSize = *(u32*)(ex + 160), ctxRva = *(u32*)(ex + 164);
  u8* ctx = buf + ctxRva;
  u64 rip = *(u64*)(ctx + 0xF8), rsp = *(u64*)(ctx + 0x98);
  printf("ctx: rip=0x%llx rsp=0x%llx rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx\n",
         rip, rsp, *(u64*)(ctx + 0x88), *(u64*)(ctx + 0x90), *(u64*)(ctx + 0xB0), *(u64*)(ctx + 0xB8));
  if (modRva) {
    u32 nMod = *(u32*)(buf + modRva);
    for (u32 i = 0; i < nMod && i < 400; i++) {
      u8* m = buf + modRva + 4 + i * 108;
      u64 base = *(u64*)m; u32 msize = *(u32*)(m + 8);
      u32 nameRva = *(u32*)(m + 20);
      u32 nameLen = (nameRva + 8 < n) ? *(u32*)(buf + nameRva) : 0; if (nameLen > 4096) nameLen = 0;
      char nm[64] = {0};
      for (u32 k = 0; k < nameLen / 2 && k < 63; k++)
        nm[k] = (char)*(u16*)(buf + nameRva + 4 + k * 2);
      int hit = (rip >= base && rip < base + msize);
      if (hit || i < 2 || (i%1==0 && i< 300))
        printf("mod[%u] %-28s base=0x%llx size=0x%llx%s\n", i, nm, base, (u64)msize, hit ? "  <-- RIP HERE" : "");
    }
  }
  /* Memory64ListStream(9): 挖 RIP 处指令字节 */
  for (u32 i = 0; i < nStreams; i++) {
    u8* e = buf + dirRva + i * 12;
    if (*(u32*)e != 9) continue;
    u64 m64Rva = *(u32*)(e + 8);
    u64 nRegions = *(u64*)(buf + m64Rva);
    u64 rvaCur = m64Rva + 8 + nRegions * 16;
    u8* want = 0; u64 wantOff = 0;
    for (u64 r = 0; r < nRegions; r++) {
      u64 start = *(u64*)(buf + m64Rva + 8 + r * 16);
      u64 dsz = *(u64*)(buf + m64Rva + 16 + r * 16);
      if (rip >= start && rip + 16 <= start + dsz) { want = buf + rvaCur + (rip - start); wantOff = rip - start; break; }
      rvaCur += dsz;
    }
    if (want) {
      printf("RIP code (region-off=0x%llx):\n", wantOff);
      for (int row = 0; row < 5; row++) {
        printf("  %+5d:", row * 16 - 32);
        for (int k = 0; k < 16; k++) printf(" %02x", want[-32 + row * 16 + k]);
        printf("\n");
      }
    } else printf("RIP code not in dump\n");
  }
  return 0;
  /* 搜 payload_w3.bin 特征定位 blob 绝对基址 */
  {
    FILE* pf = fopen("payload_w3.bin", "rb");
    if (pf) {
      static u8 sig[64]; int sigLen = (int)fread(sig, 1, 24, pf); fclose(pf);
      for (u32 i = 0; i < nStreams; i++) {
        u8* e = buf + dirRva + i * 12;
        if (*(u32*)e != 9) continue;
        u64 m64Rva = *(u32*)(e + 8);
        u64 nRegions = *(u64*)(buf + m64Rva);
        u64 rvaCur = m64Rva + 8 + nRegions * 16;
        for (u64 r = 0; r < nRegions; r++) {
          u64 start = *(u64*)(buf + m64Rva + 8 + r * 16);
          u64 dsz = *(u64*)(buf + m64Rva + 16 + r * 16);
          if (dsz > (24u << 20)) dsz = 0;
          u8* rbase = buf + rvaCur;
          for (u64 k = 0; k + 24 <= dsz; k += 4) {
            if (memcmp(rbase + k, sig, 24) == 0) {
              u64 absAddr = start + k;
              printf("BLOB FOUND abs=0x%llx rip-blob=%+lld\n", absAddr, (long long)(rip - absAddr));
            }
          }
          rvaCur += dsz;
        }
      }
    }
  }
  return 0;
}
