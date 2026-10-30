/* expchk.c — 检查 kernel32 目标导出是真实函数还是 kernelbase 转发器 */
#include <stdio.h>
#include <windows.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned short u16; typedef unsigned long long u64;

static void chk(u64 mod, u32 expRva, const char* want) {
  u32* exp = (u32*)(mod + expRva);
  u32 nNames = exp[6], funcsRva = exp[7], namesRva = exp[8], ordsRva = exp[9];
  u32* names = (u32*)(mod + namesRva);
  u32* funcs = (u32*)(mod + funcsRva);
  u16* ords = (u16*)(mod + ordsRva);
  /* export dir 覆盖范围: expRva .. expRva+size(exp[11]) */
  u32 dirEnd = expRva + exp[11];
  for (u32 i = 0; i < nNames; i++) {
    const char* n = (const char*)(mod + names[i]);
    const char* w = want;
    while (*w && *n == *w) { n++; w++; }
    if (*w || *n) continue;
    u32 rva = funcs[ords[i]];
    const char* fwd = (rva >= expRva && rva < dirEnd) ? (const char*)(mod + rva) : NULL;
    printf("%-20s rva=%08x  %s%s%s\n", want, rva,
           fwd ? "FORWARDER -> " : "REAL", fwd ? fwd : "", "");
    return;
  }
  printf("%-20s NOT FOUND\n", want);
}

int main(void) {
  u64 mod = (u64)GetModuleHandleA("kernel32.dll");
  u32 lfa = *(u32*)(mod + 0x3C);
  u32* pe = (u32*)(mod + lfa);
  u32* opt = (u32*)((u8*)pe + 0x18);
  u32 expRva = *(u32*)((u8*)opt + 0x70);
  printf("kernel32 base=%llx expRva=%x size=%x\n", mod, expRva, *(u32*)((u8*)expRva ? (mod + expRva + 44) : 0));
  const char* names[] = {
    "GetTempPathA", "GetModuleFileNameA", "CreateProcessA",
    "CreateFileA", "WriteFile", "CloseHandle", "CreateDirectoryA",
    "LoadLibraryW", "WinExec", "GetLastError", "WaitForSingleObject", "Sleep",
  };
  for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) chk(mod, expRva, names[i]);
  return 0;
}
