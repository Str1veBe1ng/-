# 课时04 IAT Hook

## 一、课程目标

本节课主要学习IAT Hook技术，这是Windows平台上一种常见的Hook方法。通过本课的学习，你将能够：

1. 理解IAT（Import Address Table）的基本概念和结构
2. 掌握IAT Hook的实现原理和技术细节
3. 实现一个完整的IAT Hook框架
4. 理解IAT Hook在程序监控和安全防护中的应用
5. 学习IAT Hook的检测和防护方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| IAT | Import Address Table，导入地址表，存储程序导入函数的实际地址 |
| ILT | Import Lookup Table，导入查找表，存储导入函数的名称或序号 |
| PE文件 | Portable Executable，Windows平台上的可执行文件格式 |
| RVA | Relative Virtual Address，相对虚拟地址，相对于模块基址的偏移 |
| 导入函数 | 程序从其他DLL中引用的函数 |
| DLL注入 | 将DLL加载到目标进程地址空间的技术 |
| API监控 | 监控程序调用API函数的行为 |

## 三、技术原理

### 3.1 IAT概述

IAT（Import Address Table，导入地址表）是PE文件格式中的一个重要组成部分。当程序需要调用外部DLL中的函数时，Windows加载器会将这些函数的实际地址填入IAT中。程序在运行时通过IAT来调用这些导入函数。

### 3.2 IAT结构

在PE文件中，IAT相关的结构包括：

1. **IMAGE_IMPORT_DESCRIPTOR**：导入表描述符，每个DLL对应一个
2. **FirstThunk**：指向IAT的指针
3. **OriginalFirstThunk**：指向ILT的指针（在绑定导入时可能为0）

### 3.3 IAT Hook原理

IAT Hook通过修改IAT中函数地址来实现Hook功能：
1. 找到目标DLL和函数在IAT中的位置
2. 备份原始函数地址
3. 将IAT中的地址修改为我们自定义函数的地址
4. 当程序调用该函数时，实际执行的是我们的Hook函数

### 3.4 IAT Hook的优势和劣势

**优势**：
- 实现相对简单
- 不修改目标函数代码
- 对目标程序影响小
- 可以Hook所有对该函数的调用

**劣势**：
- 只能Hook导入函数
- 容易被检测到
- 对于延迟加载的DLL无效
- 可能影响其他使用相同DLL的模块

## 四、代码实现

### 4.1 核心数据结构

```cpp
#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>
#pragma comment(lib, "imagehlp.lib")

// IAT Hook信息结构体
typedef struct _IAT_HOOK_INFO {
    CHAR		szModuleName[64];		// 模块名称
    CHAR		szFunctionName[64];		// 函数名称
    PVOID		pOriginalFunc;			// 原始函数地址
    PVOID		pHookFunc;				// Hook函数地址
    PVOID*		ppIATEntry;				// IAT条目地址
    BOOL		bIsHooked;				// 是否已Hook
} IAT_HOOK_INFO, * PIAT_HOOK_INFO;

// IAT Hook管理器
typedef struct _IAT_HOOK_MANAGER {
    IAT_HOOK_INFO*	pHooks;				// Hook信息数组
    INT				nHookCount;			// Hook数量
} IAT_HOOK_MANAGER, * PIAT_HOOK_MANAGER;
```

### 4.2 PE解析辅助函数

```cpp
// 获取模块基址
HMODULE GetRemoteModuleHandle(HANDLE hProcess, LPCSTR lpModuleName) {
    HMODULE hModules[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (UINT i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            CHAR szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hModules[i], szModName, sizeof(szModName))) {
                // 检查模块名是否匹配
                if (strstr(szModName, lpModuleName)) {
                    return hModules[i];
                }
            }
        }
    }
    
    return NULL;
}

// 获取函数地址
FARPROC GetRemoteProcAddress(HANDLE hProcess, HMODULE hModule, LPCSTR lpProcName) {
    return GetProcAddress(hModule, lpProcName);
}
```

### 4.3 IAT Hook核心实现

```cpp
// 查找IAT条目
PVOID* FindIATEntry(HMODULE hModule, LPCSTR lpModuleName, LPCSTR lpFunctionName) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
    
    // 获取导入表
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hModule +
        pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    // 遍历导入表
    while (pImportDesc->Name) {
        LPCSTR lpCurrModName = (LPCSTR)((PBYTE)hModule + pImportDesc->Name);
        
        // 检查模块名是否匹配（不区分大小写）
        if (_stricmp(lpCurrModName, lpModuleName) == 0) {
            // 获取IAT和ILT
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->FirstThunk);
            PIMAGE_THUNK_DATA pOrigThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->OriginalFirstThunk);
            
            // 遍历导入函数
            while (pOrigThunk->u1.AddressOfData) {
                // 获取函数名称
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)hModule + pOrigThunk->u1.AddressOfData);
                    
                    // 检查函数名是否匹配
                    if (strcmp(pImportByName->Name, lpFunctionName) == 0) {
                        return (PVOID*)&pThunk->u1.Function;
                    }
                }
                
                pThunk++;
                pOrigThunk++;
            }
        }
        
        pImportDesc++;
    }
    
    return NULL;
}

// 安装IAT Hook
BOOL InstallIATHook(PIAT_HOOK_INFO pHookInfo) {
    if (!pHookInfo || !pHookInfo->szModuleName[0] || !pHookInfo->szFunctionName[0] || !pHookInfo->pHookFunc) {
        return FALSE;
    }
    
    HMODULE hModule = GetModuleHandle(NULL);  // 当前模块
    if (!hModule) {
        return FALSE;
    }
    
    // 查找IAT条目
    pHookInfo->ppIATEntry = FindIATEntry(hModule, pHookInfo->szModuleName, pHookInfo->szFunctionName);
    if (!pHookInfo->ppIATEntry) {
        printf("Failed to find IAT entry for %s!%s\n", pHookInfo->szModuleName, pHookInfo->szFunctionName);
        return FALSE;
    }
    
    // 备份原始函数地址
    pHookInfo->pOriginalFunc = *pHookInfo->ppIATEntry;
    
    // 修改内存保护属性
    DWORD oldProtect;
    if (!VirtualProtect(pHookInfo->ppIATEntry, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    // 修改IAT条目
    *pHookInfo->ppIATEntry = pHookInfo->pHookFunc;
    
    // 恢复内存保护属性
    VirtualProtect(pHookInfo->ppIATEntry, sizeof(PVOID), oldProtect, &oldProtect);
    
    pHookInfo->bIsHooked = TRUE;
    return TRUE;
}

// 卸载IAT Hook
BOOL UninstallIATHook(PIAT_HOOK_INFO pHookInfo) {
    if (!pHookInfo || !pHookInfo->bIsHooked) {
        return FALSE;
    }
    
    // 修改内存保护属性
    DWORD oldProtect;
    if (!VirtualProtect(pHookInfo->ppIATEntry, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    // 恢复原始函数地址
    *pHookInfo->ppIATEntry = pHookInfo->pOriginalFunc;
    
    // 恢复内存保护属性
    VirtualProtect(pHookInfo->ppIATEntry, sizeof(PVOID), oldProtect, &oldProtect);
    
    pHookInfo->bIsHooked = FALSE;
    return TRUE;
}
```

### 4.4 IAT Hook管理器

```cpp
// 初始化IAT Hook管理器
PIAT_HOOK_MANAGER InitIATHookManager() {
    PIAT_HOOK_MANAGER pManager = (PIAT_HOOK_MANAGER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IAT_HOOK_MANAGER));
    if (!pManager) {
        return NULL;
    }
    
    return pManager;
}

// 添加Hook
BOOL AddIATHook(PIAT_HOOK_MANAGER pManager, LPCSTR lpModuleName, LPCSTR lpFunctionName, PVOID pHookFunc) {
    // 重新分配内存
    PIAT_HOOK_INFO pNewHooks = (PIAT_HOOK_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        pManager->pHooks, sizeof(IAT_HOOK_INFO) * (pManager->nHookCount + 1));
    if (!pNewHooks) {
        return FALSE;
    }
    
    pManager->pHooks = pNewHooks;
    
    // 填充Hook信息
    PIAT_HOOK_INFO pHook = &pManager->pHooks[pManager->nHookCount];
    strcpy_s(pHook->szModuleName, sizeof(pHook->szModuleName), lpModuleName);
    strcpy_s(pHook->szFunctionName, sizeof(pHook->szFunctionName), lpFunctionName);
    pHook->pHookFunc = pHookFunc;
    pHook->bIsHooked = FALSE;
    
    // 安装Hook
    if (!InstallIATHook(pHook)) {
        return FALSE;
    }
    
    pManager->nHookCount++;
    return TRUE;
}

// 移除所有Hook
VOID RemoveAllIATHooks(PIAT_HOOK_MANAGER pManager) {
    if (!pManager) {
        return;
    }
    
    // 卸载所有Hook
    for (INT i = 0; i < pManager->nHookCount; i++) {
        UninstallIATHook(&pManager->pHooks[i]);
    }
    
    // 释放内存
    if (pManager->pHooks) {
        HeapFree(GetProcessHeap(), 0, pManager->pHooks);
    }
    
    HeapFree(GetProcessHeap(), 0, pManager);
}
```

### 4.5 示例Hook函数

```cpp
// 示例：Hook MessageBoxW函数
typedef int (WINAPI* MessageBoxW_t)(HWND, LPCWSTR, LPCWSTR, UINT);
MessageBoxW_t g_pOriginalMessageBoxW = NULL;

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    // 记录调用信息
    wprintf(L"[IAT Hook] MessageBoxW called: %s\n", lpText);
    
    // 可以修改参数
    return g_pOriginalMessageBoxW(hWnd, L"[Hooked] Modified Text", lpCaption, uType);
}

// 示例：Hook Sleep函数
typedef void (WINAPI* Sleep_t)(DWORD);
Sleep_t g_pOriginalSleep = NULL;

void WINAPI MySleep(DWORD dwMilliseconds) {
    // 记录调用信息
    printf("[IAT Hook] Sleep called for %lu milliseconds\n", dwMilliseconds);
    
    // 可以修改行为，例如缩短睡眠时间
    g_pOriginalSleep(dwMilliseconds / 2);
}

// 使用示例
VOID DemoIATHook() {
    // 初始化Hook管理器
    PIAT_HOOK_MANAGER pManager = InitIATHookManager();
    if (!pManager) {
        printf("Failed to initialize IAT Hook manager.\n");
        return;
    }
    
    // 添加MessageBoxW Hook
    if (AddIATHook(pManager, "user32.dll", "MessageBoxW", (PVOID)MyMessageBoxW)) {
        printf("MessageBoxW IAT Hook installed successfully.\n");
        // 保存原始函数地址
        // 注意：在实际实现中，我们需要通过Hook信息结构获取原始地址
    }
    
    // 添加Sleep Hook
    if (AddIATHook(pManager, "kernel32.dll", "Sleep", (PVOID)MySleep)) {
        printf("Sleep IAT Hook installed successfully.\n");
    }
    
    // 测试Hook效果
    MessageBoxW(NULL, L"Original Message", L"Test", MB_OK);
    Sleep(2000);  // 睡眠2秒，但实际只会睡1秒
    
    // 清理Hook
    RemoveAllIATHooks(pManager);
    printf("All IAT Hooks removed.\n");
}
```

### 4.6 远程进程IAT Hook

```cpp
// 在远程进程中安装IAT Hook
BOOL InstallRemoteIATHook(HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpFunctionName, PVOID pHookFunc, PVOID* ppOriginalFunc) {
    // 获取目标进程模块句柄
    HMODULE hTargetModule = GetRemoteModuleHandle(hProcess, lpModuleName);
    if (!hTargetModule) {
        return FALSE;
    }
    
    // 获取目标进程中函数地址
    FARPROC pTargetFunc = GetRemoteProcAddress(hProcess, hTargetModule, lpFunctionName);
    if (!pTargetFunc) {
        return FALSE;
    }
    
    // 在目标进程中查找IAT条目
    // 注意：这需要在目标进程中执行，或者使用更复杂的解析方法
    // 此处为简化实现，仅展示思路
    
    // 修改目标进程内存
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, /* IAT条目地址 */, &pHookFunc, sizeof(PVOID), &bytesWritten);
}

// DLL注入实现IAT Hook
BOOL InjectDLLForIATHook(LPCSTR lpProcessName, LPCSTR lpDllPath) {
    // 1. 获取目标进程句柄
    HWND hwnd = FindWindowA(NULL, lpProcessName);
    if (!hwnd) {
        return FALSE;
    }
    
    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        return FALSE;
    }
    
    // 2. 在目标进程中分配内存
    SIZE_T dllPathLen = strlen(lpDllPath) + 1;
    PVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllPath) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 3. 写入DLL路径
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, lpDllPath, dllPathLen, &bytesWritten)) {
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 4. 获取LoadLibrary地址
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    FARPROC pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    
    // 5. 创建远程线程执行LoadLibrary
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteDllPath, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    // 6. 清理
    VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return TRUE;
}
```

## 五、课后作业

1. **基础练习**：
   - 编写一个程序，使用IAT Hook技术Hook `CreateFileW` 函数，记录所有文件访问操作
   - 实现Hook `WriteFile` 函数，监控程序的写文件行为

2. **进阶练习**：
   - 实现支持远程进程的IAT Hook框架
   - 添加对延迟加载DLL的支持
   - 实现批量Hook多个函数的功能

3. **思考题**：
   - IAT Hook与Inline Hook相比有哪些优缺点？
   - 如何检测和防范IAT Hook攻击？
   - 现代Windows系统提供了哪些机制来阻止IAT Hook？

4. **扩展阅读**：
   - 研究Microsoft Detours库中的IAT Hook实现
   - 了解Import Address Table Filtering技术
   - 学习Control Flow Guard (CFG) 对IAT Hook的影响