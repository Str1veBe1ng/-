# 课时05 VEH INT3 Hook

## 一、课程目标

本节课主要学习VEH INT3 Hook技术，这是一种基于Windows异常处理机制的高级Hook方法。通过本课的学习，你将能够：

1. 理解VEH（Vectored Exception Handler）的基本概念和工作机制
2. 掌握INT3断点指令的使用方法
3. 实现基于VEH和INT3的Hook框架
4. 理解异常处理在Hook技术中的应用
5. 学习VEH Hook的检测和防护方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| VEH | Vectored Exception Handler，向量化异常处理程序 |
| INT3 | 中断3指令，用于软件断点的特殊指令（0xCC） |
| 异常处理 | Windows系统处理程序运行时异常的机制 |
| 断点 | 调试器用来暂停程序执行的机制 |
| 调试寄存器 | CPU提供的用于硬件断点的寄存器（DR0-DR7） |
| SEH | Structured Exception Handling，结构化异常处理 |

## 三、技术原理

### 3.1 VEH概述

VEH（Vectored Exception Handler）是Windows Vista及以后版本提供的异常处理机制。与传统的SEH不同，VEH采用链表结构管理异常处理程序，并且优先级更高。VEH通过`AddVectoredExceptionHandler`函数注册，通过`RemoveVectoredExceptionHandler`函数注销。

### 3.2 INT3指令

INT3（0xCC）是x86/x64架构中的调试中断指令，专门用于设置软件断点。当CPU执行到INT3指令时，会产生一个异常，调试器或其他异常处理程序可以捕获这个异常并进行相应处理。

### 3.3 VEH INT3 Hook原理

VEH INT3 Hook结合了VEH异常处理机制和INT3断点指令：
1. 在目标函数入口处插入INT3指令（0xCC）
2. 注册VEH异常处理程序
3. 当程序执行到INT3指令时，触发异常
4. VEH处理程序捕获异常，执行Hook逻辑
5. 恢复原始指令并继续执行

### 3.4 技术优势

1. **隐蔽性强**：不修改函数代码结构
2. **兼容性好**：适用于各种类型的函数
3. **灵活性高**：可以在异常处理程序中执行任意逻辑
4. **稳定性佳**：基于系统异常处理机制

## 四、代码实现

### 4.1 核心数据结构

```cpp
#include <windows.h>
#include <stdio.h>

// VEH Hook信息结构体
typedef struct _VEH_HOOK_INFO {
    CHAR		szFunctionName[64];		// 函数名称
    PVOID		pTargetAddress;			// 目标函数地址
    BYTE		originalByte;			// 原始字节
    PVOID		pHookFunction;			// Hook函数地址
    PVOID		pTrampoline;			// Trampoline地址
    BOOL		bIsHooked;				// 是否已Hook
    BOOL		bInException;			// 是否正在异常处理中
} VEH_HOOK_INFO, * PVEH_HOOK_INFO;

// VEH Hook管理器
typedef struct _VEH_HOOK_MANAGER {
    VEH_HOOK_INFO*	pHooks;				// Hook信息数组
    INT				nHookCount;			// Hook数量
    PVOID			pExceptionHandler;	// 异常处理程序句柄
} VEH_HOOK_MANAGER, * PVEH_HOOK_MANAGER;
```

### 4.2 异常处理程序实现

```cpp
// 全局VEH管理器指针
PVEH_HOOK_MANAGER g_pVEHManager = NULL;

// VEH异常处理程序
LONG WINAPI VEHExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // 检查是否为INT3异常
    if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // 获取异常发生的地址
    PVOID exceptionAddr = (PVOID)pExceptionInfo->ExceptionRecord->ExceptionAddress;
    
    // 查找对应的Hook信息
    for (INT i = 0; i < g_pVEHManager->nHookCount; i++) {
        PVEH_HOOK_INFO pHook = &g_pVEHManager->pHooks[i];
        
        // 检查是否是我们设置的断点
        if (pHook->pTargetAddress == exceptionAddr && pHook->bIsHooked) {
            // 标记正在异常处理中
            pHook->bInException = TRUE;
            
            // 恢复原始字节
            DWORD oldProtect;
            VirtualProtect(pHook->pTargetAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(PBYTE)pHook->pTargetAddress = pHook->originalByte;
            VirtualProtect(pHook->pTargetAddress, 1, oldProtect, &oldProtect);
            
            // 设置返回地址（跳过INT3指令）
            pExceptionInfo->ContextRecord->Rip++;  // x64
            
            // 调用Hook函数（如果提供了的话）
            if (pHook->pHookFunction) {
                // 这里可以根据需要调用自定义Hook函数
                // 为了简化，我们只记录日志
                printf("[VEH Hook] Function %s called at address %p\n", pHook->szFunctionName, pHook->pTargetAddress);
            }
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    // 不是我们的断点，继续搜索其他处理程序
    return EXCEPTION_CONTINUE_SEARCH;
}

// 初始化VEH Hook管理器
PVEH_HOOK_MANAGER InitVEHHookManager() {
    PVEH_HOOK_MANAGER pManager = (PVEH_HOOK_MANAGER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(VEH_HOOK_MANAGER));
    if (!pManager) {
        return NULL;
    }
    
    // 注册VEH异常处理程序
    pManager->pExceptionHandler = AddVectoredExceptionHandler(1, VEHExceptionHandler);
    if (!pManager->pExceptionHandler) {
        HeapFree(GetProcessHeap(), 0, pManager);
        return NULL;
    }
    
    // 设置全局指针
    g_pVEHManager = pManager;
    
    return pManager;
}
```

### 4.3 VEH INT3 Hook核心实现

```cpp
// 安装VEH INT3 Hook
BOOL InstallVEHInt3Hook(PVEH_HOOK_INFO pHookInfo) {
    if (!pHookInfo || !pHookInfo->pTargetAddress) {
        return FALSE;
    }
    
    // 备份原始字节
    pHookInfo->originalByte = *(PBYTE)pHookInfo->pTargetAddress;
    
    // 修改内存保护属性
    DWORD oldProtect;
    if (!VirtualProtect(pHookInfo->pTargetAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    // 插入INT3指令（0xCC）
    *(PBYTE)pHookInfo->pTargetAddress = 0xCC;
    
    // 恢复内存保护属性
    VirtualProtect(pHookInfo->pTargetAddress, 1, oldProtect, &oldProtect);
    
    pHookInfo->bIsHooked = TRUE;
    pHookInfo->bInException = FALSE;
    
    return TRUE;
}

// 卸载VEH INT3 Hook
BOOL UninstallVEHInt3Hook(PVEH_HOOK_INFO pHookInfo) {
    if (!pHookInfo || !pHookInfo->bIsHooked) {
        return FALSE;
    }
    
    // 如果正在异常处理中，等待处理完成
    while (pHookInfo->bInException) {
        Sleep(1);
    }
    
    // 恢复原始字节
    DWORD oldProtect;
    if (!VirtualProtect(pHookInfo->pTargetAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    *(PBYTE)pHookInfo->pTargetAddress = pHookInfo->originalByte;
    
    // 恢复内存保护属性
    VirtualProtect(pHookInfo->pTargetAddress, 1, oldProtect, &oldProtect);
    
    pHookInfo->bIsHooked = FALSE;
    return TRUE;
}

// 添加Hook到管理器
BOOL AddVEHInt3Hook(PVEH_HOOK_MANAGER pManager, LPCSTR functionName, PVOID targetAddress, PVOID hookFunction) {
    // 重新分配内存
    PVEH_HOOK_INFO pNewHooks = (PVEH_HOOK_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        pManager->pHooks, sizeof(VEH_HOOK_INFO) * (pManager->nHookCount + 1));
    if (!pNewHooks) {
        return FALSE;
    }
    
    pManager->pHooks = pNewHooks;
    
    // 填充Hook信息
    PVEH_HOOK_INFO pHook = &pManager->pHooks[pManager->nHookCount];
    strcpy_s(pHook->szFunctionName, sizeof(pHook->szFunctionName), functionName);
    pHook->pTargetAddress = targetAddress;
    pHook->pHookFunction = hookFunction;
    pHook->bIsHooked = FALSE;
    pHook->bInException = FALSE;
    
    // 安装Hook
    if (!InstallVEHInt3Hook(pHook)) {
        return FALSE;
    }
    
    pManager->nHookCount++;
    return TRUE;
}
```

### 4.4 完整VEH Hook管理器

```cpp
// 移除所有VEH Hook
VOID RemoveAllVEHInt3Hooks(PVEH_HOOK_MANAGER pManager) {
    if (!pManager) {
        return;
    }
    
    // 卸载所有Hook
    for (INT i = 0; i < pManager->nHookCount; i++) {
        UninstallVEHInt3Hook(&pManager->pHooks[i]);
    }
    
    // 注销VEH异常处理程序
    if (pManager->pExceptionHandler) {
        RemoveVectoredExceptionHandler(pManager->pExceptionHandler);
    }
    
    // 释放内存
    if (pManager->pHooks) {
        HeapFree(GetProcessHeap(), 0, pManager->pHooks);
    }
    
    // 清理全局指针
    g_pVEHManager = NULL;
    
    HeapFree(GetProcessHeap(), 0, pManager);
}

// 获取函数地址的辅助函数
PVOID GetFunctionAddress(LPCSTR moduleName, LPCSTR functionName) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        return NULL;
    }
    
    return GetProcAddress(hModule, functionName);
}
```

### 4.5 示例应用

```cpp
// 示例Hook函数
VOID MyMessageBoxHook() {
    printf("[VEH INT3 Hook] MessageBox function called!\n");
}

VOID MySleepHook() {
    printf("[VEH INT3 Hook] Sleep function called!\n");
}

// 使用示例
VOID DemoVEHInt3Hook() {
    // 初始化VEH Hook管理器
    PVEH_HOOK_MANAGER pManager = InitVEHHookManager();
    if (!pManager) {
        printf("Failed to initialize VEH Hook manager.\n");
        return;
    }
    
    // 获取目标函数地址
    PVOID pMessageBoxAddr = GetFunctionAddress("user32.dll", "MessageBoxW");
    PVOID pSleepAddr = GetFunctionAddress("kernel32.dll", "Sleep");
    
    if (pMessageBoxAddr) {
        if (AddVEHInt3Hook(pManager, "MessageBoxW", pMessageBoxAddr, (PVOID)MyMessageBoxHook)) {
            printf("MessageBoxW VEH INT3 Hook installed successfully.\n");
        }
    }
    
    if (pSleepAddr) {
        if (AddVEHInt3Hook(pManager, "Sleep", pSleepAddr, (PVOID)MySleepHook)) {
            printf("Sleep VEH INT3 Hook installed successfully.\n");
        }
    }
    
    // 测试Hook效果
    printf("Testing MessageBoxW...\n");
    MessageBoxW(NULL, L"Test Message", L"VEH INT3 Hook Test", MB_OK);
    
    printf("Testing Sleep...\n");
    Sleep(1000);
    
    // 清理Hook
    RemoveAllVEHInt3Hooks(pManager);
    printf("All VEH INT3 Hooks removed.\n");
}
```

### 4.6 增强版VEH Hook实现

```cpp
// 带返回值处理的VEH Hook
typedef struct _ENHANCED_VEH_HOOK_INFO {
    CHAR		szFunctionName[64];		// 函数名称
    PVOID		pTargetAddress;			// 目标函数地址
    BYTE		originalByte;			// 原始字节
    PVOID		pHookFunction;			// Hook函数地址
    PVOID		pOriginalFunction;		// 原始函数指针
    BOOL		bIsHooked;				// 是否已Hook
    BOOL		bInException;			// 是否正在异常处理中
    DWORD		dwCallCount;			// 调用次数统计
    ULONGLONG	ullTotalTime;			// 总执行时间（纳秒）
} ENHANCED_VEH_HOOK_INFO, * PENHANCED_VEH_HOOK_INFO;

// 增强版异常处理程序
LONG WINAPI EnhancedVEHExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    PVOID exceptionAddr = (PVOID)pExceptionInfo->ExceptionRecord->ExceptionAddress;
    
    for (INT i = 0; i < g_pVEHManager->nHookCount; i++) {
        PENHANCED_VEH_HOOK_INFO pHook = (PENHANCED_VEH_HOOK_INFO)&g_pVEHManager->pHooks[i];
        
        if (pHook->pTargetAddress == exceptionAddr && pHook->bIsHooked) {
            // 记录开始时间
            LARGE_INTEGER freq, start, end;
            QueryPerformanceFrequency(&freq);
            QueryPerformanceCounter(&start);
            
            pHook->bInException = TRUE;
            pHook->dwCallCount++;
            
            // 恢复原始字节
            DWORD oldProtect;
            VirtualProtect(pHook->pTargetAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(PBYTE)pHook->pTargetAddress = pHook->originalByte;
            VirtualProtect(pHook->pTargetAddress, 1, oldProtect, &oldProtect);
            
            // 如果有Hook函数，则调用它
            if (pHook->pHookFunction) {
                // 这里可以传递参数给Hook函数
                printf("[Enhanced VEH Hook] Function %s called (count: %lu)\n", 
                       pHook->szFunctionName, pHook->dwCallCount);
            }
            
            // 设置返回地址
            pExceptionInfo->ContextRecord->Rip++;
            
            // 记录结束时间
            QueryPerformanceCounter(&end);
            ULONGLONG elapsed = (end.QuadPart - start.QuadPart) * 1000000000ULL / freq.QuadPart;
            pHook->ullTotalTime += elapsed;
            
            pHook->bInException = FALSE;
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}
```

## 五、课后作业

1. **基础练习**：
   - 编写一个程序，使用VEH INT3 Hook技术Hook `CreateFileW` 函数，记录所有文件创建操作
   - 实现Hook `WriteFile` 函数，监控程序的写文件行为并统计性能数据

2. **进阶练习**：
   - 实现支持函数参数捕获和修改的VEH Hook框架
   - 添加Hook函数的返回值处理功能
   - 实现Hook调用的性能分析和统计功能

3. **思考题**：
   - VEH INT3 Hook与传统的调试器断点有何区别？
   - 如何检测和防范VEH INT3 Hook攻击？
   - 多线程环境下VEH INT3 Hook会有哪些并发问题？如何解决？

4. **扩展阅读**：
   - 研究Windows异常处理机制的内部实现
   - 了解硬件断点（调试寄存器）的使用方法
   - 学习现代调试器如何实现断点功能