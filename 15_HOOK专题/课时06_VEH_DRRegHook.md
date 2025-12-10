# 课时06 VEH DRReg Hook

## 一、课程目标

本节课主要学习VEH DRReg Hook技术，这是一种基于调试寄存器和VEH异常处理机制的高级Hook方法。通过本课的学习，你将能够：

1. 理解CPU调试寄存器（DR0-DR7）的工作原理
2. 掌握硬件断点的设置和管理方法
3. 实现基于VEH和调试寄存器的Hook框架
4. 理解硬件断点与软件断点的区别和优势
5. 学习VEH DRReg Hook的检测和防护方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| DR寄存器 | Debug Registers，CPU提供的调试寄存器（DR0-DR7） |
| 硬件断点 | 使用CPU调试寄存器实现的断点机制 |
| DR0-DR3 | 地址寄存器，用于存储断点地址 |
| DR6 | 状态寄存器，指示哪个断点被触发 |
| DR7 | 控制寄存器，控制断点的启用和类型 |
| 单步异常 | 当TF标志位被设置时产生的异常（EXCEPTION_SINGLE_STEP） |
| 精确断点 | 硬件断点能够在精确的指令位置触发 |

## 三、技术原理

### 3.1 调试寄存器概述

x86/x64架构提供了8个调试寄存器（DR0-DR7），专门用于调试目的：

1. **DR0-DR3**：地址寄存器，每个64位（x64）或32位（x86），用于存储断点地址
2. **DR4-DR5**：保留未使用
3. **DR6**：状态寄存器，指示断点触发情况
4. **DR7**：控制寄存器，控制断点的启用、类型和条件

### 3.2 DR7控制寄存器详解

DR7寄存器控制着硬件断点的行为，其主要字段包括：

- **L0-L3**：本地断点启用位
- **G0-G3**：全局断点启用位
- **LE/GE**：本地/全局精确断点启用位
- **GD**：调试寄存器保护位
- **RW0-RW3**：读写类型（00=执行，01=写入，10=IO读写，11=读写）
- **LEN0-LEN3**：断点长度（00=1字节，01=2字节，10=8字节，11=4字节）

### 3.3 VEH DRReg Hook原理

VEH DRReg Hook利用CPU的调试寄存器设置硬件断点，并通过VEH捕获断点异常：

1. 设置调试寄存器，在目标地址设置硬件断点
2. 注册VEH异常处理程序
3. 当程序执行到断点地址时，触发单步异常
4. VEH处理程序捕获异常，执行Hook逻辑
5. 恢复执行或修改执行流程

### 3.4 技术优势

1. **难以检测**：硬件断点不会修改目标代码
2. **精确触发**：在精确的指令位置触发
3. **多功能性**：支持执行、读取、写入断点
4. **高性能**：硬件级别的断点机制

## 四、代码实现

### 4.1 核心数据结构

```cpp
#include <windows.h>
#include <stdio.h>

// 硬件断点类型
typedef enum _HWBP_TYPE {
    HWBP_EXECUTE = 0,   // 执行断点
    HWBP_WRITE = 1,     // 写入断点
    HWBP_IO = 2,        // IO读写断点
    HWBP_ACCESS = 3     // 访问断点（读写）
} HWBP_TYPE;

// 硬件断点长度
typedef enum _HWBP_SIZE {
    HWBP_SIZE_1 = 0,    // 1字节
    HWBP_SIZE_2 = 1,    // 2字节
    HWBP_SIZE_4 = 3,    // 4字节
    HWBP_SIZE_8 = 2     // 8字节（仅x64）
} HWBP_SIZE;

// DR寄存器Hook信息结构体
typedef struct _DR_HOOK_INFO {
    CHAR		szFunctionName[64];		// 函数名称
    PVOID		pTargetAddress;			// 目标地址
    DWORD		dwDrIndex;				// 使用的DR寄存器索引（0-3）
    HWBP_TYPE	type;					// 断点类型
    HWBP_SIZE	size;					// 断点大小
    PVOID		pHookFunction;			// Hook函数地址
    DWORD		dwOriginalDr7;			// 原始DR7值
    BOOL		bIsHooked;				// 是否已Hook
    DWORD		dwCallCount;			// 调用次数
} DR_HOOK_INFO, * PDR_HOOK_INFO;

// DR Hook管理器
typedef struct _DR_HOOK_MANAGER {
    DR_HOOK_INFO*	pHooks;				// Hook信息数组
    INT				nHookCount;			// Hook数量
    PVOID			pExceptionHandler;	// 异常处理程序句柄
    CRITICAL_SECTION cs;				// 同步临界区
} DR_HOOK_MANAGER, * PDR_HOOK_MANAGER;
```

### 4.2 调试寄存器操作函数

```cpp
// 获取线程上下文中的调试寄存器
BOOL GetDebugRegisters(HANDLE hThread, PCONTEXT pContext) {
    pContext->ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return GetThreadContext(hThread, pContext);
}

// 设置线程上下文中的调试寄存器
BOOL SetDebugRegisters(HANDLE hThread, PCONTEXT pContext) {
    pContext->ContextFlags = CONTEXT_DEBUG_REGISTERS;
    return SetThreadContext(hThread, pContext);
}

// 在指定线程中设置硬件断点
BOOL SetHardwareBreakpoint(HANDLE hThread, DWORD drIndex, PVOID address, HWBP_TYPE type, HWBP_SIZE size) {
    CONTEXT context;
    if (!GetDebugRegisters(hThread, &context)) {
        return FALSE;
    }
    
    // 设置地址寄存器
    switch (drIndex) {
    case 0:
        context.Dr0 = (DWORD64)address;
        break;
    case 1:
        context.Dr1 = (DWORD64)address;
        break;
    case 2:
        context.Dr2 = (DWORD64)address;
        break;
    case 3:
        context.Dr3 = (DWORD64)address;
        break;
    default:
        return FALSE;
    }
    
    // 设置控制寄存器DR7
    // 清除该断点的相关位
    context.Dr7 &= ~(0xF << (drIndex * 4));      // 清除RW和LEN位
    context.Dr7 &= ~(0x3 << (drIndex * 2));      // 清除L和G位
    
    // 设置新的断点配置
    context.Dr7 |= ((type & 0x3) << (drIndex * 4));     // 设置RW位
    context.Dr7 |= ((size & 0x3) << (drIndex * 4 + 2)); // 设置LEN位
    context.Dr7 |= (1 << (drIndex * 2));                // 启用本地断点
    
    return SetDebugRegisters(hThread, &context);
}

// 清除硬件断点
BOOL ClearHardwareBreakpoint(HANDLE hThread, DWORD drIndex) {
    CONTEXT context;
    if (!GetDebugRegisters(hThread, &context)) {
        return FALSE;
    }
    
    // 清除地址寄存器
    switch (drIndex) {
    case 0:
        context.Dr0 = 0;
        break;
    case 1:
        context.Dr1 = 0;
        break;
    case 2:
        context.Dr2 = 0;
        break;
    case 3:
        context.Dr3 = 0;
        break;
    }
    
    // 清除控制寄存器中的相关位
    context.Dr7 &= ~(0xF << (drIndex * 4));  // 清除RW和LEN位
    context.Dr7 &= ~(0x3 << (drIndex * 2));  // 清除L和G位
    
    return SetDebugRegisters(hThread, &context);
}
```

### 4.3 VEH异常处理程序

```cpp
// 全局DR管理器指针
PDR_HOOK_MANAGER g_pDRManager = NULL;

// VEH异常处理程序
LONG WINAPI DRExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // 检查是否为单步异常（硬件断点触发）
    if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // 获取触发断点的寄存器索引（从DR6寄存器）
    DWORD dr6 = (DWORD)pExceptionInfo->ContextRecord->Dr6;
    DWORD triggeredDr = 0;
    
    // 检查哪个DR寄存器被触发
    if (dr6 & 0x1) triggeredDr = 0;
    else if (dr6 & 0x2) triggeredDr = 1;
    else if (dr6 & 0x4) triggeredDr = 2;
    else if (dr6 & 0x8) triggeredDr = 3;
    else return EXCEPTION_CONTINUE_SEARCH;
    
    // 查找对应的Hook信息
    EnterCriticalSection(&g_pDRManager->cs);
    
    for (INT i = 0; i < g_pDRManager->nHookCount; i++) {
        PDR_HOOK_INFO pHook = &g_pDRManager->pHooks[i];
        
        if (pHook->dwDrIndex == triggeredDr && pHook->bIsHooked) {
            // 增加调用计数
            pHook->dwCallCount++;
            
            // 调用Hook函数（如果提供了的话）
            if (pHook->pHookFunction) {
                printf("[DR Hook] Function %s called (count: %lu)\n", 
                       pHook->szFunctionName, pHook->dwCallCount);
                
                // 这里可以调用自定义Hook函数
                // 例如：((void(*)())pHook->pHookFunction)();
            }
            
            // 清除DR6状态位
            pExceptionInfo->ContextRecord->Dr6 = 0;
            
            LeaveCriticalSection(&g_pDRManager->cs);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    LeaveCriticalSection(&g_pDRManager->cs);
    return EXCEPTION_CONTINUE_SEARCH;
}

// 初始化DR Hook管理器
PDR_HOOK_MANAGER InitDRHookManager() {
    PDR_HOOK_MANAGER pManager = (PDR_HOOK_MANAGER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(DR_HOOK_MANAGER));
    if (!pManager) {
        return NULL;
    }
    
    // 初始化临界区
    InitializeCriticalSection(&pManager->cs);
    
    // 注册VEH异常处理程序
    pManager->pExceptionHandler = AddVectoredExceptionHandler(1, DRExceptionHandler);
    if (!pManager->pExceptionHandler) {
        DeleteCriticalSection(&pManager->cs);
        HeapFree(GetProcessHeap(), 0, pManager);
        return NULL;
    }
    
    // 设置全局指针
    g_pDRManager = pManager;
    
    return pManager;
}
```

### 4.4 DR Hook核心实现

```cpp
// 安装DR Hook
BOOL InstallDRHook(PDR_HOOK_INFO pHookInfo) {
    if (!pHookInfo || !pHookInfo->pTargetAddress) {
        return FALSE;
    }
    
    // 在当前线程中设置硬件断点
    HANDLE hCurrentThread = GetCurrentThread();
    if (!SetHardwareBreakpoint(hCurrentThread, pHookInfo->dwDrIndex, 
                              pHookInfo->pTargetAddress, pHookInfo->type, pHookInfo->size)) {
        return FALSE;
    }
    
    pHookInfo->bIsHooked = TRUE;
    return TRUE;
}

// 卸载DR Hook
BOOL UninstallDRHook(PDR_HOOK_INFO pHookInfo) {
    if (!pHookInfo || !pHookInfo->bIsHooked) {
        return FALSE;
    }
    
    // 清除硬件断点
    HANDLE hCurrentThread = GetCurrentThread();
    if (!ClearHardwareBreakpoint(hCurrentThread, pHookInfo->dwDrIndex)) {
        return FALSE;
    }
    
    pHookInfo->bIsHooked = FALSE;
    return TRUE;
}

// 添加DR Hook到管理器
BOOL AddDRHook(PDR_HOOK_MANAGER pManager, LPCSTR functionName, PVOID targetAddress, 
               DWORD drIndex, HWBP_TYPE type, HWBP_SIZE size, PVOID hookFunction) {
    // 检查DR索引是否有效
    if (drIndex > 3) {
        return FALSE;
    }
    
    // 重新分配内存
    PDR_HOOK_INFO pNewHooks = (PDR_HOOK_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        pManager->pHooks, sizeof(DR_HOOK_INFO) * (pManager->nHookCount + 1));
    if (!pNewHooks) {
        return FALSE;
    }
    
    pManager->pHooks = pNewHooks;
    
    // 填充Hook信息
    PDR_HOOK_INFO pHook = &pManager->pHooks[pManager->nHookCount];
    strcpy_s(pHook->szFunctionName, sizeof(pHook->szFunctionName), functionName);
    pHook->pTargetAddress = targetAddress;
    pHook->dwDrIndex = drIndex;
    pHook->type = type;
    pHook->size = size;
    pHook->pHookFunction = hookFunction;
    pHook->bIsHooked = FALSE;
    pHook->dwCallCount = 0;
    
    // 安装Hook
    if (!InstallDRHook(pHook)) {
        return FALSE;
    }
    
    pManager->nHookCount++;
    return TRUE;
}
```

### 4.5 完整DR Hook管理器

```cpp
// 移除所有DR Hook
VOID RemoveAllDRHooks(PDR_HOOK_MANAGER pManager) {
    if (!pManager) {
        return;
    }
    
    EnterCriticalSection(&pManager->cs);
    
    // 卸载所有Hook
    for (INT i = 0; i < pManager->nHookCount; i++) {
        UninstallDRHook(&pManager->pHooks[i]);
    }
    
    // 注销VEH异常处理程序
    if (pManager->pExceptionHandler) {
        RemoveVectoredExceptionHandler(pManager->pExceptionHandler);
    }
    
    LeaveCriticalSection(&pManager->cs);
    
    // 删除临界区
    DeleteCriticalSection(&pManager->cs);
    
    // 释放内存
    if (pManager->pHooks) {
        HeapFree(GetProcessHeap(), 0, pManager->pHooks);
    }
    
    // 清理全局指针
    g_pDRManager = NULL;
    
    HeapFree(GetProcessHeap(), 0, pManager);
}

// 获取可用的DR寄存器索引
DWORD GetAvailableDRIndex(PDR_HOOK_MANAGER pManager) {
    for (DWORD i = 0; i < 4; i++) {
        BOOL bUsed = FALSE;
        for (INT j = 0; j < pManager->nHookCount; j++) {
            if (pManager->pHooks[j].dwDrIndex == i) {
                bUsed = TRUE;
                break;
            }
        }
        if (!bUsed) {
            return i;
        }
    }
    return (DWORD)-1;  // 没有可用的DR寄存器
}
```

### 4.6 示例应用

```cpp
// 示例Hook函数
VOID MyMessageBoxDRHook() {
    printf("[DR Hook] MessageBox function called via hardware breakpoint!\n");
}

VOID MySleepDRHook() {
    printf("[DR Hook] Sleep function called via hardware breakpoint!\n");
}

// 使用示例
VOID DemoDRHook() {
    // 初始化DR Hook管理器
    PDR_HOOK_MANAGER pManager = InitDRHookManager();
    if (!pManager) {
        printf("Failed to initialize DR Hook manager.\n");
        return;
    }
    
    // 获取目标函数地址
    PVOID pMessageBoxAddr = GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxW");
    PVOID pSleepAddr = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "Sleep");
    
    // 添加MessageBoxW Hook（使用DR0）
    if (pMessageBoxAddr) {
        if (AddDRHook(pManager, "MessageBoxW", pMessageBoxAddr, 0, HWBP_EXECUTE, HWBP_SIZE_1, (PVOID)MyMessageBoxDRHook)) {
            printf("MessageBoxW DR Hook installed successfully using DR0.\n");
        }
    }
    
    // 添加Sleep Hook（使用DR1）
    if (pSleepAddr) {
        if (AddDRHook(pManager, "Sleep", pSleepAddr, 1, HWBP_EXECUTE, HWBP_SIZE_1, (PVOID)MySleepDRHook)) {
            printf("Sleep DR Hook installed successfully using DR1.\n");
        }
    }
    
    // 测试Hook效果
    printf("Testing MessageBoxW...\n");
    MessageBoxW(NULL, L"Test Message", L"DR Hook Test", MB_OK);
    
    printf("Testing Sleep...\n");
    Sleep(1000);
    
    // 显示调用统计
    for (INT i = 0; i < pManager->nHookCount; i++) {
        printf("Function %s called %lu times\n", 
               pManager->pHooks[i].szFunctionName, pManager->pHooks[i].dwCallCount);
    }
    
    // 清理Hook
    RemoveAllDRHooks(pManager);
    printf("All DR Hooks removed.\n");
}
```

## 五、课后作业

1. **基础练习**：
   - 编写一个程序，使用DR Hook技术Hook `CreateFileW` 函数，记录所有文件创建操作
   - 实现写入断点，监控对特定变量的写入操作

2. **进阶练习**：
   - 实现支持多线程的DR Hook框架
   - 添加对所有4个DR寄存器的动态管理功能
   - 实现断点类型的自动识别和适配

3. **思考题**：
   - 硬件断点与软件断点相比有哪些优势和劣势？
   - 如何检测和防范DR Hook攻击？
   - 在多核系统中，硬件断点的行为有何特点？

4. **扩展阅读**：
   - 研究Intel处理器调试寄存器的详细规格
   - 了解现代调试器如何使用硬件断点
   - 学习基于性能计数器的监控技术