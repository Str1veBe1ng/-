# 课时13 - C++ SEH实现ShellCode Loader

## 课程目标
1. 理解SEH（结构化异常处理）机制
2. 掌握__try/__except的使用
3. 实现SEH方式执行ShellCode
4. 了解SEH链的操作

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| SEH | Structured Exception Handling | 结构化异常处理 |
| __try/__except | - | MSVC SEH关键字 |
| EXCEPTION_RECORD | - | 异常信息结构 |
| FS:[0] | - | x86 SEH链头指针 |

## 代码实现

```cpp
// seh_loader.cpp
// SEH方式执行ShellCode

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

LPVOID g_ShellcodeAddr = NULL;

// 方法1: 异常过滤器执行
LONG WINAPI ExceptionFilter(PEXCEPTION_POINTERS ep) {
    printf("[SEH] Exception filter called\n");
    printf("[SEH] Exception code: 0x%08X\n", 
           ep->ExceptionRecord->ExceptionCode);
    
    if (g_ShellcodeAddr) {
        // 执行ShellCode
        typedef int (*SC_FUNC)();
        SC_FUNC func = (SC_FUNC)g_ShellcodeAddr;
        int result = func();
        printf("[SEH] Shellcode returned: %d\n", result);
    }
    
    return EXCEPTION_EXECUTE_HANDLER;
}

void Method1_FilterExecution() {
    printf("[*] Method 1: Exception Filter Execution\n");
    
    g_ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!g_ShellcodeAddr) return;
    
    memcpy(g_ShellcodeAddr, shellcode, sizeof(shellcode));
    
    __try {
        // 触发异常
        *(int*)NULL = 0;
    }
    __except(ExceptionFilter(GetExceptionInformation())) {
        printf("[SEH] Exception handled\n");
    }
    
    VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
}

// 方法2: 在异常处理块中执行
void Method2_HandlerExecution() {
    printf("[*] Method 2: Handler Block Execution\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    __try {
        // 故意除以零
        int x = 1;
        int y = 0;
        int z = x / y;  // 触发异常
        printf("z = %d\n", z);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[SEH] In exception handler\n");
        
        // 在处理块中执行ShellCode
        typedef int (*SC_FUNC)();
        SC_FUNC func = (SC_FUNC)mem;
        int result = func();
        printf("[SEH] Shellcode returned: %d\n", result);
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

// 方法3: 修改SEH链 (x86)
#ifndef _WIN64
typedef struct _EXCEPTION_REGISTRATION {
    struct _EXCEPTION_REGISTRATION* Next;
    PEXCEPTION_ROUTINE Handler;
} EXCEPTION_REGISTRATION, *PEXCEPTION_REGISTRATION;

EXCEPTION_DISPOSITION __cdecl CustomHandler(
    PEXCEPTION_RECORD ExceptionRecord,
    PVOID EstablisherFrame,
    PCONTEXT ContextRecord,
    PVOID DispatcherContext)
{
    printf("[SEH] Custom handler called\n");
    
    if (g_ShellcodeAddr) {
        // 修改EIP到ShellCode
        ContextRecord->Eip = (DWORD)g_ShellcodeAddr;
        return ExceptionContinueExecution;
    }
    
    return ExceptionContinueSearch;
}

void Method3_ManualSEH() {
    printf("[*] Method 3: Manual SEH Chain (x86)\n");
    
    g_ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!g_ShellcodeAddr) return;
    
    memcpy(g_ShellcodeAddr, shellcode, sizeof(shellcode));
    
    // 手动注册SEH
    __asm {
        push CustomHandler      // Handler
        push fs:[0]            // Next
        mov fs:[0], esp        // 注册
    }
    
    // 触发异常
    __try {
        *(int*)NULL = 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 不应该到这里
    }
    
    // 恢复SEH链
    __asm {
        pop fs:[0]
        add esp, 4
    }
    
    VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
}
#endif

// 方法4: 使用SetUnhandledExceptionFilter
LONG WINAPI TopLevelHandler(PEXCEPTION_POINTERS ep) {
    printf("[TopLevel] Unhandled exception caught\n");
    
    if (g_ShellcodeAddr) {
        typedef int (*SC_FUNC)();
        ((SC_FUNC)g_ShellcodeAddr)();
    }
    
    return EXCEPTION_EXECUTE_HANDLER;
}

void Method4_TopLevelFilter() {
    printf("[*] Method 4: Top Level Exception Filter\n");
    
    g_ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!g_ShellcodeAddr) return;
    
    memcpy(g_ShellcodeAddr, shellcode, sizeof(shellcode));
    
    // 设置顶层异常过滤器
    LPTOP_LEVEL_EXCEPTION_FILTER oldFilter = 
        SetUnhandledExceptionFilter(TopLevelHandler);
    
    // 在新线程中触发未处理异常
    // （主线程的__try会捕获，所以用新线程）
    
    printf("[+] Top level filter set\n");
    
    // 恢复
    SetUnhandledExceptionFilter(oldFilter);
    VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
}

int main() {
    printf("========================================\n");
    printf("     SEH ShellCode Loader              \n");
    printf("========================================\n\n");
    
    Method1_FilterExecution();
    printf("\n");
    
    Method2_HandlerExecution();
    printf("\n");
    
    #ifndef _WIN64
    Method3_ManualSEH();
    printf("\n");
    #endif
    
    Method4_TopLevelFilter();
    
    return 0;
}
```

## 课后作业

### 作业1：SEH链遍历
实现遍历当前线程的SEH链。

### 作业2：SafeSEH绑过
研究SafeSEH保护机制及其绕过方法。
