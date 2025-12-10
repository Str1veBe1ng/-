# 课时14：SSDT Hook

## 课程目标

1. 理解SSDT Hook的原理和实现
2. 掌握x86/x64下的Hook技术差异
3. 学会检测和还原SSDT Hook
4. 理解PatchGuard对SSDT Hook的影响

---

## 名词解释

| 术语 | 解释 |
|------|------|
| SSDT Hook | 修改系统服务表实现监控/拦截 |
| Inline Hook | 修改函数开头指令跳转 |
| PatchGuard | Windows内核保护机制 |
| KPP | Kernel Patch Protection |
| Trampoline | 跳板代码，保存原始指令 |

---

## 使用工具

| 工具 | 用途 |
|------|------|
| WinDbg | 分析和调试 |
| PCHunter | 检测SSDT Hook |
| IDA Pro | 逆向分析 |

---

## 技术原理

### SSDT Hook方式

```
┌─────────────────────────────────────────────────────────────┐
│                    SSDT Hook 方式                           │
│                                                             │
│  方式1：表项修改（x86适用）                                  │
│  ┌─────────────────────────────────────────────┐           │
│  │  SSDT[index] = OriginalAddress               │           │
│  │       ↓                                      │           │
│  │  SSDT[index] = HookFunction                  │           │
│  └─────────────────────────────────────────────┘           │
│  问题：x64 PatchGuard保护                                   │
│                                                             │
│  方式2：Inline Hook（通用）                                 │
│  ┌─────────────────────────────────────────────┐           │
│  │  OriginalFunction:                           │           │
│  │    push rbp        →  jmp HookFunction       │           │
│  │    mov rbp, rsp                              │           │
│  │    ...                                       │           │
│  └─────────────────────────────────────────────┘           │
│  问题：需要处理并发、代码完整性                              │
│                                                             │
│  方式3：LSTAR/MSR Hook                                      │
│  修改MSR_LSTAR指向自定义入口                                │
│  问题：PatchGuard检测                                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 代码实现

### 示例1：x86 SSDT Hook（传统方式）

```c
// SSDTHook_x86.c - x86 SSDT Hook
#include <ntddk.h>

// 仅适用于x86
#ifndef _WIN64

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG_PTR Base;
    PULONG Count;
    ULONG Limit;
    PUCHAR Number;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

// 导入SSDT
extern PKSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable;

// 保存原始函数
typedef NTSTATUS (*PNTOPENPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
PNTOPENPROCESS g_OrigNtOpenProcess = NULL;

// NtOpenProcess的系统调用号（需要根据系统版本确定）
#define SYSCALL_NTOPENPROCESS 0xBE

// Hook函数
NTSTATUS HookedNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
) {
    if (ClientId) {
        DbgPrint("[Hook] NtOpenProcess called for PID: %d\n", 
                 (ULONG)(ULONG_PTR)ClientId->UniqueProcess);
    }
    
    return g_OrigNtOpenProcess(ProcessHandle, DesiredAccess, 
                                ObjectAttributes, ClientId);
}

// 关闭写保护
KIRQL DisableWriteProtection() {
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    
    ULONG_PTR cr0 = __readcr0();
    cr0 &= ~0x10000;  // 清除WP位
    __writecr0(cr0);
    
    return irql;
}

// 恢复写保护
VOID EnableWriteProtection(KIRQL irql) {
    ULONG_PTR cr0 = __readcr0();
    cr0 |= 0x10000;  // 设置WP位
    __writecr0(cr0);
    
    KeLowerIrql(irql);
}

// 安装Hook
NTSTATUS InstallSSDTHook() {
    KIRQL irql;
    
    // 保存原始地址
    g_OrigNtOpenProcess = (PNTOPENPROCESS)
        KeServiceDescriptorTable->Base[SYSCALL_NTOPENPROCESS];
    
    DbgPrint("[Hook] Original NtOpenProcess: 0x%p\n", g_OrigNtOpenProcess);
    
    // 关闭写保护并修改SSDT
    irql = DisableWriteProtection();
    
    KeServiceDescriptorTable->Base[SYSCALL_NTOPENPROCESS] = 
        (ULONG_PTR)HookedNtOpenProcess;
    
    EnableWriteProtection(irql);
    
    DbgPrint("[Hook] SSDT Hook installed\n");
    
    return STATUS_SUCCESS;
}

// 卸载Hook
VOID UninstallSSDTHook() {
    if (g_OrigNtOpenProcess) {
        KIRQL irql = DisableWriteProtection();
        
        KeServiceDescriptorTable->Base[SYSCALL_NTOPENPROCESS] = 
            (ULONG_PTR)g_OrigNtOpenProcess;
        
        EnableWriteProtection(irql);
        
        DbgPrint("[Hook] SSDT Hook removed\n");
    }
}

#endif // !_WIN64
```

### 示例2：Inline Hook实现

```c
// InlineHook.c - Inline Hook实现
#include <ntddk.h>

#pragma pack(push, 1)
typedef struct _JMP_ABS {
    BYTE  opcode[2];    // FF 25
    DWORD offset;       // 00 00 00 00
    PVOID address;      // 绝对地址
} JMP_ABS, *PJMP_ABS;

typedef struct _JMP_REL {
    BYTE  opcode;       // E9
    DWORD offset;       // 相对偏移
} JMP_REL, *PJMP_REL;
#pragma pack(pop)

typedef struct _HOOK_INFO {
    PVOID   OriginalFunction;
    PVOID   HookFunction;
    PVOID   Trampoline;
    BYTE    OriginalBytes[16];
    ULONG   OriginalBytesLength;
    BOOLEAN Installed;
} HOOK_INFO, *PHOOK_INFO;

// 计算需要保存的指令长度
ULONG GetInstructionLength(PVOID Address, ULONG MinLength) {
    // 简化版：返回固定值
    // 实际需要反汇编引擎如Zydis/Capstone
    return 14;  // x64跳转需要14字节
}

// 分配可执行内存
PVOID AllocateExecutableMemory(SIZE_T Size) {
    return ExAllocatePoolWithTag(NonPagedPoolExecute, Size, 'kooH');
}

// 创建Trampoline
PVOID CreateTrampoline(PVOID OriginalFunction, ULONG BytesToSave) {
    // Trampoline: 原始指令 + 跳转回原函数
    SIZE_T trampolineSize = BytesToSave + sizeof(JMP_ABS);
    PUCHAR trampoline = (PUCHAR)AllocateExecutableMemory(trampolineSize);
    
    if (!trampoline) return NULL;
    
    // 复制原始指令
    RtlCopyMemory(trampoline, OriginalFunction, BytesToSave);
    
    // 添加跳转到原函数继续执行点
    PJMP_ABS jmp = (PJMP_ABS)(trampoline + BytesToSave);
    jmp->opcode[0] = 0xFF;
    jmp->opcode[1] = 0x25;
    jmp->offset = 0;
    jmp->address = (PUCHAR)OriginalFunction + BytesToSave;
    
    return trampoline;
}

// 安装Inline Hook
NTSTATUS InstallInlineHook(PHOOK_INFO HookInfo) {
    ULONG bytesToPatch;
    KIRQL irql;
    
    // 计算需要覆盖的字节数
    bytesToPatch = GetInstructionLength(HookInfo->OriginalFunction, sizeof(JMP_ABS));
    HookInfo->OriginalBytesLength = bytesToPatch;
    
    // 保存原始字节
    RtlCopyMemory(HookInfo->OriginalBytes, HookInfo->OriginalFunction, bytesToPatch);
    
    // 创建Trampoline
    HookInfo->Trampoline = CreateTrampoline(HookInfo->OriginalFunction, bytesToPatch);
    if (!HookInfo->Trampoline) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // 构造跳转指令
    BYTE jumpCode[14] = { 
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,  // jmp qword ptr [rip+0]
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00  // 地址
    };
    *(PVOID*)(jumpCode + 6) = HookInfo->HookFunction;
    
    // 修改目标函数
    irql = KeRaiseIrqlToDpcLevel();
    
    // 使用MDL修改只读内存
    PMDL mdl = IoAllocateMdl(HookInfo->OriginalFunction, bytesToPatch, FALSE, FALSE, NULL);
    if (mdl) {
        MmBuildMdlForNonPagedPool(mdl);
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached,
                                                     NULL, FALSE, NormalPagePriority);
        if (mapped) {
            RtlCopyMemory(mapped, jumpCode, bytesToPatch);
            MmUnmapLockedPages(mapped, mdl);
        }
        IoFreeMdl(mdl);
    }
    
    KeLowerIrql(irql);
    
    HookInfo->Installed = TRUE;
    
    return STATUS_SUCCESS;
}

// 卸载Inline Hook
VOID UninstallInlineHook(PHOOK_INFO HookInfo) {
    if (!HookInfo->Installed) return;
    
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    
    // 恢复原始字节
    PMDL mdl = IoAllocateMdl(HookInfo->OriginalFunction, 
                              HookInfo->OriginalBytesLength, FALSE, FALSE, NULL);
    if (mdl) {
        MmBuildMdlForNonPagedPool(mdl);
        PVOID mapped = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached,
                                                     NULL, FALSE, NormalPagePriority);
        if (mapped) {
            RtlCopyMemory(mapped, HookInfo->OriginalBytes, 
                         HookInfo->OriginalBytesLength);
            MmUnmapLockedPages(mapped, mdl);
        }
        IoFreeMdl(mdl);
    }
    
    KeLowerIrql(irql);
    
    // 释放Trampoline
    if (HookInfo->Trampoline) {
        ExFreePoolWithTag(HookInfo->Trampoline, 'kooH');
    }
    
    HookInfo->Installed = FALSE;
}
```

### 示例3：SSDT Hook检测

```c
// SSDTDetect.c - SSDT Hook检测
#include <ntddk.h>

typedef struct _HOOK_DETECTION_RESULT {
    ULONG   SyscallNumber;
    PVOID   CurrentAddress;
    PVOID   ExpectedAddress;
    BOOLEAN IsHooked;
    WCHAR   ModuleName[64];
} HOOK_DETECTION_RESULT, *PHOOK_DETECTION_RESULT;

// 获取地址所属模块
NTSTATUS GetModuleNameByAddress(PVOID Address, PWCHAR ModuleName, ULONG Size) {
    // 使用AuxKlibQueryModuleInformation
    // 或遍历PsLoadedModuleList
    
    // 简化实现
    RtlStringCbCopyW(ModuleName, Size, L"Unknown");
    
    return STATUS_SUCCESS;
}

// 检测SSDT Hook
ULONG DetectSSDTHooks(PHOOK_DETECTION_RESULT Results, ULONG MaxResults) {
    ULONG hookCount = 0;
    PKSERVICE_TABLE_DESCRIPTOR ssdt = (PKSERVICE_TABLE_DESCRIPTOR)FindSSDT();
    
    if (!ssdt) return 0;
    
    // 获取ntoskrnl的地址范围
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"NtClose");
    PVOID ntosStart = MmGetSystemRoutineAddress(&funcName);
    
    // 估计ntoskrnl大小（简化）
    ULONG_PTR ntosEnd = (ULONG_PTR)ntosStart + 0x1000000;  // ~16MB
    
    for (ULONG i = 0; i < ssdt->Limit && hookCount < MaxResults; i++) {
#ifdef _WIN64
        LONG offset = ((PLONG)ssdt->Base)[i] >> 4;
        PVOID funcAddr = (PVOID)((PUCHAR)ssdt->Base + offset);
#else
        PVOID funcAddr = (PVOID)ssdt->Base[i];
#endif
        
        // 检查地址是否在ntoskrnl范围内
        if ((ULONG_PTR)funcAddr < (ULONG_PTR)ntosStart ||
            (ULONG_PTR)funcAddr > ntosEnd) {
            
            Results[hookCount].SyscallNumber = i;
            Results[hookCount].CurrentAddress = funcAddr;
            Results[hookCount].ExpectedAddress = NULL;  // 未知
            Results[hookCount].IsHooked = TRUE;
            
            GetModuleNameByAddress(funcAddr, Results[hookCount].ModuleName, 
                                   sizeof(Results[hookCount].ModuleName));
            
            hookCount++;
        }
    }
    
    return hookCount;
}

// 检测Inline Hook
BOOLEAN DetectInlineHook(PVOID FunctionAddress) {
    PUCHAR code = (PUCHAR)FunctionAddress;
    
    // 检查是否是跳转指令
    // JMP rel32
    if (code[0] == 0xE9) {
        return TRUE;
    }
    
    // JMP qword ptr [rip+0] (FF 25 00 00 00 00)
    if (code[0] == 0xFF && code[1] == 0x25 && 
        *(PULONG)(code + 2) == 0) {
        return TRUE;
    }
    
    // MOV RAX, addr; JMP RAX
    if (code[0] == 0x48 && code[1] == 0xB8 &&
        code[10] == 0xFF && code[11] == 0xE0) {
        return TRUE;
    }
    
    return FALSE;
}

// 扫描所有SSDT入口点
VOID ScanForHooks() {
    HOOK_DETECTION_RESULT results[100];
    ULONG count = DetectSSDTHooks(results, 100);
    
    DbgPrint("[Detect] Found %d SSDT hooks\n", count);
    
    for (ULONG i = 0; i < count; i++) {
        DbgPrint("[Detect] Syscall %d hooked, addr: 0x%p, module: %ws\n",
                 results[i].SyscallNumber,
                 results[i].CurrentAddress,
                 results[i].ModuleName);
    }
    
    // 检测常用函数的Inline Hook
    UNICODE_STRING funcNames[] = {
        RTL_CONSTANT_STRING(L"NtOpenProcess"),
        RTL_CONSTANT_STRING(L"NtReadVirtualMemory"),
        RTL_CONSTANT_STRING(L"NtWriteVirtualMemory"),
    };
    
    for (int i = 0; i < sizeof(funcNames)/sizeof(funcNames[0]); i++) {
        PVOID addr = MmGetSystemRoutineAddress(&funcNames[i]);
        if (addr && DetectInlineHook(addr)) {
            DbgPrint("[Detect] Inline hook detected: %wZ at 0x%p\n",
                     &funcNames[i], addr);
        }
    }
}
```

### 示例4：还原SSDT Hook

```c
// SSDTRestore.c - SSDT Hook还原
#include <ntddk.h>

// 从干净的ntoskrnl重新计算SSDT
// 这是一个高级技术，需要加载干净的ntoskrnl副本

typedef struct _CLEAN_SSDT_ENTRY {
    ULONG   SyscallNumber;
    ULONG   RVA;          // 相对ntoskrnl基址的偏移
} CLEAN_SSDT_ENTRY;

// 预先计算的干净SSDT条目（示例）
// 实际需要从干净系统或PE文件提取
CLEAN_SSDT_ENTRY g_CleanSSdt[] = {
    // { syscall_number, rva }
};

// 从磁盘读取ntoskrnl并解析导出表获取原始RVA
NTSTATUS GetCleanSSDTFromFile(PWCHAR FilePath) {
    HANDLE hFile;
    OBJECT_ATTRIBUTES objAttr;
    IO_STATUS_BLOCK ioStatus;
    UNICODE_STRING fileName;
    NTSTATUS status;
    
    RtlInitUnicodeString(&fileName, FilePath);
    InitializeObjectAttributes(&objAttr, &fileName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
    
    status = ZwOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE,
        &objAttr, &ioStatus, FILE_SHARE_READ,
        FILE_SYNCHRONOUS_IO_NONALERT);
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // 读取PE头
    // 解析导出表
    // 提取Nt*函数的RVA
    
    ZwClose(hFile);
    
    return STATUS_SUCCESS;
}

// 使用内存完整性检查
NTSTATUS VerifySSDTIntegrity() {
    // 比较当前SSDT和预期SSDT
    // 如果发现差异则记录或还原
    
    return STATUS_SUCCESS;
}
```

### 示例5：用户模式Hook检测工具

```c
// HookDetector.c - 用户模式检测
#include <windows.h>
#include <stdio.h>

// 检测ntdll Inline Hook
BOOL DetectNtdllHook(const char* funcName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    
    PVOID funcAddr = GetProcAddress(hNtdll, funcName);
    if (!funcAddr) return FALSE;
    
    PBYTE code = (PBYTE)funcAddr;
    
    // 正常的ntdll stub开始
    // 4C 8B D1   mov r10, rcx
    // B8 XX XX   mov eax, syscall_number
    
    // 检测跳转指令
    if (code[0] == 0xE9 ||  // JMP rel32
        code[0] == 0xEB ||  // JMP rel8
        (code[0] == 0xFF && code[1] == 0x25) ||  // JMP [addr]
        (code[0] == 0x48 && code[1] == 0xB8)) {  // MOV RAX, imm64
        
        printf("[!] Hook detected in %s\n", funcName);
        return TRUE;
    }
    
    // 验证正常的stub
    if (code[0] != 0x4C || code[1] != 0x8B || code[2] != 0xD1) {
        printf("[?] Unusual code in %s\n", funcName);
        return TRUE;
    }
    
    return FALSE;
}

void ScanNtdllForHooks() {
    const char* functions[] = {
        "NtOpenProcess",
        "NtReadVirtualMemory",
        "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtCreateThreadEx",
        "NtQuerySystemInformation",
        "NtCreateFile",
        "NtQueryInformationProcess"
    };
    
    printf("=== NTDLL Hook Detection ===\n\n");
    
    int hookCount = 0;
    for (int i = 0; i < sizeof(functions)/sizeof(functions[0]); i++) {
        if (DetectNtdllHook(functions[i])) {
            hookCount++;
        } else {
            printf("[OK] %s\n", functions[i]);
        }
    }
    
    printf("\nTotal hooks detected: %d\n", hookCount);
}

int main() {
    ScanNtdllForHooks();
    return 0;
}
```

---

## 课后作业

1. 实现一个完整的Inline Hook框架
2. 编写SSDT Hook检测和还原工具
3. 研究不同反病毒软件的Hook检测方法
4. 分析PatchGuard的工作原理

---

## 扩展阅读

- Windows内核Hook技术
- PatchGuard绕过技术
- Hypervisor Based Hooking
