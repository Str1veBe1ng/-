# 课时02 - 动态获取Kernel32.dll地址

## 课程目标
1. 理解PEB（进程环境块）的结构
2. 掌握通过PEB遍历获取模块基址的方法
3. 实现x86和x64版本的Kernel32获取代码
4. 掌握无API依赖的模块枚举技术

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| PEB | Process Environment Block | 进程环境块，包含进程的全局信息 |
| TEB | Thread Environment Block | 线程环境块，包含线程的信息 |
| LDR | Loader Data | 加载器数据，包含已加载模块列表 |
| InLoadOrderModuleList | - | 按加载顺序排列的模块链表 |
| InMemoryOrderModuleList | - | 按内存顺序排列的模块链表 |
| InInitializationOrderModuleList | - | 按初始化顺序排列的模块链表 |
| FS/GS | Segment Register | x86用FS，x64用GS访问TEB |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| x64dbg | 动态调试查看PEB/TEB | 验证偏移正确性 |
| WinDbg | 内核调试 | dt命令查看结构 |
| Visual Studio | 编译代码 | 支持内联汇编 |
| NASM | 汇编编译 | 纯汇编版本 |

## 技术原理

### 1. TEB和PEB的关系

```
x86:                                x64:
FS:[0x00] -> TEB                    GS:[0x00] -> TEB
FS:[0x30] -> TEB.ProcessEnvironmentBlock (PEB*)
                                    GS:[0x60] -> TEB.ProcessEnvironmentBlock (PEB*)
```

### 2. PEB结构（关键字段）

```
PEB (x86)                           PEB (x64)
+0x000 InheritedAddressSpace        +0x000 InheritedAddressSpace
+0x001 ReadImageFileExecOptions     +0x001 ReadImageFileExecOptions
+0x002 BeingDebugged               +0x002 BeingDebugged
...                                 ...
+0x00C Ldr (PEB_LDR_DATA*)         +0x018 Ldr (PEB_LDR_DATA*)
```

### 3. PEB_LDR_DATA结构

```c
typedef struct _PEB_LDR_DATA {
    ULONG Length;                          // +0x00
    BOOLEAN Initialized;                   // +0x04
    PVOID SsHandle;                        // +0x08
    LIST_ENTRY InLoadOrderModuleList;      // +0x0C (x86) / +0x10 (x64)
    LIST_ENTRY InMemoryOrderModuleList;    // +0x14 (x86) / +0x20 (x64)
    LIST_ENTRY InInitializationOrderModuleList; // +0x1C (x86) / +0x30 (x64)
} PEB_LDR_DATA;
```

### 4. LDR_DATA_TABLE_ENTRY结构

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;           // +0x00
    LIST_ENTRY InMemoryOrderLinks;         // +0x08 (x86) / +0x10 (x64)
    LIST_ENTRY InInitializationOrderLinks; // +0x10 (x86) / +0x20 (x64)
    PVOID DllBase;                         // +0x18 (x86) / +0x30 (x64)
    PVOID EntryPoint;                      // +0x1C (x86) / +0x38 (x64)
    ULONG SizeOfImage;                     // +0x20 (x86) / +0x40 (x64)
    UNICODE_STRING FullDllName;            // +0x24 (x86) / +0x48 (x64)
    UNICODE_STRING BaseDllName;            // +0x2C (x86) / +0x58 (x64)
} LDR_DATA_TABLE_ENTRY;
```

### 5. 模块列表遍历流程

```
TEB (FS:[0]/GS:[0])
    │
    └──> PEB (FS:[0x30]/GS:[0x60])
            │
            └──> Ldr (PEB_LDR_DATA*)
                    │
                    └──> InLoadOrderModuleList
                            │
                            ├──> Entry 0: 当前进程EXE
                            ├──> Entry 1: ntdll.dll
                            └──> Entry 2: kernel32.dll ✓
```

## 代码实现

### 1. x86版本 - C语言实现

```c
// get_kernel32_x86.c
// x86版本动态获取Kernel32.dll基址

#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// 自定义结构体（完整版）
typedef struct _MY_PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *PMY_PEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;

// 方法1：通过InLoadOrderModuleList获取（推荐）
HMODULE GetKernel32_LoadOrder() {
    PPEB pPeb;
    PMY_PEB_LDR_DATA pLdr;
    PLIST_ENTRY pListHead, pListEntry;
    PMY_LDR_DATA_TABLE_ENTRY pEntry;
    
    // 通过TEB获取PEB
    #ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
    #else
    pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    // 获取Ldr
    pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;
    
    // 遍历InLoadOrderModuleList
    pListHead = &pLdr->InLoadOrderModuleList;
    pListEntry = pListHead->Flink;
    
    while (pListEntry != pListHead) {
        pEntry = CONTAINING_RECORD(pListEntry, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        // 检查模块名（不区分大小写）
        if (pEntry->BaseDllName.Buffer != NULL) {
            // 简单比较：检查是否包含"kernel32"或"KERNEL32"
            WCHAR* name = pEntry->BaseDllName.Buffer;
            if (name[0] == 'K' || name[0] == 'k') {
                if (_wcsnicmp(name, L"kernel32", 8) == 0) {
                    return (HMODULE)pEntry->DllBase;
                }
            }
        }
        pListEntry = pListEntry->Flink;
    }
    
    return NULL;
}

// 方法2：通过InInitializationOrderModuleList获取
// 注意：初始化顺序中kernel32通常在第三位
HMODULE GetKernel32_InitOrder() {
    PPEB pPeb;
    PMY_PEB_LDR_DATA pLdr;
    PLIST_ENTRY pListHead, pListEntry;
    PMY_LDR_DATA_TABLE_ENTRY pEntry;
    int count = 0;
    
    #ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
    #else
    pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;
    pListHead = &pLdr->InInitializationOrderModuleList;
    pListEntry = pListHead->Flink;
    
    // 初始化顺序：ntdll -> kernel32 -> kernelbase (Win7+)
    while (pListEntry != pListHead) {
        // 注意：InInitializationOrderLinks偏移不同
        pEntry = CONTAINING_RECORD(pListEntry, MY_LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks);
        
        count++;
        // 在Vista及更早版本，kernel32是第二个
        // 在Win7及以上版本，kernelbase是第二个，kernel32是第三个
        // 所以需要检查名称
        
        if (pEntry->BaseDllName.Buffer != NULL) {
            if (_wcsnicmp(pEntry->BaseDllName.Buffer, L"kernel32", 8) == 0) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        
        pListEntry = pListEntry->Flink;
    }
    
    return NULL;
}

// 方法3：使用内联汇编（x86）
#ifndef _WIN64
HMODULE __declspec(naked) GetKernel32_ASM() {
    __asm {
        push esi
        push edi
        
        ; 获取PEB
        mov eax, fs:[0x30]          ; PEB
        mov eax, [eax + 0x0C]       ; PEB->Ldr
        mov eax, [eax + 0x14]       ; Ldr->InMemoryOrderModuleList.Flink
        
    next_module:
        mov esi, [eax + 0x28]       ; BaseDllName.Buffer (InMemoryOrder偏移)
        
        ; 检查是否为kernel32.dll
        ; 简单检查：第一个字符是K或k，第8个字符是3
        movzx edi, word ptr [esi]   ; 第一个字符
        or edi, 0x20                ; 转小写
        cmp edi, 'k'
        jne continue_search
        
        movzx edi, word ptr [esi + 14] ; 第8个字符 (7*2=14)
        cmp edi, '3'
        jne continue_search
        
        ; 找到kernel32
        mov eax, [eax + 0x10]       ; DllBase (InMemoryOrder偏移)
        jmp done
        
    continue_search:
        mov eax, [eax]              ; 下一个模块
        jmp next_module
        
    done:
        pop edi
        pop esi
        ret
    }
}
#endif

// 方法4：使用哈希比较（更可靠）
DWORD HashString(WCHAR* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash << 5) + hash) + (*str | 0x20); // 转小写后计算
        str++;
    }
    return hash;
}

#define KERNEL32_HASH 0x6A4ABC5B  // 预计算的kernel32.dll哈希

HMODULE GetKernel32_Hash() {
    PPEB pPeb;
    PMY_PEB_LDR_DATA pLdr;
    PLIST_ENTRY pListHead, pListEntry;
    PMY_LDR_DATA_TABLE_ENTRY pEntry;
    
    #ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
    #else
    pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;
    pListHead = &pLdr->InLoadOrderModuleList;
    pListEntry = pListHead->Flink;
    
    while (pListEntry != pListHead) {
        pEntry = CONTAINING_RECORD(pListEntry, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        if (pEntry->BaseDllName.Buffer != NULL) {
            DWORD hash = HashString(pEntry->BaseDllName.Buffer);
            if (hash == KERNEL32_HASH) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        pListEntry = pListEntry->Flink;
    }
    
    return NULL;
}

// 调试辅助：打印所有已加载模块
void PrintLoadedModules() {
    PPEB pPeb;
    PMY_PEB_LDR_DATA pLdr;
    PLIST_ENTRY pListHead, pListEntry;
    PMY_LDR_DATA_TABLE_ENTRY pEntry;
    int index = 0;
    
    #ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
    #else
    pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    pLdr = (PMY_PEB_LDR_DATA)pPeb->Ldr;
    pListHead = &pLdr->InLoadOrderModuleList;
    pListEntry = pListHead->Flink;
    
    printf("=== Loaded Modules (InLoadOrder) ===\n");
    printf("%-4s %-16s %-10s %s\n", "Idx", "Base", "Size", "Name");
    printf("%-4s %-16s %-10s %s\n", "---", "----", "----", "----");
    
    while (pListEntry != pListHead) {
        pEntry = CONTAINING_RECORD(pListEntry, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        
        printf("[%02d] 0x%p 0x%08X %ws\n",
            index++,
            pEntry->DllBase,
            pEntry->SizeOfImage,
            pEntry->BaseDllName.Buffer ? pEntry->BaseDllName.Buffer : L"(null)");
        
        pListEntry = pListEntry->Flink;
    }
}

int main() {
    printf("========================================\n");
    printf("    Get Kernel32.dll Base Address       \n");
    printf("========================================\n\n");
    
    // 打印所有模块
    PrintLoadedModules();
    
    // 测试各种方法
    printf("\n=== Testing Methods ===\n");
    
    HMODULE hKernel32;
    
    // 方法1
    hKernel32 = GetKernel32_LoadOrder();
    printf("LoadOrder Method:  0x%p\n", hKernel32);
    
    // 方法2
    hKernel32 = GetKernel32_InitOrder();
    printf("InitOrder Method:  0x%p\n", hKernel32);
    
    // 方法3 (仅x86)
    #ifndef _WIN64
    hKernel32 = GetKernel32_ASM();
    printf("ASM Method:        0x%p\n", hKernel32);
    #endif
    
    // 方法4
    hKernel32 = GetKernel32_Hash();
    printf("Hash Method:       0x%p\n", hKernel32);
    
    // 验证
    HMODULE hReal = GetModuleHandleW(L"kernel32.dll");
    printf("\nVerification (GetModuleHandle): 0x%p\n", hReal);
    
    if (hKernel32 == hReal) {
        printf("\n[+] SUCCESS: All methods returned correct address!\n");
    } else {
        printf("\n[-] WARNING: Address mismatch!\n");
    }
    
    return 0;
}
```

### 2. x64版本 - 纯汇编ShellCode

```nasm
; get_kernel32_x64.asm
; NASM语法 - x64版本获取Kernel32基址

BITS 64

global _start

section .text

_start:
    ; 获取PEB
    mov rax, gs:[0x60]          ; TEB->ProcessEnvironmentBlock
    
    ; 获取Ldr
    mov rax, [rax + 0x18]       ; PEB->Ldr
    
    ; 获取InMemoryOrderModuleList
    mov rax, [rax + 0x20]       ; Ldr->InMemoryOrderModuleList.Flink
    
    ; 第一个条目是当前进程
    ; 第二个条目是ntdll.dll
    ; 第三个条目通常是kernel32.dll或kernelbase.dll
    
.find_kernel32:
    ; rax指向LIST_ENTRY
    mov rsi, [rax + 0x50]       ; BaseDllName.Buffer (x64偏移)
    
    ; 检查第一个字符是否为'K'或'k' (0x4B或0x6B)
    movzx rdi, word [rsi]
    or rdi, 0x20                ; 转小写
    cmp rdi, 0x6B               ; 'k'
    jne .next_module
    
    ; 检查第7个字符是否为'3' (kernel32中的3)
    ; 偏移 = 6 * 2 = 12 (WCHAR)
    movzx rdi, word [rsi + 12]
    cmp rdi, 0x33               ; '3'
    jne .next_module
    
    ; 检查第8个字符是否为'2' (kernel32中的2)
    movzx rdi, word [rsi + 14]
    cmp rdi, 0x32               ; '2'
    jne .next_module
    
    ; 找到kernel32.dll
    mov rax, [rax + 0x20]       ; DllBase (x64 InMemoryOrder偏移)
    ret
    
.next_module:
    mov rax, [rax]              ; Flink -> 下一个模块
    jmp .find_kernel32
```

### 3. ShellCode提取用版本

```c
// shellcode_getkernel32.c
// 可直接提取为ShellCode的版本

#include <windows.h>
#include <stdio.h>

// ShellCode函数 - 获取Kernel32基址
// 编译后需要提取.text段的机器码
#pragma code_seg(".shell")
#pragma optimize("", off)

#ifndef _WIN64
// x86版本
__declspec(naked) void* __stdcall ShellGetKernel32() {
    __asm {
        xor eax, eax
        mov eax, fs:[0x30]          ; PEB
        mov eax, [eax + 0x0C]       ; Ldr
        mov eax, [eax + 0x14]       ; InMemoryOrderModuleList.Flink
        
    find_loop:
        mov esi, [eax + 0x28]       ; BaseDllName.Buffer
        test esi, esi
        jz next_entry
        
        ; 检查 "KERNEL32" 或 "kernel32"
        movzx ecx, word ptr [esi]       ; 第1个字符
        or ecx, 0x20
        cmp cl, 'k'
        jne next_entry
        
        movzx ecx, word ptr [esi + 0x0E] ; 第8个字符(7*2=14=0x0E)
        cmp cl, '3'
        jne next_entry
        
        ; 找到了
        mov eax, [eax + 0x10]       ; DllBase
        ret
        
    next_entry:
        mov eax, [eax]              ; Flink
        jmp find_loop
    }
}
#else
// x64版本 - 需要独立的asm文件或使用intrinsic
void* ShellGetKernel32_x64() {
    void* peb = (void*)__readgsqword(0x60);
    void* ldr = *(void**)((BYTE*)peb + 0x18);
    void* entry = *(void**)((BYTE*)ldr + 0x20); // InMemoryOrderModuleList.Flink
    
    while (entry) {
        WCHAR* name = *(WCHAR**)((BYTE*)entry + 0x50); // BaseDllName.Buffer
        if (name) {
            // 简单检查
            if ((name[0] == L'K' || name[0] == L'k') &&
                name[7] == L'3' && name[8] == L'2') {
                return *(void**)((BYTE*)entry + 0x20); // DllBase
            }
        }
        entry = *(void**)entry; // Flink
    }
    return NULL;
}
#endif

#pragma optimize("", on)
#pragma code_seg()

// 提取ShellCode
void ExtractShellcode(void* func, size_t estimatedSize) {
    unsigned char* code = (unsigned char*)func;
    
    printf("Extracted Shellcode:\n");
    printf("unsigned char shellcode[] = \n\"");
    
    size_t actualSize = 0;
    for (size_t i = 0; i < estimatedSize; i++) {
        // 检查是否到达ret指令
        if (code[i] == 0xC3 || code[i] == 0xC2) {
            actualSize = i + 1;
            if (code[i] == 0xC2) actualSize += 2; // ret imm16
            break;
        }
    }
    
    if (actualSize == 0) actualSize = estimatedSize;
    
    for (size_t i = 0; i < actualSize; i++) {
        printf("\\x%02X", code[i]);
        if ((i + 1) % 16 == 0 && i < actualSize - 1) {
            printf("\"\n\"");
        }
    }
    printf("\";\n");
    printf("\nSize: %zu bytes\n", actualSize);
}

int main() {
    printf("========================================\n");
    printf("  Kernel32 Address Shellcode Generator  \n");
    printf("========================================\n\n");
    
    #ifndef _WIN64
    // 测试函数
    void* k32 = ShellGetKernel32();
    printf("Found Kernel32 at: %p\n", k32);
    printf("Verify: %p\n\n", GetModuleHandleW(L"kernel32.dll"));
    
    // 提取ShellCode
    ExtractShellcode((void*)ShellGetKernel32, 100);
    #else
    void* k32 = ShellGetKernel32_x64();
    printf("Found Kernel32 at: %p\n", k32);
    printf("Verify: %p\n", GetModuleHandleW(L"kernel32.dll"));
    #endif
    
    return 0;
}
```

### 4. 完整的哈希匹配版本

```c
// hash_kernel32.c
// 使用哈希匹配的健壮版本

#include <windows.h>
#include <stdio.h>

// ROR13哈希算法（与Metasploit兼容）
DWORD Ror13Hash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = (hash >> 13) | (hash << 19);  // ROR 13
        hash += *str;
        str++;
    }
    return hash;
}

// Unicode版本的ROR13
DWORD Ror13HashW(const WCHAR* str) {
    DWORD hash = 0;
    while (*str) {
        WCHAR c = *str;
        if (c >= 'A' && c <= 'Z') c += 0x20;  // 转小写
        hash = (hash >> 13) | (hash << 19);
        hash += (BYTE)c;
        str++;
    }
    return hash;
}

// 预计算的哈希值
#define HASH_KERNEL32   0x6A4ABC5B  // kernel32.dll
#define HASH_NTDLL      0x3CFA685D  // ntdll.dll
#define HASH_KERNELBASE 0x9E7AEB98  // kernelbase.dll

// 通过哈希获取模块
HMODULE GetModuleByHash(DWORD hash) {
    PPEB pPeb;
    
    #ifdef _WIN64
    pPeb = (PPEB)__readgsqword(0x60);
    #else
    pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    PLIST_ENTRY pListHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pListEntry = pListHead->Flink;
    
    while (pListEntry != pListHead) {
        PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(
            pListEntry, 
            LDR_DATA_TABLE_ENTRY, 
            InLoadOrderLinks
        );
        
        if (pEntry->BaseDllName.Buffer) {
            DWORD currentHash = Ror13HashW(pEntry->BaseDllName.Buffer);
            if (currentHash == hash) {
                return (HMODULE)pEntry->DllBase;
            }
        }
        pListEntry = pListEntry->Flink;
    }
    
    return NULL;
}

// 计算模块名哈希
void CalculateModuleHashes() {
    WCHAR* modules[] = {
        L"kernel32.dll",
        L"ntdll.dll",
        L"kernelbase.dll",
        L"user32.dll",
        L"ws2_32.dll",
        L"advapi32.dll"
    };
    
    printf("=== Module Hash Values ===\n");
    printf("#define HASH_%-12s 0x%08X\n", "KERNEL32", Ror13HashW(L"kernel32.dll"));
    printf("#define HASH_%-12s 0x%08X\n", "NTDLL", Ror13HashW(L"ntdll.dll"));
    printf("#define HASH_%-12s 0x%08X\n", "KERNELBASE", Ror13HashW(L"kernelbase.dll"));
    printf("#define HASH_%-12s 0x%08X\n", "USER32", Ror13HashW(L"user32.dll"));
    printf("#define HASH_%-12s 0x%08X\n", "WS2_32", Ror13HashW(L"ws2_32.dll"));
    printf("#define HASH_%-12s 0x%08X\n", "ADVAPI32", Ror13HashW(L"advapi32.dll"));
}

int main() {
    printf("========================================\n");
    printf("    Hash-based Module Resolution        \n");
    printf("========================================\n\n");
    
    CalculateModuleHashes();
    
    printf("\n=== Testing Module Resolution ===\n");
    
    HMODULE hKernel32 = GetModuleByHash(HASH_KERNEL32);
    HMODULE hNtdll = GetModuleByHash(HASH_NTDLL);
    
    printf("Kernel32: 0x%p (Expected: 0x%p)\n", 
        hKernel32, GetModuleHandleW(L"kernel32.dll"));
    printf("Ntdll:    0x%p (Expected: 0x%p)\n", 
        hNtdll, GetModuleHandleW(L"ntdll.dll"));
    
    return 0;
}
```

## 课后作业

### 作业1：实现通用模块查找
扩展代码，实现通过模块名哈希查找任意DLL的功能。

### 作业2：实现x64内联汇编版本
使用MASM或独立的.asm文件实现x64版本的GetKernel32。

### 作业3：偏移验证工具
编写程序，自动验证当前系统上PEB/LDR结构的偏移量。
