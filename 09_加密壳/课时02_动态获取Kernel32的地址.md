# 课时02：动态获取Kernel32的地址

## 课程目标

1. 理解为什么壳需要动态获取API
2. 掌握通过PEB获取模块列表的方法
3. 学会在x86和x64下获取Kernel32基址
4. 理解模块列表的遍历方法

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| PEB | Process Environment Block | 进程环境块 |
| TEB | Thread Environment Block | 线程环境块 |
| LDR | Loader Data | 加载器数据 |
| InLoadOrderModuleList | - | 按加载顺序的模块链表 |
| InMemoryOrderModuleList | - | 按内存顺序的模块链表 |
| LDR_DATA_TABLE_ENTRY | - | 模块信息结构 |
| DllBase | - | 模块基地址 |
| BaseDllName | - | 模块名称 |

## 使用工具

- Visual Studio 2022
- x64dbg
- WinDbg
- Process Hacker

## 技术原理

### PEB结构

```
TEB (Thread Environment Block)
 ├── fs:[0x00] (x86) / gs:[0x00] (x64) = ExceptionList
 ├── fs:[0x18] (x86) / gs:[0x30] (x64) = Self (TEB地址)
 └── fs:[0x30] (x86) / gs:[0x60] (x64) = PEB

PEB (Process Environment Block)
 ├── +0x00 InheritedAddressSpace
 ├── +0x02 BeingDebugged          ★反调试
 ├── +0x08 (x86) / +0x10 (x64) = ImageBaseAddress
 └── +0x0C (x86) / +0x18 (x64) = Ldr (PEB_LDR_DATA*)

PEB_LDR_DATA
 ├── +0x00 Length
 ├── +0x04 Initialized
 ├── +0x0C (x86) / +0x10 (x64) = InLoadOrderModuleList
 ├── +0x14 (x86) / +0x20 (x64) = InMemoryOrderModuleList
 └── +0x1C (x86) / +0x30 (x64) = InInitializationOrderModuleList

模块加载顺序 (InInitializationOrderModuleList):
1. ntdll.dll
2. kernel32.dll (或 kernelbase.dll)
3. ...其他DLL
```

### LDR_DATA_TABLE_ENTRY结构

```c
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;              // 模块基址 ★
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;      // 模块名 ★
    // ...更多字段
} LDR_DATA_TABLE_ENTRY;
```

## 代码实现

### x86获取Kernel32基址

```c
// 方法1：通过PEB遍历模块列表
__declspec(naked) HMODULE GetKernel32_x86_PEB() {
    __asm {
        xor eax, eax
        mov eax, fs:[0x30]          // PEB
        mov eax, [eax + 0x0C]       // Ldr
        mov eax, [eax + 0x1C]       // InInitializationOrderModuleList
        
    next_module:
        mov ebx, [eax + 0x08]       // DllBase
        mov ecx, [eax + 0x20]       // BaseDllName.Buffer
        
        // 检查是否是kernel32.dll
        // 简单检查：第一个字符是'k'或'K' (0x6B/0x4B)
        movzx edx, word ptr [ecx]
        and edx, 0xDF               // 转大写
        cmp edx, 0x4B               // 'K'
        jne not_kernel32
        
        // 检查第7个字符是'3' (kernel32)
        movzx edx, word ptr [ecx + 12]  // 第7个字符（Unicode偏移）
        cmp edx, 0x33               // '3'
        jne not_kernel32
        
        mov eax, ebx                // 返回DllBase
        ret
        
    not_kernel32:
        mov eax, [eax]              // 下一个模块
        jmp next_module
    }
}

// 方法2：通过SEH获取（利用异常处理链）
// ntdll!KiUserExceptionDispatcher -> kernel32!UnhandledExceptionFilter
__declspec(naked) HMODULE GetKernel32_x86_SEH() {
    __asm {
        xor eax, eax
        mov eax, fs:[0x00]          // ExceptionList
        
    find_last:
        cmp dword ptr [eax], -1     // 检查是否是最后一个
        je found
        mov eax, [eax]
        jmp find_last
        
    found:
        mov eax, [eax + 4]          // Handler地址（在ntdll中）
        and eax, 0xFFFF0000         // 对齐到64KB
        
    find_mz:
        cmp word ptr [eax], 0x5A4D  // 检查MZ
        je check_pe
        sub eax, 0x10000
        jmp find_mz
        
    check_pe:
        // 这是ntdll，需要继续查找kernel32
        // 简化：直接返回找到的模块
        ret
    }
}

// 方法3：完整的字符串比较版本
HMODULE GetKernel32_x86_Full() {
    HMODULE hKernel32 = NULL;
    
    __asm {
        mov eax, fs:[0x30]          // PEB
        mov eax, [eax + 0x0C]       // Ldr
        mov esi, [eax + 0x1C]       // InInitializationOrderModuleList
        
    loop_modules:
        lodsd                       // eax = [esi]; esi += 4
        mov esi, eax
        mov ebx, [eax + 0x08]       // DllBase
        mov edi, [eax + 0x20]       // BaseDllName.Buffer
        
        // 计算字符串哈希
        xor ecx, ecx
        xor edx, edx
        
    hash_loop:
        mov dl, [edi]
        test dl, dl
        jz hash_done
        
        // 转小写
        cmp dl, 'A'
        jb no_convert
        cmp dl, 'Z'
        ja no_convert
        add dl, 0x20
        
    no_convert:
        ror ecx, 13
        add ecx, edx
        inc edi
        inc edi                     // Unicode
        jmp hash_loop
        
    hash_done:
        // kernel32.dll 哈希 = 0x6A4ABC5B
        cmp ecx, 0x6A4ABC5B
        jne loop_modules
        
        mov hKernel32, ebx
    }
    
    return hKernel32;
}
```

### x64获取Kernel32基址

```c
// x64版本
HMODULE GetKernel32_x64() {
    HMODULE hKernel32 = NULL;
    
    // 使用内嵌汇编需要MASM或单独的.asm文件
    // 这里用C实现
    
    // 获取PEB
    PPEB peb = (PPEB)__readgsqword(0x60);
    
    // 获取Ldr
    PPEB_LDR_DATA ldr = peb->Ldr;
    
    // 遍历InMemoryOrderModuleList
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    
    while (entry != head) {
        // 计算LDR_DATA_TABLE_ENTRY地址
        // InMemoryOrderLinks是结构体偏移0x10的位置
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(
            entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
        );
        
        // 检查模块名
        if (module->BaseDllName.Buffer) {
            // 简单检查kernel32
            WCHAR* name = module->BaseDllName.Buffer;
            
            if ((name[0] == L'K' || name[0] == L'k') &&
                (name[1] == L'E' || name[1] == L'e') &&
                (name[2] == L'R' || name[2] == L'r') &&
                (name[3] == L'N' || name[3] == L'n') &&
                (name[4] == L'E' || name[4] == L'e') &&
                (name[5] == L'L' || name[5] == L'l') &&
                name[6] == L'3' && name[7] == L'2') {
                return (HMODULE)module->DllBase;
            }
        }
        
        entry = entry->Flink;
    }
    
    return NULL;
}

// 纯汇编版本（需要编译为.asm）
/*
GetKernel32_x64_asm PROC
    xor rax, rax
    mov rax, gs:[60h]           ; PEB
    mov rax, [rax + 18h]        ; Ldr
    mov rsi, [rax + 20h]        ; InMemoryOrderModuleList
    
loop_modules:
    mov rsi, [rsi]              ; Flink
    mov rbx, [rsi + 20h]        ; DllBase (偏移可能需要调整)
    mov rdi, [rsi + 50h]        ; BaseDllName.Buffer
    
    ; 检查kernel32
    movzx eax, word ptr [rdi]
    and eax, 0DFh               ; 转大写
    cmp eax, 4Bh                ; 'K'
    jne loop_modules
    
    movzx eax, word ptr [rdi + 18h]  ; 第10个字符(偏移0x12的Unicode)
    cmp eax, 33h                ; '3'
    jne loop_modules
    
    mov rax, rbx
    ret
GetKernel32_x64_asm ENDP
*/
```

### 使用哈希比较模块名

```c
// 计算字符串哈希（ROR13）
DWORD HashString(const char* str) {
    DWORD hash = 0;
    
    while (*str) {
        char c = *str;
        // 转小写
        if (c >= 'A' && c <= 'Z') {
            c += 0x20;
        }
        
        hash = ((hash >> 13) | (hash << 19));  // ROR 13
        hash += c;
        str++;
    }
    
    return hash;
}

// 计算Unicode字符串哈希
DWORD HashStringW(const WCHAR* str) {
    DWORD hash = 0;
    
    while (*str) {
        WCHAR c = *str;
        // 转小写
        if (c >= L'A' && c <= L'Z') {
            c += 0x20;
        }
        
        hash = ((hash >> 13) | (hash << 19));
        hash += (char)c;  // 只取低字节
        str++;
    }
    
    return hash;
}

// 常用模块哈希值
#define HASH_KERNEL32   0x6A4ABC5B
#define HASH_NTDLL      0x3CFA685D
#define HASH_USER32     0x63C84283
#define HASH_KERNELBASE 0x7040EE75

// 通过哈希获取模块
HMODULE GetModuleByHash(DWORD hash) {
    PPEB peb;
    
    #ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
    #else
    __asm {
        mov eax, fs:[0x30]
        mov peb, eax
    }
    #endif
    
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &ldr->InMemoryOrderModuleList;
    PLIST_ENTRY entry = head->Flink;
    
    while (entry != head) {
        PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(
            entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks
        );
        
        if (module->BaseDllName.Buffer) {
            DWORD moduleHash = HashStringW(module->BaseDllName.Buffer);
            
            if (moduleHash == hash) {
                return (HMODULE)module->DllBase;
            }
        }
        
        entry = entry->Flink;
    }
    
    return NULL;
}
```

### 壳中的实际使用

```c
// 壳代码中使用（位置无关）
typedef HMODULE (WINAPI* LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI* VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* VIRTUALPROTECT)(LPVOID, SIZE_T, DWORD, PDWORD);

// 壳初始化函数
void ShellInit() {
    // 获取kernel32基址
    HMODULE hKernel32 = GetKernel32_x64();
    
    // 获取关键API
    // 这需要解析导出表，下一课讲解
    GETPROCADDRESS pGetProcAddress = FindExportByHash(hKernel32, HASH_GETPROCADDRESS);
    
    // 现在可以用GetProcAddress获取其他API
    LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)pGetProcAddress(hKernel32, "LoadLibraryA");
    VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)pGetProcAddress(hKernel32, "VirtualAlloc");
    VIRTUALPROTECT pVirtualProtect = (VIRTUALPROTECT)pGetProcAddress(hKernel32, "VirtualProtect");
    
    // 继续壳的主要功能...
}
```

## 课后作业

1. **实现x86和x64版本**
   - 编写获取Kernel32基址的代码
   - 使用x64dbg验证正确性
   - 测试不同Windows版本

2. **实现哈希查找模块**
   - 预计算常用模块哈希
   - 实现通过哈希获取任意模块
   - 处理大小写问题

3. **研究其他获取方法**
   - 研究通过SEH获取
   - 研究通过API地址回溯
   - 比较各方法的优缺点
