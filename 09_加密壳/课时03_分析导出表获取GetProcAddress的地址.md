# 课时03：分析导出表获取GetProcAddress的地址

## 课程目标

1. 掌握通过导出表查找函数的方法
2. 实现自定义GetProcAddress
3. 使用哈希代替字符串查找
4. 在壳代码中获取必要的API

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| EAT | Export Address Table | 导出地址表 |
| ENT | Export Name Table | 导出名称表 |
| EOT | Export Ordinal Table | 导出序号表 |
| Ordinal | 序号 | 函数的数字标识 |
| ROR13 | Rotate Right 13 | 循环右移13位哈希算法 |

## 使用工具

- Visual Studio 2022
- x64dbg
- PE-bear
- dumpbin

## 技术原理

### 导出表查找流程

```
1. 定位导出表
   DllBase + e_lfanew -> NT_HEADERS
   NT_HEADERS + DataDirectory[0] -> Export Directory RVA
   DllBase + Export RVA -> IMAGE_EXPORT_DIRECTORY

2. 获取三个表
   AddressOfFunctions -> EAT (函数地址数组)
   AddressOfNames -> ENT (函数名RVA数组)
   AddressOfNameOrdinals -> EOT (序号数组)

3. 查找函数名
   遍历ENT，比较函数名
   获取索引i

4. 获取序号
   Ordinal = EOT[i]

5. 获取函数地址
   FunctionRVA = EAT[Ordinal]
   FunctionVA = DllBase + FunctionRVA
```

## 代码实现

### 解析导出表获取函数地址

```c
// 通过函数名获取导出函数地址
FARPROC GetFunctionByName(HMODULE hModule, const char* funcName) {
    LPBYTE base = (LPBYTE)hModule;
    
    // 获取DOS头
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    
    // 获取NT头
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
    
    // 获取导出目录
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (exportRVA == 0) {
        return NULL;  // 没有导出表
    }
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);
    
    // 获取三个表
    DWORD* addressOfFunctions = (DWORD*)(base + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)(base + exportDir->AddressOfNames);
    WORD* addressOfOrdinals = (WORD*)(base + exportDir->AddressOfNameOrdinals);
    
    // 遍历名称表
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)(base + addressOfNames[i]);
        
        // 比较函数名
        if (strcmp(name, funcName) == 0) {
            // 获取序号
            WORD ordinal = addressOfOrdinals[i];
            
            // 获取函数RVA
            DWORD funcRVA = addressOfFunctions[ordinal];
            
            // 返回函数VA
            return (FARPROC)(base + funcRVA);
        }
    }
    
    return NULL;
}

// 通过序号获取导出函数
FARPROC GetFunctionByOrdinal(HMODULE hModule, WORD ordinal) {
    LPBYTE base = (LPBYTE)hModule;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
    
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (exportRVA == 0) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);
    
    // 计算索引（减去Base）
    DWORD index = ordinal - exportDir->Base;
    
    if (index >= exportDir->NumberOfFunctions) {
        return NULL;
    }
    
    DWORD* addressOfFunctions = (DWORD*)(base + exportDir->AddressOfFunctions);
    DWORD funcRVA = addressOfFunctions[index];
    
    return (FARPROC)(base + funcRVA);
}
```

### 使用哈希查找函数

```c
// ROR13哈希算法
DWORD Ror13Hash(const char* str) {
    DWORD hash = 0;
    
    while (*str) {
        hash = ((hash >> 13) | (hash << 19));
        hash += *str;
        str++;
    }
    
    return hash;
}

// 预计算的API哈希
#define HASH_GETPROCADDRESS     0x7C0DFCAA
#define HASH_LOADLIBRARYA       0xEC0E4E8E
#define HASH_VIRTUALALLOC       0x91AFCA54
#define HASH_VIRTUALPROTECT     0x7946C61B
#define HASH_VIRTUALFREE        0x30633AC
#define HASH_EXITPROCESS        0x73E2D87E
#define HASH_GETMODULEHANDLEA   0xD3324904

// 通过哈希获取函数
FARPROC GetFunctionByHash(HMODULE hModule, DWORD funcHash) {
    LPBYTE base = (LPBYTE)hModule;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + dosHeader->e_lfanew);
    
    DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (exportRVA == 0) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)(base + exportRVA);
    
    DWORD* addressOfFunctions = (DWORD*)(base + exportDir->AddressOfFunctions);
    DWORD* addressOfNames = (DWORD*)(base + exportDir->AddressOfNames);
    WORD* addressOfOrdinals = (WORD*)(base + exportDir->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char* name = (char*)(base + addressOfNames[i]);
        
        // 计算哈希并比较
        if (Ror13Hash(name) == funcHash) {
            WORD ordinal = addressOfOrdinals[i];
            DWORD funcRVA = addressOfFunctions[ordinal];
            return (FARPROC)(base + funcRVA);
        }
    }
    
    return NULL;
}
```

### 位置无关的汇编实现

```c
// x86汇编版本
__declspec(naked) FARPROC __stdcall GetProcAddressByHash_x86(
    HMODULE hModule, DWORD funcHash) {
    __asm {
        push ebp
        mov ebp, esp
        push ebx
        push esi
        push edi
        
        mov ebx, [ebp + 8]          // hModule (base)
        mov edx, [ebp + 12]         // funcHash
        
        // 获取导出目录
        mov eax, [ebx + 0x3C]       // e_lfanew
        mov eax, [ebx + eax + 0x78] // Export RVA (0x60 + 0x18 for x86)
        test eax, eax
        jz not_found
        add eax, ebx                // Export Directory VA
        
        // 保存导出目录
        push eax
        
        // 获取三个表
        mov ecx, [eax + 0x1C]       // AddressOfFunctions RVA
        add ecx, ebx                // EAT VA
        mov esi, [eax + 0x20]       // AddressOfNames RVA
        add esi, ebx                // ENT VA
        mov edi, [eax + 0x24]       // AddressOfOrdinals RVA
        add edi, ebx                // EOT VA
        
        // 获取名称数量
        pop eax
        mov eax, [eax + 0x18]       // NumberOfNames
        
        xor ebp, ebp                // 索引 = 0
        
    search_loop:
        cmp ebp, eax
        jge not_found
        
        // 获取函数名
        mov eax, [esi + ebp * 4]    // 名称RVA
        add eax, ebx                // 名称VA
        
        // 计算哈希
        push ecx
        push edi
        xor ecx, ecx                // hash = 0
        
    hash_loop:
        movzx edi, byte ptr [eax]
        test edi, edi
        jz hash_done
        
        ror ecx, 13
        add ecx, edi
        inc eax
        jmp hash_loop
        
    hash_done:
        // 比较哈希
        cmp ecx, edx
        pop edi
        pop ecx
        je found
        
        inc ebp
        mov eax, [esp - 4]          // NumberOfNames（之前压入）
        jmp search_loop
        
    found:
        // 获取序号
        movzx eax, word ptr [edi + ebp * 2]
        
        // 获取函数RVA
        mov eax, [ecx + eax * 4]
        add eax, ebx                // 函数VA
        jmp done
        
    not_found:
        xor eax, eax
        
    done:
        pop edi
        pop esi
        pop ebx
        pop ebp
        ret 8
    }
}
```

### 完整的API获取器

```c
// API函数指针类型
typedef HMODULE (WINAPI* PFN_LoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI* PFN_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI* PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI* PFN_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI* PFN_VirtualFree)(LPVOID, SIZE_T, DWORD);

// API表结构
typedef struct _API_TABLE {
    PFN_LoadLibraryA    LoadLibraryA;
    PFN_GetProcAddress  GetProcAddress;
    PFN_VirtualAlloc    VirtualAlloc;
    PFN_VirtualProtect  VirtualProtect;
    PFN_VirtualFree     VirtualFree;
} API_TABLE;

// 初始化API表
BOOL InitApiTable(API_TABLE* api) {
    // 获取kernel32基址
    HMODULE hKernel32 = GetModuleByHash(HASH_KERNEL32);
    if (!hKernel32) {
        return FALSE;
    }
    
    // 获取关键API
    api->LoadLibraryA = (PFN_LoadLibraryA)GetFunctionByHash(
        hKernel32, HASH_LOADLIBRARYA);
    api->GetProcAddress = (PFN_GetProcAddress)GetFunctionByHash(
        hKernel32, HASH_GETPROCADDRESS);
    api->VirtualAlloc = (PFN_VirtualAlloc)GetFunctionByHash(
        hKernel32, HASH_VIRTUALALLOC);
    api->VirtualProtect = (PFN_VirtualProtect)GetFunctionByHash(
        hKernel32, HASH_VIRTUALPROTECT);
    api->VirtualFree = (PFN_VirtualFree)GetFunctionByHash(
        hKernel32, HASH_VIRTUALFREE);
    
    // 验证
    if (!api->LoadLibraryA || !api->GetProcAddress || 
        !api->VirtualAlloc || !api->VirtualProtect) {
        return FALSE;
    }
    
    return TRUE;
}

// 计算哈希的辅助工具
void PrintFunctionHashes() {
    const char* functions[] = {
        "GetProcAddress",
        "LoadLibraryA",
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualFree",
        "ExitProcess",
        "GetModuleHandleA",
        NULL
    };
    
    for (int i = 0; functions[i]; i++) {
        printf("#define HASH_%-20s 0x%08X\n", 
               functions[i], Ror13Hash(functions[i]));
    }
}
```

## 课后作业

1. **实现完整的函数查找器**
   - 支持按名称查找
   - 支持按序号查找
   - 支持按哈希查找

2. **编写哈希生成工具**
   - 读取DLL导出表
   - 为所有导出函数生成哈希
   - 输出为头文件格式

3. **测试不同哈希算法**
   - 实现CRC32哈希
   - 实现DJB2哈希
   - 比较碰撞概率和性能
