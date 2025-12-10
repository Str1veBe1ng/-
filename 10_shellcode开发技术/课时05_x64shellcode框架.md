# 课时05 - x64 ShellCode框架

## 课程目标
1. 理解x64架构与x86的关键差异
2. 掌握x64 ShellCode的开发技术
3. 实现完整的x64 ShellCode框架
4. 掌握x64调用约定和寄存器使用

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| x64 | AMD64/x86-64 | 64位扩展架构 |
| GS | GS Segment | x64用于访问TEB的段寄存器 |
| RCX/RDX/R8/R9 | - | x64调用约定的前4个参数寄存器 |
| Shadow Space | 影子空间 | 函数调用时预留的32字节栈空间 |
| Red Zone | 红区 | 栈指针下方128字节的保留区域 |
| REX | Register Extension | x64指令前缀，用于访问扩展寄存器 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| MASM (ml64) | x64汇编 | VS自带 |
| NASM | 跨平台汇编 | 支持x64 |
| x64dbg | 64位调试 | 调试验证 |
| Visual Studio | 开发环境 | x64不支持内联汇编 |

## 技术原理

### 1. x86与x64关键差异

| 特性 | x86 | x64 |
|------|-----|-----|
| 指针大小 | 4字节 | 8字节 |
| 通用寄存器 | EAX-EDI (8个) | RAX-R15 (16个) |
| TEB访问 | FS:[0x30] | GS:[0x60] |
| 调用约定 | cdecl/stdcall | Microsoft x64 |
| 参数传递 | 栈 | RCX,RDX,R8,R9+栈 |
| 返回值 | EAX | RAX |
| 影子空间 | 无 | 32字节必需 |

### 2. x64调用约定

```
参数传递:
  整数/指针: RCX, RDX, R8, R9, 栈
  浮点数:    XMM0, XMM1, XMM2, XMM3, 栈

影子空间: 调用前必须预留32字节
  sub rsp, 0x28  ; 32(影子) + 8(对齐) = 40 = 0x28

非易失寄存器: RBX, RBP, RDI, RSI, RSP, R12-R15
易失寄存器:   RAX, RCX, RDX, R8-R11
```

### 3. PEB结构偏移对比

```
x86:                            x64:
TEB: FS:[0x00]                  TEB: GS:[0x00]
PEB: FS:[0x30]                  PEB: GS:[0x60]
Ldr: PEB+0x0C                   Ldr: PEB+0x18
InLoadOrder: Ldr+0x0C           InLoadOrder: Ldr+0x10
InMemoryOrder: Ldr+0x14         InMemoryOrder: Ldr+0x20
InInitOrder: Ldr+0x1C           InInitOrder: Ldr+0x30
```

### 4. LDR_DATA_TABLE_ENTRY偏移

```
x86:                            x64:
DllBase: +0x18                  DllBase: +0x30
EntryPoint: +0x1C               EntryPoint: +0x38
SizeOfImage: +0x20              SizeOfImage: +0x40
FullDllName: +0x24              FullDllName: +0x48
BaseDllName: +0x2C              BaseDllName: +0x58
```

## 代码实现

### 1. x64 ShellCode框架（MASM）

```asm
; x64_shellcode.asm
; x64 ShellCode完整框架 - MASM64格式
; 编译: ml64 /c x64_shellcode.asm
;       link /entry:ShellEntry /subsystem:console x64_shellcode.obj

.code

; 哈希常量
HASH_KERNEL32       EQU 06A4ABC5Bh
HASH_LOADLIBRARYA   EQU 0EC0E4E8Eh
HASH_GETPROCADDRESS EQU 07C0DFCAAh
HASH_EXITPROCESS    EQU 073E2D87Eh
HASH_MESSAGEBOXA    EQU 0BC4DA2A8h

; ====== ShellCode入口 ======
ShellEntry PROC
    ; 保存非易失寄存器
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    ; 对齐栈（16字节对齐）
    sub rsp, 28h        ; 影子空间 + 对齐
    
    ; === 获取kernel32.dll基址 ===
    xor rcx, rcx
    mov rax, gs:[60h]       ; PEB
    mov rax, [rax + 18h]    ; Ldr
    mov rsi, [rax + 20h]    ; InMemoryOrderModuleList.Flink
    
find_kernel32:
    mov rdi, [rsi + 50h]    ; BaseDllName.Buffer
    test rdi, rdi
    jz next_module
    
    ; 检查是否为kernel32
    movzx rax, word ptr [rdi]
    or rax, 20h             ; 转小写
    cmp al, 'k'
    jne next_module
    
    movzx rax, word ptr [rdi + 0Eh]
    cmp al, '3'
    jne next_module
    
    ; 找到kernel32
    mov rbx, [rsi + 20h]    ; DllBase
    jmp got_kernel32
    
next_module:
    mov rsi, [rsi]          ; Flink
    jmp find_kernel32
    
got_kernel32:
    ; rbx = kernel32.dll基址
    
    ; === 获取GetProcAddress ===
    mov rcx, rbx
    mov rdx, HASH_GETPROCADDRESS
    call GetFunctionByHash
    mov r12, rax            ; r12 = GetProcAddress
    
    ; === 获取LoadLibraryA ===
    mov rcx, rbx
    mov rdx, HASH_LOADLIBRARYA
    call GetFunctionByHash
    mov r13, rax            ; r13 = LoadLibraryA
    
    ; === 获取ExitProcess ===
    mov rcx, rbx
    mov rdx, HASH_EXITPROCESS
    call GetFunctionByHash
    mov r14, rax            ; r14 = ExitProcess
    
    ; === 加载user32.dll ===
    ; 构造字符串 "user32.dll"
    sub rsp, 20h            ; 为字符串分配空间
    mov rax, 'resu'         ; "user" (little endian)
    mov [rsp], rax
    mov rax, 'd.23'         ; "32.d" 
    mov [rsp+4], rax
    mov word ptr [rsp+8], 'll'
    mov byte ptr [rsp+10], 0
    
    lea rcx, [rsp]          ; lpLibFileName
    call r13                ; LoadLibraryA
    mov r15, rax            ; r15 = user32.dll
    add rsp, 20h
    
    ; === 获取MessageBoxA ===
    mov rcx, r15
    mov rdx, HASH_MESSAGEBOXA
    call GetFunctionByHash
    mov rbp, rax            ; rbp = MessageBoxA
    
    ; === 调用MessageBoxA ===
    sub rsp, 20h            ; 字符串空间
    mov dword ptr [rsp], 'lleH'
    mov dword ptr [rsp+4], '!o'
    mov byte ptr [rsp+6], 0
    
    xor rcx, rcx            ; hWnd = NULL
    lea rdx, [rsp]          ; lpText
    xor r8, r8              ; lpCaption = NULL
    xor r9, r9              ; uType = MB_OK
    sub rsp, 20h            ; 影子空间
    call rbp
    add rsp, 40h
    
    ; === 退出 ===
    xor rcx, rcx            ; 退出码 = 0
    call r14                ; ExitProcess(0)
    
    ; 清理并返回
    add rsp, 28h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
ShellEntry ENDP

; ====== GetFunctionByHash ======
; 参数: RCX = 模块基址, RDX = 哈希值
; 返回: RAX = 函数地址
GetFunctionByHash PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    sub rsp, 20h
    
    mov rbx, rcx            ; rbx = 模块基址
    mov r8, rdx             ; r8 = 目标哈希
    
    ; 获取导出表
    mov eax, [rbx + 3Ch]    ; e_lfanew
    mov eax, [rbx + rax + 88h]  ; 导出表RVA (x64偏移)
    test eax, eax
    jz not_found_func
    
    add rax, rbx            ; 导出表VA
    mov rdi, rax            ; rdi = 导出表
    
    mov esi, [rdi + 20h]    ; AddressOfNames RVA
    add rsi, rbx            ; rsi = 名称表
    
    xor r9, r9              ; 索引 = 0
    
find_function_loop:
    mov r10d, [rdi + 18h]   ; NumberOfNames
    cmp r9d, r10d
    jge not_found_func
    
    mov eax, [rsi + r9*4]   ; 名称RVA
    add rax, rbx            ; 名称VA
    
    ; 计算哈希
    xor r10, r10            ; hash = 0
    
hash_loop:
    movzx r11, byte ptr [rax]
    test r11b, r11b
    jz hash_done
    
    ror r10d, 13
    add r10d, r11d
    inc rax
    jmp hash_loop
    
hash_done:
    cmp r10d, r8d           ; 比较哈希
    je found_function
    
    inc r9
    jmp find_function_loop
    
found_function:
    ; 获取序号
    mov eax, [rdi + 24h]    ; AddressOfNameOrdinals RVA
    add rax, rbx
    movzx eax, word ptr [rax + r9*2]
    
    ; 获取函数地址
    mov r10d, [rdi + 1Ch]   ; AddressOfFunctions RVA
    add r10, rbx
    mov eax, [r10 + rax*4]  ; 函数RVA
    add rax, rbx            ; 函数VA
    jmp done_func
    
not_found_func:
    xor rax, rax
    
done_func:
    add rsp, 20h
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
GetFunctionByHash ENDP

END
```

### 2. NASM格式的x64 ShellCode

```nasm
; x64_shellcode_nasm.asm
; NASM格式 - x64 ShellCode
; 编译: nasm -f win64 x64_shellcode_nasm.asm -o shellcode.obj
;       或: nasm -f bin x64_shellcode_nasm.asm -o shellcode.bin

BITS 64

; 哈希常量
%define HASH_KERNEL32       0x6A4ABC5B
%define HASH_LOADLIBRARYA   0xEC0E4E8E
%define HASH_GETPROCADDRESS 0x7C0DFCAA
%define HASH_EXITPROCESS    0x73E2D87E
%define HASH_MESSAGEBOXA    0xBC4DA2A8

section .text
global _start

_start:
    ; 保存寄存器
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    
    ; === 获取kernel32基址 ===
    xor rcx, rcx
    mov rax, [gs:0x60]      ; PEB
    mov rax, [rax + 0x18]   ; Ldr
    mov rsi, [rax + 0x20]   ; InMemoryOrderModuleList.Flink
    
.find_kernel32:
    mov rdi, [rsi + 0x50]   ; BaseDllName.Buffer
    test rdi, rdi
    jz .next_module
    
    movzx rax, word [rdi]
    or rax, 0x20
    cmp al, 'k'
    jne .next_module
    
    movzx rax, word [rdi + 14]
    cmp al, '3'
    jne .next_module
    
    mov rbx, [rsi + 0x20]   ; DllBase
    jmp .got_kernel32
    
.next_module:
    mov rsi, [rsi]
    jmp .find_kernel32
    
.got_kernel32:
    ; rbx = kernel32
    
    ; === 解析导出表获取函数 ===
    ; 获取GetProcAddress
    mov rcx, rbx
    mov edx, HASH_GETPROCADDRESS
    call .get_func_by_hash
    mov r12, rax            ; r12 = GetProcAddress
    
    ; 获取LoadLibraryA
    mov rcx, rbx
    mov edx, HASH_LOADLIBRARYA
    call .get_func_by_hash
    mov r13, rax            ; r13 = LoadLibraryA
    
    ; 获取ExitProcess
    mov rcx, rbx
    mov edx, HASH_EXITPROCESS
    call .get_func_by_hash
    mov r14, rax            ; r14 = ExitProcess
    
    ; === 加载user32.dll ===
    sub rsp, 0x20
    mov dword [rsp], 'user'
    mov dword [rsp+4], '32.d'
    mov word [rsp+8], 'll'
    mov byte [rsp+10], 0
    
    mov rcx, rsp
    sub rsp, 0x20           ; 影子空间
    call r13                ; LoadLibraryA
    add rsp, 0x40
    mov r15, rax            ; r15 = user32
    
    ; === 获取MessageBoxA ===
    mov rcx, r15
    mov edx, HASH_MESSAGEBOXA
    call .get_func_by_hash
    mov rbp, rax
    
    ; === 调用MessageBoxA ===
    sub rsp, 0x10
    mov dword [rsp], 'Hell'
    mov dword [rsp+4], 'o!'
    mov byte [rsp+6], 0
    
    xor rcx, rcx            ; hWnd
    lea rdx, [rsp]          ; lpText
    xor r8, r8              ; lpCaption
    xor r9, r9              ; uType
    sub rsp, 0x20           ; 影子空间
    call rbp
    add rsp, 0x30
    
    ; === 退出 ===
    xor rcx, rcx
    sub rsp, 0x20
    call r14
    add rsp, 0x20
    
    ; 恢复并返回
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret

; ====== 内部函数：通过哈希获取函数地址 ======
; rcx = 模块基址, edx = 哈希
; 返回: rax = 函数地址
.get_func_by_hash:
    push rbx
    push rsi
    push rdi
    push r8
    push r9
    push r10
    
    mov rbx, rcx            ; 模块基址
    mov r8d, edx            ; 目标哈希
    
    ; 导出表
    mov eax, [rbx + 0x3C]   ; e_lfanew
    mov eax, [rbx + rax + 0x88]  ; x64导出表RVA
    test eax, eax
    jz .func_not_found
    add rax, rbx
    mov rdi, rax            ; 导出表
    
    mov esi, [rdi + 0x20]   ; AddressOfNames RVA
    add rsi, rbx
    
    xor r9, r9              ; 索引
    
.func_find_loop:
    cmp r9d, [rdi + 0x18]   ; NumberOfNames
    jge .func_not_found
    
    mov eax, [rsi + r9*4]
    add rax, rbx            ; 函数名VA
    
    ; 计算ROR13哈希
    xor r10, r10
.hash_calc:
    movzx ecx, byte [rax]
    test cl, cl
    jz .hash_compare
    ror r10d, 13
    add r10d, ecx
    inc rax
    jmp .hash_calc
    
.hash_compare:
    cmp r10d, r8d
    je .func_found
    inc r9
    jmp .func_find_loop
    
.func_found:
    mov eax, [rdi + 0x24]   ; AddressOfNameOrdinals
    add rax, rbx
    movzx eax, word [rax + r9*2]
    
    mov r10d, [rdi + 0x1C]  ; AddressOfFunctions
    add r10, rbx
    mov eax, [r10 + rax*4]
    add rax, rbx
    jmp .func_done
    
.func_not_found:
    xor rax, rax
    
.func_done:
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    ret
```

### 3. C语言版本（使用独立asm文件）

```c
// x64_shellcode_c.c
// x64 ShellCode框架 - C语言实现
// 需要配合独立的.asm文件或使用intrinsic

#include <windows.h>
#include <stdio.h>
#include <intrin.h>

// 哈希常量
#define HASH_KERNEL32       0x6A4ABC5B
#define HASH_LOADLIBRARYA   0xEC0E4E8E
#define HASH_GETPROCADDRESS 0x7C0DFCAA
#define HASH_EXITPROCESS    0x73E2D87E
#define HASH_MESSAGEBOXA    0xBC4DA2A8
#define HASH_USER32         0x63C84283

// 函数指针类型
typedef HMODULE (WINAPI* PFN_LOADLIBRARYA)(LPCSTR);
typedef FARPROC (WINAPI* PFN_GETPROCADDRESS)(HMODULE, LPCSTR);
typedef void    (WINAPI* PFN_EXITPROCESS)(UINT);
typedef int     (WINAPI* PFN_MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

// ROR13哈希
__forceinline DWORD Ror13Hash(const char* str) {
    DWORD hash = 0;
    while (*str) {
        hash = _rotr(hash, 13) + *str;
        str++;
    }
    return hash;
}

// 通过PEB获取模块基址
__forceinline HMODULE GetModuleByHash(DWORD hash) {
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;
    PLIST_ENTRY pHead = &pLdr->InLoadOrderModuleList;
    PLIST_ENTRY pEntry = pHead->Flink;
    
    while (pEntry != pHead) {
        PLDR_DATA_TABLE_ENTRY pModule = CONTAINING_RECORD(
            pEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks
        );
        
        if (pModule->BaseDllName.Buffer) {
            // 计算模块名哈希（小写化）
            DWORD moduleHash = 0;
            WCHAR* name = pModule->BaseDllName.Buffer;
            while (*name) {
                WCHAR c = *name;
                if (c >= 'A' && c <= 'Z') c += 0x20;
                moduleHash = _rotr(moduleHash, 13) + (BYTE)c;
                name++;
            }
            
            if (moduleHash == hash) {
                return (HMODULE)pModule->DllBase;
            }
        }
        pEntry = pEntry->Flink;
    }
    return NULL;
}

// 通过哈希从模块获取函数
__forceinline FARPROC GetFuncByHash(HMODULE hModule, DWORD hash) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((LPBYTE)hModule + pDos->e_lfanew);
    
    DWORD exportRva = pNt->OptionalHeader.DataDirectory[0].VirtualAddress;
    if (!exportRva) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + exportRva);
    
    PDWORD pFunctions = (PDWORD)((LPBYTE)hModule + pExport->AddressOfFunctions);
    PDWORD pNames = (PDWORD)((LPBYTE)hModule + pExport->AddressOfNames);
    PWORD pOrdinals = (PWORD)((LPBYTE)hModule + pExport->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char* name = (char*)((LPBYTE)hModule + pNames[i]);
        if (Ror13Hash(name) == hash) {
            return (FARPROC)((LPBYTE)hModule + pFunctions[pOrdinals[i]]);
        }
    }
    return NULL;
}

// ShellCode主逻辑 - 可以转换为纯汇编
void ShellcodeMain() {
    // 获取kernel32
    HMODULE hKernel32 = GetModuleByHash(HASH_KERNEL32);
    
    // 获取关键API
    PFN_LOADLIBRARYA pLoadLibraryA = 
        (PFN_LOADLIBRARYA)GetFuncByHash(hKernel32, HASH_LOADLIBRARYA);
    PFN_GETPROCADDRESS pGetProcAddress = 
        (PFN_GETPROCADDRESS)GetFuncByHash(hKernel32, HASH_GETPROCADDRESS);
    PFN_EXITPROCESS pExitProcess = 
        (PFN_EXITPROCESS)GetFuncByHash(hKernel32, HASH_EXITPROCESS);
    
    // 加载user32.dll
    char szUser32[] = {'u','s','e','r','3','2','.','d','l','l',0};
    HMODULE hUser32 = pLoadLibraryA(szUser32);
    
    // 获取MessageBoxA
    char szMsgBox[] = {'M','e','s','s','a','g','e','B','o','x','A',0};
    PFN_MESSAGEBOXA pMessageBoxA = 
        (PFN_MESSAGEBOXA)pGetProcAddress(hUser32, szMsgBox);
    
    // 显示消息
    char szTitle[] = {'x','6','4',' ','S','h','e','l','l',0};
    char szText[] = {'H','e','l','l','o',' ','x','6','4','!',0};
    pMessageBoxA(NULL, szText, szTitle, 0);
    
    // 退出
    pExitProcess(0);
}

// x64汇编辅助（需要在.asm文件中实现）
extern void ShellcodeEntry_ASM();

int main() {
    printf("========================================\n");
    printf("      x64 ShellCode Framework          \n");
    printf("========================================\n\n");
    
    // 测试C版本
    printf("[*] Testing C version...\n");
    printf("[*] Press Enter to execute MessageBox\n");
    getchar();
    
    ShellcodeMain();
    
    return 0;
}
```

### 4. 独立的x64汇编文件（供C调用）

```asm
; x64_shell_asm.asm
; 供C程序调用的x64 ShellCode入口
; 编译: ml64 /c x64_shell_asm.asm

.data
    szUser32 db 'user32.dll', 0
    szMsgBox db 'MessageBoxA', 0
    szTitle  db 'x64 Shell', 0
    szText   db 'Hello from ASM!', 0

.code

; 导出函数
PUBLIC ShellcodeEntry_ASM

; 哈希常量
HASH_KERNEL32       EQU 06A4ABC5Bh
HASH_LOADLIBRARYA   EQU 0EC0E4E8Eh
HASH_GETPROCADDRESS EQU 07C0DFCAAh
HASH_EXITPROCESS    EQU 073E2D87Eh

ShellcodeEntry_ASM PROC
    ; 标准函数序言
    push rbp
    mov rbp, rsp
    sub rsp, 60h            ; 本地变量 + 影子空间
    
    ; 保存非易失寄存器
    mov [rbp-8], rbx
    mov [rbp-10h], rdi
    mov [rbp-18h], rsi
    mov [rbp-20h], r12
    mov [rbp-28h], r13
    mov [rbp-30h], r14
    mov [rbp-38h], r15
    
    ; === 获取kernel32 ===
    mov rax, gs:[60h]           ; PEB
    mov rax, [rax + 18h]        ; Ldr
    mov rsi, [rax + 20h]        ; InMemoryOrderModuleList.Flink
    
@@find_k32:
    mov rdi, [rsi + 50h]        ; BaseDllName.Buffer
    test rdi, rdi
    jz @@next_mod
    
    movzx rax, word ptr [rdi]
    or rax, 20h
    cmp al, 'k'
    jne @@next_mod
    
    movzx rax, word ptr [rdi + 0Eh]
    cmp al, '3'
    jne @@next_mod
    
    mov rbx, [rsi + 20h]        ; DllBase
    jmp @@got_k32
    
@@next_mod:
    mov rsi, [rsi]
    jmp @@find_k32
    
@@got_k32:
    ; rbx = kernel32
    
    ; === 获取LoadLibraryA ===
    mov rcx, rbx
    mov edx, HASH_LOADLIBRARYA
    call GetFuncByHashInternal
    mov r12, rax                ; r12 = LoadLibraryA
    
    ; === 获取GetProcAddress ===
    mov rcx, rbx
    mov edx, HASH_GETPROCADDRESS
    call GetFuncByHashInternal
    mov r13, rax                ; r13 = GetProcAddress
    
    ; === 获取ExitProcess ===
    mov rcx, rbx
    mov edx, HASH_EXITPROCESS
    call GetFuncByHashInternal
    mov r14, rax                ; r14 = ExitProcess
    
    ; === 加载user32.dll ===
    lea rcx, szUser32
    call r12                    ; LoadLibraryA
    mov r15, rax                ; r15 = user32
    
    ; === 获取MessageBoxA ===
    mov rcx, r15
    lea rdx, szMsgBox
    call r13                    ; GetProcAddress
    mov rbp, rax                ; rbp = MessageBoxA (临时使用)
    
    ; === 调用MessageBoxA ===
    xor rcx, rcx                ; hWnd = NULL
    lea rdx, szText             ; lpText
    lea r8, szTitle             ; lpCaption  
    xor r9, r9                  ; uType = MB_OK
    call rbp
    
    ; === 退出 ===
    xor rcx, rcx
    call r14                    ; ExitProcess(0)
    
    ; 恢复寄存器
    mov rbx, [rbp-8]
    mov rdi, [rbp-10h]
    mov rsi, [rbp-18h]
    mov r12, [rbp-20h]
    mov r13, [rbp-28h]
    mov r14, [rbp-30h]
    mov r15, [rbp-38h]
    
    add rsp, 60h
    pop rbp
    ret
ShellcodeEntry_ASM ENDP

; 内部函数：通过哈希获取函数
GetFuncByHashInternal PROC
    push r10
    push r11
    
    mov r10, rcx                ; 模块基址
    mov r11d, edx               ; 目标哈希
    
    mov eax, [r10 + 3Ch]        ; e_lfanew
    mov eax, [r10 + rax + 88h]  ; 导出表RVA
    test eax, eax
    jz @@not_found
    add rax, r10                ; 导出表VA
    
    push rax                    ; 保存导出表
    
    mov ecx, [rax + 20h]        ; AddressOfNames RVA
    add rcx, r10                ; AddressOfNames VA
    
    xor edx, edx                ; 索引
    
@@loop:
    pop rax
    push rax
    cmp edx, [rax + 18h]
    jge @@not_found_pop
    
    mov eax, [rcx + rdx*4]
    add rax, r10                ; 名称VA
    
    ; 计算哈希
    push rcx
    push rdx
    xor ecx, ecx                ; hash
@@hash:
    movzx edx, byte ptr [rax]
    test dl, dl
    jz @@hash_done
    ror ecx, 13
    add ecx, edx
    inc rax
    jmp @@hash
    
@@hash_done:
    cmp ecx, r11d
    pop rdx
    pop rcx
    je @@found
    
    inc edx
    jmp @@loop
    
@@found:
    pop rax                     ; 导出表
    push rax
    mov ecx, [rax + 24h]        ; AddressOfNameOrdinals
    add rcx, r10
    movzx ecx, word ptr [rcx + rdx*2]
    
    mov eax, [rax + 1Ch]        ; AddressOfFunctions
    add rax, r10
    mov eax, [rax + rcx*4]
    add rax, r10
    pop rcx                     ; 清理栈
    jmp @@done
    
@@not_found_pop:
    pop rax
@@not_found:
    xor eax, eax
    
@@done:
    pop r11
    pop r10
    ret
GetFuncByHashInternal ENDP

END
```

## 课后作业

### 作业1：添加更多功能
扩展x64 ShellCode，添加以下功能：
- 下载并执行文件
- 反向Shell连接

### 作业2：消除空字节
检查并消除x64 ShellCode中的所有空字节。

### 作业3：实现x64 Loader
编写一个x64 ShellCode加载器，支持从文件加载并执行。
