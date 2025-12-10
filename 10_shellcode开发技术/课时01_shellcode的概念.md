# 课时01 - ShellCode的概念

## 课程目标
1. 理解ShellCode的定义、起源和用途
2. 掌握ShellCode的特点和限制
3. 了解ShellCode开发的基本流程
4. 掌握位置无关代码(PIC)的概念

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| ShellCode | Shell Code | 一段用于利用软件漏洞执行的机器码，最初用于获取shell权限 |
| PIC | Position Independent Code | 位置无关代码，可在任意内存地址执行的代码 |
| Payload | 有效载荷 | 实际执行恶意功能的代码部分 |
| Stub | 存根代码 | 用于解密或准备执行环境的前置代码 |
| RWX | Read Write Execute | 内存页的可读可写可执行权限 |
| Opcode | Operation Code | 操作码，机器指令的二进制表示 |
| NOP | No Operation | 空操作指令，x86中为0x90 |
| Gadget | 代码片段 | ROP中可利用的小段代码 |

## 使用工具

| 工具 | 用途 | 下载地址 |
|------|------|----------|
| Visual Studio | 编写和编译代码 | 官方网站 |
| NASM | 汇编器 | nasm.us |
| x64dbg | 动态调试 | github.com/x64dbg |
| HxD | 十六进制编辑器 | mh-nexus.de |
| objdump | 反汇编工具 | GNU Binutils |
| msfvenom | ShellCode生成 | Metasploit |

## 技术原理

### 1. ShellCode的历史
ShellCode最早用于Unix系统溢出攻击，目的是获取一个shell（命令行），因此得名。现代ShellCode已经扩展到各种功能：
- 反向连接（Reverse Shell）
- 下载执行（Download & Execute）
- 注入执行（Inject & Execute）
- 权限提升（Privilege Escalation）

### 2. ShellCode的特点
```
┌─────────────────────────────────────────────────┐
│              ShellCode 特点                      │
├─────────────────────────────────────────────────┤
│  1. 位置无关 - 可在任意地址执行                  │
│  2. 自包含   - 不依赖外部符号表                  │
│  3. 体积小   - 通常几百字节到几KB                │
│  4. 无空字节 - 避免字符串截断(可选)              │
│  5. 可编码   - 支持各种编码变换                  │
└─────────────────────────────────────────────────┘
```

### 3. 开发挑战
| 挑战 | 说明 | 解决方案 |
|------|------|----------|
| 地址随机化 | ASLR使地址不固定 | 动态获取API地址 |
| 无导入表 | 无法静态链接 | 遍历PEB获取函数 |
| 空字节问题 | \x00截断字符串 | 编码或替换指令 |
| 字符限制 | 某些场景有字符过滤 | Alpha编码 |
| 体积限制 | 溢出缓冲区有限 | 分阶段加载 |

### 4. 开发流程
```
源代码(C/ASM) → 编译 → 提取机器码 → 测试验证 → 编码混淆
      ↓                    ↓              ↓
   消除依赖            消除空字节      免杀处理
```

## 代码实现

### 1. 最简单的ShellCode示例（弹出MessageBox）

```c
// shellcode_concept.c
// 理解ShellCode的概念 - 硬编码地址版本（仅用于学习）

#include <windows.h>
#include <stdio.h>

// 注意：这个ShellCode硬编码了地址，仅在特定环境下工作
// 实际开发中需要动态获取地址

// x86 MessageBox ShellCode（硬编码地址，仅演示）
unsigned char simple_shellcode[] = 
    "\x31\xc0"                      // xor eax, eax
    "\x50"                          // push eax (NULL)
    "\x68\x6c\x6c\x00\x00"          // push "ll\0\0"
    "\x68\x33\x32\x2e\x64"          // push "32.d"
    "\x68\x75\x73\x65\x72"          // push "user"
    "\x89\xe1"                      // mov ecx, esp (lpLibFileName)
    "\x31\xc0"                      // xor eax, eax
    "\x50"                          // push eax (NULL - hModule)
    "\x51"                          // push ecx (lpLibFileName)
    "\xb8\x00\x00\x00\x00"          // mov eax, LoadLibraryA address (需要填充)
    "\xff\xd0"                      // call eax
    // ... 后续调用MessageBoxA
;

// ShellCode加载器
typedef void (*SHELLCODE_FUNC)();

void ExecuteShellcode(unsigned char* code, size_t size) {
    // 分配可执行内存
    LPVOID execMem = VirtualAlloc(
        NULL,
        size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!execMem) {
        printf("[-] VirtualAlloc failed: %lu\n", GetLastError());
        return;
    }
    
    printf("[+] Allocated RWX memory at: %p\n", execMem);
    
    // 复制ShellCode到可执行内存
    memcpy(execMem, code, size);
    
    // 执行ShellCode
    printf("[+] Executing shellcode...\n");
    ((SHELLCODE_FUNC)execMem)();
    
    // 释放内存
    VirtualFree(execMem, 0, MEM_RELEASE);
}

// 内联汇编演示基本ShellCode结构
__declspec(naked) void ShellcodeDemo() {
    __asm {
        // 保存寄存器
        pushad
        
        // 清零寄存器
        xor eax, eax
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx
        
        // 这里放置实际功能代码
        // ...
        
        // 恢复寄存器
        popad
        
        // 返回
        ret
    }
}

// 分析ShellCode的结构
void AnalyzeShellcode(unsigned char* code, size_t size) {
    printf("\n=== ShellCode Analysis ===\n");
    printf("Size: %zu bytes\n", size);
    
    // 统计空字节
    int nullCount = 0;
    for (size_t i = 0; i < size; i++) {
        if (code[i] == 0x00) {
            nullCount++;
        }
    }
    printf("Null bytes: %d\n", nullCount);
    
    // 显示十六进制
    printf("\nHex dump:\n");
    for (size_t i = 0; i < size; i++) {
        printf("%02X ", code[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");
    
    // 生成C数组格式
    printf("\nC array format:\n");
    printf("unsigned char shellcode[] = \"");
    for (size_t i = 0; i < size; i++) {
        printf("\\x%02X", code[i]);
        if ((i + 1) % 16 == 0 && i < size - 1) {
            printf("\"\n    \"");
        }
    }
    printf("\";\n");
}

// 演示位置无关代码的概念
void DemonstratePIC() {
    printf("\n=== Position Independent Code Demo ===\n");
    
    // 位置相关代码的问题
    printf("Position Dependent (Bad):\n");
    printf("  mov eax, 0x12345678  ; 硬编码地址，不可移植\n");
    printf("  call 0x12345678      ; 硬编码调用，不可移植\n");
    
    // 位置无关代码的解决方案
    printf("\nPosition Independent (Good):\n");
    printf("  call next            ; 获取当前位置\n");
    printf("  next: pop eax        ; eax = 当前指令地址\n");
    printf("  ; 使用相对地址计算\n");
    
    // x86获取当前位置的技巧
    printf("\nGetPC Techniques:\n");
    printf("  1. call/pop: call next; next: pop reg\n");
    printf("  2. fstenv:   fldz; fstenv [esp-0x0c]; pop reg\n");
    printf("  3. fnstenv:  fnstenv [esp-0x0c]; pop reg\n");
}

// 主函数
int main() {
    printf("========================================\n");
    printf("    ShellCode Concept Demonstration     \n");
    printf("========================================\n");
    
    // 1. 演示PIC概念
    DemonstratePIC();
    
    // 2. 简单ShellCode分析
    unsigned char demo[] = "\x90\x90\x90\xCC"; // NOP, NOP, NOP, INT3
    AnalyzeShellcode(demo, sizeof(demo) - 1);
    
    // 3. ShellCode结构说明
    printf("\n=== Typical ShellCode Structure ===\n");
    printf("┌────────────────────────────────┐\n");
    printf("│  1. GetPC (获取当前位置)       │\n");
    printf("│  2. Find kernel32.dll          │\n");
    printf("│  3. Find GetProcAddress        │\n");
    printf("│  4. Resolve needed APIs        │\n");
    printf("│  5. Execute payload            │\n");
    printf("│  6. Clean exit                 │\n");
    printf("└────────────────────────────────┘\n");
    
    printf("\n[*] Demo completed.\n");
    return 0;
}
```

### 2. 理解ShellCode开发约束

```c
// shellcode_constraints.c
// 理解ShellCode开发中的各种约束

#include <windows.h>
#include <stdio.h>

// 演示空字节问题
void NullByteDemo() {
    printf("=== Null Byte Problem ===\n\n");
    
    // 有空字节的指令
    printf("Instructions with NULL bytes:\n");
    printf("  mov eax, 1      ->  B8 01 00 00 00  (3 null bytes)\n");
    printf("  push 0          ->  6A 00           (1 null byte)\n");
    printf("  xor eax, 0      ->  83 F0 00        (1 null byte)\n");
    
    // 消除空字节的技巧
    printf("\nNull-free alternatives:\n");
    printf("  mov eax, 1      ->  xor eax,eax; inc eax  (31 C0 40)\n");
    printf("  push 0          ->  xor eax,eax; push eax (31 C0 50)\n");
    printf("  xor eax, 0      ->  (just remove it)\n");
    
    // 常用消除空字节技巧
    printf("\nCommon techniques:\n");
    printf("  1. XOR to zero: xor reg, reg\n");
    printf("  2. SUB to zero: sub reg, reg\n");
    printf("  3. INC/DEC for small values\n");
    printf("  4. NEG for negative complement\n");
    printf("  5. NOT for bitwise complement\n");
}

// 指令编码对比
void InstructionEncodingDemo() {
    printf("\n=== Instruction Encoding Comparison ===\n\n");
    
    struct {
        const char* instruction;
        const char* encoding;
        int hasNull;
    } examples[] = {
        // 有空字节
        {"mov eax, 0", "B8 00 00 00 00", 1},
        {"mov eax, 1", "B8 01 00 00 00", 1},
        {"push 0", "6A 00", 1},
        {"jmp short +2", "EB 02", 0},
        
        // 无空字节替代
        {"xor eax, eax", "31 C0", 0},
        {"xor eax, eax; inc eax", "31 C0 40", 0},
        {"xor eax, eax; push eax", "31 C0 50", 0},
        {"xor ebx, ebx", "31 DB", 0},
        {"xor ecx, ecx", "31 C9", 0},
        {"xor edx, edx", "31 D2", 0},
    };
    
    printf("%-30s %-20s %s\n", "Instruction", "Encoding", "Null-Free");
    printf("%-30s %-20s %s\n", "----------", "--------", "---------");
    
    for (int i = 0; i < sizeof(examples)/sizeof(examples[0]); i++) {
        printf("%-30s %-20s %s\n", 
            examples[i].instruction,
            examples[i].encoding,
            examples[i].hasNull ? "No" : "Yes");
    }
}

// ShellCode分类
void ShellcodeClassification() {
    printf("\n=== ShellCode Classification ===\n\n");
    
    printf("By Function:\n");
    printf("  - Bind Shell: Opens a port and waits for connection\n");
    printf("  - Reverse Shell: Connects back to attacker\n");
    printf("  - Download & Execute: Downloads and runs payload\n");
    printf("  - Egg Hunter: Searches memory for larger payload\n");
    printf("  - Staged: Small loader + larger payload\n");
    
    printf("\nBy Platform:\n");
    printf("  - Windows x86/x64\n");
    printf("  - Linux x86/x64\n");
    printf("  - macOS x64/ARM64\n");
    printf("  - ARM/ARM64 (Mobile)\n");
    
    printf("\nBy Encoding:\n");
    printf("  - Raw: Unencoded machine code\n");
    printf("  - XOR: Simple XOR encoding\n");
    printf("  - Alphanumeric: Only [A-Za-z0-9]\n");
    printf("  - Unicode: UTF-16 compatible\n");
    printf("  - Polymorphic: Self-modifying\n");
}

// 开发环境检查
void CheckDevEnvironment() {
    printf("\n=== Development Environment Check ===\n\n");
    
    // 检查架构
    #ifdef _WIN64
    printf("[+] Architecture: x64 (64-bit)\n");
    #else
    printf("[+] Architecture: x86 (32-bit)\n");
    #endif
    
    // 检查编译器
    #ifdef _MSC_VER
    printf("[+] Compiler: MSVC %d\n", _MSC_VER);
    #elif defined(__GNUC__)
    printf("[+] Compiler: GCC %d.%d\n", __GNUC__, __GNUC_MINOR__);
    #endif
    
    // 检查Windows版本
    OSVERSIONINFOW osvi = { sizeof(OSVERSIONINFOW) };
    // GetVersionExW(&osvi); // 已弃用，但演示用
    
    // 检查DEP
    DWORD flags;
    if (GetProcessDEPPolicy(GetCurrentProcess(), &flags, NULL)) {
        printf("[+] DEP: %s\n", (flags & PROCESS_DEP_ENABLE) ? "Enabled" : "Disabled");
    }
    
    // 内存页权限测试
    LPVOID mem = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (mem) {
        printf("[+] RWX allocation: Allowed\n");
        VirtualFree(mem, 0, MEM_RELEASE);
    } else {
        printf("[-] RWX allocation: Blocked\n");
    }
}

int main() {
    printf("========================================\n");
    printf("   ShellCode Development Constraints    \n");
    printf("========================================\n");
    
    NullByteDemo();
    InstructionEncodingDemo();
    ShellcodeClassification();
    CheckDevEnvironment();
    
    printf("\n[*] Constraint analysis complete.\n");
    return 0;
}
```

## 课后作业

### 作业1：空字节消除练习
将以下指令改写为无空字节版本：
```asm
mov eax, 0x00001000
mov ebx, 0
push 0x00000000
mov ecx, 0x00000001
```

### 作业2：ShellCode结构分析
分析Metasploit生成的windows/exec ShellCode，识别其各个组成部分。

### 作业3：简单加载器
编写一个ShellCode加载器，能够：
1. 从文件读取ShellCode
2. 分配可执行内存
3. 执行ShellCode
