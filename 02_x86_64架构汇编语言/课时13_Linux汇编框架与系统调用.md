# 课时13 - Linux汇编框架与系统调用

## 课程目标

1. 掌握Linux下的汇编编程框架
2. 理解Linux系统调用机制
3. 学会使用GAS和NASM语法
4. 掌握位置无关代码编写

## 名词解释

| 术语 | 英文 | 说明 |
|------|------|------|
| syscall | System Call | 系统调用，用户态进入内核态 |
| GAS | GNU Assembler | GNU汇编器，使用AT&T语法 |
| NASM | Netwide Assembler | 使用Intel语法的汇编器 |
| ELF | Executable and Linkable Format | Linux可执行文件格式 |
| PIC | Position Independent Code | 位置无关代码 |

## 使用工具

| 工具 | 用途 |
|------|------|
| nasm | NASM汇编器 |
| as/gas | GNU汇编器 |
| ld | GNU链接器 |
| gcc | 编译和链接 |
| objdump | 反汇编分析 |
| strace | 跟踪系统调用 |

## 技术原理

### Linux x86 系统调用

| 寄存器 | 用途 |
|----------|------|
| EAX | 系统调用号 |
| EBX | 第1参数 |
| ECX | 第2参数 |
| EDX | 第3参数 |
| ESI | 第4参数 |
| EDI | 第5参数 |
| int 0x80 | 触发系统调用 |

### Linux x64 系统调用

| 寄存器 | 用途 |
|----------|------|
| RAX | 系统调用号 |
| RDI | 第1参数 |
| RSI | 第2参数 |
| RDX | 第3参数 |
| R10 | 第4参数 |
| R8 | 第5参数 |
| R9 | 第6参数 |
| syscall | 触发系统调用 |

## 代码实现

### 示例1：NASM Hello World (x86)

```asm
; hello32.asm
; nasm -f elf32 hello32.asm
; ld -m elf_i386 -o hello32 hello32.o

section .data
    msg db "Hello, Linux!", 10   ; 10 = \n
    len equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov eax, 4          ; sys_write
    mov ebx, 1          ; stdout
    mov ecx, msg        ; buffer
    mov edx, len        ; length
    int 0x80            ; 系统调用
    
    ; exit(0)
    mov eax, 1          ; sys_exit
    xor ebx, ebx        ; 退出码 0
    int 0x80
```

### 示例2：NASM Hello World (x64)

```asm
; hello64.asm
; nasm -f elf64 hello64.asm
; ld -o hello64 hello64.o

section .data
    msg db "Hello, Linux x64!", 10
    len equ $ - msg

section .text
    global _start

_start:
    ; write(1, msg, len)
    mov rax, 1          ; sys_write
    mov rdi, 1          ; stdout
    lea rsi, [rel msg]  ; buffer (RIP相对)
    mov rdx, len        ; length
    syscall
    
    ; exit(0)
    mov rax, 60         ; sys_exit
    xor edi, edi        ; 退出码 0
    syscall
```

### 示例3：GAS AT&T语法

```asm
# hello_gas.s
# as --32 -o hello_gas.o hello_gas.s
# ld -m elf_i386 -o hello_gas hello_gas.o

.section .data
msg:
    .ascii "Hello from GAS!\n"
    len = . - msg

.section .text
.globl _start

_start:
    # write(1, msg, len)
    movl $4, %eax       # sys_write
    movl $1, %ebx       # stdout
    leal msg, %ecx      # buffer
    movl $len, %edx     # length
    int $0x80
    
    # exit(0)
    movl $1, %eax       # sys_exit
    xorl %ebx, %ebx
    int $0x80
```

### 示例4：文件操作系统调用

```asm
; fileops.asm (x64)
; nasm -f elf64 fileops.asm && ld -o fileops fileops.o

section .data
    filename db "test.txt", 0
    content db "Hello File!", 10
    content_len equ $ - content
    
    read_buf times 256 db 0

section .text
    global _start

_start:
    ; open(filename, O_CREAT|O_WRONLY|O_TRUNC, 0644)
    mov rax, 2              ; sys_open
    lea rdi, [rel filename]
    mov rsi, 0x241          ; O_CREAT|O_WRONLY|O_TRUNC
    mov rdx, 0644o          ; 权限
    syscall
    
    mov r12, rax            ; 保存文件描述符
    
    ; write(fd, content, len)
    mov rax, 1              ; sys_write
    mov rdi, r12            ; fd
    lea rsi, [rel content]
    mov rdx, content_len
    syscall
    
    ; close(fd)
    mov rax, 3              ; sys_close
    mov rdi, r12
    syscall
    
    ; 重新打开并读取
    mov rax, 2
    lea rdi, [rel filename]
    xor rsi, rsi            ; O_RDONLY
    syscall
    
    mov r12, rax
    
    ; read(fd, buf, 256)
    mov rax, 0              ; sys_read
    mov rdi, r12
    lea rsi, [rel read_buf]
    mov rdx, 256
    syscall
    
    mov r13, rax            ; 保存读取长度
    
    ; 写到stdout
    mov rax, 1
    mov rdi, 1
    lea rsi, [rel read_buf]
    mov rdx, r13
    syscall
    
    ; close
    mov rax, 3
    mov rdi, r12
    syscall
    
    ; exit
    mov rax, 60
    xor edi, edi
    syscall
```

### 示例5：与C程序链接

```asm
; asmlib.asm (x64)
; nasm -f elf64 asmlib.asm

section .text
    global asm_add
    global asm_strlen

; int asm_add(int a, int b)
; RDI = a, RSI = b
asm_add:
    mov eax, edi
    add eax, esi
    ret

; size_t asm_strlen(const char* s)
; RDI = s
asm_strlen:
    xor rax, rax            ; 计数器
.loop:
    cmp byte [rdi + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret
```

```c
// main.c
#include <stdio.h>

extern int asm_add(int a, int b);
extern size_t asm_strlen(const char* s);

int main() {
    printf("asm_add(10, 20) = %d\n", asm_add(10, 20));
    
    const char* str = "Hello World";
    printf("asm_strlen(\"%s\") = %zu\n", str, asm_strlen(str));
    
    return 0;
}

// 编译: gcc -c main.c && ld main.o asmlib.o -lc -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o main
// 或: gcc main.c asmlib.o -o main
```

### 示例6：Shellcode基础

```asm
; shellcode.asm (x64)
; 用于提取shellcode的无依赖代码

BITS 64

_start:
    ; 清除寄存器
    xor rax, rax
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    
    ; 拼接"/bin/sh"字符串
    push rax                ; null terminator
    mov rdi, 0x68732f6e69622f   ; "/bin/sh" in little-endian
    push rdi
    mov rdi, rsp            ; rdi = 字符串指针
    
    ; execve("/bin/sh", NULL, NULL)
    push rax                ; NULL
    push rdi                ; "/bin/sh"
    mov rsi, rsp            ; argv
    xor rdx, rdx            ; envp = NULL
    mov al, 59              ; sys_execve
    syscall

; nasm -f bin -o shellcode.bin shellcode.asm
; xxd -i shellcode.bin
```

### 示例7：常用系统调用号

```c
// 系统调用号参考（x64 Linux）
/*
read     = 0
write    = 1
open     = 2
close    = 3
stat     = 4
fstat    = 5
mmap     = 9
mprotect = 10
munmap   = 11
brk      = 12
ioctl    = 16
access   = 21
pipe     = 22
dup      = 32
dup2     = 33
fork     = 57
execve   = 59
exit     = 60
wait4    = 61
kill     = 62
getpid   = 39
getuid   = 102
getgid   = 104
setuid   = 105
setgid   = 106
socket   = 41
connect  = 42
accept   = 43
sendto   = 44
recvfrom = 45
bind     = 49
listen   = 50
*/
```

## 课后作业

1. **基础练习**：用NASM编写一个读取用户输入并回显的程序
2. **文件操作**：实现一个简单的文件复制程序
3. **系统调用**：使用mmap系统调用分配内存
4. **混合编程**：创建一个C和汇编混合的Linux程序