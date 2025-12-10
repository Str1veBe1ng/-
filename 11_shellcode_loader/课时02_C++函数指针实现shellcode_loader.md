# 课时02 - C++函数指针实现ShellCode Loader

## 课程目标
1. 理解函数指针在ShellCode执行中的应用
2. 掌握多种函数指针类型定义方式
3. 了解不同调用约定对执行的影响
4. 实现健壮的函数指针Loader

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Function Pointer | 函数指针 | 指向函数的指针，可用于间接调用 |
| cdecl | C Declaration | C语言默认调用约定，调用者清理栈 |
| stdcall | Standard Call | Windows API调用约定，被调用者清理栈 |
| fastcall | Fast Call | 使用寄存器传递前两个参数 |
| typedef | Type Definition | 类型定义，用于创建类型别名 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| Visual Studio | 开发编译 | 支持x86/x64 |
| x64dbg | 调试分析 | 观察调用过程 |
| IDA Pro | 静态分析 | 分析生成的代码 |

## 技术原理

### 1. 函数指针基础

```cpp
// 基本语法
return_type (*pointer_name)(parameter_types);

// 例子
void (*func_ptr)();                    // 无参无返回
int (*func_ptr)(int, int);            // 两参数返回int
void* (*func_ptr)(size_t);            // 返回void*
```

### 2. 使用typedef简化

```cpp
// 定义类型
typedef void (*SHELLCODE_FUNC)();
typedef int (*SHELLCODE_FUNC_INT)(int);

// 使用
SHELLCODE_FUNC func = (SHELLCODE_FUNC)address;
func();
```

### 3. 调用约定对比

```
cdecl:    调用者清理栈，参数从右向左入栈
stdcall:  被调用者清理栈，参数从右向左入栈
fastcall: 前两个参数通过ECX/EDX传递，其余入栈
thiscall: this指针通过ECX传递（C++方法）
```

## 代码实现

### 1. 基础函数指针Loader

```cpp
// func_ptr_loader.cpp
// 函数指针ShellCode Loader

#include <windows.h>
#include <stdio.h>

// 测试ShellCode
unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP
    0x31, 0xC0,              // xor eax, eax
    0x40,                    // inc eax (return 1)
    0xC3                     // ret
};

//=============================================================================
// 方法1: 最基础的函数指针
//=============================================================================
typedef void (*SHELLCODE_VOID)();

void Method1_BasicVoid() {
    printf("[*] Method 1: Basic Void Function Pointer\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) {
        printf("[-] VirtualAlloc failed\n");
        return;
    }
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 转换为函数指针并调用
    SHELLCODE_VOID func = (SHELLCODE_VOID)mem;
    printf("[*] Calling shellcode at %p\n", mem);
    func();
    
    printf("[+] Returned from shellcode\n");
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法2: 带返回值的函数指针
//=============================================================================
typedef int (*SHELLCODE_INT)();

void Method2_WithReturn() {
    printf("[*] Method 2: Function Pointer with Return Value\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    SHELLCODE_INT func = (SHELLCODE_INT)mem;
    int result = func();
    
    printf("[+] ShellCode returned: %d (0x%X)\n", result, result);
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法3: 带参数的函数指针
//=============================================================================
typedef int (*SHELLCODE_PARAMS)(int a, int b);

// 测试带参数的ShellCode (返回 a + b)
unsigned char shellcode_add[] = {
    0x8B, 0x44, 0x24, 0x04,  // mov eax, [esp+4]  ; 第一个参数
    0x03, 0x44, 0x24, 0x08,  // add eax, [esp+8]  ; 加上第二个参数
    0xC3                      // ret
};

void Method3_WithParams() {
    printf("[*] Method 3: Function Pointer with Parameters\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode_add),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode_add, sizeof(shellcode_add));
    
    SHELLCODE_PARAMS func = (SHELLCODE_PARAMS)mem;
    int result = func(10, 20);
    
    printf("[+] func(10, 20) = %d\n", result);
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法4: 使用指定调用约定
//=============================================================================
#ifdef _WIN32
typedef int (__cdecl *SHELLCODE_CDECL)(int, int);
typedef int (__stdcall *SHELLCODE_STDCALL)(int, int);

// stdcall版本的加法ShellCode
unsigned char shellcode_add_stdcall[] = {
    0x8B, 0x44, 0x24, 0x04,  // mov eax, [esp+4]
    0x03, 0x44, 0x24, 0x08,  // add eax, [esp+8]
    0xC2, 0x08, 0x00         // ret 8 (清理8字节参数)
};

void Method4_CallingConvention() {
    printf("[*] Method 4: Calling Convention\n");
    
    // cdecl版本
    LPVOID mem1 = VirtualAlloc(NULL, sizeof(shellcode_add),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem1, shellcode_add, sizeof(shellcode_add));
    
    SHELLCODE_CDECL func_cdecl = (SHELLCODE_CDECL)mem1;
    int r1 = func_cdecl(5, 3);
    printf("[+] cdecl: func(5, 3) = %d\n", r1);
    
    // stdcall版本
    LPVOID mem2 = VirtualAlloc(NULL, sizeof(shellcode_add_stdcall),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(mem2, shellcode_add_stdcall, sizeof(shellcode_add_stdcall));
    
    SHELLCODE_STDCALL func_stdcall = (SHELLCODE_STDCALL)mem2;
    int r2 = func_stdcall(5, 3);
    printf("[+] stdcall: func(5, 3) = %d\n", r2);
    
    VirtualFree(mem1, 0, MEM_RELEASE);
    VirtualFree(mem2, 0, MEM_RELEASE);
}
#endif

//=============================================================================
// 方法5: Lambda表达式封装 (C++11)
//=============================================================================
void Method5_LambdaWrapper() {
    printf("[*] Method 5: Lambda Wrapper\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 使用lambda封装
    auto execute = [mem]() -> int {
        typedef int (*SC_FUNC)();
        SC_FUNC func = (SC_FUNC)mem;
        return func();
    };
    
    int result = execute();
    printf("[+] Lambda returned: %d\n", result);
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法6: 使用std::function (C++11)
//=============================================================================
#include <functional>

void Method6_StdFunction() {
    printf("[*] Method 6: std::function\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 包装为std::function
    std::function<int()> func = reinterpret_cast<int(*)()>(mem);
    
    int result = func();
    printf("[+] std::function returned: %d\n", result);
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法7: 两步分配（安全方式）
//=============================================================================
void Method7_TwoStepAlloc() {
    printf("[*] Method 7: Two-Step Allocation (RW -> RX)\n");
    
    // 步骤1: 分配可写内存
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!mem) return;
    
    printf("[+] Allocated RW memory at %p\n", mem);
    
    // 复制ShellCode
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 步骤2: 修改为可执行
    DWORD oldProtect;
    if (!VirtualProtect(mem, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect)) {
        printf("[-] VirtualProtect failed\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    printf("[+] Changed to RX protection\n");
    
    // 执行
    typedef int (*SC_FUNC)();
    SC_FUNC func = (SC_FUNC)mem;
    int result = func();
    
    printf("[+] Returned: %d\n", result);
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法8: 带异常处理
//=============================================================================
void Method8_WithException() {
    printf("[*] Method 8: With Exception Handling\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    typedef int (*SC_FUNC)();
    SC_FUNC func = (SC_FUNC)mem;
    
    __try {
        int result = func();
        printf("[+] Returned: %d\n", result);
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception: 0x%08X\n", GetExceptionCode());
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 方法9: 从文件加载
//=============================================================================
void Method9_FromFile(const char* filename) {
    printf("[*] Method 9: Load from File\n");
    
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot open file: %s\n", filename);
        return;
    }
    
    DWORD fileSize = GetFileSize(hFile, NULL);
    printf("[+] File size: %lu bytes\n", fileSize);
    
    LPVOID mem = VirtualAlloc(NULL, fileSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) {
        CloseHandle(hFile);
        return;
    }
    
    DWORD bytesRead;
    ReadFile(hFile, mem, fileSize, &bytesRead, NULL);
    CloseHandle(hFile);
    
    printf("[+] Loaded %lu bytes to %p\n", bytesRead, mem);
    
    typedef void (*SC_FUNC)();
    SC_FUNC func = (SC_FUNC)mem;
    
    __try {
        func();
        printf("[+] Execution completed\n");
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] Exception: 0x%08X\n", GetExceptionCode());
    }
    
    VirtualFree(mem, 0, MEM_RELEASE);
}

//=============================================================================
// 主函数
//=============================================================================
int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("  Function Pointer ShellCode Loader    \n");
    printf("========================================\n\n");
    
    // 执行所有方法
    Method1_BasicVoid();
    printf("\n");
    
    Method2_WithReturn();
    printf("\n");
    
    Method3_WithParams();
    printf("\n");
    
    #ifdef _WIN32
    Method4_CallingConvention();
    printf("\n");
    #endif
    
    Method5_LambdaWrapper();
    printf("\n");
    
    Method6_StdFunction();
    printf("\n");
    
    Method7_TwoStepAlloc();
    printf("\n");
    
    Method8_WithException();
    printf("\n");
    
    // 文件加载
    if (argc >= 2) {
        Method9_FromFile(argv[1]);
    }
    
    printf("[*] All methods completed.\n");
    return 0;
}
```

### 2. 泛型函数指针Loader类

```cpp
// generic_loader.hpp
// 泛型ShellCode Loader类

#pragma once
#include <windows.h>
#include <functional>
#include <memory>
#include <stdexcept>

template<typename Signature>
class ShellcodeLoader;

// 特化版本
template<typename ReturnType, typename... Args>
class ShellcodeLoader<ReturnType(Args...)> {
public:
    using FuncType = ReturnType(*)(Args...);
    
private:
    LPVOID m_memory;
    SIZE_T m_size;
    bool m_executable;
    
public:
    ShellcodeLoader() : m_memory(nullptr), m_size(0), m_executable(false) {}
    
    ~ShellcodeLoader() {
        Free();
    }
    
    // 禁止拷贝
    ShellcodeLoader(const ShellcodeLoader&) = delete;
    ShellcodeLoader& operator=(const ShellcodeLoader&) = delete;
    
    // 允许移动
    ShellcodeLoader(ShellcodeLoader&& other) noexcept
        : m_memory(other.m_memory), m_size(other.m_size), 
          m_executable(other.m_executable) {
        other.m_memory = nullptr;
        other.m_size = 0;
    }
    
    // 加载ShellCode
    bool Load(const void* shellcode, SIZE_T size) {
        Free();
        
        m_size = size;
        m_memory = VirtualAlloc(nullptr, size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (!m_memory) return false;
        
        memcpy(m_memory, shellcode, size);
        return true;
    }
    
    // 设为可执行
    bool MakeExecutable() {
        if (!m_memory || m_executable) return false;
        
        DWORD oldProtect;
        if (!VirtualProtect(m_memory, m_size, PAGE_EXECUTE_READ, &oldProtect)) {
            return false;
        }
        
        m_executable = true;
        return true;
    }
    
    // 执行
    ReturnType Execute(Args... args) {
        if (!m_memory) {
            throw std::runtime_error("No shellcode loaded");
        }
        
        if (!m_executable) {
            if (!MakeExecutable()) {
                throw std::runtime_error("Failed to make executable");
            }
        }
        
        FuncType func = reinterpret_cast<FuncType>(m_memory);
        return func(args...);
    }
    
    // 运算符重载
    ReturnType operator()(Args... args) {
        return Execute(args...);
    }
    
    // 获取地址
    LPVOID GetAddress() const { return m_memory; }
    SIZE_T GetSize() const { return m_size; }
    
private:
    void Free() {
        if (m_memory) {
            VirtualFree(m_memory, 0, MEM_RELEASE);
            m_memory = nullptr;
            m_size = 0;
            m_executable = false;
        }
    }
};

// 使用示例
/*
int main() {
    unsigned char code[] = { 0x31, 0xC0, 0x40, 0xC3 }; // xor eax,eax; inc eax; ret
    
    ShellcodeLoader<int()> loader;
    loader.Load(code, sizeof(code));
    
    int result = loader.Execute();  // 或 loader()
    printf("Result: %d\n", result);
    
    return 0;
}
*/
```

## 课后作业

### 作业1：添加加密支持
扩展Loader，支持在加载前对ShellCode进行XOR解密。

### 作业2：实现Lazy Loading
实现延迟加载机制，在首次调用时才分配内存和复制ShellCode。

### 作业3：添加校验功能
在执行前对ShellCode进行完整性校验（如CRC32或MD5）。
