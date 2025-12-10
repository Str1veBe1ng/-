# 课时08 - TLS机制

## 课程目标

1. 理解线程本地存储的概念
2. 掌握TLS API的使用
3. 学会TLS回调函数
4. 理解TLS在反调试中的应用

## 名词解释

| 术语 | 英文 | 说明 |
|------|------|------|
| TLS | Thread Local Storage | 线程本地存储 |
| TLS索引 | TLS Index | 标识TLS槽位的整数 |
| TLS回调 | TLS Callback | 线程创建/销毁时的回调 |

## 代码实现

### 示例1：TLS API使用

```c
#include <windows.h>
#include <stdio.h>

DWORD g_tlsIndex = 0;

DWORD WINAPI ThreadFunc(LPVOID lpParam) {
    int id = (int)(size_t)lpParam;
    
    // 为当前线程设置TLS数据
    int* pData = (int*)LocalAlloc(LPTR, sizeof(int));
    *pData = id * 100;
    TlsSetValue(g_tlsIndex, pData);
    
    // 获取TLS数据
    int* pValue = (int*)TlsGetValue(g_tlsIndex);
    printf("Thread %d: TLS value = %d\n", id, *pValue);
    
    // 清理
    LocalFree(pData);
    return 0;
}

void TLSDemo() {
    // 分配TLS索引
    g_tlsIndex = TlsAlloc();
    
    HANDLE threads[3];
    for (int i = 0; i < 3; i++) {
        threads[i] = CreateThread(NULL, 0, ThreadFunc, (LPVOID)(size_t)i, 0, NULL);
    }
    
    WaitForMultipleObjects(3, threads, TRUE, INFINITE);
    
    for (int i = 0; i < 3; i++) CloseHandle(threads[i]);
    TlsFree(g_tlsIndex);
}
```

### 示例2：__declspec(thread)

```c
#include <windows.h>
#include <stdio.h>

// 静态TLS变量
__declspec(thread) int g_threadData = 0;

DWORD WINAPI StaticTLSThread(LPVOID lpParam) {
    int id = (int)(size_t)lpParam;
    
    g_threadData = id * 10;
    printf("Thread %d: g_threadData = %d\n", id, g_threadData);
    
    return 0;
}
```

### 示例3：TLS回调函数（反调试）

```c
#include <windows.h>
#include <stdio.h>

// TLS回调函数
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        // 在main之前执行！
        if (IsDebuggerPresent()) {
            MessageBoxA(NULL, "Debugger detected!", "Warning", MB_OK);
            ExitProcess(1);
        }
    }
}

// 注册TLS回调
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_tls_callback = TlsCallback;
#pragma data_seg()

int main() {
    printf("Main function running\n");
    return 0;
}
```

## 课后作业

1. **基础练习**：使用TLS实现线程安全的计数器
2. **TLS回调**：实现在main前执行的初始化代码
3. **反调试**：使用TLS回调检测调试器
4. **PE分析**：分析可执行文件的TLS目录