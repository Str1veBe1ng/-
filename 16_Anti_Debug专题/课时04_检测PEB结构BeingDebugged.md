# 课时04 检测PEB结构BeingDebugged

## 一、课程目标

本节课主要学习如何直接检测PEB（Process Environment Block）结构中的BeingDebugged字段，这是反调试技术中最基础也是最重要的方法之一。通过本课的学习，你将能够：

1. 深入理解PEB结构中BeingDebugged字段的作用和位置
2. 掌握直接读取PEB中BeingDebugged标志位的方法
3. 学会在不同架构（x86/x64）下访问PEB结构
4. 理解该技术与其他反调试技术的关系
5. 了解该技术的检测和绕过方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| PEB | Process Environment Block，进程环境块，存储进程相关信息的数据结构 |
| BeingDebugged | PEB结构中的一个标志位，偏移量为0x02（x86）或0x02（x64），用于指示进程是否被调试 |
| TEB | Thread Environment Block，线程环境块，存储线程相关信息的数据结构 |
| FS/GS寄存器 | x86/x64架构中的段寄存器，用于访问线程和进程信息 |
| 偏移量 | 数据结构中字段相对于结构起始地址的字节距离 |
| 内存布局 | 程序在内存中的组织结构 |

## 三、技术原理

### 3.1 PEB结构详解

PEB（Process Environment Block）是Windows操作系统中一个至关重要的数据结构，包含了进程运行所需的各种信息。在反调试技术中，我们重点关注以下几个字段：

1. **BeingDebugged（偏移0x02）**：1字节，指示进程是否被调试
   - 0：进程未被调试
   - 非0：进程正在被调试

2. **其他相关字段**：
   - NtGlobalFlag（偏移0x68/0xBC）：全局标志
   - ProcessHeap（偏移0x18/0x30）：进程堆信息

### 3.2 PEB结构在不同架构下的差异

#### x86架构下的PEB结构（部分）：
```
Offset  Size    Field
0x00    PVOID   InheritedAddressSpace
0x01    PVOID   ReadImageFileExecOptions
0x02    UCHAR   BeingDebugged          <- 关键字段
0x03    UCHAR   BitField
0x04    PVOID   Mutant
0x08    PVOID   ImageBaseAddress
...
```

#### x64架构下的PEB结构（部分）：
```
Offset  Size    Field
0x00    PVOID   InheritedAddressSpace
0x01    PVOID   ReadImageFileExecOptions
0x02    UCHAR   BeingDebugged          <- 关键字段
0x03    UCHAR   BitField
0x08    PVOID   Mutant
0x10    PVOID   ImageBaseAddress
...
```

注意：BeingDebugged字段在两种架构下的偏移量都是0x02。

### 3.3 访问PEB的机制

在x86架构中：
- FS寄存器指向当前线程的TEB（Thread Environment Block）
- TEB的第一个字段（偏移0x30）指向PEB

在x64架构中：
- GS寄存器指向当前线程的TEB
- TEB的第一个字段（偏移0x60）指向PEB

## 四、代码实现

### 4.1 直接读取PEB中BeingDebugged字段

```cpp
#include <windows.h>
#include <stdio.h>

// 方法1：使用编译器内置函数（推荐）
BOOL CheckPEBBeingDebugged1() {
#ifdef _WIN64
    // x64架构
    PBYTE peb = (PBYTE)__readgsqword(0x60);  // 获取PEB指针
    return peb[0x2];  // 读取BeingDebugged标志
#else
    // x86架构
    PBYTE peb = (PBYTE)__readfsdword(0x30);  // 获取PEB指针
    return peb[0x2];  // 读取BeingDebugged标志
#endif
}

// 方法2：使用内联汇编（仅x86）
#ifdef _X86_
BOOL CheckPEBBeingDebugged2() {
    __asm {
        mov eax, fs:[0x30]     ; 获取PEB指针
        movzx eax, byte ptr [eax+0x2]  ; 读取BeingDebugged标志
    }
    // 返回值在EAX中
}
#endif

// 方法3：使用NtCurrentTeb函数
#include <winnt.h>
extern "C" PVOID NTAPI NtCurrentTeb();

BOOL CheckPEBBeingDebugged3() {
#ifdef _WIN64
    PVOID teb = NtCurrentTeb();
    PBYTE peb = *(PBYTE*)((PBYTE)teb + 0x60);  // TEB+0x60 = PEB指针
    return *(PBYTE)(peb + 0x2);  // PEB+0x2 = BeingDebugged标志
#else
    PVOID teb = NtCurrentTeb();
    PBYTE peb = *(PBYTE*)((PBYTE)teb + 0x30);  // TEB+0x30 = PEB指针
    return *(PBYTE)(peb + 0x2);  // PEB+0x2 = BeingDebugged标志
#endif
}
```

### 4.2 完整的PEB访问实现

```cpp
// 获取PEB指针的通用方法
PVOID GetPEB() {
#ifdef _WIN64
    // x64架构
    return (PVOID)__readgsqword(0x60);
#else
    // x86架构
    return (PVOID)__readfsdword(0x30);
#endif
}

// 读取PEB中指定偏移的字节
BYTE ReadPEBByte(DWORD offset) {
    PBYTE peb = (PBYTE)GetPEB();
    return peb[offset];
}

// 读取PEB中指定偏移的DWORD
DWORD ReadPEBDWord(DWORD offset) {
    PBYTE peb = (PBYTE)GetPEB();
    return *(PDWORD)(peb + offset);
}

// 读取PEB中指定偏移的指针
PVOID ReadPEBPointer(DWORD offset) {
    PBYTE peb = (PBYTE)GetPEB();
    return *(PVOID*)(peb + offset);
}

// 检测BeingDebugged标志
BOOL IsProcessBeingDebugged() {
    return ReadPEBByte(0x2) != 0;
}

// 检测其他PEB字段
BOOL CheckPEBNtGlobalFlag() {
#ifdef _WIN64
    DWORD ntGlobalFlag = ReadPEBDWord(0xBC);
#else
    DWORD ntGlobalFlag = ReadPEBDWord(0x68);
#endif
    // 检查是否设置了调试相关的标志
    return (ntGlobalFlag & 0x70) != 0;
}

// 检测ProcessHeap字段
BOOL CheckPEBProcessHeap() {
#ifdef _WIN64
    PVOID processHeap = ReadPEBPointer(0x30);
#else
    PVOID processHeap = ReadPEBPointer(0x18);
#endif
    
    // 检查堆的Flags字段
    DWORD heapFlags = *(PDWORD)((PBYTE)processHeap + 0x40);
    return (heapFlags & 0x2) != 0;  // HEAP_FLAG_VALIDATE_PARAMETERS
}
```

### 4.3 反调试实现

```cpp
// 简单的反调试实现
VOID SimplePEBAntiDebug() {
    if (IsProcessBeingDebugged()) {
        printf("检测到调试器存在！程序即将退出。\n");
        ExitProcess(1);
    }
}

// 多重PEB检测
BOOL MultiPEBAntiDebug() {
    BOOL detected = FALSE;
    
    // 检测1：BeingDebugged标志
    if (IsProcessBeingDebugged()) {
        detected = TRUE;
    }
    
    // 检测2：NtGlobalFlag
    if (CheckPEBNtGlobalFlag()) {
        detected = TRUE;
    }
    
    // 检测3：ProcessHeap
    if (CheckPEBProcessHeap()) {
        detected = TRUE;
    }
    
    return detected;
}

// 增强版反调试
VOID EnhancedPEBAntiDebug() {
    // 多次检测
    for (int i = 0; i < 5; i++) {
        if (MultiPEBAntiDebug()) {
            printf("第%d次检测发现调试器！\n", i + 1);
            
            // 随机化响应
            int response = rand() % 4;
            switch (response) {
            case 0:
                ExitProcess(0);
            case 1:
                printf("发生未知错误。\n");
                Sleep(5000);
                exit(1);
            case 2:
                // 执行错误指令
                __debugbreak();
            case 3:
                // 进入无限循环
                while (1) {
                    Sleep(1000);
                }
            }
        }
        
        // 随机延迟
        Sleep(rand() % 100 + 50);
    }
    
    printf("PEB反调试检测通过。\n");
}
```

### 4.4 绕过PEB检测的方法

```cpp
// 修改PEB中BeingDebugged标志
VOID BypassPEBBeingDebugged() {
    PBYTE peb = (PBYTE)GetPEB();
    peb[0x2] = 0;  // 将BeingDebugged标志设置为0
    
    printf("PEB中的BeingDebugged标志已被修改为0。\n");
}

// 修改PEB中NtGlobalFlag
VOID BypassPEBNtGlobalFlag() {
#ifdef _WIN64
    PBYTE peb = (PBYTE)GetPEB();
    PDWORD ntGlobalFlag = (PDWORD)(peb + 0xBC);
    *ntGlobalFlag &= ~0x70;  // 清除调试相关标志
#else
    PBYTE peb = (PBYTE)GetPEB();
    PDWORD ntGlobalFlag = (PDWORD)(peb + 0x68);
    *ntGlobalFlag &= ~0x70;  // 清除调试相关标志
#endif
    
    printf("PEB中的NtGlobalFlag已被修改。\n");
}

// 修改ProcessHeap Flags
VOID BypassPEBProcessHeap() {
#ifdef _WIN64
    PBYTE peb = (PBYTE)GetPEB();
    PVOID processHeap = *(PVOID*)(peb + 0x30);
#else
    PBYTE peb = (PBYTE)GetPEB();
    PVOID processHeap = *(PVOID*)(peb + 0x18);
#endif
    
    PDWORD heapFlags = (PDWORD)((PBYTE)processHeap + 0x40);
    *heapFlags &= ~0x2;  // 清除HEAP_FLAG_VALIDATE_PARAMETERS
    
    printf("ProcessHeap Flags已被修改。\n");
}

// 综合绕过方法
VOID ComprehensiveBypass() {
    BypassPEBBeingDebugged();
    BypassPEBNtGlobalFlag();
    BypassPEBProcessHeap();
    
    printf("所有PEB相关标志均已绕过。\n");
}
```

### 4.5 完整测试程序

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 前面实现的函数声明
BOOL CheckPEBBeingDebugged1();
BOOL IsProcessBeingDebugged();
BOOL MultiPEBAntiDebug();
VOID BypassPEBBeingDebugged();

// 测试所有PEB检测方法
VOID TestAllPEBMethods() {
    printf("=== PEB检测方法测试 ===\n");
    
    // 方法1：直接读取BeingDebugged
    BOOL method1 = CheckPEBBeingDebugged1();
    printf("方法1 (直接读取): %s\n", method1 ? "被调试" : "未被调试");
    
    // 方法2：封装函数
    BOOL method2 = IsProcessBeingDebugged();
    printf("方法2 (封装函数): %s\n", method2 ? "被调试" : "未被调试");
    
    // 方法3：多重检测
    BOOL method3 = MultiPEBAntiDebug();
    printf("方法3 (多重检测): %s\n", method3 ? "被调试" : "未被调试");
    
    // 验证一致性
    if (method1 == method2) {
        printf("基本方法结果一致。\n");
    } else {
        printf("警告：基本方法结果不一致！\n");
    }
    
    printf("\n");
}

// PEB结构信息显示
VOID DisplayPEBInfo() {
    printf("=== PEB信息显示 ===\n");
    
    PVOID peb = GetPEB();
    printf("PEB地址: 0x%p\n", peb);
    
    BYTE beingDebugged = ReadPEBByte(0x2);
    printf("BeingDebugged: 0x%02X\n", beingDebugged);
    
#ifdef _WIN64
    DWORD ntGlobalFlag = ReadPEBDWord(0xBC);
    PVOID processHeap = ReadPEBPointer(0x30);
#else
    DWORD ntGlobalFlag = ReadPEBDWord(0x68);
    PVOID processHeap = ReadPEBPointer(0x18);
#endif
    
    printf("NtGlobalFlag: 0x%08X\n", ntGlobalFlag);
    printf("ProcessHeap: 0x%p\n", processHeap);
    
    DWORD heapFlags = *(PDWORD)((PBYTE)processHeap + 0x40);
    printf("Heap Flags: 0x%08X\n", heapFlags);
    
    printf("\n");
}

// 性能测试
VOID PerformanceTest() {
    const int iterations = 1000000;
    
    printf("=== 性能测试 (%d次调用) ===\n", iterations);
    
    // 测试直接读取方法
    DWORD start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        CheckPEBBeingDebugged1();
    }
    DWORD directTime = GetTickCount() - start;
    
    // 测试封装函数方法
    start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        IsProcessBeingDebugged();
    }
    DWORD wrapperTime = GetTickCount() - start;
    
    printf("直接读取耗时: %lu ms\n", directTime);
    printf("封装函数耗时: %lu ms\n", wrapperTime);
    printf("性能比率: %.2f\n", (float)wrapperTime / directTime);
    
    printf("\n");
}

// 主程序
int main() {
    srand((unsigned int)time(NULL));
    
    printf("PEB结构BeingDebugged检测演示程序\n");
    printf("================================\n\n");
    
    // 显示PEB信息
    DisplayPEBInfo();
    
    // 测试所有方法
    TestAllPEBMethods();
    
    // 性能测试
    PerformanceTest();
    
    // 实际应用示例
    printf("=== 反调试检测 ===\n");
    if (MultiPEBAntiDebug()) {
        printf("检测到调试器存在，执行反调试措施。\n");
        
        // 这里可以执行各种反调试措施
        // 为演示目的，我们只是显示信息而不真正退出
        printf("（演示模式：不实际退出程序）\n");
    } else {
        printf("未检测到调试器，程序正常运行。\n");
        MessageBoxW(NULL, L"PEB检测通过，程序正常运行", L"提示", MB_OK);
    }
    
    // 演示绕过方法
    printf("\n=== 绕过演示 ===\n");
    printf("执行PEB绕过...\n");
    ComprehensiveBypass();
    
    printf("绕过完成后再次检测：\n");
    if (MultiPEBAntiDebug()) {
        printf("仍然检测到调试器。\n");
    } else {
        printf("检测结果显示未被调试。\n");
    }
    
    return 0;
}
```

### 4.6 高级技巧和注意事项

```cpp
// 抗干扰版本（防止简单的内存修改）
BOOL AntiTamperPEBCheck() {
    // 多次读取并验证
    BOOL results[7];
    for (int i = 0; i < 7; i++) {
        results[i] = IsProcessBeingDebugged();
        Sleep(1);  // 简短延迟
    }
    
    // 检查结果一致性
    for (int i = 1; i < 7; i++) {
        if (results[i] != results[0]) {
            // 结果不一致，可能是被干扰了
            return TRUE;  // 假设存在调试器
        }
    }
    
    return results[0];
}

// 时间差检测增强版
BOOL TimeBasedPEBCheck() {
    DWORD start = GetTickCount();
    
    // 执行多次PEB检查
    for (int i = 0; i < 1000; i++) {
        if (IsProcessBeingDebugged()) {
            return TRUE;
        }
    }
    
    DWORD end = GetTickCount();
    
    // 如果执行时间过长，可能是被调试
    if ((end - start) > 100) {  // 超过100ms
        return TRUE;
    }
    
    return FALSE;
}

// 综合检测函数
BOOL ComprehensivePEBCheck() {
    // 基本检测
    if (AntiTamperPEBCheck()) {
        return TRUE;
    }
    
    // 时间差检测
    if (TimeBasedPEBCheck()) {
        return TRUE;
    }
    
    // 其他PEB字段检测
    if (CheckPEBNtGlobalFlag() || CheckPEBProcessHeap()) {
        return TRUE;
    }
    
    return FALSE;
}
```

## 五、课后作业

1. **基础练习**：
   - 在不同架构（x86和x64）下编译和测试上述代码
   - 实现一个工具，能够显示当前进程的完整PEB信息
   - 比较不同PEB检测方法的准确性和性能

2. **进阶练习**：
   - 研究PEB结构中其他可用于反调试检测的字段
   - 实现一个能够自动绕过各种PEB检测的工具
   - 设计一个多层PEB检测机制，提高检测准确性

3. **思考题**：
   - 为什么直接读取PEB比调用API更难被Hook？
   - 在不同Windows版本中，PEB结构是否有一致性？
   - 如何设计更加隐蔽的PEB检测方法？

4. **扩展阅读**：
   - 研究Windows内核中PEB结构的完整定义
   - 了解现代调试器如何应对各种PEB检测技术
   - 学习基于硬件的调试检测方法