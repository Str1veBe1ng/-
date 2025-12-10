# 课时09 未公开API检测ProcessDebugObjectHandle

## 一、课程目标

本节课主要学习如何使用未公开的NT API函数`NtQueryInformationProcess`检测ProcessDebugObjectHandle信息类，这是反调试技术中一个较为高级的检测手段。通过本课的学习，你将能够：

1. 深入理解ProcessDebugObjectHandle信息类的作用和特点
2. 掌握调用未公开NT API函数检测调试对象句柄的方法
3. 学会区分ProcessDebugObjectHandle与其他调试检测方法的差异
4. 理解该技术在反调试检测中的应用
5. 了解该技术的检测和绕过方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| ProcessDebugObjectHandle | NtQueryInformationProcess的一个信息类，用于查询进程的调试对象句柄 |
| 调试对象 | Windows系统中用于调试通信的内核对象 |
| 句柄 | 操作系统分配给对象的唯一标识符 |
| INVALID_HANDLE_VALUE | 无效句柄值，通常为-1 |
| NULL句柄 | 空句柄值，通常为0 |
| 内核对象 | Windows系统中由内核管理的对象，如进程、线程、文件等 |

## 三、技术原理

### 3.1 ProcessDebugObjectHandle信息类概述

ProcessDebugObjectHandle是`NtQueryInformationProcess`函数支持的一个信息类，其值通常为0x1E（30）。该信息类用于查询与进程关联的调试对象句柄。

当进程被调试器附加时，系统会为其创建一个调试对象，并将该对象的句柄与进程关联。通过查询这个信息类可以获取调试对象句柄：

- 当进程**未被调试**时，返回NULL（0）
- 当进程**被调试**时，返回有效的调试对象句柄（非NULL）

### 3.2 ProcessDebugObjectHandle与其他检测方法的区别

| 特性 | ProcessDebugPort | ProcessDebugFlags | ProcessDebugObjectHandle |
|------|------------------|-------------------|-------------------------|
| 信息类值 | 7 | 31 | 30 |
| 返回类型 | DWORD（端口值） | DWORD（标志值） | HANDLE（对象句柄） |
| 未调试值 | 0 | 1 | NULL (0) |
| 被调试值 | 非0 | 0 | 非NULL |
| 检测原理 | 检查调试端口 | 检查调试标志 | 检查调试对象句柄 |

### 3.3 检测原理

当进程被调试器附加时，Windows内核会创建一个调试对象（Debug Object），并将该对象的句柄与进程关联。通过查询ProcessDebugObjectHandle信息类，我们可以获取这个调试对象句柄：

- 如果返回NULL，表示进程未被调试
- 如果返回非NULL的有效句柄，表示进程正在被调试

## 四、代码实现

### 4.1 基础ProcessDebugObjectHandle检测

```cpp
#include <windows.h>
#include <stdio.h>

// NT API相关定义
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessDebugPort = 7,
    ProcessDebugFlags = 31,
    ProcessDebugObjectHandle = 30,  // 关键信息类
} PROCESSINFOCLASS;

// NTSTATUS定义
typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0
#define STATUS_PORT_NOT_SET 0xC0000353

// NtQueryInformationProcess函数指针类型
typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// 获取NT API函数地址
PNtQueryInformationProcess GetNtQueryInformationProcess() {
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) {
        return NULL;
    }
    
    return (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
}

// 基础ProcessDebugObjectHandle检测
BOOL IsDebuggedViaProcessDebugObjectHandle() {
    // 获取函数地址
    PNtQueryInformationProcess NtQueryInformationProcess = GetNtQueryInformationProcess();
    if (NtQueryInformationProcess == NULL) {
        return FALSE;
    }
    
    // 查询调试对象句柄
    HANDLE debugObjectHandle = NULL;
    ULONG returnLength = 0;
    
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),                // 当前进程句柄
        ProcessDebugObjectHandle,           // ProcessDebugObjectHandle信息类
        &debugObjectHandle,                 // 接收调试对象句柄的缓冲区
        sizeof(debugObjectHandle),          // 缓冲区大小
        &returnLength                       // 返回长度
    );
    
    if (status == STATUS_SUCCESS) {
        // 如果debugObjectHandle非NULL，表示进程被调试
        return (debugObjectHandle != NULL);
    }
    
    // 其他状态可能表示未被调试或其他错误
    return FALSE;
}
```

### 4.2 完整的ProcessDebugObjectHandle检测实现

```cpp
// ProcessDebugObjectHandle检测工具类
class DebugObjectDetector {
public:
    static PNtQueryInformationProcess GetNtQueryInformationProcess() {
        static PNtQueryInformationProcess pfn = nullptr;
        static bool initialized = false;
        
        if (!initialized) {
            HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
            if (hNtdll != NULL) {
                pfn = (PNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
            }
            initialized = true;
        }
        
        return pfn;
    }
    
    static BOOL CheckProcessDebugObjectHandle(HANDLE hProcess) {
        PNtQueryInformationProcess pfn = GetNtQueryInformationProcess();
        if (pfn == NULL) {
            return FALSE;
        }
        
        HANDLE debugObjectHandle = NULL;
        ULONG returnLength = 0;
        
        NTSTATUS status = pfn(
            hProcess,
            ProcessDebugObjectHandle,
            &debugObjectHandle,
            sizeof(debugObjectHandle),
            &returnLength
        );
        
        if (status == STATUS_SUCCESS) {
            // debugObjectHandle非NULL表示被调试
            return (debugObjectHandle != NULL);
        }
        
        return FALSE;
    }
    
    static BOOL CheckAllDebugMethods(HANDLE hProcess) {
        // ProcessDebugPort检测
        DWORD debugPort = 0;
        ULONG returnLength = 0;
        PNtQueryInformationProcess pfn = GetNtQueryInformationProcess();
        
        if (pfn != NULL) {
            NTSTATUS status = pfn(
                hProcess,
                ProcessDebugPort,
                &debugPort,
                sizeof(debugPort),
                &returnLength
            );
            
            if (status == STATUS_SUCCESS && debugPort != 0) {
                return TRUE;
            }
        }
        
        // ProcessDebugFlags检测
        DWORD debugFlags = 0;
        if (pfn != NULL) {
            NTSTATUS status = pfn(
                hProcess,
                ProcessDebugFlags,
                &debugFlags,
                sizeof(debugFlags),
                &returnLength
            );
            
            if (status == STATUS_SUCCESS && debugFlags == 0) {
                return TRUE;
            }
        }
        
        // ProcessDebugObjectHandle检测
        if (CheckProcessDebugObjectHandle(hProcess)) {
            return TRUE;
        }
        
        return FALSE;
    }
};

// 详细ProcessDebugObjectHandle检测
BOOL DetailedProcessDebugObjectHandleCheck() {
    printf("=== ProcessDebugObjectHandle详细检测 ===\n");
    
    PNtQueryInformationProcess pfn = DebugObjectDetector::GetNtQueryInformationProcess();
    if (pfn == NULL) {
        printf("无法获取NtQueryInformationProcess函数地址。\n");
        return FALSE;
    }
    
    HANDLE debugObjectHandle = NULL;
    ULONG returnLength = 0;
    
    NTSTATUS status = pfn(
        GetCurrentProcess(),
        ProcessDebugObjectHandle,
        &debugObjectHandle,
        sizeof(debugObjectHandle),
        &returnLength
    );
    
    printf("NtQueryInformationProcess返回状态: 0x%08X\n", status);
    printf("返回数据长度: %lu 字节\n", returnLength);
    printf("调试对象句柄: 0x%p\n", debugObjectHandle);
    
    if (status == STATUS_SUCCESS) {
        printf("检测结果: %s\n", debugObjectHandle ? "被调试" : "未被调试");
        return (debugObjectHandle != NULL);
    } else {
        printf("检测结果: 无法确定（错误状态）\n");
        return FALSE;
    }
}
```

### 4.3 反调试实现

```cpp
// 简单的ProcessDebugObjectHandle反调试
VOID SimpleProcessDebugObjectHandleAntiDebug() {
    if (IsDebuggedViaProcessDebugObjectHandle()) {
        printf("通过ProcessDebugObjectHandle检测到调试器存在！程序即将退出。\n");
        ExitProcess(1);
    }
}

// 多层次调试对象检测
BOOL MultiLayerDebugObjectCheck() {
    HANDLE hCurrentProcess = GetCurrentProcess();
    
    // 检测ProcessDebugObjectHandle
    if (DebugObjectDetector::CheckProcessDebugObjectHandle(hCurrentProcess)) {
        return TRUE;
    }
    
    // 检测其他调试方法
    if (DebugObjectDetector::CheckAllDebugMethods(hCurrentProcess)) {
        return TRUE;
    }
    
    return FALSE;
}

// 增强版反调试
VOID EnhancedDebugObjectAntiDebug() {
    // 多次检测
    for (int i = 0; i < 5; i++) {
        if (MultiLayerDebugObjectCheck()) {
            printf("第%d次调试对象检测发现调试环境！\n", i + 1);
            
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
    
    printf("调试对象反调试检测通过。\n");
}
```

### 4.4 绕过ProcessDebugObjectHandle检测的方法

```cpp
// Hook NtQueryInformationProcess绕过ProcessDebugObjectHandle检测
typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// 原始函数指针
PNtQueryInformationProcess g_pOriginalNtQueryInformationProcess = nullptr;

// Hook函数
NTSTATUS NTAPI MyNtQueryInformationProcessHook(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
) {
    // 调用原始函数
    NTSTATUS status = g_pOriginalNtQueryInformationProcess(
        ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength
    );
    
    // 如果是ProcessDebugObjectHandle查询且成功，修改返回值
    if (ProcessInformationClass == ProcessDebugObjectHandle && status == STATUS_SUCCESS) {
        // 将调试对象句柄设置为NULL，表示未被调试
        if (ProcessInformation && ProcessInformationLength >= sizeof(HANDLE)) {
            *(PHANDLE)ProcessInformation = NULL;
        }
    }
    
    return status;
}

// 安装Hook（简化版）
VOID HookProcessDebugObjectHandle() {
    // 获取原始函数地址
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) return;
    
    g_pOriginalNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess"
    );
    
    if (g_pOriginalNtQueryInformationProcess == NULL) return;
    
    // 这里需要实现具体的Hook逻辑（IAT Hook、Inline Hook等）
    printf("Hook NtQueryInformationProcess函数以绕过ProcessDebugObjectHandle检测。\n");
}

// 综合绕过方法
VOID ComprehensiveDebugObjectBypass() {
    // 安装Hook
    HookProcessDebugObjectHandle();
    
    printf("ProcessDebugObjectHandle相关检测已绕过。\n");
}
```

### 4.5 完整测试程序

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 前面实现的函数声明
BOOL IsDebuggedViaProcessDebugObjectHandle();
BOOL DetailedProcessDebugObjectHandleCheck();
BOOL MultiLayerDebugObjectCheck();
VOID ComprehensiveDebugObjectBypass();

// 显示调试对象信息
VOID DisplayDebugObjectInfo() {
    printf("=== 调试对象信息 ===\n");
    
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) {
        printf("无法加载ntdll.dll。\n");
        return;
    }
    
    PNtQueryInformationProcess pfn = (PNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess"
    );
    
    printf("ntdll.dll基址: 0x%p\n", hNtdll);
    printf("NtQueryInformationProcess地址: 0x%p\n", pfn);
    
    if (pfn != NULL) {
        printf("函数地址有效。\n");
    } else {
        printf("无法获取函数地址。\n");
    }
    
    printf("\n");
}

// 对比三种调试检测方法
VOID CompareAllDebugDetectionMethods() {
    printf("=== 三种调试检测方法对比 ===\n");
    
    HANDLE hCurrentProcess = GetCurrentProcess();
    
    // ProcessDebugPort检测
    DWORD debugPort = 0;
    ULONG returnLength = 0;
    PNtQueryInformationProcess pfn = DebugObjectDetector::GetNtQueryInformationProcess();
    
    if (pfn != NULL) {
        pfn(hCurrentProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), &returnLength);
    }
    printf("ProcessDebugPort检测: %s (端口值: 0x%08X)\n", 
           debugPort ? "被调试" : "未被调试", debugPort);
    
    // ProcessDebugFlags检测
    DWORD debugFlags = 1;  // 默认为未被调试
    if (pfn != NULL) {
        pfn(hCurrentProcess, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), &returnLength);
    }
    printf("ProcessDebugFlags检测: %s (标志值: %lu)\n", 
           debugFlags ? "未被调试" : "被调试", debugFlags);
    
    // ProcessDebugObjectHandle检测
    BOOL objectDetected = DebugObjectDetector::CheckProcessDebugObjectHandle(hCurrentProcess);
    HANDLE debugObjectHandle = NULL;
    if (pfn != NULL) {
        pfn(hCurrentProcess, ProcessDebugObjectHandle, &debugObjectHandle, sizeof(debugObjectHandle), &returnLength);
    }
    printf("ProcessDebugObjectHandle检测: %s (句柄: 0x%p)\n", 
           objectDetected ? "被调试" : "未被调试", debugObjectHandle);
    
    // IsDebuggerPresent检测
    BOOL apiDetected = IsDebuggerPresent();
    printf("IsDebuggerPresent检测: %s\n", apiDetected ? "被调试" : "未被调试");
    
    printf("\n");
}

// 测试所有检测方法
VOID TestAllDebugObjectMethods() {
    printf("=== 调试对象检测方法测试 ===\n");
    
    // 基础检测
    BOOL basicCheck = IsDebuggedViaProcessDebugObjectHandle();
    printf("基础ProcessDebugObjectHandle检测: %s\n", basicCheck ? "被调试" : "未被调试");
    
    // 详细检测
    printf("详细ProcessDebugObjectHandle检测:\n");
    BOOL detailedCheck = DetailedProcessDebugObjectHandleCheck();
    printf("详细检测结果: %s\n", detailedCheck ? "被调试" : "未被调试");
    
    // 多层检测
    BOOL multiCheck = MultiLayerDebugObjectCheck();
    printf("多层调试对象检测: %s\n", multiCheck ? "被调试" : "未被调试");
    
    printf("\n");
}

// 性能测试
VOID PerformanceTest() {
    const int iterations = 100000;
    
    printf("=== 性能测试 (%d次调用) ===\n", iterations);
    
    // 测试基础检测方法
    DWORD start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        IsDebuggedViaProcessDebugObjectHandle();
    }
    DWORD basicTime = GetTickCount() - start;
    
    // 测试多层检测方法
    start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        MultiLayerDebugObjectCheck();
    }
    DWORD multiTime = GetTickCount() - start;
    
    printf("基础检测耗时: %lu ms\n", basicTime);
    printf("多层检测耗时: %lu ms\n", multiTime);
    printf("性能比率: %.2f\n", (float)multiTime / basicTime);
    
    printf("\n");
}

// 主程序
int main() {
    srand((unsigned int)time(NULL));
    
    printf("未公开API检测ProcessDebugObjectHandle演示程序\n");
    printf("========================================\n\n");
    
    // 显示调试对象信息
    DisplayDebugObjectInfo();
    
    // 对比不同检测方法
    CompareAllDebugDetectionMethods();
    
    // 测试所有检测方法
    TestAllDebugObjectMethods();
    
    // 性能测试
    PerformanceTest();
    
    // 实际应用示例
    printf("=== 反调试检测 ===\n");
    if (MultiLayerDebugObjectCheck()) {
        printf("检测到调试环境，执行反调试措施。\n");
        
        // 这里可以执行各种反调试措施
        // 为演示目的，我们只是显示信息而不真正退出
        printf("（演示模式：不实际退出程序）\n");
    } else {
        printf("未检测到调试环境，程序正常运行。\n");
        MessageBoxW(NULL, L"ProcessDebugObjectHandle检测通过，程序正常运行", L"提示", MB_OK);
    }
    
    // 演示绕过方法
    printf("\n=== 绕过演示 ===\n");
    printf("执行调试对象绕过...\n");
    ComprehensiveDebugObjectBypass();
    
    printf("绕过完成后再次检测：\n");
    if (MultiLayerDebugObjectCheck()) {
        printf("仍然检测到调试环境。\n");
    } else {
        printf("检测结果显示未被调试。\n");
    }
    
    return 0;
}
```

### 4.6 高级技巧和注意事项

```cpp
// 抗干扰版本（防止简单的Hook）
BOOL AntiTamperDebugObjectCheck() {
    // 多次调用并验证
    BOOL results[7];
    
    for (int i = 0; i < 7; i++) {
        results[i] = IsDebuggedViaProcessDebugObjectHandle();
        Sleep(1);  // 简短延迟
    }
    
    // 检查结果一致性
    for (int i = 1; i < 7; i++) {
        if (results[i] != results[0]) {
            // 结果不一致，可能是被干扰了
            return TRUE;  // 假设存在调试环境
        }
    }
    
    return results[0];
}

// 时间差检测增强版
BOOL TimeBasedDebugObjectCheck() {
    DWORD start = GetTickCount();
    
    // 执行多次调试对象检查
    for (int i = 0; i < 1000; i++) {
        if (MultiLayerDebugObjectCheck()) {
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
BOOL ComprehensiveDebugObjectCheck() {
    // 抗干扰检测
    if (AntiTamperDebugObjectCheck()) {
        return TRUE;
    }
    
    // 时间差检测
    if (TimeBasedDebugObjectCheck()) {
        return TRUE;
    }
    
    // 其他调试对象检测
    HANDLE hCurrentProcess = GetCurrentProcess();
    if (DebugObjectDetector::CheckAllDebugMethods(hCurrentProcess)) {
        return TRUE;
    }
    
    return FALSE;
}

// 动态获取NT API地址（避免静态导入）
FARPROC GetDynamicNTAPIAddress(LPCSTR functionName) {
    // 动态加载ntdll.dll
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll == NULL) {
        return NULL;
    }
    
    // 获取函数地址
    FARPROC pfn = GetProcAddress(hNtdll, functionName);
    
    // 注意：在实际应用中，可能需要保持ntdll.dll的引用
    return pfn;
}

// 检测调试对象的有效性
BOOL IsValidDebugObjectHandle(HANDLE debugObjectHandle) {
    if (debugObjectHandle == NULL || debugObjectHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    
    // 尝试获取对象信息来验证句柄有效性
    // 这里可以使用NtQueryObject等函数
    
    return TRUE;
}
```

## 五、课后作业

1. **基础练习**：
   - 在不同Windows版本下测试上述代码的兼容性
   - 实现对ProcessDebugObjectHandle与其他调试检测方法的联合检测
   - 研究调试对象的内核实现机制

2. **进阶练习**：
   - 实现一个完整的NT API Hook检测和绕过框架
   - 研究如何检测和关闭调试对象句柄
   - 设计一个多层检测机制，结合多种调试对象检测技术

3. **思考题**：
   - ProcessDebugObjectHandle与ProcessDebugPort在检测效果上有何异同？
   - 为什么调试对象句柄检测被认为是一种更可靠的反调试方法？
   - 如何设计更加隐蔽的调试对象检测方法？

4. **扩展阅读**：
   - 研究Windows内核中调试对象的实现机制
   - 了解调试对象与调试端口的关系
   - 学习现代调试器如何应对调试对象检测