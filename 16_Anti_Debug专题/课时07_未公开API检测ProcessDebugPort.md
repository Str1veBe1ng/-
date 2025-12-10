# 课时07 未公开API检测ProcessDebugPort

## 一、课程目标

本节课主要学习如何使用未公开的NT API函数`NtQueryInformationProcess`检测ProcessDebugPort信息类，这是反调试技术中一个强大的检测手段。通过本课的学习，你将能够：

1. 理解NT API与Win32 API的区别和关系
2. 掌握调用未公开NT API函数的方法
3. 学会使用ProcessDebugPort信息类检测调试端口
4. 理解该技术与其他反调试技术的关系
5. 了解该技术的检测和绕过方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| NT API | Windows NT内核提供的原生API函数，通常以Nt或Zw开头 |
| NtQueryInformationProcess | NT API函数，用于查询进程信息 |
| ProcessDebugPort | NtQueryInformationProcess的一个信息类，用于查询进程的调试端口 |
| 调试端口 | 调试器与被调试进程通信的端口，当进程被调试时会存在 |
| 未公开API | Windows系统中未在官方文档中公开但实际存在的API函数 |
| SSDT | System Service Descriptor Table，系统服务描述符表，用于系统调用 |

## 三、技术原理

### 3.1 NT API概述

NT API（Native API）是Windows NT内核提供的原生API函数集合，它们比Win32 API更底层，功能更强大。许多Win32 API函数实际上是对NT API函数的封装。

常见的NT API函数命名规则：
- 以`Nt`开头：如`NtQueryInformationProcess`
- 以`Zw`开头：如`ZwQueryInformationProcess`（用户模式下的别名）

### 3.2 NtQueryInformationProcess函数

`NtQueryInformationProcess`是NT API中用于查询进程信息的重要函数。

函数原型：
```cpp
NTSTATUS NTAPI NtQueryInformationProcess(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);
```

参数说明：
- `ProcessHandle`：进程句柄
- `ProcessInformationClass`：信息类
- `ProcessInformation`：接收信息的缓冲区
- `ProcessInformationLength`：缓冲区大小
- `ReturnLength`：实际返回的数据长度

### 3.3 ProcessDebugPort信息类

`ProcessDebugPort`是`PROCESSINFOCLASS`枚举中的一个值（通常为7），用于查询进程的调试端口信息。

当进程被调试器附加时，系统会为其分配一个调试端口。通过查询这个信息类：
- 如果返回的调试端口值为0，表示进程未被调试
- 如果返回的调试端口值非0，表示进程正在被调试

## 四、代码实现

### 4.1 基础NT API调用实现

```cpp
#include <windows.h>
#include <stdio.h>

// NT API相关定义
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,
    ProcessQuotaLimits = 1,
    ProcessIoCounters = 2,
    ProcessVmCounters = 3,
    ProcessTimes = 4,
    ProcessBasePriority = 5,
    ProcessRaisePriority = 6,
    ProcessDebugPort = 7,           // 关键信息类
    ProcessExceptionPort = 8,
    ProcessAccessToken = 9,
    ProcessLdtInformation = 10,
    ProcessLdtSize = 11,
    ProcessDefaultHardErrorMode = 12,
    ProcessIoPortHandlers = 13,
    ProcessPooledUsageAndLimits = 14,
    ProcessWorkingSetWatch = 15,
    ProcessUserModeIOPL = 16,
    ProcessEnableAlignmentFaultFixup = 17,
    ProcessPriorityClass = 18,
    ProcessWx86Information = 19,
    ProcessHandleCount = 20,
    ProcessAffinityMask = 21,
    ProcessPriorityBoost = 22
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

// 基础ProcessDebugPort检测
BOOL IsDebuggedViaProcessDebugPort() {
    // 获取函数地址
    PNtQueryInformationProcess NtQueryInformationProcess = GetNtQueryInformationProcess();
    if (NtQueryInformationProcess == NULL) {
        return FALSE;
    }
    
    // 查询调试端口
    DWORD debugPort = 0;
    ULONG returnLength = 0;
    
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),        // 当前进程句柄
        ProcessDebugPort,           // ProcessDebugPort信息类
        &debugPort,                 // 接收调试端口的缓冲区
        sizeof(debugPort),          // 缓冲区大小
        &returnLength               // 返回长度
    );
    
    if (status == STATUS_SUCCESS) {
        // 如果debugPort非0，表示进程被调试
        return (debugPort != 0);
    }
    
    // 其他状态可能表示未被调试或其他错误
    return FALSE;
}
```

### 4.2 完整的NT API检测实现

```cpp
// NT API检测工具类
class NTAPIDetector {
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
    
    static BOOL CheckProcessDebugPort(HANDLE hProcess) {
        PNtQueryInformationProcess pfn = GetNtQueryInformationProcess();
        if (pfn == NULL) {
            return FALSE;
        }
        
        DWORD debugPort = 0;
        ULONG returnLength = 0;
        
        NTSTATUS status = pfn(
            hProcess,
            ProcessDebugPort,
            &debugPort,
            sizeof(debugPort),
            &returnLength
        );
        
        if (status == STATUS_SUCCESS) {
            return (debugPort != 0);
        }
        
        return FALSE;
    }
    
    static BOOL CheckProcessDebugFlags(HANDLE hProcess) {
        PNtQueryInformationProcess pfn = GetNtQueryInformationProcess();
        if (pfn == NULL) {
            return FALSE;
        }
        
        DWORD debugFlags = 0;
        ULONG returnLength = 0;
        
        // ProcessDebugFlags信息类通常是0x1F
        NTSTATUS status = pfn(
            hProcess,
            (PROCESSINFOCLASS)0x1F,
            &debugFlags,
            sizeof(debugFlags),
            &returnLength
        );
        
        if (status == STATUS_SUCCESS) {
            return (debugFlags == 0);  // 被调试时为0，未被调试时为1
        }
        
        return FALSE;
    }
};

// 详细ProcessDebugPort检测
BOOL DetailedProcessDebugPortCheck() {
    printf("=== ProcessDebugPort详细检测 ===\n");
    
    PNtQueryInformationProcess pfn = NTAPIDetector::GetNtQueryInformationProcess();
    if (pfn == NULL) {
        printf("无法获取NtQueryInformationProcess函数地址。\n");
        return FALSE;
    }
    
    DWORD debugPort = 0;
    ULONG returnLength = 0;
    
    NTSTATUS status = pfn(
        GetCurrentProcess(),
        ProcessDebugPort,
        &debugPort,
        sizeof(debugPort),
        &returnLength
    );
    
    printf("NtQueryInformationProcess返回状态: 0x%08X\n", status);
    printf("返回数据长度: %lu 字节\n", returnLength);
    printf("调试端口值: 0x%08X\n", debugPort);
    
    if (status == STATUS_SUCCESS) {
        printf("检测结果: %s\n", debugPort ? "被调试" : "未被调试");
        return (debugPort != 0);
    } else {
        printf("检测结果: 无法确定（错误状态）\n");
        return FALSE;
    }
}
```

### 4.3 反调试实现

```cpp
// 简单的ProcessDebugPort反调试
VOID SimpleProcessDebugPortAntiDebug() {
    if (IsDebuggedViaProcessDebugPort()) {
        printf("通过ProcessDebugPort检测到调试器存在！程序即将退出。\n");
        ExitProcess(1);
    }
}

// 多层次NT API检测
BOOL MultiLayerNTAPICheck() {
    HANDLE hCurrentProcess = GetCurrentProcess();
    
    // 检测1：ProcessDebugPort
    if (NTAPIDetector::CheckProcessDebugPort(hCurrentProcess)) {
        return TRUE;
    }
    
    // 检测2：ProcessDebugFlags
    if (NTAPIDetector::CheckProcessDebugFlags(hCurrentProcess)) {
        return TRUE;
    }
    
    // 检测3：其他NT API检测（可扩展）
    
    return FALSE;
}

// 增强版反调试
VOID EnhancedNTAPIAntiDebug() {
    // 多次检测
    for (int i = 0; i < 5; i++) {
        if (MultiLayerNTAPICheck()) {
            printf("第%d次NT API检测发现调试环境！\n", i + 1);
            
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
    
    printf("NT API反调试检测通过。\n");
}
```

### 4.4 绕过ProcessDebugPort检测的方法

```cpp
// Hook NtQueryInformationProcess绕过检测
typedef NTSTATUS (NTAPI *PNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// 原始函数指针
PNtQueryInformationProcess g_pOriginalNtQueryInformationProcess = nullptr;

// Hook函数
NTSTATUS NTAPI MyNtQueryInformationProcess(
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
    
    // 如果是ProcessDebugPort查询，返回特殊值
    if (ProcessInformationClass == ProcessDebugPort && status == STATUS_SUCCESS) {
        // 将调试端口设置为0，表示未被调试
        if (ProcessInformation && ProcessInformationLength >= sizeof(DWORD)) {
            *(PDWORD)ProcessInformation = 0;
        }
    }
    
    return status;
}

// 安装Hook（简化版）
VOID HookNtQueryInformationProcess() {
    // 获取原始函数地址
    HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
    if (hNtdll == NULL) return;
    
    g_pOriginalNtQueryInformationProcess = (PNtQueryInformationProcess)GetProcAddress(
        hNtdll, "NtQueryInformationProcess"
    );
    
    if (g_pOriginalNtQueryInformationProcess == NULL) return;
    
    // 这里需要实现具体的Hook逻辑（IAT Hook、Inline Hook等）
    printf("Hook NtQueryInformationProcess函数。\n");
}

// 综合绕过方法
VOID ComprehensiveNTAPIBypass() {
    // 安装Hook
    HookNtQueryInformationProcess();
    
    printf("NT API相关检测已绕过。\n");
}
```

### 4.5 完整测试程序

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 前面实现的函数声明
BOOL IsDebuggedViaProcessDebugPort();
BOOL DetailedProcessDebugPortCheck();
BOOL MultiLayerNTAPICheck();
VOID ComprehensiveNTAPIBypass();

// 显示NT API信息
VOID DisplayNTAPIInfo() {
    printf("=== NT API信息 ===\n");
    
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

// 测试所有检测方法
VOID TestAllNTAPIMethods() {
    printf("=== NT API检测方法测试 ===\n");
    
    // 基础检测
    BOOL basicCheck = IsDebuggedViaProcessDebugPort();
    printf("基础ProcessDebugPort检测: %s\n", basicCheck ? "被调试" : "未被调试");
    
    // 详细检测
    printf("详细ProcessDebugPort检测:\n");
    BOOL detailedCheck = DetailedProcessDebugPortCheck();
    printf("详细检测结果: %s\n", detailedCheck ? "被调试" : "未被调试");
    
    // 多层检测
    BOOL multiCheck = MultiLayerNTAPICheck();
    printf("多层NT API检测: %s\n", multiCheck ? "被调试" : "未被调试");
    
    printf("\n");
}

// 性能测试
VOID PerformanceTest() {
    const int iterations = 100000;
    
    printf("=== 性能测试 (%d次调用) ===\n", iterations);
    
    // 测试基础检测方法
    DWORD start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        IsDebuggedViaProcessDebugPort();
    }
    DWORD basicTime = GetTickCount() - start;
    
    // 测试多层检测方法
    start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        MultiLayerNTAPICheck();
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
    
    printf("未公开API检测ProcessDebugPort演示程序\n");
    printf("==================================\n\n");
    
    // 显示NT API信息
    DisplayNTAPIInfo();
    
    // 测试所有检测方法
    TestAllNTAPIMethods();
    
    // 性能测试
    PerformanceTest();
    
    // 实际应用示例
    printf("=== 反调试检测 ===\n");
    if (MultiLayerNTAPICheck()) {
        printf("检测到调试环境，执行反调试措施。\n");
        
        // 这里可以执行各种反调试措施
        // 为演示目的，我们只是显示信息而不真正退出
        printf("（演示模式：不实际退出程序）\n");
    } else {
        printf("未检测到调试环境，程序正常运行。\n");
        MessageBoxW(NULL, L"ProcessDebugPort检测通过，程序正常运行", L"提示", MB_OK);
    }
    
    // 演示绕过方法
    printf("\n=== 绕过演示 ===\n");
    printf("执行NT API绕过...\n");
    ComprehensiveNTAPIBypass();
    
    printf("绕过完成后再次检测：\n");
    if (MultiLayerNTAPICheck()) {
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
BOOL AntiTamperNTAPICheck() {
    // 多次调用并验证
    BOOL results[7];
    
    for (int i = 0; i < 7; i++) {
        results[i] = IsDebuggedViaProcessDebugPort();
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
BOOL TimeBasedNTAPICheck() {
    DWORD start = GetTickCount();
    
    // 执行多次NT API检查
    for (int i = 0; i < 1000; i++) {
        if (MultiLayerNTAPICheck()) {
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
BOOL ComprehensiveNTDebugCheck() {
    // 抗干扰检测
    if (AntiTamperNTAPICheck()) {
        return TRUE;
    }
    
    // 时间差检测
    if (TimeBasedNTAPICheck()) {
        return TRUE;
    }
    
    // 其他NT API检测
    HANDLE hCurrentProcess = GetCurrentProcess();
    if (NTAPIDetector::CheckProcessDebugFlags(hCurrentProcess)) {
        return TRUE;
    }
    
    return FALSE;
}

// 动态获取NT API地址（避免静态导入）
FARPROC GetNTAPIAddress(LPCSTR functionName) {
    // 动态加载ntdll.dll
    HMODULE hNtdll = LoadLibrary(L"ntdll.dll");
    if (hNtdll == NULL) {
        return NULL;
    }
    
    // 获取函数地址
    FARPROC pfn = GetProcAddress(hNtdll, functionName);
    
    // 注意：在实际应用中，可能需要保持ntdll.dll的引用
    // 这里为了简化，直接返回地址
    
    return pfn;
}
```

## 五、课后作业

1. **基础练习**：
   - 在不同Windows版本下测试上述代码的兼容性
   - 实现对其他NT API信息类的检测
   - 研究NtQuerySystemInformation等其他NT API函数

2. **进阶练习**：
   - 实现一个完整的NT API Hook框架
   - 研究如何检测和绕过NT API Hook
   - 设计一个多层检测机制，结合多种NT API检测技术

3. **思考题**：
   - NT API检测相比Win32 API检测有哪些优势和劣势？
   - 在不同调试器中，ProcessDebugPort的表现是否一致？
   - 如何设计更加隐蔽的NT API检测方法？

4. **扩展阅读**：
   - 研究Windows内核中调试端口的实现机制
   - 了解SSDT Hook和内核模式Hook技术
   - 学习现代调试器如何应对NT API检测