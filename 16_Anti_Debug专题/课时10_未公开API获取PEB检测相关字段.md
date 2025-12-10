# 课时10 未公开API获取PEB检测相关字段

## 一、课程目标

本节课主要学习如何使用未公开的NT API函数`NtQueryInformationProcess`获取ProcessBasicInformation信息类，从而直接访问PEB结构并检测其中的反调试相关字段。通过本课的学习，你将能够：

1. 深入理解ProcessBasicInformation信息类的作用和结构
2. 掌握通过NT API直接获取PEB指针的方法
3. 学会访问PEB中各种反调试相关字段
4. 理解该技术与其他PEB检测方法的关系
5. 了解该技术的检测和绕过方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| ProcessBasicInformation | NtQueryInformationProcess的一个信息类，用于查询进程基本信息 |
| PROCESS_BASIC_INFORMATION | ProcessBasicInformation信息类返回的数据结构 |
| PebBaseAddress | PROCESS_BASIC_INFORMATION结构中的PEB基地址字段 |
| UniqueProcessId | 进程唯一标识符 |
| InheritedFromUniqueProcessId | 父进程唯一标识符 |
| NT API | Windows NT内核提供的原生API函数 |

## 三、技术原理

### 3.1 ProcessBasicInformation信息类概述

ProcessBasicInformation是`NtQueryInformationProcess`函数支持的最基本的信息类，其值为0。该信息类返回一个`PROCESS_BASIC_INFORMATION`结构，包含了进程的基本信息。

### 3.2 PROCESS_BASIC_INFORMATION结构详解

```cpp
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;                // 进程退出状态
    PPEB PebBaseAddress;                // PEB基地址
    ULONG_PTR AffinityMask;             // 处理器亲和性掩码
    KPRIORITY BasePriority;             // 基本优先级
    ULONG_PTR UniqueProcessId;          // 进程唯一标识符
    ULONG_PTR InheritedFromUniqueProcessId; // 父进程唯一标识符
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;
```

其中最关键的是`PebBaseAddress`字段，它直接指向进程的PEB结构。

### 3.3 检测原理

通过ProcessBasicInformation信息类获取PEB地址后，我们可以直接访问PEB中的各种反调试字段，包括：

1. **BeingDebugged**（偏移0x02）：调试标志
2. **NtGlobalFlag**（偏移0x68/0xBC）：全局标志
3. **ProcessHeap**（偏移0x18/0x30）：进程堆指针

这种方法比直接通过FS/GS寄存器访问PEB更加隐蔽，因为它是通过正规的NT API途径获取的。

## 四、代码实现

### 4.1 基础ProcessBasicInformation检测

```cpp
#include <windows.h>
#include <stdio.h>

// NT API相关定义
typedef enum _PROCESSINFOCLASS {
    ProcessBasicInformation = 0,        // 关键信息类
    ProcessDebugPort = 7,
    ProcessDebugFlags = 31,
    ProcessDebugObjectHandle = 30,
} PROCESSINFOCLASS;

// PROCESS_BASIC_INFORMATION结构
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

// NTSTATUS定义
typedef LONG NTSTATUS;
#define STATUS_SUCCESS 0

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

// 通过NT API获取PEB地址
PVOID GetPEBViaNTAPI() {
    // 获取函数地址
    PNtQueryInformationProcess NtQueryInformationProcess = GetNtQueryInformationProcess();
    if (NtQueryInformationProcess == NULL) {
        return NULL;
    }
    
    // 查询进程基本信息
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;
    
    NTSTATUS status = NtQueryInformationProcess(
        GetCurrentProcess(),            // 当前进程句柄
        ProcessBasicInformation,        // ProcessBasicInformation信息类
        &pbi,                           // 接收进程信息的缓冲区
        sizeof(pbi),                    // 缓冲区大小
        &returnLength                   // 返回长度
    );
    
    if (status == STATUS_SUCCESS) {
        return pbi.PebBaseAddress;
    }
    
    return NULL;
}
```

### 4.2 通过NT API访问PEB字段

```cpp
// PEB字段访问工具类
class NTAPIPEBReader {
public:
    static PVOID GetPEB() {
        return GetPEBViaNTAPI();
    }
    
    static BYTE ReadPEBByte(DWORD offset) {
        PVOID peb = GetPEB();
        if (peb == NULL) return 0;
        
        return *((PBYTE)peb + offset);
    }
    
    static DWORD ReadPEBDWord(DWORD offset) {
        PVOID peb = GetPEB();
        if (peb == NULL) return 0;
        
        return *((PDWORD)((PBYTE)peb + offset));
    }
    
    static PVOID ReadPEBPointer(DWORD offset) {
        PVOID peb = GetPEB();
        if (peb == NULL) return NULL;
        
        return *((PVOID*)((PBYTE)peb + offset));
    }
    
    // 检测BeingDebugged标志
    static BOOL IsBeingDebugged() {
        return ReadPEBByte(0x02) != 0;
    }
    
    // 检测NtGlobalFlag
    static BOOL IsNtGlobalFlagSet() {
        DWORD flag = ReadPEBDWord(
#ifdef _WIN64
            0xBC  // x64偏移
#else
            0x68  // x86偏移
#endif
        );
        
        // 检查调试相关标志
        return (flag & 0x70) != 0;
    }
    
    // 检测ProcessHeap Flags
    static BOOL IsProcessHeapFlagSet() {
        PVOID processHeap = ReadPEBPointer(
#ifdef _WIN64
            0x30  // x64偏移
#else
            0x18  // x86偏移
#endif
        );
        
        if (processHeap == NULL) return FALSE;
        
        DWORD heapFlags = *((PDWORD)((PBYTE)processHeap + 0x40));
        return (heapFlags & 0x2) != 0;
    }
};

// 基础NT API PEB检测
BOOL IsDebuggedViaNTAPIPEB() {
    // 检测BeingDebugged标志
    if (NTAPIPEBReader::IsBeingDebugged()) {
        return TRUE;
    }
    
    // 检测NtGlobalFlag
    if (NTAPIPEBReader::IsNtGlobalFlagSet()) {
        return TRUE;
    }
    
    // 检测ProcessHeap Flags
    if (NTAPIPEBReader::IsProcessHeapFlagSet()) {
        return TRUE;
    }
    
    return FALSE;
}
```

### 4.3 完整的NT API PEB检测实现

```cpp
// 详细NT API PEB检测
BOOL DetailedNTAPIPEBDetection() {
    printf("=== NT API PEB检测详细信息 ===\n");
    
    // 获取PEB地址
    PVOID peb = NTAPIPEBReader::GetPEB();
    if (peb == NULL) {
        printf("无法通过NT API获取PEB地址。\n");
        return FALSE;
    }
    
    printf("PEB地址: 0x%p\n", peb);
    
    // 检测BeingDebugged
    BYTE beingDebugged = NTAPIPEBReader::ReadPEBByte(0x02);
    printf("BeingDebugged: 0x%02X (%s)\n", beingDebugged, beingDebugged ? "被调试" : "未被调试");
    
    // 检测NtGlobalFlag
#ifdef _WIN64
    DWORD ntGlobalFlag = NTAPIPEBReader::ReadPEBDWord(0xBC);
#else
    DWORD ntGlobalFlag = NTAPIPEBReader::ReadPEBDWord(0x68);
#endif
    printf("NtGlobalFlag: 0x%08X\n", ntGlobalFlag);
    
    BOOL hasDebugFlags = (ntGlobalFlag & 0x70) != 0;
    printf("包含调试标志: %s\n", hasDebugFlags ? "是" : "否");
    
    // 检测ProcessHeap
#ifdef _WIN64
    PVOID processHeap = NTAPIPEBReader::ReadPEBPointer(0x30);
#else
    PVOID processHeap = NTAPIPEBReader::ReadPEBPointer(0x18);
#endif
    printf("ProcessHeap: 0x%p\n", processHeap);
    
    if (processHeap != NULL) {
        DWORD heapFlags = *((PDWORD)((PBYTE)processHeap + 0x40));
        printf("Heap Flags: 0x%08X\n", heapFlags);
        printf("HEAP_FLAG_VALIDATE_PARAMETERS: %s\n", 
               (heapFlags & 0x2) ? "设置" : "未设置");
    }
    
    // 综合判断
    BOOL detected = NTAPIPEBReader::IsBeingDebugged() || 
                   NTAPIPEBReader::IsNtGlobalFlagSet() || 
                   NTAPIPEBReader::IsProcessHeapFlagSet();
    
    printf("综合检测结果: %s\n", detected ? "被调试" : "未被调试");
    
    return detected;
}

// 获取进程基本信息
VOID GetProcessBasicInfo() {
    PNtQueryInformationProcess pfn = GetNtQueryInformationProcess();
    if (pfn == NULL) {
        printf("无法获取NtQueryInformationProcess函数。\n");
        return;
    }
    
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG returnLength = 0;
    
    NTSTATUS status = pfn(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );
    
    if (status == STATUS_SUCCESS) {
        printf("=== 进程基本信息 ===\n");
        printf("PEB基地址: 0x%p\n", pbi.PebBaseAddress);
        printf("进程ID: %llu\n", pbi.UniqueProcessId);
        printf("父进程ID: %llu\n", pbi.InheritedFromUniqueProcessId);
        printf("基本优先级: %ld\n", pbi.BasePriority);
        printf("处理器亲和性: 0x%llX\n", pbi.AffinityMask);
    } else {
        printf("获取进程基本信息失败，状态码: 0x%08X\n", status);
    }
}
```

### 4.4 反调试实现

```cpp
// 简单的NT API PEB反调试
VOID SimpleNTAPIPEBAntiDebug() {
    if (IsDebuggedViaNTAPIPEB()) {
        printf("通过NT API PEB检测到调试器存在！程序即将退出。\n");
        ExitProcess(1);
    }
}

// 多层次NT API PEB检测
BOOL MultiLayerNTAPIPEBCheck() {
    // 第一层：直接检测
    if (IsDebuggedViaNTAPIPEB()) {
        return TRUE;
    }
    
    // 第二层：详细检测
    if (DetailedNTAPIPEBDetection()) {
        return TRUE;
    }
    
    // 第三层：时间差检测
    DWORD start = GetTickCount();
    for (int i = 0; i < 1000; i++) {
        if (IsDebuggedViaNTAPIPEB()) {
            return TRUE;
        }
    }
    DWORD end = GetTickCount();
    
    // 如果执行时间过长，可能是被调试
    if ((end - start) > 50) {
        return TRUE;
    }
    
    return FALSE;
}

// 增强版反调试
VOID EnhancedNTAPIPEBAntiDebug() {
    // 多次检测
    for (int i = 0; i < 5; i++) {
        if (MultiLayerNTAPIPEBCheck()) {
            printf("第%d次NT API PEB检测发现调试环境！\n", i + 1);
            
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
    
    printf("NT API PEB反调试检测通过。\n");
}
```

### 4.5 绕过NT API PEB检测的方法

```cpp
// Hook NtQueryInformationProcess绕过PEB检测
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
    
    // 如果是ProcessBasicInformation查询且成功，可以修改返回的PEB地址
    if (ProcessInformationClass == ProcessBasicInformation && status == STATUS_SUCCESS) {
        // 注意：直接修改PEB地址可能很危险，这里仅作演示
        // 更好的方法是修改PEB中的具体字段
        
        PPROCESS_BASIC_INFORMATION pbi = (PPROCESS_BASIC_INFORMATION)ProcessInformation;
        if (pbi && ProcessInformationLength >= sizeof(PROCESS_BASIC_INFORMATION)) {
            // 可以在这里修改PEB地址或其他字段
            // pbi->PebBaseAddress = fake_peb_address;
        }
    }
    
    return status;
}

// 修改PEB中具体字段的绕过方法
VOID BypassPEBFieldsViaNTAPI() {
    // 获取真实的PEB地址
    PVOID realPEB = GetPEBViaNTAPI();
    if (realPEB == NULL) return;
    
    // 修改BeingDebugged标志
    *((PBYTE)realPEB + 0x02) = 0;
    
    // 修改NtGlobalFlag
#ifdef _WIN64
    *((PDWORD)((PBYTE)realPEB + 0xBC)) &= ~0x70;
#else
    *((PDWORD)((PBYTE)realPEB + 0x68)) &= ~0x70;
#endif
    
    // 修改ProcessHeap Flags
#ifdef _WIN64
    PVOID processHeap = *((PVOID*)((PBYTE)realPEB + 0x30));
#else
    PVOID processHeap = *((PVOID*)((PBYTE)realPEB + 0x18));
#endif
    
    if (processHeap != NULL) {
        *((PDWORD)((PBYTE)processHeap + 0x40)) &= ~0x2;
    }
    
    printf("通过NT API获取的PEB字段已绕过。\n");
}

// 综合绕过方法
VOID ComprehensiveNTAPIPEBBypass() {
    // 修改PEB字段
    BypassPEBFieldsViaNTAPI();
    
    printf("NT API PEB相关检测已绕过。\n");
}
```

### 4.6 完整测试程序

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 前面实现的函数声明
PVOID GetPEBViaNTAPI();
BOOL IsDebuggedViaNTAPIPEB();
BOOL DetailedNTAPIPEBDetection();
BOOL MultiLayerNTAPIPEBCheck();
VOID ComprehensiveNTAPIPEBBypass();

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

// 对比不同PEB获取方法
VOID ComparePEBAccessMethods() {
    printf("=== PEB访问方法对比 ===\n");
    
    // 方法1：通过NT API获取PEB
    PVOID peb_ntapi = GetPEBViaNTAPI();
    printf("NT API获取的PEB: 0x%p\n", peb_ntapi);
    
    // 方法2：通过FS/GS寄存器获取PEB
#ifdef _WIN64
    PVOID peb_register = (PVOID)__readgsqword(0x60);
#else
    PVOID peb_register = (PVOID)__readfsdword(0x30);
#endif
    printf("寄存器获取的PEB: 0x%p\n", peb_register);
    
    // 验证一致性
    if (peb_ntapi == peb_register) {
        printf("两种方法获取的PEB地址一致。\n");
    } else {
        printf("警告：两种方法获取的PEB地址不一致！\n");
    }
    
    printf("\n");
}

// 测试所有检测方法
VOID TestAllNTAPIPEBMethods() {
    printf("=== NT API PEB检测方法测试 ===\n");
    
    // 基础检测
    BOOL basicCheck = IsDebuggedViaNTAPIPEB();
    printf("基础NT API PEB检测: %s\n", basicCheck ? "被调试" : "未被调试");
    
    // 详细检测
    printf("详细NT API PEB检测:\n");
    BOOL detailedCheck = DetailedNTAPIPEBDetection();
    printf("详细检测结果: %s\n", detailedCheck ? "被调试" : "未被调试");
    
    // 多层检测
    BOOL multiCheck = MultiLayerNTAPIPEBCheck();
    printf("多层NT API PEB检测: %s\n", multiCheck ? "被调试" : "未被调试");
    
    printf("\n");
}

// 性能测试
VOID PerformanceTest() {
    const int iterations = 100000;
    
    printf("=== 性能测试 (%d次调用) ===\n", iterations);
    
    // 测试基础检测方法
    DWORD start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        IsDebuggedViaNTAPIPEB();
    }
    DWORD basicTime = GetTickCount() - start;
    
    // 测试多层检测方法
    start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        MultiLayerNTAPIPEBCheck();
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
    
    printf("未公开API获取PEB检测相关字段演示程序\n");
    printf("==================================\n\n");
    
    // 显示NT API信息
    DisplayNTAPIInfo();
    
    // 获取进程基本信息
    GetProcessBasicInfo();
    
    // 对比不同PEB访问方法
    ComparePEBAccessMethods();
    
    // 测试所有检测方法
    TestAllNTAPIPEBMethods();
    
    // 性能测试
    PerformanceTest();
    
    // 实际应用示例
    printf("=== 反调试检测 ===\n");
    if (MultiLayerNTAPIPEBCheck()) {
        printf("检测到调试环境，执行反调试措施。\n");
        
        // 这里可以执行各种反调试措施
        // 为演示目的，我们只是显示信息而不真正退出
        printf("（演示模式：不实际退出程序）\n");
    } else {
        printf("未检测到调试环境，程序正常运行。\n");
        MessageBoxW(NULL, L"NT API PEB检测通过，程序正常运行", L"提示", MB_OK);
    }
    
    // 演示绕过方法
    printf("\n=== 绕过演示 ===\n");
    printf("执行NT API PEB绕过...\n");
    ComprehensiveNTAPIPEBBypass();
    
    printf("绕过完成后再次检测：\n");
    if (MultiLayerNTAPIPEBCheck()) {
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
BOOL AntiTamperNTAPIPEBCheck() {
    // 多次调用并验证
    BOOL results[7];
    PVOID peb_addresses[7];
    
    for (int i = 0; i < 7; i++) {
        peb_addresses[i] = GetPEBViaNTAPI();
        results[i] = IsDebuggedViaNTAPIPEB();
        Sleep(1);  // 简短延迟
    }
    
    // 检查PEB地址一致性
    for (int i = 1; i < 7; i++) {
        if (peb_addresses[i] != peb_addresses[0]) {
            // PEB地址不一致，可能是被干扰了
            return TRUE;
        }
    }
    
    // 检查检测结果一致性
    for (int i = 1; i < 7; i++) {
        if (results[i] != results[0]) {
            // 结果不一致，可能是被干扰了
            return TRUE;
        }
    }
    
    return results[0];
}

// 时间差检测增强版
BOOL TimeBasedNTAPIPEBCheck() {
    DWORD start = GetTickCount();
    
    // 执行多次NT API PEB检查
    for (int i = 0; i < 1000; i++) {
        if (IsDebuggedViaNTAPIPEB()) {
            return TRUE;
        }
    }
    
    DWORD end = GetTickCount();
    
    // 如果执行时间过长，可能是被调试
    if ((end - start) > 50) {  // 超过50ms
        return TRUE;
    }
    
    return FALSE;
}

// 综合检测函数
BOOL ComprehensiveNTAPIPEBCheck() {
    // 抗干扰检测
    if (AntiTamperNTAPIPEBCheck()) {
        return TRUE;
    }
    
    // 时间差检测
    if (TimeBasedNTAPIPEBCheck()) {
        return TRUE;
    }
    
    // 其他NT API PEB检测
    if (DetailedNTAPIPEBDetection()) {
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

// 检测NT API调用的完整性
BOOL ValidateNTAPICall() {
    PNtQueryInformationProcess pfn = GetNtQueryInformationProcess();
    if (pfn == NULL) {
        return FALSE;
    }
    
    // 可以通过检查函数代码的完整性来验证NT API未被修改
    // 这需要更高级的技术，如代码校验和检查
    
    return TRUE;
}
```

## 五、课后作业

1. **基础练习**：
   - 在不同Windows版本下测试上述代码的兼容性
   - 实现对PEB中其他字段的访问和检测
   - 研究PROCESS_BASIC_INFORMATION结构中的其他字段用途

2. **进阶练习**：
   - 实现一个完整的NT API Hook检测和绕过框架
   - 研究如何检测NT API调用的完整性
   - 设计一个多层检测机制，结合多种NT API PEB检测技术

3. **思考题**：
   - 通过NT API获取PEB与直接通过寄存器获取PEB有何优劣？
   - ProcessBasicInformation信息类还有哪些其他用途？
   - 如何设计更加隐蔽的NT API PEB检测方法？

4. **扩展阅读**：
   - 研究Windows内核中PEB结构的完整实现
   - 了解NT API与Win32 API的关系
   - 学习现代调试器如何应对NT API PEB检测