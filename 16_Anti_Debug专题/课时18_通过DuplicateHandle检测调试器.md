# 课时18 通过DuplicateHandle检测调试器

## 一、课程目标

本节课主要学习如何利用Windows API函数`DuplicateHandle`的特殊行为来检测调试器的存在。这是一种高级反调试技术，通过复制无效句柄并观察其返回值来判断是否处于调试环境中。通过本课的学习，你将能够：

1. 理解`DuplicateHandle`函数的工作原理和用途
2. 掌握利用API函数行为差异进行反调试检测的方法
3. 学会编写基于`DuplicateHandle`的反调试代码
4. 理解调试器对API函数调用的影响
5. 了解该技术的检测和绕过方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| DuplicateHandle | Windows API函数，用于复制对象句柄 |
| 句柄复制 | 创建现有句柄的新引用 |
| 进程句柄 | 指向进程对象的句柄 |
| CURRENT_PROCESS | 当前进程的伪句柄 |
| 句柄权限 | 对句柄执行操作所需的访问权限 |
| 调试器拦截 | 调试器对API调用的特殊处理 |

## 三、技术原理

### 3.1 DuplicateHandle函数概述

`DuplicateHandle`是Windows API中用于复制对象句柄的函数。它可以将一个进程中的句柄复制到另一个进程中，或者在同一进程中创建句柄的新引用。

函数原型：
```cpp
BOOL DuplicateHandle(
    HANDLE hSourceProcessHandle,
    HANDLE hSourceHandle,
    HANDLE hTargetProcessHandle,
    LPHANDLE lpTargetHandle,
    DWORD  dwDesiredAccess,
    BOOL   bInheritHandle,
    DWORD  dwOptions
);
```

参数说明：
- `hSourceProcessHandle`：源进程句柄
- `hSourceHandle`：要复制的源句柄
- `hTargetProcessHandle`：目标进程句柄
- `lpTargetHandle`：接收复制句柄的指针
- `dwDesiredAccess`：所需的访问权限
- `bInheritHandle`：是否继承句柄
- `dwOptions`：复制选项

### 3.2 调试器环境中的特殊行为

在调试器环境中，`DuplicateHandle`的行为可能会发生变化：

1. **正常环境**：对无效句柄调用返回FALSE，错误码为`ERROR_INVALID_HANDLE`
2. **调试环境**：某些调试器可能会拦截并修改这个调用

### 3.3 检测原理

通过传递无效句柄给`DuplicateHandle`并检查其返回值和错误码，可以判断程序是否在调试器中运行。这种技术利用了调试器对API调用的特殊处理方式。

## 四、代码实现

### 4.1 基础DuplicateHandle检测

```cpp
#include <windows.h>
#include <stdio.h>

// 基础DuplicateHandle检测
BOOL DetectDebuggerViaDuplicateHandle() {
    printf("=== DuplicateHandle检测 ===\n");
    
    BOOL debuggerDetected = FALSE;
    HANDLE targetHandle = NULL;
    
    // 测试1: 使用INVALID_HANDLE_VALUE复制句柄
    SetLastError(0);
    BOOL result1 = DuplicateHandle(
        GetCurrentProcess(),        // 源进程句柄
        INVALID_HANDLE_VALUE,       // 无效源句柄
        GetCurrentProcess(),        // 目标进程句柄
        &targetHandle,              // 目标句柄指针
        0,                         // 所需访问权限
        FALSE,                     // 不继承
        0                          // 选项
    );
    DWORD error1 = GetLastError();
    
    printf("DuplicateHandle(INVALID_HANDLE_VALUE):\n");
    printf("  返回值: %s\n", result1 ? "TRUE" : "FALSE");
    printf("  错误码: %lu\n", error1);
    
    // 正常情况下应该返回FALSE，错误码为6 (ERROR_INVALID_HANDLE)
    if (result1 != FALSE || error1 != ERROR_INVALID_HANDLE) {
        printf("  异常行为，可能检测到调试器。\n");
        debuggerDetected = TRUE;
    }
    
    // 测试2: 使用NULL句柄复制句柄
    SetLastError(0);
    BOOL result2 = DuplicateHandle(
        GetCurrentProcess(),
        NULL,
        GetCurrentProcess(),
        &targetHandle,
        0,
        FALSE,
        0
    );
    DWORD error2 = GetLastError();
    
    printf("DuplicateHandle(NULL):\n");
    printf("  返回值: %s\n", result2 ? "TRUE" : "FALSE");
    printf("  错误码: %lu\n", error2);
    
    // 正常情况下应该返回FALSE，错误码为6 (ERROR_INVALID_HANDLE)
    if (result2 != FALSE || error2 != ERROR_INVALID_HANDLE) {
        printf("  异常行为，可能检测到调试器。\n");
        debuggerDetected = TRUE;
    }
    
    // 测试3: 使用随机无效句柄
    HANDLE invalidHandles[] = {
        (HANDLE)0x12345678,
        (HANDLE)0xDEADBEEF,
        (HANDLE)0xBAADF00D,
        (HANDLE)-1,
        (HANDLE)-2
    };
    
    for (int i = 0; i < sizeof(invalidHandles)/sizeof(invalidHandles[0]); i++) {
        SetLastError(0);
        BOOL result = DuplicateHandle(
            GetCurrentProcess(),
            invalidHandles[i],
            GetCurrentProcess(),
            &targetHandle,
            0,
            FALSE,
            0
        );
        DWORD error = GetLastError();
        
        printf("DuplicateHandle(0x%p):\n", invalidHandles[i]);
        printf("  返回值: %s\n", result ? "TRUE" : "FALSE");
        printf("  错误码: %lu\n", error);
        
        // 正常情况下应该返回FALSE，错误码为6
        if (result != FALSE || error != ERROR_INVALID_HANDLE) {
            printf("  异常行为，可能检测到调试器。\n");
            debuggerDetected = TRUE;
        }
    }
    
    if (!debuggerDetected) {
        printf("DuplicateHandle行为正常，未检测到调试器。\n");
    }
    
    return debuggerDetected;
}
```

### 4.2 增强版DuplicateHandle检测

```cpp
// 增强版DuplicateHandle检测
BOOL EnhancedDuplicateHandleDetection() {
    printf("=== 增强版DuplicateHandle检测 ===\n");
    
    BOOL debuggerDetected = FALSE;
    HANDLE targetHandle = NULL;
    
    // 测试多种无效句柄值
    HANDLE testHandles[] = {
        INVALID_HANDLE_VALUE,           // -1
        NULL,                          // 0
        (HANDLE)1,                     // 最小有效句柄值
        (HANDLE)2,                     // 另一个小值
        (HANDLE)0x1000,                // 页面大小附近
        (HANDLE)0x12345678,            // 随机值
        (HANDLE)0xDEADBEEF,            // 经典调试值
        (HANDLE)0xBAADF00D,            // 另一个经典调试值
        (HANDLE)0xFFFFFFFF,            // 最大DWORD值
        (HANDLE)0xCCCCCCCC,            // 调试器填充模式
        (HANDLE)0xCDCDCDCD,            // 另一个调试器填充模式
    };
    
    DWORD testAccessRights[] = {
        0,                              // 无权限
        GENERIC_READ,                   // 读权限
        GENERIC_WRITE,                  // 写权限
        GENERIC_EXECUTE,                // 执行权限
        GENERIC_ALL,                    // 所有权限
        0xFFFFFFFF                      // 所有位都设置
    };
    
    int normalBehaviorCount = 0;
    int abnormalBehaviorCount = 0;
    
    for (int i = 0; i < sizeof(testHandles)/sizeof(testHandles[0]); i++) {
        for (int j = 0; j < sizeof(testAccessRights)/sizeof(testAccessRights[0]); j++) {
            SetLastError(0);
            BOOL result = DuplicateHandle(
                GetCurrentProcess(),
                testHandles[i],
                GetCurrentProcess(),
                &targetHandle,
                testAccessRights[j],
                FALSE,
                0
            );
            DWORD error = GetLastError();
            
            // 正常行为: 返回FALSE，错误码6
            if (result == FALSE && error == ERROR_INVALID_HANDLE) {
                normalBehaviorCount++;
            } else {
                abnormalBehaviorCount++;
                printf("异常行为检测: DuplicateHandle(0x%p, 0x%08X) -> %s, Error=%lu\n", 
                       testHandles[i], testAccessRights[j], result ? "TRUE" : "FALSE", error);
                
                // 如果成功复制了无效句柄，需要关闭它
                if (result == TRUE && targetHandle != NULL) {
                    CloseHandle(targetHandle);
                    targetHandle = NULL;
                }
            }
        }
    }
    
    printf("正常行为次数: %d\n", normalBehaviorCount);
    printf("异常行为次数: %d\n", abnormalBehaviorCount);
    
    // 如果异常行为比例过高，可能检测到调试器
    if (abnormalBehaviorCount > 10) {
        printf("异常行为比例过高，可能检测到调试器。\n");
        debuggerDetected = TRUE;
    }
    
    return debuggerDetected;
}

// 基于时间差的DuplicateHandle检测
BOOL TimeBasedDuplicateHandleDetection() {
    printf("=== 时间差DuplicateHandle检测 ===\n");
    
    HANDLE targetHandle = NULL;
    
    // 测量多次调用DuplicateHandle的时间
    DWORD start = GetTickCount();
    
    for (int i = 0; i < 1000; i++) {
        DuplicateHandle(
            GetCurrentProcess(),
            INVALID_HANDLE_VALUE,
            GetCurrentProcess(),
            &targetHandle,
            0,
            FALSE,
            0
        );
    }
    
    DWORD end = GetTickCount();
    DWORD elapsed = end - start;
    
    printf("1000次DuplicateHandle调用耗时: %lu ms\n", elapsed);
    
    // 在调试器中，API调用可能会变慢
    if (elapsed > 100) {  // 超过100ms可能表示被调试
        printf("调用时间过长，可能检测到调试器。\n");
        return TRUE;
    }
    
    return FALSE;
}
```

### 4.3 基于有效句柄的检测

```cpp
// 基于有效句柄的DuplicateHandle检测
BOOL DetectDebuggerViaValidHandleDuplicateHandle() {
    printf("=== 有效句柄DuplicateHandle检测 ===\n");
    
    BOOL debuggerDetected = FALSE;
    HANDLE targetHandle = NULL;
    
    // 创建一个有效句柄（事件对象）
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL) {
        printf("无法创建事件对象。\n");
        return FALSE;
    }
    
    // 测试有效句柄的行为
    SetLastError(0);
    BOOL result1 = DuplicateHandle(
        GetCurrentProcess(),
        hEvent,
        GetCurrentProcess(),
        &targetHandle,
        0,
        FALSE,
        0
    );
    DWORD error1 = GetLastError();
    
    printf("DuplicateHandle(有效句柄):\n");
    printf("  返回值: %s\n", result1 ? "TRUE" : "FALSE");
    printf("  错误码: %lu\n", error1);
    
    if (result1 != TRUE || error1 != 0) {
        printf("  有效句柄行为异常，可能检测到调试器。\n");
        debuggerDetected = TRUE;
    } else {
        // 清理复制的句柄
        if (targetHandle != NULL) {
            CloseHandle(targetHandle);
        }
    }
    
    // 测试不同的访问权限
    DWORD testPermissions[] = {
        GENERIC_READ,
        GENERIC_WRITE,
        GENERIC_EXECUTE,
        GENERIC_ALL
    };
    
    for (int i = 0; i < sizeof(testPermissions)/sizeof(testPermissions[0]); i++) {
        SetLastError(0);
        BOOL result = DuplicateHandle(
            GetCurrentProcess(),
            hEvent,
            GetCurrentProcess(),
            &targetHandle,
            testPermissions[i],
            FALSE,
            0
        );
        DWORD error = GetLastError();
        
        printf("DuplicateHandle(有效句柄, 权限=0x%08X):\n", testPermissions[i]);
        printf("  返回值: %s\n", result ? "TRUE" : "FALSE");
        printf("  错误码: %lu\n", error);
        
        if (result != TRUE || error != 0) {
            printf("  有效句柄行为异常，可能检测到调试器。\n");
            debuggerDetected = TRUE;
        } else {
            // 清理复制的句柄
            if (targetHandle != NULL) {
                CloseHandle(targetHandle);
                targetHandle = NULL;
            }
        }
    }
    
    // 清理资源
    CloseHandle(hEvent);
    
    return debuggerDetected;
}

// 比较有效句柄和无效句柄的行为
BOOL CompareValidAndInvalidHandleDuplicateBehavior() {
    printf("=== 有效句柄与无效句柄Duplicate行为比较 ===\n");
    
    HANDLE targetHandle = NULL;
    
    // 创建有效句柄
    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (hEvent == NULL) {
        printf("无法创建事件对象。\n");
        return FALSE;
    }
    
    BOOL debuggerDetected = FALSE;
    
    // 测试有效句柄
    SetLastError(0);
    BOOL validResult = DuplicateHandle(
        GetCurrentProcess(),
        hEvent,
        GetCurrentProcess(),
        &targetHandle,
        0,
        FALSE,
        0
    );
    DWORD validError = GetLastError();
    
    // 清理复制的句柄
    if (validResult && targetHandle != NULL) {
        CloseHandle(targetHandle);
        targetHandle = NULL;
    }
    
    // 测试无效句柄
    SetLastError(0);
    BOOL invalidResult = DuplicateHandle(
        GetCurrentProcess(),
        INVALID_HANDLE_VALUE,
        GetCurrentProcess(),
        &targetHandle,
        0,
        FALSE,
        0
    );
    DWORD invalidError = GetLastError();
    
    printf("有效句柄行为: 结果=%s, 错误=%lu\n", 
           validResult ? "TRUE" : "FALSE", validError);
    printf("无效句柄行为: 结果=%s, 错误=%lu\n", 
           invalidResult ? "TRUE" : "FALSE", invalidError);
    
    // 检查行为的一致性
    BOOL validBehaviorCorrect = (validResult == TRUE && validError == 0);
    BOOL invalidBehaviorCorrect = (invalidResult == FALSE && invalidError == ERROR_INVALID_HANDLE);
    
    if (!validBehaviorCorrect || !invalidBehaviorCorrect) {
        printf("句柄行为不一致，可能检测到调试器。\n");
        debuggerDetected = TRUE;
    }
    
    // 清理资源
    CloseHandle(hEvent);
    
    return debuggerDetected;
}
```

### 4.4 完整的DuplicateHandle检测实现

```cpp
// DuplicateHandle检测工具类
class DuplicateHandleDetector {
public:
    static void DisplayDuplicateHandleInfo() {
        printf("=== DuplicateHandle信息 ===\n");
        printf("INVALID_HANDLE_VALUE: 0x%p\n", INVALID_HANDLE_VALUE);
        printf("NULL: 0x%p\n", NULL);
        printf("CURRENT_PROCESS: 0x%p\n", GetCurrentProcess());
        printf("\n");
    }
    
    static BOOL DetectKnownDuplicateHandleIssues() {
        printf("=== DuplicateHandle相关检测 ===\n");
        
        BOOL detected = FALSE;
        
        // 基础检测
        if (DetectDebuggerViaDuplicateHandle()) {
            detected = TRUE;
        }
        
        // 增强检测
        if (EnhancedDuplicateHandleDetection()) {
            detected = TRUE;
        }
        
        // 时间差检测
        if (TimeBasedDuplicateHandleDetection()) {
            detected = TRUE;
        }
        
        // 有效句柄检测
        if (DetectDebuggerViaValidHandleDuplicateHandle()) {
            detected = TRUE;
        }
        
        // 行为比较
        if (CompareValidAndInvalidHandleDuplicateBehavior()) {
            detected = TRUE;
        }
        
        if (!detected) {
            printf("未检测到DuplicateHandle相关异常。\n");
        }
        
        return detected;
    }
    
    static BOOL DetectSuspiciousDuplicateHandleBehavior() {
        printf("=== 可疑DuplicateHandle行为检测 ===\n");
        
        HANDLE targetHandle = NULL;
        
        // 统计多次调用的行为
        int successCount = 0;
        int failureCount = 0;
        int unexpectedErrorCount = 0;
        
        for (int i = 0; i < 100; i++) {
            SetLastError(0);
            BOOL result = DuplicateHandle(
                GetCurrentProcess(),
                (HANDLE)(0x1000 + i),
                GetCurrentProcess(),
                &targetHandle,
                0,
                FALSE,
                0
            );
            DWORD error = GetLastError();
            
            if (result == TRUE) {
                successCount++;
                // 清理复制的句柄
                if (targetHandle != NULL) {
                    CloseHandle(targetHandle);
                    targetHandle = NULL;
                }
            } else if (error == ERROR_INVALID_HANDLE) {
                failureCount++;
            } else {
                unexpectedErrorCount++;
                printf("意外错误: DuplicateHandle(0x%p) -> Error=%lu\n", 
                       (HANDLE)(0x1000 + i), error);
            }
        }
        
        printf("成功次数: %d\n", successCount);
        printf("失败次数: %d\n", failureCount);
        printf("意外错误次数: %d\n", unexpectedErrorCount);
        
        // 正常情况下应该全部失败且错误码为6
        if (successCount > 0 || unexpectedErrorCount > 0) {
            printf("发现可疑行为，可能检测到调试器。\n");
            return TRUE;
        }
        
        return FALSE;
    }
};
```

### 4.5 反调试实现

```cpp
// 简单的DuplicateHandle反调试
VOID SimpleDuplicateHandleAntiDebug() {
    if (DuplicateHandleDetector::DetectKnownDuplicateHandleIssues()) {
        printf("通过DuplicateHandle检测到调试器存在！程序即将退出。\n");
        ExitProcess(1);
    }
}

// 多层次DuplicateHandle检测
BOOL MultiLayerDuplicateHandleDetection() {
    // 第一层：基础检测
    if (DuplicateHandleDetector::DetectKnownDuplicateHandleIssues()) {
        return TRUE;
    }
    
    // 第二层：可疑行为检测
    if (DuplicateHandleDetector::DetectSuspiciousDuplicateHandleBehavior()) {
        return TRUE;
    }
    
    // 第三层：定期检测
    static DWORD lastCheck = 0;
    DWORD currentTime = GetTickCount();
    
    if (currentTime - lastCheck > 2000) {  // 每2秒检测一次
        lastCheck = currentTime;
        if (DuplicateHandleDetector::DetectKnownDuplicateHandleIssues()) {
            return TRUE;
        }
    }
    
    return FALSE;
}

// 增强版反调试
VOID EnhancedDuplicateHandleAntiDebug() {
    // 多次检测
    for (int i = 0; i < 3; i++) {
        if (MultiLayerDuplicateHandleDetection()) {
            printf("第%d次DuplicateHandle检测发现调试环境！\n", i + 1);
            
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
    
    printf("DuplicateHandle反调试检测通过。\n");
}
```

### 4.6 绕过DuplicateHandle检测的方法

```cpp
// DuplicateHandle检测绕过技术
class DuplicateHandleObfuscator {
public:
    // 修复DuplicateHandle行为
    static BOOL RepairDuplicateHandleBehavior() {
        printf("修复DuplicateHandle行为...\n");
        
        // 这里可以实现Hook或其他技术来确保DuplicateHandle行为正常
        // 实际实现需要深入了解API Hook技术
        
        return TRUE;
    }
    
    // 模拟正常DuplicateHandle行为
    static BOOL SimulateNormalDuplicateHandleBehavior() {
        printf("模拟正常DuplicateHandle行为...\n");
        
        // 可以通过修改API调用的返回值来模拟正常行为
        
        return TRUE;
    }
    
    // 隐藏异常调用
    static BOOL HideAbnormalDuplicateHandleCalls() {
        printf("隐藏异常DuplicateHandle调用...\n");
        
        // 可以通过拦截API调用来隐藏异常行为
        
        return TRUE;
    }
};

// 综合绕过方法
VOID ComprehensiveDuplicateHandleBypass() {
    // 修复DuplicateHandle行为
    DuplicateHandleObfuscator::RepairDuplicateHandleBehavior();
    
    // 模拟正常行为
    DuplicateHandleObfuscator::SimulateNormalDuplicateHandleBehavior();
    
    // 隐藏异常调用
    DuplicateHandleObfuscator::HideAbnormalDuplicateHandleCalls();
    
    printf("DuplicateHandle检测绕过完成。\n");
}
```

### 4.7 完整测试程序

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 前面实现的函数声明
BOOL DetectDebuggerViaDuplicateHandle();
BOOL MultiLayerDuplicateHandleDetection();
VOID ComprehensiveDuplicateHandleBypass();

// 显示系统句柄信息
VOID DisplaySystemHandleInfo() {
    printf("=== 系统句柄信息 ===\n");
    
    // 显示当前进程的一些有效句柄
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();
    
    printf("当前进程句柄: 0x%p\n", hProcess);
    printf("当前线程句柄: 0x%p\n", hThread);
    
    // 显示标准句柄
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE hStderr = GetStdHandle(STD_ERROR_HANDLE);
    
    printf("标准输入句柄: 0x%p\n", hStdin);
    printf("标准输出句柄: 0x%p\n", hStdout);
    printf("标准错误句柄: 0x%p\n", hStderr);
    
    printf("\n");
}

// 性能测试
VOID PerformanceTest() {
    const int iterations = 100;
    
    printf("=== 性能测试 (%d次调用) ===\n", iterations);
    
    // 测试DuplicateHandle检测方法
    DWORD start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        DetectDebuggerViaDuplicateHandle();
    }
    DWORD duplicateTime = GetTickCount() - start;
    
    printf("DuplicateHandle检测耗时: %lu ms\n", duplicateTime);
    
    printf("\n");
}

// 主程序
int main() {
    srand((unsigned int)time(NULL));
    
    printf("通过DuplicateHandle检测调试器演示程序\n");
    printf("================================\n\n");
    
    // 显示系统句柄信息
    DisplaySystemHandleInfo();
    
    // 显示DuplicateHandle信息
    DuplicateHandleDetector::DisplayDuplicateHandleInfo();
    
    // 基础DuplicateHandle检测
    DetectDebuggerViaDuplicateHandle();
    
    // 增强版检测
    EnhancedDuplicateHandleDetection();
    
    // 时间差检测
    TimeBasedDuplicateHandleDetection();
    
    // 有效句柄检测
    DetectDebuggerViaValidHandleDuplicateHandle();
    
    // 行为比较
    CompareValidAndInvalidHandleDuplicateBehavior();
    
    // 可疑行为检测
    DuplicateHandleDetector::DetectSuspiciousDuplicateHandleBehavior();
    
    // 性能测试
    PerformanceTest();
    
    // 实际应用示例
    printf("=== 反调试检测 ===\n");
    if (MultiLayerDuplicateHandleDetection()) {
        printf("检测到调试环境，执行反调试措施。\n");
        
        // 这里可以执行各种反调试措施
        // 为演示目的，我们只是显示信息而不真正退出
        printf("（演示模式：不实际退出程序）\n");
    } else {
        printf("未检测到调试环境，程序正常运行。\n");
        MessageBoxW(NULL, L"DuplicateHandle检测通过，程序正常运行", L"提示", MB_OK);
    }
    
    // 演示绕过方法
    printf("\n=== 绕过演示 ===\n");
    printf("执行DuplicateHandle绕过...\n");
    ComprehensiveDuplicateHandleBypass();
    
    printf("绕过完成后再次检测：\n");
    if (MultiLayerDuplicateHandleDetection()) {
        printf("仍然检测到调试环境。\n");
    } else {
        printf("检测结果显示未发现DuplicateHandle异常。\n");
    }
    
    return 0;
}
```

### 4.8 高级技巧和注意事项

```cpp
// 抗干扰版本（防止简单的Hook）
BOOL AntiTamperDuplicateHandleDetection() {
    // 多次调用并验证
    BOOL results[3];
    
    for (int i = 0; i < 3; i++) {
        results[i] = MultiLayerDuplicateHandleDetection();
        Sleep(10);  // 简短延迟
    }
    
    // 检查结果一致性
    for (int i = 1; i < 3; i++) {
        if (results[i] != results[0]) {
            // 结果不一致，可能是被干扰了
            return TRUE;  // 假设存在调试环境
        }
    }
    
    return results[0];
}

// 时间差检测增强版
BOOL TimeBasedDuplicateHandleEnhancedDetection() {
    DWORD start = GetTickCount();
    
    // 执行多次DuplicateHandle检测
    for (int i = 0; i < 10; i++) {
        if (MultiLayerDuplicateHandleDetection()) {
            return TRUE;
        }
    }
    
    DWORD end = GetTickCount();
    
    // 如果执行时间过长，可能是被调试
    if ((end - start) > 1000) {  // 超过1秒
        return TRUE;
    }
    
    return FALSE;
}

// 综合检测函数
BOOL ComprehensiveDuplicateHandleDetection() {
    // 抗干扰检测
    if (AntiTamperDuplicateHandleDetection()) {
        return TRUE;
    }
    
    // 时间差检测
    if (TimeBasedDuplicateHandleEnhancedDetection()) {
        return TRUE;
    }
    
    // 其他DuplicateHandle检测
    if (DuplicateHandleDetector::DetectSuspiciousDuplicateHandleBehavior()) {
        return TRUE;
    }
    
    return FALSE;
}

// 动态获取API地址（避免静态导入）
FARPROC GetDynamicAPIAddress(LPCSTR moduleName, LPCSTR functionName) {
    // 动态加载模块
    HMODULE hModule = LoadLibraryA(moduleName);
    if (hModule == NULL) {
        return NULL;
    }
    
    // 获取函数地址
    FARPROC pfn = GetProcAddress(hModule, functionName);
    
    return pfn;
}

// 检测DuplicateHandle调用的完整性
BOOL ValidateDuplicateHandleCall() {
    // 可以通过检查DuplicateHandle函数代码的完整性来验证未被修改
    // 这需要更高级的技术，如代码校验和检查
    
    return TRUE;
}

// 多线程环境下的DuplicateHandle检测
BOOL MultiThreadDuplicateHandleDetection() {
    printf("=== 多线程DuplicateHandle检测 ===\n");
    
    // 在多线程环境中进行检测可以增加检测的可靠性
    
    return FALSE;
}
```

## 五、课后作业

1. **基础练习**：
   - 在不同Windows版本下测试上述代码的兼容性
   - 研究DuplicateHandle在不同句柄类型下的行为差异
   - 实现对DuplicateHandle返回值的完整验证

2. **进阶练习**：
   - 实现一个完整的DuplicateHandle行为监控器
   - 研究如何检测通过Hook绕过检测的调试器
   - 设计一个多层检测机制，结合DuplicateHandle和其他反调试技术

3. **思考题**：
   - DuplicateHandle检测方法有哪些明显的局限性？
   - 如何提高DuplicateHandle检测的准确性和隐蔽性？
   - 现代调试器采用了哪些技术来对抗DuplicateHandle检测？

4. **扩展阅读**：
   - 研究Windows句柄复制机制
   - 了解API Hook和反Hook技术
   - 学习现代反反调试技术