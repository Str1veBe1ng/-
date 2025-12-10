# 课时25 通过StartupInfo检测调试器

## 一、课程目标

本节课主要学习如何通过检查STARTUPINFO结构来检测调试器的存在。当程序通过调试器启动时，STARTUPINFO结构中的某些字段会与正常启动时不同。通过分析这些差异可以判断程序是否在调试环境下运行。通过本课的学习，你将能够：

1. 理解STARTUPINFO结构的作用和组成
2. 掌握通过StartupInfo检测调试器的原理
3. 学会编写基于StartupInfo的反调试代码
4. 了解该技术的检测和绕过方法
5. 理解调试器启动机制对程序环境的影响

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| STARTUPINFO | Windows API结构，包含进程启动时的信息 |
| GetStartupInfo | Windows API函数，用于获取STARTUPINFO结构 |
| dwFlags | STARTUPINFO结构中的标志字段 |
| wShowWindow | STARTUPINFO结构中的窗口显示方式字段 |
| dwX, dwY | STARTUPINFO结构中的窗口位置字段 |
| dwXSize, dwYSize | STARTUPINFO结构中的窗口大小字段 |
| hStdInput | STARTUPINFO结构中的标准输入句柄 |
| hStdOutput | STARTUPINFO结构中的标准输出句柄 |
| hStdError | STARTUPINFO结构中的标准错误句柄 |

## 三、技术原理

### 3.1 STARTUPINFO结构概述

STARTUPINFO结构是Windows API中用于指定新进程启动信息的结构体，定义如下：

```cpp
typedef struct _STARTUPINFO {
    DWORD cb;
    LPTSTR lpReserved;
    LPTSTR lpDesktop;
    LPTSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFO, *LPSTARTUPINFO;
```

### 3.2 调试器启动时的差异

当程序通过调试器启动时，STARTUPINFO结构中的某些字段会出现特定的模式：

1. **dwFlags字段**：调试器启动时可能设置特定标志
2. **wShowWindow字段**：窗口显示方式可能不同
3. **句柄字段**：标准输入输出句柄可能指向不同对象
4. **窗口位置和大小**：可能为默认值或特殊值

### 3.3 检测原理

通过比较STARTUPINFO结构中各字段的值与正常启动时的预期值，可以判断程序是否通过调试器启动。

## 四、代码实现

### 4.1 基础StartupInfo检测

```cpp
#include <windows.h>
#include <stdio.h>

// 基础StartupInfo检测
BOOL DetectDebuggerViaStartupInfo() {
    printf("=== 基础StartupInfo检测 ===\n");
    
    STARTUPINFO si;
    si.cb = sizeof(si);
    GetStartupInfo(&si);
    
    printf("STARTUPINFO信息:\n");
    printf("  cb: %lu\n", si.cb);
    printf("  dwFlags: 0x%08X\n", si.dwFlags);
    printf("  wShowWindow: %u\n", si.wShowWindow);
    printf("  dwX: %lu, dwY: %lu\n", si.dwX, si.dwY);
    printf("  dwXSize: %lu, dwYSize: %lu\n", si.dwXSize, si.dwYSize);
    printf("  hStdInput: 0x%p\n", si.hStdInput);
    printf("  hStdOutput: 0x%p\n", si.hStdOutput);
    printf("  hStdError: 0x%p\n", si.hStdError);
    
    // 检查常见异常模式
    BOOL detected = FALSE;
    
    // 检查dwFlags字段
    if (si.dwFlags & STARTF_USESHOWWINDOW) {
        printf("检测到STARTF_USESHOWWINDOW标志。\n");
        // 这本身不一定表示调试器，但值得关注
    }
    
    // 检查窗口位置是否为CW_USEDEFAULT (-1)
    if (si.dwX == CW_USEDEFAULT && si.dwY == CW_USEDEFAULT) {
        printf("窗口位置为默认值，可能是调试器启动。\n");
        detected = TRUE;
    }
    
    // 检查窗口大小是否为0
    if (si.dwXSize == 0 && si.dwYSize == 0) {
        printf("窗口大小为0，可能是调试器启动。\n");
        detected = TRUE;
    }
    
    // 检查标准句柄是否为NULL
    if (si.hStdInput == NULL && si.hStdOutput == NULL && si.hStdError == NULL) {
        printf("标准句柄均为NULL，可能是调试器启动。\n");
        detected = TRUE;
    }
    
    // 检查wShowWindow字段
    if (si.wShowWindow == SW_HIDE) {
        printf("窗口显示方式为隐藏，可能是调试器启动。\n");
        detected = TRUE;
    }
    
    return detected;
}

// 改进的StartupInfo检测
BOOL ImprovedStartupInfoDetection() {
    printf("=== 改进版StartupInfo检测 ===\n");
    
    STARTUPINFO si;
    si.cb = sizeof(si);
    GetStartupInfo(&si);
    
    BOOL detected = FALSE;
    
    // 检查cb字段是否正确
    if (si.cb != sizeof(STARTUPINFO)) {
        printf("STARTUPINFO大小异常: %lu (期望: %zu)\n", si.cb, sizeof(STARTUPINFO));
        detected = TRUE;
    }
    
    // 检查标志字段的组合
    if ((si.dwFlags & STARTF_USEPOSITION) && 
        (si.dwX == CW_USEDEFAULT || si.dwY == CW_USEDEFAULT)) {
        printf("同时设置了USEPOSITION标志和默认位置，异常。\n");
        detected = TRUE;
    }
    
    // 检查尺寸标志和实际尺寸的一致性
    if ((si.dwFlags & STARTF_USESIZE) == 0 && (si.dwXSize != 0 || si.dwYSize != 0)) {
        printf("未设置USESIZ标志但有尺寸值，异常。\n");
        detected = TRUE;
    }
    
    // 检查字符计数标志和实际计数的一致性
    if ((si.dwFlags & STARTF_USECOUNTCHARS) == 0 && 
        (si.dwXCountChars != 0 || si.dwYCountChars != 0)) {
        printf("未设置USECOUNTCHARS标志但有字符计数值，异常。\n");
        detected = TRUE;
    }
    
    // 检查填充属性标志和实际属性的一致性
    if ((si.dwFlags & STARTF_USEFILLATTRIBUTE) == 0 && si.dwFillAttribute != 0) {
        printf("未设置USEFILLATTRIBUTE标志但有填充属性值，异常。\n");
        detected = TRUE;
    }
    
    // 检查标准句柄的一致性
    if (si.dwFlags & STARTF_USESTDHANDLES) {
        // 如果设置了使用标准句柄标志，检查句柄是否有效
        if (si.hStdInput == NULL && si.hStdOutput == NULL && si.hStdError == NULL) {
            printf("设置了USESTDHANDLES标志但句柄均为NULL，异常。\n");
            detected = TRUE;
        }
    } else {
        // 如果未设置使用标准句柄标志，句柄通常应该为NULL
        if (si.hStdInput != NULL || si.hStdOutput != NULL || si.hStdError != NULL) {
            printf("未设置USESTDHANDLES标志但句柄非NULL，异常。\n");
            detected = TRUE;
        }
    }
    
    return detected;
}
```

### 4.2 高级StartupInfo检测

```cpp
// 检查STARTUPINFO的深层特征
BOOL DeepStartupInfoAnalysis() {
    printf("=== 深度StartupInfo分析 ===\n");
    
    STARTUPINFO si;
    si.cb = sizeof(si);
    GetStartupInfo(&si);
    
    BOOL detected = FALSE;
    
    // 检查lpReserved字段（通常为NULL）
    if (si.lpReserved != NULL) {
        printf("lpReserved非NULL，值: %p\n", si.lpReserved);
        detected = TRUE;
    }
    
    // 检查lpDesktop字段
    if (si.lpDesktop != NULL) {
        printf("lpDesktop非NULL，值: %ws\n", si.lpDesktop);
        // 某些调试器可能会设置特定桌面
        if (wcsstr(si.lpDesktop, L"Default") != NULL) {
            printf("检测到默认桌面，可能是调试器特征。\n");
            detected = TRUE;
        }
    }
    
    // 检查lpTitle字段
    if (si.lpTitle != NULL) {
        printf("lpTitle非NULL，值: %ws\n", si.lpTitle);
        // 检查标题中是否包含调试器相关词汇
        wchar_t* debugKeywords[] = {L"Debug", L"Olly", L"x32dbg", L"x64dbg", L"IDA"};
        for (int i = 0; i < sizeof(debugKeywords)/sizeof(debugKeywords[0]); i++) {
            if (wcsstr(si.lpTitle, debugKeywords[i]) != NULL) {
                printf("检测到调试器相关标题关键词: %ws\n", debugKeywords[i]);
                detected = TRUE;
            }
        }
    }
    
    // 检查cbReserved2和lpReserved2字段
    if (si.cbReserved2 != 0) {
        printf("cbReserved2非0: %u\n", si.cbReserved2);
        detected = TRUE;
    }
    
    if (si.lpReserved2 != NULL) {
        printf("lpReserved2非NULL，值: %p\n", si.lpReserved2);
        detected = TRUE;
    }
    
    // 检查窗口坐标的有效性
    if (si.dwFlags & STARTF_USEPOSITION) {
        // 检查坐标是否在合理范围内
        if (si.dwX > 100000 || si.dwY > 100000) {
            printf("窗口坐标异常: X=%lu, Y=%lu\n", si.dwX, si.dwY);
            detected = TRUE;
        }
    }
    
    // 检查窗口尺寸的有效性
    if (si.dwFlags & STARTF_USESIZE) {
        // 检查尺寸是否在合理范围内
        if (si.dwXSize > 10000 || si.dwYSize > 10000) {
            printf("窗口尺寸异常: Width=%lu, Height=%lu\n", si.dwXSize, si.dwYSize);
            detected = TRUE;
        }
    }
    
    return detected;
}

// 比较不同时间点的STARTUPINFO
BOOL CompareStartupInfoOverTime() {
    printf("=== STARTUPINFO时间序列比较 ===\n");
    
    STARTUPINFO si1, si2;
    
    // 第一次获取
    si1.cb = sizeof(si1);
    GetStartupInfo(&si1);
    
    // 短暂延迟
    Sleep(100);
    
    // 第二次获取
    si2.cb = sizeof(si2);
    GetStartupInfo(&si2);
    
    // 比较关键字段
    BOOL changed = FALSE;
    
    if (si1.dwFlags != si2.dwFlags) {
        printf("dwFlags发生变化: 0x%08X -> 0x%08X\n", si1.dwFlags, si2.dwFlags);
        changed = TRUE;
    }
    
    if (si1.wShowWindow != si2.wShowWindow) {
        printf("wShowWindow发生变化: %u -> %u\n", si1.wShowWindow, si2.wShowWindow);
        changed = TRUE;
    }
    
    if (si1.hStdInput != si2.hStdInput) {
        printf("hStdInput发生变化: 0x%p -> 0x%p\n", si1.hStdInput, si2.hStdInput);
        changed = TRUE;
    }
    
    if (si1.hStdOutput != si2.hStdOutput) {
        printf("hStdOutput发生变化: 0x%p -> 0x%p\n", si1.hStdOutput, si2.hStdOutput);
        changed = TRUE;
    }
    
    if (si1.hStdError != si2.hStdError) {
        printf("hStdError发生变化: 0x%p -> 0x%p\n", si1.hStdError, si2.hStdError);
        changed = TRUE;
    }
    
    if (changed) {
        printf("检测到STARTUPINFO字段变化，可能是调试器活动。\n");
        return TRUE;
    }
    
    return FALSE;
}
```

### 4.3 反调试实现

```cpp
// 简单的StartupInfo反调试
VOID SimpleStartupInfoAntiDebug() {
    if (DetectDebuggerViaStartupInfo() || 
        ImprovedStartupInfoDetection() ||
        DeepStartupInfoAnalysis()) {
        printf("通过StartupInfo检测到调试器存在！程序即将退出。\n");
        ExitProcess(1);
    }
}

// 多层次StartupInfo检测
BOOL MultiLayerStartupInfoDetection() {
    // 第一层：基础检测
    if (DetectDebuggerViaStartupInfo()) {
        return TRUE;
    }
    
    // 第二层：改进检测
    if (ImprovedStartupInfoDetection()) {
        return TRUE;
    }
    
    // 第三层：深度分析
    if (DeepStartupInfoAnalysis()) {
        return TRUE;
    }
    
    // 第四层：时间序列比较
    if (CompareStartupInfoOverTime()) {
        return TRUE;
    }
    
    return FALSE;
}

// 增强版反调试
VOID EnhancedStartupInfoAntiDebug() {
    // 多次检测
    for (int i = 0; i < 3; i++) {
        if (MultiLayerStartupInfoDetection()) {
            printf("第%d次StartupInfo检测发现调试环境！\n", i + 1);
            
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
    
    printf("StartupInfo反调试检测通过。\n");
}
```

### 4.4 绕过StartupInfo检测的方法

```cpp
// StartupInfo检测绕过技术
class StartupInfoObfuscator {
public:
    // 修改STARTUPINFO结构
    static BOOL ModifyStartupInfo() {
        printf("修改STARTUPINFO结构...\n");
        
        // 实际上，程序运行后无法修改自己的STARTUPINFO
        // 但可以通过一些技巧来规避检测
        
        return FALSE;
    }
    
    // 模拟正常的STARTUPINFO值
    static VOID SimulateNormalStartupInfo() {
        printf("模拟正常的STARTUPINFO值...\n");
        
        // 在调试器中设置符合正常程序的STARTUPINFO值
    }
    
    // 干扰STARTUPINFO相关API
    static BOOL InterfereWithStartupInfoAPI() {
        printf("干扰STARTUPINFO相关API...\n");
        
        // 可以通过Hook GetStartupInfo API来返回伪造的数据
        
        return FALSE;
    }
};

// 综合绕过方法
VOID ComprehensiveStartupInfoBypass() {
    // 修改STARTUPINFO结构
    StartupInfoObfuscator::ModifyStartupInfo();
    
    // 模拟正常的STARTUPINFO值
    StartupInfoObfuscator::SimulateNormalStartupInfo();
    
    // 干扰相关API
    StartupInfoObfuscator::InterfereWithStartupInfoAPI();
    
    printf("StartupInfo检测绕过完成。\n");
}
```

### 4.5 完整测试程序

```cpp
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// 前面实现的函数声明
BOOL DetectDebuggerViaStartupInfo();
BOOL ImprovedStartupInfoDetection();
BOOL DeepStartupInfoAnalysis();
BOOL CompareStartupInfoOverTime();
BOOL MultiLayerStartupInfoDetection();

// 显示完整的STARTUPINFO信息
VOID DisplayFullStartupInfo() {
    printf("=== 完整STARTUPINFO信息 ===\n");
    
    STARTUPINFO si;
    si.cb = sizeof(si);
    GetStartupInfo(&si);
    
    printf("STARTUPINFO结构详情:\n");
    printf("  cb: %lu (期望: %zu)\n", si.cb, sizeof(STARTUPINFO));
    printf("  lpReserved: 0x%p\n", si.lpReserved);
    printf("  lpDesktop: 0x%p", si.lpDesktop);
    if (si.lpDesktop != NULL) {
        printf(" (%ws)", si.lpDesktop);
    }
    printf("\n");
    printf("  lpTitle: 0x%p", si.lpTitle);
    if (si.lpTitle != NULL) {
        printf(" (%ws)", si.lpTitle);
    }
    printf("\n");
    printf("  dwX: %lu\n", si.dwX);
    printf("  dwY: %lu\n", si.dwY);
    printf("  dwXSize: %lu\n", si.dwXSize);
    printf("  dwYSize: %lu\n", si.dwYSize);
    printf("  dwXCountChars: %lu\n", si.dwXCountChars);
    printf("  dwYCountChars: %lu\n", si.dwYCountChars);
    printf("  dwFillAttribute: 0x%08X\n", si.dwFillAttribute);
    printf("  dwFlags: 0x%08X\n", si.dwFlags);
    printf("  wShowWindow: %u\n", si.wShowWindow);
    printf("  cbReserved2: %u\n", si.cbReserved2);
    printf("  lpReserved2: 0x%p\n", si.lpReserved2);
    printf("  hStdInput: 0x%p\n", si.hStdInput);
    printf("  hStdOutput: 0x%p\n", si.hStdOutput);
    printf("  hStdError: 0x%p\n", si.hStdError);
    
    // 解析dwFlags
    printf("  dwFlags解析:\n");
    if (si.dwFlags & STARTF_USESHOWWINDOW) printf("    STARTF_USESHOWWINDOW\n");
    if (si.dwFlags & STARTF_USESIZE) printf("    STARTF_USESIZE\n");
    if (si.dwFlags & STARTF_USEPOSITION) printf("    STARTF_USEPOSITION\n");
    if (si.dwFlags & STARTF_USECOUNTCHARS) printf("    STARTF_USECOUNTCHARS\n");
    if (si.dwFlags & STARTF_USEFILLATTRIBUTE) printf("    STARTF_USEFILLATTRIBUTE\n");
    if (si.dwFlags & STARTF_RUNFULLSCREEN) printf("    STARTF_RUNFULLSCREEN\n");
    if (si.dwFlags & STARTF_FORCEONFEEDBACK) printf("    STARTF_FORCEONFEEDBACK\n");
    if (si.dwFlags & STARTF_FORCEOFFFEEDBACK) printf("    STARTF_FORCEOFFFEEDBACK\n");
    if (si.dwFlags & STARTF_USESTDHANDLES) printf("    STARTF_USESTDHANDLES\n");
    if (si.dwFlags & STARTF_USEHOTKEY) printf("    STARTF_USEHOTKEY\n");
    
    printf("\n");
}

// 性能测试
VOID PerformanceTest() {
    const int iterations = 10;
    
    printf("=== 性能测试 (%d次调用) ===\n", iterations);
    
    // 测试基础StartupInfo检测
    DWORD start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        DetectDebuggerViaStartupInfo();
        Sleep(50);
    }
    DWORD basicTime = GetTickCount() - start;
    
    // 测试改进版检测
    start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        ImprovedStartupInfoDetection();
        Sleep(50);
    }
    DWORD improvedTime = GetTickCount() - start;
    
    // 测试深度分析
    start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        DeepStartupInfoAnalysis();
        Sleep(50);
    }
    DWORD deepTime = GetTickCount() - start;
    
    printf("基础StartupInfo检测耗时: %lu ms\n", basicTime);
    printf("改进版StartupInfo检测耗时: %lu ms\n", improvedTime);
    printf("深度StartupInfo分析耗时: %lu ms\n", deepTime);
    
    printf("\n");
}

// 主程序
int main() {
    srand((unsigned int)time(NULL));
    
    printf("通过StartupInfo检测调试器演示程序\n");
    printf("================================\n\n");
    
    // 显示完整的STARTUPINFO信息
    DisplayFullStartupInfo();
    
    // 基础StartupInfo检测
    DetectDebuggerViaStartupInfo();
    
    // 改进版检测
    ImprovedStartupInfoDetection();
    
    // 深度分析
    DeepStartupInfoAnalysis();
    
    // 时间序列比较
    CompareStartupInfoOverTime();
    
    // 性能测试
    PerformanceTest();
    
    // 实际应用示例
    printf("=== 反调试检测 ===\n");
    if (MultiLayerStartupInfoDetection()) {
        printf("检测到调试环境，执行反调试措施。\n");
        
        // 这里可以执行各种反调试措施
        // 为演示目的，我们只是显示信息而不真正退出
        printf("（演示模式：不实际退出程序）\n");
    } else {
        printf("未检测到调试环境，程序正常运行。\n");
        MessageBoxW(NULL, L"StartupInfo检测通过，程序正常运行", L"提示", MB_OK);
    }
    
    // 演示绕过方法
    printf("\n=== 绕过演示 ===\n");
    printf("执行StartupInfo绕过...\n");
    // ComprehensiveStartupInfoBypass();  // 注释掉以避免实际修改
    
    printf("绕过完成后再次检测：\n");
    if (MultiLayerStartupInfoDetection()) {
        printf("仍然检测到调试环境。\n");
    } else {
        printf("检测结果显示未发现StartupInfo异常。\n");
    }
    
    return 0;
}
```

### 4.6 高级技巧和注意事项

```cpp
// 抗干扰版本（防止简单的Hook）
BOOL AntiTamperStartupInfoDetection() {
    // 多次调用并验证
    BOOL results[3];
    
    for (int i = 0; i < 3; i++) {
        results[i] = MultiLayerStartupInfoDetection();
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

// 综合检测函数
BOOL ComprehensiveStartupInfoDetectionEnhanced() {
    // 抗干扰检测
    if (AntiTamperStartupInfoDetection()) {
        return TRUE;
    }
    
    // 多层检测
    if (MultiLayerStartupInfoDetection()) {
        return TRUE;
    }
    
    return FALSE;
}

// 动态获取StartupInfo API地址（避免静态导入）
FARPROC GetDynamicStartupInfoAPIAddress(LPCSTR functionName) {
    // 动态加载kernel32.dll
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    if (hKernel32 == NULL) {
        return NULL;
    }
    
    // 获取函数地址
    FARPROC pfn = GetProcAddress(hKernel32, functionName);
    
    return pfn;
}

// 检查StartupInfo API调用的完整性
BOOL ValidateStartupInfoAPICall() {
    // 可以通过检查相关函数代码的完整性来验证未被修改
    // 这需要更高级的技术，如代码校验和检查
    
    return TRUE;
}

// 多线程环境下的StartupInfo检测
BOOL MultiThreadStartupInfoDetection() {
    printf("=== 多线程StartupInfo检测 ===\n");
    
    // 在多线程环境中进行检测可以增加检测的可靠性
    
    return FALSE;
}

// 基于历史数据的StartupInfo检测
BOOL HistoricalStartupInfoDetection() {
    printf("=== 历史数据StartupInfo检测 ===\n");
    
    // 保存历史STARTUPINFO数据并进行比较分析
    
    return FALSE;
}
```

## 五、课后作业

1. **基础练习**：
   - 在不同调试器下测试STARTUPINFO结构的差异
   - 研究正常程序启动时STARTUPINFO的典型值
   - 实现对STARTUPINFO字段的完整验证

2. **进阶练习**：
   - 实现一个完整的STARTUPINFO行为监控器
   - 研究如何通过API Hook绕过STARTUPINFO检测
   - 设计一个多层检测机制，结合STARTUPINFO和其他反调试技术

3. **思考题**：
   - STARTUPINFO检测方法有哪些明显的局限性？
   - 如何提高STARTUPINFO检测的准确性和隐蔽性？
   - 现代调试器采用了哪些技术来对抗STARTUPINFO检测？

4. **扩展阅读**：
   - 研究Windows进程启动机制的内部实现
   - 了解STARTUPINFO结构的详细定义和用途
   - 学习现代反反调试技术