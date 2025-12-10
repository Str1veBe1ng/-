# 课时01 通过Mac地址检测虚拟机

## 一、课程目标

本节课主要学习如何通过检查网络适配器的MAC地址来检测虚拟机环境。虚拟机软件在创建虚拟网络适配器时通常会使用特定的OUI（Organizationally Unique Identifier）标识符，通过识别这些特征可以判断程序是否运行在虚拟机中。通过本课的学习，你将能够：

1. 理解MAC地址的结构和组织唯一标识符(OUI)的概念
2. 掌握获取系统网络适配器MAC地址的方法
3. 学会识别虚拟机软件特有的MAC地址特征
4. 实现基于MAC地址的虚拟机检测代码
5. 了解该技术的局限性和绕过方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| MAC地址 | Media Access Control Address，网络设备的物理地址 |
| OUI | Organizationally Unique Identifier，组织唯一标识符 |
| NIC | Network Interface Card，网络接口卡 |
| 虚拟机检测 | 识别程序是否运行在虚拟化环境中的技术 |
| GetAdaptersInfo | Windows API函数，用于获取网络适配器信息 |
| GetAdaptersAddresses | Windows API函数，用于获取网络适配器地址信息 |
| 虚拟化环境 | 通过软件模拟硬件环境的系统，如VMware、VirtualBox等 |

## 三、技术原理

### 3.1 MAC地址概述

MAC（Media Access Control）地址是网络设备的唯一标识符，由48位（6字节）组成，通常表示为12个十六进制数字，格式为XX-XX-XX-XX-XX-XX。

MAC地址分为两部分：
1. **OUI（前24位）**：由IEEE分配给设备制造商的唯一标识符
2. **厂商特定部分（后24位）**：由制造商自行分配的设备标识符

### 3.2 虚拟机MAC地址特征

常见的虚拟机软件使用的OUI标识符：

1. **VMware**：00-05-69、00-0C-29、00-1C-14、00-50-56
2. **VirtualBox**：08-00-27
3. **Hyper-V**：00-15-5D
4. **Parallels**：00-1C-42
5. **Xen**：00-16-3E

### 3.3 检测原理

通过枚举系统中的所有网络适配器，获取它们的MAC地址，并检查这些地址的OUI部分是否匹配已知的虚拟机软件标识符。

## 四、代码实现

### 4.1 基础MAC地址检测

```cpp
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <vector>

#pragma comment(lib, "IPHLPAPI.lib")

// 虚拟机OUI列表
struct VMOUI {
    BYTE oui[3];
    const char* vendor;
};

VMOUI g_vmOUIs[] = {
    {{0x00, 0x05, 0x69}, "VMware"},
    {{0x00, 0x0C, 0x29}, "VMware"},
    {{0x00, 0x1C, 0x14}, "VMware"},
    {{0x00, 0x50, 0x56}, "VMware"},
    {{0x08, 0x00, 0x27}, "VirtualBox"},
    {{0x00, 0x15, 0x5D}, "Hyper-V"},
    {{0x00, 0x1C, 0x42}, "Parallels"},
    {{0x00, 0x16, 0x3E}, "Xen"}
};

// 检查MAC地址是否属于虚拟机
BOOL IsVirtualMachineMAC(BYTE mac[6]) {
    printf("检查MAC地址: %02X-%02X-%02X-%02X-%02X-%02X\n",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    // 检查是否为全零地址
    if (mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && 
        mac[3] == 0 && mac[4] == 0 && mac[5] == 0) {
        printf("检测到全零MAC地址，可能是虚拟机。\n");
        return TRUE;
    }
    
    // 检查是否为广播地址
    if (mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF && 
        mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF) {
        printf("检测到广播MAC地址。\n");
        return FALSE;
    }
    
    // 检查OUI是否匹配虚拟机特征
    for (int i = 0; i < sizeof(g_vmOUIs) / sizeof(g_vmOUIs[0]); i++) {
        if (mac[0] == g_vmOUIs[i].oui[0] && 
            mac[1] == g_vmOUIs[i].oui[1] && 
            mac[2] == g_vmOUIs[i].oui[2]) {
            printf("检测到%s虚拟机MAC地址特征。\n", g_vmOUIs[i].vendor);
            return TRUE;
        }
    }
    
    return FALSE;
}

// 基础MAC地址检测
BOOL DetectVMViaMACAddress() {
    printf("=== 基础MAC地址检测 ===\n");
    
    // 使用GetAdaptersInfo获取网络适配器信息
    PIP_ADAPTER_INFO pAdapterInfo = NULL;
    ULONG ulOutBufLen = 0;
    
    // 第一次调用获取所需缓冲区大小
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_BUFFER_OVERFLOW) {
        printf("无法获取适配器信息大小。\n");
        return FALSE;
    }
    
    // 分配内存
    pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    if (pAdapterInfo == NULL) {
        printf("内存分配失败。\n");
        return FALSE;
    }
    
    // 第二次调用获取适配器信息
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) != ERROR_SUCCESS) {
        printf("获取适配器信息失败。\n");
        free(pAdapterInfo);
        return FALSE;
    }
    
    BOOL vmDetected = FALSE;
    
    // 遍历所有适配器
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter) {
        printf("适配器名称: %s\n", pAdapter->AdapterName);
        printf("描述: %s\n", pAdapter->Description);
        printf("地址长度: %d\n", pAdapter->AddressLength);
        
        // 检查MAC地址长度
        if (pAdapter->AddressLength == 6) {
            if (IsVirtualMachineMAC(pAdapter->Address)) {
                vmDetected = TRUE;
            }
        } else {
            printf("MAC地址长度不正确: %d\n", pAdapter->AddressLength);
        }
        
        printf("\n");
        pAdapter = pAdapter->Next;
    }
    
    free(pAdapterInfo);
    return vmDetected;
}
```

### 4.2 改进的MAC地址检测

```cpp
// 使用GetAdaptersAddresses的改进版本
BOOL ImprovedVMMACDetection() {
    printf("=== 改进版MAC地址检测 ===\n");
    
    // 使用GetAdaptersAddresses获取更详细的网络适配器信息
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG ulOutBufLen = 0;
    
    // 第一次调用获取所需缓冲区大小
    DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 
                                         GAA_FLAG_INCLUDE_PREFIX, 
                                         NULL, 
                                         pAddresses, 
                                         &ulOutBufLen);
    
    if (dwRetVal != ERROR_BUFFER_OVERFLOW) {
        printf("无法获取适配器地址大小。\n");
        return FALSE;
    }
    
    // 分配内存
    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(ulOutBufLen);
    if (pAddresses == NULL) {
        printf("内存分配失败。\n");
        return FALSE;
    }
    
    // 第二次调用获取适配器地址信息
    dwRetVal = GetAdaptersAddresses(AF_UNSPEC, 
                                   GAA_FLAG_INCLUDE_PREFIX, 
                                   NULL, 
                                   pAddresses, 
                                   &ulOutBufLen);
    
    if (dwRetVal != ERROR_SUCCESS) {
        printf("获取适配器地址信息失败。\n");
        free(pAddresses);
        return FALSE;
    }
    
    BOOL vmDetected = FALSE;
    
    // 遍历所有适配器
    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    while (pCurrAddresses) {
        printf("适配器名称: %ws\n", pCurrAddresses->FriendlyName);
        printf("描述: %ws\n", pCurrAddresses->Description);
        
        // 检查物理地址
        if (pCurrAddresses->PhysicalAddressLength == 6) {
            BYTE mac[6];
            memcpy(mac, pCurrAddresses->PhysicalAddress, 6);
            
            printf("MAC地址: %02X-%02X-%02X-%02X-%02X-%02X\n",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            
            if (IsVirtualMachineMAC(mac)) {
                vmDetected = TRUE;
            }
        } else {
            printf("物理地址长度不正确: %d\n", pCurrAddresses->PhysicalAddressLength);
        }
        
        // 检查适配器类型
        switch (pCurrAddresses->IfType) {
        case IF_TYPE_SOFTWARE_LOOPBACK:
            printf("适配器类型: 回环适配器\n");
            break;
        case IF_TYPE_ETHERNET_CSMACD:
            printf("适配器类型: 以太网适配器\n");
            break;
        default:
            printf("适配器类型: %lu\n", pCurrAddresses->IfType);
            break;
        }
        
        printf("操作状态: %lu\n", pCurrAddresses->OperStatus);
        printf("\n");
        
        pCurrAddresses = pCurrAddresses->Next;
    }
    
    free(pAddresses);
    return vmDetected;
}

// 获取所有MAC地址
std::vector<std::vector<BYTE>> GetAllMACAddresses() {
    std::vector<std::vector<BYTE>> macAddresses;
    
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG ulOutBufLen = 0;
    
    // 获取适配器地址信息
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(ulOutBufLen);
        if (pAddresses != NULL) {
            if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &ulOutBufLen) == ERROR_SUCCESS) {
                PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
                while (pCurrAddresses) {
                    if (pCurrAddresses->PhysicalAddressLength == 6) {
                        std::vector<BYTE> mac(6);
                        memcpy(&mac[0], pCurrAddresses->PhysicalAddress, 6);
                        macAddresses.push_back(mac);
                    }
                    pCurrAddresses = pCurrAddresses->Next;
                }
            }
            free(pAddresses);
        }
    }
    
    return macAddresses;
}
```

### 4.3 高级MAC地址检测技术

```cpp
// 检查MAC地址的统计特征
BOOL AnalyzeMACStatistics() {
    printf("=== MAC地址统计分析 ===\n");
    
    auto macAddresses = GetAllMACAddresses();
    
    if (macAddresses.empty()) {
        printf("未找到有效的MAC地址。\n");
        return FALSE;
    }
    
    printf("找到 %zu 个网络适配器。\n", macAddresses.size());
    
    int vmCount = 0;
    for (const auto& mac : macAddresses) {
        if (IsVirtualMachineMAC(const_cast<BYTE*>(mac.data()))) {
            vmCount++;
        }
    }
    
    // 如果大部分适配器都是虚拟机特征，则很可能是虚拟机环境
    if (vmCount > 0 && vmCount == macAddresses.size()) {
        printf("所有网络适配器都具有虚拟机特征。\n");
        return TRUE;
    }
    
    if (vmCount > 0) {
        printf("发现 %d 个具有虚拟机特征的适配器。\n", vmCount);
        return TRUE;
    }
    
    return FALSE;
}

// 检查MAC地址的熵值
double CalculateMACEntropy(const BYTE mac[6]) {
    // 计算MAC地址的熵值，用于检测是否为随机生成的地址
    int frequency[256] = {0};
    
    for (int i = 0; i < 6; i++) {
        frequency[mac[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            double p = (double)frequency[i] / 6.0;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

// 检查MAC地址熵值异常
BOOL CheckMACAddressEntropy() {
    printf("=== MAC地址熵值检查 ===\n");
    
    auto macAddresses = GetAllMACAddresses();
    
    for (const auto& mac : macAddresses) {
        double entropy = CalculateMACEntropy(mac.data());
        printf("MAC地址熵值: %.2f\n", entropy);
        
        // 正常的MAC地址熵值通常在1.5-2.5之间
        // 如果熵值过高，可能是随机生成的虚拟机地址
        if (entropy > 3.0) {
            printf("检测到异常高熵值MAC地址，可能是虚拟机。\n");
            return TRUE;
        }
    }
    
    return FALSE;
}

// 综合MAC地址检测
BOOL ComprehensiveMACDetection() {
    printf("=== 综合MAC地址检测 ===\n");
    
    BOOL result1 = DetectVMViaMACAddress();
    BOOL result2 = ImprovedVMMACDetection();
    BOOL result3 = AnalyzeMACStatistics();
    BOOL result4 = CheckMACAddressEntropy();
    
    return result1 || result2 || result3 || result4;
}
```

### 4.4 反虚拟机实现

```cpp
// 简单的MAC地址反虚拟机检测
VOID SimpleMACAntiVM() {
    if (ComprehensiveMACDetection()) {
        printf("通过MAC地址检测到虚拟机环境！程序即将退出。\n");
        ExitProcess(1);
    }
}

// 多层次MAC地址检测
BOOL MultiLayerMACDetection() {
    // 第一层：基础检测
    if (DetectVMViaMACAddress()) {
        return TRUE;
    }
    
    // 第二层：改进检测
    if (ImprovedVMMACDetection()) {
        return TRUE;
    }
    
    // 第三层：统计分析
    if (AnalyzeMACStatistics()) {
        return TRUE;
    }
    
    // 第四层：熵值检查
    if (CheckMACAddressEntropy()) {
        return TRUE;
    }
    
    return FALSE;
}

// 增强版反虚拟机检测
VOID EnhancedMACAntiVM() {
    // 多次检测
    for (int i = 0; i < 3; i++) {
        if (MultiLayerMACDetection()) {
            printf("第%d次MAC地址检测发现虚拟机环境！\n", i + 1);
            
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
    
    printf("MAC地址反虚拟机检测通过。\n");
}
```

### 4.5 绕过MAC地址检测的方法

```cpp
// MAC地址检测绕过技术
class MACObfuscator {
public:
    // 修改网络适配器MAC地址
    static BOOL ChangeMACAddress() {
        printf("修改网络适配器MAC地址...\n");
        
        // 实际应用中需要管理员权限，并且可能被安全软件阻止
        // 这里仅作为概念演示
        
        return FALSE;
    }
    
    // 隐藏虚拟机特征的MAC地址
    static BOOL HideVMCharacteristics() {
        printf("隐藏虚拟机特征的MAC地址...\n");
        
        // 可以通过修改注册表或驱动程序来隐藏虚拟机特征
        
        return FALSE;
    }
    
    // 生成随机MAC地址
    static BOOL GenerateRandomMAC() {
        printf("生成随机MAC地址...\n");
        
        // 生成看起来像真实设备的MAC地址
        
        return FALSE;
    }
};

// 综合绕过方法
VOID ComprehensiveMACBypass() {
    // 修改MAC地址
    MACObfuscator::ChangeMACAddress();
    
    // 隐藏虚拟机特征
    MACObfuscator::HideVMCharacteristics();
    
    // 生成随机MAC地址
    MACObfuscator::GenerateRandomMAC();
    
    printf("MAC地址检测绕过完成。\n");
}
```

### 4.6 完整测试程序

```cpp
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <vector>
#include <cmath>

#pragma comment(lib, "IPHLPAPI.lib")

// 前面实现的函数声明
BOOL DetectVMViaMACAddress();
BOOL ImprovedVMMACDetection();
BOOL AnalyzeMACStatistics();
BOOL CheckMACAddressEntropy();
BOOL MultiLayerMACDetection();

// 显示网络适配器信息
VOID DisplayNetworkAdapterInfo() {
    printf("=== 网络适配器信息 ===\n");
    
    auto macAddresses = GetAllMACAddresses();
    
    printf("系统中共有 %zu 个网络适配器。\n", macAddresses.size());
    
    for (size_t i = 0; i < macAddresses.size(); i++) {
        const auto& mac = macAddresses[i];
        printf("适配器 %zu: %02X-%02X-%02X-%02X-%02X-%02X\n",
               i + 1, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    
    printf("\n");
}

// 性能测试
VOID PerformanceTest() {
    const int iterations = 5;
    
    printf("=== 性能测试 (%d次调用) ===\n", iterations);
    
    // 测试基础MAC地址检测
    DWORD start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        DetectVMViaMACAddress();
        Sleep(100);
    }
    DWORD basicTime = GetTickCount() - start;
    
    // 测试改进版检测
    start = GetTickCount();
    for (int i = 0; i < iterations; i++) {
        ImprovedVMMACDetection();
        Sleep(100);
    }
    DWORD improvedTime = GetTickCount() - start;
    
    printf("基础MAC地址检测耗时: %lu ms\n", basicTime);
    printf("改进版MAC地址检测耗时: %lu ms\n", improvedTime);
    
    printf("\n");
}

// 主程序
int main() {
    srand((unsigned int)time(NULL));
    
    printf("通过Mac地址检测虚拟机演示程序\n");
    printf("==========================\n\n");
    
    // 显示网络适配器信息
    DisplayNetworkAdapterInfo();
    
    // 基础MAC地址检测
    DetectVMViaMACAddress();
    
    // 改进版检测
    ImprovedVMMACDetection();
    
    // 统计分析
    AnalyzeMACStatistics();
    
    // 熵值检查
    CheckMACAddressEntropy();
    
    // 性能测试
    PerformanceTest();
    
    // 实际应用示例
    printf("=== 反虚拟机检测 ===\n");
    if (MultiLayerMACDetection()) {
        printf("检测到虚拟机环境，执行反虚拟机措施。\n");
        
        // 这里可以执行各种反虚拟机措施
        // 为演示目的，我们只是显示信息而不真正退出
        printf("（演示模式：不实际退出程序）\n");
    } else {
        printf("未检测到虚拟机环境，程序正常运行。\n");
        MessageBoxW(NULL, L"MAC地址检测通过，程序正常运行", L"提示", MB_OK);
    }
    
    // 演示绕过方法
    printf("\n=== 绕过演示 ===\n");
    printf("执行MAC地址绕过...\n");
    // ComprehensiveMACBypass();  // 注释掉以避免实际修改系统
    
    printf("绕过完成后再次检测：\n");
    if (MultiLayerMACDetection()) {
        printf("仍然检测到虚拟机环境。\n");
    } else {
        printf("检测结果显示未发现虚拟机异常。\n");
    }
    
    return 0;
}
```

### 4.7 高级技巧和注意事项

```cpp
// 抗干扰版本（防止简单的Hook）
BOOL AntiTamperMACDetection() {
    // 多次调用并验证
    BOOL results[3];
    
    for (int i = 0; i < 3; i++) {
        results[i] = MultiLayerMACDetection();
        Sleep(10);  // 简短延迟
    }
    
    // 检查结果一致性
    for (int i = 1; i < 3; i++) {
        if (results[i] != results[0]) {
            // 结果不一致，可能是被干扰了
            return TRUE;  // 假设存在虚拟机环境
        }
    }
    
    return results[0];
}

// 综合检测函数
BOOL ComprehensiveMACDetectionEnhanced() {
    // 抗干扰检测
    if (AntiTamperMACDetection()) {
        return TRUE;
    }
    
    // 多层检测
    if (MultiLayerMACDetection()) {
        return TRUE;
    }
    
    return FALSE;
}

// 动态获取网络API地址（避免静态导入）
FARPROC GetDynamicNetworkAPIAddress(LPCSTR functionName) {
    // 动态加载iphlpapi.dll
    HMODULE hIpHlpApi = GetModuleHandle(L"iphlpapi.dll");
    if (hIpHlpApi == NULL) {
        return NULL;
    }
    
    // 获取函数地址
    FARPROC pfn = GetProcAddress(hIpHlpApi, functionName);
    
    return pfn;
}

// 检查网络API调用的完整性
BOOL ValidateNetworkAPICall() {
    // 可以通过检查相关函数代码的完整性来验证未被修改
    // 这需要更高级的技术，如代码校验和检查
    
    return TRUE;
}

// 多线程环境下的MAC地址检测
BOOL MultiThreadMACDetection() {
    printf("=== 多线程MAC地址检测 ===\n");
    
    // 在多线程环境中进行检测可以增加检测的可靠性
    
    return FALSE;
}
```

## 五、课后作业

1. **基础练习**：
   - 在不同的虚拟机软件中测试MAC地址检测的准确性
   - 研究更多虚拟机软件的OUI标识符
   - 实现对MAC地址格式的完整验证

2. **进阶练习**：
   - 实现一个完整的MAC地址行为监控器
   - 研究如何通过API Hook绕过MAC地址检测
   - 设计一个多层检测机制，结合MAC地址和其他反虚拟机技术

3. **思考题**：
   - MAC地址检测方法有哪些明显的局限性？
   - 如何提高MAC地址检测的准确性和隐蔽性？
   - 现代虚拟机采用了哪些技术来对抗MAC地址检测？

4. **扩展阅读**：
   - 研究IEEE OUI数据库和MAC地址分配机制
   - 了解网络适配器虚拟化技术
   - 学习现代反虚拟机技术