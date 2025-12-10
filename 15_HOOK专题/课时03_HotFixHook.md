# 课时03 HotFix Hook

## 一、课程目标

本节课主要学习HotFix Hook技术，这是一种常用于游戏外挂和软件破解的技术。通过本课的学习，你将能够：

1. 理解HotFix Hook的基本概念和应用场景
2. 掌握通过修改内存中的函数代码来实现热修补的方法
3. 实现动态补丁加载和应用机制
4. 理解HotFix Hook在游戏外挂中的典型应用
5. 学习HotFix Hook的检测和防护方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| HotFix | 热修补，无需重启程序即可应用的修复补丁 |
| Patch | 补丁，用于修复或修改程序功能的小段代码 |
| CRC校验 | 循环冗余校验，用于检测数据完整性的算法 |
| 特征码 | 程序中唯一标识某段代码或数据的字节序列 |
| 动态补丁 | 运行时加载并应用的补丁程序 |
| 内存扫描 | 在程序运行时搜索特定特征码的过程 |

## 三、技术原理

### 3.1 HotFix Hook概述

HotFix Hook是一种在程序运行时动态修改其内存中的代码来实现功能变更或修复的技术。它不需要重新启动程序就能立即生效，因此被称为"热修补"。

HotFix Hook广泛应用于：
1. 游戏外挂制作
2. 软件破解
3. Bug修复
4. 功能增强

### 3.2 实现原理

HotFix Hook的实现主要包括以下几个步骤：

1. **特征码定位**：在目标程序中搜索特定的字节序列来定位需要修改的代码位置
2. **内存修改**：修改目标位置的机器码来改变程序行为
3. **补丁管理**：管理和维护多个补丁的状态
4. **回滚机制**：提供撤销补丁的功能

### 3.3 特征码搜索技术

特征码是一段能够唯一标识目标代码位置的字节序列。在编写HotFix补丁时，我们需要：

1. **选择稳定特征码**：选择不容易随版本更新而变化的代码片段
2. **避免通配符过多**：过多的通配符会降低匹配精度
3. **确保唯一性**：特征码在整个程序中应该是唯一的

## 四、代码实现

### 4.1 核心数据结构

```cpp
// 补丁信息结构体
typedef struct _PATCH_INFO {
    CHAR	szName[64];				// 补丁名称
    PBYTE	pSignature;				// 特征码
    INT		nSigLen;				// 特征码长度
    PBYTE	pPatchData;				// 补丁数据
    INT		nPatchLen;				// 补丁数据长度
    DWORD	dwOffset;				// 偏移量
    PVOID	pAddress;				// 匹配到的地址
    BYTE	oriBytes[256];			// 原始字节备份
    BOOL	bApplied;				// 是否已应用
    BOOL	bEnabled;				// 是否启用
} PATCH_INFO, * PPATCH_INFO;

// HotFix管理器
typedef struct _HOTFIX_MANAGER {
    PATCH_INFO*	pPatches;			// 补丁数组
    INT			nPatchCount;		// 补丁数量
    HANDLE		hProcess;			// 目标进程句柄
} HOTFIX_MANAGER, * PHOTFIX_MANAGER;
```

### 4.2 特征码搜索实现

```cpp
#include <windows.h>
#include <stdio.h>
#include <vector>

// 特征码匹配函数（支持通配符）
BOOL PatternMatch(PBYTE pData, PBYTE pSignature, INT sigLen) {
    for (INT i = 0; i < sigLen; i++) {
        // 0x00 作为通配符
        if (pSignature[i] != 0x00 && pData[i] != pSignature[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

// 在内存中搜索特征码
PVOID FindPattern(PVOID pStartAddr, SIZE_T searchSize, PBYTE pSignature, INT sigLen) {
    PBYTE pCurrent = (PBYTE)pStartAddr;
    SIZE_T remaining = searchSize;
    
    while (remaining >= sigLen) {
        if (PatternMatch(pCurrent, pSignature, sigLen)) {
            return pCurrent;
        }
        pCurrent++;
        remaining--;
    }
    
    return NULL;
}

// 获取模块基址和大小
BOOL GetModuleInfo(LPCSTR moduleName, PVOID* pBaseAddr, SIZE_T* pSize) {
    HMODULE hModule = GetModuleHandleA(moduleName);
    if (!hModule) {
        return FALSE;
    }
    
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        return FALSE;
    }
    
    *pBaseAddr = modInfo.lpBaseOfDll;
    *pSize = modInfo.SizeOfImage;
    return TRUE;
}
```

### 4.3 HotFix Hook核心实现

```cpp
// 初始化HotFix管理器
PHOTFIX_MANAGER InitHotFixManager() {
    PHOTFIX_MANAGER pManager = (PHOTFIX_MANAGER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HOTFIX_MANAGER));
    if (!pManager) {
        return NULL;
    }
    
    pManager->hProcess = GetCurrentProcess();
    return pManager;
}

// 添加补丁
BOOL AddPatch(PHOTFIX_MANAGER pManager, LPCSTR patchName, PBYTE pSignature, INT sigLen, 
              PBYTE pPatchData, INT patchLen, DWORD offset) {
    // 重新分配内存
    PPATCH_INFO pNewPatches = (PPATCH_INFO)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
        pManager->pPatches, sizeof(PATCH_INFO) * (pManager->nPatchCount + 1));
    if (!pNewPatches) {
        return FALSE;
    }
    
    pManager->pPatches = pNewPatches;
    
    // 填充补丁信息
    PPATCH_INFO pPatch = &pManager->pPatches[pManager->nPatchCount];
    strcpy_s(pPatch->szName, sizeof(pPatch->szName), patchName);
    pPatch->pSignature = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sigLen);
    pPatch->pPatchData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, patchLen);
    
    if (!pPatch->pSignature || !pPatch->pPatchData) {
        return FALSE;
    }
    
    memcpy(pPatch->pSignature, pSignature, sigLen);
    memcpy(pPatch->pPatchData, pPatchData, patchLen);
    pPatch->nSigLen = sigLen;
    pPatch->nPatchLen = patchLen;
    pPatch->dwOffset = offset;
    pPatch->bApplied = FALSE;
    pPatch->bEnabled = TRUE;
    
    pManager->nPatchCount++;
    return TRUE;
}

// 应用所有补丁
BOOL ApplyAllPatches(PHOTFIX_MANAGER pManager) {
    // 获取主模块信息
    PVOID baseAddr;
    SIZE_T moduleSize;
    if (!GetModuleInfo(NULL, &baseAddr, &moduleSize)) {
        return FALSE;
    }
    
    BOOL bSuccess = TRUE;
    
    // 遍历所有补丁
    for (INT i = 0; i < pManager->nPatchCount; i++) {
        PPATCH_INFO pPatch = &pManager->pPatches[i];
        
        // 如果补丁未启用，则跳过
        if (!pPatch->bEnabled) {
            continue;
        }
        
        // 查找特征码
        pPatch->pAddress = FindPattern(baseAddr, moduleSize, pPatch->pSignature, pPatch->nSigLen);
        if (!pPatch->pAddress) {
            printf("Failed to find signature for patch: %s\n", pPatch->szName);
            bSuccess = FALSE;
            continue;
        }
        
        // 计算实际修改地址
        PVOID targetAddr = (PBYTE)pPatch->pAddress + pPatch->dwOffset;
        
        // 备份原始字节
        DWORD oldProtect;
        if (!VirtualProtect(targetAddr, pPatch->nPatchLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            printf("Failed to change memory protection for patch: %s\n", pPatch->szName);
            bSuccess = FALSE;
            continue;
        }
        
        memcpy(pPatch->oriBytes, targetAddr, pPatch->nPatchLen);
        
        // 应用补丁
        memcpy(targetAddr, pPatch->pPatchData, pPatch->nPatchLen);
        
        // 恢复内存保护属性
        VirtualProtect(targetAddr, pPatch->nPatchLen, oldProtect, &oldProtect);
        
        pPatch->bApplied = TRUE;
        printf("Patch applied successfully: %s\n", pPatch->szName);
    }
    
    return bSuccess;
}

// 卸载补丁
BOOL UnapplyPatch(PHOTFIX_MANAGER pManager, INT patchIndex) {
    if (patchIndex < 0 || patchIndex >= pManager->nPatchCount) {
        return FALSE;
    }
    
    PPATCH_INFO pPatch = &pManager->pPatches[patchIndex];
    if (!pPatch->bApplied) {
        return TRUE;  // 已经卸载或未应用
    }
    
    PVOID targetAddr = (PBYTE)pPatch->pAddress + pPatch->dwOffset;
    
    // 修改内存保护属性
    DWORD oldProtect;
    if (!VirtualProtect(targetAddr, pPatch->nPatchLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    // 恢复原始字节
    memcpy(targetAddr, pPatch->oriBytes, pPatch->nPatchLen);
    
    // 恢复内存保护属性
    VirtualProtect(targetAddr, pPatch->nPatchLen, oldProtect, &oldProtect);
    
    pPatch->bApplied = FALSE;
    return TRUE;
}

// 清理HotFix管理器
VOID CleanupHotFixManager(PHOTFIX_MANAGER pManager) {
    if (!pManager) {
        return;
    }
    
    // 释放所有补丁资源
    for (INT i = 0; i < pManager->nPatchCount; i++) {
        PPATCH_INFO pPatch = &pManager->pPatches[i];
        if (pPatch->pSignature) {
            HeapFree(GetProcessHeap(), 0, pPatch->pSignature);
        }
        if (pPatch->pPatchData) {
            HeapFree(GetProcessHeap(), 0, pPatch->pPatchData);
        }
    }
    
    if (pManager->pPatches) {
        HeapFree(GetProcessHeap(), 0, pManager->pPatches);
    }
    
    HeapFree(GetProcessHeap(), 0, pManager);
}
```

### 4.4 示例应用

```cpp
// 示例：创建一个简单的HotFix补丁
VOID DemoHotFixHook() {
    // 初始化HotFix管理器
    PHOTFIX_MANAGER pManager = InitHotFixManager();
    if (!pManager) {
        printf("Failed to initialize HotFix manager.\n");
        return;
    }
    
    // 示例补丁1：禁用某个检查函数
    // 假设我们要Hook的函数特征码是：8B 45 08 83 F8 01 74 05
    BYTE sig1[] = { 0x8B, 0x45, 0x08, 0x83, 0xF8, 0x01, 0x74, 0x05 };
    // 补丁数据：将条件跳转变为无条件跳转
    BYTE patch1[] = { 0x8B, 0x45, 0x08, 0x83, 0xF8, 0x01, 0xEB, 0x05 };  // EB = JMP
    
    if (AddPatch(pManager, "DisableCheck", sig1, sizeof(sig1), patch1, sizeof(patch1), 0)) {
        printf("Patch 'DisableCheck' added successfully.\n");
    }
    
    // 示例补丁2：修改数值比较
    // 假设我们要修改的特征码是：83 FF 64 7C 0A
    BYTE sig2[] = { 0x83, 0xFF, 0x64, 0x7C, 0x0A };
    // 补丁数据：将比较值从100改为200
    BYTE patch2[] = { 0x83, 0xFF, 0xC8, 0x7C, 0x0A };  // 0xC8 = 200
    
    if (AddPatch(pManager, "IncreaseLimit", sig2, sizeof(sig2), patch2, sizeof(patch2), 0)) {
        printf("Patch 'IncreaseLimit' added successfully.\n");
    }
    
    // 应用所有补丁
    if (ApplyAllPatches(pManager)) {
        printf("All patches applied successfully.\n");
    }
    else {
        printf("Some patches failed to apply.\n");
    }
    
    // 这里可以进行测试...
    
    // 清理资源
    CleanupHotFixManager(pManager);
}
```

### 4.5 补丁管理器增强版

```cpp
// 补丁状态枚举
typedef enum _PATCH_STATUS {
    PATCH_STATUS_UNKNOWN = 0,
    PATCH_STATUS_NOT_FOUND,      // 未找到特征码
    PATCH_STATUS_APPLIED,        // 已应用
    PATCH_STATUS_FAILED,         // 应用失败
    PATCH_STATUS_REMOVED         // 已移除
} PATCH_STATUS;

// 增强的补丁信息结构
typedef struct _ADVANCED_PATCH_INFO {
    CHAR		szName[64];				// 补丁名称
    CHAR		szDescription[256];		// 描述
    PBYTE		pSignature;				// 特征码
    INT			nSigLen;				// 特征码长度
    PBYTE		pMask;					// 掩码（用于更灵活的特征码匹配）
    PBYTE		pPatchData;				// 补丁数据
    INT			nPatchLen;				// 补丁数据长度
    DWORD		dwOffset;				// 偏移量
    PVOID		pAddress;				// 匹配到的地址
    BYTE		oriBytes[256];			// 原始字节备份
    PATCH_STATUS status;				// 补丁状态
    DWORD		dwCRC32;				// 补丁CRC32校验值
    SYSTEMTIME	applyTime;				// 应用时间
} ADVANCED_PATCH_INFO, * PADVANCED_PATCH_INFO;

// 带掩码的特征码匹配
BOOL PatternMatchWithMask(PBYTE pData, PBYTE pSignature, PBYTE pMask, INT sigLen) {
    for (INT i = 0; i < sigLen; i++) {
        // 如果掩码为0xFF，则需要完全匹配；否则忽略该字节
        if (pMask[i] == 0xFF && pData[i] != pSignature[i]) {
            return FALSE;
        }
    }
    return TRUE;
}
```

## 五、课后作业

1. **基础练习**：
   - 编写一个程序，使用HotFix Hook技术修改计算器程序中的加法运算结果
   - 实现一个简单的特征码生成工具，可以从二进制文件中提取特征码

2. **进阶练习**：
   - 实现支持掩码的特征码匹配功能，使特征码更加灵活
   - 添加补丁的CRC32校验功能，防止补丁被篡改
   - 实现补丁的导入导出功能，支持补丁文件的持久化存储

3. **思考题**：
   - HotFix Hook技术在软件安全领域有哪些正面和负面的应用？
   - 如何有效检测和防范HotFix Hook攻击？
   - 现代操作系统提供了哪些机制来阻止这种类型的内存修改？

4. **扩展阅读**：
   - 研究游戏反作弊系统如何检测HotFix Hook
   - 了解Windows Code Integrity机制如何防止未签名代码执行
   - 学习基于硬件的内存保护技术（如Intel MPX）