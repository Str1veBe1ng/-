# 课时01 Inline Hook

## 一、课程目标

本节课主要学习Inline Hook技术，掌握其基本原理和实现方法。通过本课的学习，你将能够：

1. 理解Inline Hook的基本概念和工作原理
2. 掌握在x86架构下实现Inline Hook的方法
3. 学会在目标函数头部插入跳转指令来重定向执行流程
4. 实现一个简单的Inline Hook框架
5. 理解Inline Hook的应用场景及潜在风险

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| Hook | 钩子，一种用于拦截和修改系统或应用程序行为的技术 |
| Inline Hook | 内联钩子，直接修改目标函数机器码来实现函数拦截的技术 |
| JMP指令 | 跳转指令，在x86汇编中用于改变程序执行流程 |
| Trampoline | 蹦床，保存原始函数被覆盖部分代码以便恢复执行的技术 |
| 原始函数 | 被Hook的目标函数 |
| Hook函数 | 替代原始函数执行的自定义函数 |

## 三、技术原理

### 3.1 Inline Hook概述

Inline Hook是一种直接修改目标函数机器码的技术，通过在目标函数的开头插入跳转指令(JMP)，将程序执行流程重定向到我们自定义的函数中。当目标函数被调用时，会先执行我们的Hook函数，然后再决定是否继续执行原始函数。

### 3.2 实现原理

1. **备份原始指令**：保存目标函数开头被覆盖的字节，通常至少需要5个字节（x86下的JMP指令长度）
2. **构建Trampoline**：创建一个蹦床函数，用于恢复原始函数的执行
3. **安装Hook**：在目标函数开头写入JMP指令跳转到Hook函数
4. **执行Hook函数**：当目标函数被调用时，先执行我们的Hook函数
5. **恢复执行**：通过Trampoline恢复原始函数的执行

### 3.3 x86架构下的实现细节

在x86架构下，常用的跳转指令有两种形式：
1. `E9 xx xx xx xx` - 相对跳转指令，占用5字节
2. `FF 25 xx xx xx xx` - 间接跳转指令，占用6字节

为了确保跳转指令能够正确覆盖原始指令，我们需要保证覆盖的字节数不少于跳转指令的长度。

## 四、代码实现

### 4.1 核心数据结构

```cpp
// Inline Hook结构体
typedef struct _INLINEHOOK_INFO {
    PVOID	pTargetFunction;	// 目标函数地址
    PVOID	pHookFunction;		// Hook函数地址
    PVOID	pTrampoline;		// Trampoline地址
    BYTE	oriByte[16];		// 原始字节备份
    INT		oriByteLen;			// 原始字节长度
    BOOL	bIsHooked;			// 是否已Hook
} INLINEHOOK_INFO, * PINLINEHOOK_INFO;
```

### 4.2 辅助函数实现

```cpp
#include <windows.h>
#include <stdio.h>

// 计算需要覆盖的指令长度
INT CalcCodeLength(PBYTE addr, INT minLen) {
    INT len = 0;
    while (len < minLen) {
        len += GetInstructionLength(addr + len);
    }
    return len;
}

// 获取单条指令长度（简化版）
INT GetInstructionLength(PBYTE instruction) {
    // 这里是一个简化的实现，实际应用中可能需要反汇编库
    // 如Capstone Engine来精确计算指令长度
    if ((*instruction & 0xFF) == 0xE9) {  // JMP rel32
        return 5;
    }
    else if ((*instruction & 0xFF) == 0xE8) {  // CALL rel32
        return 5;
    }
    else if ((*instruction & 0xF0) == 0x50) {  // PUSH reg
        return 1;
    }
    else if ((*instruction & 0xF8) == 0x50) {  // PUSH reg (alternative encoding)
        return 1;
    }
    else if ((*instruction & 0xFF) == 0x8B) {  // MOV reg, reg/mem
        return 2;  // Simplified assumption
    }
    // 默认返回最小长度
    return 5;
}

// 修改内存保护属性
BOOL ModifyMemoryProtect(PVOID address, SIZE_T size, DWORD protect) {
    DWORD oldProtect;
    return VirtualProtect(address, size, protect, &oldProtect);
}
```

### 4.3 Inline Hook核心实现

```cpp
// 安装Inline Hook
BOOL InstallInlineHook(PINLINEHOOK_INFO hookInfo) {
    if (!hookInfo || !hookInfo->pTargetFunction || !hookInfo->pHookFunction) {
        return FALSE;
    }

    // 计算需要覆盖的指令长度（至少5字节用于JMP指令）
    hookInfo->oriByteLen = CalcCodeLength((PBYTE)hookInfo->pTargetFunction, 5);
    
    // 备份原始字节
    memcpy(hookInfo->oriByte, hookInfo->pTargetFunction, hookInfo->oriByteLen);

    // 分配Trampoline内存
    hookInfo->pTrampoline = VirtualAlloc(NULL, hookInfo->oriByteLen + 5, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!hookInfo->pTrampoline) {
        return FALSE;
    }

    // 构建Trampoline
    memcpy(hookInfo->pTrampoline, hookInfo->pTargetFunction, hookInfo->oriByteLen);
    
    // 在Trampoline末尾添加JMP指令回到原函数
    PBYTE jmpBackAddr = (PBYTE)hookInfo->pTrampoline + hookInfo->oriByteLen;
    jmpBackAddr[0] = 0xE9;  // JMP rel32
    
    // 计算相对偏移
    DWORD offset = (DWORD)((PBYTE)hookInfo->pTargetFunction + hookInfo->oriByteLen - jmpBackAddr - 5);
    *(PDWORD)(jmpBackAddr + 1) = offset;

    // 修改目标函数内存保护属性
    if (!ModifyMemoryProtect(hookInfo->pTargetFunction, hookInfo->oriByteLen, PAGE_EXECUTE_READWRITE)) {
        VirtualFree(hookInfo->pTrampoline, 0, MEM_RELEASE);
        return FALSE;
    }

    // 写入JMP指令到目标函数
    PBYTE targetFunc = (PBYTE)hookInfo->pTargetFunction;
    targetFunc[0] = 0xE9;  // JMP rel32
    
    // 计算跳转到Hook函数的相对偏移
    offset = (DWORD)((PBYTE)hookInfo->pHookFunction - targetFunc - 5);
    *(PDWORD)(targetFunc + 1) = offset;

    // 填充剩余字节（NOP指令）
    for (INT i = 5; i < hookInfo->oriByteLen; i++) {
        targetFunc[i] = 0x90;  // NOP
    }

    hookInfo->bIsHooked = TRUE;
    return TRUE;
}

// 卸载Inline Hook
BOOL UninstallInlineHook(PINLINEHOOK_INFO hookInfo) {
    if (!hookInfo || !hookInfo->bIsHooked) {
        return FALSE;
    }

    // 恢复原始字节
    if (!ModifyMemoryProtect(hookInfo->pTargetFunction, hookInfo->oriByteLen, PAGE_EXECUTE_READWRITE)) {
        return FALSE;
    }

    memcpy(hookInfo->pTargetFunction, hookInfo->oriByte, hookInfo->oriByteLen);

    // 释放Trampoline内存
    if (hookInfo->pTrampoline) {
        VirtualFree(hookInfo->pTrampoline, 0, MEM_RELEASE);
        hookInfo->pTrampoline = NULL;
    }

    hookInfo->bIsHooked = FALSE;
    return TRUE;
}
```

### 4.4 示例Hook函数

```cpp
// 示例：Hook MessageBoxW函数
int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    // 在这里可以修改参数或者记录日志
    wprintf(L"Hooked MessageBoxW: %s\n", lpText);
    
    // 可以修改显示的文本
    return MessageBoxW(hWnd, L"[Hooked] Hello World!", lpCaption, uType);
}

// 使用示例
void DemoInlineHook() {
    INLINEHOOK_INFO msgBoxHook = { 0 };
    
    // 获取目标函数地址
    msgBoxHook.pTargetFunction = GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxW");
    msgBoxHook.pHookFunction = MyMessageBoxW;
    
    // 安装Hook
    if (InstallInlineHook(&msgBoxHook)) {
        printf("Inline Hook installed successfully!\n");
        
        // 测试Hook效果
        MessageBoxW(NULL, L"Original Message", L"Test", MB_OK);
        
        // 卸载Hook
        UninstallInlineHook(&msgBoxHook);
        printf("Inline Hook uninstalled.\n");
    }
    else {
        printf("Failed to install Inline Hook.\n");
    }
}
```

## 五、课后作业

1. **基础练习**：
   - 编写一个程序，使用Inline Hook技术Hook `Sleep` 函数，在函数被调用时打印日志信息
   - 实现对 `CreateFileW` 函数的Hook，记录所有被打开的文件路径

2. **进阶练习**：
   - 改进代码中的 `GetInstructionLength` 函数，使用真正的反汇编库（如Capstone）来准确计算指令长度
   - 实现支持多线程环境的Inline Hook框架，确保线程安全性

3. **思考题**：
   - Inline Hook有哪些局限性和潜在风险？
   - 如何检测和防范Inline Hook攻击？
   - 在x64架构下实现Inline Hook与x86有什么不同？

4. **扩展阅读**：
   - 研究Microsoft Detours库的实现原理
   - 了解硬件断点Hook技术
   - 学习如何绕过一些基本的Hook检测机制