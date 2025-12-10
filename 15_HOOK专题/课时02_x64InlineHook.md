# 课时02 x64 Inline Hook

## 一、课程目标

本节课主要学习在x64架构下实现Inline Hook技术，掌握其与x86架构的差异和实现方法。通过本课的学习，你将能够：

1. 理解x64架构下Inline Hook的实现原理
2. 掌握x64架构特有的跳转指令和寻址方式
3. 实现兼容x64架构的Inline Hook框架
4. 处理x64架构下的函数调用约定和寄存器保护
5. 理解x64架构下Hook技术的挑战和解决方案

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| x64架构 | 64位处理器架构，也称为x86-64或AMD64 |
| RIP-relative寻址 | x64架构下的相对寻址模式，基于指令指针寄存器 |
| RAX-R15 | x64架构下的16个通用寄存器 |
| Shadow Space | x64调用约定中为前4个参数预留的32字节栈空间 |
| Red Zone | x64 System V ABI中函数栈帧下方128字节的优化区域 |
| Wide JMP | x64架构下的绝对跳转指令，占用14字节 |

## 三、技术原理

### 3.1 x64架构与x86的区别

x64架构相比x86架构有许多重要变化，这些变化直接影响了Inline Hook的实现方式：

1. **寄存器扩展**：从8个32位寄存器扩展到16个64位寄存器
2. **寻址模式**：引入RIP-relative寻址模式
3. **调用约定**：Windows x64使用RCX、RDX、R8、R9传递前四个参数
4. **栈对齐**：要求16字节栈对齐

### 3.2 x64下的跳转指令

在x64架构下，常用的跳转指令有：

1. **短跳转**：`EB xx` - 相对跳转，占用2字节（范围-128到+127字节）
2. **近跳转**：`E9 xx xx xx xx` - 相对跳转，占用5字节（32位偏移）
3. **远跳转**：`FF 25 xx xx xx xx` 后跟8字节绝对地址 - 间接跳转，占用14字节

由于x64地址空间更大，简单的相对跳转可能无法覆盖到Hook函数，因此经常需要使用间接跳转。

### 3.3 x64 Inline Hook实现难点

1. **指令长度计算**：x64指令变长且更复杂，需要更精确的反汇编
2. **寄存器保护**：需要保存和恢复更多的寄存器状态
3. **调用约定兼容**：必须遵守x64调用约定
4. **地址空间问题**：64位地址可能导致跳转指令长度不足

## 四、代码实现

### 4.1 核心数据结构

```cpp
// x64 Inline Hook结构体
typedef struct _INLINEHOOK_X64_INFO {
    PVOID	pTargetFunction;	// 目标函数地址
    PVOID	pHookFunction;		// Hook函数地址
    PVOID	pTrampoline;		// Trampoline地址
    PVOID	pJmpAddress;		// 跳转地址存储位置
    BYTE	oriByte[32];		// 原始字节备份
    INT		oriByteLen;			// 原始字节长度
    BOOL	bIsHooked;			// 是否已Hook
} INLINEHOOK_X64_INFO, * PINLINEHOOK_X64_INFO;
```

### 4.2 辅助函数实现

```cpp
#include <windows.h>
#include <stdio.h>

// 计算x64指令长度（简化版）
INT CalcX64CodeLength(PBYTE addr, INT minLen) {
    INT len = 0;
    while (len < minLen) {
        // 这里应该使用专业的反汇编库，如Capstone
        // 此处仅为演示目的的简化实现
        if ((addr[len] & 0xFF) == 0x48 && (addr[len+1] & 0xFF) == 0x89) {  // MOV reg, reg
            len += 3;
        }
        else if ((addr[len] & 0xF8) == 0x50) {  // PUSH reg
            len += 1;
        }
        else if ((addr[len] & 0xFF) == 0xE9) {  // JMP rel32
            len += 5;
        }
        else if ((addr[len] & 0xFF) == 0xE8) {  // CALL rel32
            len += 5;
        }
        else {
            // 默认指令长度
            len += 5;
        }
    }
    return len;
}

// 修改内存保护属性
BOOL ModifyMemoryProtect(PVOID address, SIZE_T size, DWORD protect) {
    DWORD oldProtect;
    return VirtualProtect(address, size, protect, &oldProtect);
}
```

### 4.3 x64 Inline Hook核心实现

```cpp
// 安装x64 Inline Hook
BOOL InstallX64InlineHook(PINLINEHOOK_X64_INFO hookInfo) {
    if (!hookInfo || !hookInfo->pTargetFunction || !hookInfo->pHookFunction) {
        return FALSE;
    }

    // 计算需要覆盖的指令长度（至少14字节用于间接JMP指令）
    hookInfo->oriByteLen = CalcX64CodeLength((PBYTE)hookInfo->pTargetFunction, 14);
    
    // 备份原始字节
    memcpy(hookInfo->oriByte, hookInfo->pTargetFunction, hookInfo->oriByteLen);

    // 分配Trampoline内存
    hookInfo->pTrampoline = VirtualAlloc(NULL, hookInfo->oriByteLen + 14, 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!hookInfo->pTrampoline) {
        return FALSE;
    }

    // 构建Trampoline
    memcpy(hookInfo->pTrampoline, hookInfo->pTargetFunction, hookInfo->oriByteLen);
    
    // 在Trampoline末尾添加JMP指令回到原函数
    PBYTE jmpBackAddr = (PBYTE)hookInfo->pTrampoline + hookInfo->oriByteLen;
    jmpBackAddr[0] = 0xFF;      // JMP
    jmpBackAddr[1] = 0x25;      // INDIRECT
    *(PDWORD)(jmpBackAddr + 2) = 0;  // Offset (0 for absolute address)
    *(PVOID*)(jmpBackAddr + 6) = (PBYTE)hookInfo->pTargetFunction + hookInfo->oriByteLen;

    // 分配跳转地址存储空间
    hookInfo->pJmpAddress = VirtualAlloc(NULL, sizeof(PVOID), 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!hookInfo->pJmpAddress) {
        VirtualFree(hookInfo->pTrampoline, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // 设置跳转地址
    *(PVOID*)hookInfo->pJmpAddress = hookInfo->pHookFunction;

    // 修改目标函数内存保护属性
    if (!ModifyMemoryProtect(hookInfo->pTargetFunction, hookInfo->oriByteLen, PAGE_EXECUTE_READWRITE)) {
        VirtualFree(hookInfo->pTrampoline, 0, MEM_RELEASE);
        VirtualFree(hookInfo->pJmpAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // 写入间接JMP指令到目标函数
    PBYTE targetFunc = (PBYTE)hookInfo->pTargetFunction;
    targetFunc[0] = 0xFF;       // JMP
    targetFunc[1] = 0x25;       // INDIRECT
    *(PDWORD)(targetFunc + 2) = 0;  // Offset (0 for absolute address)
    *(PVOID*)(targetFunc + 6) = hookInfo->pJmpAddress;

    // 填充剩余字节（NOP指令）
    for (INT i = 14; i < hookInfo->oriByteLen; i++) {
        targetFunc[i] = 0x90;  // NOP
    }

    hookInfo->bIsHooked = TRUE;
    return TRUE;
}

// 卸载x64 Inline Hook
BOOL UninstallX64InlineHook(PINLINEHOOK_X64_INFO hookInfo) {
    if (!hookInfo || !hookInfo->bIsHooked) {
        return FALSE;
    }

    // 恢复原始字节
    if (!ModifyMemoryProtect(hookInfo->pTargetFunction, hookInfo->oriByteLen, PAGE_EXECUTE_READWRITE)) {
        return FALSE;
    }

    memcpy(hookInfo->pTargetFunction, hookInfo->oriByte, hookInfo->oriByteLen);

    // 释放内存
    if (hookInfo->pTrampoline) {
        VirtualFree(hookInfo->pTrampoline, 0, MEM_RELEASE);
        hookInfo->pTrampoline = NULL;
    }
    
    if (hookInfo->pJmpAddress) {
        VirtualFree(hookInfo->pJmpAddress, 0, MEM_RELEASE);
        hookInfo->pJmpAddress = NULL;
    }

    hookInfo->bIsHooked = FALSE;
    return TRUE;
}
```

### 4.4 x64 Hook函数示例

```cpp
// x64示例：Hook MessageBoxW函数
int WINAPI MyX64MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
    // 在这里可以修改参数或者记录日志
    wprintf(L"x64 Hooked MessageBoxW: %s\n", lpText);
    
    // 可以修改显示的文本
    return MessageBoxW(hWnd, L"[x64 Hooked] Hello World!", lpCaption, uType);
}

// x64使用示例
void DemoX64InlineHook() {
    INLINEHOOK_X64_INFO msgBoxHook = { 0 };
    
    // 获取目标函数地址
    msgBoxHook.pTargetFunction = GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxW");
    msgBoxHook.pHookFunction = MyX64MessageBoxW;
    
    // 安装Hook
    if (InstallX64InlineHook(&msgBoxHook)) {
        printf("x64 Inline Hook installed successfully!\n");
        
        // 测试Hook效果
        MessageBoxW(NULL, L"Original Message", L"x64 Test", MB_OK);
        
        // 卸载Hook
        UninstallX64InlineHook(&msgBoxHook);
        printf("x64 Inline Hook uninstalled.\n");
    }
    else {
        printf("Failed to install x64 Inline Hook.\n");
    }
}
```

### 4.5 x86/x64兼容的Hook框架

```cpp
#ifdef _WIN64
#define INSTALL_INLINE_HOOK InstallX64InlineHook
#define UNINSTALL_INLINE_HOOK UninstallX64InlineHook
#define INLINEHOOK_STRUCT INLINEHOOK_X64_INFO
#else
#define INSTALL_INLINE_HOOK InstallInlineHook
#define UNINSTALL_INLINE_HOOK UninstallInlineHook
#define INLINEHOOK_STRUCT INLINEHOOK_INFO
#endif

// 通用Hook安装函数
BOOL UniversalInlineHook(PVOID targetFunc, PVOID hookFunc, PVOID* hookHandle) {
    PINLINEHOOK_STRUCT hookInfo = (PINLINEHOOK_STRUCT)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(INLINEHOOK_STRUCT));
    if (!hookInfo) {
        return FALSE;
    }
    
    hookInfo->pTargetFunction = targetFunc;
    hookInfo->pHookFunction = hookFunc;
    
    if (INSTALL_INLINE_HOOK(hookInfo)) {
        *hookHandle = hookInfo;
        return TRUE;
    }
    else {
        HeapFree(GetProcessHeap(), 0, hookInfo);
        return FALSE;
    }
}

// 通用Hook卸载函数
BOOL UniversalUninstallHook(PVOID hookHandle) {
    PINLINEHOOK_STRUCT hookInfo = (PINLINEHOOK_STRUCT)hookHandle;
    if (!hookInfo) {
        return FALSE;
    }
    
    BOOL result = UNINSTALL_INLINE_HOOK(hookInfo);
    HeapFree(GetProcessHeap(), 0, hookInfo);
    return result;
}
```

## 五、课后作业

1. **基础练习**：
   - 编写一个同时支持x86和x64架构的Inline Hook框架
   - 使用该框架Hook `Sleep` 函数，在x64环境下验证其功能

2. **进阶练习**：
   - 实现一个更精确的x64指令长度计算器，使用Capstone反汇编引擎
   - 添加对浮点寄存器和XMM寄存器的保护机制

3. **思考题**：
   - 为什么x64架构下不能简单地使用相对跳转指令？
   - 如何解决x64架构下地址空间过大导致的跳转问题？
   - x64架构下的Hook检测和防护技术有哪些新特点？

4. **扩展阅读**：
   - 研究x64 System V ABI和Microsoft x64 Calling Convention的差异
   - 了解Control Flow Guard (CFG) 对Hook技术的影响
   - 学习如何在启用ASLR的环境中实现稳定的Hook