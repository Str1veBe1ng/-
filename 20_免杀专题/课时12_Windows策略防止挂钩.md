# 课时12：Windows策略防止挂钩

## 1. 课程目标

学习如何利用Windows安全策略来防止安全软件挂钩我们的进程，保护代码执行不被监控。

### 1.1 学习目标

- 了解Windows提供的进程保护机制
- 掌握ACG、CIG等策略的使用
- 学会配置进程缓解策略
- 理解各策略的优缺点

---

## 2. 名词解释

| 名词 | 英文全称 | 解释 |
|------|----------|------|
| **ACG** | Arbitrary Code Guard | 任意代码防护，阻止动态生成可执行代码 |
| **CIG** | Code Integrity Guard | 代码完整性保护，只允许签名代码执行 |
| **CFG** | Control Flow Guard | 控制流防护，防止ROP/JOP攻击 |
| **ASLR** | Address Space Layout Randomization | 地址空间随机化 |
| **DEP** | Data Execution Prevention | 数据执行保护 |
| **BlockNonMicrosoftBinaries** | - | 阻止非微软签名的DLL加载 |
| **Mitigation Policy** | - | 进程缓解策略 |

---

## 3. 进程缓解策略概述

### 3.1 可用的缓解策略

| 策略 | 作用 | 对抗Hook |
|------|------|----------|
| PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES | 阻止非MS签名DLL | 阻止安全软件DLL注入 |
| PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE | 禁止动态代码 | 需要特殊处理 |
| PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD | 控制流保护 | 防止Hook跳转 |
| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE | 禁止远程镜像 | 阻止网络加载 |
| PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL | 禁止低完整性镜像 | 阻止低权限加载 |

---

## 4. 核心实现代码

### 4.1 创建受保护的子进程

```cpp
#include <windows.h>
#include <stdio.h>

// 创建带有缓解策略的子进程
BOOL CreateProtectedProcess(LPCWSTR szPath) {
    printf("[*] 创建受保护进程: %ws\n", szPath);
    
    // 1. 初始化属性列表
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
    
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = 
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    
    if (!InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrSize)) {
        printf("[-] InitializeProcThreadAttributeList失败: %d\n", GetLastError());
        return FALSE;
    }
    
    // 2. 设置缓解策略
    // 阻止非微软签名的DLL加载
    DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    
    if (!UpdateProcThreadAttribute(
            pAttrList,
            0,
            PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            &policy,
            sizeof(policy),
            NULL,
            NULL)) {
        printf("[-] UpdateProcThreadAttribute失败: %d\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }
    
    printf("[+] 策略: BLOCK_NON_MICROSOFT_BINARIES\n");
    
    // 3. 创建进程
    STARTUPINFOEXW si = { 0 };
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = pAttrList;
    
    PROCESS_INFORMATION pi = { 0 };
    
    if (!CreateProcessW(
            szPath,
            NULL,
            NULL,
            NULL,
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
            NULL,
            NULL,
            &si.StartupInfo,
            &pi)) {
        printf("[-] CreateProcess失败: %d\n", GetLastError());
        DeleteProcThreadAttributeList(pAttrList);
        HeapFree(GetProcessHeap(), 0, pAttrList);
        return FALSE;
    }
    
    printf("[+] 进程创建成功! PID: %d\n", pi.dwProcessId);
    
    // 清理
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    
    return TRUE;
}
```

### 4.2 设置当前进程的缓解策略

```cpp
#include <windows.h>
#include <processthreadsapi.h>
#include <stdio.h>

// 动态设置当前进程的策略
BOOL SetCurrentProcessPolicy() {
    // 获取SetProcessMitigationPolicy函数
    typedef BOOL(WINAPI* pSetProcessMitigationPolicy)(
        PROCESS_MITIGATION_POLICY MitigationPolicy,
        PVOID lpBuffer,
        SIZE_T dwLength
    );
    
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    pSetProcessMitigationPolicy SetProcessMitigationPolicy = 
        (pSetProcessMitigationPolicy)GetProcAddress(hKernel32, "SetProcessMitigationPolicy");
    
    if (!SetProcessMitigationPolicy) {
        printf("[-] 系统不支持SetProcessMitigationPolicy\n");
        return FALSE;
    }
    
    // 设置动态代码策略
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcPolicy = { 0 };
    dcPolicy.ProhibitDynamicCode = 1;
    dcPolicy.AllowThreadOptOut = 1;  // 允许线程选择退出
    
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dcPolicy, sizeof(dcPolicy))) {
        printf("[-] 设置动态代码策略失败: %d\n", GetLastError());
    } else {
        printf("[+] 动态代码策略已启用\n");
    }
    
    // 设置二进制签名策略
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sigPolicy = { 0 };
    sigPolicy.MicrosoftSignedOnly = 1;
    
    if (!SetProcessMitigationPolicy(ProcessSignaturePolicy, &sigPolicy, sizeof(sigPolicy))) {
        printf("[-] 设置签名策略失败: %d\n", GetLastError());
    } else {
        printf("[+] 仅允许微软签名DLL\n");
    }
    
    return TRUE;
}
```

### 4.3 完整的策略保护示例

```cpp
#include <windows.h>
#include <stdio.h>

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ui64 << 44)
#define PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON (0x00000001ui64 << 36)

BOOL CreateFullyProtectedProcess(LPCWSTR szPath) {
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(NULL, 2, 0, &attrSize);
    
    LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = 
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
    InitializeProcThreadAttributeList(pAttrList, 2, 0, &attrSize);
    
    // 组合多个缓解策略
    DWORD64 policy = 0;
    policy |= PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
    // 注意：PROHIBIT_DYNAMIC_CODE会阻止VirtualAlloc(MEM_EXECUTE)和VirtualProtect(PAGE_EXECUTE_*)
    // policy |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
    
    UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                             &policy, sizeof(policy), NULL, NULL);
    
    STARTUPINFOEXW si = { sizeof(si) };
    si.lpAttributeList = pAttrList;
    
    PROCESS_INFORMATION pi = { 0 };
    
    BOOL result = CreateProcessW(szPath, NULL, NULL, NULL, FALSE,
                                  EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                                  NULL, NULL, &si.StartupInfo, &pi);
    
    if (result) {
        printf("[+] 受保护进程已创建, PID: %d\n", pi.dwProcessId);
        printf("[+] 安全软件将无法注入DLL到此进程\n");
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    
    DeleteProcThreadAttributeList(pAttrList);
    HeapFree(GetProcessHeap(), 0, pAttrList);
    
    return result;
}

int main() {
    printf("========================================\n");
    printf("    Windows策略防止挂钩演示\n");
    printf("========================================\n\n");
    
    CreateFullyProtectedProcess(L"C:\\Windows\\System32\\notepad.exe");
    
    return 0;
}
```

---

## 5. 各策略详细说明

### 5.1 BLOCK_NON_MICROSOFT_BINARIES

**作用**: 阻止非微软签名的DLL加载到进程

**效果**:
- 安全软件的Hook DLL无法注入
- 第三方DLL无法加载
- 仅限微软签名的DLL可用

**注意**: 这会阻止很多正常DLL，可能导致应用功能受限

### 5.2 PROHIBIT_DYNAMIC_CODE

**作用**: 禁止动态生成可执行代码

**影响**:
- VirtualAlloc不能使用PAGE_EXECUTE_*
- VirtualProtect不能将内存改为可执行
- JIT编译器无法工作

**绕过**: 使用AllowThreadOptOut允许特定线程动态代码

---

## 6. 注意事项

1. **策略不可逆**: 一旦设置，无法在进程运行时取消
2. **兼容性问题**: 某些应用依赖动态代码或第三方DLL
3. **调试困难**: 受保护进程可能难以调试
4. **权限要求**: 某些策略需要管理员权限

---

## 7. 课后作业

### 作业1：基础实现（必做）

1. 创建一个使用BLOCK_NON_MICROSOFT_BINARIES策略的进程
2. 验证该进程无法被常规DLL注入

### 作业2：策略测试（进阶）

1. 测试不同策略组合的效果
2. 观察哪些策略会影响ShellCode执行

---

## 8. 下一课预告

下一课我们将学习Windows策略防止ShellCode执行的技术。