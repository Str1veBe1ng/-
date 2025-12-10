# 课时13：Windows策略防止ShellCode

## 1. 课程目标

理解Windows如何使用安全策略防止ShellCode执行，以及如何绕过这些保护机制。

### 1.1 学习目标

- 了解DEP、CFG、ACG等保护机制原理
- 学习如何检测这些保护是否启用
- 掌握合法绕过这些保护的方法

---

## 2. 名词解释

| 名词 | 英文 | 解释 |
|------|------|------|
| **DEP** | Data Execution Prevention | 数据执行保护，阻止数据区域代码执行 |
| **NX** | No-Execute | 不可执行位，CPU级别的DEP支持 |
| **ACG** | Arbitrary Code Guard | 任意代码防护 |
| **CET** | Control-flow Enforcement Technology | 控制流强制技术 |
| **Shadow Stack** | - | 影子栈，防止ROP攻击 |
| **ROP** | Return-Oriented Programming | 返回导向编程 |

---

## 3. DEP保护机制

### 3.1 DEP工作原理

```
┌─────────────────────────────────────────────────────────┐
│                    进程内存空间                          │
├─────────────────────────────────────────────────────────┤
│  代码段 (.text)     │ PAGE_EXECUTE_READ  │ 可执行 ✓    │
├─────────────────────────────────────────────────────────┤
│  数据段 (.data)     │ PAGE_READWRITE     │ 不可执行 ✗  │
├─────────────────────────────────────────────────────────┤
│  堆 (Heap)          │ PAGE_READWRITE     │ 不可执行 ✗  │
├─────────────────────────────────────────────────────────┤
│  栈 (Stack)         │ PAGE_READWRITE     │ 不可执行 ✗  │
└─────────────────────────────────────────────────────────┘
         ↓ 如果在数据区执行代码
    ┌────────────────────────┐
    │  ACCESS_VIOLATION      │
    │  STATUS_ACCESS_DENIED  │
    └────────────────────────┘
```

### 3.2 检测DEP状态

```cpp
#include <windows.h>
#include <stdio.h>

void CheckDEPStatus() {
    // 方法1：GetProcessDEPPolicy
    DWORD dwFlags;
    BOOL bPermanent;
    
    if (GetProcessDEPPolicy(GetCurrentProcess(), &dwFlags, &bPermanent)) {
        printf("[*] DEP状态:\n");
        printf("    启用: %s\n", (dwFlags & PROCESS_DEP_ENABLE) ? "是" : "否");
        printf("    ATL Thunk: %s\n", 
               (dwFlags & PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION) ? "禁用" : "启用");
        printf("    永久: %s\n", bPermanent ? "是" : "否");
    }
    
    // 方法2：GetSystemDEPPolicy
    DEP_SYSTEM_POLICY_TYPE depPolicy = GetSystemDEPPolicy();
    printf("[*] 系统DEP策略: ");
    switch (depPolicy) {
        case DEPPolicyAlwaysOff: printf("始终关闭\n"); break;
        case DEPPolicyAlwaysOn:  printf("始终开启\n"); break;
        case DEPPolicyOptIn:     printf("选择性开启\n"); break;
        case DEPPolicyOptOut:    printf("选择性关闭\n"); break;
    }
    
    // 方法3：NtQueryInformationProcess
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    
    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    
    ULONG executeFlags = 0;
    NtQueryInformationProcess(GetCurrentProcess(), (PROCESSINFOCLASS)0x22, 
                             &executeFlags, sizeof(executeFlags), NULL);
    
    printf("[*] ExecuteFlags: 0x%X\n", executeFlags);
    printf("    MEM_EXECUTE_OPTION_DISABLE: %s\n", 
           (executeFlags & 0x1) ? "是" : "否");
}
```

---

## 4. 绕过DEP的方法

### 4.1 合法方法：VirtualProtect

```cpp
#include <windows.h>
#include <stdio.h>

// 使用VirtualProtect修改内存权限
BOOL ExecuteShellcodeWithVirtualProtect(LPVOID pShellcode, SIZE_T size) {
    // 1. 分配可读写内存
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pMem) {
        printf("[-] VirtualAlloc失败\n");
        return FALSE;
    }
    printf("[+] 内存分配: 0x%p (RW)\n", pMem);
    
    // 2. 复制Shellcode
    memcpy(pMem, pShellcode, size);
    printf("[+] Shellcode已复制\n");
    
    // 3. 修改权限为可执行
    DWORD dwOldProtect;
    if (!VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &dwOldProtect)) {
        printf("[-] VirtualProtect失败: %d\n", GetLastError());
        VirtualFree(pMem, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[+] 权限已修改为RX\n");
    
    // 4. 刷新指令缓存
    FlushInstructionCache(GetCurrentProcess(), pMem, size);
    
    // 5. 执行
    printf("[*] 执行Shellcode...\n");
    ((void(*)())pMem)();
    
    VirtualFree(pMem, 0, MEM_RELEASE);
    return TRUE;
}
```

### 4.2 直接分配可执行内存

```cpp
// 直接使用PAGE_EXECUTE_READWRITE
LPVOID pMem = VirtualAlloc(NULL, size, 
                           MEM_COMMIT | MEM_RESERVE, 
                           PAGE_EXECUTE_READWRITE);
memcpy(pMem, shellcode, size);
((void(*)())pMem)();
```

### 4.3 使用ROP链绕过（高级）

```
ROP链执行流程:
┌─────────────────────────────────────────────────────────┐
│  1. 找到VirtualProtect的gadget地址                       │
│  2. 准备好参数（地址、大小、新权限、旧权限指针）            │
│  3. 通过栈溢出控制返回地址                                │
│  4. 跳转到VirtualProtect gadget                          │
│  5. VirtualProtect执行，修改Shellcode内存为可执行         │
│  6. 返回到Shellcode地址执行                              │
└─────────────────────────────────────────────────────────┘
```

---

## 5. ACG保护机制

### 5.1 ACG原理

ACG阻止以下操作：
- `VirtualAlloc(PAGE_EXECUTE_*)`
- `VirtualProtect(PAGE_EXECUTE_*)`
- 任何动态生成可执行代码的操作

### 5.2 检测ACG状态

```cpp
#include <windows.h>
#include <stdio.h>

typedef BOOL(WINAPI* pGetProcessMitigationPolicy)(
    HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);

void CheckACGStatus() {
    pGetProcessMitigationPolicy GetProcessMitigationPolicy = 
        (pGetProcessMitigationPolicy)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "GetProcessMitigationPolicy");
    
    if (!GetProcessMitigationPolicy) {
        printf("[-] 系统不支持GetProcessMitigationPolicy\n");
        return;
    }
    
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy = { 0 };
    if (GetProcessMitigationPolicy(GetCurrentProcess(), 
                                   ProcessDynamicCodePolicy, 
                                   &policy, sizeof(policy))) {
        printf("[*] ACG状态:\n");
        printf("    ProhibitDynamicCode: %d\n", policy.ProhibitDynamicCode);
        printf("    AllowThreadOptOut: %d\n", policy.AllowThreadOptOut);
        printf("    AllowRemoteDowngrade: %d\n", policy.AllowRemoteDowngrade);
    }
}
```

### 5.3 绕过ACG

**方法1：线程选择退出**

```cpp
// 如果AllowThreadOptOut=1，可以使用此方法
DWORD dwPolicy = THREAD_DYNAMIC_CODE_ALLOW;
SetThreadInformation(GetCurrentThread(), 
                     ThreadDynamicCodePolicy, 
                     &dwPolicy, sizeof(dwPolicy));
```

**方法2：使用已存在的可执行内存**

- 模块镂空（Module Stomping）
- 代码洞穴（Code Cave）
- 已加载DLL的代码段

---

## 6. CFG保护机制

### 6.1 CFG原理

CFG（控制流防护）验证间接调用的目标地址是否合法。

```
无CFG保护:                       有CFG保护:
                                 
call [eax]  →  任意地址           call [eax]
                                     ↓
                                 检查eax是否在CFG位图中
                                     ↓
                                 合法 → 允许调用
                                 非法 → 触发异常
```

### 6.2 检测CFG状态

```cpp
void CheckCFGStatus() {
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy = { 0 };
    
    if (GetProcessMitigationPolicy(GetCurrentProcess(),
                                   ProcessControlFlowGuardPolicy,
                                   &cfgPolicy, sizeof(cfgPolicy))) {
        printf("[*] CFG状态:\n");
        printf("    EnableControlFlowGuard: %d\n", cfgPolicy.EnableControlFlowGuard);
        printf("    EnableExportSuppression: %d\n", cfgPolicy.EnableExportSuppression);
        printf("    StrictMode: %d\n", cfgPolicy.StrictMode);
    }
}
```

### 6.3 绕过CFG

**方法1：调用已注册的函数**

CFG允许调用PE导出表中的函数或已注册的回调函数。

**方法2：使用NtContinue**

```cpp
// NtContinue可以修改线程上下文并继续执行
// 某些版本的CFG不检查NtContinue
typedef NTSTATUS(NTAPI* pNtContinue)(PCONTEXT, BOOLEAN);
```

---

## 7. 综合检测示例

```cpp
#include <windows.h>
#include <stdio.h>

void CheckAllSecurityPolicies() {
    printf("========================================\n");
    printf("    Windows安全策略检测\n");
    printf("========================================\n\n");
    
    // DEP
    DWORD depFlags;
    BOOL depPermanent;
    GetProcessDEPPolicy(GetCurrentProcess(), &depFlags, &depPermanent);
    printf("[DEP]\n");
    printf("  启用: %s\n", (depFlags & 1) ? "是" : "否");
    printf("  永久: %s\n\n", depPermanent ? "是" : "否");
    
    // ASLR
    PROCESS_MITIGATION_ASLR_POLICY aslr = { 0 };
    GetProcessMitigationPolicy(GetCurrentProcess(), ProcessASLRPolicy, &aslr, sizeof(aslr));
    printf("[ASLR]\n");
    printf("  EnableBottomUpRandomization: %d\n", aslr.EnableBottomUpRandomization);
    printf("  EnableHighEntropy: %d\n\n", aslr.EnableHighEntropy);
    
    // ACG
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg = { 0 };
    GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &acg, sizeof(acg));
    printf("[ACG]\n");
    printf("  ProhibitDynamicCode: %d\n\n", acg.ProhibitDynamicCode);
    
    // CFG
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg = { 0 };
    GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg));
    printf("[CFG]\n");
    printf("  EnableControlFlowGuard: %d\n", cfg.EnableControlFlowGuard);
    printf("  StrictMode: %d\n\n", cfg.StrictMode);
}

int main() {
    CheckAllSecurityPolicies();
    return 0;
}
```

---

## 8. 课后作业

### 作业1：检测工具（必做）

编写程序检测当前系统和进程的安全策略状态。

### 作业2：DEP绕过（必做）

在启用DEP的情况下，使用VirtualProtect执行ShellCode。

### 作业3：ACG测试（进阶）

创建启用ACG的进程，测试哪些ShellCode执行方法失效。

---

## 9. 下一课预告

下一课我们将学习父进程伪装技术，隐藏进程的真实来源。
