# 课时19：PPL (Protected Process Light)

## 1. 课程目标

深入了解Windows的PPL保护机制，学习如何识别PPL进程以及相关的攻防技术。

### 1.1 学习目标

- 理解PP和PPL的区别
- 掌握PPL进程的识别方法
- 了解PPL的保护范围
- 学习绕过PPL的已知技术

---

## 2. 名词解释

| 名词 | 英文 | 解释 |
|------|------|------|
| **PP** | Protected Process | 受保护进程（完整保护）|
| **PPL** | Protected Process Light | 轻量级受保护进程 |
| **PS_PROTECTION** | - | 进程保护结构体 |
| **Signer** | - | 签名者级别，决定保护强度 |
| **LSASS** | Local Security Authority Subsystem Service | 本地安全验证服务 |
| **Credential Guard** | - | 凭据保护，使用虚拟化 |
| **ELAM** | Early Launch Anti-Malware | 早期启动反恶意软件 |

---

## 3. PPL基础知识

### 3.1 PP vs PPL

```
Protected Process (PP):
- Windows Vista引入
- 仅用于DRM相关进程
- 只能加载签名的DLL
- 极高保护级别

Protected Process Light (PPL):
- Windows 8.1引入
- 用于安全相关进程（LSASS、反恶意软件）
- 分多个保护级别
- 阻止非授权的访问和代码注入
```

### 3.2 保护级别层次

```
保护级别（从高到低）:
┌─────────────────────────────────────────┐
│ WinSystem (7)      - 系统最高级别       │
├─────────────────────────────────────────┤
│ WinTcb (6)         - 可信计算基         │
├─────────────────────────────────────────┤
│ Windows (5)        - Windows组件        │
├─────────────────────────────────────────┤
│ Lsa (4)            - LSA保护            │
├─────────────────────────────────────────┤
│ Antimalware (3)    - 反恶意软件         │
├─────────────────────────────────────────┤
│ CodeGen (2)        - 代码生成           │
├─────────────────────────────────────────┤
│ Authenticode (1)   - 代码签名           │
├─────────────────────────────────────────┤
│ None (0)           - 无保护             │
└─────────────────────────────────────────┘
```

### 3.3 Signer类型

| Signer | 值 | 说明 |
|--------|-----|------|
| PsProtectedSignerNone | 0 | 无签名 |
| PsProtectedSignerAuthenticode | 1 | Authenticode签名 |
| PsProtectedSignerCodeGen | 2 | 代码生成 |
| PsProtectedSignerAntimalware | 3 | 反恶意软件 |
| PsProtectedSignerLsa | 4 | LSA |
| PsProtectedSignerWindows | 5 | Windows |
| PsProtectedSignerWinTcb | 6 | 可信计算基 |
| PsProtectedSignerWinSystem | 7 | 系统 |

---

## 4. 识别PPL进程

### 4.1 使用NtQueryInformationProcess

```cpp
#include <windows.h>
#include <stdio.h>
#include <winternl.h>

typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode = 1,
    PsProtectedSignerCodeGen = 2,
    PsProtectedSignerAntimalware = 3,
    PsProtectedSignerLsa = 4,
    PsProtectedSignerWindows = 5,
    PsProtectedSignerWinTcb = 6,
    PsProtectedSignerWinSystem = 7
} PS_PROTECTED_SIGNER;

// ProcessProtectionInformation = 61
#define ProcessProtectionInformation 61

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

BOOL GetProcessProtection(DWORD dwPid, PS_PROTECTION* pProtection) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
    if (!hProcess) {
        return FALSE;
    }
    
    pNtQueryInformationProcess NtQueryInformationProcess = 
        (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        (PROCESSINFOCLASS)ProcessProtectionInformation,
        pProtection,
        sizeof(PS_PROTECTION),
        NULL
    );
    
    CloseHandle(hProcess);
    return NT_SUCCESS(status);
}

void PrintProtectionInfo(DWORD dwPid, LPCWSTR szName) {
    PS_PROTECTION protection = { 0 };
    
    if (GetProcessProtection(dwPid, &protection)) {
        if (protection.Level != 0) {
            printf("[PPL] PID: %5d | Type: %d | Signer: %d | %ws\n",
                   dwPid, protection.Type, protection.Signer, szName);
            
            printf("      ");
            switch (protection.Signer) {
                case 3: printf("Antimalware"); break;
                case 4: printf("Lsa"); break;
                case 5: printf("Windows"); break;
                case 6: printf("WinTcb"); break;
                case 7: printf("WinSystem"); break;
                default: printf("Other (%d)", protection.Signer);
            }
            printf("\n");
        }
    }
}
```

### 4.2 枚举所有PPL进程

```cpp
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

void EnumeratePPLProcesses() {
    printf("========================================\n");
    printf("    PPL进程枚举\n");
    printf("========================================\n\n");
    
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return;
    
    PROCESSENTRY32W pe = { sizeof(pe) };
    
    if (Process32FirstW(hSnap, &pe)) {
        do {
            PrintProtectionInfo(pe.th32ProcessID, pe.szExeFile);
        } while (Process32NextW(hSnap, &pe));
    }
    
    CloseHandle(hSnap);
}

int main() {
    EnumeratePPLProcesses();
    return 0;
}
```

---

## 5. PPL保护范围

### 5.1 阻止的操作

```
PPL进程阻止以下操作（来自非PPL或低级别PPL进程）:
- PROCESS_VM_READ           - 读取进程内存
- PROCESS_VM_WRITE          - 写入进程内存
- PROCESS_CREATE_THREAD     - 创建远程线程
- PROCESS_TERMINATE         - 终止进程
- PROCESS_DUP_HANDLE        - 复制句柄
- THREAD_SET_CONTEXT        - 修改线程上下文
```

### 5.2 允许的操作

```
PPL进程允许以下操作:
- PROCESS_QUERY_LIMITED_INFORMATION  - 查询基本信息
- PROCESS_SUSPEND_RESUME             - 挂起/恢复（某些情况）
```

---

## 6. LSASS PPL保护

### 6.1 启用LSASS PPL

```powershell
# 方法1：注册表
# HKLM\SYSTEM\CurrentControlSet\Control\Lsa
# RunAsPPL = 1

# 方法2：PowerShell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1

# 方法3：组策略
# 计算机配置 → 管理模板 → 系统 → 本地安全机构 → 配置LSASS以作为受保护进程运行
```

### 6.2 检查LSASS保护状态

```cpp
#include <windows.h>
#include <stdio.h>

BOOL IsLsassPPL() {
    HKEY hKey;
    DWORD dwRunAsPPL = 0;
    DWORD dwSize = sizeof(DWORD);
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        RegQueryValueExW(hKey, L"RunAsPPL", NULL, NULL, 
                        (LPBYTE)&dwRunAsPPL, &dwSize);
        RegCloseKey(hKey);
    }
    
    return dwRunAsPPL != 0;
}

int main() {
    printf("[*] LSASS PPL状态: %s\n", IsLsassPPL() ? "已启用" : "未启用");
    
    // 验证实际保护
    HANDLE hLsass = OpenProcess(PROCESS_VM_READ, FALSE, GetLsassPid());
    if (!hLsass) {
        printf("[+] 无法打开LSASS (PPL生效)\n");
    } else {
        printf("[-] 可以打开LSASS (PPL未生效)\n");
        CloseHandle(hLsass);
    }
    
    return 0;
}
```

---

## 7. 绕过PPL的已知技术

### 7.1 内核驱动方式

```
使用有漏洞的签名驱动:
1. 加载有漏洞的合法签名驱动
2. 利用驱动漏洞获取内核读写能力
3. 直接修改EPROCESS.Protection字段
4. 移除目标进程的PPL保护

常见的有漏洞驱动:
- RTCore64.sys
- DBUtil_2_3.sys
- gdrv.sys
```

### 7.2 概念性代码

```cpp
// 警告：以下为概念性代码，仅用于教育目的
// 在EPROCESS结构中修改Protection字段

/*
在内核中:
1. 获取目标进程的EPROCESS地址
2. 定位Protection字段偏移
3. 将Protection.Level设为0

EPROCESS偏移（Windows 10 21H1示例）:
Protection字段偏移约为0x87A（根据版本不同）
*/

typedef struct _EPROCESS_PARTIAL {
    // ... 其他字段
    PS_PROTECTION Protection;  // 偏移约0x87A
} EPROCESS_PARTIAL;

// 内核代码示例
void RemovePPL(PEPROCESS Process) {
    // 直接写入Protection为0
    // *(PUCHAR)((ULONG_PTR)Process + PROTECTION_OFFSET) = 0;
}
```

### 7.3 PPLDump工具原理

```
PPLDump利用流程:
1. 利用有漏洞的签名驱动获取内核读写
2. 定位lsass.exe的EPROCESS结构
3. 修改Protection字段
4. 调用MiniDumpWriteDump转储内存
5. 恢复Protection字段
```

---

## 8. 防御与检测

### 8.1 检测驱动加载

```cpp
#include <windows.h>
#include <stdio.h>

// 监控驱动加载事件
void MonitorDriverLoad() {
    // 使用ETW或回调监控驱动加载
    // 检查加载的驱动是否在已知漏洞驱动列表中
    
    const wchar_t* knownBadDrivers[] = {
        L"RTCore64.sys",
        L"DBUtil_2_3.sys",
        L"gdrv.sys"
    };
    
    // 扫描已加载驱动...
}
```

### 8.2 HVCI保护

启用Hypervisor-protected Code Integrity可以阻止加载有漏洞的驱动。

```powershell
# 检查HVCI状态
Get-ComputerInfo | Select-Object DeviceGuard*

# 启用HVCI
# Windows 安全中心 → 设备安全性 → 内核隔离详细信息
```

---

## 9. 课后作业

### 作业1：PPL枚举（必做）

1. 编写程序枚举系统中所有PPL进程
2. 输出每个PPL进程的类型和签名者

### 作业2：LSASS保护（必做）

1. 检查系统的LSASS PPL配置
2. 尝试以不同方式访问LSASS

### 作业3：保护分析（进阶）

1. 分析Windows Defender进程的PPL级别
2. 研究不同PPL级别之间的访问权限

---

## 10. 下一课预告

下一课我们将学习查杀原理，了解安全软件如何检测恶意程序。
