# 课时01：Windows环境配置

## 1. 课程目标

本课时将详细介绍如何在Windows系统上配置C/C++开发环境，为后续的安全开发打下基础。

### 1.1 学习目标

- 理解C/C++开发环境的组成部分
- 掌握Visual Studio的安装与配置
- 掌握MinGW-w64的安装与配置
- 配置VS Code轻量级开发环境
- 了解编译器工作原理

---

## 2. 核心名词解释

在开始环境配置之前，我们需要了解以下核心概念：

| 名词 | 英文全称 | 解释 |
|------|----------|------|
| **IDE** | Integrated Development Environment | 集成开发环境，集成了编辑器、编译器、调试器的一站式开发工具 |
| **编译器** | Compiler | 将源代码(.c/.cpp)转换为目标文件(.obj/.o)的程序 |
| **链接器** | Linker | 将多个目标文件和库文件链接成可执行文件(.exe)的程序 |
| **MSVC** | Microsoft Visual C++ | 微软的C/C++编译器，Windows平台首选 |
| **GCC** | GNU Compiler Collection | GNU开源编译器套件，跨平台 |
| **MinGW** | Minimalist GNU for Windows | GCC在Windows上的移植版本 |
| **SDK** | Software Development Kit | 软件开发工具包，包含头文件、库文件、文档等 |
| **Windows SDK** | - | 微软提供的Windows API开发工具包 |
| **头文件** | Header File (.h/.hpp) | 包含函数声明、宏定义、类型定义的文件 |
| **库文件** | Library File | 预编译的代码集合，分静态库(.lib/.a)和动态库(.dll/.so) |
| **环境变量** | Environment Variable | 操作系统用于存储配置信息的全局变量 |
| **PATH** | - | 系统查找可执行文件的目录列表 |
| **调试器** | Debugger | 用于逐步执行、检查程序状态的工具 |
| **GDB** | GNU Debugger | GNU开源调试器 |
| **预处理器** | Preprocessor | 处理#include、#define等预处理指令的程序 |

### 2.1 编译流程详解

```
源代码 (.c/.cpp)
     │
     ▼ [预处理器 - cpp/cl /E]
预处理后代码 (.i)
     │
     ▼ [编译器 - gcc/cl]
汇编代码 (.s)
     │
     ▼ [汇编器 - as/ml64]
目标文件 (.o/.obj)
     │
     ▼ [链接器 - ld/link]
可执行文件 (.exe)
```

### 2.2 MSVC vs GCC 对比

| 特性 | MSVC | GCC/MinGW |
|------|------|--------|
| 平台 | Windows专属 | 跨平台 |
| IDE集成 | Visual Studio | 需配合编辑器 |
| Windows兼容性 | 最佳 | 良好 |
| 编译速度 | 快 | 较慢 |
| 错误提示 | 中文友好 | 英文为主 |
| 调试器 | 内置强大调试器 | GDB |
| 安全开发推荐 | ★★★★★ | ★★★★☆ |
| 体积 | 大(10GB+) | 小(1GB) |

---

## 3. 必备工具一览

### 3.1 开发环境工具

| 工具名称 | 类型 | 用途 | 下载地址 |
|----------|------|------|----------|
| Visual Studio 2022 | IDE | 主力开发环境 | https://visualstudio.microsoft.com/ |
| VS Code | 编辑器 | 轻量级开发 | https://code.visualstudio.com/ |
| MSYS2 | 包管理器 | 安装MinGW | https://www.msys2.org/ |
| CMake | 构建工具 | 跨平台编译配置 | https://cmake.org/ |

### 3.2 调试分析工具

| 工具名称 | 用途 | 说明 |
|----------|------|------|
| x64dbg | 动态调试 | 开源调试器，适合逆向和漏洞分析 |
| WinDbg | 内核调试 | 微软官方调试器，支持内核调试 |
| IDA Pro | 静态分析 | 业界最强反汇编工具 |
| Ghidra | 静态分析 | NSA开源的逆向工具 |
| Process Monitor | 行为监控 | 监控进程的文件、注册表、网络操作 |
| Process Explorer | 进程管理 | 查看进程详细信息 |
| API Monitor | API监控 | 监控程序调用的API |

### 3.3 辅助工具

| 工具名称 | 用途 |
|----------|------|
| Notepad++ | 轻量级文本编辑 |
| HxD | 十六进制编辑器 |
| PE-bear | PE文件分析 |
| CFF Explorer | PE文件编辑 |
| Dependencies | DLL依赖查看 |

---

## 4. 方案一：Visual Studio（推荐新手）

### 2.1 下载Visual Studio

1. 访问官网：https://visualstudio.microsoft.com/zh-hans/
2. 下载 **Visual Studio Community**（免费版本）
3. 运行安装程序 `vs_setup.exe`

### 2.2 安装配置

在安装界面中，勾选以下工作负载：

```
☑ 使用C++的桌面开发
  ├── MSVC v143 - VS 2022 C++ x64/x86 生成工具
  ├── Windows 10/11 SDK
  ├── C++ CMake 工具
  └── C++ AddressSanitizer
```

### 2.3 创建第一个项目

1. 打开Visual Studio
2. 选择 **创建新项目**
3. 选择 **控制台应用** → C++
4. 输入项目名称，选择存储位置
5. 点击创建

### 2.4 编写测试代码

```cpp
#include <iostream>

int main() {
    std::cout << "Hello, Visual Studio!" << std::endl;
    return 0;
}
```

按 `Ctrl + F5` 运行程序。

---

## 3. 方案二：MinGW-w64（轻量级）

### 3.1 下载MinGW-w64

1. 访问：https://www.mingw-w64.org/downloads/
2. 推荐下载：**MSYS2**（包管理更方便）
3. 或直接下载：https://github.com/niXman/mingw-builds-binaries/releases

### 3.2 使用MSYS2安装（推荐）

```bash
# 1. 下载并安装MSYS2
# https://www.msys2.org/

# 2. 打开MSYS2 UCRT64终端，执行：
pacman -Syu

# 3. 安装GCC工具链
pacman -S mingw-w64-ucrt-x86_64-gcc
pacman -S mingw-w64-ucrt-x86_64-gdb

# 4. 验证安装
gcc --version
g++ --version
gdb --version
```

### 3.3 配置环境变量

1. 右键 **此电脑** → **属性** → **高级系统设置**
2. 点击 **环境变量**
3. 在 **系统变量** 中找到 `Path`，点击编辑
4. 添加MinGW的bin目录：

```
C:\msys64\ucrt64\bin
```

### 3.4 验证配置

打开CMD或PowerShell：

```powershell
gcc --version
# 输出：gcc (Rev3, Built by MSYS2 project) 13.2.0

g++ --version
# 输出：g++ (Rev3, Built by MSYS2 project) 13.2.0
```

---

## 4. 方案三：VS Code + MinGW

### 4.1 安装VS Code

1. 下载：https://code.visualstudio.com/
2. 安装时勾选：
   - ☑ 添加到PATH
   - ☑ 注册为默认编辑器

### 4.2 安装必要扩展

打开VS Code，按 `Ctrl+Shift+X`，搜索并安装：

```
1. C/C++ (Microsoft)
2. C/C++ Extension Pack
3. Code Runner (可选)
```

### 4.3 配置编译任务

创建 `.vscode/tasks.json`：

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Build C++ file",
            "type": "shell",
            "command": "g++",
            "args": [
                "-g",
                "-Wall",
                "-std=c++17",
                "${file}",
                "-o",
                "${fileDirname}/${fileBasenameNoExtension}.exe"
            ],
            "group": {
                "kind": "build",
                "isDefault": true
            },
            "problemMatcher": ["$gcc"]
        }
    ]
}
```

### 4.4 配置调试

创建 `.vscode/launch.json`：

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Debug C++",
            "type": "cppdbg",
            "request": "launch",
            "program": "${fileDirname}/${fileBasenameNoExtension}.exe",
            "args": [],
            "stopAtEntry": false,
            "cwd": "${workspaceFolder}",
            "environment": [],
            "externalConsole": true,
            "MIMode": "gdb",
            "miDebuggerPath": "C:/msys64/ucrt64/bin/gdb.exe",
            "setupCommands": [
                {
                    "description": "Enable pretty-printing",
                    "text": "-enable-pretty-printing",
                    "ignoreFailures": true
                }
            ],
            "preLaunchTask": "Build C++ file"
        }
    ]
}
```

### 4.5 配置IntelliSense

创建 `.vscode/c_cpp_properties.json`：

```json
{
    "configurations": [
        {
            "name": "Win32",
            "includePath": [
                "${workspaceFolder}/**",
                "C:/msys64/ucrt64/include/**"
            ],
            "defines": [
                "_DEBUG",
                "UNICODE",
                "_UNICODE"
            ],
            "compilerPath": "C:/msys64/ucrt64/bin/g++.exe",
            "cStandard": "c17",
            "cppStandard": "c++17",
            "intelliSenseMode": "windows-gcc-x64"
        }
    ],
    "version": 4
}
```

---

## 5. 命令行编译测试

### 5.1 创建测试文件

创建 `test.cpp`：

```cpp
#include <stdio.h>
#include <windows.h>

int main() {
    printf("[*] Windows C/C++ Environment Test\n");
    printf("[*] Compiler: GCC/MSVC\n");
    printf("[*] Platform: Windows x64\n");
    
    // 测试Windows API
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    printf("[*] Computer Name: %s\n", computerName);
    
    return 0;
}
```

### 5.2 编译运行

```powershell
# GCC编译
g++ -o test.exe test.cpp

# 运行
.\test.exe
```

预期输出：
```
[*] Windows C/C++ Environment Test
[*] Compiler: GCC/MSVC
[*] Platform: Windows x64
[*] Computer Name: YOUR-PC-NAME
```

---

## 6. 常见问题排查

### 6.1 'gcc' 不是内部或外部命令

**原因**：环境变量未正确配置

**解决**：
1. 检查MinGW安装路径
2. 确认Path中包含 `bin` 目录
3. 重启命令行窗口

### 6.2 缺少头文件

**原因**：SDK未安装或路径错误

**解决**：
```powershell
# MSYS2重新安装SDK
pacman -S mingw-w64-ucrt-x86_64-headers-git
```

### 6.3 链接错误 undefined reference

**原因**：缺少库文件

**解决**：
```powershell
# 链接Windows库
g++ test.cpp -o test.exe -lws2_32 -luser32 -lkernel32
```

---

## 7. 安全开发常用编译选项

### 7.1 GCC编译选项详解

```powershell
# 开启所有警告
g++ -Wall -Wextra -Werror

# 调试模式（保留调试符号，禁用优化）
g++ -g -O0

# 发布模式（优化并去除符号）
g++ -O2 -s

# 生成位置无关代码（用于Shellcode）
g++ -fPIC -pie

# 禁用栈保护（用于漏洞研究）
g++ -fno-stack-protector -z execstack

# 静态链接（独立运行，无需dll）
g++ -static -static-libgcc -static-libstdc++
```

### 7.2 编译选项名词解释

| 选项 | 全称/含义 | 作用 |
|------|-----------|------|
| `-Wall` | Warn All | 开启大部分警告 |
| `-Wextra` | Extra Warnings | 开启额外警告 |
| `-Werror` | Warnings as Errors | 将警告视为错误 |
| `-g` | Debug | 生成调试信息 |
| `-O0/O1/O2/O3` | Optimization Level | 优化级别(0-3) |
| `-s` | Strip | 去除符号表，减小体积 |
| `-fPIC` | Position Independent Code | 地址无关代码 |
| `-pie` | Position Independent Executable | 地址无关可执行文件 |
| `-fno-stack-protector` | - | 禁用栈保护(Canary) |
| `-static` | - | 静态链接所有库 |
| `-l<lib>` | Link Library | 链接指定库 |
| `-I<path>` | Include Path | 添加头文件搜索路径 |
| `-L<path>` | Library Path | 添加库文件搜索路径 |

### 7.3 MSVC编译选项

```powershell
# 使用Developer Command Prompt

# 调试编译
cl /Zi /Od test.cpp

# 发布编译（优化）
cl /O2 test.cpp

# 禁用安全检查（漏洞研究）
cl /GS- test.cpp

# 生成汇编代码
cl /FA test.cpp
```

| 选项 | 含义 |
|------|------|
| `/Zi` | 生成完整调试信息 |
| `/Od` | 禁用优化 |
| `/O2` | 最大化速度优化 |
| `/GS-` | 禁用缓冲区安全检查 |
| `/FA` | 生成汇编列表 |
| `/MT` | 静态链接运行时库 |
| `/MD` | 动态链接运行时库 |

---

## 8. 开发环境验证清单

完成环境配置后，请逐项验证：

| 检查项 | 验证命令 | 期望结果 |
|--------|----------|----------|
| GCC版本 | `gcc --version` | 显示版本号 |
| G++版本 | `g++ --version` | 显示版本号 |
| GDB调试器 | `gdb --version` | 显示版本号 |
| Make工具 | `mingw32-make --version` | 显示版本号 |
| VS编译器 | `cl` (在Developer Prompt中) | 显示版本信息 |
| CMake | `cmake --version` | 显示版本号 |

---

## 9. 常见问题与解决方案

### 9.1 环境变量问题

**问题**：`'gcc' 不是内部或外部命令`

**原因**：PATH环境变量未配置

**解决步骤**：
1. 确认MinGW安装路径，如 `C:\msys64\ucrt64\bin`
2. 右键「此电脑」→「属性」→「高级系统设置」→「环境变量」
3. 在「系统变量」中找到 `Path`，添加MinGW的bin目录
4. **重启命令行窗口**（重要！）

### 9.2 头文件找不到

**问题**：`fatal error: xxx.h: No such file or directory`

**原因**：头文件路径未配置或SDK未安装

**解决**：
```powershell
# 检查头文件位置
dir "C:\msys64\ucrt64\include\windows.h"

# 重新安装SDK
pacman -S mingw-w64-ucrt-x86_64-headers-git
```

### 9.3 链接错误

**问题**：`undefined reference to 'xxx'`

**原因**：缺少库文件链接

**解决**：添加对应的库链接
```powershell
# 常用Windows库
g++ test.cpp -o test.exe -lkernel32 -luser32 -lws2_32 -ladvapi32
```

**常用Windows库对照表**：

| 库名 | 包含的功能 |
|------|------------|
| kernel32 | 进程、线程、内存、文件操作 |
| user32 | 窗口、消息、输入 |
| gdi32 | 图形绑定接口 |
| ws2_32 | Winsock网络 |
| advapi32 | 注册表、服务、安全 |
| ntdll | Native API |
| shell32 | Shell操作 |
| ole32 | COM支持 |

---

## 10. 课后练习

### 练习1：基础环境验证（必做）

编写程序验证环境配置：

```cpp
// exercise1.cpp
#include <stdio.h>
#include <windows.h>

int main() {
    printf("=== 环境验证程序 ===\n");
    
    // 1. 获取计算机名
    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computerName);
    GetComputerNameA(computerName, &size);
    printf("[+] 计算机名: %s\n", computerName);
    
    // 2. 获取用户名
    char userName[256];
    size = sizeof(userName);
    GetUserNameA(userName, &size);
    printf("[+] 用户名: %s\n", userName);
    
    // 3. 获取系统目录
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    printf("[+] 系统目录: %s\n", sysDir);
    
    return 0;
}
```

编译命令：
```powershell
g++ exercise1.cpp -o exercise1.exe
.\exercise1.exe
```

### 练习2：弹窗程序（必做）

使用Windows API弹出对话框：

```cpp
// exercise2.cpp
#include <windows.h>

int main() {
    MessageBoxA(
        NULL,                    // 父窗口句柄
        "环境配置成功！",          // 消息内容
        "测试",                   // 标题
        MB_OK | MB_ICONINFORMATION  // 样式
    );
    return 0;
}
```

### 练习3：获取系统时间（进阶）

使用多种方式获取系统时间并格式化输出。

### 练习4：编译选项实验（进阶）

1. 使用 `-O0` 和 `-O2` 分别编译同一程序，对比exe大小
2. 使用 `-s` 选项观察符号表变化（使用`nm`命令查看）
3. 尝试使用 `objdump -d` 查看生成的汇编代码

---

## 11. 扩展阅读

### 11.1 Windows开发必读文档

- MSDN官方文档：https://learn.microsoft.com/zh-cn/windows/win32/
- Windows SDK文档：https://learn.microsoft.com/zh-cn/windows/win32/api/

### 11.2 推荐学习顺序

1. 掌握基础C/C++语法
2. 熟悉Windows API基础（进程、线程、文件）
3. 学习PE文件格式
4. 进入安全开发领域

---

## 12. 下一课预告

下一课我们将配置Linux开发环境，学习：
- Ubuntu/Kali Linux安装
- GCC在Linux下的使用
- GDB调试器基础
- Makefile编写
