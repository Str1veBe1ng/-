# 课时10：select选择模型

## 课程目标

1. 理解I/O多路复用的概念和原理
2. 掌握select函数的使用方法
3. 实现基于select的高并发服务器
4. 理解select模型的优缺点

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| I/O多路复用 | I/O Multiplexing | 单线程监控多个I/O事件 |
| fd_set | File Descriptor Set | 套接字描述符集合 |
| FD_SETSIZE | - | fd_set最大容量，默认64 |
| select | - | 阻塞等待多个套接字就绪 |
| 可读 | Readable | 接收缓冲区有数据或连接请求 |
| 可写 | Writable | 发送缓冲区有空间可写入 |
| 异常 | Exception | 带外数据到达或错误发生 |

## 使用工具

- Visual Studio 2022
- Process Monitor（监控I/O操作）
- Wireshark（网络抓包）
- ApacheBench（压力测试）

## 技术原理

### select工作原理

```
应用程序                    内核
    |                        |
    |-- select(nfds, readfds, writefds, exceptfds, timeout) -->|
    |                        |
    |     【阻塞等待】        |
    |                        | 检查所有套接字状态
    |                        | 有事件或超时返回
    |                        |
    |<-- 返回就绪的套接字数量 --|
    |                        |
    | 遍历fd_set找出就绪的套接字
    | 处理I/O事件
```

### fd_set结构

```c
// Windows中的fd_set定义
typedef struct fd_set {
    u_int   fd_count;               // 套接字数量
    SOCKET  fd_array[FD_SETSIZE];   // 套接字数组
} fd_set;

// FD_SETSIZE 默认为64，可以在包含winsock2.h前修改
#define FD_SETSIZE 1024
#include <winsock2.h>
```

### select函数

```c
int select(
    int nfds,               // 忽略（Windows兼容参数）
    fd_set* readfds,        // 检查可读的套接字集合
    fd_set* writefds,       // 检查可写的套接字集合
    fd_set* exceptfds,      // 检查异常的套接字集合
    const timeval* timeout  // 超时时间
);

// fd_set操作宏
FD_ZERO(fd_set* set);           // 清空集合
FD_SET(SOCKET s, fd_set* set);  // 添加套接字到集合
FD_CLR(SOCKET s, fd_set* set);  // 从集合移除套接字
FD_ISSET(SOCKET s, fd_set* set);// 检查套接字是否在集合中
```

## 代码实现

### 基于select的TCP服务器

```c
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// 扩大FD_SETSIZE
#define FD_SETSIZE 1024

// 客户端信息
typedef struct _CLIENT_INFO {
    SOCKET      socket;
    char        ip[32];
    int         port;
    DWORD       connectTime;
} CLIENT_INFO;

// 服务器上下文
typedef struct _SERVER_CONTEXT {
    SOCKET          listenSocket;
    CLIENT_INFO     clients[FD_SETSIZE];
    int             clientCount;
    BOOL            running;
} SERVER_CONTEXT;

// 初始化服务器
BOOL ServerInit(SERVER_CONTEXT* ctx, int port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    ctx->listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->listenSocket == INVALID_SOCKET) {
        return FALSE;
    }
    
    // 设置地址重用
    int optval = 1;
    setsockopt(ctx->listenSocket, SOL_SOCKET, SO_REUSEADDR, 
               (char*)&optval, sizeof(optval));
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(ctx->listenSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(ctx->listenSocket);
        return FALSE;
    }
    
    if (listen(ctx->listenSocket, SOMAXCONN) != 0) {
        closesocket(ctx->listenSocket);
        return FALSE;
    }
    
    ctx->clientCount = 0;
    ctx->running = TRUE;
    
    printf("[+] 服务器启动，监听端口: %d\n", port);
    
    return TRUE;
}

// 添加客户端
BOOL AddClient(SERVER_CONTEXT* ctx, SOCKET socket, 
               const char* ip, int port) {
    if (ctx->clientCount >= FD_SETSIZE - 1) {
        return FALSE;
    }
    
    CLIENT_INFO* client = &ctx->clients[ctx->clientCount];
    client->socket = socket;
    strncpy(client->ip, ip, sizeof(client->ip));
    client->port = port;
    client->connectTime = GetTickCount();
    
    ctx->clientCount++;
    
    printf("[+] 新客户端连接: %s:%d (当前: %d)\n", 
           ip, port, ctx->clientCount);
    
    return TRUE;
}

// 移除客户端
void RemoveClient(SERVER_CONTEXT* ctx, int index) {
    if (index < 0 || index >= ctx->clientCount) {
        return;
    }
    
    CLIENT_INFO* client = &ctx->clients[index];
    printf("[-] 客户端断开: %s:%d\n", client->ip, client->port);
    
    closesocket(client->socket);
    
    // 移动后面的客户端
    for (int i = index; i < ctx->clientCount - 1; i++) {
        ctx->clients[i] = ctx->clients[i + 1];
    }
    
    ctx->clientCount--;
}

// 处理客户端消息
void HandleClientMessage(SERVER_CONTEXT* ctx, int index) {
    CLIENT_INFO* client = &ctx->clients[index];
    char buffer[4096] = {0};
    
    int recvLen = recv(client->socket, buffer, sizeof(buffer) - 1, 0);
    
    if (recvLen <= 0) {
        // 连接断开
        RemoveClient(ctx, index);
        return;
    }
    
    printf("[%s:%d] %s\n", client->ip, client->port, buffer);
    
    // 回显消息
    char response[4096];
    sprintf(response, "Echo: %s", buffer);
    send(client->socket, response, strlen(response), 0);
}

// 主循环 - select模型
void ServerRun(SERVER_CONTEXT* ctx) {
    fd_set readfds;
    struct timeval timeout;
    
    while (ctx->running) {
        // 每次循环都要重新设置fd_set
        FD_ZERO(&readfds);
        
        // 添加监听套接字
        FD_SET(ctx->listenSocket, &readfds);
        
        // 添加所有客户端套接字
        for (int i = 0; i < ctx->clientCount; i++) {
            FD_SET(ctx->clients[i].socket, &readfds);
        }
        
        // 设置超时
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        // 调用select
        int result = select(0, &readfds, NULL, NULL, &timeout);
        
        if (result == SOCKET_ERROR) {
            printf("[-] select错误: %d\n", WSAGetLastError());
            break;
        }
        
        if (result == 0) {
            // 超时，可以做一些周期性工作
            continue;
        }
        
        // 检查是否有新连接
        if (FD_ISSET(ctx->listenSocket, &readfds)) {
            struct sockaddr_in clientAddr;
            int addrLen = sizeof(clientAddr);
            
            SOCKET clientSocket = accept(ctx->listenSocket, 
                                        (struct sockaddr*)&clientAddr, 
                                        &addrLen);
            
            if (clientSocket != INVALID_SOCKET) {
                char* ip = inet_ntoa(clientAddr.sin_addr);
                int port = ntohs(clientAddr.sin_port);
                
                if (!AddClient(ctx, clientSocket, ip, port)) {
                    printf("[-] 客户端已满，拒绝连接\n");
                    closesocket(clientSocket);
                }
            }
        }
        
        // 检查客户端数据（倒序遍历，方便删除）
        for (int i = ctx->clientCount - 1; i >= 0; i--) {
            if (FD_ISSET(ctx->clients[i].socket, &readfds)) {
                HandleClientMessage(ctx, i);
            }
        }
    }
}

// 停止服务器
void ServerStop(SERVER_CONTEXT* ctx) {
    ctx->running = FALSE;
    
    // 关闭所有客户端
    for (int i = 0; i < ctx->clientCount; i++) {
        closesocket(ctx->clients[i].socket);
    }
    
    closesocket(ctx->listenSocket);
    WSACleanup();
}
```

### 带写事件和超时检测的select服务器

```c
// 发送缓冲区
typedef struct _SEND_BUFFER {
    char    data[8192];
    int     length;
    int     offset;     // 已发送偏移
} SEND_BUFFER;

// 扩展客户端信息
typedef struct _CLIENT_INFO_EX {
    SOCKET          socket;
    char            ip[32];
    int             port;
    DWORD           lastActiveTime;     // 最后活动时间
    SEND_BUFFER     sendBuffer;         // 待发送数据
    BOOL            hasPendingSend;     // 有待发送数据
} CLIENT_INFO_EX;

// 超时检测和清理
void CheckClientTimeout(SERVER_CONTEXT_EX* ctx, DWORD timeout) {
    DWORD now = GetTickCount();
    
    for (int i = ctx->clientCount - 1; i >= 0; i--) {
        CLIENT_INFO_EX* client = &ctx->clients[i];
        
        if (now - client->lastActiveTime > timeout) {
            printf("[!] 客户端超时: %s:%d\n", client->ip, client->port);
            RemoveClientEx(ctx, i);
        }
    }
}

// 带写事件的select主循环
void ServerRunEx(SERVER_CONTEXT_EX* ctx) {
    fd_set readfds, writefds;
    struct timeval timeout;
    
    while (ctx->running) {
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        
        FD_SET(ctx->listenSocket, &readfds);
        
        for (int i = 0; i < ctx->clientCount; i++) {
            CLIENT_INFO_EX* client = &ctx->clients[i];
            
            // 总是检查可读
            FD_SET(client->socket, &readfds);
            
            // 有待发送数据时检查可写
            if (client->hasPendingSend) {
                FD_SET(client->socket, &writefds);
            }
        }
        
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        
        int result = select(0, &readfds, &writefds, NULL, &timeout);
        
        if (result == SOCKET_ERROR) {
            break;
        }
        
        if (result == 0) {
            // 超时，检查客户端活跃状态
            CheckClientTimeout(ctx, 60000);  // 60秒超时
            continue;
        }
        
        // 处理新连接
        if (FD_ISSET(ctx->listenSocket, &readfds)) {
            // ... 接受新连接
        }
        
        // 处理客户端事件
        for (int i = ctx->clientCount - 1; i >= 0; i--) {
            CLIENT_INFO_EX* client = &ctx->clients[i];
            
            // 处理可读
            if (FD_ISSET(client->socket, &readfds)) {
                client->lastActiveTime = GetTickCount();
                HandleClientRead(ctx, i);
            }
            
            // 处理可写
            if (FD_ISSET(client->socket, &writefds)) {
                HandleClientWrite(ctx, i);
            }
        }
    }
}

// 处理写事件
void HandleClientWrite(SERVER_CONTEXT_EX* ctx, int index) {
    CLIENT_INFO_EX* client = &ctx->clients[index];
    SEND_BUFFER* buf = &client->sendBuffer;
    
    int remaining = buf->length - buf->offset;
    if (remaining <= 0) {
        client->hasPendingSend = FALSE;
        return;
    }
    
    int sent = send(client->socket, 
                   buf->data + buf->offset, 
                   remaining, 
                   0);
    
    if (sent > 0) {
        buf->offset += sent;
        
        if (buf->offset >= buf->length) {
            // 发送完成
            client->hasPendingSend = FALSE;
            buf->offset = 0;
            buf->length = 0;
        }
    }
}

// 异步发送（不阻塞）
BOOL SendToClient(CLIENT_INFO_EX* client, const void* data, int length) {
    SEND_BUFFER* buf = &client->sendBuffer;
    
    // 检查缓冲区空间
    if (buf->length + length > sizeof(buf->data)) {
        return FALSE;
    }
    
    memcpy(buf->data + buf->length, data, length);
    buf->length += length;
    client->hasPendingSend = TRUE;
    
    return TRUE;
}
```

### C2服务器 - select模型

```c
// 消息类型
#define MSG_HEARTBEAT       1
#define MSG_COMMAND         2
#define MSG_RESULT          3
#define MSG_FILE_UPLOAD     4
#define MSG_FILE_DOWNLOAD   5

// Agent状态
typedef struct _AGENT_INFO {
    SOCKET          socket;
    char            ip[32];
    int             port;
    char            hostname[64];
    char            username[64];
    DWORD           pid;
    DWORD           lastHeartbeat;
    BOOL            authenticated;
    SEND_BUFFER     sendQueue;
} AGENT_INFO;

// C2服务器上下文
typedef struct _C2_SERVER {
    SOCKET          listenSocket;
    AGENT_INFO      agents[FD_SETSIZE];
    int             agentCount;
    BOOL            running;
} C2_SERVER;

// 处理Agent消息
void HandleAgentMessage(C2_SERVER* server, int index, 
                        void* data, int length) {
    AGENT_INFO* agent = &server->agents[index];
    
    // 解析消息头
    MSG_HEADER* header = (MSG_HEADER*)data;
    void* payload = (char*)data + sizeof(MSG_HEADER);
    
    switch (header->Type) {
        case MSG_HEARTBEAT:
            agent->lastHeartbeat = GetTickCount();
            printf("[*] 心跳: %s (%s@%s)\n", 
                   agent->ip, agent->username, agent->hostname);
            break;
            
        case MSG_RESULT:
            // 处理命令执行结果
            printf("[+] 命令结果 from %s:\n%s\n", 
                   agent->ip, (char*)payload);
            break;
            
        case MSG_FILE_UPLOAD:
            // 处理文件上传
            HandleFileUpload(server, index, payload, 
                           header->Length - sizeof(MSG_HEADER));
            break;
    }
}

// 向Agent发送命令
BOOL SendCommandToAgent(AGENT_INFO* agent, const char* command) {
    int cmdLen = strlen(command);
    int totalLen = sizeof(MSG_HEADER) + cmdLen + 1;
    
    char* buffer = (char*)malloc(totalLen);
    MSG_HEADER* header = (MSG_HEADER*)buffer;
    
    header->Magic = 0xDEADBEEF;
    header->Type = MSG_COMMAND;
    header->Length = totalLen;
    header->Sequence = GetTickCount();
    
    strcpy(buffer + sizeof(MSG_HEADER), command);
    
    BOOL result = SendToClient((CLIENT_INFO_EX*)agent, buffer, totalLen);
    free(buffer);
    
    return result;
}

// 广播命令到所有Agent
void BroadcastCommand(C2_SERVER* server, const char* command) {
    printf("[*] 广播命令: %s\n", command);
    
    for (int i = 0; i < server->agentCount; i++) {
        if (server->agents[i].authenticated) {
            SendCommandToAgent(&server->agents[i], command);
        }
    }
}
```

### select模型性能测试

```c
// 简单的Echo服务器性能测试
void BenchmarkSelectServer(SERVER_CONTEXT* ctx) {
    DWORD startTime = GetTickCount();
    DWORD messageCount = 0;
    
    fd_set readfds;
    struct timeval timeout = {0, 1000};  // 1ms超时
    
    while (ctx->running) {
        FD_ZERO(&readfds);
        FD_SET(ctx->listenSocket, &readfds);
        
        for (int i = 0; i < ctx->clientCount; i++) {
            FD_SET(ctx->clients[i].socket, &readfds);
        }
        
        int result = select(0, &readfds, NULL, NULL, &timeout);
        
        if (result > 0) {
            // 处理事件
            for (int i = ctx->clientCount - 1; i >= 0; i--) {
                if (FD_ISSET(ctx->clients[i].socket, &readfds)) {
                    char buffer[1024];
                    int len = recv(ctx->clients[i].socket, 
                                  buffer, sizeof(buffer), 0);
                    
                    if (len > 0) {
                        send(ctx->clients[i].socket, buffer, len, 0);
                        messageCount++;
                    }
                }
            }
        }
        
        // 每秒统计
        DWORD elapsed = GetTickCount() - startTime;
        if (elapsed >= 1000) {
            printf("[Stats] 消息/秒: %lu, 客户端数: %d\n", 
                   messageCount, ctx->clientCount);
            messageCount = 0;
            startTime = GetTickCount();
        }
    }
}
```

### select模型优缺点

```c
/*
优点：
1. 跨平台，Windows/Linux都支持
2. 单线程处理多个连接，节省资源
3. 实现简单，容易理解

缺点：
1. FD_SETSIZE限制（默认64，最大1024）
2. 每次调用都要重新设置fd_set
3. 每次都要遍历所有套接字检查状态
4. 性能随连接数增加而线性下降

适用场景：
- 中小规模并发（<1000连接）
- 跨平台应用
- 简单的代理/网关
*/

int main() {
    SERVER_CONTEXT ctx = {0};
    
    if (!ServerInit(&ctx, 8888)) {
        printf("服务器启动失败\n");
        return 1;
    }
    
    ServerRun(&ctx);
    ServerStop(&ctx);
    
    return 0;
}
```

## 课后作业

1. **实现聊天室服务器**
   - 支持多客户端连接
   - 消息广播功能
   - 私聊功能
   - 显示在线用户列表

2. **实现简单代理服务器**
   - HTTP代理功能
   - 支持CONNECT方法
   - 记录访问日志

3. **性能优化**
   - 扩大FD_SETSIZE
   - 实现高效的客户端管理
   - 添加内存池优化
