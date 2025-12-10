# 课时12：WSAEventSelect事件选择模型

## 课程目标

1. 理解事件对象驱动的I/O模型
2. 掌握WSAEventSelect和WSAWaitForMultipleEvents的使用
3. 实现高性能的事件驱动服务器
4. 对比三种选择模型的优缺点

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| WSAEVENT | WinSock Event | 网络事件对象 |
| WSAEventSelect | - | 将套接字与事件对象关联 |
| WSAWaitForMultipleEvents | - | 等待多个事件对象 |
| WSAEnumNetworkEvents | - | 枚举网络事件 |
| WSANETWORKEVENTS | - | 网络事件结构体 |
| WSA_MAXIMUM_WAIT_EVENTS | - | 最大等待事件数（64） |
| WSA_WAIT_EVENT_0 | - | 第一个事件触发的返回值 |
| WSA_WAIT_TIMEOUT | - | 等待超时返回值 |

## 使用工具

- Visual Studio 2022
- Process Explorer（查看事件对象）
- WinDbg（调试事件等待）
- Performance Monitor（性能监控）

## 技术原理

### WSAEventSelect工作原理

```
应用程序                          内核
    |                              |
    | WSAEventSelect(socket, event, ...)
    |----------------------------->|
    |                              | 关联套接字和事件
    |                              |
    | WSAWaitForMultipleEvents(...)
    |----------------------------->|
    |                              |
    |      【阻塞等待】             | 监控套接字
    |                              | 有事件时设置事件对象
    |                              |
    |<-- 返回触发的事件索引 ---------|
    |                              |
    | WSAEnumNetworkEvents(socket, event, &events)
    |----------------------------->|
    |                              | 返回具体事件
    |<-----------------------------|
    |                              |
    | 处理网络事件                  |
```

### 核心函数

```c
// 创建事件对象
WSAEVENT WSACreateEvent(void);

// 关闭事件对象
BOOL WSACloseEvent(WSAEVENT hEvent);

// 重置事件对象
BOOL WSAResetEvent(WSAEVENT hEvent);

// 设置事件对象
BOOL WSASetEvent(WSAEVENT hEvent);

// 关联套接字和事件
int WSAEventSelect(
    SOCKET s,
    WSAEVENT hEventObject,
    long lNetworkEvents      // 事件掩码：FD_READ | FD_WRITE | ...
);

// 等待多个事件
DWORD WSAWaitForMultipleEvents(
    DWORD cEvents,              // 事件数量
    const WSAEVENT* lphEvents,  // 事件数组
    BOOL fWaitAll,              // FALSE=任一触发即返回
    DWORD dwTimeout,            // 超时（毫秒）
    BOOL fAlertable             // 是否可警醒
);

// 枚举网络事件
int WSAEnumNetworkEvents(
    SOCKET s,
    WSAEVENT hEventObject,          // 事件对象
    LPWSANETWORKEVENTS lpNetworkEvents  // 输出事件信息
);

// 网络事件结构
typedef struct _WSANETWORKEVENTS {
    long lNetworkEvents;            // 事件掩码
    int  iErrorCode[FD_MAX_EVENTS]; // 每种事件的错误码
} WSANETWORKEVENTS;
```

## 代码实现

### 基于WSAEventSelect的服务器

```c
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// 最大连接数（受WSA_MAXIMUM_WAIT_EVENTS限制）
#define MAX_SOCKETS 63  // 留一个给监听套接字

// 套接字信息
typedef struct _SOCKET_INFO {
    SOCKET      socket;
    WSAEVENT    event;
    char        ip[32];
    int         port;
    char        recvBuffer[4096];
    int         recvLen;
    char        sendBuffer[4096];
    int         sendLen;
    int         sendOffset;
} SOCKET_INFO;

// 服务器上下文
typedef struct _EVENT_SERVER {
    SOCKET          listenSocket;
    WSAEVENT        listenEvent;
    SOCKET_INFO     sockets[MAX_SOCKETS];
    WSAEVENT        events[MAX_SOCKETS + 1];  // 包含监听事件
    int             socketCount;
    BOOL            running;
} EVENT_SERVER;

// 初始化服务器
BOOL ServerInit(EVENT_SERVER* server, int port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    // 创建监听套接字
    server->listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (server->listenSocket == INVALID_SOCKET) {
        return FALSE;
    }
    
    // 创建监听事件
    server->listenEvent = WSACreateEvent();
    if (server->listenEvent == WSA_INVALID_EVENT) {
        closesocket(server->listenSocket);
        return FALSE;
    }
    
    // 绑定和监听
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(server->listenSocket, 
            (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        return FALSE;
    }
    
    if (listen(server->listenSocket, SOMAXCONN) != 0) {
        return FALSE;
    }
    
    // 关联监听套接字和事件
    if (WSAEventSelect(server->listenSocket, server->listenEvent, 
                       FD_ACCEPT) == SOCKET_ERROR) {
        return FALSE;
    }
    
    server->socketCount = 0;
    server->running = TRUE;
    server->events[0] = server->listenEvent;
    
    printf("[+] 事件选择服务器启动，端口: %d\n", port);
    
    return TRUE;
}

// 添加客户端
int AddSocket(EVENT_SERVER* server, SOCKET socket, 
              const char* ip, int port) {
    if (server->socketCount >= MAX_SOCKETS) {
        printf("[-] 连接已满\n");
        return -1;
    }
    
    int index = server->socketCount;
    SOCKET_INFO* info = &server->sockets[index];
    
    // 创建事件对象
    info->event = WSACreateEvent();
    if (info->event == WSA_INVALID_EVENT) {
        return -1;
    }
    
    // 关联套接字和事件
    if (WSAEventSelect(socket, info->event, 
                       FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR) {
        WSACloseEvent(info->event);
        return -1;
    }
    
    info->socket = socket;
    strncpy(info->ip, ip, sizeof(info->ip));
    info->port = port;
    info->recvLen = 0;
    info->sendLen = 0;
    info->sendOffset = 0;
    
    // 添加到事件数组（索引0是监听事件）
    server->events[index + 1] = info->event;
    server->socketCount++;
    
    printf("[+] 客户端连接: %s:%d (#%d)\n", ip, port, index);
    
    return index;
}

// 移除客户端
void RemoveSocket(EVENT_SERVER* server, int index) {
    if (index < 0 || index >= server->socketCount) {
        return;
    }
    
    SOCKET_INFO* info = &server->sockets[index];
    
    printf("[-] 客户端断开: %s:%d\n", info->ip, info->port);
    
    closesocket(info->socket);
    WSACloseEvent(info->event);
    
    // 移动后面的元素
    for (int i = index; i < server->socketCount - 1; i++) {
        server->sockets[i] = server->sockets[i + 1];
        server->events[i + 1] = server->events[i + 2];
    }
    
    server->socketCount--;
}

// 处理接受连接
void HandleAccept(EVENT_SERVER* server) {
    WSANETWORKEVENTS events;
    
    WSAEnumNetworkEvents(server->listenSocket, 
                         server->listenEvent, &events);
    
    if (events.lNetworkEvents & FD_ACCEPT) {
        if (events.iErrorCode[FD_ACCEPT_BIT]) {
            printf("[-] Accept错误: %d\n", 
                   events.iErrorCode[FD_ACCEPT_BIT]);
            return;
        }
        
        struct sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(server->listenSocket,
                                    (struct sockaddr*)&clientAddr,
                                    &addrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            char* ip = inet_ntoa(clientAddr.sin_addr);
            int port = ntohs(clientAddr.sin_port);
            
            if (AddSocket(server, clientSocket, ip, port) < 0) {
                closesocket(clientSocket);
            }
        }
    }
}

// 处理客户端事件
void HandleClient(EVENT_SERVER* server, int index) {
    SOCKET_INFO* info = &server->sockets[index];
    WSANETWORKEVENTS events;
    
    // 获取并清除网络事件
    if (WSAEnumNetworkEvents(info->socket, info->event, 
                             &events) == SOCKET_ERROR) {
        RemoveSocket(server, index);
        return;
    }
    
    // 处理读事件
    if (events.lNetworkEvents & FD_READ) {
        if (events.iErrorCode[FD_READ_BIT]) {
            RemoveSocket(server, index);
            return;
        }
        
        int len = recv(info->socket, 
                      info->recvBuffer + info->recvLen,
                      sizeof(info->recvBuffer) - info->recvLen - 1,
                      0);
        
        if (len <= 0) {
            RemoveSocket(server, index);
            return;
        }
        
        info->recvLen += len;
        info->recvBuffer[info->recvLen] = '\0';
        
        printf("[%s:%d] %s\n", info->ip, info->port, info->recvBuffer);
        
        // 准备回显
        sprintf(info->sendBuffer, "Echo: %s", info->recvBuffer);
        info->sendLen = strlen(info->sendBuffer);
        info->sendOffset = 0;
        info->recvLen = 0;
    }
    
    // 处理写事件
    if (events.lNetworkEvents & FD_WRITE) {
        if (events.iErrorCode[FD_WRITE_BIT]) {
            RemoveSocket(server, index);
            return;
        }
        
        int remaining = info->sendLen - info->sendOffset;
        if (remaining > 0) {
            int sent = send(info->socket,
                           info->sendBuffer + info->sendOffset,
                           remaining, 0);
            
            if (sent > 0) {
                info->sendOffset += sent;
                if (info->sendOffset >= info->sendLen) {
                    info->sendLen = 0;
                    info->sendOffset = 0;
                }
            }
        }
    }
    
    // 处理关闭事件
    if (events.lNetworkEvents & FD_CLOSE) {
        RemoveSocket(server, index);
    }
}

// 服务器主循环
void ServerRun(EVENT_SERVER* server) {
    while (server->running) {
        // 等待事件（包含监听事件 + 客户端事件）
        DWORD eventCount = server->socketCount + 1;
        
        DWORD result = WSAWaitForMultipleEvents(
            eventCount,
            server->events,
            FALSE,      // 任一事件触发即返回
            1000,       // 1秒超时
            FALSE       // 不可警醒
        );
        
        if (result == WSA_WAIT_FAILED) {
            printf("[-] 等待失败: %d\n", WSAGetLastError());
            break;
        }
        
        if (result == WSA_WAIT_TIMEOUT) {
            // 超时，可做周期性任务
            continue;
        }
        
        // 计算触发的事件索引
        int eventIndex = result - WSA_WAIT_EVENT_0;
        
        if (eventIndex == 0) {
            // 监听套接字事件
            HandleAccept(server);
        } else {
            // 客户端事件（索引-1因为事件数组索引0是监听事件）
            HandleClient(server, eventIndex - 1);
        }
        
        // 检查其他可能触发的事件
        for (int i = eventIndex + 1; i < (int)eventCount; i++) {
            result = WSAWaitForMultipleEvents(1, &server->events[i],
                                              TRUE, 0, FALSE);
            if (result == WSA_WAIT_EVENT_0) {
                if (i == 0) {
                    HandleAccept(server);
                } else {
                    HandleClient(server, i - 1);
                }
            }
        }
    }
}

// 停止服务器
void ServerStop(EVENT_SERVER* server) {
    server->running = FALSE;
    
    // 关闭所有客户端
    while (server->socketCount > 0) {
        RemoveSocket(server, 0);
    }
    
    closesocket(server->listenSocket);
    WSACloseEvent(server->listenEvent);
    WSACleanup();
}
```

### 突破64连接限制的多线程方案

```c
// 工作线程上下文
typedef struct _WORKER_THREAD {
    EVENT_SERVER    server;
    HANDLE          thread;
    DWORD           threadId;
} WORKER_THREAD;

// 多线程服务器
typedef struct _MULTITHREAD_SERVER {
    SOCKET          listenSocket;
    WORKER_THREAD   workers[16];        // 16个工作线程
    int             workerCount;
    int             nextWorker;         // 轮询分配
    BOOL            running;
} MULTITHREAD_SERVER;

// 工作线程函数
DWORD WINAPI WorkerThread(LPVOID param) {
    WORKER_THREAD* worker = (WORKER_THREAD*)param;
    
    while (worker->server.running) {
        DWORD count = worker->server.socketCount;
        if (count == 0) {
            Sleep(10);
            continue;
        }
        
        DWORD result = WSAWaitForMultipleEvents(
            count,
            worker->server.events,
            FALSE,
            100,
            FALSE
        );
        
        if (result >= WSA_WAIT_EVENT_0 && 
            result < WSA_WAIT_EVENT_0 + count) {
            int index = result - WSA_WAIT_EVENT_0;
            HandleClient(&worker->server, index);
        }
    }
    
    return 0;
}

// 分配连接到工作线程
void DispatchConnection(MULTITHREAD_SERVER* server, 
                        SOCKET clientSocket,
                        const char* ip, int port) {
    // 轮询选择工作线程
    WORKER_THREAD* worker = &server->workers[server->nextWorker];
    server->nextWorker = (server->nextWorker + 1) % server->workerCount;
    
    // 添加到工作线程
    AddSocket(&worker->server, clientSocket, ip, port);
}

// 初始化多线程服务器
BOOL InitMultiThreadServer(MULTITHREAD_SERVER* server, 
                           int port, int threadCount) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    // 创建监听套接字
    server->listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    bind(server->listenSocket, (struct sockaddr*)&addr, sizeof(addr));
    listen(server->listenSocket, SOMAXCONN);
    
    // 创建工作线程
    server->workerCount = threadCount;
    server->nextWorker = 0;
    server->running = TRUE;
    
    for (int i = 0; i < threadCount; i++) {
        WORKER_THREAD* worker = &server->workers[i];
        worker->server.socketCount = 0;
        worker->server.running = TRUE;
        
        worker->thread = CreateThread(
            NULL, 0, WorkerThread, worker, 0, &worker->threadId
        );
    }
    
    printf("[+] 多线程服务器启动，%d个工作线程\n", threadCount);
    
    return TRUE;
}

// 主线程接受连接
void AcceptLoop(MULTITHREAD_SERVER* server) {
    while (server->running) {
        struct sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(server->listenSocket,
                                    (struct sockaddr*)&clientAddr,
                                    &addrLen);
        
        if (clientSocket != INVALID_SOCKET) {
            char* ip = inet_ntoa(clientAddr.sin_addr);
            int port = ntohs(clientAddr.sin_port);
            
            DispatchConnection(server, clientSocket, ip, port);
        }
    }
}
```

### 三种选择模型对比

```c
/*
+-------------------+-------------+----------------+----------------+
| 特性              | select      | WSAAsyncSelect | WSAEventSelect |
+-------------------+-------------+----------------+----------------+
| 最大连接数        | 64(可扩展)  | 无限制         | 64(需多线程)   |
| 线程模型          | 单线程阻塞  | 消息驱动       | 事件驱动       |
| 需要窗口          | 否          | 是             | 否             |
| 通知机制          | 轮询        | Windows消息    | 事件对象       |
| 跨平台            | 是          | 否             | 否             |
| 性能              | 中等        | 较低           | 较高           |
| 适用场景          | 简单服务器  | GUI程序        | 高性能服务器   |
+-------------------+-------------+----------------+----------------+

使用建议：
- 跨平台需求 → select
- GUI程序 → WSAAsyncSelect  
- Windows高性能服务器 → WSAEventSelect或IOCP
*/
```

## 课后作业

1. **实现连接池管理**
   - 预创建事件对象池
   - 高效的连接分配和回收
   - 支持连接复用

2. **实现多线程事件服务器**
   - 使用多个工作线程
   - 实现负载均衡
   - 突破64连接限制

3. **添加连接超时检测**
   - 记录最后活动时间
   - 定期检查超时连接
   - 自动清理僵尸连接
