# 课时14：IOCP完成端口

## 课程目标

1. 理解IOCP的设计思想和工作原理
2. 掌握IOCP相关API的使用
3. 实现高性能IOCP服务器
4. 掌握IOCP在C2开发中的应用

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| IOCP | I/O Completion Port | I/O完成端口 |
| Completion Port | - | 内核对象，管理异步I/O完成通知 |
| Worker Thread | 工作线程 | 处理I/O完成通知的线程 |
| Completion Key | 完成键 | 关联套接字的标识数据 |
| Per-Handle Data | 句柄数据 | 与套接字关联的上下文 |
| Per-I/O Data | I/O数据 | 与每次I/O操作关联的上下文 |
| GetQueuedCompletionStatus | - | 获取完成通知的函数 |
| PostQueuedCompletionStatus | - | 投递自定义完成通知 |

## 使用工具

- Visual Studio 2022
- Process Explorer（查看I/O完成端口）
- Windows Performance Toolkit
- Intel VTune（性能分析）

## 技术原理

### IOCP工作原理

```
                    应用程序
                       |
    +------------------+------------------+
    |                  |                  |
 AcceptEx          工作线程池           PostRecv/Send
    |                  |                  |
    |              [Thread 1]             |
    |              [Thread 2]             |
    |              [Thread 3]             |
    |              [Thread 4]             |
    |                  |                  |
    +------------------+------------------+
                       |
              I/O完成端口 (IOCP)
                       |
    +------------------+------------------+
    |                  |                  |
  Socket 1         Socket 2           Socket 3
    |                  |                  |
    +------------------+------------------+
                       |
                    内核
           管理异步I/O，通知完成
```

### IOCP核心函数

```c
// 创建完成端口
HANDLE CreateIoCompletionPort(
    HANDLE FileHandle,              // 关联的句柄（INVALID_HANDLE_VALUE创建新端口）
    HANDLE ExistingCompletionPort,  // 已有的完成端口（NULL创建新端口）
    ULONG_PTR CompletionKey,        // 完成键
    DWORD NumberOfConcurrentThreads // 并发线程数（0=CPU核心数）
);

// 获取完成状态
BOOL GetQueuedCompletionStatus(
    HANDLE CompletionPort,          // 完成端口
    LPDWORD lpNumberOfBytesTransferred,  // 传输字节数
    PULONG_PTR lpCompletionKey,     // 完成键
    LPOVERLAPPED* lpOverlapped,     // 重叠结构
    DWORD dwMilliseconds            // 超时
);

// 获取多个完成状态（Vista+）
BOOL GetQueuedCompletionStatusEx(
    HANDLE CompletionPort,
    LPOVERLAPPED_ENTRY lpCompletionPortEntries,  // 输出数组
    ULONG ulCount,                  // 数组大小
    PULONG ulNumEntriesRemoved,     // 实际获取数量
    DWORD dwMilliseconds,
    BOOL fAlertable
);

// 投递自定义完成通知
BOOL PostQueuedCompletionStatus(
    HANDLE CompletionPort,
    DWORD dwNumberOfBytesTransferred,
    ULONG_PTR dwCompletionKey,
    LPOVERLAPPED lpOverlapped
);
```

## 代码实现

### IOCP服务器基础结构

```c
#include <winsock2.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// 操作类型
typedef enum _IO_OPERATION {
    IO_ACCEPT,
    IO_RECV,
    IO_SEND,
    IO_DISCONNECT
} IO_OPERATION;

// Per-Handle数据（每个套接字一个）
typedef struct _PER_HANDLE_DATA {
    SOCKET          socket;
    char            ip[32];
    int             port;
    DWORD           connectTime;
    volatile LONG   refCount;       // 引用计数
} PER_HANDLE_DATA, *PPER_HANDLE_DATA;

// Per-I/O数据（每次I/O操作一个）
typedef struct _PER_IO_DATA {
    WSAOVERLAPPED   overlapped;     // 必须是第一个成员
    SOCKET          socket;
    WSABUF          wsabuf;
    char            buffer[4096];
    IO_OPERATION    operation;
    PPER_HANDLE_DATA handleData;
} PER_IO_DATA, *PPER_IO_DATA;

// IOCP服务器
typedef struct _IOCP_SERVER {
    HANDLE          completionPort;
    SOCKET          listenSocket;
    HANDLE          workerThreads[16];
    int             threadCount;
    volatile BOOL   running;
    
    // AcceptEx相关
    LPFN_ACCEPTEX               AcceptEx;
    LPFN_GETACCEPTEXSOCKADDRS   GetAcceptExSockaddrs;
} IOCP_SERVER, *PIOCP_SERVER;

// 全局服务器实例
IOCP_SERVER g_Server = {0};
```

### 加载扩展函数

```c
// 加载AcceptEx等扩展函数
BOOL LoadExtensionFunctions(SOCKET socket) {
    GUID guidAcceptEx = WSAID_ACCEPTEX;
    GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
    DWORD bytes;
    
    // 加载AcceptEx
    if (WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guidAcceptEx, sizeof(guidAcceptEx),
                 &g_Server.AcceptEx, sizeof(g_Server.AcceptEx),
                 &bytes, NULL, NULL) == SOCKET_ERROR) {
        return FALSE;
    }
    
    // 加载GetAcceptExSockaddrs
    if (WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER,
                 &guidGetAcceptExSockaddrs, sizeof(guidGetAcceptExSockaddrs),
                 &g_Server.GetAcceptExSockaddrs, 
                 sizeof(g_Server.GetAcceptExSockaddrs),
                 &bytes, NULL, NULL) == SOCKET_ERROR) {
        return FALSE;
    }
    
    return TRUE;
}
```

### 创建Per-Handle和Per-I/O数据

```c
// 创建Per-Handle数据
PPER_HANDLE_DATA CreatePerHandleData(SOCKET socket, 
                                      const char* ip, int port) {
    PPER_HANDLE_DATA data = (PPER_HANDLE_DATA)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PER_HANDLE_DATA)
    );
    
    if (data) {
        data->socket = socket;
        strncpy(data->ip, ip, sizeof(data->ip));
        data->port = port;
        data->connectTime = GetTickCount();
        data->refCount = 1;
    }
    
    return data;
}

// 释放Per-Handle数据
void ReleasePerHandleData(PPER_HANDLE_DATA data) {
    if (InterlockedDecrement(&data->refCount) == 0) {
        HeapFree(GetProcessHeap(), 0, data);
    }
}

// 创建Per-I/O数据
PPER_IO_DATA CreatePerIoData(IO_OPERATION op, PPER_HANDLE_DATA handleData) {
    PPER_IO_DATA data = (PPER_IO_DATA)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PER_IO_DATA)
    );
    
    if (data) {
        data->operation = op;
        data->handleData = handleData;
        data->wsabuf.buf = data->buffer;
        data->wsabuf.len = sizeof(data->buffer);
        
        if (handleData) {
            data->socket = handleData->socket;
            InterlockedIncrement(&handleData->refCount);
        }
    }
    
    return data;
}

// 释放Per-I/O数据
void FreePerIoData(PPER_IO_DATA data) {
    if (data->handleData) {
        ReleasePerHandleData(data->handleData);
    }
    HeapFree(GetProcessHeap(), 0, data);
}
```

### 投递AcceptEx

```c
// 投递AcceptEx请求
BOOL PostAcceptEx(void) {
    // 创建接受套接字
    SOCKET acceptSocket = WSASocket(AF_INET, SOCK_STREAM, 0,
                                    NULL, 0, WSA_FLAG_OVERLAPPED);
    
    if (acceptSocket == INVALID_SOCKET) {
        return FALSE;
    }
    
    // 创建Per-I/O数据
    PPER_IO_DATA ioData = CreatePerIoData(IO_ACCEPT, NULL);
    if (!ioData) {
        closesocket(acceptSocket);
        return FALSE;
    }
    
    ioData->socket = acceptSocket;
    
    // 调用AcceptEx
    DWORD bytesReceived;
    BOOL result = g_Server.AcceptEx(
        g_Server.listenSocket,
        acceptSocket,
        ioData->buffer,         // 接收第一批数据
        0,                      // 0表示不接收数据，只接受连接
        sizeof(SOCKADDR_IN) + 16,
        sizeof(SOCKADDR_IN) + 16,
        &bytesReceived,
        &ioData->overlapped
    );
    
    if (!result && WSAGetLastError() != ERROR_IO_PENDING) {
        closesocket(acceptSocket);
        FreePerIoData(ioData);
        return FALSE;
    }
    
    return TRUE;
}
```

### 投递Recv和Send

```c
// 投递接收请求
BOOL PostRecv(PPER_HANDLE_DATA handleData) {
    PPER_IO_DATA ioData = CreatePerIoData(IO_RECV, handleData);
    if (!ioData) {
        return FALSE;
    }
    
    DWORD flags = 0;
    DWORD bytesRecv;
    
    int result = WSARecv(
        handleData->socket,
        &ioData->wsabuf,
        1,
        &bytesRecv,
        &flags,
        &ioData->overlapped,
        NULL
    );
    
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        FreePerIoData(ioData);
        return FALSE;
    }
    
    return TRUE;
}

// 投递发送请求
BOOL PostSend(PPER_HANDLE_DATA handleData, const char* data, int len) {
    PPER_IO_DATA ioData = CreatePerIoData(IO_SEND, handleData);
    if (!ioData) {
        return FALSE;
    }
    
    memcpy(ioData->buffer, data, len);
    ioData->wsabuf.len = len;
    
    DWORD bytesSent;
    
    int result = WSASend(
        handleData->socket,
        &ioData->wsabuf,
        1,
        &bytesSent,
        0,
        &ioData->overlapped,
        NULL
    );
    
    if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        FreePerIoData(ioData);
        return FALSE;
    }
    
    return TRUE;
}
```

### 工作线程

```c
// 工作线程函数
DWORD WINAPI WorkerThread(LPVOID param) {
    PIOCP_SERVER server = (PIOCP_SERVER)param;
    
    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;
    
    while (server->running) {
        BOOL result = GetQueuedCompletionStatus(
            server->completionPort,
            &bytesTransferred,
            &completionKey,
            &overlapped,
            INFINITE
        );
        
        // 检查退出信号
        if (completionKey == 0 && overlapped == NULL) {
            break;
        }
        
        PPER_IO_DATA ioData = CONTAINING_RECORD(
            overlapped, PER_IO_DATA, overlapped
        );
        
        if (!result) {
            // I/O失败
            DWORD err = GetLastError();
            printf("[-] I/O失败: %d\n", err);
            
            if (ioData->handleData) {
                closesocket(ioData->handleData->socket);
            }
            FreePerIoData(ioData);
            continue;
        }
        
        switch (ioData->operation) {
            case IO_ACCEPT:
                HandleAcceptComplete(ioData, bytesTransferred);
                break;
                
            case IO_RECV:
                HandleRecvComplete(ioData, bytesTransferred);
                break;
                
            case IO_SEND:
                HandleSendComplete(ioData, bytesTransferred);
                break;
        }
    }
    
    return 0;
}

// 处理AcceptEx完成
void HandleAcceptComplete(PPER_IO_DATA ioData, DWORD bytesTransferred) {
    SOCKET acceptSocket = ioData->socket;
    
    // 更新套接字属性
    setsockopt(acceptSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
               (char*)&g_Server.listenSocket, sizeof(SOCKET));
    
    // 获取地址信息
    SOCKADDR_IN *localAddr, *remoteAddr;
    int localLen, remoteLen;
    
    g_Server.GetAcceptExSockaddrs(
        ioData->buffer,
        0,
        sizeof(SOCKADDR_IN) + 16,
        sizeof(SOCKADDR_IN) + 16,
        (SOCKADDR**)&localAddr, &localLen,
        (SOCKADDR**)&remoteAddr, &remoteLen
    );
    
    char* ip = inet_ntoa(remoteAddr->sin_addr);
    int port = ntohs(remoteAddr->sin_port);
    
    printf("[+] 新连接: %s:%d\n", ip, port);
    
    // 创建Per-Handle数据
    PPER_HANDLE_DATA handleData = CreatePerHandleData(acceptSocket, ip, port);
    
    // 关联到完成端口
    CreateIoCompletionPort(
        (HANDLE)acceptSocket,
        g_Server.completionPort,
        (ULONG_PTR)handleData,
        0
    );
    
    // 投递接收请求
    PostRecv(handleData);
    
    // 释放Accept的I/O数据
    FreePerIoData(ioData);
    
    // 投递新的AcceptEx
    PostAcceptEx();
}

// 处理接收完成
void HandleRecvComplete(PPER_IO_DATA ioData, DWORD bytesTransferred) {
    PPER_HANDLE_DATA handleData = ioData->handleData;
    
    if (bytesTransferred == 0) {
        // 连接断开
        printf("[-] 断开: %s:%d\n", handleData->ip, handleData->port);
        closesocket(handleData->socket);
        FreePerIoData(ioData);
        return;
    }
    
    ioData->buffer[bytesTransferred] = '\0';
    printf("[%s:%d] %s\n", handleData->ip, handleData->port, ioData->buffer);
    
    // 回显
    char response[4096];
    int len = sprintf(response, "Echo: %s", ioData->buffer);
    
    PostSend(handleData, response, len);
    
    FreePerIoData(ioData);
}

// 处理发送完成
void HandleSendComplete(PPER_IO_DATA ioData, DWORD bytesTransferred) {
    PPER_HANDLE_DATA handleData = ioData->handleData;
    
    // 发送完成，继续接收
    PostRecv(handleData);
    
    FreePerIoData(ioData);
}
```

### 服务器初始化和运行

```c
// 初始化IOCP服务器
BOOL InitIOCPServer(int port, int threadCount) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    // 创建完成端口
    g_Server.completionPort = CreateIoCompletionPort(
        INVALID_HANDLE_VALUE, NULL, 0, 0
    );
    
    if (!g_Server.completionPort) {
        return FALSE;
    }
    
    // 创建监听套接字
    g_Server.listenSocket = WSASocket(
        AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED
    );
    
    if (g_Server.listenSocket == INVALID_SOCKET) {
        return FALSE;
    }
    
    // 加载扩展函数
    if (!LoadExtensionFunctions(g_Server.listenSocket)) {
        return FALSE;
    }
    
    // 绑定和监听
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    bind(g_Server.listenSocket, (struct sockaddr*)&addr, sizeof(addr));
    listen(g_Server.listenSocket, SOMAXCONN);
    
    // 关联监听套接字到完成端口
    CreateIoCompletionPort(
        (HANDLE)g_Server.listenSocket,
        g_Server.completionPort,
        0,
        0
    );
    
    // 创建工作线程
    if (threadCount <= 0) {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        threadCount = sysInfo.dwNumberOfProcessors * 2;
    }
    
    g_Server.threadCount = threadCount;
    g_Server.running = TRUE;
    
    for (int i = 0; i < threadCount; i++) {
        g_Server.workerThreads[i] = CreateThread(
            NULL, 0, WorkerThread, &g_Server, 0, NULL
        );
    }
    
    // 预投递AcceptEx
    for (int i = 0; i < 10; i++) {
        PostAcceptEx();
    }
    
    printf("[+] IOCP服务器启动，端口: %d, 线程: %d\n", port, threadCount);
    
    return TRUE;
}

// 停止服务器
void StopIOCPServer(void) {
    g_Server.running = FALSE;
    
    // 发送退出信号给所有工作线程
    for (int i = 0; i < g_Server.threadCount; i++) {
        PostQueuedCompletionStatus(
            g_Server.completionPort, 0, 0, NULL
        );
    }
    
    // 等待工作线程结束
    WaitForMultipleObjects(
        g_Server.threadCount, 
        g_Server.workerThreads, 
        TRUE, 
        5000
    );
    
    closesocket(g_Server.listenSocket);
    CloseHandle(g_Server.completionPort);
    WSACleanup();
}
```

### C2服务器 - IOCP实现

```c
// C2 IOCP服务器
typedef struct _C2_IOCP_SERVER {
    IOCP_SERVER     base;
    
    // Agent管理
    PPER_HANDLE_DATA    agents[1024];
    int                 agentCount;
    CRITICAL_SECTION    agentLock;
} C2_IOCP_SERVER;

C2_IOCP_SERVER g_C2Server = {0};

// 处理Agent消息
void HandleAgentMessage(PPER_HANDLE_DATA agent, 
                        void* data, DWORD length) {
    MSG_HEADER* header = (MSG_HEADER*)data;
    void* payload = (char*)data + sizeof(MSG_HEADER);
    DWORD payloadLen = length - sizeof(MSG_HEADER);
    
    switch (header->Type) {
        case MSG_CHECKIN:
            HandleCheckin(agent, payload, payloadLen);
            break;
            
        case MSG_HEARTBEAT:
            printf("[Heartbeat] %s:%d\n", agent->ip, agent->port);
            break;
            
        case MSG_RESULT:
            HandleCommandResult(agent, payload, payloadLen);
            break;
            
        case MSG_FILE_DATA:
            HandleFileData(agent, payload, payloadLen);
            break;
    }
}

// 向Agent发送命令
BOOL SendCommandToAgent(PPER_HANDLE_DATA agent, 
                        DWORD cmdType, 
                        const void* data, 
                        DWORD dataLen) {
    DWORD totalLen = sizeof(MSG_HEADER) + dataLen;
    char* buffer = (char*)malloc(totalLen);
    
    MSG_HEADER* header = (MSG_HEADER*)buffer;
    header->Magic = 0xDEADBEEF;
    header->Type = cmdType;
    header->Length = totalLen;
    header->Sequence = GetTickCount();
    
    if (data && dataLen > 0) {
        memcpy(buffer + sizeof(MSG_HEADER), data, dataLen);
    }
    
    BOOL result = PostSend(agent, buffer, totalLen);
    free(buffer);
    
    return result;
}

// 广播命令
void BroadcastCommand(DWORD cmdType, const void* data, DWORD dataLen) {
    EnterCriticalSection(&g_C2Server.agentLock);
    
    for (int i = 0; i < g_C2Server.agentCount; i++) {
        SendCommandToAgent(g_C2Server.agents[i], cmdType, data, dataLen);
    }
    
    LeaveCriticalSection(&g_C2Server.agentLock);
}

int main() {
    InitializeCriticalSection(&g_C2Server.agentLock);
    
    if (!InitIOCPServer(4444, 0)) {
        printf("服务器启动失败\n");
        return 1;
    }
    
    printf("按Enter键停止服务器...\n");
    getchar();
    
    StopIOCPServer();
    DeleteCriticalSection(&g_C2Server.agentLock);
    
    return 0;
}
```

## 课后作业

1. **实现连接池和内存池**
   - 预分配Per-I/O数据
   - 实现高效的对象复用
   - 减少内存分配开销

2. **实现零拷贝传输**
   - 使用TransmitFile
   - 使用TransmitPackets
   - 实现高效文件下发

3. **性能压力测试**
   - 测试最大连接数
   - 测试吞吐量
   - 对比其他I/O模型
