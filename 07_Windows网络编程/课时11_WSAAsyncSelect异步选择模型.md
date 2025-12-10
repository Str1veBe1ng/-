# 课时11：WSAAsyncSelect异步选择模型

## 课程目标

1. 理解Windows消息驱动的I/O模型
2. 掌握WSAAsyncSelect函数的使用
3. 实现基于消息的异步网络服务器
4. 了解WSAAsyncSelect与GUI程序的结合

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| WSAAsyncSelect | Windows Socket Async Select | 异步选择函数 |
| WM_USER | User Message | 用户自定义消息起始值 |
| FD_READ | - | 数据可读事件 |
| FD_WRITE | - | 数据可写事件 |
| FD_ACCEPT | - | 连接请求事件 |
| FD_CONNECT | - | 连接完成事件 |
| FD_CLOSE | - | 连接关闭事件 |
| WSAGETSELECTEVENT | - | 获取事件类型宏 |
| WSAGETSELECTERROR | - | 获取错误码宏 |

## 使用工具

- Visual Studio 2022
- Spy++（监控窗口消息）
- Process Monitor
- Resource Hacker（查看窗口资源）

## 技术原理

### WSAAsyncSelect工作原理

```
                    应用程序
                       |
    +------------------+------------------+
    |                  |                  |
  窗口过程          消息循环            网络I/O
    |                  |                  |
    |<-- WM_SOCKET ----+<-- PostMessage --|
    |                  |                  |
 处理网络事件      GetMessage         WSAAsyncSelect
    |                  |           注册事件通知
    |                  |                  |
    +------------------+------------------+
                       |
                    内核
              监控套接字状态
              有事件时发送消息
```

### WSAAsyncSelect函数

```c
int WSAAsyncSelect(
    SOCKET s,           // 套接字
    HWND hWnd,          // 接收消息的窗口句柄
    u_int wMsg,         // 自定义消息ID
    long lEvent         // 要监听的事件
);

// 事件标志（可组合）
#define FD_READ      0x01   // 可读
#define FD_WRITE     0x02   // 可写
#define FD_OOB       0x04   // 带外数据
#define FD_ACCEPT    0x08   // 有连接请求
#define FD_CONNECT   0x10   // 连接完成
#define FD_CLOSE     0x20   // 连接关闭
#define FD_QOS       0x40   // QoS变化
#define FD_GROUP_QOS 0x80   // 组QoS变化

// 获取事件和错误
#define WSAGETSELECTEVENT(lParam) LOWORD(lParam)
#define WSAGETSELECTERROR(lParam) HIWORD(lParam)
```

## 代码实现

### 基于WSAAsyncSelect的服务器

```c
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// 自定义消息
#define WM_SOCKET (WM_USER + 100)

// 最大客户端数
#define MAX_CLIENTS 256

// 客户端信息
typedef struct _ASYNC_CLIENT {
    SOCKET  socket;
    char    ip[32];
    int     port;
    char    recvBuffer[4096];
    int     recvLen;
    char    sendBuffer[4096];
    int     sendLen;
    int     sendOffset;
} ASYNC_CLIENT;

// 服务器上下文
typedef struct _ASYNC_SERVER {
    HWND            hWnd;               // 窗口句柄
    SOCKET          listenSocket;       // 监听套接字
    ASYNC_CLIENT    clients[MAX_CLIENTS];
    int             clientCount;
} ASYNC_SERVER;

// 全局服务器实例
ASYNC_SERVER g_Server = {0};

// 查找客户端
int FindClient(SOCKET socket) {
    for (int i = 0; i < g_Server.clientCount; i++) {
        if (g_Server.clients[i].socket == socket) {
            return i;
        }
    }
    return -1;
}

// 添加客户端
int AddClient(SOCKET socket, const char* ip, int port) {
    if (g_Server.clientCount >= MAX_CLIENTS) {
        return -1;
    }
    
    int index = g_Server.clientCount++;
    ASYNC_CLIENT* client = &g_Server.clients[index];
    
    client->socket = socket;
    strncpy(client->ip, ip, sizeof(client->ip));
    client->port = port;
    client->recvLen = 0;
    client->sendLen = 0;
    client->sendOffset = 0;
    
    printf("[+] 客户端连接: %s:%d (#%d)\n", ip, port, index);
    
    return index;
}

// 移除客户端
void RemoveClient(int index) {
    if (index < 0 || index >= g_Server.clientCount) {
        return;
    }
    
    ASYNC_CLIENT* client = &g_Server.clients[index];
    printf("[-] 客户端断开: %s:%d\n", client->ip, client->port);
    
    closesocket(client->socket);
    
    // 移动后面的元素
    for (int i = index; i < g_Server.clientCount - 1; i++) {
        g_Server.clients[i] = g_Server.clients[i + 1];
    }
    g_Server.clientCount--;
}

// 处理FD_ACCEPT事件
void OnAccept(SOCKET listenSocket) {
    struct sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);
    
    SOCKET clientSocket = accept(listenSocket, 
                                (struct sockaddr*)&clientAddr, 
                                &addrLen);
    
    if (clientSocket == INVALID_SOCKET) {
        return;
    }
    
    char* ip = inet_ntoa(clientAddr.sin_addr);
    int port = ntohs(clientAddr.sin_port);
    
    // 为新客户端注册事件
    if (WSAAsyncSelect(clientSocket, g_Server.hWnd, 
                       WM_SOCKET, 
                       FD_READ | FD_WRITE | FD_CLOSE) == SOCKET_ERROR) {
        closesocket(clientSocket);
        return;
    }
    
    if (AddClient(clientSocket, ip, port) < 0) {
        closesocket(clientSocket);
    }
}

// 处理FD_READ事件
void OnRead(SOCKET socket) {
    int index = FindClient(socket);
    if (index < 0) return;
    
    ASYNC_CLIENT* client = &g_Server.clients[index];
    
    // 读取数据
    int available = sizeof(client->recvBuffer) - client->recvLen - 1;
    if (available <= 0) {
        // 缓冲区满
        client->recvLen = 0;
        available = sizeof(client->recvBuffer) - 1;
    }
    
    int recvLen = recv(socket, 
                      client->recvBuffer + client->recvLen, 
                      available, 
                      0);
    
    if (recvLen <= 0) {
        RemoveClient(index);
        return;
    }
    
    client->recvLen += recvLen;
    client->recvBuffer[client->recvLen] = '\0';
    
    printf("[%s:%d] %s\n", client->ip, client->port, client->recvBuffer);
    
    // 准备回显
    sprintf(client->sendBuffer, "Echo: %s", client->recvBuffer);
    client->sendLen = strlen(client->sendBuffer);
    client->sendOffset = 0;
    
    // 清空接收缓冲区
    client->recvLen = 0;
    
    // 触发发送（可能需要等待FD_WRITE）
    OnWrite(socket);
}

// 处理FD_WRITE事件
void OnWrite(SOCKET socket) {
    int index = FindClient(socket);
    if (index < 0) return;
    
    ASYNC_CLIENT* client = &g_Server.clients[index];
    
    // 检查是否有数据要发送
    int remaining = client->sendLen - client->sendOffset;
    if (remaining <= 0) {
        return;
    }
    
    // 发送数据
    int sent = send(socket, 
                   client->sendBuffer + client->sendOffset, 
                   remaining, 
                   0);
    
    if (sent == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            RemoveClient(index);
        }
        return;
    }
    
    client->sendOffset += sent;
    
    // 检查是否发送完成
    if (client->sendOffset >= client->sendLen) {
        client->sendLen = 0;
        client->sendOffset = 0;
    }
}

// 处理FD_CLOSE事件
void OnClose(SOCKET socket) {
    int index = FindClient(socket);
    if (index >= 0) {
        RemoveClient(index);
    }
}

// 窗口过程
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_SOCKET: {
            SOCKET socket = (SOCKET)wParam;
            int event = WSAGETSELECTEVENT(lParam);
            int error = WSAGETSELECTERROR(lParam);
            
            if (error) {
                printf("[-] Socket错误: %d\n", error);
                int index = FindClient(socket);
                if (index >= 0) {
                    RemoveClient(index);
                }
                break;
            }
            
            switch (event) {
                case FD_ACCEPT:
                    OnAccept(socket);
                    break;
                case FD_READ:
                    OnRead(socket);
                    break;
                case FD_WRITE:
                    OnWrite(socket);
                    break;
                case FD_CLOSE:
                    OnClose(socket);
                    break;
            }
            break;
        }
        
        case WM_DESTROY:
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    
    return 0;
}

// 创建消息窗口
HWND CreateMessageWindow(HINSTANCE hInstance) {
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "AsyncSocketWindow";
    
    RegisterClass(&wc);
    
    // 创建不可见的消息窗口
    HWND hWnd = CreateWindow(
        wc.lpszClassName,
        "AsyncSocket Server",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        400, 300,
        NULL, NULL,
        hInstance,
        NULL
    );
    
    return hWnd;
}

// 初始化服务器
BOOL InitServer(HINSTANCE hInstance, int port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    // 创建窗口
    g_Server.hWnd = CreateMessageWindow(hInstance);
    if (!g_Server.hWnd) {
        return FALSE;
    }
    
    // 创建监听套接字
    g_Server.listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (g_Server.listenSocket == INVALID_SOCKET) {
        return FALSE;
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(g_Server.listenSocket, 
            (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(g_Server.listenSocket);
        return FALSE;
    }
    
    if (listen(g_Server.listenSocket, SOMAXCONN) != 0) {
        closesocket(g_Server.listenSocket);
        return FALSE;
    }
    
    // 注册异步事件
    if (WSAAsyncSelect(g_Server.listenSocket, g_Server.hWnd,
                       WM_SOCKET, FD_ACCEPT) == SOCKET_ERROR) {
        closesocket(g_Server.listenSocket);
        return FALSE;
    }
    
    printf("[+] 服务器启动，监听端口: %d\n", port);
    
    return TRUE;
}

// 主函数
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    // 分配控制台用于调试
    AllocConsole();
    freopen("CONOUT$", "w", stdout);
    
    if (!InitServer(hInstance, 8888)) {
        printf("服务器启动失败\n");
        return 1;
    }
    
    // 显示窗口（可选）
    ShowWindow(g_Server.hWnd, nCmdShow);
    UpdateWindow(g_Server.hWnd);
    
    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    closesocket(g_Server.listenSocket);
    WSACleanup();
    
    return 0;
}
```

### 控制台版本（仅消息窗口）

```c
// 无GUI的异步服务器
int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    // 使用HWND_MESSAGE创建纯消息窗口
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "AsyncServerClass";
    RegisterClass(&wc);
    
    // HWND_MESSAGE表示消息专用窗口
    g_Server.hWnd = CreateWindow(
        wc.lpszClassName,
        NULL,
        0,
        0, 0, 0, 0,
        HWND_MESSAGE,  // 消息专用窗口
        NULL,
        wc.hInstance,
        NULL
    );
    
    if (!g_Server.hWnd) {
        printf("创建消息窗口失败\n");
        return 1;
    }
    
    // 初始化监听套接字...
    g_Server.listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(8888);
    
    bind(g_Server.listenSocket, (struct sockaddr*)&addr, sizeof(addr));
    listen(g_Server.listenSocket, SOMAXCONN);
    
    WSAAsyncSelect(g_Server.listenSocket, g_Server.hWnd,
                   WM_SOCKET, FD_ACCEPT);
    
    printf("[+] 异步服务器启动，端口: 8888\n");
    
    // 消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}
```

### 异步客户端实现

```c
// 异步客户端
typedef struct _ASYNC_CLIENT_CTX {
    HWND    hWnd;
    SOCKET  socket;
    BOOL    connected;
    char    recvBuffer[4096];
    int     recvLen;
} ASYNC_CLIENT_CTX;

ASYNC_CLIENT_CTX g_Client = {0};

#define WM_CLIENT_SOCKET (WM_USER + 101)

// 客户端窗口过程
LRESULT CALLBACK ClientWndProc(HWND hWnd, UINT msg, 
                               WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CLIENT_SOCKET: {
            int event = WSAGETSELECTEVENT(lParam);
            int error = WSAGETSELECTERROR(lParam);
            
            if (error) {
                printf("[-] 连接错误: %d\n", error);
                g_Client.connected = FALSE;
                break;
            }
            
            switch (event) {
                case FD_CONNECT:
                    printf("[+] 连接成功\n");
                    g_Client.connected = TRUE;
                    break;
                    
                case FD_READ: {
                    int len = recv(g_Client.socket, 
                                  g_Client.recvBuffer, 
                                  sizeof(g_Client.recvBuffer) - 1, 
                                  0);
                    if (len > 0) {
                        g_Client.recvBuffer[len] = '\0';
                        printf("[服务器] %s\n", g_Client.recvBuffer);
                    }
                    break;
                }
                
                case FD_CLOSE:
                    printf("[-] 服务器断开连接\n");
                    g_Client.connected = FALSE;
                    break;
            }
            break;
        }
        
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// 异步连接服务器
BOOL AsyncConnect(const char* host, int port) {
    // 创建消息窗口
    WNDCLASS wc = {0};
    wc.lpfnWndProc = ClientWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "AsyncClientClass";
    RegisterClass(&wc);
    
    g_Client.hWnd = CreateWindow(
        wc.lpszClassName, NULL, 0,
        0, 0, 0, 0,
        HWND_MESSAGE, NULL, wc.hInstance, NULL
    );
    
    // 创建套接字
    g_Client.socket = socket(AF_INET, SOCK_STREAM, 0);
    
    // 注册异步事件
    WSAAsyncSelect(g_Client.socket, g_Client.hWnd,
                   WM_CLIENT_SOCKET,
                   FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE);
    
    // 异步连接（立即返回）
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(host);
    addr.sin_port = htons(port);
    
    int result = connect(g_Client.socket, 
                        (struct sockaddr*)&addr, sizeof(addr));
    
    // 异步模式下connect会返回错误WSAEWOULDBLOCK
    if (result == SOCKET_ERROR && 
        WSAGetLastError() != WSAEWOULDBLOCK) {
        return FALSE;
    }
    
    printf("[*] 正在连接 %s:%d ...\n", host, port);
    
    return TRUE;
}
```

### C2 Agent使用WSAAsyncSelect

```c
// C2 Agent异步通信模块
typedef struct _C2_AGENT_ASYNC {
    HWND        hWnd;
    SOCKET      socket;
    char        c2Host[256];
    int         c2Port;
    BOOL        connected;
    DWORD       reconnectInterval;
    DWORD       lastReconnectTime;
    
    // 缓冲区
    char        recvBuffer[8192];
    int         recvLen;
    char        sendBuffer[8192];
    int         sendLen;
    int         sendOffset;
} C2_AGENT_ASYNC;

C2_AGENT_ASYNC g_Agent = {0};

#define WM_C2_SOCKET (WM_USER + 200)
#define WM_RECONNECT (WM_USER + 201)

// C2 Agent窗口过程
LRESULT CALLBACK AgentWndProc(HWND hWnd, UINT msg, 
                              WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_C2_SOCKET: {
            int event = WSAGETSELECTEVENT(lParam);
            int error = WSAGETSELECTERROR(lParam);
            
            if (error) {
                g_Agent.connected = FALSE;
                // 安排重连
                SetTimer(hWnd, 1, g_Agent.reconnectInterval, NULL);
                break;
            }
            
            switch (event) {
                case FD_CONNECT:
                    OnAgentConnected();
                    break;
                case FD_READ:
                    OnAgentRecv();
                    break;
                case FD_WRITE:
                    OnAgentSend();
                    break;
                case FD_CLOSE:
                    OnAgentDisconnect();
                    break;
            }
            break;
        }
        
        case WM_TIMER:
            if (wParam == 1 && !g_Agent.connected) {
                KillTimer(hWnd, 1);
                AgentConnect();
            }
            break;
            
        default:
            return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// 处理连接成功
void OnAgentConnected(void) {
    g_Agent.connected = TRUE;
    printf("[+] C2连接成功\n");
    
    // 发送上线信息
    SendCheckin();
}

// 处理接收数据
void OnAgentRecv(void) {
    char buffer[4096];
    int len = recv(g_Agent.socket, buffer, sizeof(buffer), 0);
    
    if (len <= 0) {
        OnAgentDisconnect();
        return;
    }
    
    // 追加到接收缓冲区
    if (g_Agent.recvLen + len < sizeof(g_Agent.recvBuffer)) {
        memcpy(g_Agent.recvBuffer + g_Agent.recvLen, buffer, len);
        g_Agent.recvLen += len;
    }
    
    // 处理完整消息
    ProcessMessages();
}

// 处理断开连接
void OnAgentDisconnect(void) {
    printf("[-] C2连接断开\n");
    
    closesocket(g_Agent.socket);
    g_Agent.socket = INVALID_SOCKET;
    g_Agent.connected = FALSE;
    
    // 安排重连
    SetTimer(g_Agent.hWnd, 1, g_Agent.reconnectInterval, NULL);
}

// Agent连接C2
void AgentConnect(void) {
    if (g_Agent.connected) return;
    
    g_Agent.socket = socket(AF_INET, SOCK_STREAM, 0);
    
    WSAAsyncSelect(g_Agent.socket, g_Agent.hWnd,
                   WM_C2_SOCKET,
                   FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(g_Agent.c2Host);
    addr.sin_port = htons(g_Agent.c2Port);
    
    connect(g_Agent.socket, (struct sockaddr*)&addr, sizeof(addr));
    
    printf("[*] 正在连接C2...\n");
}

// 初始化Agent
void InitAgent(const char* c2Host, int c2Port) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    strcpy(g_Agent.c2Host, c2Host);
    g_Agent.c2Port = c2Port;
    g_Agent.reconnectInterval = 30000;  // 30秒重连间隔
    
    // 创建消息窗口
    WNDCLASS wc = {0};
    wc.lpfnWndProc = AgentWndProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "C2AgentClass";
    RegisterClass(&wc);
    
    g_Agent.hWnd = CreateWindow(
        wc.lpszClassName, NULL, 0,
        0, 0, 0, 0,
        HWND_MESSAGE, NULL, wc.hInstance, NULL
    );
    
    // 开始连接
    AgentConnect();
}

// Agent主循环
void AgentRun(void) {
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
```

## 课后作业

1. **实现GUI聊天客户端**
   - 使用Win32 API创建聊天界面
   - 显示消息列表
   - 支持发送和接收消息
   - 显示在线状态

2. **实现多服务器连接管理**
   - 同时连接多个服务器
   - 为每个连接分配不同的消息ID
   - 实现负载均衡或故障转移

3. **添加心跳保活机制**
   - 使用SetTimer定时发送心跳
   - 检测服务器无响应
   - 实现自动重连逻辑
