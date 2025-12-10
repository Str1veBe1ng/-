# 课时08：实现FTP服务器

## 课程目标

1. 理解FTP协议工作原理
2. 实现FTP服务器核心功能
3. 掌握主动和被动模式
4. 实现文件上传下载

---

## 名词解释

| 术语 | 解释 |
|------|------|
| FTP | File Transfer Protocol文件传输协议 |
| 控制连接 | 端口21，传输命令 |
| 数据连接 | 端口20或随机，传输数据 |
| 主动模式 | PORT，服务器主动连接客户端 |
| 被动模式 | PASV，客户端连接服务器 |

---

## 代码实现

### 示例1：FTP服务器

```c
// FtpServer.c - FTP服务器
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <direct.h>

#pragma comment(lib, "ws2_32.lib")

#define FTP_PORT 21
#define FTP_ROOT "C:\\FtpRoot"

typedef struct _FTP_SESSION {
    SOCKET controlSocket;
    SOCKET dataSocket;
    SOCKET pasvSocket;
    char currentDir[MAX_PATH];
    char username[64];
    BOOL authenticated;
    BOOL pasvMode;
} FTP_SESSION;

void SendResponse(SOCKET sock, const char* response) {
    send(sock, response, strlen(response), 0);
    printf("[FTP] -> %s", response);
}

void HandleUser(FTP_SESSION* session, const char* username) {
    strcpy_s(session->username, sizeof(session->username), username);
    SendResponse(session->controlSocket, "331 Password required\r\n");
}

void HandlePass(FTP_SESSION* session, const char* password) {
    // 简化认证
    if (strcmp(session->username, "admin") == 0 && strcmp(password, "admin") == 0) {
        session->authenticated = TRUE;
        SendResponse(session->controlSocket, "230 User logged in\r\n");
    } else {
        SendResponse(session->controlSocket, "530 Login incorrect\r\n");
    }
}

void HandlePwd(FTP_SESSION* session) {
    char response[512];
    sprintf_s(response, sizeof(response), "257 \"%s\"\r\n", session->currentDir);
    SendResponse(session->controlSocket, response);
}

void HandlePasv(FTP_SESSION* session) {
    struct sockaddr_in addr;
    int addrLen = sizeof(addr);
    
    // 创建被动模式监听套接字
    session->pasvSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = 0;  // 随机端口
    
    bind(session->pasvSocket, (struct sockaddr*)&addr, sizeof(addr));
    listen(session->pasvSocket, 1);
    
    getsockname(session->pasvSocket, (struct sockaddr*)&addr, &addrLen);
    
    // 获取本机IP
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    struct hostent* host = gethostbyname(hostname);
    BYTE* ip = (BYTE*)host->h_addr;
    WORD port = ntohs(addr.sin_port);
    
    char response[128];
    sprintf_s(response, sizeof(response), 
        "227 Entering Passive Mode (%d,%d,%d,%d,%d,%d)\r\n",
        ip[0], ip[1], ip[2], ip[3], port / 256, port % 256);
    
    SendResponse(session->controlSocket, response);
    session->pasvMode = TRUE;
}

void HandleList(FTP_SESSION* session) {
    if (session->pasvMode) {
        struct sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        session->dataSocket = accept(session->pasvSocket, (struct sockaddr*)&clientAddr, &addrLen);
    }
    
    if (session->dataSocket == INVALID_SOCKET) {
        SendResponse(session->controlSocket, "425 Can't open data connection\r\n");
        return;
    }
    
    SendResponse(session->controlSocket, "150 Opening data connection\r\n");
    
    // 列出目录
    char fullPath[MAX_PATH];
    sprintf_s(fullPath, sizeof(fullPath), "%s%s\\*", FTP_ROOT, session->currentDir);
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(fullPath, &findData);
    
    if (hFind != INVALID_HANDLE_VALUE) {
        char listLine[512];
        do {
            char type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';
            sprintf_s(listLine, sizeof(listLine), 
                "%crwxr-xr-x 1 owner group %10d Jan 01 00:00 %s\r\n",
                type, findData.nFileSizeLow, findData.cFileName);
            send(session->dataSocket, listLine, strlen(listLine), 0);
        } while (FindNextFileA(hFind, &findData));
        FindClose(hFind);
    }
    
    closesocket(session->dataSocket);
    session->dataSocket = INVALID_SOCKET;
    closesocket(session->pasvSocket);
    session->pasvSocket = INVALID_SOCKET;
    session->pasvMode = FALSE;
    
    SendResponse(session->controlSocket, "226 Transfer complete\r\n");
}

void HandleRetr(FTP_SESSION* session, const char* filename) {
    if (session->pasvMode) {
        struct sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        session->dataSocket = accept(session->pasvSocket, (struct sockaddr*)&clientAddr, &addrLen);
    }
    
    char fullPath[MAX_PATH];
    sprintf_s(fullPath, sizeof(fullPath), "%s%s\\%s", FTP_ROOT, session->currentDir, filename);
    
    HANDLE hFile = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SendResponse(session->controlSocket, "550 File not found\r\n");
        return;
    }
    
    SendResponse(session->controlSocket, "150 Opening data connection\r\n");
    
    char buffer[8192];
    DWORD bytesRead;
    while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        send(session->dataSocket, buffer, bytesRead, 0);
    }
    
    CloseHandle(hFile);
    closesocket(session->dataSocket);
    session->dataSocket = INVALID_SOCKET;
    
    SendResponse(session->controlSocket, "226 Transfer complete\r\n");
}

void HandleStor(FTP_SESSION* session, const char* filename) {
    if (session->pasvMode) {
        struct sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        session->dataSocket = accept(session->pasvSocket, (struct sockaddr*)&clientAddr, &addrLen);
    }
    
    char fullPath[MAX_PATH];
    sprintf_s(fullPath, sizeof(fullPath), "%s%s\\%s", FTP_ROOT, session->currentDir, filename);
    
    HANDLE hFile = CreateFileA(fullPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        SendResponse(session->controlSocket, "550 Cannot create file\r\n");
        return;
    }
    
    SendResponse(session->controlSocket, "150 Opening data connection\r\n");
    
    char buffer[8192];
    int recvLen;
    DWORD bytesWritten;
    while ((recvLen = recv(session->dataSocket, buffer, sizeof(buffer), 0)) > 0) {
        WriteFile(hFile, buffer, recvLen, &bytesWritten, NULL);
    }
    
    CloseHandle(hFile);
    closesocket(session->dataSocket);
    session->dataSocket = INVALID_SOCKET;
    
    SendResponse(session->controlSocket, "226 Transfer complete\r\n");
}

void ProcessCommand(FTP_SESSION* session, const char* command) {
    char cmd[16], arg[256];
    arg[0] = '\0';
    
    sscanf_s(command, "%s %[^\r\n]", cmd, 16, arg, 256);
    
    printf("[FTP] <- %s %s\n", cmd, arg);
    
    if (_stricmp(cmd, "USER") == 0) HandleUser(session, arg);
    else if (_stricmp(cmd, "PASS") == 0) HandlePass(session, arg);
    else if (_stricmp(cmd, "PWD") == 0) HandlePwd(session);
    else if (_stricmp(cmd, "PASV") == 0) HandlePasv(session);
    else if (_stricmp(cmd, "LIST") == 0) HandleList(session);
    else if (_stricmp(cmd, "RETR") == 0) HandleRetr(session, arg);
    else if (_stricmp(cmd, "STOR") == 0) HandleStor(session, arg);
    else if (_stricmp(cmd, "TYPE") == 0) SendResponse(session->controlSocket, "200 Type set\r\n");
    else if (_stricmp(cmd, "SYST") == 0) SendResponse(session->controlSocket, "215 Windows\r\n");
    else if (_stricmp(cmd, "QUIT") == 0) SendResponse(session->controlSocket, "221 Goodbye\r\n");
    else SendResponse(session->controlSocket, "502 Command not implemented\r\n");
}

DWORD WINAPI FtpClientThread(LPVOID lpParam) {
    FTP_SESSION session = {0};
    session.controlSocket = (SOCKET)lpParam;
    strcpy_s(session.currentDir, sizeof(session.currentDir), "/");
    
    SendResponse(session.controlSocket, "220 FTP Server Ready\r\n");
    
    char buffer[1024];
    int recvLen;
    
    while ((recvLen = recv(session.controlSocket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[recvLen] = '\0';
        ProcessCommand(&session, buffer);
    }
    
    closesocket(session.controlSocket);
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET listenSocket;
    
    CreateDirectoryA(FTP_ROOT, NULL);
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    listenSocket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(FTP_PORT);
    
    bind(listenSocket, (struct sockaddr*)&addr, sizeof(addr));
    listen(listenSocket, 5);
    
    printf("FTP Server listening on port %d\n", FTP_PORT);
    printf("Root directory: %s\n", FTP_ROOT);
    
    while (1) {
        SOCKET client = accept(listenSocket, NULL, NULL);
        if (client != INVALID_SOCKET) {
            CreateThread(NULL, 0, FtpClientThread, (LPVOID)client, 0, NULL);
        }
    }
    
    return 0;
}
```

---

## 课后作业

1. 添加CWD/CDUP命令
2. 实现MKD/RMD命令
3. 添加用户权限管理
4. 实现断点续传

---

## 扩展阅读

- FTP协议RFC 959
- FTPS和SFTP
- 文件传输安全
