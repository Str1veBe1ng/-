# 课时06：HTTP协议

## 课程目标

1. 深入理解HTTP协议结构
2. 掌握HTTP请求和响应格式
3. 学会使用原始套接字实现HTTP
4. 理解HTTP在安全工具中的应用

---

## 名词解释

| 术语 | 解释 |
|------|------|
| HTTP | HyperText Transfer Protocol |
| Request Line | 请求行(方法 URI 版本) |
| Status Line | 状态行(版本 状态码 原因) |
| Header | 头部字段 |
| Body | 消息体 |

---

## 技术原理

### HTTP请求格式

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP请求结构                              │
│                                                             │
│  GET /path/resource HTTP/1.1\r\n     ← 请求行               │
│  Host: www.example.com\r\n           ← 头部字段             │
│  User-Agent: Mozilla/5.0\r\n                                │
│  Accept: text/html\r\n                                      │
│  Connection: keep-alive\r\n                                 │
│  \r\n                                ← 空行                 │
│  [Request Body]                      ← 请求体(POST)         │
│                                                             │
│  HTTP方法：GET POST PUT DELETE HEAD OPTIONS PATCH          │
└─────────────────────────────────────────────────────────────┘
```

---

## 代码实现

### 示例1：手动构造HTTP请求

```c
// RawHttp.c - 原始HTTP实现
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

// HTTP GET请求
BOOL HttpGetRaw(const char* host, int port, const char* path, char** response, int* respLen) {
    SOCKET sock;
    struct sockaddr_in serverAddr;
    char request[2048], buffer[4096];
    int totalRecv = 0, recvLen;
    int capacity = 8192;
    
    *response = (char*)malloc(capacity);
    if (!*response) return FALSE;
    
    // 创建连接
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    struct hostent* hostInfo = gethostbyname(host);
    if (!hostInfo) return FALSE;
    
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    memcpy(&serverAddr.sin_addr, hostInfo->h_addr, hostInfo->h_length);
    
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != 0) {
        closesocket(sock);
        return FALSE;
    }
    
    // 构造HTTP请求
    sprintf_s(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: CustomClient/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host);
    
    // 发送请求
    send(sock, request, strlen(request), 0);
    
    // 接收响应
    while ((recvLen = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        if (totalRecv + recvLen >= capacity) {
            capacity *= 2;
            *response = (char*)realloc(*response, capacity);
        }
        memcpy(*response + totalRecv, buffer, recvLen);
        totalRecv += recvLen;
    }
    
    (*response)[totalRecv] = '\0';
    *respLen = totalRecv;
    
    closesocket(sock);
    return TRUE;
}

// HTTP POST请求
BOOL HttpPostRaw(const char* host, int port, const char* path, 
                 const char* contentType, const char* body,
                 char** response, int* respLen) {
    SOCKET sock;
    struct sockaddr_in serverAddr;
    char request[4096];
    
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    struct hostent* hostInfo = gethostbyname(host);
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    memcpy(&serverAddr.sin_addr, hostInfo->h_addr, hostInfo->h_length);
    
    connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    
    // 构造POST请求
    sprintf_s(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: CustomClient/1.0\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        path, host, contentType, strlen(body), body);
    
    send(sock, request, strlen(request), 0);
    
    // 接收响应
    int capacity = 8192, totalRecv = 0, recvLen;
    char buffer[4096];
    *response = (char*)malloc(capacity);
    
    while ((recvLen = recv(sock, buffer, sizeof(buffer), 0)) > 0) {
        if (totalRecv + recvLen >= capacity) {
            capacity *= 2;
            *response = (char*)realloc(*response, capacity);
        }
        memcpy(*response + totalRecv, buffer, recvLen);
        totalRecv += recvLen;
    }
    
    (*response)[totalRecv] = '\0';
    *respLen = totalRecv;
    
    closesocket(sock);
    return TRUE;
}

// 解析HTTP响应
void ParseHttpResponse(const char* response, int* statusCode, char** headers, char** body) {
    // 找到状态码
    const char* p = strstr(response, "HTTP/1.");
    if (p) {
        p = strchr(p, ' ');
        if (p) *statusCode = atoi(p + 1);
    }
    
    // 找到头部结束位置
    const char* headerEnd = strstr(response, "\r\n\r\n");
    if (headerEnd) {
        int headerLen = headerEnd - response;
        *headers = (char*)malloc(headerLen + 1);
        strncpy_s(*headers, headerLen + 1, response, headerLen);
        
        *body = _strdup(headerEnd + 4);
    }
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    char* response;
    int respLen;
    
    if (HttpGetRaw("httpbin.org", 80, "/get", &response, &respLen)) {
        printf("Response (%d bytes):\n%s\n", respLen, response);
        free(response);
    }
    
    WSACleanup();
    return 0;
}
```

### 示例2：HTTP头部解析

```c
// HttpParser.c - HTTP解析器
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _HTTP_HEADER {
    char* name;
    char* value;
} HTTP_HEADER;

typedef struct _HTTP_REQUEST {
    char method[16];
    char path[1024];
    char version[16];
    HTTP_HEADER headers[50];
    int headerCount;
    char* body;
    int bodyLength;
} HTTP_REQUEST;

// 解析HTTP请求
BOOL ParseHttpRequest(const char* data, HTTP_REQUEST* request) {
    char* line, *saveptr;
    char* dataCopy = _strdup(data);
    
    memset(request, 0, sizeof(HTTP_REQUEST));
    
    // 解析请求行
    line = strtok_s(dataCopy, "\r\n", &saveptr);
    if (!line) return FALSE;
    
    sscanf_s(line, "%s %s %s", request->method, 16, request->path, 1024, request->version, 16);
    
    // 解析头部
    while ((line = strtok_s(NULL, "\r\n", &saveptr)) != NULL) {
        if (strlen(line) == 0) break;  // 空行，头部结束
        
        char* colon = strchr(line, ':');
        if (colon && request->headerCount < 50) {
            *colon = '\0';
            request->headers[request->headerCount].name = _strdup(line);
            
            char* value = colon + 1;
            while (*value == ' ') value++;
            request->headers[request->headerCount].value = _strdup(value);
            
            request->headerCount++;
        }
    }
    
    // 获取Body
    const char* bodyStart = strstr(data, "\r\n\r\n");
    if (bodyStart) {
        request->body = _strdup(bodyStart + 4);
        request->bodyLength = strlen(request->body);
    }
    
    free(dataCopy);
    return TRUE;
}

// 获取指定头部
const char* GetHeader(HTTP_REQUEST* request, const char* name) {
    for (int i = 0; i < request->headerCount; i++) {
        if (_stricmp(request->headers[i].name, name) == 0) {
            return request->headers[i].value;
        }
    }
    return NULL;
}

// 构建HTTP响应
void BuildHttpResponse(int statusCode, const char* contentType, 
                       const char* body, char* response, int maxLen) {
    const char* statusText;
    switch (statusCode) {
        case 200: statusText = "OK"; break;
        case 404: statusText = "Not Found"; break;
        case 500: statusText = "Internal Server Error"; break;
        default: statusText = "Unknown"; break;
    }
    
    sprintf_s(response, maxLen,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        statusCode, statusText, contentType, strlen(body), body);
}
```

---

## 课后作业

1. 实现HTTP分块传输解析
2. 添加Cookie处理
3. 实现HTTP代理
4. 编写HTTP流量分析工具

---

## 扩展阅读

- RFC 2616 HTTP/1.1
- HTTP/2协议
- HTTPS和TLS
