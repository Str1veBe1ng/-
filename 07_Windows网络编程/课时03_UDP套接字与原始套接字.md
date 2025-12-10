# 课时03：UDP套接字与原始套接字

## 课程目标

1. 掌握UDP套接字的创建和使用
2. 理解UDP和TCP的区别
3. 学会使用原始套接字
4. 实现简单的网络工具

---

## 名词解释

| 术语 | 解释 |
|------|------|
| UDP | User Datagram Protocol用户数据报协议 |
| 无连接 | 不需要建立连接即可发送数据 |
| Raw Socket | 原始套接字，直接操作IP层 |
| ICMP | Internet Control Message Protocol |
| sendto/recvfrom | UDP数据发送接收函数 |

---

## 使用工具

| 工具 | 用途 |
|------|------|
| Wireshark | 分析UDP和ICMP包 |
| netcat | 测试UDP连接 |

---

## 技术原理

### UDP vs TCP

```
┌─────────────────────────────────────────────────────────────┐
│                    UDP vs TCP 对比                          │
│                                                             │
│  特性          │    TCP           │    UDP                 │
│  ─────────────┼─────────────────┼─────────────────        │
│  连接方式      │    面向连接      │    无连接               │
│  可靠性        │    可靠传输      │    不可靠               │
│  顺序保证      │    有序          │    无序                 │
│  流量控制      │    有            │    无                   │
│  拥塞控制      │    有            │    无                   │
│  开销          │    大            │    小                   │
│  速度          │    较慢          │    快                   │
│  应用场景      │    HTTP/FTP     │    DNS/视频流/游戏      │
└─────────────────────────────────────────────────────────────┘
```

---

## 代码实现

### 示例1：UDP服务器

```c
// UdpServer.c - UDP服务器
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define UDP_PORT 5555
#define BUFFER_SIZE 4096

int main() {
    WSADATA wsaData;
    SOCKET serverSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    char buffer[BUFFER_SIZE];
    int recvLen;
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // 创建UDP套接字
    serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (serverSocket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // 绑定地址
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(UDP_PORT);
    
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    
    printf("UDP Server listening on port %d...\n", UDP_PORT);
    
    while (1) {
        // 接收数据（不需要建立连接）
        recvLen = recvfrom(serverSocket, buffer, BUFFER_SIZE - 1, 0,
                          (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (recvLen > 0) {
            buffer[recvLen] = '\0';
            
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, sizeof(clientIP));
            
            printf("Received from %s:%d: %s\n", 
                   clientIP, ntohs(clientAddr.sin_port), buffer);
            
            // 回复（发送到来源地址）
            char response[BUFFER_SIZE];
            sprintf_s(response, sizeof(response), "Echo: %s", buffer);
            sendto(serverSocket, response, strlen(response), 0,
                   (struct sockaddr*)&clientAddr, clientAddrLen);
        }
    }
    
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
```

### 示例2：UDP客户端

```c
// UdpClient.c - UDP客户端
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP   "127.0.0.1"
#define SERVER_PORT 5555
#define BUFFER_SIZE 4096

int main() {
    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;
    int serverAddrLen = sizeof(serverAddr);
    char sendBuffer[BUFFER_SIZE];
    char recvBuffer[BUFFER_SIZE];
    int recvLen;
    
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // 创建UDP套接字
    clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    // 设置服务器地址
    serverAddr.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(SERVER_PORT);
    
    // 设置超时
    int timeout = 3000;  // 3秒
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    printf("UDP Client - Enter message (quit to exit):\n");
    
    while (1) {
        printf("> ");
        fgets(sendBuffer, BUFFER_SIZE, stdin);
        sendBuffer[strcspn(sendBuffer, "\n")] = '\0';
        
        if (strcmp(sendBuffer, "quit") == 0) break;
        
        // 发送数据（不需要连接）
        sendto(clientSocket, sendBuffer, strlen(sendBuffer), 0,
               (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        
        // 接收响应
        recvLen = recvfrom(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0,
                          (struct sockaddr*)&serverAddr, &serverAddrLen);
        
        if (recvLen > 0) {
            recvBuffer[recvLen] = '\0';
            printf("Server: %s\n", recvBuffer);
        } else if (recvLen == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAETIMEDOUT) {
                printf("Timeout - no response\n");
            }
        }
    }
    
    closesocket(clientSocket);
    WSACleanup();
    return 0;
}
```

### 示例3：UDP广播

```c
// UdpBroadcast.c - UDP广播
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define BROADCAST_PORT 6666

// 广播发送者
void BroadcastSender() {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    // 启用广播
    BOOL broadcast = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char*)&broadcast, sizeof(broadcast));
    
    struct sockaddr_in broadcastAddr;
    broadcastAddr.sin_family = AF_INET;
    broadcastAddr.sin_addr.s_addr = INADDR_BROADCAST;  // 255.255.255.255
    broadcastAddr.sin_port = htons(BROADCAST_PORT);
    
    char message[256];
    int count = 0;
    
    printf("Broadcasting on port %d...\n", BROADCAST_PORT);
    
    while (1) {
        sprintf_s(message, sizeof(message), "Broadcast message #%d", ++count);
        
        sendto(sock, message, strlen(message), 0,
               (struct sockaddr*)&broadcastAddr, sizeof(broadcastAddr));
        
        printf("Sent: %s\n", message);
        Sleep(2000);
    }
    
    closesocket(sock);
}

// 广播接收者
void BroadcastReceiver() {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    
    struct sockaddr_in localAddr;
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = htons(BROADCAST_PORT);
    
    bind(sock, (struct sockaddr*)&localAddr, sizeof(localAddr));
    
    char buffer[256];
    struct sockaddr_in senderAddr;
    int senderAddrLen = sizeof(senderAddr);
    
    printf("Listening for broadcasts on port %d...\n", BROADCAST_PORT);
    
    while (1) {
        int recvLen = recvfrom(sock, buffer, sizeof(buffer) - 1, 0,
                               (struct sockaddr*)&senderAddr, &senderAddrLen);
        
        if (recvLen > 0) {
            buffer[recvLen] = '\0';
            
            char senderIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &senderAddr.sin_addr, senderIP, sizeof(senderIP));
            
            printf("From %s: %s\n", senderIP, buffer);
        }
    }
    
    closesocket(sock);
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    if (argc > 1 && strcmp(argv[1], "send") == 0) {
        BroadcastSender();
    } else {
        BroadcastReceiver();
    }
    
    WSACleanup();
    return 0;
}
```

### 示例4：原始套接字 - ICMP Ping

```c
// RawPing.c - ICMP Ping实现
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

// 使用ICMP API进行Ping
void IcmpPing(const char* target) {
    HANDLE hIcmpFile;
    unsigned long ipaddr = INADDR_NONE;
    DWORD dwRetVal = 0;
    char sendData[32] = "Data Buffer";
    LPVOID replyBuffer = NULL;
    DWORD replySize = 0;
    
    // 解析目标地址
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    
    if (getaddrinfo(target, NULL, &hints, &result) != 0) {
        printf("Failed to resolve %s\n", target);
        return;
    }
    
    ipaddr = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(result);
    
    // 打开ICMP句柄
    hIcmpFile = IcmpCreateFile();
    if (hIcmpFile == INVALID_HANDLE_VALUE) {
        printf("IcmpCreateFile failed: %d\n", GetLastError());
        return;
    }
    
    replySize = sizeof(ICMP_ECHO_REPLY) + sizeof(sendData);
    replyBuffer = (VOID*)malloc(replySize);
    
    printf("Pinging %s...\n\n", target);
    
    for (int i = 0; i < 4; i++) {
        dwRetVal = IcmpSendEcho(hIcmpFile, ipaddr, sendData, sizeof(sendData),
                                NULL, replyBuffer, replySize, 1000);
        
        if (dwRetVal != 0) {
            PICMP_ECHO_REPLY pEchoReply = (PICMP_ECHO_REPLY)replyBuffer;
            
            struct in_addr replyAddr;
            replyAddr.S_un.S_addr = pEchoReply->Address;
            
            printf("Reply from %s: bytes=%d time=%dms TTL=%d\n",
                   inet_ntoa(replyAddr),
                   pEchoReply->DataSize,
                   pEchoReply->RoundTripTime,
                   pEchoReply->Options.Ttl);
        } else {
            printf("Request timed out.\n");
        }
        
        Sleep(1000);
    }
    
    free(replyBuffer);
    IcmpCloseHandle(hIcmpFile);
}

// 原始套接字Ping（需要管理员权限）
#pragma pack(push, 1)
typedef struct _ICMP_HEADER {
    BYTE    Type;
    BYTE    Code;
    USHORT  Checksum;
    USHORT  Id;
    USHORT  Sequence;
} ICMP_HEADER;
#pragma pack(pop)

USHORT CalculateChecksum(USHORT* buffer, int size) {
    unsigned long checksum = 0;
    
    while (size > 1) {
        checksum += *buffer++;
        size -= sizeof(USHORT);
    }
    
    if (size) {
        checksum += *(UCHAR*)buffer;
    }
    
    checksum = (checksum >> 16) + (checksum & 0xFFFF);
    checksum += (checksum >> 16);
    
    return (USHORT)(~checksum);
}

void RawSocketPing(const char* target) {
    SOCKET rawSocket;
    struct sockaddr_in destAddr;
    char packet[64];
    char recvBuffer[1024];
    ICMP_HEADER* icmpHeader;
    
    // 创建原始套接字
    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (rawSocket == INVALID_SOCKET) {
        printf("Raw socket failed: %d (run as admin)\n", WSAGetLastError());
        return;
    }
    
    // 设置目标地址
    destAddr.sin_family = AF_INET;
    inet_pton(AF_INET, target, &destAddr.sin_addr);
    
    // 设置超时
    int timeout = 1000;
    setsockopt(rawSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // 构造ICMP包
    memset(packet, 0, sizeof(packet));
    icmpHeader = (ICMP_HEADER*)packet;
    icmpHeader->Type = 8;  // Echo Request
    icmpHeader->Code = 0;
    icmpHeader->Id = (USHORT)GetCurrentProcessId();
    icmpHeader->Sequence = 1;
    icmpHeader->Checksum = 0;
    icmpHeader->Checksum = CalculateChecksum((USHORT*)packet, sizeof(ICMP_HEADER));
    
    printf("Raw socket ping to %s...\n", target);
    
    // 发送
    if (sendto(rawSocket, packet, sizeof(ICMP_HEADER), 0,
               (struct sockaddr*)&destAddr, sizeof(destAddr)) == SOCKET_ERROR) {
        printf("sendto failed: %d\n", WSAGetLastError());
    } else {
        // 接收
        struct sockaddr_in fromAddr;
        int fromLen = sizeof(fromAddr);
        int recvLen = recvfrom(rawSocket, recvBuffer, sizeof(recvBuffer), 0,
                               (struct sockaddr*)&fromAddr, &fromLen);
        
        if (recvLen > 0) {
            printf("Reply received from %s\n", inet_ntoa(fromAddr.sin_addr));
        }
    }
    
    closesocket(rawSocket);
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    const char* target = (argc > 1) ? argv[1] : "8.8.8.8";
    
    IcmpPing(target);
    
    WSACleanup();
    return 0;
}
```

---

## 课后作业

1. 实现UDP文件传输
2. 编写端口扫描工具
3. 实现Traceroute功能
4. 创建UDP隧道

---

## 扩展阅读

- UDP协议详解
- 原始套接字编程
- 网络安全工具开发
