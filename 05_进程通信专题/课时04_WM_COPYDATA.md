# 课时04 - WM_COPYDATA

## 课程目标

1. 理解WM_COPYDATA的通信原理
2. 掌握跨进程数据传递
3. 学会窗口间的消息通信
4. 理解WM_COPYDATA的安全应用

## 名词解释

| 术语 | 英文 | 说明 |
|------|------|------|
| WM_COPYDATA | Copy Data Message | 用于跨进程传递数据的消息 |
| COPYDATASTRUCT | Copy Data Structure | 传递数据的结构体 |
| 同步通信 | Synchronous | SendMessage是同步的 |

## 技术原理

```c
typedef struct tagCOPYDATASTRUCT {
    ULONG_PTR dwData;   // 用户定义的数据
    DWORD cbData;       // 数据大小
    PVOID lpData;       // 数据指针
} COPYDATASTRUCT;
```

## 代码实现

### 示例1：发送数据

```c
#include <windows.h>
#include <stdio.h>

#define MY_MSG_TYPE 1001

void SendData(HWND hTargetWnd, const void* data, size_t size) {
    COPYDATASTRUCT cds;
    cds.dwData = MY_MSG_TYPE;
    cds.cbData = size;
    cds.lpData = (PVOID)data;
    
    SendMessage(hTargetWnd, WM_COPYDATA, (WPARAM)NULL, (LPARAM)&cds);
}

void SendStringDemo() {
    HWND hTarget = FindWindow(NULL, TEXT("Receiver Window"));
    
    if (hTarget) {
        const char* message = "Hello from sender!";
        SendData(hTarget, message, strlen(message) + 1);
    }
}
```

### 示例2：接收数据

```c
#include <windows.h>
#include <stdio.h>

LRESULT CALLBACK ReceiverWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COPYDATA: {
        COPYDATASTRUCT* pCds = (COPYDATASTRUCT*)lParam;
        
        if (pCds->dwData == 1001) {
            char* message = (char*)pCds->lpData;
            printf("Received: %s\n", message);
            
            // 可以返回TRUE表示处理成功
            return TRUE;
        }
        break;
    }
    
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
```

### 示例3：结构体传递

```c
#include <windows.h>
#include <stdio.h>

typedef struct {
    int id;
    char name[32];
    double value;
} MyData;

void SendStructData(HWND hTarget) {
    MyData data = {1, "Test", 3.14};
    
    COPYDATASTRUCT cds;
    cds.dwData = 2001;
    cds.cbData = sizeof(MyData);
    cds.lpData = &data;
    
    SendMessage(hTarget, WM_COPYDATA, 0, (LPARAM)&cds);
}

void ReceiveStructData(COPYDATASTRUCT* pCds) {
    if (pCds->dwData == 2001 && pCds->cbData == sizeof(MyData)) {
        MyData* pData = (MyData*)pCds->lpData;
        printf("ID: %d, Name: %s, Value: %.2f\n", 
               pData->id, pData->name, pData->value);
    }
}
```

### 示例4：完整通信示例

```c
#include <windows.h>
#include <stdio.h>

// 命令类型
#define CMD_PING    1
#define CMD_PONG    2
#define CMD_DATA    3

typedef struct {
    int command;
    char payload[256];
} Message;

void SendCommand(HWND hTarget, int cmd, const char* payload) {
    Message msg;
    msg.command = cmd;
    strncpy(msg.payload, payload, sizeof(msg.payload)-1);
    
    COPYDATASTRUCT cds;
    cds.dwData = 0;
    cds.cbData = sizeof(Message);
    cds.lpData = &msg;
    
    SendMessage(hTarget, WM_COPYDATA, 0, (LPARAM)&cds);
}

LRESULT HandleCommand(HWND hWnd, COPYDATASTRUCT* pCds) {
    if (pCds->cbData != sizeof(Message)) return FALSE;
    
    Message* pMsg = (Message*)pCds->lpData;
    
    switch (pMsg->command) {
    case CMD_PING:
        printf("Received PING, sending PONG\n");
        // 回复PONG（需要获取发送者窗口）
        break;
        
    case CMD_DATA:
        printf("Received data: %s\n", pMsg->payload);
        break;
    }
    
    return TRUE;
}
```

## 课后作业

1. **基础练习**：实现两个进程间的WM_COPYDATA通信
2. **结构传递**：传递复杂结构体数据
3. **双向通信**：实现请求-响应模式
4. **安全应用**：理解WM_COPYDATA的安全限制