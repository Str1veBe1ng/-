# 课时29：动态Patch函数

## 1. 课程目标

学习运行时动态修改代码的技术，用于绕过静态检测。

---

## 2. 技术原理

```
编译时:
┌─────────────────────────────────┐
│  加密/混淆的函数代码            │
└─────────────────────────────────┘

运行时:
┌─────────────────────────────────┐
│  1. 修改内存权限为可写          │
│  2. 解密/还原真实代码           │
│  3. 修改权限为可执行            │
│  4. 执行函数                    │
│  5. (可选)重新加密              │
└─────────────────────────────────┘
```

---

## 3. 实现代码

### 3.1 基础动态Patch

```cpp
#include <windows.h>
#include <stdio.h>

// 被加密的函数体（编译时用工具加密）
unsigned char encryptedFunc[] = {
    0x55,                   // push ebp
    0x8B, 0xEC,             // mov ebp, esp
    // ... 加密后的指令
};

// 解密密钥
BYTE key = 0x41;

void DynamicPatchAndExecute() {
    DWORD size = sizeof(encryptedFunc);
    
    // 1. 分配可写内存
    LPVOID pFunc = VirtualAlloc(NULL, size, 
                                MEM_COMMIT | MEM_RESERVE, 
                                PAGE_READWRITE);
    memcpy(pFunc, encryptedFunc, size);
    
    // 2. 解密
    LPBYTE pCode = (LPBYTE)pFunc;
    for (DWORD i = 0; i < size; i++) {
        pCode[i] ^= key;
    }
    
    // 3. 修改为可执行
    DWORD oldProtect;
    VirtualProtect(pFunc, size, PAGE_EXECUTE_READ, &oldProtect);
    
    // 4. 执行
    typedef int(*FUNC_TYPE)();
    FUNC_TYPE func = (FUNC_TYPE)pFunc;
    int result = func();
    
    // 5. 清理
    VirtualFree(pFunc, 0, MEM_RELEASE);
}
```

### 3.2 原地Patch

```cpp
#include <windows.h>

// 在.text段的函数（需要特殊编译设置）
__declspec(noinline) void EncryptedFunction() {
    // 占位指令，运行时会被替换
    __asm {
        nop
        nop
        nop
        nop
    }
}

void PatchFunctionInPlace() {
    // 获取函数地址
    LPVOID pFunc = (LPVOID)EncryptedFunction;
    
    // 修改权限
    DWORD oldProtect;
    VirtualProtect(pFunc, 100, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // 写入真实代码
    BYTE realCode[] = {
        0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
        0xC3                            // ret
    };
    memcpy(pFunc, realCode, sizeof(realCode));
    
    // 刷新缓存
    FlushInstructionCache(GetCurrentProcess(), pFunc, sizeof(realCode));
    
    // 恢复权限
    VirtualProtect(pFunc, 100, oldProtect, &oldProtect);
    
    // 调用
    EncryptedFunction();
}
```

### 3.3 延迟解密

```cpp
#include <windows.h>

typedef struct _ENCRYPTED_FUNC {
    LPBYTE pEncrypted;
    DWORD dwSize;
    BYTE key;
    BOOL bDecrypted;
    LPVOID pExecutable;
} ENCRYPTED_FUNC;

// 延迟解密执行
LPVOID LazyDecrypt(ENCRYPTED_FUNC* pEF) {
    if (pEF->bDecrypted) {
        return pEF->pExecutable;
    }
    
    // 首次调用时解密
    pEF->pExecutable = VirtualAlloc(NULL, pEF->dwSize,
                                     MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    
    for (DWORD i = 0; i < pEF->dwSize; i++) {
        ((LPBYTE)pEF->pExecutable)[i] = pEF->pEncrypted[i] ^ pEF->key;
    }
    
    pEF->bDecrypted = TRUE;
    return pEF->pExecutable;
}
```

---

## 4. 课后作业

### 作业1：基础Patch（必做）

1. 实现函数动态解密执行
2. 验证解密前后代码差异

### 作业2：原地Patch（进阶）

1. 实现原地修改.text段代码
2. 处理DEP保护

---

## 5. 下一课预告

下一课我们将学习代码混淆技术。
