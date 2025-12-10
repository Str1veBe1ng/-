# 课时26：非对称加密加密ShellCode

## 1. 课程目标

学习使用RSA等非对称加密算法加密ShellCode。

---

## 2. 非对称加密原理

```
加密端（攻击者服务器）:
公钥加密ShellCode → 密文

解密端（目标机器）:
私钥解密密文 → 明文ShellCode → 执行

优势：
- 公钥可公开
- 私钥分发灵活
- 每次执行可使用不同密钥对
```

---

## 3. RSA加密实现

### 3.1 使用CryptoAPI

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

// RSA加密（需要公钥）
BOOL RSAEncrypt(LPBYTE pData, DWORD dwDataLen, 
                LPBYTE pPublicKey, DWORD dwKeyLen,
                LPBYTE* ppEncrypted, DWORD* pdwEncryptedLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;
    
    CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W,
                         PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    // 导入公钥
    CryptImportKey(hProv, pPublicKey, dwKeyLen, 0, 0, &hKey);
    
    // 计算加密后大小
    DWORD dwLen = dwDataLen;
    CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dwLen, 0);
    
    *ppEncrypted = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, dwLen);
    memcpy(*ppEncrypted, pData, dwDataLen);
    *pdwEncryptedLen = dwDataLen;
    
    result = CryptEncrypt(hKey, 0, TRUE, 0, *ppEncrypted, pdwEncryptedLen, dwLen);
    
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return result;
}

// RSA解密（需要私钥）
BOOL RSADecrypt(LPBYTE pEncrypted, DWORD dwEncryptedLen,
                LPBYTE pPrivateKey, DWORD dwKeyLen,
                LPBYTE* ppDecrypted, DWORD* pdwDecryptedLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;
    
    CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W,
                         PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    
    // 导入私钥
    CryptImportKey(hProv, pPrivateKey, dwKeyLen, 0, 0, &hKey);
    
    *ppDecrypted = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, dwEncryptedLen);
    memcpy(*ppDecrypted, pEncrypted, dwEncryptedLen);
    *pdwDecryptedLen = dwEncryptedLen;
    
    result = CryptDecrypt(hKey, 0, TRUE, 0, *ppDecrypted, pdwDecryptedLen);
    
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return result;
}
```

---

## 4. 混合加密方案

由于RSA不适合加密大数据，通常使用混合方案：

```
1. 生成随机AES密钥
2. 使用AES加密ShellCode
3. 使用RSA加密AES密钥
4. 传输：RSA加密的AES密钥 + AES加密的ShellCode

解密时：
1. RSA解密获得AES密钥
2. AES解密获得ShellCode
```

---

## 5. 课后作业

### 作业1：RSA解密Loader（必做）

1. 使用OpenSSL生成RSA密钥对
2. 实现RSA解密Loader

### 作业2：混合加密（进阶）

1. 实现RSA+AES混合加密方案
2. 测试完整流程

---

## 6. 下一课预告

下一课我们将学习花指令技术。
