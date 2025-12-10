# 课时08 Windows内核提权

## 一、课程目标

本节课主要学习利用Windows内核漏洞进行权限提升的技术和方法。内核提权往往能够直接获取SYSTEM权限，是渗透测试中的"大杀器"。通过本课的学习，你将能够：

1. 理解Windows内核漏洞提权的基本原理
2. 掌握常见的Windows内核漏洞类型（如空指针解引用、UAF等）
3. 熟悉内核漏洞利用的利用流程和环境准备
4. 学会使用公开的内核漏洞Exploit进行提权
5. 了解Windows内核提权的防护机制及绕过思路

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| Kernel Mode | 内核模式，拥有CPU所有指令的执行权限 |
| User Mode | 用户模式，权限受限，无法直接访问硬件或内核内存 |
| HAL | 硬件抽象层，屏蔽硬件差异 |
| BSOD | Blue Screen of Death，蓝屏死机，内核错误常导致此结果 |
| IOCTL | Input/Output Control，用户态与内核驱动通信的接口 |
| Shellcode | 用于利用漏洞的一段机器码，通常用于反弹Shell或提权 |
| EPROCESS | 内核结构体，描述进程信息，包含Token |
| Token Stealing | 令牌窃取，一种常见的内核提权利用技术 |

## 三、技术原理

### 3.1 Windows体系结构

Windows操作系统分为用户模式（Ring 3）和内核模式（Ring 0）。

*   **用户模式**：应用程序运行在受限环境中，不能直接访问硬件或关键系统数据。
*   **内核模式**：操作系统核心组件和驱动程序运行在此模式，拥有完全的系统访问权限。

### 3.2 漏洞成因

内核漏洞通常发生在第三方驱动程序（`.sys`文件）或Windows内核本身（`ntoskrnl.exe`, `win32k.sys`等）。

#### 常见类型
1.  **空指针解引用 (Null Pointer Dereference)**：未初始化的指针被使用。
2.  **栈/堆缓冲区溢出 (Stack/Pool Overflow)**：写入数据超过缓冲区边界。
3.  **释放后使用 (Use-After-Free, UAF)**：引用了已经被释放的内存。
4.  **整数溢出 (Integer Overflow)**：算术运算导致数值异常，进而引发内存破坏。
5.  **逻辑漏洞**：权限检查绕过等。

### 3.3 提权利用思路 (Token Stealing)

最经典的内核提权Payload是"令牌窃取"（Token Stealing）。

1.  **获取当前进程结构 (EPROCESS)**：利用漏洞在内核态执行代码。
2.  **遍历进程链表**：找到SYSTEM进程（通常PID为4）。
3.  **复制Token**：将SYSTEM进程的Token复制并覆盖当前进程的Token。
4.  **提权完成**：当前进程瞬间拥有SYSTEM权限。

#### 伪代码示例
```c
// 伪代码：在内核态查找SYSTEM进程并替换Token
void Shellcode() {
    // 获取当前进程EPROCESS
    PEPROCESS CurrentProcess = PsGetCurrentProcess();
    PEPROCESS SystemProcess = GetSystemProcess(); // 需自行实现查找逻辑

    // 替换Token
    // Token偏移量因系统版本而异
    *(void**)(CurrentProcess + TokenOffset) = *(void**)(SystemProcess + TokenOffset);
}
```

## 四、常见内核漏洞案例

### 4.1 CVE-2018-8120 (Win32k)

*   **描述**：Win32k组件中的空指针解引用漏洞。
*   **影响范围**：Windows 7, Windows Server 2008 等。
*   **特点**：利用稳定，常用于早期的靶场环境。

### 4.2 CVE-2020-0796 (SMBGhost)

*   **描述**：SMBv3协议处理压缩数据包时的整数溢出漏洞。
*   **影响范围**：Windows 10 v1903/1909。
*   **特点**：既可用于远程代码执行（RCE），也可用于本地提权（LPE）。

### 4.3 CVE-2021-1732 (Win32k)

*   **描述**：Win32kFull.sys中的逻辑漏洞，涉及窗口对象的回调处理。
*   **影响范围**：Windows 10多个版本。
*   **特点**：曾被用于野外攻击，利用技术较为精妙。

## 五、漏洞利用实战流程

1.  **信息收集**：使用 `systeminfo` 查看补丁情况，或使用脚本（如 `Sherlock`, `Windows-Exploit-Suggester`）辅助探测。
    ```cmd
    systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
    ```
2.  **选择Exp**：根据系统版本和补丁情况，在Exploit-DB或GitHub寻找对应Exp。
3.  **编译/免杀**：部分Exp为源码（C/C++），需在相同环境下编译；若有杀软，需进行免杀处理。
4.  **执行提权**：在目标机器执行Exp，通常会弹出一个新的CMD窗口，权限为SYSTEM。
    ```cmd
    > exploit.exe
    [+] Exploiting...
    [+] Token stealing successful!
    [+] Spawning SYSTEM shell...
    ```

## 六、安全建议

1.  **及时打补丁**：内核漏洞通常由微软每月的安全更新修复。
2.  **开启防护机制**：启用SMEP（Supervisor Mode Execution Prevention）、SMAP等硬件防护。
3.  **最小权限原则**：服务和应用尽量不要以SYSTEM权限运行。
