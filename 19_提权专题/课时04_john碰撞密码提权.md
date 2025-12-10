# 课时04 john碰撞密码提权

## 一、课程目标

本节课主要学习使用John the Ripper（john）工具进行密码碰撞以实现提权的技术和方法。密码碰撞是一种重要的离线密码破解技术，在渗透测试中经常用于获取系统用户密码。通过本课的学习，你将能够：

1. 理解密码碰撞的基本原理和工作机制
2. 掌握John the Ripper工具的使用方法
3. 学会提取和处理各种密码哈希格式
4. 了解密码碰撞的优化技术和防护措施
5. 熟悉常见密码哈希格式的破解方法

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| John the Ripper | 一款开源的密码破解工具 |
| Hash | 密码经过哈希算法计算后的结果 |
| 碰撞 | 通过计算找到与目标哈希相同的明文 |
| 字典攻击 | 使用预定义单词列表进行密码破解 |
| 暴力破解 | 尝试所有可能的字符组合 |
| 彩虹表 | 预计算的哈希值与明文对照表 |
| Salt | 哈希计算中的随机值，增加安全性 |
| GPU加速 | 使用图形处理器加速密码破解 |

## 三、技术原理

### 3.1 密码哈希概述

密码哈希是将明文密码转换为固定长度字符串的过程，用于安全存储用户密码。

#### 哈希算法特性
1. **单向性**：从明文计算哈希容易，从哈希反推明文困难
2. **确定性**：相同输入产生相同输出
3. **雪崩效应**：微小输入变化导致输出巨大变化
4. **抗碰撞性**：难以找到两个不同输入产生相同输出

#### 常见哈希算法
- **MD5**：128位，已不安全
- **SHA-1**：160位，逐渐被淘汰
- **SHA-256**：256位，目前广泛使用
- **bcrypt**：带salt的哈希算法
- **scrypt**：内存密集型哈希算法

### 3.2 John the Ripper工作原理

#### 破解模式
1. **Single Crack Mode**：使用用户名和GECOS字段生成候选密码
2. **Wordlist Mode**：使用字典文件进行破解
3. **Incremental Mode**：暴力破解模式
4. **External Mode**：使用外部程序生成候选密码

#### 破解流程
1. 提取目标系统的密码哈希
2. 识别哈希格式
3. 选择合适的破解模式
4. 执行破解过程
5. 分析破解结果

### 3.3 提权原理

#### 利用条件
1. 能够获取目标系统的密码哈希
2. 哈希算法相对较弱或密码较简单
3. 有足够的计算资源和时间

#### 提权过程
1. 获取/etc/shadow或其他密码存储文件
2. 提取用户哈希信息
3. 使用john进行密码碰撞
4. 获得明文密码
5. 使用密码登录高权限账户

## 四、John工具基础使用

### 4.1 安装和配置

#### Linux系统安装
```bash
# Ubuntu/Debian系统
sudo apt-get update
sudo apt-get install john

# CentOS/RHEL系统
sudo yum install john

# 从源码编译安装
git clone https://github.com/magnumripper/JohnTheRipper.git
cd JohnTheRipper/src
./configure && make
```

#### 基本命令语法
```bash
# 基本语法
john [options] password-files

# 常用选项
--format=format    # 指定哈希格式
--wordlist=file    # 指定字典文件
--rules            # 使用规则变换
--incremental      # 使用增量模式
--show             # 显示已破解的密码
```

### 4.2 哈希格式识别

#### 自动识别
```bash
# john会自动识别大多数标准哈希格式
john hash.txt

# 显示识别到的格式
john --list=formats
```

#### 手动指定格式
```bash
# 常见格式指定
john --format=md5 hash.txt
john --format=sha1 hash.txt
john --format=sha256 hash.txt
john --format=bcrypt hash.txt
john --format=crypt hash.txt
```

### 4.3 基本破解示例

#### 字典攻击
```bash
# 使用默认字典
john --wordlist=/usr/share/john/password.lst hash.txt

# 使用自定义字典
john --wordlist=/path/to/custom.dict hash.txt

# 使用规则变换
john --wordlist=/path/to/dict --rules hash.txt
```

#### 暴力破解
```bash
# 使用默认字符集
john --incremental hash.txt

# 使用ASCII字符集
john --incremental=ASCII hash.txt

# 使用数字字符集
john --incremental=Digits hash.txt
```

## 五、密码哈希提取

### 5.1 Linux系统哈希提取

#### /etc/shadow文件
```bash
# 查看shadow文件格式
cat /etc/shadow

# 输出示例：
# username:$6$salt$hash:18032:0:99999:7:::

# 提取特定用户哈希
grep "^username:" /etc/shadow > user_hash.txt

# 批量提取所有用户哈希
cut -d: -f1,2 /etc/shadow > all_hashes.txt
```

#### /etc/passwd文件
```bash
# 查看passwd文件（通常不含哈希）
cat /etc/passwd

# 如果passwd文件包含哈希（旧系统）
grep -v "^[^:]*:[x]" /etc/passwd > old_style_hashes.txt
```

### 5.2 数据库哈希提取

#### MySQL哈希
```sql
-- 提取MySQL用户哈希
SELECT User, Password FROM mysql.user;

-- 输出示例：
-- User: root
-- Password: *6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9
```

#### PostgreSQL哈希
```sql
-- 提取PostgreSQL用户哈希
SELECT usename, passwd FROM pg_shadow;

-- 输出示例：
-- usename: postgres
-- passwd: md53175bce1d3201d16594cebf9d7eb3f9d
```

### 5.3 Windows系统哈希提取

#### SAM哈希
```bash
# 使用mimikatz提取SAM哈希
mimikatz # privilege::debug
mimikatz # token::whoami
mimikatz # lsadump::sam

# 输出示例：
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

#### NTLM哈希
```bash
# NTLM哈希格式
username:RID:LMHash:NTHash:::

# 示例：
john:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

## 六、高级破解技术

### 6.1 规则变换

#### 内置规则
```bash
# 使用内置规则
john --wordlist=dict.txt --rules hash.txt

# 查看可用规则
john --list=rules

# 使用特定规则
john --wordlist=dict.txt --rules=Single hash.txt
john --wordlist=dict.txt --rules=Extra hash.txt
```

#### 自定义规则
```bash
# 创建自定义规则文件
cat > custom.rules << 'EOF'
# 自定义规则示例
# 在单词末尾添加年份
$0 $1 $2 $3 $4 $5 $6 $7 $8 $9
# 在单词首字母大写
c
# 双写最后一个字符
$
# 添加特殊字符
$! $? $@ $# $%
EOF

# 使用自定义规则
john --wordlist=dict.txt --rules=custom.rules hash.txt
```

### 6.2 GPU加速破解

#### OpenCL支持
```bash
# 检查OpenCL支持
john --list=opencl-devices

# 使用GPU加速
john --format=raw-sha256 --wordlist=dict.txt --opencl hash.txt

# 指定特定GPU设备
john --format=raw-md5 --wordlist=dict.txt --opencl=gpu,device=1 hash.txt
```

#### CUDA支持
```bash
# 检查CUDA支持
john --list=cuda-devices

# 使用CUDA加速
john --format=raw-sha512 --wordlist=dict.txt --cuda hash.txt
```

### 6.3 分布式破解

#### 会话恢复
```bash
# 保存破解会话
john --wordlist=dict.txt --session=my_session hash.txt

# 恢复破解会话
john --restore=my_session

# 列出所有会话
john --list=ses
```

#### 多进程破解
```bash
# 使用多个核心
john --wordlist=dict.txt --fork=4 hash.txt

# 指定核心数
nproc  # 查看CPU核心数
john --wordlist=dict.txt --fork=$(nproc) hash.txt
```

## 七、优化破解效率

### 7.1 字典优化

#### 高效字典制作
```bash
# 合并多个字典
cat dict1.txt dict2.txt dict3.txt > combined_dict.txt

# 去重排序
sort combined_dict.txt | uniq > optimized_dict.txt

# 按频率排序
cat passwords.txt | sort | uniq -c | sort -nr | awk '{print $2}' > freq_sorted_dict.txt
```

#### 针对性字典
```bash
# 根据目标信息制作字典
# 包含公司名称、员工姓名、生日等
cat > target_dict.txt << 'EOF'
Company123
CompanyName2023
employee123
birthday1990
season2023
EOF
```

### 7.2 破解策略

#### 分层破解
```bash
# 第一层：常用密码字典
john --wordlist=/usr/share/john/password.lst hash.txt

# 第二层：针对性字典
john --wordlist=target_dict.txt --rules hash.txt

# 第三层：暴力破解短密码
john --incremental=ASCII --max-length=6 hash.txt

# 第四层：复杂暴力破解
john --incremental=All --min-length=7 --max-length=8 hash.txt
```

#### 并行破解
```bash
# 同时运行多个john实例
john --wordlist=dict1.txt --session=session1 hash.txt &
john --wordlist=dict2.txt --session=session2 hash.txt &
john --incremental=Digits --session=session3 hash.txt &
```

## 八、防护措施

### 8.1 密码安全

#### 强密码策略
```bash
# 配置密码复杂度要求
# /etc/pam.d/common-password
password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1

# 设置密码过期策略
# /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
```

#### 多因素认证
```bash
# 配置Google Authenticator
apt-get install libpam-google-authenticator
google-authenticator

# 编辑PAM配置
# /etc/pam.d/sshd
auth required pam_google_authenticator.so
```

### 8.2 系统加固

#### 限制登录尝试
```bash
# 配置fail2ban
apt-get install fail2ban

# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
```

#### 监控密码文件
```bash
# 使用auditd监控敏感文件
echo "-w /etc/shadow -p wa -k shadow_access" >> /etc/audit/rules.d/shadow.rules
echo "-w /etc/passwd -p wa -k passwd_access" >> /etc/audit/rules.d/passwd.rules

# 重启auditd服务
systemctl restart auditd
```

## 九、实战案例

### 9.1 Linux系统密码破解

#### 环境准备
```bash
# 创建测试用户
sudo useradd -m testuser
echo "testuser:testpass123" | sudo chpasswd

# 提取用户哈希
sudo grep "^testuser:" /etc/shadow > test_hash.txt
cat test_hash.txt
# 输出示例：testuser:$6$salt$hash:18032:0:99999:7:::
```

#### 破解过程
```bash
# 1. 使用字典攻击
john --wordlist=/usr/share/john/password.lst test_hash.txt

# 2. 使用规则变换
john --wordlist=/usr/share/john/password.lst --rules test_hash.txt

# 3. 检查破解结果
john --show test_hash.txt
# 输出示例：testuser:testpass123:1001:1001::/home/testuser:/bin/bash
```

#### 验证提权
```bash
# 使用破解的密码登录
su - testuser
# 输入密码: testpass123

# 验证权限
id
whoami
```

### 9.2 复杂密码破解

#### 多层破解策略
```bash
# 1. 首先使用常用密码字典
john --wordlist=/usr/share/john/password.lst hashes.txt

# 2. 使用针对性字典
john --wordlist=target_specific.dict --rules hashes.txt

# 3. 暴力破解短密码
john --incremental=ASCII --max-length=6 hashes.txt

# 4. 使用GPU加速破解
john --format=sha512crypt --wordlist=large.dict --opencl hashes.txt
```

#### 性能优化
```bash
# 查看系统资源
nproc          # CPU核心数
free -h        # 内存使用情况
nvidia-smi     # GPU使用情况（如果有）

# 优化john配置
# ~/.john/john.conf
[Options]
WordlistTimer = 10
Idle = Y
```

## 十、故障排除

### 10.1 常见问题

#### 哈希格式识别失败
```bash
# 手动指定格式
john --format=sha512crypt hash.txt

# 查看支持的格式
john --list=formats | grep sha

# 检查哈希格式是否正确
cat hash.txt
# 确保格式符合john的要求
```

#### 字典文件问题
```bash
# 检查字典文件编码
file dict.txt
# 如果是DOS格式，转换为Unix格式
dos2unix dict.txt

# 检查文件权限
ls -l dict.txt
# 确保有读取权限
chmod 644 dict.txt
```

#### 性能问题
```bash
# 限制CPU使用率
nice -n 19 john --wordlist=dict.txt hash.txt

# 使用ionice降低I/O优先级
ionice -c 3 john --wordlist=dict.txt hash.txt

# 指定核心数
john --wordlist=dict.txt --fork=2 hash.txt
```

### 10.2 结果验证

#### 验证破解结果
```bash
# 显示已破解的密码
john --show hash.txt

# 显示特定格式的结果
john --show --format=sha512crypt hash.txt

# 输出到文件
john --show hash.txt > cracked_passwords.txt
```

#### 清理会话文件
```bash
# 删除会话文件
rm ~/.john/john.pot
rm ~/.john/john.log

# 或者清除特定会话
john --clean-session=my_session
```

## 十一、课后作业

1. **基础练习**：
   - 在实验环境中创建多个测试用户
   - 使用不同强度的密码进行测试
   - 练习使用john进行密码破解
   - 验证破解结果并分析成功率

2. **进阶练习**：
   - 制作针对性字典文件
   - 编写自定义规则文件
   - 配置GPU加速破解环境
   - 实现分布式破解策略

3. **思考题**：
   - 密码碰撞攻击的有效性受哪些因素影响？
   - 如何在保证用户体验的前提下提高密码安全性？
   - 现代密码学如何防御密码碰撞攻击？

4. **扩展阅读**：
   - 研究新型哈希算法（如Argon2）
   - 了解硬件加速密码破解技术
   - 学习零知识证明密码验证