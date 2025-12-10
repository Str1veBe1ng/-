# 课时02：Linux环境配置

## 1. 课程目标

本课时将详细介绍如何在Linux系统上配置C/C++开发环境，包括：
- 安装GCC/G++编译器
- 安装必要的开发工具
- 配置Vim/VS Code开发环境
- 编译运行第一个程序

---

## 2. 安装GCC编译器

### 2.1 Ubuntu/Debian系列

```bash
# 更新软件包列表
sudo apt update

# 安装build-essential（包含gcc, g++, make等）
sudo apt install -y build-essential

# 安装调试器和其他工具
sudo apt install -y gdb cmake git

# 安装开发库
sudo apt install -y libssl-dev libcurl4-openssl-dev

# 验证安装
gcc --version
g++ --version
make --version
gdb --version
```

### 2.2 CentOS/RHEL/Fedora系列

```bash
# CentOS/RHEL 7/8
sudo yum groupinstall -y "Development Tools"
sudo yum install -y gcc gcc-c++ gdb cmake git

# Fedora
sudo dnf groupinstall -y "Development Tools"
sudo dnf install -y gcc gcc-c++ gdb cmake git

# 验证
gcc --version
```

### 2.3 Arch Linux

```bash
sudo pacman -S base-devel gdb cmake git

# 验证
gcc --version
```

### 2.4 Kali Linux（安全研究常用）

```bash
# Kali基于Debian，同样使用apt
sudo apt update
sudo apt install -y build-essential gdb cmake git

# 安装安全开发常用工具
sudo apt install -y nasm binutils-dev

# 验证
gcc --version
nasm --version
```

---

## 3. GCC编译器基础使用

### 3.1 编译流程图

```
源代码(.c/.cpp) → 预处理(.i) → 编译(.s) → 汇编(.o) → 链接(ELF可执行文件)
```

### 3.2 编译步骤详解

```bash
# 1. 预处理：展开宏、包含头文件
gcc -E main.c -o main.i

# 2. 编译：生成汇编代码
gcc -S main.i -o main.s

# 3. 汇编：生成目标文件
gcc -c main.s -o main.o

# 4. 链接：生成可执行文件
gcc main.o -o main

# 一步完成
gcc main.c -o main
```

### 3.3 常用编译选项

```bash
# 基本编译
gcc source.c -o output
g++ source.cpp -o output

# 启用调试信息
gcc -g source.c -o output

# 优化级别
gcc -O0 source.c -o output  # 无优化（调试用）
gcc -O2 source.c -o output  # 常用优化
gcc -O3 source.c -o output  # 最高优化
gcc -Os source.c -o output  # 优化代码大小

# 警告选项
gcc -Wall source.c          # 开启所有警告
gcc -Wextra source.c        # 额外警告
gcc -Werror source.c        # 警告视为错误

# 指定标准
gcc -std=c11 source.c       # C11标准
g++ -std=c++17 source.cpp   # C++17标准
```

---

## 4. 安全开发特殊编译选项

### 4.1 安全编译选项

```bash
# 启用栈保护（默认开启）
gcc -fstack-protector-all source.c -o output

# 启用地址空间随机化
gcc -pie -fPIE source.c -o output

# 启用RELRO
gcc -Wl,-z,relro,-z,now source.c -o output

# 启用所有安全选项
gcc -fstack-protector-all -pie -fPIE -Wl,-z,relro,-z,now source.c -o output
```

### 4.2 漏洞研究/安全测试编译选项

```bash
# 禁用栈保护（用于缓冲区溢出实验）
gcc -fno-stack-protector source.c -o output

# 禁用PIE
gcc -no-pie source.c -o output

# 栈可执行（用于Shellcode测试）
gcc -z execstack source.c -o output

# 完全禁用安全特性（仅用于漏洞研究）
gcc -fno-stack-protector -z execstack -no-pie source.c -o output

# 32位编译（在64位系统上）
gcc -m32 source.c -o output
# 需要安装：sudo apt install gcc-multilib
```

### 4.3 Shellcode编译选项

```bash
# 生成位置无关代码
gcc -fPIC -pie source.c -o output

# 开启所有段为可执行（不安全，仅测试）
gcc -Wl,-N source.c -o output

# 使用NASM编译汇编
nasm -f elf64 shellcode.asm -o shellcode.o
ld shellcode.o -o shellcode
```

---

## 5. 开发工具配置

### 5.1 Vim配置

编辑 `~/.vimrc`：

```vim
" 基本设置
set number              " 显示行号
set tabstop=4           " Tab宽度
set shiftwidth=4        " 缩进宽度
set expandtab           " Tab转空格
set autoindent          " 自动缩进
set syntax=on           " 语法高亮
set hlsearch            " 搜索高亮
set mouse=a             " 启用鼠标

" C/C++编译快捷键
autocmd FileType c nnoremap <F5> :w<CR>:!gcc -g -Wall % -o %< && ./%<<CR>
autocmd FileType cpp nnoremap <F5> :w<CR>:!g++ -g -Wall % -o %< && ./%<<CR>

" 调试快捷键
autocmd FileType c,cpp nnoremap <F6> :w<CR>:!gcc -g % -o %< && gdb ./%<<CR>
```

### 5.2 VS Code远程开发

1. 安装扩展：**Remote - SSH**
2. 连接Linux服务器
3. 安装C/C++扩展
4. 配置同Windows篇

---

## 6. GDB调试器基础

### 6.1 启动调试

```bash
# 编译时加入调试信息
gcc -g source.c -o program

# 启动GDB
gdb ./program

# 或者附加到进程
gdb -p <PID>
```

### 6.2 常用GDB命令

```gdb
# 设置断点
break main              # 在main函数设置断点
break 10                # 在第10行设置断点
break *0x400520         # 在地址设置断点

# 运行
run                     # 运行程序
run arg1 arg2           # 带参数运行
continue                # 继续运行

# 单步执行
next                    # 单步（跨过函数）
step                    # 单步（进入函数）
nexti                   # 指令级单步
stepi                   # 指令级单步（进入）
finish                  # 执行到函数返回

# 查看信息
info registers          # 查看寄存器
info breakpoints        # 查看断点
info frame              # 查看栈帧
info proc mappings      # 查看内存映射

# 查看内存
x/10x $rsp              # 查看栈顶10个十六进制字
x/s 0x400600            # 查看字符串
x/i $rip                # 查看当前指令

# 查看变量
print variable          # 打印变量
print/x variable        # 十六进制打印
display variable        # 每步显示变量

# 反汇编
disassemble main        # 反汇编main函数
disassemble /r main     # 显示机器码

# 退出
quit
```

### 6.3 GDB配置文件

创建 `~/.gdbinit`：

```gdb
# 启用历史记录
set history save on
set history filename ~/.gdb_history

# 设置反汇编风格
set disassembly-flavor intel

# 显示下一条指令
display/i $pc

# 禁用确认提示
set confirm off
```

---

## 7. Make和Makefile

### 7.1 基本Makefile结构

```makefile
# 编译器设置
CC = gcc
CXX = g++
CFLAGS = -Wall -g
CXXFLAGS = -Wall -g -std=c++17

# 目标
TARGET = program
SRCS = main.c utils.c
OBJS = $(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 链接
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET)

# 编译
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理
clean:
	rm -f $(OBJS) $(TARGET)

# 重新编译
rebuild: clean all

.PHONY: all clean rebuild
```

### 7.2 使用Make

```bash
make            # 编译
make clean      # 清理
make rebuild    # 重新编译
make -j4        # 并行编译（4线程）
```

---

## 8. 实战测试

### 8.1 创建测试程序

```c
// test.c
#include <stdio.h>
#include <unistd.h>
#include <sys/utsname.h>

int main() {
    struct utsname info;
    uname(&info);
    
    printf("[*] Linux C/C++ Environment Test\n");
    printf("[*] System: %s\n", info.sysname);
    printf("[*] Node: %s\n", info.nodename);
    printf("[*] Release: %s\n", info.release);
    printf("[*] Machine: %s\n", info.machine);
    printf("[*] PID: %d\n", getpid());
    printf("[*] UID: %d\n", getuid());
    
    return 0;
}
```

### 8.2 编译运行

```bash
gcc -o test test.c
./test
```

预期输出：
```
[*] Linux C/C++ Environment Test
[*] System: Linux
[*] Node: your-hostname
[*] Release: 5.15.0-generic
[*] Machine: x86_64
[*] PID: 12345
[*] UID: 1000
```

---

## 9. 常见问题排查

### 9.1 找不到头文件

```bash
# 安装开发库
sudo apt install libc6-dev

# 查找头文件位置
find /usr -name "stdio.h"
```

### 9.2 链接错误

```bash
# 查看库依赖
ldd ./program

# 添加库路径
export LD_LIBRARY_PATH=/path/to/lib:$LD_LIBRARY_PATH

# 编译时指定库
gcc source.c -L/path/to/lib -lmylib -o output
```

### 9.3 32位编译支持

```bash
# Ubuntu/Debian
sudo apt install gcc-multilib g++-multilib

# 编译32位程序
gcc -m32 source.c -o output32
```

---

## 10. 课后练习

1. 在Linux上安装GCC开发环境
2. 编写程序读取 `/etc/passwd` 内容
3. 编写Makefile管理多文件项目
4. 使用GDB调试并观察内存和寄存器

---

## 11. 下一课预告

下一课我们将编写第一个C/C++程序，理解程序的基本结构。
