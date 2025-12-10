# 课时06：EFLAGS标志寄存器

## 课程目标
- 理解EFLAGS寄存器的结构
- 掌握常用标志位的含义
- 理解标志位如何影响条件跳转
- 掌握标志位操作指令

---

## 名词解释

| 标志 | 位 | 说明 |
|------|-----|------|
| CF | 0 | 进位标志 |
| PF | 2 | 奇偶标志 |
| AF | 4 | 辅助进位 |
| ZF | 6 | 零标志 |
| SF | 7 | 符号标志 |
| TF | 8 | 陷阱标志 |
| IF | 9 | 中断标志 |
| DF | 10 | 方向标志 |
| OF | 11 | 溢出标志 |

---

## 代码实现

### 1. 标志位查看

```c
#include <stdio.h>
#include <windows.h>

void PrintFlags(DWORD eflags) {
    printf("【EFLAGS: 0x%08X】\n", eflags);
    printf("  CF=%d (Carry)\n", (eflags >> 0) & 1);
    printf("  PF=%d (Parity)\n", (eflags >> 2) & 1);
    printf("  ZF=%d (Zero)\n", (eflags >> 6) & 1);
    printf("  SF=%d (Sign)\n", (eflags >> 7) & 1);
    printf("  TF=%d (Trap)\n", (eflags >> 8) & 1);
    printf("  IF=%d (Interrupt)\n", (eflags >> 9) & 1);
    printf("  DF=%d (Direction)\n", (eflags >> 10) & 1);
    printf("  OF=%d (Overflow)\n", (eflags >> 11) & 1);
}

int main() {
    printf("=== EFLAGS标志寄存器 ===\n\n");
    
    DWORD flags;
    
    // 测试零标志
    printf("【测试ZF】0 - 0:\n");
    __asm {
        mov eax, 0
        sub eax, 0      // 结果为0, ZF=1
        pushfd
        pop flags
    }
    PrintFlags(flags);
    
    // 测试进位和溢出
    printf("\n【测试CF】FFFFFFFFh + 1:\n");
    __asm {
        mov eax, 0FFFFFFFFh
        add eax, 1      // CF=1
        pushfd
        pop flags
    }
    PrintFlags(flags);
    
    // 测试符号标志
    printf("\n【测试SF】0 - 1:\n");
    __asm {
        mov eax, 0
        sub eax, 1      // 结果为负, SF=1
        pushfd
        pop flags
    }
    PrintFlags(flags);
    
    return 0;
}
```

### 2. 标志位操作

```asm
.code
FlagOps PROC
    ; 设置/清除进位标志
    stc                 ; CF = 1
    clc                 ; CF = 0
    cmc                 ; CF = !CF
    
    ; 设置/清除方向标志
    std                 ; DF = 1 (向下)
    cld                 ; DF = 0 (向上)
    
    ; 保存和恢复标志
    pushfd              ; 压栈EFLAGS
    popfd               ; 出栈到EFLAGS
    
    ; LAHF/SAHF - 加载/存储低8位标志到AH
    lahf                ; AH = FLAGS低8位
    sahf                ; FLAGS低8位 = AH
    
    ret
FlagOps ENDP
```

---

## 课后作业

### 作业1：检测溢出
实现加法并通过OF检测有符号溢出。

### 作业2：结果分类
根据运算结果的标志位判断正数/负数/零。
