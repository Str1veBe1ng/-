# 课时07：JCC指令

## 课程目标
- 掌握无条件跳转指令
- 掌握条件跳转指令
- 理解CMP指令与跳转的关系
- 能够实现if/else和循环逻辑

---

## 名词解释

| 指令 | 条件 | 说明 |
|------|------|------|
| JMP | 无 | 无条件跳转 |
| JE/JZ | ZF=1 | 相等/为零 |
| JNE/JNZ | ZF=0 | 不相等/非零 |
| JA/JNBE | CF=0, ZF=0 | 无符号大于 |
| JB/JNAE | CF=1 | 无符号小于 |
| JG/JNLE | ZF=0, SF=OF | 有符号大于 |
| JL/JNGE | SF!=OF | 有符号小于 |
| JS | SF=1 | 结果为负 |
| JC | CF=1 | 有进位 |
| JO | OF=1 | 有溢出 |

---

## 代码实现

### 1. if-else实现

```asm
.code
; if (eax > ebx) ecx = 1 else ecx = 0
IfElse PROC
    cmp eax, ebx        ; 比较eax和ebx
    jle else_branch     ; 如果eax <= ebx, 跳转
    
    ; if分支
    mov ecx, 1
    jmp end_if
    
else_branch:
    ; else分支
    mov ecx, 0
    
end_if:
    ret
IfElse ENDP
```

### 2. 循环实现

```asm
.code
; for (ecx = 10; ecx > 0; ecx--) { eax += ecx; }
ForLoop PROC
    xor eax, eax        ; eax = 0
    mov ecx, 10         ; ecx = 10
    
loop_start:
    test ecx, ecx       ; 检查ecx是否为0
    jz loop_end         ; 如果为0, 退出
    
    add eax, ecx        ; eax += ecx
    dec ecx             ; ecx--
    jmp loop_start
    
loop_end:
    ; eax = 55 (1+2+...+10)
    ret
ForLoop ENDP

; 使用LOOP指令
LoopExample PROC
    xor eax, eax
    mov ecx, 10         ; 计数器
    
loop_body:
    add eax, ecx
    loop loop_body      ; ecx--, 如果ecx!=0则跳转
    
    ret
LoopExample ENDP
```

### 3. C语言示例

```c
#include <stdio.h>

int Max(int a, int b) {
    int result;
    __asm {
        mov eax, a
        cmp eax, b
        jge a_is_greater
        mov eax, b
    a_is_greater:
        mov result, eax
    }
    return result;
}

int Sum1ToN(int n) {
    int sum;
    __asm {
        xor eax, eax        ; sum = 0
        mov ecx, n          ; counter = n
    sum_loop:
        test ecx, ecx
        jz sum_done
        add eax, ecx
        dec ecx
        jmp sum_loop
    sum_done:
        mov sum, eax
    }
    return sum;
}

int main() {
    printf("=== JCC指令 ===\n\n");
    
    printf("Max(10, 20) = %d\n", Max(10, 20));
    printf("Max(30, 15) = %d\n", Max(30, 15));
    printf("Sum(1..10) = %d\n", Sum1ToN(10));
    
    return 0;
}
```

---

## 课后作业

### 作业1：实现查找
用汇编实现数组中查找指定元素。

### 作业2：实现排序
用汇编实现冒泡排序。
