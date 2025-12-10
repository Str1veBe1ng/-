# 课时03 - if-else语句识别分析

## 课程目标

1. 掌握if-else语句的汇编实现特征
2. 学会识别并还原条件分支逻辑
3. 理解编译器优化对代码的影响
4. 掌握复杂条件表达式的分析

## 名词解释

| 术语 | 英文 | 说明 |
|------|------|------|
| 条件跳转 | Conditional Jump | 根据条件决定是否跳转 |
| 短路求值 | Short-circuit Evaluation | 逻辑运算的优化求值 |
| 条件移动 | CMOVcc | 条件传送指令，避免跳转 |
| 分支合并 | Branch Merging | 多个分支合并的优化 |

## 使用工具

| 工具 | 用途 |
|------|------|
| IDA Pro | 查看控制流图 |
| Ghidra | 反编译查看伪代码 |

## 技术原理

### 基本if-else结构

```
if (condition) {
    true_branch
} else {
    false_branch
}

对应汇编模式:
cmp/test condition
jcc else_label      ; 条件不满足跳转
    true_branch
    jmp end_label   ; 跳过else
else_label:
    false_branch
end_label:
```

### 常见比较模式

| C代码 | 汇编模式 |
|--------|----------|
| if (a == b) | cmp a, b; jne else |
| if (a != b) | cmp a, b; je else |
| if (a > b) | cmp a, b; jle else |
| if (a < b) | cmp a, b; jge else |
| if (a) | test a, a; jz else |
| if (!a) | test a, a; jnz else |

## 代码实现

### 示例1：简单if-else

```c
int SimpleIf(int a, int b) {
    if (a > b) {
        return 1;
    } else {
        return 0;
    }
}

// 反汇编：
// push ebp
// mov ebp, esp
// mov eax, [ebp+8]     ; a
// cmp eax, [ebp+12]    ; 比较 a 和 b
// jle short loc_else   ; a <= b 则跳转
// mov eax, 1           ; return 1
// jmp short loc_end
// loc_else:
// xor eax, eax         ; return 0
// loc_end:
// pop ebp
// ret
```

### 示例2：if-else if-else链

```c
int GradeLevel(int score) {
    if (score >= 90) {
        return 'A';
    } else if (score >= 80) {
        return 'B';
    } else if (score >= 60) {
        return 'C';
    } else {
        return 'F';
    }
}

// 反汇编特征：多个比较和跳转
// cmp [ebp+8], 90
// jl check_80
// mov eax, 'A'
// jmp end
// check_80:
// cmp [ebp+8], 80
// jl check_60
// mov eax, 'B'
// jmp end
// check_60:
// cmp [ebp+8], 60
// jl fail
// mov eax, 'C'
// jmp end
// fail:
// mov eax, 'F'
// end:
// ret
```

### 示例3：复合条件（短路求值）

```c
int CheckRange(int x) {
    // && 短路求值
    if (x >= 0 && x <= 100) {
        return 1;
    }
    return 0;
}

// 反汇编：
// mov eax, [ebp+8]
// test eax, eax        ; x >= 0?
// js fail              ; 负数则失败（短路）
// cmp eax, 100         ; x <= 100?
// jg fail              ; 大于100则失败
// mov eax, 1
// ret
// fail:
// xor eax, eax
// ret

int CheckEither(int x) {
    // || 短路求值
    if (x < 0 || x > 100) {
        return 1;
    }
    return 0;
}

// 反汇编：
// mov eax, [ebp+8]
// test eax, eax
// js success           ; 负数则成功（短路）
// cmp eax, 100
// jle fail             ; 0-100范围内则失败
// success:
// mov eax, 1
// ret
// fail:
// xor eax, eax
// ret
```

### 示例4：条件移动优化

```c
int Max(int a, int b) {
    return (a > b) ? a : b;
}

// 未优化版本（有跳转）:
// cmp eax, ebx
// jle use_b
// ; use a
// jmp end
// use_b:
// mov eax, ebx
// end:
// ret

// 优化版本（使用CMOV）:
// cmp eax, ebx
// cmovle eax, ebx      ; 如果 a <= b，则 eax = ebx
// ret
```

### 示例5：指针空检查

```c
int SafeAccess(int* ptr) {
    if (ptr != NULL) {
        return *ptr;
    }
    return -1;
}

// 反汇编：
// mov eax, [ebp+8]     ; ptr
// test eax, eax        ; ptr != NULL?
// jz null_ptr          ; 为NULL则跳转
// mov eax, [eax]       ; return *ptr
// ret
// null_ptr:
// or eax, -1           ; return -1
// ret
```

### 示例6：识别并还原的实战

```c
// 原始反汇编：
/*
sub_401000:
    push ebp
    mov ebp, esp
    mov eax, [ebp+8]
    mov ecx, [ebp+0Ch]
    cmp eax, ecx
    jnz loc_401020
    mov eax, [ebp+10h]
    test eax, eax
    jz loc_401020
    mov eax, 1
    jmp loc_401025
loc_401020:
    xor eax, eax
loc_401025:
    pop ebp
    ret
*/

// 还原后的C代码：
int sub_401000(int a, int b, int c) {
    if (a == b && c != 0) {
        return 1;
    }
    return 0;
}
```

## 课后作业

1. **基础练习**：编写包含多级if-else的函数，观察生成的汇编
2. **复合条件**：分析包含&&和||的条件表达式
3. **优化对比**：比较Debug和Release编译的if-else差异
4. **实战还原**：从反汇编代码还原一个if-else逻辑