# 课时04 - switch语句识别分析

## 课程目标

1. 掌握switch语句的多种汇编实现方式
2. 理解跳转表的工作原理
3. 学会识别和还原switch结构
4. 理解编译器的优化策略

## 名词解释

| 术语 | 英文 | 说明 |
|------|------|------|
| 跳转表 | Jump Table | 存储case地址的数组，O(1)查找 |
| 二分查找 | Binary Search | 稀疏case值的优化方式 |
| case密度 | Case Density | case值的分布密集程度 |
| 默认分支 | Default Branch | 没有匹配的处理分支 |

## 使用工具

| 工具 | 用途 |
|------|------|
| IDA Pro | 识别跳转表结构 |
| Ghidra | 自动还原switch语句 |

## 技术原理

### switch实现方式

| case特征 | 实现方式 |
|----------|----------|
| 少量连续 | 跳转表 |
| 大量连续 | 跳转表 |
| 稀疏分散 | if-else链或二分查找 |
| 混合 | 多级跳转表 |

### 跳转表结构

```
跳转表地址 + 偏移量 * 条目大小 = 目标地址
jmp dword ptr [table + eax*4]
```

## 代码实现

### 示例1：简单switch（if-else实现）

```c
int SimpleSwitch(int x) {
    switch (x) {
        case 1: return 10;
        case 2: return 20;
        case 3: return 30;
        default: return 0;
    }
}

// case数量少时，编译器可能生成if-else链:
// cmp eax, 1
// jz case_1
// cmp eax, 2
// jz case_2
// cmp eax, 3
// jz case_3
// jmp default
```

### 示例2：跳转表实现

```c
int TableSwitch(int x) {
    switch (x) {
        case 0: return 100;
        case 1: return 200;
        case 2: return 300;
        case 3: return 400;
        case 4: return 500;
        case 5: return 600;
        default: return 0;
    }
}

// 跳转表实现的汇编：
// mov eax, [ebp+8]         ; x
// cmp eax, 5               ; 范围检查
// ja default               ; x > 5 则跳转default
// jmp dword ptr [jmp_table + eax*4]  ; 跳转表
// 
// 跳转表数据:
// jmp_table:
//   dd offset case_0
//   dd offset case_1
//   dd offset case_2
//   dd offset case_3
//   dd offset case_4
//   dd offset case_5
```

### 示例3：有偏移的跳转表

```c
int OffsetSwitch(int x) {
    switch (x) {
        case 100: return 1;
        case 101: return 2;
        case 102: return 3;
        case 103: return 4;
        default: return 0;
    }
}

// 编译器会减去基准值:
// mov eax, [ebp+8]
// sub eax, 100             ; x - 100
// cmp eax, 3               ; 范围检查 0-3
// ja default
// jmp dword ptr [jmp_table + eax*4]
```

### 示例4：稀疏case（二分查找）

```c
int SparseSwitch(int x) {
    switch (x) {
        case 1:    return 10;
        case 100:  return 20;
        case 1000: return 30;
        case 5000: return 40;
        default:   return 0;
    }
}

// 稀疏case可能用二分查找：
// cmp eax, 100
// jl check_low
// jg check_high
// ; case 100
// jmp case_100
// check_low:
// cmp eax, 1
// jz case_1
// jmp default
// check_high:
// cmp eax, 1000
// jl default
// jz case_1000
// cmp eax, 5000
// jz case_5000
// jmp default
```

### 示例5：fall-through识别

```c
int FallThrough(int x) {
    int result = 0;
    switch (x) {
        case 1:
        case 2:
        case 3:
            result = 10;
            break;
        case 4:
            result = 20;
            // 没有break，fall-through
        case 5:
            result += 5;
            break;
        default:
            result = 0;
    }
    return result;
}

// 跳转表中多个case指向同一地址:
// jmp_table:
//   dd offset case_1_2_3    ; case 1
//   dd offset case_1_2_3    ; case 2
//   dd offset case_1_2_3    ; case 3
//   dd offset case_4        ; case 4
//   dd offset case_5        ; case 5
// 
// case_4:
//   mov [result], 20
//   ; 注意：没有jmp，直接进入case_5
// case_5:
//   add [result], 5
//   jmp end
```

### 示例6：识别并还原switch

```c
// 反汇编特征识别：
/*
1. 查找范围检查:
   sub eax, base    ; 可能有基准对齐
   cmp eax, max
   ja default

2. 查找跳转表访问:
   jmp dword ptr [table + reg*4]
   或
   mov reg, [table + reg*4]
   jmp reg

3. 在IDA中:
   - 看data段中的地址数组
   - 查看交叉引用确认是跳转表
*/

// 还原步骤:
// 1. 找到范围检查 -> 确定case范围
// 2. 找到跳转表 -> 确定各case地址
// 3. 分析各case代码 -> 还原处理逻辑
// 4. 检查是否有fall-through
```

### 示例7：IDA中的switch识别

```
IDA会自动识别switch结构：

1. 在反汇编视图中显示:
   switch ( eax )
   {
     case 0:
       ...
     case 1:
       ...
   }

2. 在图形视图中：
   - 显示为多分支结构
   - 用不同颜色标记各case

3. 查看跳转表：
   - 双击跳转表地址
   - 查看完整的地址列表
```

## 课后作业

1. **基础练习**：编写不同case数量的switch，观察编译结果
2. **跳转表分析**：在IDA中找到并分析一个跳转表
3. **稀疏case**：分析稀疏case值的switch实现
4. **实战还原**：从反汇编中完整还原一个switch语句