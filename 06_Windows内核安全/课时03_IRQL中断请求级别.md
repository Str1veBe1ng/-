# 课时03：IRQL中断请求级别

## 课程目标

1. 理解IRQL的概念和作用
2. 掌握不同IRQL级别的特性
3. 学会在正确的IRQL下执行操作
4. 避免IRQL相关的蓝屏错误

---

## 名词解释

| 术语 | 解释 |
|------|------|
| IRQL | Interrupt Request Level，中断请求级别 |
| PASSIVE_LEVEL | 最低级别，普通线程运行级别 |
| APC_LEVEL | 异步过程调用级别 |
| DISPATCH_LEVEL | 调度级别，不可分页 |
| DPC | Deferred Procedure Call，延迟过程调用 |
| SpinLock | 自旋锁，DISPATCH_LEVEL使用 |

---

## 使用工具

| 工具 | 用途 |
|------|------|
| WinDbg | 查看当前IRQL |
| Driver Verifier | 检测IRQL违规 |
| !irql命令 | 显示当前处理器IRQL |

---

## 技术原理

### IRQL级别层次

```
┌─────────────────────────────────────────────────────────────┐
│                    IRQL 级别层次                            │
│                                                             │
│  级别值   名称              说明                            │
│  ────────────────────────────────────────────────────────  │
│   31    HIGH_LEVEL        机器检查/电源故障                 │
│   30    POWER_LEVEL       电源故障                         │
│   29    IPI_LEVEL         处理器间中断                     │
│   28    CLOCK_LEVEL       时钟中断                         │
│   27    PROFILE_LEVEL     性能分析                         │
│  3-26   DIRQL             设备中断（设备相关）              │
│    2    DISPATCH_LEVEL    调度器/DPC（不可换页）            │
│    1    APC_LEVEL         APC执行（不可APC中断）            │
│    0    PASSIVE_LEVEL     正常线程执行（可换页）            │
│                                                             │
│  注：值越高优先级越高，高IRQL可以打断低IRQL                  │
└─────────────────────────────────────────────────────────────┘
```

### 各级别限制

| IRQL | 可分页内存 | 等待对象 | 访问用户内存 | 常用场景 |
|------|-----------|---------|-------------|---------|
| PASSIVE_LEVEL | 是 | 是 | 是 | DriverEntry、IRP处理 |
| APC_LEVEL | 是 | 是 | 是 | 特殊APC、某些完成例程 |
| DISPATCH_LEVEL | 否 | 否 | 否 | DPC、SpinLock持有时 |
| DIRQL+ | 否 | 否 | 否 | 中断服务例程 |

---

## 代码实现

### 示例1：IRQL基础操作

```c
// IRQLBasics.c - IRQL基础操作
#include <ntddk.h>

VOID DemonstrateIRQL() {
    KIRQL oldIrql;
    KIRQL currentIrql;
    
    // 获取当前IRQL
    currentIrql = KeGetCurrentIrql();
    DbgPrint("[IRQL] Current IRQL: %d\n", currentIrql);
    
    // 判断是否在PASSIVE_LEVEL
    if (currentIrql == PASSIVE_LEVEL) {
        DbgPrint("[IRQL] Running at PASSIVE_LEVEL\n");
        
        // 在PASSIVE_LEVEL可以做的事情：
        // - 访问分页内存
        // - 等待内核对象
        // - 访问用户模式内存
        // - 调用大部分API
    }
    
    // 提升IRQL到DISPATCH_LEVEL
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    DbgPrint("[IRQL] Raised to DISPATCH_LEVEL\n");
    
    // 在DISPATCH_LEVEL的限制：
    // - 不能访问分页内存
    // - 不能等待任何对象（会死锁）
    // - 不能调用会降低IRQL的API
    // - 不能访问用户模式内存
    
    // 降低IRQL
    KeLowerIrql(oldIrql);
    DbgPrint("[IRQL] Lowered back to: %d\n", oldIrql);
}

// 安全的IRQL检查宏
#define ASSERT_PASSIVE_LEVEL() \
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL)

#define ASSERT_DISPATCH_LEVEL_OR_BELOW() \
    ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL)

VOID SafeFunction() {
    ASSERT_PASSIVE_LEVEL();  // 确保在正确的IRQL
    
    // 可以安全地进行需要PASSIVE_LEVEL的操作
}
```

### 示例2：SpinLock与IRQL

```c
// SpinLockIRQL.c - 自旋锁与IRQL
#include <ntddk.h>

typedef struct _MY_CONTEXT {
    KSPIN_LOCK  Lock;
    LIST_ENTRY  ListHead;
    ULONG       ItemCount;
} MY_CONTEXT, *PMY_CONTEXT;

MY_CONTEXT g_Context;

VOID InitializeContext() {
    // 初始化自旋锁
    KeInitializeSpinLock(&g_Context.Lock);
    InitializeListHead(&g_Context.ListHead);
    g_Context.ItemCount = 0;
}

VOID AddItem(PLIST_ENTRY Entry) {
    KIRQL oldIrql;
    
    // 获取自旋锁（自动提升到DISPATCH_LEVEL）
    KeAcquireSpinLock(&g_Context.Lock, &oldIrql);
    
    // 在持有SpinLock期间：
    // - IRQL = DISPATCH_LEVEL
    // - 不能访问分页内存
    // - 操作必须快速完成
    
    InsertTailList(&g_Context.ListHead, Entry);
    g_Context.ItemCount++;
    
    // 释放自旋锁（恢复原IRQL）
    KeReleaseSpinLock(&g_Context.Lock, oldIrql);
}

PLIST_ENTRY RemoveItem() {
    KIRQL oldIrql;
    PLIST_ENTRY entry = NULL;
    
    KeAcquireSpinLock(&g_Context.Lock, &oldIrql);
    
    if (!IsListEmpty(&g_Context.ListHead)) {
        entry = RemoveHeadList(&g_Context.ListHead);
        g_Context.ItemCount--;
    }
    
    KeReleaseSpinLock(&g_Context.Lock, oldIrql);
    
    return entry;
}

// 使用SpinLockAtDpcLevel（已在DISPATCH_LEVEL时）
VOID AddItemAtDpcLevel(PLIST_ENTRY Entry) {
    // 仅当已经在DISPATCH_LEVEL时使用
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    
    KeAcquireSpinLockAtDpcLevel(&g_Context.Lock);
    InsertTailList(&g_Context.ListHead, Entry);
    g_Context.ItemCount++;
    KeReleaseSpinLockFromDpcLevel(&g_Context.Lock);
}
```

### 示例3：DPC延迟过程调用

```c
// DPCExample.c - DPC使用示例
#include <ntddk.h>

typedef struct _DPC_CONTEXT {
    KDPC    Dpc;
    PVOID   Parameter;
    ULONG   Counter;
} DPC_CONTEXT, *PDPC_CONTEXT;

DPC_CONTEXT g_DpcContext;

// DPC回调函数 - 在DISPATCH_LEVEL执行
VOID DpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
) {
    PDPC_CONTEXT ctx = (PDPC_CONTEXT)DeferredContext;
    
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    
    // 确认IRQL
    ASSERT(KeGetCurrentIrql() == DISPATCH_LEVEL);
    
    // 在DPC中执行的操作必须：
    // - 不访问分页内存
    // - 不等待任何对象
    // - 快速完成
    
    ctx->Counter++;
    DbgPrint("[DPC] Counter: %d\n", ctx->Counter);
}

VOID InitializeDpc() {
    // 初始化DPC对象
    KeInitializeDpc(&g_DpcContext.Dpc, DpcRoutine, &g_DpcContext);
    g_DpcContext.Counter = 0;
}

VOID QueueDpc() {
    // 将DPC加入队列
    // DPC将在适当时机在DISPATCH_LEVEL执行
    KeInsertQueueDpc(&g_DpcContext.Dpc, NULL, NULL);
}

// 工作项 - 在PASSIVE_LEVEL执行耗时操作
typedef struct _WORK_ITEM_CONTEXT {
    PIO_WORKITEM WorkItem;
    PVOID        Data;
    SIZE_T       DataSize;
} WORK_ITEM_CONTEXT, *PWORK_ITEM_CONTEXT;

VOID WorkItemRoutine(
    PDEVICE_OBJECT DeviceObject,
    PVOID Context
) {
    PWORK_ITEM_CONTEXT ctx = (PWORK_ITEM_CONTEXT)Context;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    
    // 工作项在PASSIVE_LEVEL执行
    ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    
    // 可以执行任何操作：
    // - 访问分页内存
    // - 等待对象
    // - 执行耗时操作
    
    DbgPrint("[WorkItem] Processing data at PASSIVE_LEVEL\n");
    
    // 释放工作项
    IoFreeWorkItem(ctx->WorkItem);
    ExFreePool(ctx);
}

VOID QueueWorkItem(PDEVICE_OBJECT DeviceObject, PVOID Data, SIZE_T Size) {
    PWORK_ITEM_CONTEXT ctx;
    
    ctx = (PWORK_ITEM_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPool, sizeof(WORK_ITEM_CONTEXT), 'krow');
    
    if (!ctx) return;
    
    ctx->WorkItem = IoAllocateWorkItem(DeviceObject);
    ctx->Data = Data;
    ctx->DataSize = Size;
    
    // 在任意IRQL可以排队工作项
    IoQueueWorkItem(ctx->WorkItem, WorkItemRoutine, DelayedWorkQueue, ctx);
}
```

### 示例4：IRQL安全的内存分配

```c
// SafeAllocation.c - 安全内存分配
#include <ntddk.h>

// 根据IRQL选择正确的内存池
PVOID SafeAllocate(SIZE_T size) {
    POOL_TYPE poolType;
    KIRQL currentIrql = KeGetCurrentIrql();
    
    if (currentIrql >= DISPATCH_LEVEL) {
        // DISPATCH_LEVEL及以上必须使用NonPagedPool
        poolType = NonPagedPool;
    } else {
        // PASSIVE_LEVEL可以使用PagedPool
        poolType = PagedPool;
    }
    
    return ExAllocatePoolWithTag(poolType, size, 'efas');
}

// 使用Lookaside List进行快速分配
typedef struct _FAST_ALLOC_CONTEXT {
    NPAGED_LOOKASIDE_LIST LookasideList;
    ULONG ItemSize;
} FAST_ALLOC_CONTEXT;

VOID InitFastAlloc(FAST_ALLOC_CONTEXT* ctx, ULONG itemSize) {
    ExInitializeNPagedLookasideList(
        &ctx->LookasideList,
        NULL,               // 使用默认分配函数
        NULL,               // 使用默认释放函数
        0,
        itemSize,
        'tsaf',
        0
    );
    ctx->ItemSize = itemSize;
}

PVOID FastAlloc(FAST_ALLOC_CONTEXT* ctx) {
    // 可以在任意IRQL <= DISPATCH_LEVEL调用
    return ExAllocateFromNPagedLookasideList(&ctx->LookasideList);
}

VOID FastFree(FAST_ALLOC_CONTEXT* ctx, PVOID ptr) {
    ExFreeToNPagedLookasideList(&ctx->LookasideList, ptr);
}

// 在DPC/中断中安全处理数据
VOID ProcessDataInDpc(PVOID data, SIZE_T size) {
    // 错误做法：在DPC中访问分页内存
    // PVOID buffer = ExAllocatePoolWithTag(PagedPool, size, 'dab');
    
    // 正确做法：使用非分页内存
    PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, size, 'doog');
    if (buffer) {
        RtlCopyMemory(buffer, data, size);
        // 处理数据...
        ExFreePoolWithTag(buffer, 'doog');
    }
}
```

### 示例5：常见IRQL错误及解决

```c
// IRQLErrors.c - 常见IRQL错误
#include <ntddk.h>

// ==================== 错误1：在高IRQL访问分页内存 ====================
// BUGCHECK: IRQL_NOT_LESS_OR_EQUAL

// 错误代码
VOID BadPagedAccess() {
    PAGED_CODE();  // 标记此函数需要PASSIVE_LEVEL
    
    KIRQL oldIrql;
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    
    // 错误！在DISPATCH_LEVEL访问分页函数
    // 可能导致蓝屏
    
    KeLowerIrql(oldIrql);
}

// 正确代码
VOID GoodPagedAccess() {
    KIRQL currentIrql = KeGetCurrentIrql();
    
    if (currentIrql >= DISPATCH_LEVEL) {
        // 排队到工作项
        // IoQueueWorkItem(...);
        return;
    }
    
    // 在PASSIVE_LEVEL执行
    // ...分页操作...
}

// ==================== 错误2：在高IRQL等待对象 ====================
// BUGCHECK: IRQL_NOT_LESS_OR_EQUAL 或 死锁

// 错误代码
VOID BadWait() {
    KIRQL oldIrql;
    KEVENT event;
    
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    
    KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);
    
    // 错误！在DISPATCH_LEVEL等待会导致死锁
    // KeWaitForSingleObject(&event, ...);
    
    KeLowerIrql(oldIrql);
}

// 正确代码
NTSTATUS GoodWait(PKEVENT pEvent, PLARGE_INTEGER timeout) {
    if (KeGetCurrentIrql() > APC_LEVEL) {
        // 在高IRQL不能等待
        return STATUS_INVALID_DEVICE_STATE;
    }
    
    return KeWaitForSingleObject(
        pEvent,
        Executive,
        KernelMode,
        FALSE,
        timeout
    );
}

// ==================== 错误3：SpinLock嵌套获取 ====================

KSPIN_LOCK g_Lock1, g_Lock2;

// 错误：可能死锁（顺序不一致）
VOID BadLockOrder_Thread1() {
    KIRQL oldIrql1, oldIrql2;
    KeAcquireSpinLock(&g_Lock1, &oldIrql1);
    KeAcquireSpinLock(&g_Lock2, &oldIrql2);  // 线程1: Lock1 -> Lock2
    // ...
    KeReleaseSpinLock(&g_Lock2, oldIrql2);
    KeReleaseSpinLock(&g_Lock1, oldIrql1);
}

VOID BadLockOrder_Thread2() {
    KIRQL oldIrql1, oldIrql2;
    KeAcquireSpinLock(&g_Lock2, &oldIrql2);
    KeAcquireSpinLock(&g_Lock1, &oldIrql1);  // 线程2: Lock2 -> Lock1 (死锁!)
    // ...
    KeReleaseSpinLock(&g_Lock1, oldIrql1);
    KeReleaseSpinLock(&g_Lock2, oldIrql2);
}

// 正确：始终按相同顺序获取锁
VOID GoodLockOrder() {
    KIRQL oldIrql;
    
    // 使用单一锁或始终按相同顺序
    KeAcquireSpinLock(&g_Lock1, &oldIrql);
    KeAcquireSpinLockAtDpcLevel(&g_Lock2);  // 已在DISPATCH_LEVEL
    // ...
    KeReleaseSpinLockFromDpcLevel(&g_Lock2);
    KeReleaseSpinLock(&g_Lock1, oldIrql);
}
```

---

## 课后作业

1. 编写程序演示不同IRQL级别的转换
2. 实现一个线程安全的队列，使用SpinLock
3. 编写DPC和WorkItem配合处理数据的示例
4. 使用Driver Verifier检测IRQL违规

---

## 扩展阅读

- Windows内核原理与实现
- Scheduling, Thread Context, and IRQL
- Driver Verifier使用指南
