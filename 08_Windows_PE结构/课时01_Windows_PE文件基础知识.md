# 课时01：Windows PE文件基础知识

## 课程目标

1. 理解PE文件格式的历史和作用
2. 掌握PE文件的整体结构
3. 学会使用工具查看PE文件
4. 理解RVA和FOA的概念和转换

## 名词解释

| 名词 | 全称 | 解释 |
|------|------|------|
| PE | Portable Executable | 可移植可执行文件格式 |
| COFF | Common Object File Format | 通用目标文件格式 |
| RVA | Relative Virtual Address | 相对虚拟地址 |
| VA | Virtual Address | 虚拟地址 |
| FOA | File Offset Address | 文件偏移地址 |
| ImageBase | - | 映像基址 |
| Section | 区段/节 | PE文件的数据分区 |
| Header | 头部 | PE文件头信息 |

## 使用工具

- CFF Explorer（PE编辑器）
- PE-bear
- PEview
- x64dbg
- Visual Studio（dumpbin工具）
- 010 Editor（PE模板）

## 技术原理

### PE文件结构概览

```
+---------------------------+ 0x0000
|      DOS Header           |
|    (64 bytes)             |
+---------------------------+ 0x0040
|      DOS Stub             |
|    (可选，通常包含         |
|    "This program..."消息)  |
+---------------------------+ e_lfanew指向
|      PE Signature         |  "PE\0\0"
|    (4 bytes)              |
+---------------------------+
|      File Header          |
|    (20 bytes)             |
+---------------------------+
|    Optional Header        |
|    (PE32: 224 bytes       |
|     PE32+: 240 bytes)     |
+---------------------------+
|    Section Headers        |
|    (每个40 bytes)          |
+---------------------------+
|                           |
|      Section Data         |
|    (.text, .data,         |
|     .rdata, .rsrc等)      |
|                           |
+---------------------------+
```

### PE文件类型

```
文件扩展名     类型描述
.exe         可执行文件
.dll         动态链接库
.sys         驱动程序
.ocx         ActiveX控件
.scr         屏幕保护程序
.cpl         控制面板程序
.efi         EFI应用程序
```

### RVA与FOA转换

```
VA  = ImageBase + RVA
RVA = VA - ImageBase
FOA = RVA - Section.VirtualAddress + Section.PointerToRawData

转换条件：
RVA必须落在某个区段的范围内：
Section.VirtualAddress <= RVA < Section.VirtualAddress + Section.VirtualSize
```

## 代码实现

### PE文件基础结构定义

```c
#include <windows.h>
#include <stdio.h>

// 读取PE文件
LPVOID LoadPEFile(const char* filePath, DWORD* fileSize) {
    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] 无法打开文件: %s\n", filePath);
        return NULL;
    }
    
    *fileSize = GetFileSize(hFile, NULL);
    
    LPVOID fileData = VirtualAlloc(
        NULL,
        *fileSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    
    if (!fileData) {
        CloseHandle(hFile);
        return NULL;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, fileData, *fileSize, &bytesRead, NULL)) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return NULL;
    }
    
    CloseHandle(hFile);
    return fileData;
}

// 验证PE文件
BOOL ValidatePEFile(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    
    // 检查DOS签名
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] 无效的DOS签名: 0x%04X\n", dosHeader->e_magic);
        return FALSE;
    }
    
    // 获取NT头
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)fileData + dosHeader->e_lfanew
    );
    
    // 检查PE签名
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] 无效的PE签名: 0x%08X\n", ntHeaders->Signature);
        return FALSE;
    }
    
    printf("[+] 有效的PE文件\n");
    return TRUE;
}

// 判断PE位数
BOOL IsPE64(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)fileData + dosHeader->e_lfanew
    );
    
    return (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}
```

### RVA到FOA转换

```c
// 获取区段头数组
PIMAGE_SECTION_HEADER GetSectionHeaders(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)fileData + dosHeader->e_lfanew
    );
    
    return IMAGE_FIRST_SECTION(ntHeaders);
}

// 获取区段数量
WORD GetNumberOfSections(LPVOID fileData) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)fileData + dosHeader->e_lfanew
    );
    
    return ntHeaders->FileHeader.NumberOfSections;
}

// RVA转FOA
DWORD RvaToFoa(LPVOID fileData, DWORD rva) {
    PIMAGE_SECTION_HEADER sections = GetSectionHeaders(fileData);
    WORD numSections = GetNumberOfSections(fileData);
    
    // 遍历所有区段
    for (WORD i = 0; i < numSections; i++) {
        DWORD sectionStart = sections[i].VirtualAddress;
        DWORD sectionEnd = sectionStart + sections[i].Misc.VirtualSize;
        
        // 检查RVA是否在此区段范围内
        if (rva >= sectionStart && rva < sectionEnd) {
            // 计算FOA
            DWORD offset = rva - sections[i].VirtualAddress;
            return sections[i].PointerToRawData + offset;
        }
    }
    
    // RVA在头部区域（未映射到区段）
    // 直接返回RVA作为FOA
    return rva;
}

// FOA转RVA
DWORD FoaToRva(LPVOID fileData, DWORD foa) {
    PIMAGE_SECTION_HEADER sections = GetSectionHeaders(fileData);
    WORD numSections = GetNumberOfSections(fileData);
    
    for (WORD i = 0; i < numSections; i++) {
        DWORD sectionStart = sections[i].PointerToRawData;
        DWORD sectionEnd = sectionStart + sections[i].SizeOfRawData;
        
        if (foa >= sectionStart && foa < sectionEnd) {
            DWORD offset = foa - sections[i].PointerToRawData;
            return sections[i].VirtualAddress + offset;
        }
    }
    
    return foa;
}

// 通过RVA获取数据指针
LPVOID GetDataByRva(LPVOID fileData, DWORD rva) {
    DWORD foa = RvaToFoa(fileData, rva);
    return (LPVOID)((PBYTE)fileData + foa);
}
```

### PE文件信息打印

```c
// 打印PE基本信息
void PrintPEInfo(LPVOID fileData, DWORD fileSize) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileData;
    
    printf("\n=== DOS Header ===\n");
    printf("e_magic:    0x%04X (MZ)\n", dosHeader->e_magic);
    printf("e_lfanew:   0x%08X\n", dosHeader->e_lfanew);
    
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(
        (PBYTE)fileData + dosHeader->e_lfanew
    );
    
    printf("\n=== PE Signature ===\n");
    printf("Signature:  0x%08X (PE\\0\\0)\n", ntHeaders->Signature);
    
    // 判断位数
    BOOL is64 = IsPE64(fileData);
    printf("\n=== File Header ===\n");
    printf("Machine:            0x%04X (%s)\n", 
           ntHeaders->FileHeader.Machine,
           ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? "x64" :
           ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? "x86" : "Unknown");
    printf("NumberOfSections:   %d\n", ntHeaders->FileHeader.NumberOfSections);
    printf("TimeDateStamp:      0x%08X\n", ntHeaders->FileHeader.TimeDateStamp);
    printf("SizeOfOptionalHeader: %d\n", ntHeaders->FileHeader.SizeOfOptionalHeader);
    printf("Characteristics:    0x%04X\n", ntHeaders->FileHeader.Characteristics);
    
    // 解析特征
    WORD chars = ntHeaders->FileHeader.Characteristics;
    printf("  -> ");
    if (chars & IMAGE_FILE_EXECUTABLE_IMAGE) printf("EXECUTABLE ");
    if (chars & IMAGE_FILE_DLL) printf("DLL ");
    if (chars & IMAGE_FILE_LARGE_ADDRESS_AWARE) printf("LARGE_ADDRESS_AWARE ");
    if (chars & IMAGE_FILE_32BIT_MACHINE) printf("32BIT ");
    printf("\n");
    
    if (is64) {
        PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHeaders;
        PIMAGE_OPTIONAL_HEADER64 opt = &nt64->OptionalHeader;
        
        printf("\n=== Optional Header (PE32+) ===\n");
        printf("Magic:              0x%04X (PE32+)\n", opt->Magic);
        printf("AddressOfEntryPoint:0x%08X\n", opt->AddressOfEntryPoint);
        printf("ImageBase:          0x%016llX\n", opt->ImageBase);
        printf("SectionAlignment:   0x%08X\n", opt->SectionAlignment);
        printf("FileAlignment:      0x%08X\n", opt->FileAlignment);
        printf("SizeOfImage:        0x%08X\n", opt->SizeOfImage);
        printf("SizeOfHeaders:      0x%08X\n", opt->SizeOfHeaders);
        printf("Subsystem:          %d (%s)\n", opt->Subsystem,
               opt->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI ? "GUI" :
               opt->Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI ? "Console" : "Other");
        printf("NumberOfRvaAndSizes:%d\n", opt->NumberOfRvaAndSizes);
    } else {
        PIMAGE_OPTIONAL_HEADER32 opt = &ntHeaders->OptionalHeader;
        
        printf("\n=== Optional Header (PE32) ===\n");
        printf("Magic:              0x%04X (PE32)\n", opt->Magic);
        printf("AddressOfEntryPoint:0x%08X\n", opt->AddressOfEntryPoint);
        printf("ImageBase:          0x%08X\n", opt->ImageBase);
        printf("SectionAlignment:   0x%08X\n", opt->SectionAlignment);
        printf("FileAlignment:      0x%08X\n", opt->FileAlignment);
        printf("SizeOfImage:        0x%08X\n", opt->SizeOfImage);
        printf("SizeOfHeaders:      0x%08X\n", opt->SizeOfHeaders);
    }
}

// 打印区段信息
void PrintSections(LPVOID fileData) {
    PIMAGE_SECTION_HEADER sections = GetSectionHeaders(fileData);
    WORD numSections = GetNumberOfSections(fileData);
    
    printf("\n=== Sections (%d) ===\n", numSections);
    printf("%-8s %-10s %-10s %-10s %-10s %-10s\n",
           "Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize", "Chars");
    printf("%s\n", "--------------------------------------------------------------");
    
    for (WORD i = 0; i < numSections; i++) {
        char name[9] = {0};
        memcpy(name, sections[i].Name, 8);
        
        printf("%-8s 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X\n",
               name,
               sections[i].VirtualAddress,
               sections[i].Misc.VirtualSize,
               sections[i].PointerToRawData,
               sections[i].SizeOfRawData,
               sections[i].Characteristics);
        
        // 解析区段特征
        DWORD chars = sections[i].Characteristics;
        printf("         -> ");
        if (chars & IMAGE_SCN_CNT_CODE) printf("CODE ");
        if (chars & IMAGE_SCN_CNT_INITIALIZED_DATA) printf("IDATA ");
        if (chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA) printf("UDATA ");
        if (chars & IMAGE_SCN_MEM_EXECUTE) printf("EXEC ");
        if (chars & IMAGE_SCN_MEM_READ) printf("READ ");
        if (chars & IMAGE_SCN_MEM_WRITE) printf("WRITE ");
        printf("\n");
    }
}

// 主函数
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("用法: %s <PE文件路径>\n", argv[0]);
        return 1;
    }
    
    DWORD fileSize;
    LPVOID fileData = LoadPEFile(argv[1], &fileSize);
    
    if (!fileData) {
        return 1;
    }
    
    printf("[*] 文件大小: %d bytes\n", fileSize);
    
    if (!ValidatePEFile(fileData)) {
        VirtualFree(fileData, 0, MEM_RELEASE);
        return 1;
    }
    
    printf("[*] PE类型: %s\n", IsPE64(fileData) ? "PE32+ (64-bit)" : "PE32 (32-bit)");
    
    PrintPEInfo(fileData, fileSize);
    PrintSections(fileData);
    
    VirtualFree(fileData, 0, MEM_RELEASE);
    return 0;
}
```

### 使用dumpbin工具

```batch
:: 查看PE头信息
dumpbin /headers target.exe

:: 查看导入表
dumpbin /imports target.exe

:: 查看导出表
dumpbin /exports target.dll

:: 查看所有信息
dumpbin /all target.exe

:: 反汇编
dumpbin /disasm target.exe
```

## 课后作业

1. **编写PE文件验证器**
   - 验证DOS头和PE签名
   - 检查区段是否有效
   - 检测常见的PE异常

2. **实现地址转换器**
   - 支持RVA到FOA的转换
   - 支持FOA到RVA的转换
   - 支持VA的计算

3. **分析常见PE文件**
   - 分析notepad.exe
   - 分析kernel32.dll
   - 对比32位和64位PE的区别
