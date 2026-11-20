const std = @import("std");
const api = @import("api.zig");
const windows = std.os.windows;

pub const HANDLE = windows.HANDLE;
pub const HMODULE = windows.HMODULE;
pub const HINTERNET = *anyopaque;
pub const DWORD = windows.DWORD;
pub const BOOL = windows.BOOL;
pub const WCHAR = windows.WCHAR;
pub const LPCWSTR = windows.LPCWSTR;
pub const LPWSTR = windows.LPWSTR;
pub const SECURITY_ATTRIBUTES = windows.SECURITY_ATTRIBUTES;
pub const STARTUPINFOW = windows.STARTUPINFOW;
pub const PROCESS_INFORMATION = windows.PROCESS.INFORMATION;
pub const FILETIME = windows.FILETIME;
pub const INVALID_HANDLE_VALUE = windows.INVALID_HANDLE_VALUE;
pub const CreateProcessFlags = windows.CreateProcessFlags;

pub const GENERIC_READ: DWORD = 0x80000000;
pub const GENERIC_WRITE: DWORD = 0x40000000;
pub const CREATE_ALWAYS: DWORD = 2;
pub const INVALID_FILE_ATTRIBUTES: DWORD = 0xFFFFFFFF;
pub const MEM_COMMIT: DWORD = 0x00001000;
pub const MEM_RESERVE: DWORD = 0x00002000;
pub const MEM_RELEASE: DWORD = 0x00008000;
pub const PAGE_NOACCESS: DWORD = 0x01;
pub const PAGE_READONLY: DWORD = 0x02;
pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE: DWORD = 0x10;
pub const PAGE_EXECUTE_READ: DWORD = 0x20;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PROCESS_ALL_ACCESS: DWORD = 0x1F0FFF;
pub const SECTION_ALL_ACCESS: DWORD = 0xF001F;
pub const SEC_IMAGE: DWORD = 0x1000000;
pub const CP_ACP: u32 = 0;
pub const MB_PRECOMPOSED: DWORD = 0x00000001;

// Winsock
pub const SOCKET = usize;
pub const INVALID_SOCKET: SOCKET = std.math.maxInt(usize);
pub const SOCKET_ERROR: c_int = -1;
pub const AF_INET: c_int = 2;
pub const SOCK_STREAM: c_int = 1;
pub const IPPROTO_TCP: c_int = 6;
pub const SOL_SOCKET: c_int = 0xFFFF;
pub const SO_REUSEADDR: c_int = 0x0004;
pub const SO_ERROR: c_int = 0x1007;
pub const FIONBIO: i32 = @bitCast(@as(u32, 0x8004667E));
pub const WSAEWOULDBLOCK: c_int = 10035;
pub const SOMAXCONN: c_int = 0x7FFFFFFF;
pub const INADDR_ANY: u32 = 0;
pub const FD_SETSIZE: usize = 64;

pub const SOCKADDR_IN = extern struct {
    sin_family: u16,
    sin_port: u16,
    sin_addr: u32,
    sin_zero: [8]u8,
};

pub const TIMEVAL = extern struct {
    tv_sec: i32,
    tv_usec: i32,
};

pub const FD_SET = extern struct {
    fd_count: u32,
    fd_array: [FD_SETSIZE]SOCKET,
};

pub const WSADATA = extern struct {
    wVersion: u16,
    wHighVersion: u16,
    szDescription: [257]u8,
    szSystemStatus: [129]u8,
    iMaxSockets: u16,
    iMaxUdpDg: u16,
    lpVendorInfo: ?[*]u8,
};

pub const HOSTENT = extern struct {
    h_name: ?[*:0]u8,
    h_aliases: ?[*]?[*:0]u8,
    h_addrtype: i16,
    h_length: i16,
    h_addr_list: ?[*]?[*]u8,
};
pub const FILE_SHARE_READ: DWORD = 0x00000001;
pub const OPEN_EXISTING: DWORD = 3;
pub const FILE_ATTRIBUTE_NORMAL: DWORD = 0x00000080;
pub const FILE_ATTRIBUTE_DIRECTORY: DWORD = 0x00000010;
pub const STARTF_USESHOWWINDOW: DWORD = 0x00000001;
pub const STARTF_USESTDHANDLES: DWORD = 0x00000100;
pub const SW_HIDE: u16 = 0;
pub const INFINITE: DWORD = 0xFFFFFFFF;
pub const WAIT_OBJECT_0: DWORD = 0;
pub const WAIT_TIMEOUT: DWORD = 0x00000102;
pub const WAIT_FAILED: DWORD = 0xFFFFFFFF;
pub const HANDLE_FLAG_INHERIT: DWORD = 0x00000001;
pub const TH32CS_SNAPPROCESS: DWORD = 0x00000002;
pub const TH32CS_SNAPTHREAD: DWORD = 0x00000004;

pub const WIN32_FIND_DATAW = extern struct {
    dwFileAttributes: DWORD,
    ftCreationTime: FILETIME,
    ftLastAccessTime: FILETIME,
    ftLastWriteTime: FILETIME,
    nFileSizeHigh: DWORD,
    nFileSizeLow: DWORD,
    dwReserved0: DWORD,
    dwReserved1: DWORD,
    cFileName: [260]WCHAR,
    cAlternateFileName: [14]WCHAR,
};

pub const THREADENTRY32 = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ThreadID: DWORD,
    th32OwnerProcessID: DWORD,
    tpBasePri: i32,
    tpDeltaPri: i32,
    dwFlags: DWORD,
};

pub const PROCESSENTRY32W = extern struct {
    dwSize: DWORD,
    cntUsage: DWORD,
    th32ProcessID: DWORD,
    th32DefaultHeapID: usize,
    th32ModuleID: DWORD,
    cntThreads: DWORD,
    th32ParentProcessID: DWORD,
    pcPriClassBase: i32,
    dwFlags: DWORD,
    szExeFile: [260]WCHAR,
};

pub const TOKEN_QUERY: DWORD = 0x0008;
pub const TOKEN_DUPLICATE: DWORD = 0x0002;
pub const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
pub const MAXIMUM_ALLOWED: DWORD = 0x02000000;
pub const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;
pub const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;
pub const LOGON32_LOGON_NEW_CREDENTIALS: DWORD = 9;
pub const CREATE_SUSPENDED: DWORD = 0x00000004;
pub const CREATE_NEW_CONSOLE: DWORD = 0x00000010;
pub const CREATE_NO_WINDOW: DWORD = 0x08000000;
pub const WinLocalSystemSid: u32 = 22;

pub const SID_AND_ATTRIBUTES = extern struct {
    Sid: ?*anyopaque,
    Attributes: DWORD,
};

pub const TOKEN_USER = extern struct {
    User: SID_AND_ATTRIBUTES,
};

pub const TOKEN_ELEVATION = extern struct {
    TokenIsElevated: DWORD,
};

pub const LUID = extern struct {
    LowPart: DWORD,
    HighPart: i32,
};

pub const LUID_AND_ATTRIBUTES = extern struct {
    Luid: LUID,
    Attributes: DWORD,
};

pub const TOKEN_PRIVILEGES = extern struct {
    PrivilegeCount: DWORD,
    Privileges: [1]LUID_AND_ATTRIBUTES,
};

pub const TokenType = enum(u32) {
    TokenPrimary = 1,
    TokenImpersonation = 2,
    _,
};

pub const SecurityImpersonationLevel = enum(u32) {
    SecurityAnonymous = 0,
    SecurityIdentification = 1,
    SecurityImpersonation = 2,
    SecurityDelegation = 3,
    _,
};

pub const TokenInformationClass = enum(u32) {
    TokenUser = 1,
    TokenPrivileges = 3,
    TokenElevation = 20,
    _,
};

pub const ProcessMitigationPolicy = enum(u32) {
    ProcessDEPPolicy = 0,
    ProcessASLRPolicy = 1,
    ProcessDynamicCodePolicy = 2,
    ProcessStrictHandleCheckPolicy = 3,
    ProcessSystemCallDisablePolicy = 4,
    ProcessMitigationOptionsMask = 5,
    ProcessExtensionPointDisablePolicy = 6,
    ProcessControlFlowGuardPolicy = 7,
    ProcessSignaturePolicy = 8,
    _,
};

pub const PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = extern struct {
    Flags: DWORD,
};

pub const MIB_IPADDRROW = extern struct {
    dwAddr: DWORD,
    dwIndex: DWORD,
    dwMask: DWORD,
    dwBCastAddr: DWORD,
    dwReasmSize: DWORD,
    unused1: u16,
    wType: u16,
};

pub const MIB_IPADDRTABLE = extern struct {
    dwNumEntries: DWORD,
    table: [1]MIB_IPADDRROW,
};

pub const STARTUPINFOA = extern struct {
    cb: DWORD,
    lpReserved: ?[*:0]u8,
    lpDesktop: ?[*:0]u8,
    lpTitle: ?[*:0]u8,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: u16,
    cbReserved2: u16,
    lpReserved2: ?[*]u8,
    hStdInput: ?HANDLE,
    hStdOutput: ?HANDLE,
    hStdError: ?HANDLE,
};

pub const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

pub const THREAD_START_ROUTINE = *const fn (lpThreadParameter: ?*anyopaque) callconv(.winapi) DWORD;

pub fn VirtualAlloc(nxarg_lpAddress: ?*anyopaque, nxarg_dwSize: usize, nxarg_flAllocationType: DWORD, nxarg_flProtect: DWORD) ?*anyopaque {
    const address = api.nx_api(0xFAB06795, 0xC0CEBBE1) orelse unreachable;
    return @as(*const fn (?*anyopaque, usize, DWORD, DWORD) callconv(.winapi) ?*anyopaque, @ptrCast(@alignCast(address)))(nxarg_lpAddress, nxarg_dwSize, nxarg_flAllocationType, nxarg_flProtect);
}

pub fn VirtualFree(nxarg_lpAddress: ?*anyopaque, nxarg_dwSize: usize, nxarg_dwFreeType: DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x81F99658) orelse unreachable;
    return @as(*const fn (?*anyopaque, usize, DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpAddress, nxarg_dwSize, nxarg_dwFreeType);
}

pub extern "kernel32" fn VirtualProtect(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flNewProtect: DWORD,
    lpflOldProtect: *DWORD,
) callconv(.winapi) BOOL;

pub fn VirtualAllocEx(nxarg_hProcess: HANDLE, nxarg_lpAddress: ?*anyopaque, nxarg_dwSize: usize, nxarg_flAllocationType: DWORD, nxarg_flProtect: DWORD) ?*anyopaque {
    const address = api.nx_api(0xFAB06795, 0x2F6D415E) orelse unreachable;
    return @as(*const fn (HANDLE, ?*anyopaque, usize, DWORD, DWORD) callconv(.winapi) ?*anyopaque, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpAddress, nxarg_dwSize, nxarg_flAllocationType, nxarg_flProtect);
}

pub fn VirtualFreeEx(nxarg_hProcess: HANDLE, nxarg_lpAddress: ?*anyopaque, nxarg_dwSize: usize, nxarg_dwFreeType: DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0xE6B89595) orelse unreachable;
    return @as(*const fn (HANDLE, ?*anyopaque, usize, DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpAddress, nxarg_dwSize, nxarg_dwFreeType);
}

pub fn VirtualProtectEx(nxarg_hProcess: HANDLE, nxarg_lpAddress: ?*anyopaque, nxarg_dwSize: usize, nxarg_flNewProtect: DWORD, nxarg_lpflOldProtect: *DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x0F543F14) orelse unreachable;
    return @as(*const fn (HANDLE, ?*anyopaque, usize, DWORD, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpAddress, nxarg_dwSize, nxarg_flNewProtect, nxarg_lpflOldProtect);
}

pub fn WriteProcessMemory(nxarg_hProcess: HANDLE, nxarg_lpBaseAddress: ?*anyopaque, nxarg_lpBuffer: *const anyopaque, nxarg_nSize: usize, nxarg_lpNumberOfBytesWritten: ?*usize) BOOL {
    const address = api.nx_api(0xFAB06795, 0x086183F2) orelse unreachable;
    return @as(*const fn (HANDLE, ?*anyopaque, *const anyopaque, usize, ?*usize) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpBaseAddress, nxarg_lpBuffer, nxarg_nSize, nxarg_lpNumberOfBytesWritten);
}

pub fn ReadProcessMemory(nxarg_hProcess: HANDLE, nxarg_lpBaseAddress: ?*const anyopaque, nxarg_lpBuffer: *anyopaque, nxarg_nSize: usize, nxarg_lpNumberOfBytesRead: ?*usize) BOOL {
    const address = api.nx_api(0xFAB06795, 0x8D3E0663) orelse unreachable;
    return @as(*const fn (HANDLE, ?*const anyopaque, *anyopaque, usize, ?*usize) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpBaseAddress, nxarg_lpBuffer, nxarg_nSize, nxarg_lpNumberOfBytesRead);
}

pub fn DuplicateHandle(nxarg_hSourceProcessHandle: HANDLE, nxarg_hSourceHandle: HANDLE, nxarg_hTargetProcessHandle: HANDLE, nxarg_lpTargetHandle: *HANDLE, nxarg_dwDesiredAccess: DWORD, nxarg_bInheritHandle: BOOL, nxarg_dwOptions: DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x6CDC5FB6) orelse unreachable;
    return @as(*const fn (HANDLE, HANDLE, HANDLE, *HANDLE, DWORD, BOOL, DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hSourceProcessHandle, nxarg_hSourceHandle, nxarg_hTargetProcessHandle, nxarg_lpTargetHandle, nxarg_dwDesiredAccess, nxarg_bInheritHandle, nxarg_dwOptions);
}

pub const TP_TIMER_CALLBACK = *const fn (
    instance: ?*anyopaque,
    context: ?*anyopaque,
    timer: ?*anyopaque,
) callconv(.winapi) void;

pub fn SuspendThread(nxarg_hThread: HANDLE) DWORD {
    const address = api.nx_api(0xFAB06795, 0x28EF87C9) orelse unreachable;
    return @as(*const fn (HANDLE) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_hThread);
}

pub fn OpenThread(nxarg_dwDesiredAccess: DWORD, nxarg_bInheritHandle: BOOL, nxarg_dwThreadId: DWORD) ?HANDLE {
    const address = api.nx_api(0xFAB06795, 0x9D5A4999) orelse unreachable;
    return @as(*const fn (DWORD, BOOL, DWORD) callconv(.winapi) ?HANDLE, @ptrCast(@alignCast(address)))(nxarg_dwDesiredAccess, nxarg_bInheritHandle, nxarg_dwThreadId);
}

pub const PROCESS_HEAP_ENTRY = extern struct {
    lpData: ?*anyopaque,
    cbData: u32,
    cbOverhead: u8,
    iRegionIndex: u8,
    wFlags: u16,
    reserved: [24]u8,
};

pub fn GetProcessHeap() ?HANDLE {
    const address = api.nx_api(0xFAB06795, 0x0EB78BAC) orelse unreachable;
    return @as(*const fn () callconv(.winapi) ?HANDLE, @ptrCast(@alignCast(address)))();
}
pub fn GetProcessHeaps(nxarg_NumberOfHeaps: DWORD, nxarg_ProcessHeaps: ?[*]HANDLE) DWORD {
    const address = api.nx_api(0xFAB06795, 0xE5A9017F) orelse unreachable;
    return @as(*const fn (DWORD, ?[*]HANDLE) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_NumberOfHeaps, nxarg_ProcessHeaps);
}
pub fn HeapWalk(nxarg_hHeap: HANDLE, nxarg_lpEntry: *PROCESS_HEAP_ENTRY) BOOL {
    const address = api.nx_api(0xFAB06795, 0x0E711A9C) orelse unreachable;
    return @as(*const fn (HANDLE, *PROCESS_HEAP_ENTRY) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hHeap, nxarg_lpEntry);
}

pub extern "kernel32" fn GetCurrentThreadId() callconv(.winapi) DWORD;
pub extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) DWORD;

pub fn Thread32First(nxarg_hSnapshot: HANDLE, nxarg_lpte: *THREADENTRY32) BOOL {
    const address = api.nx_api(0xFAB06795, 0xD18777F4) orelse unreachable;
    return @as(*const fn (HANDLE, *THREADENTRY32) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hSnapshot, nxarg_lpte);
}

pub fn Thread32Next(nxarg_hSnapshot: HANDLE, nxarg_lpte: *THREADENTRY32) BOOL {
    const address = api.nx_api(0xFAB06795, 0x3CAB566B) orelse unreachable;
    return @as(*const fn (HANDLE, *THREADENTRY32) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hSnapshot, nxarg_lpte);
}

pub fn ResumeThread(nxarg_hThread: HANDLE) DWORD {
    const address = api.nx_api(0xFAB06795, 0x451ADAB8) orelse unreachable;
    return @as(*const fn (HANDLE) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_hThread);
}

pub fn CreateThreadpoolTimer(nxarg_pfnti: ?TP_TIMER_CALLBACK, nxarg_pv: ?*anyopaque, nxarg_pcbe: ?*anyopaque) ?*anyopaque {
    const address = api.nx_api(0xFAB06795, 0xADDA36D6) orelse unreachable;
    return @as(*const fn (?TP_TIMER_CALLBACK, ?*anyopaque, ?*anyopaque) callconv(.winapi) ?*anyopaque, @ptrCast(@alignCast(address)))(nxarg_pfnti, nxarg_pv, nxarg_pcbe);
}

pub fn CreateRemoteThread(nxarg_hProcess: HANDLE, nxarg_lpThreadAttributes: ?*SECURITY_ATTRIBUTES, nxarg_dwStackSize: usize, nxarg_lpStartAddress: ?THREAD_START_ROUTINE, nxarg_lpParameter: ?*anyopaque, nxarg_dwCreationFlags: DWORD, nxarg_lpThreadId: ?*DWORD) ?HANDLE {
    const address = api.nx_api(0xFAB06795, 0x75F98E87) orelse unreachable;
    return @as(*const fn (HANDLE, ?*SECURITY_ATTRIBUTES, usize, ?THREAD_START_ROUTINE, ?*anyopaque, DWORD, ?*DWORD) callconv(.winapi) ?HANDLE, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpThreadAttributes, nxarg_dwStackSize, nxarg_lpStartAddress, nxarg_lpParameter, nxarg_dwCreationFlags, nxarg_lpThreadId);
}

pub fn CreateProcessW(nxarg_lpApplicationName: ?[*:0]const u16, nxarg_lpCommandLine: ?[*:0]u16, nxarg_lpProcessAttributes: ?*SECURITY_ATTRIBUTES, nxarg_lpThreadAttributes: ?*SECURITY_ATTRIBUTES, nxarg_bInheritHandles: BOOL, nxarg_dwCreationFlags: DWORD, nxarg_lpEnvironment: ?*anyopaque, nxarg_lpCurrentDirectory: ?[*:0]const u16, nxarg_lpStartupInfo: *STARTUPINFOW, nxarg_lpProcessInformation: *PROCESS_INFORMATION) BOOL {
    const address = api.nx_api(0xFAB06795, 0xD3A714D9) orelse unreachable;
    return @as(*const fn (?[*:0]const u16, ?[*:0]u16, ?*SECURITY_ATTRIBUTES, ?*SECURITY_ATTRIBUTES, BOOL, DWORD, ?*anyopaque, ?[*:0]const u16, *STARTUPINFOW, *PROCESS_INFORMATION) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpApplicationName, nxarg_lpCommandLine, nxarg_lpProcessAttributes, nxarg_lpThreadAttributes, nxarg_bInheritHandles, nxarg_dwCreationFlags, nxarg_lpEnvironment, nxarg_lpCurrentDirectory, nxarg_lpStartupInfo, nxarg_lpProcessInformation);
}

pub fn CreateProcessA(nxarg_lpApplicationName: ?[*:0]const u8, nxarg_lpCommandLine: ?[*:0]u8, nxarg_lpProcessAttributes: ?*SECURITY_ATTRIBUTES, nxarg_lpThreadAttributes: ?*SECURITY_ATTRIBUTES, nxarg_bInheritHandles: BOOL, nxarg_dwCreationFlags: DWORD, nxarg_lpEnvironment: ?*anyopaque, nxarg_lpCurrentDirectory: ?[*:0]const u8, nxarg_lpStartupInfo: *STARTUPINFOA, nxarg_lpProcessInformation: *PROCESS_INFORMATION) BOOL {
    const address = api.nx_api(0xFAB06795, 0xD3A714C3) orelse unreachable;
    return @as(*const fn (?[*:0]const u8, ?[*:0]u8, ?*SECURITY_ATTRIBUTES, ?*SECURITY_ATTRIBUTES, BOOL, DWORD, ?*anyopaque, ?[*:0]const u8, *STARTUPINFOA, *PROCESS_INFORMATION) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpApplicationName, nxarg_lpCommandLine, nxarg_lpProcessAttributes, nxarg_lpThreadAttributes, nxarg_bInheritHandles, nxarg_dwCreationFlags, nxarg_lpEnvironment, nxarg_lpCurrentDirectory, nxarg_lpStartupInfo, nxarg_lpProcessInformation);
}

pub fn LoadLibraryA(nxarg_lpLibFileName: [*:0]const u8) ?HMODULE {
    const address = api.nx_api(0xFAB06795, 0x6E5A2965) orelse unreachable;
    return @as(*const fn ([*:0]const u8) callconv(.winapi) ?HMODULE, @ptrCast(@alignCast(address)))(nxarg_lpLibFileName);
}
pub extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?HMODULE;
pub fn GetModuleHandleA(nxarg_lpModuleName: ?[*:0]const u8) ?HMODULE {
    const address = api.nx_api(0xFAB06795, 0x8CF19062) orelse unreachable;
    return @as(*const fn (?[*:0]const u8) callconv(.winapi) ?HMODULE, @ptrCast(@alignCast(address)))(nxarg_lpModuleName);
}
pub extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(.winapi) ?*anyopaque;
pub extern "kernel32" fn FreeLibrary(hLibModule: HMODULE) callconv(.winapi) BOOL;

pub extern "kernel32" fn MultiByteToWideChar(
    CodePage: u32,
    dwFlags: DWORD,
    lpMultiByteStr: [*:0]const u8,
    cbMultiByte: i32,
    lpWideCharStr: [*]u16,
    cchWideChar: i32,
) callconv(.winapi) i32;

pub fn SetThreadToken(nxarg_Thread: ?*HANDLE, nxarg_Token: HANDLE) BOOL {
    const address = api.nx_api(0x7B933969, 0xA1EC1A74) orelse unreachable;
    return @as(*const fn (?*HANDLE, HANDLE) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_Thread, nxarg_Token);
}

pub fn CreateThread(nxarg_lpThreadAttributes: ?*SECURITY_ATTRIBUTES, nxarg_dwStackSize: usize, nxarg_lpStartAddress: ?THREAD_START_ROUTINE, nxarg_lpParameter: ?*anyopaque, nxarg_dwCreationFlags: DWORD, nxarg_lpThreadId: ?*DWORD) ?HANDLE {
    const address = api.nx_api(0xFAB06795, 0x500DA49B) orelse unreachable;
    return @as(*const fn (?*SECURITY_ATTRIBUTES, usize, ?THREAD_START_ROUTINE, ?*anyopaque, DWORD, ?*DWORD) callconv(.winapi) ?HANDLE, @ptrCast(@alignCast(address)))(nxarg_lpThreadAttributes, nxarg_dwStackSize, nxarg_lpStartAddress, nxarg_lpParameter, nxarg_dwCreationFlags, nxarg_lpThreadId);
}

pub const FIBER_START_ROUTINE = *const fn (?*anyopaque) callconv(.winapi) void;

pub fn CreateFiberEx(nxarg_dwStackCommitSize: usize, nxarg_dwStackReserveSize: usize, nxarg_dwFlags: DWORD, nxarg_lpStartAddress: FIBER_START_ROUTINE, nxarg_lpParameter: ?*anyopaque) ?*anyopaque {
    const address = api.nx_api(0xFAB06795, 0x1D46CEC8) orelse unreachable;
    return @as(*const fn (usize, usize, DWORD, FIBER_START_ROUTINE, ?*anyopaque) callconv(.winapi) ?*anyopaque, @ptrCast(@alignCast(address)))(nxarg_dwStackCommitSize, nxarg_dwStackReserveSize, nxarg_dwFlags, nxarg_lpStartAddress, nxarg_lpParameter);
}

pub fn ConvertThreadToFiber(nxarg_lpParameter: ?*anyopaque) ?*anyopaque {
    const address = api.nx_api(0xFAB06795, 0x40BDC873) orelse unreachable;
    return @as(*const fn (?*anyopaque) callconv(.winapi) ?*anyopaque, @ptrCast(@alignCast(address)))(nxarg_lpParameter);
}

pub fn SwitchToFiber(nxarg_lpFiber: *anyopaque) void {
    const address = api.nx_api(0xFAB06795, 0xB6AE678C) orelse unreachable;
    @as(*const fn (*anyopaque) callconv(.winapi) void, @ptrCast(@alignCast(address)))(nxarg_lpFiber);
}

pub fn EnumCalendarInfoA(nxarg_lpCalInfoEnumProc: ?*anyopaque, nxarg_Locale: u32, nxarg_Calendar: u32, nxarg_CalType: u32) BOOL {
    const address = api.nx_api(0xFAB06795, 0x6FC39B8B) orelse unreachable;
    return @as(*const fn (?*anyopaque, u32, u32, u32) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpCalInfoEnumProc, nxarg_Locale, nxarg_Calendar, nxarg_CalType);
}

pub fn EnumSystemGeoID(nxarg_GeoClass: u32, nxarg_ParentGeoId: u32, nxarg_lpGeoEnumProc: ?*anyopaque) BOOL {
    const address = api.nx_api(0xFAB06795, 0xFA89E391) orelse unreachable;
    return @as(*const fn (u32, u32, ?*anyopaque) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_GeoClass, nxarg_ParentGeoId, nxarg_lpGeoEnumProc);
}

pub fn EnumDesktopsW(nxarg_hwinsta: ?*anyopaque, nxarg_lpEnumFunc: ?*anyopaque, nxarg_lParam: isize) BOOL {
    const address = api.nx_api(0x6ACBC7D3, 0x25651308) orelse unreachable;
    return @as(*const fn (?*anyopaque, ?*anyopaque, isize) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hwinsta, nxarg_lpEnumFunc, nxarg_lParam);
}

pub fn GetProcessWindowStation() ?*anyopaque {
    const address = api.nx_api(0x6ACBC7D3, 0xFAB3A0C8) orelse unreachable;
    return @as(*const fn () callconv(.winapi) ?*anyopaque, @ptrCast(@alignCast(address)))();
}

pub fn EnumWindowStationsW(nxarg_lpEnumFunc: ?*anyopaque, nxarg_lParam: isize) BOOL {
    const address = api.nx_api(0x6ACBC7D3, 0xFA467028) orelse unreachable;
    return @as(*const fn (?*anyopaque, isize) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpEnumFunc, nxarg_lParam);
}

pub fn EnumWindows(nxarg_lpEnumFunc: ?*const fn (?*anyopaque, isize) callconv(.winapi) BOOL, nxarg_lParam: isize) BOOL {
    const address = api.nx_api(0x6ACBC7D3, 0x4F6FAFEF) orelse unreachable;
    return @as(*const fn (?*const fn (?*anyopaque, isize) callconv(.winapi) BOOL, isize) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpEnumFunc, nxarg_lParam);
}

pub fn GetWindowThreadProcessId(nxarg_hWnd: ?*anyopaque, nxarg_lpdwProcessId: ?*DWORD) DWORD {
    const address = api.nx_api(0x6ACBC7D3, 0x6C8C2A0B) orelse unreachable;
    return @as(*const fn (?*anyopaque, ?*DWORD) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_hWnd, nxarg_lpdwProcessId);
}

pub fn SendMessageW(nxarg_hWnd: ?*anyopaque, nxarg_Msg: u32, nxarg_wParam: usize, nxarg_lParam: isize) isize {
    const address = api.nx_api(0x6ACBC7D3, 0xA3FE7CF5) orelse unreachable;
    return @as(*const fn (?*anyopaque, u32, usize, isize) callconv(.winapi) isize, @ptrCast(@alignCast(address)))(nxarg_hWnd, nxarg_Msg, nxarg_wParam, nxarg_lParam);
}

pub fn WaitForInputIdle(nxarg_hProcess: HANDLE, nxarg_dwMilliseconds: DWORD) DWORD {
    const address = api.nx_api(0x6ACBC7D3, 0xE10E3959) orelse unreachable;
    return @as(*const fn (HANDLE, DWORD) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_dwMilliseconds);
}

pub const COPYDATASTRUCT = extern struct {
    dwData: usize,
    cbData: DWORD,
    lpData: ?*anyopaque,
};

pub fn CreatePipe(nxarg_hReadPipe: *HANDLE, nxarg_hWritePipe: *HANDLE, nxarg_lpPipeAttributes: ?*SECURITY_ATTRIBUTES, nxarg_nSize: DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x6CE7F8F1) orelse unreachable;
    return @as(*const fn (*HANDLE, *HANDLE, ?*SECURITY_ATTRIBUTES, DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hReadPipe, nxarg_hWritePipe, nxarg_lpPipeAttributes, nxarg_nSize);
}

pub fn SetHandleInformation(nxarg_hObject: HANDLE, nxarg_dwMask: DWORD, nxarg_dwFlags: DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x69E6CB6D) orelse unreachable;
    return @as(*const fn (HANDLE, DWORD, DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hObject, nxarg_dwMask, nxarg_dwFlags);
}

pub fn PeekNamedPipe(nxarg_hNamedPipe: HANDLE, nxarg_lpBuffer: ?*anyopaque, nxarg_nBufferSize: DWORD, nxarg_lpBytesRead: ?*DWORD, nxarg_lpTotalBytesAvail: ?*DWORD, nxarg_lpBytesLeftThisMessage: ?*DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x76E35927) orelse unreachable;
    return @as(*const fn (HANDLE, ?*anyopaque, DWORD, ?*DWORD, ?*DWORD, ?*DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hNamedPipe, nxarg_lpBuffer, nxarg_nBufferSize, nxarg_lpBytesRead, nxarg_lpTotalBytesAvail, nxarg_lpBytesLeftThisMessage);
}

pub fn TerminateProcess(nxarg_hProcess: HANDLE, nxarg_uExitCode: u32) BOOL {
    const address = api.nx_api(0xFAB06795, 0xA7AA2837) orelse unreachable;
    return @as(*const fn (HANDLE, u32) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_uExitCode);
}

pub fn ReadFile(nxarg_hFile: HANDLE, nxarg_lpBuffer: [*]u8, nxarg_nNumberOfBytesToRead: DWORD, nxarg_lpNumberOfBytesRead: *DWORD, nxarg_lpOverlapped: ?*anyopaque) BOOL {
    const address = api.nx_api(0xFAB06795, 0x482114EB) orelse unreachable;
    return @as(*const fn (HANDLE, [*]u8, DWORD, *DWORD, ?*anyopaque) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hFile, nxarg_lpBuffer, nxarg_nNumberOfBytesToRead, nxarg_lpNumberOfBytesRead, nxarg_lpOverlapped);
}

pub fn WriteFile(nxarg_hFile: HANDLE, nxarg_lpBuffer: [*]const u8, nxarg_nNumberOfBytesToWrite: DWORD, nxarg_lpNumberOfBytesWritten: *DWORD, nxarg_lpOverlapped: ?*anyopaque) BOOL {
    const address = api.nx_api(0xFAB06795, 0x1F1A5D9A) orelse unreachable;
    return @as(*const fn (HANDLE, [*]const u8, DWORD, *DWORD, ?*anyopaque) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hFile, nxarg_lpBuffer, nxarg_nNumberOfBytesToWrite, nxarg_lpNumberOfBytesWritten, nxarg_lpOverlapped);
}

pub fn CopyFileW(nxarg_lpExistingFileName: [*:0]const WCHAR, nxarg_lpNewFileName: [*:0]const WCHAR, nxarg_bFailIfExists: BOOL) BOOL {
    const address = api.nx_api(0xFAB06795, 0x673148E1) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR, [*:0]const WCHAR, BOOL) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpExistingFileName, nxarg_lpNewFileName, nxarg_bFailIfExists);
}

pub fn MoveFileW(nxarg_lpExistingFileName: [*:0]const WCHAR, nxarg_lpNewFileName: [*:0]const WCHAR) BOOL {
    const address = api.nx_api(0xFAB06795, 0x9343F2DD) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR, [*:0]const WCHAR) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpExistingFileName, nxarg_lpNewFileName);
}

pub fn DeleteFileW(nxarg_lpFileName: [*:0]const WCHAR) BOOL {
    const address = api.nx_api(0xFAB06795, 0x3A73D279) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpFileName);
}

pub fn CreateDirectoryW(nxarg_lpPathName: [*:0]const WCHAR, nxarg_lpSecurityAttributes: ?*SECURITY_ATTRIBUTES) BOOL {
    const address = api.nx_api(0xFAB06795, 0x6B006CEF) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR, ?*SECURITY_ATTRIBUTES) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpPathName, nxarg_lpSecurityAttributes);
}

pub fn GetFileAttributesW(nxarg_lpFileName: [*:0]const WCHAR) DWORD {
    const address = api.nx_api(0xFAB06795, 0x43D9242D) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_lpFileName);
}

pub extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(.winapi) BOOL;

pub fn CreateEventW(nxarg_lpEventAttributes: ?*SECURITY_ATTRIBUTES, nxarg_bManualReset: BOOL, nxarg_bInitialState: BOOL, nxarg_lpName: ?[*:0]const u16) ?HANDLE {
    const address = api.nx_api(0xFAB06795, 0x2E06A21C) orelse unreachable;
    return @as(*const fn (?*SECURITY_ATTRIBUTES, BOOL, BOOL, ?[*:0]const u16) callconv(.winapi) ?HANDLE, @ptrCast(@alignCast(address)))(nxarg_lpEventAttributes, nxarg_bManualReset, nxarg_bInitialState, nxarg_lpName);
}

pub fn SetEvent(nxarg_hEvent: HANDLE) BOOL {
    const address = api.nx_api(0xFAB06795, 0x60CFBB9D) orelse unreachable;
    return @as(*const fn (HANDLE) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hEvent);
}

pub fn GetThreadId(nxarg_Thread: HANDLE) DWORD {
    const address = api.nx_api(0xFAB06795, 0xC8CA8D74) orelse unreachable;
    return @as(*const fn (HANDLE) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_Thread);
}

pub extern "kernel32" fn WaitForSingleObject(
    hHandle: HANDLE,
    dwMilliseconds: DWORD,
) callconv(.winapi) DWORD;

pub fn GetExitCodeProcess(nxarg_hProcess: HANDLE, nxarg_lpExitCode: *DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0xF8947643) orelse unreachable;
    return @as(*const fn (HANDLE, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpExitCode);
}

pub fn GetCurrentDirectoryW(nxarg_nBufferLength: DWORD, nxarg_lpBuffer: [*]WCHAR) DWORD {
    const address = api.nx_api(0xFAB06795, 0xFBA58D7E) orelse unreachable;
    return @as(*const fn (DWORD, [*]WCHAR) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_nBufferLength, nxarg_lpBuffer);
}

pub fn SetCurrentDirectoryW(nxarg_lpPathName: [*:0]const WCHAR) BOOL {
    const address = api.nx_api(0xFAB06795, 0x8D7BBA0A) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpPathName);
}

pub fn GetComputerNameW(nxarg_lpBuffer: [*]WCHAR, nxarg_nSize: *DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x403B88D6) orelse unreachable;
    return @as(*const fn ([*]WCHAR, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpBuffer, nxarg_nSize);
}

pub fn GetUserNameW(nxarg_lpBuffer: [*]WCHAR, nxarg_pcbBuffer: *DWORD) BOOL {
    const address = api.nx_api(0x7B933969, 0xB3F477E6) orelse unreachable;
    return @as(*const fn ([*]WCHAR, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpBuffer, nxarg_pcbBuffer);
}

pub fn QueryPerformanceFrequency(nxarg_lpFrequency: *i64) BOOL {
    const address = api.nx_api(0xFAB06795, 0x9E6A6389) orelse unreachable;
    return @as(*const fn (*i64) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpFrequency);
}
pub fn QueryPerformanceCounter(nxarg_lpPerformanceCount: *i64) BOOL {
    const address = api.nx_api(0xFAB06795, 0xCE3A01D7) orelse unreachable;
    return @as(*const fn (*i64) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpPerformanceCount);
}
pub fn QueryUnbiasedInterruptTime(nxarg_UnbiasedTime: *u64) BOOL {
    const address = api.nx_api(0xFAB06795, 0x096C104C) orelse unreachable;
    return @as(*const fn (*u64) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_UnbiasedTime);
}
pub fn GetSystemMetrics(nxarg_nIndex: i32) i32 {
    const address = api.nx_api(0x6ACBC7D3, 0xDC65128B) orelse unreachable;
    return @as(*const fn (i32) callconv(.winapi) i32, @ptrCast(@alignCast(address)))(nxarg_nIndex);
}
pub fn GetUserNameA(nxarg_lpBuffer: [*]u8, nxarg_pcbBuffer: *DWORD) BOOL {
    const address = api.nx_api(0x7B933969, 0xB3F477D0) orelse unreachable;
    return @as(*const fn ([*]u8, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpBuffer, nxarg_pcbBuffer);
}
pub fn GetComputerNameA(nxarg_lpBuffer: [*]u8, nxarg_nSize: *DWORD) BOOL {
    const address = api.nx_api(0xFAB06795, 0x403B88C0) orelse unreachable;
    return @as(*const fn ([*]u8, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpBuffer, nxarg_nSize);
}
pub fn ExpandEnvironmentStringsA(nxarg_lpSrc: [*:0]const u8, nxarg_lpDst: [*]u8, nxarg_nSize: DWORD) DWORD {
    const address = api.nx_api(0xFAB06795, 0x6135046F) orelse unreachable;
    return @as(*const fn ([*:0]const u8, [*]u8, DWORD) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_lpSrc, nxarg_lpDst, nxarg_nSize);
}
pub fn VirtualAllocExNuma(nxarg_hProcess: HANDLE, nxarg_lpAddress: ?*anyopaque, nxarg_dwSize: usize, nxarg_flAllocationType: DWORD, nxarg_flProtect: DWORD, nxarg_nndPreferred: DWORD) ?*anyopaque {
    const address = api.nx_api(0xFAB06795, 0xBCF6F9AF) orelse unreachable;
    return @as(*const fn (HANDLE, ?*anyopaque, usize, DWORD, DWORD, DWORD) callconv(.winapi) ?*anyopaque, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpAddress, nxarg_dwSize, nxarg_flAllocationType, nxarg_flProtect, nxarg_nndPreferred);
}
pub fn CreateMemoryResourceNotification(nxarg_MemoryResourceNotificationType: u32) ?HANDLE {
    const address = api.nx_api(0xFAB06795, 0xC69C5CAB) orelse unreachable;
    return @as(*const fn (u32) callconv(.winapi) ?HANDLE, @ptrCast(@alignCast(address)))(nxarg_MemoryResourceNotificationType);
}
pub fn NetGetJoinInformation(nxarg_lpServer: ?[*:0]const u16, nxarg_lpNameBuffer: *?[*:0]u16, nxarg_BufferType: *u32) u32 {
    const address = api.nx_api(0xC33AF455, 0xB3A891EC) orelse unreachable;
    return @as(*const fn (?[*:0]const u16, *?[*:0]u16, *u32) callconv(.winapi) u32, @ptrCast(@alignCast(address)))(nxarg_lpServer, nxarg_lpNameBuffer, nxarg_BufferType);
}
pub fn NetApiBufferFree(nxarg_Buffer: ?*anyopaque) u32 {
    const address = api.nx_api(0xC33AF455, 0x1D36D4EC) orelse unreachable;
    return @as(*const fn (?*anyopaque) callconv(.winapi) u32, @ptrCast(@alignCast(address)))(nxarg_Buffer);
}

pub fn GetSystemTime(nxarg_lpSystemTime: *SYSTEMTIME) void {
    const address = api.nx_api(0xFAB06795, 0x56C5B543) orelse unreachable;
    @as(*const fn (*SYSTEMTIME) callconv(.winapi) void, @ptrCast(@alignCast(address)))(nxarg_lpSystemTime);
}

pub extern "kernel32" fn GetEnvironmentVariableW(
    lpName: [*:0]const WCHAR,
    lpBuffer: [*]WCHAR,
    nSize: DWORD,
) callconv(.winapi) DWORD;

pub fn GetTickCount64() u64 {
    const address = api.nx_api(0xFAB06795, 0x48E33F0D) orelse unreachable;
    return @as(*const fn () callconv(.winapi) u64, @ptrCast(@alignCast(address)))();
}

pub extern "kernel32" fn TlsAlloc() callconv(.winapi) DWORD;
pub extern "kernel32" fn TlsSetValue(dwTlsIndex: DWORD, lpTlsValue: ?*anyopaque) callconv(.winapi) BOOL;
pub fn FlushInstructionCache(nxarg_hProcess: HANDLE, nxarg_lpBaseAddress: ?*const anyopaque, nxarg_dwSize: usize) BOOL {
    const address = api.nx_api(0xFAB06795, 0x78251467) orelse unreachable;
    return @as(*const fn (HANDLE, ?*const anyopaque, usize) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hProcess, nxarg_lpBaseAddress, nxarg_dwSize);
}

pub extern "kernel32" fn Sleep(dwMilliseconds: DWORD) callconv(.winapi) void;

pub fn FindFirstFileW(nxarg_lpFileName: [*:0]const WCHAR, nxarg_lpFindFileData: *WIN32_FIND_DATAW) HANDLE {
    const address = api.nx_api(0xFAB06795, 0xCE72B5AF) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR, *WIN32_FIND_DATAW) callconv(.winapi) HANDLE, @ptrCast(@alignCast(address)))(nxarg_lpFileName, nxarg_lpFindFileData);
}

pub fn FindNextFileW(nxarg_hFindFile: HANDLE, nxarg_lpFindFileData: *WIN32_FIND_DATAW) BOOL {
    const address = api.nx_api(0xFAB06795, 0xD7D88E06) orelse unreachable;
    return @as(*const fn (HANDLE, *WIN32_FIND_DATAW) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hFindFile, nxarg_lpFindFileData);
}

pub fn FindClose(nxarg_hFindFile: HANDLE) BOOL {
    const address = api.nx_api(0xFAB06795, 0x6FF63A06) orelse unreachable;
    return @as(*const fn (HANDLE) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hFindFile);
}

pub fn CreateFileA(nxarg_lpFileName: [*:0]const u8, nxarg_dwDesiredAccess: DWORD, nxarg_dwShareMode: DWORD, nxarg_lpSecurityAttributes: ?*SECURITY_ATTRIBUTES, nxarg_dwCreationDisposition: DWORD, nxarg_dwFlagsAndAttributes: DWORD, nxarg_hTemplateFile: ?HANDLE) HANDLE {
    const address = api.nx_api(0xFAB06795, 0x09321144) orelse unreachable;
    return @as(*const fn ([*:0]const u8, DWORD, DWORD, ?*SECURITY_ATTRIBUTES, DWORD, DWORD, ?HANDLE) callconv(.winapi) HANDLE, @ptrCast(@alignCast(address)))(nxarg_lpFileName, nxarg_dwDesiredAccess, nxarg_dwShareMode, nxarg_lpSecurityAttributes, nxarg_dwCreationDisposition, nxarg_dwFlagsAndAttributes, nxarg_hTemplateFile);
}

pub fn CreateFileW(nxarg_lpFileName: [*:0]const WCHAR, nxarg_dwDesiredAccess: DWORD, nxarg_dwShareMode: DWORD, nxarg_lpSecurityAttributes: ?*SECURITY_ATTRIBUTES, nxarg_dwCreationDisposition: DWORD, nxarg_dwFlagsAndAttributes: DWORD, nxarg_hTemplateFile: ?HANDLE) HANDLE {
    const address = api.nx_api(0xFAB06795, 0x0932115A) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR, DWORD, DWORD, ?*SECURITY_ATTRIBUTES, DWORD, DWORD, ?HANDLE) callconv(.winapi) HANDLE, @ptrCast(@alignCast(address)))(nxarg_lpFileName, nxarg_dwDesiredAccess, nxarg_dwShareMode, nxarg_lpSecurityAttributes, nxarg_dwCreationDisposition, nxarg_dwFlagsAndAttributes, nxarg_hTemplateFile);
}

pub fn GetFileSizeEx(nxarg_hFile: HANDLE, nxarg_lpFileSize: *i64) BOOL {
    const address = api.nx_api(0xFAB06795, 0x0261F427) orelse unreachable;
    return @as(*const fn (HANDLE, *i64) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hFile, nxarg_lpFileSize);
}

pub fn CreateToolhelp32Snapshot(nxarg_dwFlags: DWORD, nxarg_th32ProcessID: DWORD) HANDLE {
    const address = api.nx_api(0xFAB06795, 0x6F4658BF) orelse unreachable;
    return @as(*const fn (DWORD, DWORD) callconv(.winapi) HANDLE, @ptrCast(@alignCast(address)))(nxarg_dwFlags, nxarg_th32ProcessID);
}

pub fn Process32FirstW(nxarg_hSnapshot: HANDLE, nxarg_lppe: *PROCESSENTRY32W) BOOL {
    const address = api.nx_api(0xFAB06795, 0x8757A6F2) orelse unreachable;
    return @as(*const fn (HANDLE, *PROCESSENTRY32W) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hSnapshot, nxarg_lppe);
}

pub fn Process32NextW(nxarg_hSnapshot: HANDLE, nxarg_lppe: *PROCESSENTRY32W) BOOL {
    const address = api.nx_api(0xFAB06795, 0x1BEE6B69) orelse unreachable;
    return @as(*const fn (HANDLE, *PROCESSENTRY32W) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hSnapshot, nxarg_lppe);
}

pub extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;

pub fn OpenProcessToken(nxarg_ProcessHandle: HANDLE, nxarg_DesiredAccess: DWORD, nxarg_TokenHandle: *HANDLE) BOOL {
    const address = api.nx_api(0x7B933969, 0x8DDE1581) orelse unreachable;
    return @as(*const fn (HANDLE, DWORD, *HANDLE) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_ProcessHandle, nxarg_DesiredAccess, nxarg_TokenHandle);
}

pub fn GetTokenInformation(nxarg_TokenHandle: HANDLE, nxarg_TokenInformationClass: TokenInformationClass, nxarg_TokenInformation: ?*anyopaque, nxarg_TokenInformationLength: DWORD, nxarg_ReturnLength: *DWORD) BOOL {
    const address = api.nx_api(0x7B933969, 0x7AD31776) orelse unreachable;
    return @as(*const fn (HANDLE, TokenInformationClass, ?*anyopaque, DWORD, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_TokenHandle, nxarg_TokenInformationClass, nxarg_TokenInformation, nxarg_TokenInformationLength, nxarg_ReturnLength);
}

pub fn DuplicateTokenEx(nxarg_hExistingToken: HANDLE, nxarg_dwDesiredAccess: DWORD, nxarg_lpTokenAttributes: ?*SECURITY_ATTRIBUTES, nxarg_ImpersonationLevel: SecurityImpersonationLevel, nxarg_TokenType: TokenType, nxarg_phNewToken: *HANDLE) BOOL {
    const address = api.nx_api(0x7B933969, 0xC495B408) orelse unreachable;
    return @as(*const fn (HANDLE, DWORD, ?*SECURITY_ATTRIBUTES, SecurityImpersonationLevel, TokenType, *HANDLE) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hExistingToken, nxarg_dwDesiredAccess, nxarg_lpTokenAttributes, nxarg_ImpersonationLevel, nxarg_TokenType, nxarg_phNewToken);
}

pub fn ImpersonateLoggedOnUser(nxarg_hToken: HANDLE) BOOL {
    const address = api.nx_api(0x7B933969, 0xA1023244) orelse unreachable;
    return @as(*const fn (HANDLE) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hToken);
}

pub fn RevertToSelf() BOOL {
    const address = api.nx_api(0x7B933969, 0x29E56F14) orelse unreachable;
    return @as(*const fn () callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))();
}

pub fn LogonUserW(nxarg_lpszUsername: [*:0]const u16, nxarg_lpszDomain: [*:0]const u16, nxarg_lpszPassword: [*:0]const u16, nxarg_dwLogonType: DWORD, nxarg_dwLogonProvider: DWORD, nxarg_phToken: *HANDLE) BOOL {
    const address = api.nx_api(0x7B933969, 0x3528E524) orelse unreachable;
    return @as(*const fn ([*:0]const u16, [*:0]const u16, [*:0]const u16, DWORD, DWORD, *HANDLE) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpszUsername, nxarg_lpszDomain, nxarg_lpszPassword, nxarg_dwLogonType, nxarg_dwLogonProvider, nxarg_phToken);
}

pub fn LookupAccountSidW(nxarg_lpSystemName: ?[*:0]const u16, nxarg_lpSid: ?*anyopaque, nxarg_lpName: [*]u16, nxarg_cchName: *DWORD, nxarg_lpReferencedDomainName: [*]u16, nxarg_cchReferencedDomainName: *DWORD, nxarg_peUse: *u32) BOOL {
    const address = api.nx_api(0x7B933969, 0x061E5F6D) orelse unreachable;
    return @as(*const fn (?[*:0]const u16, ?*anyopaque, [*]u16, *DWORD, [*]u16, *DWORD, *u32) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpSystemName, nxarg_lpSid, nxarg_lpName, nxarg_cchName, nxarg_lpReferencedDomainName, nxarg_cchReferencedDomainName, nxarg_peUse);
}

pub fn LookupPrivilegeNameW(nxarg_lpSystemName: ?[*:0]const u16, nxarg_lpLuid: *LUID, nxarg_lpBuffer: [*]u16, nxarg_cchBuffer: *DWORD) BOOL {
    const address = api.nx_api(0x7B933969, 0x428B6988) orelse unreachable;
    return @as(*const fn (?[*:0]const u16, *LUID, [*]u16, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpSystemName, nxarg_lpLuid, nxarg_lpBuffer, nxarg_cchBuffer);
}

pub fn LookupPrivilegeValueW(nxarg_lpSystemName: ?[*:0]const u16, nxarg_lpName: [*:0]const u16, nxarg_lpLuid: *LUID) BOOL {
    const address = api.nx_api(0x7B933969, 0xA6A19544) orelse unreachable;
    return @as(*const fn (?[*:0]const u16, [*:0]const u16, *LUID) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_lpSystemName, nxarg_lpName, nxarg_lpLuid);
}

pub fn AdjustTokenPrivileges(nxarg_TokenHandle: HANDLE, nxarg_DisableAllPrivileges: BOOL, nxarg_NewState: ?*TOKEN_PRIVILEGES, nxarg_BufferLength: DWORD, nxarg_PreviousState: ?*TOKEN_PRIVILEGES, nxarg_ReturnLength: ?*DWORD) BOOL {
    const address = api.nx_api(0x7B933969, 0xEFED1055) orelse unreachable;
    return @as(*const fn (HANDLE, BOOL, ?*TOKEN_PRIVILEGES, DWORD, ?*TOKEN_PRIVILEGES, ?*DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_TokenHandle, nxarg_DisableAllPrivileges, nxarg_NewState, nxarg_BufferLength, nxarg_PreviousState, nxarg_ReturnLength);
}

pub fn CreateProcessAsUserW(nxarg_hToken: HANDLE, nxarg_lpApplicationName: ?[*:0]const u16, nxarg_lpCommandLine: ?[*:0]u16, nxarg_lpProcessAttributes: ?*SECURITY_ATTRIBUTES, nxarg_lpThreadAttributes: ?*SECURITY_ATTRIBUTES, nxarg_bInheritHandles: BOOL, nxarg_dwCreationFlags: DWORD, nxarg_lpEnvironment: ?*anyopaque, nxarg_lpCurrentDirectory: ?[*:0]const u16, nxarg_lpStartupInfo: *STARTUPINFOW, nxarg_lpProcessInformation: *PROCESS_INFORMATION) BOOL {
    const address = api.nx_api(0x7B933969, 0xAC0F5DEC) orelse unreachable;
    return @as(*const fn (HANDLE, ?[*:0]const u16, ?[*:0]u16, ?*SECURITY_ATTRIBUTES, ?*SECURITY_ATTRIBUTES, BOOL, DWORD, ?*anyopaque, ?[*:0]const u16, *STARTUPINFOW, *PROCESS_INFORMATION) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hToken, nxarg_lpApplicationName, nxarg_lpCommandLine, nxarg_lpProcessAttributes, nxarg_lpThreadAttributes, nxarg_bInheritHandles, nxarg_dwCreationFlags, nxarg_lpEnvironment, nxarg_lpCurrentDirectory, nxarg_lpStartupInfo, nxarg_lpProcessInformation);
}

pub fn OpenProcess(nxarg_dwDesiredAccess: DWORD, nxarg_bInheritHandle: BOOL, nxarg_dwProcessId: DWORD) ?HANDLE {
    const address = api.nx_api(0xFAB06795, 0x2BD6D100) orelse unreachable;
    return @as(*const fn (DWORD, BOOL, DWORD) callconv(.winapi) ?HANDLE, @ptrCast(@alignCast(address)))(nxarg_dwDesiredAccess, nxarg_bInheritHandle, nxarg_dwProcessId);
}

pub fn SetProcessMitigationPolicy(nxarg_MitigationPolicy: ProcessMitigationPolicy, nxarg_lpBuffer: *anyopaque, nxarg_dwLength: usize) BOOL {
    const address = api.nx_api(0xFAB06795, 0x1916723F) orelse unreachable;
    return @as(*const fn (ProcessMitigationPolicy, *anyopaque, usize) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_MitigationPolicy, nxarg_lpBuffer, nxarg_dwLength);
}

pub fn IsWellKnownSid(nxarg_Sid: ?*anyopaque, nxarg_WellKnownSidType: u32) BOOL {
    const address = api.nx_api(0x7B933969, 0x4C6628AC) orelse unreachable;
    return @as(*const fn (?*anyopaque, u32) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_Sid, nxarg_WellKnownSidType);
}

pub fn GetIpAddrTable(nxarg_pIpAddrTable: ?*MIB_IPADDRTABLE, nxarg_pdwSize: *DWORD, nxarg_bOrder: BOOL) DWORD {
    const address = api.nx_api(0x8A3A67D0, 0x9F4BEC8B) orelse unreachable;
    return @as(*const fn (?*MIB_IPADDRTABLE, *DWORD, BOOL) callconv(.winapi) DWORD, @ptrCast(@alignCast(address)))(nxarg_pIpAddrTable, nxarg_pdwSize, nxarg_bOrder);
}

pub fn SystemFunction036(nxarg_RandomBuffer: *anyopaque, nxarg_RandomBufferLength: u32) u8 {
    const address = api.nx_api(0x7B933969, 0x168B07D3) orelse unreachable;
    return @as(*const fn (*anyopaque, u32) callconv(.winapi) u8, @ptrCast(@alignCast(address)))(nxarg_RandomBuffer, nxarg_RandomBufferLength);
}

pub fn nx_random_bytes(buf: []u8) void {
    if (buf.len == 0) return;
    if (SystemFunction036(buf.ptr, @intCast(buf.len)) == 0) {
        var tick = GetTickCount64();
        for (buf) |*b| {
            b.* = @truncate(tick);
            tick = tick *% 6364136223846793005 +% 1442695040888963407;
        }
    }
}

pub const NX_SECURITY_ATTRIBUTES_INHERIT = SECURITY_ATTRIBUTES{
    .nLength = @sizeOf(SECURITY_ATTRIBUTES),
    .lpSecurityDescriptor = null,
    .bInheritHandle = BOOL.TRUE,
};

// WinINet
pub const INTERNET_OPEN_TYPE_PRECONFIG: DWORD = 0;
pub const INTERNET_OPEN_TYPE_PROXY: DWORD = 3;
pub const INTERNET_SERVICE_HTTP: DWORD = 3;
pub const INTERNET_FLAG_RELOAD: DWORD = 0x80000000;
pub const INTERNET_FLAG_NO_CACHE_WRITE: DWORD = 0x04000000;
pub const INTERNET_FLAG_NO_UI: DWORD = 0x00000200;
pub const INTERNET_FLAG_SECURE: DWORD = 0x00800000;
pub const INTERNET_FLAG_IGNORE_CERT_CN_INVALID: DWORD = 0x00001000;
pub const INTERNET_FLAG_IGNORE_CERT_DATE_INVALID: DWORD = 0x00002000;
pub const INTERNET_OPTION_CONNECT_TIMEOUT: DWORD = 2;
pub const INTERNET_OPTION_SEND_TIMEOUT: DWORD = 5;
pub const INTERNET_OPTION_RECEIVE_TIMEOUT: DWORD = 6;
pub const INTERNET_OPTION_SECURITY_FLAGS: DWORD = 31;
pub const SECURITY_FLAG_IGNORE_UNKNOWN_CA: DWORD = 0x00000100;
pub const SECURITY_FLAG_IGNORE_CERT_CN_INVALID: DWORD = 0x00001000;
pub const SECURITY_FLAG_IGNORE_CERT_DATE_INVALID: DWORD = 0x00002000;
pub const SECURITY_FLAG_IGNORE_WRONG_USAGE: DWORD = 0x00000200;
pub const HTTP_QUERY_STATUS_CODE: DWORD = 19;
pub const HTTP_QUERY_FLAG_NUMBER: DWORD = 0x20000000;

pub fn WSAStartup(nxarg_wVersionRequested: u16, nxarg_lpWSAData: *WSADATA) c_int {
    const address = api.nx_api(0x6F6BE52F, 0xEA8198CD) orelse unreachable;
    return @as(*const fn (u16, *WSADATA) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_wVersionRequested, nxarg_lpWSAData);
}

pub fn WSACleanup() c_int {
    const address = api.nx_api(0x6F6BE52F, 0x08737DC2) orelse unreachable;
    return @as(*const fn () callconv(.winapi) c_int, @ptrCast(@alignCast(address)))();
}

pub fn socket(nxarg_af: c_int, nxarg_socket_type: c_int, nxarg_protocol: c_int) SOCKET {
    const address = api.nx_api(0x6F6BE52F, 0x65D7E078) orelse unreachable;
    return @as(*const fn (c_int, c_int, c_int) callconv(.winapi) SOCKET, @ptrCast(@alignCast(address)))(nxarg_af, nxarg_socket_type, nxarg_protocol);
}

pub fn connect(nxarg_s: SOCKET, nxarg_name: *const SOCKADDR_IN, nxarg_namelen: c_int) c_int {
    const address = api.nx_api(0x6F6BE52F, 0x51F8D439) orelse unreachable;
    return @as(*const fn (SOCKET, *const SOCKADDR_IN, c_int) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_name, nxarg_namelen);
}

pub fn bind(nxarg_s: SOCKET, nxarg_name: *const SOCKADDR_IN, nxarg_namelen: c_int) c_int {
    const address = api.nx_api(0x6F6BE52F, 0xEF2190EC) orelse unreachable;
    return @as(*const fn (SOCKET, *const SOCKADDR_IN, c_int) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_name, nxarg_namelen);
}

pub fn listen(nxarg_s: SOCKET, nxarg_backlog: c_int) c_int {
    const address = api.nx_api(0x6F6BE52F, 0x55201D5E) orelse unreachable;
    return @as(*const fn (SOCKET, c_int) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_backlog);
}

pub fn accept(nxarg_s: SOCKET, nxarg_addr: ?*SOCKADDR_IN, nxarg_addrlen: ?*c_int) SOCKET {
    const address = api.nx_api(0x6F6BE52F, 0x3B01C6FF) orelse unreachable;
    return @as(*const fn (SOCKET, ?*SOCKADDR_IN, ?*c_int) callconv(.winapi) SOCKET, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_addr, nxarg_addrlen);
}

pub fn closesocket(nxarg_s: SOCKET) c_int {
    const address = api.nx_api(0x6F6BE52F, 0xB90E43EE) orelse unreachable;
    return @as(*const fn (SOCKET) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s);
}

pub fn send(nxarg_s: SOCKET, nxarg_buf: [*]const u8, nxarg_len: c_int, nxarg_flags: c_int) c_int {
    const address = api.nx_api(0x6F6BE52F, 0xEF2AD259) orelse unreachable;
    return @as(*const fn (SOCKET, [*]const u8, c_int, c_int) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_buf, nxarg_len, nxarg_flags);
}

pub fn recv(nxarg_s: SOCKET, nxarg_buf: [*]u8, nxarg_len: c_int, nxarg_flags: c_int) c_int {
    const address = api.nx_api(0x6F6BE52F, 0xEF2A449F) orelse unreachable;
    return @as(*const fn (SOCKET, [*]u8, c_int, c_int) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_buf, nxarg_len, nxarg_flags);
}

pub fn ioctlsocket(nxarg_s: SOCKET, nxarg_cmd: i32, nxarg_argp: *u32) c_int {
    const address = api.nx_api(0x6F6BE52F, 0x769E68F3) orelse unreachable;
    return @as(*const fn (SOCKET, i32, *u32) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_cmd, nxarg_argp);
}

pub fn select(nxarg_nfds: c_int, nxarg_readfds: ?*FD_SET, nxarg_writefds: ?*FD_SET, nxarg_exceptfds: ?*FD_SET, nxarg_timeout: ?*TIMEVAL) c_int {
    const address = api.nx_api(0x6F6BE52F, 0x6527C10F) orelse unreachable;
    return @as(*const fn (c_int, ?*FD_SET, ?*FD_SET, ?*FD_SET, ?*TIMEVAL) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_nfds, nxarg_readfds, nxarg_writefds, nxarg_exceptfds, nxarg_timeout);
}

pub fn getsockopt(nxarg_s: SOCKET, nxarg_level: c_int, nxarg_optname: c_int, nxarg_optval: [*]u8, nxarg_optlen: *c_int) c_int {
    const address = api.nx_api(0x6F6BE52F, 0xC8639EB2) orelse unreachable;
    return @as(*const fn (SOCKET, c_int, c_int, [*]u8, *c_int) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_level, nxarg_optname, nxarg_optval, nxarg_optlen);
}

pub fn setsockopt(nxarg_s: SOCKET, nxarg_level: c_int, nxarg_optname: c_int, nxarg_optval: [*]const u8, nxarg_optlen: c_int) c_int {
    const address = api.nx_api(0x6F6BE52F, 0xF8E26C3E) orelse unreachable;
    return @as(*const fn (SOCKET, c_int, c_int, [*]const u8, c_int) callconv(.winapi) c_int, @ptrCast(@alignCast(address)))(nxarg_s, nxarg_level, nxarg_optname, nxarg_optval, nxarg_optlen);
}

pub fn gethostbyname(nxarg_name: [*:0]const u8) ?*HOSTENT {
    const address = api.nx_api(0x6F6BE52F, 0x974B4EA9) orelse unreachable;
    return @as(*const fn ([*:0]const u8) callconv(.winapi) ?*HOSTENT, @ptrCast(@alignCast(address)))(nxarg_name);
}

pub fn WSAGetLastError() c_int {
    const address = api.nx_api(0x6F6BE52F, 0x73059678) orelse unreachable;
    return @as(*const fn () callconv(.winapi) c_int, @ptrCast(@alignCast(address)))();
}

pub fn InternetOpenW(nxarg_lpszAgent: [*:0]const WCHAR, nxarg_dwAccessType: DWORD, nxarg_lpszProxy: ?[*:0]const WCHAR, nxarg_lpszProxyBypass: ?[*:0]const WCHAR, nxarg_dwFlags: DWORD) ?HINTERNET {
    const address = api.nx_api(0x4784082D, 0x4943A241) orelse unreachable;
    return @as(*const fn ([*:0]const WCHAR, DWORD, ?[*:0]const WCHAR, ?[*:0]const WCHAR, DWORD) callconv(.winapi) ?HINTERNET, @ptrCast(@alignCast(address)))(nxarg_lpszAgent, nxarg_dwAccessType, nxarg_lpszProxy, nxarg_lpszProxyBypass, nxarg_dwFlags);
}

pub fn InternetConnectW(nxarg_hInternet: HINTERNET, nxarg_lpszServerName: [*:0]const WCHAR, nxarg_nServerPort: u16, nxarg_lpszUserName: ?[*:0]const WCHAR, nxarg_lpszPassword: ?[*:0]const WCHAR, nxarg_dwService: DWORD, nxarg_dwFlags: DWORD, nxarg_dwContext: usize) ?HINTERNET {
    const address = api.nx_api(0x4784082D, 0x74418659) orelse unreachable;
    return @as(*const fn (HINTERNET, [*:0]const WCHAR, u16, ?[*:0]const WCHAR, ?[*:0]const WCHAR, DWORD, DWORD, usize) callconv(.winapi) ?HINTERNET, @ptrCast(@alignCast(address)))(nxarg_hInternet, nxarg_lpszServerName, nxarg_nServerPort, nxarg_lpszUserName, nxarg_lpszPassword, nxarg_dwService, nxarg_dwFlags, nxarg_dwContext);
}

pub fn HttpOpenRequestW(nxarg_hConnect: HINTERNET, nxarg_lpszVerb: ?[*:0]const WCHAR, nxarg_lpszObjectName: [*:0]const WCHAR, nxarg_lpszVersion: ?[*:0]const WCHAR, nxarg_lpszReferrer: ?[*:0]const WCHAR, nxarg_lplpszAcceptTypes: ?[*]const ?[*:0]const WCHAR, nxarg_dwFlags: DWORD, nxarg_dwContext: usize) ?HINTERNET {
    const address = api.nx_api(0x4784082D, 0x3F568B01) orelse unreachable;
    return @as(*const fn (HINTERNET, ?[*:0]const WCHAR, [*:0]const WCHAR, ?[*:0]const WCHAR, ?[*:0]const WCHAR, ?[*]const ?[*:0]const WCHAR, DWORD, usize) callconv(.winapi) ?HINTERNET, @ptrCast(@alignCast(address)))(nxarg_hConnect, nxarg_lpszVerb, nxarg_lpszObjectName, nxarg_lpszVersion, nxarg_lpszReferrer, nxarg_lplpszAcceptTypes, nxarg_dwFlags, nxarg_dwContext);
}

pub fn HttpSendRequestW(nxarg_hRequest: HINTERNET, nxarg_lpszHeaders: ?[*:0]const WCHAR, nxarg_dwHeadersLength: i32, nxarg_lpOptional: ?*const anyopaque, nxarg_dwOptionalLength: DWORD) BOOL {
    const address = api.nx_api(0x4784082D, 0xDFAAE6D9) orelse unreachable;
    return @as(*const fn (HINTERNET, ?[*:0]const WCHAR, i32, ?*const anyopaque, DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hRequest, nxarg_lpszHeaders, nxarg_dwHeadersLength, nxarg_lpOptional, nxarg_dwOptionalLength);
}

pub fn HttpQueryInfoW(nxarg_hRequest: HINTERNET, nxarg_dwInfoLevel: DWORD, nxarg_lpBuffer: ?*anyopaque, nxarg_lpdwBufferLength: *DWORD, nxarg_lpdwIndex: ?*DWORD) BOOL {
    const address = api.nx_api(0x4784082D, 0x75EF7768) orelse unreachable;
    return @as(*const fn (HINTERNET, DWORD, ?*anyopaque, *DWORD, ?*DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hRequest, nxarg_dwInfoLevel, nxarg_lpBuffer, nxarg_lpdwBufferLength, nxarg_lpdwIndex);
}

pub fn InternetReadFile(nxarg_hFile: HINTERNET, nxarg_lpBuffer: [*]u8, nxarg_dwNumberOfBytesToRead: DWORD, nxarg_lpdwNumberOfBytesRead: *DWORD) BOOL {
    const address = api.nx_api(0x4784082D, 0x2B4F3F94) orelse unreachable;
    return @as(*const fn (HINTERNET, [*]u8, DWORD, *DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hFile, nxarg_lpBuffer, nxarg_dwNumberOfBytesToRead, nxarg_lpdwNumberOfBytesRead);
}

pub fn InternetSetOptionW(nxarg_hInternet: HINTERNET, nxarg_dwOption: DWORD, nxarg_lpBuffer: ?*anyopaque, nxarg_dwBufferLength: DWORD) BOOL {
    const address = api.nx_api(0x4784082D, 0x2FE4A254) orelse unreachable;
    return @as(*const fn (HINTERNET, DWORD, ?*anyopaque, DWORD) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hInternet, nxarg_dwOption, nxarg_lpBuffer, nxarg_dwBufferLength);
}

pub fn InternetCloseHandle(nxarg_hInternet: HINTERNET) BOOL {
    const address = api.nx_api(0x4784082D, 0xF240AF3A) orelse unreachable;
    return @as(*const fn (HINTERNET) callconv(.winapi) BOOL, @ptrCast(@alignCast(address)))(nxarg_hInternet);
}
