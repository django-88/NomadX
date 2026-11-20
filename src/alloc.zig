const std = @import("std");
const win = @import("win32.zig");

const NX_PAGE_SIZE: usize = 4096;

fn nx_alloc(_: *anyopaque, n: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
    if (n == 0) return null;
    if (alignment.toByteUnits() > NX_PAGE_SIZE) return null;
    const memory = win.VirtualAlloc(
        null,
        n,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_READWRITE,
    ) orelse return null;
    return @ptrCast(memory);
}

fn nx_resize(_: *anyopaque, memory: []u8, _: std.mem.Alignment, new_len: usize, _: usize) bool {
    return new_len <= memory.len;
}

fn nx_remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
    return null;
}

fn nx_free(_: *anyopaque, memory: []u8, _: std.mem.Alignment, _: usize) void {
    if (memory.len == 0) return;
    _ = win.VirtualFree(memory.ptr, 0, win.MEM_RELEASE);
}

const nx_vtable = std.mem.Allocator.VTable{
    .alloc = nx_alloc,
    .resize = nx_resize,
    .remap = nx_remap,
    .free = nx_free,
};

/// Page allocator backed by the lazily resolved VirtualAlloc/VirtualFree
/// wrappers, so the image does not need std's ntdll import path.
pub const nx_page_allocator = std.mem.Allocator{
    .ptr = undefined,
    .vtable = &nx_vtable,
};
