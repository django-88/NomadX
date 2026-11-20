const std = @import("std");
const win = @import("win32.zig");
const jsonutil = @import("jsonutil.zig");
const socks = @import("socks.zig");

const page_allocator = @import("alloc.zig").nx_page_allocator;
const base64 = std.base64.standard;

const NX_MAX_LISTENERS = 4;
const NX_MAX_CONNS = 32;
const NX_OUT_MAX = 64 * 1024;
const NX_UPSTREAM_MAX = 512 * 1024;
const NX_RECV_CHUNK = 8192;

const NxListener = struct {
    sock: win.SOCKET = win.INVALID_SOCKET,
    port: u16 = 0,
};

const NxConn = struct {
    used: bool = false,
    server_id: u32 = 0,
    sock: win.SOCKET = win.INVALID_SOCKET,
    exit_sent: bool = false,
    port: u16 = 0,
    pending_out: std.ArrayList(u8) = .empty,
};

const NxMessage = struct {
    server_id: u32,
    data: []u8,
    is_exit: bool,
    port: u16,
};

var nx_listeners: [NX_MAX_LISTENERS]NxListener = @splat(.{});
var nx_conns: [NX_MAX_CONNS]NxConn = @splat(.{});
var nx_upstream: std.ArrayList(NxMessage) = .empty;
var nx_upstream_bytes: usize = 0;
var nx_next_id: u32 = 0;

fn nx_htons(value: u16) u16 {
    return (value >> 8) | (value << 8);
}

fn nx_new_id() u32 {
    nx_next_id +%= 1;
    if (nx_next_id == 0) nx_next_id = 1;
    return nx_next_id;
}

pub fn nx_has_active() bool {
    for (nx_listeners) |listener| {
        if (listener.sock != win.INVALID_SOCKET) return true;
    }
    for (nx_conns) |conn| {
        if (conn.used) return true;
    }
    return false;
}

fn nx_find(server_id: u32) ?usize {
    for (nx_conns, 0..) |conn, index| {
        if (conn.used and conn.server_id == server_id) return index;
    }
    return null;
}

fn nx_queue(server_id: u32, data: []const u8, is_exit: bool, port: u16) void {
    if (!is_exit and data.len == 0 and server_id == 0) return;
    if (data.len > 64 and nx_upstream_bytes + data.len > NX_UPSTREAM_MAX) return;

    const copy = page_allocator.dupe(u8, data) catch return;
    nx_upstream.append(page_allocator, .{
        .server_id = server_id,
        .data = copy,
        .is_exit = is_exit,
        .port = port,
    }) catch {
        page_allocator.free(copy);
        return;
    };
    nx_upstream_bytes += data.len;
}

fn nx_close_conn(conn: *NxConn, notify: bool) void {
    if (conn.sock != win.INVALID_SOCKET) {
        _ = win.closesocket(conn.sock);
        conn.sock = win.INVALID_SOCKET;
    }
    if (notify and !conn.exit_sent) {
        nx_queue(conn.server_id, &.{}, true, conn.port);
        conn.exit_sent = true;
    }
    conn.pending_out.deinit(page_allocator);
    conn.pending_out = .empty;
    conn.used = false;
}

fn nx_flush(conn: *NxConn) void {
    if (!conn.used or conn.pending_out.items.len == 0) return;
    while (conn.pending_out.items.len > 0) {
        const pending = conn.pending_out.items;
        const sent = win.send(conn.sock, pending.ptr, @intCast(pending.len), 0);
        if (sent > 0) {
            const amount: usize = @intCast(sent);
            std.mem.copyForwards(u8, pending[0 .. pending.len - amount], pending[amount..pending.len]);
            conn.pending_out.shrinkRetainingCapacity(pending.len - amount);
        } else if (sent == win.SOCKET_ERROR) {
            if (win.WSAGetLastError() != win.WSAEWOULDBLOCK) nx_close_conn(conn, true);
            break;
        } else {
            break;
        }
    }
}

fn nx_append_out(conn: *NxConn, data: []const u8) void {
    if (data.len == 0) return;
    if (conn.pending_out.items.len + data.len > NX_OUT_MAX) {
        nx_close_conn(conn, true);
        return;
    }
    conn.pending_out.appendSlice(page_allocator, data) catch {
        nx_close_conn(conn, true);
    };
}

fn nx_listener_index(port: u16) ?usize {
    for (nx_listeners, 0..) |listener, index| {
        if (listener.sock != win.INVALID_SOCKET and listener.port == port) return index;
    }
    return null;
}

pub fn nx_start(port: u16) bool {
    if (port == 0) return false;
    if (!socks.nx_init()) return false;
    if (nx_listener_index(port) != null) return true;

    var slot: ?usize = null;
    for (nx_listeners, 0..) |listener, index| {
        if (listener.sock == win.INVALID_SOCKET) {
            slot = index;
            break;
        }
    }
    const index = slot orelse return false;

    const socket = win.socket(win.AF_INET, win.SOCK_STREAM, win.IPPROTO_TCP);
    if (socket == win.INVALID_SOCKET) return false;
    var keep_socket = false;
    defer {
        if (!keep_socket) _ = win.closesocket(socket);
    }

    var yes: c_int = 1;
    _ = win.setsockopt(socket, win.SOL_SOCKET, win.SO_REUSEADDR, @ptrCast(&yes), @sizeOf(c_int));

    var address: win.SOCKADDR_IN = std.mem.zeroes(win.SOCKADDR_IN);
    address.sin_family = win.AF_INET;
    address.sin_addr = win.INADDR_ANY;
    address.sin_port = nx_htons(port);

    if (win.bind(socket, &address, @sizeOf(win.SOCKADDR_IN)) == win.SOCKET_ERROR) return false;
    if (win.listen(socket, win.SOMAXCONN) == win.SOCKET_ERROR) return false;

    var nonblocking: u32 = 1;
    _ = win.ioctlsocket(socket, win.FIONBIO, &nonblocking);
    nx_listeners[index] = .{ .sock = socket, .port = port };
    keep_socket = true;
    return true;
}

pub fn nx_stop(port: u16) void {
    if (nx_listener_index(port)) |index| {
        _ = win.closesocket(nx_listeners[index].sock);
        nx_listeners[index] = .{};
    }
    for (&nx_conns) |*conn| {
        if (conn.used and conn.port == port) nx_close_conn(conn, true);
    }
}

pub fn nx_stop_all() void {
    for (&nx_listeners) |*listener| {
        if (listener.sock != win.INVALID_SOCKET) {
            _ = win.closesocket(listener.sock);
            listener.* = .{};
        }
    }
    for (&nx_conns) |*conn| {
        if (conn.used) nx_close_conn(conn, true);
    }
}

pub fn nx_poll() void {
    if (!socks.nx_init()) return;

    for (&nx_listeners) |*listener| {
        if (listener.sock == win.INVALID_SOCKET) continue;
        while (true) {
            const client = win.accept(listener.sock, null, null);
            if (client == win.INVALID_SOCKET) break;

            var nonblocking: u32 = 1;
            _ = win.ioctlsocket(client, win.FIONBIO, &nonblocking);

            var slot: ?usize = null;
            for (nx_conns, 0..) |conn, index| {
                if (!conn.used) {
                    slot = index;
                    break;
                }
            }
            const index = slot orelse {
                _ = win.closesocket(client);
                continue;
            };

            const conn = &nx_conns[index];
            conn.* = .{
                .used = true,
                .server_id = nx_new_id(),
                .sock = client,
                .exit_sent = false,
                .port = listener.port,
            };
            nx_queue(conn.server_id, &.{}, false, conn.port);
        }
    }

    for (&nx_conns) |*conn| {
        if (!conn.used) continue;
        nx_flush(conn);
        while (nx_upstream_bytes + NX_RECV_CHUNK <= NX_UPSTREAM_MAX) {
            var buffer: [NX_RECV_CHUNK]u8 = undefined;
            const received = win.recv(conn.sock, &buffer, buffer.len, 0);
            if (received > 0) {
                nx_queue(conn.server_id, buffer[0..@intCast(received)], false, conn.port);
            } else if (received == 0) {
                nx_close_conn(conn, true);
                break;
            } else {
                if (win.WSAGetLastError() == win.WSAEWOULDBLOCK) break;
                nx_close_conn(conn, true);
                break;
            }
        }
    }
}

fn nx_encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const size = base64.Encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, size);
    _ = base64.Encoder.encode(encoded, data);
    return encoded;
}

pub fn nx_append_to_request(allocator: std.mem.Allocator, request: *jsonutil.NxObject) !void {
    if (nx_upstream.items.len == 0) return;

    var array = jsonutil.nx_init_array(allocator);
    for (nx_upstream.items) |message| {
        var item = jsonutil.nx_init_object();
        try jsonutil.nx_put_integer(allocator, &item, "server_id", message.server_id);
        try jsonutil.nx_put_bool(allocator, &item, "exit", message.is_exit);
        try jsonutil.nx_put_integer(allocator, &item, "port", message.port);
        if (!message.is_exit and message.data.len > 0) {
            const encoded = try nx_encode(allocator, message.data);
            try jsonutil.nx_put_string(allocator, &item, "data", encoded);
        }
        try array.append(.{ .object = item });
    }
    try jsonutil.nx_put_array(allocator, request, "rpfwd", array);

    for (nx_upstream.items) |message| page_allocator.free(message.data);
    nx_upstream.clearRetainingCapacity();
    nx_upstream_bytes = 0;
}

fn nx_decode(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const size = try base64.Decoder.calcSizeForSlice(text);
    const decoded = try allocator.alloc(u8, size);
    try base64.Decoder.decode(decoded, text);
    return decoded;
}

pub fn nx_handle_response(allocator: std.mem.Allocator, response: std.json.Value) void {
    const messages = jsonutil.nx_get_array(response, "rpfwd") orelse return;
    for (messages) |message| {
        if (message != .object) continue;
        const server_id_value = jsonutil.nx_get_integer(message, "server_id") orelse continue;
        if (server_id_value <= 0 or server_id_value > std.math.maxInt(u32)) continue;
        const server_id: u32 = @intCast(server_id_value);
        const is_exit = jsonutil.nx_get_bool(message, "exit") orelse false;

        const index = nx_find(server_id) orelse continue;
        const conn = &nx_conns[index];
        if (is_exit) {
            nx_close_conn(conn, false);
            continue;
        }

        const encoded = jsonutil.nx_get_string(message, "data") orelse continue;
        if (encoded.len == 0) continue;
        const data = nx_decode(allocator, encoded) catch continue;
        nx_append_out(conn, data);
        nx_flush(conn);
    }
}
