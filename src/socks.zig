const std = @import("std");
const win = @import("win32.zig");
const jsonutil = @import("jsonutil.zig");

const page_allocator = @import("alloc.zig").nx_page_allocator;
const base64 = std.base64.standard;

const NX_MAX_CONNS = 32;
const NX_REQUEST_MAX = 512;
const NX_OUT_MAX = 64 * 1024;
const NX_UPSTREAM_MAX = 512 * 1024;
const NX_RECV_CHUNK = 8192;

const NxState = enum(u8) { free, request, connecting, connected };

const NxConn = struct {
    state: NxState = .free,
    server_id: u32 = 0,
    sock: win.SOCKET = win.INVALID_SOCKET,
    request_parsed: bool = false,
    exit_sent: bool = false,
    pending_req: std.ArrayList(u8) = .empty,
    pending_out: std.ArrayList(u8) = .empty,
};

const NxMessage = struct {
    server_id: u32,
    data: []u8,
    is_exit: bool,
};

var nx_conns: [NX_MAX_CONNS]NxConn = @splat(.{});
var nx_upstream: std.ArrayList(NxMessage) = .empty;
var nx_upstream_bytes: usize = 0;
var nx_initialized = false;

pub fn nx_init() bool {
    if (nx_initialized) return true;
    var data: win.WSADATA = undefined;
    if (win.WSAStartup(0x0202, &data) != 0) return false;
    nx_initialized = true;
    return true;
}

pub fn nx_has_active() bool {
    for (nx_conns) |conn| {
        if (conn.state != .free) return true;
    }
    return false;
}

fn nx_find(server_id: u32) ?usize {
    for (nx_conns, 0..) |conn, index| {
        if (conn.state != .free and conn.server_id == server_id) return index;
    }
    return null;
}

fn nx_alloc(server_id: u32) ?usize {
    for (&nx_conns, 0..) |*conn, index| {
        if (conn.state != .free) continue;
        conn.* = .{
            .state = .request,
            .server_id = server_id,
            .sock = win.INVALID_SOCKET,
            .request_parsed = false,
            .exit_sent = false,
        };
        return index;
    }
    return null;
}

fn nx_queue(server_id: u32, data: []const u8, is_exit: bool) void {
    if (!is_exit and data.len == 0 and server_id == 0) return;
    if (data.len > 64 and nx_upstream_bytes + data.len > NX_UPSTREAM_MAX) return;

    const copy = page_allocator.dupe(u8, data) catch return;
    nx_upstream.append(page_allocator, .{
        .server_id = server_id,
        .data = copy,
        .is_exit = is_exit,
    }) catch {
        page_allocator.free(copy);
        return;
    };
    nx_upstream_bytes += data.len;
}

fn nx_close(conn: *NxConn, notify: bool) void {
    if (conn.sock != win.INVALID_SOCKET) {
        _ = win.closesocket(conn.sock);
        conn.sock = win.INVALID_SOCKET;
    }
    if (notify and !conn.exit_sent) {
        nx_queue(conn.server_id, &.{}, true);
        conn.exit_sent = true;
    }
    conn.pending_req.deinit(page_allocator);
    conn.pending_req = .empty;
    conn.pending_out.deinit(page_allocator);
    conn.pending_out = .empty;
    conn.state = .free;
    conn.request_parsed = false;
}

fn nx_reply(conn: *NxConn, success: bool) void {
    const ok = [_]u8{ 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    const fail = [_]u8{ 5, 1, 0, 1, 0, 0, 0, 0, 0, 0 };
    nx_queue(conn.server_id, if (success) &ok else &fail, false);
}

fn nx_fail_conn(conn: *NxConn) void {
    nx_reply(conn, false);
    nx_close(conn, true);
}

fn nx_append_out(conn: *NxConn, data: []const u8) void {
    if (data.len == 0) return;
    if (conn.pending_out.items.len + data.len > NX_OUT_MAX) {
        nx_fail_conn(conn);
        return;
    }
    conn.pending_out.appendSlice(page_allocator, data) catch {
        nx_fail_conn(conn);
    };
}

fn nx_parse(conn: *NxConn) i8 {
    if (conn.request_parsed) return 1;
    if (conn.pending_req.items.len < 4) return 0;

    const request = conn.pending_req.items;
    if (request[0] != 5 or request[1] != 1) {
        nx_fail_conn(conn);
        return -1;
    }

    const address_type = request[3];
    var needed: usize = 0;
    var host: [256]u8 = undefined;
    var host_len: usize = 0;

    if (address_type == 1) {
        needed = 10;
        if (conn.pending_req.items.len < needed) return 0;
    } else if (address_type == 3) {
        if (conn.pending_req.items.len < 5) return 0;
        host_len = request[4];
        needed = 5 + host_len + 2;
        if (conn.pending_req.items.len < needed) return 0;
        @memcpy(host[0..host_len], request[5 .. 5 + host_len]);
        host[host_len] = 0;
    } else {
        nx_fail_conn(conn);
        return -1;
    }

    const port: u16 = @as(u16, request[needed - 2]) | (@as(u16, request[needed - 1]) << 8);
    var address: win.SOCKADDR_IN = std.mem.zeroes(win.SOCKADDR_IN);
    address.sin_family = win.AF_INET;
    address.sin_port = port;

    if (address_type == 1) {
        address.sin_addr = std.mem.readInt(u32, request[4..8], .little);
    } else {
        const hostent = win.gethostbyname(@ptrCast(&host)) orelse {
            nx_fail_conn(conn);
            return -1;
        };
        if (@as(c_int, hostent.h_addrtype) != win.AF_INET or hostent.h_addr_list == null) {
            nx_fail_conn(conn);
            return -1;
        }
        const first = hostent.h_addr_list.?[0] orelse {
            nx_fail_conn(conn);
            return -1;
        };
        address.sin_addr = std.mem.readInt(u32, first[0..4], .little);
    }

    const socket = win.socket(win.AF_INET, win.SOCK_STREAM, win.IPPROTO_TCP);
    if (socket == win.INVALID_SOCKET) {
        nx_fail_conn(conn);
        return -1;
    }

    var nonblocking: u32 = 1;
    _ = win.ioctlsocket(socket, win.FIONBIO, &nonblocking);
    conn.sock = socket;

    const result = win.connect(socket, &address, @sizeOf(win.SOCKADDR_IN));
    const error_code = win.WSAGetLastError();
    if (result == 0) {
        conn.state = .connected;
        nx_reply(conn, true);
    } else if (error_code == win.WSAEWOULDBLOCK) {
        conn.state = .connecting;
    } else {
        nx_fail_conn(conn);
        return -1;
    }

    if (conn.pending_req.items.len > needed) {
        nx_append_out(conn, request[needed..conn.pending_req.items.len]);
    }
    conn.pending_req.clearRetainingCapacity();
    conn.request_parsed = true;
    return 1;
}

fn nx_flush(conn: *NxConn) void {
    while (conn.pending_out.items.len > 0) {
        const pending = conn.pending_out.items;
        const sent = win.send(conn.sock, pending.ptr, @intCast(pending.len), 0);
        if (sent > 0) {
            const amount: usize = @intCast(sent);
            std.mem.copyForwards(u8, pending[0 .. pending.len - amount], pending[amount..pending.len]);
            conn.pending_out.shrinkRetainingCapacity(pending.len - amount);
        } else if (sent == win.SOCKET_ERROR) {
            if (win.WSAGetLastError() != win.WSAEWOULDBLOCK) nx_close(conn, true);
            break;
        } else {
            break;
        }
    }
}

fn nx_finish_connect(conn: *NxConn) void {
    if (conn.state != .connecting or conn.sock == win.INVALID_SOCKET) return;

    var write_set: win.FD_SET = std.mem.zeroes(win.FD_SET);
    write_set.fd_count = 1;
    write_set.fd_array[0] = conn.sock;
    var timeout = win.TIMEVAL{ .tv_sec = 0, .tv_usec = 0 };

    const selected = win.select(0, null, &write_set, null, &timeout);
    if (selected == win.SOCKET_ERROR) {
        nx_fail_conn(conn);
        return;
    }
    if (selected == 0) return;

    var error_code: c_int = 0;
    var error_length: c_int = @sizeOf(c_int);
    const result = win.getsockopt(conn.sock, win.SOL_SOCKET, win.SO_ERROR, @ptrCast(&error_code), &error_length);
    if (result == 0 and error_code == 0) {
        conn.state = .connected;
        nx_reply(conn, true);
    } else {
        nx_fail_conn(conn);
    }
}

pub fn nx_poll() void {
    if (!nx_initialized) return;

    for (&nx_conns) |*conn| {
        if (conn.state == .free) continue;
        nx_finish_connect(conn);
        if (conn.state != .connected) continue;
        nx_flush(conn);

        while (nx_upstream_bytes + NX_RECV_CHUNK <= NX_UPSTREAM_MAX) {
            var buffer: [NX_RECV_CHUNK]u8 = undefined;
            const received = win.recv(conn.sock, &buffer, buffer.len, 0);
            if (received > 0) {
                nx_queue(conn.server_id, buffer[0..@intCast(received)], false);
            } else if (received == 0) {
                nx_close(conn, true);
                break;
            } else {
                if (win.WSAGetLastError() == win.WSAEWOULDBLOCK) break;
                nx_close(conn, true);
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
        if (!message.is_exit and message.data.len > 0) {
            const encoded = try nx_encode(allocator, message.data);
            try jsonutil.nx_put_string(allocator, &item, "data", encoded);
        }
        try array.append(.{ .object = item });
    }
    try jsonutil.nx_put_array(allocator, request, "socks", array);

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
    const messages = jsonutil.nx_get_array(response, "socks") orelse return;
    if (!nx_init()) return;
    for (messages) |message| {
        if (message != .object) continue;
        const server_id_value = jsonutil.nx_get_integer(message, "server_id") orelse continue;
        if (server_id_value <= 0 or server_id_value > std.math.maxInt(u32)) continue;
        const server_id: u32 = @intCast(server_id_value);
        const is_exit = jsonutil.nx_get_bool(message, "exit") orelse false;

        const existing = nx_find(server_id);
        if (is_exit) {
            if (existing) |index| nx_close(&nx_conns[index], false);
            continue;
        }

        const encoded = jsonutil.nx_get_string(message, "data") orelse continue;
        if (encoded.len == 0) continue;
        const data = nx_decode(allocator, encoded) catch continue;

        var index = existing;
        if (index == null) index = nx_alloc(server_id);
        const conn_index = index orelse continue;
        const conn = &nx_conns[conn_index];

        if (!conn.request_parsed) {
            if (conn.pending_req.items.len + data.len > NX_REQUEST_MAX) {
                nx_fail_conn(conn);
                continue;
            }
            conn.pending_req.appendSlice(page_allocator, data) catch {
                nx_fail_conn(conn);
                continue;
            };
            if (nx_parse(conn) > 0 and conn.state == .connected) nx_flush(conn);
        } else {
            nx_append_out(conn, data);
            if (conn.state == .connected) nx_flush(conn);
        }
    }
}
