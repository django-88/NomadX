const std = @import("std");
const crypto = @import("crypto.zig");
const jsonutil = @import("jsonutil.zig");
const config = @import("config.zig");

test "base64 round trip" {
    const allocator = std.testing.allocator;
    const input = "NomadX Zig beacon";
    const zero_key: [32]u8 = @splat(0);
    const encoded = try crypto.nx_encrypt_message(
        allocator,
        "00000000-0000-0000-0000-000000000000",
        zero_key,
        input,
        null,
    );
    defer allocator.free(encoded);
    const decoded = try crypto.nx_decrypt_message(
        allocator,
        "00000000-0000-0000-0000-000000000000",
        zero_key,
        encoded,
    );
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(input, decoded);
}

test "aes-cbc hmac round trip" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x42);
    const iv: [16]u8 = @splat(0x11);
    const input = "{\"action\":\"get_tasking\",\"tasking_size\":-1}";
    const encoded = try crypto.nx_encrypt_message(
        allocator,
        "00000000-0000-0000-0000-000000000000",
        key,
        input,
        iv,
    );
    defer allocator.free(encoded);
    const decoded = try crypto.nx_decrypt_message(
        allocator,
        "00000000-0000-0000-0000-000000000000",
        key,
        encoded,
    );
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(input, decoded);
}

test "json object and array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var obj = jsonutil.nx_init_object();
    try jsonutil.nx_put_string(allocator, &obj, "action", "checkin");
    try jsonutil.nx_put_integer(allocator, &obj, "pid", 123);
    var list = jsonutil.nx_init_array(allocator);
    try list.append(.{ .string = try allocator.dupe(u8, "127.0.0.1") });
    try jsonutil.nx_put_array(allocator, &obj, "ips", list);
    const text = try jsonutil.nx_stringify(allocator, .{ .object = obj });
    defer allocator.free(text);
    var parsed = try jsonutil.nx_parse(allocator, text);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("checkin", jsonutil.nx_get_string(parsed.value, "action").?);
}

test "Mythic AES-CBC/HMAC wire vector" {
    const allocator = std.testing.allocator;
    const key: [32]u8 = @splat(0x42);
    const iv: [16]u8 = @splat(0x11);
    const uuid = "00000000-0000-0000-0000-000000000000";
    const input = "{\"action\":\"get_tasking\",\"tasking_size\":-1}";
    const expected = "MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAwEREREREREREREREREREREQya1hlqwTaFNEePPy630JndAcEgMmZmc6a5QkIysLbMxceeYArz3mxRp3vhuvbxKlWf1YE7CXC3G8QtW37/Lpmah7Qp8Upkxzw/9sibw3WH";

    const encoded = try crypto.nx_encrypt_message(allocator, uuid, key, input, iv);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(expected, encoded);

    const decoded = try crypto.nx_decrypt_message(allocator, uuid, key, expected);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(input, decoded);
}

test "Mythic zero-key wire vector" {
    const allocator = std.testing.allocator;
    const zero_key: [32]u8 = @splat(0);
    const uuid = "00000000-0000-0000-0000-000000000000";
    const input = "{\"action\":\"get_tasking\",\"tasking_size\":-1}";
    const expected = "MDAwMDAwMDAtMDAwMC0wMDAwLTAwMDAtMDAwMDAwMDAwMDAweyJhY3Rpb24iOiJnZXRfdGFza2luZyIsInRhc2tpbmdfc2l6ZSI6LTF9";

    const encoded = try crypto.nx_encrypt_message(allocator, uuid, zero_key, input, null);
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings(expected, encoded);

    const decoded = try crypto.nx_decrypt_message(allocator, uuid, zero_key, expected);
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings(input, decoded);
}

test "embedded config loads" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const cfg = try config.nx_load(arena.allocator());
    try std.testing.expectEqual(@as(usize, 36), cfg.uuid.len);
    try std.testing.expectEqual(@as(u16, 443), cfg.callback_port);
    try std.testing.expectEqual(@as(usize, 64), cfg.aes_key_hex.len);
    try std.testing.expect(cfg.tls_verify);
}
