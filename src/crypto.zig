const std = @import("std");
const builtin = @import("builtin");
const win32 = @import("win32.zig");

const Aes256 = std.crypto.core.aes.Aes256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const base64 = std.base64.standard;

pub const NX_KEY_LEN = 32;
pub const NX_IV_LEN = 16;
pub const NX_MAC_LEN = 32;

pub fn nx_parse_hex_key(text: []const u8) ![NX_KEY_LEN]u8 {
    if (text.len != NX_KEY_LEN * 2) return error.InvalidKey;
    var key: [NX_KEY_LEN]u8 = undefined;
    _ = std.fmt.hexToBytes(&key, text) catch return error.InvalidKey;
    return key;
}

pub fn nx_key_is_zero(key: [NX_KEY_LEN]u8) bool {
    for (key) |b| {
        if (b != 0) return false;
    }
    return true;
}

fn nx_random_bytes(buf: []u8) void {
    if (builtin.os.tag == .windows) {
        win32.nx_random_bytes(buf);
    } else {
        @memset(buf, 0);
    }
}

fn nx_pad_length(plain_len: usize) usize {
    return ((plain_len / 16) + 1) * 16;
}

fn nx_aes_cbc_encrypt(key: [NX_KEY_LEN]u8, iv: [NX_IV_LEN]u8, plaintext: []const u8, out: []u8) void {
    var ctx = Aes256.initEnc(key);
    var prev = iv;
    var offset: usize = 0;
    while (offset < plaintext.len) : (offset += 16) {
        var block: [16]u8 = undefined;
        for (0..16) |i| {
            block[i] = plaintext[offset + i] ^ prev[i];
        }
        var encrypted: [16]u8 = undefined;
        ctx.encrypt(&encrypted, &block);
        @memcpy(out[offset .. offset + 16], &encrypted);
        prev = encrypted;
    }
}

fn nx_aes_cbc_decrypt(key: [NX_KEY_LEN]u8, iv: [NX_IV_LEN]u8, ciphertext: []const u8, out: []u8) void {
    var ctx = Aes256.initDec(key);
    var prev = iv;
    var offset: usize = 0;
    while (offset < ciphertext.len) : (offset += 16) {
        var block: [16]u8 = undefined;
        @memcpy(&block, ciphertext[offset .. offset + 16]);
        var decrypted: [16]u8 = undefined;
        ctx.decrypt(&decrypted, &block);
        for (0..16) |i| {
            out[offset + i] = decrypted[i] ^ prev[i];
        }
        prev = block;
    }
}

fn nx_hmac(key: [NX_KEY_LEN]u8, parts: []const []const u8) [NX_MAC_LEN]u8 {
    var mac: [NX_MAC_LEN]u8 = undefined;
    var ctx = HmacSha256.init(&key);
    for (parts) |part| ctx.update(part);
    ctx.final(&mac);
    return mac;
}

/// Mythic envelope: base64(UUID + AES-CBC-PKCS7(JSON) + HMAC-SHA256(IV + ciphertext)).
/// With an all-zero key, the envelope is base64(UUID + JSON) and no MAC is added.
pub fn nx_encrypt_message(
    allocator: std.mem.Allocator,
    uuid: []const u8,
    key: [NX_KEY_LEN]u8,
    json: []const u8,
    iv_override: ?[NX_IV_LEN]u8,
) ![]u8 {
    if (nx_key_is_zero(key)) {
        const payload = try allocator.alloc(u8, uuid.len + json.len);
        defer allocator.free(payload);
        @memcpy(payload[0..uuid.len], uuid);
        @memcpy(payload[uuid.len..], json);
        const encoded_len = base64.Encoder.calcSize(payload.len);
        const encoded = try allocator.alloc(u8, encoded_len);
        _ = base64.Encoder.encode(encoded, payload);
        return encoded;
    }

    var iv: [NX_IV_LEN]u8 = undefined;
    if (iv_override) |fixed| {
        iv = fixed;
    } else {
        nx_random_bytes(&iv);
    }

    const padded_len = nx_pad_length(json.len);
    const padded = try allocator.alloc(u8, padded_len);
    defer allocator.free(padded);
    @memcpy(padded[0..json.len], json);
    const pad_value: u8 = @intCast(padded_len - json.len);
    @memset(padded[json.len..], pad_value);

    const ciphertext = try allocator.alloc(u8, padded_len);
    defer allocator.free(ciphertext);
    nx_aes_cbc_encrypt(key, iv, padded, ciphertext);

    const iv_ct = try allocator.alloc(u8, NX_IV_LEN + ciphertext.len);
    defer allocator.free(iv_ct);
    @memcpy(iv_ct[0..NX_IV_LEN], &iv);
    @memcpy(iv_ct[NX_IV_LEN..], ciphertext);
    const mac = nx_hmac(key, &.{iv_ct});

    const payload = try allocator.alloc(u8, uuid.len + NX_IV_LEN + ciphertext.len + NX_MAC_LEN);
    defer allocator.free(payload);
    var offset: usize = 0;
    @memcpy(payload[offset .. offset + uuid.len], uuid);
    offset += uuid.len;
    @memcpy(payload[offset .. offset + NX_IV_LEN], &iv);
    offset += NX_IV_LEN;
    @memcpy(payload[offset .. offset + ciphertext.len], ciphertext);
    offset += ciphertext.len;
    @memcpy(payload[offset .. offset + NX_MAC_LEN], &mac);

    const encoded_len = base64.Encoder.calcSize(payload.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = base64.Encoder.encode(encoded, payload);
    return encoded;
}

fn nx_strip_whitespace(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (text) |c| {
        switch (c) {
            ' ', '\t', '\r', '\n' => continue,
            else => try out.append(allocator, c),
        }
    }
    return out.toOwnedSlice(allocator);
}

pub fn nx_decrypt_message(
    allocator: std.mem.Allocator,
    uuid: []const u8,
    key: [NX_KEY_LEN]u8,
    encoded: []const u8,
) ![]u8 {
    const cleaned = try nx_strip_whitespace(allocator, encoded);
    defer allocator.free(cleaned);
    const raw_len = try base64.Decoder.calcSizeForSlice(cleaned);
    const raw = try allocator.alloc(u8, raw_len);
    defer allocator.free(raw);
    try base64.Decoder.decode(raw, cleaned);

    if (raw.len < uuid.len) return error.InvalidEnvelope;
    if (nx_key_is_zero(key)) {
        if (raw.len < uuid.len) return error.InvalidEnvelope;
        return allocator.dupe(u8, raw[uuid.len..]);
    }

    if (raw.len < uuid.len + NX_IV_LEN + NX_MAC_LEN + 16) return error.InvalidEnvelope;
    const iv_start = uuid.len;
    const ct_start = iv_start + NX_IV_LEN;
    const ct_len = raw.len - ct_start - NX_MAC_LEN;
    if (ct_len == 0 or ct_len % 16 != 0) return error.InvalidEnvelope;
    const mac_start = ct_start + ct_len;

    const iv: [NX_IV_LEN]u8 = raw[iv_start..ct_start][0..NX_IV_LEN].*;
    const ciphertext = raw[ct_start..mac_start];
    const received_mac: [NX_MAC_LEN]u8 = raw[mac_start..][0..NX_MAC_LEN].*;
    const expected_mac = nx_hmac(key, &.{raw[iv_start..mac_start]});
    if (!std.crypto.timing_safe.eql([NX_MAC_LEN]u8, received_mac, expected_mac))
        return error.InvalidMac;

    const plaintext = try allocator.alloc(u8, ct_len);
    defer allocator.free(plaintext);
    nx_aes_cbc_decrypt(key, iv, ciphertext, plaintext);

    const pad_value = plaintext[plaintext.len - 1];
    if (pad_value == 0 or pad_value > 16) return error.InvalidPadding;
    if (plaintext.len < pad_value) return error.InvalidPadding;
    for (plaintext[plaintext.len - pad_value ..]) |b| {
        if (b != pad_value) return error.InvalidPadding;
    }

    const result_len = plaintext.len - pad_value;
    const result = try allocator.alloc(u8, result_len);
    @memcpy(result, plaintext[0..result_len]);
    return result;
}
