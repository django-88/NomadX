const std = @import("std");

pub const NxValue = std.json.Value;
pub const NxObject = std.json.ObjectMap;
pub const NxArray = std.json.Array;

pub fn nx_init_object() NxObject {
    return .empty;
}

pub fn nx_init_array(allocator: std.mem.Allocator) NxArray {
    return NxArray.init(allocator);
}

pub fn nx_put_string(allocator: std.mem.Allocator, obj: *NxObject, key: []const u8, value: []const u8) !void {
    try obj.put(
        allocator,
        try allocator.dupe(u8, key),
        .{ .string = try allocator.dupe(u8, value) },
    );
}

pub fn nx_put_integer(allocator: std.mem.Allocator, obj: *NxObject, key: []const u8, value: i64) !void {
    try obj.put(
        allocator,
        try allocator.dupe(u8, key),
        .{ .integer = value },
    );
}

pub fn nx_put_bool(allocator: std.mem.Allocator, obj: *NxObject, key: []const u8, value: bool) !void {
    try obj.put(
        allocator,
        try allocator.dupe(u8, key),
        .{ .bool = value },
    );
}

pub fn nx_put_array(allocator: std.mem.Allocator, obj: *NxObject, key: []const u8, value: NxArray) !void {
    try obj.put(
        allocator,
        try allocator.dupe(u8, key),
        .{ .array = value },
    );
}

pub fn nx_put_object(allocator: std.mem.Allocator, obj: *NxObject, key: []const u8, value: NxObject) !void {
    try obj.put(
        allocator,
        try allocator.dupe(u8, key),
        .{ .object = value },
    );
}

pub fn nx_stringify(allocator: std.mem.Allocator, value: NxValue) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

pub fn nx_parse(allocator: std.mem.Allocator, text: []const u8) !std.json.Parsed(NxValue) {
    return std.json.parseFromSlice(NxValue, allocator, text, .{});
}

pub fn nx_get_string(value: NxValue, key: []const u8) ?[]const u8 {
    if (value != .object) return null;
    const item = value.object.get(key) orelse return null;
    return switch (item) {
        .string => |s| s,
        else => null,
    };
}

pub fn nx_get_integer(value: NxValue, key: []const u8) ?i64 {
    if (value != .object) return null;
    const item = value.object.get(key) orelse return null;
    return switch (item) {
        .integer => |n| n,
        else => null,
    };
}

pub fn nx_get_bool(value: NxValue, key: []const u8) ?bool {
    if (value != .object) return null;
    const item = value.object.get(key) orelse return null;
    return switch (item) {
        .bool => |b| b,
        else => null,
    };
}

pub fn nx_get_object(value: NxValue, key: []const u8) ?NxValue {
    if (value != .object) return null;
    return value.object.get(key);
}

pub fn nx_get_array(value: NxValue, key: []const u8) ?[]const NxValue {
    if (value != .object) return null;
    const item = value.object.get(key) orelse return null;
    return switch (item) {
        .array => |a| a.items,
        else => null,
    };
}
