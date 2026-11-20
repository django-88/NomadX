const std = @import("std");

fn nx_key(index: usize) u8 {
    return @truncate(0x5A +% index *% 0x1D);
}

/// Compare a runtime string to a compile-time literal without leaving the
/// literal as a contiguous string in the image.  The compiler folds the
/// per-byte XOR into an immediate comparison.
pub fn eq(value: []const u8, comptime plain: []const u8) bool {
    if (value.len != plain.len) return false;
    inline for (plain, 0..) |byte, index| {
        const encoded = byte ^ nx_key(index);
        if (value[index] != (encoded ^ nx_key(index))) return false;
    }
    return true;
}

/// A small zero-terminated, stack-local decrypted string.  The plaintext is
/// not stored in the image; call ptr() before passing it to a Win32 API.
pub const NxZ = struct {
    buffer: [256]u8 = undefined,
    len: usize = 0,

    pub fn ptr(self: *NxZ) [*:0]const u8 {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            self.buffer[index] ^= nx_key(index);
        }
        self.buffer[self.len] = 0;
        return @ptrCast(&self.buffer);
    }

    pub fn slice(self: *NxZ) []const u8 {
        _ = self.ptr();
        return self.buffer[0..self.len];
    }
};

pub fn z(comptime plain: []const u8) NxZ {
    if (plain.len >= 255) @compileError("obfuscated string too long");
    var result = NxZ{ .len = plain.len };
    inline for (plain, 0..) |byte, index| {
        result.buffer[index] = byte ^ nx_key(index);
    }
    return result;
}
