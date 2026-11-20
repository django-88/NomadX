const std = @import("std");
const agent = @import("agent.zig");

pub export fn wWinMain(
    instance: std.os.windows.HINSTANCE,
    previous: ?std.os.windows.HINSTANCE,
    command_line: std.os.windows.LPWSTR,
    show: c_int,
) callconv(.winapi) c_int {
    _ = instance;
    _ = previous;
    _ = command_line;
    _ = show;
    agent.nx_run() catch {};
    return 0;
}
