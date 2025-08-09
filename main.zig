const std = @import("std");

// Zig 0.11: SHA-256 only
const Algo = enum { sha256 };

const Shared = struct {
    alloc: std.mem.Allocator,
    root: []const u8,                  // current root
    files: []const []const u8,         // relative paths under root
    results: []?[]u8,                  // hex per index (owned; free later)

    // work distribution
    next_idx: usize,
    work_mutex: std.Thread.Mutex,

    // progress
    progress_done: usize,
    progress_total: usize,
    progress_stride: usize,
    progress_mutex: std.Thread.Mutex,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Args: [--json] [--abs] [--threads N] [--exclude PATTERN]... [DIR]...
    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();
    _ = args.next(); // exe

    var output_json = false;
    var print_abs = false;
    var thread_count: usize = 4; // default; user can override

    var excludes = std.ArrayList([]const u8).init(alloc);
    defer { for (excludes.items) |p| alloc.free(p); excludes.deinit(); }

    var roots = std.ArrayList([]const u8).init(alloc);
    defer { for (roots.items) |p| alloc.free(p); roots.deinit(); }

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--json")) {
            output_json = true;
        } else if (std.mem.eql(u8, arg, "--abs")) {
            print_abs = true;
        } else if (std.mem.eql(u8, arg, "--threads")) {
            const n = args.next() orelse return usage("missing value for --threads");
            thread_count = try std.fmt.parseInt(usize, n, 10);
            if (thread_count == 0) thread_count = 1;
        } else if (std.mem.eql(u8, arg, "--exclude")) {
            const pat = args.next() orelse return usage("missing value for --exclude");
            try excludes.append(try dup(alloc, pat));
        } else if (std.mem.startsWith(u8, arg, "-")) {
            return usage("unknown flag");
        } else {
            try roots.append(try dup(alloc, arg)); // positional DIR
        }
    }
    if (roots.items.len == 0) try roots.append(try dup(alloc, ".")); // default

    var stdout = std.io.getStdOut().writer();
    var stderr = std.io.getStdErr().writer();

    if (output_json) try stdout.writeAll("[\n");
    var first_json = true;

    // Process each root independently
    for (roots.items) |root| {
        // 1) Collect files (relative paths)
        var files_list = std.ArrayList([]u8).init(alloc);
        defer { for (files_list.items) |p| alloc.free(p); files_list.deinit(); }

        var stack = std.ArrayList([]u8).init(alloc);
        defer { for (stack.items) |p| alloc.free(p); stack.deinit(); }
        try stack.append(try alloc.alloc(u8, 0)); // "" prefix

        while (stack.popOrNull()) |prefix| {
            defer alloc.free(prefix);

            const dir_fs_path = if (prefix.len == 0) root
                else try std.fs.path.join(alloc, &[_][]const u8{ root, prefix });
            defer if (prefix.len != 0) alloc.free(dir_fs_path);

            var dir = std.fs.cwd().openIterableDir(dir_fs_path, .{}) catch {
                continue; // skip unreadable dirs
            };
            defer dir.close();

            var it = dir.iterate();
            while (it.next() catch continue) |entry| switch (entry.kind) {
                .file => {
                    const rel = if (prefix.len == 0)
                        try dup(alloc, entry.name)
                    else
                        try std.fmt.allocPrint(alloc, "{s}/{s}", .{ prefix, entry.name });

                    if (should_skip(rel, excludes.items)) {
                        alloc.free(rel);
                    } else {
                        try files_list.append(rel);
                    }
                },
                .directory => {
                    const child = if (prefix.len == 0)
                        try dup(alloc, entry.name)
                    else
                        try std.fmt.allocPrint(alloc, "{s}/{s}", .{ prefix, entry.name });

                    if (should_skip(child, excludes.items)) {
                        alloc.free(child);
                    } else {
                        try stack.append(child);
                    }
                },
                else => {},
            };
        }

        // 2) Sort deterministically
        std.mem.sort([]u8, files_list.items, {}, comptime struct {
            fn less(_: void, a: []u8, b: []u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.less);

        const nfiles = files_list.items.len;
        const stride: usize = 200;

        try stderr.print("Hashing '{s}' ({d} files) with {d} thread(s)...\n",
            .{ root, nfiles, if (thread_count > 0) thread_count else 1 });

        // 3) Prepare shared state & spawn workers
        var results = try alloc.alloc(?[]u8, nfiles);
        defer {
            var i_free: usize = 0;
            while (i_free < nfiles) : (i_free += 1) {
                if (results[i_free]) |hex| alloc.free(hex);
            }
            alloc.free(results);
        }

        var file_views = try alloc.alloc([]const u8, nfiles);
        defer alloc.free(file_views);
        for (files_list.items, 0..) |p, i| file_views[i] = p;

        var shared = Shared{
            .alloc = alloc,
            .root = root,
            .files = file_views,
            .results = results,
            .next_idx = 0,
            .work_mutex = .{},
            .progress_done = 0,
            .progress_total = nfiles,
            .progress_stride = stride,
            .progress_mutex = .{},
        };

        const workers = if (thread_count > nfiles) nfiles else thread_count;
        var threads = try alloc.alloc(std.Thread, workers);
        defer alloc.free(threads);

        var w: usize = 0;
        while (w < workers) : (w += 1) {
            threads[w] = try std.Thread.spawn(.{}, workerHash, .{ &shared });
        }

        // 4) Join
        w = 0;
        while (w < workers) : (w += 1) threads[w].join();

        // Print final progress line if needed
        if (shared.progress_total != 0 and shared.progress_done != shared.progress_total) {
            stderr.print("hashed {d}/{d} files...\n", .{ shared.progress_done, shared.progress_total }) catch {};
        }

        // 5) Print results in index order (stable)
        var i: usize = 0;
        while (i < nfiles) : (i += 1) {
            const rel = files_list.items[i];
            const hex = results[i] orelse continue;

            if (output_json) {
                if (!first_json) try stdout.writeAll(",\n");
                first_json = false;

                if (print_abs) {
                    const full = try std.fs.path.join(alloc, &[_][]const u8{ root, rel });
                    defer alloc.free(full);
                    const abs = try toAbsolute(alloc, full);
                    defer alloc.free(abs);
                    try stdout.print("  {{\"path\":\"{s}\",\"hash\":\"{s}\"}}", .{ abs, hex });
                } else {
                    try stdout.print("  {{\"path\":\"{s}\",\"hash\":\"{s}\"}}", .{ rel, hex });
                }
            } else {
                if (print_abs) {
                    const full = try std.fs.path.join(alloc, &[_][]const u8{ root, rel });
                    defer alloc.free(full);
                    const abs = try toAbsolute(alloc, full);
                    defer alloc.free(abs);
                    try stdout.print("{s}  {s}\n", .{ hex, abs });
                } else {
                    try stdout.print("{s}  {s}\n", .{ hex, rel });
                }
            }
        }
    }

    if (output_json) try stdout.writeAll("\n]\n");
}

// ----- CLI help -----

fn usage(msg: []const u8) !void {
    var err = std.io.getStdErr().writer();
    try err.print("Error: {s}\n", .{msg});
    try err.writeAll(
        \\Usage: dirhasher [--json] [--abs] [--threads N] [--exclude PATTERN]... [DIR]...
        \\  --exclude PATTERN   skip files/dirs whose relative path contains PATTERN
        \\  --abs               print absolute paths
        \\  --threads N         number of worker threads (default: 4)
        \\If no DIR is given, current directory is used.
        \\
    );
    return error.Invalid;
}

// ----- Worker & helpers -----

fn workerHash(shared: *Shared) void {
    while (true) {
        const idx = next(shared);
        if (idx == null) break;
        const i = idx.?;

        const rel = shared.files[i];

        const full = std.fs.path.join(shared.alloc, &[_][]const u8{ shared.root, rel }) catch {
            setResult(shared, i, null);
            bumpProgress(shared);
            continue;
        };
        defer shared.alloc.free(full);

        const hex = hashFileSha256(shared.alloc, full) catch {
            setResult(shared, i, null);
            bumpProgress(shared);
            continue;
        };
        setResult(shared, i, hex);
        bumpProgress(shared);
    }
}

fn next(shared: *Shared) ?usize {
    shared.work_mutex.lock();
    defer shared.work_mutex.unlock();
    if (shared.next_idx >= shared.files.len) return null;
    const i = shared.next_idx;
    shared.next_idx += 1;
    return i;
}

fn setResult(shared: *Shared, idx: usize, hex_or_null: ?[]u8) void {
    // Each index written once by exactly one worker → no extra sync needed
    shared.results[idx] = hex_or_null;
}

fn bumpProgress(shared: *Shared) void {
    if (shared.progress_total == 0) return;

    var print_now = false;
    var done_local: usize = 0;

    shared.progress_mutex.lock();
    defer shared.progress_mutex.unlock();

    shared.progress_done += 1;
    done_local = shared.progress_done;

    if (shared.progress_stride != 0) {
        if ((done_local % shared.progress_stride == 0) or (done_local == shared.progress_total)) {
            print_now = true;
        }
    }

    if (print_now) {
        const err = std.io.getStdErr().writer();
        err.print("hashed {d}/{d} files...\n", .{ done_local, shared.progress_total }) catch {};
    }
}

fn should_skip(path: []const u8, excludes: []const []const u8) bool {
    for (excludes) |pat| {
        if (std.mem.indexOf(u8, path, pat) != null) return true; // substring (case-sensitive)
    }
    return false;
}

fn dup(alloc: std.mem.Allocator, s: []const u8) ![]u8 {
    const out = try alloc.alloc(u8, s.len);
    std.mem.copy(u8, out, s);
    return out;
}

fn toAbsolute(alloc: std.mem.Allocator, p: []const u8) ![]u8 {
    var buf: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const abs = try std.fs.realpath(p, &buf);
    return dup(alloc, abs);
}

fn hashFileSha256(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    var file = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
    defer file.close();

    var buf: [64 * 1024]u8 = undefined;
    var sha = std.crypto.hash.sha2.Sha256.init(.{});

    while (true) {
        const n = try file.read(&buf);
        if (n == 0) break;
        sha.update(buf[0..n]);
    }

    var out_sha: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    sha.final(&out_sha);

    var hex = try alloc.alloc(u8, out_sha.len * 2);
    _ = std.fmt.bufPrint(hex, "{s}", .{ std.fmt.fmtSliceHexLower(out_sha[0..]) }) catch unreachable;
    return hex;
}
