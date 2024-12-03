const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const Pattern = @import("./pattern.zig").Pattern;
const PatternError = @import("./pattern.zig").PatternError;

pub const ScannerOptions = struct {
    from: usize = 0,
    to: ?usize = null,
    first_index: bool = false,
    last_index: bool = false,
    callback: ?*const fn (matches: ?[]usize, buf: *const []const u8) void = null,
};

pub fn Scanner(comptime options: ScannerOptions) type {
    return struct {
        const Self = @This();
        allocator: Allocator,

        pub inline fn init(allocator: Allocator) Self {
            return Self{ .allocator = allocator };
        }

        pub inline fn free(self: Self, matches: anytype) void {
            switch (@TypeOf(matches)) {
                []?[]usize => {
                    for (matches) |match| self.allocator.free(match orelse continue);
                    self.allocator.free(matches);
                },
                ?[]usize => self.allocator.free(matches orelse return),
                inline else => @compileError("Invalid Type passed into Scanner.free()"),
            }
        }

        pub fn scanAll(self: Self, buf: []const u8, patterns: []const []const u8) ![]?[]usize {
            var matches = try self.allocator.alloc(?[]usize, patterns.len);
            errdefer self.allocator.free(matches);

            for (patterns, 0..) |pattern, i| {
                var pattern_bytes = try Pattern.init(self.allocator, pattern);
                defer pattern_bytes.deinit();
                const match = try self.kpmScan(buf, pattern_bytes);
                matches[i] = match;
                if (options.callback) |cb| cb(match, &buf);
            }
            return matches;
        }

        pub fn scan(self: Self, buf: []const u8, pattern: []const u8) !?[]usize {
            var pattern_bytes = try Pattern.init(self.allocator, pattern);
            defer pattern_bytes.deinit();
            return try self.kpmScan(buf, pattern_bytes);
        }

        // TODO: Can this be Vectorized?
        pub fn kpmScan(self: Self, buf: []const u8, pattern: Pattern) !?[]usize {
            const pattern_len = pattern.bytes.len;
            const buf_len = options.to orelse buf.len;
            var matches = ArrayList(usize).init(self.allocator);
            errdefer matches.deinit();

            var lps = try self.allocator.alloc(usize, pattern_len);
            defer self.allocator.free(lps);

            self.computePrefixTable(pattern, &lps);

            var i: usize = options.from; // buffer index
            var j: usize = 0; // pattern index
            var last_index: ?usize = null;

            while (i < buf_len) {
                if (buf[i] == pattern.bytes[j] or pattern.mask[j] == 0xff) {
                    i += 1;
                    j += 1;

                    if (j == pattern_len) {
                        if (!options.last_index) {
                            try matches.append(i - j);
                        } else {
                            last_index = i - j;
                        }
                        if (options.first_index) return try matches.toOwnedSlice();
                        j = lps[j - 1];
                    }
                } else if (j > 0) {
                    // KMP fallback to previous valid position
                    j = lps[j - 1];
                } else {
                    i += 1;
                }
            }

            if (options.last_index and last_index != null) try matches.append(last_index orelse unreachable);

            const slice = try matches.toOwnedSlice();
            if (slice.len == 0) {
                self.allocator.free(slice);
                return null;
            }
            return slice;
        }

        pub fn computePrefixTable(_: Self, pattern: Pattern, lps: *[]usize) void {
            const pattern_len = pattern.bytes.len;
            @memset(lps.*, 0);

            var j: usize = 0; // length of the longest prefix that is also a suffix for the preceding index
            var i: usize = 1; // pattern index

            while (i < pattern_len) {
                if (pattern.bytes[i] == pattern.bytes[j] or pattern.mask[j] == 0xff) {
                    j += 1;
                    lps.*[i] = j;
                    i += 1;
                } else {
                    j = if (j > 0) lps.*[j - 1] else 0;
                    if (j == 0) i += 1;
                }
            }
        }
    };
}

inline fn tupleToArray(comptime T: type, tuple: anytype) ![]T {
    const fields = @typeInfo(@TypeOf(tuple)).Struct.fields;
    var array = ArrayList(T).init(testing.allocator);
    inline for (fields) |field| {
        try array.append(@field(tuple, field.name));
    }
    return array.toOwnedSlice();
}

inline fn testScan(buf: []const u8, pattern: []const u8, comptime options: ScannerOptions, expected: ?[]const usize) !void {
    const allocator = testing.allocator;
    const scanner = Scanner(options).init(allocator);
    const actual = try scanner.scan(buf, pattern);
    defer if (actual != null) allocator.free(actual.?);
    if (expected == null)
        return try testing.expect(actual == null);
    try testing.expectEqualSlices(usize, expected orelse return testing.expect(false), actual orelse return testing.expect(false));
}

test "Scan pattern in buffer" {
    const pattern = "ab aa ?? ba";
    const buf = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0xab, 0xaa, 0x00, 0xba, 0x01, 0x02, 0x03 };
    const expected = &[_]usize{4};
    try testScan(buf, pattern, .{}, expected[0..]);
}

test "Scan with first_index option" {
    const pattern = "aa ?? ab";
    const buf = &[_]u8{ 0x01, 0x02, 0xaa, 0x00, 0xab, 0xaa, 0x00, 0xab };
    const options = ScannerOptions{ .first_index = true };
    const expected = &[_]usize{2};
    try testScan(buf, pattern, options, expected);
}

test "Scan with last_index option" {
    const pattern = "aa ?? ab";
    const buf = &[_]u8{ 0x01, 0x02, 0xaa, 0x00, 0xab, 0xaa, 0x00, 0xab };
    const options = ScannerOptions{ .last_index = true };
    const expected = &[_]usize{5};
    try testScan(buf, pattern, options, expected);
}

test "Scan pattern with no matches" {
    const pattern = "ab 12 ?? cd";
    const buf = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    try testScan(buf, pattern, .{}, null);
}

test "KMP LPS table computation" {
    const allocator = testing.allocator;
    const pattern_str = "ab ?? ab";
    var pattern = try Pattern.init(allocator, pattern_str);
    defer pattern.deinit();

    const scanner = Scanner(.{}).init(allocator);

    var lps_table = try allocator.alloc(usize, pattern.bytes.len);
    defer allocator.free(lps_table);
    scanner.computePrefixTable(pattern, &lps_table);

    const expected_lps_table = &[_]usize{ 0, 0, 1 };
    try testing.expectEqualSlices(usize, expected_lps_table, lps_table[0..pattern.bytes.len]);
}

test "Scan with empty buffer" {
    const pattern = "ab 01 ?? 23";
    const buf = &[_]u8{};
    try testScan(buf, pattern, .{}, null);
}

test "Scan with empty pattern" {
    const allocator = testing.allocator;
    const pattern_str = "";
    const buf = &[_]u8{ 0x01, 0x02, 0x03 };
    const scanner = Scanner(.{}).init(allocator);

    try testing.expectError(PatternError.InvalidLength, scanner.scan(buf, pattern_str));
}

test "Invalid pattern" {
    const allocator = testing.allocator;
    const pattern_str = "zz xx ?? ab"; // Invalid pattern with non-hex characters
    const scanner = Scanner(.{}).init(allocator);
    try testing.expectError(PatternError.InvalidHex, scanner.scan(&[_]u8{}, pattern_str));
}

test "binary" {
    const allocator = testing.allocator;
    const cwd = std.fs.cwd();

    var dir = try cwd.openDir("testFiles", .{});
    defer dir.close();
    const file = try dir.openFile("add", .{});
    defer file.close();

    const file_size = try file.getEndPos();
    var buf = try allocator.alloc(u8, file_size);
    defer allocator.free(buf);
    const scanner = Scanner(.{}).init(allocator);

    const bytes_read = try file.read(buf);

    const pattern = "50 00 01 00 00 00 00 00 80 07 00 00 00 00 00 00 1B 00 00 00 38 00 00 00 08 00 00 00 00 00 00 00 18 00 00 00 00 00 00 00 09 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D0 07 ?? ?? 00 00 00 00 8E 01 00 00 00 00 ?? ??"; //"50 00 01 00 00 00 00 00 80 07 00 00 00 00 00 00 1B 00 00 00 ?? 08 00 00 00 00 00 00 00 18 00 00 ?? ?? ?? ?? 00 09 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 D0 07 01 00 00 00 00 00 8E 01 ?? ?? ?? ?? 00 00";
    const expected_matches = &[_]usize{0x11100};

    const occurrences = try scanner.scan(buf[0..bytes_read], pattern);
    defer allocator.free(occurrences.?);
    try testing.expectEqualSlices(usize, expected_matches, occurrences.?);
}

test "scanAll" {
    const allocator = testing.allocator;
    const patterns = [_][]const u8{ "ab aa ?? ba", "?? 01 02 03" };
    const buf = &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0xab, 0xaa, 0x00, 0xba, 0x01, 0x02, 0x03 };

    const scanner = Scanner(.{}).init(allocator);

    const all_occurrences = try scanner.scanAll(buf, patterns[0..]);
    defer scanner.free(all_occurrences);

    const expected: []?[]usize = try tupleToArray(?[]usize, .{
        try tupleToArray(usize, .{4}),
        try tupleToArray(usize, .{7}),
    });

    defer scanner.free(expected);
    //try testing.expectEqualSlices(?[]usize, expected, all_occurrences); // for some reson this fails?
    try testing.expect(expected.len == all_occurrences.len);
    for (0..expected.len) |i| {
        try testing.expect(expected[i].?.len == all_occurrences[i].?.len);
        for (0..expected[i].?.len) |j| {
            try testing.expect(expected[i].?[j] == all_occurrences[i].?[j]);
        }
    }
}
