const std = @import("std");
const splitAny = std.mem.splitAny;
const eql = std.mem.eql;
const Allocator = std.mem.Allocator;
const testing = std.testing;

pub const PatternError = error{ InvalidLength, InvalidHex, InvalidPattern };

pub const Pattern = struct {
    bytes: []const u8,
    mask: []const u8,
    allocator: Allocator,

    pub fn init(allocator: Allocator, pattern: []const u8) !Pattern {
        if (eql(u8, pattern, ""))
            return PatternError.InvalidLength;
        var bytes = std.ArrayList(u8).init(allocator);
        var mask = std.ArrayList(u8).init(allocator);
        errdefer bytes.deinit();
        errdefer mask.deinit();
        var str_bytes = splitAny(u8, pattern, " ");
        while (str_bytes.next()) |byte_str| {
            if (byte_str.len != 2)
                return PatternError.InvalidPattern;
            if (eql(u8, byte_str, "??")) {
                try bytes.append(0);
                try mask.append(0xff);
            } else {
                const byte = std.fmt.parseInt(u8, byte_str, 16) catch return PatternError.InvalidHex;
                try bytes.append(byte);
                try mask.append(0);
            }
        }

        return .{
            .bytes = try bytes.toOwnedSlice(),
            .mask = try mask.toOwnedSlice(),
            .allocator = allocator,
        };
    }

    pub inline fn deinit(self: *Pattern) void {
        self.allocator.free(self.bytes);
        self.allocator.free(self.mask);
        self.* = undefined;
    }
};

test "Pattern with hex bytes" {
    const allocator = testing.allocator;
    const pattern_str = "01 23 45 67 89 ab ?? cd ef";
    var pattern = try Pattern.init(allocator, pattern_str);
    defer pattern.deinit();
    const expected_bytes = &[_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x00, 0xcd, 0xef };
    const expected_mask = &[_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00 };

    try testing.expectEqualSlices(u8, expected_bytes, pattern.bytes);
    try testing.expectEqualSlices(u8, expected_mask, pattern.mask);
}

test "Pattern with only wildcards" {
    const allocator = testing.allocator;
    const pattern_str = "?? ?? ?? ?? ?? ?? ?? ?? ?? af";
    var pattern = try Pattern.init(allocator, pattern_str);
    defer pattern.deinit();
    const expected_bytes = &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xaf };
    const expected_mask = &[_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0 };

    try testing.expectEqualSlices(u8, expected_bytes, pattern.bytes);
    try testing.expectEqualSlices(u8, expected_mask, pattern.mask);
}

test "Pattern with empty input" {
    const allocator = testing.allocator;
    const pattern_str = "";
    try testing.expectError(PatternError.InvalidLength, Pattern.init(allocator, pattern_str));
}

test "Pattern with invalid hex" {
    const allocator = testing.allocator;
    const pattern_str = "01 23 zz 45";

    try testing.expectError(PatternError.InvalidHex, Pattern.init(allocator, pattern_str));
}

test "Pattern with invalid input" {
    const allocator = testing.allocator;
    const pattern_str = "01 23 aaa 45";

    const pattern = Pattern.init(allocator, pattern_str);

    try testing.expectError(PatternError.InvalidPattern, pattern);
}

test "Pattern with no wildcards" {
    const allocator = testing.allocator;
    const pattern_str = "01 02 03 04";
    var pattern = try Pattern.init(allocator, pattern_str);
    defer pattern.deinit();
    const expected_bytes = &[_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const expected_mask = &[_]u8{ 0, 0, 0, 0 };

    try testing.expectEqualSlices(u8, expected_bytes, pattern.bytes);
    try testing.expectEqualSlices(u8, expected_mask, pattern.mask);
}
