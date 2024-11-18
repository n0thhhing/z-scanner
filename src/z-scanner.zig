pub const Scanner = @import("./scanner.zig").Scanner;
pub const ScannerOptions = @import("./scanner.zig").ScannerOptions;
pub const Pattern = @import("./pattern.zig").Pattern;
pub const PatternError = @import("./pattern.zig").PatternError;

test {
   _ = @import("./pattern.zig");
   _ = @import("./scanner.zig");
   @import("std").testing.refAllDecls(@import("./pattern.zig"));
   @import("std").testing.refAllDecls(@import("./scanner.zig"));
   @import("std").testing.refAllDecls(@This());
}