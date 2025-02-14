# dotenv_zig
Load ENV vars from `.env` file 

- Support for both `comptime` and `runtime` file parsing
- Support for unquoting and unescaping quotes, escaped strings

## Install

Just copy paste `src/dotenv.zig`

## Usage

- You can use `parsed.get("<key>")` which returns value as `?[]const u8`


#### Here are examples to parse and print all key value pairs

comptime example
```zig
const std = @import("std");
const dotenv = @import("dotenv.zig");

// This is embedded into the executable itself, no .env needed at runtime
const parsed = dotenv.loadEnvComptime(".env", .{});

pub fn main() !void {
  // Print all the values in the map
  for (0..parsed.kvs.len) |i| {
    std.debug.print("{s}={s}\n", .{ parsed.kvs.keys[i], parsed.kvs.values[i] });
  }
}
```

runtime example
```zig
const std = @import("std");
const dotenv = @import("dotenv.zig");

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  const allocator = gpa.allocator();
  defer if(gpa.deinit() != .ok) std.debug.panic("Memory leak\n", .{});

  // Parse env file at runtime
  var parsed = try dotenv.loadEnvRuntime(".env", allocator, .{});
  defer parsed.deinit();

  // Print all the values in the map
  var iter = parsed.map.iterator();
  while (iter.next()) |kvp| {
    std.debug.print("{s}={s}\n", .{ kvp.key_ptr.*, kvp.value_ptr.* });
  }
}
```
