# dotenv_zig
Load ENV vars from `.env` file 

This library provides functions for loading environment variables from `.env` files at both compile time and runtime. It supports unquoting and unescaping of string values and offers flexible options for whitespace handling.

## Installation

```bash
zig fetch --save git+https://github.com/ItsMeSamey/dotenv_zig#main
```

Then, add it to your `build.zig`:

```zig
const dotenv = b.dependency("dotenv", .{});
exe.root_module.addImport("dotenv", dotenv.module("dotenv"));
```

## 🚨🚨 Microlibrary 🚨🚨

This is a microlibrary. The code is mostly straightforward. Consider simply copying `dotenv.zig` directly into your project instead of adding a dependency. It's only about 250 lines of code (including tests). The choice is yours.

## Usage

### Compile-time Usage

```zig
const std = @import("std");
const dotenv = @import("dotenv");

// Load and parse the .env file at compile time.
const parsed = dotenv.loadEnvComptime(".env", .{});

pub fn main() !void {
  // Access individual values.
  if (parsed.get("MY_VARIABLE")) |value| {
    std.debug.print("MY_VARIABLE: {s}\n", .{value});
  }
}
```

### Runtime Usage

```zig
const std = @import("std");
const dotenv = @import("dotenv");

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  const allocator = gpa.allocator();
  defer gpa.deinit();

  // Load and parse the .env file at runtime.
  var env = try dotenv.loadEnvRuntime(".env", allocator, .{});
  defer env.deinit();

  // Access individual values.
  if (env.get("MY_VARIABLE")) |value| {
    std.debug.print("MY_VARIABLE: {s}\n", .{value});
  }

  // Example of setting/overriding a value:
  try env.put("NEW_VAR", "new_value");
}
```

### Iterating over environment variables (Compile-time)

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

### Iterating over environment variables (Runtime)

```zig
const std = @import("std");
const dotenv = @import("dotenv");

pub fn main() !void {
  var gpa = std.heap.GeneralPurposeAllocator(.{}){};
  const allocator = gpa.allocator();
  defer gpa.deinit();

  var env = try dotenv.loadEnvRuntime(".env", allocator, .{});
  defer env.deinit();

  var iter = env.map.iterator();
  while (iter.next()) |kvp| {
    std.debug.print("{s}={s}\n", .{ kvp.key_ptr.*, kvp.value_ptr.* });
  }
}
```

### Unescaping and Unquoting

The `UnescapeStringOptions` struct provides fine-grained control over how quoted strings are processed. You can specify whether quotes should be removed, and how whitespace should be handled.

### Error Handling

Runtime functions return errors that must be handled. Compile-time errors will cause compilation to fail.

### Example `.env` File

```
MY_VARIABLE="my value"
123 = 'Yes 123 can be a key too'
# This is a comment
ABCD = `backticks are also allowed`
MY_NAME = firstname middlename lastname
```

## How it Works

The comptime function parses and embeds the variables into the binary itself

The runtime loading functions read the specified `.env` file and parse each line. Lines beginning with `#` are treated as comments and ignored.  Lines containing an `=` character are split at the first occurrence of `=`, creating a key-value pair. This key-value pair is then added to the environment map. The library uses `std.process.EnvMap`. This allows for efficient lookups and modifications.


