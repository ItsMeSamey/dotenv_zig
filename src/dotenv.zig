//! These functions can be used to load env files at runtime or comptime.

const std = @import("std");

pub const UnescapeStringOptions = struct {
  /// Which logging function to use when priniting errors
  log_fn: fn (comptime format: []const u8, args: anytype) void = struct {
    fn log_fn(comptime format: []const u8, args: anytype) void {
      if (@inComptime()) {
        @compileError(std.fmt.comptimePrint(format, args));
      } else {
        std.log.err(format, args);
      }
    }
  }.log_fn,

  /// Whether or not to unescape and unquoted the quoted strings
  unquote_values: bool = true,

  /// Whether or not to trim whitespace,
  /// if this is `.yes`, whitespace outside of quotes will always be trimmed
  /// if this is `.quoted`, whitespace will be trimmed only if the string is quoted, (this works even if unquoting strings is disabled)
  /// if this is `.unquoted`, whitespace will be trimmed only if the string is unquoted (this works even if unquoting strings is disabled)
  /// if this is `.no`, whitespace will never be trimmed, if the string is quoted, it will be appended to start and end after unescaping
  trim_whitespace: enum {no, quoted, unquoted, yes} = .yes,

  /// Whether or not to trim whitespace after unescaping the string
  trim_whitespace_inside_quotes: bool = true
};

/// Function used to unescape quoted string and trim any whitespace
pub fn unescapeString(result: []u8, input: []const u8, comptime options: UnescapeStringOptions) ![]const u8 {
  const val = std.mem.trim(u8, input, " \t");
  if (val.len == 0 or (val[0] != '"' and val[0] != '\'' and val[0] != '`')) return switch (options.trim_whitespace) {
    .no, .quoted => input,
    .unquoted, .yes => val,
  };

  if (!options.unquote_values) return switch (options.trim_whitespace) {
    .no, .unquoted => input,
    .quoted, .yes => val,
  };

  // String must start and end with same kind of quotes
  if (val[0] != val[val.len - 1]) {
    options.log_fn("Invalid string --> {s} <--. if it starts with a quote, it must end with the same kind of quote too", .{val});
    return error.InvalidString;
  }

  var stripped_val = if (options.trim_whitespace_inside_quotes) std.mem.trim(u8, val[1..val.len - 1], " \t") else val[1..val.len - 1];

  switch (val[0]) {
    inline '"', '\'', '`' => |escape_char| {
      var idx: usize = 0;
      var result_idx: usize = 0;
      if (options.trim_whitespace == .no or options.trim_whitespace == .unquoted) {
        while (input[result_idx] != escape_char) {
          result[result_idx] = input[result_idx];
          result_idx += 1;
        }
      }
      while (idx < stripped_val.len - 1) {
        if (stripped_val[idx] == escape_char) {
          options.log_fn("Invalid escape sequence {s} in --> {s} <--", .{ stripped_val[idx .. idx + 1], val });
          return error.InvalidString;
        } else if (stripped_val[idx] == '\\') {
          switch (stripped_val[idx + 1]) {
            'n' => result[result_idx] = '\n',
            'r' => result[result_idx] = '\r',
            't' => result[result_idx] = '\t',
            '\\' => result[result_idx] = '\\',
            escape_char => result[result_idx] = escape_char,
            else => {
              options.log_fn("Unexpected escape sequence {s} in --> {s} <--", .{ stripped_val[idx .. idx + 1], val });
              return error.InvalidEscapeSequence;
            },
          }
          idx += 2;
        } else {
          result[result_idx] = stripped_val[idx];
          idx += 1;
        }
        result_idx += 1;
      }

      if (idx == stripped_val.len - 1) {
        if (stripped_val[idx] == '\\' or stripped_val[idx] == escape_char) {
          options.log_fn("Invalid terminal character {s} in --> {s} <--, string cant end with {s}", .{ stripped_val[idx .. idx + 1], val, if (stripped_val[idx] == '\\') "a \\ (backslash)" else "a the quote (" ++ [_]u8{escape_char} ++ ")" });
          return error.InvalidString;
        }
        result[result_idx] = stripped_val[idx];
        result_idx += 1;
      }

      if (options.trim_whitespace == .no or options.trim_whitespace == .unquoted) {
        var input_idx: usize = input.len - 1;
        while (input[input_idx] != escape_char) {
          result[result_idx] = input[input_idx];
          input_idx -= 1;
          result_idx += 1;
        }
      }
      return result[0..result_idx];
    },
    else => unreachable,
  }
  unreachable;
}

test unescapeString {
  var buffer: [100]u8 = undefined;

  for ([_][2][]const u8{
    .{"a", " a "},
    .{"a", " `a` "},
    .{"a", "` a `"},
    .{"a", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .yes,
      .trim_whitespace_inside_quotes = true,
    }));
  }
  for ([_][2][]const u8{
    .{"a", " a "},
    .{"a", " `a` "},
    .{" a ", "` a `"},
    .{" a ", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .yes,
      .trim_whitespace_inside_quotes = false,
    }));
  }

  for ([_][2][]const u8{
    .{" a ", " a "},
    .{"a", " `a` "},
    .{"a", "` a `"},
    .{"a", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .quoted,
      .trim_whitespace_inside_quotes = true,
    }));
  }
  for ([_][2][]const u8{
    .{" a ", " a "},
    .{"a", " `a` "},
    .{" a ", "` a `"},
    .{" a ", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .quoted,
      .trim_whitespace_inside_quotes = false,
    }));
  }

  for ([_][2][]const u8{
    .{"a", " a "},
    .{" a ", " `a` "},
    .{"a", "` a `"},
    .{" a ", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .unquoted,
      .trim_whitespace_inside_quotes = true,
    }));
  }
  for ([_][2][]const u8{
    .{"a", " a "},
    .{" a ", " `a` "},
    .{" a ", "` a `"},
    .{"  a  ", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .unquoted,
      .trim_whitespace_inside_quotes = false,
    }));
  }

  for ([_][2][]const u8{
    .{" a ", " a "},
    .{" a ", " `a` "},
    .{"a", "` a `"},
    .{" a ", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .no,
      .trim_whitespace_inside_quotes = true,
    }));
  }
  for ([_][2][]const u8{
    .{" a ", " a "},
    .{" a ", " `a` "},
    .{" a ", "` a `"},
    .{"  a  ", " ` a ` "},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
      .trim_whitespace = .no,
      .trim_whitespace_inside_quotes = false,
    }));
  }

  for ([_][2][]const u8{
    .{"\\", " \\ "},
    .{"\\", "\" \\\\ \""},
    .{"\\", "' \\\\ '"},
    .{"\\", "` \\\\ `"},
    .{"\\n", " \\n "},
    .{"\\r", " \\r "},
    .{"\\t", " \\t "},
    .{"\\\\", " \\\\ "},
    .{"\n", "' \\n '"},
    .{"\r", "' \\r '"},
    .{"\t", "' \\t '"},
    .{"\\", "' \\\\ '"},
    .{"'`", "\" '` \""},
    .{"`\"", "' `\" '"},
    .{"'\"", "` '\" `"},
    .{"'\\'", "` '\\\\' `"},
    .{"\\", " '\\\\' "},
    .{"\\", "'\\\\'"},
  }) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{}));
  }
}

/// Parses the provided `file_data` string to a StaticStringMap
/// If a parsing error occurs, a compileError is emitted
pub fn loadEnvDataComptime(comptime file_data: []const u8, comptime options: UnescapeStringOptions) std.StaticStringMap([]const u8) {
  comptime {
    const Kvp = struct { @"0": []const u8, @"1": []const u8 };
    var kvp_list: []const Kvp = &.{};

    var it = std.mem.tokenizeAny(u8, file_data, "\r\n");
    while (it.next()) |raw_line| {
      const line = std.mem.trim(u8, raw_line, " \t");
      if (line.len == 0 or line[0] == '#') continue;

      const i = std.mem.indexOfScalar(u8, line, '=') orelse continue;
      const key = std.mem.trim(u8, line[0..i], " ");

      const temp_val = line[i+1 ..];
      var data_arr: [temp_val.len]u8 = undefined;
      const val = unescapeString(data_arr[0..], temp_val, options) catch |e| { @compileError(@errorName(e)); };

      if (key.len == 0 or val.len == 0) continue;
      const copy: [val.len]u8 = val[0..val.len].*;

      kvp_list = kvp_list ++ [1]Kvp{ .{ .@"0" = key, .@"1" = copy[0..] } };
    }

    // The result may have multiple entries with the same key, but the latest is used
    return std.StaticStringMap([]const u8).initComptime(kvp_list);
  }
}

test loadEnvDataComptime {
  const env_file = 
    \\ a = b
    \\ a = "MUST NOT BE USED"
    \\ c = 'd'
    \\ 3 = " f "
    \\ 4 = 
    \\ # 5 = 6
  ;

  @setEvalBranchQuota(1000_000);
  const parsed = comptime loadEnvDataComptime(env_file, .{});
  std.debug.assert(std.mem.eql(u8, "b", parsed.get("a").?));
  std.debug.assert(std.mem.eql(u8, "d", parsed.get("c").?));
  std.debug.assert(std.mem.eql(u8, "f", parsed.get("3").?));
  std.debug.assert(null == parsed.get("4"));
  std.debug.assert(null == parsed.get("5"));
}

/// Embed and parse the provided file to StaticStringMap
pub fn loadEnvComptime(comptime file_name: []const u8, comptime options: UnescapeStringOptions) std.StaticStringMap([]const u8) {
  const file_data = @embedFile(file_name);
  return loadEnvDataComptime(file_data, options);
}

fn GetEnvRuntimeType(free_file: bool) type {
  return struct {
    map: std.process.EnvMap,
    file_data: if (free_file) []u8 else void,

    /// Get the value for the given key or null if none exists
    pub fn get(self: *const @This(), key: []const u8) ?[]const u8 {
      return self.map.get(key);
    }
    /// Put a key value pair in the map, (the key should not be mutated after this)
    pub fn put(self: *@This(), key: []const u8, value: []const u8) !void {
      return self.map.put(key, value);
    }
    /// deinit the map and free any data that needs to be freed
    pub fn deinit(self: *@This()) void {
      if (free_file) {
        self.map.hash_map.allocator.free(self.file_data);
      }
      self.map.deinit();
    }
    /// Returns an iterator over entries in the map.
    pub fn iterator(self: *const @This()) self.map.hash_map.Iterator {
      return self.map.iterator();
    }
  };
}

pub const EnvDataRuntimeType = GetEnvRuntimeType(false);

/// Parses the provided `file_data` string to a StringHashMapUnmanaged
/// The `file_data` is mutated
/// It is caller's job to free the file_data and resultant 
pub fn loadEnvDataRuntime(file_data: []u8, allocator: std.mem.Allocator, options: UnescapeStringOptions) !EnvDataRuntimeType {
  var retval = EnvDataRuntimeType{
    .map = std.process.EnvMap.init(allocator),
    .file_data = {},
  };

  var it = std.mem.tokenizeAny(u8, file_data, "\r\n");
  while (it.next()) |raw_line| {
    const line = std.mem.trim(u8, raw_line, " \t");
    if (line.len == 0 or line[0] == '#') continue;

    const i = std.mem.indexOfScalar(u8, line, '=') orelse continue;
    const key = std.mem.trim(u8, line[0..i], " ");

    const temp_val = line[i+1 ..];
    const val = try unescapeString(@constCast(temp_val), temp_val, options);

    if (key.len == 0 or val.len == 0) continue;

    try retval.map.put(key, val);
  }

  return retval;
}

test loadEnvDataRuntime {
  const env_file = 
    \\ a = b
    \\ c = 'd'
    \\ 3 = " f "
    \\ 4 = 
    \\ # 5 = 6
  ;

  const copy = try std.testing.allocator.dupe(u8, env_file[0..]);
  defer std.testing.allocator.free(copy);

  var parsed = try loadEnvDataRuntime(copy, std.testing.allocator, .{});
  defer parsed.deinit();

  std.debug.assert(std.mem.eql(u8, "b", parsed.get("a").?));
  std.debug.assert(std.mem.eql(u8, "d", parsed.get("c").?));
  std.debug.assert(std.mem.eql(u8, "f", parsed.get("3").?));
  std.debug.assert(null == parsed.get("4"));
  std.debug.assert(null == parsed.get("5"));
  std.debug.assert(3 == parsed.map.count());
}

pub const EnvRuntimeType = GetEnvRuntimeType(true);

/// Read and parse the provided file
pub fn loadEnvRuntime(file_name: []const u8, allocator: std.mem.Allocator, options: UnescapeStringOptions) !EnvRuntimeType {
  var file = try std.fs.cwd().openFile(file_name, .{});

  const file_data = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch |e| {
    file.close();
    return e;
  };
  file.close();

  const parsed_map = try loadEnvDataRuntime(file_data, allocator, options);
  return .{
    .map = parsed_map.map,
    .file_data = file_data,
  };
}

