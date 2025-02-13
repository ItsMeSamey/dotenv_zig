//! These functions can be used to load env files at runtime or comptime.

const std = @import("std");

pub const UnescapeStringOptions = struct {
  logFn: fn (comptime format: []const u8, args: anytype) void = struct {
    fn logFn(comptime format: []const u8, args: anytype) void {
      if (@inComptime()) {
        @compileError(std.fmt.comptimePrint(format, args));
      } else {
        std.log.err(format, args);
      }
    }
  }.logFn,

  // Whether or not to trim whitespace after unescaping the string
  trimWhitespaceInsideQuotes: bool = true
};

/// Function used to unescape quoted string and trim any whitespace
pub fn unescapeString(result: []u8, input: []const u8, comptime options: UnescapeStringOptions) ![]const u8 {
  const val = std.mem.trim(u8, input, " \t");
  if (val.len == 0) return val;
  if (val[0] != '"' and val[0] != '\'' and val[0] != '`') return val;

  // String must start and end with same kind of quotes
  if (val[0] != val[val.len - 1]) {
    options.logFn("Invalid string --> {s} <--. if it starts with a quote, it must end with the same kind of quote too", .{val});
    return error.InvalidString;
  }

  switch (val[0]) {
    inline '"', '\'', '`' => |escapeChar| {
      var strippedVal = val[1..val.len - 1];
      if (options.trimWhitespaceInsideQuotes) strippedVal = std.mem.trim(strippedVal);
      var idx: usize = 0;
      var resultIdx: usize = 0;
      while (idx < strippedVal.len - 1) {
        if (strippedVal[idx] == escapeChar) {
          options.logFn("Invalid escape sequence {s} in --> {s} <--", .{ strippedVal[idx .. idx + 1], val });
          return error.InvalidString;
        } else if (strippedVal[idx] == '\\') {
          switch (strippedVal[idx + 1]) {
            'n' => result[resultIdx] = '\n',
            'r' => result[resultIdx] = '\r',
            't' => result[resultIdx] = '\t',
            '\\' => result[resultIdx] = '\\',
            escapeChar => result[resultIdx] = escapeChar,
            else => {
              options.logFn("Unexpected escape sequence {s} in --> {s} <--", .{ strippedVal[idx .. idx + 1], val });
              return error.InvalidEscapeSequence;
            },
          }
          idx += 2;
        } else {
          result[resultIdx] = strippedVal[idx];
          idx += 1;
        }
        resultIdx += 1;
      }

      if (idx == strippedVal.len - 1) {
        if (strippedVal[idx] == '\\' or strippedVal[idx] == escapeChar) {
          options.logFn("Invalid terminal character {s} in --> {s} <--, string cant end with {s}", .{ strippedVal[idx .. idx + 1], val, if (strippedVal[idx] == '\\') "a \\ (backslash)" else "a the quote (" ++ [_]u8{escapeChar} ++ ")" });
          return error.InvalidString;
        }
        result[resultIdx] = strippedVal[idx];
        resultIdx += 1;
      }
      return result[0..resultIdx];
    },
    else => unreachable,
  }
  unreachable;
}

test unescapeString {
  var buffer: [100]u8 = undefined;
  const testCases = [_][2][]const u8{
    .{" \\ ", " \\ "},
    .{" \\ ", "\" \\\\ \""},
    .{" \\ ", "' \\\\ '"},
    .{" \\ ", "` \\\\ `"},
    .{" \\n ", " \\n "},
    .{" \\r ", " \\r "},
    .{" \\t ", " \\t "},
    .{" \\\\ ", " \\\\ "},
    .{" \n ", "' \\n '"},
    .{" \r ", "' \\r '"},
    .{" \t ", "' \\t '"},
    .{" \\ ", "' \\\\ '"},
    .{" '` ", "\" '` \""},
    .{" `\" ", "' `\" '"},
    .{" '\" ", "` '\" `"},
    .{" '\\' ", "` '\\\\' `"},
    .{"\\", " '\\\\' "},
    .{"\\", "'\\\\'"},
  };

  for (testCases) |testCase| {
    try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{}));
  }
}

/// Parses the provided `file_data` string to a StaticStringMap
/// If a parsing error occurs, a compileError is emitted
pub fn loadEnvDataComptime(comptime file_data: []const u8, comptime options: UnescapeStringOptions) std.StaticStringMap([]const u8) {
  comptime {
    @setEvalBranchQuota(10_000);

    const Kvp = struct { @"0": []const u8, @"1": []const u8 };
    var kvpList: []const Kvp = &.{};

    var it = std.mem.tokenizeAny(u8, file_data, "\r\n");
    while (it.next()) |rawLine| {
      const line = std.mem.trim(u8, rawLine, " \t");
      if (line.len == 0 or line[0] == '#') continue;

      const i = std.mem.indexOfScalar(u8, line, '=') orelse continue;
      const key = std.mem.trim(u8, line[0..i], " ");

      const tempVal = line[i+1 ..];
      var dataArr: [tempVal.len]u8 = undefined;
      const val = unescapeString(dataArr[0..], tempVal, options) catch |e| { @compileError(@errorName(e)); };
      @compileLog("parsed `" ++ tempVal ++ "` to `" ++ val ++ "`");

      if (key.len == 0 or val.len == 0) continue;

      kvpList = kvpList ++ [1]Kvp{ .{ .@"0" = key, .@"1" = val } };
    }

    return std.StaticStringMap([]const u8).initComptime(kvpList);
  }
}

test loadEnvDataComptime {
  const env_file = 
    \\ a = b
    \\ c = 'd'
    \\ 3 = " f "
    \\ 4 = 
    \\ # 5 = 6
  ;

  const parsed = comptime loadEnvDataComptime(env_file, .{});
  comptime {
    std.debug.assert(std.mem.eql(u8, "b", parsed.get("a").?));
    std.debug.assert(std.mem.eql(u8, "d", parsed.get("c").?));
    std.debug.assert(std.mem.eql(u8, "f", parsed.get("3").?));
    std.debug.assert(null == parsed.get("4"));
    std.debug.assert(null == parsed.get("5"));
    std.debug.assert(3 == parsed.kvs.len);
  }
}

pub fn loadEnvComptime(comptime file_name: []const u8, comptime options: UnescapeStringOptions) std.StaticStringMap([]const u8) {
  const file_data = @embedFile(file_name);
  return loadEnvDataComptime(file_data, options);
}

pub const EnvDataRuntimeType = struct {
  map: std.process.EnvMap,

  pub fn get(self: *const @This(), key: []const u8) ?[]const u8 {
    return self.map.get(key);
  }
  pub fn put(self: *@This(), key: []const u8, value: []const u8) !void {
    return self.map.put(key, value);
  }
  pub fn deinit(self: *@This()) void {
    self.map.deinit();
  }
};

/// Parses the provided `file_data` string to a StringHashMapUnmanaged
/// The `file_data` is mutated
/// It is caller's job to free the file_data and resultant 
pub fn loadEnvDataRuntime(file_data: []u8, allocator: std.mem.Allocator, options: UnescapeStringOptions) !EnvDataRuntimeType {
  var retval = EnvDataRuntimeType{
    .map = std.process.EnvMap.init(allocator)
  };

  var it = std.mem.tokenizeAny(u8, file_data, "\r\n");
  while (it.next()) |rawLine| {
    const line = std.mem.trim(u8, rawLine, " \t");
    if (line.len == 0 or line[0] == '#') continue;

    const i = std.mem.indexOfScalar(u8, line, '=') orelse continue;
    const key = std.mem.trim(u8, line[0..i], " ");

    const tempVal = line[i+1 ..];
    const val = unescapeString(tempVal, tempVal, options) catch |e| { @compileError(@errorName(e)); };

    if (key.len == 0 or val.len == 0) continue;

    try retval.map.put(key, val);
  }

  return retval;
}

pub const EnvRuntimeType = struct {
  map: std.process.EnvMap,
  file_data: []u8,

  pub fn get(self: *const @This(), key: []const u8) ?[]const u8 {
    return self.map.get(key);
  }
  pub fn put(self: *@This(), key: []const u8, value: []const u8) !void {
    return self.map.put(key, value);
  }
  pub fn deinit(self: *@This()) void {
    self.map.hash_map.allocator.free(self.file_data);
    self.map.deinit();
  }
};
pub fn loadEnvRuntime(file_name: []const u8, allocator: std.mem.Allocator, options: UnescapeStringOptions) !EnvRuntimeType {
  var file = try std.fs.cwd().openFile(file_name, .{});

  const file_data = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch |e| {
    file.close();
    return e;
  };
  file.close();

  const parsed_map = loadEnvDataRuntime(file_data, allocator, options);
  return .{
    .map = parsed_map.map,
    .file_data = file_data,
  };
}

