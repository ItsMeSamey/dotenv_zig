const std = @import("std");

pub const ParseOptions = struct {
  /// Which logging function to use when priniting errors
  log_fn: fn (comptime format: []const u8, args: anytype) void = struct {
    fn log_fn(comptime format: []const u8, args: anytype) void {
      if (@inComptime()) {
        @compileLog(std.fmt.comptimePrint(format, args));
      } else {
        std.debug.print(format, args);
      }
    }
  }.log_fn,

  /// Whether or not to unescape and unquoted the quoted strings
  unquote_values: bool = true,

  /// Whether or not to trim whitespace (whitespace inside quotes is never trimmed)
  trim_whitespace: bool = true,

  /// substitute variables inside of `${}` blocks
  substitute: bool = false,

  is_valid_first_key_char_fn: fn (self: @This(), char: u8) bool = struct {
    fn is_valid_first_key_char(self: Self, char: u8) bool {
      const is_valid = std.ascii.isAlphabetic(char) or char == '_';
      if (!is_valid) self.log_fn("First character for key should be [a-zA-Z_]; got: `{c}`\n", .{char});
      return is_valid;
    }
  }.is_valid_first_key_char,

  is_valid_key_char_fn: fn (self: @This(), char: u8) bool = struct {
    fn is_valid_key_char(self: Self, char: u8) bool {
      const is_valid = std.ascii.isAlphanumeric(char) or char == '_';
      if (!is_valid) self.log_fn("Key can only contain [a-zA-Z0-9_]; got: `{c}`\n", .{char});
      return is_valid;
    }
  }.is_valid_key_char,

  max_error_line_peek: usize = 100,

  const Self = @This();

  pub const NopLogFn = struct {
    fn log_fn(comptime _: []const u8, _: anytype) void {}
  }.log_fn;

  pub const Istring = struct {
    idx: u32,
    len: u32,
  };

  fn is_valid_first_key_char(self: @This(), char: u8) bool {
    return self.is_valid_first_key_char_fn(self, char);
  }

  fn is_valid_key_char(self: @This(), char: u8) bool {
    return self.is_valid_key_char_fn(self, char);
  }

  /// the type of map used
  pub const MapTypeContext = struct {
    result: []const u8,
    const StringContext = std.hash_map.StringContext;
    pub fn hash(self: @This(), key: anytype) u64 {
      if (@TypeOf(key) == Istring) {
        return StringContext.hash(undefined, self.result[key.idx..][0..key.len]);
      } else if (@TypeOf(key) == []const u8) {
        return StringContext.hash(undefined, key);
      }
      unreachable;
    }
    pub fn eql(self: @This(), key: anytype, key2: Istring) bool {
      const second_string = self.result[key2.idx..][0..key2.len];
      if (@TypeOf(key) == Istring) {
        return StringContext.eql(undefined, self.result[key.idx..][0..key.len], second_string);
      } else if (@TypeOf(key) == []const u8) {
        return StringContext.eql(undefined, key, second_string);
      }
      unreachable;
    }
  };

  /// The type of map's context
  pub const MapType = std.HashMapUnmanaged(Istring, Istring, MapTypeContext, std.hash_map.default_max_load_percentage);

  /// The type of map used at comptime
  pub const MapTypeComptime = std.StaticStringMap([]const u8);
};

const EnvType = struct {
  /// The underlying string map
  map: ParseOptions.MapType,
  /// If this is not void, this contains 
  _freeable_data: []const u8,

  /// Get the value for the given key or null if none exists
  pub fn get(self: *const @This(), key: []const u8) ?[]const u8 {
    const idx = self.map.getAdapted(key, @FieldType(@TypeOf(self.map).Managed, "ctx"){ .result = self._freeable_data }) orelse return null;
    return self._freeable_data[idx.idx..][0..idx.len];
  }
  // /// Put a key value pair in the map, (the key should not be mutated after this)
  // fn put(self: *@This(), allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
  //   return self.map.putContext(allocator, key, value);
  // }
  /// deinit the map and free any data that needs to be freed
  pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
    allocator.free(self._freeable_data);
    self.map.deinit(allocator);
  }

  const Entry = struct {
    key: []const u8,
    value: []const u8,
  };

  const Iterator = struct {
    iter: ParseOptions.MapType.Iterator,
    data: []const u8,

    pub fn next(self: *@This()) ?Entry {
      const result = self.iter.next() orelse return null;
      return Entry{
        .key = self.data[result.key_ptr.idx..][0..result.key_ptr.len],
        .value = self.data[result.value_ptr.idx..][0..result.value_ptr.len],
      };
    }
  };

  /// Returns an iterator over entries in the map.
  pub fn iterator(self: *const @This()) Iterator {
    return .{
      .iter = self.map.iterator(),
      .data = self._freeable_data,
    };
  }
};

pub const ParseError = ParseValueError || std.fs.File.OpenError || std.fs.File.ReadError;

/// Read and parse the `.env` file to a HashMap
pub fn load(allocator: std.mem.Allocator, comptime options: ParseOptions) ParseError!EnvType {
  return loadFrom(".env", allocator, options);
}

/// Read and parse the provided env file to a HashMap
pub fn loadFrom(file_name: []const u8, allocator: std.mem.Allocator, comptime options: ParseOptions) ParseError!EnvType {
  var file = try std.fs.cwd().openFile(file_name, .{});
  const file_data = file.readToEndAlloc(allocator, std.math.maxInt(usize)) catch |e| {
    file.close();
    return e;
  };
  file.close();
  defer allocator.free(file_data);

  return loadFromData(file_data, allocator, options);
}

/// Read and parse the `.env` file to a StaticStringMap at comptime
pub fn loadFromData(data: []const u8, allocator: std.mem.Allocator, comptime options: ParseOptions) ParseValueError!EnvType {
  return GetParser(false, options).parse(data, allocator);
}

// Parse `.env` file to a StaticStringMap at comptime
pub fn loadComptime(options: ParseOptions) ParseOptions.MapTypeComptime {
  return comptime loadFromComptime(".env", options);
}

// Parse the provided .env file to a StaticStringMap at comptime
pub fn loadFromComptime(file_name: []const u8, options: ParseOptions) ParseOptions.MapTypeComptime {
  return comptime loadFromDataComptime(@embedFile(file_name), options);
}

/// Parses the provided `file_data` string to a StaticStringMap
/// If a parsing error occurs, a compileError is emitted
pub fn loadFromDataComptime(file_data: []const u8, options: ParseOptions) ParseOptions.MapTypeComptime {
  return comptime GetParser(true, options).parse(file_data, undefined) catch |e| @compileError(@errorName(e));
}

// Rest of the parsing logic

fn isOneOf(c: u8, comptime chars: []const u8) bool {
  const VectorType = @Vector(chars.len, u8);
  const query_vec: VectorType = chars[0..chars.len].*;
  const current_vec: VectorType = @splat(c);
  return @reduce(.Min, query_vec ^ current_vec) == 0;
}

fn escaped(c: u8) ?*const [2]u8 {
  return switch (c) {
    '\\' => "\\\\",
    '\n' => "\\n",
    '\r' => "\\r",
    '\t' => "\\t",
    '\x0B' => "\\v",
    '\x0C' => "\\f",
    inline else => null,
  };
}

const HEX_DECODE_ARRAY: [128]u8 = blk: {
  var all = [1]u8{0xFF} ** 128;
  for ('0'..'9') |b| all[b] = b - '0';
  for ('A'..'F' + 1) |b| all[b] = b - 'A' + 10;
  for ('a'..'f' + 1) |b| all[b] = b - 'a' + 10;
  break :blk all;
};

const ParseKeyError = error{
  InvalidFirstKeyChar,
  InvalidKeyChar,
  UnexpectedEndOfKey,
  UnexpectedEndOfFile,
};

pub const ParseValueError = error{
  UnexpectedEndOfValue,
  UnterminatedQuote,
  InvalidEscapeSequence,
  UnterminatedSubstitutionBlock,
  UnexpectedCharacter,
  SubstitutionKeyNotFound,
} || ParseKeyError || std.mem.Allocator.Error;

fn GetParser(in_comptime: bool, options: ParseOptions) type {
  return struct {
    string: []const u8,
    allocator: if (in_comptime) void else std.mem.Allocator,
    result: if (in_comptime) struct {
      items: []const u8 = &.{},

      fn append(self: *@This(), _: void, byte: u8) !void {
        self.appendSlice(undefined, [_]u8{byte});
      }

      fn appendSlice(self: *@This(), _: void, bytes: []const u8) !void {
        self.items = self.items ++ bytes;
      }
    } else std.ArrayList(u8) = .{},
    map: if (in_comptime) ParseOptions.MapTypeComptime else ParseOptions.MapType = .{},

    at: usize = 0,
    line: usize = 0,
    line_start: usize = 0,

    fn done(self: *@This()) bool {
      return self.at >= self.string.len;
    }

    fn current(self: *@This()) ?u8 {
      if (self.done()) return null;
      return self.string[self.at];
    }

    fn currentU9(self: *@This()) u9 {
      return self.current() orelse 0x100;
    }

    fn last(self: *@This()) u8 {
      std.debug.assert(self.at != 0);
      return self.string[self.at - 1];
    }

    fn take(self: *@This()) ?u8 {
      if (self.done()) return null;
      self.at += 1;
      return self.last();
    }

    fn takeU9(self: *@This()) u9 {
      return self.take() orelse 0x100;
    }

    fn skipUpto(self: *@This(), comptime end: u8) void {
      self.skipUptoAny(std.fmt.comptimePrint("{c}", .{end}));
    }

    fn skipUptoAny(self: *@This(), comptime end: []const u8) void {
      while (self.at < self.string.len and !isOneOf(self.current().?, end)) {
        self.at += 1;
      }
    }

    fn skip(self: *@This(), comptime char: u8) void {
      self.skipAny(std.fmt.comptimePrint("{c}", .{char}));
    }
    
    fn skipAny(self: *@This(), comptime chars: []const u8) void {
      while (self.at < self.string.len and isOneOf(self.current().?, chars)) {
        self.at += 1;
      }
    }

    fn currentAsSlice(self: *@This()) []const u8 {
      std.debug.assert(self.at < self.string.len);
      return self.string[self.at..][0..1];
    }

    fn printErrorMarker(self: *@This()) void {
      const at = self.at;
      self.string = self.string[0.. @min(self.at + options.max_error_line_peek, self.string.len)];
      self.skipUpto('\n');
      options.log_fn(":{d}:{d}\n{s}\n", .{self.line, at - self.line_start, self.string[self.line_start..self.at]});
      for (1..at - self.line_start) |_| {
        options.log_fn(" ", .{});
      }
      options.log_fn("^\n", .{});
    }

    fn parseKey(self: *@This()) ParseKeyError!?[]const u8 {
      // Skip any whitespace / comment lines, break at first non-whitespace character
      while (true) {
        self.skipAny(" \t\x0B\r\x0C");
        const c = self.current() orelse return null;

        if (c == '#') {
          self.skipUpto('\n');
          _ = self.take();
        } else if (c == '\n') {
          self.line += 1;
          self.line_start = self.at;
          _ = self.take();
        } else break;
      }

      const start = self.at; // starting index of our key in the string

      // ensure first key char is valid
      if (!options.is_valid_first_key_char(self.take().?)) {
        self.at -= 1;
        options.log_fn("Invalid first character `{s}` for key at ", .{escaped(self.current().?) orelse self.currentAsSlice()});
        self.printErrorMarker();
        return ParseKeyError.InvalidFirstKeyChar;
      }

      // Consume key chars untile we encounter something unexpected
      while (self.current()) |c| {
        if (isOneOf(c, " \t\x0B=")) { // The key is done
          break;
        } else if (!options.is_valid_key_char(c)) { // Parse the key character
          options.log_fn("Invalid character `{s}` while parsing key at ", .{escaped(c) orelse self.currentAsSlice()});
          self.printErrorMarker();
          return ParseKeyError.InvalidKeyChar;
        }
        self.at += 1;
      } else {
        options.log_fn("Unexpected end of file while parsing key at ", .{});
        self.at = start;
        self.printErrorMarker();

        return ParseKeyError.UnexpectedEndOfKey;
      }

      const retval = self.string[start..self.at];
      const c = self.take() orelse {
        options.log_fn("Unexpected end of file, expected `=` ", .{});
        self.printErrorMarker();
        return ParseKeyError.UnexpectedEndOfFile;
      };
      if (c == '=') return retval;

      self.skipAny(" \t\x0B");
      const end_char = self.take() orelse {
        options.log_fn("Unexpected end of file, expected `=` ", .{});
        self.printErrorMarker();
        return ParseKeyError.UnexpectedEndOfFile;
      };

      if (end_char == '=') return retval;

      options.log_fn("Got unexpected `{s}`, expected `=` ", .{escaped(end_char) orelse self.currentAsSlice()});
      self.printErrorMarker();
      return ParseKeyError.UnexpectedEndOfKey;
    }

    fn parseValue(self: *@This()) ParseValueError!void {
      self.skipAny(" \t\x0B");
      if (self.current()) |c| {
        return switch (c) {
          '\'' => self.parseQuotedValue('\''),
          '"' => self.parseQuotedValue('"'),
          '#' => {
            self.skipUpto('\n');
            _ = self.take();
            return;
          },
          else => self.parseQuotedValue(null),
        };
      } else return;
    }

    fn parseQuotedValue(self: *@This(), comptime quote_char: ?u8) ParseValueError!void {
      if (quote_char) |qc| std.debug.assert(qc == self.take().?);

      const quote_string = if (quote_char) |c| comptime std.fmt.comptimePrint(" quoted({c})", .{c}) else "";

      blk: switch (self.takeU9()) {
        0x100 => {
          if (quote_char == null) break :blk;

          options.log_fn("Unexpected end of file while parsing a{s} value at ", .{quote_string});
          self.printErrorMarker();
          return ParseValueError.UnterminatedQuote;
        },
        '\\' => {
          switch (if (quote_char) |c| @as(u9, c) else 0x100) {
            0x100 => switch (self.takeU9()) {
              0x100 => continue :blk 0x100,
              '\\', '$' => |c| try self.result.append(self.allocator, @intCast(c)),
              '\n' => {
                self.line += 1;
                self.line_start = self.at;
                try self.result.append(self.allocator, '\n');
              },
              else => |c| try self.result.appendSlice(self.allocator, &[_]u8{'\\', @intCast(c)}),
            },
            '\'' => switch (self.takeU9()) {
              0x100 => continue :blk 0x100,
              '\\', '\'' => |c| try self.result.append(self.allocator, @intCast(c)),
              '\n' => {
                self.line += 1;
                self.line_start = self.at;
                try self.result.append(self.allocator, '\n');
              },
              else => |c| try self.result.appendSlice(self.allocator, &[_]u8{'\\', @intCast(c)}),
            },
            '"' => switch (self.takeU9()) {
              0x100 => continue :blk 0x100,
              '\\' => try self.result.append(self.allocator, '\\'),
              'n' => try self.result.append(self.allocator, '\n'),
              'r' => try self.result.append(self.allocator, '\r'),
              't' => try self.result.append(self.allocator, '\t'),
              'v' => try self.result.append(self.allocator, '\x0B'),
              'f' => try self.result.append(self.allocator, '\x0C'),
              'x' => {
                const hexa = self.take() orelse continue :blk 0x100;
                const hexb = self.take() orelse continue :blk 0x100;
                const sum: u16 = @as(u16, HEX_DECODE_ARRAY[hexa & 0x7f] << 4) + @as(u16, HEX_DECODE_ARRAY[hexb & 0x7f]);
                if (((hexa | hexb) & 0x80) == 0x80 or sum > 255) {
                  options.log_fn("Invalid hex escape sequence `\\x{s}{s}` in a{s} value at ", .{
                    escaped(hexa) orelse self.string[self.at - 2..][0..1],
                    escaped(hexb) orelse self.string[self.at - 1..][0..1],
                    quote_string,
                  });
                  self.at -= if (!std.ascii.isHex(hexa)) 2 else 1;
                  self.printErrorMarker();
                  return ParseValueError.InvalidEscapeSequence;
                }

                try self.result.append(self.allocator, @intCast(sum));
              },
              '\"' => try self.result.append(self.allocator, '"'),
              else => |c_u9| {
                const c: u8 = @intCast(c_u9);

                options.log_fn("Unexpected escape sequence `\\{s}` in a{s} value at ", .{
                  escaped(c) orelse self.currentAsSlice(), quote_string
                });
                self.at -= 1;
                self.printErrorMarker();
                return ParseValueError.InvalidEscapeSequence;
              }
            },
            else => unreachable,
          }
          continue :blk self.takeU9();
        },
        '$' => {
          const next = self.takeU9();
          if (quote_char == '\'' or next != '{') {
            try self.result.append(self.allocator, '$');
            continue :blk next;
          }

          const start = self.at;
          if (!options.is_valid_first_key_char(self.take() orelse {
            options.log_fn("Unexpected end of file while parsing {{}} in a{s} value at ", .{quote_string});
            self.printErrorMarker();
            return ParseValueError.UnterminatedSubstitutionBlock;
          })) {
            self.at -= 1;
            options.log_fn("Invalid first character `{s}` for key at ", .{escaped(self.current().?) orelse self.currentAsSlice()});
            self.printErrorMarker();
            return ParseKeyError.InvalidFirstKeyChar;
          }

          while (self.current()) |c| {
            if (c == '}') {
              self.at += 1;
              break;
            }
            if (!options.is_valid_key_char(c)) {
              options.log_fn("Invalid character `{c}` while parsing key at ", .{c});
              self.printErrorMarker();
              return ParseKeyError.InvalidKeyChar;
            }
            self.at += 1;
          } else {
            options.log_fn("Unexpected end of file while parsing key for {{}} in a{s} value at ", .{quote_string});
            self.printErrorMarker();
            return ParseValueError.UnterminatedSubstitutionBlock;
          }

          const key = self.string[start..self.at - 1];
          const val = self.map.getAdapted(key, ParseOptions.MapTypeContext{ .result = self.result.items }) orelse {
            options.log_fn("Substitution key `{s}` not found in map; at ", .{key});
            self.at = start;
            self.printErrorMarker();
            return ParseValueError.SubstitutionKeyNotFound;
          };

          try self.result.appendSlice(self.allocator, self.result.items[val.idx..][0..val.len]);
          continue :blk self.takeU9();
        },
        '\n' => {
          self.line += 1;
          self.line_start = self.at;
          if (quote_char == null) return;
          try self.result.append(self.allocator, '\n');
          continue :blk self.takeU9();
        },
        else => |c| {
          if (quote_char) |qc| {
            if (c == qc) break :blk;
          } else if (isOneOf(@intCast(c), " \t\x0B")) {
            break :blk;
          } else if (c == '#') {
            self.skipUpto('\n');
          }
          if (quote_char != null and c == quote_char.?) break :blk;
          if (c == '\n') {
            self.line += 1;
            self.line_start = self.at;
          }
          try self.result.append(self.allocator, @intCast(c));
          continue :blk self.takeU9();
        },
      }

      self.skipAny(" \t\x0B\r");
      const c = self.current() orelse return;
      if (c == '\n') return;
      if (c != '#') {
        options.log_fn("Unexpected character `{c}` in a{s} value at ", .{c, quote_string});
        self.printErrorMarker();
        return ParseValueError.UnexpectedCharacter;
      }

      self.skipUpto('\n');
      _ = self.take();
    }

    const ParseResult = if (in_comptime) ParseOptions.MapTypeComptime else EnvType;
    fn parse(data: []const u8, allocator: if (in_comptime) void else std.mem.Allocator) ParseValueError!ParseResult {
      var self: @This() = .{
        .string = data,
        .allocator = allocator,
      };

      errdefer self.deinit();

      while (!self.done()) {
        const key_start = self.result.items.len;
        const key = try self.parseKey() orelse break;
        try self.result.appendSlice(self.allocator, key);
        const key_idx: ParseOptions.Istring = .{ .idx = @intCast(key_start), .len = @intCast(key.len), };

        const val_start = self.result.items.len;
        try self.parseValue();
        const val_idx: ParseOptions.Istring = .{ .idx = @intCast(val_start), .len = @intCast(self.result.items.len - val_start), };

        try self.map.putContext(self.allocator, key_idx, val_idx, .{ .result = self.result.items });
      }

      const freeable_data = if (in_comptime) {} else try self.result.toOwnedSlice(self.allocator);

      return if (in_comptime) self.map else .{ .map = self.map, ._freeable_data = freeable_data };
    }

    fn deinit(self: *@This()) void {
      if (!in_comptime) {
        self.result.deinit(self.allocator);
        self.map.deinit(self.allocator);
      }
    }
  };
}

//------
// Tests
//------

const ENV_TEST_STRING_1: []const u8 = 
  \\ # This is a comment
  \\NOTHING=# This is also a comment so NOTHING should be an empty string
  \\NOTHING = "" # You can override values, this is still an empty string
  \\HOSTNAME = localhost
  \\PORT = 8080
  \\URL = http://${HOSTNAME}:${PORT}
  \\FALLBACK = "${NOTHING}"
  \\LITERAL = '${This Will Not Be Substitutes}'
  \\ESCAPE_SEQUENCES = "\xff\n\r\v\f"
  \\# 5 = 6 #this will cause an error if uncommented
  \\MULTILINE_VALUE = "Multi
  \\line
  \\    value"
;

// test loadFromComptime {
//
//   @setEvalBranchQuota(1000_000);
//   const parsed = comptime loadFromComptime("test.env", .{});
//   try std.testing.expectEqualStrings("b", parsed.get("a").?);
//   try std.testing.expectEqualStrings("d", parsed.get("c").?);
//   try std.testing.expectEqualStrings("f", parsed.get("3").?);
//   std.debug.assert(null == parsed.get("4"));
//   std.debug.assert(null == parsed.get("5"));
//   std.debug.assert(false);
// }

test loadFrom {
  var parsed = try loadFromData(ENV_TEST_STRING_1, std.testing.allocator, .{});
  defer parsed.deinit(std.testing.allocator);

  // var iter = parsed.iterator();
  // while (iter.next()) |kv| {
  //   std.debug.print("`{s}`: `{s}`\n", .{kv.key, kv.value});
  // }

  std.debug.assert(std.mem.eql(u8, "", parsed.get("NOTHING").?));
  std.debug.assert(std.mem.eql(u8, "localhost", parsed.get("HOSTNAME").?));
  std.debug.assert(std.mem.eql(u8, "8080", parsed.get("PORT").?));
  std.debug.assert(std.mem.eql(u8, "http://localhost:8080", parsed.get("URL").?));
  std.debug.assert(std.mem.eql(u8, "", parsed.get("FALLBACK").?));
  std.debug.assert(std.mem.eql(u8, "${This Will Not Be Substitutes}", parsed.get("LITERAL").?));
  std.debug.assert(std.mem.eql(u8, "\xff\n\r\x0B\x0C", parsed.get("ESCAPE_SEQUENCES").?));
  std.debug.assert(std.mem.eql(u8, "Multi\nline\n    value", parsed.get("MULTILINE_VALUE").?));
}

