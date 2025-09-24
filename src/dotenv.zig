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

  /// the type of map to use
  map_type: type = std.StringHashMapUnmanaged([]const u8),

  /// type of map to use at comptime
  map_type_comptime: type = std.StaticStringMap([]const u8),

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

  const Self = @This();

  pub const NopLogFn = struct {
    fn log_fn(comptime _: []const u8, _: anytype) void {}
  }.log_fn;

  fn is_valid_first_key_char(self: Self, char: u8) bool {
    return self.is_valid_first_key_char_fn(self, char);
  }

  fn is_valid_key_char(self: Self, char: u8) bool {
    return self.is_valid_key_char_fn(self, char);
  }
};

fn GetEnvType(T: type) type {
  return struct {
    /// The underlying string map
    map: T,
    /// If this is not void, this contains 
    _freeable_data: []const u8,

    /// Get the value for the given key or null if none exists
    pub fn get(self: *const @This(), key: []const u8) ?[]const u8 {
      return self.map.get(key);
    }
    /// Put a key value pair in the map, (the key should not be mutated after this)
    pub fn put(self: *@This(), allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
      return self.map.put(allocator, key, value);
    }
    /// deinit the map and free any data that needs to be freed
    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
      allocator.free(self._freeable_data);
      self.map.deinit(allocator);
    }
    /// Returns an iterator over entries in the map.
    pub fn iterator(self: *const @This()) @TypeOf(self.map).Iterator {
      return self.map.iterator();
    }
  };
}

pub const ParseError = ParseValueError || std.fs.File.OpenError || std.fs.File.ReadError;

/// Read and parse the `.env` file to a HashMap
pub fn load(allocator: std.mem.Allocator, comptime options: ParseOptions) ParseError!GetEnvType(options.map_type) {
  return loadFrom(".env", allocator, options);
}

/// Read and parse the provided env file to a HashMap
pub fn loadFrom(file_name: []const u8, allocator: std.mem.Allocator, comptime options: ParseOptions) ParseError!GetEnvType(options.map_type) {
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
pub fn loadFromData(data: [] u8, allocator: std.mem.Allocator, comptime options: ParseOptions) ParseValueError!GetEnvType(options.map_type) {
  return GetParser(false, options).parse(data, allocator);
}

// Parse `.env` file to a StaticStringMap at comptime
pub fn loadComptime(options: ParseOptions) options.map_type_comptime {
  return comptime loadFromComptime(".env", options);
}

// Parse the provided .env file to a StaticStringMap at comptime
pub fn loadFromComptime(file_name: []const u8, options: ParseOptions) options.map_type_comptime {
  return comptime loadFromDataComptime(@embedFile(file_name), options);
}

/// Parses the provided `file_data` string to a StaticStringMap
/// If a parsing error occurs, a compileError is emitted
pub fn loadFromDataComptime(file_data: []const u8, options: ParseOptions) options.map_type_comptime {
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
  var all = [1]u8{0xFF} * 128;
  for ('0'..'9') |b| all[b - '0'] = b - '0';
  for ('A'..'F') |b| all[b - '0'] = b - 'A' + 10;
  for ('a'..'f') |b| all[b - '0'] = b - 'a' + 10;
  break :blk all;
};

const ParseKeyError = error{
  InvalidFirstKeyChar,
  InvalidKeyChar,
  UnexpectedEndOfKey,
};

pub const ParseValueError = error{
  UnexpectedEndOfValue,
  UnterminatedQuote,
  InvalidEscapeSequence,
  UnterminatedSubstitutionBlock,
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
    map: if (in_comptime) options.map_type_comptime else options.map_type = .{},

    at: usize = 0,
    line: usize = 0,
    line_start: usize = 0,

    fn done(self: *@This()) bool {
      return self.at > self.string.len;
    }

    fn current(self: *@This()) ?u8 {
      if (self.done()) return null;
      return self.string[self.at];
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
      options.log_fn(":{d}:{d}\n{s}\n", .{self.line, self.at - self.line_start, self.string[self.line_start..self.at-1]});
      for (0..self.line_start - self.at) |_| {
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

      var end: usize = undefined;

      // Consume key chars untile we encounter something unexpected
      while (self.take()) |c| {
        if (isOneOf(c, " \t\x0B=")) {
          end = self.at - 1;

          if (c == '=') break;
          self.skipAny(" \t\x0B");
          const end_char = self.current() orelse continue;
          if (end_char == '=') break;

          options.log_fn("Got unexpected `{s}`, expected `=` ", .{escaped(end_char) orelse self.currentAsSlice()});
          self.printErrorMarker();
          return ParseKeyError.UnexpectedEndOfKey;
        } else if (!options.is_valid_key_char(c)) {
          self.at -= 1;
          options.log_fn("Invalid character `{s}` while parsing key at ", .{escaped(c) orelse self.currentAsSlice()});
          self.printErrorMarker();
          return ParseKeyError.InvalidKeyChar;
        }
      } else {
        options.log_fn("Unexpected end of file while parsing key at ", .{});
        self.at = start;
        self.printErrorMarker();

        return ParseKeyError.UnexpectedEndOfKey;
      }

      return self.string[start..end];
    }

    fn parseValue(self: *@This()) ParseValueError!void {
      self.skipAny(" \t\x0B");
      if (self.current()) |c| {
        return switch (c) {
          '\'' => self.parseQuotedValue('\''),
          '"' => self.parseQuotedValue('"'),
          else => self.parseQuotedValue(null),
        };
      } else return;
    }

    fn parseQuotedValue(self: *@This(), comptime quote_char: ?u8) ParseValueError!void {
      if (quote_char) |qc| std.debug.assert(qc == self.take().?);

      blk: switch (self.take()) {
        null => {
          if (quote_char == null) break :blk;

          options.log_fn("Unexpected end of file while parsing quoted({c}) value at ", .{quote_char});
          self.printErrorMarker();
          return ParseValueError.UnterminatedQuote;
        },
        '\\' => {
          switch (quote_char) {
            null => switch (self.take()) {
              null => continue :blk null,
              '\\', '$' => |c| try self.result.append(self.allocator, c),
              '\n' => {
                self.line += 1;
                self.line_start = self.at;
                try self.result.append(self.allocator, '\n');
              },
              else => |c| try self.result.appendSlice(self.allocator, &[_]u8{'\\', c}),
            },
            '\'' => switch (self.take()) {
              null => continue :blk null,
              '\\', '\'' => |c| try self.result.append(self.allocator, c),
              '\n' => {
                self.line += 1;
                self.line_start = self.at;
                try self.result.append(self.allocator, '\n');
              },
              else => |c| try self.result.appendSlice(self.allocator, &[_]u8{'\\', c}),
            },
            '"' => switch (self.take()) {
              null => continue :blk null,
              '\\' => try self.result.append(self.allocator, '\\'),
              'n' => try self.result.append(self.allocator, '\n'),
              'r' => try self.result.append(self.allocator, '\r'),
              't' => try self.result.append(self.allocator, '\t'),
              'v' => try self.result.append(self.allocator, '\x0B'),
              'f' => try self.result.append(self.allocator, '\x0C'),
              'x' => {
                const hexa = self.take() orelse continue :blk null;
                const hexb = self.take() orelse continue :blk null;
                const sum: u16 = (HEX_DECODE_ARRAY[hexa & 0x7f] << 4) + (HEX_DECODE_ARRAY[hexb & 0x7f]);
                if (((hexa | hexb) & 0x80) == 0x80 or sum > 255) {
                  options.log_fn("Invalid hex escape sequence `\\x{s}{s}` in quoted({c}) value at ", .{
                    escaped(hexa) orelse self.string[self.at - 2][0..1],
                    escaped(hexb) orelse self.string[self.at - 1][0..1],
                    quote_char,
                  });
                  self.at -= if (!std.ascii.isHex(hexa)) 2 else 1;
                  self.printErrorMarker();
                  return ParseValueError.InvalidEscapeSequence;
                }

                try self.result.append(self.allocator, @intCast(sum));
              },
              '\"' => try self.result.append(self.allocator, quote_char),
              else => |c| {
                options.log_fn("Unexpected escape sequence `\\{s}` in quoted({c}) value at ", .{
                  escaped(c) orelse self.currentAsSlice(), quote_char
                });
                self.at -= 1;
                self.printErrorMarker();
                return ParseValueError.InvalidEscapeSequence;
              }
            },
          }
          continue :blk self.take();
        },
        '$' => {
          const next = self.take();
          if (quote_char == '\'' or next != '{') {
            try self.result.append(self.allocator, '$');
            continue :blk next;
          }

          const start = self.at;
          if (!options.is_valid_first_key_char(self.take() orelse {
            options.log_fn("Unexpected end of file while parsing {{}} in a quoted({c}) value at ", .{quote_char});
            self.printErrorMarker();
            return ParseValueError.UnterminatedSubstitutionBlock;
          })) {
            self.at -= 1;
            options.log_fn("Invalid first character `{s}` for key at ", .{escaped(self.current().?) orelse self.currentAsSlice()});
            self.printErrorMarker();
            return ParseKeyError.InvalidFirstKeyChar;
          }

          while (self.current()) |c| {
            if (c == '}') break;
            if (!options.is_valid_key_char(c)) {
              options.log_fn("Invalid character `{c}` while parsing key at ", .{c});
              self.printErrorMarker();
              return ParseKeyError.InvalidKeyChar;
            }
            self.at += 1;
          } else {
            options.log_fn("Unexpected end of file while parsing key for {{}} in a quoted({c}) value at ", .{quote_char});
            self.printErrorMarker();
            return ParseValueError.UnterminatedSubstitutionBlock;
          }

          const key = self.string[start..self.at - 1];
          const val = self.map.get(key) orelse {
            options.log_fn("Substitution key `{s}` not found in map; at ", .{key});
            self.at = start;
            self.printErrorMarker();
            return ParseValueError.SubstitutionKeyNotFound;
          };

          try self.result.appendSlice(self.allocator, val);
        },
        else => |c| {
          if (c == quote_char) break :blk;
          if (c == '\n') {
            self.line += 1;
            self.line_start = self.at;
          }
          try self.result.append(self.allocator, c);
          continue :blk self.take();
        },
      }

      self.skipAny(" \t\x0B");
      const c = self.current() orelse return;
      if (c != '#') {
        options.log_fn("Unexpected character `{c}` in quoted({c}) value at ", .{c, quote_char});
        self.printErrorMarker();
        return ParseValueError.UnexpectedCharacter;
      }

      self.skipUpto('\n');
      _ = self.take();
    }

    const ParseResult = if (in_comptime) options.map_type_comptime else GetEnvType(options.map_type);
    fn parse(data: []const u8, allocator: if (in_comptime) void else std.mem.Allocator) ParseValueError!ParseResult {
      var self: @This() = .{
        .string = data,
        .allocator = allocator,
      };

      errdefer self.deinit();

      while (!self.done()) {
        const key = try self.parseKey() orelse break;
        try self.result.appendSlice(self.allocator, key);
        try self.parseValue();
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

test loadFromComptime {

  @setEvalBranchQuota(1000_000);
  const parsed = comptime loadFromComptime("test.env", .{});
  try std.testing.expectEqualStrings("b", parsed.get("a").?);
  try std.testing.expectEqualStrings("d", parsed.get("c").?);
  try std.testing.expectEqualStrings("f", parsed.get("3").?);
  std.debug.assert(null == parsed.get("4"));
  std.debug.assert(null == parsed.get("5"));
  std.debug.assert(false);
}

test loadFrom {
  var parsed = try loadFrom("src/test.env", std.testing.allocator, .{});
  defer parsed.deinit(std.testing.allocator);

  std.debug.assert(std.mem.eql(u8, "b", parsed.get("a").?));
  std.debug.assert(std.mem.eql(u8, "d", parsed.get("c").?));
  std.debug.assert(std.mem.eql(u8, "f", parsed.get("3").?));
  std.debug.assert(null == parsed.get("4"));
  std.debug.assert(null == parsed.get("5"));
  std.debug.assert(3 == parsed.map.count());
}

