const std = @import("std");

// This is taken from https://github.com/ziglang/zig/issues/1291
pub const comptime_allocator: std.mem.Allocator = .{
  .ptr = undefined,
  .vtable = &.{
    .alloc = comptimeAlloc,
    .resize = comptimeResize,
    .remap = comptimeRemap,
    .free = comptimeFree,
  },
};

fn comptimeAlloc(_: *anyopaque, len: usize, alignment: std.mem.Alignment, _: usize) ?[*]u8 {
  if (!@inComptime()) unreachable;
  var bytes: [len]u8 align(alignment.toByteUnits()) = undefined;
  return &bytes;
}

fn comptimeResize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
  // Always returning false here ensures that callsites make new allocations that fit
  // better, avoiding wasted .cdata and .data memory.
  return false;
}

fn comptimeRemap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
  // Always returning false here ensures that callsites make new allocations that fit
  // better, avoiding wasted .cdata and .data memory.
  return null;
}

fn comptimeFree(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize) void {
  // Global variables are garbage-collected by the linker.
}

pub const ComptimeHashMap = struct {
  const Self = @This();
  const default_max_load_percentage = std.hash_map.default_max_load_percentage;
  const alloc = comptime_allocator;
  pub const String = packed struct{
    idx: usize, len: usize,
    fn hash(string: @This(), ks: []const u8) u64 { return std.hash_map.StringContext.hash(undefined, ks[string.idx..][0..string.len]); }
    fn eql(string: @This(), other: []const u8, ks: []const u8) bool { return std.mem.eql(u8, ks[string.idx..][0..string.len], other); }
  };
  pub const KV = struct { key: []const u8, value: []const u8 };

  meta: []u8 = &.{},
  keys_string: []const u8 = &.{},
  values_string: []const u8 = &.{},
  keys: []String = &.{},
  values: []String = &.{},
  cap: usize = 0,
  size: usize = 0,
  available: usize = 0,

  pub fn init(init_cap: usize) Self {
    @setEvalBranchQuota(1000_000);
    const c = std.math.ceilPowerOfTwo(usize, init_cap) catch 16;
    return .{
      .meta = blk: {
        const m = alloc.alloc(u8, c) catch unreachable;
        @memset(m, 0);
        break :blk m;
      },
      .keys = alloc.alloc(String, c) catch unreachable,
      .values = alloc.alloc(String, c) catch unreachable,
      .cap = c,
      .available = c * default_max_load_percentage / 100
    };
  }

  pub const Iterator = struct {
    map: *const Self,
    i: usize = 0,

    pub fn next(it: *Iterator) ?KV {
      if (it.i >= it.map.cap) return null;
      while (it.i < it.map.cap) {
        defer it.i += 1;
        if (it.map.meta[it.i] != 0) {
          const k = it.map.keys[it.i];
          const v = it.map.values[it.i];
          return .{
            .key = it.map.keys_string[k.idx..][0..k.len],
            .value = it.map.values_string[v.idx..][0..v.len]
          };
        }
      }
      return null;
    }
  };

  pub fn iterator(self: *const Self) Iterator { return .{ .map = self }; }

  fn getFingerprint(hash: u64) u8 {
    const fp: u8 = @intCast(hash >> 56);
    return if (fp == 0) 1 else fp;
  }

  pub fn get(self: Self, key: []const u8) ?[]const u8 {
    @setEvalBranchQuota(1000_000);
    const h = std.hash_map.StringContext.hash(undefined, key);
    const fp = getFingerprint(h);
    var i: usize = @intCast(h & (self.cap - 1));
    while (self.meta[i] != 0) : (i = (i + 1) & (self.cap - 1)) {
      if (self.meta[i] == fp and self.keys[i].eql(key, self.keys_string)) {
        const v = self.values[i];
        return self.values_string[v.idx..][0..v.len];
      }
    }
    return null;
  }

  pub fn put(self: *Self, key: []const u8, value: []const u8) void {
    @setEvalBranchQuota(1000_000);
    self.grow();
    const h = std.hash_map.StringContext.hash(undefined, key);
    const fp = getFingerprint(h);
    var i: usize = @intCast(h & (self.cap - 1));
    while (self.meta[i] != 0) : (i = (i + 1) & (self.cap - 1)) {
      if (self.meta[i] == fp and self.keys[i].eql(key, self.keys_string)) {
        self.values[i] = .{ .idx = self.values_string.len, .len = value.len };
        self.values_string = self.values_string ++ value;
        return;
      }
    }
    self.meta[i] = fp;
    self.keys[i] = .{ .idx = self.keys_string.len, .len = key.len };
    self.keys_string = self.keys_string ++ key;
    self.values[i] = .{ .idx = self.values_string.len, .len = value.len };
    self.values_string = self.values_string ++ value;
    self.size += 1;
    self.available -= 1;
  }

  fn grow(self: *Self) void {
    @setEvalBranchQuota(1000_000);
    if (self.available > self.size) return;
    var new = init(if (self.size == 0) 16 else self.size * 2);

    var it = self.iterator();
    while (it.next()) |entry| {
      new.put(entry.key, entry.value);
    }

    self.* = new;
  }
};

pub const ComptimeEnvType = struct {
  const Self = @This();
  const Size = u32;
  pub const KV = ComptimeHashMap.KV;
  pub const Bucket = struct {key_idx: u40, key_len: u24};

  data: []const u8 = &.{},
  buckets: []const Bucket = &.{},
  meta: []const u8 = &.{},
  size: Size = 0,

  pub fn fromComptimeHashMap(comptime hm: ComptimeHashMap) Self {
    @setEvalBranchQuota(1000_000);
    var self: @This() = .{};
    var last_exists = false;
    for (hm.keys, hm.values, hm.meta) |key, value, meta| {
      self.meta = self.meta ++ &[_]u8{meta};
      if (meta == 0) {
        if (last_exists) {
          self.buckets = self.buckets ++ &[_]Bucket{ .{ .key_idx = @intCast(self.data.len), .key_len = undefined } };
        } else {
          self.buckets = self.buckets ++ &[_]Bucket{undefined};
        }
        last_exists = false;
      } else {
        const ks = hm.keys_string[key.idx..][0..key.len];
        const vs = hm.values_string[value.idx..][0..value.len];
        self.buckets = self.buckets ++ &[_]Bucket{ .{ .key_idx = @intCast(self.data.len), .key_len = @intCast(ks.len) } };
        self.data = self.data ++ ks ++ vs;
        last_exists = true;
        self.size += 1;
      }
    }
    self.buckets = self.buckets ++ &[_]Bucket{ .{ .key_idx = @intCast(self.data.len), .key_len = undefined } };
    std.debug.assert(self.size == hm.size);

    return self;
  }

  pub fn count(self: *const @This()) usize {
    return self.size;
  }

  pub fn capacity(self: *const @This()) usize {
    return self.buckets.len - 1;
  }

  pub const Iterator = struct {
    map: *const Self,
    i: usize = 0,

    pub fn next(it: *Iterator) ?KV {
      if (it.i >= it.map.capacity()) return null;
      while (it.i < it.map.capacity()) {
        defer it.i += 1;
        if (it.map.meta[it.i] == 0) continue;
        const bucket = it.map.buckets[it.i];
        const next_bucket = it.map.buckets[it.i + 1];
        return .{
          .key = it.map.data[@intCast(bucket.key_idx)..][0..@intCast(bucket.key_len)],
          .value = it.map.data[0..@intCast(next_bucket.key_idx)][@intCast(bucket.key_idx)..][@intCast(bucket.key_len)..]
        };
      }
      return null;
    }
  };

  pub fn iterator(self: *const Self) Iterator { return .{ .map = self }; }

  const getFingerprint = ComptimeHashMap.getFingerprint;
  pub fn get(self: Self, key: []const u8) ?[]const u8 {
    const h = std.hash_map.StringContext.hash(undefined, key);
    const fp = getFingerprint(h);
    var i: usize = @intCast(h & (self.capacity() - 1));
    while (self.meta[i] != 0) : (i = (i + 1) & (self.capacity() - 1)) {
      const b = self.buckets[i];
      if (self.meta[i] == fp and std.mem.eql(u8, key, self.data[@intCast(b.key_idx)..][0..@intCast(b.key_len)])) {
        const next = self.buckets[i + 1];
        return self.data[0..@intCast(next.key_idx)][@intCast(b.key_idx)..][@intCast(b.key_len)..];
      }
    }
    return null;
  }
};

pub const ParseOptions = struct {
  /// The logging function to use when priniting errors
  /// Set this to `NopLogFn` to disable logging
  log_fn: fn (comptime format: []const u8, args: anytype) void = DefaultLogFn,
  /// The function used to determine if the first character of a key is valid
  is_valid_first_key_char_fn: fn (self: @This(), char: u8) bool = DefaultIsValidFirstKeyChar,
  /// The function used to determine if any other character of a key is valid
  is_valid_key_char_fn: fn (self: @This(), char: u8) bool = DefaultIsValidKeyChar,
  /// How many characters to print after the point at which the error occurred in parsing
  /// This cap is only applied if there is no newline uptile next `max_error_line_peek` characters
  max_error_line_peek: usize = 100,

  const Self = @This();

  pub const DefaultLogFn = struct {
    fn log_fn(comptime format: []const u8, args: anytype) void {
      if (@inComptime()) {
        @compileLog(std.fmt.comptimePrint(format, args));
      } else {
        std.debug.print(format, args);
      }
    }
  }.log_fn;

  pub const NopLogFn = struct {
    fn log_fn(comptime _: []const u8, _: anytype) void {}
  }.log_fn;

  pub const DefaultIsValidFirstKeyChar = struct {
    fn is_valid_first_key_char(self: Self, char: u8) bool {
      const is_valid = std.ascii.isAlphabetic(char) or char == '_';
      if (!is_valid) self.log_fn("First character for key should be [a-zA-Z_]; got: `{c}`\n", .{char});
      return is_valid;
    }
  }.is_valid_first_key_char;

  pub const DefaultIsValidKeyChar = struct {
    fn is_valid_key_char(self: Self, char: u8) bool {
      const is_valid = std.ascii.isAlphanumeric(char) or char == '_';
      if (!is_valid) self.log_fn("Key can only contain [a-zA-Z0-9_]; got: `{c}`\n", .{char});
      return is_valid;
    }
  }.is_valid_key_char;

  pub const Istring = packed struct {
    idx: u32,
    len: u32,
  };

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
  pub const MapType = std.HashMapUnmanaged(Istring, []const u8, MapTypeContext, std.hash_map.default_max_load_percentage);

  /// The type of map used at comptime
  pub const ComptimeMapType = ComptimeHashMap;

  fn is_valid_first_key_char(self: @This(), char: u8) bool {
    return self.is_valid_first_key_char_fn(self, char);
  }

  fn is_valid_key_char(self: @This(), char: u8) bool {
    return self.is_valid_key_char_fn(self, char);
  }
};

const EnvType = struct {
  /// The underlying string map
  map: ParseOptions.MapType,
  _keys: []const u8,

  /// Finds the value associated with a key in the map
  pub fn get(self: *const @This(), key: []const u8) ?[]const u8 {
    return self.map.getAdapted(key, ParseOptions.MapTypeContext{ .result = self._keys });
  }

  /// Release the backing array and invalidate this map.
  /// This does *not* deinit keys, values, or the context!
  /// If your keys or values need to be released, ensure
  /// that that is done before calling this function.
  pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
    defer self.map.deinit(allocator);
    var iter = self.iterator();
    while (iter.next()) |entry| allocator.free(entry.value_ptr.*);
  }

  /// Returns an iterator over entries in the map.
  pub fn iterator(self: *const @This()) ParseOptions.MapType.Iterator {
    return self.map.iterator();
  }

  /// Format the entire map as KEY=VALUE\n lines for printing
  pub fn format(self: *const @This(), writer: std.Io.Writer) std.Io.Writer.Error!void {
    var iter = self.iterator();
    while (iter.next()) |entry| {
      try writer.print("{s}={s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
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

/// Parse `.env` file to a StaticStringMap at comptime
pub fn loadComptime(options: ParseOptions) ParseValueError!ComptimeEnvType {
  return comptime loadFromComptime(".env", options);
}

/// Parse the provided .env file to a StaticStringMap at comptime
pub fn loadFromComptime(file_name: []const u8, options: ParseOptions) ParseValueError!ComptimeEnvType {
  return comptime loadFromDataComptime(@embedFile(file_name), options);
}

/// Parses the provided `file_data` string to a StaticStringMap
/// If a parsing error occurs, a compileError is emitted
pub fn loadFromDataComptime(file_data: []const u8, options: ParseOptions) ParseValueError!ComptimeEnvType {
  return comptime GetParser(true, options).parseComptime(file_data, comptime_allocator);
}

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

const HEX_DECODE_ARRAY = blk: {
  var all: ['f' - '0' + 1]u8 = undefined;
  for ('0'..('9' + 1)) |b| all[b - '0'] = b - '0';
  for ('A'..('F' + 1)) |b| all[b - '0'] = b - 'A' + 10;
  for ('a'..('f' + 1)) |b| all[b - '0'] = b - 'a' + 10;
  break :blk all;
};

inline fn decodeHex(char: u8) u8 {
  return HEX_DECODE_ARRAY[char - @as(usize, '0')];
}

/// Errors specific to parsing keys
const ParseKeyError = error{
  /// Thrown when the first character of a key (or substitution key) is not alphabetic (a-zA-Z) or '_'
  InvalidFirstKeyChar,
  /// Thrown when a subsequent character in a key (or substitution key) is not alphanumeric (a-zA-Z0-9) or '_'
  /// Also thrown when the character immediately after optional whitespace following the key is not '=' (e.g., KEY?=value)
  InvalidKeyChar,
  /// Thrown when EOF is reached before finding '=' after parsing a key
  UnexpectedEndOfFile,
};

/// Errors specific to parsing values (includes key errors and allocator errors)
pub const ParseValueError = error{
  /// Thrown when EOF is reached inside a quoted value (' or ") without a closing quote
  UnterminatedQuote,
  /// Thrown in double-quoted values when an escape sequence is invalid:
  /// - \x followed by non-hex digits (0-9a-fA-F), including partial (e.g., \xG or \xGG where G invalid)
  /// - \ followed by an unrecognized character (not \\, \", \$, \n, \r, \t, \v, \f, \x)
  InvalidEscapeSequence,
  /// Thrown when parsing a substitution ${KEY} and EOF is reached before finding the closing '}'
  UnterminatedSubstitutionBlock,
  /// Thrown after parsing a value (quoted or unquoted), when skipping trailing whitespace,
  /// and encountering a non-newline, non-'#' character (e.g., extra text after closing quote like `"value" extra`) 
  UnexpectedCharacter,
  /// Thrown when expanding a substitution ${KEY} and no prior key named KEY exists in the map
  SubstitutionKeyNotFound,
} || ParseKeyError || std.mem.Allocator.Error;

fn GetParser(in_comptime: bool, options: ParseOptions) type {
  return struct {
    string: []const u8,
    allocator: std.mem.Allocator,
    result: std.ArrayList(u8) = .{},
    map: if (in_comptime) ParseOptions.ComptimeMapType else ParseOptions.MapType = .{},

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
      if (@inComptime()) {
        options.log_fn((" " ** @as(usize, at - self.line_start - 1)) ++ "^\n", .{});
      } else {
        for (1..at - self.line_start) |_| {
          options.log_fn(" ", .{});
        }
        options.log_fn("^\n", .{});
      }
    }

    fn parseKey(self: *@This()) ParseKeyError!?ParseOptions.Istring {
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

        return ParseKeyError.UnexpectedEndOfFile;
      }

      const retval: ParseOptions.Istring = .{ .idx = @intCast(start), .len = @intCast(self.at - start) };
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
      return ParseKeyError.InvalidKeyChar;
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

    fn trimResultEnd(self: *@This()) void {
      while (self.result.items.len > 0 and isOneOf(self.result.items[self.result.items.len - 1], " \t\x0B\r\x0C")) {
        self.result.items.len -= 1;
      }
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
                if (!std.ascii.isHex(hexa) or !std.ascii.isHex(hexb)) {
                  options.log_fn("Invalid hex escape sequence `\\x{s}{s}` in a{s} value at ", .{
                    escaped(hexa) orelse self.string[self.at - 2..][0..1],
                    escaped(hexb) orelse self.string[self.at - 1..][0..1],
                    quote_string,
                  });
                  self.at -= if (!std.ascii.isHex(hexa)) 2 else 1;
                  self.printErrorMarker();
                  return ParseValueError.InvalidEscapeSequence;
                }

                try self.result.append(self.allocator, @intCast((decodeHex(hexa) << 4) | decodeHex(hexb)));
              },
              '$' => try self.result.append(self.allocator, '$'),
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
          const maybe_val = if (in_comptime) self.map.get(key)
            else self.map.getAdapted(key, ParseOptions.MapTypeContext{ .result = self.string });
          const val = maybe_val orelse {
            options.log_fn("Substitution key `{s}` not found in map; at ", .{key});
            self.at = start;
            self.printErrorMarker();
            var iter = self.map.iterator();
            while (iter.next()) |entry| {
              options.log_fn("`{s}`: `{s}`\n", .{ self.string[entry.key_ptr.*.idx..][0..entry.key_ptr.*.len], entry.value_ptr.* });
            }
            return ParseValueError.SubstitutionKeyNotFound;
          };

          try self.result.appendSlice(self.allocator, val);
          continue :blk self.takeU9();
        },
        '\n' => {
          self.line += 1;
          self.line_start = self.at;
          if (quote_char == null) {
            self.trimResultEnd();
            return;
          }
          try self.result.append(self.allocator, '\n');
          continue :blk self.takeU9();
        },
        else => |c| {
          if (quote_char) |qc| {
            if (c == qc) break :blk;
          } else if (c == '#') {
            self.skipUpto('\n');
            self.trimResultEnd();
            return;
          }
          if (quote_char != null and c == quote_char.?) break :blk;

          try self.result.append(self.allocator, @intCast(c));
          continue :blk self.takeU9();
        },
      }

      if (quote_char == null) self.trimResultEnd();
      self.skipAny(" \t\x0B\r\x0C");
      const c = self.take() orelse return;
      if (c == '\n') return;
      if (c != '#') {
        options.log_fn("Unexpected character `{c}` in a{s} value at ", .{c, quote_string});
        self.printErrorMarker();
        return ParseValueError.UnexpectedCharacter;
      }

      self.skipUpto('\n');
      _ = self.take();
    }

    const ParseResult = EnvType;
    fn parse(data: []const u8, allocator: std.mem.Allocator) ParseValueError!ParseResult {
      var self: @This() = .{
        .string = data,
        .allocator = allocator,
      };

      errdefer self.deinit();

      while (!self.done()) {
        const key_idx = try self.parseKey() orelse break;
        // try self.result.appendSlice(self.allocator, key);

        const gpr = try self.map.getOrPutContext(self.allocator, key_idx, .{ .result = self.string });
        if (gpr.found_existing) {
          self.result = .fromOwnedSlice(@constCast(gpr.value_ptr.*));
          self.result.items.len = 0;
        }

        errdefer {
          self.map.removeByPtr(gpr.key_ptr);
        }

        try self.parseValue();
        gpr.value_ptr.* = try self.result.toOwnedSlice(allocator);
      }

      return .{ .map = self.map, ._keys = data };
    }

    fn parseComptime(comptime data: []const u8, comptime allocator: std.mem.Allocator) ParseValueError!ComptimeEnvType {
      @setEvalBranchQuota(1000_000);
      var self: @This() = .{
        .string = data,
        .allocator = allocator,
        .map = .init(16),
      };

      while (!self.done()) {
        const key_idx = try self.parseKey() orelse break;
        try self.parseValue();
        self.map.put(self.string[key_idx.idx..][0..key_idx.len], self.result.toOwnedSlice(allocator) catch unreachable);
      }

      return .fromComptimeHashMap(self.map);
    }

    fn deinit(self: *@This()) void {
      self.result.deinit(self.allocator);
      defer self.map.deinit(self.allocator);
      var iter = self.map.iterator();
      while (iter.next()) |entry| {
        self.allocator.free(entry.value_ptr.*);
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

// test loadFrom {
//   var parsed = try loadFromData(ENV_TEST_STRING_1, std.testing.allocator, .{});
//   defer parsed.deinit(std.testing.allocator);
//
//   // var iter = parsed.iterator();
//   // while (iter.next()) |kv| {
//   //   std.debug.print("`{s}`: `{s}`\n", .{ENV_TEST_STRING_1[kv.key_ptr.*.idx..][0..kv.key_ptr.*.len], kv.value_ptr.*});
//   // }
//
//   try std.testing.expectEqualStrings("", parsed.get("NOTHING").?);
//   try std.testing.expectEqualStrings("localhost", parsed.get("HOSTNAME").?);
//   try std.testing.expectEqualStrings("8080", parsed.get("PORT").?);
//   try std.testing.expectEqualStrings("http://localhost:8080", parsed.get("URL").?);
//   try std.testing.expectEqualStrings("", parsed.get("FALLBACK").?);
//   try std.testing.expectEqualStrings("${This Will Not Be Substitutes}", parsed.get("LITERAL").?);
//   try std.testing.expectEqualStrings("\xff\n\r\x0B\x0C", parsed.get("ESCAPE_SEQUENCES").?);
//   try std.testing.expectEqualStrings("Multi\nline\n    value", parsed.get("MULTILINE_VALUE").?);
//
//   const TestFns = struct {
//     fn loadFn(comptime data: []const u8, comptime options: ParseOptions) ParseError!EnvType {
//       return loadFromData(data, std.testing.allocator, options);
//     }
//
//     fn deinitFn(v: *EnvType) void {
//       v.deinit(std.testing.allocator);
//     }
//   };
//
//   _ = GetTests(TestFns.loadFn, TestFns.deinitFn);
// }

test loadFromComptime {
  const parsed = comptime loadFromDataComptime(ENV_TEST_STRING_1, .{})  catch |e| @compileError(@errorName(e));

  // var iter = parsed.iterator();
  // while (iter.next()) |kv| {
  //   std.debug.print("`{s}`: `{s}`\n", .{kv.key, kv.value});
  // }

  try std.testing.expectEqualStrings("", parsed.get("NOTHING").?);
  try std.testing.expectEqualStrings("localhost", parsed.get("HOSTNAME").?);
  try std.testing.expectEqualStrings("8080", parsed.get("PORT").?);
  try std.testing.expectEqualStrings("http://localhost:8080", parsed.get("URL").?);
  try std.testing.expectEqualStrings("", parsed.get("FALLBACK").?);
  try std.testing.expectEqualStrings("${This Will Not Be Substitutes}", parsed.get("LITERAL").?);
  try std.testing.expectEqualStrings("\xff\n\r\x0B\x0C", parsed.get("ESCAPE_SEQUENCES").?);
  try std.testing.expectEqualStrings("Multi\nline\n    value", parsed.get("MULTILINE_VALUE").?);

  const TestFns = struct {
    fn loadFn(comptime data: []const u8, comptime options: ParseOptions) ParseError!ComptimeEnvType {
      return comptime loadFromDataComptime(data, options);
    }

    fn deinitFn(_: *ComptimeEnvType) void {}
  };

  _ = GetTests(TestFns.loadFn, TestFns.deinitFn);
}

fn GetTests(loadFn: anytype, deinitFn: anytype) type {
  return struct {
    test "invalid first key character" {
      const test_data =
        \\ 1KEY=value
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidFirstKeyChar, err);
    }

    test "invalid key character" {
      const test_data =
        \\ KEY!=value
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidKeyChar, err);
    }

    test "unterminated double quote" {
      const test_data =
        \\ KEY="unterminated value
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.UnterminatedQuote, err);
    }

    test "unterminated single quote" {
      const test_data =
        \\ KEY='unterminated value
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.UnterminatedQuote, err);
    }

    test "invalid escape sequence in double quotes" {
      const test_data =
        \\ KEY="val\zue"
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidEscapeSequence, err);
    }

    test "invalid hex escape in double quotes" {
      const test_data =
        \\ KEY="val\xg12"
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidEscapeSequence, err);
    }

    test "valid hex escape in double quotes" {
      const test_data =
        \\ KEY="val\xFFue"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val\xFFue", parsed.get("KEY").?);
    }

    test "substitution key not found" {
      const test_data =
        \\ KEY=${MISSING}
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.SubstitutionKeyNotFound, err);
    }

    test "substitution in single quotes does not expand" {
      const test_data =
        \\ HOST=world
        \\ KEY='${HOST}'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("${HOST}", parsed.get("KEY").?);
    }

    test "substitution outside double quotes" {
      const test_data =
        \\ HOST=world
        \\ KEY=unquoted${HOST}
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("unquotedworld", parsed.get("KEY").?);
    }

    test "empty file" {
      const test_data = "";
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqual(@as(usize, 0), parsed.count());
    }

    test "only comments" {
      const test_data =
        \\ # Comment line 1
        \\# Comment line 2
        \\  # Comment with spaces
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqual(@as(usize, 0), parsed.count());
    }

    test "inline comment trims trailing space" {
      const test_data =
        \\ KEY=val # comment
        \\ KEY2=val2   # comment with spaces
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val", parsed.get("KEY").?);
      try std.testing.expectEqualStrings("val2", parsed.get("KEY2").?);
    }

    test "unquoted value trims leading and trailing spaces" {
      const test_data =
        \\ KEY= val 
        \\ KEY2 =  va l  
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val", parsed.get("KEY").?);
      try std.testing.expectEqualStrings("va l", parsed.get("KEY2").?);
    }

    test "unquoted value preserves interior spaces" {
      const test_data =
        \\ KEY=va l
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va l", parsed.get("KEY").?);
    }

    test "single quotes preserve escapes literally" {
      const test_data =
        \\ KEY='va\nl'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va\\nl", parsed.get("KEY").?);
    }

    test "double quotes expand newline escape" {
      const test_data =
        \\ KEY="va\nl"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "va" ++ &[_]u8{'\n'} ++ "l";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "double quotes handle backslash escape" {
      const test_data =
        \\ KEY="va\\nl"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va\\nl", parsed.get("KEY").?);
    }

    test "double quotes handle quote escape" {
      const test_data =
        \\ KEY="va\"nl"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va\"nl", parsed.get("KEY").?);
    }

    test "multiline literal in double quotes" {
      const test_data =
        \\ KEY="Multi
        \\line
        \\  value"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "Multi\nline\n  value";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "export prefix not handled (parses as invalid key)" {
      const test_data =
        \\ export KEY=value
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidKeyChar, err);
    }

    test "unexpected end of file in key" {
      const test_data =
        \\ KEY
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.UnexpectedEndOfFile, err);
    }

    test "unexpected character after key" {
      const test_data =
        \\ KEY? = value
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidKeyChar, err);
    }

    test "duplicate keys overwrite with last value" {
      const test_data =
        \\ KEY=first
        \\ KEY=second
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("second", parsed.get("KEY").?);
    }

    test "windows line endings are handled" {
      const test_data = "KEY=value\r\nKEY2= value2 \r\n";
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("value", parsed.get("KEY").?);
      try std.testing.expectEqualStrings("value2", parsed.get("KEY2").?);
    }

    test "double quotes expand carriage return escape" {
      const test_data =
        \\ KEY="va\rl"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "va" ++ &[_]u8{'\r'} ++ "l";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "double quotes expand tab escape" {
      const test_data =
        \\ KEY="va\tl"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "va" ++ &[_]u8{'\t'} ++ "l";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "double quotes expand vertical tab escape" {
      const test_data =
        \\ KEY="va\vl"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "va" ++ &[_]u8{'\x0B'} ++ "l";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "double quotes expand form feed escape" {
      const test_data =
        \\ KEY="va\fl"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "va" ++ &[_]u8{'\x0C'} ++ "l";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "unterminated substitution block" {
      const test_data =
        \\ KEY=${UNTERMINATED
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.UnterminatedSubstitutionBlock, err);
    }

    test "substitution key with invalid character" {
      const test_data =
        \\ KEY=valid
        \\ URL=http://${KEY}${KEY!}
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidKeyChar, err);
    }

    test "empty substitution key" {
      const test_data =
        \\ KEY=${}
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidFirstKeyChar, err);
    }

    test "value ends with newline in unquoted" {
      const test_data = 
        \\KEY=value\n
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("value\\n", parsed.get("KEY").?);
    }

    test "inline comment without space is parsed" {
      const test_data =
        \\ KEY=val#comment
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val", parsed.get("KEY").?);
    }

    test "quoted values preserve trailing spaces" {
      const test_data =
        \\ KEY="val "
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val ", parsed.get("KEY").?);
    }

    test "single quotes handle escaped single quote" {
      const test_data =
        \\ KEY='va\'l'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va'l", parsed.get("KEY").?);
    }

    test "double quotes handle hex escape with lowercase" {
      const test_data =
        \\ KEY="val\xffue"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val\xFFue", parsed.get("KEY").?);
    }

    test "single quotes does not parse hex char" {
      const test_data =
        \\ KEY='val\xg12'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val\\xg12", parsed.get("KEY").?);
    }

    test "double quotes escaped dollar" {
      const test_data =
        \\ KEY="va\${l}"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va${l}", parsed.get("KEY").?);
    }

    test "substitution in multiline double quotes" {
      const test_data =
        \\ HOST=world
        \\ KEY="Multi
        \\${HOST}
        \\line"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "Multi\nworld\nline";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "whitespace only lines are skipped" {
      const test_data = "   \t \nKEY=value";
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("value", parsed.get("KEY").?);
    }

    test "unquoted value with tab trims" {
      const test_data = "KEY=\tval\t";
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val", parsed.get("KEY").?);
    }

    test "quoted value with interior tab preserved" {
      const test_data = "KEY=\"va\tl\"";
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      const expected = "va\tl";
      try std.testing.expectEqualStrings(expected, parsed.get("KEY").?);
    }

    test "trailing newline in file" {
      const test_data = "KEY=value\n";
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("value", parsed.get("KEY").?);
    }

    test "key starting with underscore" {
      const test_data =
        \\ _KEY=value
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("value", parsed.get("_KEY").?);
    }

    test "value with only whitespace trims to empty" {
      const test_data = "KEY=   \t";
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("", parsed.get("KEY").?);
    }

    test "partial hex escape errors" {
      const test_data =
        \\ KEY="val\xG"
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.InvalidEscapeSequence, err);
    }

    test "escaped newline in single quotes literal" {
      const test_data =
        \\ KEY='va\nl'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va\\nl", parsed.get("KEY").?);
    }

    test "substitution key with digits" {
      const test_data =
        \\ KEY123=val
        \\ URL=${KEY123}
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val", parsed.get("URL").?);
    }

    test "inline comment after quoted value" {
      const test_data =
        \\ KEY="val" # comment
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val", parsed.get("KEY").?);
    }

    test "key with multiple = parses first" {
      const test_data =
        \\ KEY=val=more
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val=more", parsed.get("KEY").?);
    }

    test "escaped quote inside single quotes" {
      const test_data =
        \\ KEY='va\'\'l'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va''l", parsed.get("KEY").?);
    }

    test "unquoted value ending with backslash literal" {
      const test_data =
        \\ KEY=val\\
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val\\", parsed.get("KEY").?);
    }

    test "substitution EOF in key" {
      const test_data =
        \\ KEY=${UNFINISHED
      ;
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.UnterminatedSubstitutionBlock, err);
    }

    test "no value after =" {
      const test_data =
        \\ KEY=
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("", parsed.get("KEY").?);
    }

    test "comment after whitespace" {
      const test_data =
        \\ KEY=value   # comment
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("value", parsed.get("KEY").?);
    }

    test "quoted value with leading space preserved" {
      const test_data =
        \\ KEY=" val "
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings(" val ", parsed.get("KEY").?);
    }

    test "single quotes with backslash literal" {
      const test_data =
        \\ KEY='va\\l'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("va\\l", parsed.get("KEY").?);
    }

    test "hex escape at end of value" {
      const test_data =
        \\ KEY="val\xFF"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("val\xFF", parsed.get("KEY").?);
    }

    test "unexpected characters after quoted value" {
      const test_data = "KEY=\"value\" extra";
      const err = loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      try std.testing.expectError(ParseValueError.UnexpectedCharacter, err);
    }

    test "unquoted value with accented characters" {
      const test_data =
        \\ KEY=café
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("café", parsed.get("KEY").?);
    }

    test "double quoted value with emoji" {
      const test_data =
        \\ KEY="Hello 😊 World"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("Hello 😊 World", parsed.get("KEY").?);
    }

    test "single quoted value with Chinese characters" {
      const test_data =
        \\ KEY='你好世界'
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("你好世界", parsed.get("KEY").?);
    }

    test "unquoted value with Cyrillic" {
      const test_data =
        \\ KEY=Привет
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("Привет", parsed.get("KEY").?);
    }

    test "double quoted value with Arabic" {
      const test_data =
        \\ KEY="مرحبا بالعالم"
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("مرحبا بالعالم", parsed.get("KEY").?);
    }

    test "unquoted value with mixed UTF-8 and ASCII, interior em space" {
      const test_data =
        \\ KEY=café world  # em space interior
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("café world", parsed.get("KEY").?);
    }

    test "substitution expands to UTF-8 value" {
      const test_data =
        \\ GREETING=Hola
        \\ PLACE=México
        \\ MSG=${GREETING} desde ${PLACE}!
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("Hola desde México!", parsed.get("MSG").?);
    }

    test "double quoted value with trailing zero-width space trimmed" {
      const test_data =
        \\ KEY="test"  # zero-width space
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("test", parsed.get("KEY").?);
    }

    test "unquoted value with Japanese" {
      const test_data =
        \\ KEY=こんにちは
      ;
      var parsed = try loadFn(test_data, .{ .log_fn = ParseOptions.NopLogFn });
      defer deinitFn(&parsed);
      try std.testing.expectEqualStrings("こんにちは", parsed.get("KEY").?);
    }
  };
}

