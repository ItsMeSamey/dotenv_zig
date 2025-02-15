const std = @import("std");
const dotenv = @import("dotenv.zig");


const unescapeString = dotenv.unescapeString;
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

const loadEnvComptime = dotenv.loadEnvComptime;
test loadEnvComptime {

  @setEvalBranchQuota(1000_000);
  const parsed = comptime loadEnvComptime("test.env", .{});
  try std.testing.expectEqualStrings("b", parsed.get("a").?);
  try std.testing.expectEqualStrings("d", parsed.get("c").?);
  try std.testing.expectEqualStrings("f", parsed.get("3").?);
  std.debug.assert(null == parsed.get("4"));
  std.debug.assert(null == parsed.get("5"));
}

const loadEnvRuntime = dotenv.loadEnvRuntime;
test loadEnvRuntime {
  var parsed = try loadEnvRuntime("test.env", std.testing.allocator, .{});
  defer parsed.deinit();

  std.debug.assert(std.mem.eql(u8, "b", parsed.get("a").?));
  std.debug.assert(std.mem.eql(u8, "d", parsed.get("c").?));
  std.debug.assert(std.mem.eql(u8, "f", parsed.get("3").?));
  std.debug.assert(null == parsed.get("4"));
  std.debug.assert(null == parsed.get("5"));
  std.debug.assert(3 == parsed.map.count());
}

