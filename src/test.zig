const std = @import("std");
const dotenv = @import("dotenv.zig");


// const unescapeString = dotenv.unescapeString;
// test unescapeString {
//   var buffer: [100]u8 = undefined;
//
//   for ([_][2][]const u8{
//     .{"a", " a "},
//     .{"a", " `a` "},
//     .{"a", "` a `"},
//     .{"a", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .yes,
//       .trim_whitespace_inside_quotes = true,
//     }));
//   }
//   for ([_][2][]const u8{
//     .{"a", " a "},
//     .{"a", " `a` "},
//     .{" a ", "` a `"},
//     .{" a ", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .yes,
//       .trim_whitespace_inside_quotes = false,
//     }));
//   }
//
//   for ([_][2][]const u8{
//     .{" a ", " a "},
//     .{"a", " `a` "},
//     .{"a", "` a `"},
//     .{"a", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .quoted,
//       .trim_whitespace_inside_quotes = true,
//     }));
//   }
//   for ([_][2][]const u8{
//     .{" a ", " a "},
//     .{"a", " `a` "},
//     .{" a ", "` a `"},
//     .{" a ", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .quoted,
//       .trim_whitespace_inside_quotes = false,
//     }));
//   }
//
//   for ([_][2][]const u8{
//     .{"a", " a "},
//     .{" a ", " `a` "},
//     .{"a", "` a `"},
//     .{" a ", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .unquoted,
//       .trim_whitespace_inside_quotes = true,
//     }));
//   }
//   for ([_][2][]const u8{
//     .{"a", " a "},
//     .{" a ", " `a` "},
//     .{" a ", "` a `"},
//     .{"  a  ", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .unquoted,
//       .trim_whitespace_inside_quotes = false,
//     }));
//   }
//
//   for ([_][2][]const u8{
//     .{" a ", " a "},
//     .{" a ", " `a` "},
//     .{"a", "` a `"},
//     .{" a ", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .no,
//       .trim_whitespace_inside_quotes = true,
//     }));
//   }
//   for ([_][2][]const u8{
//     .{" a ", " a "},
//     .{" a ", " `a` "},
//     .{" a ", "` a `"},
//     .{"  a  ", " ` a ` "},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{
//       .trim_whitespace = .no,
//       .trim_whitespace_inside_quotes = false,
//     }));
//   }
//
//   for ([_][2][]const u8{
//     .{"\\", " \\ "},
//     .{"\\", "\" \\\\ \""},
//     .{"\\", "' \\\\ '"},
//     .{"\\", "` \\\\ `"},
//     .{"\\n", " \\n "},
//     .{"\\r", " \\r "},
//     .{"\\t", " \\t "},
//     .{"\\\\", " \\\\ "},
//     .{"\n", "' \\n '"},
//     .{"\r", "' \\r '"},
//     .{"\t", "' \\t '"},
//     .{"\\", "' \\\\ '"},
//     .{"'`", "\" '` \""},
//     .{"`\"", "' `\" '"},
//     .{"'\"", "` '\" `"},
//     .{"'\\'", "` '\\\\' `"},
//     .{"\\", " '\\\\' "},
//     .{"\\", "'\\\\'"},
//   }) |testCase| {
//     try std.testing.expectEqualStrings(testCase[0], try unescapeString(buffer[0..], testCase[1], .{}));
//   }
// }

