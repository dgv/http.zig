const std = @import("std");
const httpz = @import("../httpz.zig");

pub const Error = error{
    MissingHeader,
    MissingPayload,
    MissingSignature,
    UnsupportedAlgorithm,
    AlgorithmMismatch,
    InvalidSignature,
    TokenExpired,
    TokenNotYetValid,
    InvalidIssuer,
    InvalidAudience,
    MissingAuthorization,
};

const Allocator = std.mem.Allocator;
const Encoder = std.base64.url_safe_no_pad.Encoder;
const Decoder = std.base64.url_safe_no_pad.Decoder;

pub const Algorithm = enum {
    HS256,
    HS384,
    HS512,

    fn str(self: Algorithm) []const u8 {
        return switch (self) {
            .HS256 => "HS256",
            .HS384 => "HS384",
            .HS512 => "HS512",
        };
    }

    fn fromStr(s: []const u8) ?Algorithm {
        if (std.mem.eql(u8, s, "HS256")) return .HS256;
        if (std.mem.eql(u8, s, "HS384")) return .HS384;
        if (std.mem.eql(u8, s, "HS512")) return .HS512;
        return null;
    }

    fn sigLen(self: Algorithm) usize {
        return switch (self) {
            .HS256 => 32,
            .HS384 => 48,
            .HS512 => 64,
        };
    }
};

const Header = struct {
    alg: []const u8,
    typ: []const u8 = "JWT",
};

pub const Claims = struct {
    iss: ?[]const u8 = null,
    sub: ?[]const u8 = null,
    aud: ?[]const u8 = null,
    exp: ?i64 = null,
    nbf: ?i64 = null,
    iat: ?i64 = null,
    jti: ?[]const u8 = null,
};

fn jsonAlloc(allocator: Allocator, value: anytype) ![]const u8 {
    var buf = std.Io.Writer.Allocating.init(allocator);
    const formatter = std.json.fmt(value, .{});
    try formatter.format(&buf.writer);
    return try buf.toOwnedSlice();
}

pub fn encode(allocator: Allocator, claims: anytype, algorithm: Algorithm, secret: []const u8) ![]const u8 {
    const header_json = try jsonAlloc(allocator, Header{ .alg = algorithm.str() });
    defer allocator.free(header_json);
    const claims_json = try jsonAlloc(allocator, claims);
    defer allocator.free(claims_json);

    const header_b64_size = Encoder.calcSize(header_json.len);
    const claims_b64_size = Encoder.calcSize(claims_json.len);
    const sl = algorithm.sigLen();
    const sig_b64_size = Encoder.calcSize(sl);

    const total = header_b64_size + 1 + claims_b64_size + 1 + sig_b64_size;
    var result = try allocator.alloc(u8, total);

    _ = Encoder.encode(result[0..header_b64_size], header_json);
    result[header_b64_size] = '.';

    const p_start = header_b64_size + 1;
    _ = Encoder.encode(result[p_start..][0..claims_b64_size], claims_json);
    result[p_start + claims_b64_size] = '.';

    const sig_input = result[0..p_start + claims_b64_size];
    const sig_start = p_start + claims_b64_size + 1;
    var raw_sig: [64]u8 = undefined;
    switch (algorithm) {
        .HS256 => {
            var s: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&s, sig_input, secret);
            @memcpy(raw_sig[0..32], &s);
        },
        .HS384 => {
            var s: [48]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha384.create(&s, sig_input, secret);
            @memcpy(raw_sig[0..48], &s);
        },
        .HS512 => {
            std.crypto.auth.hmac.sha2.HmacSha512.create(raw_sig[0..64], sig_input, secret);
        },
    }
    _ = Encoder.encode(result[sig_start..], raw_sig[0..sl]);

    return result;
}

pub fn decode(comptime T: type, token: []const u8, allocator: Allocator, algorithm: Algorithm, secret: []const u8) !std.json.Parsed(T) {
    var parts = std.mem.splitScalar(u8, token, '.');

    const encoded_header = parts.next() orelse return error.MissingHeader;
    const encoded_claims = parts.next() orelse return error.MissingPayload;
    const encoded_sig = parts.next() orelse return error.MissingSignature;

    var header = try parseBase64Json(Header, allocator, encoded_header);
    defer header.deinit();

    const token_alg = Algorithm.fromStr(header.value.alg) orelse return error.UnsupportedAlgorithm;
    if (token_alg != algorithm) return error.AlgorithmMismatch;

    const last_dot = std.mem.lastIndexOfScalar(u8, token, '.').?;
    const signing_input = token[0..last_dot];

    const sl = algorithm.sigLen();
    var decoded_sig: [64]u8 = undefined;
    try Decoder.decode(decoded_sig[0..sl], encoded_sig);

    switch (algorithm) {
        .HS256 => {
            var expected: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&expected, signing_input, secret);
            if (!std.mem.eql(u8, &expected, decoded_sig[0..32])) return error.InvalidSignature;
        },
        .HS384 => {
            var expected: [48]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha384.create(&expected, signing_input, secret);
            if (!std.mem.eql(u8, &expected, decoded_sig[0..48])) return error.InvalidSignature;
        },
        .HS512 => {
            var expected: [64]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha512.create(&expected, signing_input, secret);
            if (!std.mem.eql(u8, &expected, decoded_sig[0..64])) return error.InvalidSignature;
        },
    }

    return try parseBase64Json(T, allocator, encoded_claims);
}

fn parseBase64Json(comptime T: type, allocator: Allocator, encoded: []const u8) !std.json.Parsed(T) {
    const decoded_len = try Decoder.calcSizeForSlice(encoded);
    const buf = try allocator.alloc(u8, decoded_len);
    defer allocator.free(buf);
    try Decoder.decode(buf, encoded);
    return try std.json.parseFromSlice(T, allocator, buf, .{ .allocate = .alloc_always });
}

fn nowEpoch() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

pub fn extractToken(req: *httpz.Request) ?[]const u8 {
    const auth = req.header("authorization") orelse return null;
    const prefix = "Bearer ";
    if (std.ascii.startsWithIgnoreCase(auth, prefix)) {
        return auth[prefix.len..];
    }
    return null;
}

const JwtAuth = @This();

algorithm: Algorithm,
secret: []const u8,
iss: ?[]const u8 = null,
aud: ?[]const u8 = null,
leeway: i64 = 0,

pub const Config = struct {
    algorithm: Algorithm = .HS256,
    secret: []const u8,
    iss: ?[]const u8 = null,
    aud: ?[]const u8 = null,
    leeway: i64 = 0,
};

pub fn init(config: Config) !JwtAuth {
    return .{
        .algorithm = config.algorithm,
        .secret = config.secret,
        .iss = config.iss,
        .aud = config.aud,
        .leeway = config.leeway,
    };
}

pub fn execute(self: *const JwtAuth, req: *httpz.Request, res: *httpz.Response, executor: anytype) !void {
    const token = extractToken(req) orelse {
        res.status = 401;
        res.body = "missing authorization token";
        return;
    };

    const parsed = decode(Claims, token, req.arena, self.algorithm, self.secret) catch |err| switch (err) {
        error.InvalidSignature, error.AlgorithmMismatch, error.UnsupportedAlgorithm,
        error.MissingHeader, error.MissingPayload, error.MissingSignature => {
            res.status = 401;
            res.body = "invalid token";
            return;
        },
        else => return err,
    };
    defer parsed.deinit();
    const claims = parsed.value;

    const now = nowEpoch();
    if (claims.exp) |exp| {
        if (now >= exp + self.leeway) {
            res.status = 401;
            res.body = "token expired";
            return;
        }
    }

    if (claims.nbf) |nbf| {
        if (now < nbf - self.leeway) {
            res.status = 401;
            res.body = "token not yet valid";
            return;
        }
    }

    if (self.iss) |expected| {
        if (claims.iss) |actual| {
            if (!std.mem.eql(u8, expected, actual)) {
                res.status = 401;
                res.body = "invalid issuer";
                return;
            }
        } else {
            res.status = 401;
            res.body = "missing issuer";
            return;
        }
    }

    if (self.aud) |expected| {
        if (claims.aud) |actual| {
            if (!std.mem.eql(u8, expected, actual)) {
                res.status = 401;
                res.body = "invalid audience";
                return;
            }
        } else {
            res.status = 401;
            res.body = "missing audience";
            return;
        }
    }

    return executor.next();
}

test "jwt: HS256 encode and decode" {
    const claims = Claims{
        .sub = "user123",
        .iss = "test-app",
        .exp = 9999999999,
    };
    const secret = "my-secret-key";

    const token = try encode(std.testing.allocator, claims, .HS256, secret);
    defer std.testing.allocator.free(token);

    const parsed = try decode(Claims, token, std.testing.allocator, .HS256, secret);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("user123", parsed.value.sub.?);
    try std.testing.expectEqualStrings("test-app", parsed.value.iss.?);
    try std.testing.expectEqual(@as(i64, 9999999999), parsed.value.exp.?);
}

test "jwt: HS384 encode and decode" {
    const claims = Claims{ .sub = "test" };
    const secret = "another-secret";

    const token = try encode(std.testing.allocator, claims, .HS384, secret);
    defer std.testing.allocator.free(token);

    const parsed = try decode(Claims, token, std.testing.allocator, .HS384, secret);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("test", parsed.value.sub.?);
}

test "jwt: HS512 encode and decode" {
    const claims = Claims{ .sub = "test" };
    const secret = "yet-another-secret";

    const token = try encode(std.testing.allocator, claims, .HS512, secret);
    defer std.testing.allocator.free(token);

    const parsed = try decode(Claims, token, std.testing.allocator, .HS512, secret);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("test", parsed.value.sub.?);
}

test "jwt: invalid signature" {
    const claims = Claims{ .sub = "user" };
    const token = try encode(std.testing.allocator, claims, .HS256, "secret1");
    defer std.testing.allocator.free(token);

    try std.testing.expectError(error.InvalidSignature, decode(Claims, token, std.testing.allocator, .HS256, "secret2"));
}

test "jwt: algorithm mismatch" {
    const claims = Claims{ .sub = "user" };
    const token = try encode(std.testing.allocator, claims, .HS256, "secret");
    defer std.testing.allocator.free(token);

    try std.testing.expectError(error.AlgorithmMismatch, decode(Claims, token, std.testing.allocator, .HS384, "secret"));
}

test "jwt: tampered token" {
    const claims = Claims{ .sub = "user" };
    const token = try encode(std.testing.allocator, claims, .HS256, "secret");
    defer std.testing.allocator.free(token);

    var buf = try std.testing.allocator.dupe(u8, token);
    defer std.testing.allocator.free(buf);
    buf[buf.len - 1] = if (buf[buf.len - 1] == 'A') 'B' else 'A';

    try std.testing.expectError(error.InvalidSignature, decode(Claims, buf, std.testing.allocator, .HS256, "secret"));
}

test "jwt: custom claims struct" {
    const CustomClaims = struct {
        sub: []const u8,
        name: []const u8,
        admin: bool,
    };

    const claims = CustomClaims{
        .sub = "123",
        .name = "John Doe",
        .admin = true,
    };

    const token = try encode(std.testing.allocator, claims, .HS256, "secret");
    defer std.testing.allocator.free(token);

    const parsed = try decode(CustomClaims, token, std.testing.allocator, .HS256, "secret");
    defer parsed.deinit();

    try std.testing.expectEqualStrings("123", parsed.value.sub);
    try std.testing.expectEqualStrings("John Doe", parsed.value.name);
    try std.testing.expectEqual(true, parsed.value.admin);
}

test "jwt: missing parts" {
    try std.testing.expectError(error.MissingHeader, decode(Claims, "", std.testing.allocator, .HS256, "s"));
    try std.testing.expectError(error.MissingPayload, decode(Claims, "a", std.testing.allocator, .HS256, "s"));
    try std.testing.expectError(error.MissingSignature, decode(Claims, "a.b", std.testing.allocator, .HS256, "s"));
}

test "jwt: encode does not leak" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn f(allocator: Allocator) !void {
            const claims = Claims{ .sub = "test", .iss = "leak-check" };
            const token = try encode(allocator, claims, .HS256, "secret");
            allocator.free(token);
        }
    }.f, .{});
}

test "jwt: decode does not leak" {
    const claims = Claims{ .sub = "test" };
    const token = try encode(std.testing.allocator, claims, .HS256, "secret");
    defer std.testing.allocator.free(token);

    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn f(allocator: Allocator) !void {
            const parsed = try decode(Claims, token, allocator, .HS256, "secret") catch return;
            parsed.deinit();
        }
    }.f, .{});
}

test "jwt: extractToken" {
    const testing = std.testing;
    const t = @import("../t.zig");

    {
        var ctx = t.Context.init(.{});
        defer ctx.deinit();
        var req = ctx.request();
        req.headers.add("authorization", "Bearer my-token") catch unreachable;

        const extracted = extractToken(&req);
        try testing.expectEqualStrings("my-token", extracted.?);
    }

    {
        var ctx = t.Context.init(.{});
        defer ctx.deinit();
        var req = ctx.request();
        req.headers.add("authorization", "bearer my-token") catch unreachable;

        const extracted = extractToken(&req);
        try testing.expectEqualStrings("my-token", extracted.?);
    }

    {
        var ctx = t.Context.init(.{});
        defer ctx.deinit();
        var req = ctx.request();

        const extracted = extractToken(&req);
        try testing.expectEqual(@as(?[]const u8, null), extracted);
    }

    {
        var ctx = t.Context.init(.{});
        defer ctx.deinit();
        var req = ctx.request();
        req.headers.add("authorization", "Basic dXNlcjpwYXNz") catch unreachable;

        const extracted = extractToken(&req);
        try testing.expectEqual(@as(?[]const u8, null), extracted);
    }
}
