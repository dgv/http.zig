const std = @import("std");
const httpz = @import("httpz");

const PORT = 8812;

var tokens = std.StringHashMap([]const u8).init(std.heap.page_allocator);

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var handler = Handler{};
    var server = try httpz.Server(*Handler).init(init.io, allocator, .{ .address = .localhost(PORT) }, &handler);

    defer server.deinit();
    defer server.stop();

    const jwt_mw = try server.middleware(httpz.middleware.Jwt, .{
        .secret = "change-me-in-production",
        .iss = "auth-example",
    });

    var router = try server.router(.{});

    router.post("/login", login, .{ .middlewares = &.{jwt_mw} });
    router.post("/token/refresh", refresh, .{});
    router.get("/protected", protected, .{ .middlewares = &.{jwt_mw} });
    router.get("/admin", admin, .{ .middlewares = &.{jwt_mw} });

    std.debug.print("listening http://localhost:{d}/\n", .{PORT});
    std.debug.print("  POST /login         (body: {{\"username\":\"user\",\"password\":\"pass\"}})\n", .{});
    std.debug.print("  POST /token/refresh (body: {{\"token\":\"...\"}})\n", .{});
    std.debug.print("  GET  /protected     (Authorization: Bearer <token>)\n", .{});
    std.debug.print("  GET  /admin         (Authorization: Bearer <token>)\n", .{});

    try server.listen();
}

fn epochNow() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @intCast(ts.sec);
}

const User = struct {
    id: []const u8,
    username: []const u8,
    role: []const u8,
};

fn verifyCredentials(username: []const u8, password: []const u8) ?User {
    if (std.mem.eql(u8, username, "user") and std.mem.eql(u8, password, "pass")) {
        return .{ .id = "1", .username = "user", .role = "member" };
    }
    if (std.mem.eql(u8, username, "admin") and std.mem.eql(u8, password, "admin")) {
        return .{ .id = "2", .username = "admin", .role = "admin" };
    }
    return null;
}

fn login(ctx: *Context, req: *httpz.Request, res: *httpz.Response) !void {
    _ = ctx;

    const LoginBody = struct {
        username: []const u8,
        password: []const u8,
    };

    const body = req.body() orelse {
        res.status = 400;
        res.body = "missing request body";
        return;
    };

    const parsed = std.json.parseFromSlice(LoginBody, res.arena, body, .{ .allocate = .alloc_always }) catch {
        res.status = 400;
        res.body = "invalid json";
        return;
    };

    const user = verifyCredentials(parsed.value.username, parsed.value.password) orelse {
        res.status = 401;
        res.body = "invalid credentials";
        return;
    };

    const now = epochNow();
    const access_jti = try std.fmt.allocPrint(res.arena, "acc-{s}", .{user.id});
    const access_claims = httpz.middleware.Jwt.Claims{
        .sub = user.id,
        .iss = "auth-example",
        .iat = now,
        .exp = now + 900,
        .jti = access_jti,
    };
    const access_token = try httpz.middleware.Jwt.encode(res.arena, access_claims, .HS256, "change-me-in-production");

    const refresh_jti = try std.fmt.allocPrint(res.arena, "ref-{s}", .{user.id});
    const refresh_claims = httpz.middleware.Jwt.Claims{
        .sub = user.id,
        .iss = "auth-example",
        .iat = now,
        .exp = now + 604800,
        .jti = refresh_jti,
    };
    const refresh_token = try httpz.middleware.Jwt.encode(res.arena, refresh_claims, .HS256, "change-me-in-production");

    try tokens.put(access_claims.jti.?, user.id);
    try tokens.put(refresh_claims.jti.?, user.id);

    try res.json(.{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .user = .{ .id = user.id, .username = user.username, .role = user.role },
    }, .{});
}

fn refresh(ctx: *Context, req: *httpz.Request, res: *httpz.Response) !void {
    _ = ctx;
    const RefreshBody = struct {
        token: []const u8,
    };

    const body = req.body() orelse {
        res.status = 400;
        res.body = "missing request body";
        return;
    };

    const parsed = std.json.parseFromSlice(RefreshBody, res.arena, body, .{ .allocate = .alloc_always }) catch {
        res.status = 400;
        res.body = "invalid json";
        return;
    };

    const old_claims = httpz.middleware.Jwt.decode(httpz.middleware.Jwt.Claims, parsed.value.token, res.arena, .HS256, "change-me-in-production") catch {
        res.status = 401;
        res.body = "invalid refresh token";
        return;
    };

    const jti = old_claims.value.jti orelse {
        res.status = 401;
        res.body = "invalid token id";
        return;
    };

    const user_id = tokens.get(jti) orelse {
        res.status = 401;
        res.body = "token revoked";
        return;
    };

    _ = tokens.remove(jti);

    const now = epochNow();
    const access_jti = try std.fmt.allocPrint(res.arena, "acc-{s}", .{user_id});
    const access_claims = httpz.middleware.Jwt.Claims{
        .sub = user_id,
        .iss = "auth-example",
        .iat = now,
        .exp = now + 900,
        .jti = access_jti,
    };
    const access_token = try httpz.middleware.Jwt.encode(res.arena, access_claims, .HS256, "change-me-in-production");

    const refresh_jti = try std.fmt.allocPrint(res.arena, "ref-{s}", .{user_id});
    const refresh_claims = httpz.middleware.Jwt.Claims{
        .sub = user_id,
        .iss = "auth-example",
        .iat = now,
        .exp = now + 604800,
        .jti = refresh_jti,
    };
    const refresh_token = try httpz.middleware.Jwt.encode(res.arena, refresh_claims, .HS256, "change-me-in-production");

    try tokens.put(access_claims.jti.?, user_id);
    try tokens.put(refresh_claims.jti.?, user_id);

    try res.json(.{
        .access_token = access_token,
        .refresh_token = refresh_token,
    }, .{});
}

const Handler = struct {
    pub fn dispatch(self: *Handler, action: httpz.Action(*Context), req: *httpz.Request, res: *httpz.Response) !void {
        const access_token = httpz.middleware.Jwt.extractToken(req);

        var claims: ?httpz.middleware.Jwt.Claims = null;
        if (access_token) |token| {
            if (httpz.middleware.Jwt.decode(httpz.middleware.Jwt.Claims, token, req.arena, .HS256, "change-me-in-production")) |parsed| {
                claims = parsed.value;
            } else |_| {}
        }

        var ctx = Context{
            .handler = self,
            .user_id = if (claims) |c| c.sub else null,
        };

        try action(&ctx, req, res);
    }

    pub fn notFound(_: *Handler, _: *httpz.Request, res: *httpz.Response) !void {
        res.status = 404;
        res.body = "{\"error\":\"not found\"}";
    }
};

const Context = struct {
    handler: *Handler,
    user_id: ?[]const u8,
};

fn protected(ctx: *Context, _: *httpz.Request, res: *httpz.Response) !void {
    try res.json(.{
        .message = "you have accessed a protected resource",
        .user_id = ctx.user_id,
    }, .{});
}

fn admin(ctx: *Context, _: *httpz.Request, res: *httpz.Response) !void {
    if (ctx.user_id == null) {
        res.status = 401;
        res.body = "{\"error\":\"unauthorized\"}";
        return;
    }

    try res.json(.{
        .message = "admin dashboard",
        .user_id = ctx.user_id,
        .secret = "the nuclear codes are 0000",
    }, .{});
}
