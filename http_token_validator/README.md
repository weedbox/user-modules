# http_token_validator

An optional weedbox module that globally mounts the `authenticate` middleware on the HTTP server. When included, every incoming HTTP request is checked for a JWT token.

## Overview

This module is a thin wrapper that registers the `auth.AuthManager`'s `authenticate` middleware as a global middleware on the Gin router. It is **optional** — you only need it if you want automatic token validation on all routes.

Without this module, you would need to manually apply the `authenticate` middleware to specific route groups.

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `http_server.HTTPServer` | `common-modules` | Gin HTTP server |
| `auth.AuthManager` | `user-modules/auth` | Provides the authenticate middleware |

## Module Registration

```go
http_token_validator.Module("http_token_validator")
```

## Behavior

On startup, the module:

1. Gets the `authenticate` middleware from `auth.AuthManager`
2. Registers it as global middleware on the HTTP server's router via `router.Use()`

Once mounted, **every** incoming request goes through the authenticate middleware:

- If the request has an `Authorization: Bearer <token>` header, the token is validated
  - Valid token: `X-User-Info` header is set with the user's session data
  - Invalid/expired token: Request is rejected with `401 Unauthorized`
- If the request has **no** `Authorization` header, it passes through without modification

This means unauthenticated requests are still allowed — it's the `require_permission` middleware on individual routes that enforces authentication. The `http_token_validator` simply ensures that **if** a token is present, it is valid.

## When to Use

**Include this module when:**

- You want all routes to automatically validate JWT tokens
- You are building a standard server where the authenticate middleware should run before any route handler
- You want the `X-User-Info` header to be available for all downstream handlers

**Skip this module when:**

- You want to selectively apply token validation to specific route groups
- You are behind an ingress/gateway that already handles token validation
- You want to manually control middleware ordering

## Example: Manual Alternative

If you don't use this module, you can manually apply the middleware:

```go
// In your own module's OnStart
router := httpServer.GetRouter()
authMiddleware := authManager.GetMiddleware("authenticate").(gin.HandlerFunc)

// Apply to specific route group
apiGroup := router.Group("/apis/v1")
apiGroup.Use(authMiddleware)
```
