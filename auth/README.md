# auth

A weedbox module for JWT-based authentication. Provides login/logout, access token generation, refresh token rotation, and Gin middleware for token validation and permission checking.

## Overview

The Auth module handles:

- **Login**: Authenticates credentials via the `user` module, returns a JWT access token + database-backed refresh token
- **Token Refresh**: Validates refresh tokens and issues new token pairs (with automatic rotation — old refresh tokens are revoked)
- **Logout**: Revokes refresh tokens (single or all sessions)
- **Token Validation**: Validates JWT access tokens and extracts user claims
- **Middleware**: Two-layer Gin middleware for authentication and authorization

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `database.DatabaseConnector` | `common-modules` | GORM database connection |
| `user.UserManager` | `user-modules/user` | User authentication and lookup |
| `rbac.RBACManager` | `user-modules/rbac` | Permission checking |

## Module Registration

```go
auth.Module("auth")
```

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `jwt_secret` | `string` | `"change-this-secret-in-production"` | HMAC secret for signing JWTs |
| `access_token_expiry` | `duration` | `"15m"` | Access token lifetime |
| `refresh_token_expiry` | `duration` | `"168h"` (7 days) | Refresh token lifetime |
| `issuer` | `string` | `"weedbox"` | JWT issuer claim |
| `mode` | `string` | `"standalone"` | Identity trust mode: `"standalone"` or `"gateway"` (see [Security: identity trust modes](#security-identity-trust-modes)) |
| `trusted_header_secret` | `string` | `""` | Gateway mode only: when set, an inbound `X-User-Info` is trusted only if the request carries a matching `X-Gateway-Secret` header |

**Important:** Always override `jwt_secret` in production. Deployments behind a trusted gateway that injects `X-User-Info` **must** set `mode = "gateway"` — otherwise the injected identity is stripped. See [Security: identity trust modes](#security-identity-trust-modes).

## Data Model

The `RefreshToken` model (`auth/models/refresh_token.go`) maps to the `refresh_tokens` table:

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `ID` | `varchar(36)` | Primary key | UUID v7 |
| `UserID` | `varchar(36)` | Not null, indexed | Owner user ID |
| `Token` | `varchar(512)` | Unique, not null | The refresh token string |
| `ExpiresAt` | `timestamp` | Not null, indexed | Expiration time |
| `Revoked` | `bool` | Default: `false` | Whether the token has been revoked |
| `CreatedAt` | `timestamp` | Indexed | Creation time |

## JWT Claims

Access tokens contain the following custom claims:

```json
{
  "iss": "weedbox",
  "sub": "user-uuid",
  "exp": 1234567890,
  "iat": 1234567890,
  "jti": "unique-token-id",
  "user_id": "user-uuid",
  "username": "admin",
  "email": "admin@localhost",
  "roles": ["admin"],
  "display_name": "System Administrator"
}
```

## API Reference

### AuthManager Methods

**Authentication:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `Login` | `(ctx, identifier, password string) (*TokenPair, error)` | Authenticate and return token pair |
| `RefreshTokens` | `(ctx, refreshToken string) (*TokenPair, error)` | Refresh tokens (rotates refresh token) |
| `Logout` | `(ctx, refreshToken string) error` | Revoke a single refresh token |
| `LogoutAll` | `(ctx, userID string) error` | Revoke all refresh tokens for a user |

**Token Validation:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `ValidateAccessToken` | `(tokenString string) (*AccessTokenClaims, error)` | Validate JWT and extract claims |

**Token Management:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `GetActiveRefreshTokens` | `(ctx, userID string) ([]*RefreshTokenInfo, error)` | List active refresh tokens for a user |
| `CleanupExpiredTokens` | `(ctx) (int64, error)` | Remove expired/revoked tokens from DB |

**Middleware:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `GetMiddleware` | `(name string) interface{}` | Get middleware by name (see below) |

### Middleware

The `GetMiddleware` method returns two types of middleware:

#### `"authenticate"` — Token Validation Middleware

Returns `gin.HandlerFunc`. This middleware:

1. Establishes trust in the inbound `X-User-Info` header per the configured `mode`:
   - **standalone** (default): strips any client-supplied `X-User-Info` — identity may only come from a token this service validates in the next steps.
   - **gateway**: keeps the inbound `X-User-Info` (injected by a trusted upstream); if `trusted_header_secret` is set, keeps it only when `X-Gateway-Secret` matches, otherwise strips it.
2. Reads the `Authorization: Bearer <token>` header
3. If no token is provided, passes through (identity, if any, is the trusted `X-User-Info` from step 1)
4. If a token is provided, validates it and **overwrites** `X-User-Info` with base64-encoded session data derived from the token
5. If the token is invalid or expired, returns `401 Unauthorized`

```go
authMiddleware := authManager.GetMiddleware("authenticate").(gin.HandlerFunc)
router.Use(authMiddleware)
```

#### `"require_permission"` — Permission Check Middleware

Returns `func(string) gin.HandlerFunc`. This middleware:

1. If permission is `"*"` (public endpoint), authentication is **optional**: if a trusted `X-User-Info` is present it is decoded into the Gin context so handlers can personalize, but the request is **never rejected** for missing/malformed identity.
2. Otherwise reads the `X-User-Info` header (set by the `authenticate` middleware)
3. Decodes the session and, when a non-empty permission is given, checks RBAC permissions
4. Sets session data in the Gin context for downstream handlers
5. Returns `401` if not authenticated, `403` if insufficient permissions

> Note: `require_permission("")` (empty string) requires authentication but skips the RBAC check — use it for endpoints that only need "any logged-in user" (e.g. `/me`, self-service resources).

```go
requirePerm := authManager.GetMiddleware("require_permission").(func(string) gin.HandlerFunc)
router.GET("/users", requirePerm("user.list"), listHandler)
router.POST("/public", requirePerm("*"), publicHandler)
```

### Context Helpers

Helper functions to extract session data from the Gin context (set by `require_permission` middleware):

| Function | Signature | Description |
|----------|-----------|-------------|
| `GetSession` | `(c *gin.Context) (*Session, bool)` | Get the full session |
| `GetUserID` | `(c *gin.Context) (string, bool)` | Get the authenticated user's ID |
| `GetUsername` | `(c *gin.Context) (string, bool)` | Get the authenticated user's username |
| `GetRoles` | `(c *gin.Context) ([]string, bool)` | Get the authenticated user's roles |
| `HasRole` | `(c *gin.Context, role string) bool` | Check if user has a specific role |

### Types

**TokenPair:**

```go
type TokenPair struct {
    AccessToken      string
    RefreshToken     string
    TokenType        string    // "Bearer"
    ExpiresIn        int64     // Access token lifetime in seconds
    ExpiresAt        time.Time // Access token expiry timestamp
    RefreshExpiresAt time.Time // Refresh token expiry timestamp
}
```

**Session:**

```go
type Session struct {
    UserID      string
    Username    string
    Email       string
    Roles       []string
    DisplayName string
}
```

### Errors

| Error | Description |
|-------|-------------|
| `ErrInvalidCredentials` | Wrong username/email or password |
| `ErrInvalidToken` | Token is malformed or has an invalid signature |
| `ErrTokenExpired` | Token has expired |
| `ErrTokenRevoked` | Refresh token has been revoked |
| `ErrTokenNotFound` | Refresh token not found in database |
| `ErrUserInactive` | User account is not active |
| `ErrOperationFailed` | General operation failure |

## Architecture: Two-Layer Middleware

The middleware is split into two layers to support ingress/gateway architectures:

```
Request --> [authenticate] --> [require_permission] --> Handler
               |                      |
               v                      v
         Validates JWT          Reads X-User-Info header
         Sets X-User-Info       Checks RBAC permissions
         header                 Sets session in context
```

This design allows:

- Running `authenticate` at the gateway/ingress level
- Forwarding `X-User-Info` to backend services
- Backend services only need `require_permission` to check permissions

## Security: identity trust modes

`X-User-Info` carries the caller's identity **and roles** between the two middleware layers, and `require_permission` trusts it for both authentication and RBAC. Because it is an ordinary request header, a client could forge it — so the `authenticate` middleware must decide when an inbound `X-User-Info` is trustworthy. That decision is the `mode` config:

| Mode | Trust of inbound `X-User-Info` | Use when |
|------|-------------------------------|----------|
| `standalone` (default) | **Never** — stripped on entry; identity comes only from a JWT this service validates | The service validates tokens itself (single service, direct exposure, local/dev) |
| `gateway` | **Trusted** — a trusted upstream injects it (optionally gated by `trusted_header_secret` / `X-Gateway-Secret`) | The service sits behind a gateway that terminates auth and injects `X-User-Info` |

**Requirements for `gateway` mode to be safe:**

1. The service is reachable **only** through the gateway (network policy / mTLS).
2. The gateway **strips** any client-supplied `X-User-Info` before injecting its own.
3. Recommended: set `trusted_header_secret` and have the gateway send the matching `X-Gateway-Secret`, so the service can reject requests that did not originate from the gateway (defense in depth, not reliant on network segmentation alone).

> **Do not** run `standalone`-intended services in `gateway` mode without (1) and (2): trusting an un-stripped `X-User-Info` on a directly reachable service lets any client forge identity and roles (full impersonation + privilege escalation). The default is `standalone` precisely so this trust must be opted into explicitly.

## Example: Using in a Custom Handler

```go
func myHandler(c *gin.Context) {
    // Get authenticated user info
    session, ok := auth.GetSession(c)
    if !ok {
        c.JSON(401, gin.H{"error": "not authenticated"})
        return
    }

    // Use session data
    fmt.Printf("User: %s (roles: %v)\n", session.Username, session.Roles)

    // Check role
    if auth.HasRole(c, "admin") {
        // admin-specific logic
    }
}
```
