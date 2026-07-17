# access_key_apis

A weedbox module providing REST API handlers for access keys: self-service key management for authenticated users, plus a public exchange endpoint where external programs trade a key for a standard JWT token pair.

## Overview

The AccessKeyAPIs module provides:

- **Self-service management** (`/me/...`): any authenticated user can list, create, and delete their own keys
- **Token exchange** (`/auth/access-key`): a public endpoint (like `/auth/login`) where the plaintext key itself is the credential; issued tokens carry the key owner's full identity and roles

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `http_server.HTTPServer` | `common-modules` | Gin router |
| `access_key.AccessKeyManager` | `user-modules/access_key` | Key storage and verification (injected as `name:"access_key"`) |
| `auth.AuthManager` | `user-modules/auth` | Middleware + `LoginWithTrustedIdentity` token issuance (injected as `name:"auth"`) |

## Module Registration

```go
access_key.Module("access_key"),
access_key_apis.Module("access_key_apis"),
```

The `Params` struct resolves the managers by the names `access_key` and `auth`, so register those modules under exactly those scopes.

## Endpoints

Base path: `/apis/v1`

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| `GET` | `/me/access-keys` | any authenticated user | List my keys (metadata only) |
| `POST` | `/me/access-key` | any authenticated user | Create a key; plaintext returned once |
| `DELETE` | `/me/access-key/:id` | any authenticated user | Delete my key |
| `POST` | `/auth/access-key` | public (`"*"`) | Exchange a plaintext key for a token pair |

Self-service routes use `requirePerm("")` — a valid session is required but no specific RBAC permission, since access keys are a per-account facility. Tokens issued via the exchange endpoint are equivalent to the key owner logging in: same identity, same roles.

## Request / Response Examples

### Create — `POST /apis/v1/me/access-key`

```json
{ "name": "CI pipeline", "expires_at": "2027-01-01T00:00:00Z" }
```

`expires_at` is optional RFC3339; omit it for a key that never expires. Response (`201`):

```json
{
  "message": "access key created successfully",
  "key": "ak_3J9xQ...full plaintext, shown only once...",
  "access_key": {
    "id": "0197...",
    "name": "CI pipeline",
    "prefix": "ak_3J9xQabc",
    "expires_at": "2027-01-01T00:00:00Z",
    "last_used_at": null,
    "created_at": "2026-07-17T02:00:00Z"
  }
}
```

### List — `GET /apis/v1/me/access-keys`

```json
{ "access_keys": [ { "id": "...", "name": "...", "prefix": "...", "expires_at": null, "last_used_at": null, "created_at": "..." } ] }
```

### Exchange — `POST /apis/v1/auth/access-key`

```json
{ "access_key": "ak_3J9xQ..." }
```

Response (`200`) has the same token block shape as `/auth/login`:

```json
{
  "message": "authenticated",
  "token": {
    "access_token": "eyJ...",
    "refresh_token": "...",
    "token_type": "Bearer",
    "expires_in": 900,
    "expires_at": "2026-07-17T02:15:00Z",
    "refresh_expires_at": "2026-07-24T02:00:00Z"
  }
}
```

Malformed, unknown, expired, or deleted keys — and keys whose owner is inactive — are all rejected with the same `401 {"error": "invalid access key"}` so the endpoint leaks nothing that helps probing. Deleting a key stops future exchanges; already-issued tokens stay valid until they expire.

## External Program Flow

1. User creates a key in the application UI and stores the plaintext securely.
2. The program calls `POST /apis/v1/auth/access-key` with the plaintext and receives a token pair.
3. It sends `Authorization: Bearer <access_token>` on subsequent API calls, and uses `POST /apis/v1/auth/refresh` to renew.
