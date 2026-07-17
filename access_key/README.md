# access_key

A weedbox module for user-owned API access keys. Users create long-lived keys that external programs later exchange for standard JWT token pairs (see `access_key_apis`). Keys are stored as SHA-256 hashes — the plaintext is returned exactly once at creation and can never be recovered.

## Overview

The AccessKey module handles:

- **Create**: Generates a key as `<prefix>` + 43 characters of base64url-encoded 256-bit randomness, stores only its SHA-256 hash, and returns the plaintext once
- **List**: Returns a user's keys (metadata only — display prefix, expiry, last-used time)
- **Delete**: Removes one of the user's own keys; the `user_id` condition inherently prevents deleting someone else's key
- **Verify**: Resolves a plaintext key back to its metadata, rejecting unknown or expired keys, and updates `last_used_at` best-effort

## Security Design

- The plaintext key is a 256-bit random value, so offline brute force is infeasible. A fast SHA-256 equality lookup is therefore sufficient — no slow hash (bcrypt) is needed, and the hash column doubles as a unique index.
- `Verify` distinguishes `ErrInvalidKey` and `ErrKeyExpired` internally, but API layers should collapse both (and inactive-owner failures) into one generic 401 to avoid giving probing hints.
- The stored `Prefix` is the configured prefix plus the first 8 characters of the random part — enough for users to tell keys apart, far too short to matter for guessing.
- A `nil` `ExpiresAt` means the key never expires; revoking all of a user's keys is done by deactivating the account (tokens issued via `auth` check account status).

## Dependencies

| Dependency | Source | Description |
|------------|--------|-------------|
| `database.DatabaseConnector` | `common-modules` | GORM database connection |

## Module Registration

```go
access_key.Module("access_key")
```

## Configuration

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `key_prefix` | `string` | `"ak_"` | Prefix prepended to every generated key, e.g. brand it as `"myapp_"`. **Changing it invalidates previously issued keys** — `Verify` rejects keys that do not carry the current prefix. |

## Data Model

The `AccessKey` model (`access_key/models/access_key.go`) maps to the `access_keys` table:

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `ID` | `varchar(36)` | Primary key | UUID v7 |
| `UserID` | `varchar(36)` | Not null, indexed | Owner user ID |
| `Name` | `varchar(255)` | Not null | User-chosen label |
| `Prefix` | `varchar(32)` | Not null | Display prefix (configured prefix + first 8 random chars) |
| `SecretHash` | `varchar(64)` | Unique, not null | SHA-256 hex of the plaintext key; never serialized to JSON |
| `ExpiresAt` | `timestamp` | Nullable | Expiration time; `NULL` = never expires |
| `LastUsedAt` | `timestamp` | Nullable | Last successful `Verify`, best-effort |
| `CreatedAt` | `timestamp` | Indexed | Creation time |
| `UpdatedAt` | `timestamp` | | Last update time |

## API Reference

### AccessKeyManager Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `Create` | `Create(ctx context.Context, userID, name string, expiresAt *time.Time) (*AccessKey, string, error)` | Issues a key; returns metadata plus the plaintext (once). `nil` expiry = never expires; a non-future expiry is `ErrInvalidInput` |
| `List` | `List(ctx context.Context, userID string) ([]*AccessKey, error)` | All keys owned by the user, newest first |
| `Delete` | `Delete(ctx context.Context, userID, id string) error` | Deletes the user's own key; `ErrNotFound` if no row matched |
| `Verify` | `Verify(ctx context.Context, plaintext string) (*AccessKey, error)` | Validates a plaintext key; `ErrInvalidKey` on format/hash miss, `ErrKeyExpired` on expiry |

### Errors

| Error | Meaning |
|-------|---------|
| `ErrNotFound` | Key does not exist (or is not owned by the user) |
| `ErrInvalidInput` | Missing user ID/name, or expiry not in the future |
| `ErrInvalidKey` | Plaintext has the wrong prefix or matches no stored hash |
| `ErrKeyExpired` | Key exists but its expiry has passed |

## Usage Example

```go
// Create a key that never expires
key, plaintext, err := accessKeyManager.Create(ctx, userID, "CI pipeline", nil)
// plaintext is e.g. "ak_3J9x..." — show it to the user now; it cannot be recovered

// Later, an external program presents the plaintext
key, err = accessKeyManager.Verify(ctx, plaintext)
// key.UserID identifies the owner; hand it to auth.LoginWithTrustedIdentity
```
