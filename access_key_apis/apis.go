package access_key_apis

import (
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/access_key"
	"github.com/weedbox/user-modules/auth"
)

// @Summary Create my access key
// @Description Create a new access key for the authenticated user. The plaintext key is returned only once in this response and cannot be retrieved again — store it securely. Pass expires_at (RFC3339) for an expiring key, or omit it for a key that stays valid until deleted.
// @Tags My Access Keys
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param body body CreateRequestBody true "Access key data"
// @Success 201 {object} CreateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /me/access-key [post]
// @BasePath /apis/v1
func (m *AccessKeyAPIs) create(c *gin.Context) {
	userID, ok := auth.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	var req CreateRequest
	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var expiresAt *time.Time
	if req.Body.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.Body.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at must be an RFC3339 timestamp"})
			return
		}
		expiresAt = &t
	}

	ctx := c.Request.Context()
	key, plaintext, err := m.Params().AccessKey.Create(ctx, userID, req.Body.Name, expiresAt)
	if err != nil {
		if errors.Is(err, access_key.ErrInvalidInput) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		m.Logger().Error("Failed to create access key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, CreateResponse{
		Message:   "access key created successfully",
		Key:       plaintext,
		AccessKey: m.toEntry(key),
	})
}

// @Summary List my access keys
// @Description List all access keys owned by the authenticated user. Only metadata is returned — the plaintext key is shown once at creation and cannot be recovered.
// @Tags My Access Keys
// @Produce json
// @Security BearerAuth
// @Success 200 {object} ListResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /me/access-keys [get]
// @BasePath /apis/v1
func (m *AccessKeyAPIs) list(c *gin.Context) {
	userID, ok := auth.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	ctx := c.Request.Context()
	keys, err := m.Params().AccessKey.List(ctx, userID)
	if err != nil {
		m.Logger().Error("Failed to list access keys", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	entries := make([]*AccessKeyEntry, len(keys))
	for i, k := range keys {
		entries[i] = m.toEntry(k)
	}

	c.JSON(http.StatusOK, ListResponse{AccessKeys: entries})
}

// @Summary Delete my access key
// @Description Delete an access key owned by the authenticated user. External programs holding this key can no longer exchange it for tokens; already-issued tokens stay valid until they expire.
// @Tags My Access Keys
// @Produce json
// @Security BearerAuth
// @Param id path string true "Access key ID"
// @Success 200 {object} DeleteResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /me/access-key/{id} [delete]
// @BasePath /apis/v1
func (m *AccessKeyAPIs) delete(c *gin.Context) {
	userID, ok := auth.GetUserID(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
		return
	}

	var req DeleteRequest
	if err := c.ShouldBindUri(&req.URI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	if err := m.Params().AccessKey.Delete(ctx, userID, req.URI.ID); err != nil {
		if errors.Is(err, access_key.ErrNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "Access key not found"})
			return
		}
		m.Logger().Error("Failed to delete access key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, DeleteResponse{Message: "access key deleted successfully"})
}

// @Summary Exchange an access key for tokens
// @Description Authenticate an external program with an access key and return a standard token pair (same shape as /auth/login). The issued tokens carry the key owner's full identity and roles; use the access token as a Bearer token on subsequent API calls, and /auth/refresh to renew. Invalid, expired, or deleted keys — and keys whose owner is inactive — are all rejected with 401.
// @Tags Auth
// @Accept json
// @Produce json
// @Param body body ExchangeRequestBody true "Access key"
// @Success 200 {object} ExchangeResponse
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /auth/access-key [post]
// @BasePath /apis/v1
func (m *AccessKeyAPIs) exchange(c *gin.Context) {
	var req ExchangeRequest
	if err := c.ShouldBindJSON(&req.Body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()

	key, err := m.Params().AccessKey.Verify(ctx, req.Body.AccessKey)
	if err != nil {
		// Malformed, unknown, and expired keys all yield the same 401 so the
		// endpoint leaks nothing that helps probing.
		if errors.Is(err, access_key.ErrInvalidKey) || errors.Is(err, access_key.ErrKeyExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access key"})
			return
		}
		m.Logger().Error("Failed to verify access key", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// The key itself is the proof of identity: have auth issue a standard
	// token pair for the key owner (includes the account-active check).
	tokenPair, err := m.Params().Auth.LoginWithTrustedIdentity(ctx, key.UserID)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) || errors.Is(err, auth.ErrUserInactive) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid access key"})
			return
		}
		m.Logger().Error("Failed to issue tokens for access key", zap.String("key_id", key.ID), zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, ExchangeResponse{
		Message: "authenticated",
		Token: TokenResponse{
			AccessToken:      tokenPair.AccessToken,
			RefreshToken:     tokenPair.RefreshToken,
			TokenType:        tokenPair.TokenType,
			ExpiresIn:        tokenPair.ExpiresIn,
			ExpiresAt:        tokenPair.ExpiresAt,
			RefreshExpiresAt: tokenPair.RefreshExpiresAt,
		},
	})
}

func (m *AccessKeyAPIs) toEntry(k *access_key.AccessKey) *AccessKeyEntry {
	entry := &AccessKeyEntry{
		ID:        k.ID,
		Name:      k.Name,
		Prefix:    k.Prefix,
		CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339),
	}
	if k.ExpiresAt != nil {
		s := k.ExpiresAt.UTC().Format(time.RFC3339)
		entry.ExpiresAt = &s
	}
	if k.LastUsedAt != nil {
		s := k.LastUsedAt.UTC().Format(time.RFC3339)
		entry.LastUsedAt = &s
	}
	return entry
}
