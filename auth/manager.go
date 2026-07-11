package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/auth/models"
	"github.com/weedbox/user-modules/user"
)

const (
	// maxRetries is the maximum number of retries for generating unique refresh token
	maxRetries = 3
)

// CustomClaims represents JWT claims with user information
type CustomClaims struct {
	jwt.RegisteredClaims
	UserID      string   `json:"user_id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Roles       []string `json:"roles"`
	DisplayName string   `json:"display_name"`
}

// Login authenticates a user and returns a token pair
func (m *AuthManager) Login(ctx context.Context, identifier, password string) (*TokenPair, error) {
	// Authenticate user via user module
	u, err := m.Params().User.Authenticate(ctx, identifier, password)
	if err != nil {
		if err == user.ErrInvalidCredentials {
			return nil, ErrInvalidCredentials
		}
		m.Logger().Error("Failed to authenticate user", zap.Error(err))
		return nil, ErrOperationFailed
	}

	// Check user status
	if u.Status != "active" {
		return nil, ErrUserInactive
	}

	// Generate token pair
	tokenPair, err := m.generateTokenPair(ctx, u)
	if err != nil {
		m.Logger().Error("Failed to generate token pair", zap.Error(err))
		return nil, ErrOperationFailed
	}

	return tokenPair, nil
}

// LoginWithTrustedIdentity issues a token pair for a user whose identity has
// already been verified by the caller through a trusted channel (e.g. an OAuth
// provider callback). It performs no password check, so callers MUST only pass
// user IDs they have authenticated themselves.
func (m *AuthManager) LoginWithTrustedIdentity(ctx context.Context, userID string) (*TokenPair, error) {
	u, err := m.Params().User.Get(ctx, userID)
	if err != nil {
		if err == user.ErrNotFound {
			return nil, ErrInvalidCredentials
		}
		m.Logger().Error("Failed to load user for trusted identity login", zap.Error(err))
		return nil, ErrOperationFailed
	}

	// Check user status
	if u.Status != "active" {
		return nil, ErrUserInactive
	}

	// Generate token pair
	tokenPair, err := m.generateTokenPair(ctx, u)
	if err != nil {
		m.Logger().Error("Failed to generate token pair", zap.Error(err))
		return nil, ErrOperationFailed
	}

	return tokenPair, nil
}

// RefreshTokens validates a refresh token and returns a new token pair
func (m *AuthManager) RefreshTokens(ctx context.Context, refreshToken string) (*TokenPair, error) {
	db := m.Params().Database.GetDB()

	// Find refresh token in database
	var storedToken models.RefreshToken
	if err := db.WithContext(ctx).Where("token = ?", refreshToken).First(&storedToken).Error; err != nil {
		return nil, ErrTokenNotFound
	}

	// Check if revoked
	if storedToken.Revoked {
		return nil, ErrTokenRevoked
	}

	// Check if expired
	if time.Now().After(storedToken.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Get user information
	u, err := m.Params().User.Get(ctx, storedToken.UserID)
	if err != nil {
		if err == user.ErrNotFound {
			// Revoke the token if user no longer exists
			db.WithContext(ctx).Model(&storedToken).Update("revoked", true)
			return nil, ErrInvalidToken
		}
		m.Logger().Error("Failed to get user", zap.Error(err))
		return nil, ErrOperationFailed
	}

	// Check user status
	if u.Status != "active" {
		// Revoke token for inactive users
		db.WithContext(ctx).Model(&storedToken).Update("revoked", true)
		return nil, ErrUserInactive
	}

	// Revoke old refresh token (rotation)
	if err := db.WithContext(ctx).Model(&storedToken).Update("revoked", true).Error; err != nil {
		m.Logger().Error("Failed to revoke old refresh token", zap.Error(err))
		return nil, ErrOperationFailed
	}

	// Generate new token pair
	tokenPair, err := m.generateTokenPair(ctx, u)
	if err != nil {
		m.Logger().Error("Failed to generate token pair", zap.Error(err))
		return nil, ErrOperationFailed
	}

	return tokenPair, nil
}

// Logout revokes a refresh token
func (m *AuthManager) Logout(ctx context.Context, refreshToken string) error {
	db := m.Params().Database.GetDB()

	result := db.WithContext(ctx).
		Model(&models.RefreshToken{}).
		Where("token = ?", refreshToken).
		Update("revoked", true)

	if result.Error != nil {
		m.Logger().Error("Failed to revoke refresh token", zap.Error(result.Error))
		return ErrOperationFailed
	}

	if result.RowsAffected == 0 {
		return ErrTokenNotFound
	}

	return nil
}

// LogoutAll revokes all refresh tokens for a user
func (m *AuthManager) LogoutAll(ctx context.Context, userID string) error {
	db := m.Params().Database.GetDB()

	if err := db.WithContext(ctx).
		Model(&models.RefreshToken{}).
		Where("user_id = ? AND revoked = ?", userID, false).
		Update("revoked", true).Error; err != nil {
		m.Logger().Error("Failed to revoke all refresh tokens", zap.Error(err))
		return ErrOperationFailed
	}

	return nil
}

// ValidateAccessToken validates an access token and returns the claims
func (m *AuthManager) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.jwtSecret, nil
	})

	if err != nil {
		if err == jwt.ErrTokenExpired {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return &AccessTokenClaims{
		UserID:      claims.UserID,
		Username:    claims.Username,
		Email:       claims.Email,
		Roles:       claims.Roles,
		DisplayName: claims.DisplayName,
	}, nil
}

// GetActiveRefreshTokens returns all active refresh tokens for a user
func (m *AuthManager) GetActiveRefreshTokens(ctx context.Context, userID string) ([]*RefreshTokenInfo, error) {
	db := m.Params().Database.GetDB()

	var tokens []models.RefreshToken
	if err := db.WithContext(ctx).
		Where("user_id = ? AND revoked = ? AND expires_at > ?", userID, false, time.Now()).
		Order("created_at DESC").
		Find(&tokens).Error; err != nil {
		m.Logger().Error("Failed to get active refresh tokens", zap.Error(err))
		return nil, ErrOperationFailed
	}

	result := make([]*RefreshTokenInfo, len(tokens))
	for i, t := range tokens {
		result[i] = &RefreshTokenInfo{
			ID:        t.ID,
			UserID:    t.UserID,
			ExpiresAt: t.ExpiresAt,
			Revoked:   t.Revoked,
			CreatedAt: t.CreatedAt,
		}
	}

	return result, nil
}

// CleanupExpiredTokens removes expired refresh tokens from the database
func (m *AuthManager) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	db := m.Params().Database.GetDB()

	result := db.WithContext(ctx).
		Where("expires_at < ? OR revoked = ?", time.Now(), true).
		Delete(&models.RefreshToken{})

	if result.Error != nil {
		m.Logger().Error("Failed to cleanup expired tokens", zap.Error(result.Error))
		return 0, ErrOperationFailed
	}

	return result.RowsAffected, nil
}

// generateRefreshToken generates a refresh token with timestamp + random bytes
// Format: base64(timestamp_nanos[8 bytes] + random[24 bytes])
func (m *AuthManager) generateRefreshToken() (string, error) {
	// 8 bytes for timestamp (nanoseconds) + 24 bytes random = 32 bytes total
	tokenBytes := make([]byte, 32)

	// First 8 bytes: current timestamp in nanoseconds
	timestamp := time.Now().UnixNano()
	binary.BigEndian.PutUint64(tokenBytes[:8], uint64(timestamp))

	// Remaining 24 bytes: random data
	if _, err := rand.Read(tokenBytes[8:]); err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(tokenBytes), nil
}

// isUniqueConstraintError checks if the error is a unique constraint violation
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "unique") || strings.Contains(errStr, "duplicate")
}

// generateTokenPair creates a new access token and refresh token
func (m *AuthManager) generateTokenPair(ctx context.Context, u *user.User) (*TokenPair, error) {
	now := time.Now()
	accessExpiresAt := now.Add(m.accessTokenExpiry)
	refreshExpiresAt := now.Add(m.refreshTokenExpiry)

	// Create access token
	claims := CustomClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   u.ID,
			ExpiresAt: jwt.NewNumericDate(accessExpiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
		UserID:      u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Roles:       u.Roles,
		DisplayName: u.DisplayName,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	accessToken, err := token.SignedString(m.jwtSecret)
	if err != nil {
		return nil, err
	}

	db := m.Params().Database.GetDB()

	// Try to generate and store refresh token with retry mechanism
	var refreshToken string
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		// Generate refresh token with timestamp + random
		refreshToken, err = m.generateRefreshToken()
		if err != nil {
			return nil, err
		}

		// Store refresh token in database
		refreshTokenRecord := &models.RefreshToken{
			ID:        uuid.Must(uuid.NewV7()).String(),
			UserID:    u.ID,
			Token:     refreshToken,
			ExpiresAt: refreshExpiresAt,
			Revoked:   false,
			CreatedAt: time.Now(), // Use current time for each retry
		}

		err = db.WithContext(ctx).Create(refreshTokenRecord).Error
		if err == nil {
			// Success
			return &TokenPair{
				AccessToken:      accessToken,
				RefreshToken:     refreshToken,
				TokenType:        "Bearer",
				ExpiresIn:        int64(m.accessTokenExpiry.Seconds()),
				ExpiresAt:        accessExpiresAt,
				RefreshExpiresAt: refreshExpiresAt,
			}, nil
		}

		lastErr = err

		// If it's a unique constraint error, retry with a new token
		if isUniqueConstraintError(err) {
			m.Logger().Warn("Refresh token collision, retrying",
				zap.Int("attempt", i+1),
				zap.Int("max_retries", maxRetries))
			continue
		}

		// For other errors, return immediately
		return nil, err
	}

	// All retries exhausted
	m.Logger().Error("Failed to generate unique refresh token after retries",
		zap.Int("retries", maxRetries),
		zap.Error(lastErr))
	return nil, errors.New("failed to generate refresh token")
}
