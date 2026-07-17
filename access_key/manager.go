package access_key

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"github.com/weedbox/user-modules/access_key/models"
)

// Create issues a new access key for a user and returns the plaintext exactly
// once alongside its metadata. A nil expiresAt means the key never expires.
func (m *AccessKeyManager) Create(ctx context.Context, userID, name string, expiresAt *time.Time) (*AccessKey, string, error) {
	userID = strings.TrimSpace(userID)
	name = strings.TrimSpace(name)
	if userID == "" || name == "" {
		return nil, "", fmt.Errorf("%w: user id and name are required", ErrInvalidInput)
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return nil, "", fmt.Errorf("%w: expiry must be in the future", ErrInvalidInput)
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, "", fmt.Errorf("failed to generate ID: %w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", fmt.Errorf("failed to generate secret: %w", err)
	}
	plaintext := m.keyPrefix + base64.RawURLEncoding.EncodeToString(secret)

	key := models.AccessKey{
		ID:         id.String(),
		UserID:     userID,
		Name:       name,
		Prefix:     displayPrefix(plaintext, m.keyPrefix),
		SecretHash: hashKey(plaintext),
		ExpiresAt:  expiresAt,
	}

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Create(&key).Error; err != nil {
		return nil, "", fmt.Errorf("failed to create access key: %w", err)
	}

	m.Logger().Info("Created access key",
		zap.String("id", key.ID),
		zap.String("user_id", userID),
		zap.String("prefix", key.Prefix),
	)

	return m.toAccessKey(&key), plaintext, nil
}

// List returns all access keys owned by a user (metadata only, nothing that
// can recover the plaintext), newest first.
func (m *AccessKeyManager) List(ctx context.Context, userID string) ([]*AccessKey, error) {
	var keys []models.AccessKey
	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("user_id = ?", userID).Order("created_at DESC").Find(&keys).Error; err != nil {
		return nil, fmt.Errorf("failed to list access keys: %w", err)
	}

	results := make([]*AccessKey, len(keys))
	for i, k := range keys {
		results[i] = m.toAccessKey(&k)
	}
	return results, nil
}

// Delete removes one of the user's own access keys. The user_id condition
// inherently prevents deleting keys that belong to someone else.
func (m *AccessKeyManager) Delete(ctx context.Context, userID, id string) error {
	db := m.Params().Database.GetDB().WithContext(ctx)
	result := db.Where("id = ? AND user_id = ?", id, userID).Delete(&models.AccessKey{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete access key: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return ErrNotFound
	}
	m.Logger().Info("Deleted access key", zap.String("id", id), zap.String("user_id", userID))
	return nil
}

// Verify checks a plaintext access key: on a format match, hash hit, and
// unexpired key it returns the key's metadata, updating last_used_at as a
// best-effort side effect (an update failure does not fail the verification).
func (m *AccessKeyManager) Verify(ctx context.Context, plaintext string) (*AccessKey, error) {
	if !strings.HasPrefix(plaintext, m.keyPrefix) {
		return nil, ErrInvalidKey
	}

	var key models.AccessKey
	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("secret_hash = ?", hashKey(plaintext)).First(&key).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidKey
		}
		return nil, fmt.Errorf("failed to look up access key: %w", err)
	}

	if key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now()) {
		return nil, ErrKeyExpired
	}

	now := time.Now()
	if err := db.Model(&models.AccessKey{}).Where("id = ?", key.ID).Update("last_used_at", now).Error; err != nil {
		m.Logger().Warn("Failed to update access key last_used_at", zap.String("id", key.ID), zap.Error(err))
	}

	return m.toAccessKey(&key), nil
}

// hashKey hashes the plaintext key with SHA-256 (hex). The key itself is a
// 256-bit random value, so offline brute force is infeasible and a fast hash
// used as an equality-lookup index is sufficient — no slow hash (bcrypt)
// needed.
func hashKey(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// displayPrefix keeps the configured prefix plus the first 8 characters of the
// random part — enough for users to tell keys apart, far too short to matter
// for guessing (the random part is 43 characters).
func displayPrefix(plaintext, keyPrefix string) string {
	n := len(keyPrefix) + 8
	if n > len(plaintext) {
		n = len(plaintext)
	}
	return plaintext[:n]
}

func (m *AccessKeyManager) toAccessKey(model *models.AccessKey) *AccessKey {
	return &AccessKey{
		ID:         model.ID,
		UserID:     model.UserID,
		Name:       model.Name,
		Prefix:     model.Prefix,
		ExpiresAt:  model.ExpiresAt,
		LastUsedAt: model.LastUsedAt,
		CreatedAt:  model.CreatedAt,
		UpdatedAt:  model.UpdatedAt,
	}
}
