package user

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/spf13/viper"
	"github.com/weedbox/queryhelper"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/weedbox/user-modules/user/models"
)

// Create creates a new user with hashed password
func (m *UserManager) Create(ctx context.Context, cfg *UserConfig) (*User, error) {
	// Validate password
	minPasswordLength := viper.GetInt(m.GetConfigPath("min_password_length"))
	if len(cfg.Password) < minPasswordLength {
		return nil, ErrPasswordTooShort
	}

	// Generate UUID v7
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID: %w", err)
	}

	// Hash password with bcrypt (salt is automatically generated and embedded)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(cfg.Password), m.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := models.User{
		ID:           id.String(),
		Username:     cfg.Username,
		Email:        cfg.Email,
		PasswordHash: string(passwordHash),
		DisplayName:  cfg.DisplayName,
		Roles:        cfg.Roles,
		Status:       cfg.Status,
	}

	// Set defaults
	if len(user.Roles) == 0 {
		user.Roles = []string{"user"}
	}
	if user.Status == "" {
		user.Status = "active"
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Create(&user).Error; err != nil {
		// Handle uniqueness constraint error
		if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "UNIQUE constraint failed") {
			if strings.Contains(err.Error(), "username") {
				return nil, ErrUsernameExists
			}
			if strings.Contains(err.Error(), "email") {
				return nil, ErrEmailExists
			}
			return nil, ErrUsernameExists
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	m.Logger().Info("Created user",
		zap.String("id", user.ID),
		zap.String("username", user.Username),
	)

	return m.toUser(&user), nil
}

// Get retrieves a single user by ID
func (m *UserManager) Get(ctx context.Context, userID string) (*User, error) {
	var user models.User

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return m.toUser(&user), nil
}

// GetByUsername retrieves a user by username
func (m *UserManager) GetByUsername(ctx context.Context, username string) (*User, error) {
	var user models.User

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return m.toUser(&user), nil
}

// GetByEmail retrieves a user by email
func (m *UserManager) GetByEmail(ctx context.Context, email string) (*User, error) {
	var user models.User

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return m.toUser(&user), nil
}

// Update updates a user (excluding password)
func (m *UserManager) Update(ctx context.Context, userID string, cfg *UserConfig) (*User, error) {
	var user models.User

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	// Update fields (only non-empty values)
	if cfg.Username != "" {
		user.Username = cfg.Username
	}
	if cfg.Email != "" {
		user.Email = cfg.Email
	}
	if cfg.DisplayName != "" {
		user.DisplayName = cfg.DisplayName
	}
	if len(cfg.Roles) > 0 {
		user.Roles = cfg.Roles
	}
	if cfg.Status != "" {
		user.Status = cfg.Status
	}

	if err := db.Save(&user).Error; err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			if strings.Contains(err.Error(), "username") {
				return nil, ErrUsernameExists
			}
			if strings.Contains(err.Error(), "email") {
				return nil, ErrEmailExists
			}
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	m.Logger().Info("Updated user",
		zap.String("id", user.ID),
	)

	return m.toUser(&user), nil
}

// UpdatePassword updates a user's password
func (m *UserManager) UpdatePassword(ctx context.Context, userID string, newPassword string) error {
	// Validate password
	minPasswordLength := viper.GetInt(m.GetConfigPath("min_password_length"))
	if len(newPassword) < minPasswordLength {
		return ErrPasswordTooShort
	}

	var user models.User

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	// Hash new password
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), m.bcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	user.PasswordHash = string(passwordHash)

	if err := db.Save(&user).Error; err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	m.Logger().Info("Updated user password",
		zap.String("id", user.ID),
	)

	return nil
}

// VerifyPassword verifies if the provided password matches the user's stored password
func (m *UserManager) VerifyPassword(ctx context.Context, userID string, password string) error {
	var user models.User

	db := m.Params().Database.GetDB().WithContext(ctx)
	if err := db.Where("id = ?", userID).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrNotFound
		}
		return err
	}

	// Compare password with stored hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return ErrInvalidPassword
	}

	return nil
}

// Authenticate authenticates a user by username/email and password
func (m *UserManager) Authenticate(ctx context.Context, identifier string, password string) (*User, error) {
	var user models.User

	db := m.Params().Database.GetDB().WithContext(ctx)
	// Try to find by username or email
	if err := db.Where("username = ? OR email = ?", identifier, identifier).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Check if user is active
	if user.Status != "active" {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// Update last login time
	now := time.Now()
	user.LastLoginAt = &now
	db.Save(&user)

	m.Logger().Info("User authenticated",
		zap.String("id", user.ID),
		zap.String("username", user.Username),
	)

	return m.toUser(&user), nil
}

// Delete deletes a user
func (m *UserManager) Delete(ctx context.Context, userID string) error {
	db := m.Params().Database.GetDB().WithContext(ctx)

	result := db.Where("id = ?", userID).Delete(&models.User{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete user: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrNotFound
	}

	m.Logger().Info("Deleted user",
		zap.String("id", userID),
	)

	return nil
}

// List queries users with pagination, search, sorting, and filtering
func (m *UserManager) List(ctx context.Context, req *ListUsersRequest, qh *queryhelper.QueryHelper) (*ListUsersResp, error) {
	db := m.Params().Database.GetDB().WithContext(ctx)
	query := db.Model(&models.User{})

	// Apply filter conditions
	if req != nil {
		if req.Username != nil {
			query = query.Where("username = ?", *req.Username)
		}
		if req.Email != nil {
			query = query.Where("email = ?", *req.Email)
		}
		if req.Role != nil {
			// Search for role in JSON array (SQLite compatible)
			query = query.Where("roles LIKE ?", "%\""+*req.Role+"\"%")
		}
		if req.Status != nil {
			query = query.Where("status = ?", *req.Status)
		}
	}

	// Apply QueryHelper (pagination, search, sorting)
	query, err := qh.Apply(DefaultQuerySettings, query)
	if err != nil {
		m.Logger().Error("Failed to apply queryhelper", zap.Error(err))
		return nil, err
	}

	// Execute query
	var users []models.User
	if err := query.Find(&users).Error; err != nil {
		m.Logger().Error("Failed to list users", zap.Error(err))
		return nil, err
	}

	// Transform results
	results := make([]*User, len(users))
	for i, u := range users {
		results[i] = m.toUser(&u)
	}

	return &ListUsersResp{
		Data:        results,
		QueryHelper: qh,
	}, nil
}

// toUser converts model to public structure (password hash is never exposed)
func (m *UserManager) toUser(model *models.User) *User {
	return &User{
		ID:          model.ID,
		Username:    model.Username,
		Email:       model.Email,
		DisplayName: model.DisplayName,
		Roles:       model.Roles,
		Status:      model.Status,
		LastLoginAt: model.LastLoginAt,
		CreatedAt:   model.CreatedAt,
		UpdatedAt:   model.UpdatedAt,
	}
}
