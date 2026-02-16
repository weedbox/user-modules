package user

import (
	"context"

	"github.com/spf13/viper"
	"github.com/weedbox/common-modules/database"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/user/models"
)

const ModuleName = "UserManager"

type Params struct {
	weedbox.Params
	Database database.DatabaseConnector
}

type UserManager struct {
	weedbox.Module[*Params]
	bcryptCost int
}

func Module(scope string) fx.Option {
	m := new(UserManager)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

// Default admin credentials
const (
	DefaultAdminUsername = "admin"
	DefaultAdminEmail   = "admin@localhost"
	DefaultAdminPassword = "1qaz@WSX"
)

func (m *UserManager) InitDefaultConfigs() {
	viper.SetDefault(m.GetConfigPath("max_page_size"), 100)
	viper.SetDefault(m.GetConfigPath("bcrypt_cost"), 12)            // bcrypt cost factor (10-14 recommended)
	viper.SetDefault(m.GetConfigPath("min_password_length"), 8)     // minimum password length
	viper.SetDefault(m.GetConfigPath("create_default_admin"), true) // whether to create default admin user
	viper.SetDefault(m.GetConfigPath("default_admin_password"), DefaultAdminPassword)
}

func (m *UserManager) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Load bcrypt cost from config
	m.bcryptCost = viper.GetInt(m.GetConfigPath("bcrypt_cost"))
	if m.bcryptCost < 10 || m.bcryptCost > 14 {
		m.bcryptCost = 12 // default to 12 if out of reasonable range
	}

	// Database migration
	db := m.Params().Database.GetDB()
	if err := db.AutoMigrate(&models.User{}); err != nil {
		m.Logger().Error("Failed to migrate user table", zap.Error(err))
		return err
	}

	// Initialize default admin user
	if viper.GetBool(m.GetConfigPath("create_default_admin")) {
		if err := m.initDefaultAdmin(ctx); err != nil {
			m.Logger().Error("Failed to initialize default admin user", zap.Error(err))
			return err
		}
	}

	m.Logger().Info("Started " + ModuleName)
	return nil
}

// initDefaultAdmin creates the default admin user if it doesn't exist
func (m *UserManager) initDefaultAdmin(ctx context.Context) error {
	// Check if admin user already exists
	_, err := m.GetByUsername(ctx, DefaultAdminUsername)
	if err == nil {
		// Admin user already exists
		m.Logger().Debug("Default admin user already exists, skipping creation")
		return nil
	}

	if err != ErrNotFound {
		// Unexpected error
		return err
	}

	// Get admin password from config (allows override)
	adminPassword := viper.GetString(m.GetConfigPath("default_admin_password"))
	if adminPassword == "" {
		adminPassword = DefaultAdminPassword
	}

	// Create admin user
	adminUser, err := m.Create(ctx, &UserConfig{
		Username:    DefaultAdminUsername,
		Email:       DefaultAdminEmail,
		Password:    adminPassword,
		DisplayName: "System Administrator",
		Roles:       []string{"admin"},
		Status:      "active",
	})
	if err != nil {
		return err
	}

	m.Logger().Info("Created default admin user",
		zap.String("username", adminUser.Username),
		zap.String("id", adminUser.ID),
	)

	return nil
}

func (m *UserManager) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
