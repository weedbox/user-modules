package auth

import (
	"context"
	"time"

	"github.com/spf13/viper"
	"github.com/weedbox/common-modules/database"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/auth/models"
	"github.com/weedbox/user-modules/rbac"
	"github.com/weedbox/user-modules/user"
)

const ModuleName = "Auth"

type Params struct {
	weedbox.Params
	Database database.DatabaseConnector
	User     *user.UserManager `name:"user"`
	RBAC     *rbac.RBACManager `name:"rbac"`
}

type AuthManager struct {
	weedbox.Module[*Params]

	// Configuration
	jwtSecret          []byte
	accessTokenExpiry  time.Duration
	refreshTokenExpiry time.Duration
	issuer             string
}

func Module(scope string) fx.Option {
	m := new(AuthManager)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *AuthManager) InitDefaultConfigs() {
	// JWT secret key (should be overridden in production)
	viper.SetDefault(m.GetConfigPath("jwt_secret"), "change-this-secret-in-production")

	// Access token expiry (default: 15 minutes)
	viper.SetDefault(m.GetConfigPath("access_token_expiry"), "15m")

	// Refresh token expiry (default: 7 days)
	viper.SetDefault(m.GetConfigPath("refresh_token_expiry"), "168h")

	// Token issuer
	viper.SetDefault(m.GetConfigPath("issuer"), "weedbox")
}

func (m *AuthManager) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Load configuration
	m.jwtSecret = []byte(viper.GetString(m.GetConfigPath("jwt_secret")))

	accessExpiry, err := time.ParseDuration(viper.GetString(m.GetConfigPath("access_token_expiry")))
	if err != nil {
		m.Logger().Warn("Invalid access_token_expiry, using default 15m", zap.Error(err))
		accessExpiry = 15 * time.Minute
	}
	m.accessTokenExpiry = accessExpiry

	refreshExpiry, err := time.ParseDuration(viper.GetString(m.GetConfigPath("refresh_token_expiry")))
	if err != nil {
		m.Logger().Warn("Invalid refresh_token_expiry, using default 168h", zap.Error(err))
		refreshExpiry = 7 * 24 * time.Hour
	}
	m.refreshTokenExpiry = refreshExpiry

	m.issuer = viper.GetString(m.GetConfigPath("issuer"))

	// Auto-migrate refresh token table
	db := m.Params().Database.GetDB()
	if err := db.AutoMigrate(&models.RefreshToken{}); err != nil {
		m.Logger().Error("Failed to migrate refresh_tokens table", zap.Error(err))
		return err
	}

	m.Logger().Info("Started " + ModuleName)
	return nil
}

func (m *AuthManager) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
