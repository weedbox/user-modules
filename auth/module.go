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

	// authMode is "standalone" (validate token here, never trust inbound X-User-Info) or
	// "gateway" (trust X-User-Info injected by a trusted upstream). See middleware.go.
	authMode string
	// trustedHeaderSecret, when set (gateway mode only), requires a matching X-Gateway-Secret
	// header before an inbound X-User-Info is trusted. Empty disables the check.
	trustedHeaderSecret string
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

	// Authentication mode: "standalone" (default, secure) or "gateway".
	//   standalone: this service validates the JWT itself and never trusts a client-supplied
	//               X-User-Info header (any inbound copy is stripped).
	//   gateway:    a trusted upstream injects X-User-Info and this service trusts it.
	// Gateway deployments must opt in explicitly.
	viper.SetDefault(m.GetConfigPath("mode"), ModeStandalone)

	// Optional shared secret for gateway mode. When non-empty, an inbound X-User-Info is only
	// trusted if the request also carries a matching X-Gateway-Secret header. Empty = no check.
	viper.SetDefault(m.GetConfigPath("trusted_header_secret"), "")
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

	// Load authentication mode (defaults to secure standalone on any unknown value).
	m.authMode = viper.GetString(m.GetConfigPath("mode"))
	if m.authMode != ModeStandalone && m.authMode != ModeGateway {
		m.Logger().Warn("Invalid auth mode, falling back to standalone",
			zap.String("mode", m.authMode))
		m.authMode = ModeStandalone
	}
	m.trustedHeaderSecret = viper.GetString(m.GetConfigPath("trusted_header_secret"))
	if m.authMode == ModeGateway && m.trustedHeaderSecret == "" {
		m.Logger().Warn("auth mode is 'gateway' without trusted_header_secret: any inbound " +
			"X-User-Info will be trusted; ensure the service is reachable only via the gateway " +
			"and the gateway strips client-supplied X-User-Info")
	}
	m.Logger().Info("Auth mode", zap.String("mode", m.authMode))

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
