package auth_apis

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/weedbox/common-modules/http_server"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"

	"github.com/weedbox/user-modules/auth"
)

const ModuleName = "AuthAPIs"

type Params struct {
	weedbox.Params
	HTTPServer *http_server.HTTPServer
	Auth       *auth.AuthManager `name:"auth"`
}

// requirePerm is a helper to get the require_permission middleware
func (m *AuthAPIs) requirePerm(permission string) gin.HandlerFunc {
	return m.Params().Auth.GetMiddleware("require_permission").(func(string) gin.HandlerFunc)(permission)
}

type AuthAPIs struct {
	weedbox.Module[*Params]
}

func Module(scope string) fx.Option {
	m := new(AuthAPIs)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *AuthAPIs) InitDefaultConfigs() {
	// API-specific configs if needed
}

func (m *AuthAPIs) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Register routes
	router := m.Params().HTTPServer.GetRouter().Group("/apis/v1")

	// Authentication endpoints are public ("*") because:
	// - login: unauthenticated users need to login
	// - refresh: security is validated by refresh token itself
	// - logout: security is validated by refresh token itself
	router.POST("/auth/login", m.requirePerm("*"), m.login)
	router.POST("/auth/refresh", m.requirePerm("*"), m.refresh)
	router.POST("/auth/logout", m.requirePerm("*"), m.logout)

	m.Logger().Info("Started " + ModuleName)
	return nil
}

func (m *AuthAPIs) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
