package access_key_apis

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/weedbox/common-modules/http_server"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"

	"github.com/weedbox/user-modules/access_key"
	"github.com/weedbox/user-modules/auth"
)

const ModuleName = "AccessKeyAPIs"

type Params struct {
	weedbox.Params
	HTTPServer *http_server.HTTPServer
	AccessKey  *access_key.AccessKeyManager `name:"access_key"`
	Auth       *auth.AuthManager            `name:"auth"`
}

// requirePerm is a helper to get the require_permission middleware
func (m *AccessKeyAPIs) requirePerm(permission string) gin.HandlerFunc {
	return m.Params().Auth.GetMiddleware("require_permission").(func(string) gin.HandlerFunc)(permission)
}

type AccessKeyAPIs struct {
	weedbox.Module[*Params]
}

func Module(scope string) fx.Option {
	m := new(AccessKeyAPIs)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *AccessKeyAPIs) InitDefaultConfigs() {
	// API-specific configs if needed
}

func (m *AccessKeyAPIs) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Register routes
	router := m.Params().HTTPServer.GetRouter().Group("/apis/v1")

	// Self-service key management. requirePerm("") = any authenticated user:
	// access keys are a per-account facility, not gated by an RBAC permission.
	router.GET("/me/access-keys", m.requirePerm(""), m.list)
	router.POST("/me/access-key", m.requirePerm(""), m.create)
	router.DELETE("/me/access-key/:id", m.requirePerm(""), m.delete)

	// Public ("*") like /auth/login: external programs exchange a plaintext
	// access key for a standard token pair; the key itself is the credential.
	router.POST("/auth/access-key", m.requirePerm("*"), m.exchange)

	m.Logger().Info("Started " + ModuleName)
	return nil
}

func (m *AccessKeyAPIs) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
