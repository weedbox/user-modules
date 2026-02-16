package http_token_validator

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/weedbox/common-modules/http_server"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"

	"github.com/weedbox/user-modules/auth"
)

const ModuleName = "HTTP Token Validator"

type Params struct {
	weedbox.Params
	HTTPServer *http_server.HTTPServer
	Auth       *auth.AuthManager `name:"auth"`
}

type HTTPTokenValidator struct {
	weedbox.Module[*Params]
}

func Module(scope string) fx.Option {
	m := new(HTTPTokenValidator)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *HTTPTokenValidator) InitDefaultConfigs() {
}

func (m *HTTPTokenValidator) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	// Register global auth middleware
	router := m.Params().HTTPServer.GetRouter()
	authMiddleware := m.Params().Auth.GetMiddleware("authenticate").(gin.HandlerFunc)
	router.Use(authMiddleware)

	m.Logger().Info("Started " + ModuleName)
	return nil
}

func (m *HTTPTokenValidator) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
