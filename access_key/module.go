package access_key

import (
	"context"

	"github.com/spf13/viper"
	"github.com/weedbox/common-modules/database"
	"github.com/weedbox/weedbox"
	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/weedbox/user-modules/access_key/models"
)

const ModuleName = "AccessKey"

// DefaultKeyPrefix is the fallback plaintext key prefix when key_prefix is not
// configured.
const DefaultKeyPrefix = "ak_"

type Params struct {
	weedbox.Params
	Database database.DatabaseConnector
}

type AccessKeyManager struct {
	weedbox.Module[*Params]

	// keyPrefix is prepended to every generated key so keys are recognizable
	// at a glance (and in secret scanners). Applications typically brand it,
	// e.g. "myapp_".
	keyPrefix string
}

func Module(scope string) fx.Option {
	m := new(AccessKeyManager)

	return fx.Module(
		scope,
		fx.Supply(fx.Annotated{Name: scope, Target: m}),
		fx.Invoke(func(p Params) {
			weedbox.InitModule(scope, &p, m)
		}),
	)
}

func (m *AccessKeyManager) InitDefaultConfigs() {
	// Plaintext key prefix. Changing it invalidates previously issued keys,
	// because Verify rejects keys that do not carry the current prefix.
	viper.SetDefault(m.GetConfigPath("key_prefix"), DefaultKeyPrefix)
}

func (m *AccessKeyManager) OnStart(ctx context.Context) error {
	m.Logger().Info("Starting " + ModuleName)

	m.keyPrefix = viper.GetString(m.GetConfigPath("key_prefix"))
	if m.keyPrefix == "" {
		m.keyPrefix = DefaultKeyPrefix
	}

	db := m.Params().Database.GetDB()
	if err := db.AutoMigrate(&models.AccessKey{}); err != nil {
		m.Logger().Error("Failed to migrate access_keys table", zap.Error(err))
		return err
	}

	m.Logger().Info("Started "+ModuleName, zap.String("key_prefix", m.keyPrefix))
	return nil
}

func (m *AccessKeyManager) OnStop(ctx context.Context) error {
	m.Logger().Info("Stopped " + ModuleName)
	return nil
}
