package infra

import (
	"time"

	"github.com/fystack/mpcium/pkg/constant"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"
	"github.com/spf13/viper"
)

type ConsulKV interface {
	Put(kv *api.KVPair, options *api.WriteOptions) (*api.WriteMeta, error)
	Get(key string, options *api.QueryOptions) (*api.KVPair, *api.QueryMeta, error)
	Delete(key string, options *api.WriteOptions) (*api.WriteMeta, error)
	List(prefix string, options *api.QueryOptions) (api.KVPairs, *api.QueryMeta, error)
}

func GetConsulClient(environment string) *api.Client {
	config := api.DefaultConfig()
	if environment == constant.EnvProduction {
		config.Token = viper.GetString("consul.token")
		username := viper.GetString("consul.username")
		password := viper.GetString("consul.password")
		if username != "" || password != "" {
			config.HttpAuth = &api.HttpBasicAuth{
				Username: username,
				Password: password,
			}
		}

		// Trust a custom CA for the Consul HTTPS endpoint. When unset, the
		// client falls back to CONSUL_CACERT/CONSUL_CAPATH env vars and then
		// the system trust store.
		if caCert := viper.GetString("consul.ca_cert"); caCert != "" {
			config.TLSConfig.CAFile = caCert
		}
	}

	config.Address = viper.GetString("consul.address")
	config.WaitTime = 10 * time.Second

	tokenLength := 0
	if config.Token != "" {
		tokenLength = len(config.Token)
	}

	logger.Info("Consul config",
		"environment", environment,
		"address", config.Address,
		"wait_time", config.WaitTime,
		"token_length", tokenLength,
		"http_auth", config.HttpAuth,
		"ca_cert", config.TLSConfig.CAFile,
	)

	// Ping the Consul server to verify connectivity
	client, err := api.NewClient(config)
	if err != nil {
		logger.Fatal("Failed to create consul client", err)
	}

	_, err = client.Status().Leader()
	if err != nil {
		logger.Fatal("failed to connect to Consul", err)
	}

	return client
}
