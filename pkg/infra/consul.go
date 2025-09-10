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
	}

	config.Address = viper.GetString("consul.address")
	config.WaitTime = 10 * time.Second
	// Ping the Consul server to verify connectivity
	logger.Info("Consul config",
		"environment", environment,
		"address", config.Address,
		"scheme", config.Scheme,
		"datacenter", config.Datacenter,
		"wait_time", config.WaitTime,
		"token", config.Token,
		"http_auth", config.HttpAuth,
	)
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
