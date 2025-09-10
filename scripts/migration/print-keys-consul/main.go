package main

import (
	"fmt"
	"time"

	"github.com/fystack/mpcium/pkg/constant"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"
	"github.com/spf13/viper"
)

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

func main() {
	fmt.Println("Debug consul script")
	config := api.DefaultConfig()
	config.Address = "http://localhost:8500"
	config.Token = ""
	config.WaitTime = 10 * time.Second
	// Ping the Consul server to verify connectivity

	client, err := api.NewClient(config)
	if err != nil {
		logger.Fatal("Failed to create consul client", err)
	}

	_, err = client.Status().Leader()
	if err != nil {
		logger.Fatal("failed to connect to Consul", err)
	}

	kv := client.KV()
	pairs, _, err := kv.List("mpc_peers/", nil)
	if err != nil {
		logger.Fatal("Error loading keys", err)
	}

	for _, pair := range pairs {
		fmt.Printf("Key: %s, Value: %s\n", pair.Key, string(pair.Value))
	}
}
