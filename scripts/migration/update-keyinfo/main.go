package main

import (
	"fmt"
	"log"
	"strings"

	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"
)

// script to add key type prefix ecdsa for existing keys
func main() {
	config.InitViperConfig()
	logger.Init("production", true)
	appConfig := config.LoadConfig()
	logger.Info("App config", "config", appConfig)

	consulClient := NewConsulClient(appConfig.Consul.Address)
	kv := consulClient.KV()
	// Get a handle to the KV API
	// List all keys with the specified prefix
	prefix := "threshold_keyinfo"
	keys, _, err := kv.Keys(prefix, "", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Print the keys
	// fmt.Printf("Keys with prefix \"%s\":\n", prefix)
	for _, key := range keys {
		if !strings.Contains(key, "ecdsa") && !strings.Contains(key, "eddsa") {
			pair, _, err := kv.Get(key, nil)
			if err != nil {
				log.Fatal(err)
			}

			// Define variables to store the extracted values
			var walletID string

			// Use fmt.Sscanf to extract the values
			_, err = fmt.Sscanf(key, "threshold_keyinfo/%s", &walletID)
			if err != nil {
				fmt.Println("Error:", err)
				return
			}

			if walletID != "" {
				kv.Put(&api.KVPair{Key: fmt.Sprintf("threshold_keyinfo/ecdsa:%s", walletID), Value: pair.Value}, nil)
				kv.Delete(key, nil)

			}

		}

		fmt.Println(key)
	}

}

func NewConsulClient(addr string) *api.Client {
	// Create a new Consul client
	consulConfig := api.DefaultConfig()
	consulConfig.Address = addr
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		logger.Fatal("Failed to create consul client", err)
	}
	logger.Info("Connected to consul!")
	return consulClient
}
