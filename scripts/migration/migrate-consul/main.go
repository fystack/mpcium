package main

import (
	"flag"
	"path/filepath"
	"strings"
	"time"

	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/constant"
	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/hashicorp/consul/api"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	consulAddr := flag.String("consul", "localhost:8500", "Consul address")
	environment := flag.String("env", "development", "Environment")
	configPath := flag.String("config", "", "Config path")
	flag.Parse()

	config.InitViperConfig(*configPath)
	logger.Init(*environment, true)
	appConfig := config.LoadConfig()

	// 1. Connect to Consul
	consulConfig := api.DefaultConfig()
	consulConfig.Address = *consulAddr
	consulClient, err := api.NewClient(consulConfig)
	if err != nil {
		logger.Fatal("Failed to create Consul client", err)
	}
	logger.Info("Connected to Consul", "address", *consulAddr)

	// 2. Connect to NATS
	nc, err := getNATSConnection(*environment, appConfig)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer nc.Close()

	js, err := jetstream.New(nc)
	if err != nil {
		logger.Fatal("Failed to get JetStream context", err)
	}
	logger.Info("Connected to NATS JetStream")

	// 3. Migrate Peers
	migratePeers(consulClient, js)

	// 4. Migrate Key Info (and fix format)
	migrateKeyInfo(consulClient, js)
}

func migratePeers(consul *api.Client, js jetstream.JetStream) {
	logger.Info("Migrating Peers...")
	kv := consul.KV()
	pairs, _, err := kv.List("mpc_peers/", nil)
	if err != nil {
		logger.Fatal("Failed to list peers from Consul", err)
	}

	if len(pairs) == 0 {
		logger.Warn("No peers found in Consul to migrate")
		return
	}

	peersKV, err := infra.NewNatsKVStore(js, "mpc-peers")
	if err != nil {
		logger.Fatal("Failed to create NATS KV bucket mpc-peers", err)
	}

	for _, pair := range pairs {
		key := pair.Key // e.g. mpc_peers/test_node0

		// Strip "mpc_peers/" prefix for NATS
		key = strings.TrimPrefix(key, "mpc_peers/")

		val := pair.Value

		err := peersKV.Put(key, val)
		if err != nil {
			logger.Error("Failed to put peer to NATS", err, "key", key)
		} else {
			logger.Info("Migrated peer", "key", key, "value", string(val))
		}
	}
}

func migrateKeyInfo(consul *api.Client, js jetstream.JetStream) {
	logger.Info("Migrating KeyInfo...")
	kv := consul.KV()
	pairs, _, err := kv.List("threshold_keyinfo/", nil)
	if err != nil {
		logger.Fatal("Failed to list keyinfo from Consul", err)
	}

	if len(pairs) == 0 {
		logger.Warn("No keyinfo found in Consul to migrate")
		return
	}

	keyinfoKV, err := infra.NewNatsKVStore(js, "mpc-keyinfo")
	if err != nil {
		logger.Fatal("Failed to create NATS KV bucket mpc-keyinfo", err)
	}

	for _, pair := range pairs {
		// Consul Key: threshold_keyinfo/eddsa:UUID
		// NATS Key: eddsa-UUID (Target)

		oldKey := pair.Key

		// Strip prefix
		keyWithoutPrefix := strings.TrimPrefix(oldKey, "threshold_keyinfo/")

		// Replace : with -
		newKey := strings.Replace(keyWithoutPrefix, ":", "-", -1)

		if oldKey == newKey {
			logger.Warn("Key did not contain colon, copying as is", "key", oldKey)
		}

		err := keyinfoKV.Put(newKey, pair.Value)
		if err != nil {
			logger.Error("Failed to put keyinfo to NATS", err, "key", newKey)
		} else {
			logger.Info("Migrated keyinfo", "oldKey", oldKey, "newKey", newKey)
		}
	}
}

// Copied from main.go (simplified)
func getNATSConnection(environment string, appConfig *config.AppConfig) (*nats.Conn, error) {
	url := appConfig.NATs.URL
	opts := []nats.Option{
		nats.MaxReconnects(5),
		nats.ReconnectWait(2 * time.Second),
	}

	if environment == constant.EnvProduction {
		var clientCert, clientKey, caCert string
		if appConfig.NATs.TLS != nil {
			clientCert = appConfig.NATs.TLS.ClientCert
			clientKey = appConfig.NATs.TLS.ClientKey
			caCert = appConfig.NATs.TLS.CACert
		}
		if clientCert == "" {
			clientCert = filepath.Join(".", "certs", "client-cert.pem")
		}
		if clientKey == "" {
			clientKey = filepath.Join(".", "certs", "client-key.pem")
		}
		if caCert == "" {
			caCert = filepath.Join(".", "certs", "rootCA.pem")
		}

		opts = append(opts,
			nats.ClientCert(clientCert, clientKey),
			nats.RootCAs(caCert),
			nats.UserInfo(appConfig.NATs.Username, appConfig.NATs.Password),
		)
	}

	return nats.Connect(url, opts...)
}
