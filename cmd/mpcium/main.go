package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/constant"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/eventconsumer"
	"github.com/fystack/mpcium/pkg/identity"
	"github.com/fystack/mpcium/pkg/infra"
	"github.com/fystack/mpcium/pkg/keyinfo"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/messaging"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/hashicorp/consul/api"
	"github.com/nats-io/nats.go"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

const (
	Version                    = "0.3.1"
	DefaultBackupPeriodSeconds = 300 // (5 minutes)
)

func main() {
	app := &cli.Command{
		Name:    "mpcium",
		Usage:   "Multi-Party Computation node for threshold signatures",
		Version: Version,
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start an MPCIUM node",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Node name",
						Required: true,
					},
					&cli.BoolFlag{
						Name:    "decrypt-private-key",
						Aliases: []string{"d"},
						Value:   false,
						Usage:   "Decrypt node private key",
					},
					&cli.BoolFlag{
						Name:    "prompt-credentials",
						Aliases: []string{"p"},
						Usage:   "Prompt for sensitive parameters",
					},
					&cli.BoolFlag{
						Name:  "debug",
						Usage: "Enable debug logging",
						Value: false,
					},
				},
				Action: runNode,
			},
			{
				Name:  "version",
				Usage: "Display detailed version information",
				Action: func(ctx context.Context, c *cli.Command) error {
					fmt.Printf("mpcium version %s\n", Version)
					return nil
				},
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runNode(ctx context.Context, c *cli.Command) error {
	nodeName := c.String("name")
	decryptPrivateKey := c.Bool("decrypt-private-key")
	usePrompts := c.Bool("prompt-credentials")
	debug := c.Bool("debug")

	viper.SetDefault("backup_enabled", true)
	config.InitViperConfig()
	environment := viper.GetString("environment")
	logger.Init(environment, debug)

	// Handle configuration based on prompt flag
	if usePrompts {
		promptForSensitiveCredentials()
	} else {
		// Validate the config values
		checkRequiredConfigValues()
	}

	consulClient := infra.GetConsulClient(environment)
	keyinfoStore := keyinfo.NewStore(consulClient.KV())
	peers := LoadPeersFromConsul(consulClient)
	nodeID := GetIDFromName(nodeName, peers)

	badgerKV := NewBadgerKV(nodeName, nodeID)
	defer badgerKV.Close()

	// Start background backup job
	backupEnabled := viper.GetBool("backup_enabled")
	if backupEnabled {
		backupPeriodSeconds := viper.GetInt("backup_period_seconds")
		stopBackup := StartPeriodicBackup(ctx, badgerKV, backupPeriodSeconds)
		defer stopBackup()
	}

	identityStore, err := identity.NewFileStore("identity", nodeName, decryptPrivateKey)
	if err != nil {
		logger.Fatal("Failed to create identity store", err)
	}

	natsConn, err := GetNATSConnection(environment)
	if err != nil {
		logger.Fatal("Failed to connect to NATS", err)
	}
	defer natsConn.Close()

	pubsub := messaging.NewNATSPubSub(natsConn)
	keygenBroker, err := messaging.NewJetStreamBroker(ctx, natsConn, event.KeygenBrokerStream, []string{
		event.KeygenRequestTopic,
	})
	if err != nil {
		logger.Fatal("Failed to create keygen jetstream broker", err)
	}
	signingBroker, err := messaging.NewJetStreamBroker(ctx, natsConn, event.SigningPublisherStream, []string{
		event.SigningRequestTopic,
	})
	if err != nil {
		logger.Fatal("Failed to create signing jetstream broker", err)
	}

	directMessaging := messaging.NewNatsDirectMessaging(natsConn)
	mqManager := messaging.NewNATsMessageQueueManager("mpc", []string{
		"mpc.mpc_keygen_result.*",
		event.SigningResultTopic,
		"mpc.mpc_reshare_result.*",
	}, natsConn)

	genKeyResultQueue := mqManager.NewMessageQueue("mpc_keygen_result")
	defer genKeyResultQueue.Close()
	singingResultQueue := mqManager.NewMessageQueue("mpc_signing_result")
	defer singingResultQueue.Close()
	reshareResultQueue := mqManager.NewMessageQueue("mpc_reshare_result")
	defer reshareResultQueue.Close()

	logger.Info("Node is running", "ID", nodeID, "name", nodeName)

	peerNodeIDs := GetPeerIDs(peers)
	peerRegistry := mpc.NewRegistry(nodeID, peerNodeIDs, consulClient.KV())

	mpcNode := mpc.NewNode(
		nodeID,
		peerNodeIDs,
		pubsub,
		directMessaging,
		badgerKV,
		keyinfoStore,
		peerRegistry,
		identityStore,
	)
	defer mpcNode.Close()

	// ECDH session for DH key exchange
	ecdhSession := mpcNode.GetECDHSession()

	eventConsumer := eventconsumer.NewEventConsumer(
		mpcNode,
		pubsub,
		genKeyResultQueue,
		singingResultQueue,
		reshareResultQueue,
		identityStore,
	)
	eventConsumer.Run()
	defer eventConsumer.Close()

	timeoutConsumer := eventconsumer.NewTimeOutConsumer(
		natsConn,
		singingResultQueue,
	)

	timeoutConsumer.Run()
	defer timeoutConsumer.Close()
	keygenConsumer := eventconsumer.NewKeygenConsumer(natsConn, keygenBroker, pubsub, peerRegistry)
	signingConsumer := eventconsumer.NewSigningConsumer(natsConn, signingBroker, pubsub, peerRegistry)

	// Make the node ready before starting the signing consumer
	if err := peerRegistry.Ready(); err != nil {
		logger.Error("Failed to mark peer registry as ready", err)
	}
	logger.Info("[READY] Node is ready", "nodeID", nodeID)

	logger.Info("Waiting for ECDH key exchange to complete...", "nodeID", nodeID)
	if err := ecdhSession.WaitForExchangeComplete(); err != nil {
		logger.Fatal("ECDH exchange failed", err)
	}

	logger.Info("ECDH key exchange completed successfully, starting consumers...", "nodeID", nodeID)
	appContext, cancel := context.WithCancel(context.Background())
	//Setup signal handling to cancel context on termination signals.
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		logger.Warn("Shutdown signal received, canceling context...")
		cancel()

		// Gracefully close consumers
		if err := keygenConsumer.Close(); err != nil {
			logger.Error("Failed to close keygen consumer", err)
		}
		if err := signingConsumer.Close(); err != nil {
			logger.Error("Failed to close signing consumer", err)
		}

		if err := ecdhSession.Close(); err != nil {
			logger.Error("Failed to close ECDH session", err)
		}
	}()

	var wg sync.WaitGroup
	errChan := make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := keygenConsumer.Run(appContext); err != nil {
			logger.Error("error running keygen consumer", err)
			errChan <- fmt.Errorf("keygen consumer error: %w", err)
			return
		}
		logger.Info("Keygen consumer finished successfully")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := signingConsumer.Run(appContext); err != nil {
			logger.Error("error running signing consumer", err)
			errChan <- fmt.Errorf("signing consumer error: %w", err)
			return
		}
		logger.Info("Signing consumer finished successfully")
	}()

	go func() {
		for {
			select {
			case <-appContext.Done():
				return
			case err := <-ecdhSession.ErrChan():
				if err != nil {
					logger.Error("ECDH session error", err)
					errChan <- fmt.Errorf("ecdh session error: %w", err)
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		logger.Info("All consumers have finished")
		close(errChan)
	}()
	for err := range errChan {
		if err != nil {
			logger.Error("Consumer error received", err)
			cancel()
			return err
		}
	}

	return nil
}

// Prompt user for sensitive configuration values
func promptForSensitiveCredentials() {
	fmt.Println("WARNING: Please back up your Badger DB password in a secure location.")
	fmt.Println("If you lose this password, you will permanently lose access to your data!")

	// Prompt for badger password with confirmation
	var badgerPass []byte
	var confirmPass []byte
	var err error

	for {
		fmt.Print("Enter Badger DB password: ")
		badgerPass, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			logger.Fatal("Failed to read badger password", err)
		}
		fmt.Println() // Add newline after password input

		if len(badgerPass) == 0 {
			fmt.Println("Password cannot be empty. Please try again.")
			continue
		}

		fmt.Print("Confirm Badger DB password: ")
		confirmPass, err = term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			logger.Fatal("Failed to read confirmation password", err)
		}
		fmt.Println() // Add newline after password input

		if string(badgerPass) != string(confirmPass) {
			fmt.Println("Passwords do not match. Please try again.")
			continue
		}

		break
	}

	// Show masked password for confirmation
	maskedPassword := maskString(string(badgerPass))
	fmt.Printf("Password set: %s\n", maskedPassword)

	viper.Set("badger_password", string(badgerPass))

	// Prompt for initiator public key (using regular input since it's not as sensitive)
	var initiatorKey string
	fmt.Print("Enter event initiator public key (hex): ")
	if _, err := fmt.Scanln(&initiatorKey); err != nil {
		logger.Fatal("Failed to read initiator key", err)
	}

	if initiatorKey == "" {
		logger.Fatal("Initiator public key cannot be empty", nil)
	}

	// Show masked key for confirmation
	maskedKey := maskString(initiatorKey)
	fmt.Printf("Event initiator public key set: %s\n", maskedKey)

	viper.Set("event_initiator_pubkey", initiatorKey)
	fmt.Println("\n✓ Configuration complete!")
}

// maskString shows the first and last character of a string, replacing the middle with asterisks
func maskString(s string) string {
	if len(s) <= 2 {
		return s // Too short to mask
	}

	masked := s[0:1]
	for i := 0; i < len(s)-2; i++ {
		masked += "*"
	}
	masked += s[len(s)-1:]

	return masked
}

// Check required configuration values are present
func checkRequiredConfigValues() {
	// Show warning if we're using file-based config but no password is set
	if viper.GetString("badger_password") == "" {
		logger.Fatal("Badger password is required", nil)
	}

	if viper.GetString("event_initiator_pubkey") == "" {
		logger.Fatal("Event initiator public key is required", nil)
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

func LoadPeersFromConsul(consulClient *api.Client) []config.Peer { // Create a Consul Key-Value store client
	kv := consulClient.KV()
	peers, err := config.LoadPeersFromConsul(kv, "mpc_peers/")
	if err != nil {
		logger.Fatal("Failed to load peers from Consul", err)
	}
	logger.Info("Loaded peers from consul", "peers", peers)

	return peers
}

func GetPeerIDs(peers []config.Peer) []string {
	var peersIDs []string
	for _, peer := range peers {
		peersIDs = append(peersIDs, peer.ID)
	}
	return peersIDs
}

// Given node name, loop through peers and find the matching ID
func GetIDFromName(name string, peers []config.Peer) string {
	// Get nodeID from node name
	nodeID := config.GetNodeID(name, peers)
	if nodeID == "" {
		logger.Fatal("Empty Node ID", fmt.Errorf("node ID not found for name %s", name))
	}

	return nodeID
}

func NewBadgerKV(nodeName, nodeID string) *kvstore.BadgerKVStore {
	// Badger KV DB
	// Use configured db_path or default to current directory + "db"
	basePath := viper.GetString("db_path")
	if basePath == "" {
		basePath = filepath.Join(".", "db")
	}
	dbPath := filepath.Join(basePath, nodeName)

	// Use configured backup_dir or default to current directory + "backups"
	backupDir := viper.GetString("backup_dir")
	if backupDir == "" {
		backupDir = filepath.Join(".", "backups")
	}

	// Create BadgerConfig struct
	config := kvstore.BadgerConfig{
		NodeID:              nodeName,
		EncryptionKey:       []byte(viper.GetString("badger_password")),
		BackupEncryptionKey: []byte(viper.GetString("badger_password")), // Using same key for backup encryption
		BackupDir:           backupDir,
		DBPath:              dbPath,
	}

	badgerKv, err := kvstore.NewBadgerKVStore(config)
	if err != nil {
		logger.Fatal("Failed to create badger kv store", err)
	}
	logger.Info("Connected to badger kv store", "path", dbPath, "backup_dir", backupDir)
	return badgerKv
}

func StartPeriodicBackup(ctx context.Context, badgerKV *kvstore.BadgerKVStore, periodSeconds int) func() {
	if periodSeconds <= 0 {
		periodSeconds = DefaultBackupPeriodSeconds
	}
	backupTicker := time.NewTicker(time.Duration(periodSeconds) * time.Second)
	backupCtx, backupCancel := context.WithCancel(ctx)
	go func() {
		for {
			select {
			case <-backupCtx.Done():
				logger.Info("Backup background job stopped")
				return
			case <-backupTicker.C:
				logger.Info("Running periodic BadgerDB backup...")
				err := badgerKV.Backup()
				if err != nil {
					logger.Error("Periodic BadgerDB backup failed", err)
				} else {
					logger.Info("Periodic BadgerDB backup completed successfully")
				}
			}
		}
	}()
	return backupCancel
}

func GetNATSConnection(environment string) (*nats.Conn, error) {
	url := viper.GetString("nats.url")
	opts := []nats.Option{
		nats.MaxReconnects(-1), // retry forever
		nats.ReconnectWait(2 * time.Second),
		nats.DisconnectHandler(func(nc *nats.Conn) {
			logger.Warn("Disconnected from NATS")
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			logger.Info("Reconnected to NATS", "url", nc.ConnectedUrl())
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			logger.Info("NATS connection closed!")
		}),
	}

	if environment == constant.EnvProduction {
		clientCert := filepath.Join(".", "certs", "client-cert.pem")
		clientKey := filepath.Join(".", "certs", "client-key.pem")
		caCert := filepath.Join(".", "certs", "rootCA.pem")

		opts = append(opts,
			nats.ClientCert(clientCert, clientKey),
			nats.RootCAs(caCert),
			nats.UserInfo(viper.GetString("nats.username"), viper.GetString("nats.password")),
		)
	}

	return nats.Connect(url, opts...)
}
