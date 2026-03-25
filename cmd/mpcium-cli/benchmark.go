package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fystack/mpcium/pkg/client"
	"github.com/fystack/mpcium/pkg/config"
	"github.com/fystack/mpcium/pkg/constant"
	"github.com/fystack/mpcium/pkg/event"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/types"
	"github.com/nats-io/nats.go"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

type BenchmarkResult struct {
	TotalOperations  int
	SuccessfulOps    int
	FailedOps        int
	TotalTime        time.Duration
	AverageTime      time.Duration
	MedianTime       time.Duration
	OperationTimes   []time.Duration
	ErrorRate        float64
	OperationsPerMin float64
	BatchSize        int
	TotalBatches     int
	BatchTimes       []time.Duration
}

type OperationResult struct {
	ID          string
	StartTime   time.Time
	EndTime     time.Time
	Completed   bool
	Success     bool
	ErrorReason string
	ErrorCode   string
}

func benchmarkCommand() *cli.Command {
	return &cli.Command{
		Name:        "benchmark",
		Usage:       "Benchmark tool for MPC operations",
		Description: "Run benchmarks for keygen, signing (ECDSA/EdDSA), and resharing operations",
		Commands: []*cli.Command{
			keygenBenchmarkCommand(),
			ecdsaSignBenchmarkCommand(),
			eddsaSignBenchmarkCommand(),
			reshareBenchmarkCommand(),
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "config",
				Aliases:  []string{"c"},
				Usage:    "Path to configuration file",
				Category: "configuration",
			},
			&cli.StringFlag{
				Name:     "key-path",
				Usage:    "Path to event initiator private key",
				Value:    "./event_initiator.key",
				Category: "authentication",
			},
			&cli.BoolFlag{
				Name:     "prompt-password",
				Aliases:  []string{"p"},
				Usage:    "Prompt for encrypted key password (secure)",
				Value:    false,
				Category: "authentication",
			},
			&cli.StringFlag{
				Name:     "client-id",
				Usage:    "Client ID for result routing (scopes results to this client instance)",
				Category: "configuration",
			},
			&cli.BoolFlag{
				Name:     "debug",
				Usage:    "Enable debug logging",
				Value:    false,
				Category: "logging",
			},
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output file for benchmark results",
				Value:    "benchmark/output.txt",
				Category: "output",
			},
		},
	}
}

func keygenBenchmarkCommand() *cli.Command {
	return &cli.Command{
		Name:      "keygen",
		Usage:     "Benchmark keygen operations",
		ArgsUsage: "<num_operations>",
		Action:    runKeygenBenchmark,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "timeout",
				Usage:   "Timeout per operation in seconds",
				Value:   60,
				Aliases: []string{"t"},
			},
			&cli.IntFlag{
				Name:    "batch-size",
				Usage:   "Number of operations per batch",
				Value:   10,
				Aliases: []string{"b"},
			},
		},
	}
}

func ecdsaSignBenchmarkCommand() *cli.Command {
	return &cli.Command{
		Name:      "sign-ecdsa",
		Usage:     "Benchmark ECDSA signing operations",
		ArgsUsage: "<num_operations> <wallet_id>",
		Action:    runECDSASignBenchmark,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "timeout",
				Usage:   "Timeout per operation in seconds",
				Value:   60,
				Aliases: []string{"t"},
			},
			&cli.IntFlag{
				Name:    "batch-size",
				Usage:   "Number of operations per batch",
				Value:   10,
				Aliases: []string{"b"},
			},
		},
	}
}

func eddsaSignBenchmarkCommand() *cli.Command {
	return &cli.Command{
		Name:      "sign-eddsa",
		Usage:     "Benchmark EdDSA signing operations",
		ArgsUsage: "<num_operations> <wallet_id>",
		Action:    runEdDSASignBenchmark,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "timeout",
				Usage:   "Timeout per operation in seconds",
				Value:   60,
				Aliases: []string{"t"},
			},
			&cli.IntFlag{
				Name:    "batch-size",
				Usage:   "Number of operations per batch",
				Value:   10,
				Aliases: []string{"b"},
			},
		},
	}
}

func reshareBenchmarkCommand() *cli.Command {
	return &cli.Command{
		Name:      "reshare",
		Usage:     "Benchmark reshare operations",
		ArgsUsage: "<num_operations> <wallet_id>",
		Action:    runReshareBenchmark,
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "timeout",
				Usage:   "Timeout per operation in seconds",
				Value:   60,
				Aliases: []string{"t"},
			},
			&cli.IntFlag{
				Name:    "batch-size",
				Usage:   "Number of operations per batch",
				Value:   10,
				Aliases: []string{"b"},
			},
			&cli.IntFlag{
				Name:    "new-threshold",
				Usage:   "New threshold for resharing",
				Value:   2,
				Aliases: []string{"nt"},
			},
			&cli.StringSliceFlag{
				Name:    "node-ids",
				Usage:   "Node IDs for resharing (comma separated)",
				Aliases: []string{"n"},
			},
		},
	}
}

func createMPCClient(cmd *cli.Command) (client.MPCClient, error) {
	configPath := cmd.String("config")
	keyPath := cmd.String("key-path")
	promptPassword := cmd.Bool("prompt-password")
	debug := cmd.Bool("debug")

	// Initialize configuration
	config.InitViperConfig(configPath)
	appConfig := config.LoadConfig()
	environment := appConfig.Environment

	// Initialize logger
	logger.Init(environment, debug)

	// Create NATS connection using the same logic as main mpcium
	nc, err := getNATSConnection(environment, appConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	// Handle password prompting
	var password string
	if promptPassword {
		password, err = promptForPassword()
		if err != nil {
			return nil, fmt.Errorf("failed to get password: %w", err)
		}
	}

	// Create a LocalSigner with the provided key path and password
	signerOpts := client.LocalSignerOptions{
		KeyPath:  keyPath,
		Password: password,
	}

	// Default to Ed25519 for event initiator keys
	signer, err := client.NewLocalSigner(types.EventInitiatorKeyTypeEd25519, signerOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	opts := client.Options{
		NatsConn: nc,
		Signer:   signer,
		ClientID: cmd.String("client-id"),
	}
	return client.NewMPCClient(opts), nil
}

// promptForPassword securely prompts for a password without echoing to terminal
func promptForPassword() (string, error) {
	fmt.Print("Enter password for encrypted key: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Add newline after password input
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	password := string(passwordBytes)
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

// generateUniqueID creates a highly unique ID for benchmark operations
func generateUniqueID(prefix string) string {
	// Generate random bytes for extra uniqueness
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-only if random generation fails
		return fmt.Sprintf("%s-%d-%d", prefix, time.Now().UnixNano(), os.Getpid())
	}
	randomHex := hex.EncodeToString(randomBytes)
	
	// Combine timestamp, process ID, and random bytes
	return fmt.Sprintf("%s-%d-%d-%s", prefix, time.Now().UnixNano(), os.Getpid(), randomHex)
}

// getNATSConnection creates a NATS connection with proper TLS configuration
// This is similar to GetNATSConnection in cmd/mpcium/main.go
func getNATSConnection(environment string, appConfig *config.AppConfig) (*nats.Conn, error) {
	url := appConfig.NATs.URL
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
		// Load TLS config from configuration
		var clientCert, clientKey, caCert string
		if appConfig.NATs.TLS != nil {
			clientCert = appConfig.NATs.TLS.ClientCert
			clientKey = appConfig.NATs.TLS.ClientKey
			caCert = appConfig.NATs.TLS.CACert
		}

		// Fallback to default paths if not configured
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

func runKeygenBenchmark(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 1 {
		return fmt.Errorf("missing required argument: num_operations")
	}

	numOps := cmd.Args().Get(0)
	n, err := parseNumOps(numOps)
	if err != nil {
		return err
	}

	timeout := time.Duration(cmd.Int("timeout")) * time.Second

	mpcClient, err := createMPCClient(cmd)
	if err != nil {
		return err
	}

	fmt.Printf("Starting keygen benchmark with %d operations...\n", n)

	var results []OperationResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Set up result listener
	err = mpcClient.OnWalletCreationResult(func(result event.KeygenResultEvent) {
		mu.Lock()
		defer mu.Unlock()

		for i := range results {
			if results[i].ID == result.WalletID && !results[i].Completed {
				results[i].EndTime = time.Now()
				results[i].Completed = true
				results[i].Success = result.ResultType == event.ResultTypeSuccess
				if !results[i].Success {
					results[i].ErrorReason = result.ErrorReason
					results[i].ErrorCode = result.ErrorCode
				}
				wg.Done()
				break
			}
		}
	})
	if err != nil {
		return fmt.Errorf("failed to set up result listener: %w", err)
	}

	// Run operations
	startTime := time.Now()
	for i := 0; i < n; i++ {
		// Generate unique wallet ID to avoid duplicates across runs
		walletID := generateUniqueID(fmt.Sprintf("benchmark-keygen-%d", i))

		result := OperationResult{
			ID:        walletID,
			StartTime: time.Now(),
		}

		mu.Lock()
		results = append(results, result)
		mu.Unlock()

		wg.Add(1)

		err := mpcClient.CreateWallet(walletID)
		if err != nil {
			mu.Lock()
			results[i].Completed = true
			results[i].Success = false
			results[i].ErrorReason = err.Error()
			results[i].EndTime = time.Now()
			mu.Unlock()
			wg.Done()
		}

		// Add small delay between operations to avoid overwhelming the system
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for all operations with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All operations completed
	case <-time.After(timeout * time.Duration(n)):
		fmt.Println("Timeout reached, some operations may still be pending")
	}

	totalTime := time.Since(startTime)

	// Calculate results
	benchResult := calculateBenchmarkResult(results, totalTime, 1, []time.Duration{totalTime})
	outputFile := cmd.String("output")
	if err := printBenchmarkResult("Keygen", benchResult, outputFile); err != nil {
		return fmt.Errorf("failed to write benchmark results: %w", err)
	}

	return nil
}

func runECDSASignBenchmark(ctx context.Context, cmd *cli.Command) error {
	return runSignBenchmark(ctx, cmd, types.KeyTypeSecp256k1, "ECDSA")
}

func runEdDSASignBenchmark(ctx context.Context, cmd *cli.Command) error {
	return runSignBenchmark(ctx, cmd, types.KeyTypeEd25519, "EdDSA")
}

func runSignBenchmark(ctx context.Context, cmd *cli.Command, keyType types.KeyType, keyTypeName string) error {
	if cmd.Args().Len() < 2 {
		return fmt.Errorf("missing required arguments: num_operations and wallet_id")
	}

	numOps := cmd.Args().Get(0)
	walletID := cmd.Args().Get(1)

	n, err := parseNumOps(numOps)
	if err != nil {
		return err
	}

	timeout := time.Duration(cmd.Int("timeout")) * time.Second
	batchSize := cmd.Int("batch-size")

	mpcClient, err := createMPCClient(cmd)
	if err != nil {
		return err
	}

	totalBatches := (n + batchSize - 1) / batchSize
	fmt.Printf("Starting %s signing benchmark with %d operations (%d batches of %d) for wallet %s...\n", keyTypeName, n, totalBatches, batchSize, walletID)
	fmt.Printf("Note: If you see 'Duplicate signing request detected' errors, wait a few minutes between benchmark runs\n")

	var results []OperationResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Set up result listener
	err = mpcClient.OnSignResult(func(result event.SigningResultEvent) {
		mu.Lock()
		defer mu.Unlock()

		for i := range results {
			if results[i].ID == result.TxID && !results[i].Completed {
				results[i].EndTime = time.Now()
				results[i].Completed = true
				results[i].Success = result.ResultType == event.ResultTypeSuccess
				if !results[i].Success {
					results[i].ErrorReason = result.ErrorReason
					results[i].ErrorCode = string(result.ErrorCode)
				}
				wg.Done()
				break
			}
		}
	})
	if err != nil {
		return fmt.Errorf("failed to set up result listener: %w", err)
	}

	// Run operations in batches
	startTime := time.Now()
	var batchTimes []time.Duration

	// Start progress reporting goroutine
	progressTicker := time.NewTicker(10 * time.Second)
	defer progressTicker.Stop()
	go func() {
		for range progressTicker.C {
			mu.Lock()
			completed := 0
			for _, r := range results {
				if r.Completed {
					completed++
				}
			}
			mu.Unlock()
			fmt.Printf("Progress: %d/%d results received\n", completed, n)
		}
	}()

	for batchNum := 0; batchNum < totalBatches; batchNum++ {
		batchStart := time.Now()
		batchStartIdx := batchNum * batchSize
		batchEndIdx := batchStartIdx + batchSize
		if batchEndIdx > n {
			batchEndIdx = n
		}

		fmt.Printf("Starting batch %d/%d (%d operations)...\n", batchNum+1, totalBatches, batchEndIdx-batchStartIdx)

		for i := batchStartIdx; i < batchEndIdx; i++ {
			// Generate unique transaction ID to avoid duplicates across runs
			txID := generateUniqueID(fmt.Sprintf("benchmark-%s-sign-%d", keyTypeName, i))

			// Generate random transaction data
			txData := make([]byte, 32)
			if _, err := rand.Read(txData); err != nil {
				// Use zero bytes if random generation fails (still valid for benchmark)
				txData = make([]byte, 32)
			}

			msg := &types.SignTxMessage{
				KeyType:             keyType,
				WalletID:            walletID,
				NetworkInternalCode: "benchmark",
				TxID:                txID,
				Tx:                  txData,
			}

			result := OperationResult{
				ID:        txID,
				StartTime: time.Now(),
			}

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			wg.Add(1)

			err := mpcClient.SignTransaction(msg)
			if err != nil {
				mu.Lock()
				results[i].Completed = true
				results[i].Success = false
				results[i].ErrorReason = err.Error()
				results[i].EndTime = time.Now()
				mu.Unlock()
				wg.Done()
			}

			// Add small delay between operations
			time.Sleep(10 * time.Millisecond)
		}

		batchTimes = append(batchTimes, time.Since(batchStart))
	}

	// Wait for all operations with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All operations completed
	case <-time.After(timeout * time.Duration(n)):
		fmt.Println("Timeout reached, some operations may still be pending")
	}

	totalTime := time.Since(startTime)

	// Calculate results
	benchResult := calculateBenchmarkResult(results, totalTime, batchSize, batchTimes)
	outputFile := cmd.String("output")
	if err := printBenchmarkResult(fmt.Sprintf("%s Signing", keyTypeName), benchResult, outputFile); err != nil {
		return fmt.Errorf("failed to write benchmark results: %w", err)
	}

	return nil
}

func runReshareBenchmark(ctx context.Context, cmd *cli.Command) error {
	if cmd.Args().Len() < 2 {
		return fmt.Errorf("missing required arguments: num_operations and wallet_id")
	}

	numOps := cmd.Args().Get(0)
	walletID := cmd.Args().Get(1)

	n, err := parseNumOps(numOps)
	if err != nil {
		return err
	}

	timeout := time.Duration(cmd.Int("timeout")) * time.Second
	newThreshold := cmd.Int("new-threshold")
	nodeIDs := cmd.StringSlice("node-ids")

	if len(nodeIDs) == 0 {
		return fmt.Errorf("node-ids are required for resharing benchmark")
	}

	mpcClient, err := createMPCClient(cmd)
	if err != nil {
		return err
	}

	fmt.Printf("Starting reshare benchmark with %d operations for wallet %s...\n", n, walletID)

	var results []OperationResult
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Set up result listener
	err = mpcClient.OnResharingResult(func(result event.ResharingResultEvent) {
		mu.Lock()
		defer mu.Unlock()

		// For resharing, find the first incomplete operation for this wallet
		found := false
		for i := range results {
			if strings.HasPrefix(results[i].ID, result.WalletID) && !results[i].Completed {
				results[i].EndTime = time.Now()
				results[i].Completed = true
				results[i].Success = result.ResultType == event.ResultTypeSuccess
				if !results[i].Success {
					results[i].ErrorReason = result.ErrorReason
					results[i].ErrorCode = result.ErrorCode
				}
				wg.Done()
				found = true
				break
			}
		}
		if !found {
			fmt.Printf("Warning: Received reshare result for wallet %s but no matching pending operation found\n", result.WalletID)
		}
	})
	if err != nil {
		return fmt.Errorf("failed to set up result listener: %w", err)
	}

	// Run operations
	startTime := time.Now()
	for i := 0; i < n; i++ {
		// Generate unique session ID to avoid duplicates across runs
		sessionID := generateUniqueID(fmt.Sprintf("benchmark-reshare-%d", i))

		msg := &types.ResharingMessage{
			SessionID:    sessionID,
			NodeIDs:      nodeIDs,
			NewThreshold: newThreshold,
			KeyType:      types.KeyTypeSecp256k1, // Default to secp256k1
			WalletID:     walletID,
		}

		result := OperationResult{
			ID:        fmt.Sprintf("%s-%d", walletID, i),
			StartTime: time.Now(),
		}

		mu.Lock()
		results = append(results, result)
		mu.Unlock()

		wg.Add(1)

		err := mpcClient.Resharing(msg)
		if err != nil {
			mu.Lock()
			results[i].Completed = true
			results[i].Success = false
			results[i].ErrorReason = err.Error()
			results[i].EndTime = time.Now()
			mu.Unlock()
			wg.Done()
		}

		// Add small delay between operations
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for all operations with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All operations completed
	case <-time.After(timeout * time.Duration(n)):
		fmt.Println("Timeout reached, some operations may still be pending")
	}

	totalTime := time.Since(startTime)

	// Calculate results
	benchResult := calculateBenchmarkResult(results, totalTime, 1, []time.Duration{totalTime})
	outputFile := cmd.String("output")
	if err := printBenchmarkResult("Reshare", benchResult, outputFile); err != nil {
		return fmt.Errorf("failed to write benchmark results: %w", err)
	}

	return nil
}

func parseNumOps(numOps string) (int, error) {
	var n int
	_, err := fmt.Sscanf(numOps, "%d", &n)
	if err != nil {
		return 0, fmt.Errorf("invalid number of operations: %s", numOps)
	}
	if n <= 0 {
		return 0, fmt.Errorf("number of operations must be positive")
	}
	return n, nil
}

func calculateBenchmarkResult(results []OperationResult, totalTime time.Duration, batchSize int, batchTimes []time.Duration) BenchmarkResult {
	var operationTimes []time.Duration
	successfulOps := 0
	failedOps := 0

	for _, result := range results {
		if result.Completed {
			if result.Success {
				successfulOps++
				if !result.EndTime.IsZero() {
					operationTimes = append(operationTimes, result.EndTime.Sub(result.StartTime))
				}
			} else {
				failedOps++
			}
		} else {
			failedOps++ // Uncompleted operations are considered failed
		}
	}

	totalOperations := len(results)
	errorRate := float64(failedOps) / float64(totalOperations) * 100

	var averageTime, medianTime time.Duration
	var operationsPerSec float64

	if len(operationTimes) > 0 {
		// Calculate average
		var totalOpTime time.Duration
		for _, opTime := range operationTimes {
			totalOpTime += opTime
		}
		averageTime = totalOpTime / time.Duration(len(operationTimes))

		// Calculate median
		sort.Slice(operationTimes, func(i, j int) bool {
			return operationTimes[i] < operationTimes[j]
		})
		if len(operationTimes)%2 == 0 {
			medianTime = (operationTimes[len(operationTimes)/2-1] + operationTimes[len(operationTimes)/2]) / 2
		} else {
			medianTime = operationTimes[len(operationTimes)/2]
		}

		// Calculate operations per minute
		operationsPerSec = float64(successfulOps) / totalTime.Minutes()
	}

	return BenchmarkResult{
		TotalOperations:  totalOperations,
		SuccessfulOps:    successfulOps,
		FailedOps:        failedOps,
		TotalTime:        totalTime,
		AverageTime:      averageTime,
		MedianTime:       medianTime,
		OperationTimes:   operationTimes,
		ErrorRate:        errorRate,
		OperationsPerMin: operationsPerSec,
		BatchSize:        batchSize,
		TotalBatches:     len(batchTimes),
		BatchTimes:       batchTimes,
	}
}

func printBenchmarkResult(operationType string, result BenchmarkResult, outputFile string) error {
	// Generate the benchmark report content
	reportContent := generateBenchmarkReport(operationType, result)

	// Print to console
	fmt.Print(reportContent)

	// Write to file if specified
	if outputFile != "" {
		if err := writeBenchmarkToFile(reportContent, outputFile, operationType); err != nil {
			return fmt.Errorf("failed to write to file %s: %w", outputFile, err)
		}
		fmt.Printf("\nBenchmark results written to: %s\n", outputFile)
	}

	return nil
}

func generateBenchmarkReport(operationType string, result BenchmarkResult) string {
	var report strings.Builder

	report.WriteString("\n")
	report.WriteString("===============================\n")
	report.WriteString(fmt.Sprintf("%s BENCHMARK RESULTS SUMMARY\n", strings.ToUpper(operationType)))
	report.WriteString("===============================\n")
	report.WriteString(fmt.Sprintf("Timestamp: %s\n", time.Now().Format(time.RFC3339)))
	report.WriteString(fmt.Sprintf("Operation Type: %s\n", operationType))
	report.WriteString(fmt.Sprintf("Total benchmark time: %v\n", result.TotalTime))
	report.WriteString(fmt.Sprintf("Total batches sent: %d\n", result.TotalBatches))
	report.WriteString(fmt.Sprintf("Total requests sent: %d\n", result.TotalOperations))
	report.WriteString(fmt.Sprintf("Successful completions: %d\n", result.SuccessfulOps))
	report.WriteString(fmt.Sprintf("Failed operations: %d\n", result.FailedOps))
	report.WriteString(fmt.Sprintf("Success rate: %.2f%%\n", 100.0-result.ErrorRate))
	report.WriteString(fmt.Sprintf("Error rate: %.2f%%\n", result.ErrorRate))
	report.WriteString(fmt.Sprintf("Average operations per minute: %.2f\n", result.OperationsPerMin))

	if len(result.OperationTimes) > 0 {
		report.WriteString(fmt.Sprintf("Average operation time: %v\n", result.AverageTime))
		report.WriteString(fmt.Sprintf("Median operation time: %v\n", result.MedianTime))
	}

	report.WriteString("\n")
	report.WriteString("------------------------------\n")
	report.WriteString(fmt.Sprintf("%d REQUEST ANALYSIS\n", result.BatchSize))
	report.WriteString("------------------------------\n")

	if len(result.OperationTimes) >= result.BatchSize {
		firstNResults := result.OperationTimes[:result.BatchSize]
		if len(firstNResults) > len(result.OperationTimes) {
			firstNResults = result.OperationTimes
		}

		completedCount := len(firstNResults)
		if completedCount > result.BatchSize {
			completedCount = result.BatchSize
		}

		report.WriteString(fmt.Sprintf("Completed from first %d: %d/%d\n", result.BatchSize, completedCount, result.BatchSize))

		if len(firstNResults) > 0 {
			var totalTime time.Duration
			minTime := firstNResults[0]
			maxTime := firstNResults[0]

			for _, t := range firstNResults {
				totalTime += t
				if t < minTime {
					minTime = t
				}
				if t > maxTime {
					maxTime = t
				}
			}

			report.WriteString(fmt.Sprintf("Fastest (first %d): %v\n", result.BatchSize, minTime))
			report.WriteString(fmt.Sprintf("Slowest (first %d): %v\n", result.BatchSize, maxTime))
		}
	}

	report.WriteString("\n")

	return report.String()
}

func writeBenchmarkToFile(content, outputFile, operationType string) (err error) {
	// Create directory if it doesn't exist
	dir := filepath.Dir(outputFile)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	
	// Open file for appending (create if doesn't exist)
	file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close file: %w", closeErr)
		}
	}()
	
	// Write content to file
	if _, err := file.WriteString(content); err != nil {
		return fmt.Errorf("failed to write content: %w", err)
	}
	
	// Add separator for multiple benchmark runs
	separator := fmt.Sprintf("\n%s\n\n", strings.Repeat("=", 80))
	if _, err := file.WriteString(separator); err != nil {
		return fmt.Errorf("failed to write separator: %w", err)
	}
	
	return nil
}
