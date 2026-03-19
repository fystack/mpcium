// generate-preparams pre-computes ECDSA pre-parameters and writes them as
// JSON fixture files. Run once from the e2e directory (or whenever you need
// fresh fixtures):
//
//	cd e2e && go run ./cmd/generate-preparams
//
// The output files (fixtures/node{N}_pre_params_{0,1}.json) are checked into
// the repo so that E2E tests can seed them into each node's BadgerDB, avoiding
// the expensive safe-prime generation at node startup.
//
// Each node gets its own unique pre-parameters — sharing pre-parameters across
// nodes causes tss-lib to reject duplicate h1j values during keygen round 2.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
)

const numNodes = 3

func main() {
	outDir := "fixtures"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "MkdirAll: %v\n", err)
		os.Exit(1)
	}

	for node := 0; node < numNodes; node++ {
		for i := 0; i < 2; i++ {
			name := fmt.Sprintf("node%d_pre_params_%d", node, i)
			fmt.Printf("Generating %s (this may take a minute)...\n", name)
			start := time.Now()
			params, err := keygen.GeneratePreParams(5 * time.Minute)
			if err != nil {
				fmt.Fprintf(os.Stderr, "GeneratePreParams failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("  done in %s\n", time.Since(start).Round(time.Millisecond))

			data, err := json.Marshal(params)
			if err != nil {
				fmt.Fprintf(os.Stderr, "json.Marshal failed: %v\n", err)
				os.Exit(1)
			}

			out := filepath.Join(outDir, name+".json")
			if err := os.WriteFile(out, data, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "WriteFile: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("  wrote %s (%d bytes)\n", out, len(data))
		}
	}

	fmt.Println("Done – fixture files are ready.")
}
