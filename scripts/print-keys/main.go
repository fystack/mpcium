package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/dgraph-io/badger/v4"
	"github.com/dgraph-io/badger/v4/options"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

func main() {
	app := &cli.Command{
		Name:  "print-keys",
		Usage: "Print all keys from a BadgerDB database",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "db-path",
				Aliases:  []string{"p"},
				Usage:    "Path to the BadgerDB database directory",
				Required: true,
			},
			&cli.StringFlag{
				Name:  "kdf-salt",
				Usage: "Hex-encoded KDF salt (if database uses Argon2id key derivation)",
			},
		},
		Action: printKeys,
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}

func printKeys(ctx context.Context, cmd *cli.Command) error {
	dbPath := cmd.String("db-path")
	kdfSalt := cmd.String("kdf-salt")

	// Prompt for password
	fmt.Print("Enter database password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return fmt.Errorf("failed to read password: %v", err)
	}
	fmt.Println() // Print newline after password input
	password := string(passwordBytes)

	encKey, err := kvstore.DeriveEncryptionKey(password, kdfSalt)
	if err != nil {
		return fmt.Errorf("failed to derive encryption key: %v", err)
	}

	// Configure BadgerDB options
	opts := badger.DefaultOptions(dbPath).
		WithCompression(options.ZSTD).
		WithEncryptionKey(encKey).
		WithIndexCacheSize(16 << 20).
		WithBlockCacheSize(32 << 20).
		WithReadOnly(true) // Open in read-only mode for safety

	// Open the database
	db, err := badger.Open(opts)
	if err != nil {
		return fmt.Errorf("failed to open BadgerDB: %v", err)
	}
	defer db.Close()

	fmt.Printf("Opening database at: %s\n", dbPath)
	fmt.Println("=== All Keys in Database ===")

	// Iterate through all keys
	err = db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false // We only need keys, not values
		it := txn.NewIterator(opts)
		defer it.Close()

		count := 0
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := string(item.Key())
			count++
			fmt.Printf("%d. %s\n", count, key)
		}

		if count == 0 {
			fmt.Println("No keys found in the database.")
		} else {
			fmt.Printf("\nTotal keys: %d\n", count)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to iterate over database: %v", err)
	}

	return nil
}
