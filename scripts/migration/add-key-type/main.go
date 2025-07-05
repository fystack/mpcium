package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/dgraph-io/badger/v4"
	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
)

func main() {
	logger.Init("production", false)
	nodeName := flag.String("name", "", "Provide node name")
	flag.Parse()
	if *nodeName == "" {
		logger.Fatal("Node name is required", nil)
	}

	dbPath := fmt.Sprintf("./db/%s", *nodeName)
	badgerKv, err := kvstore.NewBadgerKVStore(
		dbPath,
		[]byte(""),
	)
	if err != nil {
		logger.Fatal("Failed to create badger kv store", err)
	}

	if err := badgerKv.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			var result []byte

			if err := item.Value(func(val []byte) error {
				result = append(result, val...)
				return nil
			}); err != nil {
				return err
			}

			if !strings.HasPrefix(string(key), "eddsa:") {
				if !strings.HasPrefix(string(key), "ecdsa:") {
					if err := badgerKv.DB.Update(func(txn *badger.Txn) error {
						if err := txn.Set([]byte(fmt.Sprintf("ecdsa:%s", key)), result); err != nil {
							return err
						}
						return txn.Delete(key)
					}); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}); err != nil {
		logger.Fatal("Failed to migrate keys", err)
	}

	keys, err := badgerKv.Keys()
	if err != nil {
		logger.Fatal("Failed to get keys from badger kv store", err)
	}

	for _, key := range keys {
		fmt.Printf("key = %+v\n", key)
	}
}
