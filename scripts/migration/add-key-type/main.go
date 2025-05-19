package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/fystack/mpcium/pkg/kvstore"
	"github.com/fystack/mpcium/pkg/logger"
	"github.com/dgraph-io/badger/v4"
)

func main() {
	logger.Init("production", true)
	nodeName := flag.String("name", "", "Provide node name")
	flag.Parse()
	if *nodeName == "" {
		logger.Fatal("Node name is required", nil)
	}

	dbPath := fmt.Sprintf("./db/%s", *nodeName)
	badgerKv, err := kvstore.NewBadgerKVStore(
		dbPath,
		[]byte("1JwFmsc9lxlLfkPl"),
	)
	if err != nil {
		logger.Fatal("Failed to create badger kv store", err)
	}

	err = badgerKv.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			key := item.Key()
			var result []byte
			item.Value(func(val []byte) error {
				result = append([]byte{}, val...)
				return nil
			})

			if !strings.HasPrefix(string(key), "eddsa:") {
				if !strings.HasPrefix(string(key), "ecdsa:") {
					badgerKv.DB.Update(func(txn *badger.Txn) error {
						txn.Set([]byte(fmt.Sprintf("ecdsa:%s", key)), result)
						txn.Delete(key)
						return nil
					})
				}

			}
		}
		return nil
	})
	keys, err := badgerKv.Keys()
	if err != nil {
		logger.Fatal("Failed to get keys from badger kv store", err)
	}

	for _, key := range keys {
		fmt.Printf("key = %+v\n", key)
	}
}
