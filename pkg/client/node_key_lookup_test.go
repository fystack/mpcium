package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewNodeKeyLookup(t *testing.T) {
	dir := t.TempDir()

	writeIdentity := func(name, nodeID string, pub ed25519.PublicKey) {
		data, err := json.Marshal(map[string]string{
			"node_name":  name,
			"node_id":    nodeID,
			"public_key": hex.EncodeToString(pub),
		})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, name+"_identity.json"), data, 0600))
	}

	pub0, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	writeIdentity("node0", "id-0", pub0)
	writeIdentity("node1", "id-1", pub1)
	// Non-identity files in the same directory must be ignored.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node0_private.key"), []byte("x"), 0600))

	lookup, err := NewNodeKeyLookup(dir)
	require.NoError(t, err)

	got, err := lookup("id-0")
	require.NoError(t, err)
	require.Equal(t, []byte(pub0), got)

	got, err = lookup("id-1")
	require.NoError(t, err)
	require.Equal(t, []byte(pub1), got)

	_, err = lookup("unknown")
	require.Error(t, err)
}
