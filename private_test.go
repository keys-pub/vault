package vault

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keys-pub/keys"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	var err error
	path := testPath()
	defer func() { _ = os.Remove(path) }()

	mk := testSeed(0x01)
	db, err := openDB(path, mk)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	err = initTables(db)
	require.NoError(t, err)

	err = setConfig(db, "key1", "val1")
	require.NoError(t, err)
	val, err := getConfig(db, "key1")
	require.NoError(t, err)
	require.Equal(t, "val1", val)
	err = setConfig(db, "key1", "val1.2")
	require.NoError(t, err)
	val, err = getConfig(db, "key1")
	require.NoError(t, err)
	require.Equal(t, "val1.2", val)
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func testPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("%s.db", keys.RandFileName()))
}
