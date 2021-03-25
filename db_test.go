package vault_test

import (
	"os"
	"testing"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func testDB(t *testing.T) (*sqlx.DB, func()) {
	path := testutil.Path()
	db, err := vault.OpenDB(path, keys.Rand32())
	require.NoError(t, err)
	closeFn := func() {
		_ = db.Close()
		_ = os.Remove(path)
	}
	return db, closeFn
}

func TestDBKeys(t *testing.T) {
	db, closeFn := testDB(t)
	defer closeFn()

	err := vault.InitTables(db)
	require.NoError(t, err)

	key := api.NewKey(keys.GenerateEdX25519Key()).WithLabels("test")

	err = vault.UpdateKey(db, key)
	require.NoError(t, err)

	out, err := vault.GetKey(db, key.ID)
	require.NoError(t, err)
	require.Equal(t, out, key)

	key = key.WithNotes("testing")
	err = vault.UpdateKey(db, key)
	require.NoError(t, err)

	out, err = vault.GetKey(db, key.ID)
	require.NoError(t, err)
	require.Equal(t, out, key)
}

func TestConfig(t *testing.T) {
	var err error
	path := testPath()
	defer func() { _ = os.Remove(path) }()

	mk := testSeed(0x01)
	db, err := vault.OpenDB(path, mk)
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	err = vault.InitTables(db)
	require.NoError(t, err)

	err = vault.SetConfig(db, "key1", "val1")
	require.NoError(t, err)
	val, err := vault.GetConfig(db, "key1")
	require.NoError(t, err)
	require.Equal(t, "val1", val)
	err = vault.SetConfig(db, "key1", "val1.2")
	require.NoError(t, err)
	val, err = vault.GetConfig(db, "key1")
	require.NoError(t, err)
	require.Equal(t, "val1.2", val)
}
