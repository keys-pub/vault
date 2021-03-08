package vault_test

import (
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestVaultSetup(t *testing.T) {
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	vlt, closeFn := testVault(t, env)
	defer closeFn()

	mk := keys.Rand32()

	err = vlt.Unlock(mk)
	require.EqualError(t, err, "needs setup")

	err = vlt.Setup(mk)
	require.NoError(t, err)
	require.False(t, vlt.NeedsSetup())

	// Unlock multiple times
	err = vlt.Unlock(mk)
	require.NoError(t, err)
	err = vlt.Unlock(mk)
	require.NoError(t, err)
}

func TestVaultInvalidPassword(t *testing.T) {
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	vlt, closeFn := testVault(t, env)
	defer closeFn()

	_, err = vlt.SetupPassword("testpassword")
	require.NoError(t, err)
	require.False(t, vlt.NeedsSetup())

	_, err = vlt.UnlockWithPassword("invalidpassword")
	require.EqualError(t, err, "invalid auth")
}

func testVault(t *testing.T, env *testutil.Env) (*vault.Vault, func()) {
	var err error
	client := testutil.NewClient(t, env)
	path := testutil.Path()
	authPath := testutil.Path()

	auth, err := auth.NewDB(authPath)
	require.NoError(t, err)

	vlt, err := vault.New(path, auth, nil, vault.WithClient(client), vault.WithClock(tsutil.NewTestClock()))
	require.NoError(t, err)

	closeFn := func() {
		err = auth.Close()
		require.NoError(t, err)
		err = os.Remove(authPath)
		require.NoError(t, err)
		err = vlt.Lock()
		require.NoError(t, err)
		err = os.Remove(path)
		require.NoError(t, err)
	}

	return vlt, closeFn
}

func testVaultSetup(t *testing.T, env *testutil.Env, mk *[32]byte, ck *keys.EdX25519Key) (*vault.Vault, func()) {
	vlt, closeFn := testVault(t, env)
	err := vlt.Setup(mk)
	require.NoError(t, err)
	err = vlt.Unlock(mk)
	require.NoError(t, err)
	err = vlt.SetClientKey(ck)
	require.NoError(t, err)
	return vlt, closeFn
}

// Message to store in vault.
type Message struct {
	Text string `msgpack:"text"`
}
