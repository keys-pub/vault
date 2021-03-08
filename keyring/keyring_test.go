package keyring_test

import (
	"context"
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/keyring"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestKeyring(t *testing.T) {
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	kr, closeFn := testKeyringSetup(t, env, testutil.Seed(0x01), ck)
	defer closeFn()

	key := api.NewKey(keys.GenerateEdX25519Key())
	key.Notes = "test notes"
	key.Labels = []string{"alice", "temp"}
	key.Token = "token"
	key.CreatedAt = tsutil.NowMillis()
	key.UpdatedAt = tsutil.NowMillis()

	err = kr.Save(key)
	require.NoError(t, err)

	out, err := kr.Get(key.ID)
	require.NoError(t, err)
	require.Equal(t, key, out)
}

func TestKeyringSync(t *testing.T) {
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	kr1, closeFn1 := testKeyringSetup(t, env, testutil.Seed(0x01), ck)
	defer closeFn1()

	key := api.NewKey(keys.GenerateEdX25519Key())
	err = kr1.Save(key)
	require.NoError(t, err)
	err = kr1.Sync(context.TODO())
	require.NoError(t, err)

	kr2, closeFn2 := testKeyringSetup(t, env, testutil.Seed(0x02), ck)
	defer closeFn2()

	err = kr2.Sync(context.TODO())
	require.NoError(t, err)

	out, err := kr2.Get(key.ID)
	require.NoError(t, err)
	require.Equal(t, key, out)
}

func testKeyring(t *testing.T, env *testutil.Env) (*keyring.Keyring, func()) {
	var err error
	client := testutil.NewClient(t, env)
	path := testutil.Path()
	authPath := testutil.Path()

	auth, err := auth.NewDB(authPath)
	require.NoError(t, err)

	vlt, err := keyring.New(path, auth, vault.WithClient(client), vault.WithClock(tsutil.NewTestClock()))
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

func testKeyringSetup(t *testing.T, env *testutil.Env, mk *[32]byte, ck *keys.EdX25519Key) (*keyring.Keyring, func()) {
	vlt, closeFn := testKeyring(t, env)
	err := vlt.Setup(mk)
	require.NoError(t, err)
	err = vlt.Unlock(mk)
	require.NoError(t, err)
	err = vlt.SetClientKey(ck)
	require.NoError(t, err)
	return vlt, closeFn
}
