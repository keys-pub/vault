package vault_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestKeyring(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, vault.ErrLevel)
	defer env.CloseFn()

	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	testutil.AccountCreate(t, env, alice, "alice@getchill.app")
	ck := testutil.RegisterClient(t, env, keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0)), alice)

	vlt, closeFn := testutil.NewTestVaultWithSetup(t, env, "testpassword", ck)
	defer closeFn()
	kr := vlt.Keyring()

	bobKey := api.NewKey(keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))).WithLabels("bob", "testkey")
	err = vlt.Keyring().Set(bobKey)
	require.NoError(t, err)
	charlieKey := api.NewKey(keys.NewX25519KeyFromSeed(testutil.Seed(0x03))).WithLabels("charlie", "testkey")
	err = kr.Set(charlieKey)
	require.NoError(t, err)

	out, err := kr.KeysWithType(string(keys.X25519))
	require.NoError(t, err)
	require.Equal(t, 1, len(out))
	require.Equal(t, out[0].ID, charlieKey.ID)

	out, err = kr.KeysWithLabel("bob")
	require.NoError(t, err)
	require.Equal(t, 1, len(out))
	require.Equal(t, out[0].ID, bobKey.ID)
	out1, err := kr.KeyWithLabel("bob")
	require.NoError(t, err)
	require.NotNil(t, out1)
	require.Equal(t, out1.ID, bobKey.ID)
	_, err = kr.KeyWithLabel("testkey")
	require.EqualError(t, err, `multiple keys for label "testkey"`)

	out, err = kr.KeysWithLabel("testkey")
	require.NoError(t, err)
	require.Equal(t, 2, len(out))
	require.Equal(t, out[0].ID, bobKey.ID)
	require.Equal(t, out[1].ID, charlieKey.ID)
}
