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

	bobKey := api.NewKey(keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))).WithLabels("bob")
	err = vlt.Keyring().Set(bobKey)
	require.NoError(t, err)
	charlieKey := api.NewKey(keys.NewX25519KeyFromSeed(testutil.Seed(0x03))).WithLabels("charlie")
	err = kr.Set(charlieKey)
	require.NoError(t, err)

	sks, err := kr.KeysWithType(string(keys.X25519))
	require.NoError(t, err)
	require.Equal(t, 1, len(sks))
	require.Equal(t, sks[0].ID, charlieKey.ID)
}
