package vault_test

import (
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestKeyring(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))
	vlt, closeFn := testutil.NewTestVaultWithSetup(t, env, "testpassword", ck)
	defer closeFn()
	kr := vlt.Keyring()

	alice := api.NewKey(keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))).WithLabels("alice")
	err = kr.Set(alice)
	require.NoError(t, err)
	bob := api.NewKey(keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))).WithLabels("bob")
	bpk := api.NewKey(bob.ID)
	err = vlt.Keyring().Set(bpk)
	require.NoError(t, err)
	charlie := api.NewKey(keys.NewX25519KeyFromSeed(testutil.Seed(0x03))).WithLabels("charlie")
	err = kr.Set(charlie)
	require.NoError(t, err)

	sks, err := kr.KeysByType(string(keys.X25519))
	require.NoError(t, err)
	require.Equal(t, 1, len(sks))
	require.Equal(t, sks[0].ID, charlie.ID)
}
