package vault_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestVaultSetup(t *testing.T) {
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	vlt, closeFn := testutil.NewTestVault(t, env)
	defer closeFn()

	mk := keys.Rand32()

	err = vlt.Unlock(mk)
	require.EqualError(t, err, "setup needed")
	require.Equal(t, vault.SetupNeeded, vlt.Status())

	err = vlt.Setup(mk)
	require.NoError(t, err)
	require.Equal(t, vault.Unlocked, vlt.Status())
	err = vlt.Lock()
	require.NoError(t, err)

	err = vlt.Setup(mk)
	require.EqualError(t, err, "already setup")

	// Unlock multiple times
	err = vlt.Unlock(mk)
	require.NoError(t, err)
	require.Equal(t, vault.Unlocked, vlt.Status())
	err = vlt.Unlock(mk)
	require.NoError(t, err)

	// Lock, unlock
	err = vlt.Lock()
	require.NoError(t, err)
	require.Equal(t, vault.Locked, vlt.Status())
	err = vlt.Unlock(mk)
	require.NoError(t, err)
}

func TestVaultLocked(t *testing.T) {
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	vlt, closeFn := testutil.NewTestVault(t, env)
	defer closeFn()

	mk := keys.Rand32()
	err = vlt.Setup(mk)
	require.NoError(t, err)

	// Try accessing keyring while locked
	err = vlt.Lock()
	require.NoError(t, err)
	_, err = vlt.Keyring().Key(keys.RandID("test"))
	require.EqualError(t, err, "vault is locked")
	_, err = vlt.Keyring().Keys()
	require.EqualError(t, err, "vault is locked")
	_, err = vlt.Keyring().Find(context.TODO(), keys.RandID("test"))
	require.EqualError(t, err, "vault is locked")
	err = vlt.Keyring().Sync(context.TODO())
	require.EqualError(t, err, "vault is locked")
}

func TestVaultInvalidPassword(t *testing.T) {
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	vlt, closeFn := testutil.NewTestVault(t, env)
	defer closeFn()

	_, err = vlt.SetupPassword("testpassword")
	require.NoError(t, err)
	require.Equal(t, vault.Unlocked, vlt.Status())

	_, err = vlt.UnlockWithPassword("invalidpassword")
	require.EqualError(t, err, "invalid auth")
}
