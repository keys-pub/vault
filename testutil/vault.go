package testutil

import (
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/stretchr/testify/require"
)

func NewTestVault(t *testing.T, env *Env) (*vault.Vault, func()) {
	var err error
	client := NewClient(t, env)
	path := Path()
	authPath := Path()

	auth, err := auth.NewDB(authPath)
	require.NoError(t, err)

	vlt, err := vault.New(path, auth, vault.WithClient(client), vault.WithClock(tsutil.NewTestClock()))
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

func NewTestVaultWithSetup(t *testing.T, env *Env, mk *[32]byte, key *keys.EdX25519Key) (*vault.Vault, func()) {
	vlt, closeFn := NewTestVault(t, env)
	err := vlt.Setup(mk, vault.WithClientKey(key))
	require.NoError(t, err)
	err = vlt.Unlock(mk)
	require.NoError(t, err)
	return vlt, closeFn
}
