package testutil

import (
	"os"
	"testing"

	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/stretchr/testify/require"
)

func NewTestVault(t *testing.T, env *Env) (*vault.Vault, func()) {
	var err error
	client := NewVaultClient(t, env)
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

func NewTestVaultWithSetup(t *testing.T, env *Env, password string, ck *api.Key) (*vault.Vault, func()) {
	vlt, closeFn := NewTestVault(t, env)
	mk, err := vlt.SetupPassword(password, ck)
	require.NoError(t, err)
	err = vlt.Unlock(mk)
	require.NoError(t, err)
	return vlt, closeFn
}
