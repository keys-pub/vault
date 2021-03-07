package vault_test

import (
	"context"
	"testing"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestSync(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ctx := context.TODO()
	ck := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	// Client #1
	v1, closeFn1 := testVault(t, env, testSeed(0x01), ck)
	defer closeFn1()

	status, err := v1.SyncStatus()
	require.NoError(t, err)
	require.Equal(t, keys.ID("kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077"), status.ID)
	require.Empty(t, status.SyncedAt)

	err = v1.Add(&Message{Text: "hi alice"})
	require.NoError(t, err)
	err = v1.Add(&Message{Text: "hey bob"})
	require.NoError(t, err)

	err = v1.Sync(ctx)
	require.NoError(t, err)

	needs, err := v1.NeedsSync(time.Minute)
	require.NoError(t, err)
	require.False(t, needs)

	status, err = v1.SyncStatus()
	require.NoError(t, err)
	require.NotEmpty(t, status.SyncedAt)

	events, err := v1.Pulled(0)
	require.NoError(t, err)

	// Client #2
	v2, closeFn2 := testVault(t, env, testSeed(0x02), ck)
	defer closeFn2()

	err = v2.Add(&Message{Text: "meet at 3pm?"})
	require.NoError(t, err)

	err = v2.Sync(ctx)
	require.NoError(t, err)

	events2, err := v2.Pulled(0)
	require.NoError(t, err)
	require.Equal(t, events2[0:2], events)

	// Client #1 sync
	err = v1.Sync(ctx)
	require.NoError(t, err)
	events, err = v1.Pulled(0)
	require.NoError(t, err)
	require.Equal(t, events, events2)
}

// TODO: Test reset
