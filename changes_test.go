package vault_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/sync"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestChanges(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ctx := context.TODO()
	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))

	channels := []*keys.EdX25519Key{
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb1)),
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb2)),
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb3)),
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb4)),
	}
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))

	t.Logf("Client #1")
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	for _, channel := range channels {
		_, err = v1.Register(context.TODO(), channel)
		require.NoError(t, err)
		err = v1.Add(channel.ID(), newMessage("msg1", alice.ID()).marshal())
		require.NoError(t, err)
		empty := func(ctx *sync.Context, events []*vault.Event) error { return nil }
		err = v1.Sync(ctx, channel.ID(), empty)
		require.NoError(t, err)
	}

	t.Logf("Client #2")
	v2, closeFn2 := testutil.NewTestVaultWithSetup(t, env, "testpassword2", ck)
	defer closeFn2()

	err = v2.Keyring().Sync(context.TODO())
	require.NoError(t, err)

	chgs, err := v2.Changes(context.TODO())
	require.NoError(t, err)
	expected := []*vault.Change{
		{VID: channels[3].ID(), Local: 0, Remote: 1, Timestamp: 1234567890070},
		{VID: channels[2].ID(), Local: 0, Remote: 1, Timestamp: 1234567890048},
		{VID: channels[1].ID(), Local: 0, Remote: 1, Timestamp: 1234567890026},
		{VID: channels[0].ID(), Local: 0, Remote: 1, Timestamp: 1234567890004},
	}
	require.Equal(t, expected, chgs)
}
