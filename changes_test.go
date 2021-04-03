package vault_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/syncer"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestChanges(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, vault.ErrLevel)
	defer env.CloseFn()

	ctx := context.TODO()
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	testutil.AccountCreate(t, env, alice, "alice@getchill.app")
	ck := testutil.RegisterClient(t, env, keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0)), alice)

	channels := []*keys.EdX25519Key{
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xc1)),
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xc2)),
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xc3)),
		keys.NewEdX25519KeyFromSeed(testutil.Seed(0xc4)),
	}

	t.Logf("Client #1")
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	for _, channel := range channels {
		_, err = v1.Register(context.TODO(), channel, alice)
		require.NoError(t, err)
		err = v1.Add(channel, newMessage("msg1", alice.ID()).marshal(), syncer.CryptoBoxSealCipher{})
		require.NoError(t, err)
		empty := func(ctx *syncer.Context, events []*vault.Event) error { return nil }
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
		{VID: channels[3].ID(), Local: 0, Remote: 1, Timestamp: 1234567890110},
		{VID: channels[2].ID(), Local: 0, Remote: 1, Timestamp: 1234567890080},
		{VID: channels[1].ID(), Local: 0, Remote: 1, Timestamp: 1234567890050},
		{VID: channels[0].ID(), Local: 0, Remote: 1, Timestamp: 1234567890020},
	}
	require.Equal(t, expected, chgs)
}
