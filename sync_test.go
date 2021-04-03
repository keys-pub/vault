package vault_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/syncer"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestSyncKeyring(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, vault.ErrLevel)
	defer env.CloseFn()

	ctx := context.TODO()

	t.Logf("Client #1")
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	testutil.AccountCreate(t, env, alice, "alice@getchill.app")
	ck := testutil.RegisterClient(t, env, keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0)), alice)
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	// Add alice key
	ak := api.NewKey(alice).WithLabels("alice")
	err = v1.Keyring().Set(ak)
	require.NoError(t, err)

	err = v1.Keyring().Sync(ctx)
	require.NoError(t, err)

	outs, err := v1.Keyring().KeysWithLabel("alice")
	require.NoError(t, err)
	require.Equal(t, 1, len(outs))
	require.Equal(t, alice.ID(), outs[0].ID)

	t.Logf("Client #2")
	v2, closeFn2 := testutil.NewTestVaultWithSetup(t, env, "testpassword2", ck)
	defer closeFn2()

	err = v2.Keyring().Sync(ctx)
	require.NoError(t, err)

	out, err := v2.Keyring().Key(alice.ID())
	require.NoError(t, err)
	require.Equal(t, out, ak)

	// Update key
	out = out.WithNotes("testing")
	err = v2.Keyring().Set(out)
	require.NoError(t, err)

	err = v2.Keyring().Sync(context.TODO())
	require.NoError(t, err)

	t.Logf("Client #1")
	err = v1.Keyring().Sync(ctx)
	require.NoError(t, err)
	out2, err := v1.Keyring().Key(alice.ID())
	require.NoError(t, err)
	require.Equal(t, out2, out)
	require.Equal(t, "testing", out2.Notes)

	// Remove key
	err = v1.Keyring().Remove(alice.ID())
	require.NoError(t, err)
	err = v1.Keyring().Sync(context.TODO())
	require.NoError(t, err)

	t.Logf("Client #2")
	err = v2.Keyring().Sync(context.TODO())
	require.NoError(t, err)
	out3, err := v1.Keyring().Get(alice.ID())
	require.NoError(t, err)
	require.Nil(t, out3)
	_, err = v1.Keyring().Key(alice.ID())
	require.EqualError(t, err, "kex132yw8ht5p8cetl2jmvknewjawt9xwzdlrk2pyxlnwjyqrdq0dawqqph077 not found")

	// Sync again
	err = v2.Keyring().Sync(context.TODO())
	require.NoError(t, err)
}

func TestSyncCreateFind(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, vault.ErrLevel)
	defer env.CloseFn()

	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))
	testutil.AccountCreate(t, env, alice, "alice@getchill.app")
	ck := testutil.RegisterClient(t, env, keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0)), alice)

	channel := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb0))

	t.Logf("Client #1")
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	_, err = v1.Register(context.TODO(), channel, alice)
	require.NoError(t, err)

	out, err := v1.Keyring().Key(channel.ID())
	require.NoError(t, err)
	require.Equal(t, out.ID, channel.ID())

	t.Logf("Client #2")
	v2, closeFn2 := testutil.NewTestVaultWithSetup(t, env, "testpassword2", ck)
	defer closeFn2()

	err = v2.Keyring().Sync(context.TODO())
	require.NoError(t, err)

	out2, err := v2.Keyring().Find(context.TODO(), channel.ID())
	require.NoError(t, err)
	require.NotNil(t, out2)
	require.Equal(t, out2.ID, channel.ID())
}

type message struct {
	ID     string  `msgpack:"id"`
	Text   string  `msgpack:"text"`
	Sender keys.ID `msgpack:"sender"`
}

func newMessage(text string, sender keys.ID) *message {
	return &message{
		ID:     encoding.MustEncode(keys.RandBytes(32), encoding.Base62),
		Text:   text,
		Sender: sender,
	}
}

func (m message) marshal() []byte {
	b, err := msgpack.Marshal(m)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSyncMessages(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, vault.ErrLevel)
	defer env.CloseFn()

	ctx := context.TODO()
	cipher := syncer.NoCipher{}

	channel := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb0))

	t.Logf("Client #1")
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	testutil.AccountCreate(t, env, alice, "alice@getchill.app")
	ck := testutil.RegisterClient(t, env, keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0)), alice)
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	_, err = v1.Register(context.TODO(), channel, alice)
	require.NoError(t, err)

	err = v1.Add(channel, newMessage("msg1", alice.ID()).marshal(), cipher)
	require.NoError(t, err)
	err = v1.Add(channel, newMessage("msg2", alice.ID()).marshal(), cipher)
	require.NoError(t, err)

	msgs1 := []*message{}
	receiver1 := func(ctx *syncer.Context, events []*vault.Event) error {
		for _, event := range events {
			msgs1 = append(msgs1, unmarshalMessage(event.Data))
		}
		return nil
	}

	err = v1.Sync(ctx, channel.ID(), receiver1)
	require.NoError(t, err)

	t.Logf("Client #2")
	v2, closeFn2 := testutil.NewTestVaultWithSetup(t, env, "testpassword2", ck)
	defer closeFn2()

	msgs2 := []*message{}
	receiver2 := func(ctx *syncer.Context, events []*vault.Event) error {
		for _, event := range events {
			msgs2 = append(msgs2, unmarshalMessage(event.Data))
		}
		return nil
	}

	err = v2.Sync(ctx, channel.ID(), receiver2)
	require.NoError(t, err)

	err = v2.Add(channel, newMessage("msg3", alice.ID()).marshal(), cipher)
	require.NoError(t, err)

	err = v2.Sync(ctx, channel.ID(), receiver2)
	require.NoError(t, err)

	t.Logf("Client #1")
	err = v1.Sync(ctx, channel.ID(), receiver1)
	require.NoError(t, err)

	require.Equal(t, msgs1, msgs2)
}

func TestSyncAliceBob(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, vault.ErrLevel)
	defer env.CloseFn()

	ctx := context.TODO()
	channel := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb0))
	cipher := syncer.NoCipher{}

	t.Logf("Alice")
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	testutil.AccountCreate(t, env, alice, "alice@getchill.app")
	cka := testutil.RegisterClient(t, env, keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0)), alice)
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", cka)
	defer closeFn1()

	_, err = v1.Register(context.TODO(), channel, alice)
	require.NoError(t, err)

	err = v1.Add(channel, newMessage("hi bob", alice.ID()).marshal(), cipher)
	require.NoError(t, err)
	err = v1.Add(channel, newMessage("what's for lunch?", alice.ID()).marshal(), cipher)
	require.NoError(t, err)

	aliceMsgs := []*message{}
	aliceReceiver := func(ctx *syncer.Context, events []*vault.Event) error {
		for _, event := range events {
			aliceMsgs = append(aliceMsgs, unmarshalMessage(event.Data))
		}
		return nil
	}
	err = v1.Sync(ctx, channel.ID(), aliceReceiver)
	require.NoError(t, err)

	t.Logf("Bob")
	bob := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))
	testutil.AccountCreate(t, env, bob, "bob@getchill.app")
	ckb := testutil.RegisterClient(t, env, keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa1)), bob)
	v2, closeFn2 := testutil.NewTestVaultWithSetup(t, env, "testpassword2", ckb)
	defer closeFn2()

	_, err = v2.Register(ctx, channel, bob)
	require.NoError(t, err)

	bobMsgs := []*message{}
	bobReceiver := func(ctx *syncer.Context, events []*vault.Event) error {
		for _, event := range events {
			bobMsgs = append(bobMsgs, unmarshalMessage(event.Data))
		}
		return nil
	}

	err = v2.Sync(ctx, channel.ID(), bobReceiver)
	require.NoError(t, err)

	err = v2.Add(channel, newMessage("homemade mcribs", bob.ID()).marshal(), cipher)
	require.NoError(t, err)

	err = v2.Sync(ctx, channel.ID(), bobReceiver)
	require.NoError(t, err)

	t.Logf("Alice")
	err = v1.Sync(ctx, channel.ID(), aliceReceiver)
	require.NoError(t, err)

	require.Equal(t, aliceMsgs, bobMsgs)
}

func unmarshalMessage(b []byte) *message {
	var m message
	if err := msgpack.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return &m
}
