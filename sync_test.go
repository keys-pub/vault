package vault_test

import (
	"context"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/sync"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestSyncKeyring(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ctx := context.TODO()
	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))

	t.Logf("Client #1")
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	// Add alice key
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	ak := api.NewKey(alice).WithLabels("alice")
	err = v1.Keyring().Set(ak)
	require.NoError(t, err)

	err = v1.Keyring().Sync(ctx)
	require.NoError(t, err)

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
	out3, err := v1.Keyring().Key(alice.ID())
	require.NoError(t, err)
	require.Nil(t, out3)

	// Sync again
	err = v2.Keyring().Sync(context.TODO())
	require.NoError(t, err)
}

func TestSyncCreateFind(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))

	channel := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb0))

	t.Logf("Client #1")
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	_, err = v1.Register(context.TODO(), channel)
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
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ctx := context.TODO()
	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))
	cipher := sync.NoCipher{}

	channel := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb0))
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))

	t.Logf("Client #1")
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", ck)
	defer closeFn1()

	_, err = v1.Register(context.TODO(), channel)
	require.NoError(t, err)

	err = v1.Add(channel, newMessage("msg1", alice.ID()).marshal(), cipher)
	require.NoError(t, err)
	err = v1.Add(channel, newMessage("msg2", alice.ID()).marshal(), cipher)
	require.NoError(t, err)

	msgs1 := []*message{}
	receiver1 := func(ctx *sync.Context, events []*vault.Event) error {
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
	receiver2 := func(ctx *sync.Context, events []*vault.Event) error {
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
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ctx := context.TODO()
	channel := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xb0))
	cipher := sync.NoCipher{}

	t.Logf("Alice")
	cka := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))
	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	v1, closeFn1 := testutil.NewTestVaultWithSetup(t, env, "testpassword1", cka)
	defer closeFn1()

	_, err = v1.Register(context.TODO(), channel)
	require.NoError(t, err)

	err = v1.Add(channel, newMessage("hi bob", alice.ID()).marshal(), cipher)
	require.NoError(t, err)
	err = v1.Add(channel, newMessage("what's for lunch?", alice.ID()).marshal(), cipher)
	require.NoError(t, err)

	aliceMsgs := []*message{}
	aliceReceiver := func(ctx *sync.Context, events []*vault.Event) error {
		for _, event := range events {
			aliceMsgs = append(aliceMsgs, unmarshalMessage(event.Data))
		}
		return nil
	}
	err = v1.Sync(ctx, channel.ID(), aliceReceiver)
	require.NoError(t, err)

	t.Logf("Bob")
	ckb := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xbf))
	bob := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x02))
	v2, closeFn2 := testutil.NewTestVaultWithSetup(t, env, "testpassword2", ckb)
	defer closeFn2()

	_, err = v2.Register(ctx, channel)
	require.NoError(t, err)

	bobMsgs := []*message{}
	bobReceiver := func(ctx *sync.Context, events []*vault.Event) error {
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
