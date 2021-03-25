package vault_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/keys-pub/keys"
	httpapi "github.com/keys-pub/keys-ext/http/api"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault"
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
	ck := keys.NewEdX25519KeyFromSeed(testSeed(0xaf))

	t.Logf("--- Client #1 ---")
	v1, closeFn1 := testVaultSetup(t, env, keys.Rand32(), ck)
	defer closeFn1()

	// Add alice key
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	ak := api.NewKey(alice).WithLabels("alice")
	err = v1.Keyring().Set(ak)
	require.NoError(t, err)

	err = v1.Keyring().Sync(ctx)
	require.NoError(t, err)

	t.Logf("--- Client #2 ---")
	v2, closeFn2 := testVaultSetup(t, env, keys.Rand32(), ck)
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

	t.Logf("--- Client #1 ---")
	err = v1.Keyring().Sync(ctx)
	require.NoError(t, err)
	out2, err := v1.Keyring().Key(alice.ID())
	require.NoError(t, err)
	require.Equal(t, out2, out)
	require.Equal(t, "testing", out2.Notes)
}

func TestSyncCreateFind(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ck := keys.NewEdX25519KeyFromSeed(testSeed(0xaf))

	channel := keys.NewEdX25519KeyFromSeed(testSeed(0xb0))

	t.Logf("--- Client #1 ---")
	v1, closeFn1 := testVaultSetup(t, env, keys.Rand32(), ck)
	defer closeFn1()

	err = v1.Create(context.TODO(), channel)
	require.NoError(t, err)

	out, err := v1.Keyring().Key(channel.ID())
	require.NoError(t, err)
	require.Equal(t, out.ID, channel.ID())

	t.Logf("--- Client #2 ---")
	v2, closeFn2 := testVaultSetup(t, env, keys.Rand32(), ck)
	defer closeFn2()

	err = v2.Keyring().Sync(context.TODO())
	require.NoError(t, err)

	out2, err := v2.Keyring().Find(context.TODO(), channel.ID())
	require.NoError(t, err)
	require.Equal(t, out2.ID, channel.ID())
}

func TestSyncMessages(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ctx := context.TODO()
	ck := keys.NewEdX25519KeyFromSeed(testSeed(0xaf))

	channel := keys.NewEdX25519KeyFromSeed(testSeed(0xb0))
	alice := keys.NewEdX25519KeyFromSeed(testSeed(0x01))
	bob := keys.NewEdX25519KeyFromSeed(testSeed(0x02))

	t.Logf("--- Client #1 ---")
	v1, closeFn1 := testVaultSetup(t, env, keys.Rand32(), ck)
	defer closeFn1()

	err = v1.Create(context.TODO(), channel)
	require.NoError(t, err)

	err = v1.Add(channel.ID(), marshal(httpapi.NewMessage(alice.ID()).WithText("hi bob")))
	require.NoError(t, err)
	err = v1.Add(channel.ID(), marshal(httpapi.NewMessage(alice.ID()).WithText("what time is the meeting")))
	require.NoError(t, err)

	msgs1 := []*httpapi.Message{}
	receiverDb1 := func(ctx *vault.SyncContext, events []*vault.Event) error {
		for _, event := range events {
			msgs1 = append(msgs1, unmarshal(event.Data))
		}
		return nil
	}

	err = v1.Sync(ctx, channel.ID(), receiverDb1)
	require.NoError(t, err)

	t.Logf("--- Client #2 ---")
	v2, closeFn2 := testVaultSetup(t, env, keys.Rand32(), ck)
	defer closeFn2()

	msgs2 := []*httpapi.Message{}
	receiverDb2 := func(ctx *vault.SyncContext, events []*vault.Event) error {
		for _, event := range events {
			msgs2 = append(msgs2, unmarshal(event.Data))
		}
		return nil
	}

	err = v2.Sync(ctx, channel.ID(), receiverDb2)
	require.NoError(t, err)

	err = v2.Add(channel.ID(), marshal(httpapi.NewMessage(bob.ID()).WithText("hi alice, how about 2pm?")))
	require.NoError(t, err)

	err = v2.Sync(ctx, channel.ID(), receiverDb2)
	require.NoError(t, err)

	t.Logf("--- Client #1 ---")
	err = v1.Sync(ctx, channel.ID(), receiverDb1)
	require.NoError(t, err)

	require.Equal(t, msgs1, msgs2)
}

// TODO: Test reset

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func marshal(i interface{}) []byte {
	b, err := msgpack.Marshal(i)
	if err != nil {
		panic(err)
	}
	return b
}

func unmarshal(b []byte) *httpapi.Message {
	var m httpapi.Message
	if err := msgpack.Unmarshal(b, &m); err != nil {
		panic(err)
	}
	return &m
}
