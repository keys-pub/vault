package vault_test

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v4"
)

func TestVault(t *testing.T) {
	// vault.SetLogger(vault.NewLogger(vault.DebugLevel))
	var err error
	env := testutil.NewEnv(t, nil) // vault.NewLogger(vault.DebugLevel))
	defer env.CloseFn()

	ck := keys.NewEdX25519KeyFromSeed(testSeed(0x01))

	// Vault #1
	v1, closeFn := testVault(t, env, testSeed(0x01), ck)
	defer closeFn()

	err = v1.Add(&Message{Text: "hi alice"})
	require.NoError(t, err)
	err = v1.Add(&Message{Text: "hello bob"})
	require.NoError(t, err)
	err = v1.Add(&Message{Text: "meet at 3pm?"})
	require.NoError(t, err)

	err = v1.Sync(context.TODO())
	require.NoError(t, err)

	events, err := v1.Pulled(0)
	require.NoError(t, err)

	// Vault #2
	v2, closeFn := testVault(t, env, testSeed(0x02), ck)
	defer closeFn()

	err = v2.Sync(context.TODO())
	require.NoError(t, err)

	events2, err := v2.Pulled(0)
	require.NoError(t, err)
	require.Equal(t, events, events2)
}

func testPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("%s.db", keys.RandFileName()))
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func testVault(t *testing.T, env *testutil.Env, mk *[32]byte, ck *keys.EdX25519Key) (*vault.Vault, func()) {
	var err error
	client := testutil.NewClient(t, env, "vault")
	path := testPath()
	authPath := testPath()

	auth, err := auth.NewDB(authPath)
	require.NoError(t, err)

	vlt, err := vault.New(path, auth, nil, vault.WithClient(client), vault.WithClock(tsutil.NewTestClock()))
	require.NoError(t, err)
	err = vlt.Setup(mk)
	require.NoError(t, err)
	if ck != nil {
		err = vlt.SetClientKey(ck)
		require.NoError(t, err)
	}

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

// Message to store in vault.
type Message struct {
	Text string `msgpack:"text"`
}

// MarshalVault how to marshal for vault.
func (m *Message) MarshalVault() ([]byte, error) {
	return msgpack.Marshal(m)
}
