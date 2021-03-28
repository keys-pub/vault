package auth_test

import (
	"context"
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestSync(t *testing.T) {
	env := testutil.NewEnv(t, nil)
	client := testutil.NewClient(t, env)
	ck := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xaf))

	t.Logf("DB #1")
	path1 := testutil.Path()
	db1, err := auth.NewDB(path1, auth.WithClientKey(ck))
	require.NoError(t, err)
	defer func() { _ = os.Remove(path1) }()

	mk := testutil.Seed(0x01)

	reg1, err := db1.RegisterPassword("testpassword", mk)
	require.NoError(t, err)

	pk := keys.RandPhrase()
	_, err = db1.RegisterPaperKey(pk, mk)
	require.NoError(t, err)

	err = db1.Sync(context.TODO(), client)
	require.NoError(t, err)

	t.Logf("DB #2")
	path2 := testutil.Path()
	db2, err := auth.NewDB(path2, auth.WithClientKey(ck))
	require.NoError(t, err)
	defer func() { _ = os.Remove(path2) }()

	err = db2.Sync(context.TODO(), client)
	require.NoError(t, err)

	out, mko, err := db2.Password("testpassword")
	require.NoError(t, err)
	require.Equal(t, mk, mko)
	require.Equal(t, out.ID, reg1.ID)

}
