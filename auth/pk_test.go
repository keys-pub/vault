package auth_test

import (
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/auth/api"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestPaperKey(t *testing.T) {
	path := testutil.Path()
	db, err := auth.NewDB(path)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()

	mk := testutil.Seed(0x01)
	paperKey := keys.RandPhrase()

	reg, err := db.RegisterPaperKey(paperKey, mk)
	require.NoError(t, err)

	auths, err := db.ListByType(api.PaperKeyType)
	require.NoError(t, err)
	require.Equal(t, 1, len(auths))

	out, mko, err := db.PaperKey(paperKey)
	require.NoError(t, err)
	require.Equal(t, mk, mko)
	require.Equal(t, out.ID, reg.ID)

	_, _, err = db.PaperKey(keys.RandPhrase())
	require.EqualError(t, err, "invalid auth")

	_, _, err = db.PaperKey("")
	require.EqualError(t, err, "invalid auth")
}
