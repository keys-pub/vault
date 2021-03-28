package auth_test

import (
	"os"
	"testing"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/auth"
	"github.com/stretchr/testify/require"
)

func TestPaperKey(t *testing.T) {
	path := testPath()
	db, err := auth.NewDB(path)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()

	mk := testSeed(0x01)
	paperKey := keys.RandPhrase()

	reg, err := db.RegisterPaperKey(paperKey, mk)
	require.NoError(t, err)

	auths, err := db.ListByType(auth.PaperKeyType)
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
