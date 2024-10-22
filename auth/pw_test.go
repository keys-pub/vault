package auth_test

import (
	"os"
	"testing"

	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/auth/api"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func TestPassword(t *testing.T) {
	path := testutil.Path()
	db, err := auth.NewDB(path)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()

	mk := testutil.Seed(0x01)

	reg, err := db.RegisterPassword("testpassword", mk)
	require.NoError(t, err)

	auths, err := db.ListByType(api.PasswordType)
	require.NoError(t, err)
	require.Equal(t, 1, len(auths))

	out, mko, err := db.Password("testpassword")
	require.NoError(t, err)
	require.Equal(t, mk, mko)
	require.Equal(t, out.ID, reg.ID)

	_, _, err = db.Password("invalidpassword")
	require.EqualError(t, err, "invalid auth")

	_, _, err = db.Password("")
	require.EqualError(t, err, "invalid auth")
}
