package auth_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/testutil"
	"github.com/stretchr/testify/require"
)

func gopath(t *testing.T) string {
	cmd := exec.Command("go", "env", "GOPATH")
	out, err := cmd.Output()
	require.NoError(t, err)
	return strings.TrimSpace(string(out))
}

func TestFIDO2(t *testing.T) {
	if os.Getenv("TEST_FIDO2") == "" {
		t.Skip()
	}
	path := testutil.Path()
	db, err := auth.NewDB(path)
	require.NoError(t, err)
	defer func() { _ = os.Remove(path) }()

	mk := testutil.Seed(0x01)
	pin := "12345"

	fido2Path := filepath.Join(gopath(t), "bin", "fido2.so")
	fido2Plugin, err := fido2.OpenPlugin(fido2Path)
	if err != nil {
		t.Skipf("No fido2 plugin found %s", fido2Path)
	}

	t.Logf("Generate...")
	hs, err := auth.GenerateFIDO2HMACSecret(context.TODO(), fido2Plugin, pin, "", "test")
	require.NoError(t, err)

	t.Logf("Register...")
	reg, err := db.RegisterFIDO2HMACSecret(context.TODO(), fido2Plugin, hs, mk, pin)
	require.NoError(t, err)

	auths, err := db.ListByType(auth.FIDO2HMACSecretType)
	require.NoError(t, err)
	require.Equal(t, 1, len(auths))

	t.Logf("Auth...")
	out, mko, err := db.FIDO2HMACSecret(context.TODO(), fido2Plugin, pin)
	require.NoError(t, err)
	require.Equal(t, mk, mko)
	require.Equal(t, out.ID, reg.ID)
}
