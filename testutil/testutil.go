package testutil

import (
	"bytes"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/getchill-app/server"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault"
	"github.com/stretchr/testify/require"
)

// Env for testing.
type Env struct {
	clock      tsutil.Clock
	httpServer *httptest.Server
	srv        *server.Server
	CloseFn    func()
}

// NewEnv creates a test Env.
func NewEnv(t *testing.T, logLevel vault.LogLevel) *Env {
	clock := tsutil.NewTestClock()
	fi := dstore.NewMem()
	fi.SetClock(clock)
	client := http.NewClient()

	rds := server.NewRedisTest(clock)
	srv := server.New(fi, rds, client, clock, vault.NewLogger(logLevel))
	err := srv.SetInternalKey("6a169a699f7683c04d127504a12ace3b326e8b56a61a9b315cf6b42e20d6a44a")
	require.NoError(t, err)
	err = srv.SetTokenKey("f41deca7f9ef4f82e53cd7351a90bc370e2bf15ed74d147226439cfde740ac18")
	require.NoError(t, err)
	emailer := NewTestEmailer()
	srv.SetEmailer(emailer)

	handler := server.NewHandler(srv)
	httpServer := httptest.NewServer(handler)
	srv.URL = httpServer.URL

	return &Env{clock, httpServer, srv, func() { httpServer.Close() }}
}

// Path ...
func Path() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("%s.db", keys.RandFileName()))
}

// Seed ...
func Seed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

// TestEmailer ...
type TestEmailer struct {
	sentVerificationEmail map[string]string
}

// NewTestEmailer creates a test emailer.
func NewTestEmailer() *TestEmailer {
	return &TestEmailer{sentVerificationEmail: map[string]string{}}
}

func (t *TestEmailer) SentVerificationEmail(email string) string {
	s := t.sentVerificationEmail[email]
	return s
}

func (t *TestEmailer) SendVerificationEmail(email string, code string) error {
	t.sentVerificationEmail[email] = code
	return nil
}
