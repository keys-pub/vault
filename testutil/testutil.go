package testutil

import (
	"net/http/httptest"
	"testing"

	"github.com/keys-pub/keys-ext/http/client"
	"github.com/keys-pub/keys-ext/http/server"
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
func NewEnv(t *testing.T, logger server.Logger) *Env {
	if logger == nil {
		logger = client.NewLogger(client.ErrLevel)
	}
	clock := tsutil.NewTestClock()
	fi := dstore.NewMem()
	fi.SetClock(clock)
	client := http.NewClient()

	rds := server.NewRedisTest(clock)
	srv := server.New(fi, rds, client, clock, logger)
	srv.SetClock(clock)
	srv.SetInternalAuth("testtoken")
	_ = srv.SetInternalKey("6a169a699f7683c04d127504a12ace3b326e8b56a61a9b315cf6b42e20d6a44a")
	handler := server.NewHandler(srv)
	httpServer := httptest.NewServer(handler)
	srv.URL = httpServer.URL

	return &Env{clock, httpServer, srv, func() { httpServer.Close() }}
}

// NewClient creates a test client.
func NewClient(t *testing.T, env *Env) *vault.Client {
	cl, err := vault.NewClient(env.httpServer.URL)
	require.NoError(t, err)
	cl.SetHTTPClient(env.httpServer.Client())
	cl.SetClock(env.clock)
	return cl
}
