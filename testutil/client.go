package testutil

import (
	"context"
	"testing"

	hclient "github.com/getchill-app/http-client"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	vclient "github.com/keys-pub/vault/client"
	"github.com/stretchr/testify/require"
)

// NewKeysPubClient creates a test client.
func NewKeysPubClient(t *testing.T, env *Env) *hclient.Client {
	cl, err := hclient.New(env.httpServer.URL)
	require.NoError(t, err)
	cl.SetHTTPClient(env.httpServer.Client())
	cl.SetClock(env.clock)
	return cl
}

// NewVaultClient creates a test client.
func NewVaultClient(t *testing.T, env *Env) *vclient.Client {
	cl, err := vclient.New(env.httpServer.URL)
	require.NoError(t, err)
	cl.SetHTTPClient(env.httpServer.Client())
	cl.SetClock(env.clock)
	return cl
}

// AccountCreate creates an account.
func AccountCreate(t *testing.T, env *Env, key *keys.EdX25519Key, email string) {
	hclient := NewKeysPubClient(t, env)
	err := hclient.AccountCreate(context.TODO(), key, email)
	require.NoError(t, err)
}

// RegisterClient registers a client key.
func RegisterClient(t *testing.T, env *Env, key *keys.EdX25519Key, account *keys.EdX25519Key) *api.Key {
	vclient := NewVaultClient(t, env)
	ck, err := vclient.Register(context.TODO(), key, account)
	require.NoError(t, err)
	return ck
}
