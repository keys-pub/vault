package vault

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/http/api"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Events ...
type Events struct {
	Events    []*Event
	Index     int64
	Truncated bool
}

// Events from vault API.
// If truncated, there are more results if you call again with the new index.
func (c *Client) Events(ctx context.Context, key *keys.EdX25519Key, index int64) (*Events, error) {
	if key == nil {
		return nil, errors.Errorf("no api key")
	}
	path := dstore.Path("vault", key.ID()) + ".msgpack"
	params := url.Values{}
	if index != 0 {
		params.Add("idx", strconv.FormatInt(index, 10))
	}

	resp, err := c.Request(ctx, &Request{Method: "GET", Path: path, Params: params, Key: key})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}

	var out api.VaultResponse
	if err := msgpack.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}

	// Decrypt
	sk := secretKey(key)
	events := []*Event{}
	for _, e := range out.Vault {
		b, err := keys.SecretBoxOpen(e.Data, sk)
		if err != nil {
			return nil, err
		}
		event := &Event{
			Data:            b,
			RemoteIndex:     e.Index,
			RemoteTimestamp: tsutil.ParseMillis(e.Timestamp),
			VID:             key.ID(),
		}
		events = append(events, event)
	}

	return &Events{
		Events:    events,
		Index:     out.Index,
		Truncated: out.Truncated,
	}, nil
}

// Post events to the vault API with a key.
func (c *Client) Post(ctx context.Context, key *keys.EdX25519Key, data [][]byte) error {
	if key == nil {
		return errors.Errorf("no api key")
	}
	path := dstore.Path("vault", key.ID()) + ".msgpack"

	// Encrypt
	sk := secretKey(key)
	out := [][]byte{}
	for _, d := range data {
		b := keys.SecretBoxSeal(d, sk)
		out = append(out, b)
	}

	b, err := msgpack.Marshal(out)
	if err != nil {
		return err
	}

	start := time.Time{}
	total := int64(0)
	progress := func(n int64) {
		total += n
		if start.IsZero() {
			logger.Debugf("Sending request body...")
			start = time.Now()
		}
		if n == 0 {
			logger.Debugf("Sent request body (%d, %s)", total, time.Since(start))
		}
	}

	if _, err := c.Request(ctx, &Request{Method: "POST", Path: path, Body: b, Key: key, Progress: progress}); err != nil {
		return err
	}
	return nil
}

// Delete from vault API.
func (c *Client) Delete(ctx context.Context, key *keys.EdX25519Key) error {
	path := dstore.Path("vault", key.ID())
	if _, err := c.Request(ctx, &Request{Method: "DELETE", Path: path, Key: key}); err != nil {
		return err
	}
	return nil
}

// Register a vault.
func (c *Client) Register(ctx context.Context, vault *keys.EdX25519Key) (string, error) {
	path := dstore.Path("vault", vault.ID())
	resp, err := c.Request(ctx, &Request{Method: "PUT", Path: path, Key: vault})
	if err != nil {
		return "", err
	}
	var token api.VaultToken
	if err := json.Unmarshal(resp.Data, &token); err != nil {
		return "", err
	}
	return token.Token, nil
}

// Get a vault.
// Returns nil if not found.
func (c *Client) Get(ctx context.Context, vault *keys.EdX25519Key) (*Token, error) {
	logger.Debugf("Get vault %s", vault.ID())
	path := dstore.Path("vault", vault.ID(), "info")
	resp, err := c.Request(ctx, &Request{Method: "GET", Path: path, Key: vault})
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, nil
	}
	var token Token
	if err := json.Unmarshal(resp.Data, &token); err != nil {
		return nil, err
	}

	return &token, nil
}

// Token alias.
type Token = api.VaultToken

// RemoteStatus alias.
type RemoteStatus = api.VaultStatus

// Status ...
func (c *Client) Status(ctx context.Context, tokens []*Token) ([]*RemoteStatus, error) {
	statusReq := api.VaultsStatusRequest{
		Vaults: map[keys.ID]string{},
	}
	for _, t := range tokens {
		if t.Token == "" {
			return nil, errors.Errorf("empty token")
		}
		statusReq.Vaults[t.KID] = t.Token
	}

	body, err := json.Marshal(statusReq)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	resp, err := c.Request(ctx, &Request{Method: "POST", Path: "/vaults/status", Params: params, Body: body})
	if err != nil {
		return nil, err
	}

	var out api.VaultsStatusResponse
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		return nil, err
	}
	sort.Slice(out.Vaults, func(i, j int) bool {
		return out.Vaults[i].Timestamp > out.Vaults[j].Timestamp
	})
	return out.Vaults, nil
}
