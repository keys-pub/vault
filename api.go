package vault

import (
	"context"
	"net/url"
	"strconv"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/http/api"
	"github.com/keys-pub/keys-ext/http/client"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Client for API.
type Client struct {
	*client.Client
	collection string
}

// NewClientWithURL creates a client.
func NewClientWithURL(urs string, collection string) (*Client, error) {
	cl, err := client.New(urs)
	if err != nil {
		return nil, err
	}
	return &Client{cl, collection}, nil
}

// NewClient creates a client.
func NewClient(cl *client.Client, collection string) *Client {
	return &Client{cl, collection}
}

// Post events to the vault API with a key.
func (c *Client) Post(ctx context.Context, key *keys.EdX25519Key, data [][]byte) error {
	if key == nil {
		return errors.Errorf("no api key")
	}
	path := dstore.Path(c.collection, key.ID()) + ".msgpack"

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
			logger.Debugf("Sent request body (%d, %s)", total, time.Now().Sub(start))
		}
	}

	if _, err := c.Request(ctx, &client.Request{Method: "POST", Path: path, Body: b, Key: key, Progress: progress}); err != nil {
		return err
	}
	return nil
}

// Events ...
type Events struct {
	Events    []*Event
	Index     int64
	Truncated bool
}

func secretKey(key *keys.EdX25519Key) *[32]byte {
	b := keys.HKDFSHA256(key.Seed()[:], 32, nil, []byte("keys.pub/vault"))
	return keys.Bytes32(b)
}

// Get events from vault API.
// If truncated, there are more results if you call again with the new index.
func (c *Client) Get(ctx context.Context, key *keys.EdX25519Key, index int64) (*Events, error) {
	if key == nil {
		return nil, errors.Errorf("no api key")
	}
	path := dstore.Path(c.collection, key.ID()) + ".msgpack"
	params := url.Values{}
	if index != 0 {
		params.Add("idx", strconv.FormatInt(index, 10))
	}

	resp, err := c.Request(ctx, &client.Request{Method: "GET", Path: path, Params: params, Key: key})
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
		}
		events = append(events, event)
	}

	return &Events{events, out.Index, out.Truncated}, nil
}

// Delete from vault API.
func (c *Client) Delete(ctx context.Context, key *keys.EdX25519Key) error {
	path := dstore.Path(c.collection, key.ID())
	if _, err := c.Request(ctx, &client.Request{Method: "DELETE", Path: path, Key: key}); err != nil {
		return err
	}
	return nil
}
