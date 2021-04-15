package client

import (
	"context"
	"encoding/json"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
)

// AccountCreateRequest ...
type AccountCreateRequest struct {
	Email string `json:"email"`
}

func (c *Client) AccountCreate(ctx context.Context, account *keys.EdX25519Key, email string) error {
	path := dstore.Path("account", account.ID())
	create := &AccountCreateRequest{Email: email}
	body, err := json.Marshal(create)
	if err != nil {
		return err
	}
	if _, err := c.Request(ctx, &Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}
