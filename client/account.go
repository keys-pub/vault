package client

import (
	"context"
	"encoding/json"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/dstore"
	"github.com/keys-pub/keys/http/client"
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
	if _, err := c.Request(ctx, &client.Request{Method: "PUT", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}

// AccountCreateRequest ...
type AccountVerifyEmailRequest struct {
	Code string `json:"code"`
}

func (c *Client) AccountVerify(ctx context.Context, account *keys.EdX25519Key, code string) error {
	path := dstore.Path("account", account.ID(), "verify-email")
	body, _ := json.Marshal(&AccountVerifyEmailRequest{Code: code})
	if _, err := c.Request(ctx, &client.Request{Method: "POST", Path: path, Body: body, Key: account}); err != nil {
		return err
	}
	return nil
}
