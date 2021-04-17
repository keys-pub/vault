package client

import (
	hclient "github.com/keys-pub/keys/http/client"
)

// Client ...
type Client struct {
	*hclient.Client
}

// New creates a Client for the a Web API.
func New(urs string) (*Client, error) {
	cl, err := hclient.New(urs)
	if err != nil {
		return nil, err
	}
	return &Client{cl}, nil
}
