package syncer

import (
	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/client"
)

// Context is context for sync.
type Context struct {
	VID keys.ID
	Tx  *sqlx.Tx
}

// Receiver is notified when events are received from the remote.
type Receiver func(ctx *Context, events []*client.Event) error
