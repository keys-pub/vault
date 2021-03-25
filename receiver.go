package vault

import (
	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
)

// SyncContext is context for sync.
type SyncContext struct {
	VID keys.ID
	Tx  *sqlx.Tx
}

// Receiver is notified when events are received from the remote.
type Receiver func(ctx *SyncContext, events []*Event) error
