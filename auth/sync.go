package auth

import (
	"context"

	"github.com/keys-pub/vault/client"
	"github.com/keys-pub/vault/sync"
	"github.com/vmihailenco/msgpack/v4"
)

// Sync db.
// Returns error if sync is not enabled.
func (d *DB) Sync(ctx context.Context, client *client.Client) error {
	s := sync.NewSyncer(d.db, client, d.receive)
	if err := s.Sync(ctx, d.ck); err != nil {
		return err
	}
	return nil
}

func (d *DB) receive(ctx *sync.Context, events []*client.Event) error {
	for _, event := range events {
		var auth Auth
		if err := msgpack.Unmarshal(event.Data, &auth); err != nil {
			return err
		}
		if auth.Deleted {
			if err := deleteTx(ctx.Tx, auth.ID); err != nil {
				return err
			}
		} else {
			if err := addTx(ctx.Tx, &auth); err != nil {
				return err
			}
		}
	}
	return nil
}
