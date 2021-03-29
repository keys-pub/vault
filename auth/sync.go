package auth

import (
	"context"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/client"
	"github.com/keys-pub/vault/syncer"
	"github.com/vmihailenco/msgpack/v4"
)

// Sync db.
// Returns error if sync is not enabled.
func (d *DB) Sync(ctx context.Context, client *client.Client) error {
	d.smtx.Lock()
	defer d.smtx.Unlock()
	s := syncer.New(d.db, client, d.receive)
	if err := s.Sync(ctx, d.ck); err != nil {
		return err
	}
	return nil
}

func (d *DB) receive(ctx *syncer.Context, events []*client.Event) error {
	for _, event := range events {
		b, err := keys.CryptoBoxSealOpen(event.Data, d.ck.AsX25519())
		if err != nil {
			return err
		}
		var auth Auth
		if err := msgpack.Unmarshal(b, &auth); err != nil {
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
