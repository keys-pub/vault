package vault

import (
	"context"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/client"
	"github.com/keys-pub/vault/syncer"
)

// Event alias.
type Event = client.Event

// Events alias.
type Events = client.Events

// Sync a specific key with receiver.
func (v *Vault) Sync(ctx context.Context, vid keys.ID, receiver syncer.Receiver) error {
	vk, err := v.kr.Find(ctx, vid)
	if err != nil {
		return err
	}
	if vk == nil {
		return keys.NewErrNotFound(vid.String())
	}

	s := syncer.New(v.db, v.client, receiver)
	return s.Sync(ctx, vk)
}
