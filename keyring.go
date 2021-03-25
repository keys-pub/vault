package vault

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Keyring ...
type Keyring struct {
	db     *sqlx.DB
	ck     *api.Key
	client *Client
	clock  tsutil.Clock
}

func (k *Keyring) ensureUnlocked() error {
	if k.db == nil {
		return ErrLocked
	}
	if k.ck == nil {
		return errors.Errorf("no client key")
	}
	return nil
}

// Save a key.
// Requires Unlock.
func (k *Keyring) Set(key *api.Key) error {
	if err := k.ensureUnlocked(); err != nil {
		return err
	}
	if err := saveKey(k.db, k.ck.ID, key); err != nil {
		return err
	}
	return nil
}

// Keys in vault.
func (k *Keyring) Keys() ([]*api.Key, error) {
	if err := k.ensureUnlocked(); err != nil {
		return nil, err
	}
	return getKeys(k.db)
}

// Key lookup by id.
func (k *Keyring) Key(kid keys.ID) (*api.Key, error) {
	if err := k.ensureUnlocked(); err != nil {
		return nil, err
	}
	return getKey(k.db, kid)
}

// Sync db.
// Returns error if sync is not enabled.
func (k *Keyring) Sync(ctx context.Context) error {
	if err := k.ensureUnlocked(); err != nil {
		return err
	}

	s := &syncer{k.db, k.client, k.receive, k.clock}

	if err := s.Sync(ctx, k.ck); err != nil {
		return err
	}
	return nil
}

func (k *Keyring) receive(ctx *SyncContext, events []*Event) error {
	for _, event := range events {
		var key api.Key
		if err := msgpack.Unmarshal(event.Data, &key); err != nil {
			return err
		}
		if err := updateKeyTx(ctx.Tx, &key); err != nil {
			return err
		}
	}
	return nil
}

// Find looks for local key and if not found, syncs and retries.
func (k *Keyring) Find(ctx context.Context, kid keys.ID) (*api.Key, error) {
	if err := k.ensureUnlocked(); err != nil {
		return nil, err
	}

	key, err := getKey(k.db, kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		if err := k.Sync(ctx); err != nil {
			return nil, err
		}
	}
	return getKey(k.db, kid)
}
