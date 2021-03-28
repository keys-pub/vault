package vault

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault/client"
	"github.com/keys-pub/vault/dbu"
	"github.com/keys-pub/vault/sync"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Keyring ...
type Keyring struct {
	vlt  *Vault
	init bool
}

// NewKeyring creates a keyring.
func NewKeyring(vlt *Vault) *Keyring {
	return &Keyring{vlt: vlt}
}

func (k *Keyring) initTables() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY NOT NULL,
			type TEXT NOT NULL,
			private BLOB,
			public BLOB,
			token TEXT,	
			createdAt INTEGER,
			updatedAt INTEGER,
			notes TEXT,
			labels TEXT
		);`,
		// TODO: Indexes
	}
	for _, stmt := range stmts {
		if _, err := k.vlt.DB().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (k *Keyring) check() error {
	if k.vlt.DB() == nil {
		return ErrLocked
	}
	if k.vlt.ClientKey() == nil {
		return errors.Errorf("no client key")
	}
	if !k.init {
		if err := k.initTables(); err != nil {
			return err
		}
		k.init = true
	}
	return nil
}

// Save a key.
// Requires Unlock.
func (k *Keyring) Set(key *api.Key) error {
	if err := k.check(); err != nil {
		return err
	}
	return dbu.Transact(k.vlt.DB(), func(tx *sqlx.Tx) error {
		logger.Debugf("Saving key %s", key.ID)
		b, err := msgpack.Marshal(key)
		if err != nil {
			return err
		}
		if err := Add(tx, k.vlt.ClientKey().ID, b); err != nil {
			return err
		}
		if err := updateKeyTx(tx, key); err != nil {
			return err
		}
		return nil
	})
}

// Remove a key.
// Requires Unlock.
func (k *Keyring) Remove(kid keys.ID) error {
	if err := k.check(); err != nil {
		return err
	}
	return dbu.Transact(k.vlt.DB(), func(tx *sqlx.Tx) error {
		key := api.NewKey(kid)
		key.Deleted = true
		b, err := msgpack.Marshal(key)
		if err != nil {
			return err
		}
		if err := Add(tx, k.vlt.ClientKey().ID, b); err != nil {
			return err
		}
		return deleteKeyTx(tx, kid)
	})
}

// Keys in vault.
func (k *Keyring) Keys() ([]*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}
	return getKeys(k.vlt.DB())
}

// KeysByType in vault.
func (k *Keyring) KeysByType(typ string) ([]*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}
	return getKeysByType(k.vlt.DB(), typ)
}

// Key lookup by id.
func (k *Keyring) Key(kid keys.ID) (*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}
	return getKey(k.vlt.DB(), kid)
}

// Sync db.
// Returns error if sync is not enabled.
func (k *Keyring) Sync(ctx context.Context) error {
	if err := k.check(); err != nil {
		return err
	}

	s := sync.NewSyncer(k.vlt.DB(), k.vlt.Client(), k.receive)
	if err := s.Sync(ctx, k.vlt.ClientKey()); err != nil {
		return err
	}
	return nil
}

func (k *Keyring) receive(ctx *sync.Context, events []*Event) error {
	for _, event := range events {
		var key api.Key
		if err := msgpack.Unmarshal(event.Data, &key); err != nil {
			return err
		}
		if key.Deleted {
			if err := deleteKeyTx(ctx.Tx, key.ID); err != nil {
				return err
			}
		} else {
			if err := updateKeyTx(ctx.Tx, &key); err != nil {
				return err
			}
		}
	}
	return nil
}

// Find looks for local key and if not found, syncs and retries.
func (k *Keyring) Find(ctx context.Context, kid keys.ID) (*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}

	key, err := getKey(k.vlt.DB(), kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		if err := k.Sync(ctx); err != nil {
			return nil, err
		}
	}
	return getKey(k.vlt.DB(), kid)
}

func updateKeyTx(tx *sqlx.Tx, key *api.Key) error {
	logger.Debugf("Update key %s", key.ID)
	if _, err := tx.NamedExec(`INSERT OR REPLACE INTO keys VALUES 
		(:id, :type, :private, :public, :token, :createdAt, :updatedAt, :notes, :labels)`, key); err != nil {
		return err
	}
	return nil
}

func deleteKeyTx(tx *sqlx.Tx, kid keys.ID) error {
	if kid == "" {
		return errors.Errorf("failed to delete key: empty id")
	}
	logger.Debugf("Deleting key %s", kid)
	if _, err := tx.Exec(`DELETE FROM keys WHERE id = ?`, kid); err != nil {
		return err
	}
	return nil
}

func getKey(db *sqlx.DB, kid keys.ID) (*api.Key, error) {
	var key api.Key
	if err := db.Get(&key, "SELECT * FROM keys WHERE id = $1", kid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

func getKeys(db *sqlx.DB) ([]*api.Key, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys ORDER BY id"); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return vks, nil
}

func getKeysByType(db *sqlx.DB, typ string) ([]*api.Key, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys WHERE type = $1 ORDER BY id", typ); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return vks, nil
}

func getTokens(db *sqlx.DB) ([]*client.Token, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys WHERE type = $1 AND token != $2", "edx25519", ""); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	out := []*client.Token{}
	for _, k := range vks {
		out = append(out, &client.Token{KID: k.ID, Token: k.Token})
	}
	return out, nil
}
