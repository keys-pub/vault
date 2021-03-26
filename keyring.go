package vault

import (
	"context"
	"database/sql"

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

// NewKeyring creates a keyring.
func NewKeyring(db *sqlx.DB, ck *api.Key, client *Client, clock tsutil.Clock) (*Keyring, error) {
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
		if _, err := db.Exec(stmt); err != nil {
			return nil, err
		}
	}

	return &Keyring{db, ck, client, clock}, nil
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
	return TransactDB(k.db, func(tx *sqlx.Tx) error {
		logger.Debugf("Saving key %s", key.ID)
		b, err := msgpack.Marshal(key)
		if err != nil {
			return err
		}
		if err := Add(tx, k.ck.ID, b); err != nil {
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
	if err := k.ensureUnlocked(); err != nil {
		return err
	}

	return TransactDB(k.db, func(tx *sqlx.Tx) error {
		key := api.NewKey(kid)
		key.Deleted = true
		b, err := msgpack.Marshal(key)
		if err != nil {
			return err
		}
		if err := Add(tx, k.ck.ID, b); err != nil {
			return err
		}
		return deleteKeyTx(tx, kid)
	})
}

// Keys in vault.
func (k *Keyring) Keys() ([]*api.Key, error) {
	if err := k.ensureUnlocked(); err != nil {
		return nil, err
	}
	return getKeys(k.db)
}

// KeysByType in vault.
func (k *Keyring) KeysByType(typ string) ([]*api.Key, error) {
	if err := k.ensureUnlocked(); err != nil {
		return nil, err
	}
	return getKeysByType(k.db, typ)
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

func updateKey(db *sqlx.DB, key *api.Key) error {
	return TransactDB(db, func(tx *sqlx.Tx) error {
		return updateKeyTx(tx, key)
	})
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
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

// func getKeyWithLabel(db *sqlx.DB, label string) (*api.Key, error) {
// 	var key api.Key
// 	sqlLabel := "%^" + label + "$%"
// 	if err := db.Get(&key, "SELECT * FROM keys WHERE labels LIKE $1", sqlLabel); err != nil {
// 		if err == sql.ErrNoRows {
// 			return nil, nil
// 		}
// 		return nil, err
// 	}
// 	return &key, nil
// }

func getKeysWithLabel(db *sqlx.DB, label string) ([]*api.Key, error) {
	logger.Debugf("Get keys with label %q", label)
	var out []*api.Key
	sqlLabel := "%^" + label + "$%"
	if err := db.Select(&out, "SELECT * FROM keys WHERE labels LIKE $1", sqlLabel); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}

func getKeys(db *sqlx.DB) ([]*api.Key, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys ORDER BY id"); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return vks, nil
}

func getKeysByType(db *sqlx.DB, typ string) ([]*api.Key, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys WHERE type = $1 ORDER BY id", typ); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return vks, nil
}

func getTokens(db *sqlx.DB) ([]*Token, error) {
	var vks []*api.Key
	if err := db.Select(&vks, "SELECT * FROM keys WHERE type = $1 AND token != $2", "edx25519", ""); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	out := []*Token{}
	for _, k := range vks {
		out = append(out, &Token{KID: k.ID, Token: k.Token})
	}
	return out, nil
}
