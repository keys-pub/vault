package vault

import (
	"context"
	"database/sql"
	"sync"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault/client"
	"github.com/keys-pub/vault/syncer"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Keyring ...
type Keyring struct {
	vault *Vault
	init  bool
	smtx  sync.Mutex
}

// NewKeyring creates a keyring.
func NewKeyring(vault *Vault) *Keyring {
	return &Keyring{vault: vault}
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
		if _, err := k.vault.DB().Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (k *Keyring) check() error {
	if k.vault.DB() == nil {
		return ErrLocked
	}
	if k.vault.ClientKey() == nil {
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
	ck := k.vault.ClientKey()
	return syncer.Transact(k.vault.DB(), func(tx *sqlx.Tx) error {
		logger.Debugf("Saving key %s", key.ID)
		b, err := msgpack.Marshal(key)
		if err != nil {
			return err
		}
		if err := syncer.AddTx(tx, ck.AsEdX25519(), b, syncer.CryptoBoxSealCipher{}); err != nil {
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
	ck := k.vault.ClientKey()
	return syncer.Transact(k.vault.DB(), func(tx *sqlx.Tx) error {
		key := api.NewKey(kid)
		key.Deleted = true
		b, err := msgpack.Marshal(key)
		if err != nil {
			return err
		}
		if err := syncer.AddTx(tx, ck.AsEdX25519(), b, syncer.CryptoBoxSealCipher{}); err != nil {
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
	return getKeys(k.vault.DB())
}

// KeysWithType in vault.
func (k *Keyring) KeysWithType(typ string) ([]*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}
	return getKeysByType(k.vault.DB(), typ)
}

// KeysWithLabel in vault.
func (k *Keyring) KeysWithLabel(typ string) ([]*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}
	return getKeysByLabel(k.vault.DB(), typ)
}

// Get key by id.
// Returns nil if not found.
func (k *Keyring) Get(kid keys.ID) (*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}
	return getKey(k.vault.DB(), kid)
}

// Key by id.
// If not found, returns keys.ErrNotFound.
// You can use Get instead.
func (k *Keyring) Key(kid keys.ID) (*api.Key, error) {
	if err := k.check(); err != nil {
		return nil, err
	}
	key, err := getKey(k.vault.DB(), kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, keys.NewErrNotFound(kid.String())
	}
	return key, nil
}

// Sync db.
// Returns error if sync is not enabled.
func (k *Keyring) Sync(ctx context.Context) error {
	k.smtx.Lock()
	defer k.smtx.Unlock()

	if err := k.check(); err != nil {
		return err
	}

	s := syncer.New(k.vault.DB(), k.vault.Client(), k.receive)
	if err := s.Sync(ctx, k.vault.ClientKey()); err != nil {
		return err
	}
	return nil
}

func (k *Keyring) receive(ctx *syncer.Context, events []*Event) error {
	ck := k.vault.ClientKey()
	for _, event := range events {
		b, err := keys.CryptoBoxSealOpen(event.Data, ck.AsX25519())
		if err != nil {
			return err
		}
		var key api.Key
		if err := msgpack.Unmarshal(b, &key); err != nil {
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

	key, err := getKey(k.vault.DB(), kid)
	if err != nil {
		return nil, err
	}
	if key == nil {
		if err := k.Sync(ctx); err != nil {
			return nil, err
		}
	}
	return getKey(k.vault.DB(), kid)
}

// Tokens can be used to listen for realtime updates.
func (k *Keyring) Tokens() ([]*client.Token, error) {
	if err := k.check(); err != nil {
		return nil, err
	}

	return getTokens(k.vault.DB())
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

func getKeysByLabel(db *sqlx.DB, label string) ([]*api.Key, error) {
	logger.Debugf("Get keys with label %q", label)
	var out []*api.Key
	sqlLabel := "%^" + label + "$%"
	if err := db.Select(&out, "SELECT * FROM keys WHERE labels LIKE $1", sqlLabel); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return out, nil
}
