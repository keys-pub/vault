package keyring

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Keyring vault.
type Keyring struct {
	*vault.Vault
}

// New keyring vault.
func New(path string, auth *auth.DB, opt ...vault.Option) (*Keyring, error) {
	src := &source{}
	vlt, err := vault.New(path, auth, src, opt...)
	if err != nil {
		return nil, err
	}
	kr := &Keyring{vlt}
	return kr, nil
}

type source struct{}

// Init (vault.Source)
func (s *source) Init(db *sqlx.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS keys (
			id TEXT PRIMARY KEY NOT NULL,
			type TEXT NOT NULL,
			private BLOB,
			public BLOB,
			createdAt INTEGER,
			updatedAt INTEGER,
			labels TEXT,
			notes TEXT,
			token TEXT	
		);`,
		// TODO: Indexes
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// Receive (vault.Source)
func (s *source) Receive(tx *sqlx.Tx, events []*vault.Event) error {
	keys := make([]*api.Key, 0, len(events))
	for _, event := range events {
		var key api.Key
		if err := msgpack.Unmarshal(event.Data, &key); err != nil {
			return err
		}
		keys = append(keys, &key)
	}
	return insert(tx, keys)
}

func insert(tx *sqlx.Tx, keys []*api.Key) error {
	if _, err := tx.NamedExec(`INSERT OR REPLACE INTO keys VALUES 
		(:id, :type, :private, :public, :createdAt, :updatedAt, :labels, :notes, :token)`, keys); err != nil {
		return err
	}
	return nil
}

// Get key from vault.
func (k *Keyring) Get(id keys.ID) (*api.Key, error) {
	if k.DB() == nil {
		return nil, vault.ErrLocked
	}
	var key api.Key
	if err := k.DB().Get(&key, "SELECT * FROM keys WHERE id = $1", id); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

// Save key to vault.
func (k *Keyring) Save(key *api.Key) error {
	if key == nil {
		return errors.Errorf("nil key")
	}
	if key.ID == "" {
		return errors.Errorf("no key id")
	}

	db := k.DB()
	if db == nil {
		return vault.ErrLocked
	}

	fn := func(tx *sqlx.Tx) error {
		if err := insert(tx, []*api.Key{key}); err != nil {
			return err
		}
		return vault.Add(tx, key)
	}
	return vault.TransactDB(db, fn)
}
