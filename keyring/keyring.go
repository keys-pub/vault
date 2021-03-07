package keyring

import (
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
func New(path string, auth *auth.DB) (*Keyring, error) {
	src := &source{}
	vlt, err := vault.New(path, auth, src)
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
			updatedAt INTEGER
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
func (s *source) Receive(tx *sqlx.Tx, event *vault.Event) error {
	var key api.Key
	if err := msgpack.Unmarshal(event.Data, key); err != nil {
		return err
	}
	return nil
}

// Get key from vault.
func (k *Keyring) Get(id keys.ID) (*api.Key, error) {
	// b, err := v.Vault.Get(id.String())
	// if err != nil {
	// 	return nil, err
	// }
	// if b == nil {
	// 	return nil, nil
	// }

	// key, err := unmarshalKey(b)
	// if err != nil {
	// 	return nil, err
	// }

	// return key, nil
	return nil, errors.Errorf("not implemented")
}

// Save key to vault.
func (k *Keyring) Save(key *api.Key) error {
	if key == nil {
		return errors.Errorf("nil key")
	}

	if key.ID == "" {
		return errors.Errorf("no key id")
	}

	if err := k.Add(vaultKey{key}); err != nil {
		return err
	}

	return nil
}

type vaultKey struct {
	*api.Key
}

func (k vaultKey) MarshalVault() ([]byte, error) {
	return msgpack.Marshal(k)
}
