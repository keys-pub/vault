package vault

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/pkg/errors"
)

type Config struct {
	db *sqlx.DB
}

func (v *Vault) Config() Config {
	return Config{v.db}
}

func (c Config) String(k string) (string, error) {
	if c.db == nil {
		return "", ErrLocked
	}
	return getConfig(c.db, k)
}

func (c Config) SetString(k string, v string) error {
	if c.db == nil {
		return ErrLocked
	}
	return setConfig(c.db, k, v)
}

func (c Config) KID(k string) (keys.ID, error) {
	s, err := c.String(k)
	if err != nil {
		return "", err
	}
	kid, err := keys.ParseID(s)
	if err != nil {
		return "", err
	}
	return kid, nil
}

func (c Config) Bytes(k string) ([]byte, error) {
	if c.db == nil {
		return nil, ErrLocked
	}
	return getConfigBytes(c.db, k)
}

func (c Config) SetBytes(k string, v []byte) error {
	if c.db == nil {
		return ErrLocked
	}
	return setConfigBytes(c.db, k, v)
}

func (c Config) Set(k string, v string) error {
	if c.db == nil {
		return ErrLocked
	}
	return setConfig(c.db, k, v)
}

func setConfig(db *sqlx.DB, key string, value string) error {
	if _, err := db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ($1, $2)", key, value); err != nil {
		return errors.Wrapf(err, "failed to set config")
	}
	return nil
}

func getConfig(db *sqlx.DB, key string) (string, error) {
	var value string
	if err := db.Get(&value, "SELECT value FROM config WHERE key=$1", key); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", errors.Wrapf(err, "failed to get config")
	}
	return value, nil
}

func setConfigBytes(db *sqlx.DB, key string, b []byte) error {
	if len(b) == 0 {
		return setConfig(db, key, "")
	}
	return setConfig(db, key, encoding.MustEncode(b, encoding.Base64))
}

func getConfigBytes(db *sqlx.DB, key string) ([]byte, error) {
	s, err := getConfig(db, key)
	if err != nil {
		return nil, err
	}
	if len(s) == 0 {
		return nil, nil
	}
	b, err := encoding.DecodeBase64(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}
