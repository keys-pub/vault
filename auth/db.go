package auth

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	kapi "github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault/auth/api"
	"github.com/keys-pub/vault/syncer"
	"github.com/pkg/errors"

	// For sqlite3 (we use sqlcipher driver because it would conflict with vault
	// if we used regular sqlite driver).
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = errors.New("invalid auth")

type Auth = api.Auth
type Type = api.Type

// DB for vault.
type DB struct {
	db *sqlx.DB
	ck *kapi.Key
}

// NewDB creates an DB for auth.
// This DB is unencrypted but the auth keys themselves are encrypted.
func NewDB(path string, opt ...Option) (*DB, error) {
	opts := newOptions(opt...)

	db, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open db")
	}
	if err := initTables(db); err != nil {
		return nil, err
	}
	ck, err := initClientKey(db, opts.ClientKey)
	if err != nil {
		return nil, err
	}
	return &DB{db: db, ck: ck}, nil
}

func (d *DB) unlock(auth *Auth, key *[32]byte) *[32]byte {
	k, ok := secretBoxOpen(auth.EncryptedKey, key)
	if !ok {
		logger.Debugf("Failed %s", auth.ID)
		return nil
	}
	if len(k) != 32 {
		return nil
	}
	mk := keys.Bytes32(k)
	return mk
}

func initTables(db *sqlx.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS auth (
			id TEXT NOT NULL PRIMARY KEY, 
			ek BLOB,
			type TEXT,
			createdAt TIMESTAMP,
			salt BLOB,
			aaguid TEXT,
			nopin BOOL
		);`,
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY NOT NULL,
			value TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

// Set adds or updates auth method.
func (d *DB) Set(auth *Auth) error {
	return syncer.Transact(d.db, func(tx *sqlx.Tx) error {
		if err := setTx(tx, auth); err != nil {
			return err
		}
		return nil
	})
}

// Delete auth method.
func (d *DB) Delete(id string) error {
	return syncer.Transact(d.db, func(tx *sqlx.Tx) error {
		if err := deleteTx(tx, id); err != nil {
			return err
		}
		return nil
	})
}

func setTx(tx *sqlx.Tx, auth *Auth) error {
	sql := `INSERT OR REPLACE INTO auth (id, ek, type, createdAt, salt, aaguid, nopin) 
			VALUES (:id, :ek, :type, :createdAt, :salt, :aaguid, :nopin)`
	if _, err := tx.NamedExec(sql, auth); err != nil {
		return err
	}
	return nil
}

func deleteTx(tx *sqlx.Tx, id string) error {
	if _, err := tx.Exec("DELETE FROM auth WHERE id = $1", id); err != nil {
		return err
	}
	return nil
}

// List auth.
func (d *DB) List() ([]*Auth, error) {
	var auths []*Auth
	if err := d.db.Select(&auths, "SELECT * FROM auth"); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if len(auths) == 0 {
		return []*Auth{}, nil
	}
	return auths, nil
}

// ListByType lists auth by type.
func (d *DB) ListByType(typ Type) ([]*Auth, error) {
	var auths []*Auth
	if err := d.db.Select(&auths, "SELECT * FROM auth WHERE type = $1", typ); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if len(auths) == 0 {
		return []*Auth{}, nil
	}
	return auths, nil
}
