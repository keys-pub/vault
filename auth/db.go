package auth

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"

	// For sqlite3 (we use sqlcipher driver because it would conflict if we used
	// regular sqlite driver)
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// DB for vault.
type DB struct {
	*sqlx.DB
}

// NewDB creates an DB for auth.
// This DB is unencrypted but the auth keys themselves are encrypted.
func NewDB(path string) (*DB, error) {
	sqldb, err := sqlx.Open("sqlite3", path)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open db")
	}

	db := &DB{}
	db.DB = sqldb
	if err := db.init(); err != nil {
		return nil, err
	}
	return db, nil
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

func (d *DB) init() error {
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
	}
	for _, stmt := range stmts {
		if _, err := d.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) add(auth *Auth) error {
	sql := `INSERT INTO auth (id, ek, type, createdAt, salt, aaguid, nopin) 
			VALUES (:id, :ek, :type, :createdAt, :salt, :aaguid, :nopin)`
	if _, err := d.NamedExec(sql, auth); err != nil {
		return err
	}
	return nil
}

// List auth.
func (d *DB) List() ([]*Auth, error) {
	var auths []*Auth
	if err := d.Select(&auths, "SELECT * FROM auth"); err != nil {
		if err == sql.ErrNoRows {
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
	if err := d.Select(&auths, "SELECT * FROM auth WHERE type = $1", typ); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if len(auths) == 0 {
		return []*Auth{}, nil
	}
	return auths, nil
}
