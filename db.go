package vault

import (
	"database/sql"
	"encoding/hex"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"

	// For sqlite3 (sqlcipher driver)
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func openDB(path string, mk *[32]byte) (*sqlx.DB, error) {
	keyString := hex.EncodeToString(mk[:])
	pragma := fmt.Sprintf("?_pragma_key=x'%s'&_pragma_cipher_page_size=4096", keyString)

	db, err := sqlx.Open("sqlite3", path+pragma)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open db")
	}

	return db, nil
}

func initDB(db *sqlx.DB, setup bool) error {
	if err := initTables(db); err != nil {
		return err
	}
	if setup {
		logger.Debugf("Setting up...")
		existing, err := clientKey(db)
		if err != nil {
			return err
		}
		if existing != nil {
			return errors.Errorf("already setup")
		}

		ck := keys.NewEdX25519KeyFromSeed(keys.Rand32())
		if err := setClientKey(db, ck); err != nil {
			return err
		}
	} else {
		logger.Debugf("Checking setup...")
		ck, err := clientKey(db)
		if err != nil {
			return err
		}
		if ck == nil {
			return errors.Errorf("needs setup")
		}
	}
	return nil
}

func initTables(db *sqlx.DB) error {
	logger.Debugf("Initializing tables...")
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY NOT NULL,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS push (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			data BLOB NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS pull (						
			data BLOB NOT NULL,
			ridx INTEGER PRIMARY KEY NOT NULL,
			rts TIMESTAMP NOT NULL
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

// TransactDB creates and executes a transaction.
func TransactDB(db *sqlx.DB, txFn func(*sqlx.Tx) error) (err error) {
	if db == nil {
		return ErrLocked
	}
	tx, err := db.Beginx()
	if err != nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p) // Re-throw panic after Rollback
		} else if err != nil {
			tx.Rollback() // err is non-nil; don't change it
		} else {
			err = tx.Commit() // err is nil; returns Commit error
		}
	}()
	err = txFn(tx)
	return err
}

type push struct {
	ID   int64  `db:"id"`
	Data []byte `db:"data"`
}

func (v *Vault) add(i interface{}) error {
	fn := func(tx *sqlx.Tx) error { return Add(tx, i) }
	return TransactDB(v.db, fn)
}

// Add to vault.
func Add(tx *sqlx.Tx, i interface{}) error {
	b, err := msgpack.Marshal(i)
	if err != nil {
		return err
	}
	if _, err := tx.Exec("INSERT INTO push (data) VALUES ($1)", b); err != nil {
		return err
	}
	return nil
}

func (v *Vault) listPush(max int) ([]*push, error) {
	var pushes []*push
	if err := v.db.Select(&pushes, "SELECT * FROM push ORDER BY id LIMIT $1", max); err != nil {
		return nil, err
	}
	return pushes, nil
}

func (v *Vault) clearPush(id int64) error {
	if _, err := v.db.Exec("DELETE FROM push WHERE id <= $1", id); err != nil {
		return err
	}
	return nil
}

func (v *Vault) resetPush() error {
	return TransactDB(v.db, resetPushTx)
}

func resetPushTx(tx *sqlx.Tx) error {
	var pushes []*push
	if err := tx.Select(&pushes, "SELECT * FROM push ORDER BY id"); err != nil {
		return err
	}

	var pulls []*Event
	if err := tx.Select(&pulls, "SELECT * FROM pull"); err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		return err
	}
	if len(pulls) == 0 {
		return nil
	}

	if _, err := tx.Exec("DELETE FROM push"); err != nil {
		return err
	}

	for _, p := range pulls {
		if _, err := tx.Exec("INSERT INTO push (data) VALUES ($1)", p.Data); err != nil {
			return err
		}
	}

	for _, p := range pushes {
		if _, err := tx.Exec("INSERT INTO push (data) VALUES ($1)", p.Data); err != nil {
			return err
		}
	}

	return nil
}

func (v *Vault) setPull(events []*Event) error {
	return TransactDB(v.db, func(tx *sqlx.Tx) error {
		if err := setPullTx(tx, events); err != nil {
			return err
		}
		if v.source != nil {
			if err := v.source.Receive(tx, events); err != nil {
				return err
			}
		}
		return nil
	})
}

func setPullTx(tx *sqlx.Tx, events []*Event) error {
	if _, err := tx.NamedExec("INSERT OR REPLACE INTO pull (data, ridx, rts) VALUES (:data, :ridx, :rts)", events); err != nil {
		return err
	}
	return nil
}

func (v *Vault) listPull(from int64) ([]*Event, error) {
	var pulls []*Event
	if err := v.db.Select(&pulls, "SELECT * FROM pull WHERE ridx > $1 ORDER BY ridx", from); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pulls, nil
}

func (v *Vault) pullIndex() (int64, error) {
	var idx sql.NullInt64
	if err := v.db.Get(&idx, "SELECT MAX(ridx) FROM pull"); err != nil {
		return -1, err
	}
	if !idx.Valid {
		return -1, nil
	}
	return idx.Int64, nil
}
