package vault

import (
	"encoding/hex"
	"fmt"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/dbu"
	"github.com/pkg/errors"

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

func initTables(db *sqlx.DB) error {
	logger.Debugf("Initializing tables...")
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS config (
			key TEXT PRIMARY KEY NOT NULL,
			value TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS push (
			idx INTEGER PRIMARY KEY AUTOINCREMENT,
			data BLOB NOT NULL,
			vid TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS pull (						
			ridx INTEGER PRIMARY KEY NOT NULL,
			data BLOB NOT NULL,			
			rts TIMESTAMP NOT NULL,
			vid TEXT NOT NULL
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

func add(db *sqlx.DB, vid keys.ID, b []byte) error {
	fn := func(tx *sqlx.Tx) error { return Add(tx, vid, b) }
	return dbu.Transact(db, fn)
}

// Add to vault.
func Add(tx *sqlx.Tx, vid keys.ID, b []byte) error {
	logger.Debugf("Adding to push %s (%s)", vid)
	if _, err := tx.Exec("INSERT INTO push (vid, data) VALUES ($1, $2)", vid, b); err != nil {
		return err
	}
	return nil
}

// func resetPush(db *sqlx.DB) error {
// 	return TransactDB(db, resetPushTx)
// }

// func resetPushTx(tx *sqlx.Tx) error {
// 	var pushes []*push
// 	if err := tx.Select(&pushes, "SELECT * FROM push ORDER BY idx"); err != nil {
// 		return err
// 	}

// 	var pulls []*Event
// 	if err := tx.Select(&pulls, "SELECT * FROM pull"); err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return nil
// 		}
// 		return err
// 	}
// 	if len(pulls) == 0 {
// 		return nil
// 	}

// 	if _, err := tx.Exec("DELETE FROM push"); err != nil {
// 		return err
// 	}

// 	for _, p := range pulls {
// 		if _, err := tx.Exec("INSERT INTO push (vid, data) VALUES ($1, $2)", p.VID, p.Data); err != nil {
// 			return err
// 		}
// 	}

// 	for _, p := range pushes {
// 		if _, err := tx.Exec("INSERT INTO push (vid, data) VALUES ($1, $2)", p.VID, p.Data); err != nil {
// 			return err
// 		}
// 	}

// 	return nil
// }
