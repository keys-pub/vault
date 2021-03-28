package sync

import (
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/client"
	"github.com/pkg/errors"
)

func InitTables(db *sqlx.DB) error {
	logger.Debugf("Initializing sync tables...")
	stmts := []string{
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

// Transact creates and executes a transaction.
func Transact(db *sqlx.DB, txFn func(*sqlx.Tx) error) (err error) {
	if db == nil {
		return errors.Errorf("db not open")
	}
	tx, err := db.Beginx()
	if err != nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p) // Re-throw panic after Rollback
		} else if err != nil {
			_ = tx.Rollback() // err is non-nil; don't change it
		} else {
			err = tx.Commit() // err is nil; returns Commit error
		}
	}()
	err = txFn(tx)
	return err
}

func Add(db *sqlx.DB, vid keys.ID, b []byte) error {
	fn := func(tx *sqlx.Tx) error { return AddTx(tx, vid, b) }
	return Transact(db, fn)
}

func AddTx(tx *sqlx.Tx, vid keys.ID, b []byte) error {
	logger.Debugf("Adding to push %s (%s)", vid)
	if _, err := tx.Exec("INSERT INTO push (vid, data) VALUES ($1, $2)", vid, b); err != nil {
		return err
	}
	return nil
}

type push struct {
	Index int64   `db:"idx"`
	Data  []byte  `db:"data"`
	VID   keys.ID `db:"vid"`
}

func listPush(db *sqlx.DB, vid keys.ID, max int) ([]*push, error) {
	var pushes []*push
	if err := db.Select(&pushes, "SELECT * FROM push WHERE vid = ? ORDER BY idx LIMIT $1", vid, max); err != nil {
		return nil, err
	}
	return pushes, nil
}

func clearPush(db *sqlx.DB, id int64) error {
	if _, err := db.Exec("DELETE FROM push WHERE idx <= $1", id); err != nil {
		return err
	}
	return nil
}

func setPullTx(tx *sqlx.Tx, events []*client.Event) error {
	if _, err := tx.NamedExec("INSERT OR REPLACE INTO pull (data, ridx, rts, vid) VALUES (:data, :ridx, :rts, :vid)", events); err != nil {
		return err
	}
	return nil
}

// func listPull(db *sqlx.DB, from int64) ([]*Event, error) {
// 	var pulls []*Event
// 	if err := db.Select(&pulls, "SELECT * FROM pull WHERE ridx > $1 ORDER BY ridx", from); err != nil {
// 		if errors.Is(err, sql.ErrNoRows) {
// 			return nil, nil
// 		}
// 		return nil, err
// 	}
// 	return pulls, nil
// }

func pullIndex(db *sqlx.DB, vid keys.ID) (int64, error) {
	var pull struct {
		Index sql.NullInt64 `db:"ridx"`
	}
	if err := db.Get(&pull, "SELECT MAX(ridx) as ridx FROM pull WHERE vid = ?", vid); err != nil {
		return 0, err
	}
	if pull.Index.Valid {
		return pull.Index.Int64, nil
	}
	return 0, nil
}

func PullIndexes(db *sqlx.DB) (map[keys.ID]int64, error) {
	logger.Debugf("Pull indexes...")
	type pullIndex struct {
		VID   sql.NullString `db:"vid"`
		Index sql.NullInt64  `db:"ridx"`
	}
	var pis []*pullIndex
	if err := db.Select(&pis, "SELECT vid, MAX(ridx) as ridx FROM pull"); err != nil {
		return nil, err
	}
	m := map[keys.ID]int64{}
	for _, pi := range pis {
		if pi.VID.Valid && pi.Index.Valid {
			m[keys.ID(pi.VID.String)] = pi.Index.Int64
		}
	}
	return m, nil
}

func PushIndexes(db *sqlx.DB) (map[keys.ID]int64, error) {
	logger.Debugf("Push indexes...")
	type pushIndex struct {
		VID   sql.NullString `db:"vid"`
		Index sql.NullInt64  `db:"idx"`
	}
	var pis []*pushIndex
	if err := db.Select(&pis, "SELECT vid, MAX(idx) as idx FROM push"); err != nil {
		return nil, err
	}
	m := map[keys.ID]int64{}
	for _, pi := range pis {
		if pi.VID.Valid && pi.Index.Valid {
			m[keys.ID(pi.VID.String)] = pi.Index.Int64
		}
	}
	return m, nil
}
