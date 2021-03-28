package dbu

import (
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
)

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
