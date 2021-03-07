package vault

import "github.com/jmoiron/sqlx"

// Source is notified when the database is available and when events are
// received from the remote.
type Source interface {
	Init(db *sqlx.DB) error
	Receive(tx *sqlx.Tx, event *Event) error
}

type emptySource struct{}

func (s emptySource) Init(db *sqlx.DB) error {
	return nil
}

func (s emptySource) Receive(tx *sqlx.Tx, event *Event) error {
	return nil
}
