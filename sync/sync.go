package sync

import (
	"context"
	"database/sql"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault/client"
	"github.com/keys-pub/vault/dbu"
	"github.com/pkg/errors"
)

// Syncer syncs.
type Syncer struct {
	db       *sqlx.DB
	client   *client.Client
	receiver Receiver
}

// NewSyncer creates a Syncer.
func NewSyncer(db *sqlx.DB, client *client.Client, receiver Receiver) *Syncer {
	return &Syncer{
		db:       db,
		client:   client,
		receiver: receiver,
	}
}

func (s *Syncer) Sync(ctx context.Context, key *api.Key) error {
	logger.Infof("Syncing %s...", key.ID)

	// What happens on connection failures, context cancellation?
	//
	// If we fail during push (after succeeding on the server, the response is
	// lost), we would push duplicates on the next push.
	// These duplicates would show up in the subsequent pulls and would be up
	// to clients to deal with it, which most clients could probably ignore.

	if err := s.Push(ctx, key); err != nil {
		return errors.Wrapf(err, "failed to push vault")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.Pull(ctx, key); err != nil {
		return errors.Wrapf(err, "failed to pull vault")
	}

	return nil
}

// Push to remote.
func (s *Syncer) Push(ctx context.Context, key *api.Key) error {
	if s.client == nil {
		return errors.Errorf("no vault client set")
	}
	if !key.IsEdX25519() {
		return errors.Errorf("invalid key")
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		push, err := listPush(s.db, key.ID, 499)
		if err != nil {
			return err
		}
		if len(push) == 0 {
			return nil
		}

		from := push[0].Index
		to := int64(-1)
		out := [][]byte{}
		total := int(0)
		max := 4 * 1000 * 1000 // Max 4MB
		for _, p := range push {
			// Max data
			if total+len(p.Data) >= max {
				logger.Debugf("Max data, splitting push")
				break
			}
			out = append(out, p.Data)
			to = p.Index
			total += len(p.Data)
		}

		logger.Infof("Pushing %d-%d (%db) %s...", from, to, total, key.ID)
		if err := s.client.Post(ctx, key.AsEdX25519(), out); err != nil {
			return err
		}
		logger.Infof("Clearing push (<=%d)...", to)
		if err := clearPush(s.db, to); err != nil {
			return err
		}
	}
}

// Pull from remote.
func (s *Syncer) Pull(ctx context.Context, key *api.Key) error {
	local, err := pullIndex(s.db, key.ID)
	if err != nil {
		return err
	}

	// Keep pulling until no more or cancel.
	for {
		truncated, err := s.pullNext(ctx, key, local)
		if err != nil {
			return err
		}
		if !truncated {
			break
		}
	}
	return nil
}

func (s *Syncer) pullNext(ctx context.Context, key *api.Key, index int64) (bool, error) {
	if s.client == nil {
		return false, errors.Errorf("no vault client set")
	}
	if !key.IsEdX25519() {
		return false, errors.Errorf("invalid key")
	}

	logger.Infof("Pulling from ridx=%d", index)
	events, err := s.client.Events(ctx, key.AsEdX25519(), index)
	if err != nil {
		return false, err
	}
	if events == nil {
		return false, errors.Errorf("no vault found")
	}
	logger.Debugf("Saving (%d)...", len(events.Events))
	if err := s.applyPull(key.ID, events); err != nil {
		return false, errors.Wrapf(err, "failed to apply pull")
	}

	return events.Truncated, nil
}

func (s *Syncer) applyPull(vid keys.ID, events *client.Events) error {
	if len(events.Events) == 0 {
		return nil
	}
	return dbu.Transact(s.db, func(tx *sqlx.Tx) error {
		if err := setPullTx(tx, events.Events); err != nil {
			return err
		}

		if s.receiver != nil {
			rctx := &Context{vid, tx}
			if err := s.receiver(rctx, events.Events); err != nil {
				return err
			}
		}
		return nil
	})
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
