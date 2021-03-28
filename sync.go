package vault

import (
	"context"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/pkg/errors"
)

// Sync a specific key with receiver.
func (v *Vault) Sync(ctx context.Context, vid keys.ID, receiver Receiver) error {
	vk, err := v.kr.Find(ctx, vid)
	if err != nil {
		return err
	}
	if vk == nil {
		return keys.NewErrNotFound(vid.String())
	}

	s := NewSyncer(v.db, v.client, receiver)
	return s.Sync(ctx, vk)
}

// Syncer syncs.
type Syncer struct {
	db       *sqlx.DB
	client   *Client
	receiver Receiver
}

// NewSyncer creates a Syncer.
func NewSyncer(db *sqlx.DB, client *Client, receiver Receiver) *Syncer {
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

func (s *Syncer) applyPull(vid keys.ID, events *Events) error {
	if len(events.Events) == 0 {
		return nil
	}
	return TransactDB(s.db, func(tx *sqlx.Tx) error {
		if err := setPullTx(tx, events.Events); err != nil {
			return err
		}

		if s.receiver != nil {
			rctx := &SyncContext{vid, tx}
			if err := s.receiver(rctx, events.Events); err != nil {
				return err
			}
		}
		return nil
	})
}
