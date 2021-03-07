package vault

import (
	"context"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/pkg/errors"
)

// SyncStatus is the status of sync.
type SyncStatus struct {
	ID       keys.ID
	SyncedAt time.Time
}

// Sync db.
// Returns error if sync is not enabled.
func (v *Vault) Sync(ctx context.Context) error {
	logger.Infof("Syncing...")

	// What happens on connection failures, context cancellation?
	//
	// If we fail during push (after succeeding on the server, the response is
	// lost), we would push duplicates on the next push.
	// These duplicates would show up in the subsequent pulls but otherwise
	// wouldn't cause any problems.
	// We could de-dupe on the clients, but since this is probably rare and the
	// failure is mostly cosmetic, we will ignore for now.

	if err := v.Push(ctx); err != nil {
		return errors.Wrapf(err, "failed to push vault")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := v.Pull(ctx); err != nil {
		return errors.Wrapf(err, "failed to pull vault")
	}

	if err := setLastSync(v.db, v.clock.Now()); err != nil {
		return err
	}

	return nil
}

// SyncStatus returns status for sync, or nil, if no sync has been performed.
func (v *Vault) SyncStatus() (*SyncStatus, error) {
	lastSync, err := lastSync(v.db)
	if err != nil {
		return nil, err
	}
	status := &SyncStatus{
		SyncedAt: lastSync,
	}

	ck, err := clientKey(v.db)
	if err != nil {
		return nil, err
	}
	if ck != nil {
		status.ID = ck.ID()
	}
	return status, nil
}

// Push to remote.
func (v *Vault) Push(ctx context.Context) error {
	if v.client == nil {
		return errors.Errorf("no vault client set")
	}
	ck, err := clientKey(v.db)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		push, err := v.listPush(499)
		if err != nil {
			return err
		}
		if len(push) == 0 {
			return nil
		}

		from := push[0].ID
		to := int64(-1)
		out := [][]byte{}
		total := int(0)
		max := 4 * 1000 * 1000 // Max 4MB
		for _, p := range push {
			if total+len(p.Data) >= max {
				break
			}
			out = append(out, p.Data)
			to = p.ID
			total += len(p.Data)
		}

		logger.Infof("Pushing %d events (%d-%d) (%d)...", len(out), from, to, total)
		if err := v.client.Post(ctx, ck, out); err != nil {
			return err
		}
		logger.Infof("Clearing push (<=%d)...", to)
		if err := v.clearPush(to); err != nil {
			return err
		}
	}
}

// Pull from remote.
func (v *Vault) Pull(ctx context.Context) error {
	// Keep pulling until no more or cancel.
	for {
		truncated, err := v.pullNext(ctx)
		if err != nil {
			return err
		}
		if !truncated {
			break
		}
	}
	return nil
}

func (v *Vault) pullNext(ctx context.Context) (bool, error) {
	if v.client == nil {
		return false, errors.Errorf("no vault client set")
	}

	index, err := v.pullIndex()
	if err != nil {
		return false, err
	}

	ck, err := clientKey(v.db)
	if err != nil {
		return false, err
	}

	logger.Infof("Pulling from ridx=%d", index)
	events, err := v.client.Get(ctx, ck, index)
	if err != nil {
		return false, err
	}
	if events == nil {
		return false, errors.Errorf("no vault found")
	}
	logger.Debugf("Saving (%d)...", len(events.Events))
	if err := v.applyPull(events); err != nil {
		return false, err
	}

	return events.Truncated, nil
}

func (v *Vault) applyPull(events *Events) error {
	for _, event := range events.Events {
		if err := v.setPull(event); err != nil {
			return errors.Wrapf(err, "failed to apply pull")
		}
	}
	return nil
}

// NeedsSync ...
func (v *Vault) NeedsSync(expire time.Duration) (bool, error) {
	v.checkMtx.Lock()
	defer v.checkMtx.Unlock()

	diffCheck := v.clock.Now().Sub(v.checkedAt)
	if diffCheck >= 0 && diffCheck < expire {
		logger.Debugf("Already checked recently")
		return false, nil
	}
	v.checkedAt = v.clock.Now()

	last, err := lastSync(v.db)
	if err != nil {
		return false, err
	}
	logger.Debugf("Last synced: %s", last)
	diffLast := v.clock.Now().Sub(last)
	logger.Debugf("Synced %s ago", diffLast)
	if absDuration(diffLast) > expire {
		return true, nil
	}
	logger.Debugf("Already synced recently")
	return false, nil
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func lastSync(db *sqlx.DB) (time.Time, error) {
	return getConfigTime(db, "lastSync")
}

func setLastSync(db *sqlx.DB, t time.Time) error {
	return setConfigTime(db, "lastSync", t)
}

func setClientKey(db *sqlx.DB, key *keys.EdX25519Key) error {
	if err := setConfigBytes(db, "clientKey", key.Seed()[:]); err != nil {
		return err
	}
	return nil
}

func clientKey(db *sqlx.DB) (*keys.EdX25519Key, error) {
	clientKey, err := getConfigBytes(db, "clientKey")
	if err != nil {
		return nil, err
	}
	if len(clientKey) != 32 {
		return nil, nil
	}
	return keys.NewEdX25519KeyFromSeed(keys.Bytes32(clientKey)), nil
}

// Reset deletes vault from the remote and resets the vault log.
//
// The steps for resetting are:
// - Delete the vault from the server
// - Reset push (move/prepend pull back into push)
// - Clear config
//
func (v *Vault) reset(ctx context.Context) error {
	logger.Infof("Resetting...")

	ck, err := clientKey(v.db)
	if err != nil {
		return err
	}

	// Delete vault from the server.
	if err := v.client.Delete(ctx, ck); err != nil {
		return err
	}

	// Reset push and config.
	return transactDB(v.db, func(tx *sqlx.Tx) error {
		if err := resetPushTx(tx); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM config WHERE key=%1", "lastSync"); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM config WHERE key=%1", "clientKey"); err != nil {
			return err
		}
		return nil
	})
}
