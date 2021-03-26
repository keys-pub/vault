package vault

import (
	"context"
	"sort"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

type changes struct {
	db     *sqlx.DB
	client *Client
	clock  tsutil.Clock
}

// Change on remote.
type Change struct {
	VID       keys.ID
	Local     int64
	Remote    int64
	Timestamp int64
}

// Changes for any keys in the keyring.
// If the keyring isn't synced this may not return all changes for those keyring
// keys, so you should usually sync the keyring first.
func (v *Vault) Changes(ctx context.Context) ([]*Change, error) {
	c := &changes{v.db, v.client, v.clock}

	if err := c.resolveKeyTokens(ctx); err != nil {
		return nil, err
	}
	tokens, err := getTokens(c.db)
	if err != nil {
		return nil, err
	}
	status, err := c.client.Status(ctx, tokens)
	if err != nil {
		return nil, err
	}
	for _, st := range status {
		logger.Debugf("Status: %s %d", st.ID, st.Index)
	}
	indexes, err := pullIndexes(c.db)
	if err != nil {
		return nil, err
	}

	changes := []*Change{}
	for _, st := range status {
		kid := st.ID
		local := indexes[kid]
		if local < st.Index {
			logger.Debugf("Changed %s, %d < %d", kid, local, st.Index)
			changes = append(changes, &Change{VID: kid, Local: local, Remote: st.Index, Timestamp: st.Timestamp})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Timestamp > changes[j].Timestamp
	})
	return changes, nil
}

func (c *changes) resolveKeyTokens(ctx context.Context) error {
	logger.Debugf("Resolve key tokens...")
	check, err := getKeysWithLabel(c.db, "vault")
	if err != nil {
		return err
	}
	for _, key := range check {
		if !key.IsEdX25519() {
			return errors.Errorf("invalid key")
		}
		if key.Token == "" {
			logger.Debugf("Getting vault token...")
			token, err := c.client.Register(ctx, key.AsEdX25519())
			if err != nil {
				return err
			}
			key.Token = token
			key.UpdatedAt = c.clock.NowMillis()
			if err := updateKey(c.db, key); err != nil {
				return err
			}
		}
	}
	return nil
}
