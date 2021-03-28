package vault

import (
	"context"
	"sort"

	"github.com/keys-pub/keys"
)

// Change on remote.
type Change struct {
	VID       keys.ID
	Local     int64
	Remote    int64
	Timestamp int64
	Push      bool
}

// Changes for any keys in the keyring.
// If the keyring isn't synced this may not return all changes for those keyring
// keys, so you should usually sync the keyring first.
func (v *Vault) Changes(ctx context.Context) ([]*Change, error) {
	tokens, err := getTokens(v.db)
	if err != nil {
		return nil, err
	}
	status, err := v.client.Status(ctx, tokens)
	if err != nil {
		return nil, err
	}
	for _, st := range status {
		logger.Debugf("Status: %s %d", st.ID, st.Index)
	}
	indexes, err := pullIndexes(v.db)
	if err != nil {
		return nil, err
	}

	pushIndexes, err := pushIndexes(v.db)
	if err != nil {
		return nil, err
	}

	changes := []*Change{}
	for _, st := range status {
		kid := st.ID
		local := indexes[kid]
		_, push := pushIndexes[kid]
		if local < st.Index || push {
			logger.Debugf("Changed %s, %d < %d", kid, local, st.Index)
			changes = append(changes, &Change{VID: kid, Local: local, Remote: st.Index, Timestamp: st.Timestamp, Push: push})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		return changes[i].Timestamp > changes[j].Timestamp
	})
	return changes, nil
}

// func (v *Vault) resolveKeyTokens(ctx context.Context) error {
// 	check, err := getKeys(v.db)
// 	if err != nil {
// 		return err
// 	}
// 	for _, key := range check {
// 		if !key.IsEdX25519() {
// 			return errors.Errorf("invalid key")
// 		}
// 		if key.Token == "" {
// 			logger.Debugf("Resolving vault token %s", key.ID)
// 			token, err := v.client.Register(ctx, key.AsEdX25519())
// 			if err != nil {
// 				return err
// 			}
// 			key.Token = token
// 			key.UpdatedAt = v.clock.NowMillis()
// 			if err := updateKey(v.db, key); err != nil {
// 				return err
// 			}
// 		}
// 	}
// 	return nil
// }
