package vault

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault/auth"
)

// SetupPaperKey setup vault with a paper key.
func (v *Vault) SetupPaperKey(paperKey string, ck *api.Key) (*[32]byte, error) {
	mk := keys.Rand32()
	_, err := v.auth.RegisterPaperKey(paperKey, mk)
	if err != nil {
		return nil, err
	}
	if err := v.Setup(mk, ck); err != nil {
		return nil, err
	}
	return mk, nil
}

// RegisterPaperKey adds a paper key.
func (v *Vault) RegisterPaperKey(mk *[32]byte, paperKey string) (*auth.Auth, error) {
	if v.db == nil {
		return nil, ErrLocked
	}
	reg, err := v.auth.RegisterPaperKey(paperKey, mk)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// UnlockWithPaperKey opens vault with a paper key.
func (v *Vault) UnlockWithPaperKey(paperKey string) (*[32]byte, error) {
	_, mk, err := v.auth.PaperKey(paperKey)
	if err != nil {
		return nil, err
	}
	if err := v.Unlock(mk); err != nil {
		return nil, err
	}
	return mk, nil
}
