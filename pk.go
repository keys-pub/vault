package vault

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/auth"
)

// SetupPaperKey setup vault with a paper key.
func (v *Vault) SetupPaperKey(paperKey string, opt ...SetupOption) (*[32]byte, error) {
	mk := keys.Rand32()
	_, err := v.auth.RegisterPaperKey(paperKey, mk)
	if err != nil {
		return nil, err
	}
	if err := v.Setup(mk, opt...); err != nil {
		return nil, err
	}
	return mk, nil
}

// RegisterPaperKey adds a paper key.
func (v *Vault) RegisterPaperKey(paperKey string) (*auth.Auth, error) {
	if v.mk == nil {
		return nil, ErrLocked
	}
	reg, err := v.auth.RegisterPaperKey(paperKey, v.mk)
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
