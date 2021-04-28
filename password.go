package vault

import (
	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault/auth"
)

// SetupPassword setup vault with a password.
func (v *Vault) SetupPassword(password string) (*[32]byte, error) {
	mk := keys.Rand32()
	if _, err := v.auth.RegisterPassword(password, mk); err != nil {
		return nil, err
	}
	if err := v.Setup(mk); err != nil {
		return nil, err
	}
	return mk, nil
}

// RegisterPassword adds a password.
func (v *Vault) RegisterPassword(mk *[32]byte, password string) (*auth.Auth, error) {
	if v.db == nil {
		return nil, ErrLocked
	}
	reg, err := v.auth.RegisterPassword(password, mk)
	if err != nil {
		return nil, err
	}
	return reg, nil
}

// UnlockWithPassword opens vault with a password.
func (v *Vault) UnlockWithPassword(password string) (*[32]byte, error) {
	_, mk, err := v.auth.Password(password)
	if err != nil {
		return nil, err
	}
	if err := v.Unlock(mk); err != nil {
		return nil, err
	}
	return mk, nil
}
