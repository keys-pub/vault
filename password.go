package vault

import (
	"github.com/keys-pub/keys"
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
func (v *Vault) RegisterPassword(password string) error {
	if v.mk == nil {
		return ErrLocked
	}
	_, err := v.auth.RegisterPassword(password, v.mk)
	if err != nil {
		return err
	}
	return nil
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
