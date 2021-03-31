package auth

import (
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/vault/auth/api"
	"github.com/pkg/errors"
)

func NewPasswordAuth(password string, mk *[32]byte) (*Auth, error) {
	id := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)
	salt := keys.RandBytes(24)
	key, err := keys.KeyForPassword(password, salt)
	if err != nil {
		return nil, err
	}
	ek := secretBoxSeal(mk[:], key)
	return &Auth{
		ID:           id,
		Type:         api.PasswordType,
		EncryptedKey: ek,
		Salt:         salt,
		CreatedAt:    time.Now(),
	}, nil
}

// RegisterPassword registers a password.
func (d *DB) RegisterPassword(password string, mk *[32]byte) (*Auth, error) {
	if mk == nil {
		return nil, errors.Errorf("nil master key")
	}
	auth, err := NewPasswordAuth(password, mk)
	if err != nil {
		return nil, err
	}

	if err := d.Set(auth); err != nil {
		return nil, err
	}

	return auth, nil
}

// Password authenticates with a password.
func (d *DB) Password(password string) (*Auth, *[32]byte, error) {
	if password == "" {
		return nil, nil, ErrInvalidAuth
	}
	auths, err := d.ListByType(api.PasswordType)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to auth")
	}
	for _, auth := range auths {

		key, err := keys.KeyForPassword(password, auth.Salt)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "failed to auth")
		}

		mk := d.unlock(auth, key)
		if mk == nil {
			continue
		}

		return auth, mk, nil
	}
	return nil, nil, ErrInvalidAuth
}
