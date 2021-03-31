package auth

import (
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/vault/auth/api"
	"github.com/pkg/errors"
)

// RegisterPaperKey registers paper key auth.
func (d *DB) RegisterPaperKey(paperKey string, mk *[32]byte) (*Auth, error) {
	if mk == nil {
		return nil, errors.Errorf("nil master key")
	}
	id := encoding.MustEncode(keys.RandBytes(32), encoding.Base62)

	key, err := encoding.PhraseToBytes(paperKey, true)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode paper key")
	}

	ek := secretBoxSeal(mk[:], key)
	auth := &Auth{
		ID:           id,
		Type:         api.PaperKeyType,
		EncryptedKey: ek,
		CreatedAt:    time.Now(),
	}

	if err := d.Set(auth); err != nil {
		return nil, err
	}

	return auth, nil
}

// PaperKey authenticates using a paper key.
func (d *DB) PaperKey(paperKey string) (*Auth, *[32]byte, error) {
	auths, err := d.ListByType(api.PaperKeyType)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed to auth")
	}
	key, err := encoding.PhraseToBytes(paperKey, true)
	if err != nil {
		return nil, nil, ErrInvalidAuth
	}

	for _, auth := range auths {
		mk := d.unlock(auth, key)
		if mk == nil {
			continue
		}
		return auth, mk, nil
	}
	return nil, nil, ErrInvalidAuth
}
