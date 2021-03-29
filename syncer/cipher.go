package syncer

import (
	"github.com/keys-pub/keys"
)

// Cipher for encryption.
type Cipher interface {
	Encrypt(b []byte, key *keys.EdX25519Key) ([]byte, error)
}

type CryptoBoxSealCipher struct{}

func (c CryptoBoxSealCipher) Encrypt(b []byte, key *keys.EdX25519Key) ([]byte, error) {
	encrypted := keys.CryptoBoxSeal(b, key.X25519Key().PublicKey())
	return encrypted, nil
}

type NoCipher struct{}

func (c NoCipher) Encrypt(b []byte, key *keys.EdX25519Key) ([]byte, error) {
	return b, nil
}
