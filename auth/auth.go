package auth

import (
	"time"

	"github.com/pkg/errors"
)

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = errors.New("invalid auth")

// Auth describes an auth method encrypting a master key.
type Auth struct {
	// ID is an identifier for the auth.
	ID string `db:"id"`

	// EncryptedKey is a nacl secretbox encrypted master key using the auth key.
	EncryptedKey []byte `db:"ek"`

	// Type of auth
	Type Type `db:"type"`

	// Salt (for PasswordAuth and FIDO2HMACSecretAuth)
	Salt []byte `db:"salt"`

	// AAGUID (for FIDO2HMACSecretAuth)
	AAGUID string `json:"aaguid"`
	// NoPin (for FIDO2HMACSecretAuth)
	NoPin bool `db:"nopin"`

	CreatedAt time.Time `db:"createdAt"`
}

// Type describes an auth method.
type Type string

// Auth types.
const (
	UnknownType         Type = ""
	PaperKeyType        Type = "paper-key"
	PasswordType        Type = "password"
	FIDO2HMACSecretType Type = "fido2-hmac-secret" // #nosec
)
