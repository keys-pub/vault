package api

import "time"

// Auth describes an auth method encrypting a master key.
type Auth struct {
	// ID is an identifier for the auth.
	ID string `msgpack:"id" db:"id"`

	// EncryptedKey is a nacl secretbox encrypted master key using the auth key.
	EncryptedKey []byte `msgpack:"ek,omitempty" db:"ek"`

	// Type of auth
	Type Type `msgpack:"type,omitempty" db:"type"`

	// Salt (for PasswordAuth and FIDO2HMACSecretAuth)
	Salt []byte `msgpack:"salt,omitempty" db:"salt"`

	// AAGUID (for FIDO2HMACSecretAuth)
	AAGUID string `msgpack:"aaguid,omitempty" json:"aaguid"`
	// NoPin (for FIDO2HMACSecretAuth)
	NoPin bool `msgpack:"nopin,omitempty" db:"nopin"`

	CreatedAt time.Time `msgpack:"createdAt,omitempty" db:"createdAt"`

	// Deleted flag
	Deleted bool `msgpack:"del,omitempty" db:"del"`
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
