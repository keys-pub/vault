# Architecture

The vault package provides a syncable encrypted event log. It uses an encrypted sqlite database (with sqlcipher) that is encrypted with a master key.
This master key can be obtained from an auth method, such as a password, paper key or hardware (FIDO2) key, using the auth package, or can be managed manually.

## Vault Database

The `push` table contains data not yet synced to a remote.
The `pull` table contains data synced from a remote and includes a remote index and timestamp.
The `keys` table contains any keys in the keyring such as the client key or registered vault keys.

## Auth Database

The auth package provides a sqlite database which stores metadata about auth methods.
Each auth method encrypts a master key with an auth key (or key encrypting key/KEK).
Auth methods include passwords, paper keys and hardware (FIDO2) keys.
The auth database is NOT encrypted with sqlcipher, but the master keys in the auth db are encrypted (with the KEK).
Another way to say this is that auth metadata, such as salts or device IDs, are not encrypted.
