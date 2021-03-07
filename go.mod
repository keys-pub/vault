module github.com/keys-pub/vault

go 1.15

require (
	github.com/jmoiron/sqlx v1.3.1
	github.com/keys-pub/keys v0.1.20
	github.com/keys-pub/keys-ext/auth/fido2 v0.0.0-20210307004320-f39fc126a90e
	github.com/keys-pub/keys-ext/http/api v0.0.0-20210307010302-494711ddc471
	github.com/keys-pub/keys-ext/http/client v0.0.0-20210307010302-494711ddc471
	github.com/keys-pub/keys-ext/http/server v0.0.0-20210307010302-494711ddc471
	github.com/keys-pub/keys-ext/ws/api v0.0.0-20210307010302-494711ddc471 // indirect
	github.com/labstack/echo/v4 v4.2.0 // indirect
	github.com/lib/pq v1.9.0 // indirect
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
	golang.org/x/crypto v0.0.0-20210220033148-5ea612d1eb83
)

// replace github.com/keys-pub/keys-ext/http/client => ../keys-ext/http/client

// replace github.com/keys-pub/keys-ext/http/server => ../keys-ext/http/server

replace github.com/keys-pub/keys => ../keys
