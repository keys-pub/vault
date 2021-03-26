module github.com/keys-pub/vault

go 1.15

require (
	github.com/alta/protopatch v0.3.3 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/jmoiron/sqlx v1.3.1
	github.com/keys-pub/keys v0.1.21-0.20210326211358-fb3db764000f
	github.com/keys-pub/keys-ext/auth/fido2 v0.0.0-20210326151246-e22614b5a632
	github.com/keys-pub/keys-ext/http/api v0.0.0-20210326151246-e22614b5a632
	github.com/keys-pub/keys-ext/http/server v0.0.0-20210326151246-e22614b5a632
	github.com/labstack/echo/v4 v4.2.0 // indirect
	github.com/lib/pq v1.9.0 // indirect
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20210326060303-6b1517762897 // indirect
	google.golang.org/genproto v0.0.0-20210325224202-eed09b1b5210 // indirect
	google.golang.org/grpc v1.36.1 // indirect
)

// replace github.com/keys-pub/keys => ../keys

// replace github.com/keys-pub/keys-ext/http/api => ../keys-ext/http/api

// replace github.com/keys-pub/keys-ext/http/server => ../keys-ext/http/server

// replace github.com/keys-pub/keys-ext/ws/api => ../keys-ext/ws/api
