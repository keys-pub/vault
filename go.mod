module github.com/keys-pub/vault

go 1.15

require (
	github.com/davecgh/go-spew v1.1.1
	github.com/getchill-app/http-client v0.0.0-20210403012548-aee276f0e1d8
	github.com/getchill-app/server v0.0.0-20210403215008-63eeb378e83c
	github.com/jmoiron/sqlx v1.3.1
	github.com/keys-pub/keys v0.1.21-0.20210402011617-28dedbda9f32
	github.com/keys-pub/keys-ext/auth/fido2 v0.0.0-20210327130412-59e9fcfcf22c
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/vmihailenco/msgpack/v4 v4.3.12
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/sys v0.0.0-20210331175145-43e1dd70ce54 // indirect
)

// replace github.com/keys-pub/keys => ../keys

// replace github.com/getchill-app/server => ../../getchill/server

// replace github.com/keys-pub/keys-ext/ws/api => ../keys-ext/ws/api
