package auth

import (
	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/vmihailenco/msgpack/v4"
)

func clientKey(db *sqlx.DB) (*api.Key, error) {
	b, err := getConfigBytes(db, "clientKey")
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, nil
	}
	var k api.Key
	if err := msgpack.Unmarshal(b, &k); err != nil {
		return nil, err
	}
	return &k, nil
}

func importClientKey(db *sqlx.DB, ck *keys.EdX25519Key) (*api.Key, error) {
	if ck == nil {
		ck = keys.GenerateEdX25519Key()
	}
	key := api.NewKey(ck).Created(tsutil.NowMillis())
	b, err := msgpack.Marshal(key)
	if err != nil {
		return nil, err
	}
	if err := setConfigBytes(db, "clientKey", b); err != nil {
		return nil, err
	}
	return key, nil
}

func generateClientKey(db *sqlx.DB) (*api.Key, error) {
	key, err := clientKey(db)
	if err != nil {
		return nil, err
	}
	if key != nil {
		return key, nil
	}

	key = api.NewKey(keys.GenerateEdX25519Key()).Created(tsutil.NowMillis())
	b, err := msgpack.Marshal(key)
	if err != nil {
		return nil, err
	}
	if err := setConfigBytes(db, "clientKey", b); err != nil {
		return nil, err
	}
	return key, nil
}

func initClientKey(db *sqlx.DB, ck *keys.EdX25519Key) (*api.Key, error) {
	if ck != nil {
		return importClientKey(db, ck)
	}
	return generateClientKey(db)
}
