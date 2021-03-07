package vault

import (
	"database/sql"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys/encoding"
	"github.com/keys-pub/keys/tsutil"
	"github.com/pkg/errors"
)

func setConfig(db *sqlx.DB, key string, value string) error {
	if _, err := db.Exec("INSERT OR REPLACE INTO config (key, value) VALUES ($1, $2)", key, value); err != nil {
		return errors.Wrapf(err, "failed to set config")
	}
	return nil
}

func getConfig(db *sqlx.DB, key string) (string, error) {
	var value string
	if err := db.Get(&value, "SELECT value FROM config WHERE key=$1", key); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", errors.Wrapf(err, "failed to get config")
	}
	return value, nil
}

func setConfigBytes(db *sqlx.DB, key string, b []byte) error {
	if len(b) == 0 {
		return setConfig(db, key, "")
	}
	return setConfig(db, key, encoding.MustEncode(b, encoding.Base64))
}

func getConfigBytes(db *sqlx.DB, key string) ([]byte, error) {
	s, err := getConfig(db, key)
	if err != nil {
		return nil, err
	}
	if len(s) == 0 {
		return nil, nil
	}
	b, err := encoding.DecodeBase64(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func setConfigInt64(db *sqlx.DB, key string, n int64) error {
	if n == 0 {
		return setConfig(db, key, "")
	}
	return setConfig(db, key, strconv.FormatInt(n, 10))
}

func getConfigInt64(db *sqlx.DB, key string) (int64, error) {
	s, err := getConfig(db, key)
	if err != nil {
		return 0, err
	}
	if len(s) == 0 {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func setConfigTime(db *sqlx.DB, key string, t time.Time) error {
	return setConfigInt64(db, key, tsutil.Millis(t))
}

func getConfigTime(db *sqlx.DB, key string) (time.Time, error) {
	n, err := getConfigInt64(db, key)
	if err != nil {
		return time.Time{}, err
	}
	if n == 0 {
		return time.Time{}, nil
	}
	return tsutil.ParseMillis(n), nil
}

func setConfigBool(db *sqlx.DB, key string, b bool) error {
	return setConfig(db, key, "true")
}

func getConfigBool(db *sqlx.DB, key string) (bool, error) {
	s, err := getConfig(db, key)
	if err != nil {
		return false, err
	}
	return s == "true", nil
}
