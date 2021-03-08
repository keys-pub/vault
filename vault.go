package vault

import (
	"os"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault/auth"

	"github.com/pkg/errors"
)

// ErrLocked if locked.
var ErrLocked = errors.New("vault is locked")

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = auth.ErrInvalidAuth

// Vault syncs secrets.
type Vault struct {
	path string
	db   *sqlx.DB

	clock  tsutil.Clock
	client *Client

	source Source

	auth *auth.DB

	fido2Plugin fido2.FIDO2Server

	openMtx sync.Mutex

	checkedAt time.Time
	checkMtx  sync.Mutex

	// Master key if unlocked.
	// TODO: Let's clear this after some time
	mk *[32]byte
}

// New vault.
func New(path string, auth *auth.DB, source Source, opt ...Option) (*Vault, error) {
	opts := newOptions(opt...)

	client := opts.Client
	if client == nil {
		c, err := NewClient("https://keys.pub")
		if err != nil {
			return nil, err
		}
		client = c
	}

	clock := tsutil.NewClock()
	if source == nil {
		source = emptySource{}
	}

	return &Vault{
		path:   path,
		client: client,
		clock:  clock,
		auth:   auth,
		source: source,
	}, nil
}

// NeedsSetup returns true if vault database doesn't exist.
func (v *Vault) NeedsSetup() bool {
	v.openMtx.Lock()
	defer v.openMtx.Unlock()
	if _, err := os.Stat(v.path); os.IsNotExist(err) {
		return true
	}
	return false
}

// Setup vault.
// Doesn't unlock.
func (v *Vault) Setup(mk *[32]byte) error {
	v.openMtx.Lock()
	defer v.openMtx.Unlock()
	if v.db != nil {
		return errors.Errorf("already unlocked")
	}

	db, err := openDB(v.path, mk)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := initDB(db, true); err != nil {
		return err
	}
	if v.source != nil {
		if err := v.source.Init(db); err != nil {
			return err
		}
	}
	return nil
}

// Unlock vault.
func (v *Vault) Unlock(mk *[32]byte) error {
	v.openMtx.Lock()
	defer v.openMtx.Unlock()
	logger.Debugf("Unlock...")

	if v.db != nil {
		logger.Debugf("Already unlocked")
		return nil
	}

	db, err := openDB(v.path, mk)
	if err != nil {
		return err
	}
	if err := initDB(db, false); err != nil {
		_ = db.Close()
		return err
	}
	if v.source != nil {
		if err := v.source.Init(db); err != nil {
			_ = db.Close()
			return err
		}
	}

	v.db = db
	v.mk = mk
	return nil
}

// Lock vault.
func (v *Vault) Lock() error {
	v.openMtx.Lock()
	defer v.openMtx.Unlock()
	logger.Debugf("Locking...")

	if v.db == nil {
		logger.Debugf("Already locked")
		return nil
	}
	db := v.db
	v.db = nil
	v.mk = nil

	if err := db.Close(); err != nil {
		return errors.Wrapf(err, "failed to close db")
	}

	return nil
}

// Add to vault.
// Requires Unlock.
func (v *Vault) Add(i interface{}) error {
	if v.db == nil {
		return ErrLocked
	}
	if err := v.add(i); err != nil {
		return errors.Wrapf(err, "failed to add")
	}
	return nil
}

// Event pulled from remote.
type Event struct {
	Data            []byte    `msgpack:"data" db:"data"`
	RemoteIndex     int64     `msgpack:"-" db:"ridx"`
	RemoteTimestamp time.Time `msgpack:"-" db:"rts"`
}

// Pulled ...
func (v *Vault) Pulled(from int64) ([]*Event, error) {
	if v.db == nil {
		return nil, ErrLocked
	}
	events, err := v.listPull(from)
	if err != nil {
		return nil, err
	}
	return events, nil
}

// SetClientKey sets the client key.
// Requires Unlock.
func (v *Vault) SetClientKey(key *keys.EdX25519Key) error {
	if v.db == nil {
		return ErrLocked
	}
	if err := setClientKey(v.db, key); err != nil {
		return err
	}
	return nil
}

// ClientKey returns the client key.
// Requires Unlock.
func (v *Vault) ClientKey() (*keys.EdX25519Key, error) {
	if v.db == nil {
		return nil, ErrLocked
	}
	return clientKey(v.db)
}

// DB returns underlying database if vault is open.
// Returns nil if locked.
func (v *Vault) DB() *sqlx.DB {
	if v.db == nil {
		return nil
	}
	return v.db
}
