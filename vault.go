package vault

import (
	"context"
	"os"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/keys/api"
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

	auth *auth.DB

	fido2Plugin fido2.FIDO2Server

	// checkedAt time.Time
	// checkMtx  sync.Mutex

	// Main secret key if unlocked.
	// TODO: Let's clear this after some time
	mk *[32]byte

	ck *api.Key
	kr *Keyring
}

// New vault.
func New(path string, auth *auth.DB, opt ...Option) (*Vault, error) {
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

	return &Vault{
		path:   path,
		client: client,
		clock:  clock,
		auth:   auth,
	}, nil
}

// NeedsSetup returns true if vault database doesn't exist.
func (v *Vault) NeedsSetup() bool {
	if _, err := os.Stat(v.path); os.IsNotExist(err) {
		return true
	}
	return false
}

// Setup vault.
// Doesn't unlock.
func (v *Vault) Setup(mk *[32]byte, opt ...SetupOption) error {
	logger.Debugf("Setup...")
	if v.db != nil {
		return errors.Errorf("already unlocked")
	}
	opts := newSetupOptions(opt...)

	db, err := openDB(v.path, mk)
	if err != nil {
		return err
	}
	onErrFn := func() {
		_ = db.Close()
	}

	if err := initTables(db); err != nil {
		onErrFn()
		return err
	}

	// Generate or import client key
	var ck *api.Key
	var kerr error
	if opts.ClientKey != nil {
		ck, kerr = importClientKey(db, opts.ClientKey, v.clock)
	} else {
		key := keys.GenerateEdX25519Key()
		ck, kerr = importClientKey(db, key, v.clock)
	}
	if kerr != nil {
		onErrFn()
		return kerr
	}

	v.unlocked(mk, ck, db)

	logger.Debugf("Setup complete")
	return nil
}

// Unlock vault.
func (v *Vault) Unlock(mk *[32]byte) error {
	logger.Debugf("Unlock...")

	if v.db != nil {
		logger.Debugf("Already unlocked")
		return nil
	}

	db, err := openDB(v.path, mk)
	if err != nil {
		return err
	}
	onErrFn := func() {
		_ = db.Close()
	}

	if err := initTables(db); err != nil {
		onErrFn()
		return err
	}

	ck, err := getKeyWithLabel(db, "main")
	if err != nil {
		onErrFn()
		return err
	}
	if ck == nil {
		onErrFn()
		return errors.Errorf("needs setup")
	}

	v.unlocked(mk, ck, db)

	logger.Debugf("Unlocked")
	return nil
}

func (v *Vault) unlocked(mk *[32]byte, ck *api.Key, db *sqlx.DB) {
	v.mk = mk
	v.ck = ck
	v.db = db
	v.kr = &Keyring{db, ck, v.client, v.clock}
}

func (v *Vault) locked() {
	v.db = nil
	v.mk = nil
	v.ck = nil
	v.kr = nil
}

// Lock vault.
func (v *Vault) Lock() error {
	logger.Debugf("Locking...")

	if v.db == nil {
		logger.Debugf("Already locked")
		return nil
	}
	db := v.db
	v.locked()

	if err := db.Close(); err != nil {
		return errors.Wrapf(err, "failed to close db")
	}

	return nil
}

// Add to vault.
// The `vid` is a vault identifier.
// You can create a vault using Create.
// Requires Unlock.
func (v *Vault) Add(vid keys.ID, b []byte) error {
	if v.db == nil {
		return ErrLocked
	}
	key, err := v.Keyring().Key(vid)
	if err != nil {
		return err
	}
	if key == nil {
		return errors.Wrapf(keys.NewErrNotFound((vid.String())), "failed to add")
	}
	if !key.HasLabel("vault") {
		return errors.Errorf("not a vault key")
	}
	if err := add(v.db, vid, b); err != nil {
		return errors.Wrapf(err, "failed to add")
	}
	return nil
}

// Event pulled from remote.
type Event struct {
	Data            []byte    `db:"data"`
	RemoteIndex     int64     `db:"ridx"`
	RemoteTimestamp time.Time `db:"rts"`
	VID             keys.ID   `db:"vid"`
}

// Create a vault.
// Requires Unlock.
func (v *Vault) Create(ctx context.Context, key *keys.EdX25519Key) error {
	if v.db == nil {
		return ErrLocked
	}
	vk := api.NewKey(key).WithLabels("vault").Created(v.clock.NowMillis())
	token, err := v.client.Create(ctx, key)
	if err != nil {
		return err
	}
	vk.Token = token

	if err := saveKey(v.db, v.ck.ID, vk); err != nil {
		return err
	}

	if err = v.kr.Sync(ctx); err != nil {
		return err
	}

	return nil
}

// Keyring for keys in vault.
func (v *Vault) Keyring() *Keyring {
	return v.kr
}

// DB returns underlying database if vault is open.
// Returns nil if locked.
func (v *Vault) DB() *sqlx.DB {
	if v.db == nil {
		return nil
	}
	return v.db
}

// ClientKey is the vault client key.
func (v *Vault) ClientKey() (*api.Key, error) {
	ck, err := getKeyWithLabel(v.db, "client")
	if err != nil {
		return nil, err
	}
	return ck, nil
}

func importClientKey(db *sqlx.DB, key *keys.EdX25519Key, clock tsutil.Clock) (*api.Key, error) {
	logger.Debugf("Import client key...")
	ck, err := getKeyWithLabel(db, "client")
	if err != nil {
		return nil, err
	}
	if ck != nil {
		return nil, errors.Errorf("already setup")
	}
	ck = api.NewKey(key).WithLabels("client", "vault")
	ck.CreatedAt = clock.NowMillis()
	ck.UpdatedAt = clock.NowMillis()
	if err := updateKey(db, ck); err != nil {
		return nil, err
	}
	return ck, nil
}
