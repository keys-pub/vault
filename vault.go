package vault

import (
	"context"
	"os"

	"github.com/jmoiron/sqlx"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/client"
	"github.com/vmihailenco/msgpack/v4"

	"github.com/pkg/errors"
)

// ErrLocked if locked.
var ErrLocked = errors.New("vault is locked")

// ErrInvalidAuth if auth is invalid.
var ErrInvalidAuth = auth.ErrInvalidAuth

// ErrSetupNeeded if setup if needed.
var ErrSetupNeeded = errors.New("setup needed")

// Vault syncs secrets.
type Vault struct {
	path string
	db   *sqlx.DB

	clock  tsutil.Clock
	client *client.Client

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

	cl := opts.Client
	if cl == nil {
		c, err := client.New("https://keys.pub")
		if err != nil {
			return nil, err
		}
		cl = c
	}

	clock := tsutil.NewClock()

	v := &Vault{
		path:   path,
		client: cl,
		clock:  clock,
		auth:   auth,
	}
	v.kr = NewKeyring(v)
	return v, nil
}

// Auth returns auth db.
func (v *Vault) Auth() *auth.DB {
	return v.auth
}

// Status for vault.
type Status string

// Status of vault.
const (
	Locked      Status = "locked"
	Unlocked    Status = "unlocked"
	SetupNeeded Status = "setup-needed"
)

// Status returns vault status.
func (v *Vault) Status() Status {
	if _, err := os.Stat(v.path); os.IsNotExist(err) {
		return SetupNeeded
	}
	if v.db == nil {
		return Locked
	}
	return Unlocked
}

// Setup vault.
// Doesn't unlock.
func (v *Vault) Setup(mk *[32]byte, opt ...SetupOption) error {
	logger.Debugf("Setup...")
	if v.db != nil {
		return errors.Errorf("already unlocked")
	}
	opts := newSetupOptions(opt...)

	if _, err := os.Stat(v.path); err == nil {
		return errors.Errorf("already setup")
	}

	// This creates a new db file (and on error we'll remove it).
	db, err := openDB(v.path, mk)
	if err != nil {
		return err
	}
	onErrFn := func() {
		_ = db.Close()
		_ = os.Remove(v.path)
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

	if _, err := os.Stat(v.path); os.IsNotExist(err) {
		return ErrSetupNeeded
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

	ck, err := clientKey(db)
	if err != nil {
		onErrFn()
		return err
	}
	if ck == nil {
		onErrFn()
		return errors.Errorf("missing client key")
	}

	v.unlocked(mk, ck, db)

	logger.Debugf("Unlocked")
	return nil
}

func (v *Vault) unlocked(mk *[32]byte, ck *api.Key, db *sqlx.DB) {
	v.mk = mk
	v.ck = ck
	v.db = db
}

func (v *Vault) locked() {
	v.db = nil
	v.mk = nil
	v.ck = nil
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

// Register a vault.
// You can register a key that already exists.
// You can sync a keyring vault to get registered vault keys as well.
// Requires Unlock.
func (v *Vault) Register(ctx context.Context, key *keys.EdX25519Key) error {
	if v.db == nil {
		return ErrLocked
	}
	vk := api.NewKey(key).Created(v.clock.NowMillis())
	token, err := v.client.Register(ctx, key)
	if err != nil {
		return err
	}
	vk.Token = token

	if err := v.Keyring().Set(vk); err != nil {
		return err
	}

	if err = v.kr.Sync(ctx); err != nil {
		return err
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
	if err := add(v.db, vid, b); err != nil {
		return errors.Wrapf(err, "failed to add")
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
func (v *Vault) ClientKey() *api.Key {
	return v.ck
}

// Client is the vault client.
func (v *Vault) Client() *client.Client {
	return v.client
}

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

func importClientKey(db *sqlx.DB, key *keys.EdX25519Key, clock tsutil.Clock) (*api.Key, error) {
	logger.Debugf("Import client key...")
	ck, err := clientKey(db)
	if err != nil {
		return nil, err
	}
	if ck != nil {
		return nil, errors.Errorf("already setup")
	}
	ck = api.NewKey(key)
	ck.CreatedAt = clock.NowMillis()
	ck.UpdatedAt = clock.NowMillis()

	b, err := msgpack.Marshal(ck)
	if err != nil {
		return nil, err
	}
	if err := setConfigBytes(db, "clientKey", b); err != nil {
		return nil, err
	}

	return ck, nil
}

func (v *Vault) Reset() error {
	return errors.Errorf("not implemented")
}
