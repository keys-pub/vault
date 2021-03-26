package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/keys/tsutil"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/pkg/errors"
)

func main() {
	logger := vault.NewLogger(vault.DebugLevel)
	vault.SetLogger(logger)

	auth, err := auth.NewDB("/tmp/auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	vlt, err := vault.New("/tmp/vault.db", auth)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := vlt.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(errors.Wrapf(err, "failed to open vault"))
	}
	defer vlt.Lock()

	test := api.NewKey(keys.GenerateEdX25519Key()).WithLabels("test").Created(tsutil.NowMillis())
	if err := vlt.Keyring().Set(test); err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	err = vlt.Keyring().Sync(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sync took %s\n", time.Since(start))

	ks, err := vlt.Keyring().Keys()
	if err != nil {
		log.Fatal(err)
	}
	for _, key := range ks {
		fmt.Printf("%s %s\n", key.ID, tsutil.ParseMillis(key.CreatedAt))
	}
}
