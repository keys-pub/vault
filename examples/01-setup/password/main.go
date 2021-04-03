package main

import (
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys/api"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/keys-pub/vault/testutil"
)

func main() {
	logger := vault.NewLogger(vault.DebugLevel)
	vault.SetLogger(logger)

	// Client key
	ck := api.NewKey(keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0)))
	ck.Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.ZEPKPTYpg3WWXfgGsOVp--hd-U4lNhEXxsl5tx79NBE"

	auth, err := auth.NewDB("/tmp/auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	vlt, err := vault.New("/tmp/vault.db", auth)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := vlt.SetupPassword("testpassword", ck); err != nil {
		log.Fatal(err)
	}

	if _, err := vlt.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(err)
	}
	defer vlt.Lock()
}
