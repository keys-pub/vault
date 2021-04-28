package main

import (
	"log"

	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
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

	if _, err := vlt.SetupPassword("testpassword"); err != nil {
		log.Fatal(err)
	}

	if _, err := vlt.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(err)
	}
	defer vlt.Lock()
}
