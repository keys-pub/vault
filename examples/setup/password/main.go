package main

import (
	"bytes"
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/http/client"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
)

func main() {
	logger := vault.NewLogger(vault.DebugLevel)
	vault.SetLogger(logger)
	client.SetLogger(logger)

	auth, err := auth.NewDB("/tmp/auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	vlt, err := vault.New("/tmp/vault.db", auth, nil)
	if err != nil {
		log.Fatal(err)
	}

	if err := vlt.SetupPassword("testpassword"); err != nil {
		log.Fatal(err)
	}

	if err := vlt.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(err)
	}
	defer vlt.Lock()
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
