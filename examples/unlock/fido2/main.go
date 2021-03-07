package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/keys-ext/http/client"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
)

func main() {
	logger := vault.NewLogger(vault.DebugLevel)
	vault.SetLogger(logger)
	client.SetLogger(logger)

	// FIDO2 (TODO: Path)
	fido2Plugin, err := fido2.OpenPlugin("/Users/gabe/go/bin/fido2.so")
	if err != nil {
		log.Fatal(err)
	}

	// Auth
	auth, err := auth.NewDB("/tmp/auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer auth.Close()

	// Vault
	vlt, err := vault.New("/tmp/vault.db", auth, nil)
	if err != nil {
		log.Fatal(err)
	}
	vlt.SetFIDO2Plugin(fido2Plugin)

	pin := "12345"

	devices, err := vlt.FIDO2Devices(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	if len(devices) == 0 {
		log.Fatal("no FIDO2 devices found")
	}
	fmt.Printf("Found %d device(s)\n", len(devices))
	device := devices[0].Path
	fmt.Printf("Using device: %s\n", device)

	// Unlock
	fmt.Println("Unlocking with FIDO2 hmac-secret...")
	if err := vlt.UnlockWithFIDO2HMACSecret(context.TODO(), pin); err != nil {
		log.Fatal(err)
	}
	defer vlt.Lock()
}

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}
