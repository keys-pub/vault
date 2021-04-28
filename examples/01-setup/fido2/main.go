package main

import (
	"context"
	"fmt"
	"log"

	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
)

func main() {
	logger := vault.NewLogger(vault.DebugLevel)
	vault.SetLogger(logger)

	// FIDO2
	fido2Plugin, err := fido2.OpenPlugin("fido2.so")
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
	vlt, err := vault.New("/tmp/vault.db", auth)
	if err != nil {
		log.Fatal(err)
	}
	vlt.SetFIDO2Plugin(fido2Plugin)

	pin := "12345"

	// Generate
	fmt.Println("Generating FIDO2 hmac-secret...")
	hs, err := vlt.GenerateFIDO2HMACSecret(context.TODO(), pin, "", "getchill.app/examples")
	if err != nil {
		log.Fatal(err)
	}

	// Setup
	fmt.Println("Setting up with FIDO2 hmac-secret...")
	if _, err := vlt.SetupFIDO2HMACSecret(context.TODO(), hs, pin); err != nil {
		log.Fatal(err)
	}

	// Unlock
	fmt.Println("Unlocking with FIDO2 hmac-secret...")
	if _, err := vlt.UnlockWithFIDO2HMACSecret(context.TODO(), pin); err != nil {
		log.Fatal(err)
	}
	defer vlt.Lock()

}
