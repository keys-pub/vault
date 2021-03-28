package main

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/keys-pub/keys-ext/auth/fido2"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
)

func main() {
	logger := vault.NewLogger(vault.DebugLevel)
	vault.SetLogger(logger)

	// FIDO2
	fido2Plugin, err := fido2.OpenPlugin(goBin("fido2.so"))
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

	// Registering new auth method requires unlock
	if _, err := vlt.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(err)
	}
	defer vlt.Lock()

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

	// Generate
	fmt.Println("Generating FIDO2 hmac-secret...")
	hs, err := vlt.GenerateFIDO2HMACSecret(context.TODO(), pin, device, "keys.pub/vault/examples")
	if err != nil {
		log.Fatal(err)
	}

	// Register
	fmt.Println("Register FIDO2 hmac-secret...")
	reg, err := vlt.RegisterFIDO2HMACSecret(context.TODO(), hs, pin)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Registered: %s", spew.Sdump(reg))
}

func goBin(file string) string {
	out, err := exec.Command("go", "env", "GOPATH").Output()
	if err != nil {
		panic(err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "bin", file)
}
