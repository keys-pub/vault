package main

import (
	"context"
	"log"

	hclient "github.com/getchill-app/http-client"
	"github.com/keys-pub/keys"
	"github.com/keys-pub/vault"
	vclient "github.com/keys-pub/vault/client"
	"github.com/keys-pub/vault/testutil"
	"github.com/pkg/errors"
)

func main() {
	logger := vault.NewLogger(vault.DebugLevel)
	vault.SetLogger(logger)

	url := "https://getchill.app/"

	alice := keys.NewEdX25519KeyFromSeed(testutil.Seed(0x01))
	hclient, err := hclient.New(url)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Creating account...\n")
	if err := hclient.AccountCreate(context.TODO(), alice, "alice@getchill.app"); err != nil {
		log.Fatal(errors.Wrapf(err, "failed to create account"))
	}

	vclient, err := vclient.New(url)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Registering key...\n")
	key := keys.NewEdX25519KeyFromSeed(testutil.Seed(0xa0))
	reg, err := vclient.Register(context.TODO(), key, alice)
	if err != nil {
		log.Fatal(errors.Wrapf(err, "failed to register key"))
	}

	log.Printf("Registered %s\n", reg.ID)
	log.Printf("Token: %s\n", reg.Token)
}
