package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/keys-pub/keys"
	"github.com/keys-pub/keys-ext/http/client"
	"github.com/keys-pub/vault"
	"github.com/keys-pub/vault/auth"
	"github.com/pkg/errors"
	"github.com/vmihailenco/msgpack/v4"
)

// Message to store in vault.
type Message struct {
	ID   string `msgpack:"id"`
	Text string `msgpack:"text"`
}

// MarshalVault how to marshal for vault.
func (m *Message) MarshalVault() ([]byte, error) {
	return msgpack.Marshal(m)
}

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

	if _, err := vlt.UnlockWithPassword("testpassword"); err != nil {
		log.Fatal(errors.Wrapf(err, "failed to open vault"))
	}
	defer vlt.Lock()

	status, err := vlt.SyncStatus()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Status: %v\n", status)

	msg := &Message{ID: keys.RandBase62(16), Text: keys.RandPhrase()}
	fmt.Printf("Adding message: %v\n", msg)
	if err := vlt.Add(msg); err != nil {
		log.Fatal(err)
	}

	start := time.Now()
	err = vlt.Sync(context.TODO())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Sync took %s\n", time.Since(start))

	events, err := vlt.Pulled(0)
	if err != nil {
		log.Fatal(err)
	}
	// for _, e := range events {
	// 	fmt.Printf("%d %s (%d)\n", e.Index, e.Timestamp, len(e.Data))
	// }
	fmt.Printf("%d event(s)\n", len(events))
}
