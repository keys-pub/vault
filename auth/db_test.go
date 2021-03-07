package auth_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/keys-pub/keys"
)

func testSeed(b byte) *[32]byte {
	return keys.Bytes32(bytes.Repeat([]byte{b}, 32))
}

func testPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("%s.db", keys.RandFileName()))
}
