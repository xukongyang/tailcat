// The derpmap-encrypt command encrypts a JSON DERP map with
// AES-256-GCM for serving over --derpmap-url. The output format is
// a 12-byte random nonce followed by the ciphertext and its 16-byte
// authentication tag, matching what tailcat's --derpmap-key option
// expects to decrypt.
//
// Usage:
//
//	derpmap-encrypt -genkey
//	derpmap-encrypt -key <hex-key> <derpmap.json>
//	derpmap-encrypt -key <hex-key> -decrypt <derpmap.json.enc>
//
// The first form prints a fresh random 32-byte key, hex-encoded.
// The second encrypts derpmap.json to derpmap.json.enc. The third
// decrypts to stdout, to check a file before serving it.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func main() {
	genkey := flag.Bool("genkey", false, "generate a random 32-byte key and exit")
	keyHex := flag.String("key", "", "hex-encoded 32-byte AES key, as printed by -genkey")
	decrypt := flag.Bool("decrypt", false, "decrypt the input file to stdout instead of encrypting")
	flag.Parse()

	if *genkey {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			fatalf("generating key: %v", err)
		}
		fmt.Println(hex.EncodeToString(key))
		return
	}

	key, err := parseKey(*keyHex)
	if err != nil {
		fatalf("%v", err)
	}
	if flag.NArg() != 1 {
		usage()
	}
	gcm, err := newGCM(key)
	if err != nil {
		fatalf("%v", err)
	}

	if *decrypt {
		data, err := os.ReadFile(flag.Arg(0))
		if err != nil {
			fatalf("%v", err)
		}
		plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], nil)
		if err != nil {
			fatalf("decrypting %v: %v (wrong key, or file truncated or modified)", flag.Arg(0), err)
		}
		os.Stdout.Write(plain)
		return
	}

	plain, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fatalf("%v", err)
	}
	if !json.Valid(plain) {
		fatalf("%v is not valid JSON; refusing to encrypt", flag.Arg(0))
	}
	// Seal appends to its first argument, so the result starts with
	// the fresh nonce. Each run must use a new nonce: reusing one
	// with the same key breaks AES-GCM's security completely.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		fatalf("generating nonce: %v", err)
	}
	out := gcm.Seal(nonce, nonce, plain, nil)
	outPath := flag.Arg(0) + ".enc"
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		fatalf("%v", err)
	}
	fmt.Printf("wrote %v (%d bytes from %d bytes of JSON)\n", outPath, len(out), len(plain))
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: derpmap-encrypt -genkey")
	fmt.Fprintln(os.Stderr, "       derpmap-encrypt -key <hex-key> <derpmap.json>")
	fmt.Fprintln(os.Stderr, "       derpmap-encrypt -key <hex-key> -decrypt <derpmap.json.enc>")
	os.Exit(2)
}

func parseKey(s string) ([]byte, error) {
	if s == "" {
		usage()
	}
	key, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("-key must be hex-encoded: %v", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("-key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	return key, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "derpmap-encrypt: "+format+"\n", args...)
	os.Exit(1)
}
