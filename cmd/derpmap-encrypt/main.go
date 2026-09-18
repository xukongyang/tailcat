// The derpmap-encrypt command encrypts a JSON DERP map with
// AES-256-GCM for serving over --derpmap-url. The output format is
// a 12-byte random nonce followed by the ciphertext and its 16-byte
// authentication tag, matching what tailcat's --derpmap-key option
// expects to decrypt.
//
// Usage:
//
//	derpmap-encrypt -genkey
//	derpmap-encrypt -genkey -o <keyfile>
//	derpmap-encrypt -key <hex-key> <derpmap.json>
//	derpmap-encrypt -key <hex-key> -decrypt <derpmap.json.enc>
//
// The first form prints a fresh random 32-byte key, hex-encoded. The
// second writes one to keyfile instead (mode 0600 on Unix; on
// Windows, restrict the file with icacls), so the key never appears
// in a shell's history or in process listings. The third encrypts
// derpmap.json to derpmap.json.enc. The fourth decrypts to stdout,
// to check a file before serving it.
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
	keyOut := flag.String("o", "", "with -genkey, write the key to this file (mode 0600) instead of printing it")
	keyHex := flag.String("key", "", "hex-encoded 32-byte AES key, as printed by -genkey")
	decrypt := flag.Bool("decrypt", false, "decrypt the input file to stdout instead of encrypting")
	flag.Parse()

	if *genkey {
		if *keyOut == "" {
			key := make([]byte, 32)
			if _, err := rand.Read(key); err != nil {
				fatalf("generating key: %v", err)
			}
			fmt.Println(hex.EncodeToString(key))
			return
		}
		if _, err := genKeyFile(*keyOut); err != nil {
			fatalf("%v", err)
		}
		fmt.Printf("wrote %v\n", *keyOut)
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

// genKeyFile generates a fresh key and writes it, hex-encoded with a
// trailing newline, to path with mode 0600 on Unix. On Windows the
// mode argument is inert; restrict the file with icacls instead. It
// returns the hex string, so callers can verify what was written.
func genKeyFile(path string) (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("generating key: %v", err)
	}
	hexStr := hex.EncodeToString(key)
	if err := os.WriteFile(path, []byte(hexStr+"\n"), 0o600); err != nil {
		return "", err
	}
	return hexStr, nil
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
