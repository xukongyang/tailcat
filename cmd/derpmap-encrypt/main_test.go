package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "derpmap.key")
	hexStr, err := genKeyFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(hexStr); n != 64 {
		t.Fatalf("genKeyFile = %d hex chars; want 64", n)
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil || len(b) != 32 {
		t.Fatalf("genKeyFile = %q; want 64 hex chars for 32 bytes", hexStr)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(data)); got != hexStr {
		t.Errorf("file = %q; want %q", got, hexStr)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("file permissions = %v; want 0600", fi.Mode().Perm())
		}
	}
}
