package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestEncodeFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "derpmap.json.enc")
	data := []byte{0, 1, 2, 250, 251, 255}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	// The default is the prefixed form --derpmap-url takes directly.
	got, err := encodeFile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := "base64:" + base64.StdEncoding.EncodeToString(data); got != want {
		t.Errorf("encodeFile = %q; want %q", got, want)
	}

	// -raw prints only the payload.
	got, err = encodeFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if want := base64.StdEncoding.EncodeToString(data); got != want {
		t.Errorf("encodeFile raw = %q; want %q", got, want)
	}

	// Missing files report an error.
	if _, err := encodeFile(filepath.Join(dir, "nope"), false); err == nil {
		t.Error("encoding a missing file succeeded; want an error")
	}
}
