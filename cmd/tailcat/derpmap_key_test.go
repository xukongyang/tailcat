package main

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tailscale/tailcat"
)

func TestResolveDerpMapKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "derpmap.key")
	if err := os.WriteFile(keyPath, []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A pipe as --derpmap-key-fd, with a trailing newline like most
	// writers leave.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.WriteString("abcd\n"); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	defer pr.Close()

	// One source at a time wins; the file and stdin forms trim
	// surrounding whitespace, and an empty read is an error.
	for _, tt := range []struct {
		name    string
		key     string
		keyFile string
		keyFD   int
		stdin   string
		want    string
	}{
		{"flag", "abcd", "", -1, "", "abcd"},
		{"file", "", keyPath, -1, "", "abcd"},
		{"fd", "", "", int(pr.Fd()), "", "abcd"},
		{"stdin", "", "", -1, "abcd\n", "abcd"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stdin io.Reader
			if tt.name == "stdin" {
				stdin = strings.NewReader(tt.stdin)
			}
			got, err := resolveDerpMapKey(tt.key, tt.keyFile, tt.keyFD, stdin)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("resolveDerpMapKey = %q; want %q", got, tt.want)
			}
		})
	}

	// More than one source is a configuration error.
	if _, err := resolveDerpMapKey("abcd", keyPath, -1, nil); err == nil {
		t.Error("flag and file together succeeded; want an error")
	}
	if _, err := resolveDerpMapKey("abcd", "", int(pr.Fd()), nil); err == nil {
		t.Error("flag and fd together succeeded; want an error")
	}
	if _, err := resolveDerpMapKey("", keyPath, -1, strings.NewReader("abcd")); err == nil {
		t.Error("file and stdin together succeeded; want an error")
	}

	// A missing file reports the stat error.
	if _, err := resolveDerpMapKey("", filepath.Join(dir, "nope"), -1, nil); err == nil {
		t.Error("missing key file succeeded; want an error")
	}

	// A source that reads empty is an error: the user clearly meant
	// to provide a key.
	empty := filepath.Join(dir, "empty.key")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveDerpMapKey("", empty, -1, nil); err == nil {
		t.Error("empty key file succeeded; want an error")
	}
	if _, err := resolveDerpMapKey("", "", -1, strings.NewReader("  \n")); err == nil {
		t.Error("whitespace-only stdin succeeded; want an error")
	}

	// On Unix, a group- or world-readable key file is rejected, like
	// an unprotected SSH private key.
	if runtime.GOOS != "windows" {
		loose := filepath.Join(dir, "loose.key")
		if err := os.WriteFile(loose, []byte("abcd"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := resolveDerpMapKey("", loose, -1, nil)
		if err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Errorf("world-readable key file: err = %v; want a permissions error", err)
		}
	}
}

func TestResolveDerpMapSource(t *testing.T) {
	payload := []byte(`{"Regions":{}}`)

	// The flag's default URL counts as "not set": only an explicitly
	// different URL conflicts with the fd and stdin forms.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write(payload); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	defer pr.Close()

	gotURL, gotData, err := resolveDerpMapSource(tailcat.DefaultDERPMapURL, -1, nil)
	if err != nil || gotURL != tailcat.DefaultDERPMapURL || gotData != nil {
		t.Errorf("default = (%q, %v, %v); want the default URL, no data", gotURL, gotData, err)
	}

	gotURL, gotData, err = resolveDerpMapSource("https://example.com/dm.json", -1, nil)
	if err != nil || gotURL != "https://example.com/dm.json" || gotData != nil {
		t.Errorf("explicit URL = (%q, %v, %v)", gotURL, gotData, err)
	}

	gotURL, gotData, err = resolveDerpMapSource(tailcat.DefaultDERPMapURL, -1, strings.NewReader(string(payload)))
	if err != nil || gotURL != "" || string(gotData) != string(payload) {
		t.Errorf("stdin = (%q, %q, %v)", gotURL, gotData, err)
	}

	gotURL, gotData, err = resolveDerpMapSource(tailcat.DefaultDERPMapURL, int(pr.Fd()), nil)
	if err != nil || gotURL != "" || string(gotData) != string(payload) {
		t.Errorf("fd = (%q, %q, %v)", gotURL, gotData, err)
	}

	// More than one source is an error.
	if _, _, err := resolveDerpMapSource("https://example.com/dm.json", -1, strings.NewReader("x")); err == nil {
		t.Error("URL and stdin together succeeded; want an error")
	}
	if _, _, err := resolveDerpMapSource("https://example.com/dm.json", int(pr.Fd()), nil); err == nil {
		t.Error("URL and fd together succeeded; want an error")
	}
	if _, _, err := resolveDerpMapSource(tailcat.DefaultDERPMapURL, int(pr.Fd()), strings.NewReader("x")); err == nil {
		t.Error("fd and stdin together succeeded; want an error")
	}

	// An empty read is an error: the user meant to provide a map.
	if _, _, err := resolveDerpMapSource(tailcat.DefaultDERPMapURL, -1, strings.NewReader("  \n")); err == nil {
		t.Error("whitespace-only stdin succeeded; want an error")
	}
}

func TestResolveDerpAuth(t *testing.T) {
	dir := t.TempDir()
	// All secret sources: value, file, descriptor, and stdin. The
	// fd and stdin forms match --derpmap-key-fd/--derpmap-key-stdin.
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pw.WriteString("sec-from-pipe\n"); err != nil {
		t.Fatal(err)
	}
	pw.Close()
	defer pr.Close()
	tokenPath := filepath.Join(dir, "auth-token")
	if err := os.WriteFile(tokenPath, []byte("tok-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(dir, "auth-secret")
	if err := os.WriteFile(secretPath, []byte("sec-456\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := resolveDerpAuth("tok-abc", "", "sec-xyz", "", -1, nil); err == nil {
		t.Error("token and secret together succeeded; want an error")
	}
	// token/token-file are exclusive; secret/secret-file are exclusive.
	if _, _, err := resolveDerpAuth("tok", tokenPath, "", "", -1, nil); err == nil {
		t.Error("token and token-file together succeeded; want an error")
	}
	if _, _, err := resolveDerpAuth("", "", "sec", secretPath, -1, nil); err == nil {
		t.Error("secret and secret-file together succeeded; want an error")
	}
	if _, _, err := resolveDerpAuth("", "", "sec", "", int(pr.Fd()), nil); err == nil {
		t.Error("secret and fd together succeeded; want an error")
	}
	if _, _, err := resolveDerpAuth("", "", "", secretPath, -1, strings.NewReader("x")); err == nil {
		t.Error("file and stdin together succeeded; want an error")
	}
	if _, _, err := resolveDerpAuth("", "", "", "", int(pr.Fd()), strings.NewReader("x")); err == nil {
		t.Error("fd and stdin together succeeded; want an error")
	}
	// The token pair and the secret pair are mutually exclusive.
	if _, _, err := resolveDerpAuth("tok", "", "sec", "", -1, nil); err == nil {
		t.Error("token and secret together succeeded; want an error")
	}
	if _, _, err := resolveDerpAuth("", "", "sec", secretPath, -1, nil); err == nil {
		t.Error("token and secret-file together succeeded; want an error")
	}
	// The fd and stdin forms read and trim like the file form.
	if _, sec, err := resolveDerpAuth("", "", "", "", int(pr.Fd()), nil); err != nil || sec != "sec-from-pipe" {
		t.Errorf("secret-fd = (%q, %v); want sec-from-pipe", sec, err)
	}
	if _, sec, err := resolveDerpAuth("", "", "", "", -1, strings.NewReader("sec-from-stdin\n")); err != nil || sec != "sec-from-stdin" {
		t.Errorf("secret-stdin = (%q, %v); want sec-from-stdin", sec, err)
	}
	if _, _, err := resolveDerpAuth("", "", "", "", -1, strings.NewReader("  \n")); err == nil {
		t.Error("whitespace-only stdin succeeded; want an error")
	}
	// Nothing given means no admission credentials.
	if tok, sec, err := resolveDerpAuth("", "", "", "", -1, nil); err != nil || tok != "" || sec != "" {
		t.Errorf("no source = (%q, %q, %v); want empty", tok, sec, err)
	}
	// A secret file is read and trimmed.
	if _, sec, err := resolveDerpAuth("", "", "", secretPath, -1, nil); err != nil || sec != "sec-456" {
		t.Errorf("secret-file = (%q, %v); want sec-456", sec, err)
	}
	// A missing file reports the error.
	if _, _, err := resolveDerpAuth("", "", "", filepath.Join(dir, "nope"), -1, nil); err == nil {
		t.Error("missing secret file succeeded; want an error")
	}
}
