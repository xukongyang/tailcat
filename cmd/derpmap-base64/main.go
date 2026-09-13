// The derpmap-base64 command prints a file (typically a
// derpmap-encrypt output like derpmap.json.enc) as a single-line
// base64 string. By default the line carries the base64: prefix that
// tailcat's --derpmap-url and TAILCAT_DERPMAP_URL accept directly:
//
//	TAILCAT_DERPMAP_URL="$(derpmap-base64 derpmap.json.enc)" tailcat serve exit-node
//
// Usage:
//
//	derpmap-base64 [-raw] <file>
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
)

func main() {
	raw := flag.Bool("raw", false, "print only the base64 payload, without the base64: prefix")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: derpmap-base64 [-raw] <file>")
		os.Exit(2)
	}
	out, err := encodeFile(flag.Arg(0), *raw)
	if err != nil {
		fmt.Fprintln(os.Stderr, "derpmap-base64:", err)
		os.Exit(1)
	}
	fmt.Println(out)
}

// encodeFile returns the contents of path as one line of base64,
// prefixed with "base64:" unless raw is set.
func encodeFile(path string, raw bool) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := base64.StdEncoding.EncodeToString(data)
	if raw {
		return s, nil
	}
	return "base64:" + s, nil
}
