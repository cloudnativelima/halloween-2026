//go:build ignore

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) != 3 {
		fail(errors.New("usage: decode.go <seed-file> <output-file>"))
	}

	encoded, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		fail(err)
	}
	if len(seed) != 32 {
		fail(errors.New("seed must decode to 32 bytes"))
	}
	if err := os.WriteFile(os.Args[2], seed, 0600); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
