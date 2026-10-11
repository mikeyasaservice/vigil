package main

import (
	"fmt"
	"os"

	"vigil-managed-dedicated-aws/internal/spec"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: json-digest <json-file>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read JSON: %v\n", err)
		os.Exit(1)
	}
	digest, err := spec.CanonicalDigest(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "canonicalize JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(digest)
}
