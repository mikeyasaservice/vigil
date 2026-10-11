package main

import (
	"fmt"
	"os"

	"vigil-managed-dedicated-aws/internal/reconciler"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: artifact-digest <source-directory>")
		os.Exit(2)
	}
	digest, err := reconciler.TreeDigest(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "digest artifact: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("approved:sha256:%s\n", digest)
}
