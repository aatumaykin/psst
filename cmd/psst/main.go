package main

import (
	"os"

	"github.com/aatumaykin/psst/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
