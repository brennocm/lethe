// Command lethe is the OpSec leak monitor: CLI, daemon and session agent.
package main

import (
	"os"

	"lethe/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
