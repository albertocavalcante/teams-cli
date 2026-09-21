// Command teams is a command-line client for Microsoft Teams.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/albertocavalcante/teams-cli/internal/cli"
)

func main() {
	// run owns the deferred cleanup; os.Exit here would skip it.
	os.Exit(run())
}

func run() int {
	// Ctrl-C has to cancel the in-flight Graph request, not just kill the
	// process, so a login callback server or a paging loop unwinds cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.NewRootCommand().ExecuteContext(ctx); err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		return 1
	}
	return 0
}
