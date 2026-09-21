package cli

import (
	"errors"
	"fmt"
	"io"
	"os"

	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

// composeFlags are the body sources shared by every command that posts a
// message: chat send, channel send, and channel reply.
type composeFlags struct {
	body     string
	bodyFile string
	html     bool
}

// content resolves the body from --body, --body-file, or stdin. Exactly one
// source is allowed, so an accidental combination fails loudly rather than
// silently picking one.
func (f composeFlags) content(stdin io.Reader) (string, error) {
	sources := 0
	if f.body != "" {
		sources++
	}
	if f.bodyFile != "" {
		sources++
	}
	if sources > 1 {
		return "", errors.New("use only one of --body or --body-file")
	}
	switch {
	case f.body != "":
		return f.body, nil
	case f.bodyFile == "-":
		content, err := io.ReadAll(stdin)
		if err != nil {
			return "", fmt.Errorf("read body from stdin: %w", err)
		}
		return string(content), nil
	case f.bodyFile != "":
		content, err := os.ReadFile(f.bodyFile)
		if err != nil {
			return "", fmt.Errorf("read body file: %w", err)
		}
		return string(content), nil
	default:
		return "", nil
	}
}

// itemBody resolves the body and wraps it as the SDK expects, or returns nil
// when nothing was given -- leaving the caller to decide whether an empty
// body is an error.
func (f composeFlags) itemBody(stdin io.Reader) (*teams.ItemBody, error) {
	content, err := f.content(stdin)
	if err != nil {
		return nil, err
	}
	if content == "" {
		return nil, nil
	}
	if f.html {
		return teams.HTMLBody(content), nil
	}
	return teams.TextBody(content), nil
}

func (f *composeFlags) register(cmd *cobra.Command) {
	flags := cmd.Flags()
	flags.StringVar(&f.body, "body", "", "message body text")
	flags.StringVar(&f.bodyFile, "body-file", "", "read the body from a file, or - for stdin")
	flags.BoolVar(&f.html, "html", false, "treat the body as HTML instead of plain text")
}
