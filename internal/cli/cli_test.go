package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	msauth "github.com/albertocavalcante/msauth-go"
	msgraph "github.com/albertocavalcante/msgraph-go"
	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

// capture is one request the fake server saw.
type capture struct {
	Method string
	Path   string
	Body   []byte
}

// runCLI executes the command tree against a fake Graph server, faking only
// authentication -- everything below the CLI, including the real msgraph-go
// and teams-go clients, runs its production code path against httptest.
// It returns stdout, stderr, the requests the server saw, and the command
// error.
func runCLI(t *testing.T, handler func(*capture) (int, string), args ...string) (stdout, stderr string, seen []capture, err error) {
	t.Helper()

	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		record := capture{Method: r.Method, Path: r.URL.EscapedPath(), Body: body}
		mu.Lock()
		seen = append(seen, record)
		mu.Unlock()

		status, payload := handler(&record)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if payload != "" {
			_, _ = io.WriteString(w, payload)
		}
	}))
	t.Cleanup(server.Close)

	testApp := &app{
		newClients: fakeClients(server.URL),
		// The sign-in the CLI performs by default, so a capability check in
		// tests describes a realistic grant rather than an empty one.
		grantedScopes: func(context.Context, *app) ([]string, error) {
			return append([]string(nil), defaultScopes...), nil
		},
	}
	root := newRootCommand(testApp)

	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), seen, err
}

// fakeClients builds a real msgraph-go and teams-go client pointed at the
// fake server, skipping only authentication. Everything below the CLI is the
// production code path.
func fakeClients(baseURL string) func(context.Context, *app, []string) (*msauth.Authenticator, *teams.Client, error) {
	return func(_ context.Context, _ *app, _ []string) (*msauth.Authenticator, *teams.Client, error) {
		graph, err := msgraph.New(
			msgraph.TokenSourceFunc(func(context.Context) (string, error) { return "test-token", nil }),
			msgraph.WithBaseURL(baseURL),
		)
		if err != nil {
			return nil, nil, err
		}
		client, err := teams.New(graph)
		if err != nil {
			return nil, nil, err
		}
		// No authenticator: clientsFor treats a nil authenticator as "nothing
		// to check a token against" and returns the client directly, which is
		// what lets these tests run with no real sign-in.
		return nil, client, nil
	}
}

func nothingHandler(*capture) (int, string) { return http.StatusOK, `{}` }

// Every runnable command should carry an example; they are the docs people
// actually read, and the ones a caller pastes and edits.
func TestEveryCommandHasAnExample(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.Runnable() && cmd.Example == "" && cmd.Name() != "completion" && cmd.Name() != "help" {
			t.Errorf("command %q has no Example", cmd.CommandPath())
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(NewRootCommand())
}

// A nil slice must marshal as [], or `jq '.[]'` fails outright on null
// rather than yielding nothing.
func TestEmptyJSONIsAListNotNull(t *testing.T) {
	var buf bytes.Buffer
	var rows []chatRow
	if err := writeJSON(&buf, rows); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(buf.String()); got != "[]" {
		t.Fatalf("writeJSON(nil slice) = %q, want []", got)
	}
}

// --dry-run must reach the server zero times, for a command that changes a
// chat.
func TestDryRunMakesNoRequests(t *testing.T) {
	stdout, _, seen, err := runCLI(t, func(*capture) (int, string) {
		t.Error("a dry run reached the server")
		return http.StatusOK, `{}`
	}, "chat", "rm", "19:abc@thread.v2", "1622547684000", "--dry-run")
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Fatalf("a dry run made %d requests", len(seen))
	}
	if !strings.HasPrefix(stdout, "would ") {
		t.Fatalf("stdout = %q, want a description starting with \"would \"", stdout)
	}
}

// The previous test is not vacuous: the same command, without --dry-run,
// actually reaches the server.
func TestWithoutDryRunTheCommandsActuallyRun(t *testing.T) {
	_, _, seen, err := runCLI(t, func(*capture) (int, string) {
		return http.StatusOK, `{}`
	}, "chat", "rm", "19:abc@thread.v2", "1622547684000")
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatal("the command made no requests at all")
	}
	if !strings.HasSuffix(seen[0].Path, "/softDelete") {
		t.Fatalf("path = %q, want the softDelete endpoint", seen[0].Path)
	}
}

// The error for a capability only a tenant administrator can grant must
// never suggest signing in again: no consent screen a signed-in user sees
// ever offers Team.ReadBasic.All, so that advice would send someone in a
// loop against a screen that never changes.
func TestAdminOnlyCapabilityDoesNotSuggestSigningInAgain(t *testing.T) {
	_, _, seen, err := runCLI(t, nothingHandler, "teams")
	if err == nil {
		t.Fatal("expected an error: the default scopes hold no team-listing permission")
	}
	if strings.Contains(strings.ToLower(err.Error()), "login") {
		t.Fatalf("admin-only error suggested signing in again: %v", err)
	}
	if len(seen) != 0 {
		t.Fatal("a capability known to be missing before any request still reached the server")
	}
}

func TestTruncateIsRuneAware(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		value  string
		maxLen int
		want   string
	}{
		{"exactly at the limit", "abcde", 5, "abcde"},
		{"one under", "abcd", 5, "abcd"},
		{"one over", "abcdef", 5, "ab..."},
		{"empty", "", 5, ""},
		{"no room for an ellipsis", "abcdef", 3, "abc"},
		{"zero length", "abcdef", 0, ""},
		{"negative length", "abcdef", -1, ""},
		{"newlines become spaces", "a\nb", 10, "a b"},
		// Multi-byte runes: truncating by bytes would split a character.
		{"multi-byte runes, under the limit", "héllo", 5, "héllo"},
		{"multi-byte runes, over the limit", "héllo wörld", 7, "héll..."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.value, tc.maxLen)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.value, tc.maxLen, got, tc.want)
			}
			if len([]rune(got)) > max(tc.maxLen, 0) {
				t.Errorf("truncate(%q, %d) = %q, longer than the limit", tc.value, tc.maxLen, got)
			}
		})
	}
}

// FuzzTruncateStaysWithinLimit checks the one thing every caller relies on:
// whatever truncate is given, the result never exceeds the limit asked for,
// and it never panics -- a negative maxLen used to be an unchecked slice
// bound.
func FuzzTruncateStaysWithinLimit(f *testing.F) {
	for _, seed := range []struct {
		value  string
		maxLen int
	}{
		{"hello world", 5},
		{"", 0},
		{"héllo wörld", 3},
		{"a\nb\nc", 4},
		{"x", -1},
		{"", -100},
	} {
		f.Add(seed.value, seed.maxLen)
	}

	f.Fuzz(func(t *testing.T, value string, maxLen int) {
		got := truncate(value, maxLen)
		if maxLen <= 0 {
			if got != "" {
				t.Fatalf("truncate(%q, %d) = %q, want empty for a non-positive limit", value, maxLen, got)
			}
			return
		}
		if n := len([]rune(got)); n > maxLen {
			t.Fatalf("truncate(%q, %d) = %q (%d runes), longer than the limit", value, maxLen, got, n)
		}
		if strings.Contains(got, "\n") {
			t.Fatalf("truncate(%q, %d) = %q, kept a newline", value, maxLen, got)
		}
	})
}

// TestJSONAndTableRenderTheSameRows proves the table and --json outputs come
// from the same row values for chats and messages: whatever a JSON row says,
// the table for the identical fake response has to say too.
func TestJSONAndTableRenderTheSameRows(t *testing.T) {
	t.Run("chats", func(t *testing.T) {
		handler := func(c *capture) (int, string) {
			switch {
			case c.Path == "/me":
				return http.StatusOK, `{"id":"self-1"}`
			case strings.HasPrefix(c.Path, "/chats"):
				return http.StatusOK, `{"value":[{"id":"19:abc@thread.v2","chatType":"group","topic":"Widgets",
					"lastMessagePreview":{"body":{"content":"hello there"}}}]}`
			default:
				return http.StatusOK, `{}`
			}
		}

		jsonOut, _, _, err := runCLI(t, handler, "chats", "--json")
		if err != nil {
			t.Fatal(err)
		}
		var rows []chatRow
		if err := json.Unmarshal([]byte(jsonOut), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(rows))
		}

		tableOut, _, _, err := runCLI(t, handler, "chats")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{rows[0].Name, rows[0].ID, rows[0].Preview} {
			if !strings.Contains(tableOut, want) {
				t.Fatalf("table output missing %q, which the JSON row carried:\n%s", want, tableOut)
			}
		}
	})

	t.Run("messages", func(t *testing.T) {
		handler := func(*capture) (int, string) {
			return http.StatusOK, `{"value":[{"id":"1622547684000","createdDateTime":"2026-01-01T00:00:00Z",
				"from":{"user":{"displayName":"Alberto"}},"body":{"contentType":"text","content":"hi there"}}]}`
		}

		jsonOut, _, _, err := runCLI(t, handler, "chat", "read", "19:abc@thread.v2", "--json")
		if err != nil {
			t.Fatal(err)
		}
		var rows []messageRow
		if err := json.Unmarshal([]byte(jsonOut), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("rows = %d, want 1", len(rows))
		}

		tableOut, _, _, err := runCLI(t, handler, "chat", "read", "19:abc@thread.v2")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{rows[0].Sender, rows[0].Text} {
			if !strings.Contains(tableOut, want) {
				t.Fatalf("table output missing %q, which the JSON row carried:\n%s", want, tableOut)
			}
		}
	})
}

// An empty --authority must become the work/school endpoint: left at
// msauth-go's own default, which targets personal Microsoft accounts, every
// Teams sign-in would fail.
func TestAuthorityDefaultsToOrganizations(t *testing.T) {
	if got := resolveAuthority(""); got != defaultAuthority {
		t.Fatalf("resolveAuthority(\"\") = %q, want %q", got, defaultAuthority)
	}
	const explicit = "https://login.microsoftonline.com/common"
	if got := resolveAuthority(explicit); got != explicit {
		t.Fatalf("resolveAuthority(%q) = %q, want it unchanged", explicit, got)
	}
}

func TestRootHelpListsCommands(t *testing.T) {
	stdout, _, _, err := runCLI(t, nothingHandler, "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"login", "chats", "chat", "search", "presence", "channels"} {
		if !strings.Contains(stdout, name) {
			t.Fatalf("help does not mention %q:\n%s", name, stdout)
		}
	}
}
