package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	msauth "github.com/albertocavalcante/msauth-go"
	teams "github.com/albertocavalcante/teams-go"
)

var testLocalToken = "l365_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x7f}, 32))

func localTestProfile(t *testing.T, graphURL string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenPath, []byte(testLocalToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	profilePath := filepath.Join(dir, "profile.json")
	profile := map[string]any{
		"schemaVersion": 1,
		"graphBaseURL":  graphURL,
		"tokenFile":     tokenPath,
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profilePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return profilePath
}

func runLocalCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	a := &app{
		newClients: func(context.Context, *app, []string) (*msauth.Authenticator, *teams.Client, error) {
			panic("local command entered Microsoft authentication")
		},
		grantedScopes: func(context.Context, *app) ([]string, error) {
			panic("local command entered Microsoft scope lookup")
		},
	}
	root := newRootCommand(a)
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

func TestLocalWhoamiUsesValidatedServerIdentity(t *testing.T) {
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	var seen atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testLocalToken {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		seen.Add(1)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/me":
			_, _ = fmt.Fprint(w, `{"id":"ada","userPrincipalName":"ada@example.test","displayName":"Ada"}`)
		case "/_local365/session":
			_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"ada","expiresOn":%q,"grantedScopes":["User.Read"]}`, expiry.Format(time.RFC3339))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "whoami", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Mode          string   `json:"mode"`
		UserID        string   `json:"userId"`
		TenantID      string   `json:"tenantId"`
		Username      string   `json:"username"`
		GrantedScopes []string `json:"grantedScopes"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if got.Mode != "local" || got.UserID != "ada" || got.TenantID != "tenant" || got.Username != "ada@example.test" || len(got.GrantedScopes) != 1 || got.GrantedScopes[0] != "User.Read" {
		t.Fatalf("whoami = %+v", got)
	}
	if seen.Load() != 2 {
		t.Fatalf("requests = %d, want 2", seen.Load())
	}
}

func TestLocalWhoamiRejectsSessionActorMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/me" {
			_, _ = fmt.Fprint(w, `{"id":"ada"}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"grace","expiresOn":%q,"grantedScopes":["User.Read"]}`, time.Now().Add(time.Hour).Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("err = %v, want identity mismatch", err)
	}
}

func TestLocalProfileFailsClosedForOtherCommandsAndAuthFlags(t *testing.T) {
	profile := localTestProfile(t, "http://127.0.0.1:9/v1.0")
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"--local-profile", profile, "chats"}, "currently supports only whoami"},
		{[]string{"--local-profile", profile, "scopes"}, "currently supports only whoami"},
		{[]string{"--local-profile", profile, "whoami", "--authority", "https://login.microsoftonline.com/common"}, "cannot be combined"},
		{[]string{"--local-profile", profile, "whoami", "--token-cache-dir", t.TempDir()}, "cannot be combined"},
	} {
		_, err := runLocalCLI(t, test.args...)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%v: err = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestLocalWhoamiRejectsRedirectAndNonLoopbackProfile(t *testing.T) {
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirected.Add(1)
	}))
	t.Cleanup(other.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || redirected.Load() != 0 {
		t.Fatalf("err = %v, redirected requests = %d", err, redirected.Load())
	}
	profile = localTestProfile(t, "http://localhost:1234/v1.0")
	_, err = runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("err = %v, want loopback rejection", err)
	}
}

func TestLocalProfileRejectsEditableIdentityAndExposedToken(t *testing.T) {
	profile := localTestProfile(t, "http://127.0.0.1:9/v1.0")
	data, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["userId"] = "somebody-else"
	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("err = %v, want unknown identity field", err)
	}

	delete(doc, "userId")
	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tokenFile := doc["tokenFile"].(string)
	if err := os.Chmod(tokenFile, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "readable only by its owner") {
		t.Fatalf("err = %v, want token permission error", err)
	}
}

func TestLocalProfileRequiresPrivateSharedDirectory(t *testing.T) {
	profile := localTestProfile(t, "http://127.0.0.1:9/v1.0")
	otherToken := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(otherToken, []byte("other-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	doc["tokenFile"] = otherToken
	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "same private directory") {
		t.Fatalf("err = %v, want directory mismatch", err)
	}

	doc["tokenFile"] = filepath.Join(filepath.Dir(profile), "nested") + "/../token"
	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "canonical path") {
		t.Fatalf("err = %v, want non-canonical path rejection", err)
	}

	doc["tokenFile"] = filepath.Join(filepath.Dir(profile), "token")
	data, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(profile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(profile), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("err = %v, want private directory error", err)
	}
}

func TestLocalProfileRejectsSymlinkedTokenFile(t *testing.T) {
	profile := localTestProfile(t, "http://127.0.0.1:9/v1.0")
	tokenFile := filepath.Join(filepath.Dir(profile), "token")
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(profile, tokenFile); err != nil {
		t.Fatal(err)
	}
	_, err := runLocalCLI(t, "--local-profile", profile, "whoami")
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("err = %v, want symlink rejection", err)
	}
}

func TestLocalProfileRejectsNonLocalTokenBeforeNetwork(t *testing.T) {
	profile := localTestProfile(t, "http://127.0.0.1:9/v1.0")
	tokenFile := filepath.Join(filepath.Dir(profile), "token")
	for _, token := range []string{
		"eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLm1pY3Jvc29mdC5jb20ifQ.signature",
		"l365_too-short",
		"l365_" + strings.Repeat("A", 42) + "!",
	} {
		if err := os.WriteFile(tokenFile, []byte(token), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runLocalCLI(t, "--local-profile", profile, "whoami")
		if err == nil || !strings.Contains(err.Error(), "Local365 token") {
			t.Fatalf("token %q: err = %v, want local-token rejection", token, err)
		}
	}
}

func TestLocalTransportCannotDialAnotherHostOrPort(t *testing.T) {
	base, err := url.Parse("http://127.0.0.1:12345/v1.0")
	if err != nil {
		t.Fatal(err)
	}
	client := localHTTPClient(base)
	for _, target := range []string{"http://example.invalid/", "http://127.0.0.1:12346/"} {
		request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if response != nil {
			response.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "refused dial") {
			t.Fatalf("target %s: err = %v, want refused dial", target, err)
		}
	}
}
