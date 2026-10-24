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
	"slices"
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
		{[]string{"--local-profile", profile, "chat", "send", "chat-1"}, "currently supports only"},
		{[]string{"--local-profile", profile, "channel", "read", "team-1", "channel-1"}, "currently supports only"},
		{[]string{"--local-profile", profile, "teams"}, "currently supports only"},
		{[]string{"--local-profile", profile, "chat", "read", "chat-1", "--authority", "https://login.microsoftonline.com/common"}, "cannot be combined"},
		{[]string{"--local-profile", profile, "chats", "--authority", "https://login.microsoftonline.com/common"}, "cannot be combined"},
		{[]string{"--local-profile", profile, "whoami", "--authority", "https://login.microsoftonline.com/common"}, "cannot be combined"},
		{[]string{"--local-profile", profile, "whoami", "--token-cache-dir", t.TempDir()}, "cannot be combined"},
	} {
		_, err := runLocalCLI(t, test.args...)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Fatalf("%v: err = %v, want %q", test.args, err, test.want)
		}
	}
}

func TestLocalChatsUsesSDKQueryAndRendersActorView(t *testing.T) {
	var seen atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testLocalToken {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/me":
			if r.Method != http.MethodGet || r.URL.Query().Get("$select") != "id" {
				t.Errorf("self request = %s %s", r.Method, r.URL.String())
			}
			_, _ = fmt.Fprint(w, `{"id":"ada"}`)
		case "/v1.0/chats":
			seen.Add(1)
			query := r.URL.Query()
			if r.Method != http.MethodGet || query.Get("$expand") != "members,lastMessagePreview" || query.Get("$orderby") != "lastMessagePreview/createdDateTime desc" || query.Get("$top") != "50" || len(query) != 3 {
				t.Errorf("chat request = %s %s", r.Method, r.URL.String())
			}
			_, _ = fmt.Fprint(w, `{"value":[{"id":"chat-unread","chatType":"oneOnOne","topic":null,"members":[{"userId":"ada","displayName":"Ada"},{"userId":"grace","displayName":"Grace"}],"viewpoint":{"lastMessageReadDateTime":"2026-01-01T00:00:00Z"},"lastMessagePreview":{"createdDateTime":"2026-01-02T00:00:00Z","body":{"contentType":"text","content":"Hi Ada"}}},{"id":"chat-read","chatType":"group","topic":"Planning","viewpoint":{"lastMessageReadDateTime":"2026-01-03T00:00:00Z"},"lastMessagePreview":{"createdDateTime":"2026-01-02T00:00:00Z","body":{"contentType":"text","content":"Done"}}}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")

	out, err := runLocalCLI(t, "--local-profile", profile, "chats", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []chatRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].ID != "chat-unread" || rows[0].Name != "Grace" || rows[0].Preview != "Hi Ada" || rows[0].Unread == nil || !*rows[0].Unread || rows[1].Name != "Planning" || rows[1].Unread == nil || *rows[1].Unread {
		t.Fatalf("chats = %+v", rows)
	}
	out, err = runLocalCLI(t, "--local-profile", profile, "chats", "--unread", "--json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "chat-unread" {
		t.Fatalf("unread chats = %+v", rows)
	}
	if seen.Load() != 2 {
		t.Fatalf("chat listing requests = %d, want 2", seen.Load())
	}
}

func TestLocalChatsDeniedWithoutGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/me" {
			_, _ = fmt.Fprint(w, `{"id":"ada"}`)
			return
		}
		if r.URL.Path != "/v1.0/chats" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":"Local365_Forbidden","message":"Chat.Read is required"}}`)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "chats")
	if err == nil || !strings.Contains(err.Error(), "Chat.Read") {
		t.Fatalf("chats error = %v, want denied grant", err)
	}
}

func TestLocalChatsRejectsRemoteNextLink(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/me" {
			_, _ = fmt.Fprint(w, `{"id":"ada"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"value":[{"id":"chat-1","chatType":"group","topic":"Planning"}],"@odata.nextLink":"http://example.invalid/v1.0/chats?page=2"}`)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "chats", "--all")
	if err == nil || !strings.Contains(err.Error(), "untrusted request host") {
		t.Fatalf("chats error = %v, want remote continuation refused", err)
	}
}

func TestLocalChatsFollowsLocalNextLink(t *testing.T) {
	var pages atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1.0/me" {
			_, _ = fmt.Fprint(w, `{"id":"ada"}`)
			return
		}
		if r.URL.Path != "/v1.0/chats" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		pages.Add(1)
		if r.URL.Query().Get("$skiptoken") == "page-2" {
			_, _ = fmt.Fprint(w, `{"value":[{"id":"chat-2","chatType":"group","topic":"Second"}]}`)
			return
		}
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"chat-1","chatType":"group","topic":"First"}],"@odata.nextLink":%q}`, server.URL+"/v1.0/chats?$skiptoken=page-2")
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "chats", "--all", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []chatRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Name != "First" || rows[1].Name != "Second" || pages.Load() != 2 {
		t.Fatalf("paged chats = %+v; requests = %d", rows, pages.Load())
	}
}

func TestLocalScopesUsesSessionGrants(t *testing.T) {
	var seen atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.URL.Path != "/_local365/session" || r.Header.Get("Authorization") != "Bearer "+testLocalToken {
			t.Errorf("request = %s %s, authorization = %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"ada","expiresOn":%q,"grantedScopes":["User.Read","Chat.ReadBasic"]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "scopes", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Mode          string   `json:"mode"`
		GrantedScopes []string `json:"grantedScopes"`
		Capabilities  []struct {
			Name             string `json:"capability"`
			Permitted        bool   `json:"permitted"`
			AdminOnly        bool   `json:"adminOnly"`
			AvailableLocally *bool  `json:"availableLocally"`
		} `json:"capabilities"`
		SignInCommand  string `json:"signInCommand"`
		LocalGrantHint string `json:"localGrantHint"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("output %q: %v", out, err)
	}
	if report.Mode != "local" || len(report.GrantedScopes) != 2 || report.SignInCommand != "" || report.LocalGrantHint == "" {
		t.Fatalf("report = %+v", report)
	}
	status := map[string]bool{}
	available := map[string]bool{}
	for _, capability := range report.Capabilities {
		status[capability.Name] = capability.Permitted
		if capability.AvailableLocally == nil {
			t.Fatalf("local availability missing for %q", capability.Name)
		}
		available[capability.Name] = *capability.AvailableLocally
		if capability.AdminOnly {
			t.Fatalf("local capability %q incorrectly needs Microsoft admin consent", capability.Name)
		}
	}
	if !status[string(teams.ReadIdentity)] || status[string(teams.ListChats)] || status[string(teams.ReadChatMessages)] || status[string(teams.SendChatMessage)] {
		t.Fatalf("capability statuses = %v", status)
	}
	if !available[string(teams.ReadIdentity)] || !available[string(teams.ListChats)] || !available[string(teams.ReadChatMessages)] || available[string(teams.SendChatMessage)] {
		t.Fatalf("local availability = %v", available)
	}
	if seen.Load() != 1 {
		t.Fatalf("requests = %d, want one session request", seen.Load())
	}
}

func TestLocalScopesWantGrantedAndAvailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"grace","expiresOn":%q,"grantedScopes":["User.Read","chat.read"]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "scopes", "--want", string(teams.ListChats), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		SignInCommand  string `json:"signInCommand"`
		LocalGrantHint string `json:"localGrantHint"`
		Capabilities   []struct {
			Name             string `json:"capability"`
			Permitted        bool   `json:"permitted"`
			AvailableLocally *bool  `json:"availableLocally"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.SignInCommand != "" || report.LocalGrantHint != "" {
		t.Fatalf("granted capability should have no grant advice: %+v", report)
	}
	seen := map[string]bool{}
	for _, capability := range report.Capabilities {
		if capability.Name == string(teams.ListChats) || capability.Name == string(teams.ReadChatMessages) {
			if !capability.Permitted || capability.AvailableLocally == nil || !*capability.AvailableLocally {
				t.Fatalf("chat capability = %+v, want granted and available locally", capability)
			}
			seen[capability.Name] = true
		}
	}
	if !seen[string(teams.ListChats)] || !seen[string(teams.ReadChatMessages)] {
		t.Fatalf("missing local chat capabilities: %v", seen)
	}
}

func TestLocalScopesBasicChatGrantDoesNotClaimRunnableChats(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"ada","expiresOn":%q,"grantedScopes":["User.Read","Chat.ReadBasic"]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "scopes", "--want", string(teams.ListChats), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		LocalGrantHint string `json:"localGrantHint"`
		Capabilities   []struct {
			Name             string   `json:"capability"`
			Permitted        bool     `json:"permitted"`
			AvailableLocally *bool    `json:"availableLocally"`
			Accepts          []string `json:"satisfiedBy"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.LocalGrantHint == "" {
		t.Fatalf("missing local grant hint: %+v", report)
	}
	for _, capability := range report.Capabilities {
		if capability.Name == string(teams.ListChats) {
			if capability.Permitted || capability.AvailableLocally == nil || !*capability.AvailableLocally || slices.Contains(capability.Accepts, "Chat.ReadBasic") || !slices.Contains(capability.Accepts, "Chat.Read") {
				t.Fatalf("basic-only list chats report = %+v", capability)
			}
			return
		}
	}
	t.Fatal("list chats missing from capability report")
}

func TestLocalReadIdentityMatchesGraphMeWithDirectoryReadAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1.0/me":
			_, _ = fmt.Fprint(w, `{"id":"ada","userPrincipalName":"ada@example.test","displayName":"Ada"}`)
		case "/_local365/session":
			_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"ada","expiresOn":%q,"grantedScopes":["Directory.Read.All"]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	if _, err := runLocalCLI(t, "--local-profile", profile, "whoami", "--json"); err != nil {
		t.Fatalf("whoami with Directory.Read.All: %v", err)
	}
	out, err := runLocalCLI(t, "--local-profile", profile, "scopes", "--want", string(teams.ReadIdentity), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		LocalGrantHint string `json:"localGrantHint"`
		Capabilities   []struct {
			Name             string   `json:"capability"`
			Permitted        bool     `json:"permitted"`
			Accepts          []string `json:"satisfiedBy"`
			AvailableLocally *bool    `json:"availableLocally"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	if report.LocalGrantHint != "" {
		t.Fatalf("grant hint = %q, want none", report.LocalGrantHint)
	}
	for _, capability := range report.Capabilities {
		if capability.Name == string(teams.ReadIdentity) {
			if !capability.Permitted || capability.AvailableLocally == nil || !*capability.AvailableLocally || !slices.Contains(capability.Accepts, "Directory.Read.All") {
				t.Fatalf("read identity = %+v, want granted, available, and Directory.Read.All accepted", capability)
			}
			return
		}
	}
	t.Fatal("read identity missing from local capability report")
}

func TestLocalScopesWantExplainsSeedGrantsWithoutMicrosoftLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"ada","expiresOn":%q,"grantedScopes":["User.Read"]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "scopes", "--want", string(teams.SendChatMessage))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "ChatMessage.Send") || !strings.Contains(out, "Local365 seed") || strings.Contains(out, "teams login") {
		t.Fatalf("local scopes output = %q", out)
	}
}

func TestLocalScopesRejectsInvalidWantAndSessionFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "scopes")
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("err = %v, want session unauthorized", err)
	}
	_, err = runLocalCLI(t, "--local-profile", profile, "scopes", "--scopes", "Chat.Read")
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Fatalf("err = %v, want real-auth flag rejection", err)
	}
	valid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"tenantId":"tenant","userId":"ada","expiresOn":%q,"grantedScopes":["User.Read"]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(valid.Close)
	profile = localTestProfile(t, valid.URL+"/v1.0")
	_, err = runLocalCLI(t, "--local-profile", profile, "scopes", "--want", "not a capability")
	if err == nil || !strings.Contains(err.Error(), "unknown capability") {
		t.Fatalf("err = %v, want invalid capability error", err)
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
