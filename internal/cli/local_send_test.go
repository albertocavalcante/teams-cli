package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	teams "github.com/albertocavalcante/teams-go"
)

func TestLocalChatSendUsesLoopbackGraphAndRendersResult(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Method != http.MethodPost || request.URL.EscapedPath() != "/v1.0/chats/chat-1/messages" || request.URL.RawQuery != "" {
			t.Errorf("send request = %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer "+testLocalToken || !strings.HasPrefix(request.Header.Get("Content-Type"), "application/json") {
			t.Errorf("send headers: authorization=%q content-type=%q", request.Header.Get("Authorization"), request.Header.Get("Content-Type"))
		}
		var draft struct {
			Body struct {
				ContentType string `json:"contentType"`
				Content     string `json:"content"`
			} `json:"body"`
		}
		if err := json.NewDecoder(request.Body).Decode(&draft); err != nil {
			t.Errorf("decode draft: %v", err)
		}
		if draft.Body.ContentType != "text" || draft.Body.Content != "Hello Ada" {
			t.Errorf("draft = %+v", draft)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(writer, `{"id":"new-1","chatId":"chat-1","messageType":"message","createdDateTime":"2026-10-24T10:00:00Z","lastModifiedDateTime":"2026-10-24T10:00:00Z","from":{"user":{"id":"ada","displayName":"Ada"}},"body":{"contentType":"text","content":"Hello Ada"}}`)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "--json", "chat", "send", "chat-1", "--body", "Hello Ada")
	if err != nil {
		t.Fatal(err)
	}
	var result actionResult
	if err := json.Unmarshal([]byte(out), &result); err != nil || result.Action != "send" || result.ID != "new-1" {
		t.Fatalf("result %q: %+v, %v", out, result, err)
	}
	if requests.Load() != 1 {
		t.Fatalf("requests = %d, want 1", requests.Load())
	}
}

func TestLocalChatSendBodyFileAndDryRun(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		var draft struct {
			Body struct {
				Content string `json:"content"`
			} `json:"body"`
		}
		if err := json.NewDecoder(request.Body).Decode(&draft); err != nil || draft.Body.Content != "from file" {
			t.Errorf("draft = %+v; err = %v", draft, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(writer, `{"id":"new-2"}`)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	bodyPath := filepath.Join(t.TempDir(), "message.txt")
	if err := os.WriteFile(bodyPath, []byte("from file"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runLocalCLI(t, "--local-profile", profile, "chat", "send", "chat-1", "--body-file", bodyPath)
	if err != nil || !strings.Contains(out, "Sent. Id: new-2") {
		t.Fatalf("text result = %q; err = %v", out, err)
	}
	out, err = runLocalCLI(t, "--local-profile", profile, "chat", "send", "chat-1", "--body", "dry", "--dry-run")
	if err != nil || !strings.HasPrefix(out, "would ") || requests.Load() != 1 {
		t.Fatalf("dry run = %q; err = %v; requests = %d", out, err, requests.Load())
	}
}

func TestLocalChatSendRejectsUnsupportedHTMLBeforeRequest(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "chat", "send", "chat-1", "--body", "<b>hello</b>", "--html")
	if err == nil || !strings.Contains(err.Error(), "HTML") || requests.Load() != 0 {
		t.Fatalf("HTML err = %v; requests = %d", err, requests.Load())
	}
}

func TestLocalChatSendPropagatesScopeDenial(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(writer, `{"error":{"code":"Authorization_RequestDenied","message":"ChatMessage.Send permission is required"}}`)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "chat", "send", "chat-1", "--body", "hello")
	if err == nil || !strings.Contains(err.Error(), "403") || requests.Load() != 1 {
		t.Fatalf("denial err = %v; requests = %d", err, requests.Load())
	}
}

func TestLocalChatSendScopeReportMatchesAvailability(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/_local365/session" {
			t.Errorf("unexpected path %q", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"tenantId":"tenant","userId":"ada","expiresOn":%q,"grantedScopes":["ChatMessage.Send"]}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "scopes", "--want", string(teams.SendChatMessage), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Capabilities []struct {
			Name             string `json:"capability"`
			Permitted        bool   `json:"permitted"`
			AvailableLocally *bool  `json:"availableLocally"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatal(err)
	}
	for _, capability := range report.Capabilities {
		if capability.Name == string(teams.SendChatMessage) {
			if !capability.Permitted || capability.AvailableLocally == nil || !*capability.AvailableLocally {
				t.Fatalf("send capability = %+v", capability)
			}
			return
		}
	}
	t.Fatal("send capability missing from local scopes report")
}

func TestMicrosoftChatSendStillAcceptsHTML(t *testing.T) {
	out, _, seen, err := runCLI(t, func(request *capture) (int, string) {
		if request.Method != http.MethodPost || request.Path != "/chats/chat-1/messages" {
			t.Errorf("request = %+v", request)
		}
		var draft struct {
			Body struct {
				ContentType string `json:"contentType"`
				Content     string `json:"content"`
			} `json:"body"`
		}
		if err := json.Unmarshal(request.Body, &draft); err != nil || draft.Body.ContentType != "html" || draft.Body.Content != "<b>hello</b>" {
			t.Errorf("draft = %+v; err = %v", draft, err)
		}
		return http.StatusCreated, `{"id":"production-1"}`
	}, "chat", "send", "chat-1", "--body", "<b>hello</b>", "--html")
	if err != nil || !strings.Contains(out, "Sent. Id: production-1") || len(seen) != 1 {
		t.Fatalf("production send output = %q; err = %v; requests = %d", out, err, len(seen))
	}
}
