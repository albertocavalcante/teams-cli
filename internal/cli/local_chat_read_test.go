package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalChatReadUsesSDKQueryAndRendersMessages(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1.0/chats/chat-ada-grace/messages" || r.Method != http.MethodGet ||
			r.Header.Get("Authorization") != "Bearer "+testLocalToken {
			t.Errorf("message request = %s %s, authorization = %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		query := r.URL.Query()
		if query.Get("$orderby") != "createdDateTime desc" || query.Get("$top") != "50" || len(query) != 2 {
			t.Errorf("message query = %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"recent","createdDateTime":%q,"lastModifiedDateTime":%q,"from":{"user":{"id":"grace","displayName":"Grace Hopper"}},"body":{"contentType":"text","content":"Hello Ada"}},{"id":"old","createdDateTime":%q,"body":{"contentType":"text","content":"Old note"}}]}`,
			now.Add(-time.Hour).Format(time.RFC3339), now.Add(-time.Hour).Format(time.RFC3339), now.Add(-48*time.Hour).Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")

	out, err := runLocalCLI(t, "--local-profile", profile, "chat", "read", "chat-ada-grace", "--since", "24h", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []messageRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "recent" || rows[0].Sender != "Grace Hopper" || rows[0].Text != "Hello Ada" || !rows[0].Time.Equal(now.Add(-time.Hour)) {
		t.Fatalf("local chat messages = %+v", rows)
	}
	table, err := runLocalCLI(t, "--local-profile", profile, "chat", "read", "chat-ada-grace", "--limit", "1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(table, "Grace Hopper") || !strings.Contains(table, "Hello Ada") || strings.Contains(table, "Old note") || requests.Load() != 2 {
		t.Fatalf("table = %q, requests = %d", table, requests.Load())
	}
}

func TestLocalChatReadModifiedBeforeAndSince(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if query.Get("$orderby") != "lastModifiedDateTime desc" || query.Get("$top") != "50" || len(query) != 3 {
			t.Errorf("modified query = %s", r.URL.RawQuery)
		}
		filter := strings.TrimPrefix(query.Get("$filter"), "lastModifiedDateTime lt ")
		before, err := time.Parse(time.RFC3339, filter)
		if err != nil || before.Before(now.Add(-2*time.Hour-10*time.Second)) || before.After(now.Add(-2*time.Hour+10*time.Second)) {
			t.Errorf("before filter = %q, parse error = %v", query.Get("$filter"), err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"changed","createdDateTime":%q,"lastModifiedDateTime":%q,"body":{"contentType":"text","content":"Changed"}},{"id":"old","createdDateTime":%q,"lastModifiedDateTime":%q,"body":{"contentType":"text","content":"Old"}}]}`,
			now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-3*time.Hour).Format(time.RFC3339),
			now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-5*time.Hour).Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	out, err := runLocalCLI(t, "--local-profile", profile, "chat", "read", "chat-ada-grace", "--order", "modified", "--since", "4h", "--before", "2h", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []messageRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "changed" || !rows[0].ModifiedTime.Equal(now.Add(-3*time.Hour)) {
		t.Fatalf("modified messages = %+v", rows)
	}
}

func TestLocalChatReadRejectsMissingModifiedTimestamp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"value":[{"id":"missing","createdDateTime":%q,"body":{"contentType":"text","content":"Missing modified time"}}]}`, time.Now().UTC().Format(time.RFC3339))
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "chat", "read", "chat-ada-grace", "--order", "modified", "--since", "24h", "--json")
	if err == nil || !strings.Contains(err.Error(), "no timestamp") {
		t.Fatalf("missing timestamp error = %v", err)
	}
}

func TestLocalChatReadDeniesInsufficientGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"error":{"code":"Authorization_RequestDenied","message":"Chat.Read is required"}}`)
	}))
	t.Cleanup(server.Close)
	profile := localTestProfile(t, server.URL+"/v1.0")
	_, err := runLocalCLI(t, "--local-profile", profile, "chat", "read", "chat-ada-grace", "--json")
	if err == nil || !strings.Contains(err.Error(), "Chat.Read") {
		t.Fatalf("insufficient grant error = %v", err)
	}
}

func TestLocalChatReadPaginatesOnlyOnSameOrigin(t *testing.T) {
	t.Run("local continuation", func(t *testing.T) {
		var pages atomic.Int32
		var server *httptest.Server
		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			pages.Add(1)
			if r.URL.Query().Get("$skiptoken") == "page-2" {
				_, _ = fmt.Fprint(w, `{"value":[{"id":"second","createdDateTime":"2026-10-24T09:00:00Z"}]}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"value":[{"id":"first","createdDateTime":"2026-10-24T10:00:00Z"}],"@odata.nextLink":%q}`, server.URL+"/v1.0/chats/chat-ada-grace/messages?$skiptoken=page-2")
		}))
		t.Cleanup(server.Close)
		profile := localTestProfile(t, server.URL+"/v1.0")
		out, err := runLocalCLI(t, "--local-profile", profile, "chat", "read", "chat-ada-grace", "--limit", "0", "--json")
		if err != nil {
			t.Fatal(err)
		}
		var rows []messageRow
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].ID != "first" || rows[1].ID != "second" || pages.Load() != 2 {
			t.Fatalf("paged messages = %+v, requests = %d", rows, pages.Load())
		}
	})

	t.Run("remote continuation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"value":[{"id":"first","createdDateTime":"2026-10-24T10:00:00Z"}],"@odata.nextLink":"http://example.invalid/v1.0/chats/chat-ada-grace/messages?$skiptoken=page-2"}`)
		}))
		t.Cleanup(server.Close)
		profile := localTestProfile(t, server.URL+"/v1.0")
		_, err := runLocalCLI(t, "--local-profile", profile, "chat", "read", "chat-ada-grace", "--limit", "0", "--json")
		if err == nil || !strings.Contains(err.Error(), "untrusted request host") {
			t.Fatalf("remote continuation error = %v", err)
		}
	})
}
