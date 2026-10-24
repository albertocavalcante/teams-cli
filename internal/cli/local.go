package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	msgraph "github.com/albertocavalcante/msgraph-go"
	"github.com/spf13/cobra"
)

const (
	maxLocalProfileBytes = 8192
	maxLocalTokenBytes   = 4096
	maxLocalSessionBytes = 16384
)

// localProfile contains connection details only. The server-side token
// session, never an editable profile field, determines the acting identity.
type localProfile struct {
	SchemaVersion int    `json:"schemaVersion"`
	GraphBaseURL  string `json:"graphBaseURL"`
	TokenFile     string `json:"tokenFile"`
}

type localSession struct {
	TenantID      string    `json:"tenantId"`
	UserID        string    `json:"userId"`
	ExpiresOn     time.Time `json:"expiresOn"`
	GrantedScopes []string  `json:"grantedScopes"`
}

type localMe struct {
	ID                string `json:"id"`
	UserPrincipalName string `json:"userPrincipalName"`
	DisplayName       string `json:"displayName"`
}

// localWhoamiResult keeps local actor IDs distinct from Microsoft's home
// account ID, which does not exist for a synthetic Local365 user.
type localWhoamiResult struct {
	Mode          string    `json:"mode"`
	Username      string    `json:"username"`
	DisplayName   string    `json:"displayName,omitempty"`
	UserID        string    `json:"userId"`
	TenantID      string    `json:"tenantId"`
	ExpiresOn     time.Time `json:"tokenExpiresOn"`
	GrantedScopes []string  `json:"grantedScopes"`
}

// validateLocalCommand runs before a local command can reach any auth factory.
// Until each later command has its own local path, an explicit refusal is
// safer than accidentally using a cached Microsoft token.
func validateLocalCommand(cmd *cobra.Command) error {
	for _, name := range []string{"scopes", "client-id", "authority", "token-cache-dir"} {
		if flag := cmd.Root().PersistentFlags().Lookup(name); flag != nil && flag.Changed {
			return fmt.Errorf("--local-profile cannot be combined with --%s", name)
		}
	}
	if cmd.Name() != "whoami" {
		return fmt.Errorf("local profile currently supports only whoami; %q is not available locally yet", cmd.CommandPath())
	}
	return nil
}

func readPrivateFile(path string, limit int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symlink is not allowed")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, opened) {
		return nil, errors.New("private file changed while opening")
	}
	if !opened.Mode().IsRegular() || opened.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("file must be regular and readable only by its owner")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 || !os.SameFile(opened, after) {
		return nil, errors.New("private file changed while reading")
	}
	return data, nil
}

func loadLocalProfile(path string) (localProfile, *url.URL, string, error) {
	profilePath, err := filepath.Abs(path)
	if err != nil {
		return localProfile{}, nil, "", fmt.Errorf("resolve local profile: %w", err)
	}
	dir := filepath.Dir(profilePath)
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return localProfile{}, nil, "", fmt.Errorf("inspect local profile directory: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o700 {
		return localProfile{}, nil, "", errors.New("local profile directory must be a private 0700 directory")
	}
	data, err := readPrivateFile(profilePath, maxLocalProfileBytes)
	if err != nil {
		return localProfile{}, nil, "", fmt.Errorf("read local profile: %w", err)
	}
	var profile localProfile
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&profile); err != nil {
		return localProfile{}, nil, "", fmt.Errorf("decode local profile: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return localProfile{}, nil, "", errors.New("local profile contains trailing JSON")
	}
	if profile.SchemaVersion != 1 {
		return localProfile{}, nil, "", fmt.Errorf("unsupported local profile schema version %d", profile.SchemaVersion)
	}
	base, err := url.Parse(profile.GraphBaseURL)
	if err != nil || base.Scheme != "http" || base.Hostname() != "127.0.0.1" || base.EscapedPath() != "/v1.0" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return localProfile{}, nil, "", errors.New("local graphBaseURL must be http://127.0.0.1:<port>/v1.0")
	}
	port, err := strconv.Atoi(base.Port())
	if err != nil || port < 1 || port > 65535 {
		return localProfile{}, nil, "", errors.New("local graphBaseURL requires a valid port")
	}
	if !filepath.IsAbs(profile.TokenFile) {
		return localProfile{}, nil, "", errors.New("local tokenFile must be an absolute path")
	}
	if profile.TokenFile != filepath.Clean(profile.TokenFile) {
		return localProfile{}, nil, "", errors.New("local tokenFile must use a canonical path")
	}
	if filepath.Dir(filepath.Clean(profile.TokenFile)) != dir || filepath.Clean(profile.TokenFile) == profilePath {
		return localProfile{}, nil, "", errors.New("local tokenFile must be a separate file in the same private directory as the profile")
	}
	tokenBytes, err := readPrivateFile(profile.TokenFile, maxLocalTokenBytes)
	if err != nil {
		return localProfile{}, nil, "", fmt.Errorf("read local token: %w", err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return localProfile{}, nil, "", errors.New("local token file contains no valid token")
	}
	encoded, ok := strings.CutPrefix(token, "l365_")
	if !ok {
		return localProfile{}, nil, "", errors.New("local token file must contain a Local365 token")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return localProfile{}, nil, "", errors.New("local token file must contain a Local365 token with 32 base64url bytes")
	}
	finalDirInfo, err := os.Lstat(dir)
	if err != nil || !finalDirInfo.IsDir() || finalDirInfo.Mode().Perm() != 0o700 || !os.SameFile(dirInfo, finalDirInfo) {
		return localProfile{}, nil, "", errors.New("local profile directory changed while reading")
	}
	return profile, base, token, nil
}

// localHTTPClient cannot proxy, redirect, or dial outside this profile's
// literal loopback address and port, even if a local service sends a link or
// redirect to a different host.
func localHTTPClient(base *url.URL) *http.Client {
	address := base.Host
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout: 60 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if network != "tcp" || addr != address {
					return nil, fmt.Errorf("local profile refused dial to %q", addr)
				}
				return dialer.DialContext(ctx, network, addr)
			},
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 10 * time.Second,
		},
	}
}

func getLocalSession(ctx context.Context, client *http.Client, base *url.URL, token string) (localSession, error) {
	endpoint := *base
	endpoint.Path = "/_local365/session"
	endpoint.RawPath = ""
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return localSession{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return localSession{}, fmt.Errorf("local session: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return localSession{}, fmt.Errorf("local session returned HTTP %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxLocalSessionBytes+1))
	if err != nil {
		return localSession{}, fmt.Errorf("read local session: %w", err)
	}
	if len(data) > maxLocalSessionBytes {
		return localSession{}, errors.New("local session exceeds response limit")
	}
	var session localSession
	if err := json.Unmarshal(data, &session); err != nil {
		return localSession{}, fmt.Errorf("decode local session: %w", err)
	}
	if session.TenantID == "" || session.UserID == "" || session.ExpiresOn.IsZero() || !session.ExpiresOn.After(time.Now()) {
		return localSession{}, errors.New("local session has missing or expired identity")
	}
	return session, nil
}

func (a *app) localWhoami(ctx context.Context) (localWhoamiResult, error) {
	_, base, token, err := loadLocalProfile(a.localProfile)
	if err != nil {
		return localWhoamiResult{}, err
	}
	httpClient := localHTTPClient(base)
	graph, err := msgraph.New(msgraph.TokenSourceFunc(func(context.Context) (string, error) {
		return token, nil
	}), msgraph.WithBaseURL(base.String()), msgraph.WithHTTPClient(httpClient))
	if err != nil {
		return localWhoamiResult{}, fmt.Errorf("configure local Graph client: %w", err)
	}
	var me localMe
	if _, err := graph.Get(ctx, "/me", msgraph.Params{}, &me); err != nil {
		return localWhoamiResult{}, fmt.Errorf("local whoami: %w", err)
	}
	if me.ID == "" {
		return localWhoamiResult{}, errors.New("local /me returned no user ID")
	}
	session, err := getLocalSession(ctx, httpClient, base, token)
	if err != nil {
		return localWhoamiResult{}, err
	}
	if me.ID != session.UserID {
		return localWhoamiResult{}, errors.New("local identity mismatch between /me and token session")
	}
	username := me.UserPrincipalName
	if username == "" {
		username = me.DisplayName
	}
	if username == "" {
		username = me.ID
	}
	return localWhoamiResult{
		Mode:          "local",
		Username:      username,
		DisplayName:   me.DisplayName,
		UserID:        me.ID,
		TenantID:      session.TenantID,
		ExpiresOn:     session.ExpiresOn,
		GrantedScopes: session.GrantedScopes,
	}, nil
}
