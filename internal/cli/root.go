// Package cli implements the teams command tree.
//
// Commands stay thin: they parse flags, call teams-go, and render. Anything
// that decides what a request means -- a filter, a mention, what "unread"
// means -- belongs in the SDK, not here.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	msauth "github.com/albertocavalcante/msauth-go"
	"github.com/albertocavalcante/msauth-go/cache"
	msgraph "github.com/albertocavalcante/msgraph-go"
	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

// defaultScopes cover the capabilities every command below Team/Channel
// listing needs, and every one of them is user-consentable: a first run
// grants them without a tenant administrator in the loop. Team.ReadBasic.All,
// Channel.ReadBasic.All, ChannelMessage.Read.All, and Presence.Read.All are
// deliberately left out -- see [teams.NeedsAdminConsent] -- because asking
// for a permission a personal consent screen will never offer just fails
// login for no reason.
var defaultScopes = []string{"User.Read", "Chat.ReadWrite", "ChatMessage.Send", "Presence.Read"}

// defaultAuthority is used when --authority is left empty.
//
// msauth-go's own default authority targets personal Microsoft accounts
// only. Every Teams endpoint over Microsoft Graph is documented work-or-school
// only and refuses a personal account outright, so leaving this at the
// msauth-go default would fail every single sign-in this tool ever attempts
// -- and the identity service's error for that case names no cause, so
// nobody signing in for the first time could work out why from the failure
// alone.
const defaultAuthority = "https://login.microsoftonline.com/organizations"

// app holds process-wide options and lazily builds clients, so a command that
// only prints help never touches the keychain.
type app struct {
	scopes    []string
	clientID  string
	authority string
	cacheDir  string
	timeout   time.Duration
	jsonOut   bool
	dryRun    bool

	out io.Writer
	err io.Writer

	// needs is what the running command asked for, so a refusal that never
	// reached [requireAll] -- because the account was not signed in at all,
	// and so nothing was known about its consent -- can still say what was
	// being attempted.
	needs []teams.Capability

	// grantedOnce memoizes the permission lookup for the life of the process.
	// Each call builds an authenticator and reads the token cache, so asking
	// twice in one command costs twice, and several code paths want the
	// answer.
	grantedOnce sync.Once
	grantedHeld []string
	grantedErr  error

	// newClients is swapped in tests to avoid real auth and network. It takes
	// the scopes to request, because a token is issued for the scopes asked
	// for rather than for everything consent covers: requesting less than a
	// command needs yields a token that is refused, however broad the grant.
	newClients func(ctx context.Context, a *app, scopes []string) (*msauth.Authenticator, *teams.Client, error)
	// grantedScopes reports the permissions the current sign-in actually
	// holds, which is not the same as the ones that were requested: consent
	// can grant fewer. Injectable so tests can describe a sign-in without
	// performing one.
	grantedScopes func(context.Context, *app) ([]string, error)
}

// liveGrantedScopes reports what consent actually covers.
//
// One request with the configured scopes is enough: the granted scopes on the
// resulting token list everything the account has consented to, not merely
// what was asked for.
func liveGrantedScopes(ctx context.Context, a *app) ([]string, error) {
	return grantedFor(ctx, a, a.scopes)
}

func grantedFor(ctx context.Context, a *app, scopes []string) ([]string, error) {
	auth, _, err := a.newClients(ctx, a, scopes)
	if err != nil {
		return nil, err
	}
	if auth == nil {
		return nil, errors.New("no authenticator is configured")
	}
	token, err := auth.TokenInfo(ctx)
	if err != nil {
		return nil, explainAuthError(err)
	}
	return token.GrantedScopes, nil
}

// granted reports the permissions this sign-in holds, computing it once.
func (a *app) granted(ctx context.Context) ([]string, error) {
	if a.grantedScopes == nil {
		return nil, errors.New("no permission lookup is configured")
	}
	a.grantedOnce.Do(func() {
		a.grantedHeld, a.grantedErr = a.grantedScopes(ctx, a)
	})
	return a.grantedHeld, a.grantedErr
}

// clients builds clients for the configured scopes, with no capability
// preference. login, logout, and whoami use this: they act on whatever the
// current sign-in covers rather than needing a specific permission.
func (a *app) clients(ctx context.Context) (*msauth.Authenticator, *teams.Client, error) {
	return a.newClients(ctx, a, a.scopes)
}

// clientsFor builds clients whose token covers the given capabilities.
//
// The identity service does not treat permissions as nested, so there is no
// single request that works for every account: someone who consented to
// Chat.ReadWrite cannot be issued Chat.Read, and someone who consented to
// Chat.Read cannot be issued Chat.ReadWrite. Both spellings are tried, least
// privileged first, so the narrower permission is preferred when it is
// available and the broader one still works when it is not.
func (a *app) clientsFor(ctx context.Context, capabilities ...teams.Capability) (*msauth.Authenticator, *teams.Client, error) {
	var (
		auth   *msauth.Authenticator
		client *teams.Client
		err    error
	)
	candidates := a.scopeCandidates(capabilities...)
	// Trying the narrower spelling first costs a refused round trip to the
	// identity service on every command whose capability was consented to in
	// its broader form. Asking what is already granted is a cache hit, so put
	// the spelling that can succeed first.
	if len(candidates) > 1 {
		if held, err := a.granted(ctx); err == nil {
			candidates = preferGranted(candidates, held)
		}
	}

	for _, scopes := range candidates {
		auth, client, err = a.newClients(ctx, a, scopes)
		if err != nil {
			return nil, nil, err
		}
		// Clients are built lazily, so the token has to be asked for here to
		// learn whether this spelling of the permission is obtainable. A test
		// double supplies no authenticator; there is no token to check.
		if auth == nil {
			return nil, client, nil
		}
		if _, tokenErr := auth.TokenInfo(ctx); tokenErr != nil {
			if errors.Is(tokenErr, msauth.ErrLoginRequired) {
				err = tokenErr
				continue
			}
			return nil, nil, tokenErr
		}
		return auth, client, nil
	}
	if err == nil {
		err = msauth.ErrLoginRequired
	}
	return nil, nil, err
}

// preferGranted moves the first candidate whose scopes are all already held
// to the front, leaving the order otherwise intact.
func preferGranted(candidates [][]string, granted []string) [][]string {
	held := make(map[string]bool, len(granted))
	for _, scope := range granted {
		held[strings.ToLower(strings.TrimSpace(scope))] = true
	}

	for i, candidate := range candidates {
		all := true
		for _, scope := range candidate {
			if !held[strings.ToLower(scope)] && !teams.IsReservedScope(scope) {
				all = false
				break
			}
		}
		if all && i > 0 {
			reordered := append([][]string{candidates[i]}, candidates[:i]...)
			return append(reordered, candidates[i+1:]...)
		}
		if all {
			return candidates
		}
	}
	return candidates
}

// scopeCandidates lists the scope sets worth trying for a set of
// capabilities, narrowest first, without repeating one.
func (a *app) scopeCandidates(capabilities ...teams.Capability) [][]string {
	if len(capabilities) == 0 {
		return [][]string{a.scopes}
	}

	narrow := teams.ScopesToRequest(a.scopes, capabilities...)

	broad := slices.Clone(a.scopes)
	for _, capability := range capabilities {
		if scope, ok := teams.MostPrivilegedScope(capability); ok {
			broad = append(broad, scope)
		}
	}
	broad = teams.ScopesToRequest(broad, capabilities...)

	if slices.Equal(narrow, broad) {
		return [][]string{narrow}
	}
	return [][]string{narrow, broad}
}

// clientFor returns a client whose token covers the capabilities a command
// needs, recording them in a.needs first so a refusal further down can name
// what was being attempted.
//
// Before spending a round trip on it, the capabilities are checked against
// what the current sign-in already holds (via [requireAll]), which is what
// lets the resulting error distinguish a gap a fresh sign-in can close from
// one only a tenant administrator can -- see [teams.NeedsAdminConsent]. That
// check is skipped, not failed, when the permission lookup itself errors
// (typically: nobody is signed in yet); [app.clientsFor] then surfaces the
// same problem through [explainAuthError].
func (a *app) clientFor(ctx context.Context, capabilities ...teams.Capability) (*teams.Client, error) {
	a.needs = capabilities
	if len(capabilities) > 0 {
		if held, err := a.granted(ctx); err == nil {
			if missing := requireAll(held, capabilities); missing != nil {
				return nil, missing
			}
		}
	}

	_, client, err := a.clientsFor(ctx, capabilities...)
	if err != nil {
		return nil, a.explain(err)
	}
	return client, nil
}

// requireAll reports the capabilities the granted scopes do not satisfy,
// split into what a tenant administrator alone can fix and what a fresh
// sign-in can, using [teams.Require] and [teams.NeedsAdminConsent].
//
// Telling someone missing an administrator-only permission to sign in again
// is advice they cannot act on: no consent screen a signed-in user sees will
// ever offer Team.ReadBasic.All or its siblings, so retrying only loops
// against a screen that never changes. Separating the two groups is what
// lets the message for one never suggest the remedy for the other.
func requireAll(granted []string, capabilities []teams.Capability) error {
	var adminOnly, consentable []*teams.ErrMissingCapability
	for _, capability := range capabilities {
		err := teams.Require(granted, capability)
		if err == nil {
			continue
		}
		var missing *teams.ErrMissingCapability
		if errors.As(err, &missing) {
			if missing.AdminOnly {
				adminOnly = append(adminOnly, missing)
			} else {
				consentable = append(consentable, missing)
			}
		}
	}
	if len(adminOnly) == 0 && len(consentable) == 0 {
		return nil
	}

	var sentences []string
	if len(adminOnly) > 0 {
		sentences = append(sentences, adminOnlySentence(adminOnly))
	}
	if len(consentable) > 0 {
		sentences = append(sentences, consentableSentence(granted, consentable))
	}
	return errors.New(strings.Join(sentences, "\n"))
}

// adminOnlySentence explains a gap only a tenant administrator can close.
// It deliberately never mentions signing in: that is not a remedy here.
func adminOnlySentence(missing []*teams.ErrMissingCapability) string {
	names := make([]string, len(missing))
	var permissions []string
	seen := map[string]bool{}
	for i, m := range missing {
		names[i] = string(m.Capability)
		for _, scope := range m.Accepts {
			if !seen[scope] {
				seen[scope] = true
				permissions = append(permissions, scope)
			}
		}
	}
	return fmt.Sprintf(
		"not permitted to %s: a tenant administrator has to grant %s -- no consent screen offered to a signed-in user ever includes it",
		strings.Join(names, " and "), strings.Join(permissions, " or "))
}

// consentableSentence explains a gap a fresh sign-in can close, and names the
// command that closes it.
func consentableSentence(granted []string, missing []*teams.ErrMissingCapability) string {
	names := make([]string, len(missing))
	capabilities := make([]teams.Capability, len(missing))
	for i, m := range missing {
		names[i] = string(m.Capability)
		capabilities[i] = m.Capability
	}
	return fmt.Sprintf("this needs permission to %s, which this sign-in does not have:\n  teams login --scopes %s",
		strings.Join(names, " and "),
		strings.Join(teams.ScopesToRequest(granted, capabilities...), ","))
}

// explain turns a failure into a sentence that names a remedy which works,
// for the case [app.clientFor]'s proactive check could not run at all --
// typically because nobody is signed in yet, so nothing is known about
// consent. Once signed in, [requireAll] handles the more specific cases.
func (a *app) explain(err error) error {
	if err == nil || len(a.needs) == 0 || !errors.Is(err, msauth.ErrLoginRequired) {
		return explainAuthError(err)
	}
	names := make([]string, len(a.needs))
	for i, capability := range a.needs {
		names[i] = string(capability)
	}
	return fmt.Errorf("not signed in: run 'teams login' first (this needs permission to %s)",
		strings.Join(names, " and "))
}

// wouldChange reports whether a mutation should be described instead of
// performed. Every command that changes a chat or channel routes through it,
// so --dry-run cannot be half-implemented: a command that forgets to ask
// simply has no dry-run behavior to get wrong.
func (a *app) wouldChange(format string, args ...any) bool {
	if !a.dryRun {
		return false
	}
	fmt.Fprintf(a.out, "would "+format+"\n", args...)
	return true
}

// context applies the configured timeout to a command's context.
func (a *app) context(cmd *cobra.Command) (context.Context, context.CancelFunc) {
	if a.timeout <= 0 {
		return context.WithCancel(cmd.Context())
	}
	return context.WithTimeout(cmd.Context(), a.timeout)
}

// resolveAuthority applies the fallback described on [defaultAuthority]. It
// is a pure function, split out of [buildClients], so the fallback can be
// pinned by a test without going anywhere near the keychain or the network
// that constructing a real [msauth.Authenticator] touches.
func resolveAuthority(value string) string {
	if value == "" {
		return defaultAuthority
	}
	return value
}

func buildClients(_ context.Context, a *app, scopes []string) (*msauth.Authenticator, *teams.Client, error) {
	if len(scopes) == 0 {
		scopes = a.scopes
	}
	auth, err := msauth.New(msauth.Config{
		ClientID:  a.clientID,
		Authority: resolveAuthority(a.authority),
		Scopes:    scopes,
	}, tokenStore(a.cacheDir))
	if err != nil {
		return nil, nil, fmt.Errorf("configure authentication: %w", err)
	}
	graph, err := msgraph.New(auth.TokenSource(scopes...))
	if err != nil {
		return nil, nil, fmt.Errorf("configure graph client: %w", err)
	}
	client, err := teams.New(graph)
	if err != nil {
		return nil, nil, fmt.Errorf("configure teams client: %w", err)
	}
	return auth, client, nil
}

// tokenStore picks the OS keychain by default, or an encrypted file when the
// caller names a directory -- headless machines have no keyring.
func tokenStore(dir string) cache.Store {
	if dir == "" {
		return cache.NewKeychainStore()
	}
	return cache.NewFileStore(dir)
}

// NewRootCommand builds the teams command tree.
func NewRootCommand() *cobra.Command {
	return newRootCommand(&app{newClients: buildClients, grantedScopes: liveGrantedScopes})
}

// newRootCommand builds the tree around a supplied app, which lets tests
// substitute the client factory without reaching into the command tree.
func newRootCommand(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:   "teams",
		Short: "Read and send Microsoft Teams chats and channel messages from the command line",
		Long: "teams is a command-line client for Microsoft Teams over Microsoft Graph.\n\n" +
			"Every Teams endpoint is work-or-school only: there is no personal-account\n" +
			"path, unlike mail or calendar over Graph. Sign in once with an account\n" +
			"that belongs to a tenant, and tokens are cached and refreshed silently\n" +
			"after that.",
		Example: strings.Join([]string{
			"  # Sign in once, then list unread chats",
			"  teams login",
			"  teams chats --unread",
			"",
			"  # Read a chat and reply",
			"  teams chat read <chat-id>",
			"  teams chat send <chat-id> --body 'on it'",
			"",
			"  # Machine-readable output for scripting",
			"  teams chats --json | jq -r '.[].id'",
		}, "\n"),
		SilenceUsage:  true,
		SilenceErrors: true,
		// Without this, a typo like "teams chatz" silently runs the root help.
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	flags := root.PersistentFlags()
	flags.StringSliceVar(&a.scopes, "scopes", defaultScopes, "delegated Microsoft Graph scopes")
	flags.StringVar(&a.clientID, "client-id", msgraph.GraphCLIClientID,
		"Entra application (client) ID; defaults to Microsoft's shared \"Microsoft Graph Command Line "+
			"Tools\" client. Pass your own app registration if you need a tenant administrator to be able "+
			"to attribute or revoke this tool's consent separately from every other tool that uses the "+
			"shared one.")
	flags.StringVar(&a.authority, "authority", "",
		"Microsoft identity authority URL; defaults to the work/school endpoint. Every Teams endpoint "+
			"is work-or-school only, and msauth-go's own default targets personal Microsoft accounts, so "+
			"leaving this at that default would fail every sign-in with an error that does not say why.")
	flags.StringVar(&a.cacheDir, "token-cache-dir", "",
		"store tokens in an encrypted file in this directory instead of the OS keychain")
	flags.DurationVar(&a.timeout, "timeout", 2*time.Minute, "timeout for each command; 0 disables it")
	flags.BoolVar(&a.jsonOut, "json", false, "emit JSON instead of a table")
	flags.BoolVar(&a.dryRun, "dry-run", false, "describe what would change without changing anything")

	root.AddCommand(
		newLoginCommand(a),
		newLogoutCommand(a),
		newWhoamiCommand(a),
		newScopesCommand(a),
		newChatsCommand(a),
		newChatCommand(a),
		newSearchCommand(a),
		newJoinedTeamsCommand(a),
		newChannelsCommand(a),
		newChannelCommand(a),
		newPresenceCommand(a),
	)
	return root
}

// bind points the command tree at explicit streams. Tests use it; cobra sets
// them from os.Stdout/os.Stderr otherwise.
func (a *app) bind(cmd *cobra.Command) {
	a.out = cmd.OutOrStdout()
	a.err = cmd.ErrOrStderr()
}

// explainAuthError turns a login-required failure into an actionable message
// rather than leaking MSAL's internals.
func explainAuthError(err error) error {
	if errors.Is(err, msauth.ErrLoginRequired) {
		return errors.New("not signed in: run 'teams login' first")
	}
	if errors.Is(err, msauth.ErrNoScopes) {
		return errors.New("no scopes requested: pass --scopes")
	}
	return err
}
