package cli

import (
	"fmt"
	"strings"
	"time"

	msauth "github.com/albertocavalcante/msauth-go"
	msgraph "github.com/albertocavalcante/msgraph-go"
	"github.com/spf13/cobra"
)

func newLoginCommand(a *app) *cobra.Command {
	var device bool

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to a Microsoft work or school account",
		Long: "Sign in and cache a refresh token.\n\n" +
			"Teams has no personal-account path: --device is for a work or school\n" +
			"account on a machine with no browser, and the interactive browser flow\n" +
			"below also requires one -- a personal Microsoft account is refused by the\n" +
			"Teams endpoints themselves, not by this command.",
		Example: strings.Join([]string{
			"  # Browser sign-in",
			"  teams login",
			"",
			"  # Device code, for a machine with no browser",
			"  teams login --device",
			"",
			"  # Ask for read-only chat access instead of the default scopes",
			"  teams login --scopes User.Read,Chat.Read",
		}, "\n"),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.bind(cmd)
			// Consent recorded against Microsoft's own client cannot be told
			// apart, by a tenant administrator, from consent any other tool
			// built on the same client recorded -- there is no per-tool
			// attribution or revocation. This is not a blocking prompt: it
			// only says so before the browser or device-code flow opens, so
			// the choice to bring an own registration is made with that cost
			// in view.
			if a.clientID == msgraph.GraphCLIClientID {
				fmt.Fprintln(a.err, "Note: signing in with Microsoft's shared \"Microsoft Graph Command Line "+
					"Tools\" client. A tenant administrator cannot attribute or revoke this tool's consent "+
					"separately from every other tool that uses the same client; pass --client-id with your "+
					"own app registration to change that.")
			}

			ctx, cancel := a.context(cmd)
			defer cancel()

			auth, _, err := a.clients(ctx)
			if err != nil {
				return err
			}
			opts := []msauth.LoginOption{
				msauth.WithPrompt(func(message string) {
					fmt.Fprintln(a.err, message)
				}),
			}
			if device {
				opts = append(opts, msauth.WithDevice())
			}
			identity, err := auth.Login(ctx, opts...)
			if err != nil {
				return fmt.Errorf("login: %w", err)
			}
			if a.jsonOut {
				return writeJSON(a.out, identity)
			}
			fmt.Fprintf(a.out, "Signed in as %s\n", identity.Username)
			return nil
		},
	}
	cmd.Flags().BoolVar(&device, "device", false, "use device-code flow (a browser-less work or school sign-in)")
	return cmd
}

func newLogoutCommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Remove cached credentials",
		Long: "Remove the cached account and its tokens from the local token store.\n\n" +
			"This does not revoke the grant server-side; it only forgets it here.",
		Example: "  teams logout",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			auth, _, err := a.clients(ctx)
			if err != nil {
				return err
			}
			if err := auth.Logout(ctx); err != nil {
				return fmt.Errorf("logout: %w", err)
			}
			fmt.Fprintln(a.out, "Signed out.")
			return nil
		},
	}
}

// whoamiResult is the JSON shape of the whoami command.
type whoamiResult struct {
	Username      string    `json:"username"`
	HomeAccountID string    `json:"homeAccountId"`
	ExpiresOn     time.Time `json:"tokenExpiresOn"`
	GrantedScopes []string  `json:"grantedScopes"`
	MissingScopes []string  `json:"missingScopes,omitempty"`
}

func newWhoamiCommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Show the signed-in account and token status",
		Long: "Show the cached account, when its access token expires, and which of the\n" +
			"requested scopes consent actually granted.",
		Example: "  teams whoami\n" +
			"  teams whoami --json",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			auth, _, err := a.clients(ctx)
			if err != nil {
				return err
			}
			identity, err := auth.Identity(ctx)
			if err != nil {
				return explainAuthError(err)
			}
			token, err := auth.TokenInfo(ctx)
			if err != nil {
				return explainAuthError(err)
			}

			result := whoamiResult{
				Username:      identity.Username,
				HomeAccountID: identity.HomeAccountID,
				ExpiresOn:     token.ExpiresOn,
				GrantedScopes: token.GrantedScopes,
				MissingScopes: missingScopes(a.scopes, token),
			}
			if a.jsonOut {
				return writeJSON(a.out, result)
			}

			fmt.Fprintf(a.out, "Account:  %s\n", result.Username)
			fmt.Fprintf(a.out, "Token:    valid for %s\n", time.Until(result.ExpiresOn).Round(time.Second))
			fmt.Fprintf(a.out, "Scopes:   %s\n", strings.Join(result.GrantedScopes, ", "))
			if len(result.MissingScopes) > 0 {
				// A declined scope shows up as a refusal on an unrelated
				// command later, so surface it here where it is explainable.
				fmt.Fprintf(a.err, "Warning:  not granted: %s\n", strings.Join(result.MissingScopes, ", "))
			}
			return nil
		},
	}
}

// missingScopes reports requested scopes that consent did not grant.
func missingScopes(requested []string, token msauth.AccessToken) []string {
	var missing []string
	for _, scope := range requested {
		if !token.HasScope(scope) {
			missing = append(missing, scope)
		}
	}
	return missing
}
