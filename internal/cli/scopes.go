package cli

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"

	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

// capabilityReport is the JSON shape of the scopes command.
type capabilityReport struct {
	Mode         string             `json:"mode,omitempty"`
	Granted      []string           `json:"grantedScopes"`
	Capabilities []capabilityStatus `json:"capabilities"`
	// SignInCommand is populated only when something user-consentable is
	// missing, so a script can test for it rather than parse prose. It is
	// left empty when the only gaps need a tenant administrator: there is no
	// sign-in line that would grant those.
	SignInCommand string `json:"signInCommand,omitempty"`
	// LocalGrantHint is shown only with a local profile. Local grants come from
	// the selected synthetic persona's seed, never Microsoft consent.
	LocalGrantHint string `json:"localGrantHint,omitempty"`
}

type capabilityStatus struct {
	Name      string   `json:"capability"`
	Permitted bool     `json:"permitted"`
	AdminOnly bool     `json:"adminOnly,omitempty"`
	Accepts   []string `json:"satisfiedBy"`
	// AvailableLocally is set only in Local365 mode. A Graph permission can be
	// granted before the matching emulator route or CLI command exists.
	AvailableLocally *bool `json:"availableLocally,omitempty"`
}

func localCapabilityAvailable(capability teams.Capability) bool {
	return capability == teams.ReadIdentity || capability == teams.ListChats || capability == teams.ReadChatMessages
}

// Local365's /me route accepts additional directory scopes that the Teams
// SDK's general ReadIdentity capability table does not list. Local reporting
// must agree with the route the local whoami command actually calls.
var localIdentityScopes = []string{
	"User.Read",
	"User.ReadWrite",
	"User.ReadBasic.All",
	"User.Read.All",
	"User.ReadWrite.All",
	"Directory.Read.All",
	"Directory.ReadWrite.All",
}

// Local chats requests a message preview. Chat.ReadBasic can list basic chat
// metadata through Local365, but cannot run that CLI query locally.
var localChatListScopes = []string{"Chat.Read", "Chat.ReadWrite"}

func localCapabilityGranted(granted []string, capability teams.Capability) bool {
	switch capability {
	case teams.ReadIdentity, teams.ListChats:
		accepted := localCapabilityScopes(capability)
		for _, scope := range granted {
			if slices.ContainsFunc(accepted, func(candidate string) bool { return strings.EqualFold(candidate, scope) }) {
				return true
			}
		}
		return false
	default:
		return teams.Granted(granted, capability)
	}
}

func localCapabilityScopes(capability teams.Capability) []string {
	switch capability {
	case teams.ReadIdentity:
		return slices.Clone(localIdentityScopes)
	case teams.ListChats:
		return slices.Clone(localChatListScopes)
	default:
		return teams.ScopesFor(capability)
	}
}

func localMissingFor(granted []string, capabilities []teams.Capability) []teams.Capability {
	var missing []teams.Capability
	for _, capability := range capabilities {
		if !localCapabilityGranted(granted, capability) {
			missing = append(missing, capability)
		}
	}
	return missing
}

func newScopesCommand(a *app) *cobra.Command {
	var want []string

	cmd := &cobra.Command{
		Use:   "scopes",
		Short: "Show which permissions you hold and what they allow",
		Long: "Show what the current sign-in permits, and what it does not.\n\n" +
			"The service is unhelpful when a permission is missing: it refuses the\n" +
			"request with an error that names nothing, so there is no way to learn\n" +
			"from the failure what to ask for. This asks beforehand instead. Half of\n" +
			"the Teams permissions -- everything for listing teams, listing channels,\n" +
			"reading channel messages, and reading someone else's presence -- can only\n" +
			"be granted by a tenant administrator; those are marked ADMIN ONLY rather\n" +
			"than given a sign-in line, because no consent screen a signed-in user\n" +
			"sees ever offers them.\n\n" +
			"With --want, the command prints the sign-in line that would grant the\n" +
			"named user-consentable capabilities, keeping everything already granted.\n\n" +
			"With --local-profile, grants come from the synthetic Local365 persona.\n" +
			"The LOCAL column shows which capabilities have working local commands.",
		Example: strings.Join([]string{
			"  teams scopes",
			"  teams scopes --json",
			"",
			"  # What would I need to send chat messages?",
			"  teams scopes --want 'send a chat message'",
		}, "\n"),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			local := a.localProfile != ""
			var granted []string
			if local {
				session, err := a.loadLocalSession(ctx)
				if err != nil {
					return err
				}
				granted = session.GrantedScopes
			} else {
				var err error
				granted, err = a.grantedScopes(ctx, a)
				if err != nil {
					return err
				}
			}

			report := capabilityReport{Granted: granted}
			if local {
				report.Mode = "local"
			}
			var missing []teams.Capability
			for _, capability := range teams.Capabilities() {
				permitted := teams.Granted(granted, capability)
				if local {
					permitted = localCapabilityGranted(granted, capability)
				}
				if !permitted {
					missing = append(missing, capability)
				}
				var available *bool
				if local {
					implemented := localCapabilityAvailable(capability)
					available = &implemented
				}
				accepts := teams.ScopesFor(capability)
				if local {
					accepts = localCapabilityScopes(capability)
				}
				report.Capabilities = append(report.Capabilities, capabilityStatus{
					Name:             string(capability),
					Permitted:        permitted,
					AdminOnly:        !local && teams.NeedsAdminConsent(capability),
					Accepts:          accepts,
					AvailableLocally: available,
				})
			}

			// --want narrows the suggestion to what was asked for; otherwise
			// everything user-consentable and missing is offered.
			target := missing
			var err error
			if len(want) > 0 {
				target, err = parseCapabilities(want)
				if err != nil {
					return err
				}
				if local {
					target = localMissingFor(granted, target)
				} else {
					target = teams.MissingFor(granted, target...)
				}
			}
			if local {
				if len(target) > 0 {
					report.LocalGrantHint = "Update this persona's scopes in the Local365 seed and restart Local365 to test these grants."
				}
			} else {
				var consentable []teams.Capability
				for _, capability := range target {
					if !teams.NeedsAdminConsent(capability) {
						consentable = append(consentable, capability)
					}
				}
				if len(consentable) > 0 {
					report.SignInCommand = "teams login --scopes " +
						strings.Join(teams.ScopesToRequest(granted, consentable...), ",")
				}
			}

			if a.jsonOut {
				return writeJSON(a.out, report)
			}

			tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
			if local {
				fmt.Fprintln(tw, "CAPABILITY\tPERMITTED\tLOCAL\tSATISFIED BY")
			} else {
				fmt.Fprintln(tw, "CAPABILITY\tPERMITTED\tSATISFIED BY")
			}
			for _, status := range report.Capabilities {
				mark := "no"
				if status.Permitted {
					mark = "yes"
				}
				if status.AdminOnly && !status.Permitted {
					mark = "no (admin only)"
				}
				if local {
					localMark := "no"
					if status.AvailableLocally != nil && *status.AvailableLocally {
						localMark = "yes"
					}
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", status.Name, mark, localMark, strings.Join(status.Accepts, " or "))
				} else {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", status.Name, mark, strings.Join(status.Accepts, " or "))
				}
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if report.SignInCommand != "" {
				fmt.Fprintf(a.out, "\nTo grant what is missing:\n  %s\n", report.SignInCommand)
			}
			if report.LocalGrantHint != "" {
				fmt.Fprintf(a.out, "\n%s\n", report.LocalGrantHint)
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&want, "want", nil,
		"capabilities to check for, by name; repeatable")
	return cmd
}

// parseCapabilities resolves capability names, listing the valid ones when a
// name is not recognized rather than leaving the caller to guess.
func parseCapabilities(names []string) ([]teams.Capability, error) {
	var resolved []teams.Capability
	for _, name := range names {
		wanted := strings.ToLower(strings.TrimSpace(name))
		var match teams.Capability
		for _, capability := range teams.Capabilities() {
			if strings.EqualFold(string(capability), wanted) {
				match = capability
				break
			}
		}
		if match == "" {
			valid := make([]string, 0, len(teams.Capabilities()))
			for _, capability := range teams.Capabilities() {
				valid = append(valid, fmt.Sprintf("%q", capability))
			}
			return nil, fmt.Errorf("unknown capability %q; valid names are %s",
				name, strings.Join(valid, ", "))
		}
		resolved = append(resolved, match)
	}
	return resolved, nil
}
