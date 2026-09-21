package cli

import (
	"fmt"
	"strings"
	"text/tabwriter"

	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

// capabilityReport is the JSON shape of the scopes command.
type capabilityReport struct {
	Granted      []string           `json:"grantedScopes"`
	Capabilities []capabilityStatus `json:"capabilities"`
	// SignInCommand is populated only when something user-consentable is
	// missing, so a script can test for it rather than parse prose. It is
	// left empty when the only gaps need a tenant administrator: there is no
	// sign-in line that would grant those.
	SignInCommand string `json:"signInCommand,omitempty"`
}

type capabilityStatus struct {
	Name      string   `json:"capability"`
	Permitted bool     `json:"permitted"`
	AdminOnly bool     `json:"adminOnly,omitempty"`
	Accepts   []string `json:"satisfiedBy"`
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
			"named user-consentable capabilities, keeping everything already granted.",
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

			granted, err := a.grantedScopes(ctx, a)
			if err != nil {
				return err
			}

			report := capabilityReport{Granted: granted}
			var missing []teams.Capability
			for _, capability := range teams.Capabilities() {
				permitted := teams.Granted(granted, capability)
				if !permitted {
					missing = append(missing, capability)
				}
				report.Capabilities = append(report.Capabilities, capabilityStatus{
					Name:      string(capability),
					Permitted: permitted,
					AdminOnly: teams.NeedsAdminConsent(capability),
					Accepts:   teams.ScopesFor(capability),
				})
			}

			// --want narrows the suggestion to what was asked for; otherwise
			// everything user-consentable and missing is offered.
			target := missing
			if len(want) > 0 {
				target, err = parseCapabilities(want)
				if err != nil {
					return err
				}
				target = teams.MissingFor(granted, target...)
			}
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

			if a.jsonOut {
				return writeJSON(a.out, report)
			}

			tw := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "CAPABILITY\tPERMITTED\tSATISFIED BY")
			for _, status := range report.Capabilities {
				mark := "no"
				if status.Permitted {
					mark = "yes"
				}
				if status.AdminOnly && !status.Permitted {
					mark = "no (admin only)"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", status.Name, mark, strings.Join(status.Accepts, " or "))
			}
			if err := tw.Flush(); err != nil {
				return err
			}
			if report.SignInCommand != "" {
				fmt.Fprintf(a.out, "\nTo grant what is missing:\n  %s\n", report.SignInCommand)
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
