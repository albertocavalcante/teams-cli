package cli

import (
	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

func newPresenceCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "presence [user-id]",
		Short: "Show Teams presence",
		Long: "Show the signed-in user's own presence, or another user's given their\n" +
			"id from `teams chat members`.\n\n" +
			"Reading your own presence is user-consentable. Reading someone else's\n" +
			"needs a permission only a tenant administrator can grant -- see `teams\n" +
			"scopes` for which one -- and no consent screen a signed-in user sees\n" +
			"ever offers it, so retrying sign-in will not fix a refusal there.",
		Example: "  teams presence\n" +
			"  teams presence 4b0d....-aaaa-....-....",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			var (
				presence teams.Presence
				err      error
			)
			if len(args) == 0 {
				var client *teams.Client
				client, err = a.clientFor(ctx, teams.ReadOwnPresence)
				if err != nil {
					return err
				}
				presence, _, err = client.MyPresence(ctx)
			} else {
				var client *teams.Client
				client, err = a.clientFor(ctx, teams.ReadPresence)
				if err != nil {
					return err
				}
				presence, _, err = client.UserPresence(ctx, teams.UserID(args[0]))
			}
			if err != nil {
				return explainAuthError(err)
			}

			row := presenceRowOf(presence)
			if a.jsonOut {
				return writeJSON(a.out, row)
			}
			return writePresenceTable(a.out, row)
		},
	}
	return cmd
}
