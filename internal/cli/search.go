package cli

import (
	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

func newSearchCommand(a *app) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Full-text search across your chat and channel messages",
		Long: "Run a full-text message search, in relevance order.\n\n" +
			"With chat permission alone -- no channel-message permission -- this\n" +
			"returns chat hits and no channel hits, with nothing in the response\n" +
			"distinguishing that from a search that genuinely found nothing in\n" +
			"channels. An answer that looks complete is not the same as one that\n" +
			"searched everywhere it could have.",
		Example: "  teams search 'quarterly report'\n" +
			"  teams search 'quarterly report' --limit 5 --json | jq -r '.[].text'",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			client, err := a.clientFor(ctx, teams.SearchMessages)
			if err != nil {
				return err
			}

			var rows []searchRow
			query := teams.SearchQuery{Term: args[0], Size: teams.MaxSearchPageSize}
			for hit, hitErr := range client.SearchMessages(ctx, query) {
				if hitErr != nil {
					return explainAuthError(hitErr)
				}
				rows = append(rows, searchRowOf(hit))
				if limit > 0 && len(rows) >= limit {
					break
				}
			}
			if a.jsonOut {
				return writeJSON(a.out, rows)
			}
			return writeSearchTable(a.out, rows)
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "n", 25, "maximum hits to show; 0 means no limit")
	return cmd
}
