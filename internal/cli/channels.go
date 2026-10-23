package cli

import (
	"errors"

	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

// adminConsentNote is appended to the Long text of every command whose
// capability [teams.NeedsAdminConsent] reports true, so the requirement
// shows up in --help, before a command fails with a 403 that names nothing.
const adminConsentNote = "\n\nThis needs a permission only a tenant administrator can grant; see\n" +
	"`teams scopes` for which one, and ask them rather than retrying sign-in."

func newJoinedTeamsCommand(a *app) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "teams",
		Short: "List the teams you belong to",
		Long: "List the teams the signed-in user belongs to.\n\n" +
			"The listing only ever populates id, displayName, description, and\n" +
			"whether the team is archived -- every other property, including\n" +
			"visibility and the web link, comes back empty here regardless of what\n" +
			"the team actually has set." + adminConsentNote,
		Example: "  teams teams\n" +
			"  teams teams --json | jq -r '.[].id'",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			client, err := a.clientFor(ctx, teams.ListTeams)
			if err != nil {
				return err
			}
			var rows []teamRow
			for team, teamErr := range client.JoinedTeams(ctx) {
				if teamErr != nil {
					return explainAuthError(teamErr)
				}
				rows = append(rows, teamRowOf(team))
				if limit > 0 && len(rows) >= limit {
					break
				}
			}
			if a.jsonOut {
				return writeJSON(a.out, rows)
			}
			return writeTeamTable(a.out, rows)
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "n", 0, "maximum teams to show; 0 means no limit")
	return cmd
}

func newChannelsCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "channels <team-id>",
		Short: "List a team's channels",
		Long: "List a team's channels.\n\n" +
			"A private or shared channel keeps its messages on a back end the\n" +
			"team's own message endpoints do not reach: `teams channel read` against\n" +
			"one of those returns an empty listing, not a permission error, which\n" +
			"reads as \"no messages yet\" rather than \"wrong place.\"" + adminConsentNote,
		Example: "  teams channels 19:team-id@thread.tacv2\n" +
			"  teams channels 19:team-id@thread.tacv2 --json | jq -r '.[].id'",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			client, err := a.clientFor(ctx, teams.ListChannels)
			if err != nil {
				return err
			}
			var rows []channelRow
			for channel, chErr := range client.Channels(ctx, teams.TeamID(args[0]), teams.ChannelQuery{}) {
				if chErr != nil {
					return explainAuthError(chErr)
				}
				rows = append(rows, channelRowOf(channel))
			}
			if a.jsonOut {
				return writeJSON(a.out, rows)
			}
			return writeChannelTable(a.out, rows)
		},
	}
	return cmd
}

// newChannelCommand groups the subcommands that read or change one channel,
// given a team id from `teams teams` and a channel id from `teams channels`.
func newChannelCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "channel",
		Short: "Read or change one channel",
		Long: "Subcommands that read or post to a single channel, addressed by the\n" +
			"team id `teams teams` prints and the channel id `teams channels` prints.",
	}
	cmd.AddCommand(
		newChannelReadCommand(a),
		newChannelSendCommand(a),
		newChannelReplyCommand(a),
	)
	return cmd
}

func newChannelReadCommand(a *app) *cobra.Command {
	var (
		limit   int
		replies bool
	)

	cmd := &cobra.Command{
		Use:   "read <team-id> <channel-id>",
		Short: "Read a channel's messages",
		Long: "Read a channel's root messages, ordered by the latest change to each thread.\n\n" +
			"This returns root messages only, however far the listing pages: a\n" +
			"reply never appears here unless --replies is given. --replies\n" +
			"includes every reply to each selected root message, following the\n" +
			"thread's continuation links when needed." +
			adminConsentNote,
		Example: "  teams channel read 19:team-id@thread.tacv2 19:channel-id@thread.tacv2\n" +
			"  teams channel read 19:team-id@thread.tacv2 19:channel-id@thread.tacv2 --replies",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			client, err := a.clientFor(ctx, teams.ReadChannelMessages)
			if err != nil {
				return err
			}

			query := teams.ChannelMessageQuery{
				Top:         teams.MaxMessagePageSize,
				WithReplies: replies,
			}

			var rows []messageRow
			rootCount := 0
			for message, msgErr := range client.ChannelMessages(ctx, teams.TeamID(args[0]), teams.ChannelID(args[1]), query) {
				if msgErr != nil {
					return explainAuthError(msgErr)
				}
				rows = append(rows, messageRowOf(message))
				rootCount++
				if replies {
					for i := range message.Replies {
						rows = append(rows, messageRowOf(message.Replies[i]))
					}
					for reply, replyErr := range client.MoreReplies(ctx, message) {
						if replyErr != nil {
							return explainAuthError(replyErr)
						}
						rows = append(rows, messageRowOf(reply))
					}
				}
				if limit > 0 && rootCount >= limit {
					break
				}
			}
			if a.jsonOut {
				return writeJSON(a.out, rows)
			}
			return writeMessageTable(a.out, rows)
		},
	}

	flags := cmd.Flags()
	flags.IntVarP(&limit, "limit", "n", 25, "maximum root messages to show; 0 means no limit")
	flags.BoolVar(&replies, "replies", false, "also show every reply to each selected root message")
	return cmd
}

func newChannelSendCommand(a *app) *cobra.Command {
	var compose composeFlags

	cmd := &cobra.Command{
		Use:     "send <team-id> <channel-id>",
		Short:   "Post a new message to a channel",
		Long:    "Compose and post a new root message to a channel.",
		Example: "  teams channel send 19:team-id@thread.tacv2 19:channel-id@thread.tacv2 --body 'status update'",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			body, err := compose.itemBody(cmd.InOrStdin())
			if err != nil {
				return err
			}
			draft := teams.Draft{Body: body}
			if draft.IsEmpty() {
				return errors.New("nothing to send: pass --body or --body-file")
			}

			ctx, cancel := a.context(cmd)
			defer cancel()
			client, err := a.clientFor(ctx, teams.SendChannelMessage)
			if err != nil {
				return err
			}
			if a.wouldChange("post a message to channel %s in team %s", args[1], args[0]) {
				return nil
			}

			message, _, err := client.SendChannelMessage(ctx, teams.TeamID(args[0]), teams.ChannelID(args[1]), draft)
			if err != nil {
				return explainAuthError(err)
			}
			return a.reportAction(actionResult{Action: "send", ID: message.ID.String()},
				"Posted. Id: "+message.ID.String())
		},
	}
	compose.register(cmd)
	return cmd
}

func newChannelReplyCommand(a *app) *cobra.Command {
	var compose composeFlags

	cmd := &cobra.Command{
		Use:   "reply <team-id> <channel-id> <message-id>",
		Short: "Reply to a channel message",
		Long: "Reply to a root channel message.\n\n" +
			"The thread is one level deep: replying to a reply's own id fails,\n" +
			"because a reply has no replies collection of its own.",
		Example: "  teams channel reply 19:team-id@thread.tacv2 19:channel-id@thread.tacv2 1622547684000 --body '+1'",
		Args:    cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			body, err := compose.itemBody(cmd.InOrStdin())
			if err != nil {
				return err
			}
			draft := teams.Draft{Body: body}
			if draft.IsEmpty() {
				return errors.New("nothing to send: pass --body or --body-file")
			}

			ctx, cancel := a.context(cmd)
			defer cancel()
			client, err := a.clientFor(ctx, teams.SendChannelMessage)
			if err != nil {
				return err
			}
			if a.wouldChange("reply to message %s in channel %s", args[2], args[1]) {
				return nil
			}

			reply, _, err := client.ReplyToChannelMessage(
				ctx, teams.TeamID(args[0]), teams.ChannelID(args[1]), teams.MessageID(args[2]), draft)
			if err != nil {
				return explainAuthError(err)
			}
			return a.reportAction(actionResult{Action: "reply", ID: reply.ID.String()},
				"Replied. Id: "+reply.ID.String())
		},
	}
	compose.register(cmd)
	return cmd
}
