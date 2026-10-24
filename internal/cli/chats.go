package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	msgraph "github.com/albertocavalcante/msgraph-go"
	teams "github.com/albertocavalcante/teams-go"
	"github.com/spf13/cobra"
)

// selfResponse is GET /me narrowed to the one property this package reads.
type selfResponse struct {
	ID string `json:"id"`
}

// resolveSelf reads the signed-in user's own Graph id, which
// [teams.Chat.DisplayName] needs to name "the other participant" in a
// one-on-one chat rather than the signed-in account itself. teams-go does
// not model /me -- it is a directory endpoint, not a Teams one -- so this
// calls it directly through [teams.Client.Graph] rather than inventing a
// Teams-specific way to learn who is signed in.
func resolveSelf(ctx context.Context, client *teams.Client) (teams.UserID, error) {
	var me selfResponse
	if _, err := client.Graph().Get(ctx, "/me", msgraph.Params{Select: []string{"id"}}, &me); err != nil {
		return "", explainAuthError(err)
	}
	return teams.UserID(me.ID), nil
}

func newChatsCommand(a *app) *cobra.Command {
	var (
		unreadOnly bool
		limit      int
		all        bool
	)

	cmd := &cobra.Command{
		Use:   "chats",
		Short: "List your chats",
		Long: "List chats, most recently active first.\n\n" +
			"This includes one-on-one, group, and meeting chats. A one-on-one\n" +
			"chat's name is the other participant, resolved from its members; the\n" +
			"service never names the chat itself.",
		Example: strings.Join([]string{
			"  teams chats",
			"  teams chats --unread",
			"  teams chats --all --json | jq -r '.[].id'",
		}, "\n"),
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			var client *teams.Client
			var err error
			if a.localProfile != "" {
				client, err = a.localTeamsClient()
			} else {
				client, err = a.clientFor(ctx, teams.ListChats)
			}
			if err != nil {
				return err
			}
			self, err := resolveSelf(ctx, client)
			if err != nil {
				return err
			}

			top := limit
			if all {
				top = 0
			}
			query := teams.ChatQuery{
				WithMembers:            true,
				WithLastMessagePreview: true,
				ByRecentMessage:        true,
				Top:                    teams.MaxChatPageSize,
			}

			var rows []chatRow
			for chat, chatErr := range client.Chats(ctx, query) {
				if chatErr != nil {
					return explainAuthError(chatErr)
				}
				row := chatRowOf(chat, self)
				if unreadOnly && (row.Unread == nil || !*row.Unread) {
					continue
				}
				rows = append(rows, row)
				if top > 0 && len(rows) >= top {
					break
				}
			}
			if a.jsonOut {
				return writeJSON(a.out, rows)
			}
			return writeChatTable(a.out, rows)
		},
	}

	flags := cmd.Flags()
	flags.BoolVarP(&unreadOnly, "unread", "u", false, "only chats with an unread message")
	flags.IntVarP(&limit, "limit", "n", 25, "maximum chats to show; 0 means no limit")
	flags.BoolVar(&all, "all", false, "show every chat rather than stopping at --limit")
	return cmd
}

// newChatCommand groups the subcommands that read or change one chat, given
// its id from `teams chats`. It has no Example of its own and no RunE:
// cobra's default behavior for a non-runnable parent -- print usage -- is
// already what running it bare should do.
func newChatCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "chat",
		Short: "Read or change one chat",
		Long:  "Subcommands that read or change a single chat, addressed by the id `teams chats` prints.",
	}
	cmd.AddCommand(
		newChatReadCommand(a),
		newChatSendCommand(a),
		newChatReactCommand(a, true),
		newChatReactCommand(a, false),
		newChatRmCommand(a),
		newChatMembersCommand(a),
	)
	return cmd
}

// parseMessageOrder maps --order to the SDK's typed enum, naming the flag
// in the error so a caller with several similarly-named flags in play can
// tell which one was wrong.
func parseMessageOrder(value string) (teams.MessageOrder, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "created":
		return teams.ByCreated, nil
	case "modified":
		return teams.ByLastModified, nil
	default:
		return "", fmt.Errorf("invalid --order %q: want \"created\" or \"modified\"", value)
	}
}

func newChatReadCommand(a *app) *cobra.Command {
	var (
		limit  int
		since  time.Duration
		before time.Duration
		order  string
	)

	cmd := &cobra.Command{
		Use:   "read <chat-id>",
		Short: "Read a chat's messages",
		Long: "Read a chat's messages, newest first.\n\n" +
			"--order modified sorts and windows by when a message was last touched\n" +
			"rather than when it was sent -- which also moves when someone reacts to\n" +
			"it, edits it, or soft-deletes it. That makes it useful for polling what\n" +
			"changed since a previous read, and the wrong choice for building a\n" +
			"transcript, which --order created (the default) is for. JSON output\n" +
			"shows creation as time and, when available, modifiedTime separately.",
		Example: strings.Join([]string{
			"  teams chat read 19:abc...@thread.v2",
			"  teams chat read 19:abc...@thread.v2 --since 24h",
			"  teams chat read 19:abc...@thread.v2 --order modified --since 10m",
			"  teams chat read 19:abc...@thread.v2 --json | jq -r '.[].text'",
		}, "\n"),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			messageOrder, err := parseMessageOrder(order)
			if err != nil {
				return err
			}

			ctx, cancel := a.context(cmd)
			defer cancel()
			var client *teams.Client
			if a.localProfile != "" {
				client, err = a.localTeamsClient()
			} else {
				client, err = a.clientFor(ctx, teams.ReadChatMessages)
			}
			if err != nil {
				return err
			}

			query := teams.MessageQuery{Order: messageOrder, Top: teams.MaxMessagePageSize}
			now := time.Now()
			if since > 0 {
				query.Since = now.Add(-since)
			}
			if before > 0 {
				query.Before = now.Add(-before)
			}

			var rows []messageRow
			for message, msgErr := range client.Messages(ctx, teams.ChatID(args[0]), query) {
				if msgErr != nil {
					return explainAuthError(msgErr)
				}
				rows = append(rows, messageRowOf(message))
				if limit > 0 && len(rows) >= limit {
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
	flags.IntVarP(&limit, "limit", "n", 25, "maximum messages to show; 0 means no limit")
	flags.DurationVar(&since, "since", 0, "only messages at or after this long ago, e.g. 24h")
	flags.DurationVar(&before, "before", 0, "only messages strictly before this long ago")
	flags.StringVar(&order, "order", "created", `sort and window by "created" or "modified"`)
	return cmd
}

func newChatSendCommand(a *app) *cobra.Command {
	var compose composeFlags

	cmd := &cobra.Command{
		Use:   "send <chat-id>",
		Short: "Send a message to a chat",
		Long:  "Compose and send a message to a chat.",
		Example: strings.Join([]string{
			"  teams chat send 19:abc...@thread.v2 --body 'on it'",
			"  echo 'from a pipe' | teams chat send 19:abc...@thread.v2 --body-file -",
			"  teams chat send 19:abc...@thread.v2 --body '<b>done</b>' --html",
		}, "\n"),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			if a.localProfile != "" && compose.html {
				return errors.New("Local365 chat send does not support HTML bodies yet")
			}
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
			var client *teams.Client
			if a.localProfile != "" {
				client, err = a.localTeamsClient()
			} else {
				client, err = a.clientFor(ctx, teams.SendChatMessage)
			}
			if err != nil {
				return err
			}
			if a.wouldChange("send a message to %s", args[0]) {
				return nil
			}

			message, _, err := client.SendMessage(ctx, teams.ChatID(args[0]), draft)
			if err != nil {
				return explainAuthError(err)
			}
			return a.reportAction(actionResult{Action: "send", ID: message.ID.String()},
				"Sent. Id: "+message.ID.String())
		},
	}
	compose.register(cmd)
	return cmd
}

const reactionHelp = `--emoji takes one of the six built-in reactions -- like, heart, laugh,
surprised, sad, angry -- or a tenant's custom reaction name; the service, not
this tool, decides which names it accepts.`

func newChatReactCommand(a *app, set bool) *cobra.Command {
	var emoji string

	use, short, long, example, verb := "react <chat-id> <message-id>", "React to a chat message",
		"React to a chat message.\n\n"+reactionHelp,
		"  teams chat react 19:abc...@thread.v2 1622547684000 --emoji like",
		"react to"
	if !set {
		use, short, long, example, verb = "unreact <chat-id> <message-id>", "Remove a reaction from a chat message",
			"Remove a reaction from a chat message. Removing one that was never set\n"+
				"is not an error.\n\n"+reactionHelp,
			"  teams chat unreact 19:abc...@thread.v2 1622547684000 --emoji like",
			"remove a reaction from"
	}

	cmd := &cobra.Command{
		Use:     use,
		Short:   short,
		Long:    long,
		Example: example,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			if strings.TrimSpace(emoji) == "" {
				return errors.New("--emoji is required")
			}
			reaction := teams.ReactionType(strings.ToLower(strings.TrimSpace(emoji)))

			ctx, cancel := a.context(cmd)
			defer cancel()
			client, err := a.clientFor(ctx, teams.ChangeChat)
			if err != nil {
				return err
			}
			if a.wouldChange("%s message %s in %s with %q", verb, args[1], args[0], reaction) {
				return nil
			}

			action, human := "unreact", "Reaction removed."
			if set {
				action, human = "react", "Reacted."
				_, err = client.SetReaction(ctx, teams.ChatID(args[0]), teams.MessageID(args[1]), reaction)
			} else {
				_, err = client.UnsetReaction(ctx, teams.ChatID(args[0]), teams.MessageID(args[1]), reaction)
			}
			if err != nil {
				return explainAuthError(err)
			}
			return a.reportAction(actionResult{Action: action}, human)
		},
	}
	cmd.Flags().StringVar(&emoji, "emoji", "",
		"reaction name: like, heart, laugh, surprised, sad, angry, or a tenant's custom reaction name")
	return cmd
}

func newChatRmCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "rm <chat-id> <message-id>",
		Aliases: []string{"delete"},
		Short:   "Soft-delete a chat message",
		Long: "Soft-delete a message.\n\n" +
			"This does not make the message disappear: it keeps its id, keeps\n" +
			"appearing in every listing that already reached it, and the service\n" +
			"empties its body. A caller that wants it gone from a rendered\n" +
			"transcript has to filter it out itself.",
		Example: "  teams chat rm 19:abc...@thread.v2 1622547684000",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			client, err := a.clientFor(ctx, teams.ChangeChat)
			if err != nil {
				return err
			}
			if a.wouldChange("soft-delete message %s in %s", args[1], args[0]) {
				return nil
			}
			if _, err := client.SoftDeleteMessage(ctx, teams.ChatID(args[0]), teams.MessageID(args[1])); err != nil {
				return explainAuthError(err)
			}
			return a.reportAction(actionResult{Action: "rm"}, "Deleted.")
		},
	}
	return cmd
}

func newChatMembersCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "members <chat-id>",
		Short: "List a chat's members",
		Long: "List a chat's members directly, which is not truncated at 25 with no\n" +
			"continuation link the way a chat's expanded members are.",
		Example: "  teams chat members 19:abc...@thread.v2",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a.bind(cmd)
			ctx, cancel := a.context(cmd)
			defer cancel()

			client, err := a.clientFor(ctx, teams.ListChats)
			if err != nil {
				return err
			}
			var rows []memberRow
			for member, err := range client.ChatMembers(ctx, teams.ChatID(args[0])) {
				if err != nil {
					return explainAuthError(err)
				}
				rows = append(rows, memberRowOf(member))
			}
			if a.jsonOut {
				return writeJSON(a.out, rows)
			}
			return writeMemberTable(a.out, rows)
		},
	}
	return cmd
}
