package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
	"text/tabwriter"
	"time"

	teams "github.com/albertocavalcante/teams-go"
)

func writeJSON(w io.Writer, value any) error {
	// A nil slice marshals to null, which breaks every pipeline that iterates
	// the output: `jq '.[]'` fails outright on null rather than yielding
	// nothing. An empty result is an empty list, so it is written as one.
	value = emptyNotNull(value)

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	// Chat and channel message bodies legitimately contain <, >, and &;
	// escaping them would corrupt piped output for no benefit outside a
	// browser.
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}

// emptyNotNull replaces a nil slice with an empty one of the same type,
// leaving everything else alone.
func emptyNotNull(value any) any {
	if value == nil {
		return nil
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Slice && reflected.IsNil() {
		return reflect.MakeSlice(reflected.Type(), 0, 0).Interface()
	}
	return value
}

// truncate shortens a string to maxLen runes, marking the cut with an
// ellipsis. Newlines are replaced with spaces first, since they would break
// a table row. A non-positive maxLen returns empty rather than panicking on
// a negative slice bound -- every caller in this package passes a fixed
// column width, but a value that can come from arithmetic on a flag deserves
// a defined answer for the input nothing here is expected to produce.
func truncate(value string, maxLen int) string {
	value = strings.ReplaceAll(value, "\n", " ")
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxLen {
		return value
	}
	if maxLen <= 3 {
		return string(runes[:maxLen])
	}
	return string(runes[:maxLen-3]) + "..."
}

// actionResult is what a command that changes a chat or channel reports to a
// script: whether it happened and, when the service minted one, the
// identifier a follow-up command needs.
type actionResult struct {
	Action string `json:"action"`
	ID     string `json:"id,omitempty"`
}

// reportAction prints the outcome of a mutating command in whichever form was
// asked for.
func (a *app) reportAction(result actionResult, human string) error {
	if a.jsonOut {
		return writeJSON(a.out, result)
	}
	fmt.Fprintln(a.out, human)
	return nil
}

// chatRow is the flattened shape used for both the chats table and --json, so
// the two never drift apart.
type chatRow struct {
	ID string `json:"id"`
	// Unread is a pointer because "read" and "never fetched a read mark" are
	// different facts; see [teams.Chat.Unread]. A nil here renders as blank,
	// not as read.
	Unread  *bool  `json:"unread"`
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Preview string `json:"preview,omitempty"`
}

func chatRowOf(chat teams.Chat, self teams.UserID) chatRow {
	row := chatRow{
		ID:   chat.ID.String(),
		Name: chat.DisplayName(self),
		Kind: string(chat.Type),
	}
	if unread, known := chat.Unread(); known {
		row.Unread = &unread
	}
	if chat.LastMessagePreview != nil {
		row.Preview = strings.TrimSpace(chat.LastMessagePreview.Body.Text())
	}
	return row
}

// writeChatTable renders chats as aligned columns. The id is last because
// [Client.GetMessage] and friends take it as their next argument; everything
// else about the row is for a person to read, not to paste back in.
func writeChatTable(w io.Writer, rows []chatRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No chats.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, " \tNAME\tKIND\tPREVIEW\tID")
	for _, row := range rows {
		marker := " "
		if row.Unread != nil && *row.Unread {
			marker = "*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			marker, truncate(row.Name, 32), row.Kind, truncate(row.Preview, 48), row.ID)
	}
	return tw.Flush()
}

// messageRow is the flattened shape used for both the message table and
// --json. There is no ID column here: unlike a chat, team, or channel, a
// message id is not the next command's argument for the common case of just
// reading a transcript, and a chat message id is long enough to wreck a
// table's alignment for a column most output never uses. --json still
// carries it, for the commands (react, rm) that do need it.
type messageRow struct {
	ID           string    `json:"id"`
	ReplyToID    string    `json:"replyToId,omitempty"`
	Time         time.Time `json:"time"`
	ModifiedTime time.Time `json:"modifiedTime,omitzero"`
	Sender       string    `json:"sender"`
	Text         string    `json:"text"`
	Edited       bool      `json:"edited,omitempty"`
	Deleted      bool      `json:"deleted,omitempty"`
}

func messageRowOf(message teams.ChatMessage) messageRow {
	sender := message.From.Name()
	if message.IsSystemEvent() {
		sender = "system"
	}
	return messageRow{
		ID:           message.ID.String(),
		ReplyToID:    message.ReplyToID.String(),
		Time:         message.CreatedDateTime,
		ModifiedTime: message.LastModifiedDateTime,
		Sender:       sender,
		Text:         message.PlainText(),
		Edited:       message.Edited(),
		Deleted:      message.Deleted(),
	}
}

// writeMessageTable renders messages as aligned columns, with no id column;
// see [messageRow].
func writeMessageTable(w io.Writer, rows []messageRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No messages.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, " \tTIME\tSENDER\tTEXT")
	for _, row := range rows {
		marker := " "
		switch {
		case row.Deleted:
			marker = "~"
		case row.Edited:
			marker = "*"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			marker, row.Time.Local().Format("2006-01-02 15:04"), truncate(row.Sender, 24), truncate(row.Text, 100))
	}
	return tw.Flush()
}

// teamRow is the flattened shape used for both the teams table and --json.
type teamRow struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Archived    bool   `json:"archived,omitempty"`
}

func teamRowOf(team teams.Team) teamRow {
	return teamRow{
		ID:          team.ID.String(),
		DisplayName: team.DisplayName,
		Description: team.Description,
		Archived:    team.IsArchived,
	}
}

// writeTeamTable renders joined teams as aligned columns. The id is last: it
// is what `teams channels` takes next.
func writeTeamTable(w io.Writer, rows []teamRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No teams.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, " \tNAME\tDESCRIPTION\tID")
	for _, row := range rows {
		marker := " "
		if row.Archived {
			marker = "!"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", marker, truncate(row.DisplayName, 32), truncate(row.Description, 48), row.ID)
	}
	return tw.Flush()
}

// channelRow is the flattened shape used for both the channels table and
// --json.
type channelRow struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Membership  string `json:"membershipType,omitempty"`
	Archived    bool   `json:"archived,omitempty"`
}

func channelRowOf(channel teams.Channel) channelRow {
	return channelRow{
		ID:          channel.ID.String(),
		DisplayName: channel.DisplayName,
		Description: channel.Description,
		Membership:  string(channel.Membership),
		Archived:    channel.IsArchived,
	}
}

// writeChannelTable renders channels as aligned columns. The id is last: it
// is what `teams channel read` takes next.
func writeChannelTable(w io.Writer, rows []channelRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No channels.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, " \tNAME\tTYPE\tID")
	for _, row := range rows {
		marker := " "
		if row.Archived {
			marker = "!"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", marker, truncate(row.DisplayName, 32), row.Membership, row.ID)
	}
	return tw.Flush()
}

// memberRow is the flattened shape used for both the members table and
// --json.
type memberRow struct {
	DisplayName string   `json:"displayName"`
	Email       string   `json:"email,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	UserID      string   `json:"userId"`
}

func memberRowOf(member teams.ConversationMember) memberRow {
	roles := make([]string, 0, len(member.Roles))
	for _, role := range member.Roles {
		roles = append(roles, string(role))
	}
	return memberRow{
		DisplayName: member.DisplayName,
		Email:       member.Email,
		Roles:       roles,
		UserID:      member.UserID.String(),
	}
}

// writeMemberTable renders members as aligned columns. The user id is last:
// it is what `teams presence` takes.
func writeMemberTable(w io.Writer, rows []memberRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No members.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tEMAIL\tROLES\tUSER ID")
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
			truncate(row.DisplayName, 28), row.Email, strings.Join(row.Roles, ","), row.UserID)
	}
	return tw.Flush()
}

// searchRow is the flattened shape used for both the search table and
// --json. ChatID is empty for a channel-message hit: react, unreact, and rm
// are chat-only operations, so there is nothing to chain a channel hit into.
type searchRow struct {
	ID     string `json:"id"`
	ChatID string `json:"chatId,omitempty"`
	Rank   int32  `json:"rank"`
	Sender string `json:"sender"`
	Text   string `json:"text"`
}

func searchRowOf(hit teams.SearchHit) searchRow {
	return searchRow{
		ID:     hit.Message.ID.String(),
		ChatID: hit.Message.ChatID.String(),
		Rank:   hit.Rank,
		Sender: hit.Message.From.Name(),
		Text:   hit.Message.PlainText(),
	}
}

// writeSearchTable renders search hits as aligned columns. Both ids are
// last -- chat id, then message id -- since `teams chat react` and `teams
// chat rm` need both together.
func writeSearchTable(w io.Writer, rows []searchRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(w, "No matches.")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SENDER\tTEXT\tCHAT ID\tID")
	for _, row := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", truncate(row.Sender, 24), truncate(row.Text, 72), row.ChatID, row.ID)
	}
	return tw.Flush()
}

// presenceRow is the flattened shape used for both the presence output and
// --json.
type presenceRow struct {
	ID           string `json:"id,omitempty"`
	Availability string `json:"availability"`
	Activity     string `json:"activity,omitempty"`
	OutOfOffice  bool   `json:"outOfOffice,omitempty"`
}

func presenceRowOf(presence teams.Presence) presenceRow {
	row := presenceRow{
		ID:           presence.ID.String(),
		Availability: string(presence.Availability),
		Activity:     string(presence.Activity),
	}
	if presence.OutOfOffice != nil {
		row.OutOfOffice = presence.OutOfOffice.IsOutOfOffice
	}
	return row
}

// writePresenceTable renders one presence as an aligned single-row table,
// matching every other listing in this package rather than a one-off format.
func writePresenceTable(w io.Writer, row presenceRow) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "AVAILABILITY\tACTIVITY\tOUT OF OFFICE\tID")
	outOfOffice := "no"
	if row.OutOfOffice {
		outOfOffice = "yes"
	}
	fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", row.Availability, row.Activity, outOfOffice, row.ID)
	return tw.Flush()
}
