# Live Teams tenant smoke check

Run this only with a work or school account that can access a known chat and
channel. The checks are read-only after sign-in. Keep raw JSON local: messages
may contain private content, and a successful run does not require publishing
tokens, message bodies, chat IDs, or channel IDs.

Record the CLI version or commit, date, tenant type, granted scope names, and
pass/fail for each row. A local fake Graph test cannot close this service
compatibility gate.

## Prerequisites

1. Install the released CLI with `go install github.com/albertocavalcante/teams-cli/cmd/teams@latest`.
2. Run `teams login`, then `teams whoami` and `teams scopes`. Confirm the
   account is from a work or school tenant. Channel reads require a channel
   message permission granted by a tenant administrator; `teams scopes` names
   missing permissions.
3. Choose a quiet chat with a known message older than 24 hours and a known
   recently changed message if available. Choose a distinctive, already
   indexed search phrase that matches a known channel message and few other
   messages. Choose a channel with known roots and replies. If possible,
   choose a channel whose first two roots include a thread with more than 200
   replies to exercise its continuation.

## Read checks

Replace the placeholders with IDs from the account. Use `--json` and save any
output only to a private local location if it must be inspected in detail.

| Check | Command | Pass condition |
| --- | --- | --- |
| Chat list | `teams chats --limit 2 --json` | JSON is an array with at most two chats. |
| Chat window | `teams chat read <chat-id> --since 24h --limit 0 --json` | Every returned message is within the requested created-time window; a known older message is absent. |
| Modified window | `teams chat read <chat-id> --order modified --since 24h --limit 0 --json` | Every returned `modifiedTime` is within the window, including a known changed older message if available. `time` remains its creation time. |
| Channel roots | `teams channel read <team-id> <channel-id> --limit 2 --json` | At most two roots are returned; replies are absent. |
| Channel replies | `teams channel read <team-id> <channel-id> --limit 2 --replies --json` | At most two rows lack `replyToId`; reply rows name the selected root in `replyToId`, and all visible replies to those roots appear. A thread over 200 replies exercises `replies@odata.nextLink`. |
| Search | `teams search '<distinctive known phrase>' --limit 0 --json` | JSON remains an array. With only chat permission, stderr warns that channel coverage may be incomplete. With channel permission, the known indexed channel hit is present. |

Search indexing may lag writes, so use a stable, already indexed phrase rather
than a message sent moments ago. The channel checks cannot pass on a tenant
without the necessary administrator grant; record them as unavailable, not as
successes. If any command fails, retain the HTTP status, request ID, and
redacted error text for diagnosis. Do not copy access tokens or raw message
content into an issue or CI log.
