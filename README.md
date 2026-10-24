# teams-cli

`teams` reads and sends Microsoft Teams chats and channel messages from the command line. It uses `msauth-go` for delegated sign-in, `msgraph-go` for HTTP, and `teams-go` for Teams behavior.

Teams endpoints require a Microsoft work or school account. Tokens are cached in the OS keychain by default. Use `--token-cache-dir` for the encrypted file store on a headless machine.

## Install

```sh
go install github.com/albertocavalcante/teams-cli/cmd/teams@latest
```

## Use

```sh
teams login
teams chats --unread
teams chat read <chat-id> --since 24h
teams chat send <chat-id> --body 'On it.'
teams teams
teams channels <team-id>
teams channel read <team-id> <channel-id> --replies
teams search 'quarterly report' --json
teams presence
```

`teams scopes` shows what the current sign-in permits. Chat reads and sends can use delegated permissions a user can consent to. Several team, channel, and other-user presence reads require tenant administrator consent; the CLI names the missing permission instead of repeating a sign-in that cannot grant it.

With a Local365 profile, `teams --local-profile <profile.json> whoami` and `teams --local-profile <profile.json> scopes` use the synthetic persona instead of Microsoft sign-in. Local `scopes` reports both the persona's granted Graph permissions and whether each capability is implemented locally. A grant alone does not make an unfinished local command available. `--want` explains how to change synthetic grants in the Local365 seed; it never suggests `teams login`. Other commands currently refuse local mode before reaching Microsoft authentication.

`teams channel read` lists root messages by each thread's latest change. `--replies` includes every reply for each selected root, following the thread's continuation links. `--limit` counts roots. `teams search` warns when its results may omit channels because the sign-in lacks channel-message read permission. `--json` emits structured output, and `--dry-run` previews commands that change data. Every command has examples in `--help`.

Message JSON uses `time` for creation and includes `modifiedTime` when Graph provides it, so the timestamp used by `chat read --order modified --since` is visible. Channel replies include `replyToId` to identify their root.

The CLI currently covers chat and channel messaging, members, search, reactions, soft deletion, and presence. Creating chats, managing teams or channels, hosted content, meetings, calls, tabs, and Shifts are outside the current command surface.

## Develop

```sh
just ci
```

The local tests use a fake Graph server. Live tenant checks are still needed for service compatibility, especially for administrator-granted channel operations.
Use the [live tenant smoke check](docs/live-tenant-smoke.md) when a suitable account is available.
