# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-10-22

### Added
- Proton Drive write tools on the MCP server: `drive_upload`, `drive_mkdir`,
  `drive_move`, `drive_rename`, `drive_trash`, `drive_share_link` and
  `drive_unshare_link`. The server now exposes 18 tools (was 8). The library
  already supported these operations; this wires them through to MCP clients.
- `drive_share_link` returns a public link whose URL is the whole secret (the
  password rides in the fragment), so its tool description tells an agent to use
  it only for files the person means to share.
- `send_message` now takes `attachments`, a list of local file paths to attach,
  so an agent can download a file with `drive_download` and send it on.
- Send-policy tools the agent can read and change: `email_policy_status`,
  `email_allow` (set a recipient allowlist, open it, or block all sends) and
  `set_send_confirmation` (a soft two-step rule where `confirm=true` sends). The
  server now exposes 18 tools.
- A `protonlite policy` CLI for the **hard** controls a person sets out of band,
  which the agent cannot loosen: `policy show`, `policy ceiling <addrs>` (a
  recipient ceiling the allowlist tool cannot exceed) and `policy require-confirm
  on|off`. When hard confirmation is on (via the CLI or the env vars
  `PROTON_ALLOWED_RECIPIENTS` / `PROTON_REQUIRE_SEND_CONFIRMATION`), `send_message`
  is refused outright for the agent -- the `confirm` argument cannot lift it -- and
  a person sends from the terminal with `protonlite send`.
- `drive_move`/`drive_rename` report the plaintext name (not the opaque link id),
  and `drive_list` labels its size as the encrypted on-disk size, so a size check
  after a round trip does not look like corruption.

## [0.1.2] - 2026-10-22

### Added
- `protonlite mcp` subcommand that runs the MCP server over stdio. It starts the
  same server as the `protonlite-mcp` entry point, so
  `uvx --from "protonlite[mcp]" protonlite mcp` runs it without a local install.
- Listing on the official MCP registry. The README carries an `mcp-name` marker,
  which the registry reads to verify ownership of the PyPI package.

## [0.1.1] - 2026-10-22

### Changed
- SEO metadata. Broadened the PyPI keywords (`protonmail`, `proton-mail`,
  `python`, `mcp`, and more) and reworded the README opening so Proton Mail,
  Python and the MCP server are discoverable on PyPI and GitHub.

## [0.1.0] - 2026-10-22

### Added
- Initial release. A pure-Python Proton Mail, Calendar, Contacts and Drive client
  and CLI that works on a free plan with no Proton Mail Bridge, with the
  end-to-end crypto ported from Proton's MIT-licensed Go libraries.
- Optional MCP server (`pip install "protonlite[mcp]"`) exposing `list_messages`,
  `read_message`, `search_messages`, `send_message`, `calendar`, `contacts`,
  `drive_list` and `drive_download`.

[0.1.3]: https://github.com/Maytrella007/protonlite/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/Maytrella007/protonlite/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Maytrella007/protonlite/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Maytrella007/protonlite/releases/tag/v0.1.0
