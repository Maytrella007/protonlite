# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.2]: https://github.com/Maytrella007/protonlite/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/Maytrella007/protonlite/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Maytrella007/protonlite/releases/tag/v0.1.0
