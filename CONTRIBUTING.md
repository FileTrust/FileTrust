# Contributing

Open an issue describing the problem before substantial changes. Submit focused
pull requests with a clear description of the behavior and validation performed.
Use signed commits and conventional commit titles.

Build the node with `make build`. Build contracts with `make contracts`, and run
`make check` to inspect the files selected for publication. Explain any additional
verification appropriate to your change; the internal development test suites
are not included in this minimal distribution.

Keep manifests and lockfiles in sync. Do not change verifier constants or replace
proof parameters as part of an unrelated fix. Changes to consensus state or
contract interfaces need explicit migration and compatibility documentation.

Never commit a wallet, seed phrase, deployment key, validator identity, operator
environment, node state, log or backup. Use empty required fields and loopback or
reserved example endpoints in configuration templates.

Preserve the license and copyright notices applicable to each component.
