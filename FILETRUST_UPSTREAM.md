# Upstream provenance

FileTrust's chain implementation is derived from the official Cosmos EVM source:

- Repository: https://github.com/cosmos/evm
- Baseline tag: `v0.7.0`
- Baseline commit: `f4ab9a3e3fbe353468327d5cacda94b33b41ed11`
- Upstream license: Apache-2.0; retained in `LICENSE` and `NOTICE`

FileTrust customizes the application entry points, address prefix and chain
configuration in `evmd/cmd/evmd/`, `evmd/config/` and `evmd/genesis.go`.
The standalone Makefile builds `filetrustd`. The local-test command generates
fresh accounts rather than embedding shared development seed phrases, and does
not print them by default. FileTrust's protocol contracts and verifier adapters
are under `filetrust/evm/`.

This distribution retains the Go packages required by the node command, their
embedded artifacts and protobuf sources. Upstream development suites, unused
packages and maintenance workflows are omitted. Required helpers whose package
paths contain `testutil` or `tests/network` remain because the node imports them.
The complete upstream framework and its development tools remain available from
the official repository.

FileTrust-owned protocol sources use FSL-1.1-ALv2. Generated verifiers and
extracted libraries retain their MIT notices. See `LICENSE-EXCEPTIONS.md` and
`filetrust/evm/LICENSE-EXCEPTIONS.md` for the detailed scope. The upstream license
and attribution are not replaced by the FileTrust license.
