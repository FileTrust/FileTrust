# FileTrust blockchain

FileTrust is a Cosmos SDK and Cosmos EVM blockchain with a native FTU coin,
Ethereum JSON-RPC, and Solidity contracts for storage proofs, Guardian DKG,
VaultKeeper registration, staking, rewards and protocol governance.

This repository contains the chain implementation and its authoritative contract
and verifier sources. This initial source publication is for review and local
development. A production network release needs a separately reviewed genesis,
validator set and network configuration; none is supplied here.

## Build the node

Use Go 1.25.9 or newer, a C compiler, Make and Git. CGO is required. Linux is the
initial build target.

```sh
git clone https://github.com/FileTrust/FileTrust.git
cd FileTrust
make build
./build/filetrustd version
```

The root Go module contains the Cosmos EVM implementation. `evmd/` is the
application module and uses a local replacement pointing to its parent. The
upstream Go module names are retained deliberately; build this checkout rather
than installing it under an unrelated Go import path.

## Build the contracts

Use Node.js 24 and npm. The dependency lockfile, Solidity version and compiler
settings are committed so another checkout can use the same build inputs.

```sh
cd filetrust/evm
npm ci --ignore-scripts
npm run compile
npm run check:sizes
```

Generated artifacts and dependency directories are not source-control inputs.
The verifier constants in the checked-in Solidity sources belong to specific
proof parameters. Do not generate a new trusted setup to reproduce an existing
deployment; that creates different parameters and incompatible proofs.

## Run an isolated local chain

The local helper additionally requires Bash, Python 3 and jq:

```sh
./scripts/local_filetrust_node.sh --init-only
./scripts/local_filetrust_node.sh --no-build
```

It creates fresh local validator and development identities under `.local/` and
uses loopback JSON-RPC at `http://127.0.0.1:8545`. The local EVM chain ID is
`31338`; the Cosmos chain ID is `filetrust_31338-1`. Identity files and chain
state are ignored by Git. The test keyring is suitable only for isolated local
development. Create and secure real validator keys independently when operating
a reviewed public network.

## Deploy the protocol

See [deployment instructions](docs/deployment.md). The included environment
template contains public protocol parameters and empty operator inputs. Signing
keys, treasury choices and governance accounts must be supplied by the operator.
Never commit them.

Deployment generates addresses, ABI bundles, ownership handover records and a
manifest that clients can use to check runtime code and contract wiring. Those
records belong to a particular deployment and are not bundled as defaults.

## Source layout

| Path | Purpose |
| --- | --- |
| `evmd/` | Chain application and `filetrustd` command |
| `x/`, `ante/`, `precompiles/`, `rpc/` | Cosmos EVM execution, transaction processing and APIs |
| `proto/`, `api/` | Protocol definitions and required generated bindings |
| `contracts/` | Upstream contract sources and embedded artifacts required by Go packages |
| `filetrust/evm/` | FileTrust protocol contracts, verifiers and minimal deployment support |
| `filetrust/architecture/` | Chain policy and governance model |
| `testutil/`, `evmd/tests/network/` | Upstream helpers imported by the node command itself |

The two contract directories serve different purposes and are not mirrored
copies. Internal test suites, benchmarks, temporary probes and server-management
tools are outside this minimal source distribution.

## Security and contributions

Run `make check` before committing. CI also scans Git history and builds the
node and contracts. See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[CONTRIBUTING.md](CONTRIBUTING.md) for change guidance.

## Licensing and upstream attribution

FileTrust-owned protocol code is **FSL-1.1-ALv2**, a Fair Source license with an
Apache 2.0 future grant; see [LICENSE-FILETRUST](LICENSE-FILETRUST). Upstream
Cosmos EVM code retains Apache-2.0 in [LICENSE](LICENSE) and [NOTICE](NOTICE).
Third-party verifiers and libraries retain MIT and their original attribution.
See [LICENSE-EXCEPTIONS.md](LICENSE-EXCEPTIONS.md) for the scope of each license.

This is a public source repository; FSL-covered code is not immediately licensed
as open source. [FILETRUST_UPSTREAM.md](FILETRUST_UPSTREAM.md) records the upstream
source lineage. No private repository history is part of this repository.
