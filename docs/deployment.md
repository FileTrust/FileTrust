# Protocol deployment

These instructions describe deployment tooling for a chain you control. They do
not identify an existing mainnet or contain production network settings.

## Prepare

Build the node and contracts as described in the root README. Start an isolated
local chain, or configure your own reviewed network endpoint.

```sh
cd filetrust/evm
cp deploy.env.example deploy.env
```

Edit the local, ignored `deploy.env`:

- Set `FILETRUST_COSMOS_RPC_URL` to your endpoint.
- Set `FILETRUST_DEPLOY_KEY_FILE` to an owner-only regular file outside Git that
  contains your funded deployment key. Use mode `0600`; never paste the key into
  configuration examples, command arguments, issues or logs.
- Set `FILETRUST_DEPLOY_MAX_DEBIT_WEI` to a reviewed, positive allowance in aftu.
  The deployment reserves worst-case transaction costs before broadcasting and
  stops when the allowance is exhausted. This is not an estimate of actual cost.
- Review the immutable circuit shapes, proof periods and economic parameters.
  They must match the proof parameters used by participating nodes.

The local chain helper generates fresh accounts in its ignored node home. To
fund a local rehearsal, use a locally generated account you control; no shared
seed or deployer identity is distributed with the repository.

For a future production deployment, select `FILETRUST_DEPLOY_PROFILE=mainnet`
and supply a treasury contract, proposer multisig and independent canceller.
The deployment rejects missing or unsafe governance configuration. The profile
name alone does not make a network production-ready.

## Deploy and record

```sh
set -a
. ./deploy.env
set +a
npm run deploy
npm run manifest
```

Run the commands from `filetrust/evm/`. Compilation settings are checked against
the source before deployment. The generated files are:

- `filetrust/evm/deployed_addresses.json`
- `filetrust/evm/network_config_bundle.json`
- `filetrust/evm/deployment_manifest.json`
- `reports/deployment/`, containing transaction records, the allowance journal
  and ownership handover information

They are ignored by Git and belong to that deployment. Review address and
infrastructure information before distributing any generated records. For an
intentionally public network, verified contract addresses and runtime hashes
are public facts; signing keys and operator infrastructure remain private.

Do not remove an allowance journal to bypass a failed or uncertain deployment.
Review chain state and the existing transaction records before retrying.

## Complete governance ownership

The deployment records the ownership acceptance batch. On a local profile it
can schedule the batch using the deployer; on a production profile the proposer
multisig must schedule it. After the configured timelock delay:

```sh
npm run handover
```

Use a signer authorized for the selected governance configuration. Verify the
resulting owner and pending-owner fields before considering deployment complete.
Generate and review the final manifest against the final on-chain state. Client
installation and client configuration are managed separately; these scripts do
not modify sibling application checkouts.
