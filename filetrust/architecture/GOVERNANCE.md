# FileTrust EVM governance

## Public deployment authority

`FileTrustTimelock` owns every contract that exposes privileged protocol
maintenance. The deployment script deploys the timelock first, completes all
initial wiring, binds the slashing and reward rights once, locks the
ReputationManager protocol list, and then hands every contract to the timelock.

The hand-over takes two steps for the OpenZeppelin-owned contracts
(StakingManager, RewardManager, ReputationManager, GuardianRegistry,
AccessControlFT, GuardianWorkReward, GuardianShareProof): the transfer only names
the timelock as pending owner, and the timelock takes over by executing one
`acceptOwnership` batch after its delay. The batch is written to
`reports/deployment/governance_handover.json`; in the local profile the
deployer proposes and schedules it at once. Once it is ready, anyone runs
`scripts/accept_governance_handover.js`, which executes it and verifies every
owner. Until then the deployer still owns those contracts. The custom-owned
contracts move in one verified step. None of them can be left without an owner.

The default delay is 172800 seconds (48 hours). Execution is open by default:
anyone may execute an operation after its delay, but cannot create one. Set
`GOVERNANCE_EXECUTOR_ADDRESS` only if execution must be closed. Each proposer may
cancel its own proposals, and `GOVERNANCE_CANCELLER_ADDRESS` names an independent
account that may cancel any scheduled operation without proposing any. The
timelock has no external administrator; role and delay changes must pass
through the timelock itself.

Slashed stake goes to the protocol treasury, which must be a contract. In the
local profile it is the timelock; it is never the deployer's wallet.

`FILETRUST_DEPLOY_PROFILE=mainnet` takes no defaults and stops before the first
transaction unless all of these are set, none of them to the deployer, the
canceller independent of the proposer, and the treasury and proposer already
deployed as contracts:

```bash
FILETRUST_DEPLOY_PROFILE=mainnet
FILETRUST_TREASURY_ADDRESS=0x...      # treasury contract
GOVERNANCE_PROPOSER_ADDRESS=0x...     # proposer multisig
GOVERNANCE_CANCELLER_ADDRESS=0x...    # independent canceller
GOVERNANCE_DELAY_SECONDS=172800       # at least 48 hours
```

## Selective upgrades

Cryptographic verifier contracts are immutable. Their callers hold the active
verifier address, and the timelock can select a reviewed replacement after the
public delay. This covers storage proofs, partition proofs, DKG share proofs,
share possession proofs, and PRE partial proofs. Every switch emits an event,
so the complete verifier history remains observable.

The state-bearing FileTrust contracts are deliberately not generic delegatecall
proxies in version one. A proxy would permit replacement of all user-state
logic and materially increase governance power. A state-bearing replacement
therefore requires a separately reviewed migration or the Phase 2 Cosmos
module upgrade process. This is the selective boundary: proof algorithms may
be replaced through stable governed callers, while user records cannot be
silently reinterpreted by changing a proxy implementation.

Before scheduling any operation, publish its target, calldata, salt, rationale,
source commit, audit result, and testnet transaction. Monitor timelock schedule,
cancel, and execute events from an independent indexer.
