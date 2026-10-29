# FileTrust chain policy

- Native supply: exactly 10,000,000,000 FTU at genesis.
- Base denomination: `aftu`; display denomination: `ftu`; precision: 18.
- Inflation: disabled; the mint module is capped at the genesis supply.
- Local Cosmos chain ID: `filetrust_31338-1`.
- Local EVM chain ID: `31338`.
- Address prefix: `filetrust`.
- Initial EVM base fee and floor: 1,000,000 wei (0.001 gwei).
- Fee movement: gradual, configured with denominator 100.
- Local maximum block gas: 100,000,000.
- Governance and coordinated software upgrades remain enabled.
- Public chain IDs, allocations, governance durations, and validator set must
  be frozen in a reviewed public genesis document; local values are not
  mainnet defaults.
