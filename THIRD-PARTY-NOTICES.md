# Third-party notices

## Cosmos EVM and the Cosmos stack

The chain is derived from Cosmos EVM v0.7.0. Keep the upstream Apache-2.0
`LICENSE`, `NOTICE`, source attribution and the more specific original file
notices. `FILETRUST_UPSTREAM.md` records the upstream lineage and FileTrust's
distribution changes.

`x/erc20/keeper/proposals.go` and `x/erc20/types/utils.go` retain their original
LGPL-3.0-only headers. Full LGPL and referenced GPL texts are under `LICENSES/`.
The pinned Cosmos go-ethereum library is also LGPL-covered; preserve its
conditions and source/rebuild access when distributing a linked node binary.
Other Go dependencies retain the licenses of their pinned upstream modules.

## Solidity verifier components — MIT

The Groth16 verifier template is attributed to Remco Bloemen. The generated
storage and partition verifiers and extracted `BN254MathLib`,
`PublicInputMSMLib` and `PublicInputMSMLib512` retain their MIT terms and source
attribution.

The pairing library and generated share/PRE verifiers in
`filetrust/evm/contracts/zkdkg/` retain their MIT notices, including Christian
Reitwiessner's 2017 copyright where present. FileTrust's FSL does not replace
those terms. The complete MIT text and path mapping are in
`filetrust/evm/LICENSE-EXCEPTIONS.md`; the MIT text also applies to other included
source files explicitly marked MIT, including the upstream ERC20 contract source.

## OpenZeppelin Contracts — MIT

The FileTrust contract workspace pins OpenZeppelin Contracts 5.7.0. The upstream
embedded ERC20 artifact has its own source and build manifest under `contracts/`,
whose lockfile uses OpenZeppelin 4.9.6. These are distinct build inputs.
OpenZeppelin's notices remain applicable to redistributed source and compiled
contracts containing its code.

## Specifications

The FileTrust-authored Baby Jubjub and secp256k1 helpers identify their curve
specifications in source. Following public curve parameters does not replace
the license of third-party implementation code.
