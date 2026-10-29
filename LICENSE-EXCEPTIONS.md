# License scope

The repository includes components with different licenses. A public source
repository does not make all included code available under one license.

| Component | Terms |
| --- | --- |
| Cosmos EVM source, generated bindings and embedded upstream artifacts | Apache-2.0, or the more specific original file notice; see `LICENSE` and `NOTICE` |
| FileTrust-owned protocol contracts marked `FSL-1.1-ALv2` | `LICENSE-FILETRUST` and `filetrust/evm/LICENSE` |
| FileTrust-owned additions under `filetrust/` and the local-node helper | FSL-1.1-ALv2 unless a more specific file notice applies |
| Generated Groth16/share verifiers, extracted verifier libraries and pairing code | Existing MIT terms; see `filetrust/evm/LICENSE-EXCEPTIONS.md` |
| OpenZeppelin and other downloaded dependencies | Their own licenses and notices; they are not relicensed by FileTrust |
| `x/erc20/keeper/proposals.go` and `x/erc20/types/utils.go` | Original LGPL-3.0-only notices; full LGPL and referenced GPL texts are in `LICENSES/` |

Preserve copyright notices, the upstream Apache license and NOTICE, and the
applicable MIT notices when redistributing source or compiled contracts.
Previously granted MIT permissions for earlier copies are not revoked.

The node also links the pinned Cosmos go-ethereum fork, whose library packages
retain LGPL terms. The source manifests and local replacement preserve the
ability to replace that dependency and rebuild. Keep the applicable license
texts and make corresponding source available when distributing node binaries;
this initial publication distributes source, not prebuilt binaries.
