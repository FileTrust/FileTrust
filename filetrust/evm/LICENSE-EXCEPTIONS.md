# EVM workspace licensing

FileTrust-owned protocol contracts marked `FSL-1.1-ALv2` use the Functional
Source License, Version 1.1, with the Apache 2.0 Future License. The complete
terms are in `LICENSE` in this directory. This is the same license used for
FileTrust-owned code in the parent project.

The license change does not revoke any MIT permissions already granted for
earlier copies. FSL is Fair Source; it must not be described as an immediate
open-source license. Its Apache 2.0 future grant follows the timing in `LICENSE`.

## MIT exceptions

The following checked-in sources retain their existing MIT terms and attribution:

| Source | Attribution or purpose |
| --- | --- |
| `contracts/StorageProofGnarkVerifier.sol` | Generated from Remco Bloemen's Groth16 verifier template |
| `contracts/PartitionVerifierN16D28.sol` | Generated from the same template |
| `contracts/PartitionStorageProofGnarkVerifier.sol` and `PartitionStorageProofGnarkVerifier512.sol` | Generated from the same template |
| `contracts/BN254MathLib.sol`, `PublicInputMSMLib.sol` and `PublicInputMSMLib512.sol` | Extracts from the same template |
| `contracts/zkdkg/*.sol` | Generated verifiers and the pairing library; preserve their existing notices, including Christian Reitwiessner's attribution where present |

OpenZeppelin dependencies also retain their MIT license. The FSL declaration
for this workspace does not replace dependency licenses or copyright notices.
Include the applicable dependency notices when distributing compiled contracts.

The Cosmos EVM fork outside this workspace remains subject to its Apache 2.0
license and upstream `NOTICE`. This document does not relicense that code.

## MIT license text

Copyright holders and attribution are identified in the corresponding source
files and upstream dependency notices; those notices must be retained.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
