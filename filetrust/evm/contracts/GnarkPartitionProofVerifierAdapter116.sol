// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: GnarkPartitionProofVerifierAdapter116
// Purpose:  The protocol's side of the gnark-generated partition-proof verifier, at
//           116 public inputs.
//
// Project:  FileTrust -- decentralized file storage with proven custody
// Author:   Ali Farahpoor
// Company:  Electra Sphere Innovations (ElectraSI.es)
// Location: Barcelona, Spain
// Contact:  support@filetrust.io
//
// Version:      1.0.0
// Release Date: 29 October 2026
//
// Documentation: https://docs.filetrust.io
// Website:       https://www.filetrust.io
//
pragma solidity ^0.8.37;

import "./IStorageProofVerifier.sol";

/// @notice Interface for the gnark-generated Solidity verifier for the
/// partition proof circuit N=16 sectors, M=4 challenges each.
/// Public input layout (N=16, M=4):
///   [0]           challengeSeedHi
///   [1]           challengeSeedLo
///   [2]           round
///   [3+i]         sectorRootHi[i]        i=0..15
///   [19+i]        sectorRootLo[i]        i=0..15
///   [35+i]        sectorBlockCount[i]    i=0..15
///   [51]          challengeCount
///   [52+i*4+j]    challengeIndex[i][j]   i=0..15, j=0..3
/// Total: 4 + 3*16 + 16*4 = 116
interface IGnarkPartitionProofVerifierN16M4 {
    function verifyProof(
        uint256[8]   calldata proof,
        uint256[116] calldata input
    ) external view;
}

/// @notice Adapter from StorageProofSC generic bytes-based verifier interface
/// to the gnark-generated partition proof verifier for N=16, M=4 (116 public inputs).
contract GnarkPartitionProofVerifierAdapter116 is IStorageProofVerifier {
    IGnarkPartitionProofVerifierN16M4 public immutable generatedVerifier;

    uint256 public constant PUBLIC_INPUT_COUNT = 116;

    constructor(address generatedVerifier_) {
        require(generatedVerifier_ != address(0), "GnarkPartitionAdapter116: zero verifier");
        generatedVerifier = IGnarkPartitionProofVerifierN16M4(generatedVerifier_);
    }

    function verifyProof(
        bytes     calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        require(publicInputs.length == PUBLIC_INPUT_COUNT, "GnarkPartitionAdapter116: bad public input length");

        // gnark proof.WriteRawTo() gives 324 bytes; the Solidity verifier uses
        // the first 256 bytes: A(2) + B(4) + C(2) = uint256[8].
        require(proof.length >= 256, "GnarkPartitionAdapter116: proof too short");

        uint256[8] memory proofWords;
        for (uint256 i = 0; i < 8; i++) {
            uint256 word;
            assembly {
                word := calldataload(add(proof.offset, mul(i, 0x20)))
            }
            proofWords[i] = word;
        }

        uint256[116] memory fixedInputs;
        for (uint256 i = 0; i < 116; i++) {
            fixedInputs[i] = publicInputs[i];
        }

        generatedVerifier.verifyProof(proofWords, fixedInputs);
        return true;
    }
}
