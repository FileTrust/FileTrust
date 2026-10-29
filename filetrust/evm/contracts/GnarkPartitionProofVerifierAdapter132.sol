// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: GnarkPartitionProofVerifierAdapter132
// Purpose:  The protocol's side of the gnark-generated partition-proof verifier, at
//           132 public inputs.
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

/// @notice Interface for the gnark-generated Solidity verifier for the W3-fixed
/// partition proof circuit: N=16 sectors, M=4 challenges each, with commitment leaf.
/// Public input layout (N=16, M=4) — W3 fix adds N=16 pieceCommitment inputs:
///   [0]            challengeSeedHi
///   [1]            challengeSeedLo
///   [2]            round
///   [3+i]          sectorRootHi[i]        i=0..15
///   [19+i]         sectorRootLo[i]        i=0..15
///   [35+i]         sectorBlockCount[i]    i=0..15
///   [51]           challengeCount
///   [52+i*4+j]     challengeIndex[i][j]   i=0..15, j=0..3
///   [116+i]        pieceCommitment[i]     i=0..15  ← W3 fix
/// Total: 4 + 4*16 + 16*4 = 132
interface IGnarkPartitionProofVerifierN16M4W3 {
    function verifyProof(
        uint256[8]   calldata proof,
        uint256[132] calldata input
    ) external view;
}

/// @notice Adapter from StorageProofSC generic bytes-based verifier interface to the
/// gnark-generated partition proof verifier for N=16, M=4, W3 fix (132 public inputs).
contract GnarkPartitionProofVerifierAdapter132 is IStorageProofVerifier {
    IGnarkPartitionProofVerifierN16M4W3 public immutable generatedVerifier;

    uint256 public constant PUBLIC_INPUT_COUNT = 132;

    constructor(address generatedVerifier_) {
        require(generatedVerifier_ != address(0), "GnarkPartitionAdapter132: zero verifier");
        generatedVerifier = IGnarkPartitionProofVerifierN16M4W3(generatedVerifier_);
    }

    function verifyProof(
        bytes     calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        require(publicInputs.length == PUBLIC_INPUT_COUNT, "GnarkPartitionAdapter132: bad public input length");
        require(proof.length >= 256, "GnarkPartitionAdapter132: proof too short");

        uint256[8] memory proofWords;
        for (uint256 i = 0; i < 8; i++) {
            uint256 word;
            assembly {
                word := calldataload(add(proof.offset, mul(i, 0x20)))
            }
            proofWords[i] = word;
        }

        uint256[132] memory fixedInputs;
        for (uint256 i = 0; i < 132; i++) {
            fixedInputs[i] = publicInputs[i];
        }

        generatedVerifier.verifyProof(proofWords, fixedInputs);
        return true;
    }
}
