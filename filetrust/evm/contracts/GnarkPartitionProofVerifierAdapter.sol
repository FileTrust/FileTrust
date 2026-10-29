// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: GnarkPartitionProofVerifierAdapter
// Purpose:  The protocol's side of the gnark-generated partition-proof verifier.
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
/// partition proof circuit (N=8 sectors, M=4 challenges each → 60 public inputs).
/// Public input layout:
///   [0]         challengeSeedHi
///   [1]         challengeSeedLo
///   [2]         round
///   [3+i]       sectorRootHi[i]        i=0..N-1
///   [3+N+i]     sectorRootLo[i]        i=0..N-1
///   [3+2N+i]    sectorBlockCount[i]    i=0..N-1
///   [3+3N]      challengeCount
///   [4+3N+i*M+j] challengeIndex[i][j]  i=0..N-1, j=0..M-1
/// Total: 4 + 3N + N*M = 4 + 24 + 32 = 60  (for N=8, M=4)
interface IGnarkPartitionProofVerifierFixed60 {
    function verifyProof(
        uint256[8]  calldata proof,
        uint256[60] calldata input
    ) external view;
}

/// @notice Adapter from StorageProofSC generic bytes-based verifier interface
/// to the gnark-generated partition proof verifier (uint256[8] + uint256[60]).
contract GnarkPartitionProofVerifierAdapter is IStorageProofVerifier {
    IGnarkPartitionProofVerifierFixed60 public immutable generatedVerifier;

    uint256 public constant PUBLIC_INPUT_COUNT = 60;

    constructor(address generatedVerifier_) {
        require(generatedVerifier_ != address(0), "GnarkPartitionAdapter: zero verifier");
        generatedVerifier = IGnarkPartitionProofVerifierFixed60(generatedVerifier_);
    }

    function verifyProof(
        bytes    calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        require(publicInputs.length == PUBLIC_INPUT_COUNT, "GnarkPartitionAdapter: bad public input length");

        // gnark proof.WriteRawTo() gives 324 bytes; the Solidity verifier uses
        // the first 256 bytes: A(2) + B(4) + C(2) = uint256[8].
        require(proof.length >= 256, "GnarkPartitionAdapter: proof too short");

        uint256[8] memory proofWords;
        for (uint256 i = 0; i < 8; i++) {
            uint256 word;
            assembly {
                word := calldataload(add(proof.offset, mul(i, 0x20)))
            }
            proofWords[i] = word;
        }

        uint256[60] memory fixedInputs;
        for (uint256 i = 0; i < 60; i++) {
            fixedInputs[i] = publicInputs[i];
        }

        generatedVerifier.verifyProof(proofWords, fixedInputs);
        return true;
    }
}
