// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: GnarkStorageProofVerifierAdapter
// Purpose:  The protocol's side of the gnark-generated storage-proof verifier.
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

/// @notice Interface for gnark-generated Solidity verifier.
/// The generated contract is usually named Verifier and has:
/// verifyProof(uint256[8], uint256[11]) with no return value.
/// If it does not revert, proof is valid.
interface IGnarkStorageProofVerifierFixed11 {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[11] calldata input
    ) external view;
}

/// @notice Adapter from StorageProofSC generic bytes-based verifier interface
/// to gnark's generated uint256[8] proof verifier.
contract GnarkStorageProofVerifierAdapter is IStorageProofVerifier {
    IGnarkStorageProofVerifierFixed11 public immutable generatedVerifier;

    constructor(address generatedVerifier_) {
        require(generatedVerifier_ != address(0), "GnarkAdapter: zero verifier");
        generatedVerifier = IGnarkStorageProofVerifierFixed11(generatedVerifier_);
    }

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external view returns (bool) {
        require(publicInputs.length == 11, "GnarkAdapter: bad public input length");

        // gnark proof.WriteRawTo() currently gives 324 bytes.
        // The generated Solidity verifier expects the first 256 bytes:
        // uint256[8] = A(2), B(4), C(2).
        require(proof.length >= 256, "GnarkAdapter: proof too short");

        uint256[8] memory proofWords;
        for (uint256 i = 0; i < 8; i++) {
            uint256 word;
            assembly {
                word := calldataload(add(proof.offset, mul(i, 0x20)))
            }
            proofWords[i] = word;
        }

        uint256[11] memory fixedInputs;
        for (uint256 i = 0; i < 11; i++) {
            fixedInputs[i] = publicInputs[i];
        }

        generatedVerifier.verifyProof(proofWords, fixedInputs);
        return true;
    }
}