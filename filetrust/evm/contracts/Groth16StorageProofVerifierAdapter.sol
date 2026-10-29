// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: Groth16StorageProofVerifierAdapter
// Purpose:  The protocol's side of a snarkjs Groth16 storage-proof verifier.
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

/// @notice Interface matching the common snarkjs Groth16 Solidity verifier output.
interface ISnarkjsGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata input
    ) external view returns (bool r);
}

/// @notice Adapter that lets StorageProofSC use a generated Groth16 verifier.
/// proof must be abi.encode(a, b, c).
contract Groth16StorageProofVerifierAdapter is IStorageProofVerifier {
    ISnarkjsGroth16Verifier public immutable generatedVerifier;

    constructor(address generatedVerifier_) {
        require(generatedVerifier_ != address(0), "Adapter: zero verifier");
        generatedVerifier = ISnarkjsGroth16Verifier(generatedVerifier_);
    }

    function verifyProof(bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool) {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c) = abi.decode(
            proof,
            (uint256[2], uint256[2][2], uint256[2])
        );
        return generatedVerifier.verifyProof(a, b, c, publicInputs);
    }
}
