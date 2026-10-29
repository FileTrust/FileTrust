// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DeletionReleaseIdentity
// Purpose:  The single definition of what identifies a deletion-release operation, so
//           no two contracts can disagree about which one they mean.
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

/// @notice Canonical deletion-release operation identity. Both FileRegistrationSC
///         and DeletionReleaseSC use this one ABI-safe encoding.
library DeletionReleaseIdentity {
    bytes32 internal constant OPERATION_V1 =
        keccak256("FileTrustDeletionReleaseOperationV1");

    function operationId(
        uint256 chainId,
        address fileRegistration,
        address deletionRelease,
        address vk,
        bytes32 commitmentHash,
        bytes32 sourcePartitionKey,
        uint64 fifoGeneration
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            OPERATION_V1,
            chainId,
            fileRegistration,
            deletionRelease,
            vk,
            commitmentHash,
            sourcePartitionKey,
            fifoGeneration
        ));
    }
}
