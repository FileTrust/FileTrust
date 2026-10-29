// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DkgAttemptTypes
// Purpose:  Shared immutable request metadata and bounded DKG lifecycle interfaces.
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

library DkgAttemptTypes {
    struct Request {
        bytes32 materialId;
        bytes32 fileId;
        address dataOwner;
        uint32 epoch;
        uint32 version;
        uint32 oldVersion;
        uint8 oldT;
        uint8 newT;
        uint64 unopenedDeadline;
        bool refresh;
        uint256 publicKeyX;
        uint256 publicKeyY;
        address[] oldGuardians;
        address[] receivers;
        uint8[] dealerIndices;
    }
}

interface IDkgAttemptCoordinator {
    function acl() external view returns (address);
    function attemptController() external view returns (address);
    function disputeManager() external view returns (address);
    function reputationManager() external view returns (address);
    function getMaterialAttemptId(bytes32 fileId, uint32 epoch, uint32 version) external view returns (bytes32);
    function getV2Key(bytes32 fileId) external view returns (bool, bool, address, uint8, uint8, uint32, uint32, uint256, uint256);
    function getV2SharePublicKey(bytes32 fileId, uint32 epoch, uint32 version, uint8 index) external view returns (bool, uint256, uint256);
    function getRefreshRequest(bytes32 fileId, uint32 epoch, uint32 version) external view returns (bool, bool, uint32, uint8, uint8, uint8, uint8, address[] memory, address[] memory, uint8[] memory);
    function refreshSettled(bytes32 fileId, uint32 epoch) external view returns (bool);
    function refreshDeadline(bytes32 fileId, uint32 epoch) external view returns (uint64);
    function getAttemptWork(bytes32 materialId) external view returns (uint32 dealers, uint32 receivers, uint32 contributors);
    function closeAttempt(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version, uint8 outcome, uint8 faults) external;
}

interface IDkgAttemptEvidence {
    function snapshotAttempt(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version) external returns (bytes32, uint64);
    function pendingDisputes(bytes32 materialId) external view returns (uint256);
    function excludedDealers(bytes32 materialId) external view returns (uint32);
    function pendingReceiverDisputes(bytes32 materialId, address guardian) external view returns (uint256);
    function materialCommitmentHash(bytes32 materialId, uint32 epoch, uint32 version, uint8 index) external view returns (bytes32);
    function materialEncryptedShare(bytes32 materialId, uint32 epoch, uint32 version, uint8 dealerIndex, uint8 receiverIndex) external view returns (uint256);
}

interface IDkgAttemptController {
    function coordinator() external view returns (address);
    function acl() external view returns (address);
    function activeCount() external view returns (uint256);
    function isBound(bytes32 materialId) external view returns (bool);
    function getAttemptRequest(bytes32 fileId, uint32 epoch, uint32 version) external view returns (DkgAttemptTypes.Request memory);
    function validateDealer(bytes32 materialId, address guardian, uint8 index) external view returns (uint8 receiverCount);
    function validateCommitments(bytes32 materialId, address guardian, uint8 index, uint256[] calldata xs, uint256[] calldata ys) external returns (uint8 receiverCount);
    function validateEncryptedShare(bytes32 materialId, address guardian, uint8 fromIndex, uint8 toIndex, uint256 ciphertext) external view returns (address recipient, uint8 receiverCount);
    function validateSharePublication(bytes32 materialId, address guardian, uint8 index, uint256 x, uint256 y) external view;
    function requireMaterialOpen(bytes32 materialId) external view;
    function requireShareOpen(bytes32 materialId) external view;
    function requireComplaintOpen(bytes32 materialId) external view;
    function markMaterialsReady(bytes32 materialId) external;
    function materialsReady(bytes32 materialId) external view returns (bool);
    function complete(bytes32 materialId) external;
    function expire(bytes32 materialId) external;
}
