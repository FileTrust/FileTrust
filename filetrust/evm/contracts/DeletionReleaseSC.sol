// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DeletionReleaseSC
// Purpose:  Space is released only once the state that replaces it has been proven --
//           never on the strength of a promise to delete.
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

import {DeletionReleaseIdentity} from "./DeletionReleaseIdentity.sol";

interface IFileRegistration_DR {
    function trustedStorageProofSC() external view returns (address);
    function deletionRelease() external view returns (address);
    function isDeletionReleaseOperationDeclared(
        bytes32 operationId,
        bytes32 fileCommitment,
        bytes32 partitionKey,
        address vk,
        bytes32 pieceCommitment
    ) external view returns (bool);
}

interface IPartitionSnapshotProof_DR {
    function storageProof() external view returns (address);
    function deletionRelease() external view returns (address);
}

interface IStorageProof_DR {
    function fileRegistration() external view returns (address);
    function deletionRelease() external view returns (address);
    function getPartitionReleaseState(bytes32 partitionKey)
        external view returns (
            address vk,
            uint8 kind,
            bool active,
            uint64 contentVersion,
            bytes32 contentHash,
            uint64 committedBytes,
            uint64 registrationNonce,
            uint64 transitionNonce
        );
    function getPartitionPieceCommitments(bytes32 partitionKey)
        external view returns (bytes32[] memory);
    function getPartitionVersionLineage(bytes32 partitionKey, uint64 contentVersion)
        external view returns (uint64 registeredNonce, uint64 supersededNonce);
    function isPartitionManifestEmpty(bytes32 partitionKey) external view returns (bool);
}

/// @title DeletionReleaseSC
/// @notice Deletion-scoped successor obligations and accepted receipts. This
///         contract never certifies capacity and never changes admission.
contract DeletionReleaseSC {
    error DeletionReleaseInvariant(uint8 code);
    uint8 public constant PARTITION_KIND_DATA = 1;

    enum ReleaseRoute { None, ActiveSnapshot, EmptyTransition }
    enum ReleaseState {
        None,
        AwaitingSuccessorIdentity,
        AwaitingSuccessorProof,
        Satisfied,
        Confirmed
    }
    enum RecoveryReason {
        None,
        DeclarationMismatch,
        MissingSuccessorCallback,
        SupersessionAmbiguous,
        SatisfiedIdentityChanged
    }

    struct OperationShellInput {
        address vk;
        bytes32 operationId;
        bytes32 sourcePartitionKey;
        uint8 sourceKind;
        bool sourceActive;
        uint64 sourceContentVersion;
        bytes32 sourceContentHash;
        uint64 sourceCommittedBytes;
        uint64 sourceRegistrationNonce;
        uint64 sourceTransitionNonce;
        bytes32 deletedFileCommitment;
        bytes32 deletedPieceCommitment;
        uint64 fifoGeneration;
    }

    struct DeletionReleaseOperation {
        address vk;
        bytes32 operationId;
        bytes32 sourcePartitionKey;
        uint8 sourceKind;
        bool sourceActive;
        uint64 sourceContentVersion;
        bytes32 sourceContentHash;
        uint64 sourceCommittedBytes;
        uint64 sourceRegistrationNonce;
        uint64 sourceTransitionNonce;
        bytes32 deletedFileCommitment;
        bytes32 deletedPieceCommitment;
        uint64 fifoGeneration;
        uint64 revision;
        ReleaseRoute route;
        ReleaseState state;
        bool recoveryRequired;
        RecoveryReason recoveryReason;
    }

    struct SuccessorRevision {
        uint64 revision;
        ReleaseRoute route;
        uint8 predecessorKind;
        bool predecessorActive;
        uint64 predecessorContentVersion;
        bytes32 predecessorContentHash;
        uint64 predecessorCommittedBytes;
        uint64 predecessorRegistrationNonce;
        uint64 predecessorTransitionNonce;
        uint8 successorKind;
        bool successorActive;
        uint64 successorContentVersion;
        bytes32 successorContentHash;
        uint64 successorCommittedBytes;
        uint64 successorRegistrationNonce;
        uint64 successorTransitionNonce;
        bytes32 obligationIdentityHash;
    }

    struct ActiveSuccessorReceipt {
        uint64 revision;
        uint64 proofAuthorityId;
        uint64 frozenSnapshotNonce;
        bytes32 partitionKey;
        uint8 kind;
        bool active;
        uint64 contentVersion;
        bytes32 contentHash;
        uint64 committedBytes;
        uint64 registrationNonce;
        bool acceptedAsCurrent;
        uint64 acceptedAt;
        uint64 acceptedBlock;
    }

    struct EmptyTransitionReceipt {
        uint64 revision;
        bytes32 partitionKey;
        uint64 predecessorContentVersion;
        uint64 successorContentVersion;
        uint64 successorRegistrationNonce;
        uint64 successorTransitionNonce;
        uint64 acceptedAt;
        uint64 acceptedBlock;
    }

    address public immutable fileRegistration;
    address public immutable snapshotProof;
    address public immutable storageProof;

    mapping(bytes32 => DeletionReleaseOperation) private operations;
    mapping(bytes32 => mapping(uint64 => SuccessorRevision)) private revisions;
    mapping(bytes32 => ActiveSuccessorReceipt) private activeReceipts;
    mapping(bytes32 => EmptyTransitionReceipt) private emptyReceipts;
    mapping(bytes32 => bytes32) public unresolvedOperationByPartition;
    mapping(bytes32 => uint64) public fifoGenerationByPartition;

    event OperationCreated(
        bytes32 indexed operationId,
        bytes32 indexed partitionKey,
        address indexed vk,
        bytes32 fileCommitment,
        bytes32 pieceCommitment,
        uint64 fifoGeneration
    );
    event SuccessorResolved(
        bytes32 indexed operationId,
        uint64 indexed revision,
        bytes32 indexed partitionKey,
        uint8 route,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 registrationNonce,
        uint64 transitionNonce
    );
    event SuccessorSuperseded(
        bytes32 indexed operationId,
        uint64 indexed previousRevision,
        uint64 indexed newRevision,
        bytes32 previousIdentityHash,
        bytes32 newIdentityHash
    );
    event ActiveReceiptAccepted(
        bytes32 indexed operationId,
        uint64 indexed revision,
        uint64 indexed proofAuthorityId,
        uint64 frozenSnapshotNonce,
        uint64 acceptedBlock
    );
    event EmptyTransitionReceiptAccepted(
        bytes32 indexed operationId,
        uint64 indexed revision,
        uint64 transitionNonce,
        uint64 acceptedBlock
    );
    event RecoveryQuarantineChanged(
        bytes32 indexed operationId,
        bool required,
        uint8 reason
    );
    event OperationConfirmed(bytes32 indexed operationId, bytes32 indexed partitionKey);

    modifier onlyFileRegistration() {
        if (msg.sender != fileRegistration) revert DeletionReleaseInvariant(1);
        if (IFileRegistration_DR(fileRegistration).deletionRelease() != address(this))
            revert DeletionReleaseInvariant(2);
        _;
    }

    modifier onlyStorageProof() {
        if (msg.sender != storageProof) revert DeletionReleaseInvariant(3);
        if (IStorageProof_DR(storageProof).deletionRelease() != address(this))
            revert DeletionReleaseInvariant(4);
        _;
    }

    modifier onlySnapshotProof() {
        if (msg.sender != snapshotProof) revert DeletionReleaseInvariant(5);
        if (IPartitionSnapshotProof_DR(snapshotProof).deletionRelease() != address(this))
            revert DeletionReleaseInvariant(6);
        _;
    }

    constructor(address fileRegistration_, address snapshotProof_, address storageProof_) {
        if (fileRegistration_ == address(0) || fileRegistration_.code.length == 0)
            revert DeletionReleaseInvariant(7);
        if (snapshotProof_ == address(0) || snapshotProof_.code.length == 0)
            revert DeletionReleaseInvariant(8);
        if (storageProof_ == address(0) || storageProof_.code.length == 0)
            revert DeletionReleaseInvariant(9);
        if (IFileRegistration_DR(fileRegistration_).trustedStorageProofSC() != storageProof_)
            revert DeletionReleaseInvariant(10);
        if (IPartitionSnapshotProof_DR(snapshotProof_).storageProof() != storageProof_)
            revert DeletionReleaseInvariant(11);
        if (IStorageProof_DR(storageProof_).fileRegistration() != fileRegistration_)
            revert DeletionReleaseInvariant(12);
        fileRegistration = fileRegistration_;
        snapshotProof = snapshotProof_;
        storageProof = storageProof_;
    }

    function createOperation(OperationShellInput calldata input)
        external onlyFileRegistration
    {
        if (input.vk == address(0)) revert DeletionReleaseInvariant(13);
        if (input.sourcePartitionKey == bytes32(0)) revert DeletionReleaseInvariant(14);
        if (input.sourceKind != PARTITION_KIND_DATA || !input.sourceActive)
            revert DeletionReleaseInvariant(15);
        require(
            input.sourceContentVersion > 0 && input.sourceContentHash != bytes32(0) &&
            input.sourceCommittedBytes > 0 && input.sourceRegistrationNonce > 0 &&
            input.sourceTransitionNonce > 0,
            "DR: incomplete source"
        );
        if (input.deletedPieceCommitment == bytes32(0))
            revert DeletionReleaseInvariant(16);
        require(_sourceIsCurrent(input), "DR: source identity not current");
        require(
            unresolvedOperationByPartition[input.sourcePartitionKey] == bytes32(0),
            "DR: partition operation unresolved"
        );
        uint64 expectedGeneration = fifoGenerationByPartition[input.sourcePartitionKey] + 1;
        require(input.fifoGeneration == expectedGeneration, "DR: bad FIFO generation");
        bytes32 expectedId = DeletionReleaseIdentity.operationId(
            block.chainid,
            fileRegistration,
            address(this),
            input.vk,
            input.deletedFileCommitment,
            input.sourcePartitionKey,
            input.fifoGeneration
        );
        require(input.operationId == expectedId, "DR: bad operation id");
        require(operations[input.operationId].state == ReleaseState.None,
                "DR: operation exists");
        require(
            IFileRegistration_DR(fileRegistration).isDeletionReleaseOperationDeclared(
                input.operationId,
                input.deletedFileCommitment,
                input.sourcePartitionKey,
                input.vk,
                input.deletedPieceCommitment
            ),
            "DR: declaration mismatch"
        );

        operations[input.operationId] = DeletionReleaseOperation({
            vk: input.vk,
            operationId: input.operationId,
            sourcePartitionKey: input.sourcePartitionKey,
            sourceKind: input.sourceKind,
            sourceActive: input.sourceActive,
            sourceContentVersion: input.sourceContentVersion,
            sourceContentHash: input.sourceContentHash,
            sourceCommittedBytes: input.sourceCommittedBytes,
            sourceRegistrationNonce: input.sourceRegistrationNonce,
            sourceTransitionNonce: input.sourceTransitionNonce,
            deletedFileCommitment: input.deletedFileCommitment,
            deletedPieceCommitment: input.deletedPieceCommitment,
            fifoGeneration: input.fifoGeneration,
            revision: 0,
            route: ReleaseRoute.None,
            state: ReleaseState.AwaitingSuccessorIdentity,
            recoveryRequired: false,
            recoveryReason: RecoveryReason.None
        });
        unresolvedOperationByPartition[input.sourcePartitionKey] = input.operationId;
        fifoGenerationByPartition[input.sourcePartitionKey] = input.fifoGeneration;
        emit OperationCreated(
            input.operationId,
            input.sourcePartitionKey,
            input.vk,
            input.deletedFileCommitment,
            input.deletedPieceCommitment,
            input.fifoGeneration
        );
    }

    function resolveSuccessor(
        bytes32 operationId,
        uint8 predecessorKind,
        bool predecessorActive,
        uint64 predecessorContentVersion,
        bytes32 predecessorContentHash,
        uint64 predecessorCommittedBytes,
        uint64 predecessorRegistrationNonce,
        uint64 predecessorTransitionNonce
    ) external onlyStorageProof returns (bool resolved) {
        DeletionReleaseOperation storage operation = operations[operationId];
        require(operation.state != ReleaseState.None, "DR: unknown operation");
        require(operation.state != ReleaseState.Confirmed, "DR: operation confirmed");
        require(
            unresolvedOperationByPartition[operation.sourcePartitionKey] == operationId,
            "DR: operation not partition owner"
        );
        require(_declared(operation), "DR: declaration unresolved");

        if (operation.state == ReleaseState.Satisfied) return false;
        require(!operation.recoveryRequired, "DR: recovery required");

        SuccessorRevision storage prior = revisions[operationId][operation.revision];
        if (operation.revision == 0) {
            require(
                predecessorKind == operation.sourceKind &&
                predecessorActive == operation.sourceActive &&
                predecessorContentVersion == operation.sourceContentVersion &&
                predecessorContentHash == operation.sourceContentHash &&
                predecessorCommittedBytes == operation.sourceCommittedBytes &&
                predecessorRegistrationNonce == operation.sourceRegistrationNonce &&
                predecessorTransitionNonce == operation.sourceTransitionNonce,
                "DR: source predecessor mismatch"
            );
        } else {
            require(
                predecessorKind == prior.successorKind &&
                predecessorActive == prior.successorActive &&
                predecessorContentVersion == prior.successorContentVersion &&
                predecessorContentHash == prior.successorContentHash &&
                predecessorCommittedBytes == prior.successorCommittedBytes &&
                predecessorRegistrationNonce == prior.successorRegistrationNonce &&
                predecessorTransitionNonce == prior.successorTransitionNonce,
                "DR: revision predecessor mismatch"
            );
        }

        (
            address successorVK,
            uint8 successorKind,
            bool successorActive,
            uint64 successorVersion,
            bytes32 successorHash,
            uint64 successorBytes,
            uint64 successorRegistrationNonce,
            uint64 successorTransitionNonce
        ) = IStorageProof_DR(storageProof).getPartitionReleaseState(
            operation.sourcePartitionKey
        );
        bytes32[] memory successorPieces = IStorageProof_DR(storageProof)
            .getPartitionPieceCommitments(operation.sourcePartitionKey);
        require(successorVK == operation.vk, "DR: successor VK changed");
        require(successorKind == PARTITION_KIND_DATA, "DR: successor kind changed");
        require(successorVersion > predecessorContentVersion,
                "DR: successor version not newer");
        require(successorRegistrationNonce > predecessorRegistrationNonce,
                "DR: successor registration not newer");
        require(successorTransitionNonce > predecessorTransitionNonce,
                "DR: successor transition not newer");
        (uint64 registeredNonce, uint64 supersededNonce) =
            IStorageProof_DR(storageProof).getPartitionVersionLineage(
                operation.sourcePartitionKey, predecessorContentVersion
            );
        require(registeredNonce == predecessorRegistrationNonce,
                "DR: predecessor registration mismatch");
        require(supersededNonce == successorRegistrationNonce,
                "DR: predecessor link mismatch");
        require(!_contains(successorPieces, operation.deletedPieceCommitment),
                "DR: deleted piece still present");

        ReleaseRoute route = successorActive
            ? ReleaseRoute.ActiveSnapshot
            : ReleaseRoute.EmptyTransition;
        if (!successorActive) {
            require(
                successorHash == bytes32(0) && successorBytes == 0 &&
                successorPieces.length == 0 && successorTransitionNonce != 0 &&
                IStorageProof_DR(storageProof).isPartitionManifestEmpty(
                    operation.sourcePartitionKey
                ),
                "DR: malformed empty successor"
            );
        } else {
            require(successorHash != bytes32(0) && successorBytes > 0,
                    "DR: malformed active successor");
        }

        uint64 previousRevision = operation.revision;
        bytes32 previousIdentity = previousRevision == 0
            ? bytes32(0)
            : prior.obligationIdentityHash;
        uint64 newRevision = previousRevision + 1;
        bytes32 identityHash = _obligationIdentity(
            operation,
            newRevision,
            route,
            successorKind,
            successorActive,
            successorVersion,
            successorHash,
            successorBytes,
            successorRegistrationNonce,
            successorTransitionNonce
        );
        revisions[operationId][newRevision] = SuccessorRevision({
            revision: newRevision,
            route: route,
            predecessorKind: predecessorKind,
            predecessorActive: predecessorActive,
            predecessorContentVersion: predecessorContentVersion,
            predecessorContentHash: predecessorContentHash,
            predecessorCommittedBytes: predecessorCommittedBytes,
            predecessorRegistrationNonce: predecessorRegistrationNonce,
            predecessorTransitionNonce: predecessorTransitionNonce,
            successorKind: successorKind,
            successorActive: successorActive,
            successorContentVersion: successorVersion,
            successorContentHash: successorHash,
            successorCommittedBytes: successorBytes,
            successorRegistrationNonce: successorRegistrationNonce,
            successorTransitionNonce: successorTransitionNonce,
            obligationIdentityHash: identityHash
        });
        operation.revision = newRevision;
        operation.route = route;
        operation.state = ReleaseState.AwaitingSuccessorProof;

        if (previousRevision != 0) {
            emit SuccessorSuperseded(
                operationId, previousRevision, newRevision,
                previousIdentity, identityHash
            );
        }
        emit SuccessorResolved(
            operationId,
            newRevision,
            operation.sourcePartitionKey,
            uint8(route),
            successorVersion,
            successorHash,
            successorRegistrationNonce,
            successorTransitionNonce
        );

        if (route == ReleaseRoute.EmptyTransition) {
            emptyReceipts[operationId] = EmptyTransitionReceipt({
                revision: newRevision,
                partitionKey: operation.sourcePartitionKey,
                predecessorContentVersion: predecessorContentVersion,
                successorContentVersion: successorVersion,
                successorRegistrationNonce: successorRegistrationNonce,
                successorTransitionNonce: successorTransitionNonce,
                acceptedAt: uint64(block.timestamp),
                acceptedBlock: uint64(block.number)
            });
            operation.state = ReleaseState.Satisfied;
            emit EmptyTransitionReceiptAccepted(
                operationId, newRevision, successorTransitionNonce, uint64(block.number)
            );
        }
        return true;
    }

    function recordActiveReceipt(
        bytes32 partitionKey,
        uint64 proofAuthorityId,
        uint64 frozenSnapshotNonce,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes,
        bool acceptedAsCurrent
    ) external onlySnapshotProof returns (bool satisfied) {
        bytes32 operationId = unresolvedOperationByPartition[partitionKey];
        if (operationId == bytes32(0)) return false;
        DeletionReleaseOperation storage operation = operations[operationId];
        if (operation.state == ReleaseState.Satisfied ||
            operation.state == ReleaseState.Confirmed) return false;
        SuccessorRevision storage revision = revisions[operationId][operation.revision];
        bool exact = acceptedAsCurrent && operation.revision != 0 &&
            operation.route == ReleaseRoute.ActiveSnapshot &&
            revision.successorKind == kind && revision.successorActive &&
            revision.successorContentVersion == contentVersion &&
            revision.successorContentHash == contentHash &&
            revision.successorCommittedBytes == committedBytes;
        if (!exact) return false; // historical/unrelated proof remains valid historically
        require(!operation.recoveryRequired, "DR: recovery required");
        require(proofAuthorityId != 0 && frozenSnapshotNonce != 0,
                "DR: incomplete active receipt");
        (
            address currentVK,
            uint8 currentKind,
            bool currentActive,
            uint64 currentVersion,
            bytes32 currentHash,
            uint64 currentBytes,
            uint64 currentRegistrationNonce,
            
        ) = IStorageProof_DR(storageProof).getPartitionReleaseState(partitionKey);
        bytes32[] memory currentPieces = IStorageProof_DR(storageProof)
            .getPartitionPieceCommitments(partitionKey);
        require(
            currentVK == operation.vk && currentKind == kind && currentActive &&
            currentVersion == contentVersion && currentHash == contentHash &&
            currentBytes == committedBytes &&
            currentRegistrationNonce == revision.successorRegistrationNonce,
            "DR: active receipt not current"
        );
        require(!_contains(currentPieces, operation.deletedPieceCommitment),
                "DR: deleted piece restored");
        ActiveSuccessorReceipt storage receipt = activeReceipts[operationId];
        receipt.revision = operation.revision;
        receipt.proofAuthorityId = proofAuthorityId;
        receipt.frozenSnapshotNonce = frozenSnapshotNonce;
        receipt.partitionKey = partitionKey;
        receipt.kind = kind;
        receipt.active = true;
        receipt.contentVersion = contentVersion;
        receipt.contentHash = contentHash;
        receipt.committedBytes = committedBytes;
        receipt.registrationNonce = currentRegistrationNonce;
        receipt.acceptedAsCurrent = true;
        receipt.acceptedAt = uint64(block.timestamp);
        receipt.acceptedBlock = uint64(block.number);
        operation.state = ReleaseState.Satisfied;
        emit ActiveReceiptAccepted(
            operationId,
            operation.revision,
            proofAuthorityId,
            frozenSnapshotNonce,
            uint64(block.number)
        );
        return true;
    }

    function consumeSatisfied(bytes32 operationId)
        external onlyFileRegistration returns (bool newlyConfirmed)
    {
        DeletionReleaseOperation storage operation = operations[operationId];
        if (operation.state == ReleaseState.Confirmed) return false;
        require(operation.state == ReleaseState.Satisfied, "DR: release not satisfied");
        require(!operation.recoveryRequired, "DR: recovery required");
        require(_declared(operation), "DR: declaration unresolved");
        operation.state = ReleaseState.Confirmed;
        delete unresolvedOperationByPartition[operation.sourcePartitionKey];
        emit OperationConfirmed(operationId, operation.sourcePartitionKey);
        return true;
    }

    /// @notice Evidence-only audit. The caller supplies no replacement identity.
    function auditOperation(bytes32 operationId) external returns (bool quarantined) {
        DeletionReleaseOperation storage operation = operations[operationId];
        require(operation.state != ReleaseState.None, "DR: unknown operation");
        RecoveryReason reason = _recoveryReason(operation);
        if (reason != RecoveryReason.None) {
            operation.recoveryRequired = true;
            operation.recoveryReason = reason;
            emit RecoveryQuarantineChanged(operationId, true, uint8(reason));
            return true;
        }
        return operation.recoveryRequired;
    }

    /// @notice Clears only a disagreement that authoritative chain reads prove gone.
    function reconcileOperation(bytes32 operationId) external returns (bool recovered) {
        DeletionReleaseOperation storage operation = operations[operationId];
        require(operation.state != ReleaseState.None, "DR: unknown operation");
        require(operation.recoveryRequired, "DR: operation not quarantined");
        require(_recoveryReason(operation) == RecoveryReason.None,
                "DR: disagreement unresolved");
        operation.recoveryRequired = false;
        operation.recoveryReason = RecoveryReason.None;
        emit RecoveryQuarantineChanged(operationId, false, uint8(RecoveryReason.None));
        return true;
    }

    function getOperation(bytes32 operationId)
        external view returns (DeletionReleaseOperation memory)
    {
        return operations[operationId];
    }

    function getRevision(bytes32 operationId, uint64 revision)
        external view returns (SuccessorRevision memory)
    {
        return revisions[operationId][revision];
    }

    function getActiveReceipt(bytes32 operationId)
        external view returns (ActiveSuccessorReceipt memory)
    {
        return activeReceipts[operationId];
    }

    function getEmptyReceipt(bytes32 operationId)
        external view returns (EmptyTransitionReceipt memory)
    {
        return emptyReceipts[operationId];
    }

    function isReleaseSatisfied(bytes32 operationId) external view returns (bool) {
        DeletionReleaseOperation storage operation = operations[operationId];
        return operation.state == ReleaseState.Satisfied && !operation.recoveryRequired;
    }

    function isActiveProofAuthorized(
        bytes32 partitionKey,
        address vk,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external view returns (bool) {
        bytes32 operationId = unresolvedOperationByPartition[partitionKey];
        if (operationId == bytes32(0)) return false;
        DeletionReleaseOperation storage operation = operations[operationId];
        if (operation.state != ReleaseState.AwaitingSuccessorProof ||
            operation.recoveryRequired || operation.route != ReleaseRoute.ActiveSnapshot ||
            operation.vk != vk) return false;
        SuccessorRevision storage revision = revisions[operationId][operation.revision];
        return revision.successorActive &&
            revision.successorContentVersion == contentVersion &&
            revision.successorContentHash == contentHash &&
            revision.successorCommittedBytes == committedBytes;
    }

    function isOperationConfirmed(bytes32 operationId) external view returns (bool) {
        return operations[operationId].state == ReleaseState.Confirmed;
    }

    function _declared(DeletionReleaseOperation storage operation)
        internal view returns (bool)
    {
        return IFileRegistration_DR(fileRegistration).isDeletionReleaseOperationDeclared(
            operation.operationId,
            operation.deletedFileCommitment,
            operation.sourcePartitionKey,
            operation.vk,
            operation.deletedPieceCommitment
        );
    }

    function _sourceIsCurrent(OperationShellInput calldata input)
        internal view returns (bool)
    {
        (
            address vk,
            uint8 kind,
            bool active,
            uint64 version,
            bytes32 contentHash,
            uint64 committedBytes,
            uint64 registrationNonce,
            uint64 transitionNonce
        ) = IStorageProof_DR(storageProof).getPartitionReleaseState(
            input.sourcePartitionKey
        );
        bytes32[] memory pieces = IStorageProof_DR(storageProof)
            .getPartitionPieceCommitments(input.sourcePartitionKey);
        return vk == input.vk && kind == input.sourceKind &&
            active == input.sourceActive && version == input.sourceContentVersion &&
            contentHash == input.sourceContentHash &&
            committedBytes == input.sourceCommittedBytes &&
            registrationNonce == input.sourceRegistrationNonce &&
            transitionNonce == input.sourceTransitionNonce &&
            _contains(pieces, input.deletedPieceCommitment);
    }

    function _recoveryReason(DeletionReleaseOperation storage operation)
        internal view returns (RecoveryReason)
    {
        // Confirmation consumes the pending declaration in FileRegistration.
        if (operation.state == ReleaseState.Confirmed) return RecoveryReason.None;
        if (!_declared(operation)) return RecoveryReason.DeclarationMismatch;
        (
            address currentVK,
            uint8 currentKind,
            bool currentActive,
            uint64 currentVersion,
            bytes32 currentHash,
            uint64 currentBytes,
            uint64 currentRegistrationNonce,
            uint64 currentTransitionNonce
        ) = IStorageProof_DR(storageProof).getPartitionReleaseState(
            operation.sourcePartitionKey
        );
        bytes32[] memory currentPieces = IStorageProof_DR(storageProof)
            .getPartitionPieceCommitments(operation.sourcePartitionKey);
        if (operation.state == ReleaseState.AwaitingSuccessorIdentity) {
            // Before the atomic removal callback, the exact original source
            // must still contain the piece. Successor absence is not due yet.
            if (currentVK == operation.vk && currentKind == operation.sourceKind &&
                currentActive == operation.sourceActive &&
                currentVersion == operation.sourceContentVersion &&
                currentHash == operation.sourceContentHash &&
                currentBytes == operation.sourceCommittedBytes &&
                currentRegistrationNonce == operation.sourceRegistrationNonce &&
                currentTransitionNonce == operation.sourceTransitionNonce &&
                _contains(currentPieces, operation.deletedPieceCommitment)) {
                return RecoveryReason.None;
            }
            return currentVK != operation.vk ||
                _contains(currentPieces, operation.deletedPieceCommitment)
                ? RecoveryReason.SupersessionAmbiguous
                : RecoveryReason.MissingSuccessorCallback;
        }
        if (currentVK != operation.vk ||
            _contains(currentPieces, operation.deletedPieceCommitment)) {
            return operation.state == ReleaseState.Satisfied
                ? RecoveryReason.SatisfiedIdentityChanged
                : RecoveryReason.SupersessionAmbiguous;
        }
        if (operation.state == ReleaseState.AwaitingSuccessorProof) {
            SuccessorRevision storage revision = revisions[operation.operationId][operation.revision];
            if (currentVersion != revision.successorContentVersion ||
                currentHash != revision.successorContentHash ||
                currentRegistrationNonce != revision.successorRegistrationNonce) {
                return RecoveryReason.SupersessionAmbiguous;
            }
        }
        return RecoveryReason.None;
    }

    function _contains(bytes32[] memory values, bytes32 target)
        internal pure returns (bool)
    {
        for (uint256 i = 0; i < values.length; i++) {
            if (values[i] == target) return true;
        }
        return false;
    }

    function _obligationIdentity(
        DeletionReleaseOperation storage operation,
        uint64 revision,
        ReleaseRoute route,
        uint8 successorKind,
        bool successorActive,
        uint64 successorVersion,
        bytes32 successorHash,
        uint64 successorBytes,
        uint64 successorRegistrationNonce,
        uint64 successorTransitionNonce
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256("FileTrustDeletionReleaseIdentityV1"),
            block.chainid,
            address(this),
            operation.operationId,
            operation.vk,
            operation.sourcePartitionKey,
            operation.sourceContentVersion,
            operation.sourceContentHash,
            operation.sourceRegistrationNonce,
            successorKind,
            successorActive,
            successorVersion,
            successorHash,
            successorBytes,
            successorRegistrationNonce,
            successorTransitionNonce,
            revision,
            route
        ));
    }
}
