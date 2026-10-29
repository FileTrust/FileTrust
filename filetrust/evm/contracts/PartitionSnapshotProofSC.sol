// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: PartitionSnapshotProofSC
// Purpose:  Freezing a partition's exact state at a cutoff, so the proof that follows
//           is about that state and no other.
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

import {ProofAuthorityDomains} from "./ProofAuthorityDomains.sol";

import "./IStorageProofVerifier.sol";

interface IVaultKeeperRegistry_PS {
    function isEligibleVaultKeeper(address vk) external view returns (bool);
}

interface IStorageProofSnapshotSource_PS {
    function currentRound() external view returns (uint64);
    function proofDeadlineSeconds() external view returns (uint64);
    function partitionCircuitSectors() external view returns (uint8);
    function partitionCircuitChallenges() external view returns (uint8);
    function fileRegistration() external view returns (address);
    function getPartitionSectorRoots(bytes32 pKey) external view returns (bytes32[] memory);
    function getPartitionSectorIds(bytes32 pKey) external view returns (bytes32[] memory);
    function getPartitionBlockCounts(bytes32 pKey) external view returns (uint32[] memory);
    function getPartitionPieceCommitments(bytes32 pKey) external view returns (bytes32[] memory);
    function acceptFrozenPartitionProof(
        bytes32 pKey,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 round,
        uint64 proofEpochId
    ) external returns (bool acceptedAsCurrent);
    function partitions(bytes32 pKey)
        external view returns (
            address vk,
            bytes32 partitionKey,
            uint8 deadlineIndex,
            uint8 partitionIndex,
            uint8 partitionKind,
            uint64 committedBytes,
            uint64 expiration,
            uint64 registeredAt,
            uint64 updatedAt,
            uint64 lastProofRound,
            uint16 challengeCount,
            bool active,
            bytes32 contentHash,
            uint64 contentVersion,
            bytes32 lastProvenContentHash,
            bytes32 challengeAnchor,
            uint64 anchorBlock
        );
}

/// @notice G.2A exact incremental membership. The snapshot contract is the sole acceptance
///         authority; membership itself is owned entirely by CapacityIncrementalBatchSC.
interface ICapacityIncrementalBatch_PS {
    function activeBatchIdOf(address vk) external view returns (uint64);
    function selectedMemberKeys(uint64 batchId) external view returns (bytes32[] memory);
    function selectedMemberAccepted(uint64 batchId, bytes32 partitionKey)
        external view returns (bool exists, bool accepted);
    function abandonBatch(address vk, uint8 reason) external returns (uint64 batchId);
    function isSelectedPartitionFor(
        address vk,
        bytes32 partitionKey,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes,
        uint64 authorityId,
        uint64 round
    ) external view returns (bool);
    function recordAcceptedMember(address vk, bytes32 partitionKey, bytes32 identityHash, uint64 authorityId, uint64 round)
        external returns (bool);
}

interface ICapacityCertificationHash_PS {
    function certificationIdentityHash(
        bytes32 partitionKey,
        uint8 kind,
        bool active,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external pure returns (bytes32);
}

interface IDeletionRelease_PS {
    function snapshotProof() external view returns (address);
    function isActiveProofAuthorized(
        bytes32 pKey,
        address vk,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external view returns (bool);
    function recordActiveReceipt(
        bytes32 partitionKey,
        uint64 proofAuthorityId,
        uint64 frozenSnapshotNonce,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes,
        bool acceptedAsCurrent
    ) external returns (bool satisfied);
}

interface ICapacityProofSnapshotSink_PS {
    function recordVerifiedSnapshotVersion(
        address vk,
        bytes32 partitionKey,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 provedBytes,
        uint64 proofRound,
        uint64 proofEpochId
    ) external returns (bool counted);

    function getActiveProofEpoch(address vk)
        external view returns (
            uint64 epochId,
            uint64 targetRound,
            uint64 cutoffNonce,
            uint32 expectedPartitions,
            uint32 provenPartitions,
            uint64 expectedBytes,
            bool active,
            bool invalidated
        );

    function isActiveEpochVersion(
        address vk,
        bytes32 partitionKey,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 epochId
    ) external view returns (bool);
}

/// @title PartitionSnapshotProofSC
/// @notice Bounded immutable partition snapshots with post-freeze chain entropy.
///
/// Exactly one frozen snapshot exists per partition key. The live successor stays
/// in StorageProofSC and may coalesce independent additions. Deleting a slot that
/// appears in the frozen snapshot invalidates it. Successful historical proofs
/// remain auditable, but StorageProofSC decides whether the exact version is still
/// current before changing proof status, capacity, rewards, or dispute state.
contract PartitionSnapshotProofSC {
    uint64 public constant STANDALONE_DELETION_PROOF_FLAG = uint64(1) << 63;
    struct FrozenSnapshot {
        address vk;
        uint8 partitionKind;
        uint8 circuitSectors;
        uint8 circuitChallenges;
        uint16 challengeCount;
        uint64 proofEpochId;
        uint64 contentVersion;
        uint64 round;
        uint64 committedBytes;
        uint64 expiration;
        uint64 frozenAt;
        uint64 freezeBlock;
        uint64 deadline;
        bytes32 contentHash;
        bytes32 challengeAnchor;
        bool exists;
        bytes32[] sectorIds;
        bytes32[] sectorRoots;
        uint32[] sectorBlockCounts;
        bytes32[] pieceCommitments;
    }

    struct ProofReceipt {
        uint64 proofEpochId;
        uint64 contentVersion;
        uint64 round;
        uint64 acceptedAt;
        bytes32 contentHash;
        uint64 snapshotNonce;
        bool acceptedAsCurrent;
    }

    address public owner;
    IStorageProofSnapshotSource_PS public immutable storageProof;
    IVaultKeeperRegistry_PS public vaultKeeperRegistry;
    IStorageProofVerifier public partitionVerifier;
    ICapacityProofSnapshotSink_PS public capacityProof;
    /// @notice CapacityIncrementalBatchSC — exact incremental membership (G.2A). Set once;
    ///         the reciprocal binding on that side verifies this pointer before accepting
    ///         this contract as its acceptance authority.
    address public incrementalBatch;
    /// @notice CapacityCertificationSC, used ONLY for its canonical identity-hash view so no
    ///         second identity encoding exists anywhere.
    address public certificationHasher;
    address public deletionRelease;

    mapping(bytes32 => FrozenSnapshot) private frozenSnapshots;
    mapping(bytes32 => ProofReceipt) public lastProofReceipts;
    mapping(bytes32 => ProofReceipt) public currentProofReceipts;

    /// @notice Monotonic freeze-generation counter per partition key. Deliberately kept
    ///         SEPARATE from the deletable FrozenSnapshot record: it increments on every
    ///         capture and every reanchor and is never reset or deleted, so a slot that
    ///         is freed (submit/abandon/supersede) and later recaptured can never repeat
    ///         an earlier generation (ABA guard). The active snapshot's generation is
    ///         always the current counter value; nonce 0 never identifies a submittable
    ///         snapshot.
    mapping(bytes32 => uint64) public partitionFrozenSnapshotNonce;

    event VaultKeeperRegistrySet(address indexed registry);
    event PartitionVerifierSet(address indexed verifier);
    event CapacityProofSet(address indexed capacityProof);
    event IncrementalBatchSet(address indexed incrementalBatch, address indexed certificationHasher);
    event DeletionReleaseSet(address indexed deletionRelease);
    event PartitionSnapshotFrozen(
        bytes32 indexed partitionKey,
        address indexed vk,
        uint64 indexed contentVersion,
        bytes32 contentHash,
        uint64 proofEpochId,
        uint64 round,
        uint64 freezeBlock,
        uint64 deadline
    );
    event PartitionSnapshotSealed(
        bytes32 indexed partitionKey,
        uint64 indexed contentVersion,
        uint64 proofEpochId,
        uint64 round,
        bytes32 challengeAnchor,
        bytes32 seed
    );
    event PartitionSnapshotReanchored(
        bytes32 indexed partitionKey,
        uint64 indexed contentVersion,
        uint64 proofEpochId,
        uint64 round,
        uint64 freezeBlock
    );
    event PartitionSnapshotInvalidated(
        bytes32 indexed partitionKey,
        uint64 indexed contentVersion,
        bytes32 reason
    );
    event FrozenPartitionProofSubmitted(
        bytes32 indexed partitionKey,
        address indexed vk,
        uint64 indexed contentVersion,
        uint64 proofEpochId,
        uint64 round,
        bytes32 contentHash,
        bool acceptedAsCurrent
    );
    event FrozenPartitionProofAlreadyAccepted(
        bytes32 indexed partitionKey,
        uint64 indexed contentVersion,
        uint64 proofEpochId,
        uint64 round,
        bytes32 contentHash
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "SnapshotProof: only owner");
        _;
    }

    constructor(address storageProof_, address verifier_) {
        require(storageProof_ != address(0), "SnapshotProof: zero storage proof");
        owner = msg.sender;
        storageProof = IStorageProofSnapshotSource_PS(storageProof_);
        if (verifier_ != address(0)) partitionVerifier = IStorageProofVerifier(verifier_);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "SnapshotProof: zero owner");
        owner = newOwner;
    }

    function setVaultKeeperRegistry(address registry) external onlyOwner {
        require(registry != address(0), "SnapshotProof: zero registry");
        vaultKeeperRegistry = IVaultKeeperRegistry_PS(registry);
        emit VaultKeeperRegistrySet(registry);
    }

    /// @notice Bound once (Phase 2, D8): keys are replaced through the FileTrustVerifierRouter
    ///         this names, with a bounded transition window.
    function setPartitionVerifier(address verifier_) external onlyOwner {
        require(verifier_ != address(0), "SnapshotProof: zero verifier");
        require(address(partitionVerifier) == address(0), "SnapshotProof: verifier bound");
        partitionVerifier = IStorageProofVerifier(verifier_);
        emit PartitionVerifierSet(verifier_);
    }

    function setCapacityProof(address capacityProof_) external onlyOwner {
        require(capacityProof_ != address(0), "SnapshotProof: zero capacity proof");
        require(address(capacityProof) == address(0), "SnapshotProof: capacity proof already set");
        capacityProof = ICapacityProofSnapshotSink_PS(capacityProof_);
        emit CapacityProofSet(capacityProof_);
    }

    /// @notice One-time wiring of the incremental-batch membership authority and the frozen
    ///         certification contract that computes canonical identity hashes.
    function setIncrementalBatch(address incrementalBatch_, address certificationHasher_)
        external onlyOwner
    {
        require(incrementalBatch == address(0), "SnapshotProof: incremental batch already set");
        require(incrementalBatch_ != address(0) && incrementalBatch_.code.length > 0,
                "SnapshotProof: bad incremental batch");
        require(certificationHasher_ != address(0) && certificationHasher_.code.length > 0,
                "SnapshotProof: bad certification hasher");
        incrementalBatch = incrementalBatch_;
        certificationHasher = certificationHasher_;
        emit IncrementalBatchSet(incrementalBatch_, certificationHasher_);
    }

    function setDeletionRelease(address deletionRelease_) external onlyOwner {
        require(deletionRelease_ != address(0), "SnapshotProof: zero deletion release");
        require(deletionRelease_.code.length > 0, "SnapshotProof: deletion release no code");
        require(deletionRelease == address(0), "SnapshotProof: deletion release already set");
        require(
            IDeletionRelease_PS(deletionRelease_).snapshotProof() == address(this),
            "SnapshotProof: deletion release not reciprocal"
        );
        deletionRelease = deletionRelease_;
        emit DeletionReleaseSet(deletionRelease_);
    }

    /// @notice Safely abandon this VK's stuck incremental batch and release its campaign lock.
    /// @dev The ONLY route to release an incremental campaign other than completion, and it is
    ///      not a force-unlock: every unaccepted selected member is checked for a live frozen
    ///      snapshot under the batch's own authority id, and any such snapshot must be
    ///      terminally resolved first. There is no administrative override and no reset.
    function abandonIncrementalBatch(uint8 reason) external returns (uint64 batchId) {
        require(incrementalBatch != address(0), "SnapshotProof: incremental batch unset");
        ICapacityIncrementalBatch_PS batch = ICapacityIncrementalBatch_PS(incrementalBatch);
        batchId = batch.activeBatchIdOf(msg.sender);
        require(batchId != 0, "SnapshotProof: no active incremental batch");

        bytes32[] memory keys = batch.selectedMemberKeys(batchId);
        for (uint256 i = 0; i < keys.length; i++) {
            (bool exists, bool accepted) = batch.selectedMemberAccepted(batchId, keys[i]);
            if (!exists || accepted) continue;          // accepted members keep their accounting
            FrozenSnapshot storage snapshot = frozenSnapshots[keys[i]];
            require(
                !(snapshot.exists && snapshot.proofEpochId == batchId),
                "SnapshotProof: live selected snapshot"
            );
        }
        return batch.abandonBatch(msg.sender, reason);
    }

    function freezePartitionSnapshot(bytes32 pKey, uint64 proofEpochId, uint64 round)
        external returns (uint64 contentVersion, uint64 anchorBlock, uint64 snapshotNonce)
    {
        require(!frozenSnapshots[pKey].exists, "SnapshotProof: snapshot already frozen");
        require(address(capacityProof) != address(0), "SnapshotProof: capacity proof unset");
        require(address(vaultKeeperRegistry) != address(0), "SnapshotProof: registry unset");
        require(vaultKeeperRegistry.isEligibleVaultKeeper(msg.sender), "SnapshotProof: VK not eligible");
        (
            address vk,
            uint8 partitionKind,
            uint64 committedBytes,
            uint64 expiration,
            uint16 challengeCount,
            bool active,
            bytes32 contentHash,
            uint64 version
        ) = _livePartition(pKey);
        require(vk == msg.sender, "SnapshotProof: not partition VK");
        require(active && expiration > block.timestamp, "SnapshotProof: partition inactive");
        require(contentHash != bytes32(0) && version > 0, "SnapshotProof: empty content");

        _requireProofAuthorized(
            vk, pKey, partitionKind, committedBytes, version, contentHash, proofEpochId, round, true
        );

        _captureSnapshot(
            pKey, vk, partitionKind, committedBytes, expiration, challengeCount,
            contentHash, version, proofEpochId, round
        );
        FrozenSnapshot storage captured = frozenSnapshots[pKey];
        return (version, captured.freezeBlock, partitionFrozenSnapshotNonce[pKey]);
    }

    /// @notice StorageProofSC calls this immediately before overwriting a live
    ///         partition. If the version belongs to an active epoch, its public
    ///         manifest is frozen atomically in the same transaction. Uploads can
    ///         therefore continue without making the epoch's cutoff unprovable.
    function preservePartitionSnapshotBeforeUpdate(bytes32 pKey)
        external returns (bool preserved)
    {
        require(msg.sender == address(storageProof), "SnapshotProof: only storage proof");
        (
            address vk,
            uint8 partitionKind,
            uint64 committedBytes,
            uint64 expiration,
            uint16 challengeCount,
            bool active,
            bytes32 contentHash,
            uint64 version
        ) = _livePartition(pKey);
        if (!active || contentHash == bytes32(0) || version == 0) return false;

        (uint64 epochId, uint64 round,,,,, bool epochActive, bool invalidated) =
            capacityProof.getActiveProofEpoch(vk);
        if (!epochActive || invalidated ||
            !capacityProof.isActiveEpochVersion(vk, pKey, version, contentHash, epochId)) {
            return false;
        }

        FrozenSnapshot storage existing = frozenSnapshots[pKey];
        if (existing.exists) {
            if (existing.proofEpochId == epochId && existing.contentVersion == version &&
                existing.contentHash == contentHash) return true;
            emit PartitionSnapshotInvalidated(
                pKey, existing.contentVersion, bytes32("superseded-epoch")
            );
            delete frozenSnapshots[pKey];
        }
        _captureSnapshot(
            pKey, vk, partitionKind, committedBytes, expiration, challengeCount,
            contentHash, version, epochId, round
        );
        return true;
    }

    function _captureSnapshot(
        bytes32 pKey,
        address vk,
        uint8 partitionKind,
        uint64 committedBytes,
        uint64 expiration,
        uint16 challengeCount,
        bytes32 contentHash,
        uint64 version,
        uint64 proofEpochId,
        uint64 round
    ) internal {
        require(!frozenSnapshots[pKey].exists, "SnapshotProof: snapshot already frozen");
        // Every capture advances the persistent generation counter; the first capture on
        // a partition therefore always yields nonce >= 1.
        partitionFrozenSnapshotNonce[pKey] += 1;

        bytes32[] memory sectorIds = storageProof.getPartitionSectorIds(pKey);
        bytes32[] memory roots = storageProof.getPartitionSectorRoots(pKey);
        uint32[] memory counts = storageProof.getPartitionBlockCounts(pKey);
        bytes32[] memory pieces = storageProof.getPartitionPieceCommitments(pKey);
        require(
            sectorIds.length > 0 && sectorIds.length == roots.length &&
            roots.length == counts.length && roots.length == pieces.length,
            "SnapshotProof: malformed source"
        );

        uint8 circuitSectors = storageProof.partitionCircuitSectors();
        uint8 circuitChallenges = storageProof.partitionCircuitChallenges();
        require(sectorIds.length <= circuitSectors, "SnapshotProof: source exceeds circuit");
        require(challengeCount > 0 && challengeCount <= circuitChallenges,
                "SnapshotProof: bad challenge count");

        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        snapshot.vk = vk;
        snapshot.partitionKind = partitionKind;
        snapshot.circuitSectors = circuitSectors;
        snapshot.circuitChallenges = circuitChallenges;
        snapshot.challengeCount = challengeCount;
        snapshot.proofEpochId = proofEpochId;
        snapshot.contentVersion = version;
        snapshot.round = round;
        snapshot.committedBytes = committedBytes;
        snapshot.expiration = expiration;
        snapshot.frozenAt = uint64(block.timestamp);
        snapshot.freezeBlock = uint64(block.number);
        snapshot.deadline = uint64(block.timestamp) + storageProof.proofDeadlineSeconds();
        snapshot.contentHash = contentHash;
        snapshot.exists = true;
        for (uint256 i = 0; i < roots.length; i++) {
            snapshot.sectorIds.push(sectorIds[i]);
            snapshot.sectorRoots.push(roots[i]);
            snapshot.sectorBlockCounts.push(counts[i]);
            snapshot.pieceCommitments.push(pieces[i]);
        }

        emit PartitionSnapshotFrozen(
            pKey, vk, version, contentHash, proofEpochId, round,
            snapshot.freezeBlock, snapshot.deadline
        );
    }

    /// @notice Persists entropy from the freeze block, which was unknowable when
    ///         the immutable content transaction was submitted.
    function sealPartitionSnapshot(bytes32 pKey) external returns (bytes32 seed) {
        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        require(snapshot.exists, "SnapshotProof: no frozen snapshot");
        require(snapshot.challengeAnchor == bytes32(0), "SnapshotProof: already sealed");
        require(block.number > snapshot.freezeBlock, "SnapshotProof: wait one block");
        require(block.number <= uint256(snapshot.freezeBlock) + 256,
                "SnapshotProof: anchor unavailable; reanchor");
        bytes32 anchor = blockhash(snapshot.freezeBlock);
        require(anchor != bytes32(0), "SnapshotProof: anchor unavailable");
        snapshot.challengeAnchor = anchor;
        seed = _snapshotSeed(pKey, snapshot);
        emit PartitionSnapshotSealed(
            pKey,
            snapshot.contentVersion,
            snapshot.proofEpochId,
            snapshot.round,
            anchor,
            seed
        );
    }

    /// @notice Re-anchor an expired/unavailable challenge without changing the
    ///         immutable content version.
    function reanchorFrozenPartitionSnapshot(
        bytes32 pKey,
        uint64 contentVersion,
        uint64 newRound,
        uint64 proofEpochId,
        bytes32 contentHash,
        uint64 snapshotNonce
    ) external returns (uint64 anchorBlock, uint64 newSnapshotNonce) {
        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        require(snapshot.exists && snapshot.vk == msg.sender, "SnapshotProof: not snapshot VK");
        require(snapshot.contentVersion == contentVersion, "SnapshotProof: version mismatch");
        require(snapshot.proofEpochId == proofEpochId, "SnapshotProof: epoch mismatch");
        require(snapshot.contentHash == contentHash, "SnapshotProof: content hash mismatch");
        uint64 currentNonce = partitionFrozenSnapshotNonce[pKey];
        if (currentNonce != 0) {
            require(snapshotNonce == currentNonce, "SnapshotProof: snapshot nonce mismatch");
        }
        // Defensive: a zero-generation record (impossible after drain-before-cutover
        // migration) is never trusted; the reanchor force-assigns a fresh nonce >= 1
        // below regardless of the caller-supplied value.
        require(
            block.timestamp > snapshot.deadline ||
            (snapshot.challengeAnchor == bytes32(0) &&
                block.number > uint256(snapshot.freezeBlock) + 256),
            "SnapshotProof: current anchor active"
        );
        require(newRound == snapshot.round, "SnapshotProof: epoch round cannot change");
        _requireSubmissionAuthorized(pKey, snapshot);
        newSnapshotNonce = currentNonce + 1;
        partitionFrozenSnapshotNonce[pKey] = newSnapshotNonce;
        snapshot.round = newRound;
        snapshot.freezeBlock = uint64(block.number);
        snapshot.challengeAnchor = bytes32(0);
        snapshot.deadline = uint64(block.timestamp) + storageProof.proofDeadlineSeconds();
        emit PartitionSnapshotReanchored(
            pKey, contentVersion, snapshot.proofEpochId, newRound, snapshot.freezeBlock
        );
        return (snapshot.freezeBlock, newSnapshotNonce);
    }

    function computeFrozenPartitionDetSeed(
        bytes32 pKey,
        uint64 contentVersion,
        uint64 round
    ) public view returns (bytes32) {
        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        _requireExactSnapshot(snapshot, contentVersion, round);
        require(snapshot.challengeAnchor != bytes32(0), "SnapshotProof: snapshot not sealed");
        return _snapshotSeed(pKey, snapshot);
    }

    function expectedFrozenPartitionPublicInputs(
        bytes32 pKey,
        uint64 contentVersion,
        uint64 round
    ) external view returns (uint256[] memory) {
        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        _requireExactSnapshot(snapshot, contentVersion, round);
        require(snapshot.challengeAnchor != bytes32(0), "SnapshotProof: snapshot not sealed");
        return _buildPublicInputs(snapshot, _snapshotSeed(pKey, snapshot));
    }

    function submitFrozenPartitionZkProof(
        bytes32 pKey,
        uint64 contentVersion,
        uint64 proofEpochId,
        uint64 round,
        bytes32 contentHash,
        uint64 snapshotNonce,
        bytes calldata proof,
        uint256[] calldata publicInputs
    ) external returns (bool acceptedAsCurrent) {
        require(snapshotNonce != 0, "SnapshotProof: zero snapshot nonce");
        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        if (!snapshot.exists) {
            ProofReceipt storage receipt = lastProofReceipts[pKey];
            require(
                receipt.contentVersion == contentVersion &&
                receipt.proofEpochId == proofEpochId && receipt.round == round &&
                receipt.contentHash == contentHash &&
                receipt.snapshotNonce == snapshotNonce,
                "SnapshotProof: no frozen snapshot"
            );
            emit FrozenPartitionProofAlreadyAccepted(
                pKey, contentVersion, proofEpochId, round, receipt.contentHash
            );
            return receipt.acceptedAsCurrent;
        }
        _requireExactSnapshot(snapshot, contentVersion, round);
        require(snapshot.proofEpochId == proofEpochId, "SnapshotProof: epoch mismatch");
        require(snapshot.contentHash == contentHash, "SnapshotProof: content hash mismatch");
        require(
            snapshotNonce == partitionFrozenSnapshotNonce[pKey],
            "SnapshotProof: snapshot nonce mismatch"
        );
        require(snapshot.vk == msg.sender, "SnapshotProof: not snapshot VK");
        require(block.timestamp <= snapshot.deadline, "SnapshotProof: deadline elapsed");
        require(snapshot.expiration > block.timestamp, "SnapshotProof: storage expired");
        require(snapshot.challengeAnchor != bytes32(0), "SnapshotProof: snapshot not sealed");
        require(address(partitionVerifier) != address(0), "SnapshotProof: verifier unset");
        _requireSubmissionAuthorized(pKey, snapshot);

        uint256[] memory expected = _buildPublicInputs(snapshot, _snapshotSeed(pKey, snapshot));
        require(publicInputs.length == expected.length, "SnapshotProof: bad input length");
        for (uint256 i = 0; i < expected.length; i++) {
            require(publicInputs[i] == expected[i], "SnapshotProof: public input mismatch");
        }
        require(partitionVerifier.verifyProof(proof, publicInputs),
                "SnapshotProof: invalid ZK proof");

        address vk = snapshot.vk;
        uint8 partitionKind = snapshot.partitionKind;
        uint64 committedBytes = snapshot.committedBytes;
        acceptedAsCurrent = storageProof.acceptFrozenPartitionProof(
            pKey, contentVersion, contentHash, round, proofEpochId
        );
        capacityProof.recordVerifiedSnapshotVersion(
            vk,
            pKey,
            partitionKind,
            contentVersion,
            contentHash,
            committedBytes,
            round,
            proofEpochId
        );
        // G.2A: mark the EXACT selected member accepted, atomically with the proof accounting
        // and the certification update above. A revert here takes all three down together, so
        // the three contracts can never disagree about what was proven.
        if (incrementalBatch != address(0) &&
            ProofAuthorityDomains.isIncrementalAuthority(proofEpochId)) {
            bytes32 identityHash = ICapacityCertificationHash_PS(certificationHasher)
                .certificationIdentityHash(
                    pKey, partitionKind, true, contentVersion, contentHash, committedBytes
                );
            ICapacityIncrementalBatch_PS(incrementalBatch).recordAcceptedMember(
                vk, pKey, identityHash, proofEpochId, round
            );
        }
        if (deletionRelease != address(0)) {
            IDeletionRelease_PS(deletionRelease).recordActiveReceipt(
                pKey,
                proofEpochId,
                snapshotNonce,
                partitionKind,
                contentVersion,
                contentHash,
                committedBytes,
                acceptedAsCurrent
            );
        }
        lastProofReceipts[pKey] = ProofReceipt({
            proofEpochId: proofEpochId,
            contentVersion: contentVersion,
            round: round,
            acceptedAt: uint64(block.timestamp),
            contentHash: contentHash,
            snapshotNonce: snapshotNonce,
            acceptedAsCurrent: acceptedAsCurrent
        });
        if (acceptedAsCurrent) {
            currentProofReceipts[pKey] = lastProofReceipts[pKey];
        }
        delete frozenSnapshots[pKey];
        emit FrozenPartitionProofSubmitted(
            pKey, vk, contentVersion, proofEpochId, round, contentHash, acceptedAsCurrent
        );
    }

    function abandonFrozenPartitionSnapshot(
        bytes32 pKey,
        uint64 contentVersion,
        uint64 proofEpochId,
        bytes32 contentHash,
        uint64 snapshotNonce
    ) external {
        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        require(snapshot.exists && snapshot.vk == msg.sender, "SnapshotProof: not snapshot VK");
        require(snapshot.contentVersion == contentVersion, "SnapshotProof: version mismatch");
        require(snapshot.proofEpochId == proofEpochId, "SnapshotProof: epoch mismatch");
        require(snapshot.contentHash == contentHash, "SnapshotProof: content hash mismatch");
        require(snapshotNonce != 0, "SnapshotProof: zero snapshot nonce");
        require(
            snapshotNonce == partitionFrozenSnapshotNonce[pKey],
            "SnapshotProof: snapshot nonce mismatch"
        );
        (uint64 activeEpoch,,,,,, bool epochActive,) =
            capacityProof.getActiveProofEpoch(snapshot.vk);
        bool stillRequired = epochActive && activeEpoch == snapshot.proofEpochId &&
            capacityProof.isActiveEpochVersion(
                snapshot.vk,
                pKey,
                snapshot.contentVersion,
                snapshot.contentHash,
                snapshot.proofEpochId
            );
        require(
            block.timestamp > snapshot.deadline || !stillRequired,
            "SnapshotProof: snapshot deadline active"
        );
        emit PartitionSnapshotInvalidated(pKey, contentVersion, bytes32("expired"));
        delete frozenSnapshots[pKey];
    }

    function getFrozenPartitionSnapshotStatus(bytes32 pKey)
        external view returns (
            bool exists,
            uint64 proofEpochId,
            uint64 contentVersion,
            bytes32 contentHash,
            uint64 round,
            uint64 anchorBlock,
            bytes32 challengeAnchor,
            uint64 deadline,
            bool proven,
            bool current,
            uint64 snapshotNonce
        )
    {
        FrozenSnapshot storage snapshot = frozenSnapshots[pKey];
        if (snapshot.exists) {
            (
                ,,,,, bool active, bytes32 liveHash, uint64 liveVersion
            ) = _livePartition(pKey);
            return (
                true,
                snapshot.proofEpochId,
                snapshot.contentVersion,
                snapshot.contentHash,
                snapshot.round,
                snapshot.freezeBlock,
                snapshot.challengeAnchor,
                snapshot.deadline,
                false,
                active && liveVersion == snapshot.contentVersion && liveHash == snapshot.contentHash,
                partitionFrozenSnapshotNonce[pKey]
            );
        }
        ProofReceipt storage receipt = lastProofReceipts[pKey];
        return (
            false,
            receipt.proofEpochId,
            receipt.contentVersion,
            receipt.contentHash,
            receipt.round,
            0,
            bytes32(0),
            0,
            receipt.contentVersion != 0,
            _receiptIsCurrent(pKey, receipt),
            partitionFrozenSnapshotNonce[pKey]
        );
    }

    /// @notice Exact-current proof gate for FileRegistration, disputes and escrow.
    /// A live version change makes an older receipt false without any cleanup tx.
    function getCurrentPartitionProofStatus(bytes32 pKey)
        external view returns (
            bool current,
            uint64 contentVersion,
            bytes32 contentHash,
            uint64 proofRound,
            uint64 acceptedAt
        )
    {
        ProofReceipt storage receipt = currentProofReceipts[pKey];
        return (
            _receiptIsCurrent(pKey, receipt),
            receipt.contentVersion,
            receipt.contentHash,
            receipt.round,
            receipt.acceptedAt
        );
    }

    function getFrozenPartitionSectorRoots(bytes32 pKey)
        external view returns (bytes32[] memory)
    {
        return frozenSnapshots[pKey].sectorRoots;
    }

    function getFrozenPartitionBlockCounts(bytes32 pKey)
        external view returns (uint32[] memory)
    {
        return frozenSnapshots[pKey].sectorBlockCounts;
    }

    function getFrozenPartitionPieceCommitments(bytes32 pKey)
        external view returns (bytes32[] memory)
    {
        return frozenSnapshots[pKey].pieceCommitments;
    }

    function _livePartition(bytes32 pKey)
        internal view returns (
            address vk,
            uint8 partitionKind,
            uint64 committedBytes,
            uint64 expiration,
            uint16 challengeCount,
            bool active,
            bytes32 contentHash,
            uint64 contentVersion
        )
    {
        (
            vk,
            ,
            ,
            ,
            partitionKind,
            committedBytes,
            expiration,
            ,
            ,
            ,
            challengeCount,
            active,
            contentHash,
            contentVersion,
            ,
            ,

        ) = storageProof.partitions(pKey);
    }

    function _receiptIsCurrent(bytes32 pKey, ProofReceipt storage receipt)
        internal view returns (bool)
    {
        if (!receipt.acceptedAsCurrent || receipt.contentVersion == 0) return false;
        (
            ,,,,, bool active, bytes32 liveHash, uint64 liveVersion
        ) = _livePartition(pKey);
        return active && liveVersion == receipt.contentVersion && liveHash == receipt.contentHash;
    }

    function _requireExactSnapshot(
        FrozenSnapshot storage snapshot,
        uint64 contentVersion,
        uint64 round
    ) internal view {
        require(snapshot.exists, "SnapshotProof: no frozen snapshot");
        require(snapshot.contentVersion == contentVersion, "SnapshotProof: version mismatch");
        require(snapshot.round == round, "SnapshotProof: round mismatch");
    }

    /// @dev G.2A proof authorisation. An incremental batch authorises ONLY the exact frozen
    ///      identities it selected; a partition that is merely cutoff-eligible is rejected.
    ///      Authority domains never fall back to one another on a membership mismatch.
    function _requireProofAuthorized(
        address vk,
        bytes32 pKey,
        uint8 partitionKind,
        uint64 committedBytes,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 proofEpochId,
        uint64 round,
        bool capturing
    ) internal view {
        require(round <= storageProof.currentRound(), "SnapshotProof: future proof round");
        if (ProofAuthorityDomains.isIncrementalAuthority(proofEpochId)) {
            require(incrementalBatch != address(0) &&
                ICapacityIncrementalBatch_PS(incrementalBatch).isSelectedPartitionFor(
                    vk, pKey, partitionKind, contentVersion, contentHash, committedBytes,
                    proofEpochId, round
                ), "SnapshotProof: incremental epoch mismatch");
            return;
        }
        _requireActiveEpochMember(
            vk, pKey, committedBytes, contentVersion, contentHash, proofEpochId, round, capturing
        );
    }

    function _requireSubmissionAuthorized(bytes32 pKey, FrozenSnapshot storage snapshot) private view {
        require(snapshot.round <= storageProof.currentRound(), "SnapshotProof: future proof round");
        if (!ProofAuthorityDomains.isIncrementalAuthority(snapshot.proofEpochId)) {
            (, , , , , bool active, bytes32 hash, uint64 version) = _livePartition(pKey);
            // A genuinely superseded snapshot remains provable as history. It
            // cannot update current storage freshness or certify its successor.
            if (!active || version != snapshot.contentVersion || hash != snapshot.contentHash) return;
        }
        _requireProofAuthorized(snapshot.vk, pKey, snapshot.partitionKind,
            snapshot.committedBytes, snapshot.contentVersion, snapshot.contentHash,
            snapshot.proofEpochId, snapshot.round, false);
    }

    function _requireActiveEpochMember(
        address vk,
        bytes32 pKey,
        uint64 committedBytes,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 proofEpochId,
        uint64 round,
        bool capturing
    ) internal view {
        if (ProofAuthorityDomains.isDeletionAuthority(proofEpochId)) {
            // G.2C: the id must be the canonical encoding of THIS snapshot's content version.
            // `encodeDeletion` enforces `0 < contentVersion < 1 << 63`, which is what makes the
            // deletion encoding injective; a malformed or out-of-range id reverts here.
            require(
                proofEpochId == ProofAuthorityDomains.encodeDeletion(contentVersion),
                "SnapshotProof: bad deletion proof context"
            );
            require(!capturing || round == storageProof.currentRound(),
                    "SnapshotProof: deletion proof round is not current");
            require(deletionRelease != address(0),
                    "SnapshotProof: deletion release unset");
            require(
                IDeletionRelease_PS(deletionRelease)
                    .isActiveProofAuthorized(
                        pKey, vk, contentVersion, contentHash, committedBytes
                    ),
                "SnapshotProof: deletion successor not authorized"
            );
            return;
        }
        (uint64 epochId, uint64 targetRound,,,,, bool active, bool invalidated) =
            capacityProof.getActiveProofEpoch(vk);
        require(active && !invalidated, "SnapshotProof: no active capacity epoch");
        require(epochId == proofEpochId && targetRound == round,
                "SnapshotProof: capacity epoch mismatch");
        require(
            capacityProof.isActiveEpochVersion(
                vk, pKey, contentVersion, contentHash, proofEpochId
            ),
            "SnapshotProof: version is not an epoch member"
        );
    }

    function _snapshotSeed(bytes32 pKey, FrozenSnapshot storage snapshot)
        internal view returns (bytes32)
    {
        return keccak256(abi.encodePacked(
            "FileTrustPartitionSnapshotV2",
            address(this),
            block.chainid,
            pKey,
            snapshot.proofEpochId,
            snapshot.contentVersion,
            snapshot.contentHash,
            snapshot.round,
            snapshot.challengeAnchor
        ));
    }

    function _buildPublicInputs(FrozenSnapshot storage snapshot, bytes32 seed)
        internal view returns (uint256[] memory inputs)
    {
        uint256 N = uint256(snapshot.circuitSectors);
        uint256 M = uint256(snapshot.circuitChallenges);
        inputs = new uint256[](4 + 4 * N + N * M);
        (uint256 seedHi, uint256 seedLo) = _splitBytes32(seed);
        inputs[0] = seedHi;
        inputs[1] = seedLo;
        inputs[2] = uint256(snapshot.round);
        uint256 k = snapshot.sectorRoots.length;
        for (uint256 i = 0; i < N; i++) {
            uint256 si = i < k ? i : k - 1;
            (uint256 rootHi, uint256 rootLo) = _splitBytes32(snapshot.sectorRoots[si]);
            inputs[3 + i] = rootHi;
            inputs[3 + N + i] = rootLo;
            inputs[3 + 2 * N + i] = uint256(snapshot.sectorBlockCounts[si]);
        }
        inputs[3 + 3 * N] = uint256(snapshot.challengeCount);
        for (uint256 i = 0; i < N; i++) {
            uint256 si = i < k ? i : k - 1;
            uint256[] memory indexes = _challengeIndexes(
                seed,
                snapshot.sectorBlockCounts[si],
                snapshot.challengeCount
            );
            for (uint256 j = 0; j < M; j++) {
                inputs[4 + 3 * N + i * M + j] = j < indexes.length ? indexes[j] : 0;
            }
        }
        for (uint256 i = 0; i < N; i++) {
            uint256 si = i < k ? i : k - 1;
            inputs[4 + 3 * N + N * M + i] = uint256(snapshot.pieceCommitments[si]);
        }
    }

    function _challengeIndexes(bytes32 seed, uint32 blockCount, uint16 challengeCount)
        internal pure returns (uint256[] memory indexes)
    {
        require(blockCount > 0, "SnapshotProof: zero blocks");
        indexes = new uint256[](challengeCount);
        uint256 found = 0;
        uint256 counter = 0;
        while (found < challengeCount) {
            uint256 candidate = uint256(keccak256(abi.encodePacked(seed, counter))) % blockCount;
            bool duplicate = false;
            for (uint256 j = 0; j < found; j++) {
                if (indexes[j] == candidate) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) {
                indexes[found] = candidate;
                found++;
            }
            counter++;
        }
    }

    function _splitBytes32(bytes32 value) internal pure returns (uint256 hi, uint256 lo) {
        uint256 raw = uint256(value);
        hi = raw >> 128;
        lo = raw & ((uint256(1) << 128) - 1);
    }
}
