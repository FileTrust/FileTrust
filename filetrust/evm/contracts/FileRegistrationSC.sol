// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: FileRegistrationSC
// Purpose:  Registering a stored piece against a Vault Keeper, and the custody
//           obligation that registration creates.
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
import {FileTrustDeprecatable} from "./governance/FileTrustDeprecatable.sol";

interface IVaultKeeperRegistry_FR {
    function updateLatestServiceEnd(address vk, uint64 serviceEnd) external;
    function isEligibleVaultKeeper(address vk) external view returns (bool);
}

/// @notice Minimal read-only interface for StorageProofSC used by FileRegistrationSC.
interface IStorageProofSC {
    function partitionKeyOf(address vk, uint8 deadlineIndex, uint8 partitionIndex)
        external pure returns (bytes32);

    function getPartitionSectorRoots(bytes32 pKey)
        external view returns (bytes32[] memory);

    function getPartitionPieceCommitments(bytes32 pKey)
        external view returns (bytes32[] memory);
}

/// @dev Extended interface used only by assessSectorRisk to read proof status.
///      Kept separate so the core IStorageProofSC stays minimal.
interface IStorageProofSCFull is IStorageProofSC {
    function getPartitionProofStatus(bytes32 pKey)
        external view returns (address vk, bool active, uint64 lastProofRound, uint64 registeredAt);

    function getPartitionVersionStatus(bytes32 pKey)
        external view returns (
            bytes32 contentHash,
            uint64 contentVersion,
            bytes32 lastProvenContentHash,
            bool currentContentProven
        );
    function getPartitionReleaseState(bytes32 pKey)
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
}

interface ICapacityProof_FR {
    function consumeQuote(bytes32 registrationCommitment, address expectedVK)
        external returns (uint64 reservedBytes);
    function markDeletionPending(
        bytes32 registrationCommitment,
        address expectedVK,
        bytes32 partitionKey,
        uint64 currentContentVersion
    ) external;
    function releaseDeletedAllocation(
        bytes32 registrationCommitment,
        address expectedVK,
        bytes32 partitionKey,
        uint64 successorContentVersion,
        bytes32 successorContentHash
    ) external;
    function releaseExpiredRegistration(
        bytes32 registrationCommitment,
        address expectedVK
    ) external;
    function releaseUnbackedExpiredRegistration(
        bytes32 registrationCommitment,
        address expectedVK
    ) external;
}

interface IPartitionSnapshotProof_FR {
    function getCurrentPartitionProofStatus(bytes32 pKey)
        external view returns (
            bool current,
            uint64 contentVersion,
            bytes32 contentHash,
            uint64 proofRound,
            uint64 acceptedAt
        );
}

interface IDeletionRelease_FR {
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
    function fileRegistration() external view returns (address);
    function fifoGenerationByPartition(bytes32 partitionKey) external view returns (uint64);
    function createOperation(OperationShellInput calldata input) external;
    function consumeSatisfied(bytes32 operationId) external returns (bool newlyConfirmed);
}

/// @title FileRegistrationSC
/// @notice Privacy-preserving file-storage commitment layer for FileTrust.
///
/// Normal operation
/// ----------------
/// When a VK accepts a piece from a DO it:
///   1. Receives a nonce from the DO (generated off-chain, never stored on-chain).
///   2. Computes commitmentHash = keccak256(abi.encodePacked(pieceRoot, nonce))
///      so that pieceRoot and nonce remain private.
///   3. Calls registerFileStorage() with commitmentHash and the sector placement info.
///   4. Returns a signed PrivateReceiptV1 (off-chain) containing commitmentHash,
///      the echoed nonce, and the on-chain sectorRoot so the DO can verify locally.
///
/// The resulting on-chain record establishes a verifiable chain:
///   commitmentHash → sectorRoot → partition sectorRoots[] → ZK partition proof
///
/// Privacy guarantees
/// ------------------
///   - DO address, fileId, CID, pieceRoot, peerId, and DO-to-VK mapping are NEVER stored.
///   - Only commitmentHash (a blinded binding) and VK-public data are on-chain.
///   - Revealing pieceRoot + nonce happens only during a dispute.
///
/// Partition linkage
/// -----------------
///   After VK calls registerOrUpdatePartition() on StorageProofSC,
///   verifyPartitionContainsSector() can be called to confirm that the sectorRoot
///   registered under commitmentHash actually appears in that partition's sectorRoots[].
///   This is callable by anyone — it only writes a boolean flag, no trust required.
///
/// Sector migration (W7 fix)
/// -------------------------
///   A VK may legitimately move a sector to a different partition slot (e.g. for load
///   balancing).  The on-chain migration protocol prevents silent eviction:
///     1. VK calls updateFileStoragePartition() WHILE the sector is still in the old
///        partition.  This resets partitionLinked and stores a pending migration.
///     2. VK registers the new partition with the sector included.
///     3. DO calls verifyPartitionContainsSector() at the new coordinates, confirming
///        the migration on-chain.  Only at this point is migrationDeclared[oldKey] = true.
///     4. VK may now safely drop the sector from the old partition.
///   Any eviction that skips step 1 — or where step 1 is called after the sector is
///   already gone — is detected by StorageReceiptDispute as an invalid eviction.
contract FileRegistrationSC is FileTrustDeprecatable {

    // ─── Structs ─────────────────────────────────────────────────────────────

    struct FileStorageRecord {
        bytes32 sectorRoot;       // ZK MiMC sector root the VK registered
        bytes32 zkPieceCommitment; // MiMC("FT-COMMIT-V1", pieceRoot_1, ...) — W3 fix
        address vkAddress;        // VK who registered (= msg.sender at registration time)
        uint8   deadlineIndex;    // Proof deadline slot index (updated on migration)
        uint8   partitionIndex;   // Partition index within the deadline (updated on migration)
        uint64  serviceEnd;       // Unix timestamp until piece storage is promised
        uint64  registeredAt;     // Block timestamp of registration
        bool    partitionLinked;  // True after verifyPartitionContainsSector confirms inclusion
        bytes32 deletionAuthHash; // Optional: keccak256(DO-chosen deletion secret)
    }

    /// @dev W7: tracks a declared-but-not-yet-confirmed sector migration.
    ///      Created by updateFileStoragePartition(), cleared by verifyPartitionContainsSector().
    struct PendingMigration {
        uint8 oldDeadlineIndex;
        uint8 oldPartitionIndex;
        bool  pending;
    }

    /// @dev Tracks an on-chain file-deletion declaration by VK and its confirmation status.
    ///      Created by registerFileDeletion(), confirmed by confirmFileDeletion().
    struct DeletionRecord {
        uint64 declaredAt;    // block.timestamp when VK declared deletion
        uint64 graceSeconds;  // snapshot of deletionGraceSeconds at declaration time
        uint64 confirmedAt;   // block.timestamp when deletion was confirmed on-chain
        bool   confirmed;     // true once piece is verified absent from partition
        bool   authorized;    // true when declared with a matching deletion auth secret
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    /// @dev Primary index: commitmentHash → record.
    mapping(bytes32 => FileStorageRecord) public fileRecords;

    /// @dev Reverse index: sectorRoot → list of commitmentHashes registered under it.
    ///      Allows the dispute layer to enumerate every hidden commitment that would
    ///      be affected by a sector omission from a partition.
    mapping(bytes32 => bytes32[]) public sectorRootToCommitments;

    /// @dev Reverse index: registrationCommitment → commitmentHash.
    ///      Used by VKEscrow.claimEscrow() to verify VK registered the file.
    ///      Only populated when registrationCommitment is non-zero (new flow).
    mapping(bytes32 => bytes32) public registrationCommitmentToCommitmentHash;
    /// @dev Reverse index: commitmentHash → registrationCommitment (for lifecycle queries).
    mapping(bytes32 => bytes32) public commitmentHashToRegistrationCommitment;

    /// @dev Attempts expired by the trusted timeout resolver. This supports
    ///      both never-registered attempts and registrations mined after their
    ///      escrow-snapshotted deadline.
    mapping(bytes32 => bool) public expiredRegistrationCommitments;
    mapping(bytes32 => bool) public expiredCommitmentHashes;

    /// @dev W7: pending migration awaiting DO confirmation.
    ///      Key = commitmentHash.
    mapping(bytes32 => PendingMigration) public pendingMigrations;

    /// @dev W7: confirmed migrations.
    ///      Key = keccak256(vkAddress, sectorRoot, oldDeadlineIndex, oldPartitionIndex).
    ///      Set to true only after the DO re-links at the new partition.
    ///      Queried by StorageReceiptDispute to distinguish legitimate migration from eviction.
    mapping(bytes32 => bool) public migrationDeclared;

    /// @dev Deletion records keyed by commitmentHash.
    ///      Created by registerFileDeletion(), confirmed by confirmFileDeletion().
    mapping(bytes32 => DeletionRecord) public deletionRecords;

    /// @dev Aggregate authorization for proving the current successor of a
    ///      partition with one or more declared deletions. This reveals no new
    ///      DO/file relationship: the file record already publishes its VK and
    ///      partition coordinates. The count keeps concurrent deletions on one
    ///      partition correct and bounded.
    mapping(bytes32 => bytes32) private deletionPartitionKey;
    mapping(bytes32 => bool) private expiredUnbackedDeletion;
    mapping(bytes32 => bytes32) public deletionOperationIds;

    /// @dev Global grace period VKs have to update their partition after declaring deletion.
    ///      Snapshotted into each DeletionRecord so future admin changes don't affect open deletions.
    uint64 public deletionGraceSeconds = 7 days;

    /// @dev Trusted StorageProofSC address, set once at construction.
    ///      Prevents callers of verifyPartitionContainsSector / updateFileStoragePartition
    ///      from supplying a fake contract to forge partition linkage or eviction protection.
    address public trustedStorageProofSC;

    address public owner;
    address public vaultKeeperRegistry;
    address public registrationTimeoutResolver;
    address public capacityProof;
    address public partitionSnapshotProof;
    address public deletionRelease;

    // ─── Events ───────────────────────────────────────────────────────────────

    event FileStorageRegistered(
        bytes32 indexed commitmentHash,
        bytes32 indexed sectorRoot,
        address indexed vkAddress,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        uint64  serviceEnd
    );

    event PartitionLinked(
        bytes32 indexed commitmentHash,
        bytes32 indexed sectorRoot
    );

    /// @notice VK accepted a longer storage obligation for an existing record.
    event FileStorageServiceEndExtended(
        bytes32 indexed commitmentHash,
        address indexed vkAddress,
        uint64          serviceEnd
    );

    /// @dev W7: VK declared intent to move a sector. Migration NOT yet confirmed.
    event FileStoragePartitionMigrated(
        bytes32 indexed commitmentHash,
        bytes32 indexed sectorRoot,
        address indexed vkAddress,
        uint8   oldDeadlineIndex,
        uint8   oldPartitionIndex,
        uint8   newDeadlineIndex,
        uint8   newPartitionIndex
    );

    /// @dev W7: DO confirmed migration by re-linking at new partition. Migration complete.
    event PartitionMigrationConfirmed(
        bytes32 indexed commitmentHash,
        bytes32 indexed sectorRoot,
        address indexed vkAddress,
        uint8   oldDeadlineIndex,
        uint8   oldPartitionIndex,
        uint8   newDeadlineIndex,
        uint8   newPartitionIndex
    );

    /// @dev Emitted when VK declares that a file should be deleted (off-chain DO request acknowledged).
    event FileDeletionDeclared(
        bytes32 indexed commitmentHash,
        address indexed vkAddress,
        uint64  graceSeconds,
        uint64  declaredAt
    );

    /// @dev Emitted when deletion is confirmed on-chain: piece is no longer in the partition.
    event FileDeletionConfirmed(
        bytes32 indexed commitmentHash,
        address indexed vkAddress
    );

    event FileDeletionAuthorized(
        bytes32 indexed commitmentHash,
        address indexed vkAddress
    );

    event FileStorageRegistrationExpired(
        bytes32 indexed registrationCommitment,
        bytes32 indexed commitmentHash,
        address indexed vkAddress,
        uint64 registrationDeadline,
        bool registeredLate
    );

    /// @dev Emitted when the owner updates the global deletion grace period.
    event DeletionGraceSecondsUpdated(uint64 oldValue, uint64 newValue);
    event CapacityProofSet(address indexed capacityProof);
    event PartitionSnapshotProofSet(address indexed partitionSnapshotProof);
    event DeletionReleaseSet(address indexed deletionRelease);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor(address _storageProofSC) {
        require(_storageProofSC != address(0), "FileReg: zero storageProofSC");
        trustedStorageProofSC = _storageProofSC;
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "FileReg: only owner");
        require(newOwner != address(0), "FileReg: zero owner");
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /// @notice Close this version to new registrations without a capacity reservation when its successor opens (Phase 2), for
    ///         good. A registration
    ///         that consumes a quote reserved before deprecation, and every existing record's
    ///         extensions, migrations and deletions, keep working.
    function deprecate(address successor) external {
        require(msg.sender == owner, "FileReg: only owner");
        _deprecate(successor);
    }

    function setVaultKeeperRegistry(address _vkr) external {
        require(msg.sender == owner, "FileReg: only owner");
        vaultKeeperRegistry = _vkr;
    }

    function setRegistrationTimeoutResolver(address resolver) external {
        require(msg.sender == owner, "FileReg: only owner");
        require(resolver != address(0), "FileReg: zero timeout resolver");
        registrationTimeoutResolver = resolver;
    }

    function setCapacityProof(address capacityProof_) external {
        require(msg.sender == owner, "FileReg: only owner");
        require(capacityProof_ != address(0), "FileReg: zero capacity proof");
        require(capacityProof == address(0), "FileReg: capacity proof already set");
        capacityProof = capacityProof_;
        emit CapacityProofSet(capacityProof_);
    }

    function setPartitionSnapshotProof(address snapshotProof_) external {
        require(msg.sender == owner, "FileReg: only owner");
        require(snapshotProof_ != address(0), "FileReg: zero snapshot proof");
        require(partitionSnapshotProof == address(0), "FileReg: snapshot proof already set");
        partitionSnapshotProof = snapshotProof_;
        emit PartitionSnapshotProofSet(snapshotProof_);
    }

    function setDeletionRelease(address deletionRelease_) external {
        require(msg.sender == owner, "FileReg: only owner");
        require(deletionRelease_ != address(0), "FileReg: zero deletion release");
        require(deletionRelease_.code.length > 0, "FileReg: deletion release no code");
        require(deletionRelease == address(0), "FileReg: deletion release already set");
        require(
            IDeletionRelease_FR(deletionRelease_).fileRegistration() == address(this),
            "FileReg: deletion release not reciprocal"
        );
        deletionRelease = deletionRelease_;
        emit DeletionReleaseSet(deletionRelease_);
    }

    // ─── VK registration ─────────────────────────────────────────────────────

    /// @notice Register a hidden piece-storage commitment on-chain.
    /// @param registrationCommitment  keccak256(regNullifier || regSecret) — links to VKEscrow.
    ///                                Pass bytes32(0) for legacy registrations without escrow.
    function registerFileStorage(
        bytes32 commitmentHash,
        bytes32 sectorRoot,
        bytes32 zkPieceCommitment,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        uint64  serviceEnd,
        bytes32 registrationCommitment
    ) external {
        _registerFileStorage(
            commitmentHash,
            sectorRoot,
            zkPieceCommitment,
            deadlineIndex,
            partitionIndex,
            serviceEnd,
            registrationCommitment,
            bytes32(0)
        );
    }

    /// @notice Register a hidden piece-storage commitment with a DO-chosen deletion auth hash.
    /// @dev deletionAuthHash = keccak256(deletionAuthSecret). The secret is revealed only
    ///      when the DO asks the VK to delete the piece before serviceEnd.
    function registerFileStorageV2(
        bytes32 commitmentHash,
        bytes32 sectorRoot,
        bytes32 zkPieceCommitment,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        uint64  serviceEnd,
        bytes32 registrationCommitment,
        bytes32 deletionAuthHash
    ) external {
        _registerFileStorage(
            commitmentHash,
            sectorRoot,
            zkPieceCommitment,
            deadlineIndex,
            partitionIndex,
            serviceEnd,
            registrationCommitment,
            deletionAuthHash
        );
    }

    function _registerFileStorage(
        bytes32 commitmentHash,
        bytes32 sectorRoot,
        bytes32 zkPieceCommitment,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        uint64  serviceEnd,
        bytes32 registrationCommitment,
        bytes32 deletionAuthHash
    ) internal {
        require(commitmentHash    != bytes32(0), "FileReg: zero commitmentHash");
        require(sectorRoot        != bytes32(0), "FileReg: zero sectorRoot");
        require(zkPieceCommitment != bytes32(0), "FileReg: zero zkPieceCommitment");
        require(serviceEnd         > 0,          "FileReg: zero serviceEnd");
        require(vaultKeeperRegistry != address(0), "FileReg: VK registry not configured");
        require(
            IVaultKeeperRegistry_FR(vaultKeeperRegistry).isEligibleVaultKeeper(msg.sender),
            "FileReg: VK not eligible"
        );
        require(
            fileRecords[commitmentHash].vkAddress == address(0),
            "FileReg: already registered"
        );
        // Prevent two VKs from using the same registrationCommitment (collision protection).
        if (registrationCommitment != bytes32(0)) {
            require(
                !expiredRegistrationCommitments[registrationCommitment],
                "FileReg: registration attempt expired"
            );
            require(
                registrationCommitmentToCommitmentHash[registrationCommitment] == bytes32(0),
                "FileReg: registrationCommitment already used"
            );
        }
        if (capacityProof != address(0)) {
            require(registrationCommitment != bytes32(0),
                    "FileReg: capacity-backed registration requires reservation");
            ICapacityProof_FR(capacityProof).consumeQuote(
                registrationCommitment, msg.sender
            );
        } else {
            _requireNotDeprecated();
        }

        fileRecords[commitmentHash] = FileStorageRecord({
            sectorRoot:       sectorRoot,
            zkPieceCommitment: zkPieceCommitment,
            vkAddress:        msg.sender,
            deadlineIndex:    deadlineIndex,
            partitionIndex:   partitionIndex,
            serviceEnd:       serviceEnd,
            registeredAt:     uint64(block.timestamp),
            partitionLinked:  false,
            deletionAuthHash: deletionAuthHash
        });

        sectorRootToCommitments[sectorRoot].push(commitmentHash);

        if (registrationCommitment != bytes32(0)) {
            registrationCommitmentToCommitmentHash[registrationCommitment] = commitmentHash;
            commitmentHashToRegistrationCommitment[commitmentHash] = registrationCommitment;
        }

        // Extend VK's tracked latest service obligation so StakingManager can enforce
        // stake withdrawal only after all stored files have passed their serviceEnd.
        IVaultKeeperRegistry_FR(vaultKeeperRegistry).updateLatestServiceEnd(msg.sender, serviceEnd);

        emit FileStorageRegistered(
            commitmentHash,
            sectorRoot,
            msg.sender,
            deadlineIndex,
            partitionIndex,
            serviceEnd
        );
    }

    /// @notice Fence an escrow-backed registration attempt after its deadline.
    ///         A record registered on time is protected and cannot be expired.
    function expireRegistrationCommitment(
        bytes32 registrationCommitment,
        address expectedVK,
        uint64 registrationDeadline
    ) external returns (bytes32 commitmentHash, bool registeredLate) {
        require(msg.sender == registrationTimeoutResolver, "FileReg: only timeout resolver");
        require(registrationCommitment != bytes32(0), "FileReg: zero registration commitment");
        require(expectedVK != address(0), "FileReg: zero VK");
        require(registrationDeadline > 0 && block.timestamp > registrationDeadline,
                "FileReg: registration deadline active");
        require(!expiredRegistrationCommitments[registrationCommitment],
                "FileReg: registration already expired");

        commitmentHash = registrationCommitmentToCommitmentHash[registrationCommitment];
        if (commitmentHash != bytes32(0)) {
            FileStorageRecord storage rec = fileRecords[commitmentHash];
            require(rec.vkAddress == expectedVK, "FileReg: quote VK mismatch");
            require(rec.registeredAt > registrationDeadline,
                    "FileReg: timely registration exists");
            expiredCommitmentHashes[commitmentHash] = true;
            registeredLate = true;
            if (deletionRecords[commitmentHash].declaredAt == 0) {
                (bytes32 deletionKey, bool unbacked) = _authorizeDeletionSuccessor(
                    commitmentHash, registrationCommitment, rec, true
                );
                uint64 grace = deletionGraceSeconds;
                deletionRecords[commitmentHash] = DeletionRecord({
                    declaredAt: uint64(block.timestamp),
                    graceSeconds: grace,
                    confirmedAt: 0,
                    confirmed: false,
                    authorized: true
                });
                if (!unbacked) {
                    _createDeletionReleaseOperation(commitmentHash, deletionKey, rec);
                }
                emit FileDeletionAuthorized(commitmentHash, rec.vkAddress);
                emit FileDeletionDeclared(
                    commitmentHash, rec.vkAddress, grace, uint64(block.timestamp)
                );
            }
        } else if (capacityProof != address(0)) {
            ICapacityProof_FR(capacityProof).releaseExpiredRegistration(
                registrationCommitment, expectedVK
            );
        }
        expiredRegistrationCommitments[registrationCommitment] = true;
        emit FileStorageRegistrationExpired(
            registrationCommitment,
            commitmentHash,
            expectedVK,
            registrationDeadline,
            registeredLate
        );
    }

    // ─── Partition linkage ────────────────────────────────────────────────────

    /// @notice Verify that the registered sectorRoot for a commitmentHash appears
    ///         in the partition's sectorRoots[] on StorageProofSC, then mark the
    ///         record partitionLinked = true.
    ///
    /// @dev Callable by anyone.  If a pending migration exists for this commitmentHash
    ///      and the sector is now confirmed in the new partition, the migration is
    ///      finalized: migrationDeclared[oldKey] is set and the pending entry is cleared.
    function verifyPartitionContainsSector(
        bytes32 commitmentHash
    ) external {
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        require(rec.vkAddress  != address(0), "FileReg: record not found");
        require(!rec.partitionLinked,          "FileReg: already linked");

        IStorageProofSC sc = IStorageProofSC(trustedStorageProofSC);
        bytes32 pKey = sc.partitionKeyOf(
            rec.vkAddress, rec.deadlineIndex, rec.partitionIndex
        );
        bytes32[] memory roots = sc.getPartitionSectorRoots(pKey);

        uint256 slotIndex = type(uint256).max;
        for (uint256 i = 0; i < roots.length; i++) {
            if (roots[i] == rec.sectorRoot) {
                slotIndex = i;
                break;
            }
        }
        require(slotIndex != type(uint256).max, "FileReg: sectorRoot not in partition");

        // W3: verify zkPieceCommitment for this sector slot.
        bytes32[] memory pcs = sc.getPartitionPieceCommitments(pKey);
        require(
            slotIndex < pcs.length && pcs[slotIndex] == rec.zkPieceCommitment,
            "FileReg: zkPieceCommitment mismatch (W3)"
        );

        // W7: if this verifyPartitionContainsSector call is the DO's confirmation of a
        //     pending migration, finalize it — set migrationDeclared for the OLD slot.
        PendingMigration storage pm = pendingMigrations[commitmentHash];
        if (pm.pending) {
            bytes32 migKey = keccak256(abi.encodePacked(
                rec.vkAddress, rec.sectorRoot,
                pm.oldDeadlineIndex, pm.oldPartitionIndex
            ));
            migrationDeclared[migKey] = true;
            emit PartitionMigrationConfirmed(
                commitmentHash, rec.sectorRoot, rec.vkAddress,
                pm.oldDeadlineIndex, pm.oldPartitionIndex,
                rec.deadlineIndex,   rec.partitionIndex
            );
            pm.pending = false;
        }

        rec.partitionLinked = true;
        emit PartitionLinked(commitmentHash, rec.sectorRoot);
    }

    // ─── Sector migration (W7 fix) ────────────────────────────────────────────

    /// @notice VK declares intent to move a sector to a different partition slot.
    ///
    /// @dev MUST be called while the sector is still in the old partition.
    ///      Calling this after the sector has already been dropped will revert.
    ///      After this call:
    ///        - partitionLinked is reset to false.
    ///        - The record's deadlineIndex/partitionIndex point to the new slot.
    ///        - A pending migration is stored; migration is NOT yet finalized.
    ///      The migration becomes fully confirmed (migrationDeclared = true for the OLD
    ///      partition coordinates) only when the DO calls verifyPartitionContainsSector
    ///      at the new partition.  The VK should not drop the sector from the old
    ///      partition until that confirmation has been emitted on-chain.
    ///
    /// @param commitmentHash    The file commitment being migrated.
    /// @param newDeadlineIndex  Target deadline slot.
    /// @param newPartitionIndex Target partition slot.
    function updateFileStoragePartition(
        bytes32 commitmentHash,
        uint8   newDeadlineIndex,
        uint8   newPartitionIndex
    ) external {
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        require(rec.vkAddress  != address(0), "FileReg: record not found");
        require(rec.vkAddress  == msg.sender,  "FileReg: not record VK");
        require(vaultKeeperRegistry != address(0), "FileReg: VK registry not configured");
        require(
            IVaultKeeperRegistry_FR(vaultKeeperRegistry).isEligibleVaultKeeper(msg.sender),
            "FileReg: VK not eligible"
        );
        require(rec.partitionLinked,            "FileReg: not yet linked");
        require(
            newDeadlineIndex != rec.deadlineIndex || newPartitionIndex != rec.partitionIndex,
            "FileReg: same partition"
        );
        require(!pendingMigrations[commitmentHash].pending, "FileReg: migration already pending");

        // Verify the sector is STILL in the old partition at declaration time.
        // This prevents a malicious VK from dropping the sector first and then
        // retroactively calling updateFileStoragePartition to falsely protect against
        // a dispute.
        IStorageProofSC sc = IStorageProofSC(trustedStorageProofSC);
        bytes32 oldPKey = sc.partitionKeyOf(rec.vkAddress, rec.deadlineIndex, rec.partitionIndex);
        bytes32[] memory roots = sc.getPartitionSectorRoots(oldPKey);
        bool found = false;
        for (uint256 i = 0; i < roots.length; i++) {
            if (roots[i] == rec.sectorRoot) { found = true; break; }
        }
        require(found, "FileReg: sector already dropped from old partition");

        uint8 oldDL = rec.deadlineIndex;
        uint8 oldPI = rec.partitionIndex;

        // Update record to point at the new partition.
        rec.deadlineIndex  = newDeadlineIndex;
        rec.partitionIndex = newPartitionIndex;
        rec.partitionLinked = false;   // DO must re-verify at new location

        // Store pending migration so verifyPartitionContainsSector can confirm it.
        pendingMigrations[commitmentHash] = PendingMigration({
            oldDeadlineIndex:  oldDL,
            oldPartitionIndex: oldPI,
            pending:           true
        });

        emit FileStoragePartitionMigrated(
            commitmentHash, rec.sectorRoot, msg.sender,
            oldDL, oldPI,
            newDeadlineIndex, newPartitionIndex
        );
    }

    // ─── File deletion (new) ─────────────────────────────────────────────────

    /// @notice VK declares that it will delete a stored piece at the DO's request.
    ///
    /// @dev Called by VK after receiving an off-chain deletion request from the DO.
    ///      Mirrors the registration step of the storage lifecycle in reverse:
    ///        1. DO requests deletion off-chain.
    ///        2. VK calls registerFileDeletion() here.
    ///        3. VK calls StorageProofSC.registerOrUpdatePartition() with the piece removed.
    ///        4. Anyone calls confirmFileDeletion() to finalize on-chain.
    ///
    ///      The grace period (snapshotted from deletionGraceSeconds) gives VK time to
    ///      update the partition before the DO can file a deletion-failure dispute.
    function registerFileDeletion(bytes32 commitmentHash) external {
        _registerFileDeletion(commitmentHash, bytes32(0), false);
    }

    /// @notice Declare deletion with a DO-provided authorization secret.
    /// @dev Required for records registered with registerFileStorageV2 and deletionAuthHash != 0.
    function registerFileDeletionAuthorized(
        bytes32 commitmentHash,
        bytes32 deletionAuthSecret
    ) external {
        _registerFileDeletion(commitmentHash, deletionAuthSecret, true);
    }

    function _registerFileDeletion(
        bytes32 commitmentHash,
        bytes32 deletionAuthSecret,
        bool requireAuthorization
    ) internal {
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        require(rec.vkAddress != address(0), "FileReg: record not found");
        require(rec.vkAddress == msg.sender,  "FileReg: not record VK");
        require(deletionRecords[commitmentHash].declaredAt == 0,
                "FileReg: deletion already declared");

        bool authorized = false;
        if (rec.deletionAuthHash != bytes32(0)) {
            require(requireAuthorization, "FileReg: deletion authorization required");
            require(deletionAuthSecret != bytes32(0), "FileReg: zero deletion auth secret");
            require(
                keccak256(abi.encodePacked(deletionAuthSecret)) == rec.deletionAuthHash,
                "FileReg: invalid deletion auth secret"
            );
            authorized = true;
        } else {
            require(!requireAuthorization, "FileReg: deletion auth hash missing");
        }

        (bytes32 deletionKey, bool unbacked) = _authorizeDeletionSuccessor(
            commitmentHash,
            commitmentHashToRegistrationCommitment[commitmentHash],
            rec,
            false
        );

        uint64 grace = deletionGraceSeconds;
        deletionRecords[commitmentHash] = DeletionRecord({
            declaredAt:   uint64(block.timestamp),
            graceSeconds: grace,
            confirmedAt:  0,
            confirmed:    false,
            authorized:   authorized
        });
        if (!unbacked) {
            _createDeletionReleaseOperation(commitmentHash, deletionKey, rec);
        }

        if (authorized) {
            emit FileDeletionAuthorized(commitmentHash, msg.sender);
        }
        emit FileDeletionDeclared(commitmentHash, msg.sender, grace, uint64(block.timestamp));
    }

    function _authorizeDeletionSuccessor(
        bytes32 commitmentHash,
        bytes32 registrationCommitment,
        FileStorageRecord storage rec,
        bool allowUnbackedExpired
    ) internal returns (bytes32 pKey, bool unbacked) {
        pKey = IStorageProofSC(trustedStorageProofSC).partitionKeyOf(
            rec.vkAddress, rec.deadlineIndex, rec.partitionIndex
        );
        bytes32[] memory roots = IStorageProofSC(trustedStorageProofSC)
            .getPartitionSectorRoots(pKey);
        bytes32[] memory pieces = IStorageProofSC(trustedStorageProofSC)
            .getPartitionPieceCommitments(pKey);
        bool backedByClaimedSlot = false;
        uint256 slotCount = roots.length < pieces.length ? roots.length : pieces.length;
        for (uint256 i = 0; i < slotCount; i++) {
            if (roots[i] == rec.sectorRoot && pieces[i] == rec.zkPieceCommitment) {
                backedByClaimedSlot = true;
                break;
            }
        }
        if (!backedByClaimedSlot && allowUnbackedExpired) {
            if (capacityProof != address(0)) {
                require(registrationCommitment != bytes32(0),
                        "FileReg: deletion reservation missing");
                ICapacityProof_FR(capacityProof).releaseUnbackedExpiredRegistration(
                    registrationCommitment, rec.vkAddress
                );
            }
            deletionPartitionKey[commitmentHash] = pKey;
            expiredUnbackedDeletion[commitmentHash] = true;
            return (pKey, true);
        }
        require(backedByClaimedSlot, "FileReg: deletion file slot unavailable");
        (, uint64 contentVersion,,) = IStorageProofSCFull(trustedStorageProofSC)
            .getPartitionVersionStatus(pKey);
        require(contentVersion > 0, "FileReg: deletion partition unavailable");
        if (capacityProof != address(0)) {
            require(registrationCommitment != bytes32(0),
                    "FileReg: deletion reservation missing");
            ICapacityProof_FR(capacityProof).markDeletionPending(
                registrationCommitment, rec.vkAddress, pKey, contentVersion
            );
        }
        deletionPartitionKey[commitmentHash] = pKey;
        return (pKey, false);
    }

    function _createDeletionReleaseOperation(
        bytes32 commitmentHash,
        bytes32 pKey,
        FileStorageRecord storage rec
    ) internal {
        require(deletionRelease != address(0), "FileReg: deletion release not configured");
        (
            address vk,
            uint8 kind,
            bool active,
            uint64 contentVersion,
            bytes32 contentHash,
            uint64 committedBytes,
            uint64 registrationNonce,
            uint64 transitionNonce
        ) = IStorageProofSCFull(trustedStorageProofSC)
            .getPartitionReleaseState(pKey);
        bytes32[] memory pieces = IStorageProofSC(trustedStorageProofSC)
            .getPartitionPieceCommitments(pKey);
        require(vk == rec.vkAddress && kind == 1 && active,
                "FileReg: invalid deletion source");
        bool found;
        for (uint256 i = 0; i < pieces.length; i++) {
            if (pieces[i] == rec.zkPieceCommitment) {
                found = true;
                break;
            }
        }
        require(found, "FileReg: deleted piece not in source");
        uint64 fifoGeneration =
            IDeletionRelease_FR(deletionRelease).fifoGenerationByPartition(pKey) + 1;
        require(fifoGeneration != 0, "FileReg: deletion FIFO exhausted");
        bytes32 operationId = DeletionReleaseIdentity.operationId(
            block.chainid,
            address(this),
            deletionRelease,
            vk,
            commitmentHash,
            pKey,
            fifoGeneration
        );
        deletionOperationIds[commitmentHash] = operationId;
        IDeletionRelease_FR(deletionRelease).createOperation(
            IDeletionRelease_FR.OperationShellInput({
                vk: vk,
                operationId: operationId,
                sourcePartitionKey: pKey,
                sourceKind: kind,
                sourceActive: active,
                sourceContentVersion: contentVersion,
                sourceContentHash: contentHash,
                sourceCommittedBytes: committedBytes,
                sourceRegistrationNonce: registrationNonce,
                sourceTransitionNonce: transitionNonce,
                deletedFileCommitment: commitmentHash,
                deletedPieceCommitment: rec.zkPieceCommitment,
                fifoGeneration: fifoGeneration
            })
        );
    }

    /// @notice Confirm on-chain that VK has removed the piece from its partition.
    ///
    /// @dev Callable by anyone — trustless, because it only reads partition state from
    ///      the trusted StorageProofSC and sets a boolean flag.  No economic effect here;
    ///      the confirmed flag simply prevents future storage-failure disputes on this
    ///      commitment and satisfies any open deletion-failure dispute.
    ///
    ///      VK must have called StorageProofSC.registerOrUpdatePartition() first, removing
    ///      the zkPieceCommitment from that partition's pieceCommitments[] array.
    ///      If the partition still contains other files, the current partition version
    ///      must also be proven before confirmation succeeds.
    function confirmFileDeletion(bytes32 commitmentHash) external {
        DeletionRecord storage dr = deletionRecords[commitmentHash];
        require(dr.declaredAt > 0,  "FileReg: deletion not declared");
        if (dr.confirmed) return;

        FileStorageRecord storage rec = fileRecords[commitmentHash];
        IStorageProofSC sc = IStorageProofSC(trustedStorageProofSC);
        bytes32 pKey = sc.partitionKeyOf(
            rec.vkAddress, rec.deadlineIndex, rec.partitionIndex
        );
        bool unbackedExpired = expiredUnbackedDeletion[commitmentHash];
        bytes32[] memory pcs = sc.getPartitionPieceCommitments(pKey);
        for (uint256 i = 0; i < pcs.length; i++) {
            require(
                pcs[i] != rec.zkPieceCommitment,
                "FileReg: piece still present in partition"
            );
        }
        (bytes32 successorHash, uint64 successorVersion,,) =
            IStorageProofSCFull(trustedStorageProofSC).getPartitionVersionStatus(pKey);
        if (!unbackedExpired) {
            bytes32 operationId = deletionOperationIds[commitmentHash];
            require(operationId != bytes32(0), "FileReg: deletion operation missing");
            IDeletionRelease_FR(deletionRelease).consumeSatisfied(operationId);
        }
        if (capacityProof != address(0) && !unbackedExpired) {
            bytes32 registrationCommitment =
                commitmentHashToRegistrationCommitment[commitmentHash];
            ICapacityProof_FR(capacityProof).releaseDeletedAllocation(
                registrationCommitment,
                rec.vkAddress,
                pKey,
                successorVersion,
                successorHash
            );
        }

        require(deletionPartitionKey[commitmentHash] == pKey,
                "FileReg: deletion partition identity changed");
        delete deletionPartitionKey[commitmentHash];
        if (unbackedExpired) {
            require(expiredCommitmentHashes[commitmentHash],
                    "FileReg: unbacked deletion is not expired");
            delete expiredUnbackedDeletion[commitmentHash];
        }

        dr.confirmed   = true;
        dr.confirmedAt = uint64(block.timestamp);
        emit FileDeletionConfirmed(commitmentHash, rec.vkAddress);
    }

    /// @notice Update the global grace period given to VKs after declaring deletion.
    function setDeletionGraceSeconds(uint64 newGrace) external {
        require(msg.sender == owner, "FileReg: only owner");
        require(newGrace >= 1 hours, "FileReg: grace too short");
        emit DeletionGraceSecondsUpdated(deletionGraceSeconds, newGrace);
        deletionGraceSeconds = newGrace;
    }

    // ─── View functions ───────────────────────────────────────────────────────

    function getRecord(bytes32 commitmentHash)
        external view returns (FileStorageRecord memory)
    {
        return fileRecords[commitmentHash];
    }

    function isDeletionReleaseOperationDeclared(
        bytes32 operationId,
        bytes32 commitmentHash,
        bytes32 pKey,
        address vk,
        bytes32 pieceCommitment
    ) external view returns (bool) {
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        DeletionRecord storage record = deletionRecords[commitmentHash];
        return deletionRelease != address(0) &&
            deletionOperationIds[commitmentHash] == operationId &&
            deletionPartitionKey[commitmentHash] == pKey &&
            record.declaredAt != 0 && !record.confirmed &&
            rec.vkAddress == vk && rec.zkPieceCommitment == pieceCommitment;
    }

    function recordExists(bytes32 commitmentHash)
        external view returns (bool)
    {
        return fileRecords[commitmentHash].vkAddress != address(0);
    }

    /// @notice Return ALL commitmentHashes registered under sectorRoot (unbounded).
    ///         For large sectors use getCommitmentsForSector(sectorRoot, offset, limit).
    function getCommitmentsForSector(bytes32 sectorRoot)
        external view returns (bytes32[] memory)
    {
        return sectorRootToCommitments[sectorRoot];
    }

    /// @notice Paginated variant — safe for sectors with many commitments.
    /// @param offset  First index to return (0-based).
    /// @param limit   Maximum entries to return.
    /// @return page   Slice of commitmentHashes[offset .. offset+limit].
    /// @return total  Total number of commitments registered under this sectorRoot.
    function getCommitmentsForSector(
        bytes32 sectorRoot,
        uint256 offset,
        uint256 limit
    ) external view returns (bytes32[] memory page, uint256 total) {
        bytes32[] storage all = sectorRootToCommitments[sectorRoot];
        total = all.length;
        if (offset >= total || limit == 0) {
            return (new bytes32[](0), total);
        }
        uint256 end  = offset + limit;
        if (end > total) end = total;
        uint256 size = end - offset;
        page = new bytes32[](size);
        for (uint256 i = 0; i < size; i++) {
            page[i] = all[offset + i];
        }
    }

    /// @notice Returns the number of commitments registered under a sectorRoot.
    ///         Used by StorageReceiptDispute to populate SectorRiskNotice cheaply.
    function sectorCommitmentCount(bytes32 sectorRoot)
        external view returns (uint256)
    {
        return sectorRootToCommitments[sectorRoot].length;
    }

    // ─── W8: assessSectorRisk ────────────────────────────────────────────────

    /// @notice Per-commitment risk entry returned by assessSectorRisk.
    struct CommitmentRiskEntry {
        bytes32 commitmentHash;
        address vkAddress;
        bool    partitionLinked;
        uint8   deadlineIndex;
        uint8   partitionIndex;
        bool    partitionActive;   // only populated when storageProofSC != address(0)
        uint64  lastProofRound;    // only populated when storageProofSC != address(0)
    }

    /// @notice Returns the risk status of every commitment stored in a sector.
    ///         Pass storageProofSC = address(0) to skip the on-chain proof status lookup.
    ///
    /// @dev    View-only — safe to call off-chain at any gas cost.  For sectors with
    ///         many commitments, call getCommitmentsForSector with pagination first to
    ///         identify which subset you care about, then call this for just those entries.
    function assessSectorRisk(
        bytes32 sectorRoot,
        address storageProofSC
    ) external view returns (CommitmentRiskEntry[] memory entries) {
        bytes32[] storage chs = sectorRootToCommitments[sectorRoot];
        uint256 n = chs.length;
        entries = new CommitmentRiskEntry[](n);

        for (uint256 i = 0; i < n; i++) {
            bytes32 ch = chs[i];
            FileStorageRecord storage rec = fileRecords[ch];
            entries[i].commitmentHash  = ch;
            entries[i].vkAddress       = rec.vkAddress;
            entries[i].partitionLinked = rec.partitionLinked;
            entries[i].deadlineIndex   = rec.deadlineIndex;
            entries[i].partitionIndex  = rec.partitionIndex;

            if (storageProofSC != address(0) && rec.vkAddress != address(0)) {
                IStorageProofSC sp = IStorageProofSC(storageProofSC);
                bytes32 pKey = sp.partitionKeyOf(
                    rec.vkAddress, rec.deadlineIndex, rec.partitionIndex
                );
                // IStorageProofSC doesn't expose getPartitionProofStatus here; use
                // a try-call on the full interface cast.
                try IStorageProofSCFull(storageProofSC).getPartitionProofStatus(pKey)
                    returns (address, bool active, uint64 lpr, uint64)
                {
                    entries[i].partitionActive = active;
                    entries[i].lastProofRound  = lpr;
                } catch {}
            }
        }
    }

    /// @notice Returns true when a registrationCommitment was registered on-chain by any VK.
    ///         Called by VKEscrow.claimEscrow() to verify VK actually stored the file.
    function registrationCommitmentExists(bytes32 registrationCommitment)
        external view returns (bool)
    {
        return registrationCommitmentToCommitmentHash[registrationCommitment] != bytes32(0);
    }

    /// @notice Returns true only when registrationCommitment exists and has not
    ///         been deletion-confirmed on-chain yet.
    function registrationCommitmentIsActive(bytes32 registrationCommitment)
        external view returns (bool)
    {
        if (expiredRegistrationCommitments[registrationCommitment]) return false;
        bytes32 ch = registrationCommitmentToCommitmentHash[registrationCommitment];
        if (ch == bytes32(0)) return false;
        if (expiredCommitmentHashes[ch]) return false;
        return !deletionRecords[ch].confirmed;
    }

    /// @notice Exact-current proof evidence used by escrow at service end.
    ///         It reveals no new relationship before claim because callers need
    ///         the private registration commitment to select a record.
    function registrationCurrentProofStatus(bytes32 registrationCommitment)
        external view returns (address vk, bool current, uint64 acceptedAt)
    {
        if (expiredRegistrationCommitments[registrationCommitment]) {
            return (address(0), false, 0);
        }
        bytes32 commitmentHash =
            registrationCommitmentToCommitmentHash[registrationCommitment];
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        if (
            commitmentHash == bytes32(0) || rec.vkAddress == address(0) ||
            expiredCommitmentHashes[commitmentHash] ||
            deletionRecords[commitmentHash].confirmed ||
            !rec.partitionLinked || partitionSnapshotProof == address(0)
        ) return (rec.vkAddress, false, 0);
        bytes32 pKey = IStorageProofSC(trustedStorageProofSC).partitionKeyOf(
            rec.vkAddress, rec.deadlineIndex, rec.partitionIndex
        );
        (current,,,, acceptedAt) = IPartitionSnapshotProof_FR(partitionSnapshotProof)
            .getCurrentPartitionProofStatus(pKey);
        return (rec.vkAddress, current, acceptedAt);
    }

    /// @notice serviceEnd currently recorded for a registration, or 0 if unknown.
    ///         VKEscrow reads this at claim time to confirm the VK carries the
    ///         obligation for the whole term it is being paid for.
    function registrationServiceEnd(bytes32 registrationCommitment)
        external view returns (uint64)
    {
        bytes32 commitmentHash =
            registrationCommitmentToCommitmentHash[registrationCommitment];
        if (commitmentHash == bytes32(0)) return 0;
        return fileRecords[commitmentHash].serviceEnd;
    }

    /// @notice VK extends its own storage obligation to a later serviceEnd.
    ///
    /// @dev Forward-only and VK-only. This is the liability half of a renewal:
    ///      the VK accepts the longer term here BEFORE it can be paid for it,
    ///      because VKEscrow.claimEscrow() checks this record covers the escrow's
    ///      serviceEnd. Leaks nothing new — the record already publishes its VK
    ///      and partition coordinates, and no DO identity appears here.
    function extendServiceEnd(bytes32 commitmentHash, uint64 newServiceEnd) external {
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        require(rec.vkAddress != address(0), "FileReg: record not found");
        require(rec.vkAddress == msg.sender, "FileReg: not record VK");
        require(newServiceEnd > rec.serviceEnd, "FileReg: serviceEnd not later");
        require(!expiredCommitmentHashes[commitmentHash], "FileReg: registration expired");
        require(!deletionRecords[commitmentHash].confirmed, "FileReg: piece already deleted");
        // An obligation that already lapsed cannot be revived: assessSectorRisk
        // stops holding the VK liable at serviceEnd, so the piece may be gone.
        require(rec.serviceEnd > block.timestamp, "FileReg: service period ended");

        rec.serviceEnd = newServiceEnd;

        // Keep stake withdrawal gated behind the extended obligation.
        IVaultKeeperRegistry_FR(vaultKeeperRegistry).updateLatestServiceEnd(
            msg.sender, newServiceEnd
        );

        emit FileStorageServiceEndExtended(commitmentHash, msg.sender, newServiceEnd);
    }

    function commitmentHashIsActive(bytes32 commitmentHash) external view returns (bool) {
        if (fileRecords[commitmentHash].vkAddress == address(0)) return false;
        if (expiredCommitmentHashes[commitmentHash]) return false;
        return !deletionRecords[commitmentHash].confirmed;
    }

    /// @notice Returns the migration key used in migrationDeclared for a given
    ///         (vk, sectorRoot, old partition) combination.
    ///         Useful off-chain for querying migration status.
    function migrationKey(
        address vkAddress,
        bytes32 sectorRoot,
        uint8   oldDeadlineIndex,
        uint8   oldPartitionIndex
    ) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            vkAddress, sectorRoot, oldDeadlineIndex, oldPartitionIndex
        ));
    }

    // ─── Deletion view helpers ────────────────────────────────────────────────

    /// @notice Returns true when VK has declared deletion for this commitmentHash.
    function isDeletionDeclared(bytes32 commitmentHash) external view returns (bool) {
        return deletionRecords[commitmentHash].declaredAt > 0;
    }

    /// @notice Returns true when deletion has been confirmed on-chain
    ///         (piece verified absent from partition).
    function isDeletionConfirmed(bytes32 commitmentHash) external view returns (bool) {
        return deletionRecords[commitmentHash].confirmed;
    }

    /// @notice Returns the full deletion record for a commitmentHash.
    function getDeletionRecord(bytes32 commitmentHash)
        external view
        returns (uint64 declaredAt, uint64 graceSeconds, bool confirmed)
    {
        DeletionRecord storage dr = deletionRecords[commitmentHash];
        return (dr.declaredAt, dr.graceSeconds, dr.confirmed);
    }

    function getDeletionRecordV2(bytes32 commitmentHash)
        external view
        returns (
            uint64 declaredAt,
            uint64 graceSeconds,
            uint64 confirmedAt,
            bool confirmed,
            bool authorized
        )
    {
        DeletionRecord storage dr = deletionRecords[commitmentHash];
        return (dr.declaredAt, dr.graceSeconds, dr.confirmedAt, dr.confirmed, dr.authorized);
    }

    function isDeletionAuthorized(bytes32 commitmentHash) external view returns (bool) {
        return deletionRecords[commitmentHash].authorized;
    }

    /// @notice Returns block.timestamp at which deletion was confirmed on-chain.
    ///         Zero if deletion has not been confirmed yet.
    ///         Used by VKEscrow.claimEscrowOnDeletion() to compute the pro-rated payment.
    function getDeletionConfirmedAt(bytes32 commitmentHash)
        external view returns (uint64)
    {
        return deletionRecords[commitmentHash].confirmedAt;
    }

    /// @notice Returns the fields from FileStorageRecord needed by StorageReceiptDispute
    ///         to evaluate a deletion-failure dispute without reading the full struct.
    function getFileRecordForDeletion(bytes32 commitmentHash)
        external view
        returns (
            address vk,
            uint8   deadlineIndex,
            uint8   partitionIndex,
            bytes32 zkPieceCommitment
        )
    {
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        return (rec.vkAddress, rec.deadlineIndex, rec.partitionIndex, rec.zkPieceCommitment);
    }

    /// @notice Returns the full on-chain lifecycle state for one commitmentHash.
    ///         Used for reconciliation between successful final files and stale
    ///         earlier registrations after retries.
    function getCommitmentLifecycle(bytes32 commitmentHash)
        external view
        returns (
            bool exists,
            bool deletionDeclared,
            bool deletionConfirmed,
            uint64 deletionDeclaredAt,
            uint64 deletionConfirmedAt,
            bytes32 registrationCommitment
        )
    {
        FileStorageRecord storage rec = fileRecords[commitmentHash];
        DeletionRecord storage dr = deletionRecords[commitmentHash];
        exists = rec.vkAddress != address(0);
        deletionDeclared = dr.declaredAt > 0;
        deletionConfirmed = dr.confirmed;
        deletionDeclaredAt = dr.declaredAt;
        deletionConfirmedAt = dr.confirmedAt;
        registrationCommitment = commitmentHashToRegistrationCommitment[commitmentHash];
    }

    /// @notice Count active vs total commitments registered under a sectorRoot.
    ///         Active means deletion is not confirmed for that commitment.
    function sectorActiveCommitmentCounts(bytes32 sectorRoot)
        external view returns (uint256 active, uint256 total)
    {
        bytes32[] storage chs = sectorRootToCommitments[sectorRoot];
        total = chs.length;
        for (uint256 i = 0; i < total; i++) {
            if (!deletionRecords[chs[i]].confirmed) {
                active += 1;
            }
        }
    }

    /// @notice Returns true only when releasing one old data slot cannot orphan a live file.
    /// @dev Called by StorageProofSC before it allows a data partition update/deactivation
    ///      to remove an existing sectorRoot + zkPieceCommitment from old coordinates.
    function canReleaseDataSlot(
        address vk,
        uint8 deadlineIndex,
        uint8 partitionIndex,
        bytes32 sectorRoot,
        bytes32 pieceCommitment
    ) external view returns (bool) {
        bytes32[] storage chs = sectorRootToCommitments[sectorRoot];
        bytes32 migKey = keccak256(abi.encodePacked(
            vk, sectorRoot, deadlineIndex, partitionIndex
        ));
        bool migrationConfirmed = migrationDeclared[migKey];

        for (uint256 i = 0; i < chs.length; i++) {
            bytes32 ch = chs[i];
            FileStorageRecord storage rec = fileRecords[ch];
            if (
                rec.vkAddress != vk ||
                rec.sectorRoot != sectorRoot ||
                rec.zkPieceCommitment != pieceCommitment
            ) {
                continue;
            }

            PendingMigration storage pm = pendingMigrations[ch];
            bool referencesOldSlot = (
                rec.deadlineIndex == deadlineIndex &&
                rec.partitionIndex == partitionIndex
            );
            bool pendingFromOldSlot = (
                pm.pending &&
                pm.oldDeadlineIndex == deadlineIndex &&
                pm.oldPartitionIndex == partitionIndex
            );
            bool safelyMigratedFromOldSlot = (
                migrationConfirmed &&
                rec.partitionLinked &&
                (rec.deadlineIndex != deadlineIndex || rec.partitionIndex != partitionIndex)
            );

            if (!referencesOldSlot && !pendingFromOldSlot && !safelyMigratedFromOldSlot) {
                continue;
            }

            DeletionRecord storage dr = deletionRecords[ch];
            if (expiredCommitmentHashes[ch]) {
                continue;
            }
            if (dr.confirmed) {
                continue;
            }
            if (rec.serviceEnd <= block.timestamp) {
                continue;
            }
            if (safelyMigratedFromOldSlot) {
                continue;
            }
            if (dr.declaredAt > 0 && (dr.authorized || rec.deletionAuthHash == bytes32(0))) {
                continue;
            }
            return false;
        }

        return true;
    }
}
