// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: StorageProofSC
// Purpose:  Vault Keepers proving, round after round, that they still hold exactly
//           what they took on -- and never revealing whose data it is.
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

interface IReputationManager_SP {
    function recordVKProofSuccess(address vk) external;
    function recordVKProofMissed(address vk) external;
    function recordVKProofMissedFor(address vk, bytes32 eventId) external;
}

interface IRewardManager_SP {
    function creditVKProof(address vk) external;
}

interface IStakingManager_SP {
    function stakeOf(address account) external view returns (uint256);
    function slash(address guardian, uint256 amount) external;
}

interface IVaultKeeperRegistry_SP {
    function suspendVaultKeeper(address vkAddress, uint64 until) external;
    function isEligibleVaultKeeper(address vk) external view returns (bool);
    function deprecatedAt() external view returns (uint64);
}

interface IFileRegistrationLifecycleGuard_SP {
    function canReleaseDataSlot(
        address vk,
        uint8 deadlineIndex,
        uint8 partitionIndex,
        bytes32 sectorRoot,
        bytes32 pieceCommitment
    ) external view returns (bool);
}

interface ICapacityProofSync_SP {
    function syncPartitionRegistration(bytes32 partitionKey) external;
}

interface IPartitionSnapshotHook_SP {
    function preservePartitionSnapshotBeforeUpdate(bytes32 partitionKey)
        external returns (bool preserved);
}

interface IDeletionRelease_SP {
    function storageProof() external view returns (address);
    function unresolvedOperationByPartition(bytes32 partitionKey)
        external view returns (bytes32);
    function resolveSuccessor(
        bytes32 operationId,
        uint8 predecessorKind,
        bool predecessorActive,
        uint64 predecessorContentVersion,
        bytes32 predecessorContentHash,
        uint64 predecessorCommittedBytes,
        uint64 predecessorRegistrationNonce,
        uint64 predecessorTransitionNonce
    ) external returns (bool);
}

/// @title FileTrust StorageProofSC
/// @notice Public VK-sector and VK-partition proof contract.
/// It does not store DO address, fileId, pieceRoot, CID, peerId, or DO-to-VK mappings.
/// It only tracks VK-owned sectors/partitions and verified ZK proofs.
///
/// Partition model (Filecoin-inspired):
///   - proofPeriod is divided into deadlineCount equal deadline windows.
///   - Each VK assigns each sector to a deadline deterministically.
///   - One batch ZK proof covers all sectors in a partition.
///
/// Two proof submission modes:
///   Legacy (2 tx): openPartitionChallenge → submitPartitionZkProof
///   Deterministic (1 tx): submitPartitionZkProofDeterministic
///     The challenge seed is derived from a blockhash anchor set at registration time,
///     so the VK can compute the seed without a separate on-chain call.
contract StorageProofSC {

    error DeletionReleaseInvariant(uint8 code);
    error StorageProofInvariant(uint8 code);

    struct PartitionLineage {
        uint64 registeredNonce;
        uint64 supersededNonce;
    }

    struct ReleaseIdentity {
        uint8 kind;
        bool active;
        uint64 contentVersion;
        bytes32 contentHash;
        uint64 committedBytes;
        uint64 registrationNonce;
        uint64 transitionNonce;
    }

    // ─── Per-sector structs ───────────────────────────────────────────────────

    struct SectorInfo {
        address vk;
        bytes32 sectorId;
        bytes32 sectorRoot;
        uint64  expiration;
        uint64  registeredAt;
        uint64  updatedAt;
        uint64  lastProofRound;
        uint32  sectorBlockCount;
        uint16  challengeCount;
        bool    active;
    }

    struct ChallengeInfo {
        bytes32 seed;
        uint64  deadline;
        uint64  openedAt;
        uint64  openedAtBlock;
        bool    exists;
        bool    proven;
    }

    // ─── Partition structs ────────────────────────────────────────────────────

    struct PartitionInfo {
        address   vk;
        bytes32   partitionKey;
        uint8     deadlineIndex;
        uint8     partitionIndex;
        uint8     partitionKind; // 1=data, 2=capacity
        bytes32[] sectorIds;
        bytes32[] sectorRoots;
        uint32[]  sectorBlockCounts;
        bytes32[] pieceCommitments; // W3 fix: MiMC zkPieceCommitment per sector slot
        uint64    committedBytes;
        uint64    expiration;
        uint64    registeredAt;
        uint64    updatedAt;
        uint64    lastProofRound;
        uint16    challengeCount;
        bool      active;
        bytes32   contentHash;
        uint64    contentVersion;
        bytes32   lastProvenContentHash;
        /// @dev Deterministic-challenge anchor: blockhash(block.number - 1) captured
        /// at the time of the most recent registerOrUpdatePartition call.
        bytes32   challengeAnchor;
        uint64    anchorBlock;
    }

    struct PartitionChallengeInfo {
        bytes32 seed;
        uint64  deadline;
        uint64  openedAt;
        uint64  openedAtBlock;
        bool    exists;
        bool    proven;
        bytes32 provenContentHash;
    }

    // ─── Events ───────────────────────────────────────────────────────────────

    event VerifierUpdated(address indexed verifier);
    event PartitionVerifierUpdated(address indexed partitionVerifier);
    event ProofPeriodUpdated(uint64 proofPeriodSeconds, uint64 proofDeadlineSeconds, uint16 maxChallengeCount);
    event PartitionCircuitParamsUpdated(uint8 partitionCircuitSectors, uint8 partitionCircuitChallenges);
    event ReputationManagerSet(address indexed reputationManager);
    event WrongProofAttempted(address indexed vk, uint32 attempts, uint64 timestamp);
    event FileRegistrationGuardSet(address indexed fileRegistration, bool required);
    event CapacityProofContractSet(address indexed capacityProof);
    event PartitionSnapshotProofContractSet(address indexed partitionSnapshotProof);
    event DeletionReleaseSet(address indexed deletionRelease);
    event RoundChallengeAnchorSet(uint64 indexed round, bytes32 anchor, uint64 blockNumber);

    event SectorRegistered(
        bytes32 indexed sectorKey, address indexed vk, bytes32 indexed sectorId,
        bytes32 sectorRoot, uint64 expiration, uint32 sectorBlockCount, uint16 challengeCount
    );
    event SectorUpdated(
        bytes32 indexed sectorKey, address indexed vk, bytes32 indexed sectorId,
        bytes32 oldSectorRoot, bytes32 newSectorRoot,
        uint64 expiration, uint32 sectorBlockCount, uint16 challengeCount
    );
    event SectorStatusChanged(bytes32 indexed sectorKey, address indexed vk, bool active);
    event ChallengeOpened(
        bytes32 indexed sectorKey, address indexed vk, bytes32 indexed sectorId,
        uint64 round, bytes32 seed, uint64 deadline
    );
    event SectorProofSubmitted(
        bytes32 indexed sectorKey, address indexed vk, bytes32 indexed sectorId,
        uint64 round, bytes32 sectorRoot, bytes32 seed
    );
    event SectorProofMissed(bytes32 indexed sectorKey, address indexed vk, bytes32 indexed sectorId, uint64 round);

    event PartitionRegistered(
        bytes32 indexed partitionKey, address indexed vk,
        uint8 deadlineIndex, uint8 partitionIndex, uint8 partitionKind,
        uint256 sectorCount, uint64 committedBytes, uint64 expiration
    );
    event PartitionUpdated(
        bytes32 indexed partitionKey, address indexed vk,
        uint8 partitionKind, uint256 sectorCount, uint64 committedBytes
    );
    event PartitionContentVersionUpdated(
        bytes32 indexed partitionKey, address indexed vk,
        uint64 contentVersion, bytes32 contentHash
    );
    event PartitionDeactivated(
        bytes32 indexed partitionKey, address indexed vk,
        uint8 partitionKind
    );
    event PartitionChallengeOpened(
        bytes32 indexed partitionKey, address indexed vk,
        uint64 round, bytes32 seed, uint64 deadline
    );
    /// @dev Emitted by the legacy two-tx proof flow.
    event PartitionProofSubmitted(
        bytes32 indexed partitionKey, address indexed vk, uint64 round, bytes32 seed
    );
    /// @dev Emitted by the deterministic single-tx proof flow.
    event PartitionProofSubmittedDeterministic(
        bytes32 indexed partitionKey, address indexed vk, uint64 round, bytes32 detSeed
    );
    /// @dev A retry reached the chain after this exact partition content had
    /// already been proved for the same round. No rewards/accounting are repeated.
    event PartitionProofAlreadyAccepted(
        bytes32 indexed partitionKey, address indexed vk, uint64 round, bytes32 contentHash
    );

    event ZkBlockSizeUpdated(uint32 zkBlockSizeBytes);

    // ─── Storage ──────────────────────────────────────────────────────────────

    address public owner;
    address public reputationManager;
    address public rewardManager;
    address public stakingManager;
    address public vaultKeeperRegistry;
    address public fileRegistration;
    address public capacityProof;
    address public partitionSnapshotProof;
    address public deletionRelease;
    bool public dataLifecycleGuardRequired;
    IStorageProofVerifier public verifier;
    uint8 public constant PARTITION_KIND_DATA = 1;
    uint8 public constant PARTITION_KIND_CAPACITY = 2;
    uint8 public constant CAPACITY_PARTITION_INDEX_OFFSET = 128;

    // ─── Wrong-proof escalation ───────────────────────────────────────────────

    /// @dev Number of consecutive wrong proof attempts per VK. Resets on success.
    mapping(address => uint32) public wrongProofAttempts;

    // Configurable escalation thresholds (attempt count triggers level):
    uint32 public wrongProofRepThreshold     = 3;  // attempts >= this → reputation penalty
    uint32 public wrongProofSlashThreshold   = 6;  // attempts >= this → small stake slash + rep
    uint32 public wrongProofSuspendThreshold = 10; // attempts >= this → large slash + suspension

    // Slash sizes as basis points of the VK's current stake:
    uint16 public wrongProofSlashBps        = 50;  // 0.5% of stake on slash level
    uint16 public wrongProofSuspendSlashBps = 200; // 2%   of stake on suspension level

    // How long a suspension lasts (seconds):
    uint64 public wrongProofSuspendSeconds = 86400; // 24 hours

    /// @dev Per-VK: block.timestamp of the last successful proof submission.
    mapping(address => uint64) public lastProofAt;
    IStorageProofVerifier public partitionVerifier;

    uint32 public zkBlockSizeBytes = 128;

    uint64 public proofPeriodSeconds   = 1 days;
    uint64 public proofDeadlineSeconds = 6 hours;
    uint16 public maxChallengeCount    = 16;

    uint8 public partitionCircuitSectors    = 8;
    uint8 public partitionCircuitChallenges = 4;

    mapping(bytes32 => SectorInfo)                          public sectors;
    mapping(bytes32 => mapping(uint64 => ChallengeInfo))    public challenges;
    mapping(address => bytes32[])                           private vkSectorKeys;
    mapping(bytes32 => bool)                                private knownSectorKey;

    mapping(bytes32 => PartitionInfo)                                    public partitions;
    mapping(bytes32 => mapping(uint64 => PartitionChallengeInfo))        public partitionChallenges;
    /// @dev Shared (not per-partition) deterministic-challenge anchor, lazily fixed the
    /// first time anyone calls ensureRoundChallengeAnchor() for that round. Before that
    /// call, blockhash(block.number - 1) for whatever block ends up executing it is not
    /// knowable by anyone, so no partition's round-`round` deterministic seed can be
    /// computed before the round has actually started.
    mapping(uint64 => bytes32)                                           public roundChallengeAnchor;
    /// @dev Tracks rounds already proven via the deterministic path (no ChallengeInfo stored).
    mapping(bytes32 => mapping(uint64 => bool))                          private partitionDetProven;
    mapping(bytes32 => mapping(uint64 => bytes32))                       private partitionDetProvenContentHash;
    mapping(address => bytes32[])                                        private vkPartitionKeys;
    mapping(bytes32 => bool)                                             private knownPartitionKey;
    mapping(bytes32 => uint64) public partitionLastCurrentProofAt;
    /// @dev Exact partition contents proven in a round, across both proof paths.
    /// Retaining history allows A -> B -> A composition cycles to recognize the
    /// original A proof without treating B's proof as valid for A.
    mapping(bytes32 => mapping(uint64 => mapping(bytes32 => bool)))       private partitionContentProven;
    /// @dev Fresh snapshot epochs may repeat inside one storage round. Binding
    ///      acceptance to epochId prevents a proof from an older cycle being
    ///      replayed into a newer capacity manifest.
    mapping(bytes32 => mapping(uint64 => bytes32))                        private snapshotEpochContent;
    /// @dev Economic/reputation credit is limited to one proof per partition
    ///      and storage round even when operational catch-up uses more epochs.
    mapping(bytes32 => mapping(uint64 => bool))                           private partitionRoundCredited;
    /// @dev G.4: StorageProof is the sole authoritative partition lineage.
    mapping(address => uint64) private partitionRegistrationSequence;
    mapping(bytes32 => uint64) public partitionCurrentRegistrationNonce;
    mapping(bytes32 => uint64) public partitionTransitionNonce;
    mapping(bytes32 => mapping(uint64 => PartitionLineage)) private partitionVersionLineage;
    /// @dev Sector challenges already charged as missed: one missed challenge, one penalty.
    mapping(bytes32 => mapping(uint64 => bool)) private sectorMissCharged;

    // ─── Modifiers ────────────────────────────────────────────────────────────

    modifier onlyOwner() { if (msg.sender != owner) revert StorageProofInvariant(1); _; }
    modifier onlySectorVk(bytes32 sk) { if (sectors[sk].vk != msg.sender) revert StorageProofInvariant(2); _; }
    error ContractDeprecated();

    /// @dev Phase 2: once the VaultKeeper layer of this version is deprecated
    ///      (VaultKeeperRegistry.deprecate), no new partition or sector is accepted here.
    ///      Existing ones keep updating, proving and being charged. One switch, kept in the
    ///      registry, because this contract has no room for its own.
    function _requireVaultKeeperLayerOpen() private view {
        if (IVaultKeeperRegistry_SP(vaultKeeperRegistry).deprecatedAt() != 0) revert ContractDeprecated();
    }

    modifier onlyEligibleVK() {
        if (vaultKeeperRegistry == address(0)) revert StorageProofInvariant(3);
        if (!IVaultKeeperRegistry_SP(vaultKeeperRegistry).isEligibleVaultKeeper(msg.sender))
            revert StorageProofInvariant(4);
        _;
    }

    // ─── Constructor / admin ──────────────────────────────────────────────────

    constructor(address verifier_) {
        owner    = msg.sender;
        verifier = IStorageProofVerifier(verifier_);
        emit VerifierUpdated(verifier_);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0));
        owner = newOwner;
    }

    // Verifiers are bound once (Phase 2, D8): a FileTrustVerifierRouter replaces keys with a
    // bounded transition window, so no single call can swap one under work in flight.
    function setVerifier(address v) external onlyOwner {
        require(v != address(0) && address(verifier) == address(0));
        verifier = IStorageProofVerifier(v);
        emit VerifierUpdated(v);
    }

    function setPartitionVerifier(address v) external onlyOwner {
        require(v != address(0) && address(partitionVerifier) == address(0));
        partitionVerifier = IStorageProofVerifier(v);
        emit PartitionVerifierUpdated(v);
    }

    function setProofPeriod(uint64 period, uint64 deadline, uint16 maxC) external onlyOwner {
        require(period  >= 60 && deadline >= 60);
        require(maxC > 0 && maxC <= 64);
        proofPeriodSeconds   = period;
        proofDeadlineSeconds = deadline;
        maxChallengeCount    = maxC;
        emit ProofPeriodUpdated(period, deadline, maxC);
    }

    function setPartitionCircuitParams(uint8 sectors_, uint8 challenges_) external onlyOwner {
        require(sectors_ > 0 && sectors_ <= 64 && challenges_ > 0 && challenges_ <= 64);
        partitionCircuitSectors    = sectors_;
        partitionCircuitChallenges = challenges_;
        emit PartitionCircuitParamsUpdated(sectors_, challenges_);
    }

    function setZkBlockSizeBytes(uint32 size_) external onlyOwner {
        if (size_ == 0) revert StorageProofInvariant(5);
        zkBlockSizeBytes = size_;
        emit ZkBlockSizeUpdated(size_);
    }

    function setReputationManager(address rm) external onlyOwner {
        reputationManager = rm;
        emit ReputationManagerSet(rm);
    }

    function setRewardManager(address rm) external onlyOwner {
        rewardManager = rm;
    }

    function setStakingManager(address sm) external onlyOwner {
        stakingManager = sm;
    }

    function setVaultKeeperRegistry(address vkr) external onlyOwner {
        vaultKeeperRegistry = vkr;
    }

    function setFileRegistrationGuard(address fr, bool required) external onlyOwner {
        fileRegistration = fr;
        dataLifecycleGuardRequired = required;
        emit FileRegistrationGuardSet(fr, required);
    }

    function setCapacityProof(address capacityProof_) external onlyOwner {
        if (capacityProof_ == address(0)) revert StorageProofInvariant(6);
        if (capacityProof != address(0)) revert StorageProofInvariant(7);
        capacityProof = capacityProof_;
        emit CapacityProofContractSet(capacityProof_);
    }

    function setPartitionSnapshotProof(address snapshotProof_) external onlyOwner {
        if (snapshotProof_ == address(0)) revert StorageProofInvariant(8);
        if (partitionSnapshotProof != address(0)) revert StorageProofInvariant(9);
        partitionSnapshotProof = snapshotProof_;
        emit PartitionSnapshotProofContractSet(snapshotProof_);
    }

    function setDeletionRelease(address deletionRelease_) external onlyOwner {
        if (deletionRelease_ == address(0)) revert DeletionReleaseInvariant(1);
        if (deletionRelease_.code.length == 0) revert DeletionReleaseInvariant(2);
        if (deletionRelease != address(0)) revert DeletionReleaseInvariant(3);
        if (IDeletionRelease_SP(deletionRelease_).storageProof() != address(this))
            revert DeletionReleaseInvariant(4);
        deletionRelease = deletionRelease_;
        emit DeletionReleaseSet(deletionRelease_);
    }

    /// @notice Configure wrong-proof escalation thresholds.
    /// @param repThreshold     Attempts at which reputation penalty begins.
    /// @param slashThreshold   Attempts at which stake slash begins.
    /// @param suspendThreshold Attempts at which suspension + larger slash applies.
    function setWrongProofThresholds(uint32 repThreshold, uint32 slashThreshold, uint32 suspendThreshold) external onlyOwner {
        if (repThreshold == 0 || slashThreshold < repThreshold ||
            suspendThreshold < slashThreshold) revert StorageProofInvariant(30);
        wrongProofRepThreshold     = repThreshold;
        wrongProofSlashThreshold   = slashThreshold;
        wrongProofSuspendThreshold = suspendThreshold;
    }

    /// @notice Configure slash basis points and suspension duration for wrong proofs.
    ///         Neither rate may be above 5,000 basis points: one wrong proof never takes
    ///         more than half the stake.
    /// @param slashBps        Basis points of stake slashed at slash level (e.g. 50 = 0.5%).
    /// @param suspendSlashBps Basis points of stake slashed at suspend level (e.g. 200 = 2%).
    /// @param suspendSeconds  Duration of a suspension in seconds.
    function setWrongProofSlashParams(uint16 slashBps, uint16 suspendSlashBps, uint64 suspendSeconds) external onlyOwner {
        if (suspendSlashBps < slashBps || suspendSlashBps > 5000) revert StorageProofInvariant(10);
        wrongProofSlashBps        = slashBps;
        wrongProofSuspendSlashBps = suspendSlashBps;
        wrongProofSuspendSeconds  = suspendSeconds;
    }

    // ─── View helpers ─────────────────────────────────────────────────────────

    function sectorKeyOf(address vk, bytes32 sectorId) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(vk, sectorId));
    }

    function partitionKeyOf(address vk, uint8 deadlineIndex, uint8 partitionIndex) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(vk, deadlineIndex, partitionIndex));
    }

    /// @notice Content-version exhaustion (G.2C).
    /// @dev A deletion obligation is addressed by `DELETION_FLAG | contentVersion`, which is
    ///      injective only while `contentVersion < 1 << 63`. A version at or above that bound
    ///      could not be represented, so this fails closed BEFORE any registration, deletion,
    ///      snapshot or journal state is committed rather than wrapping, truncating or masking
    ///      the value into the deletion domain.
    ///
    ///      This is protocol exhaustion, not a retryable failure: at one version per mutation
    ///      it is unreachable in practice, and if it were ever reached the partition would need
    ///      a new key, not a retry.
    error ContentVersionExhausted(bytes32 partitionKey, uint64 contentVersion);

    function _nextContentVersion(uint64 currentVersion) internal pure returns (uint64) {
        if (currentVersion >= ProofAuthorityDomains.maxRepresentableContentVersion()) {
            revert ContentVersionExhausted(bytes32(0), currentVersion);
        }
        return currentVersion + 1;
    }

    /// @notice Largest content version a partition may ever hold.
    function maxContentVersion() external pure returns (uint64) {
        return ProofAuthorityDomains.maxRepresentableContentVersion();
    }

    function partitionKindOf(uint8 partitionIndex) public pure returns (uint8) {
        return partitionIndex >= CAPACITY_PARTITION_INDEX_OFFSET
            ? PARTITION_KIND_CAPACITY
            : PARTITION_KIND_DATA;
    }

    function currentRound() public view returns (uint64) {
        return uint64(block.timestamp / proofPeriodSeconds);
    }

    /// @notice Lazily fixes the shared deterministic-challenge anchor for `round`, the
    /// first time anyone calls this for that round. Anyone may call it (no proof, cheap);
    /// it takes no side on which partition/VK benefits. Until it has been called for a
    /// given round, that round's deterministic seed is unknowable by anyone, including
    /// every VK — closing the gap where the old fixed-at-registration anchor let a VK (or
    /// anyone) precompute a future round's exact challenge far in advance. A VK's normal
    /// flow becomes: once its round starts, call this once (if nobody else already has),
    /// then read expectedPartitionPublicInputsDeterministic, then build and submit its proof.
    function ensureRoundChallengeAnchor(uint64 round) public returns (bytes32 anchor) {
        anchor = roundChallengeAnchor[round];
        if (anchor != bytes32(0)) return anchor;
        // Custom error, not a require string: this contract is close to the EIP-170
        // code-size limit and revert strings cost bytecode (see production_contract_size.test.js).
        if (round > currentRound()) revert StorageProofInvariant(31);
        anchor = blockhash(block.number - 1);
        if (anchor == bytes32(0)) return anchor; // unavailable this block; retry next tx
        roundChallengeAnchor[round] = anchor;
        emit RoundChallengeAnchorSet(round, anchor, uint64(block.number));
    }

    function getVkSectorKeys(address vk)      external view returns (bytes32[] memory) { return vkSectorKeys[vk]; }
    function getVkPartitionKeys(address vk)   external view returns (bytes32[] memory) { return vkPartitionKeys[vk]; }
    function getPartitionSectorRoots(bytes32 pKey)      external view returns (bytes32[] memory) { return partitions[pKey].sectorRoots; }
    function getPartitionSectorIds(bytes32 pKey)        external view returns (bytes32[] memory) { return partitions[pKey].sectorIds; }
    function getPartitionBlockCounts(bytes32 pKey)      external view returns (uint32[]  memory) { return partitions[pKey].sectorBlockCounts; }
    function getPartitionPieceCommitments(bytes32 pKey) external view returns (bytes32[] memory) { return partitions[pKey].pieceCommitments; }
    function getPartitionChallengeAnchor(bytes32 pKey) external view returns (bytes32 anchor, uint64 anchorBlock_) {
        return (partitions[pKey].challengeAnchor, partitions[pKey].anchorBlock);
    }
    function isDetProven(bytes32 pKey, uint64 round) external view returns (bool) {
        return partitionDetProven[pKey][round];
    }
    function isPartitionContentProven(bytes32 pKey, uint64 round, bytes32 contentHash)
        external view returns (bool)
    {
        return partitionContentProven[pKey][round][contentHash];
    }

    /// @notice Returns proof status for a partition.
    /// Used by StorageReceiptDispute to evaluate disputes.
    /// registeredAt is included so the dispute contract can enforce the W9 proof
    /// grace period: "never proved" disputes are only valid after registeredAt +
    /// proofPeriodSeconds, giving the VK a full period to submit their first proof.
    function getPartitionProofStatus(bytes32 pKey)
        external view returns (address vk, bool active, uint64 lastProofRound, uint64 registeredAt)
    {
        PartitionInfo storage p = partitions[pKey];
        return (p.vk, p.active, p.lastProofRound, p.registeredAt);
    }
    function getPartitionVersionStatus(bytes32 pKey)
        external view returns (
            bytes32 contentHash,
            uint64 contentVersion,
            bytes32 lastProvenContentHash,
            bool currentContentProven
        )
    {
        PartitionInfo storage p = partitions[pKey];
        return (
            p.contentHash,
            p.contentVersion,
            p.lastProvenContentHash,
            p.contentHash != bytes32(0) && p.contentHash == p.lastProvenContentHash
        );
    }

    /// @notice G.4 authoritative current identity used by DeletionReleaseSC.
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
        )
    {
        PartitionInfo storage p = partitions[pKey];
        return (
            p.vk,
            p.partitionKind,
            p.active,
            p.contentVersion,
            p.contentHash,
            p.committedBytes,
            partitionCurrentRegistrationNonce[pKey],
            partitionTransitionNonce[pKey]
        );
    }

    function getPartitionVersionLineage(bytes32 pKey, uint64 contentVersion)
        external view returns (uint64 registeredNonce, uint64 supersededNonce)
    {
        PartitionLineage storage lineage = partitionVersionLineage[pKey][contentVersion];
        return (lineage.registeredNonce, lineage.supersededNonce);
    }

    function isPartitionManifestEmpty(bytes32 pKey) external view returns (bool) {
        PartitionInfo storage p = partitions[pKey];
        return !p.active && p.committedBytes == 0 && p.contentHash == bytes32(0) &&
            p.sectorIds.length == 0 && p.sectorRoots.length == 0 &&
            p.sectorBlockCounts.length == 0 && p.pieceCommitments.length == 0;
    }

    /// @notice Canonical current-proof callback. Once configured, legacy
    /// partition submissions are disabled and only the post-freeze verifier may
    /// advance proof, reward, dispute or payment state.
    function acceptFrozenPartitionProof(
        bytes32 pKey,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 round,
        uint64 proofEpochId
    ) external returns (bool acceptedAsCurrent) {
        if (msg.sender != partitionSnapshotProof) revert StorageProofInvariant(11);
        if (proofEpochId == 0) revert StorageProofInvariant(12);
        if (round > currentRound()) revert StorageProofInvariant(22);
        PartitionInfo storage p = partitions[pKey];
        if (p.vk == address(0)) revert StorageProofInvariant(13);
        bytes32 acceptedContent = snapshotEpochContent[pKey][proofEpochId];
        if (acceptedContent != bytes32(0) && acceptedContent != contentHash)
            revert StorageProofInvariant(14);
        if (acceptedContent == contentHash) {
            emit PartitionProofAlreadyAccepted(pKey, p.vk, round, contentHash);
            return p.active && p.contentVersion == contentVersion && p.contentHash == contentHash;
        }
        snapshotEpochContent[pKey][proofEpochId] = contentHash;
        partitionContentProven[pKey][round][contentHash] = true;
        acceptedAsCurrent = p.active &&
            p.contentVersion == contentVersion && p.contentHash == contentHash;
        if (!acceptedAsCurrent) return false;
        if (round > p.lastProofRound) p.lastProofRound = round;
        p.lastProvenContentHash = contentHash;
        p.updatedAt = uint64(block.timestamp);
        partitionLastCurrentProofAt[pKey] = uint64(block.timestamp);
        if (!partitionRoundCredited[pKey][round]) {
            partitionRoundCredited[pKey][round] = true;
            _tryRecordProofSuccess(p.vk);
        }
    }

    // ─── Per-sector functions (unchanged) ────────────────────────────────────

    function registerOrUpdateSector(
        bytes32 sectorId, bytes32 sectorRoot, uint64 expiration,
        uint32 sectorBlockCount, uint16 challengeCount
    ) external onlyEligibleVK returns (bytes32 sectorKey) {
        require(sectorRoot != bytes32(0) && expiration > block.timestamp);
        require(sectorBlockCount > 0);
        require(challengeCount > 0 && challengeCount <= maxChallengeCount);
        require(uint256(challengeCount) <= uint256(sectorBlockCount));

        sectorKey = sectorKeyOf(msg.sender, sectorId);
        SectorInfo storage s = sectors[sectorKey];
        if (s.vk == address(0)) {
            _requireVaultKeeperLayerOpen();
            s.vk = msg.sender; s.sectorId = sectorId; s.sectorRoot = sectorRoot;
            s.expiration = expiration; s.registeredAt = uint64(block.timestamp);
            s.updatedAt = uint64(block.timestamp); s.sectorBlockCount = sectorBlockCount;
            s.challengeCount = challengeCount; s.active = true;
            if (!knownSectorKey[sectorKey]) { vkSectorKeys[msg.sender].push(sectorKey); knownSectorKey[sectorKey] = true; }
            emit SectorRegistered(sectorKey, msg.sender, sectorId, sectorRoot, expiration, sectorBlockCount, challengeCount);
        } else {
            require(s.vk == msg.sender);
            bytes32 old = s.sectorRoot;
            s.sectorRoot = sectorRoot; s.expiration = expiration; s.updatedAt = uint64(block.timestamp);
            s.sectorBlockCount = sectorBlockCount; s.challengeCount = challengeCount; s.active = true;
            emit SectorUpdated(sectorKey, msg.sender, sectorId, old, sectorRoot, expiration, sectorBlockCount, challengeCount);
        }
    }

    function setSectorActive(bytes32 sectorId, bool active) external {
        if (active) {
            if (vaultKeeperRegistry == address(0)) revert StorageProofInvariant(3);
            if (!IVaultKeeperRegistry_SP(vaultKeeperRegistry).isEligibleVaultKeeper(msg.sender))
                revert StorageProofInvariant(4);
        }
        bytes32 sk = sectorKeyOf(msg.sender, sectorId);
        require(sectors[sk].vk == msg.sender);
        sectors[sk].active = active; sectors[sk].updatedAt = uint64(block.timestamp);
        emit SectorStatusChanged(sk, msg.sender, active);
    }

    function openChallenge(bytes32 sectorId, uint64 round) external onlyEligibleVK returns (bytes32 seed) {
        bytes32 sk = sectorKeyOf(msg.sender, sectorId);
        SectorInfo storage s = sectors[sk];
        require(s.vk == msg.sender && s.active && s.expiration > block.timestamp);
        require(round <= currentRound() + 1);
        ChallengeInfo storage c = challenges[sk][round];
        require(!c.exists);
        seed = keccak256(abi.encodePacked(blockhash(block.number-1), block.prevrandao, address(this), block.chainid, sk, s.sectorRoot, round, msg.sender));
        c.seed = seed; c.deadline = uint64(block.timestamp+proofDeadlineSeconds);
        c.openedAt = uint64(block.timestamp); c.openedAtBlock = uint64(block.number);
        c.exists = true; c.proven = false;
        emit ChallengeOpened(sk, msg.sender, sectorId, round, seed, c.deadline);
    }

    function submitZkSectorProof(bytes32 sectorId, uint64 round, bytes calldata proof, uint256[] calldata publicInputs)
        external onlyEligibleVK onlySectorVk(sectorKeyOf(msg.sender, sectorId))
    {
        bytes32 sk = sectorKeyOf(msg.sender, sectorId);
        SectorInfo storage s = sectors[sk];
        ChallengeInfo storage c = challenges[sk][round];
        require(s.active && c.exists && !c.proven);
        require(block.timestamp <= c.deadline && block.number > c.openedAtBlock);
        require(address(verifier) != address(0));
        _validatePublicInputs(s, c, round, publicInputs);
        bool zkValid = verifier.verifyProof(proof, publicInputs);
        if (!zkValid) { _handleWrongProof(msg.sender); return; }
        c.proven = true; s.lastProofRound = round; s.updatedAt = uint64(block.timestamp);
        emit SectorProofSubmitted(sk, msg.sender, sectorId, round, s.sectorRoot, c.seed);
    }

    function markMissed(bytes32 sk, uint64 round) external {
        SectorInfo storage s = sectors[sk];
        require(s.vk != address(0));
        ChallengeInfo storage c = challenges[sk][round];
        require(c.exists && !c.proven && block.timestamp > c.deadline);
        if (sectorMissCharged[sk][round]) revert StorageProofInvariant(32);
        // Marked before the reputation call, so a report re-entering from inside it finds
        // the miss already charged.
        sectorMissCharged[sk][round] = true;
        emit SectorProofMissed(sk, s.vk, s.sectorId, round);
        _recordProofMissed(sk, round, s.vk);
    }

    function expectedPublicInputs(bytes32 sk, uint64 round) external view returns (uint256[] memory) {
        require(sectors[sk].vk != address(0) && challenges[sk][round].exists);
        return _buildExpectedPublicInputs(sectors[sk], challenges[sk][round], round);
    }

    // ─── Partition registration ───────────────────────────────────────────────

    /// @notice Register or update a partition.
    /// Records a challenge anchor = blockhash(block.number - 1) so the VK can
    /// compute deterministic challenge seeds without a separate openChallenge tx.
    function registerOrUpdatePartition(
        uint8 deadlineIndex, uint8 partitionIndex,
        bytes32[] calldata sectorIds, bytes32[] calldata sectorRoots,
        uint32[] calldata sectorBlockCounts, bytes32[] calldata pieceCommitments,
        uint64 expiration, uint16 challengeCount
    ) external onlyEligibleVK returns (bytes32 pKey) {
        uint256 k = sectorIds.length;
        require(k > 0 && k <= partitionCircuitSectors);
        require(sectorRoots.length == k && sectorBlockCounts.length == k);
        if (pieceCommitments.length != k) revert StorageProofInvariant(15);
        require(expiration > block.timestamp);
        require(challengeCount > 0 && challengeCount <= partitionCircuitChallenges);
        uint64 committedBytes = 0;
        for (uint256 i = 0; i < k; i++) {
            require(sectorRoots[i] != bytes32(0) && sectorBlockCounts[i] > 0);
            if (pieceCommitments[i] == bytes32(0)) revert StorageProofInvariant(16);
            require(uint256(challengeCount) <= uint256(sectorBlockCounts[i]));
            committedBytes += uint64(sectorBlockCounts[i]) * uint64(zkBlockSizeBytes);
        }

        pKey = partitionKeyOf(msg.sender, deadlineIndex, partitionIndex);
        PartitionInfo storage p = partitions[pKey];
        bool firstRegistration = p.vk == address(0);
        if (firstRegistration) _requireVaultKeeperLayerOpen();
        uint8 partitionKind = partitionKindOf(partitionIndex);
        bytes32 newContentHash = keccak256(abi.encode(
            deadlineIndex,
            partitionIndex,
            partitionKind,
            sectorIds,
            sectorRoots,
            sectorBlockCounts,
            pieceCommitments,
            committedBytes,
            expiration,
            challengeCount
        ));
        bool identityChanged = !firstRegistration &&
            (!p.active || p.contentHash != newContentHash);
        ReleaseIdentity memory predecessor;
        bytes32 deletionOperationId;
        if (identityChanged) {
            predecessor = _releaseIdentity(pKey, p);
            deletionOperationId = _unresolvedDeletionOperation(pKey);
        }

        // Capture unpredictable anchor BEFORE storing sector roots.
        bytes32 anchor = blockhash(block.number - 1);

        bool refreshChallengeAnchor = false;
        bool mayRestoreExactProof = false;

        if (p.vk == address(0)) {
            p.vk = msg.sender; p.partitionKey = pKey;
            p.deadlineIndex = deadlineIndex; p.partitionIndex = partitionIndex;
            p.expiration = expiration; p.registeredAt = uint64(block.timestamp);
            p.updatedAt = uint64(block.timestamp); p.challengeCount = challengeCount; p.active = true;
            p.contentVersion = 1;
            refreshChallengeAnchor = true;
            if (!knownPartitionKey[pKey]) { vkPartitionKeys[msg.sender].push(pKey); knownPartitionKey[pKey] = true; }
            emit PartitionRegistered(pKey, msg.sender, deadlineIndex, partitionIndex, partitionKind, k, committedBytes, expiration);
        } else {
            require(p.vk == msg.sender);
            if (p.active && p.contentHash != newContentHash && partitionSnapshotProof != address(0)) {
                IPartitionSnapshotHook_SP(partitionSnapshotProof)
                    .preservePartitionSnapshotBeforeUpdate(pKey);
            }
            mayRestoreExactProof = partitionSnapshotProof == address(0) &&
                p.active && p.contentHash != newContentHash;
            if (p.active && p.partitionKind == PARTITION_KIND_DATA) {
                _assertDataRemovalAllowed(p, sectorRoots, pieceCommitments);
            }
            if (!p.active || p.contentHash != newContentHash) {
                p.lastProofRound = 0;
                p.lastProvenContentHash = bytes32(0);
                partitionLastCurrentProofAt[pKey] = 0;
                p.registeredAt = uint64(block.timestamp);
                p.contentVersion = _nextContentVersion(p.contentVersion);
                refreshChallengeAnchor = true;
                emit PartitionContentVersionUpdated(pKey, msg.sender, p.contentVersion, newContentHash);
            }
            p.expiration = expiration; p.updatedAt = uint64(block.timestamp);
            p.challengeCount = challengeCount; p.active = true;
            emit PartitionUpdated(pKey, msg.sender, partitionKind, k, committedBytes);
        }
        p.partitionKind = partitionKind;
        p.committedBytes = committedBytes;
        p.contentHash = newContentHash;
        if (refreshChallengeAnchor || p.challengeAnchor == bytes32(0)) {
            p.challengeAnchor = anchor;
            p.anchorBlock     = uint64(block.number);
        }

        delete p.sectorIds; delete p.sectorRoots; delete p.sectorBlockCounts; delete p.pieceCommitments;
        for (uint256 i = 0; i < k; i++) {
            p.sectorIds.push(sectorIds[i]);
            p.sectorRoots.push(sectorRoots[i]);
            p.sectorBlockCounts.push(sectorBlockCounts[i]);
            p.pieceCommitments.push(pieceCommitments[i]);
        }

        if (firstRegistration || identityChanged) {
            _advancePartitionLineage(
                pKey,
                p,
                predecessor.contentVersion,
                predecessor.registrationNonce
            );
        }

        // A continuously-active partition may return to exact content that was
        // already proven in this round. Restore only that hash's status and
        // accounting. Reactivation after deactivation always requires a new proof.
        if (mayRestoreExactProof) {
            uint64 chainRound = currentRound();
            uint64 restoredRound = 0;
            if (partitionContentProven[pKey][chainRound + 1][newContentHash]) {
                restoredRound = chainRound + 1;
            } else if (partitionContentProven[pKey][chainRound][newContentHash]) {
                restoredRound = chainRound;
            }
            if (restoredRound != 0) {
                p.lastProofRound = restoredRound;
                p.lastProvenContentHash = newContentHash;
            }
        }
        _syncCapacityRegistration(pKey);
        if (identityChanged && deletionOperationId != bytes32(0)) {
            _resolveDeletionSuccessor(deletionOperationId, predecessor);
        }
    }

    function deactivatePartition(uint8 deadlineIndex, uint8 partitionIndex)
        external onlyEligibleVK returns (bytes32 pKey)
    {
        pKey = partitionKeyOf(msg.sender, deadlineIndex, partitionIndex);
        PartitionInfo storage p = partitions[pKey];
        if (p.vk != msg.sender) revert StorageProofInvariant(17);
        if (!p.active) revert StorageProofInvariant(18);
        ReleaseIdentity memory predecessor = _releaseIdentity(pKey, p);
        bytes32 deletionOperationId = _unresolvedDeletionOperation(pKey);

        if (partitionSnapshotProof != address(0)) {
            IPartitionSnapshotHook_SP(partitionSnapshotProof)
                .preservePartitionSnapshotBeforeUpdate(pKey);
        }

        if (p.partitionKind == PARTITION_KIND_DATA) {
            _assertDataPartitionReleaseAllowed(p);
        }

        uint8 oldKind = p.partitionKind;
        delete p.sectorIds;
        delete p.sectorRoots;
        delete p.sectorBlockCounts;
        delete p.pieceCommitments;
        p.committedBytes = 0;
        p.expiration = 0;
        p.updatedAt = uint64(block.timestamp);
        p.lastProofRound = 0;
        partitionLastCurrentProofAt[pKey] = 0;
        p.contentHash = bytes32(0);
        p.lastProvenContentHash = bytes32(0);
        p.contentVersion = _nextContentVersion(p.contentVersion);
        p.active = false;
        _advancePartitionLineage(
            pKey,
            p,
            predecessor.contentVersion,
            predecessor.registrationNonce
        );
        _syncCapacityRegistration(pKey);
        if (deletionOperationId != bytes32(0)) {
            _resolveDeletionSuccessor(deletionOperationId, predecessor);
        }
        emit PartitionDeactivated(pKey, msg.sender, oldKind);
    }

    // ─── Legacy two-tx partition proof path ───────────────────────────────────

    function openPartitionChallenge(bytes32 pKey, uint64 round) external onlyEligibleVK returns (bytes32 seed) {
        PartitionInfo storage p = partitions[pKey];
        require(p.vk == msg.sender && p.active && p.expiration > block.timestamp);
        require(round <= currentRound() + 1);
        PartitionChallengeInfo storage c = partitionChallenges[pKey][round];
        require(!c.exists);
        seed = keccak256(abi.encodePacked(blockhash(block.number-1), block.prevrandao, address(this), block.chainid, pKey, round, msg.sender));
        c.seed = seed; c.deadline = uint64(block.timestamp+proofDeadlineSeconds);
        c.openedAt = uint64(block.timestamp); c.openedAtBlock = uint64(block.number);
        c.exists = true; c.proven = false;
        emit PartitionChallengeOpened(pKey, msg.sender, round, seed, c.deadline);
    }

    /// @notice Legacy two-tx proof submission. Requires a prior openPartitionChallenge.
    function submitPartitionZkProof(bytes32 pKey, uint64 round, bytes calldata proof, uint256[] calldata publicInputs) external onlyEligibleVK {
        if (partitionSnapshotProof != address(0)) revert StorageProofInvariant(19);
        PartitionInfo storage p = partitions[pKey];
        require(p.vk == msg.sender && p.active && address(partitionVerifier) != address(0));
        PartitionChallengeInfo storage c = partitionChallenges[pKey][round];
        require(c.exists);
        if (partitionContentProven[pKey][round][p.contentHash]) {
            emit PartitionProofAlreadyAccepted(pKey, msg.sender, round, p.contentHash);
            return;
        }
        require(block.timestamp <= c.deadline && block.number > c.openedAtBlock);
        _validatePartitionPublicInputsFromSeed(p, c.seed, round, publicInputs);
        bool zkValid = partitionVerifier.verifyProof(proof, publicInputs);
        if (!zkValid) { _handleWrongProof(msg.sender); return; }
        c.proven = true; c.provenContentHash = p.contentHash;
        partitionContentProven[pKey][round][p.contentHash] = true;
        p.lastProofRound = round; p.lastProvenContentHash = p.contentHash; p.updatedAt = uint64(block.timestamp);
        partitionLastCurrentProofAt[pKey] = uint64(block.timestamp);
        _tryRecordProofSuccess(msg.sender);
        emit PartitionProofSubmitted(pKey, msg.sender, round, c.seed);
    }

    function expectedPartitionPublicInputs(bytes32 pKey, uint64 round) external view returns (uint256[] memory) {
        PartitionInfo storage p = partitions[pKey];
        PartitionChallengeInfo storage c = partitionChallenges[pKey][round];
        require(p.vk != address(0) && c.exists);
        return _buildPartitionPublicInputsFromSeed(p, c.seed, round);
    }

    // ─── Deterministic single-tx partition proof path ─────────────────────────

    /// @notice Compute the deterministic challenge seed for a partition/round.
    /// Uses the challenge anchor captured at registration time.
    /// seed = keccak256(address(this), chainid, pKey, keccak256(sectorRoots), round, anchor)
    function computePartitionDetSeed(bytes32 pKey, uint64 round) public view returns (bytes32 seed) {
        PartitionInfo storage p = partitions[pKey];
        if (p.vk == address(0)) revert StorageProofInvariant(13);
        seed = _computePartitionDetSeed(pKey, p, round);
    }

    /// @notice Returns expected public inputs for the deterministic proof path.
    /// The VK calls this (via eth_call) to get inputs before generating the ZK proof.
    function expectedPartitionPublicInputsDeterministic(bytes32 pKey, uint64 round) external view returns (uint256[] memory) {
        PartitionInfo storage p = partitions[pKey];
        if (p.vk == address(0)) revert StorageProofInvariant(13);
        bytes32 detSeed = _computePartitionDetSeed(pKey, p, round);
        return _buildPartitionPublicInputsFromSeed(p, detSeed, round);
    }

    /// @notice Single-tx periodic proof of the exact current partition content.
    /// Does NOT require a prior openPartitionChallenge transaction. This path remains
    /// available when PartitionSnapshotProofSC is configured: snapshots authorize
    /// capacity/deletion history, while this function owns recurring StorageProof rounds.
    /// A concurrent content change makes the public inputs stale and the transaction reverts.
    function submitPartitionZkProofDeterministic(
        bytes32 pKey, uint64 round, bytes calldata proof, uint256[] calldata publicInputs
    ) external onlyEligibleVK {
        PartitionInfo storage p = partitions[pKey];
        if (p.vk != msg.sender) revert StorageProofInvariant(17);
        if (!p.active) revert StorageProofInvariant(18);
        if (p.expiration <= block.timestamp) revert StorageProofInvariant(21);
        if (round > currentRound() + 1) revert StorageProofInvariant(22);
        if (partitionContentProven[pKey][round][p.contentHash]) {
            emit PartitionProofAlreadyAccepted(pKey, msg.sender, round, p.contentHash);
            return;
        }
        if (p.challengeAnchor == bytes32(0)) revert StorageProofInvariant(23);
        if (address(partitionVerifier) == address(0)) revert StorageProofInvariant(24);

        bytes32 detSeed = _computePartitionDetSeed(pKey, p, round);
        _validatePartitionPublicInputsFromSeed(p, detSeed, round, publicInputs);
        bool zkValid = partitionVerifier.verifyProof(proof, publicInputs);
        if (!zkValid) { _handleWrongProof(msg.sender); return; }

        partitionDetProven[pKey][round] = true;
        partitionDetProvenContentHash[pKey][round] = p.contentHash;
        partitionContentProven[pKey][round][p.contentHash] = true;
        p.lastProofRound = round;
        p.lastProvenContentHash = p.contentHash;
        p.updatedAt      = uint64(block.timestamp);
        partitionLastCurrentProofAt[pKey] = uint64(block.timestamp);
        if (!partitionRoundCredited[pKey][round]) {
            partitionRoundCredited[pKey][round] = true;
            _tryRecordProofSuccess(msg.sender);
        }
        emit PartitionProofSubmittedDeterministic(pKey, msg.sender, round, detSeed);
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    function _tryRecordProofSuccess(address vk) internal {
        lastProofAt[vk] = uint64(block.timestamp);
        if (wrongProofAttempts[vk] > 0) wrongProofAttempts[vk] = 0;
        if (reputationManager != address(0)) {
            try IReputationManager_SP(reputationManager).recordVKProofSuccess(vk) {} catch {}
        }
        if (rewardManager != address(0)) {
            try IRewardManager_SP(rewardManager).creditVKProof(vk) {} catch {}
        }
    }

    /// @dev A report either charges the miss or reverts whole. Swallowing a failure here would
    ///      leave the challenge marked but uncharged, and a reporter could arrange the failure:
    ///      a call starved of gas fails inside the try while this frame still finishes.
    ///      (A plain call would do the same, but costs ~1 KB more code under viaIR.)
    function _recordProofMissed(bytes32 sk, uint64 round, address vk) internal {
        if (reputationManager == address(0)) return;
        try IReputationManager_SP(reputationManager).recordVKProofMissedFor(vk, keccak256(abi.encode(sk, round))) {}
        catch { revert StorageProofInvariant(33); }
    }

    // ─── Wrong-proof escalation helpers ──────────────────────────────────────

    /// @dev A wrong proof is recorded with every penalty its level carries, or not at all:
    ///      each call below reverts the proof when it fails, for any reason, with the code
    ///      _recordProofMissed uses (33: a penalty could not be charged). Swallowing a
    ///      failure let the VaultKeeper, which sets its own gas limit, starve the calls (a call
    ///      gets at most 63/64 of the gas left) while its proof still went through; and
    ///      eth_estimateGas finds such a limit by itself.
    function _handleWrongProof(address vk) internal {
        wrongProofAttempts[vk] += 1;
        uint32 attempts = wrongProofAttempts[vk];
        emit WrongProofAttempted(vk, attempts, uint64(block.timestamp));

        // Below repThreshold the WrongProofAttempted event is the only signal. The thresholds
        // are ordered (setWrongProofThresholds), so each level adds to the one below it.
        if (attempts < wrongProofRepThreshold) return;
        _applyWrongProofRepPenalty(vk);
        if (attempts < wrongProofSlashThreshold) return;
        bool suspend = attempts >= wrongProofSuspendThreshold;
        _applyWrongProofSlash(vk, suspend ? wrongProofSuspendSlashBps : wrongProofSlashBps);
        if (suspend) _applyWrongProofSuspend(vk);
    }

    function _applyWrongProofRepPenalty(address vk) internal {
        if (reputationManager == address(0)) return;
        try IReputationManager_SP(reputationManager).recordVKProofMissed(vk) {} catch { revert StorageProofInvariant(33); }
    }

    function _applyWrongProofSlash(address vk, uint16 bps) internal {
        if (stakingManager == address(0) || bps == 0) return;
        IStakingManager_SP sm = IStakingManager_SP(stakingManager);
        uint256 stake;
        try sm.stakeOf(vk) returns (uint256 s) { stake = s; } catch { revert StorageProofInvariant(33); }
        if (stake == 0) return;
        uint256 amount = stake * uint256(bps) / 10000;
        if (amount == 0) return;
        try sm.slash(vk, amount) {} catch { revert StorageProofInvariant(33); }
    }

    function _applyWrongProofSuspend(address vk) internal {
        if (vaultKeeperRegistry == address(0) || wrongProofSuspendSeconds == 0) return;
        uint64 until = uint64(block.timestamp) + wrongProofSuspendSeconds;
        try IVaultKeeperRegistry_SP(vaultKeeperRegistry).suspendVaultKeeper(vk, until) {} catch { revert StorageProofInvariant(33); }
    }

    function _computePartitionDetSeed(bytes32 pKey, PartitionInfo storage p, uint64 round)
        internal view returns (bytes32)
    {
        // Domain-separated by contract address and chain id to prevent cross-chain replay.
        // Commits to sector roots via their keccak hash so challenge depends on registered data.
        // p.challengeAnchor still varies the seed across content versions (unchanged purpose).
        // roundChallengeAnchor[round] is the part that makes THIS round unpredictable before
        // ensureRoundChallengeAnchor(round) has been called at least once — see that function.
        bytes32 rootsHash = keccak256(abi.encodePacked(p.sectorRoots));
        return keccak256(abi.encodePacked(
            address(this),
            block.chainid,
            pKey,
            rootsHash,
            uint64(round),
            p.challengeAnchor,
            roundChallengeAnchor[round]
        ));
    }

    function _assertDataRemovalAllowed(
        PartitionInfo storage p,
        bytes32[] calldata newSectorRoots,
        bytes32[] calldata newPieceCommitments
    ) internal view {
        uint256 k = p.sectorRoots.length;
        for (uint256 i = 0; i < k; i++) {
            bytes32 oldRoot = p.sectorRoots[i];
            bytes32 oldPC = i < p.pieceCommitments.length ? p.pieceCommitments[i] : bytes32(0);
            if (!_partitionUpdateKeepsDataSlot(oldRoot, oldPC, newSectorRoots, newPieceCommitments)) {
                _assertDataSlotReleaseAllowed(
                    p.deadlineIndex,
                    p.partitionIndex,
                    oldRoot,
                    oldPC
                );
            }
        }
    }

    function _assertDataPartitionReleaseAllowed(PartitionInfo storage p) internal view {
        uint256 k = p.sectorRoots.length;
        for (uint256 i = 0; i < k; i++) {
            _assertDataSlotReleaseAllowed(
                p.deadlineIndex,
                p.partitionIndex,
                p.sectorRoots[i],
                i < p.pieceCommitments.length ? p.pieceCommitments[i] : bytes32(0)
            );
        }
    }

    function _assertDataSlotReleaseAllowed(
        uint8 deadlineIndex,
        uint8 partitionIndex,
        bytes32 sectorRoot,
        bytes32 pieceCommitment
    ) internal view {
        if (fileRegistration == address(0)) {
            if (dataLifecycleGuardRequired) revert StorageProofInvariant(25);
            return;
        }
        if (!IFileRegistrationLifecycleGuard_SP(fileRegistration).canReleaseDataSlot(
                msg.sender,
                deadlineIndex,
                partitionIndex,
                sectorRoot,
                pieceCommitment
            )) revert StorageProofInvariant(26);
    }

    function _partitionUpdateKeepsDataSlot(
        bytes32 oldRoot,
        bytes32 oldPC,
        bytes32[] calldata newSectorRoots,
        bytes32[] calldata newPieceCommitments
    ) internal pure returns (bool) {
        uint256 k = newSectorRoots.length;
        for (uint256 i = 0; i < k; i++) {
            if (newSectorRoots[i] == oldRoot && newPieceCommitments[i] == oldPC) {
                return true;
            }
        }
        return false;
    }

    function _validatePublicInputs(SectorInfo storage s, ChallengeInfo storage c, uint64 round, uint256[] calldata pi) internal view {
        uint256[] memory exp = _buildExpectedPublicInputs(s, c, round);
        require(pi.length == exp.length);
        for (uint256 i = 0; i < exp.length; i++)
            if (pi[i] != exp[i]) revert StorageProofInvariant(27);
    }

    function _buildExpectedPublicInputs(SectorInfo storage s, ChallengeInfo storage c, uint64 round) internal view returns (uint256[] memory inputs) {
        uint16 cc = s.challengeCount;
        inputs = new uint256[](7 + cc);
        (uint256 rHi, uint256 rLo) = _splitBytes32(s.sectorRoot);
        (uint256 sHi, uint256 sLo) = _splitBytes32(c.seed);
        inputs[0]=rHi; inputs[1]=rLo; inputs[2]=sHi; inputs[3]=sLo;
        inputs[4]=uint256(round); inputs[5]=uint256(s.sectorBlockCount); inputs[6]=uint256(cc);
        uint256[] memory idxs = _challengeIndexes(c.seed, s.sectorBlockCount, cc);
        for (uint256 i = 0; i < cc; i++) inputs[7+i] = idxs[i];
    }

    function _validatePartitionPublicInputsFromSeed(PartitionInfo storage p, bytes32 seed, uint64 round, uint256[] calldata pi) internal view {
        uint256[] memory exp = _buildPartitionPublicInputsFromSeed(p, seed, round);
        if (pi.length != exp.length) revert StorageProofInvariant(28);
        for (uint256 i = 0; i < exp.length; i++)
            if (pi[i] != exp[i]) revert StorageProofInvariant(29);
    }

    /// @dev Core builder: same layout for both legacy and deterministic paths.
    ///   [0]              seedHi
    ///   [1]              seedLo
    ///   [2]              round
    ///   [3+i]            sectorRootHi[i]         i=0..N-1  (padded by repeating last)
    ///   [3+N+i]          sectorRootLo[i]         i=0..N-1
    ///   [3+2N+i]         sectorBlockCount[i]     i=0..N-1
    ///   [3+3N]           challengeCount
    ///   [4+3N+i*M+j]     challengeIndex[i][j]    i=0..N-1, j=0..M-1
    ///   [4+3N+NM+i]      pieceCommitment[i]      i=0..N-1  ← W3 fix
    ///   Total: 4 + 4N + NM  (= 132 for N=16, M=4)
    function _buildPartitionPublicInputsFromSeed(PartitionInfo storage p, bytes32 seed, uint64 round) internal view returns (uint256[] memory inputs) {
        uint256 N = uint256(partitionCircuitSectors);
        uint256 M = uint256(partitionCircuitChallenges);
        inputs = new uint256[](4 + 4*N + N*M);
        (uint256 sHi, uint256 sLo) = _splitBytes32(seed);
        inputs[0] = sHi; inputs[1] = sLo; inputs[2] = uint256(round);
        uint256 k = p.sectorRoots.length;
        for (uint256 i = 0; i < N; i++) {
            uint256 si = (i < k) ? i : (k-1);
            (uint256 rHi, uint256 rLo) = _splitBytes32(p.sectorRoots[si]);
            inputs[3+i]     = rHi;
            inputs[3+N+i]   = rLo;
            inputs[3+2*N+i] = uint256(p.sectorBlockCounts[si]);
        }
        inputs[3+3*N] = uint256(p.challengeCount);
        for (uint256 i = 0; i < N; i++) {
            uint256 si = (i < k) ? i : (k-1);
            uint256[] memory idxs = _challengeIndexes(seed, p.sectorBlockCounts[si], p.challengeCount);
            for (uint256 j = 0; j < M; j++) {
                inputs[4+3*N+i*M+j] = (j < idxs.length) ? idxs[j] : 0;
            }
        }
        // W3 fix: append pieceCommitment[i] for i=0..N-1
        for (uint256 i = 0; i < N; i++) {
            uint256 si = (i < k) ? i : (k-1);
            inputs[4+3*N+N*M+i] = uint256(
                (si < p.pieceCommitments.length) ? p.pieceCommitments[si] : bytes32(0)
            );
        }
    }

    function _challengeIndexes(bytes32 seed, uint32 blockCount, uint16 challengeCount) internal pure returns (uint256[] memory idxs) {
        require(blockCount > 0);
        idxs = new uint256[](challengeCount);
        uint256 found = 0; uint256 counter = 0;
        while (found < challengeCount) {
            uint256 candidate = uint256(keccak256(abi.encodePacked(seed, counter))) % uint256(blockCount);
            bool dup = false;
            for (uint256 j = 0; j < found; j++) { if (idxs[j] == candidate) { dup = true; break; } }
            if (!dup) { idxs[found] = candidate; found++; }
            counter++;
        }
    }

    function _splitBytes32(bytes32 v) internal pure returns (uint256 hi, uint256 lo) {
        uint256 x = uint256(v);
        hi = x >> 128;
        lo = x & ((uint256(1) << 128) - 1);
    }

    function _syncCapacityRegistration(bytes32 pKey) internal {
        if (capacityProof != address(0)) {
            ICapacityProofSync_SP(capacityProof).syncPartitionRegistration(pKey);
        }
    }

    function _releaseIdentity(bytes32 pKey, PartitionInfo storage p)
        internal view returns (ReleaseIdentity memory identity)
    {
        identity = ReleaseIdentity({
            kind: p.partitionKind,
            active: p.active,
            contentVersion: p.contentVersion,
            contentHash: p.contentHash,
            committedBytes: p.committedBytes,
            registrationNonce: partitionCurrentRegistrationNonce[pKey],
            transitionNonce: partitionTransitionNonce[pKey]
        });
    }

    function _advancePartitionLineage(
        bytes32 pKey,
        PartitionInfo storage p,
        uint64 predecessorVersion,
        uint64 predecessorRegistrationNonce
    ) internal {
        uint64 nextRegistration = partitionRegistrationSequence[p.vk] + 1;
        if (nextRegistration == 0) revert DeletionReleaseInvariant(5);
        partitionRegistrationSequence[p.vk] = nextRegistration;
        if (predecessorVersion != 0) {
            PartitionLineage storage predecessor =
                partitionVersionLineage[pKey][predecessorVersion];
            if (predecessor.registeredNonce != predecessorRegistrationNonce ||
                predecessor.supersededNonce != 0) revert DeletionReleaseInvariant(6);
            predecessor.supersededNonce = nextRegistration;
        }
        PartitionLineage storage successor =
            partitionVersionLineage[pKey][p.contentVersion];
        if (successor.registeredNonce != 0) revert DeletionReleaseInvariant(7);
        successor.registeredNonce = nextRegistration;
        partitionCurrentRegistrationNonce[pKey] = nextRegistration;
        uint64 nextTransition = partitionTransitionNonce[pKey] + 1;
        if (nextTransition == 0) revert DeletionReleaseInvariant(8);
        partitionTransitionNonce[pKey] = nextTransition;
    }

    function _unresolvedDeletionOperation(bytes32 pKey)
        internal view returns (bytes32)
    {
        if (deletionRelease == address(0)) return bytes32(0);
        return IDeletionRelease_SP(deletionRelease)
            .unresolvedOperationByPartition(pKey);
    }

    function _resolveDeletionSuccessor(
        bytes32 operationId,
        ReleaseIdentity memory predecessor
    ) internal {
        IDeletionRelease_SP(deletionRelease).resolveSuccessor(
            operationId,
            predecessor.kind,
            predecessor.active,
            predecessor.contentVersion,
            predecessor.contentHash,
            predecessor.committedBytes,
            predecessor.registrationNonce,
            predecessor.transitionNonce
        );
    }

}
