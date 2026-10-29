// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: CapacityProofSC
// Purpose:  A Vault Keeper's declared and proven free space, and how much new storage
//           that space is allowed to admit.
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

/// @notice Minimal registry surface used to keep capacity authority restricted to
///         registered, staked Vault Keepers.
interface IVaultKeeperRegistry_CP {
    function isEligibleVaultKeeper(address vk) external view returns (bool);
    function defaultAdmissionMarginBytes() external view returns (uint64);
}

interface IStorageProof_CP {
    function currentRound() external view returns (uint64);
    function partitionCurrentRegistrationNonce(bytes32 pKey) external view returns (uint64);
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

/// @notice Sole certification authority surface. CapacityProofSC never holds ring state;
///         it only reports registered-identity transitions to the certification contract.
/// @notice Campaign coordinator (CapacityIncrementalBatchSC). Only claim/release live here;
///         all campaign and membership logic is owned by that contract.
interface ICapacityCampaign_CP {
    function claimFullCampaign(address vk, uint64 authorityId, uint8 mode) external;
    function releaseFullCampaign(address vk) external;
    function capacityProof() external view returns (address);
}

interface ICapacityCertification_CP {
    function certifyPartition(
        address vk,
        bytes32 partitionKey,
        uint8 kind,
        bool active,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external;
    function invalidatePartition(bytes32 partitionKey) external;
    function certificationIdentityHash(
        bytes32 partitionKey,
        uint8 kind,
        bool active,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external pure returns (bytes32);
    function isCertifiedCurrent(bytes32 partitionKey, bytes32 identityHash)
        external view returns (bool);
    function certifiedFree(address vk) external view returns (uint64);
    function safeAllocatableBytes(
        address vk,
        uint64 declared,
        uint64 allocated,
        uint64 reserved,
        uint64 margin
    ) external view returns (uint64);
}

/// @title CapacityProofSC
/// @notice Authoritative, privacy-preserving capacity and admission accounting.
///
/// The contract deliberately keeps payment commitments, DO addresses, file IDs,
/// piece roots and peer IDs out of capacity state.  A reservation is keyed only by
/// the already-random registration commitment and accounts for a privacy-padded
/// allocation extent.
///
/// Safety invariant:
///   conservative free <= proven backing
///   conservative free <= current registered free backing
///   conservative free <= declared capacity - live allocations - live quotes
///
/// A historical partition proof may complete only the immutable epoch that
/// captured it. It cannot increase current partition totals, and sellable free
/// space remains clamped by both the live registration and allocation ledgers.
contract CapacityProofSC {
    uint64 public constant STANDALONE_DELETION_PROOF_FLAG = uint64(1) << 63;
    uint8 public constant PARTITION_KIND_DATA = 1;
    uint8 public constant PARTITION_KIND_CAPACITY = 2;

    uint8 public constant RESERVATION_NONE = 0;
    uint8 public constant RESERVATION_QUOTED = 1;
    uint8 public constant RESERVATION_STORED = 2;
    uint8 public constant RESERVATION_DELETION_PENDING = 3;
    uint8 public constant RESERVATION_RELEASED = 4;
    uint8 public constant RESERVATION_EXPIRED = 5;
    uint8 public constant RESERVATION_ACTIVE_TRANSFER = 6;

    struct QuoteReservation {
        address vk;
        uint64 reservedBytes;
        uint64 expiresAt;
        uint8 state;
    }

    struct PartitionAccount {
        address vk;
        uint8 kind;
        bool active;
        uint64 contentVersion;
        bytes32 contentHash;
        uint64 registeredBytes;
        uint64 provedVersion;
        bytes32 provedContentHash;
        uint64 provedBytes;
        uint64 provedRound;
        uint64 countedProofEpoch;
        uint64 registrationNonce;
        bytes32 versionAccountKey;
    }

    struct PartitionVersionAccount {
        address vk;
        bytes32 partitionKey;
        uint8 kind;
        uint64 contentVersion;
        bytes32 contentHash;
        uint64 registeredBytes;
        uint64 registeredNonce;
        uint64 supersededNonce;
        uint64 countedProofEpoch;
    }

    struct ProofEpoch {
        uint64 epochId;
        uint64 targetRound;
        uint64 cutoffNonce;
        uint32 expectedPartitions;
        uint32 provenPartitions;
        uint64 expectedBytes;
        uint64 provenBytes;
        uint64 provenFreeBytes;
        uint64 provenDataBytes;
        uint64 allocatedBytesAtCutoff;
        bool invalidated;
        bool active;
    }

    struct ProofEpochExclusion {
        uint64 contentVersion;
        bytes32 contentHash;
        uint64 excludedBytes;
        bool excluded;
    }

    address public owner;
    address public vaultKeeperRegistry;
    address public storageProof;
    address public fileRegistration;
    address public partitionSnapshotProof;

    /// @notice Maximum age of the most recent current capacity proof before new
    ///         admission closes. Existing storage, proof, deletion and download
    ///         operations are not blocked by this admission-only gate.
    uint64 public maxProofAgeSeconds = 30 hours;

    /// @notice CapacityCertificationSC — the sole owner of rolling certificate freshness
    ///         and bucket totals (G.1A). Immutable: the reciprocal binding on the
    ///         certification side is one-time and irreversible, so this side must not drift.
    address public immutable certificationContract;
    /// @notice CapacityIncrementalBatchSC — the authoritative per-VK capacity-campaign lock
    ///         (G.2B). Set exactly once and never replaceable; the setter verifies the
    ///         coordinator already points back at this contract.
    address public campaignCoordinator;
    /// @notice Hard upper bound on a quote reservation. It must cover quote
    ///         validity plus the escrow registration window, while bounding DoS.
    uint64 public maxQuoteReservationSeconds = 30 minutes;
    /// @notice Maximum single active-transfer lease. The owning VK may renew
    ///         while a resumable transfer is making progress; abandoned leases
    ///         remain permissionlessly reclaimable.
    uint64 public maxActiveTransferSeconds = 7 days;
    /// @notice Maximum temporary physical overlap while one immutable free
    ///         chunk is retired after its successor data chunk is committed.
    uint64 public maxManifestOverheadBytes = type(uint64).max;

    mapping(address => uint64) public declaredCapacity;
    mapping(address => uint64) public registeredCapacityFreeBytes;
    mapping(address => uint64) public registeredDataUsedBytes;
    /// @dev Sum of min(last proved bytes, current registered bytes) per active
    ///      capacity partition. This permits immutable snapshots to remain a
    ///      conservative baseline while a smaller live successor is prepared.
    mapping(address => uint64) public provedCapacityFreeBytes;
    /// @dev Only exact-current data versions contribute here.
    mapping(address => uint64) public provedDataUsedBytes;
    mapping(address => uint64) public quoteReservedBytes;
    mapping(address => uint64) public allocatedStoredBytes;
    mapping(address => uint64) public lastCapacityProofAt;
    mapping(address => uint64) public capacityProofSequence;
    mapping(address => uint64) public provedBackingBytes;
    mapping(address => uint64) public partitionRegistrationNonce;
    mapping(address => uint32) public activePartitionCount;
    mapping(address => ProofEpoch) public proofEpochs;
    mapping(address => uint64) public lastCompleteFreeBytes;
    mapping(address => uint64) public lastCompleteDataBytes;
    mapping(address => uint64) public lastCompleteAllocatedBytes;
    mapping(address => uint64) public lastCompletedProofRound;
    mapping(address => mapping(uint64 => uint64)) public abortedEpochRound;
    mapping(address => mapping(uint64 => mapping(bytes32 => ProofEpochExclusion)))
        private proofEpochExclusions;

    mapping(bytes32 => QuoteReservation) private quoteReservations;
    mapping(bytes32 => PartitionAccount) private partitionAccounts;
    mapping(bytes32 => PartitionVersionAccount) private partitionVersionAccounts;
    mapping(bytes32 => bytes32) private deletionPartitionKeys;
    mapping(bytes32 => uint64) private deletionAfterContentVersions;

    event VaultKeeperRegistrySet(address indexed registry);
    event StorageProofSet(address indexed storageProof);
    event FileRegistrationSet(address indexed fileRegistration);
    event PartitionSnapshotProofSet(address indexed partitionSnapshotProof);
    event MaxProofAgeSecondsSet(uint64 seconds_);
    event MaxQuoteReservationSecondsSet(uint64 seconds_);
    event MaxActiveTransferSecondsSet(uint64 seconds_);
    event MaxManifestOverheadBytesSet(uint64 bytes_);
    event CapacityDeclared(address indexed vk, uint64 totalCapacityBytes);
    event QuoteReserved(
        bytes32 indexed registrationCommitment,
        address indexed vk,
        uint64 reservedBytes,
        uint64 expiresAt
    );
    event QuoteReservationStateChanged(
        bytes32 indexed registrationCommitment,
        address indexed vk,
        uint8 oldState,
        uint8 newState,
        uint64 reservedBytes
    );
    event PartitionCapacityRegistered(
        bytes32 indexed partitionKey,
        address indexed vk,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 registeredBytes,
        bool active
    );
    event PartitionCapacityProven(
        bytes32 indexed partitionKey,
        address indexed vk,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 provedBytes,
        uint64 proofSequence
    );
    event ProofEpochStarted(
        address indexed vk,
        uint64 indexed epochId,
        uint64 targetRound,
        uint64 cutoffNonce,
        uint32 expectedPartitions,
        uint64 expectedBytes
    );
    event ProofEpochCompleted(
        address indexed vk,
        uint64 indexed epochId,
        uint64 targetRound,
        uint64 proofSequence,
        uint64 backedBytes
    );
    event ProofEpochAborted(address indexed vk, uint64 indexed epochId, uint64 targetRound);
    event ProofEpochCutoffMemberExcluded(
        address indexed vk,
        uint64 indexed epochId,
        bytes32 partitionKey,
        uint64 contentVersion,
        uint64 excludedBytes
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "CP: only owner");
        _;
    }

    modifier onlyStorageProof() {
        require(msg.sender == storageProof, "CP: only storage proof");
        _;
    }

    modifier onlyFileRegistration() {
        require(msg.sender == fileRegistration, "CP: only file registration");
        _;
    }

    modifier onlyPartitionSnapshotProof() {
        require(msg.sender == partitionSnapshotProof, "CP: only snapshot proof");
        _;
    }

    modifier onlyEligibleVK() {
        require(vaultKeeperRegistry != address(0), "CP: registry unset");
        require(
            IVaultKeeperRegistry_CP(vaultKeeperRegistry).isEligibleVaultKeeper(msg.sender),
            "CP: VK not eligible"
        );
        _;
    }

    /// @param certificationContract_ deployed CapacityCertificationSC. The reciprocal
    ///        binding is completed on that side by `bindCapacityProof(address(this))`, which
    ///        verifies this pointer before accepting authority.
    constructor(address certificationContract_) {
        owner = msg.sender;
        require(certificationContract_ != address(0), "CP: zero certification");
        require(
            certificationContract_.code.length > 0,
            "CP: certification has no code"
        );
        certificationContract = certificationContract_;
    }

    /// @notice One-time, irreversible wiring of the campaign coordinator. There is no reset
    ///         and no replacement: a campaign lock that could be re-pointed would not be a lock.
    function setCampaignCoordinator(address coordinator) external onlyOwner {
        require(campaignCoordinator == address(0), "CP: coordinator already set");
        // A non-contract address cannot answer the reciprocity call, so that check subsumes
        // the code-length check.
        require(ICapacityCampaign_CP(coordinator).capacityProof() == address(this),
                "CP: coordinator not reciprocal");
        campaignCoordinator = coordinator;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "CP: zero owner");
        owner = newOwner;
    }

    function setVaultKeeperRegistry(address registry) external onlyOwner {
        require(registry != address(0), "CP: zero registry");
        vaultKeeperRegistry = registry;
        emit VaultKeeperRegistrySet(registry);
    }

    function setStorageProof(address storageProof_) external onlyOwner {
        require(storageProof_ != address(0), "CP: zero storage proof");
        require(storageProof == address(0), "CP: storage proof already set");
        storageProof = storageProof_;
        emit StorageProofSet(storageProof_);
    }

    function setFileRegistration(address fileRegistration_) external onlyOwner {
        require(fileRegistration_ != address(0), "CP: zero file registration");
        require(fileRegistration == address(0), "CP: file reg already set");
        fileRegistration = fileRegistration_;
        emit FileRegistrationSet(fileRegistration_);
    }

    function setPartitionSnapshotProof(address snapshotProof_) external onlyOwner {
        require(snapshotProof_ != address(0), "CP: zero snapshot proof");
        require(partitionSnapshotProof == address(0), "CP: snapshot proof already set");
        partitionSnapshotProof = snapshotProof_;
        emit PartitionSnapshotProofSet(snapshotProof_);
    }

    function setMaxProofAgeSeconds(uint64 seconds_) external onlyOwner {
        require(seconds_ >= 10 minutes, "CP: proof age too short");
        maxProofAgeSeconds = seconds_;
        emit MaxProofAgeSecondsSet(seconds_);
    }

    function setMaxQuoteReservationSeconds(uint64 seconds_) external onlyOwner {
        require(seconds_ >= 2 minutes && seconds_ <= 1 days, "CP: bad quote bound");
        maxQuoteReservationSeconds = seconds_;
        emit MaxQuoteReservationSecondsSet(seconds_);
    }

    function setMaxActiveTransferSeconds(uint64 seconds_) external onlyOwner {
        require(seconds_ >= 10 minutes && seconds_ <= 30 days,
                "CP: bad active transfer bound");
        maxActiveTransferSeconds = seconds_;
        emit MaxActiveTransferSecondsSet(seconds_);
    }

    function setMaxManifestOverheadBytes(uint64 bytes_) external onlyOwner {
        require(bytes_ > 0, "CP: zero manifest overhead");
        maxManifestOverheadBytes = bytes_;
        emit MaxManifestOverheadBytesSet(bytes_);
    }

    function declareCapacity(uint64 totalCapacityBytes) external onlyEligibleVK {
        require(totalCapacityBytes > 0, "CP: zero capacity");
        uint256 committed = uint256(quoteReservedBytes[msg.sender]) +
            uint256(allocatedStoredBytes[msg.sender]);
        require(committed <= totalCapacityBytes, "CP: below commitments");
        uint256 registered = uint256(registeredCapacityFreeBytes[msg.sender]) +
            uint256(registeredDataUsedBytes[msg.sender]);
        uint256 permittedOverhead = _permittedManifestOverhead(totalCapacityBytes);
        require(registered <= uint256(totalCapacityBytes) + permittedOverhead,
                "CP: manifest overhead too big");
        if (declaredCapacity[msg.sender] != 0 &&
            declaredCapacity[msg.sender] != totalCapacityBytes)
        {
            ProofEpoch storage epoch = proofEpochs[msg.sender];
            if (epoch.active) {
                _abortProofEpoch(msg.sender, epoch.epochId);
            }
        }
        declaredCapacity[msg.sender] = totalCapacityBytes;
        emit CapacityDeclared(msg.sender, totalCapacityBytes);
    }

    /// @notice Atomically reserves a blinded allocation before a signed quote is
    ///         returned. Exact retries are idempotent; conflicting reuse reverts.
    function reserveQuote(
        bytes32 registrationCommitment,
        uint64 reservedBytes,
        uint64 expiresAt
    ) external onlyEligibleVK {
        require(registrationCommitment != bytes32(0), "CP: zero commitment");
        require(reservedBytes > 0, "CP: zero reservation");
        require(expiresAt > block.timestamp, "CP: expiry in past");
        require(
            uint256(expiresAt) <= block.timestamp + maxQuoteReservationSeconds,
            "CP: expiry too distant"
        );

        QuoteReservation storage existing = quoteReservations[registrationCommitment];
        if (existing.state != RESERVATION_NONE) {
            require(
                existing.state == RESERVATION_QUOTED &&
                existing.vk == msg.sender &&
                existing.reservedBytes == reservedBytes &&
                existing.expiresAt == expiresAt,
                "CP: conflicting reservation"
            );
            return;
        }

        // The chain, not the VK process, is the final admission authority. A
        // stale historical proof must never be usable to create fresh storage
        // obligations even if a buggy or malicious VK advertises itself open.
        require(
            isAdmissionOpen(msg.sender, reservedBytes),
            "CP: admission"
        );
        quoteReservations[registrationCommitment] = QuoteReservation({
            vk: msg.sender,
            reservedBytes: reservedBytes,
            expiresAt: expiresAt,
            state: RESERVATION_QUOTED
        });
        quoteReservedBytes[msg.sender] += reservedBytes;
        emit QuoteReserved(registrationCommitment, msg.sender, reservedBytes, expiresAt);
    }

    /// @notice Convert a quote reservation to a live storage allocation. The
    ///         capacity charge is continuous across the transition.
    function consumeQuote(bytes32 registrationCommitment, address expectedVK)
        external onlyFileRegistration returns (uint64 reservedBytes)
    {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        require(
            reservation.state == RESERVATION_QUOTED ||
            reservation.state == RESERVATION_ACTIVE_TRANSFER,
            "CP: quote not active"
        );
        require(reservation.vk == expectedVK, "CP: quote VK mismatch");
        require(block.timestamp <= reservation.expiresAt, "CP: quote expired");
        reservedBytes = reservation.reservedBytes;
        quoteReservedBytes[expectedVK] -= reservedBytes;
        allocatedStoredBytes[expectedVK] += reservedBytes;
        _setReservationState(registrationCommitment, reservation, RESERVATION_STORED);
    }

    /// @notice After privately verifying escrow, the owning VK leases the
    ///         reservation for an active/resumable transfer. No payment or DO
    ///         linkage is revealed. Monotonic bounded renewals are idempotent.
    function activateQuote(bytes32 registrationCommitment, uint64 activeUntil) external {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        require(reservation.vk == msg.sender, "CP: not quote VK");
        require(
            reservation.state == RESERVATION_QUOTED ||
            reservation.state == RESERVATION_ACTIVE_TRANSFER,
            "CP: quote not activatable"
        );
        require(block.timestamp <= reservation.expiresAt,
                "CP: reservation already expired");
        require(activeUntil >= reservation.expiresAt,
                "CP: active lease cannot shrink");
        require(activeUntil > block.timestamp, "CP: active lease in past");
        require(
            uint256(activeUntil) <= block.timestamp + maxActiveTransferSeconds,
            "CP: active lease too distant"
        );
        if (
            reservation.state == RESERVATION_ACTIVE_TRANSFER &&
            activeUntil == reservation.expiresAt
        ) return;
        reservation.expiresAt = activeUntil;
        if (reservation.state != RESERVATION_ACTIVE_TRANSFER) {
            _setReservationState(
                registrationCommitment,
                reservation,
                RESERVATION_ACTIVE_TRANSFER
            );
        }
    }

    function markDeletionPending(
        bytes32 registrationCommitment,
        address expectedVK,
        bytes32 partitionKey,
        uint64 currentContentVersion
    )
        external onlyFileRegistration
    {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        require(reservation.state == RESERVATION_STORED, "CP: storage not active");
        require(reservation.vk == expectedVK, "CP: storage VK mismatch");
        PartitionAccount storage account = partitionAccounts[partitionKey];
        require(
            account.active && account.vk == expectedVK && account.kind == PARTITION_KIND_DATA,
            "CP: deletion partition mismatch"
        );
        require(
            account.contentVersion == currentContentVersion,
            "CP: deletion version mismatch"
        );
        deletionPartitionKeys[registrationCommitment] = partitionKey;
        deletionAfterContentVersions[registrationCommitment] = currentContentVersion;
        PartitionVersionAccount storage deletingVersion =
            partitionVersionAccounts[account.versionAccountKey];
        // Prefer excluding the soon-to-change cutoff member over aborting the
        // entire epoch. Continuous deletion traffic must not starve capacity
        // sequence progress that empty successors need for release. Abort only
        // when exclusion would make the epoch mathematically incompletable.
        _excludeCutoffMemberOnDeletion(expectedVK, deletingVersion);
        _setReservationState(registrationCommitment, reservation, RESERVATION_DELETION_PENDING);
    }

    /// @notice Release allocation only after FileRegistrationSC has trustlessly
    ///         confirmed absence from a current, proven data partition version.
    function releaseDeletedAllocation(
        bytes32 registrationCommitment,
        address expectedVK,
        bytes32 partitionKey,
        uint64 successorContentVersion,
        bytes32 successorContentHash
    )
        external onlyFileRegistration
    {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        require(
            reservation.state == RESERVATION_DELETION_PENDING,
            "CP: deletion not pending"
        );
        require(reservation.vk == expectedVK, "CP: deletion VK mismatch");
        require(
            deletionPartitionKeys[registrationCommitment] == partitionKey,
            "CP: deletion partition changed"
        );
        require(
            successorContentVersion > deletionAfterContentVersions[registrationCommitment],
            "CP: deletion successor missing"
        );
        // G.4: DeletionReleaseSC is the sole proof/transition receipt authority.
        // This contract now performs accounting only after FileRegistrationSC
        // atomically consumes that deletion-scoped satisfaction.
        PartitionAccount storage account = partitionAccounts[partitionKey];
        require(
            account.vk == expectedVK &&
            account.contentVersion == successorContentVersion &&
            account.contentHash == successorContentHash,
            "CP: successor identity mismatch"
        );
        allocatedStoredBytes[expectedVK] -= reservation.reservedBytes;
        _setReservationState(registrationCommitment, reservation, RESERVATION_RELEASED);
    }

    /// @notice Release an absent or late registration fenced by the trusted
    ///         FileRegistration timeout flow.
    function releaseExpiredRegistration(bytes32 registrationCommitment, address expectedVK)
        external onlyFileRegistration
    {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        require(reservation.vk == expectedVK, "CP: expiry VK mismatch");
        if (reservation.state == RESERVATION_EXPIRED) return;
        if (
            reservation.state == RESERVATION_QUOTED ||
            reservation.state == RESERVATION_ACTIVE_TRANSFER
        ) {
            quoteReservedBytes[expectedVK] -= reservation.reservedBytes;
        } else if (reservation.state == RESERVATION_STORED) {
            // A late registration may already occupy disk. Keep it charged until
            // the ordinary deletion + successor-proof lifecycle releases it.
            return;
        } else if (reservation.state == RESERVATION_DELETION_PENDING) {
            return;
        } else {
            revert("CP: reservation not expirable");
        }
        _setReservationState(registrationCommitment, reservation, RESERVATION_EXPIRED);
    }

    /// @notice Release a quote that reached STORED only through a registration
    ///         mined after its signed deadline, while the trusted storage
    ///         contract proves that the claimed file slot was never registered.
    ///         FileRegistrationSC performs that absence check and is the sole
    ///         caller; ordinary stored allocations cannot use this path.
    function releaseUnbackedExpiredRegistration(
        bytes32 registrationCommitment,
        address expectedVK
    ) external onlyFileRegistration {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        require(reservation.state == RESERVATION_STORED,
                "CP: late reg not stored");
        require(reservation.vk == expectedVK,
                "CP: late reg VK mismatch");
        allocatedStoredBytes[expectedVK] -= reservation.reservedBytes;
        _setReservationState(registrationCommitment, reservation, RESERVATION_RELEASED);
    }

    function expireQuote(bytes32 registrationCommitment) external {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        require(
            reservation.state == RESERVATION_QUOTED ||
            reservation.state == RESERVATION_ACTIVE_TRANSFER,
            "CP: quote not active"
        );
        require(block.timestamp > reservation.expiresAt, "CP: quote not expired");
        quoteReservedBytes[reservation.vk] -= reservation.reservedBytes;
        _setReservationState(registrationCommitment, reservation, RESERVATION_EXPIRED);
    }

    /// @notice Pull canonical current partition registration state. Permissionless
    ///         synchronization is safe because every field is read from the one
    ///         configured StorageProofSC; omission is fail-closed.
    function syncPartitionRegistration(bytes32 partitionKey) external {
        require(storageProof != address(0), "CP: storage proof unset");
        (
            address vk,
            ,
            ,
            ,
            uint8 kind,
            uint64 registeredBytes,
            ,
            ,
            ,
            ,
            ,
            bool active,
            bytes32 contentHash,
            uint64 contentVersion,
            ,
            ,

        ) = IStorageProof_CP(storageProof).partitions(partitionKey);
        require(vk != address(0), "CP: unknown partition");
        require(kind == PARTITION_KIND_DATA || kind == PARTITION_KIND_CAPACITY,
                "CP: bad partition kind");
        PartitionAccount storage account = partitionAccounts[partitionKey];
        require(account.vk == address(0) || account.vk == vk, "CP: partition VK changed");

        bool existed = account.vk != address(0);
        bool unchanged = existed &&
            account.kind == kind && account.active == active &&
            account.contentVersion == contentVersion && account.contentHash == contentHash &&
            account.registeredBytes == (active ? registeredBytes : 0);
        if (unchanged) return;

        if (existed) {
            _subtractRegistered(account.vk, account.kind, account.registeredBytes, account.active);
            if (account.active) activePartitionCount[vk] -= 1;
            if (account.provedBytes > 0) {
                if (account.kind == PARTITION_KIND_CAPACITY) {
                    _subtractCapacityBacking(vk, account.provedBytes);
                } else {
                    _subtractDataProof(vk, account.provedBytes);
                }
            }
            // G.1A: drop the external certification strictly BEFORE the registration fields
            // below are overwritten. The certification contract subtracts using its OWN stored
            // record (old vk, kind, bytes and expiry slot), so nothing here needs to survive
            // the overwrite. Reached only on a genuine change — the `unchanged` early return
            // above skips identical re-registration. A revert inside propagates and reverts
            // this entire registration; no partial divergence between the two contracts.
            ICapacityCertification_CP(certificationContract).invalidatePartition(partitionKey);
        }

        uint64 registrationNonce =
            IStorageProof_CP(storageProof).partitionCurrentRegistrationNonce(partitionKey);
        require(registrationNonce > partitionRegistrationNonce[vk],
                "CP: non-monotonic registration nonce");
        partitionRegistrationNonce[vk] = registrationNonce;
        if (existed && account.versionAccountKey != bytes32(0)) {
            partitionVersionAccounts[account.versionAccountKey].supersededNonce = registrationNonce;
        }

        bytes32 versionKey = keccak256(abi.encodePacked(
            partitionKey, contentVersion, contentHash
        ));
        if (active) {
            PartitionVersionAccount storage versionAccount = partitionVersionAccounts[versionKey];
            require(versionAccount.registeredNonce == 0, "CP: duplicate version account");
            versionAccount.vk = vk;
            versionAccount.partitionKey = partitionKey;
            versionAccount.kind = kind;
            versionAccount.contentVersion = contentVersion;
            versionAccount.contentHash = contentHash;
            versionAccount.registeredBytes = registeredBytes;
            versionAccount.registeredNonce = registrationNonce;
        }

        account.vk = vk;
        account.kind = kind;
        account.active = active;
        account.contentVersion = contentVersion;
        account.contentHash = contentHash;
        account.registeredBytes = active ? registeredBytes : 0;
        account.provedVersion = 0;
        account.provedContentHash = bytes32(0);
        account.provedBytes = 0;
        account.provedRound = 0;
        account.countedProofEpoch = 0;
        account.registrationNonce = registrationNonce;
        account.versionAccountKey = active ? versionKey : bytes32(0);

        _addRegistered(vk, kind, account.registeredBytes, active);
        if (active) activePartitionCount[vk] += 1;

        emit PartitionCapacityRegistered(
            partitionKey, vk, kind, contentVersion, contentHash, account.registeredBytes, active
        );
    }

    /// @notice Snapshot verifier hook. A superseded version can count only for
    /// the immutable cutoff epoch in which it was a manifest member. It never
    /// changes current partition proof totals.
    function recordVerifiedSnapshotVersion(
        address vk,
        bytes32 partitionKey,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 provedBytes,
        uint64 proofRound,
        uint64 proofEpochId
    ) external onlyPartitionSnapshotProof returns (bool counted) {
        bytes32 versionKey = keccak256(abi.encodePacked(
            partitionKey, contentVersion, contentHash
        ));
        PartitionVersionAccount storage versionAccount = partitionVersionAccounts[versionKey];
        require(
            versionAccount.vk == vk && versionAccount.partitionKey == partitionKey &&
            versionAccount.kind == kind && versionAccount.contentVersion == contentVersion &&
            versionAccount.contentHash == contentHash &&
            versionAccount.registeredBytes == provedBytes,
            "CP: unknown snapshot version"
        );
        PartitionAccount storage current = partitionAccounts[partitionKey];
        bool acceptedAsCurrent = current.active &&
            current.versionAccountKey == versionKey && current.vk == vk &&
            current.kind == kind && current.registeredBytes == provedBytes;
        if (acceptedAsCurrent) {
            if (current.provedBytes > 0) {
                if (kind == PARTITION_KIND_CAPACITY) {
                    _subtractCapacityBacking(vk, current.provedBytes);
                } else {
                    _subtractDataProof(vk, current.provedBytes);
                }
            }
            current.provedVersion = contentVersion;
            current.provedContentHash = contentHash;
            current.provedBytes = provedBytes;
            current.provedRound = proofRound;
            if (kind == PARTITION_KIND_CAPACITY) {
                provedCapacityFreeBytes[vk] += provedBytes;
            } else {
                provedDataUsedBytes[vk] += provedBytes;
            }
            // G.1A: certify externally, and only for the EXACT current identity. A stale or
            // superseded proof takes the `acceptedAsCurrent == false` path and never reaches
            // this call, so it stays historically recorded without adding certified capacity.
            // The call shares this transaction with the proof accounting above: either both
            // land or the whole submission reverts.
            ICapacityCertification_CP(certificationContract).certifyPartition(
                vk, partitionKey, kind, true, contentVersion, contentHash, provedBytes
            );
        }
        uint64 beforeCount = proofEpochs[vk].provenPartitions;
        uint64 sequence = _countVerifiedVersion(versionAccount, proofRound, proofEpochId);
        emit PartitionCapacityProven(
            partitionKey, vk, kind, contentVersion, contentHash, provedBytes, sequence
        );
        return proofEpochs[vk].provenPartitions > beforeCount;
    }

    /// @notice Opens a bounded incremental proof epoch over the current immutable
    /// manifest. Later append/update traffic creates successor versions while the
    /// snapshot contract preserves every included cutoff version. A deletion of
    /// cutoff data excludes that version when the remaining manifest stays fully
    /// backed, and aborts only when exclusion would under-back the statement.
    /// @notice Open a FULL capacity epoch. `mode` is mandatory and recorded on-chain, so every
    ///         sweep states its reason and can never be mistaken for routine work.
    /// @dev G.2A: incremental batches are NOT epochs. They are opened, membership-enforced and
    ///      completed by CapacityIncrementalBatchSC, which owns the exact selected identity set.
    ///      This function therefore refuses BATCH_MODE_INCREMENTAL outright, and every path
    ///      below remains the pre-G.2 full-sweep behaviour.
    function beginProofEpoch(uint64 epochId, uint64 targetRound, uint8 mode)
        external onlyEligibleVK
    {
        // G.2B: the campaign coordinator owns both the batch-mode vocabulary and the
        // proof-authority id namespace. It validates `mode` and confirms that `epochId` lies in
        // the full-epoch domain (bits 63..62 == 00) as part of claiming the campaign below, so
        // this contract carries neither vocabulary nor namespace logic. An unset coordinator
        // needs no explicit guard: Solidity's extcodesize check on the high-level call below
        // reverts before any epoch state is written, and deployment plus the deployment
        // manifest both verify the wiring is present and reciprocal.
        ProofEpoch storage previous = proofEpochs[msg.sender];
        require(!previous.active, "CP: epoch already active");
        require(epochId > previous.epochId, "CP: stale epoch id");
        require(declaredCapacity[msg.sender] > 0, "CP: capacity not declared");
        require(storageProof != address(0), "CP: storage proof unset");
        require(targetRound == IStorageProof_CP(storageProof).currentRound(),
                "CP: epoch not current round");
        require(targetRound >= lastCompletedProofRound[msg.sender],
                "CP: proof round predates epoch");
        uint256 registeredTotal = uint256(registeredCapacityFreeBytes[msg.sender]) +
            uint256(registeredDataUsedBytes[msg.sender]);
        uint64 declared = declaredCapacity[msg.sender];
        // During continuous uploads the last immutable free-capacity snapshot
        // and its data successor coexist until the background builder retires
        // the overlap. Proving that bounded overlap is safe: the allocation
        // ledger still clamps admission, while requiring at least `declared`
        // bytes preserves physical backing and lets epochs progress under load.
        uint256 permittedOverhead = _permittedManifestOverhead(declared);
        require(registeredTotal >= declared,
                "CP: manifest below declared");
        require(registeredTotal <= uint256(declared) + permittedOverhead,
                "CP: manifest overhead too big");
        uint64 registeredBytes = uint64(registeredTotal);
        uint32 expectedPartitions = activePartitionCount[msg.sender];
        require(expectedPartitions > 0, "CP: empty manifest");

        // Claim the single per-VK capacity campaign BEFORE the epoch becomes active. An
        // incremental batch in flight makes this revert, and no epoch state is written.
        ICapacityCampaign_CP(campaignCoordinator).claimFullCampaign(msg.sender, epochId, mode);

        proofEpochs[msg.sender] = ProofEpoch({
            epochId: epochId,
            targetRound: targetRound,
            cutoffNonce: partitionRegistrationNonce[msg.sender],
            expectedPartitions: expectedPartitions,
            provenPartitions: 0,
            expectedBytes: registeredBytes,
            provenBytes: 0,
            provenFreeBytes: 0,
            provenDataBytes: 0,
            allocatedBytesAtCutoff: allocatedStoredBytes[msg.sender],
            invalidated: false,
            active: true
        });
        emit ProofEpochStarted(
            msg.sender,
            epochId,
            targetRound,
            partitionRegistrationNonce[msg.sender],
            expectedPartitions,
            registeredBytes
        );
    }

    /// @notice Abort an epoch whose immutable cutoff can no longer be completed.
    ///         Partial progress never replaces the last completed capacity proof.
    ///         Retrying an already-aborted epoch is intentionally idempotent.
    function abortProofEpoch(uint64 epochId) external onlyEligibleVK {
        _abortProofEpoch(msg.sender, epochId);
    }

    /// @notice When a deletion is declared against a cutoff member, drop that
    ///         member from the active epoch's expectations instead of aborting.
    ///         Remaining sealed cutoff members can still complete the sequence.
    ///         If exclusion would leave the epoch unable to meet declared
    ///         capacity, fall back to a full abort.
    function _excludeCutoffMemberOnDeletion(
        address vk,
        PartitionVersionAccount storage deletingVersion
    ) internal {
        ProofEpoch storage epoch = proofEpochs[vk];
        if (!epoch.active || epoch.invalidated) {
            return;
        }
        bool memberAtCutoff = deletingVersion.registeredNonce != 0 &&
            deletingVersion.registeredNonce <= epoch.cutoffNonce &&
            (deletingVersion.supersededNonce == 0 ||
                deletingVersion.supersededNonce > epoch.cutoffNonce);
        if (!memberAtCutoff) {
            return;
        }
        // Already proved or previously excluded for this epoch: keep progress.
        if (deletingVersion.countedProofEpoch == epoch.epochId) {
            return;
        }
        if (
            epoch.expectedPartitions == 0 ||
            epoch.expectedBytes < deletingVersion.registeredBytes
        ) {
            _abortProofEpoch(vk, epoch.epochId);
            return;
        }
        uint64 nextExpectedBytes = epoch.expectedBytes - deletingVersion.registeredBytes;
        if (nextExpectedBytes < declaredCapacity[vk]) {
            _abortProofEpoch(vk, epoch.epochId);
            return;
        }
        epoch.expectedPartitions -= 1;
        epoch.expectedBytes = nextExpectedBytes;
        deletingVersion.countedProofEpoch = epoch.epochId;
        proofEpochExclusions[vk][epoch.epochId][deletingVersion.partitionKey] =
            ProofEpochExclusion({
                contentVersion: deletingVersion.contentVersion,
                contentHash: deletingVersion.contentHash,
                excludedBytes: deletingVersion.registeredBytes,
                excluded: true
            });
        emit ProofEpochCutoffMemberExcluded(
            vk,
            epoch.epochId,
            deletingVersion.partitionKey,
            deletingVersion.contentVersion,
            deletingVersion.registeredBytes
        );
        _tryCompleteProofEpoch(vk);
    }

    function _abortProofEpoch(address vk, uint64 epochId) internal {
        ProofEpoch storage epoch = proofEpochs[vk];
        require(epoch.epochId == epochId, "CP: epoch mismatch");
        if (!epoch.active) return;
        epoch.invalidated = true;
        epoch.active = false;
        ICapacityCampaign_CP(campaignCoordinator).releaseFullCampaign(vk);
        abortedEpochRound[vk][epochId] = epoch.targetRound;
        emit ProofEpochAborted(vk, epochId, epoch.targetRound);
    }

    /// @notice Shared completion gate used by ordinary version proofs and by
    ///         deletion-time cutoff exclusions.
    function _tryCompleteProofEpoch(address vk) internal returns (uint64 sequence) {
        sequence = capacityProofSequence[vk];
        ProofEpoch storage epoch = proofEpochs[vk];
        if (
            !epoch.active || epoch.invalidated ||
            epoch.provenPartitions != epoch.expectedPartitions ||
            epoch.provenBytes != epoch.expectedBytes ||
            epoch.provenBytes < declaredCapacity[vk]
        ) {
            return sequence;
        }
        epoch.active = false;
        ICapacityCampaign_CP(campaignCoordinator).releaseFullCampaign(vk);
        provedBackingBytes[vk] = declaredCapacity[vk];
        lastCompleteFreeBytes[vk] = epoch.provenFreeBytes;
        lastCompleteDataBytes[vk] = epoch.provenDataBytes;
        lastCompleteAllocatedBytes[vk] = epoch.allocatedBytesAtCutoff;
        lastCapacityProofAt[vk] = uint64(block.timestamp);
        lastCompletedProofRound[vk] = epoch.targetRound;
        sequence += 1;
        capacityProofSequence[vk] = sequence;
        emit ProofEpochCompleted(
            vk,
            epoch.epochId,
            epoch.targetRound,
            sequence,
            declaredCapacity[vk]
        );
    }

    function _countVerifiedVersion(
        PartitionVersionAccount storage versionAccount,
        uint64 proofRound,
        uint64 proofEpochId
    ) internal returns (uint64 sequence) {
        address vk = versionAccount.vk;
        sequence = capacityProofSequence[vk];
        ProofEpoch storage epoch = proofEpochs[vk];
        bool memberAtCutoff = versionAccount.registeredNonce != 0 &&
            versionAccount.registeredNonce <= epoch.cutoffNonce &&
            (versionAccount.supersededNonce == 0 ||
                versionAccount.supersededNonce > epoch.cutoffNonce);
        if (
            !epoch.active || epoch.invalidated || epoch.epochId != proofEpochId ||
            !memberAtCutoff || proofRound != epoch.targetRound ||
            versionAccount.countedProofEpoch == epoch.epochId
        ) return sequence;

        versionAccount.countedProofEpoch = epoch.epochId;
        epoch.provenPartitions += 1;
        epoch.provenBytes += versionAccount.registeredBytes;
        if (versionAccount.kind == PARTITION_KIND_CAPACITY) {
            epoch.provenFreeBytes += versionAccount.registeredBytes;
        } else {
            epoch.provenDataBytes += versionAccount.registeredBytes;
        }
        sequence = _tryCompleteProofEpoch(vk);
    }

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
        )
    {
        ProofEpoch storage epoch = proofEpochs[vk];
        return (
            epoch.epochId,
            epoch.targetRound,
            epoch.cutoffNonce,
            epoch.expectedPartitions,
            epoch.provenPartitions,
            epoch.expectedBytes,
            epoch.active,
            epoch.invalidated
        );
    }

    function isActiveEpochVersion(
        address vk,
        bytes32 partitionKey,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 epochId
    ) external view returns (bool) {
        ProofEpoch storage epoch = proofEpochs[vk];
        if (!epoch.active || epoch.invalidated || epoch.epochId != epochId) return false;
        bytes32 versionKey = keccak256(abi.encodePacked(
            partitionKey, contentVersion, contentHash
        ));
        PartitionVersionAccount storage versionAccount = partitionVersionAccounts[versionKey];
        return versionAccount.vk == vk &&
            versionAccount.partitionKey == partitionKey &&
            versionAccount.countedProofEpoch != epoch.epochId &&
            versionAccount.registeredNonce != 0 &&
            versionAccount.registeredNonce <= epoch.cutoffNonce &&
            (versionAccount.supersededNonce == 0 ||
                versionAccount.supersededNonce > epoch.cutoffNonce);
    }

    function getProofEpochExclusion(
        address vk,
        uint64 epochId,
        bytes32 partitionKey
    ) external view returns (
        bool excluded,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 excludedBytes
    ) {
        ProofEpochExclusion storage exclusion =
            proofEpochExclusions[vk][epochId][partitionKey];
        return (
            exclusion.excluded,
            exclusion.contentVersion,
            exclusion.contentHash,
            exclusion.excludedBytes
        );
    }

    function conservativeFreeCapacity(address vk) public view returns (uint64) {
        uint64 declared = declaredCapacity[vk];
        uint64 allocated = allocatedStoredBytes[vk];
        uint64 quoted = quoteReservedBytes[vk];
        uint256 committed = uint256(quoted) + uint256(allocated);
        if (committed >= declared) return 0;
        uint64 ledgerFree = uint64(uint256(declared) - committed);

        uint64 baselineFree = lastCompleteFreeBytes[vk];
        uint64 baselineAllocated = lastCompleteAllocatedBytes[vk];
        uint64 addedAfterCutoff = allocated > baselineAllocated
            ? allocated - baselineAllocated
            : 0;
        uint256 postCutoffDeductions = uint256(addedAfterCutoff) + uint256(quoted);
        if (postCutoffDeductions >= baselineFree) return 0;
        uint64 proofFree = uint64(uint256(baselineFree) - postCutoffDeductions);
        if (proofFree > declared) proofFree = declared;
        uint64 currentRegisteredFree = registeredCapacityFreeBytes[vk];
        uint64 conservative = proofFree < ledgerFree ? proofFree : ledgerFree;
        return currentRegisteredFree < conservative ? currentRegisteredFree : conservative;
    }

    /// @notice Admissible bytes under the frozen G.5 rule.
    ///
    ///     ledgerFree         = saturating(declaredCapacity - allocatedStoredBytes)
    ///     freshCertifiedFree = min(certifiedFree, ledgerFree)
    ///     safeAllocatable    = saturating(freshCertifiedFree - quoteReservedBytes - margin)
    ///
    /// This is the identical arithmetic the VK evaluates off-chain, so the chain's
    /// final authority and the VK's advertised admission agree exactly.
    ///
    /// PREVIOUS DEFECT (fixed 2026-08-12): admission subtracted the FULL
    /// allocatedStoredBytes from certifiedFree. CapacityCertificationSC accumulates
    /// certifiedFreeBytes and certifiedDataBytes as SEPARATE aggregates, so
    /// certifiedFree already excludes stored data; subtracting it again double-counted
    /// stored bytes and under-admitted by roughly certifiedData. Observed live on
    /// 2026-08-12: declared 4,630,511,616 / certifiedFree 3,690,987,520 /
    /// allocated 1,022,164,992 / margin 104,857,600 yielded 2,563,964,928 instead of
    /// the frozen-rule 3,503,489,024, so a VK could advertise capacity the chain then
    /// refused. Ordinary small stores never reach the boundary, which hid it.
    /// Inlined rather than factored into a helper: CapacityProofSC sits against a hard
    /// 23,000-byte budget (production_contract_size.test.js), and every input is already
    /// readable through the existing public getters declaredCapacity / allocatedStoredBytes /
    /// quoteReservedBytes / certifiedFree / defaultAdmissionMarginBytes, so off-chain callers
    /// can reproduce safeAllocatable exactly without a dedicated view.
    /// @notice Chain-authoritative admission under the FROZEN G.5 rule, identical to the VK:
    ///
    ///     ledgerFree         = saturating(declaredCapacity - allocatedStoredBytes)
    ///     freshCertifiedFree = min(certifiedFree, ledgerFree)
    ///     unreserved         = saturating(freshCertifiedFree - quoteReservedBytes)
    ///     safeAllocatable    = saturating(unreserved - margin)
    ///     admit  <=>  safeAllocatable > 0 && requestedBytes <= unreserved
    ///
    /// The second clause measures against `unreserved`, NOT `safeAllocatable`, because
    /// the margin is a LAST ACCEPTANCE and not a floor. Admission stays open only while
    /// safeAllocatable > 0, and while it is open a request may consume the margin itself;
    /// the store that does so closes admission for everything after it.
    ///
    /// PREVIOUS DEFECT (fixed 2026-10-01): the second clause read `<= safeAllocatable`,
    /// which makes the margin permanently unusable. This claimed to be "identical to the
    /// VK" and was not: the keeper has implemented and tested the last-acceptance rule
    /// since 2026-09-15 (admission_margin_last_acceptance_test.go), so the keeper accepted
    /// and the chain then reverted the reservation with "CP: admission". On a keeper
    /// declaring 200 MiB against a 100 MiB margin that stranded half the disk.
    ///
    /// PREVIOUS DEFECT (fixed 2026-08-12): this subtracted the FULL allocatedStoredBytes from
    /// certifiedFree. CapacityCertificationSC._totals keeps certifiedFreeBytes and
    /// certifiedDataBytes as SEPARATE aggregates, so certifiedFree already excludes stored
    /// data; subtracting it again double-counted stored bytes. Live 2026-08-12: declared
    /// 4,630,511,616 / certifiedFree 3,690,987,520 / allocated 1,022,164,992 / margin
    /// 104,857,600 gave 2,563,964,928 instead of the frozen-rule 3,503,489,024, so the VK
    /// advertised capacity the chain then refused.
    ///
    /// The arithmetic itself lives in CapacityCertificationSC because this contract is at its
    /// hard 23,000-byte budget; reserveQuote calls this function, so there remains exactly one
    /// admission calculation on chain.
    function isAdmissionOpen(address vk, uint64 requestedBytes) public view returns (bool) {
        IVaultKeeperRegistry_CP registry = IVaultKeeperRegistry_CP(vaultKeeperRegistry);
        if (!registry.isEligibleVaultKeeper(vk)) return false;
        uint64 margin = registry.defaultAdmissionMarginBytes();
        uint64 safeAllocatable = ICapacityCertification_CP(certificationContract)
            .safeAllocatableBytes(
                vk,
                declaredCapacity[vk],
                allocatedStoredBytes[vk],
                quoteReservedBytes[vk],
                margin
            );
        // The margin decides whether admission is open at all.
        if (safeAllocatable == 0) return false;
        // Whether the request FITS is measured against the unreserved bytes,
        // because the margin is a last acceptance and not a floor. Reached only
        // when safeAllocatable > 0, and safeAllocatableBytes clamps to zero rather
        // than going negative, so nothing was clamped and
        // safeAllocatable + margin is exactly the unreserved total. That keeps
        // one admission calculation on chain, which the byte budget requires.
        return requestedBytes <= safeAllocatable + margin;
    }

    function getQuoteReservation(bytes32 registrationCommitment)
        external view returns (
            address vk,
            uint64 reservedBytes,
            uint64 expiresAt,
            uint8 state
        )
    {
        QuoteReservation storage reservation = quoteReservations[registrationCommitment];
        return (
            reservation.vk,
            reservation.reservedBytes,
            reservation.expiresAt,
            reservation.state
        );
    }

    function getPartitionAccount(bytes32 partitionKey)
        external view returns (PartitionAccount memory)
    {
        return partitionAccounts[partitionKey];
    }

    function getPartitionVersionAccount(
        bytes32 partitionKey,
        uint64 contentVersion,
        bytes32 contentHash
    ) external view returns (PartitionVersionAccount memory) {
        return partitionVersionAccounts[keccak256(abi.encodePacked(
            partitionKey, contentVersion, contentHash
        ))];
    }

    function capacityAccountingOf(address vk) external view returns (
        uint64 declaredBytes,
        uint64 registeredFree,
        uint64 registeredData,
        uint64 provedFree,
        uint64 provedData,
        uint64 quoteReserved,
        uint64 allocatedStored,
        uint64 conservativeFree,
        uint64 latestCapacityProofAt,
        bool proofFresh
    ) {
        declaredBytes = declaredCapacity[vk];
        registeredFree = registeredCapacityFreeBytes[vk];
        registeredData = registeredDataUsedBytes[vk];
        provedFree = provedCapacityFreeBytes[vk];
        provedData = provedDataUsedBytes[vk];
        quoteReserved = quoteReservedBytes[vk];
        allocatedStored = allocatedStoredBytes[vk];
        conservativeFree = conservativeFreeCapacity(vk);
        latestCapacityProofAt = lastCapacityProofAt[vk];
        proofFresh = latestCapacityProofAt != 0 &&
            block.timestamp <= uint256(latestCapacityProofAt) + maxProofAgeSeconds;
    }

    /// @notice The last atomically completed full-manifest proof checkpoint.
    /// Current per-partition proof counters intentionally fall to zero when a
    /// live version changes; these checkpoint values do not. Consumers such as
    /// Explorer can therefore distinguish a durable historical backing
    /// checkpoint from exact-current proof progress and from live registration.
    function capacityCheckpointOf(address vk) external view returns (
        uint64 checkpointFree,
        uint64 checkpointData,
        uint64 allocatedAtCheckpoint,
        uint64 backedBytes,
        uint64 proofSequence,
        uint64 proofRound,
        uint64 proofAt,
        bool proofFresh
    ) {
        checkpointFree = lastCompleteFreeBytes[vk];
        checkpointData = lastCompleteDataBytes[vk];
        allocatedAtCheckpoint = lastCompleteAllocatedBytes[vk];
        backedBytes = provedBackingBytes[vk];
        proofSequence = capacityProofSequence[vk];
        proofRound = lastCompletedProofRound[vk];
        proofAt = lastCapacityProofAt[vk];
        proofFresh = proofAt != 0 &&
            block.timestamp <= uint256(proofAt) + maxProofAgeSeconds;
    }

    function _setReservationState(
        bytes32 registrationCommitment,
        QuoteReservation storage reservation,
        uint8 newState
    ) internal {
        uint8 oldState = reservation.state;
        reservation.state = newState;
        emit QuoteReservationStateChanged(
            registrationCommitment,
            reservation.vk,
            oldState,
            newState,
            reservation.reservedBytes
        );
    }

    function _permittedManifestOverhead(uint64 declared) internal view returns (uint256) {
        uint256 permitted = maxManifestOverheadBytes;
        if (permitted > declared) permitted = declared;
        uint256 representable = uint256(type(uint64).max) - uint256(declared);
        return permitted < representable ? permitted : representable;
    }

    function _capacityBacking(PartitionAccount storage account) internal view returns (uint64) {
        if (!account.active || account.kind != PARTITION_KIND_CAPACITY) return 0;
        return account.provedBytes < account.registeredBytes
            ? account.provedBytes
            : account.registeredBytes;
    }

    function _addRegistered(address vk, uint8 kind, uint64 amount, bool active) internal {
        if (!active || amount == 0) return;
        if (kind == PARTITION_KIND_CAPACITY) registeredCapacityFreeBytes[vk] += amount;
        else registeredDataUsedBytes[vk] += amount;
    }

    function _subtractRegistered(address vk, uint8 kind, uint64 amount, bool active) internal {
        if (!active || amount == 0) return;
        if (kind == PARTITION_KIND_CAPACITY) {
            registeredCapacityFreeBytes[vk] -= amount;
        } else {
            registeredDataUsedBytes[vk] -= amount;
        }
    }

    function _subtractCapacityBacking(address vk, uint64 amount) internal {
        if (amount == 0) return;
        provedCapacityFreeBytes[vk] -= amount;
    }

    function _subtractDataProof(address vk, uint64 amount) internal {
        if (amount == 0) return;
        provedDataUsedBytes[vk] -= amount;
    }
}
