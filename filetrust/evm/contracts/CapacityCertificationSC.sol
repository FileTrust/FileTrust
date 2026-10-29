// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: CapacityCertificationSC
// Purpose:  How long a proven partition still counts as proven, held in a ring of
//           expiry slots that is read at a fixed cost however much is stored.
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

/// @notice The reciprocal edge this contract verifies before accepting its authority.
interface ICapacityProofBinding_CC {
    function certificationContract() external view returns (address);
}

/// @notice CapacityProofSC's running totals of a keeper's proven space.
interface ICapacityProofTotals_CC {
    function provedCapacityFreeBytes(address vk) external view returns (uint64);
    function provedDataUsedBytes(address vk) external view returns (uint64);
}

/// @notice The one RewardManager entry this contract calls.
interface IRewardManager_CC {
    function creditVKCapacity(address vk, uint256 provenBytes) external;
}

/// @title CapacityCertificationSC
/// @notice Sole owner of rolling per-partition capacity certification and its aggregate
///         freshness totals (Track G, tagged expiry-slot ring).
///
/// Extracted from CapacityProofSC in G.1A. The certification semantics frozen in G.0/G.1
/// are unchanged; only their storage location and authority boundary moved.
///
/// Division of authority — this contract owns:
///   * per-partition certification records and their certified identity,
///   * the expiry-slot ring and its bucket totals,
///   * freshness evaluation and the aggregate certified free/data views.
///
/// CapacityProofSC remains the authority for registered partition identity, accepted-current
/// proof decisions, historical proof accounting, capacity epochs and epoch completion.
///
/// Ring model. A certificate is filed into the bucket for the ABSOLUTE slot at which it
/// expires, and that absolute slot is stored in the bucket as a generation tag. A bucket
/// contributes to the aggregate only while its tag is strictly ahead of the current slot, so
/// expiry costs no transaction, and a recycled ring index is always distinguishable from the
/// older generation that previously occupied it.
///
/// Error direction is one-sided. `expirySlot = floor((t + age) / slotSeconds)` places the
/// effective expiry at or before the true expiry and never more than one slot early: the ring
/// may under-count, never over-count.
///
/// G.1A scope: SHADOW ACCOUNTING. Nothing here gates upload admission, batching triggers,
/// epoch membership, proof scheduling or deletion release. Those are G.2–G.6.
contract CapacityCertificationSC {
    uint8 public constant PARTITION_KIND_DATA = 1;
    uint8 public constant PARTITION_KIND_CAPACITY = 2;

    /// @notice Bound on ring geometry so the aggregate views stay cheaply bounded. At the
    ///         30 h certification age a deadlineCount up to 192 (slotSeconds 450) still fits,
    ///         and the D.1 configuration (slotSeconds 1800) needs 62.
    uint16 public constant MAX_CERTIFICATION_RING_SIZE = 256;

    /// @notice Gas reserved for paying a capacity reward inside a certification.
    uint256 public constant CAPACITY_REWARD_GAS = 80_000;

    error NotCapacityProof();
    error AlreadyBound();
    error NotOwner();
    error InvalidAuthority();
    error ReciprocalWiringMismatch();
    error CertificationCountUnderflow();
    error CertificationGenerationLive();
    error InactiveIdentity();
    error BadPartitionKind();
    error ZeroVaultKeeper();
    error InsufficientGasForReward();

    /// @notice One rolling certificate per partition key.
    /// @dev `certifiedExpirySlot` is an ABSOLUTE slot, not a ring index; 0 means never
    ///      certified. `vk` is retained so a withdrawal always addresses the bucket that
    ///      actually holds the contribution, independent of any later caller argument.
    struct PartitionCertification {
        address vk;
        uint64 provedAt;
        uint64 certifiedExpirySlot;
        uint64 certifiedBytes;
        uint8 certifiedKind;
        bytes32 certifiedIdentityHash;
    }

    /// @notice One ring generation. `expirySlot` is the absolute-slot generation tag.
    struct CertificationBucket {
        uint64 expirySlot;
        uint64 certifiedFreeBytes;
        uint64 certifiedDataBytes;
        uint32 partitionCount;
    }

    /// @notice Deployer. May perform the one-time authority binding and nothing else.
    address public immutable owner;

    /// @notice The only address permitted to certify or invalidate. Set exactly once by
    ///         `bindCapacityProof` and never replaceable.
    address public capacityProofSC;

    /// @notice RewardManager that pays keepers for proven space. Bound once by the deployer,
    ///         like the capacity-proof authority, and never replaceable; zero means no
    ///         capacity reward. The amounts live in RewardManager and stay adjustable there.
    address public rewardManager;

    /// @notice Ring geometry. Immutable for the lifetime of the deployment: a resize would
    ///         reinterpret every stored generation tag and is a migration event, not an
    ///         administrative action.
    uint64 public immutable slotSeconds;
    uint16 public immutable ringSize;
    uint64 public immutable certificationMaxProofAgeSeconds;

    mapping(bytes32 => PartitionCertification) public partitionCertifications;
    mapping(address => mapping(uint16 => CertificationBucket)) public certificationBuckets;

    event CapacityProofBound(address indexed capacityProof);
    event RewardManagerBound(address indexed rewardManager);
    event PartitionCertified(
        bytes32 indexed partitionKey,
        address indexed vk,
        uint8 kind,
        uint64 certifiedBytes,
        uint64 expirySlot,
        bytes32 identityHash
    );
    event PartitionCertificationInvalidated(bytes32 indexed partitionKey, address indexed vk);

    constructor(
        uint64 slotSeconds_,
        uint16 ringSize_,
        uint64 certificationMaxProofAgeSeconds_
    ) {
        require(slotSeconds_ > 0, "CapacityCertification: zero slotSeconds");
        require(certificationMaxProofAgeSeconds_ > 0, "CapacityCertification: zero certification age");
        require(ringSize_ <= MAX_CERTIFICATION_RING_SIZE, "CapacityCertification: ring too large");
        uint256 minimumRing =
            (uint256(certificationMaxProofAgeSeconds_) + uint256(slotSeconds_) - 1)
            / uint256(slotSeconds_) + 2;
        require(uint256(ringSize_) >= minimumRing, "CapacityCertification: ring too small");
        owner = msg.sender;
        slotSeconds = slotSeconds_;
        ringSize = ringSize_;
        certificationMaxProofAgeSeconds = certificationMaxProofAgeSeconds_;
    }

    // ─── authority ─────────────────────────────────────────────────────────────────────

    /// @notice One-time, irreversible binding of the sole certification authority.
    /// @dev Rejects the zero address, an address with no code, a second call, and any
    ///      candidate that does not already point back at this contract. After this
    ///      returns there is no path — administrative or otherwise — to replace the
    ///      authority or alter ring geometry.
    function bindCapacityProof(address capacityProof) external {
        if (msg.sender != owner) revert NotOwner();
        if (capacityProofSC != address(0)) revert AlreadyBound();
        if (capacityProof == address(0) || capacityProof.code.length == 0) revert InvalidAuthority();
        if (ICapacityProofBinding_CC(capacityProof).certificationContract() != address(this)) {
            revert ReciprocalWiringMismatch();
        }
        capacityProofSC = capacityProof;
        emit CapacityProofBound(capacityProof);
    }

    /// @notice One-time binding of the RewardManager that pays for proven space.
    function bindRewardManager(address rewardManager_) external {
        if (msg.sender != owner) revert NotOwner();
        if (rewardManager != address(0)) revert AlreadyBound();
        if (rewardManager_ == address(0) || rewardManager_.code.length == 0) revert InvalidAuthority();
        rewardManager = rewardManager_;
        emit RewardManagerBound(rewardManager_);
    }

    modifier onlyCapacityProof() {
        if (msg.sender != capacityProofSC || capacityProofSC == address(0)) revert NotCapacityProof();
        _;
    }

    // ─── identity ──────────────────────────────────────────────────────────────────────

    /// @notice Canonical binding of everything that makes a certificate valid for exactly
    ///         one registered identity. `abi.encode` (not `encodePacked`) so no two distinct
    ///         field tuples can collide.
    function certificationIdentityHash(
        bytes32 partitionKey,
        uint8 kind,
        bool active,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) public pure returns (bytes32) {
        return keccak256(
            abi.encode(partitionKey, kind, active, contentVersion, contentHash, committedBytes)
        );
    }

    // ─── transitions ───────────────────────────────────────────────────────────────────

    /// @notice Certify a partition's exact current identity. Only the bound CapacityProofSC
    ///         may call this, and only for an active identity.
    function certifyPartition(
        address vk,
        bytes32 partitionKey,
        uint8 kind,
        bool active,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external onlyCapacityProof {
        if (!active) revert InactiveIdentity();
        if (kind != PARTITION_KIND_CAPACITY && kind != PARTITION_KIND_DATA) revert BadPartitionKind();
        if (vk == address(0)) revert ZeroVaultKeeper();

        PartitionCertification storage record = partitionCertifications[partitionKey];
        uint64 currentSlot = _currentSlot();

        // 1. withdraw the previous contribution FIRST, including when the refresh lands in
        //    the same expiry slot — replacement, never accumulation.
        _withdraw(record);

        // 2. open or reuse the target generation
        uint64 newSlot = uint64(
            (block.timestamp + uint256(certificationMaxProofAgeSeconds)) / uint256(slotSeconds)
        );
        CertificationBucket storage bucket = _bucket(vk, newSlot);
        if (bucket.expirySlot != newSlot) {
            if (bucket.expirySlot > currentSlot) revert CertificationGenerationLive();
            bucket.certifiedFreeBytes = 0;
            bucket.certifiedDataBytes = 0;
            bucket.partitionCount = 0;
            bucket.expirySlot = newSlot;
        }

        // 3. add
        if (kind == PARTITION_KIND_CAPACITY) bucket.certifiedFreeBytes += committedBytes;
        else bucket.certifiedDataBytes += committedBytes;
        bucket.partitionCount += 1;

        bytes32 identityHash = certificationIdentityHash(
            partitionKey, kind, active, contentVersion, contentHash, committedBytes
        );
        record.vk = vk;
        record.provedAt = uint64(block.timestamp);
        record.certifiedExpirySlot = newSlot;
        record.certifiedBytes = committedBytes;
        record.certifiedKind = kind;
        record.certifiedIdentityHash = identityHash;

        emit PartitionCertified(partitionKey, vk, kind, committedBytes, newSlot, identityHash);
        _creditProvenSpace(vk);
    }

    /// @dev Pays the keeper for its proven space through RewardManager.creditVKCapacity,
    ///      inside the proof transaction the keeper already sends. The space is read from
    ///      CapacityProofSC's running totals -- two storage reads, already updated for this
    ///      proof -- not summed over the ring, which would cost a read per ring bucket on
    ///      every proof. The reward call gets a fixed gas budget that is checked first: a
    ///      reward swallowed by the catch when gas runs short would let a sender's gas
    ///      estimate settle just below it and skip it forever. The catch only absorbs a
    ///      reward that genuinely fails, so a reward can never block a certification.
    function _creditProvenSpace(address vk) private {
        address rm = rewardManager;
        if (rm == address(0)) return;
        ICapacityProofTotals_CC proof = ICapacityProofTotals_CC(capacityProofSC);
        uint256 proven = uint256(proof.provedCapacityFreeBytes(vk)) + uint256(proof.provedDataUsedBytes(vk));
        if (gasleft() < CAPACITY_REWARD_GAS + 10_000) revert InsufficientGasForReward();
        try IRewardManager_CC(rm).creditVKCapacity{gas: CAPACITY_REWARD_GAS}(vk, proven) {} catch {}
    }

    /// @notice Drop a partition's certification on a genuine identity change or deactivation.
    /// @dev The subtraction uses this contract's OWN stored record — old vk, old kind, old
    ///      bytes, old expiry slot — never a caller-supplied value, so a caller cannot
    ///      withdraw an amount the ring never received.
    function invalidatePartition(bytes32 partitionKey) external onlyCapacityProof {
        PartitionCertification storage record = partitionCertifications[partitionKey];
        if (record.certifiedExpirySlot == 0) return;    // never certified — nothing to undo
        address vk = record.vk;
        _withdraw(record);
        record.provedAt = 0;
        record.certifiedExpirySlot = 0;
        record.certifiedBytes = 0;
        record.certifiedKind = 0;
        record.certifiedIdentityHash = bytes32(0);
        emit PartitionCertificationInvalidated(partitionKey, vk);
    }

    /// @dev Withdraw a record's live contribution from the generation that actually holds it.
    ///      The tag equality check is what prevents a stale record from subtracting bytes
    ///      belonging to a later reuse of the same ring index.
    function _withdraw(PartitionCertification storage record) internal {
        uint64 oldSlot = record.certifiedExpirySlot;
        if (oldSlot == 0) return;                                   // never certified
        CertificationBucket storage bucket = _bucket(record.vk, oldSlot);
        if (bucket.expirySlot != oldSlot) return;                   // generation superseded
        if (record.certifiedKind == PARTITION_KIND_CAPACITY) {
            bucket.certifiedFreeBytes -= record.certifiedBytes;
        } else {
            bucket.certifiedDataBytes -= record.certifiedBytes;
        }
        if (bucket.partitionCount == 0) revert CertificationCountUnderflow();
        bucket.partitionCount -= 1;
    }

    function _bucket(address vk, uint64 absoluteSlot)
        internal view returns (CertificationBucket storage)
    {
        return certificationBuckets[vk][uint16(absoluteSlot % uint64(ringSize))];
    }

    function _currentSlot() internal view returns (uint64) {
        return uint64(block.timestamp / slotSeconds);
    }

    // ─── views ─────────────────────────────────────────────────────────────────────────

    /// @notice Current absolute certification slot.
    function currentCertificationSlot() external view returns (uint64) {
        return _currentSlot();
    }

    /// @dev One bounded sweep. O(ringSize), never O(partition count).
    function _totals(address vk) internal view returns (uint64 freeBytes, uint64 dataBytes) {
        uint64 currentSlot = _currentSlot();
        uint16 size = ringSize;
        for (uint16 i = 0; i < size; i++) {
            CertificationBucket storage bucket = certificationBuckets[vk][i];
            if (bucket.expirySlot > currentSlot) {
                freeBytes += bucket.certifiedFreeBytes;
                dataBytes += bucket.certifiedDataBytes;
            }
        }
    }

    /// @notice Fresh certified FREE capacity for a VK.
    function certifiedFree(address vk) external view returns (uint64) {
        (uint64 freeBytes, ) = _totals(vk);
        return freeBytes;
    }

    /// @notice Fresh certified DATA bytes for a VK.
    function certifiedData(address vk) external view returns (uint64) {
        (, uint64 dataBytes) = _totals(vk);
        return dataBytes;
    }

    /// @notice Both aggregates in one sweep.
    function certifiedTotals(address vk) external view returns (uint64 freeBytes, uint64 dataBytes) {
        return _totals(vk);
    }

    /// @notice The frozen G.5 admissible byte count:
    ///
    ///     ledgerFree         = saturating(declared - allocated)
    ///     freshCertifiedFree = min(certifiedFree, ledgerFree)
    ///     safeAllocatable    = saturating(freshCertifiedFree - reserved - margin)
    ///
    /// The ledger inputs belong to CapacityProofSC and are passed in; the certified free
    /// aggregate is owned here. This arithmetic lives in the certification contract because
    /// CapacityProofSC sits against a hard 23,000-byte budget with only three bytes spare,
    /// so the corrected rule could not be expressed inline there — the same "move code out"
    /// remedy G.1A applied. CapacityProofSC.isAdmissionOpen is the only caller, so the chain
    /// keeps exactly one admission calculation.
    ///
    /// NOTE: `certifiedFree` deliberately does NOT have `allocated` subtracted from it here.
    /// _totals accumulates certifiedFreeBytes and certifiedDataBytes as separate aggregates,
    /// so certified free already excludes stored data; subtracting it again double-counts.
    /// That double-count was the 2026-08-12 admission defect.
    function safeAllocatableBytes(
        address vk,
        uint64 declared,
        uint64 allocated,
        uint64 reserved,
        uint64 margin
    ) external view returns (uint64) {
        (uint64 certifiedFreeBytes, ) = _totals(vk);
        uint256 free = certifiedFreeBytes;
        uint256 ledgerFree = allocated >= declared ? 0 : uint256(declared) - allocated;
        if (ledgerFree < free) free = ledgerFree;
        uint256 deductions = uint256(reserved) + margin;
        if (deductions >= free) return 0;
        return uint64(free - deductions);
    }

    /// @notice Whether a partition currently holds an unexpired certificate.
    function isCertificationFresh(bytes32 partitionKey) public view returns (bool) {
        return partitionCertifications[partitionKey].certifiedExpirySlot > _currentSlot();
    }

    /// @notice Whether a partition's certificate is both fresh AND bound to `identityHash`.
    ///         This is the `certifiedCurrent` predicate frozen in G.0.
    function isCertifiedCurrent(bytes32 partitionKey, bytes32 identityHash)
        external view returns (bool)
    {
        PartitionCertification storage record = partitionCertifications[partitionKey];
        return record.certifiedExpirySlot > _currentSlot()
            && record.certifiedIdentityHash == identityHash;
    }
}
