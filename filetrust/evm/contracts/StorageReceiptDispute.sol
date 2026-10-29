// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: StorageReceiptDispute
// Purpose:  A Data Owner's complaint that a Vault Keeper broke its storage promise,
//           decided on evidence the Keeper itself signed.
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

import "./StorageProofSC.sol";

/// @dev Minimal interface — StorageReceiptDispute only needs slash, slashTo, stakeOf, minStake.
interface IStakingManager_W6 {
    function slash(address guardian, uint256 amount) external;
    /// @dev slashTo sends slashed stake directly to recipient instead of treasury.
    ///      Used to compensate DO for transaction costs on successful dispute.
    function slashTo(address guardian, uint256 amount, address recipient) external;
    function stakeOf(address guardian) external view returns (uint256);
    function minStake() external view returns (uint256);
}

/// @dev VKEscrow interface used by StorageReceiptDispute to refund DO on successful dispute.
interface IVKEscrow_Dispute {
    function refundDisputed(bytes32 paymentCommitment) external;
    function registrationDeadlineOf(bytes32 paymentCommitment) external view returns (uint64);
    function escrowStatus(bytes32 paymentCommitment)
        external
        view
        returns (
            uint256 totalAmount,
            uint64  serviceStart,
            uint64  serviceEnd,
            bytes32 sizeCommitment,
            bytes32 linkCommitment,
            uint256 claimedAmount,
            uint256 claimableNow,
            address depositor
        );
}

/// @dev ReputationManager records storage-dispute penalties under a dedicated VK function.
interface IReputationManager_W6 {
    function recordVKDisputePenalty(
        address vk,
        uint32  repPenalty,
        uint8   violationLevel
    ) external;
}

/// @dev VaultKeeperRegistry must support enforcer-initiated suspension and deactivation.
interface IVaultKeeperRegistry_W6 {
    function isRegisteredVaultKeeper(address vk) external view returns (bool);
    function suspendVaultKeeper(address vkAddress, uint64 until) external;
    function deactivateVaultKeeper(address vkAddress) external;
    function admissionClosed(address vkAddress) external view returns (bool);
    function isAdmissionOpen(address vkAddress) external view returns (bool);
    function wasAdmissionOpenAt(address vkAddress, uint64 timestamp) external view returns (bool);
}

/// @dev W7+W8: FileRegistrationSC interface used by the dispute contract.
interface IFileRegistrationSC_W7 {
    /// @dev W7: confirms a DO-acknowledged sector migration for old (vk, sectorRoot, DL, PI).
    function migrationDeclared(bytes32 migKey) external view returns (bool);
    /// @dev W8: returns how many commitmentHashes were registered under a given sectorRoot.
    ///      Used to populate SectorRiskNotice without emitting unbounded arrays.
    function sectorCommitmentCount(bytes32 sectorRoot) external view returns (uint256);
}

/// @dev Extends W7 interface with deletion-facility queries used for:
///      (a) rejecting storage-failure disputes on DO-confirmed-deleted files, and
///      (b) evaluating deletion-failure disputes submitted by DOs.
interface IFileRegistrationSC_Deletions is IFileRegistrationSC_W7 {
    function registrationCommitmentExists(bytes32 registrationCommitment) external view returns (bool);
    function isDeletionConfirmed(bytes32 commitmentHash) external view returns (bool);
    function isDeletionDeclared(bytes32 commitmentHash) external view returns (bool);
    function getDeletionRecord(bytes32 commitmentHash)
        external view returns (uint64 declaredAt, uint64 graceSeconds, bool confirmed);
    function getFileRecordForDeletion(bytes32 commitmentHash)
        external view returns (address vk, uint8 deadlineIndex, uint8 partitionIndex, bytes32 zkPieceCommitment);
    function fileRecords(bytes32 commitmentHash)
        external view
        returns (
            bytes32 sectorRoot,
            bytes32 zkPieceCommitment,
            address vkAddress,
            uint8   deadlineIndex,
            uint8   partitionIndex,
            uint64  serviceEnd,
            uint64  registeredAt,
            bool    partitionLinked,
            bytes32 deletionAuthHash
        );
    function isDeletionAuthorized(bytes32 commitmentHash) external view returns (bool);
    function registrationCommitmentToCommitmentHash(bytes32 registrationCommitment)
        external view returns (bytes32);
    function capacityProof() external view returns (address);
}

/// @dev CapacityProofSC keeps the VaultKeeper that reserved a registration commitment in
///      every reservation state.
interface ICapacityProof_Dispute {
    function getQuoteReservation(bytes32 registrationCommitment)
        external view returns (address vk, uint64 reservedBytes, uint64 expiresAt, uint8 state);
}

/// @title StorageReceiptDispute — W6 enforcement
/// @notice Allows a Data Owner (DO) to dispute a VK's broken storage promise.
///         When a dispute is determined valid, automatic penalties are applied
///         on-chain without requiring any further action from the DO.
///
/// Normal operation
/// ----------------
/// After a successful store the VK signs a PrivateReceiptV1 and returns it to DO
/// off-chain.  The receipt is never published on-chain.  DO stores it locally.
///
/// Dispute path
/// ------------
/// If the VK never proves the promised partition (or the partition is gone/inactive),
/// DO calls submitDispute() with the receipt fields and VK signature.  The contract:
///   1. Verifies the VK's signature over the receipt digest.
///   2. Checks on-chain partition proof status.
///   3. If invalid: records DisputeInvalid, no action.
///   4. If valid:   records DisputeValid and immediately:
///        a. Slashes stake (StakingManager)
///        b. Reduces reputation (ReputationManager)
///        c. Suspends or permanently removes VK (VaultKeeperRegistry)
///        d. Auto-deactivates VK if stake falls below minimum
///
/// Only a registered VK's receipt can be disputed, only until the service end it promised
/// (or the later one its registration was extended to), and only for a file that VK
/// registered, named by DO's commitment nonce, or for a sector nothing was ever registered
/// under. A deletion DO authorized, or one confirmed, makes the dispute Invalid.
///
/// A valid dispute moves no escrow: VKEscrow refunds any escrow it is told to, and nothing
/// in a receipt shows which escrow paid for it. settleDisputedEscrow refunds the escrow, and
/// pays DO's compensation, once the escrow's link commitment is opened to the registration
/// of the disputed file; the money goes to the escrow's depositor, whoever calls. Without
/// that link, DO's escrow stays where it is: the VK cannot claim it without a current proof
/// at service end, and DO reclaims it after the grace period.
///
/// Violation levels (cumulative valid dispute count):
///   0 = Warning   (offense 1)        slash 0.5%  rep -50
///   1 = Minor     (offense 2–3)      slash 1%    rep -100
///   2 = Major     (offense 4–5)      slash 5%    rep -200   temp 72 h
///   3 = Malicious (offense 6+)       slash 25%   rep -500   permanent removal
///
/// Anti-abuse
/// ----------
/// Each receipt has a unique (vk, receiptNonce, pieceRoot) — disputes are
/// deduplicated by receipt, so a DO can file at most one dispute per receipt.
/// A fabricated receipt requires a valid VK signature (ecrecover-verified).
///
/// Privacy
/// -------
/// The receipt does not include DO address, fileId, CID, or policyId.
/// Only during a dispute does the receipt become public on-chain.
///
/// Signature format (must match receipt.go)
/// -----------------------------------------
/// digest  = keccak256(abi.encodePacked(all receipt fields except vkSignature))
/// ethHash = keccak256("\x19Ethereum Signed Message:\n32" ++ digest)
/// sig     = secp256k1_sign(ethHash, vkPrivKey)   v ∈ {27, 28}
///
/// Packing order (matches receipt.go packReceiptForHashing):
///   uint16  receiptVersion
///   bytes32 receiptNonce
///   address vkAddress
///   bytes32 pieceRoot
///   uint64  pieceSize
///   bytes32 keccak256(sectorId)
///   bytes32 sectorRoot
///   uint8   deadlineIndex
///   uint8   partitionIndex
///   bytes32 partitionRoot
///   uint64  serviceEnd
///   uint64  timestamp
///   uint64  chainId
///   address storageProofContract
contract StorageReceiptDispute {

    error Unauthorized();
    error ZeroAddress();
    error InvalidParameters();
    error InvalidReceipt();
    error InvalidSignature();
    error DuplicateDispute();
    error ContractNotConfigured();
    error InvalidDeletionState();
    error GracePeriodActive();
    error UnknownVaultKeeper();
    error ServiceEnded();
    error RegistrationNotProven();
    error InvalidEscrowLink();
    error NotSettleable();

    StorageProofSC public immutable storageProof;

    // ─── Enforcement contracts (optional — enforcement skipped if unset) ───────
    IStakingManager_W6      public stakingManager;
    IReputationManager_W6   public reputationManager;
    IVaultKeeperRegistry_W6 public vkRegistry;
    /// @dev W7 + deletion: if set, used to distinguish legitimate migrations from silent
    ///      evictions (W7) and to evaluate deletion-facility disputes.
    IFileRegistrationSC_Deletions public fileRegistration;
    /// @dev VKEscrow: refundDisputed() is called by settleDisputedEscrow, for the escrow
    ///      proven to pay for the file of a valid dispute.
    IVKEscrow_Dispute        public vkEscrow;

    // ─── DO compensation parameters ───────────────────────────────────────────
    // When a valid dispute's escrow is settled, its depositor is compensated from VK stake
    // via slashTo(vk, doCompensationBps * minStake / 10000, depositor).
    // This is in ADDITION to the regular slash (which still goes to treasury).
    uint256 public doCompensationBps = 10; // 0.1% of minStake by default

    // ─── Deletion-dispute state ───────────────────────────────────────────────
    /// @notice Per-VK count of valid deletion-failure disputes (tracked separately from
    ///         storage-failure disputes so each violation type can be assessed independently).
    mapping(address => uint32) public validDeletionDisputeCount;

    /// @dev Deduplication: true once a deletion-failure dispute has been filed for
    ///      a given (vk, commitmentHash) pair. Prevents DO from re-filing the same dispute.
    mapping(bytes32 => bool) public deletionDisputeFiled;

    // ─── Admission-failure dispute state ────────────────────────────────────────
    /// @notice Per-VK count of valid admission-failure disputes (false-capacity claims).
    mapping(address => uint32) public validAdmissionDisputeCount;
    /// @dev Deduplication for (vk, paymentCommitment) admission disputes.
    mapping(bytes32 => bool) public admissionDisputeFiled;
    /// @dev Authorized off-chain reporters (Guardian-style submitters).
    mapping(address => bool) public authorizedDisputeReporters;

    // ─── Admission penalty parameters (lighter than storage-failure penalties) ─
    uint256 public admSlashBps_warning = 50;    // 0.50% of minStake
    uint256 public admSlashBps_minor   = 100;   // 1.00% of minStake
    uint32  public admRepPenalty_warning = 50;
    uint32  public admRepPenalty_minor   = 100;
    uint32  public admOffenseThreshold_minor = 3;

    // ─── Deletion penalty parameters (lighter than storage-failure penalties) ─
    uint256 public delSlashBps_warning = 25;   // 0.25% of minStake
    uint256 public delSlashBps_minor   = 50;   // 0.50% of minStake
    uint32  public delRepPenalty_warning = 25;
    uint32  public delRepPenalty_minor   = 50;
    // Threshold for escalation from warning to minor on deletion disputes:
    uint32  public delOffenseThreshold_minor = 3;

    // ─── Owner ────────────────────────────────────────────────────────────────
    address public owner;

    // ─── Violation level constants ────────────────────────────────────────────
    uint8 public constant VIOLATION_WARNING   = 0;
    uint8 public constant VIOLATION_MINOR     = 1;
    uint8 public constant VIOLATION_MAJOR     = 2;
    uint8 public constant VIOLATION_MALICIOUS = 3;

    // ─── Violation thresholds ─────────────────────────────────────────────────
    // Offense count at which each level is applied.
    uint32 public offenseThreshold_minor     = 2;
    uint32 public offenseThreshold_major     = 4;
    uint32 public offenseThreshold_malicious = 6;

    // ─── Stake slash parameters (basis points of minStake) ───────────────────
    uint256 public slashBps_warning   =   50;   // 0.5%
    uint256 public slashBps_minor     =  100;   // 1%
    uint256 public slashBps_major     =  500;   // 5%
    uint256 public slashBps_malicious = 2500;   // 25%

    // ─── Reputation penalty (points deducted) ────────────────────────────────
    uint32 public repPenalty_warning   =   50;
    uint32 public repPenalty_minor     =  100;
    uint32 public repPenalty_major     =  200;
    uint32 public repPenalty_malicious =  500;

    // ─── Suspension duration for MAJOR violations ─────────────────────────────
    uint64 public suspensionSeconds_major = 72 hours;

    // ─── W10: proof-lapse staleness threshold ────────────────────────────────
    // A "never lapsed" dispute is valid when currentRound() > lastProofRound + stalenessThreshold.
    // Default 2: VK may miss at most 1 full proof period before becoming disputable.
    uint64 public stalenessThreshold = 2;

    // ─── Per-VK enforcement state ─────────────────────────────────────────────
    /// @notice Total number of valid disputes confirmed against this VK.
    mapping(address => uint32) public validDisputeCount;
    /// @notice Timestamp of most recent valid dispute against this VK.
    mapping(address => uint64) public lastValidDisputeAt;
    /// @notice For MAJOR violations: suspended until this timestamp (0 = not suspended).
    mapping(address => uint64) public suspendedUntil;
    /// @notice True when VK has been permanently removed (MALICIOUS or stake exhaustion).
    mapping(address => bool)   public permanentlySuspended;

    // ─── Dispute state ────────────────────────────────────────────────────────
    enum DisputeStatus { Pending, Valid, Invalid }

    struct DisputeRecord {
        address       vk;
        bytes32       sectorRoot;
        uint8         deadlineIndex;
        uint8         partitionIndex;
        bytes32       partitionRoot;
        uint64        serviceEnd;
        uint64        submittedAt;
        DisputeStatus status;
        string        reason;
        // Escrow integration: zero until settleDisputedEscrow refunds the file's escrow.
        bytes32       paymentCommitment; // the settled VKEscrow deposit commitment
        address       doAddress;         // the submitter, then the settled escrow's depositor
    }

    mapping(bytes32 => DisputeRecord) public disputes;
    bytes32[] public disputeIds;

    /// @notice The registered file a storage dispute is about (its FileRegistrationSC
    ///         commitmentHash), or zero for a piece that was never registered. Only a
    ///         dispute about a registered file can settle an escrow.
    mapping(bytes32 => bytes32) public disputeCommitmentHash;
    /// @notice True once a valid dispute's escrow was refunded through settleDisputedEscrow.
    mapping(bytes32 => bool) public disputedEscrowSettled;

    // ─── Events ───────────────────────────────────────────────────────────────
    event DisputeSubmitted(
        bytes32 indexed disputeId,
        address indexed vk,
        uint8 deadlineIndex,
        uint8 partitionIndex,
        bytes32 partitionRoot
    );
    event DisputeValid(
        bytes32 indexed disputeId,
        address indexed vk,
        string reason
    );
    event DisputeInvalid(
        bytes32 indexed disputeId,
        address indexed vk,
        string reason
    );

    /// @notice Emitted once per valid dispute after all penalties have been applied.
    event W6EnforcementApplied(
        bytes32 indexed disputeId,
        address indexed vk,
        uint8   violationLevel,
        uint256 stakeSlashed,
        uint32  reputationPenalty,
        uint32  totalValidDisputes,
        uint64  suspendedUntil,
        bool    permanentlyRemoved
    );
    event VKSuspendedByDispute(
        address indexed vk,
        uint64  suspendedUntil,
        uint32  totalValidDisputes
    );
    event VKPermanentlyRemovedByDispute(
        address indexed vk,
        uint32  totalValidDisputes
    );

    /// @notice W8: emitted on every valid dispute so DO clients can detect sector risk
    ///         without reading unbounded arrays.  Interested parties query
    ///         FileRegistrationSC.getCommitmentsForSector / assessSectorRisk for details.
    event SectorRiskNotice(
        address indexed vk,
        bytes32 indexed sectorRoot,
        string  reason,
        uint256 commitmentCount
    );

    /// @notice A valid dispute's escrow was refunded to its depositor, with `compensation`
    ///         from the VK's stake.
    event DisputedEscrowSettled(
        bytes32 indexed disputeId,
        bytes32 indexed paymentCommitment,
        address indexed depositor,
        uint256 compensation
    );

    event StakingManagerSet(address indexed sm);
    event ReputationManagerSet(address indexed rm);
    event VKRegistrySet(address indexed vkr);
    event FileRegistrationSet(address indexed fileRegistration);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // ─── Deletion-dispute events ──────────────────────────────────────────────
    event DeletionDisputeSubmitted(
        bytes32 indexed delDisputeId,
        address indexed vk,
        bytes32 indexed commitmentHash
    );
    event DeletionDisputeValid(
        bytes32 indexed delDisputeId,
        address indexed vk,
        bytes32 commitmentHash,
        string  reason
    );
    event DeletionDisputeInvalid(
        bytes32 indexed delDisputeId,
        address indexed vk,
        string  reason
    );
    event DeletionEnforcementApplied(
        bytes32 indexed delDisputeId,
        address indexed vk,
        uint256 stakeSlashed,
        uint32  repPenalty,
        uint32  totalDeletionDisputes
    );

    event AuthorizedDisputeReporterUpdated(address indexed reporter, bool authorized);

    event AdmissionDisputeSubmitted(
        bytes32 indexed admDisputeId,
        address indexed vk,
        bytes32 indexed paymentCommitment,
        address doAddress
    );
    event AdmissionDisputeValid(
        bytes32 indexed admDisputeId,
        address indexed vk,
        bytes32 paymentCommitment,
        string  reason
    );
    event AdmissionDisputeInvalid(
        bytes32 indexed admDisputeId,
        address indexed vk,
        string  reason
    );
    event AdmissionEnforcementApplied(
        bytes32 indexed admDisputeId,
        address indexed vk,
        uint256 stakeSlashed,
        uint32  repPenalty,
        uint32  totalValidAdmissionDisputes
    );

    // ─── Modifiers ────────────────────────────────────────────────────────────
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // ─── Constructor ──────────────────────────────────────────────────────────
    constructor(address storageProof_) {
        if (storageProof_ == address(0)) revert ZeroAddress();
        storageProof = StorageProofSC(storageProof_);
        owner = msg.sender;
    }

    // ─── Admin ────────────────────────────────────────────────────────────────
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function setStakingManager(address sm) external onlyOwner {
        stakingManager = IStakingManager_W6(sm);
        emit StakingManagerSet(sm);
    }

    function setReputationManager(address rm) external onlyOwner {
        reputationManager = IReputationManager_W6(rm);
        emit ReputationManagerSet(rm);
    }

    function setVKRegistry(address vkr) external onlyOwner {
        vkRegistry = IVaultKeeperRegistry_W6(vkr);
        emit VKRegistrySet(vkr);
    }

    /// @notice Set the FileRegistrationSC address for W7 migration-aware and deletion dispute resolution.
    function setFileRegistration(address fr) external onlyOwner {
        fileRegistration = IFileRegistrationSC_Deletions(fr);
        emit FileRegistrationSet(fr);
    }

    /// @notice Set the VKEscrow address for automatic escrow refund on successful dispute.
    function setVKEscrow(address _vkEscrow) external onlyOwner {
        vkEscrow = IVKEscrow_Dispute(_vkEscrow);
    }

    /// @notice Authorize an off-chain reporter to submit admission-failure disputes.
    function setAuthorizedDisputeReporter(address reporter, bool authorized) external onlyOwner {
        if (reporter == address(0)) revert ZeroAddress();
        authorizedDisputeReporters[reporter] = authorized;
        emit AuthorizedDisputeReporterUpdated(reporter, authorized);
    }

    /// @notice Set DO compensation basis points (of minStake) sent via slashTo on dispute.
    function setDoCompensationBps(uint256 bps) external onlyOwner {
        if (bps > 500) revert InvalidParameters();
        doCompensationBps = bps;
    }

    /// @notice Adjust violation offense thresholds.
    function setViolationThresholds(
        uint32 minor, uint32 major, uint32 malicious
    ) external onlyOwner {
        if (!(0 < minor && minor < major && major < malicious)) revert InvalidParameters();
        offenseThreshold_minor     = minor;
        offenseThreshold_major     = major;
        offenseThreshold_malicious = malicious;
    }

    /// @notice Adjust stake slash basis points. Max 5000 (50%) per level.
    function setSlashParams(
        uint256 bpsWarning, uint256 bpsMinor, uint256 bpsMajor, uint256 bpsMalicious
    ) external onlyOwner {
        if (bpsMalicious > 5000) revert InvalidParameters();
        slashBps_warning   = bpsWarning;
        slashBps_minor     = bpsMinor;
        slashBps_major     = bpsMajor;
        slashBps_malicious = bpsMalicious;
    }

    /// @notice Adjust reputation penalty points per violation level.
    function setRepPenalties(
        uint32 warning, uint32 minor, uint32 major, uint32 malicious
    ) external onlyOwner {
        repPenalty_warning   = warning;
        repPenalty_minor     = minor;
        repPenalty_major     = major;
        repPenalty_malicious = malicious;
    }

    /// @notice Set the W10 proof-lapse staleness threshold (in rounds).
    ///         A VK becomes disputable when currentRound() > lastProofRound + threshold.
    ///         Minimum 1 to avoid immediate disputes in the same round.
    function setStalenessThreshold(uint64 threshold) external onlyOwner {
        if (threshold < 1) revert InvalidParameters();
        stalenessThreshold = threshold;
    }

    /// @notice Set the duration of MAJOR-level temporary suspension.
    function setSuspensionSeconds(uint64 majorSeconds) external onlyOwner {
        if (majorSeconds < 60) revert InvalidParameters();
        suspensionSeconds_major = majorSeconds;
    }

    /// @notice Adjust deletion-failure penalty parameters.
    function setDeletionSlashParams(
        uint256 bpsWarning,
        uint256 bpsMinor,
        uint32  repWarning,
        uint32  repMinor,
        uint32  offenseThresholdMinor
    ) external onlyOwner {
        if (bpsMinor > 500 || offenseThresholdMinor < 2) revert InvalidParameters();
        delSlashBps_warning      = bpsWarning;
        delSlashBps_minor        = bpsMinor;
        delRepPenalty_warning    = repWarning;
        delRepPenalty_minor      = repMinor;
        delOffenseThreshold_minor = offenseThresholdMinor;
    }

    // ─── Core dispute function ────────────────────────────────────────────────

    /// @notice Submit a dispute using a VK-signed storage receipt.
    /// @param receiptVersion       Must be 1.
    /// @param receiptNonce         Random nonce from the receipt (bytes32).
    /// @param vk                   VK Ethereum address from the receipt.
    /// @param pieceRoot            Piece Merkle root (bytes32).
    /// @param pieceSize            Piece size in bytes.
    /// @param sectorId             Raw sector ID string as UTF-8 bytes.
    /// @param sectorRoot           ZK sector root at time of storage (bytes32).
    /// @param deadlineIndex        Deadline slot index (0..deadlineCount-1).
    /// @param partitionIndex       Partition slot within the deadline.
    /// @param partitionRoot        Partition Merkle root at time of storage (bytes32).
    /// @param serviceEnd           Unix timestamp of service end.
    /// @param timestamp_           Unix timestamp when the receipt was issued.
    /// @param chainId_             Chain ID from the receipt.
    /// @param storageProofContract_ StorageProofSC address from the receipt.
    /// @param sig                  VK's Ethereum personal_sign signature (65 bytes).
    /// @param paymentCommitment    Ignored since Phase 1D (kept for compatibility): a dispute
    ///                             moves no escrow. See settleDisputedEscrow.
    /// @dev Without DO's commitment nonce, only a receipt for a sector nothing was ever
    ///      registered under can be disputed; use submitDisputeWithDeletionCheck otherwise.
    function submitDispute(
        uint16  receiptVersion,
        bytes32 receiptNonce,
        address vk,
        bytes32 pieceRoot,
        uint64  pieceSize,
        bytes   calldata sectorId,
        bytes32 sectorRoot,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        bytes32 partitionRoot,
        uint64  serviceEnd,
        uint64  timestamp_,
        uint64  chainId_,
        address storageProofContract_,
        bytes   calldata sig,
        bytes32 paymentCommitment
    ) external {
        _verifyReceiptAndDispatch(
            receiptVersion, receiptNonce, vk, pieceRoot, pieceSize,
            keccak256(sectorId), sectorRoot, deadlineIndex, partitionIndex, partitionRoot,
            serviceEnd, timestamp_, chainId_, storageProofContract_, sig,
            paymentCommitment, bytes32(0)
        );
    }

    /// @notice Variant of submitDispute that also checks whether the disputed file was
    ///         confirmed-deleted by DO request.  If deletion is confirmed on-chain the
    ///         dispute is immediately resolved as Invalid, protecting VK from being
    ///         penalised for legitimately removing a piece at DO's request.
    ///
    /// @param commitmentNonce  The nonce DO used when computing commitmentHash off-chain:
    ///                         commitmentHash = keccak256(pieceRoot ++ commitmentNonce).
    ///                         DO holds this nonce in their local receipt copy. It must name
    ///                         a file the receipt's VK registered, unless nothing was ever
    ///                         registered under the receipt's sector. Pass bytes32(0) to
    ///                         behave identically to submitDispute().
    function submitDisputeWithDeletionCheck(
        uint16  receiptVersion,
        bytes32 receiptNonce,
        address vk,
        bytes32 pieceRoot,
        uint64  pieceSize,
        bytes   calldata sectorId,
        bytes32 sectorRoot,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        bytes32 partitionRoot,
        uint64  serviceEnd,
        uint64  timestamp_,
        uint64  chainId_,
        address storageProofContract_,
        bytes   calldata sig,
        bytes32 paymentCommitment,
        bytes32 commitmentNonce
    ) external {
        _verifyReceiptAndDispatch(
            receiptVersion, receiptNonce, vk, pieceRoot, pieceSize,
            keccak256(sectorId), sectorRoot, deadlineIndex, partitionIndex, partitionRoot,
            serviceEnd, timestamp_, chainId_, storageProofContract_, sig,
            paymentCommitment, commitmentNonce
        );
    }

    /// @dev Validates the VK receipt signature then hands off to _submitDisputeCore.
    ///      Signature verification (digest + recover) is isolated here so that
    ///      _submitDisputeCore only receives the minimum fields it needs, keeping both
    ///      functions within the EVM stack limit.
    function _verifyReceiptAndDispatch(
        uint16  receiptVersion,
        bytes32 receiptNonce,
        address vk,
        bytes32 pieceRoot,
        uint64  pieceSize,
        bytes32 sectorIdHash,
        bytes32 sectorRoot,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        bytes32 partitionRoot,
        uint64  serviceEnd,
        uint64  timestamp_,
        uint64  chainId_,
        address storageProofContract_,
        bytes   calldata sig,
        bytes32 paymentCommitment,
        bytes32 commitmentNonce
    ) internal {
        if (receiptVersion != 1 || vk == address(0) ||
            storageProofContract_ != address(storageProof) ||
            chainId_ != uint64(block.chainid)) revert InvalidReceipt();

        bytes32 digest = _computeReceiptDigest(
            receiptVersion, receiptNonce, vk, pieceRoot, pieceSize,
            sectorIdHash, sectorRoot,
            deadlineIndex, partitionIndex, partitionRoot,
            serviceEnd, timestamp_, chainId_, storageProofContract_
        );
        if (_recoverSigner(digest, sig) != vk) revert InvalidSignature();

        _submitDisputeCore(
            receiptNonce, vk, pieceRoot, sectorRoot,
            deadlineIndex, partitionIndex, partitionRoot, serviceEnd,
            paymentCommitment, commitmentNonce
        );
    }

    /// @dev Creates the dispute record, runs the deletion exclusion check, then resolves.
    ///      Receives only the fields needed after signature verification, keeping the
    ///      stack well within EVM limits.
    function _submitDisputeCore(
        bytes32 receiptNonce,
        address vk,
        bytes32 pieceRoot,
        bytes32 sectorRoot,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        bytes32 partitionRoot,
        uint64  serviceEnd,
        bytes32 paymentCommitment,
        bytes32 commitmentNonce
    ) internal {
        bytes32 disputeId = keccak256(abi.encodePacked(
            vk, receiptNonce, pieceRoot
        ));
        if (disputes[disputeId].vk != address(0)) revert DuplicateDispute();
        paymentCommitment; // kept in the signatures for compatibility; see settleDisputedEscrow
        bytes32 ch = _disputedFile(vk, pieceRoot, sectorRoot, serviceEnd, commitmentNonce);

        disputes[disputeId] = DisputeRecord({
            vk:               vk,
            sectorRoot:       sectorRoot,
            deadlineIndex:    deadlineIndex,
            partitionIndex:   partitionIndex,
            partitionRoot:    partitionRoot,
            serviceEnd:       serviceEnd,
            submittedAt:      uint64(block.timestamp),
            status:           DisputeStatus.Pending,
            reason:           "",
            paymentCommitment: bytes32(0),
            doAddress:        msg.sender
        });
        disputeIds.push(disputeId);
        if (ch != bytes32(0)) disputeCommitmentHash[disputeId] = ch;

        emit DisputeSubmitted(disputeId, vk, deadlineIndex, partitionIndex, partitionRoot);

        // A deletion DO authorized (pending or confirmed) means the VK removed the piece as
        // asked: the storage-failure dispute is invalid.
        if (ch != bytes32(0) &&
            (fileRegistration.isDeletionConfirmed(ch) || fileRegistration.isDeletionAuthorized(ch))) {
            _resolve(disputeId, DisputeStatus.Invalid, "file deletion confirmed by DO request");
            return;
        }

        _resolveByPartitionStatus(disputeId, vk, sectorRoot, deadlineIndex, partitionIndex);
    }

    /// @dev What a storage dispute may judge. The receipt's VK must be a registered
    ///      VaultKeeper: a throwaway key has no partition, so its "failure" proved nothing.
    ///      The receipt must name a file that VK registered, through DO's commitment nonce,
    ///      so a deletion of it cannot be hidden by leaving the nonce out or getting it
    ///      wrong; or a sector nothing was ever registered under, so there is nothing to
    ///      hide (the VK took the piece and never registered it). The dispute must come
    ///      while the VK still owes the storage: until the receipt's service end, or the
    ///      later one its registration was extended to. Returns the file's commitmentHash,
    ///      or zero for a piece that was never registered.
    function _disputedFile(
        address vk,
        bytes32 pieceRoot,
        bytes32 sectorRoot,
        uint64  serviceEnd,
        bytes32 commitmentNonce
    ) internal view returns (bytes32 ch) {
        if (address(vkRegistry) == address(0) || address(fileRegistration) == address(0)) {
            revert ContractNotConfigured();
        }
        if (!vkRegistry.isRegisteredVaultKeeper(vk)) revert UnknownVaultKeeper();
        uint64 obligationEnd = serviceEnd;
        if (commitmentNonce != bytes32(0)) {
            ch = keccak256(abi.encodePacked(pieceRoot, commitmentNonce));
            (, , address recordVK, , , uint64 recordEnd, , , ) = fileRegistration.fileRecords(ch);
            if (recordVK == address(0)) {
                ch = bytes32(0);
            } else {
                if (recordVK != vk) revert InvalidReceipt();
                if (recordEnd > obligationEnd) obligationEnd = recordEnd;
            }
        }
        if (ch == bytes32(0) && fileRegistration.sectorCommitmentCount(sectorRoot) != 0) {
            revert RegistrationNotProven();
        }
        if (block.timestamp > obligationEnd) revert ServiceEnded();
    }

    /// @notice Refund the escrow that paid for the file of a valid storage dispute, and pay
    ///         its depositor DO's compensation from the VK's stake. The escrow must be that
    ///         file's: its link commitment, keccak256(paymentCommitment ++
    ///         registrationCommitment ++ linkNonce), must open to the registration commitment
    ///         the disputed VK registered the file under. Anyone may call it; the money goes
    ///         to the escrow's depositor. Once per dispute, and only while the escrow is
    ///         unclaimed.
    function settleDisputedEscrow(
        bytes32 disputeId,
        bytes32 paymentCommitment,
        bytes32 registrationCommitment,
        bytes32 linkNonce
    ) external {
        DisputeRecord storage d = disputes[disputeId];
        bytes32 ch = disputeCommitmentHash[disputeId];
        if (d.status != DisputeStatus.Valid || ch == bytes32(0) || disputedEscrowSettled[disputeId]) {
            revert NotSettleable();
        }
        (uint256 totalAmount, , , , bytes32 linkCommitment, uint256 claimedAmount, , address depositor) =
            vkEscrow.escrowStatus(paymentCommitment);
        if (totalAmount == 0 || claimedAmount != 0) revert NotSettleable();
        if (fileRegistration.registrationCommitmentToCommitmentHash(registrationCommitment) != ch ||
            keccak256(abi.encodePacked(paymentCommitment, registrationCommitment, linkNonce)) != linkCommitment) {
            revert InvalidEscrowLink();
        }

        disputedEscrowSettled[disputeId] = true;
        d.paymentCommitment = paymentCommitment;
        d.doAddress = depositor;
        vkEscrow.refundDisputed(paymentCommitment);

        uint256 comp = 0;
        if (address(stakingManager) != address(0) && doCompensationBps > 0) {
            uint256 stake = stakingManager.stakeOf(d.vk);
            if (stake > 0) {
                uint256 minS = stakingManager.minStake();
                comp = ((minS > 0 ? minS : stake) * doCompensationBps) / 10000;
                if (comp > stake) comp = stake;
                if (comp > 0) stakingManager.slashTo(d.vk, comp, depositor);
            }
        }
        emit DisputedEscrowSettled(disputeId, paymentCommitment, depositor, comp);
    }

    /// @dev Encapsulates W7+W9-aware partition status resolution, keeping submitDispute
    ///      below the EVM stack limit.
    ///
    /// Resolution order:
    ///   a) Confirmed migration present      → Invalid  (W7: VK followed migration protocol)
    ///   b) Partition never registered       → Valid
    ///   c) Partition inactive               → Valid
    ///   d) Partition never proved AND grace period elapsed → Valid  (W9 guard)
    ///   d) Partition never proved AND grace period active  → REVERT (W9 guard)
    ///   e) Sector absent from partition     → Valid    (W7: silent eviction detected)
    ///   f) Sector present and proved        → Invalid
    function _resolveByPartitionStatus(
        bytes32 disputeId,
        address vk,
        bytes32 sectorRoot,
        uint8   deadlineIndex,
        uint8   partitionIndex
    ) internal {
        // W7 fast path: check confirmed migration before any cross-contract work.
        bytes32 migKey = keccak256(abi.encodePacked(
            vk, sectorRoot, deadlineIndex, partitionIndex
        ));
        if (address(fileRegistration) != address(0) &&
            fileRegistration.migrationDeclared(migKey))
        {
            _resolve(disputeId, DisputeStatus.Invalid,
                     "sector legitimately migrated to new partition");
            return;
        }

        bytes32 pKey = storageProof.partitionKeyOf(vk, deadlineIndex, partitionIndex);
        (address pVK, bool active, uint64 lastProofRound, uint64 registeredAt) =
            storageProof.getPartitionProofStatus(pKey);
        (bytes32 contentHash,, , bool currentContentProven) =
            storageProof.getPartitionVersionStatus(pKey);

        if (pVK == address(0)) {
            _resolve(disputeId, DisputeStatus.Valid, "partition never registered");
        } else if (!active) {
            _resolve(disputeId, DisputeStatus.Valid, "partition registered but inactive");
        } else if (contentHash == bytes32(0) || !currentContentProven) {
            // A proof for an older partition version must not protect the current
            // sector set. StorageProofSC resets registeredAt on content changes,
            // so the same first-proof grace window applies to the new version.
            if (block.timestamp < uint256(registeredAt) + uint256(storageProof.proofPeriodSeconds()))
                revert GracePeriodActive();
            _resolve(disputeId, DisputeStatus.Valid, "current partition version not proved");
        } else if (lastProofRound == 0) {
            // W9: a "never proved" dispute is only valid after the VK has had at least
            // one full proof period from registration.  Reverting (not resolving Invalid)
            // preserves the receipt so the DO can retry once the grace period expires.
            if (block.timestamp < uint256(registeredAt) + uint256(storageProof.proofPeriodSeconds()))
                revert GracePeriodActive();
            _resolve(disputeId, DisputeStatus.Valid, "partition registered but never proved");
        } else {
            // W10: partition was proved at least once — but is the proof still current?
            // If more than stalenessThreshold rounds have elapsed since the last proof,
            // the VK has effectively stopped storing: dispute is valid immediately,
            // before incurring the cost of the W7 sector-roots storage read.
            uint64 curRound = storageProof.currentRound();
            if (curRound > lastProofRound + stalenessThreshold) {
                _resolve(disputeId, DisputeStatus.Valid, "proof has lapsed");
                return;
            }

            // W7: proof is current — verify the sector is still in the partition.
            bytes32[] memory roots = storageProof.getPartitionSectorRoots(pKey);
            bool sectorPresent = false;
            for (uint256 i = 0; i < roots.length; i++) {
                if (roots[i] == sectorRoot) { sectorPresent = true; break; }
            }
            if (sectorPresent) {
                _resolve(disputeId, DisputeStatus.Invalid,
                         "partition was proved and sector is present");
            } else {
                _resolve(disputeId, DisputeStatus.Valid,
                         "sector dropped from partition without migration");
            }
        }
    }

    /// @notice Dispute that a VK declared file deletion but failed to remove the piece
    ///         from its partition within the agreed grace period.
    ///
    /// @dev Anti-spam: the caller must supply the original VK-signed storage receipt so
    ///      the contract can verify VK actually accepted this file.  The receipt's pieceRoot
    ///      together with commitmentNonce must reproduce commitmentHash, binding the receipt
    ///      to the on-chain deletion record without requiring DO identity on-chain.
    ///
    ///      Penalty: lighter than storage-failure (deletion is administrative, not fraud).
    ///      Suspension is NOT triggered; only stake slash + reputation penalty.
    ///
    /// @param commitmentHash    The blinded commitment VK registered via registerFileStorage().
    ///                          DO holds this in their local receipt copy.
    /// @param commitmentNonce   DO's nonce: keccak256(pieceRoot ++ commitmentNonce) == commitmentHash.
    /// @param receiptVersion    Must be 1 (same version as storage receipt).
    /// @param receiptNonce      Random nonce from the VK-signed receipt.
    /// @param vk                VK address from the receipt.
    /// @param pieceRoot         Piece Merkle root from the receipt.
    /// @param pieceSize         Piece size from the receipt.
    /// @param sectorId          Sector ID bytes from the receipt.
    /// @param sectorRoot        Sector root from the receipt.
    /// @param deadlineIndex     Deadline index from the receipt.
    /// @param partitionIndex    Partition index from the receipt.
    /// @param partitionRoot     Partition root from the receipt.
    /// @param serviceEnd        Service end timestamp from the receipt.
    /// @param timestamp_        Receipt issue timestamp.
    /// @param chainId_          Chain ID from the receipt.
    /// @param storageProofContract_ StorageProofSC address from the receipt.
    /// @param sig               VK's original storage receipt signature (65 bytes).
    function submitDeletionFailureDispute(
        bytes32 commitmentHash,
        bytes32 commitmentNonce,
        uint16  receiptVersion,
        bytes32 receiptNonce,
        address vk,
        bytes32 pieceRoot,
        uint64  pieceSize,
        bytes   calldata sectorId,
        bytes32 sectorRoot,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        bytes32 partitionRoot,
        uint64  serviceEnd,
        uint64  timestamp_,
        uint64  chainId_,
        address storageProofContract_,
        bytes   calldata sig
    ) external {
        if (address(fileRegistration) == address(0)) revert ContractNotConfigured();

        // 1. Bind receipt to deletion record: keccak256(pieceRoot ++ commitmentNonce) must
        //    equal commitmentHash.  This proves the caller knows the nonce used at
        //    registration time, without trusting the caller's word for commitmentHash.
        if (keccak256(abi.encodePacked(pieceRoot, commitmentNonce)) != commitmentHash)
            revert InvalidReceipt();

        // 2. Verify VK's original storage receipt signature (proves VK stored this file).
        if (receiptVersion != 1 || storageProofContract_ != address(storageProof) ||
            chainId_ != uint64(block.chainid)) revert InvalidReceipt();
        {
            bytes32 digest = _computeReceiptDigest(
                receiptVersion, receiptNonce, vk, pieceRoot, pieceSize,
                keccak256(sectorId), sectorRoot,
                deadlineIndex, partitionIndex, partitionRoot,
                serviceEnd, timestamp_, chainId_, storageProofContract_
            );
            if (_recoverSigner(digest, sig) != vk) revert InvalidSignature();
        }

        // 3. Deletion must have been declared by VK and not yet confirmed.
        if (!fileRegistration.isDeletionDeclared(commitmentHash) ||
            fileRegistration.isDeletionConfirmed(commitmentHash)) revert InvalidDeletionState();

        // 4. Grace period must have elapsed.
        (uint64 declaredAt, uint64 graceSeconds, ) = fileRegistration.getDeletionRecord(commitmentHash);
        if (block.timestamp <= uint256(declaredAt) + uint256(graceSeconds)) revert GracePeriodActive();

        // 5. Verify the piece is STILL present in the partition (VK did not delete it).
        (address recVK, uint8 recDL, uint8 recPI, bytes32 zkPC) =
            fileRegistration.getFileRecordForDeletion(commitmentHash);
        if (recVK != vk) revert InvalidReceipt();
        bytes32 pKey = storageProof.partitionKeyOf(vk, recDL, recPI);
        bytes32[] memory pcs = storageProof.getPartitionPieceCommitments(pKey);
        bool stillPresent = false;
        for (uint256 i = 0; i < pcs.length; i++) {
            if (pcs[i] == zkPC) { stillPresent = true; break; }
        }
        if (!stillPresent) revert InvalidDeletionState();

        // 6. Deduplication: one deletion dispute per (vk, commitmentHash).
        bytes32 delDisputeId = keccak256(abi.encodePacked(
            "delDispute", vk, commitmentHash
        ));
        if (deletionDisputeFiled[delDisputeId]) revert DuplicateDispute();
        deletionDisputeFiled[delDisputeId] = true;

        emit DeletionDisputeSubmitted(delDisputeId, vk, commitmentHash);
        emit DeletionDisputeValid(delDisputeId, vk, commitmentHash,
                                  "deletion declared but piece not removed within grace period");

        _enforceDeletionPenalty(delDisputeId, vk);
    }

    /// @dev Lighter penalty path for deletion-failure disputes.
    ///      Uses a separate offense counter so deletion failures don't inflate the VK's
    ///      storage-failure dispute count (and vice versa).
    ///      Suspension is intentionally NOT applied: deletion failure is treated as
    ///      an administrative lapse, not malicious storage fraud.
    function _enforceDeletionPenalty(bytes32 delDisputeId, address vk) internal {
        validDeletionDisputeCount[vk] += 1;
        uint32 count = validDeletionDisputeCount[vk];

        uint256 slashBps  = count >= delOffenseThreshold_minor
            ? delSlashBps_minor   : delSlashBps_warning;
        uint32  repPenalty = count >= delOffenseThreshold_minor
            ? delRepPenalty_minor : delRepPenalty_warning;

        uint256 slashed = 0;
        if (address(stakingManager) != address(0)) {
            uint256 stake = stakingManager.stakeOf(vk);
            if (stake > 0) {
                uint256 minS   = stakingManager.minStake();
                uint256 base   = minS > 0 ? minS : stake;
                uint256 amount = (base * slashBps) / 10000;
                if (amount > stake) amount = stake;
                if (amount > 0) {
                    try stakingManager.slash(vk, amount) {
                        slashed = amount;
                    } catch {}
                }
            }
        }

        if (address(reputationManager) != address(0)) {
            try reputationManager.recordVKDisputePenalty(vk, repPenalty, VIOLATION_WARNING)
            {} catch {}
        }

        emit DeletionEnforcementApplied(delDisputeId, vk, slashed, repPenalty, count);
    }

    /// @notice DO disputes a VK that issued a signed, unexpired quote and then
    ///         signed an authoritative capacity rejection after escrow deposit.
    /// @param vk                  Target VK address from the quote / peer selection.
    /// @param paymentCommitment   Escrow payment commitment deposited by msg.sender.
    /// @param registrationCommitment Registration commitment from the VK quote; the VK must
    ///                               have reserved it, and it must not exist on-chain when
    ///                               the store was rejected.
    /// @param linkNonce           Link nonce the VK gave with the quote: the escrow's link
    ///                            commitment must open to registrationCommitment with it.
    function submitAdmissionFailureDispute(
        address vk,
        bytes32 paymentCommitment,
        bytes32 registrationCommitment,
        bytes32 linkNonce,
        uint256 quotedPriceWei,
        uint64 quoteValidUntil,
        bytes calldata quoteSignature,
        bytes calldata failureSignature
    ) external {
        _submitAdmissionFailureDispute(
            msg.sender, vk, paymentCommitment, registrationCommitment, linkNonce,
            quotedPriceWei, quoteValidUntil, quoteSignature, failureSignature
        );
    }

    /// @notice Guardian-style reporter path submits the same signed evidence on behalf
    ///         of the escrow depositor.
    function reportAdmissionFailureDispute(
        address doAddress,
        address vk,
        bytes32 paymentCommitment,
        bytes32 registrationCommitment,
        bytes32 linkNonce,
        uint256 quotedPriceWei,
        uint64 quoteValidUntil,
        bytes calldata quoteSignature,
        bytes calldata failureSignature
    ) external {
        if (!authorizedDisputeReporters[msg.sender]) revert Unauthorized();
        if (doAddress == address(0)) revert ZeroAddress();
        _submitAdmissionFailureDispute(
            doAddress, vk, paymentCommitment, registrationCommitment, linkNonce,
            quotedPriceWei, quoteValidUntil, quoteSignature, failureSignature
        );
    }

    function _submitAdmissionFailureDispute(
        address doAddress,
        address vk,
        bytes32 paymentCommitment,
        bytes32 registrationCommitment,
        bytes32 linkNonce,
        uint256 quotedPriceWei,
        uint64 quoteValidUntil,
        bytes calldata quoteSignature,
        bytes calldata failureSignature
    ) internal {
        if (
            vk == address(0) || paymentCommitment == bytes32(0) ||
            registrationCommitment == bytes32(0) || quotedPriceWei == 0 ||
            quoteValidUntil == 0
        ) revert InvalidParameters();

        bytes32 admDisputeId = keccak256(abi.encodePacked("admDispute", vk, paymentCommitment));
        emit AdmissionDisputeSubmitted(admDisputeId, vk, paymentCommitment, doAddress);

        if (admissionDisputeFiled[admDisputeId]) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "admission dispute already filed");
            return;
        }

        if (address(vkRegistry) == address(0) || address(vkEscrow) == address(0)) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "admission evidence contracts not configured");
            return;
        }

        (
            uint256 totalAmount,
            uint64 serviceStart,
            uint64 serviceEnd,
            bytes32 sizeCommitment,
            bytes32 linkCommitment,
            uint256 claimedAmount,
            ,
            address depositor
        ) = vkEscrow.escrowStatus(paymentCommitment);

        if (totalAmount == 0) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "escrow not found");
            return;
        }
        if (depositor != doAddress) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "depositor mismatch");
            return;
        }
        if (claimedAmount > 0) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "escrow already claimed or refunded");
            return;
        }
        if (totalAmount < quotedPriceWei || serviceStart > quoteValidUntil) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "escrow does not match valid quote");
            return;
        }
        // A quote and a refusal show only that a key quoted and refused this payment
        // commitment (Phase 1D D18). The escrow pays the VaultKeeper that reserved the
        // registration commitment its link commitment opens to, with the nonce the
        // VaultKeeper gave with the quote.
        (address reservedBy, , , ) = ICapacityProof_Dispute(fileRegistration.capacityProof())
            .getQuoteReservation(registrationCommitment);
        if (
            reservedBy != vk ||
            keccak256(abi.encodePacked(paymentCommitment, registrationCommitment, linkNonce)) != linkCommitment
        ) revert InvalidEscrowLink();
        // VaultKeepers sign V2 quotes; a V2 deposit records the quote's transfer deadline
        // as the escrow's registration deadline (Phase 1D D20).
        bytes32 quoteDigest = keccak256(abi.encodePacked(
            "FileTrustAdmissionQuoteV2",
            uint64(block.chainid),
            vk,
            address(vkEscrow),
            paymentCommitment,
            registrationCommitment,
            sizeCommitment,
            linkCommitment,
            quotedPriceWei,
            serviceEnd,
            quoteValidUntil,
            vkEscrow.registrationDeadlineOf(paymentCommitment)
        ));
        if (_recoverSigner(quoteDigest, quoteSignature) != vk) revert InvalidSignature();
        bytes32 failureDigest = keccak256(abi.encodePacked(
            "FileTrustAdmissionFailureV1",
            uint64(block.chainid),
            vk,
            address(vkEscrow),
            paymentCommitment,
            registrationCommitment
        ));
        if (_recoverSigner(failureDigest, failureSignature) != vk) revert InvalidSignature();
        if (!vkRegistry.isRegisteredVaultKeeper(vk)) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "unknown VK");
            return;
        }
        if (fileRegistration.registrationCommitmentExists(registrationCommitment)) {
            emit AdmissionDisputeInvalid(admDisputeId, vk, "registration commitment exists");
            return;
        }

        admissionDisputeFiled[admDisputeId] = true;
        emit AdmissionDisputeValid(
            admDisputeId,
            vk,
            paymentCommitment,
            "VK rejected store while admission was declared open"
        );

        if (address(vkEscrow) != address(0)) {
            try vkEscrow.refundDisputed(paymentCommitment) {} catch {}
        }

        _enforceAdmissionPenalty(admDisputeId, vk, doAddress);
    }

    /// @dev Lighter penalty path for admission-failure disputes.
    function _enforceAdmissionPenalty(bytes32 admDisputeId, address vk, address doAddress) internal {
        validAdmissionDisputeCount[vk] += 1;
        uint32 count = validAdmissionDisputeCount[vk];

        uint256 slashBps = count >= admOffenseThreshold_minor
            ? admSlashBps_minor
            : admSlashBps_warning;
        uint32 repPenalty = count >= admOffenseThreshold_minor
            ? admRepPenalty_minor
            : admRepPenalty_warning;

        uint256 slashed = 0;
        if (address(stakingManager) != address(0)) {
            uint256 stake = stakingManager.stakeOf(vk);
            if (stake > 0) {
                uint256 minS = stakingManager.minStake();
                uint256 base = minS > 0 ? minS : stake;
                uint256 amount = (base * slashBps) / 10000;
                if (amount > stake) amount = stake;
                if (amount > 0) {
                    try stakingManager.slash(vk, amount) {
                        slashed = amount;
                    } catch {}
                }
            }
            if (doAddress != address(0) && doCompensationBps > 0) {
                uint256 minS = stakingManager.minStake();
                if (minS > 0) {
                    uint256 comp = (minS * doCompensationBps) / 10000;
                    if (comp > 0) {
                        try stakingManager.slashTo(vk, comp, doAddress) {} catch {}
                    }
                }
            }
        }

        if (address(reputationManager) != address(0)) {
            try reputationManager.recordVKDisputePenalty(vk, repPenalty, VIOLATION_WARNING)
            {} catch {}
        }

        emit AdmissionEnforcementApplied(admDisputeId, vk, slashed, repPenalty, count);
    }

    /// @notice Total number of submitted disputes.
    function disputeCount() external view returns (uint256) {
        return disputeIds.length;
    }

    /// @notice Violation level that will be applied on the NEXT valid dispute for vk.
    function nextViolationLevel(address vk) public view returns (uint8) {
        uint32 next = validDisputeCount[vk] + 1;
        if (next >= offenseThreshold_malicious) return VIOLATION_MALICIOUS;
        if (next >= offenseThreshold_major)     return VIOLATION_MAJOR;
        if (next >= offenseThreshold_minor)     return VIOLATION_MINOR;
        return VIOLATION_WARNING;
    }

    // ─── Internal helpers ─────────────────────────────────────────────────────

    function _computeReceiptDigest(
        uint16  receiptVersion,
        bytes32 receiptNonce,
        address vk,
        bytes32 pieceRoot,
        uint64  pieceSize,
        bytes32 sectorIdHash,
        bytes32 sectorRoot,
        uint8   deadlineIndex,
        uint8   partitionIndex,
        bytes32 partitionRoot,
        uint64  serviceEnd,
        uint64  timestamp_,
        uint64  chainId_,
        address storageProofContract_
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            uint16(receiptVersion),
            receiptNonce,
            vk,
            pieceRoot,
            uint64(pieceSize),
            sectorIdHash,
            sectorRoot,
            uint8(deadlineIndex),
            uint8(partitionIndex),
            partitionRoot,
            uint64(serviceEnd),
            uint64(timestamp_),
            uint64(chainId_),
            storageProofContract_
        ));
    }

    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8   v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();
        bytes32 ethHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", digest
        ));
        address signer = ecrecover(ethHash, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }

    function _resolve(bytes32 disputeId, DisputeStatus status, string memory reason) internal {
        disputes[disputeId].status = status;
        disputes[disputeId].reason = reason;
        address vk        = disputes[disputeId].vk;
        bytes32 sectorRoot = disputes[disputeId].sectorRoot;
        if (status == DisputeStatus.Valid) {
            emit DisputeValid(disputeId, vk, reason);
            // W8: lightweight sector-risk notice — count only, no unbounded array in the event.
            // DO clients use FileRegistrationSC.getCommitmentsForSector / assessSectorRisk
            // to enumerate affected commitments at their own pace.
            if (address(fileRegistration) != address(0)) {
                uint256 count = fileRegistration.sectorCommitmentCount(sectorRoot);
                if (count > 0) {
                    emit SectorRiskNotice(vk, sectorRoot, reason, count);
                }
            }
            _enforceW6(disputeId, vk);
        } else {
            emit DisputeInvalid(disputeId, vk, reason);
        }
    }

    /// @dev Returns (violationLevel, slashBps, repPenalty) for a given offense count.
    function _violationParams(uint32 count)
        internal view
        returns (uint8 level, uint256 slashBps, uint32 repPenalty)
    {
        if (count >= offenseThreshold_malicious) {
            return (VIOLATION_MALICIOUS, slashBps_malicious, repPenalty_malicious);
        }
        if (count >= offenseThreshold_major) {
            return (VIOLATION_MAJOR, slashBps_major, repPenalty_major);
        }
        if (count >= offenseThreshold_minor) {
            return (VIOLATION_MINOR, slashBps_minor, repPenalty_minor);
        }
        return (VIOLATION_WARNING, slashBps_warning, repPenalty_warning);
    }

    /// @dev Core W6 enforcement: slash stake, record reputation, suspend/remove VK.
    ///      All external calls are wrapped in try/catch so enforcement never reverts
    ///      the dispute transaction even if a downstream contract misbehaves.
    function _enforceW6(bytes32 disputeId, address vk) internal {
        validDisputeCount[vk] += 1;
        lastValidDisputeAt[vk] = uint64(block.timestamp);
        uint32 count = validDisputeCount[vk];

        (uint8 level, uint256 slashBps, uint32 repPenalty) = _violationParams(count);

        // ── 1. Slash stake ──────────────────────────────────────────────────
        uint256 slashed = 0;
        if (address(stakingManager) != address(0)) {
            uint256 stake = stakingManager.stakeOf(vk);
            if (stake > 0) {
                uint256 minS  = stakingManager.minStake();
                // Slash a fraction of minStake (or of actual stake if no minStake set).
                uint256 base   = minS > 0 ? minS : stake;
                uint256 amount = (base * slashBps) / 10000;
                if (amount > stake) amount = stake;
                if (amount > 0) {
                    try stakingManager.slash(vk, amount) {
                        slashed = amount;
                    } catch {}
                }
            }
        }

        // ── 1b. No escrow moves here: settleDisputedEscrow refunds the file's escrow and
        //        pays the compensation to its depositor, once the escrow is proven to be it.

        // ── 2. Record reputation penalty ─────────────────────────────────
        if (address(reputationManager) != address(0)) {
            try reputationManager.recordVKDisputePenalty(vk, repPenalty, level) {} catch {}
        }

        // ── 3. Suspension / removal based on violation level ─────────────
        uint64 suspUntil      = 0;
        bool   permanentRemoval = false;

        if (level == VIOLATION_MAJOR) {
            suspUntil = uint64(block.timestamp) + suspensionSeconds_major;
            suspendedUntil[vk] = suspUntil;
            _trySuspendInRegistry(vk, suspUntil);
            emit VKSuspendedByDispute(vk, suspUntil, count);

        } else if (level == VIOLATION_MALICIOUS) {
            permanentlySuspended[vk] = true;
            permanentRemoval = true;
            _tryDeactivateInRegistry(vk);
            emit VKPermanentlyRemovedByDispute(vk, count);
        }

        // ── 4. Stake-exhaustion check ─────────────────────────────────────
        // If stake fell below minimum after slashing, auto-deactivate regardless
        // of violation level.  This is the protection for Test E.
        if (!permanentRemoval && address(stakingManager) != address(0)) {
            uint256 remaining = stakingManager.stakeOf(vk);
            uint256 minS      = stakingManager.minStake();
            if (minS > 0 && remaining < minS) {
                permanentlySuspended[vk] = true;
                permanentRemoval = true;
                _tryDeactivateInRegistry(vk);
                emit VKPermanentlyRemovedByDispute(vk, count);
            }
        }

        emit W6EnforcementApplied(
            disputeId, vk, level, slashed, repPenalty, count,
            suspUntil, permanentRemoval
        );
    }

    function _trySuspendInRegistry(address vk, uint64 until) internal {
        if (address(vkRegistry) == address(0)) return;
        try vkRegistry.isRegisteredVaultKeeper(vk) returns (bool registered) {
            if (registered) {
                try vkRegistry.suspendVaultKeeper(vk, until) {} catch {}
            }
        } catch {}
    }

    function _tryDeactivateInRegistry(address vk) internal {
        if (address(vkRegistry) == address(0)) return;
        try vkRegistry.isRegisteredVaultKeeper(vk) returns (bool registered) {
            if (registered) {
                try vkRegistry.deactivateVaultKeeper(vk) {} catch {}
            }
        } catch {}
    }
}
