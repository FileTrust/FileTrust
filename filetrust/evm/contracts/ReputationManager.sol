// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: ReputationManager
// Purpose:  The standing record of every promise a Vault Keeper or Guardian has kept,
//           and every one it has broken.
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

import "./governance/FileTrustOwnable.sol";

interface IStakingManager {
    function stakeOf(address staker) external view returns (uint256);
    function slash(address guardian, uint256 amount) external;
    function slashGuardianPenalty(address guardian, uint256 amount, address reporter) external returns (uint256);
    function maxGuardianPenaltyWei() external view returns (uint256);
}

/**
 * ReputationManager
 *
 * Tracks reputation for two completely separate node types:
 *   - Guardians  (DKG / PRE cryptographic roles)  — stored in _guardianStats
 *   - VaultKeepers (storage / partition proofs)    — stored in _vkStats
 *
 * The two namespaces never overlap. Guardian functions only touch _guardianStats;
 * VK functions only touch _vkStats. An address can exist in both mappings if a
 * single operator runs both node types, but the stats are fully independent.
 */
contract ReputationManager is FileTrustOwnable {

    // ─── Guardian data ────────────────────────────────────────────────────────

    struct GuardianStats {
        uint32 reputationScore;
        uint32 completedDKG;
        uint32 failedDKG;
        uint32 completedPRE;
        uint32 failedPRE;
        uint32 readyButNotUsedPRE;
        uint32 dkgComplaints;
        uint32 preComplaints;
        uint32 penaltyPoints;
        uint32 totalSlashedEvents;
        uint64 lastActivityAt;
        uint64 lastPenaltyAt;
        // unused for Guardians — kept for ABI stability
        uint32 storageDisputeComplaints;
        uint32 storageDisputePenaltyPoints;
        // Share-proof custody tracking (Guardians)
        uint32 missedShareProofs;        // consecutive misses (resets on success)
        uint32 totalShareProofPenalties; // lifetime penalty count (never resets)
    }

    // ─── VaultKeeper data ─────────────────────────────────────────────────────

    struct VKStats {
        uint32 reputationScore;
        uint32 penaltyPoints;
        uint32 disputeComplaints;        // storage disputes lost
        uint32 disputePenaltyPoints;     // rep points lost to disputes
        uint32 missedProofs;             // consecutive missed partition proofs (resets on success)
        uint32 totalMissedPenalties;     // lifetime missed-proof penalty count
        uint64 lastActivityAt;
    }

    // ─────────────────────────────────────────────────────────────────────────

    constructor() Ownable(msg.sender) {}

    uint256 public constant SLASH_UNIT = 1e15;
    /// @notice Fine for a DKG complaint, taken when the complaint is recorded: 0.001 FTU by
    ///         default, set by the owner (the timelock) up to 1% of the minimum stake new
    ///         Guardians are admitted with. StakingManager takes at most 1% of the minimum a
    ///         Guardian was admitted with, and sends it to the treasury. The fine counts
    ///         toward the same complaint's penalty points: see complaintFineCreditWei.
    uint256 public verifiedDkgComplaintSlashWei = 1e15;

    // Configurable reputation parameters (set at deploy time via setters).
    uint32 public initialReputation       = 1000;
    uint32 public maxReputation           = 10000;
    uint32 public seriousPenaltyThreshold = 20;
    uint32 public proofSuccessRepDelta    = 1;

    mapping(address => GuardianStats) private _guardianStats;
    mapping(address => VKStats)       private _vkStats;

    mapping(address => bool) public authorizedProtocols;
    mapping(address => bool) public authorizedReporters;
    address public stakingManager;
    /// @notice True once the deployment locked the protocol list: from then on a protocol
    ///         can only be removed. A protocol contract turns penalty points into stake
    ///         slashes, so adding one later would be adding a slasher.
    bool public protocolsLocked;

    /// @dev Penalty events already charged, keyed by reporting protocol, penalty kind (the
    ///      selector of the keyed function that charged it), subject and event id.
    mapping(bytes32 => bool) private _chargedPenaltyEvents;

    /// @notice Penalty points already turned into a stake slash. Points stay cumulative,
    ///         but each is slashed at most once: a serious penalty slashes only the points
    ///         not slashed before, and the repeat-offender DKG slash counts here too.
    mapping(address => uint32) public guardianPointsSlashed;
    mapping(address => uint32) public vkPointsSlashed;

    /// @notice Complaint fines a Guardian paid that still count toward their complaints'
    ///         points. Each fine counts up to the value of its own complaint's points; when
    ///         those points are slashed, the slash deducts this credit. A points slash takes
    ///         every point not slashed before, so the credit is used up together with the
    ///         complaints it came from: it never offsets another offense, never pays out
    ///         and is never used twice.
    mapping(address => uint256) public complaintFineCreditWei;

    // ─── Shared admin events ─────────────────────────────────────────────────

    event ProtocolContractUpdated(address indexed protocol, bool authorized);
    event ProtocolContractsLocked();
    event ReporterUpdated(address indexed reporter, bool allowed);
    event StakingManagerUpdated(address indexed stakingManager);
    event VerifiedDkgComplaintSlashUpdated(uint256 amount);
    /// @notice A complaint fine took `paid`, of which `credit` counts toward the complaint's points.
    event ComplaintFineCharged(address indexed guardian, uint256 paid, uint256 credit);
    /// @notice A points slash deducted `amount` of complaint fines already paid.
    event ComplaintFineCredited(address indexed guardian, uint256 amount);
    event DuplicatePenaltyIgnored(
        address indexed protocol,
        bytes4  indexed kind,
        address indexed subject,
        bytes32 eventId
    );

    // ─── Guardian events (unchanged) ─────────────────────────────────────────

    event DkgCommitmentRecorded(address indexed guardian, uint32 reputationScore, uint64 timestamp);
    event DkgShareRecorded(address indexed guardian, uint32 reputationScore, uint64 timestamp);
    event DkgFinalized(address indexed guardian, uint32 completedDKG, uint32 reputationScore, uint256 speedScore, uint64 timestamp);
    event RefreshSuccessRecorded(address indexed guardian, uint32 completedDKG, uint32 reputationScore, uint256 speedScore, uint64 timestamp);
    event PrePartialRecorded(address indexed guardian, uint32 reputationScore, uint64 timestamp);
    event PreReadyNotUsedRecorded(
        address indexed guardian,
        uint32 readyButNotUsedPRE,
        uint32 reputationScore,
        uint64 timestamp
    );
    event DkgSuccessRecorded(
        address indexed guardian,
        uint32 completedDKG,
        uint32 reputationScore,
        uint256 speedScore,
        uint64 timestamp
    );
    event DkgFailureRecorded(
        address indexed guardian,
        uint32 failedDKG,
        uint32 reputationScore,
        uint32 penaltyPoints,
        uint8 reasonCode,
        uint64 timestamp
    );
    event DkgFailureWarned(
        address indexed guardian,
        uint32 failedDKG,
        uint8 reasonCode,
        uint64 timestamp
    );
    event PreSuccessRecorded(
        address indexed guardian,
        uint32 completedPRE,
        uint32 reputationScore,
        uint256 speedScore,
        uint64 timestamp
    );
    event PreFailureRecorded(
        address indexed guardian,
        uint32 failedPRE,
        uint32 reputationScore,
        uint32 penaltyPoints,
        uint8 reasonCode,
        uint64 timestamp
    );
    event DkgComplaintSubmitted(
        address indexed guardian,
        address indexed reporter,
        uint8 reasonCode,
        uint32 dkgComplaints,
        uint32 penaltyPoints,
        uint64 timestamp
    );
    event PreComplaintSubmitted(
        address indexed guardian,
        address indexed reporter,
        uint8 reasonCode,
        uint32 preComplaints,
        uint32 penaltyPoints,
        uint64 timestamp
    );
    event SeriousPenaltyTriggered(
        address indexed guardian,
        uint32 penaltyPoints,
        uint32 dkgComplaints,
        uint32 preComplaints,
        uint64 timestamp
    );
    event ShareProofMissedRecorded(
        address indexed guardian,
        uint32  missedShareProofs,
        uint32  reputationScore,
        uint32  penaltyPoints,
        uint64  timestamp
    );
    event ShareProofMissedWarned(
        address indexed guardian,
        uint32  missedShareProofs,
        uint64  timestamp
    );
    event ShareProofSuccessRecorded(
        address indexed guardian,
        uint32  reputationScore,
        uint64  timestamp
    );

    // ─── VaultKeeper events ───────────────────────────────────────────────────

    event VKDisputePenaltyRecorded(
        address indexed vk,
        uint8   violationLevel,
        uint32  repPenalty,
        uint32  disputeComplaints,
        uint32  reputationScore,
        uint64  timestamp
    );
    event VKProofMissedRecorded(
        address indexed vk,
        uint32  missedProofs,
        uint32  reputationScore,
        uint32  penaltyPoints,
        uint64  timestamp
    );
    event VKProofMissedWarned(
        address indexed vk,
        uint32  missedProofs,
        uint64  timestamp
    );
    event VKProofSuccessRecorded(
        address indexed vk,
        uint32  reputationScore,
        uint64  timestamp
    );
    event VKSeriousPenaltyTriggered(
        address indexed vk,
        uint32  penaltyPoints,
        uint64  timestamp
    );

    // ─── Shared modifier ─────────────────────────────────────────────────────

    modifier onlyAuthorizedProtocol() {
        require(authorizedProtocols[msg.sender], "Reputation: unauthorized protocol");
        _;
    }

    // ─── Shared admin functions ───────────────────────────────────────────────

    function setProtocolContract(address protocol, bool authorized) external onlyOwner {
        require(!authorized || !protocolsLocked, "Reputation: protocols locked");
        authorizedProtocols[protocol] = authorized;
        emit ProtocolContractUpdated(protocol, authorized);
    }

    /// @notice Close the protocol list for good. Called once, when deployment has added
    ///         every protocol contract.
    function lockProtocolContracts() external onlyOwner {
        require(!protocolsLocked, "Reputation: protocols locked");
        protocolsLocked = true;
        emit ProtocolContractsLocked();
    }

    function setAuthorizedReporter(address reporter, bool allowed) external onlyOwner {
        authorizedReporters[reporter] = allowed;
        emit ReporterUpdated(reporter, allowed);
    }

    /// @notice Bind the StakingManager that penalties slash through, once.
    function setStakingManager(address manager) external onlyOwner {
        require(stakingManager == address(0) && manager.code.length != 0, "Reputation: bad staking manager");
        stakingManager = manager;
        emit StakingManagerUpdated(manager);
    }

    /// @notice Set the DKG complaint fine. Zero turns it off; above 1% of the minimum stake
    ///         new Guardians are admitted with is refused.
    function setVerifiedDkgComplaintSlashWei(uint256 amount) external onlyOwner {
        require(
            amount == 0 || (stakingManager != address(0) && amount <= IStakingManager(stakingManager).maxGuardianPenaltyWei()),
            "Reputation: fine above ceiling"
        );
        verifiedDkgComplaintSlashWei = amount;
        emit VerifiedDkgComplaintSlashUpdated(amount);
    }

    /// @notice The complaint fine under its name before Phase 1C, for existing clients.
    function VERIFIED_DKG_COMPLAINT_SLASH() external view returns (uint256) {
        return verifiedDkgComplaintSlashWei;
    }

    function setProofSuccessRepDelta(uint32 delta) external onlyOwner {
        require(delta > 0, "Reputation: zero delta");
        proofSuccessRepDelta = delta;
    }

    function setInitialReputation(uint32 value) external onlyOwner {
        require(value > 0, "Reputation: zero initial");
        initialReputation = value;
    }

    function setMaxReputation(uint32 value) external onlyOwner {
        require(value > 0, "Reputation: zero max");
        maxReputation = value;
    }

    function setSeriousPenaltyThreshold(uint32 value) external onlyOwner {
        require(value > 0, "Reputation: zero threshold");
        seriousPenaltyThreshold = value;
    }

    // ─── Penalty event keys ──────────────────────────────────────────────────
    //
    // A protocol that reports a miss through a keyed function (recordShareProofMissedFor,
    // recordVKProofMissedFor) names it with an event id. The same protocol reporting the same
    // event for the same subject again changes nothing, so one offense costs one penalty even
    // if the reporting contract repeats itself. The protocols keep their own once-only records
    // too; this is the second line.

    /// @notice Whether `protocol` already charged `eventId` of `kind` (the selector of the keyed
    ///         function it went through) to `subject`.
    function isPenaltyEventCharged(address protocol, bytes4 kind, address subject, bytes32 eventId)
        external
        view
        returns (bool)
    {
        return _chargedPenaltyEvents[_penaltyEventKey(protocol, kind, subject, eventId)];
    }

    function _firstCharge(address subject, bytes32 eventId) private returns (bool) {
        bytes32 key = _penaltyEventKey(msg.sender, msg.sig, subject, eventId);
        if (_chargedPenaltyEvents[key]) {
            emit DuplicatePenaltyIgnored(msg.sender, msg.sig, subject, eventId);
            return false;
        }
        _chargedPenaltyEvents[key] = true;
        return true;
    }

    function _penaltyEventKey(address protocol, bytes4 kind, address subject, bytes32 eventId)
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(protocol, kind, subject, eventId));
    }

    // =========================================================================
    // GUARDIAN FUNCTIONS — do not mix with VK logic
    // =========================================================================

    function getGuardianReputation(address guardian) external view returns (uint32) {
        GuardianStats storage stats = _guardianStats[guardian];
        if (stats.lastActivityAt == 0) {
            return initialReputation;
        }
        return stats.reputationScore;
    }

    function getGuardianStats(address guardian)
        external
        view
        returns (
            uint32 reputationScore,
            uint32 completedDKG,
            uint32 failedDKG,
            uint32 completedPRE,
            uint32 failedPRE,
            uint32 dkgComplaints,
            uint32 preComplaints,
            uint32 penaltyPoints,
            uint64 lastActivityAt,
            uint32 readyButNotUsedPRE
        )
    {
        GuardianStats storage stats = _guardianStats[guardian];
        if (stats.lastActivityAt == 0) {
            return (initialReputation, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }
        return (
            stats.reputationScore,
            stats.completedDKG,
            stats.failedDKG,
            stats.completedPRE,
            stats.failedPRE,
            stats.dkgComplaints,
            stats.preComplaints,
            stats.penaltyPoints,
            stats.lastActivityAt,
            stats.readyButNotUsedPRE
        );
    }

    function recordDkgCommitment(address guardian) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);
        stats.lastActivityAt = uint64(block.timestamp);
        _increaseReputation(stats, 1);
        emit DkgCommitmentRecorded(guardian, stats.reputationScore, uint64(block.timestamp));
    }

    function recordDkgShareSubmission(address guardian) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);
        stats.lastActivityAt = uint64(block.timestamp);
        _increaseReputation(stats, 1);
        emit DkgShareRecorded(guardian, stats.reputationScore, uint64(block.timestamp));
    }

    function recordDkgSuccess(address guardian, uint256 speedScore) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.completedDKG += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        uint32 reputationDelta = 5 + _successReputationBonus(speedScore);
        _increaseReputation(stats, reputationDelta);

        emit DkgSuccessRecorded(
            guardian,
            stats.completedDKG,
            stats.reputationScore,
            speedScore,
            uint64(block.timestamp)
        );
    }

    function recordDkgFinalized(address guardian, uint256 speedScore) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);
        stats.completedDKG += 1;
        stats.lastActivityAt = uint64(block.timestamp);
        uint32 reputationDelta = 4 + _successReputationBonus(speedScore);
        _increaseReputation(stats, reputationDelta);
        emit DkgFinalized(guardian, stats.completedDKG, stats.reputationScore, speedScore, uint64(block.timestamp));
    }

    function recordDkgFailure(address guardian, uint8 reasonCode) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.failedDKG += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        if (stats.failedDKG == 1) {
            // First offense: warning only — benefit of the doubt (transient network issue).
            emit DkgFailureWarned(guardian, stats.failedDKG, reasonCode, uint64(block.timestamp));
            return;
        }

        uint32 penalty = _failureReputationPenalty(reasonCode);
        _decreaseReputation(stats, penalty);
        stats.penaltyPoints += penalty;

        emit DkgFailureRecorded(
            guardian,
            stats.failedDKG,
            stats.reputationScore,
            stats.penaltyPoints,
            reasonCode,
            uint64(block.timestamp)
        );

        if (stats.failedDKG >= 4) {
            // Repeated offender: this failure's points are slashed at once, also below the
            // threshold. The serious-penalty slash below does not slash them again.
            guardianPointsSlashed[guardian] += penalty;
            _slashIfConfigured(guardian, SLASH_UNIT * uint256(penalty));
        }

        _checkSeriousPenalty(guardian, stats);
    }

    function recordPrePartial(address guardian) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);
        stats.lastActivityAt = uint64(block.timestamp);
        _increaseReputation(stats, 1);
        emit PrePartialRecorded(guardian, stats.reputationScore, uint64(block.timestamp));
    }

    function recordPreSuccess(address guardian, uint256 speedScore) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.completedPRE += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        uint32 reputationDelta = 3 + _successReputationBonus(speedScore);
        _increaseReputation(stats, reputationDelta);

        emit PreSuccessRecorded(
            guardian,
            stats.completedPRE,
            stats.reputationScore,
            speedScore,
            uint64(block.timestamp)
        );
    }

    function recordPreReadyNotUsed(address guardian) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.readyButNotUsedPRE += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        // Smaller than a full PRE success. This rewards a verifiable,
        // timely readiness signal without equating it to an accepted PRE partial.
        _increaseReputation(stats, 1);

        emit PreReadyNotUsedRecorded(
            guardian,
            stats.readyButNotUsedPRE,
            stats.reputationScore,
            uint64(block.timestamp)
        );
    }

    function recordRefreshSuccess(address guardian, uint256 speedScore) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.completedDKG += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        uint32 reputationDelta = 3 + _successReputationBonus(speedScore);
        _increaseReputation(stats, reputationDelta);

        emit RefreshSuccessRecorded(
            guardian,
            stats.completedDKG,
            stats.reputationScore,
            speedScore,
            uint64(block.timestamp)
        );
    }

    function recordPreFailure(address guardian, uint8 reasonCode) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.failedPRE += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        uint32 penalty = _failureReputationPenalty(reasonCode);
        _decreaseReputation(stats, penalty);
        stats.penaltyPoints += penalty;

        emit PreFailureRecorded(
            guardian,
            stats.failedPRE,
            stats.reputationScore,
            stats.penaltyPoints,
            reasonCode,
            uint64(block.timestamp)
        );

        _checkSeriousPenalty(guardian, stats);
    }

    function submitDkgComplaint(address guardian, address reporter, uint8 reasonCode) external onlyAuthorizedProtocol {
        require(_reporterAllowed(reporter), "Reputation: reporter not authorized");
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.dkgComplaints += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        uint32 complaintPenalty = _complaintPenalty(reasonCode, stats.dkgComplaints);
        stats.penaltyPoints += complaintPenalty;

        emit DkgComplaintSubmitted(
            guardian,
            reporter,
            reasonCode,
            stats.dkgComplaints,
            stats.penaltyPoints,
            uint64(block.timestamp)
        );

        _chargeComplaintFine(guardian, complaintPenalty);
        _checkSeriousPenalty(guardian, stats);
    }

    /// @notice Record a DKG complaint whose truth was checked by an authorized protocol contract.
    /// @dev This is the production path for cryptographic DKG accountability. It deliberately
    /// bypasses the owner-maintained reporter allowlist because the protocol contract has already
    /// verified objective evidence, for example an expired zkDKG dealer-justification dispute.
    function recordVerifiedDkgComplaint(address guardian, address reporter, uint8 reasonCode)
        external
        onlyAuthorizedProtocol
    {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.dkgComplaints += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        uint32 complaintPenalty = _complaintPenalty(reasonCode, stats.dkgComplaints);
        stats.penaltyPoints += complaintPenalty;

        emit DkgComplaintSubmitted(
            guardian,
            reporter,
            reasonCode,
            stats.dkgComplaints,
            stats.penaltyPoints,
            uint64(block.timestamp)
        );

        _chargeComplaintFine(guardian, complaintPenalty);
        _checkSeriousPenalty(guardian, stats);
    }

    function submitPreComplaint(address guardian, address reporter, uint8 reasonCode) external onlyAuthorizedProtocol {
        require(_reporterAllowed(reporter), "Reputation: reporter not authorized");
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.preComplaints += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        uint32 complaintPenalty = _complaintPenalty(reasonCode, stats.preComplaints);
        stats.penaltyPoints += complaintPenalty;

        emit PreComplaintSubmitted(
            guardian,
            reporter,
            reasonCode,
            stats.preComplaints,
            stats.penaltyPoints,
            uint64(block.timestamp)
        );

        _checkSeriousPenalty(guardian, stats);
    }

    function recordShareProofMissed(address guardian) external onlyAuthorizedProtocol {
        _recordShareProofMissed(guardian);
    }

    /// @notice recordShareProofMissed for one identified miss; a repeat of the same
    ///         `eventId` for the same Guardian from the same protocol is ignored.
    function recordShareProofMissedFor(address guardian, bytes32 eventId) external onlyAuthorizedProtocol {
        if (_firstCharge(guardian, eventId)) {
            _recordShareProofMissed(guardian);
        }
    }

    function _recordShareProofMissed(address guardian) private {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);

        stats.missedShareProofs += 1;
        stats.lastActivityAt = uint64(block.timestamp);

        if (stats.missedShareProofs == 1) {
            // First miss: warning only. Network hiccups happen.
            emit ShareProofMissedWarned(guardian, stats.missedShareProofs, uint64(block.timestamp));
            return;
        }

        uint32 penalty = 5;
        _decreaseReputation(stats, penalty);
        stats.penaltyPoints += penalty;
        stats.totalShareProofPenalties += 1;

        emit ShareProofMissedRecorded(
            guardian,
            stats.missedShareProofs,
            stats.reputationScore,
            stats.penaltyPoints,
            uint64(block.timestamp)
        );

        _checkSeriousPenalty(guardian, stats);
    }

    function recordShareProofSuccess(address guardian) external onlyAuthorizedProtocol {
        GuardianStats storage stats = _guardianStats[guardian];
        _initializeGuardianIfNeeded(stats);
        stats.missedShareProofs = 0;
        stats.lastActivityAt = uint64(block.timestamp);
        _increaseReputation(stats, proofSuccessRepDelta);
        emit ShareProofSuccessRecorded(guardian, stats.reputationScore, uint64(block.timestamp));
    }

    function getMissedShareProofCount(address guardian) external view returns (uint32) {
        return _guardianStats[guardian].missedShareProofs;
    }

    function getTotalShareProofPenalties(address guardian) external view returns (uint32) {
        return _guardianStats[guardian].totalShareProofPenalties;
    }

    // =========================================================================
    // VAULTKEEPER FUNCTIONS — do not mix with Guardian logic
    // =========================================================================

    function getVKReputation(address vk) external view returns (uint32) {
        VKStats storage stats = _vkStats[vk];
        if (stats.lastActivityAt == 0) {
            return initialReputation;
        }
        return stats.reputationScore;
    }

    function getVKStats(address vk)
        external
        view
        returns (
            uint32 reputationScore,      // [0]
            uint32 penaltyPoints,        // [1]
            uint32 disputeComplaints,    // [2]
            uint32 disputePenaltyPoints, // [3]
            uint32 missedProofs,         // [4]
            uint32 totalMissedPenalties, // [5]
            uint64 lastActivityAt        // [6]
        )
    {
        VKStats storage stats = _vkStats[vk];
        if (stats.lastActivityAt == 0) {
            return (initialReputation, 0, 0, 0, 0, 0, 0);
        }
        return (
            stats.reputationScore,
            stats.penaltyPoints,
            stats.disputeComplaints,
            stats.disputePenaltyPoints,
            stats.missedProofs,
            stats.totalMissedPenalties,
            stats.lastActivityAt
        );
    }

    /// @notice Record a validated storage-dispute penalty for a VaultKeeper.
    /// @dev Called by StorageReceiptDispute when a dispute resolves as Valid.
    /// @param vk             VK address being penalised.
    /// @param repPenalty     Reputation points to deduct.
    /// @param violationLevel 0=warning, 1=minor, 2=major, 3=malicious.
    function recordVKDisputePenalty(
        address vk,
        uint32  repPenalty,
        uint8   violationLevel
    ) external onlyAuthorizedProtocol {
        VKStats storage stats = _vkStats[vk];
        _initializeVKIfNeeded(stats);

        stats.disputeComplaints     += 1;
        stats.disputePenaltyPoints  += repPenalty;
        stats.penaltyPoints         += repPenalty;
        stats.lastActivityAt         = uint64(block.timestamp);

        _decreaseVKReputation(stats, repPenalty);

        emit VKDisputePenaltyRecorded(
            vk,
            violationLevel,
            repPenalty,
            stats.disputeComplaints,
            stats.reputationScore,
            uint64(block.timestamp)
        );

        _checkVKSeriousPenalty(vk, stats);
    }

    /// @notice Record a successful partition proof for a VaultKeeper (+rep).
    /// @dev Called by StorageProofSC on each accepted proof submission.
    function recordVKProofSuccess(address vk) external onlyAuthorizedProtocol {
        VKStats storage stats = _vkStats[vk];
        _initializeVKIfNeeded(stats);
        stats.missedProofs   = 0;
        stats.lastActivityAt = uint64(block.timestamp);
        _increaseVKReputation(stats, proofSuccessRepDelta);
        emit VKProofSuccessRecorded(vk, stats.reputationScore, uint64(block.timestamp));
    }

    /// @notice Record a missed partition proof deadline for a VaultKeeper (-rep after 1st).
    /// @dev Called by StorageProofSC for repeated wrong proofs.
    function recordVKProofMissed(address vk) external onlyAuthorizedProtocol {
        _recordVKProofMissed(vk);
    }

    /// @notice recordVKProofMissed for one identified miss; a repeat of the same `eventId`
    ///         for the same VaultKeeper from the same protocol is ignored.
    /// @dev Called by StorageProofSC.markMissed() with the missed challenge as the event.
    function recordVKProofMissedFor(address vk, bytes32 eventId) external onlyAuthorizedProtocol {
        if (_firstCharge(vk, eventId)) {
            _recordVKProofMissed(vk);
        }
    }

    function _recordVKProofMissed(address vk) private {
        VKStats storage stats = _vkStats[vk];
        _initializeVKIfNeeded(stats);

        stats.missedProofs   += 1;
        stats.lastActivityAt  = uint64(block.timestamp);

        if (stats.missedProofs == 1) {
            // First miss: warning only. Network hiccups happen.
            emit VKProofMissedWarned(vk, stats.missedProofs, uint64(block.timestamp));
            return;
        }

        uint32 penalty = 5;
        _decreaseVKReputation(stats, penalty);
        stats.penaltyPoints         += penalty;
        stats.totalMissedPenalties  += 1;

        emit VKProofMissedRecorded(
            vk,
            stats.missedProofs,
            stats.reputationScore,
            stats.penaltyPoints,
            uint64(block.timestamp)
        );

        _checkVKSeriousPenalty(vk, stats);
    }

    // =========================================================================
    // GUARDIAN INTERNAL HELPERS — only used by Guardian functions above
    // =========================================================================

    function _initializeGuardianIfNeeded(GuardianStats storage stats) internal {
        if (stats.lastActivityAt == 0) {
            stats.reputationScore = initialReputation;
        }
    }

    function _reporterAllowed(address reporter) internal view returns (bool) {
        return authorizedReporters[reporter];
    }

    function _successReputationBonus(uint256 speedScore) internal pure returns (uint32) {
        if (speedScore >= 100) {
            return 2;
        }
        return 1;
    }

    function _failureReputationPenalty(uint8 reasonCode) internal pure returns (uint32) {
        if (reasonCode == 0) {
            return 1;
        }
        if (reasonCode == 1) {
            return 2;
        }
        return 3;
    }

    function _complaintPenalty(uint8 reasonCode, uint32 complaintCount) internal pure returns (uint32) {
        uint32 basePenalty = _failureReputationPenalty(reasonCode);
        uint32 escalation = 1 + ((complaintCount - 1) / 5);
        return basePenalty * escalation;
    }

    function _increaseReputation(GuardianStats storage stats, uint32 delta) internal {
        uint256 next = uint256(stats.reputationScore) + delta;
        if (next > maxReputation) {
            stats.reputationScore = maxReputation;
        } else {
            stats.reputationScore = uint32(next);
        }
    }

    function _decreaseReputation(GuardianStats storage stats, uint32 delta) internal {
        if (delta >= stats.reputationScore) {
            stats.reputationScore = 0;
        } else {
            stats.reputationScore -= delta;
        }
    }

    function _checkSeriousPenalty(address guardian, GuardianStats storage stats) internal {
        if (stats.penaltyPoints >= seriousPenaltyThreshold) {
            emit SeriousPenaltyTriggered(
                guardian,
                stats.penaltyPoints,
                stats.dkgComplaints,
                stats.preComplaints,
                uint64(block.timestamp)
            );
            stats.totalSlashedEvents += 1;
            stats.lastPenaltyAt = uint64(block.timestamp);
            uint256 amount = _takeNewPoints(guardian, stats.penaltyPoints, guardianPointsSlashed);
            // Complaint fines already paid count toward their own complaints' points, which
            // are all among these: the credit never exceeds them (complaintFineCreditWei).
            uint256 credit = complaintFineCreditWei[guardian];
            if (credit != 0) {
                uint256 used = credit < amount ? credit : amount;
                complaintFineCreditWei[guardian] = credit - used;
                amount -= used;
                emit ComplaintFineCredited(guardian, used);
            }
            _slashIfConfigured(guardian, amount);
        }
    }

    /// @dev Takes the complaint fine, capped by StakingManager, and keeps what it took, up to
    ///      the value of this complaint's `points`, as credit toward their slash. A Guardian
    ///      with no stake pays nothing and earns no credit (see _hasStake).
    function _chargeComplaintFine(address guardian, uint32 points) private {
        uint256 fine = verifiedDkgComplaintSlashWei;
        if (stakingManager == address(0) || fine == 0) return;
        uint256 paid = _hasStake(guardian)
            ? IStakingManager(stakingManager).slashGuardianPenalty(guardian, fine, address(0))
            : 0;
        uint256 value = uint256(points) * SLASH_UNIT;
        uint256 credit = paid < value ? paid : value;
        if (credit != 0) complaintFineCreditWei[guardian] += credit;
        emit ComplaintFineCharged(guardian, paid, credit);
    }

    /// @dev The points of `subject` that were never slashed, in wei, recorded as slashed now,
    ///      so a later penalty past the threshold slashes its own new points and not the
    ///      whole history again.
    function _takeNewPoints(address subject, uint32 points, mapping(address => uint32) storage slashed)
        private
        returns (uint256)
    {
        uint32 already = slashed[subject];
        if (points <= already) return 0;
        slashed[subject] = points;
        return uint256(points - already) * SLASH_UNIT;
    }

    function _slashIfConfigured(address guardian, uint256 amount) internal {
        if (stakingManager != address(0) && amount > 0 && _hasStake(guardian)) {
            IStakingManager(stakingManager).slash(guardian, amount);
        }
    }

    /// @dev StakingManager refuses to slash an empty stake, and that refusal used to revert
    ///      the whole penalty: a protocol that catches it (ZkDkgDisputeManager) lost the
    ///      offense, and one that reverts with it (StorageProofSC.markMissed) could never
    ///      report it. A subject with no stake is not asked for money: its offense and points
    ///      are recorded, points due are counted as slashed, and nothing is owed later.
    function _hasStake(address subject) private view returns (bool) {
        return IStakingManager(stakingManager).stakeOf(subject) != 0;
    }

    // =========================================================================
    // VAULTKEEPER INTERNAL HELPERS — only used by VK functions above
    // =========================================================================

    function _initializeVKIfNeeded(VKStats storage stats) internal {
        if (stats.lastActivityAt == 0) {
            stats.reputationScore = initialReputation;
        }
    }

    function _increaseVKReputation(VKStats storage stats, uint32 delta) internal {
        uint256 next = uint256(stats.reputationScore) + delta;
        if (next > maxReputation) {
            stats.reputationScore = maxReputation;
        } else {
            stats.reputationScore = uint32(next);
        }
    }

    function _decreaseVKReputation(VKStats storage stats, uint32 delta) internal {
        if (delta >= stats.reputationScore) {
            stats.reputationScore = 0;
        } else {
            stats.reputationScore -= delta;
        }
    }

    function _checkVKSeriousPenalty(address vk, VKStats storage stats) internal {
        if (stats.penaltyPoints >= seriousPenaltyThreshold) {
            emit VKSeriousPenaltyTriggered(vk, stats.penaltyPoints, uint64(block.timestamp));
            _slashIfConfigured(vk, _takeNewPoints(vk, stats.penaltyPoints, vkPointsSlashed));
        }
    }
}
