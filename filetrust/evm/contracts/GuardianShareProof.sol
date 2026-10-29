// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: GuardianShareProof
// Purpose:  Each Guardian proving, in a window of its own, that it still holds the
//           share it was given.
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
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./BabyJubjub.sol";

interface IAccessControlFT_ShareProof {
    function getFilePolicy(bytes32 fileId)
        external
        view
        returns (bool exists, bool active, address dataOwner, uint8 threshold, address[] memory guardians);

    function guardianRegistry() external view returns (address);
}

interface IZkDkgCoordinatorV2_ShareProof {
    function getV2Key(bytes32 fileId)
        external
        view
        returns (
            bool exists,
            bool finalized,
            address dataOwner,
            uint8 t,
            uint8 n,
            uint32 keyEpoch,
            uint32 shareVersion,
            uint256 publicKeyX,
            uint256 publicKeyY
        );

    function getV2SharePublicKeyFull(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 shareIndex
    ) external view returns (bool exists, address guardian, uint8 storedShareIndex, uint256 x, uint256 y);
}

interface IGuardianRegistry_ShareProof {
    function getGuardianAvailability(address guardian)
        external
        view
        returns (uint256 maxServiceDays, bool unlimited, bool exists);
}

interface IReputationManager_ShareProof {
    function recordShareProofMissedFor(address guardian, bytes32 eventId) external;
    function recordShareProofSuccess(address guardian) external;
}

interface IRewardManager_ShareProof {
    function creditShareProof(address guardian) external;

    function reserveCustodyStretch(bytes32 fileId, uint64 startTime, uint64 endTime)
        external
        returns (uint256 stretchIndex, uint256 priceWei);

    function activateCustodyStretch(bytes32 fileId, uint256 stretchIndex) external;

    function releaseCustodyStretch(bytes32 fileId, uint256 stretchIndex) external;
}

interface IStakingManager_ShareProof {
    function slashGuardianPenalty(address guardian, uint256 amount, address reporter) external returns (uint256);
    function maxGuardianPenaltyWei() external view returns (uint256);
}

struct SharePossessionG1Point {
    uint256 X;
    uint256 Y;
}

struct SharePossessionG2Point {
    uint256[2] X;
    uint256[2] Y;
}

struct SharePossessionGroth16Proof {
    SharePossessionG1Point a;
    SharePossessionG2Point b;
    SharePossessionG1Point c;
}

interface ISharePossessionVerifier {
    function verifyTx(SharePossessionGroth16Proof calldata proof, uint256[8] calldata input)
        external
        view
        returns (bool);
}

/**
 * GuardianShareProof
 *
 * Daily randomized proof of knowledge for a Guardian's finalized V2 DKG share.
 * Each Guardian proves at most one randomly selected active policy per proof
 * epoch. The secret share is never stored, emitted, or passed in calldata.
 */
contract GuardianShareProof is FileTrustOwnable, ReentrancyGuard {
    uint256 private constant BABY_P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant BABY_L =
        2736030358979909402780800718157159386076813972158567259200215660948447373041;

    struct PublicShare {
        bool exists;
        uint32 shareVersion;
        uint8 shareIndex;
        uint256 x;
        uint256 y;
    }

    struct PolicyServicePeriod {
        bool exists;
        uint64 serviceStart;
        uint64 serviceEnd;
        uint64 durationDays;
    }

    /// @dev A renewal waiting for its Guardians to agree. See the extension
    ///      section further down for why every one of them has to say yes.
    struct ServiceExtension {
        bool   pending;
        uint32 round;           // which proposal this is, counted per policy
        uint64 newServiceEnd;   // the later end being asked for
        uint64 confirmBy;       // Guardians must answer before this
        uint8  acceptedCount;
        uint8  guardianCount;   // how many had to agree when it was proposed
        uint32 custodyStretch;  // the parked stretch of days in RewardManager
        bool   custodyReserved; // false when no reward manager is wired
        // The exact Guardian list the proposal was made to. Any change to it —
        // added, removed, swapped, even reordered — voids the proposal. Without
        // this a DO could swap Guardians mid-window and let the replacements'
        // answers make up the count for a Guardian that never agreed.
        bytes32 guardianSetHash;
    }

    IAccessControlFT_ShareProof public acl;
    IZkDkgCoordinatorV2_ShareProof public coordinatorV2;
    address public rewardManager;
    address public reputationManager;
    address public sharePossessionVerifier;
    address public stakingManager;
    uint256 public proofPeriodSeconds = 1 days;
    uint256 public proofGraceSeconds = 1 hours;
    uint256 public missedEpochPenaltyWei = 1e15; // 0.001 FTU slashed per missed epoch
    uint256 public maxReporterBatchSize  = 500;  // max Gs per batch report tx

    // Spread proof-window config
    uint256 public slotSeconds         = 300;   // 5-minute slots
    uint256 public windowSeconds       = 300;   // non-overlapping window per selected slot
    uint256 public avgBlockSeconds     = 12;    // assumed avg block time for slot math
    bool    public proofWindowEnforced = false; // false = legacy (any-time); true = slots enforced

    /// @dev Ceiling on how long Guardians get to answer a renewal, so a DO's
    ///      money is never parked for long against a promise nobody made. The
    ///      DO picks the actual deadline per request and may pick a shorter one.
    uint64 public constant maxExtensionConfirmSeconds = 3 days;

    mapping(bytes32 => PolicyServicePeriod) private _policyServicePeriods;
    mapping(bytes32 => ServiceExtension) private _serviceExtensions;
    /// @dev policy => round => guardian => said yes. Keyed by round so a new
    ///      proposal never inherits answers given to an older one.
    mapping(bytes32 => mapping(uint32 => mapping(address => bool))) private _extensionAccepted;
    /// @dev Rounds only ever go up, so a stale accept can never be replayed.
    mapping(bytes32 => uint32) private _extensionRounds;
    mapping(address => bytes32[]) private _guardianPolicyIds;
    mapping(bytes32 => mapping(address => bool)) private _guardianTrackedForPolicy;
    mapping(bytes32 => mapping(uint32 => mapping(address => PublicShare))) private _publicShares;
    mapping(bytes32 => mapping(uint32 => mapping(address => mapping(uint256 => uint256)))) private _proofRecordMeta;
    mapping(address => uint256) public lastProofAt;

    /// @dev guardian => proof epoch => what that epoch settled. A missed epoch is one
    ///      punishable event: one reputation miss and one slash, however many times and
    ///      through whichever entry point it is reported. Keyed by proof epoch alone, so a
    ///      key refresh after a valid proof does not make the epoch look missed.
    mapping(address => mapping(uint256 => uint8)) private _epochOutcome;

    uint256 private constant _PROOF_META_SUBMITTED = 1;
    uint256 private constant _PROOF_META_VALID = 2;
    uint256 private constant _PROOF_META_SUBMITTED_AT_SHIFT = 8;

    uint8 private constant _EPOCH_VALID_PROOF = 1;       // a valid share proof was accepted
    uint8 private constant _EPOCH_MISS_REPUTATION = 2;   // the miss cost its reputation penalty
    uint8 private constant _EPOCH_MISS_SLASH = 4;        // the miss cost its stake slash

    event AccessControlSet(address indexed acl);
    event CoordinatorV2Set(address indexed coordinatorV2);
    event RewardManagerSet(address indexed rewardManager);
    event ReputationManagerSet(address indexed reputationManager);
    event SharePossessionVerifierSet(address indexed verifier);
    event ProofTimingSet(uint256 proofPeriodSeconds, uint256 proofGraceSeconds);
    event ProofWindowConfigUpdated(uint256 slotSeconds, uint256 windowSeconds, uint256 avgBlockSeconds, bool enforced);
    event PolicyServicePeriodSet(
        bytes32 indexed policyId,
        address indexed dataOwner,
        uint256 serviceStart,
        uint256 serviceEnd,
        uint256 durationDays
    );
    event ServicePeriodCustodyReserved(
        bytes32 indexed policyId,
        uint256 indexed stretchIndex,
        uint64 startTime,
        uint64 endTime,
        uint256 priceWei
    );
    event ServicePeriodExtensionRequested(
        bytes32 indexed policyId,
        address indexed dataOwner,
        uint32 indexed round,
        uint64 currentServiceEnd,
        uint64 newServiceEnd,
        uint64 confirmBy,
        uint8 guardianCount
    );
    event ServicePeriodExtensionAccepted(
        bytes32 indexed policyId,
        address indexed guardian,
        uint32 indexed round,
        uint8 acceptedCount,
        uint8 guardianCount
    );
    event ServicePeriodExtended(
        bytes32 indexed policyId,
        uint32 indexed round,
        uint64 previousServiceEnd,
        uint64 newServiceEnd,
        uint64 durationDays
    );
    event ServicePeriodExtensionCancelled(
        bytes32 indexed policyId,
        uint32 indexed round,
        uint64 newServiceEnd,
        uint8 acceptedCount
    );
    event GuardianPublicShareRegistered(
        bytes32 indexed policyId,
        uint32 indexed keyEpoch,
        address indexed guardian,
        uint32 shareVersion,
        uint8 shareIndex,
        uint256 publicShareX,
        uint256 publicShareY
    );
    event ShareProofSubmitted(
        bytes32 indexed policyId,
        uint32 indexed keyEpoch,
        address indexed guardian,
        uint256 proofEpoch,
        bool valid
    );
    event ShareProofMissed(
        bytes32 indexed policyId,
        uint32 indexed keyEpoch,
        address indexed guardian,
        uint256 proofEpoch
    );

    constructor(address aclAddress, address coordinatorV2Address) Ownable(msg.sender) {
        require(aclAddress != address(0), "ShareProof: zero ACL");
        require(coordinatorV2Address != address(0), "ShareProof: zero coordinator");
        acl = IAccessControlFT_ShareProof(aclAddress);
        coordinatorV2 = IZkDkgCoordinatorV2_ShareProof(coordinatorV2Address);
        emit AccessControlSet(aclAddress);
        emit CoordinatorV2Set(coordinatorV2Address);
    }

    function setAccessControl(address aclAddress) external onlyOwner {
        require(aclAddress != address(0), "ShareProof: zero ACL");
        acl = IAccessControlFT_ShareProof(aclAddress);
        emit AccessControlSet(aclAddress);
    }

    function setCoordinatorV2(address coordinatorV2Address) external onlyOwner {
        require(coordinatorV2Address != address(0), "ShareProof: zero coordinator");
        coordinatorV2 = IZkDkgCoordinatorV2_ShareProof(coordinatorV2Address);
        emit CoordinatorV2Set(coordinatorV2Address);
    }

    function setRewardManager(address manager) external onlyOwner {
        rewardManager = manager;
        emit RewardManagerSet(manager);
    }

    function setReputationManager(address manager) external onlyOwner {
        reputationManager = manager;
        emit ReputationManagerSet(manager);
    }

    /// @notice Bound once (Phase 2, D8): keys are replaced through the FileTrustVerifierRouter
    ///         this names, with a bounded transition window.
    function setSharePossessionVerifier(address verifier) external onlyOwner {
        require(verifier != address(0) && sharePossessionVerifier == address(0), "ShareProof: verifier bound once");
        sharePossessionVerifier = verifier;
        emit SharePossessionVerifierSet(verifier);
    }

    function setStakingManager(address manager) external onlyOwner {
        stakingManager = manager;
    }

    /// @notice At most 1% of the minimum stake new Guardians are admitted with. StakingManager
    ///         also charges each Guardian at most 1% of the minimum it was admitted with.
    function setMissedEpochPenaltyWei(uint256 amount) external onlyOwner {
        require(amount <= IStakingManager_ShareProof(stakingManager).maxGuardianPenaltyWei(), "ShareProof: penalty above ceiling");
        missedEpochPenaltyWei = amount;
    }

    function setMaxReporterBatchSize(uint256 size) external onlyOwner {
        require(size > 0, "ShareProof: zero batch size");
        maxReporterBatchSize = size;
    }

    function setProofPeriodSeconds(uint256 periodSeconds) external onlyOwner {
        require(periodSeconds > 0, "ShareProof: zero period");
        proofPeriodSeconds = periodSeconds;
        emit ProofTimingSet(periodSeconds, proofGraceSeconds);
    }

    function setProofTiming(uint256 periodSeconds, uint256 graceSeconds) external onlyOwner {
        require(periodSeconds > 0, "ShareProof: zero period");
        proofPeriodSeconds = periodSeconds;
        proofGraceSeconds = graceSeconds;
        emit ProofTimingSet(periodSeconds, graceSeconds);
    }

    function setProofWindowConfig(
        uint256 _slotSeconds,
        uint256 _windowSeconds,
        uint256 _avgBlockSeconds,
        bool    _enforce
    ) external onlyOwner {
        require(_slotSeconds > 0,               "ShareProof: zero slot");
        require(_windowSeconds > 0,             "ShareProof: zero window");
        require(_windowSeconds <= _slotSeconds, "ShareProof: window > slot");
        require(_avgBlockSeconds > 0,           "ShareProof: zero block time");
        slotSeconds         = _slotSeconds;
        windowSeconds       = _windowSeconds;
        avgBlockSeconds     = _avgBlockSeconds;
        proofWindowEnforced = _enforce;
        emit ProofWindowConfigUpdated(_slotSeconds, _windowSeconds, _avgBlockSeconds, _enforce);
    }

    function getProofEpoch() public view returns (uint256) {
        return block.timestamp / proofPeriodSeconds;
    }

    /// @notice Initialize a policy's service term once. Existing terms, including
    ///         expired ones, cannot be reset. To buy more days on a live term use
    ///         requestServicePeriodExtension instead; a new agreement needs a new policy.
    function setPolicyServicePeriod(bytes32 policyId, uint256 durationDays) external {
        require(durationDays > 0, "ShareProof: zero duration");
        // A restart would move the ground under a renewal the Guardians are
        // still answering, and strand the days the DO already paid for.
        require(!_serviceExtensions[policyId].pending, "ShareProof: extension pending");
        (bool exists, bool active, address dataOwner, , address[] memory guardians) = acl.getFilePolicy(policyId);
        require(exists && active, "ShareProof: no active policy");
        require(msg.sender == dataOwner || msg.sender == owner(), "ShareProof: not policy DO");
        require(!_policyServicePeriods[policyId].exists, "ShareProof: service period exists");

        _validateGuardianAvailability(guardians, durationDays);

        uint256 serviceStart = block.timestamp;
        uint256 serviceEnd = serviceStart + (durationDays * 1 days);
        _policyServicePeriods[policyId] = PolicyServicePeriod({
            exists: true,
            serviceStart: uint64(serviceStart),
            serviceEnd: uint64(serviceEnd),
            durationDays: uint64(durationDays)
        });

        emit PolicyServicePeriodSet(policyId, dataOwner, serviceStart, serviceEnd, durationDays);
    }

    function getPolicyServicePeriod(bytes32 policyId)
        external
        view
        returns (bool exists, uint256 serviceStart, uint256 serviceEnd, uint256 durationDays)
    {
        PolicyServicePeriod storage period = _policyServicePeriods[policyId];
        return (period.exists, period.serviceStart, period.serviceEnd, period.durationDays);
    }

    // ─── Renewal: buying more days on a term that is already running ──────────
    //
    // setPolicyServicePeriod above only initializes a term. Reinitialization
    // would erase the original start and change obligations without consent,
    // so all later changes to a live term must use the renewal flow below.
    //
    // Renewal here is forward-only. serviceStart never moves, so the record of
    // what was already owed survives untouched, and serviceEnd only moves once
    // every Guardian on the policy has said yes.
    //
    // Ordering matches the Vault Keeper side: the money for the extra days parks
    // first, the Guardians take on the longer job second, and the term moves
    // last. If they do not all answer in time the DO cancels, gets the parked
    // money back, and the original term runs on untouched.
    //
    // Every Guardian must agree, not a threshold of them. Each one holds a share
    // and owes a daily proof for it, so a majority cannot vote the rest into
    // more work. One Guardian staying silent blocks the renewal — the DO cancels
    // and buys a fresh agreement, which is the same fallback it had before.

    /// @notice Pay the Guardians for the current term. Optional and separate
    ///         from setting the term, so nothing that worked before starts
    ///         needing money to work now.
    /// @dev The stretch covers the whole term from its original start, not from
    ///      today. That is what the Guardians actually held the share for, and
    ///      it makes the price a fixed number the DO can read with quoteCustody
    ///      and fund exactly — starting at `now` would move the price between
    ///      reading it and paying it.
    /// @dev No consent step: the Guardians already took this term on when they
    ///      registered their share for it. Only renewals need a fresh yes.
    function reserveServicePeriodCustody(bytes32 policyId)
        external
        returns (uint256 stretchIndex, uint256 priceWei)
    {
        PolicyServicePeriod storage period = _policyServicePeriods[policyId];
        require(period.exists, "ShareProof: no service period");
        require(block.timestamp < period.serviceEnd, "ShareProof: service period ended");
        require(rewardManager != address(0), "ShareProof: reward manager not set");
        _requirePolicyDO(policyId);

        (stretchIndex, priceWei) = IRewardManager_ShareProof(rewardManager)
            .reserveCustodyStretch(policyId, period.serviceStart, period.serviceEnd);
        IRewardManager_ShareProof(rewardManager).activateCustodyStretch(policyId, stretchIndex);
        emit ServicePeriodCustodyReserved(
            policyId, stretchIndex, period.serviceStart, period.serviceEnd, priceWei
        );
    }

    /// @notice DO asks its Guardians to hold the share until a later date.
    ///         Must be called while the term is still running: once it has
    ///         ended the Guardians may already have dropped the share, so the
    ///         DO buys a fresh agreement instead.
    /// @param policyId       The policy whose term is being lengthened.
    /// @param newServiceEnd  The later end date. Must be after the current one.
    /// @param confirmBy      Deadline for the Guardians to answer.
    /// @return round         Identifier the Guardians quote back when accepting.
    function requestServicePeriodExtension(
        bytes32 policyId,
        uint64 newServiceEnd,
        uint64 confirmBy
    ) external returns (uint32 round) {
        PolicyServicePeriod storage period = _policyServicePeriods[policyId];
        require(period.exists, "ShareProof: no service period");
        require(!_serviceExtensions[policyId].pending, "ShareProof: extension already pending");
        require(block.timestamp < period.serviceEnd, "ShareProof: service period ended");
        require(newServiceEnd > period.serviceEnd, "ShareProof: newServiceEnd not later");
        require(confirmBy > block.timestamp, "ShareProof: confirmBy in past");
        require(
            uint256(confirmBy) <= block.timestamp + maxExtensionConfirmSeconds,
            "ShareProof: confirmBy too distant"
        );
        // The DO must learn the answer while the original term still runs, so a
        // refusal still leaves time to arrange something else.
        require(confirmBy <= period.serviceEnd, "ShareProof: confirmBy after service end");

        address[] memory guardians = _requirePolicyDO(policyId);
        require(guardians.length > 0, "ShareProof: policy has no guardians");
        require(guardians.length <= type(uint8).max, "ShareProof: too many guardians");

        // Availability is a promise about the whole job, so it is rechecked
        // against the full span from the original start, not just the new days.
        // Rounded up, so a Guardian is never held past the limit it published.
        uint256 totalDays =
            (uint256(newServiceEnd) - uint256(period.serviceStart) + 1 days - 1) / 1 days;
        _validateGuardianAvailability(guardians, totalDays);

        // Money parks before anyone takes on the longer job.
        uint32 stretchIndex;
        bool custodyReserved;
        if (rewardManager != address(0)) {
            (uint256 reserved, ) = IRewardManager_ShareProof(rewardManager)
                .reserveCustodyStretch(policyId, period.serviceEnd, newServiceEnd);
            stretchIndex = uint32(reserved);
            custodyReserved = true;
        }

        round = _extensionRounds[policyId] + 1;
        _extensionRounds[policyId] = round;
        _serviceExtensions[policyId] = ServiceExtension({
            pending:         true,
            round:           round,
            newServiceEnd:   newServiceEnd,
            confirmBy:       confirmBy,
            acceptedCount:   0,
            guardianCount:   uint8(guardians.length),
            custodyStretch:  stretchIndex,
            custodyReserved: custodyReserved,
            guardianSetHash: keccak256(abi.encode(guardians))
        });

        emit ServicePeriodExtensionRequested(
            policyId,
            msg.sender,
            round,
            period.serviceEnd,
            newServiceEnd,
            confirmBy,
            uint8(guardians.length)
        );
    }

    /// @notice A Guardian agrees to hold its share for the longer term. The term
    ///         moves the moment the last one of them agrees.
    function acceptServicePeriodExtension(bytes32 policyId, uint32 round) external {
        ServiceExtension storage ext = _serviceExtensions[policyId];
        require(ext.pending, "ShareProof: no extension pending");
        require(ext.round == round, "ShareProof: stale extension round");
        require(block.timestamp <= ext.confirmBy, "ShareProof: accept window closed");

        (bool exists, bool active, , , address[] memory guardians) = acl.getFilePolicy(policyId);
        require(exists && active, "ShareProof: no active policy");
        // Answers are only good for the Guardian list they were asked of.
        require(
            keccak256(abi.encode(guardians)) == ext.guardianSetHash,
            "ShareProof: guardian set changed"
        );

        bool selected;
        for (uint256 i = 0; i < guardians.length; i++) {
            if (guardians[i] == msg.sender) {
                selected = true;
                break;
            }
        }
        require(selected, "ShareProof: not a policy guardian");
        require(!_extensionAccepted[policyId][round][msg.sender], "ShareProof: already accepted");

        _extensionAccepted[policyId][round][msg.sender] = true;
        ext.acceptedCount += 1;
        emit ServicePeriodExtensionAccepted(
            policyId, msg.sender, round, ext.acceptedCount, ext.guardianCount
        );

        if (ext.acceptedCount >= ext.guardianCount) {
            _applyServiceExtension(policyId);
        }
    }

    /// @notice DO takes back money parked against a renewal the Guardians never
    ///         all agreed to. The original term is untouched and runs on.
    /// @dev Only after the answer deadline, so a DO cannot pull the offer out
    ///      from under Guardians who are part-way through accepting it.
    function cancelServicePeriodExtension(bytes32 policyId) external {
        ServiceExtension storage ext = _serviceExtensions[policyId];
        require(ext.pending, "ShareProof: no extension pending");
        require(block.timestamp > ext.confirmBy, "ShareProof: accept window still open");
        _requirePolicyDO(policyId);

        uint32 round = ext.round;
        uint64 newServiceEnd = ext.newServiceEnd;
        uint8 acceptedCount = ext.acceptedCount;
        bool custodyReserved = ext.custodyReserved;
        uint32 stretchIndex = ext.custodyStretch;

        delete _serviceExtensions[policyId];

        if (custodyReserved) {
            IRewardManager_ShareProof(rewardManager).releaseCustodyStretch(policyId, stretchIndex);
        }
        emit ServicePeriodExtensionCancelled(policyId, round, newServiceEnd, acceptedCount);
    }

    /// @notice The renewal a policy is waiting on, and whether `guardian` has
    ///         already answered it. Pass the zero address to skip that part.
    function getServicePeriodExtension(bytes32 policyId, address guardian)
        external
        view
        returns (
            bool pending,
            uint32 round,
            uint64 newServiceEnd,
            uint64 confirmBy,
            uint8 acceptedCount,
            uint8 guardianCount,
            bool acceptWindowOpen,
            bool guardianAccepted
        )
    {
        ServiceExtension storage ext = _serviceExtensions[policyId];
        return (
            ext.pending,
            ext.round,
            ext.newServiceEnd,
            ext.confirmBy,
            ext.acceptedCount,
            ext.guardianCount,
            ext.pending && block.timestamp <= ext.confirmBy,
            _extensionAccepted[policyId][ext.round][guardian]
        );
    }

    /// @dev Moves the end date once everyone has agreed, keeping serviceStart
    ///      where it was so the days already served still count, and turns on
    ///      the stretch of days the DO paid for.
    function _applyServiceExtension(bytes32 policyId) internal {
        ServiceExtension storage ext = _serviceExtensions[policyId];
        PolicyServicePeriod storage period = _policyServicePeriods[policyId];

        uint64 previousEnd = period.serviceEnd;
        uint32 round = ext.round;
        bool custodyReserved = ext.custodyReserved;
        uint32 stretchIndex = ext.custodyStretch;

        period.serviceEnd = ext.newServiceEnd;
        period.durationDays =
            uint64((uint256(period.serviceEnd) - uint256(period.serviceStart)) / 1 days);

        delete _serviceExtensions[policyId];

        if (custodyReserved) {
            IRewardManager_ShareProof(rewardManager).activateCustodyStretch(policyId, stretchIndex);
        }
        emit ServicePeriodExtended(
            policyId, round, previousEnd, period.serviceEnd, period.durationDays
        );
    }

    function _requirePolicyDO(bytes32 policyId) internal view returns (address[] memory guardians) {
        bool exists;
        bool active;
        address dataOwner;
        (exists, active, dataOwner, , guardians) = acl.getFilePolicy(policyId);
        require(exists && active, "ShareProof: no active policy");
        require(msg.sender == dataOwner || msg.sender == owner(), "ShareProof: not policy DO");
    }

    function getGuardianPolicyCount(address guardian) external view returns (uint256) {
        return _guardianPolicyIds[guardian].length;
    }

    function getGuardianPolicyAt(address guardian, uint256 index) external view returns (bytes32) {
        return _guardianPolicyIds[guardian][index];
    }

    function isRegisteredForPolicy(bytes32 policyId, address guardian) external view returns (bool) {
        return _guardianTrackedForPolicy[policyId][guardian];
    }

    function registerAsGuardianForPolicy(bytes32 policyId) external {
        require(_policyServicePeriods[policyId].exists, "ShareProof: no service period");
        (bool isGuardian, ) = _shareIndexOfGuardian(policyId, msg.sender);
        require(isGuardian, "ShareProof: not a policy guardian");
        if (!_guardianTrackedForPolicy[policyId][msg.sender]) {
            _guardianTrackedForPolicy[policyId][msg.sender] = true;
            _guardianPolicyIds[msg.sender].push(policyId);
        }
    }

    function hasActiveGuardianObligations(address guardian) public view returns (bool) {
        bytes32[] storage policyIds = _guardianPolicyIds[guardian];
        for (uint256 i = 0; i < policyIds.length; i++) {
            if (_hasActiveGuardianObligation(policyIds[i], guardian)) {
                return true;
            }
        }
        return false;
    }

    function hadActiveObligationInEpoch(address guardian, uint256 epoch) external view returns (bool) {
        return _hadActiveObligationInEpoch(guardian, epoch);
    }

    function registerPolicyGuardian(
        bytes32 policyId,
        uint32 keyEpoch,
        uint8 shareIndex
    ) public returns (address guardian, uint32 shareVersion, uint256 publicShareX, uint256 publicShareY) {
        return _registerPolicyGuardian(policyId, keyEpoch, shareIndex);
    }

    function registerMyPolicyShare(bytes32 policyId, uint32 keyEpoch) external {
        (bool selected, uint8 shareIndex) = _shareIndexOfGuardian(policyId, msg.sender);
        require(selected, "ShareProof: not policy guardian");
        _registerPolicyGuardian(policyId, keyEpoch, shareIndex);
    }

    function getRegisteredPublicShare(bytes32 policyId, uint32 keyEpoch, address guardian)
        external
        view
        returns (bool exists, uint32 shareVersion, uint8 shareIndex, uint256 x, uint256 y)
    {
        PublicShare storage publicShare = _publicShares[policyId][keyEpoch][guardian];
        return (
            publicShare.exists,
            publicShare.shareVersion,
            publicShare.shareIndex,
            publicShare.x,
            publicShare.y
        );
    }

    function getShareProofRecord(bytes32 policyId, uint32 keyEpoch, address guardian, uint256 proofEpoch)
        external
        view
        returns (bool submitted, bool valid, uint256 submittedAt)
    {
        uint256 meta = _proofRecordMeta[policyId][keyEpoch][guardian][proofEpoch];
        submitted = _metaSubmitted(meta);
        valid = _metaValid(meta);
        submittedAt = submitted ? _metaSubmittedAt(meta) : 0;
    }

    function hasSubmittedProofForEpoch(address guardian, uint256 proofEpoch) external view returns (bool) {
        return _hasSubmittedProofForEpoch(guardian, proofEpoch);
    }

    /// @notice What `proofEpoch` settled for `guardian`: whether a valid proof was accepted,
    ///         and which missed-epoch penalties are already charged. A penalty that was not
    ///         configured when the miss was reported also reads as charged.
    function getEpochOutcome(address guardian, uint256 proofEpoch)
        external
        view
        returns (bool validProof, bool reputationCharged, bool slashCharged)
    {
        uint8 outcome = _epochOutcome[guardian][proofEpoch];
        return (
            outcome & _EPOCH_VALID_PROOF != 0,
            outcome & _EPOCH_MISS_REPUTATION != 0,
            outcome & _EPOCH_MISS_SLASH != 0
        );
    }

    function getEligiblePolicies(address guardian, uint256 proofEpoch) public view returns (bytes32[] memory) {
        bytes32[] storage policyIds = _guardianPolicyIds[guardian];
        uint256 count = 0;
        for (uint256 i = 0; i < policyIds.length; i++) {
            if (_isPolicyEligible(policyIds[i], guardian, proofEpoch)) {
                count++;
            }
        }

        bytes32[] memory eligible = new bytes32[](count);
        uint256 out = 0;
        for (uint256 i = 0; i < policyIds.length; i++) {
            if (_isPolicyEligible(policyIds[i], guardian, proofEpoch)) {
                eligible[out] = policyIds[i];
                out++;
            }
        }
        return eligible;
    }

    function isPolicyEligibleForGuardian(bytes32 policyId, address guardian, uint256 proofEpoch)
        external
        view
        returns (bool)
    {
        return _isPolicyEligible(policyId, guardian, proofEpoch);
    }

    function selectPolicyForGuardian(address guardian, uint256 proofEpoch, uint256 challengeBlockNumber)
        public
        view
        returns (
            bool found,
            bytes32 policyId,
            uint32 keyEpoch,
            uint8 shareIndex,
            uint256 selectedIndex,
            uint256 eligiblePolicyCount
        )
    {
        bytes32 challengeBlockHash = _challengeBlockHash(challengeBlockNumber);
        bytes32[] memory eligible = getEligiblePolicies(guardian, proofEpoch);
        if (eligible.length == 0) {
            return (false, bytes32(0), 0, 0, 0, 0);
        }

        selectedIndex = uint256(keccak256(abi.encodePacked(
            challengeBlockHash,
            guardian,
            proofEpoch,
            eligible.length
        ))) % eligible.length;
        policyId = eligible[selectedIndex];
        (, , , , , keyEpoch, , , ) = coordinatorV2.getV2Key(policyId);
        (, shareIndex) = _shareIndexOfGuardian(policyId, guardian);
        return (true, policyId, keyEpoch, shareIndex, selectedIndex, eligible.length);
    }

    function getSelectedPolicyForGuardian(address guardian)
        external
        view
        returns (
            bool found,
            bytes32 policyId,
            uint32 keyEpoch,
            uint8 shareIndex,
            uint256 selectedIndex,
            uint256 eligiblePolicyCount
        )
    {
        return selectPolicyForGuardian(guardian, getProofEpoch(), block.number - 1);
    }

    /**
     * @notice Free polling call — Guardian checks this every few minutes.
     *         Returns selected=true only when the Guardian is due to submit right now.
     *         When proofWindowEnforced=false the window is always open (legacy mode).
     *
     * @return selected        true → submit a proof now using slotStartBlock as challengeBlockNumber.
     * @return inFallback      true → inside the guaranteed end-of-day fallback window.
     * @return policyId        Which policy to prove.
     * @return keyEpoch        Key epoch for that policy.
     * @return shareIndex      Guardian's share index in that policy.
     * @return windowEndBlock  First block number at which this slot's window is closed (0 = unlimited).
     * @return slotStartBlock  Pass this as challengeBlockNumber to submitSharePossessionProofForBlock.
     */
    function isProofWindowOpen(address guardian)
        external
        view
        returns (
            bool    selected,
            bool    inFallback,
            bytes32 policyId,
            uint32  keyEpoch,
            uint8   shareIndex,
            uint256 windowEndBlock,
            uint256 slotStartBlock
        )
    {
        uint256 epoch = getProofEpoch();

        if (_hasSubmittedProofForEpoch(guardian, epoch)) {
            return (false, false, bytes32(0), 0, 0, 0, 0);
        }

        bytes32[] memory eligible = getEligiblePolicies(guardian, epoch);
        if (eligible.length == 0) {
            return (false, false, bytes32(0), 0, 0, 0, 0);
        }

        bytes32 slotHash;

        if (!proofWindowEnforced) {
            // Legacy mode: always open; use block.number-1 as the challenge block.
            slotStartBlock = block.number > 0 ? block.number - 1 : 0;
            slotHash       = blockhash(slotStartBlock);
            if (slotHash == bytes32(0)) return (false, false, bytes32(0), 0, 0, 0, 0);
            windowEndBlock = 0;
            selected       = true;
        } else {
            slotStartBlock = _slotStartBlock();
            if (slotStartBlock == 0 || slotStartBlock >= block.number) {
                return (false, false, bytes32(0), 0, 0, 0, 0);
            }
            slotHash = blockhash(slotStartBlock);
            if (slotHash == bytes32(0)) return (false, false, bytes32(0), 0, 0, 0, 0);

            windowEndBlock = _slotWindowEndBlock(slotStartBlock);
            if (block.number >= windowEndBlock) {
                // This slot's window has already closed; Guardian will see a new slot next poll.
                return (false, false, bytes32(0), 0, 0, 0, slotStartBlock);
            }

            uint256 _totalSlots = _totalSlotsInEpoch();
            uint256 _slotIdx    = _currentSlotIndex(epoch);
            inFallback = _isFallbackSlot(_slotIdx, _totalSlots);
            (selected, policyId, keyEpoch, shareIndex) =
                _selectPolicyForOpenSlot(eligible, guardian, epoch, _slotIdx);
            if (!selected) {
                return (false, false, bytes32(0), 0, 0, 0, slotStartBlock);
            }
        }

        if (!proofWindowEnforced) {
            // Legacy mode: deterministically pick which policy to prove from the challenge hash.
            uint256 policyIndex = uint256(keccak256(abi.encodePacked(
                slotHash, guardian, epoch, eligible.length
            ))) % eligible.length;
            policyId = eligible[policyIndex];
            (, , , , , uint32 _keyEpoch, , ,) = coordinatorV2.getV2Key(policyId);
            keyEpoch = _keyEpoch;
            (, shareIndex) = _shareIndexOfGuardian(policyId, guardian);
        }
    }

    /**
     * @notice Returns current slot state — for monitoring, debugging, and DO dashboards.
     */
    function getCurrentSlotInfo() external view returns (
        uint256 epoch,
        uint256 slotIndex,
        uint256 totalSlots,
        uint256 remainingSlots,
        uint256 slotStartBlock_,
        bytes32 slotHash,
        bool    isLastSlot,
        uint256 windowEndBlock
    ) {
        epoch           = getProofEpoch();
        totalSlots      = _totalSlotsInEpoch();
        slotIndex       = _currentSlotIndex(epoch);
        remainingSlots  = totalSlots - slotIndex;
        slotStartBlock_ = _slotStartBlock();
        if (slotStartBlock_ > 0 && slotStartBlock_ < block.number) {
            slotHash = blockhash(slotStartBlock_);
        }
        isLastSlot     = (slotIndex >= totalSlots - 1);
        windowEndBlock = _slotWindowEndBlock(slotStartBlock_);
    }

    function deriveChallenge(bytes32 policyId, uint32 keyEpoch, address guardian, uint256 proofEpoch)
        public
        view
        returns (uint256)
    {
        bytes32 previousBlockHash = blockhash(block.number - 1);
        return deriveProofChallengeFromBlockHash(previousBlockHash, policyId, keyEpoch, guardian, proofEpoch, 0, 0);
    }

    function deriveChallengeFromBlockHash(
        bytes32 previousBlockHash,
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 proofEpoch
    ) public pure returns (uint256) {
        return deriveProofChallengeFromBlockHash(previousBlockHash, policyId, keyEpoch, guardian, proofEpoch, 0, 0);
    }

    function deriveProofChallenge(
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 proofEpoch,
        uint256 rx,
        uint256 ry
    ) public view returns (uint256) {
        return deriveProofChallengeFromBlockHash(
            blockhash(block.number - 1),
            policyId,
            keyEpoch,
            guardian,
            proofEpoch,
            rx,
            ry
        );
    }

    function deriveProofChallengeFromBlockHash(
        bytes32 previousBlockHash,
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 proofEpoch,
        uint256 rx,
        uint256 ry
    ) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            previousBlockHash,
            policyId,
            keyEpoch,
            guardian,
            proofEpoch,
            rx,
            ry
        ))) % BABY_L;
    }

    function computeSharePossessionContextHash(
        uint256 challengeBlockNumber,
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 proofEpoch,
        uint256 challengePointX,
        uint256 challengePointY,
        uint256 shareX,
        uint256 shareY,
        uint256 responsePointX,
        uint256 responsePointY
    ) public view returns (uint256) {
        return _computeSharePossessionContextHash(
            _challengeBlockHash(challengeBlockNumber),
            policyId,
            keyEpoch,
            guardian,
            proofEpoch,
            challengePointX,
            challengePointY,
            shareX,
            shareY,
            responsePointX,
            responsePointY
        );
    }

    function submitSharePossessionProof(
        bytes32 policyId,
        uint32 keyEpoch,
        uint256 rx,
        uint256 ry,
        uint256 z
    ) external pure returns (bool) {
        policyId;
        keyEpoch;
        rx;
        ry;
        z;
        revert("ShareProof: native verifier disabled");
    }

    function submitSharePossessionProofForBlock(
        bytes32 policyId,
        uint32 keyEpoch,
        uint256 challengeBlockNumber,
        uint256 rx,
        uint256 ry,
        uint256 z
    ) external pure returns (bool) {
        policyId;
        keyEpoch;
        challengeBlockNumber;
        rx;
        ry;
        z;
        revert("ShareProof: native verifier disabled");
    }

    function submitSharePossessionProof(
        bytes32 policyId,
        uint32 keyEpoch,
        uint256 challengePointX,
        uint256 challengePointY,
        uint256 responsePointX,
        uint256 responsePointY,
        SharePossessionGroth16Proof calldata proof
    ) external returns (bool valid) {
        return _submitSharePossessionProofGroth16(
            policyId,
            keyEpoch,
            block.number - 1,
            challengePointX,
            challengePointY,
            responsePointX,
            responsePointY,
            proof
        );
    }

    function submitSharePossessionProofForBlock(
        bytes32 policyId,
        uint32 keyEpoch,
        uint256 challengeBlockNumber,
        uint256 challengePointX,
        uint256 challengePointY,
        uint256 responsePointX,
        uint256 responsePointY,
        SharePossessionGroth16Proof calldata proof
    ) external returns (bool valid) {
        return _submitSharePossessionProofGroth16(
            policyId,
            keyEpoch,
            challengeBlockNumber,
            challengePointX,
            challengePointY,
            responsePointX,
            responsePointY,
            proof
        );
    }

    function checkMissedProof(
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 proofEpoch
    ) external returns (bool missed) {
        return checkMissedProofForBlock(policyId, keyEpoch, guardian, proofEpoch, block.number - 1);
    }

    function checkMissedProofForBlock(
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 proofEpoch,
        uint256 challengeBlockNumber
    ) public nonReentrant returns (bool missed) {
        require(block.timestamp > ((proofEpoch + 1) * proofPeriodSeconds) + proofGraceSeconds, "ShareProof: deadline open");
        // An epoch outside every service period owed no proof. Without the epoch check any
        // past epoch number could be charged as one more miss.
        if (!_hasActiveGuardianObligation(policyId, guardian) || !_hadActiveObligationInEpoch(guardian, proofEpoch)) {
            return false;
        }

        (bool found, bytes32 selectedPolicy, uint32 selectedEpoch, , , ) =
            selectPolicyForGuardian(guardian, proofEpoch, challengeBlockNumber);
        if (!found || selectedPolicy != policyId || selectedEpoch != keyEpoch) {
            return false;
        }

        // One valid proof settles the whole epoch, so the miss is the epoch's, not this
        // policy's: a Guardian that proved the policy it was selected for has not missed.
        // Returns the fact of the miss; the reputation penalty is charged only once.
        missed = !_hasValidProofForEpoch(guardian, proofEpoch);
        if (missed) {
            _chargeMissedEpoch(policyId, keyEpoch, guardian, proofEpoch, false);
        }
    }

    /**
     * @notice Mark that a Guardian proved nothing valid during `epoch`. An invalid proof
     *         counts as missed. Callable by anyone after the epoch + grace period ends; the
     *         first report that charges the stake slash collects the reporter bounty.
     *         Uses epoch-level tracking — simpler than the policy-specific checkMissedProof.
     */
    function markMissedEpoch(address guardian, uint256 epoch) external nonReentrant {
        require(
            block.timestamp > (epoch + 1) * proofPeriodSeconds + proofGraceSeconds,
            "ShareProof: epoch not finished"
        );
        require(!_hasValidProofForEpoch(guardian, epoch), "ShareProof: proof was submitted");
        require(_hadActiveObligationInEpoch(guardian, epoch), "ShareProof: no obligations in epoch");
        require(_chargeMissedEpoch(bytes32(0), 0, guardian, epoch, true), "ShareProof: miss already charged");
    }

    /**
     * @notice Batch version of markMissedEpoch.
     *         Reporter submits up to maxReporterBatchSize Guardians in one tx.
     *         Skips (does not revert) any Guardian that proved, had no obligation, or was
     *         already charged — a Guardian listed twice is charged once.
     */
    function markMissedEpochBatch(address[] calldata guardians, uint256 epoch) external nonReentrant {
        require(
            block.timestamp > (epoch + 1) * proofPeriodSeconds + proofGraceSeconds,
            "ShareProof: epoch not finished"
        );
        uint256 limit = guardians.length < maxReporterBatchSize ? guardians.length : maxReporterBatchSize;
        for (uint256 i = 0; i < limit; i++) {
            address g = guardians[i];
            if (_hasValidProofForEpoch(g, epoch)) continue;
            if (!_hadActiveObligationInEpoch(g, epoch)) continue;
            _chargeMissedEpoch(bytes32(0), 0, g, epoch, true);
        }
    }

    /// @dev Charges a missed epoch what it still owes: the reputation miss and, with
    ///      `withSlash`, the stake slash -- each at most once. StakingManager takes the slash
    ///      in one step: 10% to the reporter, 90% to the treasury. A Guardian reporting its
    ///      own miss, directly or through a contract its own key calls, names no reporter
    ///      and the treasury gets it all: the bounty is for catching somebody else. A second
    ///      wallet of the same operator cannot be told apart, and gets the 10%. A penalty's
    ///      bit is taken before any call, so a re-entrant report finds it charged, and given
    ///      back if its call fails, so a report that cannot complete it (a Guardian with no
    ///      stake, a reporter refusing the bounty) leaves it for the next report. A report
    ///      starved of gas cannot use a penalty up either: after a starved call this frame
    ///      keeps about 1/64 of the gas, which either gives the bit back like any failure or,
    ///      too little for the write (or for the guard's own), reverts the report whole. A
    ///      penalty not configured at report time counts as charged. Returns false when
    ///      nothing was owed.
    function _chargeMissedEpoch(
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 epoch,
        bool withSlash
    ) internal returns (bool owedAny) {
        uint8 before = _epochOutcome[guardian][epoch];
        uint8 owed = (withSlash ? _EPOCH_MISS_REPUTATION | _EPOCH_MISS_SLASH : _EPOCH_MISS_REPUTATION) & ~before;
        if (owed == 0) return false;
        _epochOutcome[guardian][epoch] = before | owed;

        uint8 failed;
        if (owed & _EPOCH_MISS_REPUTATION != 0 && reputationManager != address(0)) {
            try IReputationManager_ShareProof(reputationManager).recordShareProofMissedFor(guardian, bytes32(epoch)) {}
            catch { failed = _EPOCH_MISS_REPUTATION; }
        }
        if (owed & _EPOCH_MISS_SLASH != 0 && stakingManager != address(0) && missedEpochPenaltyWei > 0) {
            address reporter = msg.sender == guardian || tx.origin == guardian ? address(0) : msg.sender;
            try IStakingManager_ShareProof(stakingManager).slashGuardianPenalty(guardian, missedEpochPenaltyWei, reporter) {}
            catch { failed |= _EPOCH_MISS_SLASH; }
        }
        if (failed != 0) {
            _epochOutcome[guardian][epoch] = before | (owed & ~failed);
        }

        // One miss, one event: emitted by the report that first charges anything for it.
        if (owed != failed && before & (_EPOCH_MISS_REPUTATION | _EPOCH_MISS_SLASH) == 0) {
            emit ShareProofMissed(policyId, keyEpoch, guardian, epoch);
        }
        return true;
    }

    function _submitSharePossessionProofGroth16(
        bytes32 policyId,
        uint32 keyEpoch,
        uint256 challengeBlockNumber,
        uint256 challengePointX,
        uint256 challengePointY,
        uint256 responsePointX,
        uint256 responsePointY,
        SharePossessionGroth16Proof calldata proof
    ) internal returns (bool valid) {
        require(sharePossessionVerifier != address(0), "ShareProof: verifier not set");
        uint256 proofEpoch = getProofEpoch();
        if (proofWindowEnforced) {
            _requireProofWindow(msg.sender, proofEpoch, challengeBlockNumber, policyId);
        }
        bytes32 challengeBlockHash = _challengeBlockHash(challengeBlockNumber);
        (uint32 selectedEpoch, uint8 shareIndex) =
            _requireSubmittedPolicySelected(msg.sender, proofEpoch, challengeBlockHash, policyId);
        require(selectedEpoch == keyEpoch, "ShareProof: policy not selected");
        require(BabyJubjub.isOnCurve(challengePointX, challengePointY), "ShareProof: challenge point off curve");
        require(BabyJubjub.isOnCurve(responsePointX, responsePointY), "ShareProof: response point off curve");

        if (!_publicShares[policyId][keyEpoch][msg.sender].exists) {
            _registerPolicyGuardian(policyId, keyEpoch, shareIndex);
        }

        PublicShare storage publicShare = _publicShares[policyId][keyEpoch][msg.sender];
        uint256 contextHash = _computeSharePossessionContextHash(
            challengeBlockHash,
            policyId,
            keyEpoch,
            msg.sender,
            proofEpoch,
            challengePointX,
            challengePointY,
            publicShare.x,
            publicShare.y,
            responsePointX,
            responsePointY
        );
        uint256[8] memory input = [
            publicShare.x,
            publicShare.y,
            challengePointX,
            challengePointY,
            responsePointX,
            responsePointY,
            contextHash,
            uint256(1)
        ];
        valid = ISharePossessionVerifier(sharePossessionVerifier).verifyTx(proof, input);
        _proofRecordMeta[policyId][keyEpoch][msg.sender][proofEpoch] = _packProofMeta(valid);
        if (valid) {
            _epochOutcome[msg.sender][proofEpoch] |= _EPOCH_VALID_PROOF;
        }
        lastProofAt[msg.sender] = block.timestamp;

        emit ShareProofSubmitted(policyId, keyEpoch, msg.sender, proofEpoch, valid);

        if (valid) {
            if (reputationManager != address(0)) {
                try IReputationManager_ShareProof(reputationManager).recordShareProofSuccess(msg.sender) {} catch {}
            }
            if (rewardManager != address(0)) {
                try IRewardManager_ShareProof(rewardManager).creditShareProof(msg.sender) {} catch {}
            }
        }

        return valid;
    }

    function _computeSharePossessionContextHash(
        bytes32 challengeBlockHash,
        bytes32 policyId,
        uint32 keyEpoch,
        address guardian,
        uint256 proofEpoch,
        uint256 challengePointX,
        uint256 challengePointY,
        uint256 shareX,
        uint256 shareY,
        uint256 responsePointX,
        uint256 responsePointY
    ) internal view returns (uint256) {
        // Bound to this contract and chain (Phase 2): a proof made for one GuardianShareProof
        // version is never accepted, or paid, by another.
        return uint256(keccak256(abi.encode(
            address(this),
            block.chainid,
            challengeBlockHash,
            policyId,
            keyEpoch,
            guardian,
            proofEpoch,
            challengePointX,
            challengePointY,
            shareX,
            shareY,
            responsePointX,
            responsePointY
        ))) % BABY_P;
    }

    function _registerPolicyGuardian(
        bytes32 policyId,
        uint32 keyEpoch,
        uint8 shareIndex
    ) internal returns (address guardian, uint32 shareVersion, uint256 publicShareX, uint256 publicShareY) {
        guardian = _guardianAt(policyId, shareIndex);

        (bool keyExists, bool finalized, , , , uint32 activeEpoch, uint32 activeShareVersion, , ) =
            coordinatorV2.getV2Key(policyId);
        require(keyExists && finalized, "ShareProof: no finalized V2 key");
        require(activeEpoch == keyEpoch, "ShareProof: inactive epoch");
        shareVersion = activeShareVersion;

        (bool pkExists, address pkGuardian, uint8 storedShareIndex, uint256 x, uint256 y) =
            coordinatorV2.getV2SharePublicKeyFull(policyId, keyEpoch, shareVersion, shareIndex);
        require(pkExists, "ShareProof: missing public share");
        require(pkGuardian == guardian && storedShareIndex == shareIndex, "ShareProof: public share mismatch");
        require(BabyJubjub.isOnCurve(x, y), "ShareProof: public share off curve");

        _publicShares[policyId][keyEpoch][guardian] = PublicShare({
            exists: true,
            shareVersion: shareVersion,
            shareIndex: shareIndex,
            x: x,
            y: y
        });

        emit GuardianPublicShareRegistered(policyId, keyEpoch, guardian, shareVersion, shareIndex, x, y);
        return (guardian, shareVersion, x, y);
    }

    // ── Slot helpers ────────────────────────────────────────────────────────────

    function _blocksPerSlot() internal view returns (uint256) {
        uint256 bps = slotSeconds / avgBlockSeconds;
        return bps > 0 ? bps : 1;
    }

    function _windowBlocks() internal view returns (uint256) {
        uint256 wb = windowSeconds / avgBlockSeconds;
        return wb > 0 ? wb : 1;
    }

    function _slotWindowEndBlock(uint256 slotStartBlock_) internal view returns (uint256) {
        return slotStartBlock_ + _windowBlocks();
    }

    function _slotStartBlock() internal view returns (uint256) {
        uint256 bps   = _blocksPerSlot();
        uint256 start = (block.number / bps) * bps;
        // Ensure we return a strictly past block so blockhash() works.
        return start < block.number ? start : (start >= bps ? start - bps : 0);
    }

    function _totalSlotsInEpoch() internal view returns (uint256) {
        uint256 total = proofPeriodSeconds / slotSeconds;
        return total > 0 ? total : 1;
    }

    function _primarySlotCount(uint256 totalSlots) internal pure returns (uint256) {
        return totalSlots > 1 ? totalSlots - 1 : 1;
    }

    function _isFallbackSlot(uint256 slotIndex, uint256 totalSlots) internal pure returns (bool) {
        return totalSlots <= 1 || slotIndex >= totalSlots - 1;
    }

    function _currentSlotIndex(uint256 epoch) internal view returns (uint256) {
        uint256 epochStart = epoch * proofPeriodSeconds;
        if (block.timestamp < epochStart) return 0;
        uint256 elapsed = block.timestamp - epochStart;
        uint256 idx = elapsed / slotSeconds;
        uint256 total = _totalSlotsInEpoch();
        return idx < total ? idx : total - 1;
    }

    function _selectPolicyForOpenSlot(
        bytes32[] memory eligible,
        address guardian,
        uint256 epoch,
        uint256 slotIndex
    ) internal view returns (bool selected, bytes32 policyId, uint32 keyEpoch, uint8 shareIndex) {
        if (eligible.length == 0) {
            return (false, bytes32(0), 0, 0);
        }

        uint256 totalSlots = _totalSlotsInEpoch();
        if (_isFallbackSlot(slotIndex, totalSlots)) {
            policyId = eligible[_selectedPolicyIndex(guardian, epoch, eligible.length)];
            (, , , , , keyEpoch, , ,) = coordinatorV2.getV2Key(policyId);
            (, shareIndex) = _shareIndexOfGuardian(policyId, guardian);
            return (shareIndex > 0, policyId, keyEpoch, shareIndex);
        }

        for (uint256 i = 0; i < eligible.length; i++) {
            (, shareIndex) = _shareIndexOfGuardian(eligible[i], guardian);
            if (
                shareIndex > 0
                    && _assignedProofSlot(eligible[i], epoch, shareIndex, totalSlots) == slotIndex
            ) {
                policyId = eligible[i];
                (, , , , , keyEpoch, , ,) = coordinatorV2.getV2Key(policyId);
                return (true, policyId, keyEpoch, shareIndex);
            }
        }

        return (false, bytes32(0), 0, 0);
    }

    function _selectedPolicyIndex(address guardian, uint256 epoch, uint256 eligibleCount) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(
            guardian,
            epoch,
            eligibleCount
        ))) % eligibleCount;
    }

    function _assignedProofSlot(
        bytes32 policyId,
        uint256 epoch,
        uint8 shareIndex,
        uint256 totalSlots
    ) internal view returns (uint256) {
        uint256 primarySlots = _primarySlotCount(totalSlots);
        uint256 guardianCount = _policyGuardianCount(policyId);
        if (guardianCount == 0 || shareIndex == 0) {
            return uint256(keccak256(abi.encodePacked(policyId, epoch, shareIndex))) % primarySlots;
        }

        uint256 offset = uint256(keccak256(abi.encodePacked(
            policyId,
            epoch,
            guardianCount
        ))) % primarySlots;

        if (guardianCount <= primarySlots) {
            uint256 stride = primarySlots / guardianCount;
            return (offset + ((uint256(shareIndex) - 1) * stride)) % primarySlots;
        }

        return uint256(keccak256(abi.encodePacked(
            policyId,
            epoch,
            shareIndex
        ))) % primarySlots;
    }

    function _policyGuardianCount(bytes32 policyId) internal view returns (uint256) {
        (bool exists, bool active, , , address[] memory guardians) = acl.getFilePolicy(policyId);
        if (!exists || !active) {
            return 0;
        }
        return guardians.length;
    }

    function _requireProofWindow(
        address guardian,
        uint256 epoch,
        uint256 challengeBlockNumber_,
        bytes32 submittedPolicyId
    ) internal view {
        uint256 bps = _blocksPerSlot();
        require(challengeBlockNumber_ % bps == 0, "ShareProof: not a slot start");
        require(challengeBlockNumber_ == _slotStartBlock(), "ShareProof: stale slot");
        require(block.number < _slotWindowEndBlock(challengeBlockNumber_), "ShareProof: window closed");
        bytes32 slotHash = blockhash(challengeBlockNumber_);
        require(slotHash != bytes32(0), "ShareProof: slot hash unavailable");
        bytes32[] memory eligible = getEligiblePolicies(guardian, epoch);
        (bool selected, bytes32 policyId, , ) =
            _selectPolicyForOpenSlot(eligible, guardian, epoch, _currentSlotIndex(epoch));
        require(
            selected && policyId == submittedPolicyId,
            "ShareProof: not selected for this slot"
        );
    }

    function _hadActiveObligationInEpoch(address guardian, uint256 epoch) internal view returns (bool) {
        uint256 epochStart = epoch * proofPeriodSeconds;
        uint256 epochEnd   = (epoch + 1) * proofPeriodSeconds;
        bytes32[] storage policyIds = _guardianPolicyIds[guardian];
        for (uint256 i = 0; i < policyIds.length; i++) {
            PolicyServicePeriod storage period = _policyServicePeriods[policyIds[i]];
            if (period.exists && period.serviceStart < epochEnd && period.serviceEnd > epochStart) {
                (bool sel, ) = _shareIndexOfGuardian(policyIds[i], guardian);
                if (sel) return true;
            }
        }
        return false;
    }

    // ────────────────────────────────────────────────────────────────────────────

    function _validateGuardianAvailability(address[] memory guardians, uint256 durationDays) internal view {
        address registry = acl.guardianRegistry();
        if (registry == address(0)) {
            return;
        }
        for (uint256 i = 0; i < guardians.length; i++) {
            try IGuardianRegistry_ShareProof(registry).getGuardianAvailability(guardians[i])
                returns (uint256 maxServiceDays, bool, bool exists)
            {
                require(!exists || maxServiceDays == 0 || durationDays <= maxServiceDays, "ShareProof: guardian duration unavailable");
            } catch {
                // Older registry deployments do not expose availability yet.
            }
        }
    }

    function _requireSubmittedPolicySelected(
        address guardian,
        uint256 proofEpoch,
        bytes32 challengeBlockHash,
        bytes32 submittedPolicyId
    ) internal view returns (uint32 selectedKeyEpoch, uint8 selectedShareIndex) {
        bytes32[] storage policyIds = _guardianPolicyIds[guardian];
        uint256 eligibleCount = 0;
        uint256 submittedIndex = type(uint256).max;

        for (uint256 i = 0; i < policyIds.length; i++) {
            (bool eligible, uint32 keyEpoch, uint8 shareIndex, bool submitted, ) =
                _policyEligibilityInfo(policyIds[i], guardian, proofEpoch);
            require(!submitted, "ShareProof: epoch proof already submitted");
            if (eligible) {
                if (policyIds[i] == submittedPolicyId) {
                    submittedIndex = eligibleCount;
                    selectedKeyEpoch = keyEpoch;
                    selectedShareIndex = shareIndex;
                }
                eligibleCount++;
            }
        }

        require(eligibleCount > 0, "ShareProof: no eligible policy");
        require(submittedIndex != type(uint256).max, "ShareProof: policy not selected");
        if (!proofWindowEnforced) {
            uint256 selectedIndex = uint256(keccak256(abi.encodePacked(
                challengeBlockHash,
                guardian,
                proofEpoch,
                eligibleCount
            ))) % eligibleCount;
            require(submittedIndex == selectedIndex, "ShareProof: policy not selected");
        }
    }

    function _guardianAt(bytes32 policyId, uint8 shareIndex) internal view returns (address guardian) {
        (bool exists, bool active, , , address[] memory guardians) = acl.getFilePolicy(policyId);
        require(exists && active, "ShareProof: no active policy");
        require(shareIndex > 0 && shareIndex <= guardians.length, "ShareProof: bad share index");
        return guardians[uint256(shareIndex) - 1];
    }

    function _shareIndexOfGuardian(bytes32 policyId, address guardian) internal view returns (bool selected, uint8 shareIndex) {
        (bool exists, bool active, , , address[] memory guardians) = acl.getFilePolicy(policyId);
        if (!exists || !active) {
            return (false, 0);
        }
        for (uint8 i = 0; i < guardians.length; i++) {
            if (guardians[i] == guardian) {
                return (true, i + 1);
            }
        }
        return (false, 0);
    }

    function _isPolicyEligible(bytes32 policyId, address guardian, uint256 proofEpoch) internal view returns (bool) {
        (bool eligible, , , , ) = _policyEligibilityInfo(policyId, guardian, proofEpoch);
        return eligible;
    }

    function _policyEligibilityInfo(bytes32 policyId, address guardian, uint256 proofEpoch)
        internal
        view
        returns (bool eligible, uint32 keyEpoch, uint8 shareIndex, bool submitted, bool valid)
    {
        PolicyServicePeriod storage period = _policyServicePeriods[policyId];
        if (!period.exists || block.timestamp < period.serviceStart || block.timestamp > period.serviceEnd) {
            return (false, 0, 0, false, false);
        }

        (bool policyExists, bool active, , , address[] memory guardians) = acl.getFilePolicy(policyId);
        if (!policyExists || !active) {
            return (false, 0, 0, false, false);
        }
        for (uint8 i = 0; i < guardians.length; i++) {
            if (guardians[i] == guardian) {
                shareIndex = i + 1;
                break;
            }
        }
        if (shareIndex == 0) {
            return (false, 0, 0, false, false);
        }

        (bool keyExists, bool finalized, , , , uint32 activeKeyEpoch, uint32 shareVersion, , ) =
            coordinatorV2.getV2Key(policyId);
        if (!keyExists || !finalized) {
            return (false, 0, 0, false, false);
        }
        keyEpoch = activeKeyEpoch;
        uint256 meta = _proofRecordMeta[policyId][keyEpoch][guardian][proofEpoch];
        submitted = _metaSubmitted(meta);
        valid = _metaValid(meta);
        if (valid) {
            return (false, keyEpoch, shareIndex, submitted, valid);
        }
        if (_publicShares[policyId][keyEpoch][guardian].exists) {
            return (true, keyEpoch, shareIndex, submitted, valid);
        }

        (bool pkExists, address pkGuardian, uint8 storedShareIndex, , ) =
            coordinatorV2.getV2SharePublicKeyFull(policyId, keyEpoch, shareVersion, shareIndex);
        return (
            pkExists && pkGuardian == guardian && storedShareIndex == shareIndex,
            keyEpoch,
            shareIndex,
            submitted,
            valid
        );
    }

    function _packProofMeta(bool valid) internal view returns (uint256) {
        return _PROOF_META_SUBMITTED
            | (valid ? _PROOF_META_VALID : 0)
            | (block.timestamp << _PROOF_META_SUBMITTED_AT_SHIFT);
    }

    function _metaSubmitted(uint256 meta) internal pure returns (bool) {
        return (meta & _PROOF_META_SUBMITTED) != 0;
    }

    function _metaValid(uint256 meta) internal pure returns (bool) {
        return (meta & _PROOF_META_VALID) != 0;
    }

    function _metaSubmittedAt(uint256 meta) internal pure returns (uint256) {
        return meta >> _PROOF_META_SUBMITTED_AT_SHIFT;
    }

    function _hasSubmittedProofForEpoch(address guardian, uint256 proofEpoch) internal view returns (bool) {
        bytes32[] storage policyIds = _guardianPolicyIds[guardian];
        for (uint256 i = 0; i < policyIds.length; i++) {
            (bool keyExists, bool finalized, , , , uint32 keyEpoch, , , ) = coordinatorV2.getV2Key(policyIds[i]);
            if (
                keyExists
                    && finalized
                    && _metaSubmitted(_proofRecordMeta[policyIds[i]][keyEpoch][guardian][proofEpoch])
            ) {
                return true;
            }
        }
        return false;
    }

    /// @dev Only a valid proof settles an epoch. An invalid one still blocks a second
    ///      submission (_requireSubmittedPolicySelected), but it excuses no penalty.
    function _hasValidProofForEpoch(address guardian, uint256 proofEpoch) internal view returns (bool) {
        return _epochOutcome[guardian][proofEpoch] & _EPOCH_VALID_PROOF != 0;
    }

    function _hasActiveGuardianObligation(bytes32 policyId, address guardian) internal view returns (bool) {
        PolicyServicePeriod storage period = _policyServicePeriods[policyId];
        if (!period.exists || block.timestamp < period.serviceStart || block.timestamp > period.serviceEnd) {
            return false;
        }
        (bool selected, ) = _shareIndexOfGuardian(policyId, guardian);
        return selected;
    }

    function _challengeBlockHash(uint256 challengeBlockNumber) internal view returns (bytes32) {
        require(challengeBlockNumber < block.number, "ShareProof: challenge in future");
        require(block.number - challengeBlockNumber <= 256, "ShareProof: challenge too old");
        bytes32 challengeBlockHash = blockhash(challengeBlockNumber);
        require(challengeBlockHash != bytes32(0), "ShareProof: missing challenge block");
        return challengeBlockHash;
    }

}
