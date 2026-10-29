// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DkgAttemptController
// Purpose:  Connect accepted DKG duties to actual work, escrow and objective expiry.
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

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "./DkgAttemptRegistry.sol";
import "./DkgAttemptEscrow.sol";
import "./DkgAttemptTypes.sol";
import "./BabyJubjub.sol";
import "./DkgCommitmentBook.sol";

interface IDkgControllerAcl {
    function owner() external view returns (address);
    function guardianRegistry() external view returns (address);
    function getFilePolicy(bytes32 fileId) external view returns (bool, bool, address, uint8, address[] memory);
    function getDkgFilePolicy(bytes32 fileId) external view returns (bool, bool, address, uint8, address[] memory);
    function getFilePolicyMode(bytes32 fileId) external view returns (uint8);
    function hasRequestedKeyGenForFile(bytes32 fileId) external view returns (bool);
    function keyGenDeadlineForFile(bytes32 fileId) external view returns (uint64);
}
interface IDkgControllerGuardians {
    function isActiveGuardian(address guardian) external view returns (bool);
}
interface IDkgControllerReputation {
    function recordDkgFailure(address guardian, uint8 reasonCode) external;
}

/// @notice Production accounting/lifecycle component for a versioned DKG
/// deployment. It never treats a heartbeat or a DO allegation as work failure.
/// @dev Payments for publication work are settled only after complaints close.
/// Compensation reimburses fees actually earned in this attempt, capped by each
/// accepted bond. It does not promise reimbursement of arbitrary DO gas costs.
contract DkgAttemptController is ReentrancyGuard {
    struct Preparation { bytes32 requestHash; bytes32 encryptionHash; address evidence; uint64 disputeDuration; }
    struct Role { uint8 dealerIndex; uint8 receiverIndex; }
    struct Work {
        uint32 dealers;
        uint32 receivers;
        uint32 contributors;
        uint32 bad;
        bool failed;
        bool cancelled;
        bool blockedReceivers;
    }
    struct Job {
        bytes32 registryId;
        bytes32 fileId;
        bytes32 contextHash;
        address dataOwner;
        address evidence;
        address reputation;
        uint32 epoch;
        uint32 version;
        uint8 receiverCount;
        uint8 threshold;
        uint64 dealerDuration;
        uint64 receiverDuration;
        uint64 disputeDuration;
        uint64 readyAt;
        bool refresh;
        bool closed;
    }

    address public immutable coordinator;
    address public immutable acl;
    address public immutable staking;
    DkgCommitmentBook public immutable commitments;
    DkgAttemptRegistry public registry;
    DkgAttemptEscrow public escrow;
    uint256 public activeCount;
    uint64 public constant MAX_STAGE_DURATION = 1 days;
    mapping(bytes32 => Job) private _jobs;
    mapping(bytes32 => Preparation) public preparations;
    mapping(bytes32 => bytes32) public materialForRegistryId;
    mapping(bytes32 => address[]) private _participants;
    mapping(bytes32 => mapping(address => Role)) private _roles;
    mapping(bytes32 => address[]) private _receivers;
    mapping(bytes32 => mapping(address => bool)) public reputationPending;

    error Unauthorized();
    error InvalidContext();
    error InvalidState();
    error InvalidTerms();
    error TooEarly();
    error UnresolvedComplaints();
    error WorkAlreadyCompleted();

    event AttemptBound(bytes32 indexed materialId, bytes32 indexed registryId, bytes32 indexed fileId, bytes32 contextHash);
    event MaterialStageReady(bytes32 indexed materialId, uint64 readyAt);
    event AttemptAccounted(bytes32 indexed materialId, uint8 outcome, uint8 faults, uint256 compensation);
    event ReputationDeferred(bytes32 indexed materialId, address indexed guardian);
    event AttemptPrepared(bytes32 indexed materialId, bytes32 requestHash, address evidence);

    constructor(address coordinator_, address acl_, address staking_) {
        if (coordinator_.code.length == 0 || acl_.code.length == 0 || staking_.code.length == 0
            || IDkgAttemptCoordinator(coordinator_).acl() != acl_) revert InvalidContext();
        coordinator = coordinator_; acl = acl_; staking = staking_;
        commitments = new DkgCommitmentBook();
    }

    modifier onlyCoordinator() { if (msg.sender != coordinator) revert Unauthorized(); _; }
    modifier onlyRegistry() { if (msg.sender != address(registry)) revert Unauthorized(); _; }

    function configure(address registry_, address escrow_) external {
        if (msg.sender != IDkgControllerAcl(acl).owner()) revert Unauthorized();
        if (address(registry) != address(0) || registry_.code.length == 0 || escrow_.code.length == 0) revert InvalidContext();
        DkgAttemptRegistry book = DkgAttemptRegistry(registry_);
        DkgAttemptEscrow money = DkgAttemptEscrow(payable(escrow_));
        if (book.coordinator() != address(this) || money.coordinator() != address(this)
            || address(money.staking()) != staking) revert InvalidContext();
        registry = book; escrow = money;
    }

    function participantsFor(bytes32 fileId, uint32 epoch, uint32 version) external view returns (address[] memory) {
        DkgAttemptTypes.Request memory r = getAttemptRequest(fileId, epoch, version);
        return _members(r);
    }

    /// @notice Freeze public key/verifier/commitment metadata before financial
    /// opening. No fee, bond or accepted duty exists at this stage. Separating
    /// it keeps a disjoint 20-old/20-new committee under transaction gas caps.
    function prepare(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version) external nonReentrant {
        DkgAttemptTypes.Request memory r = getAttemptRequest(fileId, epoch, version);
        if (materialId != r.materialId || r.dataOwner != msg.sender || block.timestamp > r.unopenedDeadline
            || address(registry) == address(0) || _jobs[materialId].registryId != bytes32(0)) revert InvalidContext();
        _members(r);
        _prepare(r);
    }

    function _prepare(DkgAttemptTypes.Request memory r) private returns (Preparation memory p) {
        address evidence = IDkgAttemptCoordinator(coordinator).disputeManager();
        bytes32 requestHash = keccak256(abi.encode(r));
        p = preparations[r.materialId];
        if (p.evidence != address(0)) {
            if (p.requestHash != requestHash || p.evidence != evidence) revert InvalidContext();
            return p;
        }
        (bytes32 encryptionHash, uint64 duration) = IDkgAttemptEvidence(evidence).snapshotAttempt(r.materialId, r.fileId, r.epoch, r.version);
        if (duration == 0 || duration > MAX_STAGE_DURATION) revert InvalidTerms();
        commitments.open(r, coordinator);
        p = Preparation(requestHash, encryptionHash, evidence, duration);
        preparations[r.materialId] = p;
        emit AttemptPrepared(r.materialId, requestHash, evidence);
    }

    function open(
        bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version,
        uint64 acceptBy, uint64 dealerDuration, uint64 receiverDuration,
        DkgAttemptEscrow.FeeCaps[] calldata fees, uint256[] calldata bonds
    ) external payable nonReentrant returns (bytes32 registryId) {
        if (address(registry) == address(0) || IDkgAttemptCoordinator(coordinator).attemptController() != address(this)) revert InvalidContext();
        DkgAttemptTypes.Request memory r = getAttemptRequest(fileId, epoch, version);
        if (r.materialId != materialId || materialId == bytes32(0) || r.dataOwner != msg.sender
            || _jobs[materialId].registryId != bytes32(0) || block.timestamp > r.unopenedDeadline) revert InvalidContext();
        if (dealerDuration == 0 || receiverDuration == 0 || dealerDuration > MAX_STAGE_DURATION
            || receiverDuration > MAX_STAGE_DURATION || acceptBy <= block.timestamp
            || uint256(acceptBy) > block.timestamp + MAX_STAGE_DURATION) revert InvalidTerms();
        address[] memory members = _members(r);
        if (fees.length != members.length || bonds.length != members.length) revert InvalidTerms();
        Preparation memory p = _prepare(r);
        if (uint256(acceptBy) + dealerDuration + receiverDuration + p.disputeDuration > type(uint64).max) revert InvalidTerms();
        bytes32 prices = keccak256(abi.encode(members, fees));
        bytes32 contextHash = keccak256(abi.encode(block.chainid, coordinator, p.evidence, r, p.encryptionHash, prices,
            dealerDuration, receiverDuration, p.disputeDuration));
        bytes32[] memory duties = new bytes32[](members.length);
        address guardianRegistry = IDkgControllerAcl(acl).guardianRegistry();
        for (uint256 i; i < members.length; ++i) {
            address g = members[i];
            if (!IDkgControllerGuardians(guardianRegistry).isActiveGuardian(g)) revert InvalidTerms();
            Role memory role;
            for (uint256 j; j < r.dealerIndices.length; ++j) {
                uint8 index = r.dealerIndices[j];
                if (r.oldGuardians[uint256(index) - 1] == g) role.dealerIndex = index;
            }
            for (uint256 j; j < r.receivers.length; ++j) if (r.receivers[j] == g) role.receiverIndex = uint8(j + 1);
            if ((role.dealerIndex == 0 && fees[i].material != 0)
                || (role.receiverIndex == 0 && fees[i].shareKey != 0)) revert InvalidTerms();
            _roles[materialId][g] = role;
            duties[i] = keccak256(abi.encode(contextHash, g, role));
        }
        registryId = registry.open(fileId, msg.sender, contextHash, acceptBy, dealerDuration + receiverDuration, members, duties, bonds);
        escrow.fund{value: msg.value}(registryId, msg.sender, members, fees);
        if (escrow.getFund(registryId).priceHash != prices) revert InvalidTerms();
        _jobs[materialId] = Job(registryId, fileId, contextHash, msg.sender, p.evidence,
            IDkgAttemptCoordinator(coordinator).reputationManager(), epoch, version, uint8(r.receivers.length), r.newT,
            dealerDuration, receiverDuration, p.disputeDuration, 0, r.refresh, false);
        materialForRegistryId[registryId] = materialId;
        _participants[materialId] = members;
        _receivers[materialId] = r.receivers;
        ++activeCount;
        emit AttemptBound(materialId, registryId, fileId, contextHash);
    }

    function reserveDkgDuty(bytes32 id, address guardian, uint256 amount) external onlyRegistry {
        Job storage j = _job(materialForRegistryId[id]);
        if (j.closed) revert InvalidState();
        escrow.reserve(id, guardian, amount);
        escrow.credit(id, guardian, 0, escrow.getFees(id, guardian).acceptance);
    }

    function isBound(bytes32 materialId) external view returns (bool) { return _jobs[materialId].registryId != bytes32(0); }
    function materialsReady(bytes32 materialId) external view returns (bool) { return _jobs[materialId].readyAt != 0; }

    function requireMaterialOpen(bytes32 materialId) public view {
        Job storage j = _job(materialId);
        DkgAttemptRegistry.Attempt memory a = _running(j);
        if (block.timestamp > a.workDeadline - j.receiverDuration) revert InvalidState();
    }

    function requireShareOpen(bytes32 materialId) external view {
        Job storage j = _job(materialId);
        DkgAttemptRegistry.Attempt memory a = _running(j);
        if (j.readyAt == 0 || block.timestamp > a.workDeadline) revert InvalidState();
    }

    function validateDealer(bytes32 materialId, address guardian, uint8 index) public view returns (uint8 receiverCount) {
        requireMaterialOpen(materialId);
        if (index == 0 || _roles[materialId][guardian].dealerIndex != index
            || !IDkgControllerGuardians(IDkgControllerAcl(acl).guardianRegistry()).isActiveGuardian(guardian)) revert Unauthorized();
        return _jobs[materialId].receiverCount;
    }

    function validateCommitments(bytes32 materialId, address guardian, uint8 index, uint256[] calldata xs, uint256[] calldata ys) external onlyCoordinator returns (uint8 receiverCount) {
        receiverCount = validateDealer(materialId, guardian, index);
        Job storage j = _jobs[materialId];
        if (xs.length != j.threshold || ys.length != j.threshold) revert InvalidTerms();
        uint256[] memory compressed = new uint256[](xs.length);
        for (uint256 i; i < xs.length; ++i) {
            if (!BabyJubjub.isOnCurve(xs[i], ys[i])) revert InvalidTerms();
            // Exactly ecc/edwardsCompress in the unchanged ZoKrates circuit:
            // big-endian y with x parity in bit 255, not the raw x coordinate.
            compressed[i] = ys[i] | ((xs[i] & 1) << 255);
        }
        if (IDkgAttemptEvidence(j.evidence).materialCommitmentHash(materialId, j.epoch, j.version, index)
            != keccak256(abi.encodePacked(compressed))) revert InvalidTerms();
        commitments.record(materialId, index, xs, ys);
    }

    function validateEncryptedShare(bytes32 materialId, address guardian, uint8 fromIndex, uint8 toIndex, uint256 ciphertext) external view returns (address recipient, uint8 receiverCount) {
        receiverCount = validateDealer(materialId, guardian, fromIndex);
        Job storage j = _jobs[materialId];
        if (toIndex == 0 || toIndex > receiverCount || (!j.refresh && toIndex == fromIndex)) revert InvalidTerms();
        if (ciphertext != IDkgAttemptEvidence(j.evidence).materialEncryptedShare(materialId, j.epoch, j.version, fromIndex, toIndex)) revert InvalidTerms();
        return (_receivers[materialId][uint256(toIndex) - 1], receiverCount);
    }

    function validateSharePublication(bytes32 materialId, address guardian, uint8 index, uint256 x, uint256 y) external view {
        Job storage j = _job(materialId);
        DkgAttemptRegistry.Attempt memory a = _running(j);
        if (j.readyAt == 0 || block.timestamp > a.workDeadline || index == 0
            || _roles[materialId][guardian].receiverIndex != index
            || IDkgAttemptEvidence(j.evidence).pendingReceiverDisputes(materialId, guardian) != 0
            || !IDkgControllerGuardians(IDkgControllerAcl(acl).guardianRegistry()).isActiveGuardian(guardian)
            || !BabyJubjub.isOnCurve(x, y) || BabyJubjub.isIdentity(x, y)) revert InvalidState();
        (uint256 expectedX, uint256 expectedY) = commitments.expectedShare(materialId, index);
        if (x != expectedX || y != expectedY) revert InvalidTerms();
    }

    function requireComplaintOpen(bytes32 materialId) external view {
        Job storage j = _job(materialId);
        if (block.timestamp > _running(j).workDeadline) revert InvalidState();
    }

    function markMaterialsReady(bytes32 materialId) external onlyCoordinator {
        Job storage j = _job(materialId);
        if (j.readyAt != 0) return;
        requireMaterialOpen(materialId);
        j.readyAt = uint64(block.timestamp);
        emit MaterialStageReady(materialId, j.readyAt);
    }

    function complete(bytes32 materialId) external onlyCoordinator nonReentrant {
        Job storage j = _job(materialId); _running(j);
        (, uint32 receivers, uint32 contributors) = IDkgAttemptCoordinator(coordinator).getAttemptWork(materialId);
        if (j.readyAt == 0 || receivers != _all(j.receiverCount)) revert InvalidState();
        if (IDkgAttemptEvidence(j.evidence).pendingDisputes(materialId) != 0) revert UnresolvedComplaints();
        if ((IDkgAttemptEvidence(j.evidence).excludedDealers(materialId) & contributors) != 0) revert InvalidState();
        (, , , , , , , uint256 pkx, uint256 pky) = IDkgAttemptCoordinator(coordinator).getV2Key(j.fileId);
        commitments.validateKey(materialId, pkx, pky);
        // All publications were individually deadline-checked. Finalization may
        // arrive after the deadline following a resolved complaint or DO restart.
        registry.finishCompleted(j.registryId);
    }

    function cancel(bytes32 materialId) external nonReentrant {
        Job storage j = _job(materialId);
        if (msg.sender != j.dataOwner) revert Unauthorized();
        registry.cancel(j.registryId);
    }

    function cancelUnopened(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version) external nonReentrant {
        DkgAttemptTypes.Request memory r = getAttemptRequest(fileId, epoch, version);
        if (r.materialId != materialId || r.dataOwner != msg.sender) revert Unauthorized();
        if (_jobs[materialId].registryId != bytes32(0)) revert InvalidState();
        IDkgAttemptCoordinator(coordinator).closeAttempt(materialId, fileId, epoch, version, uint8(DkgAttemptRegistry.State.Cancelled), 0);
    }

    function expire(bytes32 materialId) external nonReentrant {
        Job storage j = _job(materialId);
        if (j.closed) revert InvalidState();
        DkgAttemptRegistry.Attempt memory a = registry.getAttempt(j.registryId);
        if (a.state == DkgAttemptRegistry.State.Accepting) {
            if (block.timestamp <= a.acceptBy) revert TooEarly();
            registry.expireAcceptance(j.registryId);
            return;
        }
        _running(j);
        if (IDkgAttemptEvidence(j.evidence).pendingDisputes(materialId) != 0) revert UnresolvedComplaints();
        (, uint32 receivers, uint32 contributors) = IDkgAttemptCoordinator(coordinator).getAttemptWork(materialId);
        uint32 bad = IDkgAttemptEvidence(j.evidence).excludedDealers(materialId);
        if (j.readyAt != 0 && receivers == _all(j.receiverCount) && (bad & contributors) == 0) {
            if (block.timestamp <= a.workDeadline) revert TooEarly();
            registry.finishUnactivated(j.registryId);
            return;
        }
        if ((contributors & bad) != 0 || (j.readyAt == 0 && block.timestamp > a.workDeadline - j.receiverDuration)) {
            registry.finishFailedStage(j.registryId);
        } else if (block.timestamp > a.workDeadline) {
            registry.finish(j.registryId, false);
        } else revert TooEarly();
    }

    /// @dev Mandatory registry callback. Book closure, credits, refunds, policy
    /// closure and bond return are one transaction; no failed payment is swallowed.
    function settleDkgAttempt(bytes32 id, uint8 outcome) external onlyRegistry {
        bytes32 materialId = materialForRegistryId[id];
        Job storage j = _job(materialId);
        if (j.closed || uint8(registry.getAttempt(id).state) != outcome) revert InvalidState();
        Work memory work;
        work.failed = outcome == uint8(DkgAttemptRegistry.State.Expired);
        work.cancelled = outcome == uint8(DkgAttemptRegistry.State.Cancelled);
        if (!work.failed && !work.cancelled && outcome != uint8(DkgAttemptRegistry.State.Succeeded)
            && outcome != uint8(DkgAttemptRegistry.State.Unactivated)) revert InvalidState();
        (work.dealers, work.receivers, work.contributors) = IDkgAttemptCoordinator(coordinator).getAttemptWork(materialId);
        work.bad = IDkgAttemptEvidence(j.evidence).excludedDealers(materialId);
        work.blockedReceivers = j.readyAt == 0 || (work.bad & work.contributors) != 0;
        address[] storage members = _participants[materialId];
        address[] memory faulty = new address[](members.length);
        uint8 faults;
        for (uint256 i; i < members.length; ++i) {
            if (_accountMember(materialId, members[i], work)) faulty[faults++] = members[i];
        }
        uint256 compensation = _compensate(materialId, j, faulty, faults);
        escrow.settle(id);
        j.closed = true; --activeCount;
        IDkgAttemptCoordinator(coordinator).closeAttempt(materialId, j.fileId, j.epoch, j.version, outcome, faults);
        emit AttemptAccounted(materialId, outcome, faults, compensation);
    }

    function _accountMember(bytes32 materialId, address guardian, Work memory w) private returns (bool faulty) {
        Job storage j = _jobs[materialId];
        if (!registry.getDuty(j.registryId, guardian).accepted) return false;
        Role storage role = _roles[materialId][guardian];
        bool dealerComplete = role.dealerIndex != 0 && _bit(w.dealers, role.dealerIndex) && !_bit(w.bad, role.dealerIndex);
        bool received = role.receiverIndex != 0 && _bit(w.receivers, role.receiverIndex);
        if (!w.cancelled) {
            DkgAttemptEscrow.FeeCaps memory fees = escrow.getFees(j.registryId, guardian);
            if (dealerComplete) escrow.credit(j.registryId, guardian, 1, fees.material);
            if (received) escrow.credit(j.registryId, guardian, 2, fees.shareKey);
        }
        return w.failed && ((role.dealerIndex != 0 && (_bit(w.bad, role.dealerIndex) || (j.readyAt == 0 && !dealerComplete)))
            || (!w.blockedReceivers && role.receiverIndex != 0 && !received));
    }

    function _compensate(bytes32 materialId, Job storage j, address[] memory faulty, uint8 faults) private returns (uint256 actual) {
        if (faults == 0) return 0;
        uint256 spent = escrow.getFund(j.registryId).spent;
        for (uint8 i; i < faults; ++i) {
            uint256 requested = spent / faults + (i < spent % faults ? 1 : 0);
            if (requested != 0) actual += escrow.compensate(j.registryId, faulty[i], requested);
            if (j.reputation != address(0)) {
                reputationPending[materialId][faulty[i]] = true;
                _reportReputation(materialId, faulty[i]);
            }
        }
    }

    function syncReputation(bytes32 materialId, address guardian) external nonReentrant returns (bool) {
        _job(materialId);
        return _reportReputation(materialId, guardian);
    }

    function _reportReputation(bytes32 materialId, address guardian) private returns (bool) {
        if (!reputationPending[materialId][guardian]) return false;
        reputationPending[materialId][guardian] = false;
        try IDkgControllerReputation(_jobs[materialId].reputation).recordDkgFailure(guardian, 1) {
            return true;
        } catch {
            reputationPending[materialId][guardian] = true;
            emit ReputationDeferred(materialId, guardian);
            return false;
        }
    }

    function releaseDkgDuty(bytes32 id, address guardian) external onlyRegistry { escrow.release(id, guardian); }

    function getJob(bytes32 materialId) external view returns (Job memory) { return _jobs[materialId]; }
    function getParticipants(bytes32 materialId) external view returns (address[] memory) { return _participants[materialId]; }
    function getRole(bytes32 materialId, address guardian) external view returns (Role memory) { return _roles[materialId][guardian]; }

    function getAttemptRequest(bytes32 fileId, uint32 epoch, uint32 version) public view returns (DkgAttemptTypes.Request memory r) {
        IDkgControllerAcl policy = IDkgControllerAcl(acl);
        (bool exists, bool active, address dataOwner, uint8 t, address[] memory guardians) = policy.getDkgFilePolicy(fileId);
        if (!exists || !active || policy.getFilePolicyMode(fileId) != 1) revert InvalidContext();
        IDkgAttemptCoordinator c = IDkgAttemptCoordinator(coordinator);
        r.materialId = c.getMaterialAttemptId(fileId, epoch, version);
        r.fileId = fileId; r.dataOwner = dataOwner; r.epoch = epoch; r.version = version;
        if (r.materialId == bytes32(0)) revert InvalidContext();
        (bool keyExists, , , , , uint32 activeEpoch, , uint256 pkx, uint256 pky) = c.getV2Key(fileId);
        if (version == 1) {
            if (!policy.hasRequestedKeyGenForFile(fileId) || epoch != (keyExists ? activeEpoch + 1 : 1)) revert InvalidContext();
            r.newT = t; r.receivers = guardians; r.oldGuardians = guardians;
            r.unopenedDeadline = policy.keyGenDeadlineForFile(fileId);
            r.dealerIndices = new uint8[](guardians.length);
            for (uint8 i; i < guardians.length; ++i) r.dealerIndices[i] = i + 1;
        } else {
            (bool pending, bool finalized, uint32 oldVersion, uint8 oldT, , uint8 newT, , address[] memory old, address[] memory receivers, uint8[] memory indices) = c.getRefreshRequest(fileId, epoch, version);
            if (!pending || finalized || c.refreshSettled(fileId, epoch)) revert InvalidContext();
            r.refresh = true; r.oldVersion = oldVersion; r.oldT = oldT; r.newT = newT;
            r.oldGuardians = old; r.receivers = receivers; r.dealerIndices = indices;
            r.unopenedDeadline = c.refreshDeadline(fileId, epoch); r.publicKeyX = pkx; r.publicKeyY = pky;
        }
    }

    function _job(bytes32 materialId) private view returns (Job storage j) {
        j = _jobs[materialId];
        if (j.registryId == bytes32(0)) revert InvalidContext();
    }
    function _running(Job storage j) private view returns (DkgAttemptRegistry.Attempt memory a) {
        a = registry.getAttempt(j.registryId);
        if (j.closed || a.state != DkgAttemptRegistry.State.Running) revert InvalidState();
    }
    function _all(uint8 n) private pure returns (uint32) { return uint32((uint256(1) << n) - 1); }
    function _bit(uint32 mask, uint8 i) private pure returns (bool) { return i != 0 && (mask & (uint32(1) << (i - 1))) != 0; }

    function _members(DkgAttemptTypes.Request memory r) private pure returns (address[] memory members) {
        if (r.receivers.length == 0 || r.receivers.length > 20 || r.newT < 2 || r.newT > r.receivers.length
            || r.oldGuardians.length > 20 || r.dealerIndices.length == 0 || r.dealerIndices.length > 20) revert InvalidContext();
        address[] memory values = new address[](40);
        uint256 n;
        for (uint256 i; i < r.receivers.length; ++i) values[n++] = r.receivers[i];
        for (uint256 i; i < r.dealerIndices.length; ++i) {
            uint8 index = r.dealerIndices[i];
            if (index == 0 || index > r.oldGuardians.length) revert InvalidContext();
            address g = r.oldGuardians[uint256(index) - 1];
            bool exists;
            for (uint256 k; k < n; ++k) if (values[k] == g) exists = true;
            if (!exists) values[n++] = g;
        }
        for (uint256 i = 1; i < n; ++i) {
            address g = values[i]; uint256 k = i;
            while (k != 0 && uint160(values[k - 1]) > uint160(g)) { values[k] = values[k - 1]; --k; }
            values[k] = g;
        }
        members = new address[](n);
        for (uint256 i; i < n; ++i) {
            if (values[i] == address(0) || (i != 0 && values[i] == values[i - 1])) revert InvalidContext();
            members[i] = values[i];
        }
    }
}
