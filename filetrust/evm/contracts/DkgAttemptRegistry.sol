// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DkgAttemptRegistry
// Purpose:  Bounded DKG attempts and explicit Guardian acceptance of immutable duties.
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

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

interface IDkgAttemptCollateral {
    function reserveDkgDuty(bytes32 attemptId, address guardian, uint256 amount) external;
    function settleDkgAttempt(bytes32 attemptId, uint8 outcome) external;
    function releaseDkgDuty(bytes32 attemptId, address guardian) external;
}

/// @notice Attempt identity, immutable terms and explicit Guardian acceptance.
/// @dev New protocol component, not wired into existing deployments. The
/// coordinator must assess work/payment evidence and settle the budget in the
/// mandatory closure callback BEFORE any bond is released, even when nobody
/// accepted. Failed settlement rolls back closure. It does not infer nonresponse
/// from heartbeats, nor collect penalties for unaccepted or cancelled work.
contract DkgAttemptRegistry is EIP712, ReentrancyGuard {
    using ECDSA for bytes32;

    enum State { Absent, Accepting, Running, Succeeded, Expired, Cancelled, Unactivated }

    struct Attempt {
        bytes32 fileId;
        address dataOwner;
        bytes32 contextHash;
        bytes32 termsHash;
        uint64 sequence;
        uint64 acceptBy;
        uint64 workDuration;
        uint64 workDeadline;
        uint8 acceptedCount;
        State state;
    }

    struct Duty {
        bytes32 obligationHash;
        uint256 bond;
        bool accepted;
    }

    bytes32 public constant ACCEPT_TYPEHASH = keccak256(
        "DkgAcceptance(bytes32 attemptId,address guardian,bytes32 termsHash)"
    );
    uint256 public constant MAX_PARTICIPANTS = 40;
    address public immutable coordinator;
    mapping(bytes32 => uint64) public sequenceOf;
    mapping(bytes32 => bytes32) public activeAttemptOf;
    // Acceptance expiry is financially neutral like cancellation, but clients
    // must distinguish its cause even when a third party performs settlement.
    mapping(bytes32 => bool) public acceptanceTimedOut;
    mapping(bytes32 => Attempt) private _attempts;
    mapping(bytes32 => address[]) private _participants;
    mapping(bytes32 => mapping(address => Duty)) private _duties;

    error InvalidAttempt();
    error WrongState();
    error NotCoordinator();
    error NotParticipant();
    error AcceptanceExpired();

    event AttemptOpened(bytes32 indexed attemptId, bytes32 indexed fileId, address indexed dataOwner, uint64 sequence, bytes32 termsHash);
    event DutyAccepted(bytes32 indexed attemptId, address indexed guardian);
    event AttemptStarted(bytes32 indexed attemptId, uint64 workDeadline);
    event AttemptClosed(bytes32 indexed attemptId, State outcome);

    constructor(address coordinator_) EIP712("FileTrust DKG Attempt", "1") {
        if (coordinator_ == address(0) || coordinator_.code.length == 0) revert InvalidAttempt();
        coordinator = coordinator_;
    }

    modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert NotCoordinator();
        _;
    }

    /// @param contextHash Commits the ordered old/new committees, encryption-key
    /// identities, thresholds, operation, active key/version, protocol version
    /// and payment terms. Integration must compute it from validated snapshots.
    /// @param obligations Per-participant role/work hashes; a Guardian serving
    /// both roles appears once with a hash committing both obligations.
    function open(
        bytes32 fileId,
        address dataOwner,
        bytes32 contextHash,
        uint64 acceptBy,
        uint64 workDuration,
        address[] calldata participants,
        bytes32[] calldata obligations,
        uint256[] calldata bonds
    ) external onlyCoordinator nonReentrant returns (bytes32 id) {
        uint256 n = participants.length;
        if (fileId == bytes32(0) || dataOwner == address(0) || contextHash == bytes32(0)
            || n == 0 || n > MAX_PARTICIPANTS || obligations.length != n || bonds.length != n
            || acceptBy <= block.timestamp || workDuration == 0
            || uint256(acceptBy) + uint256(workDuration) > type(uint64).max
            || activeAttemptOf[fileId] != bytes32(0)) revert InvalidAttempt();
        uint64 sequence = ++sequenceOf[fileId];
        id = keccak256(abi.encode(block.chainid, address(this), fileId, sequence));
        bytes32 terms = keccak256(abi.encode(
            fileId, dataOwner, contextHash, acceptBy, workDuration, participants, obligations, bonds
        ));
        _attempts[id] = Attempt(fileId, dataOwner, contextHash, terms, sequence,
            acceptBy, workDuration, 0, 0, State.Accepting);
        address previous;
        for (uint256 i; i < n; ++i) {
            address g = participants[i];
            // Strict ordering rejects both zero and duplicate identities in O(N).
            if (uint160(g) <= uint160(previous) || obligations[i] == bytes32(0) || bonds[i] == 0) revert InvalidAttempt();
            previous = g;
            _participants[id].push(g);
            _duties[id][g] = Duty(obligations[i], bonds[i], false);
        }
        activeAttemptOf[fileId] = id;
        emit AttemptOpened(id, fileId, dataOwner, sequence, terms);
    }

    function acceptanceDigest(bytes32 id, address guardian) public view returns (bytes32) {
        Attempt storage a = _attempts[id];
        if (a.state == State.Absent || _duties[id][guardian].obligationHash == bytes32(0)) revert NotParticipant();
        return _hashTypedDataV4(keccak256(abi.encode(ACCEPT_TYPEHASH, id, guardian, a.termsHash)));
    }

    /// @notice Direct acceptance is available without any signature relay.
    function accept(bytes32 id) external nonReentrant {
        _accept(id, msg.sender);
    }

    /// @notice Anyone may relay an exact EIP-712 acceptance. The relay cannot
    /// alter its job or terms, and collateral is reserved before it is recorded.
    function acceptSigned(bytes32 id, address guardian, bytes calldata signature) external nonReentrant {
        if (acceptanceDigest(id, guardian).recover(signature) != guardian) revert NotParticipant();
        _accept(id, guardian);
    }

    function acceptSignedBatch(bytes32 id, address[] calldata guardians, bytes[] calldata signatures) external nonReentrant {
        if (guardians.length == 0 || guardians.length > MAX_PARTICIPANTS || guardians.length != signatures.length) revert InvalidAttempt();
        for (uint256 i; i < guardians.length; ++i) {
            if (acceptanceDigest(id, guardians[i]).recover(signatures[i]) != guardians[i]) revert NotParticipant();
            _accept(id, guardians[i]);
        }
    }

    function _accept(bytes32 id, address guardian) private {
        Attempt storage a = _attempts[id];
        if (a.state != State.Accepting) revert WrongState();
        if (block.timestamp > a.acceptBy) revert AcceptanceExpired();
        Duty storage d = _duties[id][guardian];
        if (d.obligationHash == bytes32(0)) revert NotParticipant();
        if (d.accepted) revert WrongState();
        IDkgAttemptCollateral(coordinator).reserveDkgDuty(id, guardian, d.bond);
        d.accepted = true;
        ++a.acceptedCount;
        emit DutyAccepted(id, guardian);
        if (a.acceptedCount == _participants[id].length) {
            a.state = State.Running;
            a.workDeadline = uint64(block.timestamp) + a.workDuration;
            emit AttemptStarted(id, a.workDeadline);
        }
    }

    /// @notice Unstarted work can be cancelled without a nonresponse penalty.
    /// Protocol integration must authenticate the DO before calling this method.
    function cancel(bytes32 id) external onlyCoordinator nonReentrant {
        if (_attempts[id].state != State.Accepting) revert WrongState();
        _close(id, State.Cancelled);
    }

    /// @notice No acceptance means no work duty arose; release accepted bonds.
    function expireAcceptance(bytes32 id) external nonReentrant {
        Attempt storage a = _attempts[id];
        if (a.state != State.Accepting) revert WrongState();
        if (block.timestamp <= a.acceptBy) revert AcceptanceExpired();
        acceptanceTimedOut[id] = true;
        _close(id, State.Cancelled);
    }

    /// @dev Coordinator must verify success or assess missed duties/payments
    /// first. No arbitrary account may decide success or financial fault.
    function finish(bytes32 id, bool success) external onlyCoordinator nonReentrant {
        Attempt storage a = _attempts[id];
        if (a.state != State.Running) revert WrongState();
        if (success ? block.timestamp > a.workDeadline : block.timestamp <= a.workDeadline) revert WrongState();
        _close(id, success ? State.Succeeded : State.Expired);
    }

    /// @dev The bound production controller verifies that every required
    /// publication arrived on time, even if finalization follows a DO restart
    /// or a later complaint resolution. This does not admit late publications.
    function finishCompleted(bytes32 id) external onlyCoordinator nonReentrant {
        if (_attempts[id].state != State.Running) revert WrongState();
        _close(id, State.Succeeded);
    }

    /// @dev Only the controller may prove an earlier stage irrecoverable (for
    /// example a missed material deadline). It must assess that exact stage,
    /// not blame receivers whose prerequisites were never delivered.
    function finishFailedStage(bytes32 id) external onlyCoordinator nonReentrant {
        if (_attempts[id].state != State.Running) revert WrongState();
        _close(id, State.Expired);
    }

    /// @dev Timely work must not leave Guardian collateral locked forever if
    /// the owner never activates the prepared key. The controller checks the
    /// work deadline and absence of unresolved evidence; this is not success.
    function finishUnactivated(bytes32 id) external onlyCoordinator nonReentrant {
        if (_attempts[id].state != State.Running) revert WrongState();
        _close(id, State.Unactivated);
    }

    function _close(bytes32 id, State outcome) private {
        Attempt storage a = _attempts[id];
        a.state = outcome;
        delete activeAttemptOf[a.fileId];
        IDkgAttemptCollateral(coordinator).settleDkgAttempt(id, uint8(outcome));
        address[] storage participants = _participants[id];
        for (uint256 i; i < participants.length; ++i) {
            if (_duties[id][participants[i]].accepted) {
                IDkgAttemptCollateral(coordinator).releaseDkgDuty(id, participants[i]);
            }
        }
        emit AttemptClosed(id, outcome);
    }

    function getAttempt(bytes32 id) external view returns (Attempt memory) { return _attempts[id]; }
    function getParticipants(bytes32 id) external view returns (address[] memory) { return _participants[id]; }
    function getDuty(bytes32 id, address guardian) external view returns (Duty memory) { return _duties[id][guardian]; }
}
