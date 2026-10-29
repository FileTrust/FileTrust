// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DkgAttemptEscrow
// Purpose:  Attempt-specific work budgets and separately backed Guardian collateral.
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
import "./PayoutLib.sol";

interface IDkgAttemptStake {
    function reserveDkgBond(bytes32 attemptId, address guardian, uint256 amount) external;
    function depositStakeFor(address guardian) external payable;
}

/// @notice Per-attempt work budgets and separately backed Guardian collateral.
/// @dev New protocol component, not wired into existing deployments. The trusted
/// coordinator must validate consent, work evidence and fault BEFORE calling
/// these methods. This component never decides fault from heartbeat age.
contract DkgAttemptEscrow is ReentrancyGuard {
    struct FeeCaps { uint128 acceptance; uint128 material; uint128 shareKey; }
    struct Fund {
        address dataOwner;
        bytes32 priceHash;
        uint256 remaining;
        uint256 spent;
        uint256 compensation;
        bool settled;
    }
    address public immutable coordinator;
    IDkgAttemptStake public immutable staking;
    mapping(bytes32 => Fund) private _funds;
    mapping(bytes32 => mapping(address => FeeCaps)) private _fees;
    mapping(bytes32 => mapping(address => bool)) private _assigned;
    mapping(bytes32 => mapping(address => uint8)) private _credited;
    mapping(bytes32 => mapping(address => bool)) private _reservedOnce;
    mapping(bytes32 => mapping(address => bool)) private _compensationAssessed;
    mapping(bytes32 => mapping(address => uint256)) public bondOf;
    mapping(address => uint256) public claimable;
    uint256 public budgetLiability;
    uint256 public bondLiability;
    uint256 public claimLiability;

    error Unauthorized();
    error InvalidFunding();
    error InvalidState();
    error InvalidWork();

    event AttemptFunded(bytes32 indexed attemptId, address indexed dataOwner, bytes32 priceHash, uint256 amount);
    event WorkCredited(bytes32 indexed attemptId, address indexed guardian, uint8 action, uint256 amount);
    event BondReserved(bytes32 indexed attemptId, address indexed guardian, uint256 amount);
    event CompensationCredited(bytes32 indexed attemptId, address indexed guardian, address indexed dataOwner, uint256 amount);
    event AttemptRefunded(bytes32 indexed attemptId, address indexed dataOwner, uint256 amount);
    event BondReturned(bytes32 indexed attemptId, address indexed guardian, uint256 amount);
    event Claimed(address indexed account, address indexed recipient, uint256 amount);

    constructor(address coordinator_, address staking_) {
        if (coordinator_.code.length == 0 || staking_.code.length == 0) revert InvalidFunding();
        coordinator = coordinator_; staking = IDkgAttemptStake(staking_);
    }
    modifier onlyCoordinator() { if (msg.sender != coordinator) revert Unauthorized(); _; }
    receive() external payable { if (msg.sender != address(staking)) revert Unauthorized(); }

    function fund(bytes32 id, address dataOwner, address[] calldata guardians, FeeCaps[] calldata fees)
        external payable onlyCoordinator nonReentrant
    {
        uint256 n = guardians.length;
        if (id == bytes32(0) || dataOwner == address(0) || _funds[id].dataOwner != address(0)
            || n == 0 || n > 40 || fees.length != n || msg.value == 0) revert InvalidFunding();
        uint256 maximum; address previous;
        for (uint256 i; i < n; ++i) {
            address g = guardians[i];
            if (uint160(g) <= uint160(previous)) revert InvalidFunding();
            previous = g;
            _assigned[id][g] = true; _fees[id][g] = fees[i];
            maximum += uint256(fees[i].acceptance) + uint256(fees[i].material) + uint256(fees[i].shareKey);
        }
        if (msg.value < maximum) revert InvalidFunding();
        bytes32 priceHash = keccak256(abi.encode(guardians, fees));
        _funds[id] = Fund(dataOwner, priceHash, msg.value, 0, 0, false);
        budgetLiability += msg.value;
        emit AttemptFunded(id, dataOwner, priceHash, msg.value);
    }

    function reserve(bytes32 id, address guardian, uint256 amount) external onlyCoordinator nonReentrant {
        _requireOpen(id);
        if (!_assigned[id][guardian] || amount == 0 || _reservedOnce[id][guardian]) revert InvalidFunding();
        // Verify value actually arrived, rather than trusting a reservation flag.
        uint256 beforeBalance = address(this).balance;
        staking.reserveDkgBond(id, guardian, amount);
        if (address(this).balance != beforeBalance + amount) revert InvalidFunding();
        _reservedOnce[id][guardian] = true;
        bondOf[id][guardian] = amount; bondLiability += amount;
        emit BondReserved(id, guardian, amount);
    }

    /// @param action 0 acceptance, 1 verified material, 2 verified share key.
    /// @dev Amount includes only the agreed capped work/gas allowance. The
    /// coordinator must authenticate completion; caller cannot be a Guardian.
    function credit(bytes32 id, address guardian, uint8 action, uint256 amount)
        external onlyCoordinator nonReentrant returns (bool newlyCredited)
    {
        Fund storage f = _requireOpen(id);
        if (!_assigned[id][guardian] || !_reservedOnce[id][guardian] || action > 2) revert InvalidWork();
        uint8 bit = uint8(1) << action;
        if ((_credited[id][guardian] & bit) != 0) return false;
        FeeCaps storage caps = _fees[id][guardian];
        uint256 limit = action == 0 ? caps.acceptance : action == 1 ? caps.material : caps.shareKey;
        if (amount > limit || amount > f.remaining) revert InvalidWork();
        _credited[id][guardian] |= bit;
        f.remaining -= amount; f.spent += amount; budgetLiability -= amount;
        claimable[guardian] += amount; claimLiability += amount;
        emit WorkCredited(id, guardian, action, amount);
        return true;
    }

    /// @notice Credits at most this accepted duty's remaining reserved backing.
    /// Returns the actual amount; a caller must not describe a larger requested
    /// reimbursement as paid. No custody/other attempt stake is consumed.
    function compensate(bytes32 id, address guardian, uint256 requested)
        external onlyCoordinator nonReentrant returns (uint256 actual)
    {
        Fund storage f = _requireOpen(id);
        if (!_reservedOnce[id][guardian] || requested == 0) revert InvalidWork();
        if (_compensationAssessed[id][guardian]) return 0;
        _compensationAssessed[id][guardian] = true;
        uint256 backing = bondOf[id][guardian];
        actual = requested < backing ? requested : backing;
        if (actual == 0) return 0;
        bondOf[id][guardian] = backing - actual; bondLiability -= actual;
        f.compensation += actual;
        claimable[f.dataOwner] += actual; claimLiability += actual;
        emit CompensationCredited(id, guardian, f.dataOwner, actual);
    }

    function settle(bytes32 id) external onlyCoordinator nonReentrant returns (uint256 refund) {
        Fund storage f = _requireOpen(id);
        f.settled = true; refund = f.remaining; f.remaining = 0;
        budgetLiability -= refund; claimable[f.dataOwner] += refund; claimLiability += refund;
        emit AttemptRefunded(id, f.dataOwner, refund);
    }

    function release(bytes32 id, address guardian) external onlyCoordinator nonReentrant {
        if (!_funds[id].settled) revert InvalidState();
        uint256 amount = bondOf[id][guardian];
        if (amount == 0) return;
        delete bondOf[id][guardian]; bondLiability -= amount;
        staking.depositStakeFor{value: amount}(guardian);
        emit BondReturned(id, guardian, amount);
    }

    function withdrawTo(address recipient) external nonReentrant {
        uint256 amount = claimable[msg.sender];
        if (recipient == address(0) || amount == 0) revert InvalidFunding();
        claimable[msg.sender] = 0; claimLiability -= amount;
        PayoutLib.send(recipient, amount);
        emit Claimed(msg.sender, recipient, amount);
    }

    function _requireOpen(bytes32 id) private view returns (Fund storage f) {
        f = _funds[id];
        if (f.dataOwner == address(0) || f.settled) revert InvalidState();
    }
    function getFund(bytes32 id) external view returns (Fund memory) { return _funds[id]; }
    function getFees(bytes32 id, address guardian) external view returns (FeeCaps memory) { return _fees[id][guardian]; }
    function workCredited(bytes32 id, address guardian, uint8 action) external view returns (bool) {
        if (action > 2) return false;
        return (_credited[id][guardian] & (uint8(1) << action)) != 0;
    }
}
