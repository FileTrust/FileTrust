// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: GuardianWorkReward
// Purpose:  Early-network pay for Guardian work, from a pool the owner funds and
//           capped per Guardian.
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
import "./PayoutLib.sol";

interface IGuardianRegistry_GWR {
    function isActiveGuardian(address guardian) external view returns (bool);
}

/// @title GuardianWorkReward
/// @notice Early-network reward for Guardian work, paid from FTU deposited into its pool. It pays
///         a fixed amount to every Guardian of a finished DKG, to each Guardian whose PRE part
///         was used, and a smaller amount to a Guardian that was ready for a PRE that did not
///         need it -- the same three events that earn reputation. One cap per Guardian bounds
///         what it can ever receive across all three, and only active, staked Guardians are
///         paid. This is on top of the DKG and PRE fees the data owner and the requester pay
///         through RewardManager; it never touches those escrows.
/// @dev Kept out of RewardManager, which is close to the EIP-170 size limit. The DKG
///      coordinator and TElGv2 call `credit` inside the work transactions they already
///      process, with a fixed gas budget and a try/catch, so this contract can never block a
///      DKG or a PRE. Those two callers are bound once and can only be revoked afterwards, so
///      no owner can later add a caller that pays the pool out. Anyone may add to the pool.
contract GuardianWorkReward is FileTrustOwnable {
    uint8 public constant KIND_DKG = 0;
    uint8 public constant KIND_PRE = 1;
    uint8 public constant KIND_PRE_READY = 2;

    IGuardianRegistry_GWR public immutable guardianRegistry;

    uint256 public pool;
    uint256 public dkgRewardWei;
    uint256 public preRewardWei;
    uint256 public preReadyRewardWei;
    uint256 public capWei;
    mapping(address => uint256) public paid;
    mapping(address => bool) public authorizedCallers;
    /// @notice True once the callers are bound; from then on they can only be revoked.
    bool public callersBound;

    event CallerAuthorized(address indexed caller, bool authorized);
    event RewardsSet(uint256 dkgWei, uint256 preWei, uint256 preReadyWei, uint256 capWei);
    event PoolDeposited(address indexed sender, uint256 amount, uint256 balance);
    event GuardianRewarded(address indexed guardian, uint8 indexed kind, uint256 amount);

    constructor(address guardianRegistry_) Ownable(msg.sender) {
        require(guardianRegistry_ != address(0), "GWR: zero registry");
        guardianRegistry = IGuardianRegistry_GWR(guardianRegistry_);
    }

    /// @notice Authorize the protocol contracts that credit work. Called once, at
    ///         deployment, with all of them.
    function bindCallers(address[] calldata callers) external onlyOwner {
        require(!callersBound && callers.length != 0, "GWR: callers already bound");
        callersBound = true;
        for (uint256 i = 0; i < callers.length; i++) {
            address caller = callers[i];
            require(caller.code.length != 0 && !authorizedCallers[caller], "GWR: bad caller");
            authorizedCallers[caller] = true;
            emit CallerAuthorized(caller, true);
        }
    }

    /// @notice Take a compromised caller's rights away for good.
    function revokeCaller(address caller) external onlyOwner {
        require(authorizedCallers[caller], "GWR: not a caller");
        authorizedCallers[caller] = false;
        emit CallerAuthorized(caller, false);
    }

    /// @notice Reward per finished DKG, per used PRE part, per PRE ready-but-not-used, and the
    ///         most one Guardian can ever receive. Zero turns a reward off.
    function setRewards(uint256 dkgWei, uint256 preWei, uint256 preReadyWei, uint256 capWei_)
        external
        onlyOwner
    {
        dkgRewardWei = dkgWei;
        preRewardWei = preWei;
        preReadyRewardWei = preReadyWei;
        capWei = capWei_;
        emit RewardsSet(dkgWei, preWei, preReadyWei, capWei_);
    }

    function deposit() external payable {
        require(msg.value > 0, "GWR: zero deposit");
        pool += msg.value;
        emit PoolDeposited(msg.sender, msg.value, pool);
    }

    /// @notice Pay each Guardian the reward for `kind`, never past its cap and never more
    ///         than the pool holds. A Guardian that is not active and staked, or whose
    ///         address refuses FTU, is skipped without affecting the others.
    function credit(address[] calldata guardians, uint8 kind) external {
        require(authorizedCallers[msg.sender], "GWR: not authorized");
        uint256 reward = kind == KIND_DKG ? dkgRewardWei
            : kind == KIND_PRE ? preRewardWei
            : kind == KIND_PRE_READY ? preReadyRewardWei
            : 0;
        if (reward == 0) return;
        uint256 cap = capWei;
        for (uint256 i = 0; i < guardians.length; i++) {
            address guardian = guardians[i];
            uint256 already = paid[guardian];
            uint256 amount = already < cap ? cap - already : 0;
            if (amount > reward) amount = reward;
            if (amount > pool) amount = pool;
            if (amount == 0 || !guardianRegistry.isActiveGuardian(guardian)) continue;
            paid[guardian] = already + amount;
            pool -= amount;
            if (!PayoutLib.trySend(guardian, amount)) {
                paid[guardian] = already;
                pool += amount;
                continue;
            }
            emit GuardianRewarded(guardian, kind, amount);
        }
    }
}
