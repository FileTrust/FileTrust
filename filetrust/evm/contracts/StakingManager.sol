// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: StakingManager
// Purpose:  Stake put up by Guardians and Vault Keepers, what locks it, and what it
//           costs them to break a promise.
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

interface IGuardianRegistry {
    function isActiveGuardian(address guardian) external view returns (bool);
    function minStake() external view returns (uint256);
    function admissionMinStakeOf(address guardian) external view returns (uint256);
}

interface IGuardianShareProof_Staking {
    function hasActiveGuardianObligations(address guardian) external view returns (bool);
}

interface IVaultKeeperRegistry_SM {
    function isRegisteredVaultKeeper(address vk) external view returns (bool);
    function latestServiceEnd(address vk) external view returns (uint64);
}

interface IDkgAttemptEscrow_SM {
    function staking() external view returns (address);
}

/// @dev Who may take stake is fixed when the protocol is deployed. The slashers are
///      bound once, as protocol contracts, and afterwards can only be revoked; the DKG
///      attempt escrow is bound once and must name this contract as its own. Slashed
///      stake goes to the treasury, a contract named at construction, never the owner.
contract StakingManager is FileTrustOwnable {
    mapping(address => uint256) public stakeOf;
    mapping(address => uint256) public lockedStakeOf;
    mapping(address => bool) public authorizedSlashers;

    uint256 public minStake;
    address public treasury;
    address public guardianRegistry;
    address public guardianShareProof;
    address public vaultKeeperRegistry;
    address public dkgAttemptEscrow;
    /// @notice True once the slashers are bound; from then on they can only be revoked.
    bool public slashersBound;
    /// @notice True once a DKG attempt escrow was bound. None is bound again, also after
    ///         that one is revoked.
    bool public dkgAttemptEscrowBound;

    /// @notice Share of a Guardian penalty paid to an independent reporter, in basis points;
    ///         the treasury gets the rest.
    uint256 public constant REPORTER_SHARE_BPS = 1_000;
    /// @notice Most one Guardian penalty takes, in basis points of the minimum stake the
    ///         Guardian was admitted with.
    uint256 public constant GUARDIAN_PENALTY_CAP_BPS = 100;

    event StakeDeposited(address indexed guardian, uint256 amount, uint256 totalStake);
    event StakeWithdrawn(address indexed guardian, uint256 amount, uint256 remainingStake);
    event StakeLocked(address indexed guardian, uint256 amount, uint256 lockedStake);
    event StakeUnlocked(address indexed guardian, uint256 amount, uint256 lockedStake);
    event StakeSlashed(address indexed guardian, uint256 amount, uint256 remainingStake, address indexed treasury);
    event MinimumStakeUpdated(uint256 minStake);
    event TreasuryUpdated(address indexed treasury);
    event AuthorizedSlasherUpdated(address indexed slasher, bool allowed);
    event GuardianRegistryUpdated(address indexed guardianRegistry);
    event GuardianShareProofUpdated(address indexed guardianShareProof);
    event VaultKeeperRegistryUpdated(address indexed vaultKeeperRegistry);
    event DkgAttemptEscrowUpdated(address indexed escrow);
    event DkgBondReserved(bytes32 indexed attemptId, address indexed guardian, uint256 amount);

    constructor(uint256 _minStake, address _treasury) Ownable(msg.sender) {
        _requireTreasury(_treasury);
        minStake = _minStake;
        treasury = _treasury;
    }

    receive() external payable {
        revert("StakingManager: use depositStake");
    }

    modifier onlyAuthorizedSlasher() {
        require(authorizedSlashers[msg.sender], "StakingManager: not authorized slasher");
        _;
    }

    function setMinStake(uint256 _minStake) external onlyOwner {
        minStake = _minStake;
        emit MinimumStakeUpdated(_minStake);
    }

    function minimumGuardianStake() external view returns (uint256) {
        return minStake;
    }

    function setTreasury(address _treasury) external onlyOwner {
        _requireTreasury(_treasury);
        treasury = _treasury;
        emit TreasuryUpdated(_treasury);
    }

    /// @dev Slashed stake belongs to the protocol, so the treasury is a contract -- a
    ///      multisig, a timelock or a treasury contract -- and never a single key such as
    ///      the deployer's.
    function _requireTreasury(address _treasury) private view {
        require(_treasury.code.length != 0 && _treasury != address(this), "StakingManager: treasury must be a contract");
    }

    // The sources of truth below are bound once (Phase 2, D7): re-pointing one would change
    // admission minimums, penalty caps or withdrawal obligations under live stake. A new
    // protocol version comes with its own StakingManager.
    function setGuardianRegistry(address registry) external onlyOwner {
        require(registry != address(0) && guardianRegistry == address(0), "StakingManager: guardian registry bound once");
        guardianRegistry = registry;
        emit GuardianRegistryUpdated(registry);
    }

    function setGuardianShareProof(address shareProof) external onlyOwner {
        require(shareProof != address(0) && guardianShareProof == address(0), "StakingManager: share proof bound once");
        guardianShareProof = shareProof;
        emit GuardianShareProofUpdated(shareProof);
    }

    function setVaultKeeperRegistry(address _vkr) external onlyOwner {
        require(_vkr != address(0) && vaultKeeperRegistry == address(0), "StakingManager: VK registry bound once");
        vaultKeeperRegistry = _vkr;
        emit VaultKeeperRegistryUpdated(_vkr);
    }

    /// @notice Authorize the protocol contracts that may lock and slash stake. Called once,
    ///         at deployment, with every slasher; afterwards the list can only shrink, so
    ///         no owner can later add a contract, or a key, that takes stake.
    function bindSlashers(address[] calldata slashers) external onlyOwner {
        require(!slashersBound && slashers.length != 0, "StakingManager: slashers already bound");
        slashersBound = true;
        for (uint256 i = 0; i < slashers.length; ++i) {
            address slasher = slashers[i];
            require(slasher.code.length != 0 && !authorizedSlashers[slasher], "StakingManager: invalid slasher");
            authorizedSlashers[slasher] = true;
            emit AuthorizedSlasherUpdated(slasher, true);
        }
    }

    /// @notice Take a compromised slasher's rights away for good.
    function revokeSlasher(address slasher) external onlyOwner {
        require(authorizedSlashers[slasher], "StakingManager: not a slasher");
        authorizedSlashers[slasher] = false;
        emit AuthorizedSlasherUpdated(slasher, false);
    }

    /// @notice Bind the DKG attempt escrow, once. It must be a contract that names this
    ///         StakingManager as its own, so the collateral it reserves can only come back
    ///         here (DkgAttemptEscrow.staking is immutable).
    function setDkgAttemptEscrow(address escrow) external onlyOwner {
        require(!dkgAttemptEscrowBound, "StakingManager: escrow already bound");
        require(
            escrow.code.length != 0 && IDkgAttemptEscrow_SM(escrow).staking() == address(this),
            "StakingManager: invalid escrow"
        );
        dkgAttemptEscrowBound = true;
        dkgAttemptEscrow = escrow;
        emit DkgAttemptEscrowUpdated(escrow);
    }

    /// @notice Stop a compromised escrow from reserving more collateral. What it already
    ///         holds still comes back through depositStakeFor. No escrow is bound again,
    ///         so new DKG attempts need a new deployment after this.
    function revokeDkgAttemptEscrow() external onlyOwner {
        require(dkgAttemptEscrow != address(0), "StakingManager: no escrow");
        dkgAttemptEscrow = address(0);
        emit DkgAttemptEscrowUpdated(address(0));
    }

    /// @notice Segregate consented DKG collateral from other protocol penalties.
    /// @dev Only the configured attempt escrow may reserve it, after the
    /// coordinator validates acceptance. Existing locks and minimum stake stay
    /// backed. Returning unused collateral uses depositStakeFor, not a slash.
    function reserveDkgBond(bytes32 attemptId, address guardian, uint256 amount) external {
        require(msg.sender == dkgAttemptEscrow, "StakingManager: not DKG escrow");
        require(amount > 0 && attemptId != bytes32(0), "StakingManager: invalid DKG bond");
        uint256 available = availableStake(guardian);
        require(available >= minStake && amount <= available - minStake, "StakingManager: insufficient DKG backing");
        stakeOf[guardian] -= amount;
        PayoutLib.send(msg.sender, amount);
        emit DkgBondReserved(attemptId, guardian, amount);
    }

    function depositStake() external payable {
        _depositStakeFor(msg.sender, msg.value);
    }

    function depositStakeFor(address guardian) external payable {
        require(guardian != address(0), "StakingManager: zero guardian");
        _depositStakeFor(guardian, msg.value);
    }

    function _depositStakeFor(address guardian, uint256 amount) internal {
        require(msg.value > 0, "StakingManager: zero deposit");
        require(amount == msg.value, "StakingManager: bad deposit");
        stakeOf[guardian] += amount;
        emit StakeDeposited(guardian, amount, stakeOf[guardian]);
    }

    function withdrawStake(uint256 amount) external {
        _withdrawStake(msg.sender, amount);
    }

    /// @notice GuardianRegistry.withdrawStake, for the Guardian that called it: the stake
    ///         is paid to that Guardian, under exactly the rules of withdrawStake.
    function withdrawStakeFor(address guardian, uint256 amount) external {
        require(msg.sender == guardianRegistry, "StakingManager: not guardian registry");
        _withdrawStake(guardian, amount);
    }

    function _withdrawStake(address staker, uint256 amount) private {
        require(amount > 0, "StakingManager: zero amount");
        require(availableStake(staker) >= amount, "StakingManager: insufficient available stake");

        uint256 newStake = stakeOf[staker] - amount;
        // The minimum is what an active Guardian keeps, not a lock on everyone who ever
        // registered. A Guardian that is not active -- it deactivated, or a raised
        // minimum left it below the new figure -- takes its stake out once no obligation
        // holds it, so changing the minimum never traps stake that is already in.
        if (guardianRegistry != address(0) && IGuardianRegistry(guardianRegistry).isActiveGuardian(staker)) {
            require(newStake >= minStake, "StakingManager: active guardian needs min stake");
        }

        if (guardianShareProof != address(0)) {
            require(
                !IGuardianShareProof_Staking(guardianShareProof).hasActiveGuardianObligations(staker),
                "StakingManager: active service obligations"
            );
        }

        if (vaultKeeperRegistry != address(0)) {
            IVaultKeeperRegistry_SM vkReg = IVaultKeeperRegistry_SM(vaultKeeperRegistry);
            if (vkReg.isRegisteredVaultKeeper(staker)) {
                require(
                    block.timestamp >= vkReg.latestServiceEnd(staker),
                    "StakingManager: VK has active storage obligations"
                );
            }
        }

        stakeOf[staker] = newStake;
        PayoutLib.send(staker, amount);
        emit StakeWithdrawn(staker, amount, newStake);
    }

    function lockStake(address guardian, uint256 amount) external onlyAuthorizedSlasher {
        require(amount > 0, "StakingManager: zero amount");
        require(availableStake(guardian) >= amount, "StakingManager: insufficient available stake");

        lockedStakeOf[guardian] += amount;
        emit StakeLocked(guardian, amount, lockedStakeOf[guardian]);
    }

    function unlockStake(address guardian, uint256 amount) external onlyAuthorizedSlasher {
        require(amount > 0, "StakingManager: zero amount");
        require(lockedStakeOf[guardian] >= amount, "StakingManager: not enough locked stake");

        lockedStakeOf[guardian] -= amount;
        emit StakeUnlocked(guardian, amount, lockedStakeOf[guardian]);
    }

    function slash(address guardian, uint256 amount) external onlyAuthorizedSlasher {
        require(amount > 0, "StakingManager: zero amount");
        require(stakeOf[guardian] > 0, "StakingManager: no stake to slash");

        uint256 slashAmount = amount;
        if (slashAmount > stakeOf[guardian]) {
            slashAmount = stakeOf[guardian];
        }

        stakeOf[guardian] -= slashAmount;
        if (lockedStakeOf[guardian] > stakeOf[guardian]) {
            lockedStakeOf[guardian] = stakeOf[guardian];
        }

        address recipient = treasury;
        PayoutLib.send(recipient, slashAmount);

        emit StakeSlashed(guardian, slashAmount, stakeOf[guardian], recipient);
    }

    function slashTo(address guardian, uint256 amount, address recipient) external onlyAuthorizedSlasher {
        require(amount > 0, "StakingManager: zero amount");
        require(recipient != address(0), "StakingManager: zero recipient");
        require(stakeOf[guardian] > 0, "StakingManager: no stake to slash");

        uint256 slashAmount = amount;
        if (slashAmount > stakeOf[guardian]) {
            slashAmount = stakeOf[guardian];
        }

        stakeOf[guardian] -= slashAmount;
        if (lockedStakeOf[guardian] > stakeOf[guardian]) {
            lockedStakeOf[guardian] = stakeOf[guardian];
        }

        PayoutLib.send(recipient, slashAmount);

        emit StakeSlashed(guardian, slashAmount, stakeOf[guardian], recipient);
    }

    /// @notice Take a Guardian penalty of `amount` in one step, at most guardianPenaltyCap and
    ///         at most the stake: REPORTER_SHARE_BPS of what is taken goes to `reporter`, the
    ///         rest to the treasury. With no reporter (zero, or the Guardian itself) the
    ///         treasury gets it all. The caller names the reporter, never where the rest goes.
    ///         A zero cap takes nothing. Returns what was taken.
    function slashGuardianPenalty(address guardian, uint256 amount, address reporter)
        external
        onlyAuthorizedSlasher
        returns (uint256 slashed)
    {
        uint256 cap = guardianPenaltyCap(guardian);
        slashed = amount < cap ? amount : cap;
        if (slashed == 0) return 0;
        uint256 stake = stakeOf[guardian];
        require(stake > 0, "StakingManager: no stake to slash");
        if (slashed > stake) slashed = stake;

        stake -= slashed;
        stakeOf[guardian] = stake;
        if (lockedStakeOf[guardian] > stake) {
            lockedStakeOf[guardian] = stake;
        }

        uint256 share = reporter == address(0) || reporter == guardian ? 0 : slashed * REPORTER_SHARE_BPS / 10_000;
        address recipient = treasury;
        PayoutLib.send(recipient, slashed - share);
        emit StakeSlashed(guardian, slashed - share, stake, recipient);
        if (share != 0) {
            PayoutLib.send(reporter, share);
            emit StakeSlashed(guardian, share, stake, reporter);
        }
    }

    /// @notice Most one penalty takes from `guardian`: GUARDIAN_PENALTY_CAP_BPS of the minimum
    ///         stake GuardianRegistry admitted it with. A later minimum, a top-up or a
    ///         re-registration does not change it. Without a registry or a record it is zero.
    function guardianPenaltyCap(address guardian) public view returns (uint256) {
        if (guardianRegistry == address(0)) return 0;
        return IGuardianRegistry(guardianRegistry).admissionMinStakeOf(guardian) * GUARDIAN_PENALTY_CAP_BPS / 10_000;
    }

    /// @notice Most a Guardian penalty may be set to: GUARDIAN_PENALTY_CAP_BPS of the minimum
    ///         stake new Guardians are admitted with. Guardians admitted under a different
    ///         minimum are still charged at most their own cap.
    function maxGuardianPenaltyWei() external view returns (uint256) {
        if (guardianRegistry == address(0)) return 0;
        return IGuardianRegistry(guardianRegistry).minStake() * GUARDIAN_PENALTY_CAP_BPS / 10_000;
    }

    function availableStake(address guardian) public view returns (uint256) {
        uint256 stake = stakeOf[guardian];
        uint256 locked = lockedStakeOf[guardian];
        return stake <= locked ? 0 : stake - locked;
    }

    function hasMinimumStake(address guardian) public view returns (bool) {
        return stakeOf[guardian] >= minStake;
    }
}
