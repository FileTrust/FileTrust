// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: GuardianRegistry
// Purpose:  Who the Guardians are, the keys shares are encrypted to, and the stake
//           each one has put behind its word.
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
import {FileTrustDeprecatable} from "./governance/FileTrustDeprecatable.sol";
import "./PayoutLib.sol";

interface IStakingManager {
    function depositStakeFor(address guardian) external payable;
    function withdrawStakeFor(address guardian, uint256 amount) external;
    function stakeOf(address guardian) external view returns (uint256);
    function hasMinimumStake(address guardian) external view returns (bool);
}

interface IRewardManager_Registry {
    function creditGuardianJoin(address guardian) external;
}

interface IGuardianShareProof_Registry {
    function hasActiveGuardianObligations(address guardian) external view returns (bool);
}

interface IReputationManager {
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
            uint64 lastActivityAt
        );
}

/**
 * GuardianRegistry
 *
 * Launch-focused registry for Guardian identity, status, public encryption key,
 * metadata, and Guardian-declared service fees.
 *
 * Notes:
 * - Guardian extra fees stay here because they belong to the Guardian profile.
 * - Reputation updates are delegated to ReputationManager when configured.
 * - Stake storage is kept here for backward compatibility with the current codebase.
 *   StakingManager becomes the source of truth when configured. It is bound once,
 *   before any Guardian registers, so stake is never stranded here and the registry
 *   never switches back to holding it.
 * - The registry is not a second way to move stake: it refuses FTU sent to it directly,
 *   and nobody, the owner included, can pay out a Guardian's stake from it except that
 *   Guardian's own withdrawal.
 */
contract GuardianRegistry is FileTrustOwnable, FileTrustDeprecatable {
    struct GuardianProfile {
        address guardianAddress;

        // Public key used by DO / protocol to encrypt DKG and TElG shares for this Guardian.
        bytes encryptionPublicKey;

        // Baby Jubjub key used by the zkDKG migration lane. This is separate from
        // the legacy X25519 transport key and is the key referenced by the
        // dealer-justification circuit adapted from soberm/zkDKG.
        uint256 dkgBabyJubjubPublicKeyX;
        uint256 dkgBabyJubjubPublicKeyY;

        // Optional off-chain metadata URI, for example IPFS/HTTPS JSON.
        string metadataURI;

        // Guardian-declared extra service fees.
        // These are not protocol SU base prices. They are Guardian premium fees.
        uint256 dkgFee;
        uint256 telgFee;
        uint256 refreshFee;

        // Backward-compatible stake field.
        // Later this can be mirrored/moved to StakingManager.
        uint256 stake;

        // Backward-compatible reputation/activity fields.
        // ReputationManager should be the main writer once deployed.
        uint32 reputationScore;
        uint32 completedJobs;
        uint32 failedJobs;
        uint32 disputes;

        // Status data.
        bool active;
        uint64 registeredAt;
        uint64 lastHeartbeat;
    }

    struct GuardianServicePricing {
        uint256 dkgMaterialSu;
        uint256 dkgShareKeySu;
        uint256 preBatchPartialSu;
        uint256 dailyShareCustodySu;
        uint256 maxServiceDays;
        bool exists;
    }

    uint256 public minStake;

    address public reputationManager;
    address public stakingManager;
    address public rewardManager;
    address public pricingManager;
    address public guardianShareProof;

    mapping(address => GuardianProfile) private _guardians;
    mapping(address => GuardianServicePricing) private _guardianServicePricing;
    address[] private _guardianList;
    mapping(address => bool) private _knownGuardian;
    /// @notice The minimum stake each Guardian was admitted with, recorded at its first
    ///         registration. StakingManager caps a Guardian penalty at 1% of it, so a later
    ///         minimum, a top-up or a re-registration never raises a Guardian's cap.
    mapping(address => uint256) public admissionMinStakeOf;

    event MinStakeUpdated(uint256 minStake);
    event ManagerUpdated(bytes32 indexed managerType, address indexed manager);

    event GuardianRegistered(
        address indexed guardian,
        uint256 stake,
        uint256 dkgFee,
        uint256 telgFee,
        uint256 refreshFee
    );

    event GuardianUpdated(
        address indexed guardian,
        uint256 dkgFee,
        uint256 telgFee,
        uint256 refreshFee
    );

    event GuardianFeesUpdated(
        address indexed guardian,
        uint256 dkgFee,
        uint256 telgFee,
        uint256 refreshFee
    );

    event GuardianServicePricingUpdated(
        address indexed guardian,
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 preBatchPartialSu
    );

    event GuardianServicePricingWithCustodyUpdated(
        address indexed guardian,
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 preBatchPartialSu,
        uint256 dailyShareCustodySu
    );

    event GuardianServiceAvailabilityUpdated(address indexed guardian, uint256 maxServiceDays);

    event GuardianPricesUpdated(
        address indexed guardian,
        uint256 dkgSu,
        uint256 preSu,
        uint256 dailyShareCustodySu
    );

    event GuardianStatusChanged(address indexed guardian, bool active);
    event GuardianHeartbeat(address indexed guardian, uint64 timestamp);
    event GuardianStakeDeposited(address indexed guardian, uint256 amount, uint256 totalStake);
    event GuardianStakeWithdrawn(address indexed guardian, uint256 amount, uint256 remainingStake);
    // No longer emitted (slashing happens in StakingManager); kept for ABI stability.
    event GuardianStakeSlashed(address indexed guardian, uint256 amount, uint256 remainingStake, address indexed recipient);
    event GuardianDkgBabyJubjubKeyUpdated(address indexed guardian, uint256 x, uint256 y);

    event ReputationUpdated(
        address indexed guardian,
        uint32 reputationScore,
        uint32 completedJobs,
        uint32 failedJobs,
        uint32 disputes
    );

    modifier onlyKnownGuardian(address guardian) {
        require(_knownGuardian[guardian], "Registry: unknown guardian");
        _;
    }

    modifier onlyReputationWriter() {
        require(
            msg.sender == owner() || msg.sender == reputationManager,
            "Registry: not reputation writer"
        );
        _;
    }

    constructor(uint256 _minStake) Ownable(msg.sender) {
        minStake = _minStake;
    }

    /// @notice Close this version to new Guardian registrations when its successor opens
    ///         (Phase 2), for good. Registered Guardians keep updating, staking, serving
    ///         and withdrawing.
    function deprecate(address successor) external onlyOwner { _deprecate(successor); }

    function setMinStake(uint256 _minStake) external onlyOwner {
        minStake = _minStake;
        emit MinStakeUpdated(_minStake);
    }

    function setReputationManager(address manager) external onlyOwner {
        reputationManager = manager;
        emit ManagerUpdated("REPUTATION_MANAGER", manager);
    }

    function setStakingManager(address manager) external onlyOwner {
        require(stakingManager == address(0), "Registry: staking manager already set");
        require(manager.code.length != 0, "Registry: invalid staking manager");
        // Before anyone registers, so no stake held here is ever stranded behind it.
        require(_guardianList.length == 0, "Registry: guardians already registered");
        stakingManager = manager;
        emit ManagerUpdated("STAKING_MANAGER", manager);
    }

    function setRewardManager(address manager) external onlyOwner {
        rewardManager = manager;
        emit ManagerUpdated("REWARD_MANAGER", manager);
    }

    function setPricingManager(address manager) external onlyOwner {
        pricingManager = manager;
        emit ManagerUpdated("PRICING_MANAGER", manager);
    }

    function setGuardianShareProof(address shareProof) external onlyOwner {
        guardianShareProof = shareProof;
        emit ManagerUpdated("GUARDIAN_SHARE_PROOF", shareProof);
    }

    function registerGuardian(
        bytes calldata encryptionPublicKey,
        string calldata metadataURI,
        uint256 dkgFee,
        uint256 telgFee,
        uint256 refreshFee,
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 preBatchPartialSu,
        uint256 dailyShareCustodySu,
        uint256 maxServiceDays
    ) external payable {
        require(encryptionPublicKey.length > 0, "Registry: empty public key");

        GuardianProfile storage g = _guardians[msg.sender];

        if (!_knownGuardian[msg.sender]) {
            _requireNotDeprecated();
            _knownGuardian[msg.sender] = true;
            admissionMinStakeOf[msg.sender] = minStake;
            _guardianList.push(msg.sender);
            g.registeredAt = uint64(block.timestamp);
            g.guardianAddress = msg.sender;
            g.reputationScore = 100;
            if (rewardManager != address(0)) {
                try IRewardManager_Registry(rewardManager).creditGuardianJoin(msg.sender) {} catch {}
            }
        }

        if (stakingManager != address(0)) {
            if (msg.value > 0) {
                IStakingManager(stakingManager).depositStakeFor{value: msg.value}(msg.sender);
            }
            g.stake = IStakingManager(stakingManager).stakeOf(msg.sender);
        } else {
            if (msg.value > 0) {
                g.stake += msg.value;
            }
        }

        require(g.stake >= minStake, "Registry: insufficient stake");

        g.encryptionPublicKey = encryptionPublicKey;
        g.metadataURI = metadataURI;
        g.dkgFee = dkgFee;
        g.telgFee = telgFee;
        g.refreshFee = refreshFee;
        g.active = true;
        g.lastHeartbeat = uint64(block.timestamp);

        _guardianServicePricing[msg.sender] = GuardianServicePricing({
            dkgMaterialSu: dkgMaterialSu,
            dkgShareKeySu: dkgShareKeySu,
            preBatchPartialSu: preBatchPartialSu,
            dailyShareCustodySu: dailyShareCustodySu,
            maxServiceDays: maxServiceDays,
            exists: true
        });

        emit GuardianRegistered(msg.sender, g.stake, dkgFee, telgFee, refreshFee);
        emit GuardianServicePricingUpdated(msg.sender, dkgMaterialSu, dkgShareKeySu, preBatchPartialSu);
        emit GuardianServicePricingWithCustodyUpdated(msg.sender, dkgMaterialSu, dkgShareKeySu, preBatchPartialSu, dailyShareCustodySu);
        emit GuardianServiceAvailabilityUpdated(msg.sender, maxServiceDays);
        emit GuardianPricesUpdated(msg.sender, dkgMaterialSu + dkgShareKeySu, preBatchPartialSu, dailyShareCustodySu);
    }

    function updateGuardian(
        bytes calldata encryptionPublicKey,
        string calldata metadataURI,
        uint256 dkgFee,
        uint256 telgFee,
        uint256 refreshFee
    ) external onlyKnownGuardian(msg.sender) {
        require(encryptionPublicKey.length > 0, "Registry: empty public key");

        GuardianProfile storage g = _guardians[msg.sender];

        g.encryptionPublicKey = encryptionPublicKey;
        g.metadataURI = metadataURI;
        g.dkgFee = dkgFee;
        g.telgFee = telgFee;
        g.refreshFee = refreshFee;

        emit GuardianUpdated(msg.sender, dkgFee, telgFee, refreshFee);
        emit GuardianFeesUpdated(msg.sender, dkgFee, telgFee, refreshFee);
    }

    function updateGuardianFees(
        uint256 dkgFee,
        uint256 telgFee,
        uint256 refreshFee
    ) external onlyKnownGuardian(msg.sender) {
        GuardianProfile storage g = _guardians[msg.sender];

        g.dkgFee = dkgFee;
        g.telgFee = telgFee;
        g.refreshFee = refreshFee;

        emit GuardianFeesUpdated(msg.sender, dkgFee, telgFee, refreshFee);
    }

    function setGuardianServicePricing(
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 preBatchPartialSu
    ) external onlyKnownGuardian(msg.sender) {
        GuardianServicePricing storage existing = _guardianServicePricing[msg.sender];
        _guardianServicePricing[msg.sender] = GuardianServicePricing({
            dkgMaterialSu: dkgMaterialSu,
            dkgShareKeySu: dkgShareKeySu,
            preBatchPartialSu: preBatchPartialSu,
            dailyShareCustodySu: existing.dailyShareCustodySu,
            maxServiceDays: existing.maxServiceDays,
            exists: true
        });

        emit GuardianServicePricingUpdated(
            msg.sender,
            dkgMaterialSu,
            dkgShareKeySu,
            preBatchPartialSu
        );
        emit GuardianServicePricingWithCustodyUpdated(
            msg.sender,
            dkgMaterialSu,
            dkgShareKeySu,
            preBatchPartialSu,
            existing.dailyShareCustodySu
        );
        emit GuardianPricesUpdated(
            msg.sender,
            dkgMaterialSu + dkgShareKeySu,
            preBatchPartialSu,
            existing.dailyShareCustodySu
        );
    }

    function setGuardianServicePricingWithCustody(
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 preBatchPartialSu,
        uint256 dailyShareCustodySu
    ) external onlyKnownGuardian(msg.sender) {
        GuardianServicePricing storage existing = _guardianServicePricing[msg.sender];
        _guardianServicePricing[msg.sender] = GuardianServicePricing({
            dkgMaterialSu: dkgMaterialSu,
            dkgShareKeySu: dkgShareKeySu,
            preBatchPartialSu: preBatchPartialSu,
            dailyShareCustodySu: dailyShareCustodySu,
            maxServiceDays: existing.maxServiceDays,
            exists: true
        });

        emit GuardianServicePricingUpdated(
            msg.sender,
            dkgMaterialSu,
            dkgShareKeySu,
            preBatchPartialSu
        );
        emit GuardianServicePricingWithCustodyUpdated(
            msg.sender,
            dkgMaterialSu,
            dkgShareKeySu,
            preBatchPartialSu,
            dailyShareCustodySu
        );
        emit GuardianPricesUpdated(
            msg.sender,
            dkgMaterialSu + dkgShareKeySu,
            preBatchPartialSu,
            dailyShareCustodySu
        );
    }

    function setGuardianPrices(
        uint256 dkgSU,
        uint256 preSU,
        uint256 dailyShareCustodySU
    ) external onlyKnownGuardian(msg.sender) {
        GuardianServicePricing storage existing = _guardianServicePricing[msg.sender];
        _guardianServicePricing[msg.sender] = GuardianServicePricing({
            dkgMaterialSu: dkgSU,
            dkgShareKeySu: 0,
            preBatchPartialSu: preSU,
            dailyShareCustodySu: dailyShareCustodySU,
            maxServiceDays: existing.maxServiceDays,
            exists: true
        });

        emit GuardianServicePricingUpdated(
            msg.sender,
            dkgSU,
            0,
            preSU
        );
        emit GuardianServicePricingWithCustodyUpdated(
            msg.sender,
            dkgSU,
            0,
            preSU,
            dailyShareCustodySU
        );
        emit GuardianPricesUpdated(
            msg.sender,
            dkgSU,
            preSU,
            dailyShareCustodySU
        );
    }

    function setGuardianServicePricingWithAvailability(
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 preBatchPartialSu,
        uint256 dailyShareCustodySu,
        uint256 maxServiceDays
    ) external onlyKnownGuardian(msg.sender) {
        _guardianServicePricing[msg.sender] = GuardianServicePricing({
            dkgMaterialSu: dkgMaterialSu,
            dkgShareKeySu: dkgShareKeySu,
            preBatchPartialSu: preBatchPartialSu,
            dailyShareCustodySu: dailyShareCustodySu,
            maxServiceDays: maxServiceDays,
            exists: true
        });

        emit GuardianServicePricingUpdated(
            msg.sender,
            dkgMaterialSu,
            dkgShareKeySu,
            preBatchPartialSu
        );
        emit GuardianServicePricingWithCustodyUpdated(
            msg.sender,
            dkgMaterialSu,
            dkgShareKeySu,
            preBatchPartialSu,
            dailyShareCustodySu
        );
        emit GuardianServiceAvailabilityUpdated(msg.sender, maxServiceDays);
        emit GuardianPricesUpdated(
            msg.sender,
            dkgMaterialSu + dkgShareKeySu,
            preBatchPartialSu,
            dailyShareCustodySu
        );
    }

    function setGuardianPricesWithAvailability(
        uint256 dkgSU,
        uint256 preSU,
        uint256 dailyShareCustodySU,
        uint256 maxServiceDays
    ) external onlyKnownGuardian(msg.sender) {
        _guardianServicePricing[msg.sender] = GuardianServicePricing({
            dkgMaterialSu: dkgSU,
            dkgShareKeySu: 0,
            preBatchPartialSu: preSU,
            dailyShareCustodySu: dailyShareCustodySU,
            maxServiceDays: maxServiceDays,
            exists: true
        });

        emit GuardianServicePricingUpdated(
            msg.sender,
            dkgSU,
            0,
            preSU
        );
        emit GuardianServicePricingWithCustodyUpdated(
            msg.sender,
            dkgSU,
            0,
            preSU,
            dailyShareCustodySU
        );
        emit GuardianServiceAvailabilityUpdated(msg.sender, maxServiceDays);
        emit GuardianPricesUpdated(
            msg.sender,
            dkgSU,
            preSU,
            dailyShareCustodySU
        );
    }

    function setDkgBabyJubjubPublicKey(uint256 x, uint256 y) external onlyKnownGuardian(msg.sender) {
        require(x != 0 || y != 0, "Registry: empty BabyJub key");
        GuardianProfile storage g = _guardians[msg.sender];
        g.dkgBabyJubjubPublicKeyX = x;
        g.dkgBabyJubjubPublicKeyY = y;
        emit GuardianDkgBabyJubjubKeyUpdated(msg.sender, x, y);
    }

    function depositStake() external payable onlyKnownGuardian(msg.sender) {
        require(msg.value > 0, "Registry: zero deposit");

        GuardianProfile storage g = _guardians[msg.sender];
        if (stakingManager != address(0)) {
            IStakingManager(stakingManager).depositStakeFor{value: msg.value}(msg.sender);
            g.stake = IStakingManager(stakingManager).stakeOf(msg.sender);
        } else {
            g.stake += msg.value;
        }

        emit GuardianStakeDeposited(msg.sender, msg.value, g.stake);
    }

    function withdrawStake(uint256 amount) external onlyKnownGuardian(msg.sender) {
        require(amount > 0, "Registry: zero amount");

        GuardianProfile storage g = _guardians[msg.sender];
        require(!g.active, "Registry: deactivate first");

        if (stakingManager != address(0)) {
            // StakingManager pays the Guardian and applies all of its own rules,
            // obligations included.
            IStakingManager(stakingManager).withdrawStakeFor(msg.sender, amount);
            g.stake = IStakingManager(stakingManager).stakeOf(msg.sender);
        } else {
            if (guardianShareProof != address(0)) {
                require(
                    !IGuardianShareProof_Registry(guardianShareProof).hasActiveGuardianObligations(msg.sender),
                    "Registry: active service obligations"
                );
            }
            require(g.stake >= amount, "Registry: insufficient stake");
            g.stake -= amount;
            PayoutLib.send(msg.sender, amount);
        }

        emit GuardianStakeWithdrawn(msg.sender, amount, g.stake);
    }

    function setActive(bool active) external onlyKnownGuardian(msg.sender) {
        GuardianProfile storage g = _guardians[msg.sender];

        if (active) {
            require(g.stake >= minStake, "Registry: insufficient stake");
            require(g.encryptionPublicKey.length > 0, "Registry: empty public key");
        }

        g.active = active;

        emit GuardianStatusChanged(msg.sender, active);
    }

    function heartbeat() external onlyKnownGuardian(msg.sender) {
        GuardianProfile storage g = _guardians[msg.sender];
        g.lastHeartbeat = uint64(block.timestamp);

        emit GuardianHeartbeat(msg.sender, uint64(block.timestamp));
    }

    function updateReputation(
        address guardian,
        uint32 reputationScore,
        uint32 completedJobs,
        uint32 failedJobs,
        uint32 disputes
    ) external onlyReputationWriter onlyKnownGuardian(guardian) {
        GuardianProfile storage g = _guardians[guardian];

        g.reputationScore = reputationScore;
        g.completedJobs = completedJobs;
        g.failedJobs = failedJobs;
        g.disputes = disputes;

        emit ReputationUpdated(
            guardian,
            reputationScore,
            completedJobs,
            failedJobs,
            disputes
        );
    }

    function recordActivity(
        address guardian,
        uint32 completedDelta,
        uint32 failedDelta,
        uint32 disputeDelta,
        int32 reputationDelta
    ) external onlyReputationWriter onlyKnownGuardian(guardian) {
        GuardianProfile storage g = _guardians[guardian];

        g.completedJobs += completedDelta;
        g.failedJobs += failedDelta;
        g.disputes += disputeDelta;

        if (reputationDelta >= 0) {
            uint256 newScore = uint256(g.reputationScore) + uint32(reputationDelta);
            g.reputationScore = newScore > type(uint32).max ? type(uint32).max : uint32(newScore);
        } else {
            uint32 penalty = uint32(-reputationDelta);
            g.reputationScore = penalty >= g.reputationScore ? 0 : g.reputationScore - penalty;
        }

        emit ReputationUpdated(
            guardian,
            g.reputationScore,
            g.completedJobs,
            g.failedJobs,
            g.disputes
        );
    }

    function getGuardian(address guardian) external view returns (GuardianProfile memory) {
        GuardianProfile memory g = _guardians[guardian];

        if (stakingManager != address(0)) {
            g.stake = IStakingManager(stakingManager).stakeOf(guardian);
        }

        if (reputationManager != address(0)) {
            (
                uint32 _reputationScore,
                uint32 _completedDKG,
                uint32 _failedDKG,
                uint32 _completedPRE,
                uint32 _failedPRE,
                uint32 _dkgComplaints,
                uint32 _preComplaints, ,
            ) = IReputationManager(reputationManager).getGuardianStats(guardian);
            g.reputationScore = _reputationScore;
            g.completedJobs = _completedDKG + _completedPRE;
            g.failedJobs = _failedDKG + _failedPRE;
            g.disputes = _dkgComplaints + _preComplaints;
        }

        return g;
    }

    function getGuardianCount() external view returns (uint256) {
        return _guardianList.length;
    }

    function getGuardianAt(uint256 index) external view returns (address) {
        return _guardianList[index];
    }

    function getAllGuardians() external view returns (address[] memory) {
        return _guardianList;
    }

    function isRegisteredGuardian(address guardian) external view returns (bool) {
        return _knownGuardian[guardian];
    }

    function isActiveGuardian(address guardian) external view returns (bool) {
        GuardianProfile storage g = _guardians[guardian];
        bool meetsStake = g.stake >= minStake;
        if (stakingManager != address(0)) {
            meetsStake = IStakingManager(stakingManager).hasMinimumStake(guardian);
        }
        return _knownGuardian[guardian] && g.active && meetsStake;
    }

    function getGuardianPublicKey(address guardian) external view returns (bytes memory) {
        return _guardians[guardian].encryptionPublicKey;
    }

    function getGuardianDkgBabyJubjubPublicKey(address guardian) external view returns (uint256 x, uint256 y) {
        GuardianProfile storage g = _guardians[guardian];
        return (g.dkgBabyJubjubPublicKeyX, g.dkgBabyJubjubPublicKeyY);
    }

    function getGuardianFees(
        address guardian
    ) external view returns (uint256 dkgFee, uint256 telgFee, uint256 refreshFee) {
        GuardianProfile storage g = _guardians[guardian];
        return (g.dkgFee, g.telgFee, g.refreshFee);
    }

    function getGuardianServicePricing(
        address guardian
    ) external view returns (uint256 dkgMaterialSu, uint256 dkgShareKeySu, uint256 preBatchPartialSu) {
        GuardianServicePricing storage pricing = _guardianServicePricing[guardian];
        return (pricing.dkgMaterialSu, pricing.dkgShareKeySu, pricing.preBatchPartialSu);
    }

    function getGuardianServicePricingWithStatus(
        address guardian
    )
        external
        view
        returns (
            uint256 dkgMaterialSu,
            uint256 dkgShareKeySu,
            uint256 preBatchPartialSu,
            bool exists
        )
    {
        GuardianServicePricing storage pricing = _guardianServicePricing[guardian];
        return (
            pricing.dkgMaterialSu,
            pricing.dkgShareKeySu,
            pricing.preBatchPartialSu,
            pricing.exists
        );
    }

    function hasGuardianServicePricing(address guardian) external view returns (bool) {
        return _guardianServicePricing[guardian].exists;
    }

    function getGuardianServicePricingWithCustody(
        address guardian
    )
        external
        view
        returns (
            uint256 dkgMaterialSu,
            uint256 dkgShareKeySu,
            uint256 preBatchPartialSu,
            uint256 dailyShareCustodySu,
            bool exists
        )
    {
        GuardianServicePricing storage pricing = _guardianServicePricing[guardian];
        return (
            pricing.dkgMaterialSu,
            pricing.dkgShareKeySu,
            pricing.preBatchPartialSu,
            pricing.dailyShareCustodySu,
            pricing.exists
        );
    }

    function getGuardianPrices(
        address guardian
    ) external view returns (uint256 dkgSU, uint256 preSU, uint256 dailyShareCustodySU, bool exists) {
        GuardianServicePricing storage pricing = _guardianServicePricing[guardian];
        return (
            pricing.dkgMaterialSu + pricing.dkgShareKeySu,
            pricing.preBatchPartialSu,
            pricing.dailyShareCustodySu,
            pricing.exists
        );
    }

    function getGuardianAvailability(
        address guardian
    ) external view returns (uint256 maxServiceDays, bool unlimited, bool exists) {
        GuardianServicePricing storage pricing = _guardianServicePricing[guardian];
        return (pricing.maxServiceDays, pricing.maxServiceDays == 0, pricing.exists);
    }

    function getGuardianServiceInfo(
        address guardian
    )
        external
        view
        returns (
            uint256 dkgMaterialSu,
            uint256 dkgShareKeySu,
            uint256 preBatchPartialSu,
            uint256 dailyShareCustodySu,
            uint256 maxServiceDays,
            bool exists
        )
    {
        GuardianServicePricing storage pricing = _guardianServicePricing[guardian];
        return (
            pricing.dkgMaterialSu,
            pricing.dkgShareKeySu,
            pricing.preBatchPartialSu,
            pricing.dailyShareCustodySu,
            pricing.maxServiceDays,
            pricing.exists
        );
    }

    function getGuardianPricesWithAvailability(
        address guardian
    )
        external
        view
        returns (
            uint256 dkgSU,
            uint256 preSU,
            uint256 dailyShareCustodySU,
            uint256 maxServiceDays,
            bool exists
        )
    {
        GuardianServicePricing storage pricing = _guardianServicePricing[guardian];
        return (
            pricing.dkgMaterialSu + pricing.dkgShareKeySu,
            pricing.preBatchPartialSu,
            pricing.dailyShareCustodySu,
            pricing.maxServiceDays,
            pricing.exists
        );
    }

    function getGuardianOperationalStatus(
        address guardian
    ) external view returns (
        bool registered,
        bool active,
        uint256 stake,
        uint32 reputationScore,
        uint32 completedJobs,
        uint32 failedJobs,
        uint32 disputes,
        uint64 lastHeartbeat
    ) {
        GuardianProfile storage g = _guardians[guardian];
        uint256 stakeValue = g.stake;
        uint32 reputationValue = g.reputationScore;
        uint32 completedValue = g.completedJobs;
        uint32 failedValue = g.failedJobs;
        uint32 disputesValue = g.disputes;

        if (stakingManager != address(0)) {
            stakeValue = IStakingManager(stakingManager).stakeOf(guardian);
        }

        if (reputationManager != address(0)) {
            (
                uint32 _reputationScore,
                uint32 _completedDKG,
                uint32 _failedDKG,
                uint32 _completedPRE,
                uint32 _failedPRE,
                uint32 _dkgComplaints,
                uint32 _preComplaints, ,
            ) = IReputationManager(reputationManager).getGuardianStats(guardian);
            reputationValue = _reputationScore;
            completedValue = _completedDKG + _completedPRE;
            failedValue = _failedDKG + _failedPRE;
            disputesValue = _dkgComplaints + _preComplaints;
        }

        return (
            _knownGuardian[guardian],
            g.active,
            stakeValue,
            reputationValue,
            completedValue,
            failedValue,
            disputesValue,
            g.lastHeartbeat
        );
    }
}
