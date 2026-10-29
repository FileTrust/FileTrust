// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: RewardManager
// Purpose:  The pools that pay for storage, proofs and access, and the escrow held
//           behind each job until the work is done.
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

interface IAccessControlFT_Rewards {
    enum DkgMode {
        LEGACY,
        ZKDKG_V2
    }

    function getFilePolicy(bytes32 fileId)
        external
        view
        returns (bool exists, bool active, address dataOwner, uint8 threshold, address[] memory guardians);
    function getFilePolicyMode(bytes32 fileId) external view returns (DkgMode);
    function hasRequestedKeyGenForFile(bytes32 fileId) external view returns (bool);
}

interface IDataVault_Rewards {
    function isAccessRequestAuthorized(uint256 requestId) external view returns (bool);
    function admitAccessRequest(uint256 requestId) external;
    function getAccessRequest(uint256 requestId)
        external
        view
        returns (
            bool exists,
            bytes32 fileId,
            address requester,
            uint256 batchId,
            string memory dataId,
            uint64 ts,
            uint32 keyEpoch,
            uint256 pkReqX,
            uint256 pkReqY,
            uint256[] memory indices
        );
}

interface IGuardianRegistryPricing_Rewards {
    function getGuardianServicePricingWithStatus(address guardian)
        external
        view
        returns (
            uint256 dkgMaterialSu,
            uint256 dkgShareKeySu,
            uint256 preBatchPartialSu,
            bool exists
        );

    function getGuardianServicePricingWithCustody(address guardian)
        external
        view
        returns (
            uint256 dkgMaterialSu,
            uint256 dkgShareKeySu,
            uint256 preBatchPartialSu,
            uint256 dailyShareCustodySu,
            bool exists
        );
}

/// @dev Who may move escrowed money is fixed at deployment. The rewarders are bound once,
///      as protocol contracts, and can only be revoked afterwards; the ACL is fixed at
///      construction and the DataVault and Guardian price list are bound once. Every
///      refund pays the data owner or requester the ACL or DataVault records, never an
///      address a caller names. Reward pools take deposits from anyone and pay out only
///      through the rewarders' credits.
contract RewardManager is FileTrustOwnable {
    bytes32 public constant ACTION_V2_DKG_MATERIAL = "V2_DKG_MATERIAL";
    bytes32 public constant ACTION_V2_DKG_SHARE_KEY = "V2_DKG_SHARE_KEY";
    bytes32 public constant ACTION_V2_PRE_BATCH_PARTIAL = "V2_PRE_BATCH_PARTIAL";
    bytes32 public constant ACTION_V2_PRE_READY_NOT_USED = "V2_PRE_READY_NOT_USED";

    uint256 public suToWeiRate;
    uint256 public fixedGasPriceWei = 1 gwei;

    uint256 public dkgMaterialSu = 12_000;
    uint256 public dkgShareKeySu = 6_325;
    uint256 public dkgFinalizationSu = 0;
    uint256 public preBatchPartialSu = 30_542;
    uint256 public preReadyNotUsedSu = 20;
    uint256 public v2DkgBaseSu = 100;
    uint256 public v2PreBaseSu = 50;
    uint256 public gasReimbursementBufferBps = 1_000;
    uint256 public overheadGasV2DkgMaterial = 260_000;
    uint256 public overheadGasV2DkgShareKey = 70_000;
    uint256 public overheadGasV2PreBatchPartial = 120_000;
    uint256 public estimatedGasV2DkgMaterial = 520_000;
    uint256 public estimatedGasV2DkgShareKey = 190_000;
    uint256 public estimatedGasV2PreBatchPartial = 1_250_000;
    uint256 public estimatedGasKeyGenRequest = 100_000;
    uint256 public estimatedGasPreRequest = 200_000;

    uint256 public joinRewardPool;
    uint256 public joinRewardWei;

    uint256 public proofRewardPool;
    uint256 public proofRewardWei;

    uint256 public vkJoinRewardPool;
    uint256 public vkJoinRewardWei;

    uint256 public vkProofRewardPool;
    uint256 public vkProofRewardWei;

    uint256 public vkFileRewardPool;
    uint256 public vkFileRewardWei;

    // Capacity reward: per proven GB (1e9 bytes) of a keeper's space, up to a per-keeper
    // cap, paid once for the largest space proven. See creditVKCapacity.
    uint256 public vkCapacityRewardPool;
    uint256 public vkCapacityRewardPerGbWei;
    uint256 public vkCapacityRewardCapWei;
    mapping(address => uint256) public vkCapacityRewardPaid;

    IAccessControlFT_Rewards public acl;
    IDataVault_Rewards public dataVault;
    IGuardianRegistryPricing_Rewards public guardianRegistry;

    struct PolicyEscrow {
        uint128 balance;    // current spendable balance
        uint128 deposited;  // cumulative total ever deposited (never decremented)
    }

    /// @dev One paid stretch of custody days. The first service term is one
    ///      stretch and every renewal adds another, each carrying the prices
    ///      that were true when the DO bought it. See the custody section below.
    struct CustodyStretch {
        uint64  startTime;
        uint64  endTime;
        uint128 reservedWei;  // price of this stretch, frozen at purchase
        uint128 paidWei;      // how much Guardians have drawn from it so far
        bool    active;       // false while a renewal still waits for consent
        // Where this stretch's frozen prices are filed. Handed out once and
        // never again, so a cancelled stretch cannot leave prices behind for a
        // later stretch to inherit — see releaseCustodyStretch.
        uint32  priceBook;
    }

    mapping(address => bool) public authorizedRewarders;
    /// @notice True once the rewarders are bound; from then on they can only be revoked.
    bool public rewardersBound;
    mapping(bytes32 => PolicyEscrow) private _policyEscrowData;
    mapping(uint256 => uint256) private _accessEscrow;
    mapping(address => uint256) private _claimable;
    mapping(bytes32 => mapping(address => uint256)) private _earnedByPolicy;
    mapping(uint256 => mapping(address => uint256)) private _earnedByAccessRequest;
    mapping(bytes32 => uint256) private _refundedByPolicy;
    mapping(uint256 => uint256) private _depositedByAccessRequest;
    mapping(uint256 => uint256) private _refundedByAccessRequest;
    mapping(uint256 => bool) private _accessEscrowComplete;
    /// @dev request => Guardian => its PRE price in service units plus one, frozen when
    ///      the requester first paid for the request (zero: no price frozen).
    mapping(uint256 => mapping(address => uint256)) private _quotedPreSuPlusOne;

    mapping(bytes32 => CustodyStretch[]) private _custodyStretches;
    /// @dev Last price book handed out for a policy. Only ever goes up.
    mapping(bytes32 => uint32) private _custodyPriceBooks;
    /// @dev policy => price book => guardian => wei per day, frozen at purchase.
    mapping(bytes32 => mapping(uint32 => mapping(address => uint256))) private _custodyDailyRateWei;
    /// @dev policy => price book => guardian => the moment that Guardian is paid up to.
    mapping(bytes32 => mapping(uint32 => mapping(address => uint64))) private _custodyPaidThrough;
    /// @dev All custody money the DO has put in and not taken back.
    mapping(bytes32 => uint256) private _custodyBalance;
    /// @dev The part of that money already committed to stretches.
    mapping(bytes32 => uint256) private _custodyCommitted;

    /// @dev Ceiling on how many stretches one policy may carry, so every loop
    ///      over them stays cheap no matter how often the DO renews. Past it the
    ///      DO buys a fresh agreement rather than renewing the same one again.
    uint16 public constant maxCustodyStretches = 24;

    // No longer emitted (the ACL is fixed at construction); kept for ABI stability.
    event AccessControlSet(address indexed acl);
    event DataVaultSet(address indexed dataVault);
    event GuardianRegistrySet(address indexed guardianRegistry);
    event AuthorizedRewarderUpdated(address indexed rewarder, bool authorized);
    event SuToWeiRateUpdated(uint256 suToWeiRate);
    event FixedGasPriceUpdated(uint256 fixedGasPriceWei);
    event RewardGasConfigUpdated(
        uint256 overheadGasV2DkgMaterial,
        uint256 overheadGasV2DkgShareKey,
        uint256 overheadGasV2PreBatchPartial,
        uint256 estimatedGasV2DkgMaterial,
        uint256 estimatedGasV2DkgShareKey,
        uint256 estimatedGasV2PreBatchPartial
    );
    event PricesUpdated(
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 dkgFinalizationSu,
        uint256 preBatchPartialSu,
        uint256 preReadyNotUsedSu,
        uint256 v2DkgBaseSu,
        uint256 v2PreBaseSu,
        uint256 gasReimbursementBufferBps
    );
    event PolicyEscrowDeposited(bytes32 indexed fileId, address indexed payer, uint256 amountWei, uint256 balanceWei);
    event AccessEscrowDeposited(
        uint256 indexed requestId,
        bytes32 indexed fileId,
        address indexed requester,
        uint256 amountWei,
        uint256 balanceWei
    );
    event GuardianRewardCredited(
        bytes32 indexed fileId,
        address indexed guardian,
        bytes32 indexed rewardType,
        uint256 serviceUnits,
        uint256 amountWei
    );
    event GuardianMeasuredRewardCredited(
        bytes32 indexed fileId,
        address indexed guardian,
        bytes32 indexed rewardType,
        uint256 measuredGas,
        uint256 overheadGas,
        uint256 reimbursableGas,
        uint256 gasReimbursementWei,
        uint256 incentiveServiceUnits,
        uint256 incentiveWei,
        uint256 amountWei
    );
    event GuardianAccessRewardCredited(
        uint256 indexed requestId,
        bytes32 indexed fileId,
        address indexed guardian,
        bytes32 rewardType,
        uint256 serviceUnits,
        uint256 amountWei
    );
    event GuardianMeasuredAccessRewardCredited(
        uint256 indexed requestId,
        bytes32 indexed fileId,
        address indexed guardian,
        bytes32 rewardType,
        uint256 measuredGas,
        uint256 overheadGas,
        uint256 reimbursableGas,
        uint256 gasReimbursementWei,
        uint256 incentiveServiceUnits,
        uint256 incentiveWei,
        uint256 amountWei
    );
    event RewardsClaimed(address indexed guardian, uint256 amountWei);
    event PolicyEscrowRefunded(bytes32 indexed fileId, address indexed dataOwner, uint256 amountWei, uint256 balanceWei);
    event AccessEscrowCompleted(uint256 indexed requestId, bytes32 indexed fileId, address indexed requester);
    event AccessEscrowRefunded(
        uint256 indexed requestId,
        bytes32 indexed fileId,
        address indexed requester,
        uint256 amountWei,
        uint256 balanceWei
    );
    event JoinRewardPoolDeposited(address indexed sender, uint256 amount, uint256 balance);
    event JoinRewardAmountSet(uint256 amount);
    event GuardianJoinRewarded(address indexed guardian, uint256 amount);
    event ProofRewardPoolDeposited(address indexed sender, uint256 amount, uint256 balance);
    event ProofRewardAmountSet(uint256 amount);
    event GuardianShareProofRewarded(address indexed guardian, uint256 amount);
    event VKJoinRewardPoolDeposited(address indexed sender, uint256 amount, uint256 balance);
    event VKJoinRewardAmountSet(uint256 amount);
    event VKJoinRewarded(address indexed vk, uint256 amount);
    event VKProofRewardPoolDeposited(address indexed sender, uint256 amount, uint256 balance);
    event VKProofRewardAmountSet(uint256 amount);
    event VKProofRewarded(address indexed vk, uint256 amount);
    event VKFileRewardPoolDeposited(address indexed sender, uint256 amount, uint256 balance);
    event VKFileRewardAmountSet(uint256 amount);
    event VKFileRewarded(address indexed vk, uint256 amount);
    event VKCapacityRewardPoolDeposited(address indexed sender, uint256 amount, uint256 balance);
    event VKCapacityRewardSet(uint256 perGbWei, uint256 capWei);
    event VKCapacityRewarded(address indexed vk, uint256 provenBytes, uint256 amount);
    event CustodyEscrowDeposited(bytes32 indexed fileId, address indexed payer, uint256 amountWei, uint256 balanceWei);
    event CustodyEscrowRefunded(bytes32 indexed fileId, address indexed dataOwner, uint256 amountWei, uint256 balanceWei);
    event CustodyStretchReserved(
        bytes32 indexed fileId,
        uint256 indexed stretchIndex,
        uint64 startTime,
        uint64 endTime,
        uint256 priceWei
    );
    event CustodyStretchActivated(bytes32 indexed fileId, uint256 indexed stretchIndex);
    event CustodyStretchReleased(bytes32 indexed fileId, uint256 indexed stretchIndex, uint256 freedWei);
    event CustodyClaimed(bytes32 indexed fileId, address indexed guardian, uint256 amountWei, uint64 paidThrough);
    event GuardianRewardPricingUsed(
        address indexed guardian,
        bytes32 indexed actionType,
        uint256 serviceUnits,
        bool guardianSpecific,
        uint256 suToWeiRate
    );

    modifier onlyAuthorizedRewarder() {
        require(authorizedRewarders[msg.sender], "RewardManager: unauthorized rewarder");
        _;
    }

    constructor(address aclAddress, uint256 initialSuToWeiRate) Ownable(msg.sender) {
        require(aclAddress != address(0), "RewardManager: zero ACL");
        require(initialSuToWeiRate > 0, "RewardManager: zero rate");
        acl = IAccessControlFT_Rewards(aclAddress);
        suToWeiRate = initialSuToWeiRate;
    }

    receive() external payable {
        revert("RewardManager: use escrow deposit function");
    }

    /// @notice Bind the DataVault, once. It names every access request's requester, so
    ///         swapping it would redirect access escrow.
    function setDataVault(address dataVaultAddress) external onlyOwner {
        require(address(dataVault) == address(0) && dataVaultAddress.code.length != 0, "RewardManager: bad DataVault");
        dataVault = IDataVault_Rewards(dataVaultAddress);
        emit DataVaultSet(dataVaultAddress);
    }

    /// @notice Bind the Guardian price list, once. It sets what every credit pays.
    function setGuardianRegistry(address guardianRegistryAddress) external onlyOwner {
        require(
            address(guardianRegistry) == address(0) && guardianRegistryAddress.code.length != 0,
            "RewardManager: bad GuardianRegistry"
        );
        guardianRegistry = IGuardianRegistryPricing_Rewards(guardianRegistryAddress);
        emit GuardianRegistrySet(guardianRegistryAddress);
    }

    /// @notice Authorize the protocol contracts that credit work and refund escrow.
    ///         Called once, at deployment, with all of them; afterwards the list can
    ///         only shrink, so no owner can later add a contract, or a key, that moves
    ///         escrowed money.
    function bindRewarders(address[] calldata rewarders) external onlyOwner {
        require(!rewardersBound && rewarders.length != 0, "RewardManager: rewarders already bound");
        rewardersBound = true;
        for (uint256 i = 0; i < rewarders.length; ++i) {
            address rewarder = rewarders[i];
            require(rewarder.code.length != 0 && !authorizedRewarders[rewarder], "RewardManager: bad rewarder");
            authorizedRewarders[rewarder] = true;
            emit AuthorizedRewarderUpdated(rewarder, true);
        }
    }

    /// @notice Take a compromised rewarder's rights away for good.
    function revokeRewarder(address rewarder) external onlyOwner {
        require(authorizedRewarders[rewarder], "RewardManager: not a rewarder");
        authorizedRewarders[rewarder] = false;
        emit AuthorizedRewarderUpdated(rewarder, false);
    }

    function setSuToWeiRate(uint256 rate) external onlyOwner {
        require(rate > 0, "RewardManager: zero rate");
        suToWeiRate = rate;
        emit SuToWeiRateUpdated(rate);
    }

    function setFixedGasPriceWei(uint256 gasPriceWei) external onlyOwner {
        require(gasPriceWei > 0, "RewardManager: zero gas price");
        fixedGasPriceWei = gasPriceWei;
        emit FixedGasPriceUpdated(gasPriceWei);
    }

    function setJoinRewardWei(uint256 amount) external onlyOwner {
        joinRewardWei = amount;
        emit JoinRewardAmountSet(amount);
    }

    function depositJoinRewardPool() external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        joinRewardPool += msg.value;
        emit JoinRewardPoolDeposited(msg.sender, msg.value, joinRewardPool);
    }

    function creditGuardianJoin(address guardian) external onlyAuthorizedRewarder {
        require(guardian != address(0), "RewardManager: zero guardian");
        if (joinRewardWei == 0 || joinRewardPool < joinRewardWei) return;
        joinRewardPool -= joinRewardWei;
        PayoutLib.send(guardian, joinRewardWei);
        emit GuardianJoinRewarded(guardian, joinRewardWei);
    }

    function setProofRewardWei(uint256 amount) external onlyOwner {
        proofRewardWei = amount;
        emit ProofRewardAmountSet(amount);
    }

    function depositProofRewardPool() external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        proofRewardPool += msg.value;
        emit ProofRewardPoolDeposited(msg.sender, msg.value, proofRewardPool);
    }

    function creditShareProof(address guardian) external onlyAuthorizedRewarder {
        require(guardian != address(0), "RewardManager: zero guardian");
        if (proofRewardWei == 0 || proofRewardPool < proofRewardWei) return;
        proofRewardPool -= proofRewardWei;
        PayoutLib.send(guardian, proofRewardWei);
        emit GuardianShareProofRewarded(guardian, proofRewardWei);
    }

    function setVKJoinRewardWei(uint256 amount) external onlyOwner {
        vkJoinRewardWei = amount;
        emit VKJoinRewardAmountSet(amount);
    }

    function depositVKJoinRewardPool() external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        vkJoinRewardPool += msg.value;
        emit VKJoinRewardPoolDeposited(msg.sender, msg.value, vkJoinRewardPool);
    }

    function creditVKJoin(address vk) external onlyAuthorizedRewarder {
        if (vkJoinRewardWei == 0 || vkJoinRewardPool < vkJoinRewardWei) return;
        vkJoinRewardPool -= vkJoinRewardWei;
        PayoutLib.send(vk, vkJoinRewardWei);
        emit VKJoinRewarded(vk, vkJoinRewardWei);
    }

    function setVKProofRewardWei(uint256 amount) external onlyOwner {
        vkProofRewardWei = amount;
        emit VKProofRewardAmountSet(amount);
    }

    function depositVKProofRewardPool() external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        vkProofRewardPool += msg.value;
        emit VKProofRewardPoolDeposited(msg.sender, msg.value, vkProofRewardPool);
    }

    function creditVKProof(address vk) external onlyAuthorizedRewarder {
        if (vkProofRewardWei == 0 || vkProofRewardPool < vkProofRewardWei) return;
        vkProofRewardPool -= vkProofRewardWei;
        PayoutLib.send(vk, vkProofRewardWei);
        emit VKProofRewarded(vk, vkProofRewardWei);
    }

    function setVKFileRewardWei(uint256 amount) external onlyOwner {
        vkFileRewardWei = amount;
        emit VKFileRewardAmountSet(amount);
    }

    function depositVKFileRewardPool() external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        vkFileRewardPool += msg.value;
        emit VKFileRewardPoolDeposited(msg.sender, msg.value, vkFileRewardPool);
    }

    function creditVKFile(address vk) external onlyAuthorizedRewarder {
        if (vkFileRewardWei == 0 || vkFileRewardPool < vkFileRewardWei) return;
        vkFileRewardPool -= vkFileRewardWei;
        PayoutLib.send(vk, vkFileRewardWei);
        emit VKFileRewarded(vk, vkFileRewardWei);
    }

    /// @notice Capacity reward per proven GB, and the most one keeper can ever receive.
    ///         A zero rate or a zero cap pays nothing.
    function setVKCapacityReward(uint256 perGbWei, uint256 capWei) external onlyOwner {
        vkCapacityRewardPerGbWei = perGbWei;
        vkCapacityRewardCapWei = capWei;
        emit VKCapacityRewardSet(perGbWei, capWei);
    }

    function depositVKCapacityRewardPool() external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        vkCapacityRewardPool += msg.value;
        emit VKCapacityRewardPoolDeposited(msg.sender, msg.value, vkCapacityRewardPool);
    }

    /// @notice Pay a keeper for space it has proven: the rate for every 1e9 proven bytes, up
    ///         to the cap, minus what it was already paid. Proving the same space again pays
    ///         nothing; proving more pays only the difference. When the pool runs short the
    ///         keeper gets what is left, and the rest on a later proof after a top-up.
    function creditVKCapacity(address vk, uint256 provenBytes) external onlyAuthorizedRewarder {
        uint256 perGb = vkCapacityRewardPerGbWei;
        if (vk == address(0) || perGb == 0) return;
        uint256 earned = provenBytes * perGb / 1e9;
        if (earned > vkCapacityRewardCapWei) earned = vkCapacityRewardCapWei;
        uint256 paid = vkCapacityRewardPaid[vk];
        if (earned <= paid) return;
        uint256 amount = earned - paid;
        if (amount > vkCapacityRewardPool) amount = vkCapacityRewardPool;
        if (amount == 0) return;
        vkCapacityRewardPaid[vk] = paid + amount;
        vkCapacityRewardPool -= amount;
        PayoutLib.send(vk, amount);
        emit VKCapacityRewarded(vk, provenBytes, amount);
    }

    function setRewardGasConfig(
        uint256 _overheadGasV2DkgMaterial,
        uint256 _overheadGasV2DkgShareKey,
        uint256 _overheadGasV2PreBatchPartial,
        uint256 _estimatedGasV2DkgMaterial,
        uint256 _estimatedGasV2DkgShareKey,
        uint256 _estimatedGasV2PreBatchPartial
    ) external onlyOwner {
        overheadGasV2DkgMaterial = _overheadGasV2DkgMaterial;
        overheadGasV2DkgShareKey = _overheadGasV2DkgShareKey;
        overheadGasV2PreBatchPartial = _overheadGasV2PreBatchPartial;
        estimatedGasV2DkgMaterial = _estimatedGasV2DkgMaterial;
        estimatedGasV2DkgShareKey = _estimatedGasV2DkgShareKey;
        estimatedGasV2PreBatchPartial = _estimatedGasV2PreBatchPartial;
        emit RewardGasConfigUpdated(
            _overheadGasV2DkgMaterial,
            _overheadGasV2DkgShareKey,
            _overheadGasV2PreBatchPartial,
            _estimatedGasV2DkgMaterial,
            _estimatedGasV2DkgShareKey,
            _estimatedGasV2PreBatchPartial
        );
    }

    function setPrices(
        uint256 _dkgMaterialSu,
        uint256 _dkgShareKeySu,
        uint256 _dkgFinalizationSu,
        uint256 _preBatchPartialSu,
        uint256 _preReadyNotUsedSu,
        uint256 _v2DkgBaseSu,
        uint256 _v2PreBaseSu,
        uint256 _gasReimbursementBufferBps
    ) external onlyOwner {
        require(_gasReimbursementBufferBps <= 10_000, "RewardManager: bad buffer");
        dkgMaterialSu = _dkgMaterialSu;
        dkgShareKeySu = _dkgShareKeySu;
        dkgFinalizationSu = _dkgFinalizationSu;
        preBatchPartialSu = _preBatchPartialSu;
        preReadyNotUsedSu = _preReadyNotUsedSu;
        v2DkgBaseSu = _v2DkgBaseSu;
        v2PreBaseSu = _v2PreBaseSu;
        gasReimbursementBufferBps = _gasReimbursementBufferBps;
        emit PricesUpdated(
            _dkgMaterialSu,
            _dkgShareKeySu,
            _dkgFinalizationSu,
            _preBatchPartialSu,
            _preReadyNotUsedSu,
            _v2DkgBaseSu,
            _v2PreBaseSu,
            _gasReimbursementBufferBps
        );
    }

    function depositPolicyEscrow(bytes32 fileId) external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        (bool exists, , address dataOwner, , ) = acl.getFilePolicy(fileId);
        require(exists, "RewardManager: unknown policy");
        require(msg.sender == dataOwner, "RewardManager: not policy DO");
        _policyEscrowData[fileId].balance += uint128(msg.value);
        _policyEscrowData[fileId].deposited += uint128(msg.value);
        emit PolicyEscrowDeposited(fileId, msg.sender, msg.value, _policyEscrowData[fileId].balance);
    }

    function estimateV2DkgEscrow(bytes32 fileId) public view returns (uint256) {
        (bool exists, , , , address[] memory guardians) = acl.getFilePolicy(fileId);
        require(exists, "RewardManager: unknown policy");
        require(acl.getFilePolicyMode(fileId) == IAccessControlFT_Rewards.DkgMode.ZKDKG_V2, "RewardManager: wrong mode");
        return _estimateV2DkgEscrowForGuardianList(guardians);
    }

    function estimateV2DkgEscrowForGuardians(bytes32 fileId, address[] calldata guardians)
        external
        view
        returns (uint256)
    {
        _requireV2ModeIfPolicyExists(fileId);
        return _estimateV2DkgEscrowForGuardianList(guardians);
    }

    function estimateV2PreEscrow(bytes32 fileId, uint256) public view returns (uint256) {
        (bool exists, , , uint8 threshold, address[] memory guardians) = acl.getFilePolicy(fileId);
        require(exists, "RewardManager: unknown policy");
        require(acl.getFilePolicyMode(fileId) == IAccessControlFT_Rewards.DkgMode.ZKDKG_V2, "RewardManager: wrong mode");
        require(uint256(threshold) <= guardians.length, "RewardManager: bad threshold");
        uint256 base = _suToWei(v2PreBaseSu);
        uint256[] memory guardianCosts = new uint256[](guardians.length);
        for (uint256 i = 0; i < guardians.length; i++) {
            guardianCosts[i] = estimateRewardForGuardianAction(guardians[i], ACTION_V2_PRE_BATCH_PARTIAL);
        }
        // The escrow deposit path uses a conservative threshold subset so any
        // valid threshold of selected Guardians can be rewarded, then unused
        // escrow can be refunded after access completion.
        return _withBuffer(base + _sumLargest(guardianCosts, uint256(threshold)));
    }

    function estimateV2PreEscrowCheapest(bytes32 fileId, uint256) public view returns (uint256) {
        (bool exists, , , uint8 threshold, address[] memory guardians) = acl.getFilePolicy(fileId);
        require(exists, "RewardManager: unknown policy");
        require(acl.getFilePolicyMode(fileId) == IAccessControlFT_Rewards.DkgMode.ZKDKG_V2, "RewardManager: wrong mode");
        require(uint256(threshold) <= guardians.length, "RewardManager: bad threshold");
        uint256 base = _suToWei(v2PreBaseSu);
        uint256[] memory guardianCosts = new uint256[](guardians.length);
        for (uint256 i = 0; i < guardians.length; i++) {
            guardianCosts[i] = estimateRewardForGuardianAction(guardians[i], ACTION_V2_PRE_BATCH_PARTIAL);
        }
        return _withBuffer(base + _sumSmallest(guardianCosts, uint256(threshold)));
    }

    function estimateV2PreEscrowForGuardians(
        bytes32 fileId,
        uint256,
        address[] calldata guardians,
        uint256 threshold
    ) external view returns (uint256 minPreEscrowEstimate, uint256 maxPreEscrowEstimate) {
        _requireV2ModeIfPolicyExists(fileId);
        require(threshold <= guardians.length, "RewardManager: bad threshold");
        uint256 base = _suToWei(v2PreBaseSu);
        uint256[] memory guardianCosts = new uint256[](guardians.length);
        for (uint256 i = 0; i < guardians.length; i++) {
            guardianCosts[i] = estimateRewardForGuardianAction(guardians[i], ACTION_V2_PRE_BATCH_PARTIAL);
        }
        minPreEscrowEstimate = _withBuffer(base + _sumSmallest(_copyValues(guardianCosts), threshold));
        maxPreEscrowEstimate = _withBuffer(base + _sumLargest(guardianCosts, threshold));
    }

    function calculateReward(bytes32 actionType, uint256 measuredGas)
        public
        view
        returns (
            uint256 totalRewardWei,
            uint256 gasReimbursementWei,
            uint256 incentiveWei,
            uint256 overheadGas,
            uint256 reimbursableGas,
            uint256 incentiveServiceUnits
        )
    {
        overheadGas = _overheadGas(actionType);
        incentiveServiceUnits = _incentiveSu(actionType);
        reimbursableGas = measuredGas + overheadGas;
        gasReimbursementWei = reimbursableGas * fixedGasPriceWei;
        incentiveWei = _suToWei(incentiveServiceUnits);
        totalRewardWei = gasReimbursementWei + incentiveWei;
    }

    function estimateRewardForAction(bytes32 actionType) public view returns (uint256) {
        (uint256 totalRewardWei, , , , , ) = calculateReward(actionType, _estimatedGas(actionType));
        return totalRewardWei;
    }

    function calculateRewardForGuardian(address guardian, bytes32 actionType, uint256 measuredGas)
        public
        view
        returns (
            uint256 totalRewardWei,
            uint256 gasReimbursementWei,
            uint256 incentiveWei,
            uint256 overheadGas,
            uint256 reimbursableGas,
            uint256 incentiveServiceUnits,
            bool usedGuardianSpecificPrice
        )
    {
        return _calculateRewardForGuardian(guardian, actionType, measuredGas);
    }

    function calculateGuardianReward(address guardian, bytes32 actionType, uint256 measuredGas)
        public
        view
        returns (
            uint256 totalRewardWei,
            uint256 gasReimbursementWei,
            uint256 incentiveWei,
            uint256 overheadGas,
            uint256 reimbursableGas,
            uint256 incentiveServiceUnits
        )
    {
        bool usedGuardianSpecificPrice;
        (
            totalRewardWei,
            gasReimbursementWei,
            incentiveWei,
            overheadGas,
            reimbursableGas,
            incentiveServiceUnits,
            usedGuardianSpecificPrice
        ) = _calculateRewardForGuardian(guardian, actionType, measuredGas);
    }

    function estimateRewardForGuardianAction(address guardian, bytes32 actionType) public view returns (uint256) {
        (uint256 totalRewardWei, , , , , ) = calculateGuardianReward(guardian, actionType, _estimatedGas(actionType));
        return totalRewardWei;
    }

    function guardianActionIncentiveSu(address guardian, bytes32 actionType)
        external
        view
        returns (uint256 incentiveServiceUnits, bool guardianSpecific)
    {
        (incentiveServiceUnits, guardianSpecific) = _guardianIncentiveSuWithSource(guardian, actionType);
    }

    function estimatePolicyEscrow(
        bytes32 fileId,
        uint256,
        uint256
    ) external view returns (uint256) {
        return estimateV2DkgEscrow(fileId);
    }

    function hasV2DkgEscrow(bytes32 fileId) external view returns (bool) {
        return _policyEscrowData[fileId].balance >= estimateV2DkgEscrow(fileId);
    }

    function hasV2PreEscrow(bytes32 fileId, uint256 batchId) external view returns (bool) {
        return _policyEscrowData[fileId].balance >= estimateV2PreEscrow(fileId, batchId);
    }

    function hasV2AccessEscrow(uint256 requestId) external view returns (bool) {
        _requestContext(requestId);
        return _accessEscrow[requestId] > 0;
    }

    function policyEscrowBalance(bytes32 fileId) external view returns (uint256) {
        return _policyEscrowData[fileId].balance;
    }

    function policyEscrowDeposited(bytes32 fileId) external view returns (uint256) {
        return _policyEscrowData[fileId].deposited;
    }

    function policyEscrowRefunded(bytes32 fileId) external view returns (uint256) {
        return _refundedByPolicy[fileId];
    }

    function accessEscrowBalance(uint256 requestId) external view returns (uint256) {
        return _accessEscrow[requestId];
    }

    function accessEscrowDeposited(uint256 requestId) external view returns (uint256) {
        return _depositedByAccessRequest[requestId];
    }

    function accessEscrowRefunded(uint256 requestId) external view returns (uint256) {
        return _refundedByAccessRequest[requestId];
    }

    function isAccessEscrowComplete(uint256 requestId) external view returns (bool) {
        return _accessEscrowComplete[requestId];
    }

    function claimableReward(address guardian) external view returns (uint256) {
        return _claimable[guardian];
    }

    function guardianEarnedByPolicy(bytes32 fileId, address guardian) external view returns (uint256) {
        return _earnedByPolicy[fileId][guardian];
    }

    function guardianEarnedByAccessRequest(uint256 requestId, address guardian) external view returns (uint256) {
        return _earnedByAccessRequest[requestId][guardian];
    }

    function creditV2DkgMaterial(bytes32 fileId, address guardian) external onlyAuthorizedRewarder {
        _creditMeasuredPolicy(fileId, guardian, ACTION_V2_DKG_MATERIAL, 0);
    }

    function creditV2SharePublicKey(bytes32 fileId, address guardian) external onlyAuthorizedRewarder {
        _creditMeasuredPolicy(fileId, guardian, ACTION_V2_DKG_SHARE_KEY, 0);
    }

    function creditV2PreBatchPartial(bytes32 fileId, uint256, address guardian) external onlyAuthorizedRewarder {
        _creditMeasuredPolicy(fileId, guardian, ACTION_V2_PRE_BATCH_PARTIAL, 0);
    }

    function creditV2PreBatchPartialForRequest(uint256 requestId, address guardian) external onlyAuthorizedRewarder {
        _creditMeasuredAccess(requestId, guardian, ACTION_V2_PRE_BATCH_PARTIAL, 0);
    }

    function creditMeasuredPolicyReward(
        bytes32 fileId,
        address guardian,
        bytes32 actionType,
        uint256 measuredGas
    ) external onlyAuthorizedRewarder {
        _creditMeasuredPolicy(fileId, guardian, actionType, measuredGas);
    }

    function creditMeasuredAccessReward(
        uint256 requestId,
        address guardian,
        bytes32 actionType,
        uint256 measuredGas
    ) external onlyAuthorizedRewarder {
        _creditMeasuredAccess(requestId, guardian, actionType, measuredGas);
    }

    function markAccessEscrowComplete(uint256 requestId) external onlyAuthorizedRewarder {
        (bytes32 fileId, address requester, ) = _requestContext(requestId);
        _accessEscrowComplete[requestId] = true;
        emit AccessEscrowCompleted(requestId, fileId, requester);
    }

    function depositAccessEscrow(uint256 requestId) external payable {
        _depositAccessEscrow(requestId, msg.sender, msg.value);
    }

    function depositAccessEscrowFor(uint256 requestId, address payer) external payable {
        require(address(dataVault) != address(0), "RewardManager: DataVault not set");
        require(msg.sender == address(dataVault), "RewardManager: not DataVault");
        _depositAccessEscrow(requestId, payer, msg.value);
    }

    function claimRewards() external {
        uint256 amount = _claimable[msg.sender];
        require(amount > 0, "RewardManager: no rewards");
        _claimable[msg.sender] = 0;
        PayoutLib.send(msg.sender, amount);
        emit RewardsClaimed(msg.sender, amount);
    }

    function refundUnusedEscrow(bytes32 fileId, uint256 amount) external {
        (bool exists, , address dataOwner, , ) = acl.getFilePolicy(fileId);
        require(exists, "RewardManager: unknown policy");
        require(msg.sender == dataOwner, "RewardManager: not policy DO");
        require(!acl.hasRequestedKeyGenForFile(fileId), "RewardManager: keygen active");
        require(amount > 0 && amount <= _policyEscrowData[fileId].balance, "RewardManager: bad refund");
        _policyEscrowData[fileId].balance -= uint128(amount);
        _refundedByPolicy[fileId] += amount;
        PayoutLib.send(msg.sender, amount);
        emit PolicyEscrowRefunded(fileId, msg.sender, amount, _policyEscrowData[fileId].balance);
    }

    /// @notice Returns the per-failing-Guardian compensation amount for a failed DKG round.
    ///         Covers: what DO already paid out to good Gs this round + DO's own request gas.
    /// @param fileId             The file whose keygen expired.
    /// @param nonParticipantCount Number of Guardians that never submitted material.
    function calculateDkgExpiryCompensation(bytes32 fileId, uint8 nonParticipantCount)
        external
        view
        returns (uint256 perFailingGuardianWei)
    {
        if (nonParticipantCount == 0) return 0;
        PolicyEscrow storage pe = _policyEscrowData[fileId];
        uint256 alreadyPaid = pe.deposited > pe.balance
            ? pe.deposited - pe.balance
            : 0;
        uint256 doRequestGasWei = estimatedGasKeyGenRequest * fixedGasPriceWei;
        return (alreadyPaid + doRequestGasWei) / uint256(nonParticipantCount);
    }

    function creditPreReadyNotUsed(uint256 requestId, address guardian) external onlyAuthorizedRewarder {
        require(guardian != address(0), "RewardManager: zero guardian");
        uint256 amount = _suToWei(preReadyNotUsedSu);
        if (amount == 0 || _accessEscrow[requestId] < amount) return;
        (bytes32 fileId, , ) = _requestContext(requestId);
        _accessEscrow[requestId] -= amount;
        _claimable[guardian] += amount;
        _earnedByPolicy[fileId][guardian] += amount;
        _earnedByAccessRequest[requestId][guardian] += amount;
        emit GuardianAccessRewardCredited(requestId, fileId, guardian, ACTION_V2_PRE_READY_NOT_USED, preReadyNotUsedSu, amount);
    }

    function calculatePreExpiryCompensation(uint256 requestId, uint8 inactiveAbsentCount)
        external
        view
        returns (uint256 perFailingGuardianWei)
    {
        uint256 deposited = _depositedByAccessRequest[requestId];
        if (inactiveAbsentCount == 0 || deposited == 0) return 0;
        uint256 unspent = _accessEscrow[requestId] + _refundedByAccessRequest[requestId];
        uint256 alreadyPaid = deposited > unspent
            ? deposited - unspent
            : 0;
        uint256 requesterGasWei = estimatedGasPreRequest * fixedGasPriceWei;
        return (alreadyPaid + requesterGasWei) / uint256(inactiveAbsentCount);
    }

    /// @notice Return an expired request's access escrow to the requester the DataVault
    ///         recorded. The address argument is kept for ABI compatibility and ignored:
    ///         no caller chooses who is refunded. A requester wallet that refuses the
    ///         payment gets it as a claim instead (claimRewards), so a refusal can neither
    ///         block the expiry nor leave the money stranded.
    function refundAccessEscrowForExpiry(uint256 requestId, address) external onlyAuthorizedRewarder {
        (bytes32 fileId, address requester, ) = _requestContext(requestId);
        // Close even an unfunded preparation: it must never be funded after
        // TElG has expired it. Close before sending any refund to the requester.
        _accessEscrowComplete[requestId] = true;
        uint256 balance = _accessEscrow[requestId];
        if (balance == 0) return;
        _accessEscrow[requestId] = 0;
        _refundedByAccessRequest[requestId] += balance;
        if (!PayoutLib.trySend(requester, balance)) _claimable[requester] += balance;
        emit AccessEscrowRefunded(requestId, fileId, requester, balance, 0);
    }

    function refundUnusedAccessEscrow(uint256 requestId) external {
        (bytes32 fileId, address requester, ) = _requestContext(requestId);
        require(msg.sender == requester, "RewardManager: not requester");
        require(_accessEscrowComplete[requestId], "RewardManager: access not complete");
        uint256 amount = _accessEscrow[requestId];
        require(amount > 0, "RewardManager: no access escrow");
        _accessEscrow[requestId] = 0;
        _refundedByAccessRequest[requestId] += amount;
        PayoutLib.send(msg.sender, amount);
        emit AccessEscrowRefunded(requestId, fileId, requester, amount, 0);
    }

    // ─── Daily share custody: paying Guardians for the days they hold a share ──
    //
    // A Guardian's daily custody price was already quoted to the Data Owner and
    // printed in its logs, but no money ever moved for it. That left nothing to
    // buy when a DO wanted to extend a running service term.
    //
    // Custody money lives in its own per-policy pot, kept apart from the escrow
    // that pays for DKG and PRE work so neither can eat the other. Days are sold
    // in stretches: the first term is one stretch and every renewal adds another.
    // Each stretch freezes the per-Guardian daily price at the moment those days
    // were bought. So a Guardian cannot raise its price afterwards and drain a
    // pot the DO already filled, and a renewal settles at the price it was
    // actually bought at instead of an average across the whole agreement.
    //
    // None of this touches the existing reward paths. A policy that never funds
    // custody behaves exactly as it did before.

    /// @notice DO puts money in for the days its Guardians hold a share.
    function depositCustodyEscrow(bytes32 fileId) external payable {
        require(msg.value > 0, "RewardManager: zero deposit");
        _requirePolicyDO(fileId);
        _custodyBalance[fileId] += msg.value;
        emit CustodyEscrowDeposited(fileId, msg.sender, msg.value, _custodyBalance[fileId]);
    }

    /// @notice What a stretch of days would cost at today's prices. The DO reads
    ///         this before funding so it knows exactly what to send: the sum is
    ///         built the same way `reserveCustodyStretch` builds it, rounding
    ///         included, so a DO that funds this much can always reserve.
    function quoteCustody(bytes32 fileId, uint64 startTime, uint64 endTime)
        public
        view
        returns (uint256 priceWei)
    {
        require(endTime > startTime, "RewardManager: empty stretch");
        address[] memory guardians = _policyGuardians(fileId);
        uint256 span = uint256(endTime) - uint256(startTime);
        for (uint256 i = 0; i < guardians.length; i++) {
            priceWei += (_dailyCustodyWei(guardians[i]) * span) / 1 days;
        }
    }

    /// @notice Buy a stretch of custody days at today's prices, parked but not
    ///         yet earnable. Only the Guardian service-period contract may call
    ///         this — it is the thing that knows when a term starts and ends.
    /// @dev Stretches must run back to back, which is what stops the same days
    ///      from being sold twice.
    function reserveCustodyStretch(bytes32 fileId, uint64 startTime, uint64 endTime)
        external
        onlyAuthorizedRewarder
        returns (uint256 stretchIndex, uint256 priceWei)
    {
        require(endTime > startTime, "RewardManager: empty stretch");
        CustodyStretch[] storage stretches = _custodyStretches[fileId];
        require(stretches.length < maxCustodyStretches, "RewardManager: custody stretch limit");
        if (stretches.length > 0) {
            require(
                startTime >= stretches[stretches.length - 1].endTime,
                "RewardManager: stretch overlaps the previous one"
            );
        }

        address[] memory guardians = _policyGuardians(fileId);
        uint256 span = uint256(endTime) - uint256(startTime);
        stretchIndex = stretches.length;
        uint32 priceBook = _custodyPriceBooks[fileId] + 1;
        _custodyPriceBooks[fileId] = priceBook;
        for (uint256 i = 0; i < guardians.length; i++) {
            uint256 rate = _dailyCustodyWei(guardians[i]);
            _custodyDailyRateWei[fileId][priceBook][guardians[i]] = rate;
            _custodyPaidThrough[fileId][priceBook][guardians[i]] = startTime;
            priceWei += (rate * span) / 1 days;
        }
        // A zero price is allowed: Guardians that have not set a custody price
        // simply hold the share for free, and renewal must still work for them.
        require(custodyFree(fileId) >= priceWei, "RewardManager: custody not funded");

        _custodyCommitted[fileId] += priceWei;
        stretches.push(CustodyStretch({
            startTime:   startTime,
            endTime:     endTime,
            reservedWei: uint128(priceWei),
            paidWei:     0,
            active:      false,
            priceBook:   priceBook
        }));
        emit CustodyStretchReserved(fileId, stretchIndex, startTime, endTime, priceWei);
    }

    /// @notice Make a parked stretch earnable, once every Guardian has agreed to it.
    function activateCustodyStretch(bytes32 fileId, uint256 stretchIndex) external onlyAuthorizedRewarder {
        CustodyStretch storage stretch = _requireStretch(fileId, stretchIndex);
        require(!stretch.active, "RewardManager: stretch already active");
        stretch.active = true;
        emit CustodyStretchActivated(fileId, stretchIndex);
    }

    /// @notice Give back a stretch nobody agreed to. Only the newest stretch can
    ///         go, and only while it is still parked, so paid history behind it
    ///         can never be rewritten.
    /// @dev The next stretch reuses this array slot but never this price book,
    ///      so the prices frozen here become unreachable. Without that, a
    ///      Guardian dropped from the policy between the cancel and the next
    ///      purchase would keep a live price and could draw against days bought
    ///      for somebody else.
    function releaseCustodyStretch(bytes32 fileId, uint256 stretchIndex) external onlyAuthorizedRewarder {
        CustodyStretch[] storage stretches = _custodyStretches[fileId];
        require(stretchIndex + 1 == stretches.length, "RewardManager: not the newest stretch");
        CustodyStretch storage stretch = stretches[stretchIndex];
        require(!stretch.active, "RewardManager: stretch already active");
        uint256 freed = uint256(stretch.reservedWei) - uint256(stretch.paidWei);
        _custodyCommitted[fileId] -= freed;
        stretches.pop();
        emit CustodyStretchReleased(fileId, stretchIndex, freed);
    }

    /// @notice A Guardian draws the custody pay it has earned by holding its share.
    /// @dev Pay accrues with the clock across the days the DO bought. A missed
    ///      daily proof is already punished by slashing and reputation, so it is
    ///      deliberately not punished a second time here.
    function claimCustody(bytes32 fileId) external returns (uint256 amountWei) {
        CustodyStretch[] storage stretches = _custodyStretches[fileId];
        uint64 paidThrough;
        for (uint256 i = 0; i < stretches.length; i++) {
            (uint256 owed, uint64 to) = _custodyDue(fileId, stretches[i], msg.sender);
            if (owed == 0) continue;
            stretches[i].paidWei += uint128(owed);
            _custodyPaidThrough[fileId][stretches[i].priceBook][msg.sender] = to;
            amountWei += owed;
            paidThrough = to;
        }
        require(amountWei > 0, "RewardManager: no custody due");
        require(_custodyBalance[fileId] >= amountWei, "RewardManager: custody pot short");
        _custodyBalance[fileId] -= amountWei;
        _custodyCommitted[fileId] -= amountWei;
        _claimable[msg.sender] += amountWei;
        _earnedByPolicy[fileId][msg.sender] += amountWei;
        emit CustodyClaimed(fileId, msg.sender, amountWei, paidThrough);
    }

    /// @notice DO takes back custody money no stretch has claimed. Money already
    ///         inside a stretch belongs to the Guardians earning it and is never
    ///         swept out from under them.
    function refundUnusedCustody(bytes32 fileId, uint256 amount) external {
        _requirePolicyDO(fileId);
        require(amount > 0 && amount <= custodyFree(fileId), "RewardManager: bad custody refund");
        _custodyBalance[fileId] -= amount;
        PayoutLib.send(msg.sender, amount);
        emit CustodyEscrowRefunded(fileId, msg.sender, amount, _custodyBalance[fileId]);
    }

    /// @notice Custody money not yet committed to any stretch — what a new
    ///         stretch can be paid for, and all the DO may refund.
    function custodyFree(bytes32 fileId) public view returns (uint256) {
        return _custodyBalance[fileId] - _custodyCommitted[fileId];
    }

    /// @notice Everything a DO or Guardian needs to see about one policy's
    ///         custody pot, including what `guardian` could draw right now.
    ///         Pass the zero address when only the pot matters.
    function custodyStatus(bytes32 fileId, address guardian)
        external
        view
        returns (
            uint256 balanceWei,
            uint256 committedWei,
            uint256 freeWei,
            uint256 stretchCount,
            uint256 claimableWei
        )
    {
        CustodyStretch[] storage stretches = _custodyStretches[fileId];
        for (uint256 i = 0; i < stretches.length; i++) {
            (uint256 owed, ) = _custodyDue(fileId, stretches[i], guardian);
            claimableWei += owed;
        }
        return (
            _custodyBalance[fileId],
            _custodyCommitted[fileId],
            custodyFree(fileId),
            stretches.length,
            claimableWei
        );
    }

    /// @notice One paid stretch, and what this Guardian's day costs inside it.
    function getCustodyStretch(bytes32 fileId, uint256 stretchIndex, address guardian)
        external
        view
        returns (
            uint64 startTime,
            uint64 endTime,
            uint256 reservedWei,
            uint256 paidWei,
            bool active,
            uint256 dailyRateWei
        )
    {
        CustodyStretch storage stretch = _requireStretch(fileId, stretchIndex);
        return (
            stretch.startTime,
            stretch.endTime,
            stretch.reservedWei,
            stretch.paidWei,
            stretch.active,
            _custodyDailyRateWei[fileId][stretch.priceBook][guardian]
        );
    }

    /// @dev Custody a Guardian has earned in one stretch but not yet drawn, and
    ///      the moment that payment would run up to. Capped at what the stretch
    ///      was bought for, so no stretch can ever pay out more than its price.
    function _custodyDue(
        bytes32 fileId,
        CustodyStretch storage stretch,
        address guardian
    ) internal view returns (uint256 owed, uint64 to) {
        if (!stretch.active) return (0, 0);
        uint256 rate = _custodyDailyRateWei[fileId][stretch.priceBook][guardian];
        if (rate == 0) return (0, 0);

        uint64 from = _custodyPaidThrough[fileId][stretch.priceBook][guardian];
        if (from < stretch.startTime) from = stretch.startTime;
        to = block.timestamp < stretch.endTime ? uint64(block.timestamp) : stretch.endTime;
        if (to <= from) return (0, 0);

        owed = (rate * (uint256(to) - uint256(from))) / 1 days;
        uint256 room = uint256(stretch.reservedWei) - uint256(stretch.paidWei);
        if (owed > room) owed = room;
    }

    function _requireStretch(bytes32 fileId, uint256 stretchIndex)
        internal
        view
        returns (CustodyStretch storage)
    {
        require(stretchIndex < _custodyStretches[fileId].length, "RewardManager: no such stretch");
        return _custodyStretches[fileId][stretchIndex];
    }

    function _requirePolicyDO(bytes32 fileId) internal view {
        (bool exists, , address dataOwner, , ) = acl.getFilePolicy(fileId);
        require(exists, "RewardManager: unknown policy");
        require(msg.sender == dataOwner, "RewardManager: not policy DO");
    }

    function _policyGuardians(bytes32 fileId) internal view returns (address[] memory guardians) {
        bool exists;
        (exists, , , , guardians) = acl.getFilePolicy(fileId);
        require(exists, "RewardManager: unknown policy");
    }

    /// @dev A Guardian's own daily custody price, or zero when it never set one
    ///      or the registry is not wired. Never reverts: an unpriced Guardian
    ///      holds its share for free rather than blocking the whole policy.
    function _dailyCustodyWei(address guardian) internal view returns (uint256) {
        if (address(guardianRegistry) == address(0) || guardian == address(0)) return 0;
        try guardianRegistry.getGuardianServicePricingWithCustody(guardian) returns (
            uint256,
            uint256,
            uint256,
            uint256 dailyShareCustodySu,
            bool exists
        ) {
            if (exists) return _suToWei(dailyShareCustodySu);
        } catch {}
        return 0;
    }

    function _credit(bytes32 fileId, address guardian, bytes32 rewardType, uint256 serviceUnits) internal {
        require(guardian != address(0), "RewardManager: zero guardian");
        uint256 amount = _suToWei(serviceUnits);
        require(_policyEscrowData[fileId].balance >= amount, "RewardManager: insufficient escrow");
        _policyEscrowData[fileId].balance -= uint128(amount);
        _claimable[guardian] += amount;
        _earnedByPolicy[fileId][guardian] += amount;
        emit GuardianRewardCredited(fileId, guardian, rewardType, serviceUnits, amount);
    }

    function _creditAccess(uint256 requestId, address guardian, bytes32 rewardType, uint256 serviceUnits) internal {
        require(guardian != address(0), "RewardManager: zero guardian");
        (bytes32 fileId, , ) = _requestContext(requestId);
        uint256 amount = _suToWei(serviceUnits);
        require(_accessEscrow[requestId] >= amount, "RewardManager: insufficient access escrow");
        _accessEscrow[requestId] -= amount;
        _claimable[guardian] += amount;
        _earnedByPolicy[fileId][guardian] += amount;
        _earnedByAccessRequest[requestId][guardian] += amount;
        emit GuardianAccessRewardCredited(requestId, fileId, guardian, rewardType, serviceUnits, amount);
    }

    function _creditMeasuredPolicy(bytes32 fileId, address guardian, bytes32 actionType, uint256 measuredGas) internal {
        require(guardian != address(0), "RewardManager: zero guardian");
        (
            uint256 amount,
            uint256 gasReimbursementWei,
            uint256 incentiveWei,
            uint256 overheadGas,
            uint256 reimbursableGas,
            uint256 incentiveServiceUnits,
            bool usedGuardianSpecificPrice
        ) = _calculateRewardForGuardian(guardian, actionType, measuredGas);
        require(_policyEscrowData[fileId].balance >= amount, "RewardManager: insufficient escrow");
        _policyEscrowData[fileId].balance -= uint128(amount);
        _claimable[guardian] += amount;
        _earnedByPolicy[fileId][guardian] += amount;
        emit GuardianMeasuredRewardCredited(
            fileId,
            guardian,
            actionType,
            measuredGas,
            overheadGas,
            reimbursableGas,
            gasReimbursementWei,
            incentiveServiceUnits,
            incentiveWei,
            amount
        );
        emit GuardianRewardPricingUsed(guardian, actionType, incentiveServiceUnits, usedGuardianSpecificPrice, suToWeiRate);
    }

    function _creditMeasuredAccess(uint256 requestId, address guardian, bytes32 actionType, uint256 measuredGas) internal {
        require(guardian != address(0), "RewardManager: zero guardian");
        (bytes32 fileId, , ) = _requestContext(requestId);
        (
            uint256 amount,
            uint256 gasReimbursementWei,
            uint256 incentiveWei,
            uint256 overheadGas,
            uint256 reimbursableGas,
            uint256 incentiveServiceUnits,
            bool usedGuardianSpecificPrice
        ) = _calculateRewardForGuardian(guardian, actionType, measuredGas);
        // The price a Guardian had when the request was paid for is the most it is paid
        // for it: raising its price during the request takes nothing more from the
        // requester and leaves the other Guardians' share of the escrow in place.
        uint256 quoted = _quotedPreSuPlusOne[requestId][guardian];
        if (quoted != 0 && incentiveServiceUnits >= quoted) {
            incentiveServiceUnits = quoted - 1;
            incentiveWei = _suToWei(incentiveServiceUnits);
            amount = gasReimbursementWei + incentiveWei;
        }
        require(_accessEscrow[requestId] >= amount, "RewardManager: insufficient access escrow");
        _accessEscrow[requestId] -= amount;
        _claimable[guardian] += amount;
        _earnedByPolicy[fileId][guardian] += amount;
        _earnedByAccessRequest[requestId][guardian] += amount;
        emit GuardianMeasuredAccessRewardCredited(
            requestId,
            fileId,
            guardian,
            actionType,
            measuredGas,
            overheadGas,
            reimbursableGas,
            gasReimbursementWei,
            incentiveServiceUnits,
            incentiveWei,
            amount
        );
        emit GuardianRewardPricingUsed(guardian, actionType, incentiveServiceUnits, usedGuardianSpecificPrice, suToWeiRate);
    }

    function _depositAccessEscrow(uint256 requestId, address payer, uint256 amount) internal {
        require(amount > 0, "RewardManager: zero deposit");
        (bytes32 fileId, address requester, uint256 batchId) = _requestContext(requestId);
        require(payer == requester, "RewardManager: not request payer");
        require(!_accessEscrowComplete[requestId], "RewardManager: access complete");
        require(dataVault.isAccessRequestAuthorized(requestId),
            "RewardManager: request not authorized");
        if (_depositedByAccessRequest[requestId] == 0) {
            dataVault.admitAccessRequest(requestId);
            address[] memory guardians = _policyGuardians(fileId);
            for (uint256 i = 0; i < guardians.length; i++) {
                _quotedPreSuPlusOne[requestId][guardians[i]] =
                    _guardianIncentiveSu(guardians[i], ACTION_V2_PRE_BATCH_PARTIAL) + 1;
            }
        }
        _accessEscrow[requestId] += amount;
        _depositedByAccessRequest[requestId] += amount;
        require(_accessEscrow[requestId] >= estimateV2PreEscrow(fileId, batchId), "RewardManager: access escrow too low");
        emit AccessEscrowDeposited(requestId, fileId, requester, amount, _accessEscrow[requestId]);
    }

    function _requestContext(uint256 requestId) internal view returns (bytes32 fileId, address requester, uint256 batchId) {
        require(address(dataVault) != address(0), "RewardManager: DataVault not set");
        bool exists;
        (exists, fileId, requester, batchId, , , , , , ) = dataVault.getAccessRequest(requestId);
        require(exists, "RewardManager: unknown request");
    }

    function _suToWei(uint256 serviceUnits) internal view returns (uint256) {
        return serviceUnits * suToWeiRate;
    }

    function _withBuffer(uint256 amount) internal view returns (uint256) {
        return amount + (amount * gasReimbursementBufferBps) / 10_000;
    }

    function _incentiveSu(bytes32 actionType) internal view returns (uint256) {
        if (actionType == ACTION_V2_DKG_MATERIAL) return dkgMaterialSu;
        if (actionType == ACTION_V2_DKG_SHARE_KEY) return dkgShareKeySu;
        if (actionType == ACTION_V2_PRE_BATCH_PARTIAL) return preBatchPartialSu;
        revert("RewardManager: unknown action");
    }

    function _calculateRewardForGuardian(address guardian, bytes32 actionType, uint256 measuredGas)
        internal
        view
        returns (
            uint256 totalRewardWei,
            uint256 gasReimbursementWei,
            uint256 incentiveWei,
            uint256 overheadGas,
            uint256 reimbursableGas,
            uint256 incentiveServiceUnits,
            bool usedGuardianSpecificPrice
        )
    {
        overheadGas = _overheadGas(actionType);
        (incentiveServiceUnits, usedGuardianSpecificPrice) = _guardianIncentiveSuWithSource(guardian, actionType);
        reimbursableGas = measuredGas + overheadGas;
        gasReimbursementWei = reimbursableGas * fixedGasPriceWei;
        incentiveWei = _suToWei(incentiveServiceUnits);
        totalRewardWei = gasReimbursementWei + incentiveWei;
    }

    function _guardianIncentiveSu(address guardian, bytes32 actionType) internal view returns (uint256) {
        (uint256 incentiveServiceUnits, ) = _guardianIncentiveSuWithSource(guardian, actionType);
        return incentiveServiceUnits;
    }

    function _guardianIncentiveSuWithSource(address guardian, bytes32 actionType)
        internal
        view
        returns (uint256 incentiveServiceUnits, bool guardianSpecific)
    {
        if (address(guardianRegistry) != address(0) && guardian != address(0)) {
            try guardianRegistry.getGuardianServicePricingWithStatus(guardian) returns (
                uint256 dkgMaterial,
                uint256 dkgShareKey,
                uint256 preBatchPartial,
                bool exists
            ) {
                if (exists) {
                    if (actionType == ACTION_V2_DKG_MATERIAL) return (dkgMaterial, true);
                    if (actionType == ACTION_V2_DKG_SHARE_KEY) return (dkgShareKey, true);
                    if (actionType == ACTION_V2_PRE_BATCH_PARTIAL) return (preBatchPartial, true);
                }
            } catch {}
        }
        return (_incentiveSu(actionType), false);
    }

    function _overheadGas(bytes32 actionType) internal view returns (uint256) {
        if (actionType == ACTION_V2_DKG_MATERIAL) return overheadGasV2DkgMaterial;
        if (actionType == ACTION_V2_DKG_SHARE_KEY) return overheadGasV2DkgShareKey;
        if (actionType == ACTION_V2_PRE_BATCH_PARTIAL) return overheadGasV2PreBatchPartial;
        revert("RewardManager: unknown action");
    }

    function _estimatedGas(bytes32 actionType) internal view returns (uint256) {
        if (actionType == ACTION_V2_DKG_MATERIAL) return estimatedGasV2DkgMaterial;
        if (actionType == ACTION_V2_DKG_SHARE_KEY) return estimatedGasV2DkgShareKey;
        if (actionType == ACTION_V2_PRE_BATCH_PARTIAL) return estimatedGasV2PreBatchPartial;
        revert("RewardManager: unknown action");
    }

    function _estimateV2DkgEscrowForGuardianList(address[] memory guardians) internal view returns (uint256) {
        uint256 base = _suToWei(v2DkgBaseSu + dkgFinalizationSu);
        uint256 guardianTotal = 0;
        for (uint256 i = 0; i < guardians.length; i++) {
            guardianTotal += estimateRewardForGuardianAction(guardians[i], ACTION_V2_DKG_MATERIAL);
            guardianTotal += estimateRewardForGuardianAction(guardians[i], ACTION_V2_DKG_SHARE_KEY);
        }
        return _withBuffer(base + guardianTotal);
    }

    function _requireV2ModeIfPolicyExists(bytes32 fileId) internal view {
        (bool exists, , , , ) = acl.getFilePolicy(fileId);
        if (exists) {
            require(acl.getFilePolicyMode(fileId) == IAccessControlFT_Rewards.DkgMode.ZKDKG_V2, "RewardManager: wrong mode");
        }
    }

    function _copyValues(uint256[] memory values) internal pure returns (uint256[] memory out) {
        out = new uint256[](values.length);
        for (uint256 i = 0; i < values.length; i++) {
            out[i] = values[i];
        }
    }

    function _sumSmallest(uint256[] memory values, uint256 count) internal pure returns (uint256) {
        require(count <= values.length, "RewardManager: bad count");
        uint256 total = 0;
        for (uint256 i = 0; i < count; i++) {
            uint256 selected = i;
            for (uint256 j = i + 1; j < values.length; j++) {
                if (values[j] < values[selected]) {
                    selected = j;
                }
            }
            if (selected != i) {
                uint256 tmp = values[i];
                values[i] = values[selected];
                values[selected] = tmp;
            }
            total += values[i];
        }
        return total;
    }

    function _sumLargest(uint256[] memory values, uint256 count) internal pure returns (uint256) {
        require(count <= values.length, "RewardManager: bad count");
        uint256 total = 0;
        for (uint256 i = 0; i < count; i++) {
            uint256 selected = i;
            for (uint256 j = i + 1; j < values.length; j++) {
                if (values[j] > values[selected]) {
                    selected = j;
                }
            }
            if (selected != i) {
                uint256 tmp = values[i];
                values[i] = values[selected];
                values[selected] = tmp;
            }
            total += values[i];
        }
        return total;
    }
}
