// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: VaultKeeperRegistry
// Purpose:  Who the Vault Keepers are, what they charge, how much they can take on,
//           and how long they are already obligated for.
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

import {FileTrustDeprecatable} from "./governance/FileTrustDeprecatable.sol";

interface IReputationManager_VK {
    function getVKReputation(address vk) external view returns (uint32);
}

interface IStakingManager_VKR {
    function depositStakeFor(address guardian) external payable;
    function stakeOf(address guardian) external view returns (uint256);
    function minStake() external view returns (uint256);
}

interface IRewardManager_VKR {
    function creditVKJoin(address vk) external;
}

contract VaultKeeperRegistry is FileTrustDeprecatable {
    struct VaultKeeperProfile {
        address vkAddress;
        uint256 storageFee;    // SU per GB per day (1 GB = 1,000,000,000 bytes)
        uint256 stake;
        bool active;
        uint256 registeredAt;
        uint256 lastHeartbeat;
        // W6: timestamp until which the VK is temporarily suspended (0 = not suspended)
        uint64 suspendedUntil;
        // Maximum service duration this VK accepts (days). 0 = unlimited.
        uint32 maxServiceDays;
    }

    struct VaultKeeperEndpoint {
        bytes32 endpointHash;
        uint64 seq;
        uint64 updatedAt;
    }

    struct AdmissionCheckpoint {
        uint64 timestamp;
        bool closed;
    }

    address public owner;
    address public reputationManager;
    address public stakingManager;
    address public rewardManager;
    address public authorizedFileRegistrar;

    mapping(address => VaultKeeperProfile) private vaultKeepers;
    mapping(address => VaultKeeperEndpoint) private vaultKeeperEndpoints;
    // Per-VK maximum accepted piece size in bytes. 0 = unlimited / not declared.
    mapping(address => uint64) public maxPieceSizeBytes;
    mapping(address => bool) public isRegisteredVaultKeeper;
    address[] private vaultKeeperList;

    // The keeper's libp2p peer id, kept as current state.
    //
    // It used to live only inside the registration and update events, so anyone
    // needing it had to search chain history. That is refused outright by chains
    // capping log ranges -- Cosmos allows 10,000 blocks, which a one-second chain
    // outgrows in about three hours -- and it grows without limit even where it
    // works. Holding it here makes it one direct read whose cost never changes
    // with the age of the chain.
    mapping(address => string) public vaultKeeperPeerId;

    // Admission control: VK sets closed when unreserved free capacity drops below its
    // local margin. DO checks isAdmissionOpen() before depositing escrow for new stores.
    mapping(address => bool) public admissionClosed;
    mapping(address => uint64) public admissionClosedAt;
    mapping(address => uint64) public reportedAdmissionFreeBytes;
    mapping(address => uint8) public admissionClosureReason;
    mapping(address => uint64) public admissionObservationBlock;
    mapping(address => AdmissionCheckpoint[]) private admissionHistory;
    /// @dev Owner-configurable conservative margin (bytes). CapacityProofSC applies this
    ///      value to its public admission view; VKs may configure a larger local margin.
    uint64 private _defaultAdmissionMarginBytes;

    // W6: contracts authorised to call suspendVaultKeeper / deactivateVaultKeeper
    mapping(address => bool) public authorizedEnforcers;

    /// @dev Per-VK: the furthest serviceEnd among all files this VK has stored.
    ///      Updated by FileRegistrationSC on each registerFileStorage call.
    ///      StakingManager checks this before allowing VK stake withdrawal.
    mapping(address => uint64) public latestServiceEnd;

    event VaultKeeperRegistered(
        address indexed vkAddress,
        string peerId,
        string metadataURI,
        uint256 storageFee,
        uint256 stake,
        uint32  maxServiceDays
    );

    event VaultKeeperUpdated(
        address indexed vkAddress,
        string peerId,
        string metadataURI,
        uint256 storageFee,
        uint32  maxServiceDays
    );

    event VaultKeeperStatusChanged(address indexed vkAddress, bool active);
    event VaultKeeperHeartbeat(address indexed vkAddress, uint256 timestamp);
    event VaultKeeperEndpointUpdated(
        address indexed vkAddress,
        bytes32 indexed endpointHash,
        uint64 seq,
        uint64 updatedAt
    );
    event VaultKeeperCapacityUpdated(address indexed vkAddress, uint64 maxPieceSizeBytes);
    // W6 events
    event VaultKeeperSuspended(address indexed vkAddress, uint64 suspendedUntil);
    event AuthorizedEnforcerUpdated(address indexed enforcer, bool authorized);
    event ReputationManagerSet(address indexed reputationManager);
    event StakingManagerSet(address indexed stakingManager);
    event RewardManagerSet(address indexed rewardManager);
    event FileRegistrarSet(address indexed fileRegistrar);
    event VKLatestServiceEndUpdated(address indexed vk, uint64 serviceEnd);
    event AdmissionStatusChanged(
        address indexed vkAddress,
        bool admissionClosed,
        uint64 reportedFreeBytes,
        uint64 updatedAt
    );
    event CertifiedAdmissionStatusChanged(
        address indexed vkAddress,
        bool admissionClosed,
        uint64 safeAllocatable,
        uint8 closureReason,
        uint64 observationBlock,
        uint64 updatedAt
    );
    event DefaultAdmissionMarginBytesSet(uint64 marginBytes);

    modifier onlyOwner() {
        require(msg.sender == owner, "VKRegistry: only owner");
        _;
    }

    modifier onlyRegistered() {
        require(isRegisteredVaultKeeper[msg.sender], "VKRegistry: not registered");
        _;
    }

    modifier onlyEligible() {
        require(isEligibleVaultKeeper(msg.sender), "VKRegistry: insufficient stake");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "VKRegistry: zero owner");
        owner = newOwner;
    }

    /// @notice Close this version's VaultKeeper layer to new business when its successor
    ///         opens (Phase 2), for good: no new VaultKeeper registrations here, no new
    ///         capacity admission or quote (the admission margin reads as the maximum), and
    ///         no new partition or sector in StorageProofSC, which reads this switch.
    ///         Registered VaultKeepers stay eligible, update, stake, prove and withdraw.
    function deprecate(address successor) external onlyOwner { _deprecate(successor); }

    function setReputationManager(address rm) external onlyOwner {
        reputationManager = rm;
        emit ReputationManagerSet(rm);
    }

    function setStakingManager(address _sm) external onlyOwner {
        require(_sm != address(0), "VKRegistry: zero stakingManager");
        stakingManager = _sm;
        emit StakingManagerSet(_sm);
    }

    function setRewardManager(address _rm) external onlyOwner {
        rewardManager = _rm;
        emit RewardManagerSet(_rm);
    }

    function setFileRegistrar(address _fr) external onlyOwner {
        authorizedFileRegistrar = _fr;
        emit FileRegistrarSet(_fr);
    }

    /// @notice Called by FileRegistrationSC on each registerFileStorage to extend
    ///         the tracked latest service obligation for this VK.
    function updateLatestServiceEnd(address vk, uint64 serviceEnd) external {
        require(msg.sender == authorizedFileRegistrar, "VKRegistry: not file registrar");
        if (serviceEnd > latestServiceEnd[vk]) {
            latestServiceEnd[vk] = serviceEnd;
            emit VKLatestServiceEndUpdated(vk, serviceEnd);
        }
    }

    // W6: authorize or de-authorize an enforcer contract (e.g. StorageReceiptDispute).
    function setAuthorizedEnforcer(address enforcer, bool authorized) external onlyOwner {
        require(enforcer != address(0), "VKRegistry: zero enforcer");
        authorizedEnforcers[enforcer] = authorized;
        emit AuthorizedEnforcerUpdated(enforcer, authorized);
    }

    /// @notice Sets the registry-wide default admission margin hint (bytes).
    function setDefaultAdmissionMarginBytes(uint64 marginBytes) external onlyOwner {
        _defaultAdmissionMarginBytes = marginBytes;
        emit DefaultAdmissionMarginBytesSet(marginBytes);
    }

    /// @notice The admission margin every VaultKeeper keeps free. Once this VaultKeeper
    ///         layer is deprecated (Phase 2) it reads as the largest value, so
    ///         CapacityProofSC admits no new capacity and reserves no new quote. Quotes
    ///         already reserved are consumed, retried and expired as before.
    function defaultAdmissionMarginBytes() public view returns (uint64) {
        return deprecatedAt != 0 ? type(uint64).max : _defaultAdmissionMarginBytes;
    }

    /// @notice VK updates on-chain admission status when local capacity crosses the margin.
    ///         Only the registered VK may call this for its own address.
    function updateAdmissionStatus(bool closed, uint64 reportedFreeBytes_) external onlyRegistered {
        _updateAdmissionStatus(closed, reportedFreeBytes_, 0, uint64(block.number));
    }

    /// @notice G.5 aggregate admission report. It intentionally contains no DO,
    ///         request, file, owner, or requester-to-VK identifier.
    function updateAdmissionStatusV2(
        bool closed,
        uint64 safeAllocatable,
        uint8 closureReason,
        uint64 observationBlock
    ) external onlyRegistered {
        require(observationBlock > 0 && observationBlock <= block.number, "VKRegistry: bad observation block");
        require(closed || closureReason == 0, "VKRegistry: open with reason");
        require(!closed || closureReason > 0, "VKRegistry: closed without reason");
        _updateAdmissionStatus(closed, safeAllocatable, closureReason, observationBlock);
    }

    function _updateAdmissionStatus(
        bool closed,
        uint64 reportedFreeBytes_,
        uint8 closureReason,
        uint64 observationBlock
    ) internal {
        require(_hasMinimumStake(msg.sender), "VKRegistry: insufficient stake");
        require(!_isSuspended(msg.sender), "VKRegistry: still suspended");

        bool changed = admissionClosed[msg.sender] != closed;
        admissionClosed[msg.sender] = closed;
        if (closed) {
            if (admissionClosedAt[msg.sender] == 0) {
                admissionClosedAt[msg.sender] = uint64(block.timestamp);
            }
        } else {
            admissionClosedAt[msg.sender] = 0;
        }
        reportedAdmissionFreeBytes[msg.sender] = reportedFreeBytes_;
        admissionClosureReason[msg.sender] = closureReason;
        admissionObservationBlock[msg.sender] = observationBlock;
        if (changed) {
            admissionHistory[msg.sender].push(AdmissionCheckpoint(uint64(block.timestamp), closed));
        }
        vaultKeepers[msg.sender].lastHeartbeat = block.timestamp;

        emit AdmissionStatusChanged(msg.sender, closed, reportedFreeBytes_, uint64(block.timestamp));
        emit CertifiedAdmissionStatusChanged(
            msg.sender, closed, reportedFreeBytes_, closureReason, observationBlock, uint64(block.timestamp)
        );
        emit VaultKeeperHeartbeat(msg.sender, block.timestamp);
    }

    /// @notice Historical admission state used to adjudicate escrow/store races.
    ///         Binary search keeps verification bounded as checkpoints accumulate.
    function wasAdmissionOpenAt(address vkAddress, uint64 timestamp) external view returns (bool) {
        AdmissionCheckpoint[] storage history = admissionHistory[vkAddress];
        if (history.length == 0 || timestamp < history[0].timestamp) return false;
        uint256 low = 0;
        uint256 high = history.length;
        while (low + 1 < high) {
            uint256 mid = (low + high) / 2;
            if (history[mid].timestamp <= timestamp) low = mid;
            else high = mid;
        }
        return !history[low].closed;
    }

    /// @notice Fast admission gate for DO: eligible VK with admission not closed.
    function isAdmissionOpen(address vkAddress) external view returns (bool) {
        if (!isEligibleVaultKeeper(vkAddress)) return false;
        return !admissionClosed[vkAddress];
    }

    /// @notice Returns the VK's declared admission state for explorer / DO fallbacks.
    function getAdmissionStatus(address vkAddress)
        external
        view
        returns (bool closed, uint64 closedAt, uint64 reportedFreeBytes)
    {
        return (
            admissionClosed[vkAddress],
            admissionClosedAt[vkAddress],
            reportedAdmissionFreeBytes[vkAddress]
        );
    }

    function registerVaultKeeper(
        string calldata peerId,
        string calldata metadataURI,
        uint256 storageFee,
        uint32  maxServiceDays
    ) external payable {
        _registerVaultKeeper(peerId, metadataURI, storageFee, maxServiceDays, 0);
    }

    function registerVaultKeeperWithCapacity(
        string calldata peerId,
        string calldata metadataURI,
        uint256 storageFee,
        uint32  maxServiceDays,
        uint64  maxPieceSizeBytes_
    ) external payable {
        _registerVaultKeeper(peerId, metadataURI, storageFee, maxServiceDays, maxPieceSizeBytes_);
    }

    function _registerVaultKeeper(
        string calldata peerId,
        string calldata metadataURI,
        uint256 storageFee,
        uint32  maxServiceDays,
        uint64  maxPieceSizeBytes_
    ) internal {
        _requireNotDeprecated();
        require(!isRegisteredVaultKeeper[msg.sender], "VKRegistry: already registered");
        require(bytes(peerId).length > 0, "VKRegistry: empty peerId");
        require(stakingManager != address(0), "VKRegistry: staking not configured");
        require(_stakeWithPendingDeposit(msg.sender, msg.value) >= _minStake(), "VKRegistry: insufficient stake");

        vaultKeepers[msg.sender] = VaultKeeperProfile({
            vkAddress: msg.sender,
            storageFee: storageFee,
            stake: msg.value,
            active: true,
            registeredAt: block.timestamp,
            lastHeartbeat: block.timestamp,
            suspendedUntil: 0,
            maxServiceDays: maxServiceDays
        });

        isRegisteredVaultKeeper[msg.sender] = true;
        vaultKeeperList.push(msg.sender);
        maxPieceSizeBytes[msg.sender] = maxPieceSizeBytes_;
        vaultKeeperPeerId[msg.sender] = peerId;
        admissionHistory[msg.sender].push(AdmissionCheckpoint(uint64(block.timestamp), false));

        // Forward stake ETH to StakingManager so it can be slashed and withdrawn properly.
        if (msg.value > 0 && stakingManager != address(0)) {
            IStakingManager_VKR(stakingManager).depositStakeFor{value: msg.value}(msg.sender);
        }

        // Early-stage registration incentive: credit VK join reward from pool.
        if (rewardManager != address(0)) {
            try IRewardManager_VKR(rewardManager).creditVKJoin(msg.sender) {} catch {}
        }

        emit VaultKeeperRegistered(msg.sender, peerId, metadataURI, storageFee, msg.value, maxServiceDays);
        emit VaultKeeperCapacityUpdated(msg.sender, maxPieceSizeBytes_);
    }

    function updateVaultKeeper(
        string calldata peerId,
        string calldata metadataURI,
        uint256 storageFee,
        uint32  maxServiceDays
    ) external onlyRegistered {
        _updateVaultKeeper(peerId, metadataURI, storageFee, maxServiceDays, maxPieceSizeBytes[msg.sender]);
    }

    function updateVaultKeeperWithCapacity(
        string calldata peerId,
        string calldata metadataURI,
        uint256 storageFee,
        uint32  maxServiceDays,
        uint64  maxPieceSizeBytes_
    ) external onlyRegistered {
        _updateVaultKeeper(peerId, metadataURI, storageFee, maxServiceDays, maxPieceSizeBytes_);
    }

    function _updateVaultKeeper(
        string calldata peerId,
        string calldata metadataURI,
        uint256 storageFee,
        uint32  maxServiceDays,
        uint64  maxPieceSizeBytes_
    ) internal {
        require(bytes(peerId).length > 0, "VKRegistry: empty peerId");
        require(_hasMinimumStake(msg.sender), "VKRegistry: insufficient stake");
        require(!_isSuspended(msg.sender), "VKRegistry: still suspended");

        VaultKeeperProfile storage vk = vaultKeepers[msg.sender];
        vk.storageFee = storageFee;
        vk.maxServiceDays = maxServiceDays;
        vk.lastHeartbeat = block.timestamp;
        maxPieceSizeBytes[msg.sender] = maxPieceSizeBytes_;
        vaultKeeperPeerId[msg.sender] = peerId;

        emit VaultKeeperUpdated(msg.sender, peerId, metadataURI, storageFee, maxServiceDays);
        emit VaultKeeperCapacityUpdated(msg.sender, maxPieceSizeBytes_);
    }

    function getVaultKeeperCapacity(address vkAddress) external view returns (uint64) {
        require(isRegisteredVaultKeeper[vkAddress], "VKRegistry: unknown VK");
        return maxPieceSizeBytes[vkAddress];
    }

    function setActive(bool active) external onlyRegistered {
        if (active) {
            require(_hasMinimumStake(msg.sender), "VKRegistry: insufficient stake");
            // Cannot reactivate while a temporary suspension is in force.
            require(!_isSuspended(msg.sender), "VKRegistry: still suspended");
        }
        vaultKeepers[msg.sender].active = active;
        vaultKeepers[msg.sender].lastHeartbeat = block.timestamp;

        emit VaultKeeperStatusChanged(msg.sender, active);
    }

    function heartbeat() external onlyRegistered {
        require(isEligibleVaultKeeper(msg.sender), "VKRegistry: insufficient stake");
        vaultKeepers[msg.sender].lastHeartbeat = block.timestamp;
        emit VaultKeeperHeartbeat(msg.sender, block.timestamp);
    }

    function updateEndpoint(bytes32 endpointHash, uint64 seq) external onlyRegistered {
        require(endpointHash != bytes32(0), "VKRegistry: empty endpoint hash");
        require(_hasMinimumStake(msg.sender), "VKRegistry: insufficient stake");
        require(!_isSuspended(msg.sender), "VKRegistry: still suspended");

        VaultKeeperEndpoint storage endpoint = vaultKeeperEndpoints[msg.sender];
        require(seq > endpoint.seq, "VKRegistry: stale endpoint seq");

        uint64 updatedAt = uint64(block.timestamp);
        endpoint.endpointHash = endpointHash;
        endpoint.seq = seq;
        endpoint.updatedAt = updatedAt;

        vaultKeepers[msg.sender].lastHeartbeat = block.timestamp;

        emit VaultKeeperEndpointUpdated(msg.sender, endpointHash, seq, updatedAt);
        emit VaultKeeperHeartbeat(msg.sender, block.timestamp);
    }

    function getVaultKeeperEndpoint(
        address vkAddress
    ) external view returns (bytes32 endpointHash, uint64 seq, uint64 updatedAt) {
        VaultKeeperEndpoint storage endpoint = vaultKeeperEndpoints[vkAddress];
        return (endpoint.endpointHash, endpoint.seq, endpoint.updatedAt);
    }

    function addStake() external payable onlyRegistered {
        require(msg.value > 0, "VKRegistry: zero stake");
        vaultKeepers[msg.sender].stake += msg.value;
        if (stakingManager != address(0)) {
            IStakingManager_VKR(stakingManager).depositStakeFor{value: msg.value}(msg.sender);
        }
    }

    function minimumVaultKeeperStake() public view returns (uint256) {
        return _minStake();
    }

    function isEligibleVaultKeeper(address vkAddress) public view returns (bool) {
        if (!isRegisteredVaultKeeper[vkAddress]) return false;
        VaultKeeperProfile storage vk = vaultKeepers[vkAddress];
        if (!vk.active) return false;
        if (_isSuspended(vkAddress)) return false;
        return _hasMinimumStake(vkAddress);
    }

    /// @notice Returns VK reputation from ReputationManager (1000 default if not configured).
    function getVKReputation(address vkAddress) external view returns (uint32) {
        if (reputationManager == address(0)) return 1000;
        try IReputationManager_VK(reputationManager).getVKReputation(vkAddress) returns (uint32 rep) {
            return rep;
        } catch {
            return 1000;
        }
    }

    // W6: Temporarily suspend a VK until `until`.  Owner or authorized enforcer only.
    function suspendVaultKeeper(address vkAddress, uint64 until) external {
        require(msg.sender == owner || authorizedEnforcers[msg.sender],
                "VKRegistry: not authorized");
        require(isRegisteredVaultKeeper[vkAddress], "VKRegistry: unknown VK");
        require(until > block.timestamp, "VKRegistry: until must be future");
        vaultKeepers[vkAddress].suspendedUntil = until;
        vaultKeepers[vkAddress].active = false;
        emit VaultKeeperSuspended(vkAddress, until);
        emit VaultKeeperStatusChanged(vkAddress, false);
    }

    // Deactivate (permanently).  Owner or authorized enforcer only (W6).
    function deactivateVaultKeeper(address vkAddress) external {
        require(msg.sender == owner || authorizedEnforcers[msg.sender],
                "VKRegistry: not authorized");
        require(isRegisteredVaultKeeper[vkAddress], "VKRegistry: unknown VK");
        vaultKeepers[vkAddress].active = false;
        emit VaultKeeperStatusChanged(vkAddress, false);
    }

    function getVaultKeeper(address vkAddress) external view returns (VaultKeeperProfile memory) {
        require(isRegisteredVaultKeeper[vkAddress], "VKRegistry: unknown VK");
        VaultKeeperProfile memory vk = vaultKeepers[vkAddress];
        // Return actual current stake from StakingManager (reflects slashes and withdrawals).
        if (stakingManager != address(0)) {
            try IStakingManager_VKR(stakingManager).stakeOf(vkAddress) returns (uint256 s) {
                vk.stake = s;
            } catch {}
        }
        return vk;
    }

    /// @notice Returns true if the VK is currently in a temporary suspension window.
    function isVKSuspended(address vkAddress) external view returns (bool) {
        return vaultKeepers[vkAddress].suspendedUntil > block.timestamp;
    }

    function getAllVaultKeepers() external view returns (address[] memory) {
        return vaultKeeperList;
    }

    /// @notice One page of registered keepers, newest pages reachable via count.
    /// @dev getAllVaultKeepers returns the entire list in a single response, which
    /// stops being answerable once the network is large. Callers should read
    /// getVaultKeeperCount and walk pages instead. Returns a short array at the
    /// end of the list rather than reverting, so a caller racing a registration
    /// does not fail.
    function getVaultKeeperPage(uint256 offset, uint256 limit)
        external
        view
        returns (address[] memory page)
    {
        uint256 total = vaultKeeperList.length;
        if (offset >= total || limit == 0) {
            return new address[](0);
        }
        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }
        page = new address[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = vaultKeeperList[i];
        }
    }

    /// @notice Everything a caller needs about one keeper, in a single call.
    /// @dev Choosing a keeper otherwise costs several round trips each, times
    /// every keeper in the network, on every upload.
    function getVaultKeeperSummary(address vkAddress)
        external
        view
        returns (
            string memory peerId,
            uint256 storageFee,
            uint256 stake,
            bool active,
            uint64 suspendedUntil,
            uint32 maxServiceDays,
            uint64 maxPieceSize,
            bool admissionOpen,
            uint64 reportedFreeBytes
        )
    {
        require(isRegisteredVaultKeeper[vkAddress], "VKRegistry: unknown VK");
        VaultKeeperProfile memory vk = vaultKeepers[vkAddress];
        uint256 currentStake = vk.stake;
        if (stakingManager != address(0)) {
            try IStakingManager_VKR(stakingManager).stakeOf(vkAddress) returns (uint256 s) {
                currentStake = s;
            } catch {}
        }
        return (
            vaultKeeperPeerId[vkAddress],
            vk.storageFee,
            currentStake,
            vk.active,
            vk.suspendedUntil,
            vk.maxServiceDays,
            maxPieceSizeBytes[vkAddress],
            !admissionClosed[vkAddress],
            reportedAdmissionFreeBytes[vkAddress]
        );
    }

    function getVaultKeeperCount() external view returns (uint256) {
        return vaultKeeperList.length;
    }

    function _stakeWithPendingDeposit(address vkAddress, uint256 pendingDeposit) internal view returns (uint256) {
        return _stakeOf(vkAddress) + pendingDeposit;
    }

    function _hasMinimumStake(address vkAddress) internal view returns (bool) {
        return _stakeOf(vkAddress) >= _minStake();
    }

    function _isSuspended(address vkAddress) internal view returns (bool) {
        return vaultKeepers[vkAddress].suspendedUntil != 0 &&
            block.timestamp < vaultKeepers[vkAddress].suspendedUntil;
    }

    function _stakeOf(address vkAddress) internal view returns (uint256) {
        if (stakingManager == address(0)) return 0;
        try IStakingManager_VKR(stakingManager).stakeOf(vkAddress) returns (uint256 s) {
            return s;
        } catch {
            return 0;
        }
    }

    function _minStake() internal view returns (uint256) {
        if (stakingManager == address(0)) return type(uint256).max;
        try IStakingManager_VKR(stakingManager).minStake() returns (uint256 s) {
            return s;
        } catch {
            return type(uint256).max;
        }
    }
}
