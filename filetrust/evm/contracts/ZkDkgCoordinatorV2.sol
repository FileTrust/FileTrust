// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: ZkDkgCoordinatorV2
// Purpose:  The key generation that gives a file's policy its Guardian shares, with
//           every step proven rather than trusted.
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
import "./DkgAttemptTypes.sol";

error ZkDkgV2_AlreadySettled();
error ZkDkgV2_AlreadySubmitted();
error ZkDkgV2_DeadlineNotPassed();
error ZkDkgV2_DuplicateOldIndex();
error ZkDkgV2_Error();
error ZkDkgV2_ExcludedDealer();
error ZkDkgV2_GuardianNotEligible();
error ZkDkgV2_InvalidDuration();
error ZkDkgV2_InvalidIndex();
error ZkDkgV2_InvalidMaterial();
error ZkDkgV2_MissingDealers();
error ZkDkgV2_MissingOldShareKey();
error ZkDkgV2_NoActiveKey();
error ZkDkgV2_NoActivePolicy();
error ZkDkgV2_NoPendingKeygen();
error ZkDkgV2_NoPendingRefresh();
error ZkDkgV2_NoTimestamp();
error ZkDkgV2_NotACLOwner();
error ZkDkgV2_NotDisputeManager();
error ZkDkgV2_NotEnoughOldParticipants();
error ZkDkgV2_PendingRefreshExists();
error ZkDkgV2_StaleRefresh();
error ZkDkgV2_Unauthorized();
error ZkDkgV2_WrongEpoch();
error ZkDkgV2_WrongMode();
error ZkDkgV2_WrongVersion();

interface IAccessControlFT_ZkDkgV2 {
    enum DkgMode {
        LEGACY,
        ZKDKG_V2
    }

    function getFilePolicy(bytes32 fileId)
        external
        view
        returns (bool exists, bool active, address dataOwner, uint8 threshold, address[] memory guardians);
    function getDkgFilePolicy(bytes32 fileId) external view returns (bool, bool, address, uint8, address[] memory);
    function activateV2FilePolicy(bytes32 fileId, uint8 threshold, bytes32 guardiansHash) external;
    function getFilePolicyMode(bytes32 fileId) external view returns (DkgMode);
    function hasRequestedKeyGenForFile(bytes32 fileId) external view returns (bool);
    function getKeyGenRequestedAtForFile(bytes32 fileId) external view returns (uint64);
    function keyGenAttemptNonce(bytes32 fileId) external view returns (uint64);
    function keyGenDeadlineForFile(bytes32 fileId) external view returns (uint64);
    function clearKeyGenRequestForFileFromDKG(bytes32 fileId) external;
    function isGuardianForFile(bytes32 fileId, address guardian) external view returns (bool);
    function guardianRegistry() external view returns (address);
    function owner() external view returns (address);
}

interface IZkDkgDisputeManager_V2 {
    function isDealerExcluded(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex
    ) external view returns (bool);
}

interface IReputationManager_ZkDkgV2 {
    function recordDkgSuccess(address guardian, uint256 speedScore) external;
    function recordDkgFailure(address guardian, uint8 reasonCode) external;
}

interface IGuardianRegistry_ZkDkgV2 {
    function isActiveGuardian(address guardian) external view returns (bool);
}

interface IRewardManager_ZkDkgV2 {
    function creditV2SharePublicKey(bytes32 fileId, address guardian) external;
    function ACTION_V2_DKG_SHARE_KEY() external view returns (bytes32);
    function creditMeasuredPolicyReward(bytes32 fileId, address guardian, bytes32 actionType, uint256 measuredGas)
        external;
    function calculateDkgExpiryCompensation(bytes32 fileId, uint8 nonParticipantCount)
        external view returns (uint256 perFailingGuardianWei);
    function refundPolicyEscrowForExpiry(bytes32 fileId, address dataOwner) external;
}

interface IGuardianWorkReward_ZkDkgV2 {
    function credit(address[] calldata guardians, uint8 kind) external;
}

interface IStakingManager_ZkDkgV2 {
    function slashTo(address guardian, uint256 amount, address recipient) external;
}

interface IGuardianShareProof_ZkDkgV2 {
    function lastProofAt(address guardian) external view returns (uint256);
}

contract ZkDkgCoordinatorV2 is ReentrancyGuard {
    struct V2Key {
        bool exists;
        bool finalized;
        address dataOwner;
        uint8 t;
        uint8 n;
        uint32 keyEpoch;
        uint32 shareVersion;
        uint256 publicKeyX;
        uint256 publicKeyY;
    }

    struct SharePublicKey {
        bool exists;
        address guardian;
        uint8 shareIndex;
        uint256 x;
        uint256 y;
    }

    struct V2DealerCommitments {
        bool exists;
        address dealer;
        uint8 dealerIndex;
        uint256[] points; // interleaved: [x0, y0, x1, y1, ...]
    }

    struct V2EncryptedShare {
        bool exists;
        address dealer;
        address recipient;
        uint8 fromIndex;
        uint8 toIndex;
        bytes encryptedPayload;
    }

    struct V2RefreshRequest {
        bool exists;
        bool finalized;
        uint32 keyEpoch;
        uint32 oldShareVersion;
        uint32 shareVersion;
        uint8 oldT;
        uint8 oldN;
        uint8 newT;
        uint8 newN;
        address[] oldGuardians;
        address[] newGuardians;
        uint8[] oldParticipantIndices;
    }

    IAccessControlFT_ZkDkgV2 public immutable acl;
    IZkDkgDisputeManager_V2 public disputeManager;
    IDkgAttemptController public attemptController;
    address public reputationManager;
    address public rewardManager;
    address public stakingManager;
    address public guardianShareProof;
    uint256 public maxInactivitySeconds = 26 hours;

    uint64 public dkgKeyGenDeadline = 1 hours;

    mapping(bytes32 => V2Key) private _keys;
    mapping(bytes32 => mapping(uint32 => mapping(uint8 => bool))) private _dealerMaterialSubmitted;
    mapping(bytes32 => mapping(uint32 => uint256)) private _dealerMaterialCount;
    mapping(bytes32 => mapping(uint32 => mapping(uint32 => mapping(uint8 => SharePublicKey)))) private _sharePublicKeys;
    mapping(bytes32 => mapping(uint32 => mapping(uint32 => mapping(uint8 => V2DealerCommitments)))) private _dealerCommitments;
    mapping(bytes32 => mapping(uint32 => mapping(uint32 => mapping(uint8 => mapping(uint8 => V2EncryptedShare))))) private _encryptedShares;
    mapping(bytes32 => mapping(uint32 => V2RefreshRequest)) private _pendingRefresh;
    mapping(bytes32 => mapping(uint32 => uint64)) private _refreshRequestedAt;
    mapping(bytes32 => mapping(uint32 => uint64)) public refreshDeadline;
    mapping(bytes32 => mapping(uint32 => bool)) public refreshSettled;
    mapping(bytes32 => mapping(uint32 => uint64)) private _refreshAttemptNonce;
    mapping(bytes32 => mapping(uint32 => bytes32)) private _refreshMaterialId;
    mapping(bytes32 => mapping(uint32 => mapping(uint32 => bytes32))) private _activatedMaterialId;
    mapping(bytes32 => uint32) private _completedDealers;
    mapping(bytes32 => uint32) private _receivedShares;
    mapping(bytes32 => uint32) private _contributors;
    // Every receiver must combine the same old dealers. Bits are old index-1;
    // the supported committees fit in 32 bits. Zero means no set was finalized.
    mapping(bytes32 => mapping(uint32 => mapping(uint32 => uint32))) public v2RefreshContributorMask;

    /// @notice Early-network reward pool paid to every Guardian of a finished DKG; zero is off.
    address public guardianWorkReward;
    /// @notice Gas reserved for that reward inside finalizeV2Dkg: a base plus a share per
    ///         Guardian (measured with the real registry: about 68k for one Guardian and 46k
    ///         per Guardian for twenty, paying each for the first time).
    uint256 private constant GUARDIAN_WORK_REWARD_BASE_GAS = 40_000;
    uint256 private constant GUARDIAN_WORK_REWARD_GAS = 60_000;

    event AttemptControllerSet(address indexed controller);
    event AttemptClosed(bytes32 indexed materialId, bytes32 indexed fileId, uint32 epoch, uint32 version, uint8 outcome, uint8 faults);
    event RefreshMaterialsReady(bytes32 indexed materialId, bytes32 indexed fileId, uint32 epoch, uint32 version, uint32 contributors);
    event DisputeManagerSet(address indexed disputeManager);
    event ReputationManagerSet(address indexed manager);
    event RewardManagerSet(address indexed manager);
    event GuardianWorkRewardSet(address indexed reward);
    event StakingManagerSet(address indexed manager);
    event GuardianShareProofSet(address indexed guardianShareProof);
    event MaxInactivitySecondsSet(uint256 maxInactivitySeconds);
    event DkgKeyGenDeadlineSet(uint64 duration);
    event DkgKeyGenExpired(bytes32 materialId, bytes32 indexed fileId, uint32 indexed keyEpoch, uint8 nonParticipantCount);
    event V2RefreshExpired(bytes32 materialId, bytes32 indexed fileId, uint32 indexed keyEpoch, uint32 indexed shareVersion, uint8 absentCount);
    event V2RefreshAbsentPenalized(bytes32 materialId, bytes32 indexed fileId, uint32 indexed keyEpoch, uint32 indexed shareVersion, uint8 absentCount);
    event ZkDkgV2DealerMaterialAccepted(
        bytes32 materialId,
        bytes32 indexed fileId,
        uint32 indexed keyEpoch,
        address indexed dealer,
        uint8 dealerIndex
    );
    event ZkDkgV2Finalized(
        bytes32 materialId,
        bytes32 indexed fileId,
        address indexed dataOwner,
        uint32 indexed keyEpoch,
        uint32 shareVersion,
        uint8 t,
        uint8 n,
        uint256 publicKeyX,
        uint256 publicKeyY
    );
    event V2DealerCommitmentsPublished(
        bytes32 materialId,
        bytes32 indexed fileId,
        uint256 indexed keyEpoch,
        uint256 indexed shareVersion,
        uint256 dealerIndex,
        address dealer
    );
    event V2EncryptedSharePublished(
        bytes32 materialId,
        bytes32 indexed fileId,
        uint256 indexed keyEpoch,
        uint256 indexed shareVersion,
        uint256 fromIndex,
        uint256 toIndex,
        address dealer,
        address recipient
    );
    event ZkDkgV2SamePkRefreshRequested(
        bytes32 materialId,
        bytes32 indexed fileId,
        uint32 indexed keyEpoch,
        uint32 indexed shareVersion,
        uint32 oldShareVersion,
        uint8 oldT,
        uint8 oldN,
        uint8 newT,
        uint8 newN
    );
    event ZkDkgV2SamePkRefreshFinalized(
        bytes32 materialId,
        bytes32 indexed fileId,
        uint32 indexed keyEpoch,
        uint32 indexed shareVersion,
        uint8 newT,
        uint8 newN
    );

    constructor(address aclAddress, address disputeManagerAddress) {
        if (aclAddress == address(0)) revert ZkDkgV2_Error();
        acl = IAccessControlFT_ZkDkgV2(aclAddress);
        if (disputeManagerAddress != address(0)) {
            disputeManager = IZkDkgDisputeManager_V2(disputeManagerAddress);
        }
    }

    function setAttemptController(address manager) external onlyAclOwner {
        require(address(attemptController) == address(0) && manager.code.length != 0, ZkDkgV2_Error());
        IDkgAttemptController c = IDkgAttemptController(manager);
        require(c.coordinator() == address(this) && c.acl() == address(acl), ZkDkgV2_Error());
        attemptController = c;
        emit AttemptControllerSet(manager);
    }

    modifier idleConfiguration() {
        require(address(attemptController) == address(0) || attemptController.activeCount() == 0, ZkDkgV2_PendingRefreshExists());
        _;
    }

    function setDisputeManager(address manager) external onlyAclOwner idleConfiguration {
        if (manager == address(0)) revert ZkDkgV2_Error();
        disputeManager = IZkDkgDisputeManager_V2(manager);
        emit DisputeManagerSet(manager);
    }

    function setReputationManager(address manager) external onlyAclOwner idleConfiguration {
        if (manager == address(0)) revert ZkDkgV2_Error();
        reputationManager = manager;
        emit ReputationManagerSet(manager);
    }

    function setRewardManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert ZkDkgV2_Error();
        rewardManager = manager;
        emit RewardManagerSet(manager);
    }

    function setGuardianWorkReward(address reward) external onlyAclOwner {
        guardianWorkReward = reward;
        emit GuardianWorkRewardSet(reward);
    }

    function setStakingManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert ZkDkgV2_Error();
        stakingManager = manager;
        emit StakingManagerSet(manager);
    }

    function setGuardianShareProof(address _guardianShareProof) external onlyAclOwner {
        guardianShareProof = _guardianShareProof;
        emit GuardianShareProofSet(_guardianShareProof);
    }

    function setMaxInactivitySeconds(uint256 _maxInactivitySeconds) external onlyAclOwner {
        require(_maxInactivitySeconds > 0, ZkDkgV2_InvalidDuration());
        maxInactivitySeconds = _maxInactivitySeconds;
        emit MaxInactivitySecondsSet(_maxInactivitySeconds);
    }

    function setDkgKeyGenDeadline(uint64 duration) external onlyAclOwner {
        require(duration > 0, ZkDkgV2_InvalidDuration());
        dkgKeyGenDeadline = duration;
        emit DkgKeyGenDeadlineSet(duration);
    }

    /// @notice Expire a stalled keygen round after the deadline passes.
    ///         Penalizes every Guardian that never submitted dealer material,
    ///         slashes their stake to compensate the DO, refunds remaining escrow to DO,
    ///         then clears the ACL keygen flag so the DO can retry immediately.
    /// @param fileId   The file whose keygen is stuck.
    /// @param keyEpoch The epoch number the failed round was using (agreed off-chain by Guardians).
    function expireDkgKeyGenForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch) external nonReentrant {
        _requireMaterialId(materialId, fileId, keyEpoch, 1);
        _expireDkgKeyGen(fileId, keyEpoch);
    }

    function _expireDkgKeyGen(bytes32 fileId, uint32 keyEpoch) internal {
        bytes32 materialId = getMaterialAttemptId(fileId, keyEpoch, 1);
        if (attemptController.isBound(materialId)) attemptController.expire(materialId);
        else {
            require(acl.hasRequestedKeyGenForFile(fileId) && block.timestamp > acl.keyGenDeadlineForFile(fileId), ZkDkgV2_DeadlineNotPassed());
            acl.clearKeyGenRequestForFileFromDKG(fileId);
            emit AttemptClosed(materialId, fileId, keyEpoch, 1, 5, 0);
        }
    }
    function acknowledgeDealerMaterialForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint8 dealerIndex, address dealer) external nonReentrant {
        require(msg.sender == address(disputeManager), ZkDkgV2_NotDisputeManager());
        _requireMaterialId(materialId, fileId, keyEpoch, 1);
        _acknowledgeDealerMaterial(fileId, keyEpoch, dealerIndex, dealer);
    }

    function acknowledgeRefreshDealerMaterialForAttempt(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version, uint8 index, address dealer) external nonReentrant {
        require(msg.sender == address(disputeManager) && version > 1, ZkDkgV2_NotDisputeManager());
        _requireMaterialId(materialId, fileId, epoch, version);
        uint8 n = attemptController.validateDealer(materialId, dealer, index);
        require(!_dealerMaterialSubmitted[materialId][epoch][index], ZkDkgV2_AlreadySubmitted());
        _dealerMaterialSubmitted[materialId][epoch][index] = true;
        _recordDealerComplete(fileId, epoch, version, index, n);
    }
    function _acknowledgeDealerMaterial(bytes32 fileId, uint32 epoch, uint8 index, address dealer) internal {
        bytes32 materialId = getMaterialAttemptId(fileId, epoch, 1);
        uint8 n = attemptController.validateDealer(materialId, dealer, index);
        require(!_dealerMaterialSubmitted[materialId][epoch][index], ZkDkgV2_AlreadySubmitted());
        _dealerMaterialSubmitted[materialId][epoch][index] = true;
        ++_dealerMaterialCount[materialId][epoch];
        emit ZkDkgV2DealerMaterialAccepted(materialId, fileId, epoch, dealer, index);
        _recordDealerComplete(fileId, epoch, 1, index, n);
    }
    function finalizeV2DkgForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint256 publicKeyX, uint256 publicKeyY) external nonReentrant {
        _requireMaterialId(materialId, fileId, keyEpoch, 1);
        _finalizeV2Dkg(fileId, keyEpoch, publicKeyX, publicKeyY);
    }

    function _finalizeV2Dkg(bytes32 fileId, uint32 keyEpoch, uint256 publicKeyX, uint256 publicKeyY) internal {
        _requireFreshRequest(fileId, keyEpoch);
        if (address(disputeManager) == address(0)) revert ZkDkgV2_Error();
        (bool exists, bool active, address dataOwner, uint8 t, address[] memory guardians) = acl.getDkgFilePolicy(fileId);
        if (!(exists && active)) revert ZkDkgV2_Error();
        require(acl.getFilePolicyMode(fileId) == IAccessControlFT_ZkDkgV2.DkgMode.ZKDKG_V2, ZkDkgV2_WrongMode());
        require(msg.sender == dataOwner, ZkDkgV2_Unauthorized());
        require(acl.hasRequestedKeyGenForFile(fileId), ZkDkgV2_NoPendingKeygen());
        require(keyEpoch > 0, ZkDkgV2_WrongEpoch());
        require(!_keys[fileId].exists || keyEpoch == _keys[fileId].keyEpoch + 1, ZkDkgV2_WrongEpoch());
        bytes32 materialId = getMaterialAttemptId(fileId, keyEpoch, 1);
        require(_dealerMaterialCount[materialId][keyEpoch] >= guardians.length, ZkDkgV2_MissingDealers());

        uint8 n = uint8(guardians.length);
        require(_receivedShares[materialId] == _all(n), ZkDkgV2_MissingOldShareKey());
        for (uint8 i = 1; i <= n; i++) {
            require(_dealerMaterialSubmitted[materialId][keyEpoch][i], ZkDkgV2_MissingDealers());
            require(!disputeManager.isDealerExcluded(fileId, keyEpoch, 1, false, i), ZkDkgV2_ExcludedDealer());
        }

        V2Key storage k = _keys[fileId];
        k.exists = true;
        k.finalized = true;
        k.dataOwner = dataOwner;
        k.t = t;
        k.n = n;
        k.keyEpoch = keyEpoch;
        k.shareVersion = 1;
        k.publicKeyX = publicKeyX;
        k.publicKeyY = publicKeyY;
        _activatedMaterialId[fileId][keyEpoch][1] = materialId;

        acl.activateV2FilePolicy(fileId, t, keccak256(abi.encode(guardians)));
        acl.clearKeyGenRequestForFileFromDKG(fileId);
        attemptController.complete(materialId);

        if (reputationManager != address(0)) {
            IReputationManager_ZkDkgV2 rm = IReputationManager_ZkDkgV2(reputationManager);
            for (uint256 i = 0; i < guardians.length; i++) {
                try rm.recordDkgSuccess(guardians[i], 0) {
                } catch {
                }
            }
        }
        _rewardGuardianWork(guardians);

        emit ZkDkgV2Finalized(materialId, fileId, dataOwner, keyEpoch, 1, t, n, publicKeyX, publicKeyY);
    }

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
        )
    {
        V2Key storage k = _keys[fileId];
        return (k.exists, k.finalized, k.dataOwner, k.t, k.n, k.keyEpoch, k.shareVersion, k.publicKeyX, k.publicKeyY);
    }

    function getActiveShareVersion(bytes32 fileId, uint32 keyEpoch) external view returns (uint32) {
        V2Key storage k = _keys[fileId];
        require(k.exists && k.finalized && k.keyEpoch == keyEpoch, ZkDkgV2_NoActiveKey());
        return k.shareVersion;
    }


    function getAttemptWork(bytes32 materialId) external view returns (uint32 dealers, uint32 receivers, uint32 contributors) {
        return (_completedDealers[materialId], _receivedShares[materialId], _contributors[materialId]);
    }

    function closeAttempt(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version, uint8 outcome, uint8 faults) external {
        require(msg.sender == address(attemptController), ZkDkgV2_Unauthorized());
        _requireMaterialId(materialId, fileId, epoch, version);
        if (outcome != 3) {
            if (version == 1) acl.clearKeyGenRequestForFileFromDKG(fileId);
            else {
                require(!_pendingRefresh[fileId][epoch].finalized, ZkDkgV2_AlreadySettled());
                refreshSettled[fileId][epoch] = true;
            }
            if (outcome == 4) {
                if (version == 1) emit DkgKeyGenExpired(materialId, fileId, epoch, faults);
                else emit V2RefreshExpired(materialId, fileId, epoch, version, faults);
            }
        }
        emit AttemptClosed(materialId, fileId, epoch, version, outcome, faults);
    }

    /// @notice Material context is independent of the successful key/share
    /// version. A new request never makes the prior context's data part of the
    /// retry. Successful versions retain their original context identifiers.
    function getMaterialAttemptId(bytes32 fileId, uint32 keyEpoch, uint32 shareVersion) public view returns (bytes32) {
        if (shareVersion == 1) {
            V2Key storage k = _keys[fileId];
            if (acl.hasRequestedKeyGenForFile(fileId) && keyEpoch == (k.exists ? k.keyEpoch + 1 : 1)) {
                return keccak256(abi.encode(block.chainid, address(this), fileId, keyEpoch, uint8(0), acl.keyGenAttemptNonce(fileId)));
            }
        } else {
            V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
            if (r.exists && r.shareVersion == shareVersion) return _refreshMaterialId[fileId][keyEpoch];
        }
        return _activatedMaterialId[fileId][keyEpoch][shareVersion];
    }

    function dealerMaterialSubmitted(bytes32 fileId, uint32 keyEpoch, uint8 index) public view returns (bool) {
        return _dealerMaterialSubmitted[getMaterialAttemptId(fileId, keyEpoch, 1)][keyEpoch][index];
    }

    function dealerMaterialCount(bytes32 fileId, uint32 keyEpoch) external view returns (uint256) {
        return _dealerMaterialCount[getMaterialAttemptId(fileId, keyEpoch, 1)][keyEpoch];
    }

    function _requireMaterialId(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version) internal view {
        if (materialId == bytes32(0) || materialId != getMaterialAttemptId(fileId, epoch, version)) revert ZkDkgV2_Error();
    }

    function _requireFreshMaterialOpen(bytes32 fileId, uint32 epoch) internal view {
        _requireFreshRequest(fileId, epoch);
        attemptController.requireMaterialOpen(getMaterialAttemptId(fileId, epoch, 1));
    }

    function _requireFreshRequest(bytes32 fileId, uint32 epoch) internal view {
        V2Key storage k = _keys[fileId];
        if (!acl.hasRequestedKeyGenForFile(fileId) || epoch != (k.exists ? k.keyEpoch + 1 : 1)
            || address(attemptController) == address(0)) revert ZkDkgV2_Error();
    }
    function validateMaterialAttempt(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version) external view {
        _requireMaterialId(materialId, fileId, epoch, version);
        if (version == 1) _requireFreshMaterialOpen(fileId, epoch);
        else _requirePendingV2Refresh(fileId, epoch, version);
    }

    function hasPendingV2Refresh(bytes32 fileId) external view returns (bool) {
        uint32 epoch = _keys[fileId].keyEpoch;
        V2RefreshRequest storage r = _pendingRefresh[fileId][epoch];
        return r.exists && !r.finalized && !refreshSettled[fileId][epoch];
    }

    function requestV2SamePkShareRefreshForVersion(bytes32 fileId, uint32 keyEpoch, uint32 activeVersion, bytes32 previousAttempt, uint8[] calldata oldParticipantIndices) external nonReentrant {
        if (_keys[fileId].shareVersion != activeVersion || _refreshMaterialId[fileId][keyEpoch] != previousAttempt) revert ZkDkgV2_Error();
        _requestV2SamePkShareRefresh(fileId, keyEpoch, oldParticipantIndices);
    }

    function _requestV2SamePkShareRefresh(bytes32 fileId, uint32 keyEpoch, uint8[] calldata oldParticipantIndices) internal {
        require(!acl.hasRequestedKeyGenForFile(fileId), ZkDkgV2_PendingRefreshExists());
        (bool exists, bool active, address dataOwner, uint8 newT, address[] memory newGuardians) = acl.getDkgFilePolicy(fileId);
        require(exists && active, ZkDkgV2_NoActivePolicy());
        require(newGuardians.length >= newT, ZkDkgV2_InvalidIndex());
        require(acl.getFilePolicyMode(fileId) == IAccessControlFT_ZkDkgV2.DkgMode.ZKDKG_V2, ZkDkgV2_WrongMode());
        require(msg.sender == dataOwner, ZkDkgV2_Unauthorized());

        V2Key storage k = _keys[fileId];
        require(k.exists && k.finalized, ZkDkgV2_NoActiveKey());
        require(k.keyEpoch == keyEpoch, ZkDkgV2_WrongEpoch());
        // Freeze one old-threshold set before coefficients are generated.
        // Retries select another set; no timing-dependent reweighting of an
        // already encrypted polynomial is allowed inside this attempt.
        require(oldParticipantIndices.length == uint256(k.t), ZkDkgV2_NotEnoughOldParticipants());

        V2RefreshRequest storage existingRefresh = _pendingRefresh[fileId][keyEpoch];
        require(!existingRefresh.exists || existingRefresh.finalized || refreshSettled[fileId][keyEpoch], ZkDkgV2_PendingRefreshExists());

        address[] memory oldGuardians = new address[](uint256(k.n));
        for (uint8 i = 1; i <= k.n; i++) {
            SharePublicKey storage oldPk = _sharePublicKeys[getMaterialAttemptId(fileId, keyEpoch, k.shareVersion)][keyEpoch][k.shareVersion][i];
            require(oldPk.exists, ZkDkgV2_MissingOldShareKey());
            oldGuardians[uint256(i) - 1] = oldPk.guardian;
        }

        bool[] memory seen = new bool[](uint256(k.n) + 1);
        for (uint256 i = 0; i < oldParticipantIndices.length; i++) {
            uint8 oldIndex = oldParticipantIndices[i];
            require(oldIndex > 0 && oldIndex <= k.n, ZkDkgV2_InvalidIndex());
            require(!seen[uint256(oldIndex)], ZkDkgV2_DuplicateOldIndex());
            seen[uint256(oldIndex)] = true;
        }

        delete _pendingRefresh[fileId][keyEpoch];
        _refreshRequestedAt[fileId][keyEpoch] = uint64(block.timestamp);
        refreshDeadline[fileId][keyEpoch] = uint64(block.timestamp) + dkgKeyGenDeadline;
        delete refreshSettled[fileId][keyEpoch];
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        r.exists = true;
        r.finalized = false;
        r.keyEpoch = keyEpoch;
        r.oldShareVersion = k.shareVersion;
        r.shareVersion = k.shareVersion + 1;
        r.oldT = k.t;
        r.oldN = k.n;
        r.newT = newT;
        r.newN = uint8(newGuardians.length);
        delete v2RefreshContributorMask[fileId][keyEpoch][r.shareVersion];
        uint64 nonce = ++_refreshAttemptNonce[fileId][keyEpoch];
        _refreshMaterialId[fileId][keyEpoch] = keccak256(abi.encode(block.chainid, address(this), fileId, keyEpoch, uint8(1), nonce));

        for (uint256 i = 0; i < oldGuardians.length; i++) {
            r.oldGuardians.push(oldGuardians[i]);
        }
        for (uint256 i = 0; i < newGuardians.length; i++) {
            r.newGuardians.push(newGuardians[i]);
        }
        for (uint256 i = 0; i < oldParticipantIndices.length; i++) {
            r.oldParticipantIndices.push(oldParticipantIndices[i]);
        }

        emit ZkDkgV2SamePkRefreshRequested(
            _refreshMaterialId[fileId][keyEpoch],
            fileId,
            keyEpoch,
            r.shareVersion,
            r.oldShareVersion,
            r.oldT,
            r.oldN,
            r.newT,
            r.newN
        );
    }

    function getRefreshRequestedAt(bytes32 fileId, uint32 keyEpoch) external view returns (uint64) {
        return _refreshRequestedAt[fileId][keyEpoch];
    }

    function getRefreshRequest(bytes32 fileId, uint32 keyEpoch, uint32 shareVersion)
        external
        view
        returns (
            bool exists,
            bool finalized,
            uint32 oldShareVersion,
            uint8 oldT,
            uint8 oldN,
            uint8 newT,
            uint8 newN,
            address[] memory oldGuardians,
            address[] memory newGuardians,
            uint8[] memory oldParticipantIndices
        )
    {
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        if (!r.exists || r.shareVersion != shareVersion) {
            return (
                false,
                false,
                0,
                0,
                0,
                0,
                0,
                new address[](0),
                new address[](0),
                new uint8[](0)
            );
        }
        return (
            r.exists,
            r.finalized,
            r.oldShareVersion,
            r.oldT,
            r.oldN,
            r.newT,
            r.newN,
            r.oldGuardians,
            r.newGuardians,
            r.oldParticipantIndices
        );
    }

    /// @notice Settle a refresh round after the deadline passes.
    ///         If the refresh never finalized: marks it done (so DO can retry),
    ///         punishes absent old Gs, and refunds DO's escrow.
    ///         If the refresh already finalized but some old Gs skipped:
    ///         applies reputation penalty only (no compensation — refresh succeeded).
    function settleV2RefreshForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint32 shareVersion) external nonReentrant {
        _requireMaterialId(materialId, fileId, keyEpoch, shareVersion);
        _settleV2Refresh(fileId, keyEpoch, shareVersion);
    }

    function _settleV2Refresh(bytes32 fileId, uint32 keyEpoch, uint32 shareVersion) internal {
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        require(r.exists && !r.finalized && r.shareVersion == shareVersion && !refreshSettled[fileId][keyEpoch], ZkDkgV2_NoPendingRefresh());
        bytes32 materialId = _refreshMaterialId[fileId][keyEpoch];
        if (attemptController.isBound(materialId)) attemptController.expire(materialId);
        else {
            require(block.timestamp > refreshDeadline[fileId][keyEpoch], ZkDkgV2_DeadlineNotPassed());
            refreshSettled[fileId][keyEpoch] = true;
            emit AttemptClosed(materialId, fileId, keyEpoch, shareVersion, 5, 0);
        }
    }
    function getPendingV2Refresh(bytes32 fileId, uint32 keyEpoch)
        external
        view
        returns (
            bool exists,
            bool finalized,
            uint32 shareVersion,
            uint32 oldShareVersion,
            uint8 oldT,
            uint8 oldN,
            uint8 newT,
            uint8 newN,
            address[] memory oldGuardians,
            address[] memory newGuardians,
            uint8[] memory oldParticipantIndices
        )
    {
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        return (
            r.exists,
            r.finalized,
            r.shareVersion,
            r.oldShareVersion,
            r.oldT,
            r.oldN,
            r.newT,
            r.newN,
            r.oldGuardians,
            r.newGuardians,
            r.oldParticipantIndices
        );
    }

    function getV2RefreshProgress(bytes32 fileId, uint32 keyEpoch, uint32 shareVersion)
        external
        view
        returns (
            uint256 commitmentCount,
            uint256 encryptedShareCount,
            uint256 requiredCommitments,
            uint256 requiredEncryptedShares,
            bool finalized
        )
    {
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        if (!r.exists || r.shareVersion != shareVersion) {
            V2Key storage k = _keys[fileId];
            return (0, 0, 0, 0, k.exists && k.keyEpoch == keyEpoch && k.shareVersion >= shareVersion);
        }

        for (uint256 i = 0; i < r.oldParticipantIndices.length; i++) {
            uint8 oldIndex = r.oldParticipantIndices[i];
            if (_dealerCommitments[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][oldIndex].exists) {
                commitmentCount += 1;
            }
            for (uint8 j = 1; j <= r.newN; j++) {
                if (_encryptedShares[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][oldIndex][j].exists) {
                    encryptedShareCount += 1;
                }
            }
        }

        requiredCommitments = r.oldT;
        requiredEncryptedShares = uint256(r.oldT) * uint256(r.newN);
        finalized = r.finalized;
    }

    function publishV2SharePublicKeyForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint8 shareIndex, uint256 x, uint256 y) external nonReentrant {
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        uint32 version = r.exists && !r.finalized && materialId == _refreshMaterialId[fileId][keyEpoch]
            ? r.shareVersion : 1;
        _requireMaterialId(materialId, fileId, keyEpoch, version);
        _publishV2SharePublicKey(materialId, keyEpoch, version, shareIndex, x, y);
    }
    function _publishV2SharePublicKey(bytes32 materialId, uint32 keyEpoch, uint32 version, uint8 shareIndex, uint256 x, uint256 y) internal {
        attemptController.validateSharePublication(materialId, msg.sender, shareIndex, x, y);
        SharePublicKey storage pk = _sharePublicKeys[materialId][keyEpoch][version][shareIndex];
        require(!pk.exists, ZkDkgV2_AlreadySubmitted());
        pk.exists = true; pk.guardian = msg.sender; pk.shareIndex = shareIndex; pk.x = x; pk.y = y;
        _receivedShares[materialId] |= uint32(1) << (shareIndex - 1);
    }
    function publishV2DealerCommitmentsForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint32 shareVersion, uint8 dealerIndex, uint256[] calldata xs, uint256[] calldata ys) external nonReentrant {
        _requireMaterialId(materialId, fileId, keyEpoch, shareVersion);
        _publishV2DealerCommitments(fileId, keyEpoch, shareVersion, dealerIndex, xs, ys);
    }

    function _publishV2DealerCommitments(bytes32 fileId, uint32 epoch, uint32 version, uint8 index, uint256[] calldata xs, uint256[] calldata ys) internal {
        bytes32 materialId = getMaterialAttemptId(fileId, epoch, version);
        uint8 n = attemptController.validateCommitments(materialId, msg.sender, index, xs, ys);
        V2DealerCommitments storage c = _dealerCommitments[materialId][epoch][version][index];
        require(!c.exists, ZkDkgV2_AlreadySubmitted());
        c.exists = true; c.dealer = msg.sender; c.dealerIndex = index;
        for (uint256 i; i < xs.length; ++i) { c.points.push(xs[i]); c.points.push(ys[i]); }
        emit V2DealerCommitmentsPublished(materialId, fileId, epoch, version, index, msg.sender);
        _recordDealerComplete(fileId, epoch, version, index, n);
    }
    function getV2DealerCommitments(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 dealerIndex
    ) external view returns (bool exists, address dealer, uint8 storedDealerIndex, uint256[] memory xs, uint256[] memory ys) {
        V2DealerCommitments storage c = _dealerCommitments[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][dealerIndex];
        if (!c.exists) return (false, address(0), 0, new uint256[](0), new uint256[](0));
        uint256 n = c.points.length / 2;
        xs = new uint256[](n);
        ys = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            xs[i] = c.points[2 * i];
            ys[i] = c.points[2 * i + 1];
        }
        return (c.exists, c.dealer, c.dealerIndex, xs, ys);
    }

    function hasV2DealerCommitments(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 dealerIndex
    ) external view returns (bool) {
        return _dealerCommitments[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][dealerIndex].exists;
    }

    function publishV2EncryptedShareForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint32 shareVersion, uint8 fromIndex, uint8 toIndex, bytes calldata encryptedPayload) external nonReentrant {
        _requireMaterialId(materialId, fileId, keyEpoch, shareVersion);
        _publishV2EncryptedShare(fileId, keyEpoch, shareVersion, fromIndex, toIndex, encryptedPayload);
    }

    function _publishV2EncryptedShare(bytes32 fileId, uint32 epoch, uint32 version, uint8 fromIndex, uint8 toIndex, bytes calldata payload) internal {
        bytes32 materialId = getMaterialAttemptId(fileId, epoch, version);
        require(payload.length == 32, ZkDkgV2_InvalidMaterial());
        (address recipient, uint8 n) = attemptController.validateEncryptedShare(materialId, msg.sender, fromIndex, toIndex, abi.decode(payload, (uint256)));
        V2EncryptedShare storage s = _encryptedShares[materialId][epoch][version][fromIndex][toIndex];
        require(!s.exists, ZkDkgV2_AlreadySubmitted());
        s.exists = true; s.dealer = msg.sender; s.recipient = recipient;
        s.fromIndex = fromIndex; s.toIndex = toIndex; s.encryptedPayload = payload;
        emit V2EncryptedSharePublished(materialId, fileId, epoch, version, fromIndex, toIndex, msg.sender, recipient);
        _recordDealerComplete(fileId, epoch, version, fromIndex, n);
    }
    function getV2EncryptedShare(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 fromIndex,
        uint8 toIndex
    ) external view returns (bool exists, address dealer, address recipient, bytes memory encryptedPayload) {
        V2EncryptedShare storage s = _encryptedShares[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][fromIndex][toIndex];
        return (s.exists, s.dealer, s.recipient, s.encryptedPayload);
    }

    function hasV2EncryptedShare(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 fromIndex,
        uint8 toIndex
    ) external view returns (bool) {
        return _encryptedShares[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][fromIndex][toIndex].exists;
    }

    function getV2SharePublicKey(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 shareIndex
    ) external view returns (bool exists, uint256 x, uint256 y) {
        SharePublicKey storage pk = _sharePublicKeys[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][shareIndex];
        return (pk.exists, pk.x, pk.y);
    }

    function getV2SharePublicKeyFull(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 shareIndex
    ) external view returns (bool exists, address guardian, uint8 storedShareIndex, uint256 x, uint256 y) {
        SharePublicKey storage pk = _sharePublicKeys[getMaterialAttemptId(fileId, keyEpoch, shareVersion)][keyEpoch][shareVersion][shareIndex];
        return (pk.exists, pk.guardian, pk.shareIndex, pk.x, pk.y);
    }

    function _requirePendingV2Refresh(bytes32 fileId, uint32 keyEpoch, uint32 shareVersion)
        internal view returns (V2RefreshRequest storage r)
    {
        r = _pendingRefresh[fileId][keyEpoch];
        require(r.exists && !r.finalized && !refreshSettled[fileId][keyEpoch], ZkDkgV2_NoPendingRefresh());
        require(r.shareVersion == shareVersion, ZkDkgV2_WrongVersion());
        attemptController.requireMaterialOpen(_refreshMaterialId[fileId][keyEpoch]);
    }
    function _isRefreshOldParticipant(V2RefreshRequest storage r, uint8 oldIndex) internal view returns (bool) {
        for (uint256 i = 0; i < r.oldParticipantIndices.length; i++) {
            if (r.oldParticipantIndices[i] == oldIndex) {
                return true;
            }
        }
        return false;
    }


    function _tryFinalizeV2Refresh(bytes32 fileId, uint32 keyEpoch, uint32 shareVersion) internal {
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        bytes32 materialId = _refreshMaterialId[fileId][keyEpoch];
        if (!r.exists || r.finalized || r.shareVersion != shareVersion || _contributors[materialId] != 0) return;
        uint32 selected;
        uint8 complete;
        for (uint256 i; i < r.oldParticipantIndices.length; ++i) {
            uint8 index = r.oldParticipantIndices[i];
            if ((_completedDealers[materialId] & (uint32(1) << (index - 1))) != 0
                && !disputeManager.isDealerExcluded(fileId, keyEpoch, shareVersion, true, index)) {
                selected |= uint32(1) << (index - 1);
                if (++complete == r.oldT) break;
            }
        }
        if (complete < r.oldT) return;
        _contributors[materialId] = selected;
        v2RefreshContributorMask[fileId][keyEpoch][shareVersion] = selected;
        attemptController.markMaterialsReady(materialId);
        emit RefreshMaterialsReady(materialId, fileId, keyEpoch, shareVersion, selected);
    }

    function finalizeV2RefreshForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint32 version) external nonReentrant {
        _requireMaterialId(materialId, fileId, keyEpoch, version);
        V2RefreshRequest storage r = _pendingRefresh[fileId][keyEpoch];
        V2Key storage k = _keys[fileId];
        require(msg.sender == k.dataOwner, ZkDkgV2_Unauthorized());
        require(r.exists && !r.finalized && !refreshSettled[fileId][keyEpoch] && r.shareVersion == version
            && k.shareVersion == r.oldShareVersion && _receivedShares[materialId] == _all(r.newN), ZkDkgV2_StaleRefresh());
        k.t = r.newT; k.n = r.newN; k.shareVersion = version;
        _activatedMaterialId[fileId][keyEpoch][version] = materialId;
        r.finalized = true;
        acl.activateV2FilePolicy(fileId, r.newT, keccak256(abi.encode(r.newGuardians)));
        attemptController.complete(materialId);
        emit ZkDkgV2SamePkRefreshFinalized(materialId, fileId, keyEpoch, version, r.newT, r.newN);
    }

    function _all(uint8 n) internal pure returns (uint32) { return uint32((uint256(1) << n) - 1); }

    function _recordDealerComplete(bytes32 fileId, uint32 epoch, uint32 version, uint8 index, uint8 receiverCount) internal {
        bytes32 materialId = getMaterialAttemptId(fileId, epoch, version);
        uint32 bit = uint32(1) << (index - 1);
        if ((_completedDealers[materialId] & bit) != 0 || !_dealerMaterialSubmitted[materialId][epoch][index]
            || !_dealerCommitments[materialId][epoch][version][index].exists) return;
        for (uint8 j = 1; j <= receiverCount; ++j) {
            if (version == 1 && j == index) continue;
            if (!_encryptedShares[materialId][epoch][version][index][j].exists) return;
        }
        _completedDealers[materialId] |= bit;
        if (version > 1) _tryFinalizeV2Refresh(fileId, epoch, version);
        else if (_completedDealers[materialId] == _all(receiverCount)) {
            _contributors[materialId] = _all(receiverCount);
            attemptController.markMaterialsReady(materialId);
        }
    }
    modifier onlyAclOwner() {
        require(msg.sender == acl.owner(), ZkDkgV2_NotACLOwner());
        _;
    }

    /// @dev Pays the early-network DKG reward to every Guardian of the finished DKG. The
    ///      reward call gets a fixed gas budget that is checked first: a reward swallowed by
    ///      the catch when gas runs short would let the sender's gas estimate settle just
    ///      below it and skip it forever. The catch only absorbs a reward that genuinely
    ///      fails, so the reward can never block a DKG.
    function _rewardGuardianWork(address[] memory guardians) private {
        address reward = guardianWorkReward;
        if (reward == address(0)) return;
        uint256 budget = GUARDIAN_WORK_REWARD_BASE_GAS + GUARDIAN_WORK_REWARD_GAS * guardians.length;
        if (gasleft() < budget + budget / 63 + 10_000) revert ZkDkgV2_Error();
        try IGuardianWorkReward_ZkDkgV2(reward).credit{gas: budget}(guardians, 0) {} catch {}
    }


    function _requireActiveStakedGuardian(address guardian) internal view {
        address registry = acl.guardianRegistry();
        if (registry != address(0)) {
            require(IGuardianRegistry_ZkDkgV2(registry).isActiveGuardian(guardian), ZkDkgV2_GuardianNotEligible());
        }
    }
}
