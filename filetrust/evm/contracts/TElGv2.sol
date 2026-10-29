// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: TElGv2
// Purpose:  Guardians turn a file's key over to an admitted reader without any one of
//           them ever seeing the key, each proving its part was honest.
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

error TElGv2_Error();

interface IAccessControlFT_TElGv2 {
    enum DkgMode {
        LEGACY,
        ZKDKG_V2
    }

    function getFilePolicy(bytes32 fileId)
        external
        view
        returns (bool exists, bool active, address dataOwner, uint8 threshold, address[] memory guardians);
    function getFilePolicyMode(bytes32 fileId) external view returns (DkgMode);
    function isGuardianForFile(bytes32 fileId, address guardian) external view returns (bool);
    function isRequesterForFile(bytes32 fileId, address requester) external view returns (bool);
    function hasRequestedReenc(address requester) external view returns (bool);
    function clearReencRequestForFileFromTElg(bytes32 fileId, address requester) external;
    function guardianRegistry() external view returns (address);
    function owner() external view returns (address);
}

interface IDataVault_TElGv2 {
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
    function getAccessRequestShareVersion(uint256 requestId) external view returns (uint32 shareVersion);
    function getAccessRequestTiming(uint256 requestId) external view returns (uint64, uint64, uint64);
    function getEncCid(uint256 index) external view returns (uint256, uint256, bytes memory, bytes memory);
    function getV2BatchC1(uint256 batchId) external view returns (bool exists, uint256 C1x, uint256 C1y);
}

interface IZkDkgCoordinatorV2_TElGv2 {
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
    function getV2SharePublicKey(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 shareIndex
    ) external view returns (bool exists, uint256 x, uint256 y);
}

interface IZkDkgDisputeManager_TElGv2 {
    function isDealerExcluded(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex
    ) external view returns (bool);
}

interface IReputationManager_TElGv2 {
    function recordPreSuccess(address guardian, uint256 speedScore) external;
    function recordPreFailure(address guardian, uint8 reasonCode) external;
    function recordPreReadyNotUsed(address guardian) external;
}

interface IGuardianRegistry_TElGv2 {
    function isActiveGuardian(address guardian) external view returns (bool);
}

interface IRewardManager_TElGv2 {
    function creditV2PreBatchPartial(bytes32 fileId, uint256 batchId, address guardian) external;
    function creditV2PreBatchPartialForRequest(uint256 requestId, address guardian) external;
    function ACTION_V2_PRE_BATCH_PARTIAL() external view returns (bytes32);
    function creditMeasuredAccessReward(uint256 requestId, address guardian, bytes32 actionType, uint256 measuredGas)
        external;
    function estimateRewardForAction(bytes32 actionType) external view returns (uint256);
    function hasV2AccessEscrow(uint256 requestId) external view returns (bool);
    function accessEscrowDeposited(uint256 requestId) external view returns (uint256);
    function isAccessEscrowComplete(uint256 requestId) external view returns (bool);
    function markAccessEscrowComplete(uint256 requestId) external;
    function calculatePreExpiryCompensation(uint256 requestId, uint8 inactiveAbsentCount) external view returns (uint256);
    function refundAccessEscrowForExpiry(uint256 requestId, address requester) external;
    function creditPreReadyNotUsed(uint256 requestId, address guardian) external;
}

interface IGuardianWorkReward_TElGv2 {
    function credit(address[] calldata guardians, uint8 kind) external;
}

interface IStakingManager_TElGv2 {
    function slashTo(address guardian, uint256 amount, address recipient) external;
}

interface IGuardianShareProof_TElGv2 {
    function lastProofAt(address guardian) external view returns (uint256);
}

struct V2PreG1Point {
    uint256 X;
    uint256 Y;
}

struct V2PreG2Point {
    uint256[2] X;
    uint256[2] Y;
}

struct V2PrePartialProof {
    V2PreG1Point a;
    V2PreG2Point b;
    V2PreG1Point c;
}

interface IV2PrePartialVerifier {
    // Public inputs order: [sharePubX, sharePubY, c1x, c1y, E1x, E1y, E2x, E2y, pkReqX, pkReqY, contextHash, 1]
    function verifyTx(V2PrePartialProof calldata proof, uint256[12] calldata input) external view returns (bool);
}

contract TElGv2 {
    struct V2AccessPartial {
        bool exists;
        address guardian;
        uint8 shareIndex;
        bytes32 partialsHash;
        uint256[] cidIndices;
        uint256[] E1x;
        uint256[] E1y;
        uint256[] E2x;
        uint256[] E2y;
    }

    struct V2PartialBatch {
        uint256[] cidIndices;
        uint256[] E1x;
        uint256[] E1y;
        uint256[] E2x;
        uint256[] E2y;
        V2PrePartialProof[] proofs;
    }

    struct V2BatchAccessPartial {
        bool exists;
        address guardian;
        uint8 shareIndex;
        uint256 E1x;
        uint256 E1y;
        uint256 E2x;
        uint256 E2y;
        bytes32 partialHash;
    }

    /// The fourteen values a per-cid DLEQ proof is bound to.
    ///
    /// A struct rather than fourteen arguments: carried on the stack they sit
    /// deeper than it reaches, and the compiler refuses the function. The
    /// order here is the order they are hashed in, and must stay the order the
    /// off-chain prover uses.
    struct DleqValues {
        uint256 requestId;
        uint32 shareVersion;
        uint8 shareIndex;
        uint256 cidIndex;
        uint256 c1x;
        uint256 c1y;
        uint256 shareX;
        uint256 shareY;
        uint256 e1x;
        uint256 e1y;
        uint256 e2x;
        uint256 e2y;
        uint256 pkReqX;
        uint256 pkReqY;
    }

    struct SubmitContext {
        bytes32 fileId;
        address requester;
        uint32 keyEpoch;
        uint32 shareVersion;
        uint8 threshold;
        uint8 participantCount;
        uint256 shareX;
        uint256 shareY;
        uint256[] requestIndices;
        uint256 batchId;
        uint256 pkReqX;
        uint256 pkReqY;
    }

    IAccessControlFT_TElGv2 public immutable acl;
    IDataVault_TElGv2 public immutable dataVault;
    IZkDkgCoordinatorV2_TElGv2 public coordinator;
    IZkDkgDisputeManager_TElGv2 public disputeManager;
    address public reputationManager;
    address public rewardManager;
    address public v2PrePartialVerifier;
    address public stakingManager;
    address public guardianShareProof;
    uint256 public maxInactivitySeconds = 26 hours;
    uint64 public preDeadline = 1 hours;

    uint256 private constant BABY_JUBJUB_FIELD_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    mapping(uint256 => mapping(address => V2AccessPartial)) private _partials;
    mapping(uint256 => mapping(address => V2BatchAccessPartial)) private _batchPartials;
    mapping(uint256 => address[]) private _partialGuardians;
    mapping(uint256 => mapping(uint8 => bool)) private _shareIndexUsed;
    mapping(uint256 => bool) private _preExpired;
    mapping(uint256 => mapping(address => bool)) private _declaredReady;
    mapping(uint256 => mapping(address => bool)) private _badPartialSubmitter;
    mapping(address => uint256) public preBadPartialCount;

    /// @notice Early-network reward pool paid for a used PRE part and for a PRE
    ///         ready-but-not-used; zero is off.
    address public guardianWorkReward;
    /// @notice Gas reserved for that reward inside a PRE transaction (measured with the real
    ///         registry: about 68k when a Guardian is paid for the first time).
    uint256 private constant GUARDIAN_WORK_REWARD_GAS = 100_000;

    event CoordinatorSet(address indexed coordinator);
    event DisputeManagerSet(address indexed disputeManager);
    event ReputationManagerSet(address indexed manager);
    event RewardManagerSet(address indexed manager);
    event GuardianWorkRewardSet(address indexed reward);
    event V2PrePartialVerifierSet(address indexed verifier);
    event StakingManagerSet(address indexed stakingManager);
    event GuardianShareProofSet(address indexed guardianShareProof);
    event MaxInactivitySecondsSet(uint256 maxInactivitySeconds);
    event PreDeadlineSet(uint64 deadline);
    event PreRequestExpired(uint256 indexed requestId, bytes32 indexed fileId, address indexed requester, uint8 absentCount);
    event PreReadyDeclared(uint256 indexed requestId, bytes32 indexed fileId, address indexed guardian);
    event PreBadPartialDetected(uint256 indexed requestId, bytes32 indexed fileId, address indexed guardian, uint8 shareIndex);
    event V2AccessPartialSubmitted(
        bytes32 indexed fileId,
        uint256 indexed requestId,
        address indexed guardian,
        uint8 shareIndex,
        uint256 count,
        bytes32 partialsHash
    );
    event V2BatchAccessPartialSubmitted(
        bytes32 indexed fileId,
        uint256 indexed requestId,
        uint256 indexed batchId,
        address guardian,
        uint8 shareIndex,
        uint256 E1x,
        uint256 E1y,
        uint256 E2x,
        uint256 E2y,
        bytes32 partialHash
    );

    constructor(
        address aclAddress,
        address dataVaultAddress,
        address coordinatorAddress,
        address disputeManagerAddress
    ) {
        if (aclAddress == address(0) || dataVaultAddress == address(0)) revert TElGv2_Error();
        acl = IAccessControlFT_TElGv2(aclAddress);
        dataVault = IDataVault_TElGv2(dataVaultAddress);
        if (coordinatorAddress != address(0)) {
            coordinator = IZkDkgCoordinatorV2_TElGv2(coordinatorAddress);
        }
        if (disputeManagerAddress != address(0)) {
            disputeManager = IZkDkgDisputeManager_TElGv2(disputeManagerAddress);
        }
    }

    function setCoordinator(address coordinatorAddress) external onlyAclOwner {
        if (coordinatorAddress == address(0)) revert TElGv2_Error();
        coordinator = IZkDkgCoordinatorV2_TElGv2(coordinatorAddress);
        emit CoordinatorSet(coordinatorAddress);
    }

    function setDisputeManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert TElGv2_Error();
        disputeManager = IZkDkgDisputeManager_TElGv2(manager);
        emit DisputeManagerSet(manager);
    }

    function setReputationManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert TElGv2_Error();
        reputationManager = manager;
        emit ReputationManagerSet(manager);
    }

    function setRewardManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert TElGv2_Error();
        rewardManager = manager;
        emit RewardManagerSet(manager);
    }

    function setGuardianWorkReward(address reward) external onlyAclOwner {
        guardianWorkReward = reward;
        emit GuardianWorkRewardSet(reward);
    }

    /// @notice Bound once (Phase 2, D8): keys are replaced through the FileTrustVerifierRouter
    ///         this names, with a bounded transition window.
    function setV2PrePartialVerifier(address verifier) external onlyAclOwner {
        if (verifier == address(0) || v2PrePartialVerifier != address(0)) revert TElGv2_Error();
        v2PrePartialVerifier = verifier;
        emit V2PrePartialVerifierSet(verifier);
    }

    function setStakingManager(address manager) external onlyAclOwner {
        stakingManager = manager;
        emit StakingManagerSet(manager);
    }

    function setGuardianShareProof(address _guardianShareProof) external onlyAclOwner {
        guardianShareProof = _guardianShareProof;
        emit GuardianShareProofSet(_guardianShareProof);
    }

    function setMaxInactivitySeconds(uint256 _maxInactivitySeconds) external onlyAclOwner {
        require(_maxInactivitySeconds > 0, "TElGv2: zero inactivity window");
        maxInactivitySeconds = _maxInactivitySeconds;
        emit MaxInactivitySecondsSet(_maxInactivitySeconds);
    }

    function setPreDeadline(uint64 duration) external onlyAclOwner {
        require(duration > 0, "TElGv2: zero deadline");
        preDeadline = duration;
        emit PreDeadlineSet(duration);
    }

    function submitV2AccessPartial(
        uint256 requestId,
        uint8 shareIndex,
        V2PartialBatch calldata batch
    ) external {
        uint256 startGas = gasleft();
        if (
            address(coordinator) == address(0) ||
            address(disputeManager) == address(0) ||
            v2PrePartialVerifier == address(0)
        ) revert TElGv2_Error();
        if (
            shareIndex == 0 ||
            batch.cidIndices.length == 0 ||
            batch.cidIndices.length != batch.E1x.length ||
            batch.cidIndices.length != batch.E1y.length ||
            batch.cidIndices.length != batch.E2x.length ||
            batch.cidIndices.length != batch.E2y.length
        ) {
            revert TElGv2_Error();
        }
        require(batch.proofs.length == batch.cidIndices.length, "TElGv2: proof length mismatch");

        require(!_preExpired[requestId], "TElGv2: request expired");
        SubmitContext memory ctx = _loadSubmitContext(requestId, shareIndex);
        require(acl.getFilePolicyMode(ctx.fileId) == IAccessControlFT_TElGv2.DkgMode.ZKDKG_V2, "TElGv2: wrong mode");
        require(acl.isGuardianForFile(ctx.fileId, msg.sender), "TElGv2: not guardian");
        _requireActiveStakedGuardian(msg.sender);
        require(acl.isRequesterForFile(ctx.fileId, ctx.requester), "TElGv2: requester not allowed");
        require(acl.hasRequestedReenc(ctx.requester), "TElGv2: no request");
        require(!_partials[requestId][msg.sender].exists, "TElGv2: duplicate guardian");
        require(!_shareIndexUsed[requestId][shareIndex], "TElGv2: duplicate share index");
        require(batch.cidIndices.length == ctx.requestIndices.length, "TElGv2: incomplete partial");
        require(shareIndex <= ctx.participantCount, "TElGv2: bad share index");
        (bool batchC1Exists, , ) = dataVault.getV2BatchC1(ctx.batchId);
        require(!batchC1Exists, "TElGv2: use batch partial");
        require(
            !disputeManager.isDealerExcluded(ctx.fileId, ctx.keyEpoch, ctx.shareVersion, false, shareIndex),
            "TElGv2: excluded guardian"
        );
        require(_partialGuardians[requestId].length < ctx.threshold, "TElGv2: threshold reached");
        if (rewardManager != address(0)) {
            require(IRewardManager_TElGv2(rewardManager).hasV2AccessEscrow(requestId), "TElGv2: missing access escrow");
        }

        if (!_verifyAllPartials(ctx, requestId, shareIndex, batch)) {
            _badPartialSubmitter[requestId][msg.sender] = true;
            preBadPartialCount[msg.sender]++;
            emit PreBadPartialDetected(requestId, ctx.fileId, msg.sender, shareIndex);
            revert("TElGv2: invalid partial proof");
        }

        V2AccessPartial storage p = _partials[requestId][msg.sender];
        p.exists = true;
        p.guardian = msg.sender;
        p.shareIndex = shareIndex;
        p.partialsHash = keccak256(abi.encode(requestId, shareIndex, batch.cidIndices, batch.E1x, batch.E1y, batch.E2x, batch.E2y));
        for (uint256 i = 0; i < batch.cidIndices.length; i++) {
            p.cidIndices.push(batch.cidIndices[i]);
            p.E1x.push(batch.E1x[i]);
            p.E1y.push(batch.E1y[i]);
            p.E2x.push(batch.E2x[i]);
            p.E2y.push(batch.E2y[i]);
        }

        _partialGuardians[requestId].push(msg.sender);
        _shareIndexUsed[requestId][shareIndex] = true;

        if (reputationManager != address(0)) {
            try IReputationManager_TElGv2(reputationManager).recordPreSuccess(msg.sender, 0) {
            } catch {
            }
        }
        if (rewardManager != address(0)) {
            IRewardManager_TElGv2 rm = IRewardManager_TElGv2(rewardManager);
            rm.creditMeasuredAccessReward(requestId, msg.sender, rm.ACTION_V2_PRE_BATCH_PARTIAL(), startGas - gasleft());
            if (_partialGuardians[requestId].length >= ctx.threshold) {
                rm.markAccessEscrowComplete(requestId);
            }
        }
        _rewardGuardianWork(1);

        emit V2AccessPartialSubmitted(ctx.fileId, requestId, msg.sender, shareIndex, batch.cidIndices.length, p.partialsHash);
    }

    function submitV2BatchAccessPartial(
        uint256 requestId,
        uint8 shareIndex,
        uint256 e1x,
        uint256 e1y,
        uint256 e2x,
        uint256 e2y,
        V2PrePartialProof calldata proof
    ) external {
        uint256 startGas = gasleft();
        if (
            address(coordinator) == address(0) ||
            address(disputeManager) == address(0) ||
            v2PrePartialVerifier == address(0)
        ) revert TElGv2_Error();
        if (shareIndex == 0) revert TElGv2_Error();

        require(!_preExpired[requestId], "TElGv2: request expired");
        SubmitContext memory ctx = _loadSubmitContext(requestId, shareIndex);
        require(acl.getFilePolicyMode(ctx.fileId) == IAccessControlFT_TElGv2.DkgMode.ZKDKG_V2, "TElGv2: wrong mode");
        require(acl.isGuardianForFile(ctx.fileId, msg.sender), "TElGv2: not guardian");
        _requireActiveStakedGuardian(msg.sender);
        require(acl.isRequesterForFile(ctx.fileId, ctx.requester), "TElGv2: requester not allowed");
        require(acl.hasRequestedReenc(ctx.requester), "TElGv2: no request");
        require(!_partials[requestId][msg.sender].exists, "TElGv2: duplicate guardian");
        require(!_shareIndexUsed[requestId][shareIndex], "TElGv2: duplicate share index");
        require(shareIndex <= ctx.participantCount, "TElGv2: bad share index");
        require(
            !disputeManager.isDealerExcluded(ctx.fileId, ctx.keyEpoch, ctx.shareVersion, false, shareIndex),
            "TElGv2: excluded guardian"
        );
        require(_partialGuardians[requestId].length < ctx.threshold, "TElGv2: threshold reached");
        if (rewardManager != address(0)) {
            require(IRewardManager_TElGv2(rewardManager).hasV2AccessEscrow(requestId), "TElGv2: missing access escrow");
        }

        (bool batchC1Exists, uint256 batchC1x, uint256 batchC1y) = dataVault.getV2BatchC1(ctx.batchId);
        require(batchC1Exists, "TElGv2: missing batch C1");

        if (!_verifyBatchDleq(
            ctx,
            requestId,
            shareIndex,
            batchC1x,
            batchC1y,
            e1x, e1y, e2x, e2y,
            proof
        )) {
            _badPartialSubmitter[requestId][msg.sender] = true;
            preBadPartialCount[msg.sender]++;
            emit PreBadPartialDetected(requestId, ctx.fileId, msg.sender, shareIndex);
            revert("TElGv2: invalid batch partial proof");
        }

        bytes32 partialHash = keccak256(abi.encode(requestId, ctx.batchId, shareIndex, batchC1x, batchC1y, e1x, e1y, e2x, e2y));
        V2BatchAccessPartial storage bp = _batchPartials[requestId][msg.sender];
        bp.exists = true;
        bp.guardian = msg.sender;
        bp.shareIndex = shareIndex;
        bp.E1x = e1x;
        bp.E1y = e1y;
        bp.E2x = e2x;
        bp.E2y = e2y;
        bp.partialHash = partialHash;

        V2AccessPartial storage p = _partials[requestId][msg.sender];
        p.exists = true;
        p.guardian = msg.sender;
        p.shareIndex = shareIndex;

        _partialGuardians[requestId].push(msg.sender);
        _shareIndexUsed[requestId][shareIndex] = true;

        if (reputationManager != address(0)) {
            try IReputationManager_TElGv2(reputationManager).recordPreSuccess(msg.sender, 0) {
            } catch {
            }
        }
        if (rewardManager != address(0)) {
            IRewardManager_TElGv2 rm = IRewardManager_TElGv2(rewardManager);
            rm.creditMeasuredAccessReward(requestId, msg.sender, rm.ACTION_V2_PRE_BATCH_PARTIAL(), startGas - gasleft());
            if (_partialGuardians[requestId].length >= ctx.threshold) {
                rm.markAccessEscrowComplete(requestId);
            }
        }
        _rewardGuardianWork(1);

        emit V2BatchAccessPartialSubmitted(ctx.fileId, requestId, ctx.batchId, msg.sender, shareIndex, e1x, e1y, e2x, e2y, partialHash);
        emit V2AccessPartialSubmitted(ctx.fileId, requestId, msg.sender, shareIndex, ctx.requestIndices.length, partialHash);
    }

    function getV2Partial(uint256 requestId, address guardian)
        external
        view
        returns (
            bool exists,
            uint8 shareIndex,
            bytes32 partialsHash,
            uint256[] memory cidIndices,
            uint256[] memory E1x,
            uint256[] memory E1y,
            uint256[] memory E2x,
            uint256[] memory E2y
        )
    {
        V2AccessPartial storage p = _partials[requestId][guardian];
        return (p.exists, p.shareIndex, p.partialsHash, p.cidIndices, p.E1x, p.E1y, p.E2x, p.E2y);
    }

    function getV2PartialGuardians(uint256 requestId) external view returns (address[] memory) {
        return _partialGuardians[requestId];
    }

    function getV2BatchPartial(uint256 requestId, address guardian)
        external
        view
        returns (bool exists, uint8 shareIndex, bytes32 partialHash, uint256 E1x, uint256 E1y, uint256 E2x, uint256 E2y)
    {
        V2BatchAccessPartial storage p = _batchPartials[requestId][guardian];
        return (p.exists, p.shareIndex, p.partialHash, p.E1x, p.E1y, p.E2x, p.E2y);
    }

    function computeV2DleqChallenge(
        uint256 requestId,
        uint32 shareVersion,
        uint8 shareIndex,
        uint256 cidIndex,
        uint256 c1x,
        uint256 c1y,
        uint256 shareX,
        uint256 shareY,
        uint256 e1x,
        uint256 e1y,
        uint256 e2x,
        uint256 e2y,
        uint256 pkReqX,
        uint256 pkReqY
    ) external pure returns (uint256) {
        return _computeDleqChallenge(
            requestId, shareVersion, shareIndex, cidIndex,
            c1x, c1y, shareX, shareY,
            e1x, e1y, e2x, e2y, pkReqX, pkReqY
        );
    }

    function _loadSubmitContext(uint256 requestId, uint8 shareIndex)
        internal
        view
        returns (SubmitContext memory ctx)
    {
        bool reqExists;
        (
            reqExists,
            ctx.fileId,
            ctx.requester,
            ctx.batchId,
            ,
            ,
            ctx.keyEpoch,
            ctx.pkReqX,
            ctx.pkReqY,
            ctx.requestIndices
        ) = dataVault.getAccessRequest(requestId);
        require(reqExists, "TElGv2: unknown request");

        _requirePreWindow(requestId);

        bool keyExists;
        bool finalized;
        uint32 keyEpochV2;
        (
            keyExists,
            finalized,
            ,
            ctx.threshold,
            ctx.participantCount,
            keyEpochV2,
            ctx.shareVersion,
            ,
        ) = coordinator.getV2Key(ctx.fileId);
        require(keyExists && finalized, "TElGv2: V2 key not finalized");
        require(ctx.keyEpoch == keyEpochV2, "TElGv2: wrong epoch");

        bool sharePkExists;
        (sharePkExists, ctx.shareX, ctx.shareY) =
            coordinator.getV2SharePublicKey(ctx.fileId, ctx.keyEpoch, ctx.shareVersion, shareIndex);
        require(sharePkExists, "TElGv2: missing share public key");
    }

    function _verifyAllPartials(
        SubmitContext memory ctx,
        uint256 requestId,
        uint8 shareIndex,
        V2PartialBatch calldata batch
    ) internal view returns (bool) {
        for (uint256 i = 0; i < batch.cidIndices.length; i++) {
            if (!_verifyPartialAt(ctx, requestId, shareIndex, batch, i)) return false;
        }
        return true;
    }

    /// One entry of the batch, in a frame of its own, with its fourteen DLEQ
    /// values gathered in memory rather than on the stack.
    ///
    /// Done inline, this is the loop's own state plus fourteen values live at
    /// once, which is deeper than the stack reaches: solc 0.8.37 stops with
    /// "variable is 1 too deep in the stack" even through the IR pipeline. The
    /// values are the same ones, written one at a time into a struct, so the
    /// challenge and the verifier input are unchanged.
    function _verifyPartialAt(
        SubmitContext memory ctx,
        uint256 requestId,
        uint8 shareIndex,
        V2PartialBatch calldata batch,
        uint256 i
    ) private view returns (bool) {
        uint256 cidIndex = batch.cidIndices[i];
        require(cidIndex == ctx.requestIndices[i], "TElGv2: wrong cid index");

        DleqValues memory d;
        d.requestId = requestId;
        d.shareVersion = ctx.shareVersion;
        d.shareIndex = shareIndex;
        d.cidIndex = cidIndex;
        (d.c1x, d.c1y, , ) = dataVault.getEncCid(cidIndex);
        d.shareX = ctx.shareX;
        d.shareY = ctx.shareY;
        d.e1x = batch.E1x[i];
        d.e1y = batch.E1y[i];
        d.e2x = batch.E2x[i];
        d.e2y = batch.E2y[i];
        d.pkReqX = ctx.pkReqX;
        d.pkReqY = ctx.pkReqY;

        return _verifyDleq(d, batch.proofs[i]);
    }

    function _verifyDleq(DleqValues memory d, V2PrePartialProof calldata proof)
        internal
        view
        returns (bool)
    {
        uint256[12] memory input = [
            d.shareX, d.shareY, d.c1x, d.c1y,
            d.e1x, d.e1y, d.e2x, d.e2y,
            d.pkReqX, d.pkReqY,
            _dleqChallenge(d), uint256(1)
        ];
        return IV2PrePartialVerifier(v2PrePartialVerifier).verifyTx(proof, input);
    }

    function _verifyBatchDleq(
        SubmitContext memory ctx,
        uint256 requestId,
        uint8 shareIndex,
        uint256 batchC1x,
        uint256 batchC1y,
        uint256 e1x,
        uint256 e1y,
        uint256 e2x,
        uint256 e2y,
        V2PrePartialProof calldata proof
    ) internal view returns (bool) {
        uint256 contextHash = _computeBatchDleqChallenge(
            requestId,
            ctx.batchId,
            ctx.fileId,
            ctx.keyEpoch,
            ctx.shareVersion,
            shareIndex,
            batchC1x,
            batchC1y,
            ctx.shareX,
            ctx.shareY,
            e1x, e1y, e2x, e2y,
            ctx.pkReqX, ctx.pkReqY
        );
        uint256[12] memory input = [
            ctx.shareX, ctx.shareY,
            batchC1x, batchC1y,
            e1x, e1y,
            e2x, e2y,
            ctx.pkReqX, ctx.pkReqY,
            contextHash, uint256(1)
        ];
        return IV2PrePartialVerifier(v2PrePartialVerifier).verifyTx(proof, input);
    }

    function _computeDleqChallenge(
        uint256 requestId,
        uint32 shareVersion,
        uint8 shareIndex,
        uint256 cidIndex,
        uint256 c1x,
        uint256 c1y,
        uint256 shareX,
        uint256 shareY,
        uint256 e1x,
        uint256 e1y,
        uint256 e2x,
        uint256 e2y,
        uint256 pkReqX,
        uint256 pkReqY
    ) internal pure returns (uint256) {
        DleqValues memory d;
        d.requestId = requestId;
        d.shareVersion = shareVersion;
        d.shareIndex = shareIndex;
        d.cidIndex = cidIndex;
        d.c1x = c1x;
        d.c1y = c1y;
        d.shareX = shareX;
        d.shareY = shareY;
        d.e1x = e1x;
        d.e1y = e1y;
        d.e2x = e2x;
        d.e2y = e2y;
        d.pkReqX = pkReqX;
        d.pkReqY = pkReqY;
        return _dleqChallenge(d);
    }

    /// The challenge, over exactly the fourteen values in the order the
    /// off-chain prover hashes them. The one place it is computed.
    function _dleqChallenge(DleqValues memory d) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(
            d.requestId, d.shareVersion, d.shareIndex, d.cidIndex,
            d.c1x, d.c1y, d.shareX, d.shareY,
            d.e1x, d.e1y, d.e2x, d.e2y,
            d.pkReqX, d.pkReqY
        ))) % BABY_JUBJUB_FIELD_ORDER;
    }

    function computeV2BatchDleqChallenge(
        uint256 requestId,
        uint256 batchId,
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 shareIndex,
        uint256 batchC1x,
        uint256 batchC1y,
        uint256 shareX,
        uint256 shareY,
        uint256 e1x,
        uint256 e1y,
        uint256 e2x,
        uint256 e2y,
        uint256 pkReqX,
        uint256 pkReqY
    ) external pure returns (uint256) {
        return _computeBatchDleqChallenge(
            requestId, batchId, fileId, keyEpoch, shareVersion, shareIndex,
            batchC1x, batchC1y, shareX, shareY,
            e1x, e1y, e2x, e2y, pkReqX, pkReqY
        );
    }

    function _computeBatchDleqChallenge(
        uint256 requestId,
        uint256 batchId,
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint8 shareIndex,
        uint256 batchC1x,
        uint256 batchC1y,
        uint256 shareX,
        uint256 shareY,
        uint256 e1x,
        uint256 e1y,
        uint256 e2x,
        uint256 e2y,
        uint256 pkReqX,
        uint256 pkReqY
    ) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(
            requestId, batchId, fileId, keyEpoch, shareVersion, shareIndex,
            batchC1x, batchC1y, shareX, shareY,
            e1x, e1y, e2x, e2y, pkReqX, pkReqY
        ))) % BABY_JUBJUB_FIELD_ORDER;
    }

    function expirePreRequest(uint256 requestId) external {
        require(!_preExpired[requestId], "TElGv2: already expired");

        (bool reqExists, bytes32 fileId, address requester, , , , , , , ) =
            dataVault.getAccessRequest(requestId);
        require(reqExists, "TElGv2: unknown request");
        (, uint64 admittedAt, uint64 deadline) = dataVault.getAccessRequestTiming(requestId);
        require(block.timestamp > deadline, "TElGv2: deadline not passed");

        (, , , uint8 threshold, address[] memory guardians) = acl.getFilePolicy(fileId);
        require(_partialGuardians[requestId].length < uint256(threshold), "TElGv2: threshold met");

        _preExpired[requestId] = true;

        // The deposit path admits an obligation only after the authorized
        // requester has supplied the full required escrow. Use its persistent
        // deposit record, not the remaining balance after legitimate rewards.
        bool funded = admittedAt != 0 && rewardManager != address(0) &&
            IRewardManager_TElGv2(rewardManager).accessEscrowDeposited(requestId) > 0 &&
            !IRewardManager_TElGv2(rewardManager).isAccessEscrowComplete(requestId) &&
            acl.isRequesterForFile(fileId, requester) && acl.hasRequestedReenc(requester);
        // Clear before any compensation/refund callback can open a new request.
        try acl.clearReencRequestForFileFromTElg(fileId, requester) {} catch {}
        if (rewardManager != address(0)) {
            IRewardManager_TElGv2(rewardManager).markAccessEscrowComplete(requestId);
        }

        uint8 n = uint8(guardians.length);
        address[] memory inactiveGs = new address[](n);
        uint8 absentCount = 0;
        uint8 inactiveCount = 0;

        for (uint8 i = 0; funded && i < n; i++) {
            address g = guardians[i];
            if (!_partials[requestId][g].exists) {
                absentCount++;
                if (reputationManager != address(0)) {
                    try IReputationManager_TElGv2(reputationManager).recordPreFailure(g, 0) {} catch {}
                }
                if (!_isGuardianActive(g) || _badPartialSubmitter[requestId][g]) {
                    inactiveGs[inactiveCount] = g;
                    inactiveCount++;
                }
            }
        }

        if (inactiveCount > 0 && stakingManager != address(0) && rewardManager != address(0)) {
            uint256 perG = IRewardManager_TElGv2(rewardManager).calculatePreExpiryCompensation(
                requestId, inactiveCount
            );
            if (perG > 0) {
                IStakingManager_TElGv2 sm = IStakingManager_TElGv2(stakingManager);
                for (uint8 j = 0; j < inactiveCount; j++) {
                    try sm.slashTo(inactiveGs[j], perG, requester) {} catch {}
                }
            }
        }

        if (rewardManager != address(0)) {
            // Not in try/catch: a refund that failed here would leave the request expired
            // and the requester's escrow behind for good, since nothing else returns it.
            // Reverting instead lets the expiry be sent again. RewardManager never refuses
            // for the requester's sake: a payment the requester's wallet refuses becomes a
            // claim.
            IRewardManager_TElGv2(rewardManager).refundAccessEscrowForExpiry(requestId, requester);
        }

        emit PreRequestExpired(requestId, fileId, requester, absentCount);
    }

    function declareReadyForRequest(uint256 requestId) external {
        require(!_preExpired[requestId], "TElGv2: request expired");
        require(!_declaredReady[requestId][msg.sender], "TElGv2: already declared");

        (bool reqExists, bytes32 fileId, , , , , , , , ) = dataVault.getAccessRequest(requestId);
        require(reqExists, "TElGv2: unknown request");
        _requirePreWindow(requestId);

        (, , , uint8 threshold, ) = acl.getFilePolicy(fileId);
        require(_partialGuardians[requestId].length >= uint256(threshold), "TElGv2: threshold not met");

        require(acl.isGuardianForFile(fileId, msg.sender), "TElGv2: not guardian");
        require(!_partials[requestId][msg.sender].exists, "TElGv2: already submitted");

        _declaredReady[requestId][msg.sender] = true;

        if (reputationManager != address(0)) {
            try IReputationManager_TElGv2(reputationManager).recordPreReadyNotUsed(msg.sender) {} catch {}
        }
        if (rewardManager != address(0)) {
            try IRewardManager_TElGv2(rewardManager).creditPreReadyNotUsed(requestId, msg.sender) {} catch {}
        }
        _rewardGuardianWork(2);

        emit PreReadyDeclared(requestId, fileId, msg.sender);
    }

    function isBadPartialSubmitter(uint256 requestId, address guardian) external view returns (bool) {
        return _badPartialSubmitter[requestId][guardian];
    }

    function _requirePreWindow(uint256 requestId) private view {
        (, uint64 admittedAt, uint64 deadline) = dataVault.getAccessRequestTiming(requestId);
        require(admittedAt != 0, "TElGv2: missing access escrow");
        require(block.timestamp <= deadline, "TElGv2: window closed");
    }

    modifier onlyAclOwner() {
        require(msg.sender == acl.owner(), "TElGv2: not ACL owner");
        _;
    }

    /// @dev Pays the sender the early-network PRE reward: kind 1 for a used PRE part, kind 2
    ///      for ready-but-not-used. The reward call gets a fixed gas budget that is checked
    ///      first: a reward swallowed by the catch when gas runs short would let the sender's
    ///      gas estimate settle just below it and skip it forever. The catch only absorbs a
    ///      reward that genuinely fails, so the reward can never block a PRE.
    function _rewardGuardianWork(uint8 kind) private {
        address reward = guardianWorkReward;
        if (reward == address(0)) return;
        if (gasleft() < GUARDIAN_WORK_REWARD_GAS + GUARDIAN_WORK_REWARD_GAS / 63 + 10_000) revert TElGv2_Error();
        address[] memory guardian = new address[](1);
        guardian[0] = msg.sender;
        try IGuardianWorkReward_TElGv2(reward).credit{gas: GUARDIAN_WORK_REWARD_GAS}(guardian, kind) {} catch {}
    }

    function _isGuardianActive(address guardian) internal view returns (bool) {
        if (guardianShareProof == address(0)) {
            return false;
        }
        try IGuardianShareProof_TElGv2(guardianShareProof).lastProofAt(guardian) returns (uint256 lastProof) {
            return lastProof > 0 && block.timestamp - lastProof <= maxInactivitySeconds;
        } catch {
            return false;
        }
    }

    function _requireActiveStakedGuardian(address guardian) internal view {
        address registry = acl.guardianRegistry();
        if (registry != address(0)) {
            require(IGuardianRegistry_TElGv2(registry).isActiveGuardian(guardian), "TElGv2: guardian not eligible");
        }
    }
}
