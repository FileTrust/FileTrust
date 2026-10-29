// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: ZkDkgDisputeManager
// Purpose:  Excluding a dealer whose share has been proven wrong, without stopping
//           the Guardians who dealt honestly.
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

import "./DkgAttemptTypes.sol";
import "./BabyJubjub.sol";
import "./BabyJubjubProjective.sol";

error ZkDkgDispute_Error();

interface IAccessControlFT_ZkDkg {
    function getFilePolicy(bytes32 fileId)
        external
        view
        returns (bool exists, bool active, address dataOwner, uint8 threshold, address[] memory guardians);
    function getDkgFilePolicy(bytes32 fileId) external view returns (bool, bool, address, uint8, address[] memory);
    function isGuardianForFile(bytes32 fileId, address guardian) external view returns (bool);
    function owner() external view returns (address);
    function guardianRegistry() external view returns (address);
}

interface IDKG_ZkDkg {
    function getMaterialAttemptId(bytes32 fileId, uint32 keyEpoch, uint32 shareVersion) external view returns (bytes32);
    function validateMaterialAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint32 shareVersion) external view;
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
        );
}

interface IGuardianRegistry_ZkDkg {
    function getGuardianDkgBabyJubjubPublicKey(address guardian) external view returns (uint256 x, uint256 y);
    function isActiveGuardian(address guardian) external view returns (bool);
}

interface IReputationManager_ZkDkg {
    function recordDkgFailure(address guardian, uint8 reasonCode) external;
    function recordVerifiedDkgComplaint(address guardian, address reporter, uint8 reasonCode) external;
}

interface IZkDkgCoordinatorV2_Acknowledge {
    function acknowledgeDealerMaterialForAttempt(bytes32 materialId, bytes32 fileId, uint32 keyEpoch, uint8 dealerIndex, address dealer)
        external;
    function acknowledgeRefreshDealerMaterialForAttempt(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version, uint8 index, address dealer) external;
}

interface IRewardManager_ZkDkg {
    function creditV2DkgMaterial(bytes32 fileId, address guardian) external;
    function ACTION_V2_DKG_MATERIAL() external view returns (bytes32);
    function creditMeasuredPolicyReward(bytes32 fileId, address guardian, bytes32 actionType, uint256 measuredGas)
        external;
    function fixedGasPriceWei() external view returns (uint256);
    function estimatedGasKeyGenRequest() external view returns (uint256);
}

struct ZkDkgG1Point {
    uint256 X;
    uint256 Y;
}

struct ZkDkgG2Point {
    uint256[2] X;
    uint256[2] Y;
}

struct ZkDkgShareProof {
    ZkDkgG1Point a;
    ZkDkgG2Point b;
    ZkDkgG1Point c;
}

interface IZkDkgShareVerifier {
    function verifyTx(ZkDkgShareProof calldata proof, uint256[2] calldata input) external view returns (bool);
}

interface IStakingManager_ZkDkg {
    function slashTo(address guardian, uint256 amount, address recipient) external;
}

contract ZkDkgDisputeManager {
    struct BabyJubjubBatch {
        bool exists;
        bool isRefresh;
        address dealer;
        uint8 dealerIndex;
        bytes32 commitmentHash;
        bytes32 encryptedShareHash;
        uint256 firstCoefficient;
        uint256[] encryptedShares;
        address verifier;
    }

    struct EncryptedShareDispute {
        bool exists;
        bool resolved;
        bool dealerJustified;
        bool isRefresh;
        bytes32 fileId;
        uint32 keyEpoch;
        uint32 shareVersion;
        uint8 dealerIndex;
        uint8 receiverIndex;
        address dealer;
        address receiver;
        uint64 openedAt;
        uint64 deadline;
        uint256 encryptedShare;
        uint256 receiverGasCost;
        bytes32 materialId;
        address verifier;
    }

    uint256 private constant BABY_JUBJUB_FIELD_ORDER =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IAccessControlFT_ZkDkg public immutable acl;
    IDKG_ZkDkg public dkg;
    address public reputationManager;
    address public rewardManager;
    address public zkDkgShareVerifier;
    address public zkDkgCoordinatorV2;
    address public stakingManager;
    uint64 public zkDkgDisputePeriod = 1 days;
    mapping(uint8 => address) public zkDkgShareVerifierByParticipantCount;
    mapping(uint8 => mapping(uint8 => address)) public zkDkgShareVerifierByCommittee;

    mapping(bytes32 => mapping(uint32 => mapping(uint32 => mapping(bool => mapping(uint8 => BabyJubjubBatch)))))
        private _batches;
    mapping(bytes32 => EncryptedShareDispute) private _disputes;
    mapping(bytes32 => bool) private _excludedDealer;
    mapping(bytes32 => bool) private _doCompensatedForRound;
    mapping(bytes32 => mapping(address => uint256[2])) private _encryptionKeys;
    mapping(bytes32 => mapping(address => uint256[2])) private _receiverKeys;
    mapping(bytes32 => bool) public validatedEncryptionKeys;
    mapping(bytes32 => address) private _materialVerifier;
    mapping(bytes32 => uint64) public materialDisputePeriod;
    mapping(bytes32 => uint256) public pendingDisputes;
    mapping(bytes32 => uint32) public excludedDealers;
    mapping(bytes32 => mapping(address => uint256)) public pendingReceiverDisputes;

    event DkgContractSet(address indexed dkg);
    event ZkDkgCoordinatorV2Set(address indexed coordinator);
    event ReputationManagerSet(address indexed manager);
    event RewardManagerSet(address indexed manager);
    event ZkDkgShareVerifierSet(address indexed verifier);
    event ZkDkgShareVerifierForParticipantCountSet(uint8 indexed participantCount, address indexed verifier);
    event ZkDkgShareVerifierForCommitteeSet(
        uint8 indexed participantCount,
        uint8 indexed threshold,
        address indexed verifier
    );
    event StakingManagerSet(address indexed manager);
    event ZkDkgDisputePeriodSet(uint64 period);
    event ZkDkgBabyJubjubMaterialPublished(
        bytes32 materialId,
        bytes32 indexed fileId,
        uint32 indexed keyEpoch,
        uint32 indexed shareVersion,
        bool isRefresh,
        address dealer,
        uint8 dealerIndex,
        bytes32 commitmentHash,
        bytes32 encryptedShareHash
    );
    event ZkDkgEncryptedShareDisputeOpened(
        bytes32 indexed disputeId,
        bytes32 indexed fileId,
        uint32 indexed keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        address receiver,
        address dealer,
        uint8 receiverIndex,
        uint8 dealerIndex,
        uint64 deadline
    );
    event ZkDkgEncryptedShareDisputeJustified(
        bytes32 indexed disputeId,
        address indexed dealer,
        address indexed receiver
    );
    event ZkDkgEncryptedShareDisputeExpired(
        bytes32 indexed disputeId,
        address indexed dealer,
        address indexed receiver
    );
    event ZkDkgDealerExcluded(
        bytes32 indexed fileId,
        uint32 indexed keyEpoch,
        uint32 indexed shareVersion,
        bool isRefresh,
        address dealer,
        uint8 dealerIndex
    );

    constructor(address aclAddress, address dkgAddress, address verifierAddress) {
        if (aclAddress == address(0)) revert ZkDkgDispute_Error();
        acl = IAccessControlFT_ZkDkg(aclAddress);
        if (dkgAddress != address(0)) {
            dkg = IDKG_ZkDkg(dkgAddress);
        }
        if (verifierAddress != address(0)) {
            zkDkgShareVerifier = verifierAddress;
        }
    }

    function setDkg(address dkgAddress) external onlyAclOwner {
        if (dkgAddress == address(0)) revert ZkDkgDispute_Error();
        dkg = IDKG_ZkDkg(dkgAddress);
        emit DkgContractSet(dkgAddress);
    }

    function setReputationManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert ZkDkgDispute_Error();
        reputationManager = manager;
        emit ReputationManagerSet(manager);
    }

    function setRewardManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert ZkDkgDispute_Error();
        rewardManager = manager;
        emit RewardManagerSet(manager);
    }

    function setZkDkgShareVerifier(address verifier) external onlyAclOwner {
        if (verifier == address(0)) revert ZkDkgDispute_Error();
        zkDkgShareVerifier = verifier;
        emit ZkDkgShareVerifierSet(verifier);
    }

    function setZkDkgShareVerifierForParticipantCount(uint8 participantCount, address verifier) external onlyAclOwner {
        if (participantCount == 0 || verifier == address(0)) revert ZkDkgDispute_Error();
        zkDkgShareVerifierByParticipantCount[participantCount] = verifier;
        emit ZkDkgShareVerifierForParticipantCountSet(participantCount, verifier);
    }

    function setZkDkgShareVerifierForCommittee(
        uint8 participantCount,
        uint8 threshold,
        address verifier
    ) external onlyAclOwner {
        if (participantCount == 0 || threshold == 0 || threshold > participantCount || verifier == address(0)) {
            revert ZkDkgDispute_Error();
        }
        zkDkgShareVerifierByCommittee[participantCount][threshold] = verifier;
        emit ZkDkgShareVerifierForCommitteeSet(participantCount, threshold, verifier);
    }

    function setZkDkgCoordinatorV2(address coordinator) external onlyAclOwner {
        if (coordinator == address(0)) revert ZkDkgDispute_Error();
        zkDkgCoordinatorV2 = coordinator;
        emit ZkDkgCoordinatorV2Set(coordinator);
    }

    function setStakingManager(address manager) external onlyAclOwner {
        if (manager == address(0)) revert ZkDkgDispute_Error();
        stakingManager = manager;
        emit StakingManagerSet(manager);
    }

    function setZkDkgDisputePeriod(uint64 period) external onlyAclOwner {
        if (period == 0) revert ZkDkgDispute_Error();
        zkDkgDisputePeriod = period;
        emit ZkDkgDisputePeriodSet(period);
    }

    function publishZkDkgBabyJubjubMaterial(
        bytes32 materialId,
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex,
        uint256[] calldata commitments,
        uint256[] calldata encryptedShares,
        uint256 firstCoefficient
    ) external {
        _publishBabyJubjubMaterial(
            materialId,
            fileId,
            keyEpoch,
            shareVersion,
            isRefresh,
            dealerIndex,
            commitments,
            encryptedShares,
            firstCoefficient
        );
    }

    function publishAndAcknowledgeV2Material(
        bytes32 materialId,
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex,
        uint256[] calldata commitments,
        uint256[] calldata encryptedShares,
        uint256 firstCoefficient
    ) external {
        if (isRefresh || shareVersion != 1 || zkDkgCoordinatorV2 == address(0)) revert ZkDkgDispute_Error();
        _publishBabyJubjubMaterial(
            materialId,
            fileId,
            keyEpoch,
            shareVersion,
            isRefresh,
            dealerIndex,
            commitments,
            encryptedShares,
            firstCoefficient
        );
    }

    function _publishBabyJubjubMaterial(
        bytes32 materialId,
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex,
        uint256[] calldata commitments,
        uint256[] calldata encryptedShares,
        uint256 firstCoefficient
    ) internal returns (address dealer) {
        dkg.validateMaterialAttempt(materialId, fileId, keyEpoch, shareVersion);
        if (fileId == bytes32(0) || keyEpoch == 0 || shareVersion == 0 || dealerIndex == 0) {
            revert ZkDkgDispute_Error();
        }
        if (commitments.length == 0 || encryptedShares.length == 0 || firstCoefficient != commitments[0]) revert ZkDkgDispute_Error();

        uint8 threshold;
        uint8 participantCount;
        (threshold, participantCount, dealer) =
            _resolveDealer(fileId, keyEpoch, shareVersion, isRefresh, dealerIndex);
        if (msg.sender != dealer) revert ZkDkgDispute_Error();
        // A refresh dealer belongs to the old share committee, which may be
        // different from the new policy committee. _resolveDealer verifies it.
        _requireActiveStakedGuardian(msg.sender);
        require(commitments.length == uint256(threshold), "ZKDKG: bad commitment count");
        if (isRefresh) {
            require(encryptedShares.length == uint256(participantCount), "ZKDKG: bad refresh share count");
        } else {
            require(encryptedShares.length == uint256(participantCount) - 1, "ZKDKG: bad share count");
        }
        for (uint256 i; i < encryptedShares.length; ++i) {
            if (encryptedShares[i] >= BABY_JUBJUB_FIELD_ORDER) revert ZkDkgDispute_Error();
        }

        BabyJubjubBatch storage batch = _batches[materialId][keyEpoch][shareVersion][isRefresh][dealerIndex];
        if (batch.exists) revert ZkDkgDispute_Error();

        batch.exists = true;
        batch.isRefresh = isRefresh;
        batch.dealer = dealer;
        batch.dealerIndex = dealerIndex;
        batch.commitmentHash = keccak256(abi.encodePacked(commitments));
        batch.encryptedShareHash = keccak256(abi.encodePacked(encryptedShares));
        batch.firstCoefficient = firstCoefficient;
        batch.verifier = _materialVerifier[materialId];
        if (batch.verifier.code.length == 0) revert ZkDkgDispute_Error();
        _copyCalldataUint256ToStorage(encryptedShares, batch.encryptedShares);
        if (isRefresh) {
            IZkDkgCoordinatorV2_Acknowledge(zkDkgCoordinatorV2).acknowledgeRefreshDealerMaterialForAttempt(
                materialId, fileId, keyEpoch, shareVersion, dealerIndex, dealer);
        } else {
            IZkDkgCoordinatorV2_Acknowledge(zkDkgCoordinatorV2).acknowledgeDealerMaterialForAttempt(
                materialId, fileId, keyEpoch, dealerIndex, dealer);
        }

        emit ZkDkgBabyJubjubMaterialPublished(
            materialId,
            fileId,
            keyEpoch,
            shareVersion,
            isRefresh,
            dealer,
            dealerIndex,
            batch.commitmentHash,
            batch.encryptedShareHash
        );
    }

    function openZkDkgEncryptedShareDispute(
        bytes32 materialId,
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex,
        uint8 receiverIndex
    ) external returns (bytes32 disputeId) {
        uint256 startGas = gasleft();
        if (dkg.getMaterialAttemptId(fileId, keyEpoch, shareVersion) != materialId || materialId == bytes32(0)) revert ZkDkgDispute_Error();
        IDkgAttemptController(IDkgAttemptCoordinator(address(dkg)).attemptController()).requireComplaintOpen(materialId);
        (, address dealer, address receiver) =
            _resolveDealerReceiver(fileId, keyEpoch, shareVersion, isRefresh, dealerIndex, receiverIndex);
        if (msg.sender != receiver) revert ZkDkgDispute_Error();
        (, uint32 receivers, ) = IDkgAttemptCoordinator(address(dkg)).getAttemptWork(materialId);
        if ((receivers & (uint32(1) << (receiverIndex - 1))) != 0) revert ZkDkgDispute_Error();

        BabyJubjubBatch storage batch = _batches[materialId][keyEpoch][shareVersion][isRefresh][dealerIndex];
        if (!batch.exists) revert ZkDkgDispute_Error();

        uint256 encryptedShare = batch.encryptedShares[_shareArrayIndex(
            dealerIndex,
            receiverIndex,
            batch.encryptedShares.length,
            !isRefresh
        )];

        disputeId = disputeIdFor(materialId, keyEpoch, shareVersion, isRefresh, dealerIndex, receiverIndex);
        EncryptedShareDispute storage d = _disputes[disputeId];
        if (d.exists) revert ZkDkgDispute_Error();

        d.exists = true;
        d.resolved = false;
        d.dealerJustified = false;
        d.isRefresh = isRefresh;
        d.fileId = fileId;
        d.keyEpoch = keyEpoch;
        d.shareVersion = shareVersion;
        d.dealerIndex = dealerIndex;
        d.receiverIndex = receiverIndex;
        d.dealer = dealer;
        d.receiver = receiver;
        d.openedAt = uint64(block.timestamp);
        d.deadline = uint64(block.timestamp) + materialDisputePeriod[materialId];
        d.encryptedShare = encryptedShare;
        d.receiverGasCost = (startGas - gasleft()) * tx.gasprice;
        d.materialId = materialId;
        d.verifier = batch.verifier;
        ++pendingDisputes[materialId];
        ++pendingReceiverDisputes[materialId][receiver];

        emit ZkDkgEncryptedShareDisputeOpened(
            disputeId,
            fileId,
            keyEpoch,
            shareVersion,
            isRefresh,
            receiver,
            dealer,
            receiverIndex,
            dealerIndex,
            d.deadline
        );
    }

    function justifyZkDkgEncryptedShareDispute(bytes32 disputeId, ZkDkgShareProof calldata proof) external {
        EncryptedShareDispute storage d = _disputes[disputeId];
        if (!(d.exists && !d.resolved)) revert ZkDkgDispute_Error();
        if (msg.sender != d.dealer) revert ZkDkgDispute_Error();
        require(block.timestamp <= d.deadline, "ZKDKG: dispute expired");

        uint256[2] memory input = [_justificationHash(d), uint256(1)];
        // The original profile/verifier stays authoritative after a retry or
        // registry rotation. Never reinterpret an old complaint using new terms.
        address verifier = d.verifier;
        if (verifier == address(0)) revert ZkDkgDispute_Error();
        require(IZkDkgShareVerifier(verifier).verifyTx(proof, input), "ZKDKG: invalid proof");

        d.resolved = true;
        d.dealerJustified = true;
        --pendingDisputes[d.materialId];
        --pendingReceiverDisputes[d.materialId][d.receiver];

        if (reputationManager != address(0)) {
            try IReputationManager_ZkDkg(reputationManager).recordVerifiedDkgComplaint(d.receiver, d.dealer, 3) {
            } catch {
            }
        }

        emit ZkDkgEncryptedShareDisputeJustified(disputeId, d.dealer, d.receiver);
    }

    function finalizeExpiredZkDkgEncryptedShareDispute(bytes32 disputeId) external {
        EncryptedShareDispute storage d = _disputes[disputeId];
        if (!(d.exists && !d.resolved)) revert ZkDkgDispute_Error();
        require(block.timestamp > d.deadline, "ZKDKG: dispute still live");

        d.resolved = true;
        d.dealerJustified = false;
        --pendingDisputes[d.materialId];
        --pendingReceiverDisputes[d.materialId][d.receiver];
        _excludedDealer[dealerScope(d.materialId, d.keyEpoch, d.shareVersion, d.isRefresh, d.dealerIndex)] = true;
        excludedDealers[d.materialId] |= uint32(1) << (d.dealerIndex - 1);

        if (reputationManager != address(0)) {
            try IReputationManager_ZkDkg(reputationManager).recordVerifiedDkgComplaint(d.dealer, d.receiver, 2) {
            } catch {
            }
        }
        // Financial fault is assessed exactly once by the accepted-duty
        // controller against this attempt's segregated bond. No direct slash
        // consumes custody stake or treats a swallowed callback as payment.

        emit ZkDkgDealerExcluded(d.fileId, d.keyEpoch, d.shareVersion, d.isRefresh, d.dealer, d.dealerIndex);
        emit ZkDkgEncryptedShareDisputeExpired(disputeId, d.dealer, d.receiver);
    }

    function getDispute(bytes32 disputeId) external view returns (EncryptedShareDispute memory) {
        return _disputes[disputeId];
    }

    function justificationPublicInputHash(bytes32 disputeId) external view returns (uint256) {
        EncryptedShareDispute storage d = _disputes[disputeId];
        if (!d.exists) revert ZkDkgDispute_Error();
        return _justificationHash(d);
    }

    function isDealerExcluded(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex
    ) external view returns (bool) {
        return _excludedDealer[dealerScope(dkg.getMaterialAttemptId(fileId, keyEpoch, shareVersion), keyEpoch, shareVersion, isRefresh, dealerIndex)];
    }

    function disputeIdFor(
        bytes32 materialId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex,
        uint8 receiverIndex
    ) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), materialId, keyEpoch, shareVersion, isRefresh, dealerIndex, receiverIndex));
    }

    function dealerScope(
        bytes32 materialId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(materialId, keyEpoch, shareVersion, isRefresh, dealerIndex));
    }

    function _resolveDealer(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex
    ) internal view returns (uint8 threshold, uint8 participantCount, address dealer) {
        if (isRefresh) {
            (
                bool refreshExists,
                bool finalized,
                ,
                ,
                uint8 oldN,
                uint8 newT,
                uint8 newN,
                address[] memory oldGuardians,
                ,
                uint8[] memory oldParticipantIndices
            ) = dkg.getRefreshRequest(fileId, keyEpoch, shareVersion);
            if (!(refreshExists && !finalized)) revert ZkDkgDispute_Error();
            if (!(dealerIndex > 0 && dealerIndex <= oldN && _containsIndex(oldParticipantIndices, dealerIndex))) {
                revert ZkDkgDispute_Error();
            }
            return (newT, newN, oldGuardians[uint256(dealerIndex) - 1]);
        }

        if (shareVersion != 1) revert ZkDkgDispute_Error();
        (bool exists, bool active, , uint8 policyThreshold, address[] memory guardians) = acl.getDkgFilePolicy(fileId);
        if (!(exists && active && dealerIndex <= guardians.length)) revert ZkDkgDispute_Error();
        return (policyThreshold, uint8(guardians.length), guardians[uint256(dealerIndex) - 1]);
    }

    function _resolveDealerReceiver(
        bytes32 fileId,
        uint32 keyEpoch,
        uint32 shareVersion,
        bool isRefresh,
        uint8 dealerIndex,
        uint8 receiverIndex
    ) internal view returns (uint8 participantCount, address dealer, address receiver) {
        if (isRefresh) {
            (
                bool refreshExists,
                bool finalized,
                ,
                ,
                uint8 oldN,
                ,
                uint8 newN,
                address[] memory oldGuardians,
                address[] memory newGuardians,
                uint8[] memory oldParticipantIndices
            ) = dkg.getRefreshRequest(fileId, keyEpoch, shareVersion);
            if (!(refreshExists && !finalized)) revert ZkDkgDispute_Error();
            if (!(dealerIndex > 0 && dealerIndex <= oldN && _containsIndex(oldParticipantIndices, dealerIndex))) {
                revert ZkDkgDispute_Error();
            }
            if (!(receiverIndex > 0 && receiverIndex <= newN)) revert ZkDkgDispute_Error();
            return (newN, oldGuardians[uint256(dealerIndex) - 1], newGuardians[uint256(receiverIndex) - 1]);
        }

        if (shareVersion != 1 || dealerIndex == receiverIndex) revert ZkDkgDispute_Error();
        (bool exists, bool active, , , address[] memory guardians) = acl.getDkgFilePolicy(fileId);
        if (!(exists && active)) revert ZkDkgDispute_Error();
        if (!(dealerIndex > 0 && dealerIndex <= guardians.length && receiverIndex > 0 && receiverIndex <= guardians.length)) {
            revert ZkDkgDispute_Error();
        }
        return (uint8(guardians.length), guardians[uint256(dealerIndex) - 1], guardians[uint256(receiverIndex) - 1]);
    }

    function _justificationHash(EncryptedShareDispute storage d) internal view returns (uint256) {
        BabyJubjubBatch storage batch = _batches[d.materialId][d.keyEpoch][d.shareVersion][d.isRefresh][d.dealerIndex];
        if (!batch.exists) revert ZkDkgDispute_Error();

        uint256[2] storage dealerPk = _encryptionKeys[d.materialId][d.dealer];
        uint256[2] storage receiverPk = _receiverKeys[d.materialId][d.receiver];

        return uint256(keccak256(
            bytes.concat(
                batch.commitmentHash,
                bytes32(dealerPk[0]),
                bytes32(dealerPk[1]),
                bytes32(receiverPk[0]),
                bytes32(receiverPk[1]),
                bytes32(uint256(d.receiverIndex)),
                bytes32(d.encryptedShare)
            )
        )) % BABY_JUBJUB_FIELD_ORDER;
    }

    function _babyJubjubPublicKey(address guardian) internal view returns (uint256 x, uint256 y) {
        address registry = acl.guardianRegistry();
        if (registry == address(0)) revert ZkDkgDispute_Error();
        (x, y) = IGuardianRegistry_ZkDkg(registry).getGuardianDkgBabyJubjubPublicKey(guardian);
        if (x == 0 && y == 0) revert ZkDkgDispute_Error();
    }

    function _verifierFor(uint8 n, uint8 t) internal view returns (address verifier) {
        verifier = zkDkgShareVerifierByCommittee[n][t];
        if (verifier == address(0)) verifier = zkDkgShareVerifierByParticipantCount[n];
        if (verifier == address(0)) verifier = zkDkgShareVerifier;
    }

    function _snapshotCommitteeKeys(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version, bool refresh) internal {
        address[] memory receivers;
        if (refresh) {
            (, , , , , , , address[] memory oldGuardians, address[] memory newGuardians, uint8[] memory indices) = dkg.getRefreshRequest(fileId, epoch, version);
            for (uint256 i; i < indices.length; ++i) _snapshotKey(materialId, oldGuardians[uint256(indices[i]) - 1]);
            receivers = newGuardians;
        } else {
            (, , , , receivers) = acl.getDkgFilePolicy(fileId);
        }
        for (uint256 i; i < receivers.length; ++i) _snapshotKey(materialId, receivers[i]);
    }

    function _snapshotKey(bytes32 materialId, address guardian) internal {
        uint256[2] storage key = _encryptionKeys[materialId][guardian];
        if (key[0] != 0 || key[1] != 0) return;
        (key[0], key[1]) = _babyJubjubPublicKey(guardian);
        if (!validatedEncryptionKeys[keccak256(abi.encode(key[0], key[1]))]) revert ZkDkgDispute_Error();
    }

    /// @notice Anyone may prevalidate a public point once. It does not assign
    /// that key to a Guardian; only the Guardian's registry transaction does.
    /// Splitting this bounded operation from open keeps N=20 snapshots below
    /// the transaction gas cap without skipping the subgroup check.
    function validateEncryptionKey(uint256 x, uint256 y) external {
        bytes32 key = keccak256(abi.encode(x, y));
        if (validatedEncryptionKeys[key]) return;
        if (!BabyJubjubProjective.inPrimeSubgroup(x, y)) revert ZkDkgDispute_Error();
        validatedEncryptionKeys[key] = true;
    }

    function snapshotAttempt(bytes32 materialId, bytes32 fileId, uint32 epoch, uint32 version) external returns (bytes32 digest, uint64 period) {
        IDkgAttemptCoordinator c = IDkgAttemptCoordinator(address(dkg));
        if (msg.sender != c.attemptController() || _materialVerifier[materialId] != address(0)) revert ZkDkgDispute_Error();
        DkgAttemptTypes.Request memory r = IDkgAttemptController(msg.sender).getAttemptRequest(fileId, epoch, version);
        if (r.materialId != materialId || materialId == bytes32(0)) revert ZkDkgDispute_Error();
        // An exact committee profile is mandatory; a default for another
        // threshold must never silently select a different trusted setup.
        address verifier = zkDkgShareVerifierByCommittee[uint8(r.receivers.length)][r.newT];
        if (verifier.code.length == 0) revert ZkDkgDispute_Error();
        _materialVerifier[materialId] = verifier;
        period = zkDkgDisputePeriod; materialDisputePeriod[materialId] = period;
        _snapshotCommitteeKeys(materialId, fileId, epoch, version, r.refresh);
        // The existing circuit has no attempt-id input. A public per-attempt
        // receiver-key offset changes its DH mask even when a refresh keeps
        // the same polynomial constant commitment. No setup/circuit change.
        (uint256 hx, uint256 hy) = BabyJubjubProjective.mul(receiverKeyTweak(materialId), BabyJubjub.GX, BabyJubjub.GY);
        for (uint256 i; i < r.receivers.length; ++i) {
            address g = r.receivers[i];
            uint256[2] storage original = _encryptionKeys[materialId][g];
            uint256[2] storage derived = _receiverKeys[materialId][g];
            (derived[0], derived[1]) = BabyJubjubProjective.addAffine(original[0], original[1], hx, hy);
            if (BabyJubjub.isIdentity(derived[0], derived[1])) revert ZkDkgDispute_Error();
            digest = keccak256(abi.encode(digest, g, original, derived));
        }
        for (uint256 i; i < r.dealerIndices.length; ++i) {
            address g = r.oldGuardians[uint256(r.dealerIndices[i]) - 1];
            digest = keccak256(abi.encode(digest, g, _encryptionKeys[materialId][g]));
        }
        digest = keccak256(abi.encode(digest, verifier, period));
    }

    /// @notice The verifier frozen when this attempt was prepared. Workers
    /// must check this snapshot before accepting; the global profile may change.
    function getMaterialVerifier(bytes32 materialId) external view returns (address) {
        return _materialVerifier[materialId];
    }

    function getEncryptionKey(bytes32 materialId, address guardian) external view returns (uint256 x, uint256 y) {
        uint256[2] storage key = _encryptionKeys[materialId][guardian];
        return (key[0], key[1]);
    }

    function receiverKeyTweak(bytes32 materialId) public pure returns (uint256) {
        uint256 subgroupOrder = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
        return uint256(keccak256(abi.encodePacked("FileTrust-DKG-receiver-v1", materialId))) % (subgroupOrder - 1) + 1;
    }

    function getReceiverEncryptionKey(bytes32 materialId, address guardian) external view returns (uint256 x, uint256 y) {
        uint256[2] storage key = _receiverKeys[materialId][guardian];
        return (key[0], key[1]);
    }

    function getMaterialBatch(bytes32 materialId, uint32 epoch, uint32 version, bool refresh, uint8 dealerIndex) external view returns (BabyJubjubBatch memory) {
        return _batches[materialId][epoch][version][refresh][dealerIndex];
    }

    function materialCommitmentHash(bytes32 materialId, uint32 epoch, uint32 version, uint8 index) external view returns (bytes32) {
        return _batches[materialId][epoch][version][version > 1][index].commitmentHash;
    }

    function materialEncryptedShare(bytes32 materialId, uint32 epoch, uint32 version, uint8 dealerIndex, uint8 receiverIndex) external view returns (uint256) {
        BabyJubjubBatch storage b = _batches[materialId][epoch][version][version > 1][dealerIndex];
        if (!b.exists) revert ZkDkgDispute_Error();
        return b.encryptedShares[_shareArrayIndex(dealerIndex, receiverIndex, b.encryptedShares.length, version == 1)];
    }

    function _requireActiveStakedGuardian(address guardian) internal view {
        address registry = acl.guardianRegistry();
        if (registry != address(0)) {
            require(IGuardianRegistry_ZkDkg(registry).isActiveGuardian(guardian), "ZKDKG: guardian not eligible");
        }
    }

    function _shareArrayIndex(
        uint8 dealerIndex,
        uint8 receiverIndex,
        uint256 encryptedShareCount,
        bool omitDealer
    ) internal pure returns (uint256) {
        if (receiverIndex == 0) revert ZkDkgDispute_Error();
        uint256 idx = uint256(receiverIndex) - 1;
        if (omitDealer) {
            if (dealerIndex == receiverIndex) revert ZkDkgDispute_Error();
            if (receiverIndex > dealerIndex) {
                idx -= 1;
            }
        }
        if (idx >= encryptedShareCount) revert ZkDkgDispute_Error();
        return idx;
    }

    function _containsIndex(uint8[] memory values, uint8 needle) internal pure returns (bool) {
        for (uint256 i = 0; i < values.length; i++) {
            if (values[i] == needle) return true;
        }
        return false;
    }

    function _copyCalldataUint256ToStorage(uint256[] calldata source, uint256[] storage target) internal {
        while (target.length > 0) {
            target.pop();
        }
        for (uint256 i = 0; i < source.length; i++) {
            target.push(source[i]);
        }
    }

    modifier onlyAclOwner() {
        require(msg.sender == acl.owner(), "ZKDKG: not ACL owner");
        _;
    }
}
