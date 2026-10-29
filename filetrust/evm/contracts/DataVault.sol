// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DataVault
// Purpose:  The encrypted pointers to a file's pieces, and the requests to re-encrypt
//           them for an admitted reader.
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

interface IAccessControlFT_DataVault {
    enum DkgMode {
        LEGACY,
        ZKDKG_V2
    }

    function isDataOwner(address a) external view returns (bool);
    function hasRequestedReenc(address requester) external view returns (bool);

    function isFileDataOwner(bytes32 fileId, address dataOwner) external view returns (bool);
    function isRequesterForFile(bytes32 fileId, address requester) external view returns (bool);
    function getFilePolicyMode(bytes32 fileId) external view returns (DkgMode);
    function telgV2() external view returns (address);
}

interface IPreDeadline_DataVault {
    function preDeadline() external view returns (uint64);
}

interface IDKG_DataVault {
    function getActiveShareVersion(bytes32 fileId, uint32 keyEpoch) external view returns (uint32);
}

interface IRewardManager_DataVault {
    function depositAccessEscrowFor(uint256 requestId, address payer) external payable;
    function dataVault() external view returns (address);
    function isAccessEscrowComplete(uint256 requestId) external view returns (bool);
}

contract DataVault is FileTrustDeprecatable {
    uint16 public constant META_PIECE_INDEX = type(uint16).max;

    struct EncCid {
        uint256 C1x;        // TElG C1.x for K
        uint256 C1y;        // TElG C1.y for K
        bytes C2;           // TElG C2 for K
        bytes ctSym;        // symmetric ciphertext: encrypted VaultMesh payload, e.g. {cid, peerId}
        uint256 batchId;    // owning batch
        uint16 pieceIndex;  // IDA piece index. META_PIECE_INDEX is reserved for metadata such as AES info.
        bool valid;         // only valid records are used for new access requests
        uint256 replacedBy; // 0 means not replaced. Otherwise stores new encCids index + 1.
    }

    struct Batch {
        // Slot 0: fileId (32 bytes, full slot)
        bytes32 fileId;
        // Slot 1: dataOwner(20)+ts(8)+n(2)+t(2) = exactly 32 bytes, full slot
        address dataOwner;
        uint64 ts;
        uint16 n;
        uint16 t;
        // Slot 2: keyEpoch(4)+v2BatchC1Exists(1)+exists(1) = 6 bytes packed
        uint32 keyEpoch;
        bool v2BatchC1Exists;
        bool exists;
        // Slot 3-4: each uint256 needs its own slot
        uint256 v2BatchC1x;
        uint256 v2BatchC1y;
        // Dynamic types last — each starts a new slot
        string dataId;
        uint256[] cidIndices; // all historical encCids indices for this batch, including invalid/replaced ones
    }

    struct AccessRequest {
        address requester;   // slot 0: 20 bytes \
        bool exists;         // slot 0:  1 byte   | packed (29 bytes used)
        uint32 keyEpoch;     // slot 0:  4 bytes  |
        uint32 shareVersion; // slot 0:  4 bytes /
        bytes32 fileId;      // slot 1
        uint256 batchId;     // slot 2
        string dataId;       // slot 3 (dynamic)
        uint64 ts;           // slot 4: file metadata time, never a PRE deadline clock
        uint256 pkReqX;      // slot 5
        uint256 pkReqY;      // slot 6
        uint256[] indices;   // slot 7 (legacy; new requests derive indices from batchId)
    }

    struct ReencCid {
        uint256 cidIndex;
        uint256 C1xPrime;
        uint256 C1yPrime;
        bytes C2Prime;
    }

    IAccessControlFT_DataVault public acl;

    EncCid[] public encCids;

    uint256 public nextBatchId;
    mapping(uint256 => Batch) public batches;

    mapping(bytes32 => uint256) public batchIdByFileId;
    mapping(bytes32 => uint256) public batchCountByFileId;
    mapping(bytes32 => mapping(uint256 => uint256)) public batchIdByFileIdAndIndex;

    mapping(bytes32 => uint256) public batchIdByKey;
    mapping(bytes32 => uint256) public batchIdByFileKey;

    // batchId -> pieceIndex -> current valid encCids index + 1
    mapping(uint256 => mapping(uint16 => uint256)) public currentCidIndexPlusOneByPiece;

    uint256 public nextAccessRequestId;
    mapping(uint256 => AccessRequest) public accessRequests;

    mapping(uint256 => ReencCid[]) private _reencCids;

    mapping(bytes32 => uint256) public reusableRequestPlusOneByKey;

    address public owner;
    address public telg;
    address public rewardManager;
    IDKG_DataVault public dkg;
    IDKG_DataVault public dkgV2;

    // A V2 request is prepared once and then funded by its requester. Keep a
    // single live record per requester/file across every preparation entry point.
    // Plus one is required because access request zero is a valid request.
    mapping(bytes32 => mapping(address => uint256)) private _liveAccessRequestPlusOne;

    struct PreRequestTiming {
        uint64 preparedAt;
        uint64 admittedAt; // zero until the first successful access escrow deposit
        uint64 deadline;   // preparation cleanup deadline, replaced once at admission
    }
    mapping(uint256 => PreRequestTiming) private _preRequestTiming;

    event PreRequestAdmitted(uint256 indexed requestId, uint64 admittedAt, uint64 deadline);

    event BatchCreated(
        bytes32 indexed fileId,
        uint256 indexed batchId,
        address indexed dataOwner,
        string dataId,
        uint64 ts,
        uint16 n,
        uint16 t,
        uint32 keyEpoch
    );

    // Kept for old listeners.
    event EncCidAdded(
        bytes32 indexed fileId,
        uint256 index,
        uint256 indexed batchId,
        address indexed doAddr
    );

    event EncCidAddedV2(
        bytes32 indexed fileId,
        uint256 index,
        uint256 indexed batchId,
        address indexed doAddr,
        uint16 pieceIndex,
        bool valid
    );

    event EncCidsBatchAdded(
        bytes32 indexed fileId,
        uint256 indexed batchId,
        address indexed doAddr,
        uint256 firstIndex,
        uint256 count
    );

    event V2BatchC1Set(bytes32 indexed fileId, uint256 indexed batchId, uint256 C1x, uint256 C1y);

    event EncCidReplaced(
        bytes32 indexed fileId,
        uint256 indexed batchId,
        address indexed doAddr,
        uint256 oldIndex,
        uint256 newIndex,
        uint16 pieceIndex
    );

    event EncCidInvalidated(
        bytes32 indexed fileId,
        uint256 indexed batchId,
        address indexed doAddr,
        uint256 oldIndex,
        uint16 pieceIndex
    );

    event DataAccessRequestedV2(
        bytes32 indexed fileId,
        uint256 indexed requestId,
        address indexed requester,
        uint256 batchId,
        string dataId,
        uint64 ts,
        uint32 keyEpoch,
        uint32 shareVersion,
        uint256[] indices,
        uint256 pkReqX,
        uint256 pkReqY
    );

    event TelgSet(address indexed telg);
    event RewardManagerSet(address indexed rewardManager);
    event DkgSet(address indexed dkg);
    event DkgV2Set(address indexed dkgV2);

    event ReencryptedCidsStored(
        bytes32 indexed fileId,
        uint256 indexed requestId,
        address indexed requester,
        uint256 count
    );

    event ReusableRequestCached(
        bytes32 indexed reuseKey,
        bytes32 indexed fileId,
        uint256 indexed requestId,
        address requester,
        uint256 batchId
    );
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address aclAddress) {
        require(aclAddress != address(0), "DV: zero ACL");
        acl = IAccessControlFT_DataVault(aclAddress);
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "DV: not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "DV: zero owner");
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /// @notice Close this version to new data batches when its successor opens (Phase 2), for
    ///         good. A batch being written can still be finished, and
    ///         access under existing policies is unchanged.
    function deprecate(address successor) external onlyOwner { _deprecate(successor); }

    modifier onlyTelg() {
        require(msg.sender == telg, "DV: not TElG");
        _;
    }

    function setTelg(address _telg) external onlyOwner {
        require(_telg != address(0), "DV: zero TElG");
        telg = _telg;
        emit TelgSet(_telg);
    }

    /// @notice Bind the RewardManager that requesters' access escrow is forwarded to,
    ///         once. It must name this DataVault as its own, so the money can only land
    ///         where its refunds are paid back to the requester this vault recorded.
    function setRewardManager(address _rewardManager) external onlyOwner {
        require(rewardManager == address(0) && _rewardManager.code.length != 0
                && IRewardManager_DataVault(_rewardManager).dataVault() == address(this),
                "DV: bad RewardManager");
        rewardManager = _rewardManager;
        emit RewardManagerSet(_rewardManager);
    }

    function setDkg(address _dkg) external onlyOwner {
        require(_dkg != address(0), "DV: zero DKG");
        dkg = IDKG_DataVault(_dkg);
        emit DkgSet(_dkg);
    }

    function setDkgV2(address _dkgV2) external onlyOwner {
        require(_dkgV2 != address(0), "DV: zero DKGv2");
        dkgV2 = IDKG_DataVault(_dkgV2);
        emit DkgV2Set(_dkgV2);
    }

    function _activeShareVersion(bytes32 fileId, uint32 keyEpoch) internal view returns (uint32) {
        IDKG_DataVault source = dkg;
        if (acl.getFilePolicyMode(fileId) == IAccessControlFT_DataVault.DkgMode.ZKDKG_V2) {
            source = dkgV2;
        }

        if (address(source) == address(0)) {
            return 1;
        }

        uint32 sv = source.getActiveShareVersion(fileId, keyEpoch);
        require(sv > 0, "DV: no active shareVersion");
        return sv;
    }

    function _batchKey(string memory dataId, uint64 ts) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(dataId, ts));
    }

    function _fileBatchKey(bytes32 fileId, string memory dataId, uint64 ts) internal pure returns (bytes32) {
        return keccak256(abi.encode(fileId, dataId, ts));
    }

    function _reuseKey(
        address requester,
        bytes32 fileId,
        uint256 batchId,
        uint256 pkReqX,
        uint256 pkReqY
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(requester, fileId, batchId, pkReqX, pkReqY));
    }

    function createBatch(
        bytes32 fileId,
        string calldata dataId,
        uint64 ts,
        uint16 n,
        uint16 t,
        uint32 keyEpoch
    ) external returns (uint256 batchId) {
        _requireNotDeprecated();
        require(fileId != bytes32(0), "DV: empty fileId");
        require(acl.isDataOwner(msg.sender), "DV: not DO");
        require(acl.isFileDataOwner(fileId, msg.sender), "DV: not file DO");
        require(bytes(dataId).length != 0, "DV: empty dataId");
        require(n > 0, "DV: n=0");
        require(t > 0 && t <= n, "DV: bad t");

        bytes32 fileKey = _fileBatchKey(fileId, dataId, ts);
        require(batchIdByFileKey[fileKey] == 0, "DV: file batch exists");

        bytes32 key = _batchKey(dataId, ts);

        batchId = ++nextBatchId;

        Batch storage b = batches[batchId];
        b.fileId = fileId;
        b.dataOwner = msg.sender;
        b.dataId = dataId;
        b.ts = ts;
        b.n = n;
        b.t = t;
        b.keyEpoch = keyEpoch;
        b.exists = true;

        batchIdByFileId[fileId] = batchId;
        batchIdByFileKey[fileKey] = batchId;

        uint256 pos = batchCountByFileId[fileId];
        batchIdByFileIdAndIndex[fileId][pos] = batchId;
        batchCountByFileId[fileId] = pos + 1;

        if (batchIdByKey[key] == 0) {
            batchIdByKey[key] = batchId;
        }

        emit BatchCreated(fileId, batchId, msg.sender, dataId, ts, n, t, keyEpoch);
    }

    function createV2BatchWithCids(
        bytes32 fileId,
        string calldata dataId,
        uint64 ts,
        uint16 n,
        uint16 t,
        uint32 keyEpoch,
        uint256 C1x,
        uint256 C1y,
        uint16[] calldata pieceIndices,
        uint256[] calldata cidC1xs,
        uint256[] calldata cidC1ys,
        bytes[] calldata C2s,
        bytes[] calldata ctSyms
    ) external returns (uint256 batchId, uint256 firstIndex, uint256 count) {
        require(fileId != bytes32(0), "DV: empty fileId");
        require(acl.isDataOwner(msg.sender), "DV: not DO");
        require(acl.isFileDataOwner(fileId, msg.sender), "DV: not file DO");
        require(acl.getFilePolicyMode(fileId) == IAccessControlFT_DataVault.DkgMode.ZKDKG_V2, "DV: not V2");
        require(bytes(dataId).length != 0, "DV: empty dataId");
        require(n > 0, "DV: n=0");
        require(t > 0 && t <= n, "DV: bad t");
        require(C1x != 0 || C1y != 0, "DV: empty V2 batch C1");

        count = pieceIndices.length;
        require(count > 0, "DV: empty CID batch");
        require(cidC1xs.length == count, "DV: C1x length");
        require(cidC1ys.length == count, "DV: C1y length");
        require(C2s.length == count, "DV: C2 length");
        require(ctSyms.length == count, "DV: ctSym length");

        bytes32 fileKey = _fileBatchKey(fileId, dataId, ts);
        require(batchIdByFileKey[fileKey] == 0, "DV: file batch exists");

        bytes32 key = _batchKey(dataId, ts);

        batchId = ++nextBatchId;

        Batch storage b = batches[batchId];
        b.fileId = fileId;
        b.dataOwner = msg.sender;
        b.dataId = dataId;
        b.ts = ts;
        b.n = n;
        b.t = t;
        b.keyEpoch = keyEpoch;
        b.v2BatchC1Exists = true;
        b.v2BatchC1x = C1x;
        b.v2BatchC1y = C1y;
        b.exists = true;

        batchIdByFileId[fileId] = batchId;
        batchIdByFileKey[fileKey] = batchId;

        uint256 pos = batchCountByFileId[fileId];
        batchIdByFileIdAndIndex[fileId][pos] = batchId;
        batchCountByFileId[fileId] = pos + 1;

        if (batchIdByKey[key] == 0) {
            batchIdByKey[key] = batchId;
        }

        emit BatchCreated(fileId, batchId, msg.sender, dataId, ts, n, t, keyEpoch);
        emit V2BatchC1Set(fileId, batchId, C1x, C1y);

        firstIndex = encCids.length;
        for (uint256 i = 0; i < count; i++) {
            _addEncCidToBatch(batchId, pieceIndices[i], cidC1xs[i], cidC1ys[i], C2s[i], ctSyms[i], false);
        }

        emit EncCidsBatchAdded(fileId, batchId, msg.sender, firstIndex, count);
    }

    // Backward-compatible function. New code should pass pieceIndex explicitly.
    function addEncCidToBatch(
        uint256 batchId,
        uint256 C1x,
        uint256 C1y,
        bytes calldata C2,
        bytes calldata ctSym
    ) external {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        require(acl.isFileDataOwner(b.fileId, msg.sender), "DV: not file DO");

        uint16 pieceIndex = uint16(_validRecordsCount(batchId));
        _addEncCidToBatch(batchId, pieceIndex, C1x, C1y, C2, ctSym, false);
    }

    function setV2BatchC1(uint256 batchId, uint256 C1x, uint256 C1y) external {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        require(acl.isFileDataOwner(b.fileId, msg.sender), "DV: not file DO");
        require(acl.getFilePolicyMode(b.fileId) == IAccessControlFT_DataVault.DkgMode.ZKDKG_V2, "DV: not V2");
        require(!b.v2BatchC1Exists, "DV: V2 batch C1 exists");
        require(C1x != 0 || C1y != 0, "DV: empty V2 batch C1");
        b.v2BatchC1Exists = true;
        b.v2BatchC1x = C1x;
        b.v2BatchC1y = C1y;
        emit V2BatchC1Set(b.fileId, batchId, C1x, C1y);
    }

    function getV2BatchC1(uint256 batchId) external view returns (bool exists, uint256 C1x, uint256 C1y) {
        Batch storage b = batches[batchId];
        return (b.v2BatchC1Exists, b.v2BatchC1x, b.v2BatchC1y);
    }

    // VaultMesh-aware function. ctSym must contain encrypted payload, e.g. encrypted JSON {cid, peerId}.
    function addEncCidToBatch(
        uint256 batchId,
        uint16 pieceIndex,
        uint256 C1x,
        uint256 C1y,
        bytes calldata C2,
        bytes calldata ctSym
    ) external {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        require(acl.isFileDataOwner(b.fileId, msg.sender), "DV: not file DO");
        require(currentCidIndexPlusOneByPiece[batchId][pieceIndex] == 0, "DV: active piece exists");

        _addEncCidToBatch(batchId, pieceIndex, C1x, C1y, C2, ctSym, false);
    }

    function addManyEncCidsToBatch(
        uint256 batchId,
        uint16[] calldata pieceIndices,
        uint256[] calldata C1xs,
        uint256[] calldata C1ys,
        bytes[] calldata C2s,
        bytes[] calldata ctSyms
    ) external returns (uint256 firstIndex, uint256 count) {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        require(acl.isFileDataOwner(b.fileId, msg.sender), "DV: not file DO");

        count = pieceIndices.length;
        require(count > 0, "DV: empty CID batch");
        require(C1xs.length == count, "DV: C1x length");
        require(C1ys.length == count, "DV: C1y length");
        require(C2s.length == count, "DV: C2 length");
        require(ctSyms.length == count, "DV: ctSym length");

        firstIndex = encCids.length;
        for (uint256 i = 0; i < count; i++) {
            _addEncCidToBatch(batchId, pieceIndices[i], C1xs[i], C1ys[i], C2s[i], ctSyms[i], false);
        }

        emit EncCidsBatchAdded(b.fileId, batchId, msg.sender, firstIndex, count);
    }

    function replaceEncCidForPiece(
        uint256 batchId,
        uint256 oldIndex,
        uint16 pieceIndex,
        uint256 C1x,
        uint256 C1y,
        bytes calldata C2,
        bytes calldata ctSym
    ) external returns (uint256 newIndex) {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        require(acl.isFileDataOwner(b.fileId, msg.sender), "DV: not file DO");
        require(oldIndex < encCids.length, "DV: bad old index");

        EncCid storage oldCid = encCids[oldIndex];
        require(oldCid.batchId == batchId, "DV: wrong batch");
        require(oldCid.pieceIndex == pieceIndex, "DV: wrong piece");
        require(oldCid.valid, "DV: old inactive");
        require(oldCid.replacedBy == 0, "DV: already replaced");

        newIndex = _addEncCidToBatch(batchId, pieceIndex, C1x, C1y, C2, ctSym, true);

        oldCid.valid = false;
        oldCid.replacedBy = newIndex + 1;
        currentCidIndexPlusOneByPiece[batchId][pieceIndex] = newIndex + 1;

        emit EncCidReplaced(b.fileId, batchId, msg.sender, oldIndex, newIndex, pieceIndex);
    }

    function invalidateEncCid(uint256 batchId, uint256 oldIndex) external {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        require(acl.isFileDataOwner(b.fileId, msg.sender), "DV: not file DO");
        require(oldIndex < encCids.length, "DV: bad old index");

        EncCid storage oldCid = encCids[oldIndex];
        require(oldCid.batchId == batchId, "DV: wrong batch");
        require(oldCid.valid, "DV: already inactive");

        oldCid.valid = false;

        uint16 pieceIndex = oldCid.pieceIndex;
        if (currentCidIndexPlusOneByPiece[batchId][pieceIndex] == oldIndex + 1) {
            currentCidIndexPlusOneByPiece[batchId][pieceIndex] = 0;
        }

        emit EncCidInvalidated(b.fileId, batchId, msg.sender, oldIndex, pieceIndex);
    }

    function _addEncCidToBatch(
        uint256 batchId,
        uint16 pieceIndex,
        uint256 C1x,
        uint256 C1y,
        bytes calldata C2,
        bytes calldata ctSym,
        bool replacing
    ) internal returns (uint256 index) {
        Batch storage b = batches[batchId];

        if (!replacing) {
            require(currentCidIndexPlusOneByPiece[batchId][pieceIndex] == 0, "DV: active piece exists");
        }

        index = encCids.length;

        encCids.push(
            EncCid({
                C1x: C1x,
                C1y: C1y,
                C2: C2,
                ctSym: ctSym,
                batchId: batchId,
                pieceIndex: pieceIndex,
                valid: true,
                replacedBy: 0
            })
        );

        b.cidIndices.push(index);
        currentCidIndexPlusOneByPiece[batchId][pieceIndex] = index + 1;

        emit EncCidAddedV2(b.fileId, index, batchId, msg.sender, pieceIndex, true);
    }

    function getEncCid(uint256 index)
    external
    view
    returns (uint256, uint256, bytes memory, bytes memory)
    {
        EncCid storage e = encCids[index];
        return (e.C1x, e.C1y, e.C2, e.ctSym);
    }

    function getEncCidV2(uint256 index)
    external
    view
    returns (
        uint256 C1x,
        uint256 C1y,
        bytes memory C2,
        bytes memory ctSym,
        uint256 batchId,
        uint16 pieceIndex,
        bool valid,
        uint256 replacedBy
    )
    {
        EncCid storage e = encCids[index];
        return (e.C1x, e.C1y, e.C2, e.ctSym, e.batchId, e.pieceIndex, e.valid, e.replacedBy);
    }

    function isEncCidValid(uint256 index) external view returns (bool) {
        if (index >= encCids.length) {
            return false;
        }
        return encCids[index].valid;
    }

    function getCurrentCidIndexForPiece(
        uint256 batchId,
        uint16 pieceIndex
    ) external view returns (bool exists, uint256 cidIndex) {
        uint256 plusOne = currentCidIndexPlusOneByPiece[batchId][pieceIndex];
        if (plusOne == 0) {
            return (false, 0);
        }
        return (true, plusOne - 1);
    }

    function getCount() external view returns (uint256) {
        return encCids.length;
    }

    function getBatch(uint256 batchId)
    external
    view
    returns (
        bytes32 fileId,
        address dataOwner,
        string memory dataId,
        uint64 ts,
        uint16 n,
        uint16 t,
        uint32 keyEpoch,
        uint256[] memory cidIndices
    )
    {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        return (
            b.fileId,
            b.dataOwner,
            b.dataId,
            b.ts,
            b.n,
            b.t,
            b.keyEpoch,
            _validCidIndicesForBatch(batchId)
        );
    }

    function getBatchAllCidIndices(uint256 batchId) external view returns (uint256[] memory cidIndices) {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        return b.cidIndices;
    }

    function getValidCidIndicesForBatch(uint256 batchId) external view returns (uint256[] memory cidIndices) {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: unknown batchId");
        return _validCidIndicesForBatch(batchId);
    }

    function _requestCidIndices(AccessRequest storage r) internal view returns (uint256[] memory cidIndices) {
        if (r.indices.length > 0) {
            return r.indices;
        }
        if (!r.exists || r.batchId == 0) {
            return new uint256[](0);
        }
        return _validCidIndicesForBatch(r.batchId);
    }

    function _validRecordsCount(uint256 batchId) internal view returns (uint256 count) {
        Batch storage b = batches[batchId];
        uint256 len = b.cidIndices.length;
        for (uint256 i = 0; i < len; i++) {
            if (encCids[b.cidIndices[i]].valid) {
                count++;
            }
        }
    }

    function _validDataPieceCount(uint256 batchId) internal view returns (uint256 count) {
        Batch storage b = batches[batchId];
        uint256 len = b.cidIndices.length;
        for (uint256 i = 0; i < len; i++) {
            EncCid storage e = encCids[b.cidIndices[i]];
            if (e.valid && e.pieceIndex != META_PIECE_INDEX) {
                count++;
            }
        }
    }

    function _validCidIndicesForBatch(uint256 batchId) internal view returns (uint256[] memory cidIndices) {
        Batch storage b = batches[batchId];
        uint256 count = _validRecordsCount(batchId);
        cidIndices = new uint256[](count);

        uint256 out = 0;
        uint256 len = b.cidIndices.length;
        for (uint256 i = 0; i < len; i++) {
            uint256 cidIndex = b.cidIndices[i];
            if (encCids[cidIndex].valid) {
                cidIndices[out] = cidIndex;
                out++;
            }
        }
    }

    function _validCidIndicesWithCheck(uint256 batchId, uint16 threshold)
        internal view returns (uint256[] memory cidIndices)
    {
        Batch storage b = batches[batchId];
        uint256 len = b.cidIndices.length;
        uint256 validTotal = 0;
        uint256 dataCount = 0;
        for (uint256 i = 0; i < len; i++) {
            EncCid storage e = encCids[b.cidIndices[i]];
            if (e.valid) {
                validTotal++;
                if (e.pieceIndex != META_PIECE_INDEX) dataCount++;
            }
        }
        require(dataCount >= threshold, "DV: not enough valid pieces");
        cidIndices = new uint256[](validTotal);
        uint256 out = 0;
        for (uint256 i = 0; i < len; i++) {
            uint256 cidIndex = b.cidIndices[i];
            if (encCids[cidIndex].valid) cidIndices[out++] = cidIndex;
        }
    }

    function getBatchIdForFile(bytes32 fileId) external view returns (bool exists, uint256 batchId) {
        uint256 id = batchIdByFileId[fileId];
        if (id == 0 || !batches[id].exists) {
            return (false, 0);
        }
        return (true, id);
    }

    function getBatchIdForFileData(
        bytes32 fileId,
        string calldata dataId,
        uint64 ts
    ) external view returns (bool exists, uint256 batchId) {
        bytes32 key = _fileBatchKey(fileId, dataId, ts);
        uint256 id = batchIdByFileKey[key];

        if (id == 0 || !batches[id].exists) {
            return (false, 0);
        }

        return (true, id);
    }

    function getBatchIdForFileAt(
        bytes32 fileId,
        uint256 index
    ) external view returns (bool exists, uint256 batchId) {
        if (index >= batchCountByFileId[fileId]) {
            return (false, 0);
        }

        uint256 id = batchIdByFileIdAndIndex[fileId][index];

        if (id == 0 || !batches[id].exists) {
            return (false, 0);
        }

        return (true, id);
    }

    function getBatchIdFor(
        string calldata dataId,
        uint64 ts
    ) external view returns (bool exists, uint256 batchId) {
        bytes32 key = _batchKey(dataId, ts);
        uint256 id = batchIdByKey[key];

        if (id == 0 || !batches[id].exists) {
            return (false, 0);
        }

        return (true, id);
    }

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
    )
    {
        AccessRequest storage r = accessRequests[requestId];

        if (!r.exists) {
            return (false, bytes32(0), address(0), 0, "", 0, 0, 0, 0, new uint256[](0));
        }

        return (
            r.exists,
            r.fileId,
            r.requester,
            r.batchId,
            r.dataId,
            r.ts,
            r.keyEpoch,
            r.pkReqX,
            r.pkReqY,
            _requestCidIndices(r)
        );
    }

    function getAccessRequestShareVersion(uint256 requestId) external view returns (uint32 shareVersion) {
        AccessRequest storage r = accessRequests[requestId];
        if (!r.exists) {
            return 0;
        }
        return r.shareVersion;
    }

    /// @notice Funding admits only a request whose access permission and PRE
    /// request flag still exist, including when preparation and payment differ.
    function isAccessRequestAuthorized(uint256 requestId) external view returns (bool) {
        AccessRequest storage r = accessRequests[requestId];
        PreRequestTiming storage timing = _preRequestTiming[requestId];
        return r.exists && (timing.admittedAt == 0 || block.timestamp <= timing.deadline) &&
            acl.isRequesterForFile(r.fileId, r.requester) && acl.hasRequestedReenc(r.requester);
    }

    function getAccessRequestTiming(uint256 requestId) external view returns (
        uint64 preparedAt, uint64 admittedAt, uint64 deadline
    ) {
        PreRequestTiming storage timing = _preRequestTiming[requestId];
        return (timing.preparedAt, timing.admittedAt, timing.deadline);
    }

    /// @dev Called only on the first deposit, in the same atomic transaction
    /// that checks full funding. A failed deposit rolls the timing back too.
    function admitAccessRequest(uint256 requestId) external {
        require(msg.sender == rewardManager && accessRequests[requestId].exists, "DV: not funding manager");
        PreRequestTiming storage timing = _preRequestTiming[requestId];
        require(timing.admittedAt == 0, "DV: already admitted");
        timing.admittedAt = uint64(block.timestamp);
        timing.deadline = _newPreDeadline();
        emit PreRequestAdmitted(requestId, timing.admittedAt, timing.deadline);
    }

    function _newPreDeadline() private view returns (uint64) {
        // DataVault.telg is the legacy ciphertext writer; V2 timing comes from
        // the V2 protocol bound in the ACL, as in the production deployment.
        uint256 end = block.timestamp + IPreDeadline_DataVault(acl.telgV2()).preDeadline();
        require(end <= type(uint64).max, "DV: deadline overflow");
        return uint64(end);
    }

    function getAccessRequestV2(uint256 requestId)
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
        uint32 shareVersion,
        uint256 pkReqX,
        uint256 pkReqY,
        uint256[] memory indices
    )
    {
        AccessRequest storage r = accessRequests[requestId];

        if (!r.exists) {
            return (false, bytes32(0), address(0), 0, "", 0, 0, 0, 0, 0, new uint256[](0));
        }

        return (
            r.exists,
            r.fileId,
            r.requester,
            r.batchId,
            r.dataId,
            r.ts,
            r.keyEpoch,
            r.shareVersion,
            r.pkReqX,
            r.pkReqY,
            _requestCidIndices(r)
        );
    }

    function findReusableRequestByFile(
        bytes32 fileId,
        uint256 pkReqX,
        uint256 pkReqY
    ) external view returns (bool found, uint256 requestId, uint256 batchId) {
        batchId = batchIdByFileId[fileId];

        if (batchId == 0 || !batches[batchId].exists) {
            return (false, 0, 0);
        }

        bytes32 rKey = _reuseKey(msg.sender, fileId, batchId, pkReqX, pkReqY);
        uint256 requestPlusOne = reusableRequestPlusOneByKey[rKey];

        if (requestPlusOne == 0) {
            return (false, 0, batchId);
        }

        requestId = requestPlusOne - 1;
        AccessRequest storage r = accessRequests[requestId];

        if (
            !r.exists ||
            r.requester != msg.sender ||
            r.fileId != fileId ||
            r.batchId != batchId ||
            r.pkReqX != pkReqX ||
            r.pkReqY != pkReqY ||
            _reencCids[requestId].length == 0
        ) {
            return (false, 0, batchId);
        }

        return (true, requestId, batchId);
    }

    function findReusableRequest(
        string calldata dataId,
        uint64 ts,
        uint256 pkReqX,
        uint256 pkReqY
    ) external view returns (bool found, uint256 requestId, uint256 batchId) {
        bytes32 bKey = _batchKey(dataId, ts);
        batchId = batchIdByKey[bKey];

        if (batchId == 0 || !batches[batchId].exists) {
            return (false, 0, 0);
        }

        Batch storage b = batches[batchId];
        bytes32 rKey = _reuseKey(msg.sender, b.fileId, batchId, pkReqX, pkReqY);
        uint256 requestPlusOne = reusableRequestPlusOneByKey[rKey];

        if (requestPlusOne == 0) {
            return (false, 0, batchId);
        }

        requestId = requestPlusOne - 1;
        AccessRequest storage r = accessRequests[requestId];

        if (
            !r.exists ||
            r.requester != msg.sender ||
            r.batchId != batchId ||
            r.pkReqX != pkReqX ||
            r.pkReqY != pkReqY ||
            _reencCids[requestId].length == 0
        ) {
            return (false, 0, batchId);
        }

        return (true, requestId, batchId);
    }

    function hasReencryptedCids(uint256 requestId) external view returns (bool) {
        return _reencCids[requestId].length > 0;
    }

    function getReencryptedCidsCount(uint256 requestId) external view returns (uint256) {
        return _reencCids[requestId].length;
    }

    function requestDataAccessByFile(
        bytes32 fileId,
        uint256 pkReqX,
        uint256 pkReqY
    ) external returns (uint256 requestId) {
        require(fileId != bytes32(0), "DV: empty fileId");
        require(acl.isRequesterForFile(fileId, msg.sender), "DV: requester not allowed");
        require(acl.hasRequestedReenc(msg.sender), "DV: reenc not requested");

        uint256 batchId = batchIdByFileId[fileId];
        require(batchId != 0, "DV: batch not found");

        Batch storage b = batches[batchId];
        require(b.exists, "DV: batch not found");

        requestId = _createAccessRequest(b, batchId, msg.sender, pkReqX, pkReqY);
    }

    function requestDataAccessByBatch(
        uint256 batchId,
        uint256 pkReqX,
        uint256 pkReqY
    ) external returns (uint256 requestId) {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: batch not found");
        require(acl.isRequesterForFile(b.fileId, msg.sender), "DV: requester not allowed");
        require(acl.hasRequestedReenc(msg.sender), "DV: reenc not requested");

        requestId = _createAccessRequest(b, batchId, msg.sender, pkReqX, pkReqY);
    }

    function requestDataAccessByBatchWithEscrow(
        uint256 batchId,
        uint256 pkReqX,
        uint256 pkReqY
    ) external payable returns (uint256 requestId) {
        Batch storage b = batches[batchId];
        require(b.exists, "DV: batch not found");
        require(acl.getFilePolicyMode(b.fileId) == IAccessControlFT_DataVault.DkgMode.ZKDKG_V2, "DV: not V2");
        require(acl.isRequesterForFile(b.fileId, msg.sender), "DV: requester not allowed");
        require(acl.hasRequestedReenc(msg.sender), "DV: reenc not requested");

        requestId = _createAccessRequest(b, batchId, msg.sender, pkReqX, pkReqY);
        _depositAccessEscrow(requestId, msg.sender, msg.value);
    }

    function requestDataAccessForFileData(
        bytes32 fileId,
        string calldata dataId,
        uint64 ts,
        uint256 pkReqX,
        uint256 pkReqY
    ) external returns (uint256 requestId) {
        require(fileId != bytes32(0), "DV: empty fileId");
        require(acl.isRequesterForFile(fileId, msg.sender), "DV: requester not allowed");
        require(acl.hasRequestedReenc(msg.sender), "DV: reenc not requested");

        bytes32 key = _fileBatchKey(fileId, dataId, ts);
        uint256 batchId = batchIdByFileKey[key];
        require(batchId != 0, "DV: batch not found");

        Batch storage b = batches[batchId];
        require(b.exists, "DV: batch not found");

        requestId = _createAccessRequest(b, batchId, msg.sender, pkReqX, pkReqY);
    }

    function requestDataAccessForFileDataWithEscrow(
        bytes32 fileId,
        string calldata dataId,
        uint64 ts,
        uint256 pkReqX,
        uint256 pkReqY
    ) external payable returns (uint256 requestId) {
        require(fileId != bytes32(0), "DV: empty fileId");
        require(acl.getFilePolicyMode(fileId) == IAccessControlFT_DataVault.DkgMode.ZKDKG_V2, "DV: not V2");
        require(acl.isRequesterForFile(fileId, msg.sender), "DV: requester not allowed");
        require(acl.hasRequestedReenc(msg.sender), "DV: reenc not requested");

        bytes32 key = _fileBatchKey(fileId, dataId, ts);
        uint256 batchId = batchIdByFileKey[key];
        require(batchId != 0, "DV: batch not found");

        Batch storage b = batches[batchId];
        require(b.exists, "DV: batch not found");

        requestId = _createAccessRequest(b, batchId, msg.sender, pkReqX, pkReqY);
        _depositAccessEscrow(requestId, msg.sender, msg.value);
    }

    function requestDataAccess(
        string calldata dataId,
        uint64 ts,
        uint256 pkReqX,
        uint256 pkReqY
    ) external returns (uint256 requestId) {
        bytes32 key = _batchKey(dataId, ts);
        uint256 batchId = batchIdByKey[key];
        require(batchId != 0, "DV: batch not found");

        Batch storage b = batches[batchId];
        require(b.exists, "DV: batch not found");
        require(acl.isRequesterForFile(b.fileId, msg.sender), "DV: requester not allowed");
        require(acl.hasRequestedReenc(msg.sender), "DV: reenc not requested");

        requestId = _createAccessRequest(b, batchId, msg.sender, pkReqX, pkReqY);
    }

    function _createAccessRequest(
        Batch storage b,
        uint256 batchId,
        address requester,
        uint256 pkReqX,
        uint256 pkReqY
    ) internal returns (uint256 requestId) {
        bool isV2 = acl.getFilePolicyMode(b.fileId) == IAccessControlFT_DataVault.DkgMode.ZKDKG_V2;
        if (isV2) {
            uint256 previous = _liveAccessRequestPlusOne[b.fileId][requester];
            require(previous == 0 || (rewardManager != address(0) &&
                IRewardManager_DataVault(rewardManager).isAccessEscrowComplete(previous - 1)),
                "DV: access request active");
        }
        uint256[] memory activeIndices = _validCidIndicesWithCheck(batchId, b.t);
        require(activeIndices.length > 0, "DV: no valid cids");

        requestId = nextAccessRequestId++;
        if (isV2) {
            _liveAccessRequestPlusOne[b.fileId][requester] = requestId + 1;
            _preRequestTiming[requestId] = PreRequestTiming(uint64(block.timestamp), 0, _newPreDeadline());
        }

        AccessRequest storage r = accessRequests[requestId];
        r.exists = true;
        r.fileId = b.fileId;
        r.requester = requester;
        r.batchId = batchId;
        r.dataId = b.dataId;
        r.ts = b.ts;
        r.keyEpoch = b.keyEpoch;
        r.shareVersion = _activeShareVersion(b.fileId, b.keyEpoch);
        r.pkReqX = pkReqX;
        r.pkReqY = pkReqY;

        emit DataAccessRequestedV2(
            b.fileId,
            requestId,
            requester,
            r.batchId,
            b.dataId,
            b.ts,
            b.keyEpoch,
            r.shareVersion,
            activeIndices,
            pkReqX,
            pkReqY
        );
    }

    function _depositAccessEscrow(uint256 requestId, address requester, uint256 amount) internal {
        require(amount > 0, "DV: empty access escrow");
        require(rewardManager != address(0), "DV: no RewardManager");
        IRewardManager_DataVault(rewardManager).depositAccessEscrowFor{value: amount}(requestId, requester);
    }

    function storeReencryptedCids(
        uint256 requestId,
        address requester,
        uint256[] calldata cidIndices,
        uint256[] calldata C1xPrime,
        uint256[] calldata C1yPrime,
        bytes[] calldata C2Prime
    ) external onlyTelg {
        AccessRequest storage req = accessRequests[requestId];

        require(req.exists, "DV: unknown requestId");
        require(req.requester == requester, "DV: requester mismatch");

        uint256[] memory expectedIndices = _requestCidIndices(req);
        uint256 len = cidIndices.length;

        require(len > 0, "DV: empty reenc");
        require(
            len == C1xPrime.length &&
            len == C1yPrime.length &&
            len == C2Prime.length,
            "DV: array length mismatch"
        );

        require(len == expectedIndices.length, "DV: incomplete reenc");

        ReencCid[] storage list = _reencCids[requestId];
        require(list.length == 0, "DV: reenc already stored");

        for (uint256 i = 0; i < len; i++) {
            require(cidIndices[i] == expectedIndices[i], "DV: wrong cid index");
            require(cidIndices[i] < encCids.length, "DV: bad cid index");
            require(encCids[cidIndices[i]].valid, "DV: inactive cid");

            list.push(
                ReencCid({
                    cidIndex: cidIndices[i],
                    C1xPrime: C1xPrime[i],
                    C1yPrime: C1yPrime[i],
                    C2Prime: C2Prime[i]
                })
            );
        }

        bytes32 rKey = _reuseKey(req.requester, req.fileId, req.batchId, req.pkReqX, req.pkReqY);
        reusableRequestPlusOneByKey[rKey] = requestId + 1;

        emit ReencryptedCidsStored(req.fileId, requestId, requester, len);
        emit ReusableRequestCached(rKey, req.fileId, requestId, requester, req.batchId);
    }

    function getReencryptedCids(uint256 requestId)
    external
    view
    returns (
        uint256[] memory cidIndices,
        uint256[] memory C1xPrime,
        uint256[] memory C1yPrime,
        bytes[] memory C2Prime
    )
    {
        ReencCid[] storage list = _reencCids[requestId];
        uint256 len = list.length;

        cidIndices = new uint256[](len);
        C1xPrime = new uint256[](len);
        C1yPrime = new uint256[](len);
        C2Prime = new bytes[](len);

        for (uint256 i = 0; i < len; i++) {
            ReencCid storage r = list[i];
            cidIndices[i] = r.cidIndex;
            C1xPrime[i] = r.C1xPrime;
            C1yPrime[i] = r.C1yPrime;
            C2Prime[i] = r.C2Prime;
        }
    }
}
