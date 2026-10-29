// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: AccessControlFT
// Purpose:  Who may read a file: its owner's policy, that policy's Guardians, and
//           the readers the owner has admitted.
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

interface IGuardianRegistryFT {
    function isActiveGuardian(address guardian) external view returns (bool);
    function getGuardianAvailability(address guardian) external view returns (uint256 maxServiceDays, bool unlimited, bool exists);
}

interface IRewardManagerFT {
    function hasV2DkgEscrow(bytes32 fileId) external view returns (bool);
}

interface IDkgLifecycleFT {
    function dkgKeyGenDeadline() external view returns (uint64);
    function hasPendingV2Refresh(bytes32 fileId) external view returns (bool);
    function getV2Key(bytes32 fileId) external view returns (bool, bool, address, uint8, uint8, uint32, uint32, uint256, uint256);
}

contract AccessControlFT is FileTrustOwnable, FileTrustDeprecatable {
    // enum Role { None=0, Shareholder=1, DataOwner=2, Requester=3 }
    enum Role {
        None,
        Shareholder,
        DataOwner,
        Requester
    }

    enum DkgMode {
        LEGACY,
        ZKDKG_V2
    }

    struct FileAccessPolicy {
        bool exists;
        bool active;
        address dataOwner;
        uint8 threshold;
        DkgMode mode;
        address[] selectedGuardians;
    }

    struct FilePolicyProposal {
        bool exists;
        uint8 threshold;
        address[] guardians;
    }

    // ---------------------------------------------------------------------
    // OLD state, kept for backward compatibility
    // ---------------------------------------------------------------------

    // account -> role
    mapping(address => Role) private _roles;

    // DO -> has requested TElG / DKG key
    mapping(address => bool) private _keyGenRequested;

    // Requester -> has requested re-encryption (PRE / TElG)
    mapping(address => bool) private _reencRequested;

    // DKG contract address
    address public dkg;
    address public dkgV2;

    // TElG / PRE contract address
    address public telg;
    address public telgV2;

    // ---------------------------------------------------------------------
    // NEW dynamic per-file access-control state
    // ---------------------------------------------------------------------

    address public guardianRegistry;
    address public rewardManager;

    mapping(bytes32 => FileAccessPolicy) private _filePolicies;
    mapping(bytes32 => FilePolicyProposal) private _filePolicyProposals;
    mapping(bytes32 => mapping(address => bool)) private _guardianForFile;
    mapping(bytes32 => mapping(address => bool)) private _requesterForFile;

    bytes32[] private _filePolicyIds;

    // Who may read a file, and which files an owner has, kept as lists.
    //
    // The mappings above answer "is this person allowed" but cannot answer "who
    // is allowed", and there was no per-owner index at all. Anyone needing
    // either had to replay RequesterAdded/Removed and FilePolicyCreated events
    // from the beginning of the chain. That is refused outright by chains
    // capping log ranges -- Cosmos allows 10,000 blocks -- and on a chain a few
    // years old it is not slow but impossible, which would leave an owner
    // returning after a long absence unable to recover what it owns.
    //
    // Holding the lists here makes both answerable in reads whose cost depends
    // on how many entries exist, never on the age of the chain.
    mapping(bytes32 => address[]) private _fileRequesterList;
    // 1-based position in the list above; 0 means absent. Lets a removal find
    // its entry without scanning.
    mapping(bytes32 => mapping(address => uint256)) private _fileRequesterIndex;
    mapping(address => bytes32[]) private _ownerPolicyIds;

    struct KeyGenFileRequest {
        bool requested;
        uint64 requestedAt;
    }

    // Optional per-file request flags. The current DKG script still uses the
    // legacy DO-level flag, but these are kept for the upgraded flow.
    mapping(bytes32 => KeyGenFileRequest) private _keyGenFileRequests;
    // Survives clearing a request: a retry is a different work context even
    // when it is still trying to create the same successful key epoch.
    mapping(bytes32 => uint64) public keyGenAttemptNonce;
    mapping(bytes32 => uint64) public keyGenDeadlineForFile;
    mapping(bytes32 => mapping(address => bool)) private _reencRequestedForFile;

    uint256 private constant MAX_ZKDKG_GUARDIANS = 20;

    // ---------------------------------------------------------------------
    // OLD events, kept
    // ---------------------------------------------------------------------

    event RoleUpdated(address indexed account, Role role);

    event KeyGenRequested(address indexed dataOwner);
    event KeyGenRequestCleared(address indexed dataOwner);

    event ReencRequested(address indexed requester);
    event ReencRequestCleared(address indexed requester);

    // ---------------------------------------------------------------------
    // NEW events
    // ---------------------------------------------------------------------

    event GuardianRegistrySet(address indexed guardianRegistry);
    event RewardManagerSet(address indexed rewardManager);
    event DkgSet(address indexed dkg);
    event DkgV2Set(address indexed dkgV2);
    event FilePolicyProposed(bytes32 indexed fileId, uint8 threshold, uint256 guardianCount);
    event TelgSet(address indexed telg);
    event TelgV2Set(address indexed telgV2);

    event FilePolicyCreated(
        bytes32 indexed fileId,
        address indexed dataOwner,
        uint8 threshold,
        uint256 guardianCount
    );

    event FilePolicyUpdated(
        bytes32 indexed fileId,
        address indexed dataOwner,
        uint8 threshold,
        uint256 guardianCount
    );

    event FilePolicyStatusChanged(bytes32 indexed fileId, bool active);
    event FilePolicyModeSet(bytes32 indexed fileId, DkgMode mode);

    event RequesterAddedToFile(bytes32 indexed fileId, address indexed requester);
    event RequesterRemovedFromFile(bytes32 indexed fileId, address indexed requester);

    event KeyGenRequestedForFile(bytes32 indexed fileId, address indexed dataOwner);
    event KeyGenRequestForFileCleared(bytes32 indexed fileId, address indexed dataOwner);
    event KeyGenRequestForFileExpired(bytes32 indexed fileId, address indexed dataOwner);

    event ReencRequestedForFile(bytes32 indexed fileId, address indexed requester);
    event ReencRequestForFileCleared(bytes32 indexed fileId, address indexed requester);

    // OZ v5 style Ownable
    constructor() Ownable(msg.sender) {}

    // ---------------------------------------------------------------------
    // DKG management, old + new compatible
    // ---------------------------------------------------------------------

    function setDkg(address _dkg) external onlyOwner {
        dkg = _dkg;
        emit DkgSet(_dkg);
    }

    function setDkgV2(address _dkgV2) external onlyOwner {
        dkgV2 = _dkgV2;
        emit DkgV2Set(_dkgV2);
    }

    modifier onlyDkg() {
        require(msg.sender == dkg || msg.sender == dkgV2, "ACL: not DKG");
        _;
    }

    // ---------------------------------------------------------------------
    // TElG / PRE management, old + new compatible
    // ---------------------------------------------------------------------

    function setTelg(address _telg) external onlyOwner {
        telg = _telg;
        emit TelgSet(_telg);
    }

    function setTelgV2(address _telgV2) external onlyOwner {
        telgV2 = _telgV2;
        emit TelgV2Set(_telgV2);
    }

    modifier onlyTelg() {
        require(msg.sender == telg || msg.sender == telgV2, "ACL: not TElG");
        _;
    }

    // ---------------------------------------------------------------------
    // GuardianRegistry wiring
    // ---------------------------------------------------------------------

    /// @notice Close this version to new file policies when its successor opens (Phase 2), for
    ///         good. Existing policies keep their requesters, updates,
    ///         key generation and re-encryption requests.
    function deprecate(address successor) external onlyOwner { _deprecate(successor); }

    function setGuardianRegistry(address _guardianRegistry) external onlyOwner {
        guardianRegistry = _guardianRegistry;
        emit GuardianRegistrySet(_guardianRegistry);
    }

    function setRewardManager(address _rewardManager) external onlyOwner {
        rewardManager = _rewardManager;
        emit RewardManagerSet(_rewardManager);
    }

    // ---------------------------------------------------------------------
    // OLD role management, kept exactly compatible with old JS scripts
    // ---------------------------------------------------------------------

    function setRole(address account, uint8 role) external onlyOwner {
        require(role <= uint8(Role.Requester), "ACL: invalid role");
        _roles[account] = Role(role);
        emit RoleUpdated(account, Role(role));
    }

    function getRole(address account) external view returns (Role) {
        return _roles[account];
    }

    function roleOf(address account) external view returns (Role) {
        return _roles[account];
    }

    function isShareholder(address account) public view returns (bool) {
        return _roles[account] == Role.Shareholder;
    }

    function isDataOwner(address account) public view returns (bool) {
        return _roles[account] == Role.DataOwner;
    }

    function isRequester(address account) public view returns (bool) {
        return _roles[account] == Role.Requester;
    }

    // ---------------------------------------------------------------------
    // OLD KeyGen request logic, kept
    // ---------------------------------------------------------------------

    /// @notice Called by a DO to request threshold key generation.
    function requestKeyGen() external {
        require(isDataOwner(msg.sender), "ACL: caller is not DO");
        _keyGenRequested[msg.sender] = true;
        emit KeyGenRequested(msg.sender);
    }

    /// @notice View used by DKG / DataVault to see if DO asked for a key.
    function hasRequestedKeyGen(address dataOwner) external view returns (bool) {
        return _keyGenRequested[dataOwner];
    }

    /// @notice Owner can clear the flag manually, old admin behavior.
    function clearKeyGenRequest(address dataOwner) external onlyOwner {
        require(_keyGenRequested[dataOwner], "ACL: no request");
        _keyGenRequested[dataOwner] = false;
        emit KeyGenRequestCleared(dataOwner);
    }

    /// @notice DKG clears the flag once key is stored. Required by old and current DKG.sol.
    function clearKeyGenRequestFromDKG(address dataOwner) external onlyDkg {
        require(_keyGenRequested[dataOwner], "ACL: no request");
        _keyGenRequested[dataOwner] = false;
        emit KeyGenRequestCleared(dataOwner);
    }

    // ---------------------------------------------------------------------
    // OLD Re-encryption request logic, kept
    // ---------------------------------------------------------------------

    /// @notice Called by a Requester to ask shareholders to perform re-encryption.
    function requestReenc() external {
        require(isRequester(msg.sender), "ACL: caller is not REQ");
        require(!_reencRequested[msg.sender], "ACL: reenc already requested");

        _reencRequested[msg.sender] = true;
        emit ReencRequested(msg.sender);
    }

    /// @notice View used by DataVault / TElG to see if requester asked for PRE.
    function hasRequestedReenc(address requester) external view returns (bool) {
        return _reencRequested[requester];
    }

    /// @notice Owner can clear the re-encryption flag manually, old admin behavior.
    function clearReencRequest(address requester) external onlyOwner {
        require(_reencRequested[requester], "ACL: no reenc request");
        _reencRequested[requester] = false;
        emit ReencRequestCleared(requester);
    }

    /// @notice TElG/PRE contract clears the flag once re-encryption is handled.
    function clearReencRequestFromTElg(address requester) external onlyTelg {
        require(_reencRequested[requester], "ACL: no reenc request");
        _reencRequested[requester] = false;
        emit ReencRequestCleared(requester);
    }

    // ---------------------------------------------------------------------
    // NEW dynamic per-file policy logic
    // ---------------------------------------------------------------------

    /// @notice Any normal wallet can become DO by creating its first file policy.
    /// @param doInput  Caller-chosen 32-byte seed. The on-chain fileId is derived as
    ///                 keccak256(abi.encodePacked(msg.sender, doInput)) so no two DOs
    ///                 can occupy the same policy slot regardless of their chosen seed.
    ///                 DO can compute the resulting fileId off-chain before calling.
    function createFilePolicy(
        bytes32 doInput,
        address[] calldata selectedGuardians,
        uint8 threshold
    ) external returns (bytes32 fileId) {
        fileId = _createFilePolicy(doInput, selectedGuardians, threshold, DkgMode.LEGACY, 0);
    }

    function createFilePolicyWithMode(
        bytes32 doInput,
        address[] calldata selectedGuardians,
        uint8 threshold,
        DkgMode mode,
        uint256 serviceDays
    ) external returns (bytes32 fileId) {
        fileId = _createFilePolicy(doInput, selectedGuardians, threshold, mode, serviceDays);
    }

    function _createFilePolicy(
        bytes32 doInput,
        address[] calldata selectedGuardians,
        uint8 threshold,
        DkgMode mode,
        uint256 serviceDays
    ) internal returns (bytes32 fileId) {
        _requireNotDeprecated();
        require(doInput != bytes32(0), "ACL: empty doInput");
        fileId = keccak256(abi.encodePacked(msg.sender, doInput));
        require(!_filePolicies[fileId].exists, "ACL: policy exists");

        // Dynamic DO registration. This replaces the old need to run setRole(DO, 2)
        // before the DO creates a file policy.
        if (_roles[msg.sender] == Role.None) {
            _roles[msg.sender] = Role.DataOwner;
            emit RoleUpdated(msg.sender, Role.DataOwner);
        }

        require(_roles[msg.sender] == Role.DataOwner, "ACL: caller role conflict");
        _validatePolicyModeCommittee(mode, selectedGuardians.length, threshold);

        _validateGuardianList(selectedGuardians, threshold, serviceDays);

        FileAccessPolicy storage policy = _filePolicies[fileId];
        policy.exists = true;
        policy.active = true;
        policy.dataOwner = msg.sender;
        policy.threshold = threshold;
        policy.mode = mode;

        _filePolicyIds.push(fileId);
        _ownerPolicyIds[msg.sender].push(fileId);

        for (uint256 i = 0; i < selectedGuardians.length; i++) {
            address guardian = selectedGuardians[i];
            policy.selectedGuardians.push(guardian);
            _guardianForFile[fileId][guardian] = true;
        }

        emit FilePolicyCreated(fileId, msg.sender, threshold, selectedGuardians.length);
        emit FilePolicyModeSet(fileId, mode);
    }

    function updateFilePolicy(
        bytes32 fileId,
        address[] calldata selectedGuardians,
        uint8 threshold,
        uint256 serviceDays
    ) external {
        require(_filePolicies[fileId].exists, "ACL: file policy missing");
        require(_filePolicies[fileId].dataOwner == msg.sender, "ACL: caller is not file DO");
        if (_filePolicies[fileId].mode == DkgMode.ZKDKG_V2) {
            require(!_keyGenFileRequests[fileId].requested, "ACL: keygen pending");
        }
        _validatePolicyModeCommittee(_filePolicies[fileId].mode, selectedGuardians.length, threshold);
        if (_filePolicies[fileId].mode == DkgMode.ZKDKG_V2 && dkgV2 != address(0)) {
            require(!IDkgLifecycleFT(dkgV2).hasPendingV2Refresh(fileId), "ACL: refresh pending");
        }

        _validateGuardianListForUpdate(selectedGuardians, threshold, serviceDays);

        if (_filePolicies[fileId].mode == DkgMode.ZKDKG_V2 && dkgV2.code.length != 0) {
            (bool keyExists, bool finalized, , , , , , , ) = IDkgLifecycleFT(dkgV2).getV2Key(fileId);
            if (keyExists && finalized) {
                FilePolicyProposal storage proposal = _filePolicyProposals[fileId];
                proposal.exists = true; proposal.threshold = threshold;
                proposal.guardians = selectedGuardians;
                emit FilePolicyProposed(fileId, threshold, selectedGuardians.length);
                return;
            }
        }

        _applyFileCommittee(fileId, selectedGuardians, threshold);
    }

    function _applyFileCommittee(bytes32 fileId, address[] memory selectedGuardians, uint8 threshold) internal {

        FileAccessPolicy storage policy = _filePolicies[fileId];

        for (uint256 i = 0; i < policy.selectedGuardians.length; i++) {
            _guardianForFile[fileId][policy.selectedGuardians[i]] = false;
        }

        delete policy.selectedGuardians;

        for (uint256 i = 0; i < selectedGuardians.length; i++) {
            address guardian = selectedGuardians[i];
            policy.selectedGuardians.push(guardian);
            _guardianForFile[fileId][guardian] = true;
        }

        policy.threshold = threshold;

        emit FilePolicyUpdated(fileId, policy.dataOwner, threshold, selectedGuardians.length);
    }

    /// @notice The active policy remains unchanged while DKG prepares a
    /// proposed committee. Only successful key activation applies it.
    function getDkgFilePolicy(bytes32 fileId) external view returns (bool exists, bool active, address dataOwner, uint8 threshold, address[] memory guardians) {
        FileAccessPolicy storage p = _filePolicies[fileId];
        FilePolicyProposal storage proposal = _filePolicyProposals[fileId];
        return (p.exists, p.active, p.dataOwner, proposal.exists ? proposal.threshold : p.threshold,
            proposal.exists ? proposal.guardians : p.selectedGuardians);
    }

    function activateV2FilePolicy(bytes32 fileId, uint8 threshold, bytes32 guardiansHash) external {
        require(msg.sender == dkgV2 && _filePolicies[fileId].mode == DkgMode.ZKDKG_V2, "ACL: not V2 DKG");
        FilePolicyProposal storage proposal = _filePolicyProposals[fileId];
        if (proposal.exists) {
            require(proposal.threshold == threshold && keccak256(abi.encode(proposal.guardians)) == guardiansHash, "ACL: proposal changed");
            _applyFileCommittee(fileId, proposal.guardians, threshold);
            delete _filePolicyProposals[fileId];
        } else {
            FileAccessPolicy storage p = _filePolicies[fileId];
            require(p.threshold == threshold && keccak256(abi.encode(p.selectedGuardians)) == guardiansHash, "ACL: committee changed");
        }
    }

    function setFilePolicyActive(bytes32 fileId, bool active) external {
        require(_filePolicies[fileId].exists, "ACL: file policy missing");
        require(_filePolicies[fileId].dataOwner == msg.sender, "ACL: caller is not file DO");
        if (_filePolicies[fileId].mode == DkgMode.ZKDKG_V2 && !active) {
            require(!_keyGenFileRequests[fileId].requested, "ACL: keygen pending");
            require(dkgV2 == address(0) || !IDkgLifecycleFT(dkgV2).hasPendingV2Refresh(fileId), "ACL: refresh pending");
        }

        _filePolicies[fileId].active = active;
        emit FilePolicyStatusChanged(fileId, active);
    }

    function addRequesterToFile(bytes32 fileId, address requester) external {
        require(_filePolicies[fileId].exists, "ACL: file policy missing");
        require(_filePolicies[fileId].dataOwner == msg.sender, "ACL: caller is not file DO");
        require(requester != address(0), "ACL: zero requester");

        _requesterForFile[fileId][requester] = true;
        // Keep the list in step, and only once: adding the same requester twice
        // must not leave two entries behind.
        if (_fileRequesterIndex[fileId][requester] == 0) {
            _fileRequesterList[fileId].push(requester);
            _fileRequesterIndex[fileId][requester] = _fileRequesterList[fileId].length;
        }

        // Dynamic requester registration for old compatibility.
        if (_roles[requester] == Role.None) {
            _roles[requester] = Role.Requester;
            emit RoleUpdated(requester, Role.Requester);
        }

        emit RequesterAddedToFile(fileId, requester);
    }

    function removeRequesterFromFile(bytes32 fileId, address requester) external {
        require(_filePolicies[fileId].exists, "ACL: file policy missing");
        require(_filePolicies[fileId].dataOwner == msg.sender, "ACL: caller is not file DO");
        require(requester != address(0), "ACL: zero requester");

        _requesterForFile[fileId][requester] = false;
        // Drop it from the list by moving the last entry into its place, so a
        // removal costs the same whether the file has three readers or three
        // thousand.
        uint256 position = _fileRequesterIndex[fileId][requester];
        if (position != 0) {
            address[] storage list = _fileRequesterList[fileId];
            uint256 lastIndex = list.length - 1;
            uint256 targetIndex = position - 1;
            if (targetIndex != lastIndex) {
                address moved = list[lastIndex];
                list[targetIndex] = moved;
                _fileRequesterIndex[fileId][moved] = position;
            }
            list.pop();
            _fileRequesterIndex[fileId][requester] = 0;
        }
        emit RequesterRemovedFromFile(fileId, requester);
    }

    // ---------------------------------------------------------------------
    // NEW optional per-file request flags
    // ---------------------------------------------------------------------

    function requestKeyGenForFile(bytes32 fileId) external {
        // Legacy requests without a nonce must not be replayable into a retry.
        if (_filePolicies[fileId].mode == DkgMode.ZKDKG_V2) {
            require(keyGenAttemptNonce[fileId] == 0, "ACL: use nonce-aware request");
        }
        _requestKeyGenForFile(fileId);
    }

    function requestKeyGenForFileWithNonce(bytes32 fileId, uint64 previousNonce) external {
        require(keyGenAttemptNonce[fileId] == previousNonce, "ACL: request nonce changed");
        _requestKeyGenForFile(fileId);
    }

    function _requestKeyGenForFile(bytes32 fileId) internal {
        require(_filePolicies[fileId].exists, "ACL: file policy missing");
        require(_filePolicies[fileId].active, "ACL: policy inactive");
        require(_filePolicies[fileId].dataOwner == msg.sender, "ACL: caller is not file DO");
        if (_filePolicies[fileId].mode == DkgMode.ZKDKG_V2) {
            require(!_keyGenFileRequests[fileId].requested, "ACL: keygen pending");
            FilePolicyProposal storage proposal = _filePolicyProposals[fileId];
            require(proposal.exists ? proposal.guardians.length >= proposal.threshold
                : _filePolicies[fileId].selectedGuardians.length >= _filePolicies[fileId].threshold, "ACL: empty DKG committee");
            require(dkgV2.code.length > 0, "ACL: DKG not configured");
            require(!IDkgLifecycleFT(dkgV2).hasPendingV2Refresh(fileId), "ACL: refresh pending");
            uint256 deadline = block.timestamp + IDkgLifecycleFT(dkgV2).dkgKeyGenDeadline();
            require(deadline > block.timestamp && deadline <= type(uint64).max, "ACL: invalid DKG deadline");
            keyGenDeadlineForFile[fileId] = uint64(deadline);
        }
        // V2 work is funded in its own attempt escrow after this nonce is
        // allocated, then starts only after every assigned duty is accepted.
        // Policy-wide balances must not fund or charge a different retry.

        _keyGenRequested[msg.sender] = true;
        _keyGenFileRequests[fileId].requested = true;
        _keyGenFileRequests[fileId].requestedAt = uint64(block.timestamp);
        ++keyGenAttemptNonce[fileId];

        emit KeyGenRequested(msg.sender);
        emit KeyGenRequestedForFile(fileId, msg.sender);
    }

    function hasRequestedKeyGenForFile(bytes32 fileId) external view returns (bool) {
        return _keyGenFileRequests[fileId].requested;
    }

    function getKeyGenRequestedAtForFile(bytes32 fileId) external view returns (uint64) {
        return _keyGenFileRequests[fileId].requestedAt;
    }

    function clearKeyGenRequestForFileFromDKG(bytes32 fileId) external onlyDkg {
        require(_filePolicies[fileId].exists, "ACL: file policy missing");
        if (_filePolicies[fileId].mode == DkgMode.ZKDKG_V2) require(msg.sender == dkgV2, "ACL: not V2 DKG");

        address dataOwner = _filePolicies[fileId].dataOwner;
        delete _keyGenFileRequests[fileId];
        _keyGenRequested[dataOwner] = false;

        emit KeyGenRequestForFileCleared(fileId, dataOwner);
        emit KeyGenRequestCleared(dataOwner);
    }

    function requestReencForFile(bytes32 fileId) external {
        require(isRequesterForFile(fileId, msg.sender), "ACL: requester not allowed");

        _reencRequested[msg.sender] = true;
        _reencRequestedForFile[fileId][msg.sender] = true;

        emit ReencRequested(msg.sender);
        emit ReencRequestedForFile(fileId, msg.sender);
    }

    function hasRequestedReencForFile(
        bytes32 fileId,
        address requester
    ) external view returns (bool) {
        return _reencRequestedForFile[fileId][requester];
    }

    function clearReencRequestForFileFromTElg(
        bytes32 fileId,
        address requester
    ) external onlyTelg {
        _reencRequestedForFile[fileId][requester] = false;
        _reencRequested[requester] = false;

        emit ReencRequestForFileCleared(fileId, requester);
        emit ReencRequestCleared(requester);
    }

    // ---------------------------------------------------------------------
    // NEW per-file read helpers
    // ---------------------------------------------------------------------

    function getFilePolicy(
        bytes32 fileId
    )
    external
    view
    returns (
        bool exists,
        bool active,
        address dataOwner,
        uint8 threshold,
        address[] memory selectedGuardians
    )
    {
        FileAccessPolicy storage policy = _filePolicies[fileId];

        return (
            policy.exists,
            policy.active,
            policy.dataOwner,
            policy.threshold,
            policy.selectedGuardians
        );
    }

    function getFilePolicyMode(bytes32 fileId) external view returns (DkgMode) {
        require(_filePolicies[fileId].exists, "ACL: file policy missing");
        return _filePolicies[fileId].mode;
    }

    function getGuardiansForFile(bytes32 fileId) external view returns (address[] memory) {
        return _filePolicies[fileId].selectedGuardians;
    }

    function getFilePolicyCount() external view returns (uint256) {
        return _filePolicyIds.length;
    }

    /// @notice How many requesters may currently read this file.
    function getFileRequesterCount(bytes32 fileId) external view returns (uint256) {
        return _fileRequesterList[fileId].length;
    }

    /// @notice One page of the requesters who may currently read this file.
    /// @dev Answers a question the mappings could not: they say whether a given
    /// address is allowed, not who is. Without this, listing readers meant
    /// replaying every add and remove from the start of the chain. Order is not
    /// stable -- removals move the last entry into the gap -- so a caller
    /// walking pages while entries are removed should treat the result as a set.
    function getFileRequesterPage(bytes32 fileId, uint256 offset, uint256 limit)
        external
        view
        returns (address[] memory page)
    {
        return _slice(_fileRequesterList[fileId], offset, limit);
    }

    /// @notice How many file policies this data owner has created.
    function getOwnerPolicyCount(address dataOwner) external view returns (uint256) {
        return _ownerPolicyIds[dataOwner].length;
    }

    /// @notice One page of the file ids this data owner has created.
    /// @dev What lets an owner returning after a long absence recover what it
    /// owns in a few reads, instead of replaying the chain from the beginning --
    /// which on a chain years old cannot be done at all.
    function getOwnerPolicyPage(address dataOwner, uint256 offset, uint256 limit)
        external
        view
        returns (bytes32[] memory page)
    {
        bytes32[] storage ids = _ownerPolicyIds[dataOwner];
        uint256 total = ids.length;
        if (offset >= total || limit == 0) {
            return new bytes32[](0);
        }
        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }
        page = new bytes32[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = ids[i];
        }
    }

    /// @dev Shared paging for address lists. Returns a short page at the end of
    /// the list rather than reverting, so a caller racing a write does not fail.
    function _slice(address[] storage list, uint256 offset, uint256 limit)
        private
        view
        returns (address[] memory page)
    {
        uint256 total = list.length;
        if (offset >= total || limit == 0) {
            return new address[](0);
        }
        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }
        page = new address[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            page[i - offset] = list[i];
        }
    }

    function getFileCount() external view returns (uint256) {
        return _filePolicyIds.length;
    }

    function getFileIdAt(uint256 index) external view returns (bytes32) {
        return _filePolicyIds[index];
    }

    function getAllFileIds() external view returns (bytes32[] memory) {
        return _filePolicyIds;
    }

    function isFileDataOwner(bytes32 fileId, address account) public view returns (bool) {
        return _filePolicies[fileId].exists && _filePolicies[fileId].dataOwner == account;
    }

    function isFilePolicyActive(bytes32 fileId) external view returns (bool) {
        return _filePolicies[fileId].exists && _filePolicies[fileId].active;
    }

    function isGuardianForFile(bytes32 fileId, address guardian) public view returns (bool) {
        return (
            _filePolicies[fileId].exists &&
            _filePolicies[fileId].active &&
            _guardianForFile[fileId][guardian]
        );
    }

    function isRequesterForFile(bytes32 fileId, address requester) public view returns (bool) {
        return (
            _filePolicies[fileId].exists &&
            _filePolicies[fileId].active &&
            _requesterForFile[fileId][requester]
        );
    }

    function isRequesterAllowedForFile(
        bytes32 fileId,
        address requester
    ) external view returns (bool) {
        return isRequesterForFile(fileId, requester);
    }

    function isSupportedZkDkgGuardianCount(uint256 guardianCount) public pure returns (bool) {
        return (
            guardianCount == 3 ||
            guardianCount == 5 ||
            guardianCount == 7 ||
            guardianCount == 10 ||
            guardianCount == 15 ||
            guardianCount == 20
        );
    }

    // ---------------------------------------------------------------------
    // Internal validation
    // ---------------------------------------------------------------------

    function _validatePolicyModeCommittee(
        DkgMode mode,
        uint256 guardianCount,
        uint8 threshold
    ) internal pure {
        if (mode != DkgMode.ZKDKG_V2) return;
        if (guardianCount == 0) return;
        require(threshold >= 2, "ACL: zkdkg threshold too low");
        require(guardianCount <= MAX_ZKDKG_GUARDIANS, "ACL: too many guardians");
        require(isSupportedZkDkgGuardianCount(guardianCount), "ACL: unsupported guardian count");
    }

    function _validateGuardianListForUpdate(
        address[] calldata selectedGuardians,
        uint8 threshold,
        uint256 serviceDays
    ) internal view {
        require(threshold > 0, "ACL: threshold zero");
        require(
            selectedGuardians.length == 0 || threshold <= selectedGuardians.length,
            "ACL: threshold too high"
        );
        for (uint256 i = 0; i < selectedGuardians.length; i++) {
            address guardian = selectedGuardians[i];
            require(guardian != address(0), "ACL: zero guardian");

            if (guardianRegistry != address(0)) {
                require(
                    IGuardianRegistryFT(guardianRegistry).isActiveGuardian(guardian),
                        "ACL: guardian not active"
                );
                if (serviceDays > 0) {
                    try IGuardianRegistryFT(guardianRegistry).getGuardianAvailability(guardian)
                        returns (uint256 maxServiceDays, bool, bool exists)
                    {
                        require(
                            !exists || maxServiceDays == 0 || serviceDays <= maxServiceDays,
                            "ACL: guardian unavailable for service duration"
                        );
                    } catch {}
                }
            } else {
                require(isShareholder(guardian), "ACL: guardian not shareholder");
            }

            for (uint256 j = i + 1; j < selectedGuardians.length; j++) {
                require(selectedGuardians[j] != guardian, "ACL: duplicate guardian");
            }
        }
    }

    function _validateGuardianList(
        address[] calldata selectedGuardians,
        uint8 threshold,
        uint256 serviceDays
    ) internal view {
        require(selectedGuardians.length > 0, "ACL: no guardians");
        require(threshold > 0, "ACL: threshold zero");
        require(threshold <= selectedGuardians.length, "ACL: threshold too high");
        for (uint256 i = 0; i < selectedGuardians.length; i++) {
            address guardian = selectedGuardians[i];
            require(guardian != address(0), "ACL: zero guardian");

            if (guardianRegistry != address(0)) {
                require(
                    IGuardianRegistryFT(guardianRegistry).isActiveGuardian(guardian),
                        "ACL: guardian not active"
                );
                if (serviceDays > 0) {
                    try IGuardianRegistryFT(guardianRegistry).getGuardianAvailability(guardian)
                        returns (uint256 maxServiceDays, bool, bool exists)
                    {
                        require(
                            !exists || maxServiceDays == 0 || serviceDays <= maxServiceDays,
                            "ACL: guardian unavailable for service duration"
                        );
                    } catch {}
                }
            } else {
                require(isShareholder(guardian), "ACL: guardian not shareholder");
            }

            for (uint256 j = i + 1; j < selectedGuardians.length; j++) {
                require(selectedGuardians[j] != guardian, "ACL: duplicate guardian");
            }
        }
    }
}
