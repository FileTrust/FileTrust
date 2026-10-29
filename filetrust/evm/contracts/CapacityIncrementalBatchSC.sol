// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: CapacityIncrementalBatchSC
// Purpose:  Proving only the partitions that changed, instead of sweeping every one
//           of them every time.
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

import {ProofAuthorityDomains} from "./ProofAuthorityDomains.sol";

/// @notice Registered partition state, owned by CapacityProofSC. Field order and types mirror
///         `CapacityProofSC.PartitionAccount` exactly; this contract only READS it.
struct RegisteredPartitionAccount {
    address vk;
    uint8 kind;
    bool active;
    uint64 contentVersion;
    bytes32 contentHash;
    uint64 registeredBytes;
    uint64 provedVersion;
    bytes32 provedContentHash;
    uint64 provedBytes;
    uint64 provedRound;
    uint64 countedProofEpoch;
    uint64 registrationNonce;
    bytes32 versionAccountKey;
}

interface ICapacityProof_IB {
    function getPartitionAccount(bytes32 partitionKey)
        external view returns (RegisteredPartitionAccount memory);
    function certificationContract() external view returns (address);
    function partitionRegistrationNonce(address vk) external view returns (uint64);
    function storageProof() external view returns (address);
}

interface IStorageRound_IB {
    function currentRound() external view returns (uint64);
}

interface ICapacityCertification_IB {
    /// @dev The single canonical identity encoding in the whole system (frozen in G.1A).
    function certificationIdentityHash(
        bytes32 partitionKey,
        uint8 kind,
        bool active,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external pure returns (bytes32);
    function capacityProofSC() external view returns (address);
}

interface ISnapshotProofBinding_IB {
    function incrementalBatch() external view returns (address);
}

interface IVaultKeeperRegistry_IB {
    function isEligibleVaultKeeper(address vk) external view returns (bool);
}

/// @title CapacityIncrementalBatchSC
/// @notice Exact membership and completion for incremental capacity batches (G.2A).
///
/// G.2 recorded only `mode`, `selectedPartitions` and `selectedBytes` on the capacity epoch.
/// That is an AGGREGATE, and the on-chain membership rule underneath it stayed cutoff-based:
/// a batch that selected partition A could be completed by proving partition B instead, as
/// long as the count and byte totals still matched. This contract closes that hole by
/// committing to the exact identity of every selected partition and refusing to advance on
/// anything else.
///
/// Responsibilities — ONLY exact incremental membership and completion. It never certifies
/// capacity, never writes a full-sweep checkpoint, and duplicates no state owned by
/// CapacityCertificationSC (rolling certification, freshness, buckets, totals) or by
/// CapacityProofSC (full epochs, historical proof accounting, accepted-current decisions).
contract CapacityIncrementalBatchSC {
    /// @notice Mirrors CapacityProofSC.BATCH_MODE_INCREMENTAL. A batch here is always
    ///         incremental; the field is retained so an audit reads one vocabulary.
    uint8 public constant BATCH_REASON_INCREMENTAL = 1;

    /// @notice Bound on one batch so `openBatch` stays a bounded transaction.
    uint16 public constant MAX_SELECTED_MEMBERS = 512;

    /// @notice Maximum members in one batch.
    ///
    /// Measured, not guessed. `openBatch` costs ~114k gas per member (a cold
    /// `getPartitionAccount` staticcall, a pure identity-hash staticcall, two cold SSTOREs for
    /// the member record and the identity-seen flag, an array push and an event). 64 members
    /// measured 7,296,860 gas — 24.3% of a 30M block, which leaves too little margin on a
    /// chain with a lower limit. 32 members costs ~3.6M, about 12% of a 30M block, and:
    ///   * sits far above the observed dirty-partition count (D.1 mutated 1 of 13, and the
    ///     off-chain candidate threshold is well below 32), so ordinary traffic never chunks;
    ///   * keeps the safe-abandonment scan, which walks every unaccepted member, bounded;
    ///   * bounds recovery iteration to at most 32 snapshot lifecycles per chunk.
    uint16 public constant MAX_INCREMENTAL_BATCH_MEMBERS = 32;

    error NotOwner();
    error AlreadyBound();
    error InvalidAuthority();
    error ReciprocalWiringMismatch();
    error NotSnapshotProof();
    error NotEligibleVaultKeeper();
    error BatchAlreadyActive();
    error NoActiveBatch();
    error EmptySelection();
    error SelectionTooLarge();
    error DuplicateSelectedKey();
    error DuplicateSelectedIdentity();
    error InactiveSelectedPartition();
    error SelectedPartitionNotOwned();
    error IdentityNotRegistered();
    error NotSelectedIdentity();
    error BatchAccountingMismatch();
    error CampaignAlreadyActive();
    error NotCapacityProof();
    error NoCampaignToRelease();
    error CampaignKindMismatch();
    error LiveSelectedSnapshot();
    error BadAbandonReason();
    error BadFullSweepMode();
    error WrongBatchContext();

    /// @notice One frozen selected member. `identityHash` is the canonical G.1A hash of the
    ///         exact identity that, and only that, may satisfy this member.
    struct SelectedMember {
        bytes32 identityHash;
        uint64 committedBytes;
        uint8 kind;
        bool accepted;
    }

    struct Batch {
        uint64 batchId;
        address vk;
        uint64 targetRound;
        uint64 cutoffNonce;
        uint8 reason;
        uint32 selectedPartitions;
        uint32 acceptedPartitions;
        uint64 selectedBytes;
        uint64 acceptedBytes;
        bool active;
        bool completed;
    }

    /// @notice The single active capacity campaign per VK. A campaign is EITHER a full epoch
    ///         or an incremental batch — never both. Moving incremental batches out of
    ///         CapacityProofSC removed the single-active-epoch exclusion that contract gave
    ///         for free; this restores it as an explicit global invariant.
    enum CampaignKind { None, Full, Incremental }

    struct ActiveCampaign {
        CampaignKind kind;
        uint64 authorityId;
    }

    mapping(address => ActiveCampaign) public activeCampaign;

    /// @notice Explicit abandonment reasons. There is no unreasoned abandonment.
    uint8 public constant ABANDON_RECOVERY_UNCERTAIN = 1;
    uint8 public constant ABANDON_UNRECOVERABLE_SELECTED_SNAPSHOT = 2;
    uint8 public constant ABANDON_OPERATOR_AUDIT_RECOVERY = 3;
    uint8 public constant ABANDON_DEPLOYMENT_MIGRATION = 4;
    uint8 public constant ABANDON_REASON_MAX = 4;

    /// @notice Full-sweep modes (BATCH_MODE_* from G.2): 2 initial · 3 explicit_audit ·
    ///         4 migration · 5 recovery_uncertain · 6 freshness_recovery · 7 capacity_change.
    ///         Mode 1 is incremental and is never a full sweep.
    uint8 public constant FULL_SWEEP_MODE_MAX = 7;

    /// @notice The explicit reason each full sweep was opened with, by authority id. Every
    ///         opened campaign therefore still states its reason on chain.
    mapping(uint64 => uint8) public fullSweepModeOf;

    address public immutable owner;
    address public immutable capacityProof;
    address public immutable certification;
    address public vaultKeeperRegistry;

    /// @notice The only address permitted to accept a selected member. Set exactly once.
    address public snapshotProof;

    /// @notice RAW incremental sequence. The authority id is `INCREMENTAL_FLAG | sequence`;
    ///         the sequence itself never wraps or resets — exhaustion fails closed.
    uint64 public nextIncrementalSequence = 1;
    mapping(uint64 => Batch) public batches;
    mapping(address => uint64) public activeBatchIdOf;
    mapping(uint64 => mapping(bytes32 => SelectedMember)) internal batchMembers;
    mapping(uint64 => mapping(bytes32 => bool)) internal batchIdentitySeen;
    mapping(uint64 => bytes32[]) internal batchMemberKeys;

    event SnapshotProofBound(address indexed snapshotProof);
    event IncrementalBatchOpened(
        address indexed vk,
        uint64 indexed batchId,
        uint64 targetRound,
        uint64 cutoffNonce,
        uint32 selectedPartitions,
        uint64 selectedBytes
    );
    event IncrementalMemberSelected(
        uint64 indexed batchId, bytes32 indexed partitionKey, bytes32 identityHash, uint64 committedBytes
    );
    event IncrementalMemberAccepted(
        uint64 indexed batchId, bytes32 indexed partitionKey, bytes32 identityHash
    );
    event IncrementalBatchCompleted(
        address indexed vk, uint64 indexed batchId, uint32 acceptedPartitions, uint64 acceptedBytes
    );
    event IncrementalBatchAborted(address indexed vk, uint64 indexed batchId, uint32 acceptedPartitions);
    event CapacityCampaignClaimed(address indexed vk, CampaignKind kind, uint64 authorityId);
    event FullSweepCampaignClaimed(address indexed vk, uint64 indexed authorityId, uint8 mode);
    event CapacityCampaignReleased(address indexed vk, CampaignKind kind, uint64 authorityId);
    event IncrementalBatchAbandoned(
        address indexed vk, uint64 indexed batchId, uint8 reason, uint32 acceptedPartitions
    );

    /// @param capacityProof_ deployed CapacityProofSC. The certification contract is read from
    ///        it rather than supplied separately, so this contract cannot be pointed at a
    ///        certification contract the capacity contract does not itself use.
    constructor(address capacityProof_) {
        require(capacityProof_ != address(0), "IB: zero capacity proof");
        require(capacityProof_.code.length > 0, "IB: capacity proof has no code");
        address certification_ = ICapacityProof_IB(capacityProof_).certificationContract();
        require(certification_ != address(0) && certification_.code.length > 0,
                "IB: certification unreachable");
        require(ICapacityCertification_IB(certification_).capacityProofSC() == capacityProof_,
                "IB: certification pair not reciprocal");
        owner = msg.sender;
        capacityProof = capacityProof_;
        certification = certification_;
    }

    function setVaultKeeperRegistry(address registry) external {
        if (msg.sender != owner) revert NotOwner();
        require(vaultKeeperRegistry == address(0), "IB: registry already set");
        require(registry != address(0) && registry.code.length > 0, "IB: bad registry");
        vaultKeeperRegistry = registry;
    }

    /// @notice One-time, irreversible binding of the sole acceptance authority.
    function bindSnapshotProof(address snapshotProof_) external {
        if (msg.sender != owner) revert NotOwner();
        if (snapshotProof != address(0)) revert AlreadyBound();
        if (snapshotProof_ == address(0) || snapshotProof_.code.length == 0) revert InvalidAuthority();
        if (ISnapshotProofBinding_IB(snapshotProof_).incrementalBatch() != address(this)) {
            revert ReciprocalWiringMismatch();
        }
        snapshotProof = snapshotProof_;
        emit SnapshotProofBound(snapshotProof_);
    }

    modifier onlySnapshotProof() {
        if (snapshotProof == address(0) || msg.sender != snapshotProof) revert NotSnapshotProof();
        _;
    }

    // ─── batch creation ────────────────────────────────────────────────────────────────

    /// @notice Open an incremental batch over an EXACT selected set.
    /// @dev Count and bytes are DERIVED from the accepted list — never supplied by the caller —
    ///      and every selected identity is verified against current CapacityProofSC
    ///      registration state before it is frozen. After this returns the set is permanent.
    function openBatch(uint64 targetRound, bytes32[] calldata partitionKeys)
        external returns (uint64 batchId)
    {
        if (vaultKeeperRegistry == address(0) ||
            !IVaultKeeperRegistry_IB(vaultKeeperRegistry).isEligibleVaultKeeper(msg.sender)) {
            revert NotEligibleVaultKeeper();
        }
        if (activeBatchIdOf[msg.sender] != 0) revert BatchAlreadyActive();
        if (partitionKeys.length == 0) revert EmptySelection();
        if (partitionKeys.length > MAX_INCREMENTAL_BATCH_MEMBERS) revert SelectionTooLarge();
        require(targetRound == IStorageRound_IB(ICapacityProof_IB(capacityProof).storageProof()).currentRound(),
            "IB: target round is not current");

        // Claim the single per-VK capacity campaign BEFORE any member state is written, so a
        // rejected claim leaves nothing behind. A full epoch in flight blocks this outright.
        _claimCampaign(msg.sender, CampaignKind.Incremental, 0);

        uint64 sequence = nextIncrementalSequence;
        batchId = ProofAuthorityDomains.incrementalAuthorityId(sequence);
        nextIncrementalSequence = sequence + 1;
        activeCampaign[msg.sender].authorityId = batchId;

        uint64 selectedBytes;
        for (uint256 i = 0; i < partitionKeys.length; i++) {
            bytes32 key = partitionKeys[i];
            if (batchMembers[batchId][key].identityHash != bytes32(0)) revert DuplicateSelectedKey();

            RegisteredPartitionAccount memory account =
                ICapacityProof_IB(capacityProof).getPartitionAccount(key);
            // Ordered so the reported reason is the precise one: an inactive but registered
            // partition reports inactivity, not "not registered".
            if (account.vk == address(0)) revert IdentityNotRegistered();
            if (account.vk != msg.sender) revert SelectedPartitionNotOwned();
            if (!account.active) revert InactiveSelectedPartition();
            if (account.contentHash == bytes32(0)) revert IdentityNotRegistered();

            bytes32 identityHash = ICapacityCertification_IB(certification).certificationIdentityHash(
                key, account.kind, true, account.contentVersion, account.contentHash,
                account.registeredBytes
            );
            if (batchIdentitySeen[batchId][identityHash]) revert DuplicateSelectedIdentity();
            batchIdentitySeen[batchId][identityHash] = true;

            batchMembers[batchId][key] = SelectedMember({
                identityHash: identityHash,
                committedBytes: account.registeredBytes,
                kind: account.kind,
                accepted: false
            });
            batchMemberKeys[batchId].push(key);
            selectedBytes += account.registeredBytes;
            emit IncrementalMemberSelected(batchId, key, identityHash, account.registeredBytes);
        }

        uint64 cutoffNonce = ICapacityProof_IB(capacityProof).partitionRegistrationNonce(msg.sender);
        batches[batchId] = Batch({
            batchId: batchId,
            vk: msg.sender,
            targetRound: targetRound,
            cutoffNonce: cutoffNonce,
            reason: BATCH_REASON_INCREMENTAL,
            selectedPartitions: uint32(partitionKeys.length),
            acceptedPartitions: 0,
            selectedBytes: selectedBytes,
            acceptedBytes: 0,
            active: true,
            completed: false
        });
        activeBatchIdOf[msg.sender] = batchId;
        emit CapacityCampaignClaimed(msg.sender, CampaignKind.Incremental, batchId);
        emit IncrementalBatchOpened(
            msg.sender, batchId, targetRound, cutoffNonce,
            uint32(partitionKeys.length), selectedBytes
        );
    }

    /// @notice Safely abandon a stuck incremental batch and release the campaign.
    /// @dev Reachable ONLY through the bound proof-authority path, which has already verified
    ///      that no unaccepted selected member still holds a live frozen snapshot under this
    ///      batch's authority id. There is deliberately no force-unlock and no administrative
    ///      reset: a campaign lock can only be released by completion or by this checked route.
    ///
    ///      Abandonment certifies nothing, touches no full-sweep checkpoint, resets no accepted
    ///      historical proof, and erases no successor obligation — accepted members keep their
    ///      accepted flag and their accounting, and unaccepted members simply return to
    ///      ordinary successor work off chain.
    function abandonBatch(address vk, uint8 reason)
        external onlySnapshotProof returns (uint64 batchId)
    {
        if (reason == 0 || reason > ABANDON_REASON_MAX) revert BadAbandonReason();
        batchId = activeBatchIdOf[vk];
        if (batchId == 0) revert NoActiveBatch();
        Batch storage batch = batches[batchId];
        batch.active = false;
        activeBatchIdOf[vk] = 0;
        _releaseCampaign(vk, CampaignKind.Incremental);
        emit IncrementalBatchAbandoned(vk, batchId, reason, batch.acceptedPartitions);
        emit IncrementalBatchAborted(vk, batchId, batch.acceptedPartitions);
    }

    // ─── campaign lock ─────────────────────────────────────────────────────────────────

    /// @notice Claim the full-epoch campaign. Only CapacityProofSC may call this, and it does
    ///         so before its epoch becomes active — a rejected claim reverts the whole
    ///         `beginProofEpoch`, so no epoch state is written.
    /// @dev G.2B also moved full-sweep MODE validation and recording here, so CapacityProofSC
    ///      carries no batch-mode vocabulary at all and stays inside its size budget. Mode 1
    ///      (incremental) is refused: an incremental campaign is never a full epoch.
    function claimFullCampaign(address vk, uint64 authorityId, uint8 mode) external {
        if (msg.sender != capacityProof) revert NotCapacityProof();
        if (mode <= BATCH_REASON_INCREMENTAL || mode > FULL_SWEEP_MODE_MAX) revert BadFullSweepMode();
        // G.2B: the full-epoch id domain (bits 63..62 == 00) is validated HERE, so the single
        // canonical domain definition is applied in one place and CapacityProofSC carries no
        // namespace logic. A bad id reverts the claim, which reverts the whole beginProofEpoch.
        ProofAuthorityDomains.fullEpochAuthorityId(authorityId);
        _claimCampaign(vk, CampaignKind.Full, authorityId);
        fullSweepModeOf[authorityId] = mode;
        emit FullSweepCampaignClaimed(vk, authorityId, mode);
        emit CapacityCampaignClaimed(vk, CampaignKind.Full, authorityId);
    }

    /// @notice Release the full-epoch campaign on completion or abort. CapacityProofSC only.
    function releaseFullCampaign(address vk) external {
        if (msg.sender != capacityProof) revert NotCapacityProof();
        _releaseCampaign(vk, CampaignKind.Full);
    }

    function _claimCampaign(address vk, CampaignKind kind, uint64 authorityId) internal {
        ActiveCampaign storage campaign = activeCampaign[vk];
        if (campaign.kind != CampaignKind.None) revert CampaignAlreadyActive();
        campaign.kind = kind;
        campaign.authorityId = authorityId;
    }

    function _releaseCampaign(address vk, CampaignKind kind) internal {
        ActiveCampaign storage campaign = activeCampaign[vk];
        if (campaign.kind == CampaignKind.None) revert NoCampaignToRelease();
        if (campaign.kind != kind) revert CampaignKindMismatch();
        uint64 authorityId = campaign.authorityId;
        campaign.kind = CampaignKind.None;
        campaign.authorityId = 0;
        emit CapacityCampaignReleased(vk, kind, authorityId);
    }

    /// @notice The active campaign for a VK, read straight from chain truth on restart.
    function campaignOf(address vk) external view returns (CampaignKind kind, uint64 authorityId) {
        ActiveCampaign storage campaign = activeCampaign[vk];
        return (campaign.kind, campaign.authorityId);
    }

    // ─── membership gate ───────────────────────────────────────────────────────────────

    /// @notice Identity-only membership view. Proof authorization must also bind the
    ///         campaign and round through isSelectedPartitionFor:
    ///         an active batch exists, this partition is explicitly selected, the frozen
    ///         identity matches EXACTLY, and the member has not already been accepted.
    function isSelectedIdentity(address vk, bytes32 partitionKey, bytes32 identityHash)
        public view returns (bool)
    {
        uint64 batchId = activeBatchIdOf[vk];
        if (batchId == 0) return false;
        if (!batches[batchId].active) return false;
        SelectedMember storage member = batchMembers[batchId][partitionKey];
        if (member.identityHash == bytes32(0)) return false;
        if (member.identityHash != identityHash) return false;
        return !member.accepted;
    }

    /// @notice Convenience form for callers holding the raw identity fields.
    function isSelectedPartition(
        address vk,
        bytes32 partitionKey,
        uint8 kind,
        uint64 contentVersion,
        bytes32 contentHash,
        uint64 committedBytes
    ) external view returns (bool) {
        bytes32 identityHash = ICapacityCertification_IB(certification).certificationIdentityHash(
            partitionKey, kind, true, contentVersion, contentHash, committedBytes
        );
        return isSelectedIdentity(vk, partitionKey, identityHash);
    }

    // ─── acceptance and completion ─────────────────────────────────────────────────────

    /// @notice Membership with the exact campaign and round used by the proof.
    function isSelectedPartitionFor(
        address vk, bytes32 partitionKey, uint8 kind, uint64 contentVersion,
        bytes32 contentHash, uint64 committedBytes, uint64 authorityId, uint64 round
    ) external view returns (bool) {
        if (!_isActiveBatch(vk, authorityId, round)) return false;
        bytes32 identityHash = ICapacityCertification_IB(certification).certificationIdentityHash(
            partitionKey, kind, true, contentVersion, contentHash, committedBytes
        );
        return isSelectedIdentity(vk, partitionKey, identityHash);
    }

    function _isActiveBatch(address vk, uint64 authorityId, uint64 round) private view returns (bool) {
        Batch storage batch = batches[authorityId];
        ActiveCampaign storage campaign = activeCampaign[vk];
        return authorityId != 0 && activeBatchIdOf[vk] == authorityId &&
            batch.active && batch.vk == vk && batch.targetRound == round &&
            campaign.kind == CampaignKind.Incremental && campaign.authorityId == authorityId;
    }

    /// @notice Mark one EXACT selected identity accepted. Only the bound snapshot-proof
    ///         contract may call this, and only in the same transaction as the proof it
    ///         accepted — a revert here takes the proof accounting and the certification
    ///         update down with it.
    /// @dev A duplicate acceptance of the same member is a no-op: it does not increment the
    ///      accepted count or bytes, and cannot complete the batch a second time.
    function recordAcceptedMember(
        address vk, bytes32 partitionKey, bytes32 identityHash, uint64 batchId, uint64 round
    )
        external onlySnapshotProof returns (bool accepted)
    {
        Batch storage batch = batches[batchId];
        if (batch.vk != vk || batch.batchId == 0 || batch.targetRound != round) revert WrongBatchContext();

        SelectedMember storage member = batchMembers[batchId][partitionKey];
        if (member.identityHash == bytes32(0)) revert NotSelectedIdentity();
        if (member.identityHash != identityHash) revert NotSelectedIdentity();
        if (member.accepted) return false;                    // duplicate: nothing advances
        if (!_isActiveBatch(vk, batchId, round)) revert WrongBatchContext();

        member.accepted = true;
        batch.acceptedPartitions += 1;
        batch.acceptedBytes += member.committedBytes;
        emit IncrementalMemberAccepted(batchId, partitionKey, identityHash);

        // Completion is per-member: every selected identity has reached its accepted terminal
        // state. The aggregate byte total is only a consistency check on top of that.
        if (batch.acceptedPartitions == batch.selectedPartitions) {
            if (batch.acceptedBytes != batch.selectedBytes) revert BatchAccountingMismatch();
            batch.active = false;
            batch.completed = true;
            activeBatchIdOf[vk] = 0;
            _releaseCampaign(vk, CampaignKind.Incremental);
            emit IncrementalBatchCompleted(
                vk, batchId, batch.acceptedPartitions, batch.acceptedBytes
            );
        }
        return true;
    }

    // ─── views (restart reconstruction) ────────────────────────────────────────────────

    function getActiveBatch(address vk) external view returns (Batch memory) {
        return batches[activeBatchIdOf[vk]];
    }

    function selectedMemberKeys(uint64 batchId) external view returns (bytes32[] memory) {
        return batchMemberKeys[batchId];
    }

    function selectedMember(uint64 batchId, bytes32 partitionKey)
        external view returns (SelectedMember memory)
    {
        return batchMembers[batchId][partitionKey];
    }

    /// @notice Compact probe used by the safe-abandonment route.
    function selectedMemberAccepted(uint64 batchId, bytes32 partitionKey)
        external view returns (bool exists, bool accepted)
    {
        SelectedMember storage member = batchMembers[batchId][partitionKey];
        return (member.identityHash != bytes32(0), member.accepted);
    }

    function selectedMemberCount(uint64 batchId) external view returns (uint256) {
        return batchMemberKeys[batchId].length;
    }
}
