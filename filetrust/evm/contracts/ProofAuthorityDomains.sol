// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: ProofAuthorityDomains
// Purpose:  The three kinds of proof authority are given permanently separate id
//           spaces, so no proof can ever be replayed as another kind.
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

/// @title ProofAuthorityDomains
/// @notice THE canonical definition of the `proofEpochId` namespace (G.2B).
///
/// `proofEpochId` is the authority under which a partition snapshot is frozen, proven,
/// reanchored or abandoned. Three unrelated producers write into it:
///
///   * full capacity epochs      — `CapacityProofSC.beginProofEpoch`, VK-chosen id
///   * incremental capacity batches — `CapacityIncrementalBatchSC.openBatch`, contract-issued
///   * deletion-successor proofs  — `DELETION_FLAG | contentVersion`, caller-constructed
///
/// and several consumers key state by it, most importantly
/// `StorageProofSC.snapshotEpochContent[partitionKey][proofEpochId]`, which pins the content
/// accepted under that authority. Two producers sharing a value therefore corrupt each other.
///
/// G.2A separated incremental ids by starting them at `1 << 32`. That is NOT a permanent
/// namespace: a full epoch id is VK-chosen and bounded only by `< 1 << 63`, so a VK can simply
/// choose `(1 << 32) + n` and collide. This library replaces that threshold with permanent,
/// mutually exclusive BIT domains:
///
///   bit 63 = 1              → deletion authority   (any lower bits)
///   bit 63 = 0, bit 62 = 1  → incremental capacity batch
///   bits 63..62 = 00        → full capacity epoch
///
/// Every contract and script uses these constants. There is no second definition, and no
/// consumer classifies a domain by magnitude.
library ProofAuthorityDomains {
    /// @notice Deletion-successor proofs. Historically `STANDALONE_DELETION_PROOF_FLAG`.
    uint64 internal constant DELETION_FLAG = uint64(1) << 63;
    /// @notice Incremental capacity batches.
    uint64 internal constant INCREMENTAL_FLAG = uint64(1) << 62;
    /// @notice Exclusive upper bound on the RAW sequence of a full epoch or an incremental
    ///         batch. Both raw sequences must satisfy `0 < raw < FULL_ID_LIMIT`, which keeps
    ///         bits 63 and 62 free to carry the domain.
    uint64 internal constant FULL_ID_LIMIT = uint64(1) << 62;

    error FullEpochIdOutOfDomain(uint64 rawId);
    error IncrementalSequenceOutOfDomain(uint64 rawSequence);
    error InvalidDeletionContentVersion(uint64 contentVersion);

    /// @notice Authority id of a full capacity epoch. The raw id IS the authority id; the
    ///         bound is what keeps it out of the incremental and deletion domains.
    function fullEpochAuthorityId(uint64 rawFullEpochId) internal pure returns (uint64) {
        if (rawFullEpochId == 0 || rawFullEpochId >= FULL_ID_LIMIT) {
            revert FullEpochIdOutOfDomain(rawFullEpochId);
        }
        return rawFullEpochId;
    }

    /// @notice Authority id of an incremental capacity batch.
    /// @dev Fails closed on sequence exhaustion: no wrap, no reset, no reuse.
    function incrementalAuthorityId(uint64 rawSequence) internal pure returns (uint64) {
        if (rawSequence == 0 || rawSequence >= FULL_ID_LIMIT) {
            revert IncrementalSequenceOutOfDomain(rawSequence);
        }
        return INCREMENTAL_FLAG | rawSequence;
    }

    /// @notice Authority id of a deletion-successor proof.
    /// @dev The bound is what makes the encoding INJECTIVE. `DELETION_FLAG | contentVersion`
    ///      alone is not: `encodeDeletion(1)` and `encodeDeletion((1 << 63) + 1)` would both
    ///      produce `(1 << 63) | 1`, so two distinct deletion obligations would share one
    ///      authority id — and `StorageProofSC.snapshotEpochContent[partition][authorityId]`
    ///      would then pin one obligation's content against the other's key.
    ///
    ///      Requiring `0 < contentVersion < DELETION_FLAG` makes bit 63 carry the domain and
    ///      bits 62..0 carry the version with no overlap, so encoding is a bijection onto the
    ///      deletion domain and `deletionContentVersion(encodeDeletion(v)) == v` for every
    ///      valid v.
    function encodeDeletion(uint64 contentVersion) internal pure returns (uint64) {
        if (contentVersion == 0 || contentVersion >= DELETION_FLAG) {
            revert InvalidDeletionContentVersion(contentVersion);
        }
        return DELETION_FLAG | contentVersion;
    }

    /// @notice Content version carried inside a deletion authority id.
    function deletionContentVersion(uint64 authorityId) internal pure returns (uint64) {
        if (!isDeletionAuthority(authorityId)) {
            revert InvalidDeletionContentVersion(authorityId);
        }
        uint64 contentVersion = authorityId & (DELETION_FLAG - 1);
        if (contentVersion == 0) revert InvalidDeletionContentVersion(contentVersion);
        return contentVersion;
    }

    /// @notice The exclusive upper bound on a partition content version. A version at or above
    ///         this could not be represented as a deletion obligation, so it must never be
    ///         reachable — see the exhaustion guard in StorageProofSC.
    function maxRepresentableContentVersion() internal pure returns (uint64) {
        return DELETION_FLAG - 1;
    }

    /// @notice Classification is by BIT, never by magnitude, and the order is significant:
    ///         bit 63 wins, so a deletion id is deletion regardless of its lower bits.
    function isDeletionAuthority(uint64 authorityId) internal pure returns (bool) {
        return (authorityId & DELETION_FLAG) != 0;
    }

    function isIncrementalAuthority(uint64 authorityId) internal pure returns (bool) {
        return (authorityId & DELETION_FLAG) == 0 && (authorityId & INCREMENTAL_FLAG) != 0;
    }

    function isFullEpochAuthority(uint64 authorityId) internal pure returns (bool) {
        return authorityId != 0 &&
            (authorityId & DELETION_FLAG) == 0 &&
            (authorityId & INCREMENTAL_FLAG) == 0;
    }

    /// @notice Raw sequence carried inside an incremental authority id.
    function incrementalSequenceOf(uint64 authorityId) internal pure returns (uint64) {
        return authorityId & (INCREMENTAL_FLAG - 1);
    }
}
