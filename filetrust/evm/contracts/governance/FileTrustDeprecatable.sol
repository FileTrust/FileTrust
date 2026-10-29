// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: FileTrustDeprecatable
// Purpose:  The one-way switch that closes a contract version to new business
//           while it keeps serving every obligation it already accepted.
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

/// @notice When a successor version opens, the old one stops taking new obligations and
///         keeps finishing the ones it holds. A contract calls `_requireNotDeprecated` only
///         in the entry points that create a new obligation; proofs, penalties, disputes,
///         claims, refunds, withdrawals, deletions and updates of existing records never
///         check it. Deprecation is recorded once and never undone. Who may call it is the
///         inheriting contract's rule: its owner, which is the timelock after the
///         governance hand-over.
abstract contract FileTrustDeprecatable {
    /// @notice Chain time of deprecation; zero while new obligations are accepted.
    uint64 public deprecatedAt;

    /// @param successor The version that takes the new business, or zero if none is named.
    event Deprecated(address indexed successor, uint64 deprecatedAt);

    error ContractDeprecated();

    function _deprecate(address successor) internal {
        if (deprecatedAt != 0) revert ContractDeprecated();
        deprecatedAt = uint64(block.timestamp);
        emit Deprecated(successor, uint64(block.timestamp));
    }

    function _requireNotDeprecated() internal view {
        if (deprecatedAt != 0) revert ContractDeprecated();
    }
}
