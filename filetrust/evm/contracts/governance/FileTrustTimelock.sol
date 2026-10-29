// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: FileTrustTimelock
// Purpose:  The public delay between an approved change to FileTrust and the moment
//           it takes effect, so nothing happens unannounced.
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

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @notice Public delay between an approved FileTrust protocol change and execution.
/// @dev The timelock is self-administered. Pass address(0) as an executor to allow
///      anyone to execute a ready operation without giving them proposal authority.
///      Each proposer may cancel its own proposals; `cancellers` are further accounts
///      that may cancel any scheduled operation but propose none -- an independent
///      check on the proposer, such as a separate multisig.
contract FileTrustTimelock is TimelockController {
    /// @notice The delay this timelock was deployed with. Its delay never goes below it
    ///         (Phase 2, D15): every protocol switch is only as visible as the delay.
    uint256 public immutable minimumDelayFloor;

    constructor(
        uint256 minimumDelay,
        address[] memory proposers,
        address[] memory executors,
        address[] memory cancellers
    ) TimelockController(minimumDelay, proposers, executors, address(0)) {
        require(minimumDelay >= 1 hours, "FileTrustTimelock: delay too short");
        require(proposers.length != 0, "FileTrustTimelock: no proposer");
        minimumDelayFloor = minimumDelay;
        for (uint256 i = 0; i < cancellers.length; ++i) {
            require(cancellers[i] != address(0), "FileTrustTimelock: zero canceller");
            _grantRole(CANCELLER_ROLE, cancellers[i]);
        }
    }

    /// @notice A proposal through the timelock itself may lengthen the delay, or shorten it
    ///         back down to the floor, never below.
    function updateDelay(uint256 newDelay) public override {
        require(newDelay >= minimumDelayFloor, "FileTrustTimelock: delay below floor");
        super.updateDelay(newDelay);
    }
}
