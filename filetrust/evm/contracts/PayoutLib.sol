// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: PayoutLib
// Purpose:  The one way money leaves a FileTrust contract: the books are settled
//           first, the payment is made last.
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

/// @title Paying native coin out of a FileTrust contract.
/// @notice One way to send money, so the question of how it is sent is settled
///         in a single place.
///
/// `address.transfer` used to be that place. Solidity deprecated it in 0.8.37
/// and will remove it, because it forwards a fixed 2300 gas: a recipient that
/// is a contract -- a VK or Guardian run from a wallet contract, say -- cannot
/// always accept money within that, and the payment reverts for a reason that
/// has nothing to do with whether it was owed.
///
/// So the call forwards all the gas it has. That hands control to the recipient
/// while this contract is mid-transaction, which is only safe where the money
/// has already been accounted for before the call. Every caller here does
/// that: a balance is zeroed or a claim is marked before `send` is reached, so
/// a recipient that calls back finds nothing left to take. Keep it that way --
/// state first, `send` last.
library PayoutLib {
    error PayoutFailed(address to, uint256 amount);

    /// Send `amount` to `to`, and revert the whole transaction if it does not
    /// arrive. Silence on failure would leave the money here while the records
    /// said it had been paid.
    function send(address to, uint256 amount) internal {
        (bool ok, ) = payable(to).call{value: amount}("");
        if (!ok) revert PayoutFailed(to, amount);
    }

    /// Try to send `amount`, and say whether it arrived instead of reverting.
    ///
    /// For paying a list of people in one transaction, where one refusing the
    /// money must not cost the rest their payment. The gas is capped here and
    /// not in `send`: the recipients are a list of addresses this contract did
    /// not choose, any one of which could otherwise burn the whole
    /// transaction's gas and stop everybody behind it from being paid. The cap
    /// is well above a plain account and above a wallet contract that records
    /// the receipt, and far below enough to do damage with.
    function trySend(address to, uint256 amount) internal returns (bool ok) {
        (ok, ) = payable(to).call{value: amount, gas: 30_000}("");
    }
}
