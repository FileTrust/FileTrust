// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: FileTrustVerifierRouter
// Purpose:  Replacing one circuit's ZK verifier with a bounded transition window, so a
//           new key never fails the honest proofs already made with the old one.
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

/// @title FileTrustVerifierRouter
/// @notice Stands in for one circuit's verifier. A consumer binds it once and calls it with
///         the circuit's own verify function; the router asks the current verifier and,
///         until its window closes, the previous one, with the caller's calldata unchanged.
///
///         Answer: true when any verifier it consults returns true. False only when every
///         one of them returned false. Otherwise -- a verifier reverted, ran out of gas or
///         answered something that is not a bool, and none accepted -- the router reverts
///         with that verifier's revert data, as a lone verifier would: the proof gets no
///         verdict, so the consumer's transaction reverts and nothing is charged. An
///         infrastructure failure is never a cryptographic rejection.
///
///         Governance (the timelock) rotates with an explicit window, at most
///         `maxTransitionWindow`; zero switches at once (for a compromised key). A rotation
///         during a window retires the older verifier. An address once configured can never
///         be configured again. During a window, proofs forged with the previous setup's
///         secrets are accepted too: windows are for honest work in flight, and a suspected
///         compromise is answered with `endTransition` or a zero window.
/// @dev    Consumers call verifiers as views (STATICCALL), so the router cannot emit per
///         proof; `acceptingVerifier` lets an indexer find, at the proof's block, which
///         verifier accepted it.
contract FileTrustVerifierRouter is FileTrustOwnable {
    /// @notice The selector of the circuit's verify function; every other call is refused.
    bytes4 public immutable verifySelector;
    /// @notice The longest window a rotation may give the previous verifier.
    uint64 public immutable maxTransitionWindow;

    address public currentVerifier;
    address public previousVerifier;
    /// @notice The previous verifier is consulted until this time, inclusive.
    uint64 public previousValidUntil;
    /// @notice Every address ever configured; none of them can be configured again.
    mapping(address => bool) public everConfigured;

    event VerifierRotated(address indexed previousVerifier, address indexed currentVerifier, uint64 previousValidUntil);
    event TransitionEnded(address indexed retiredVerifier);

    error UnsupportedCall();
    error InvalidVerifier();
    error InvalidRouterParameters();
    error WindowTooLong();
    error NoTransition();
    error VerifierCallFailed();
    error MalformedVerdict();

    uint8 private constant ACCEPTED = 1;
    uint8 private constant REJECTED = 2;
    uint8 private constant FAILED = 3;

    constructor(address initialVerifier, bytes4 verifySelector_, uint64 maxTransitionWindow_) Ownable(msg.sender) {
        if (verifySelector_ == bytes4(0) || maxTransitionWindow_ == 0) revert InvalidRouterParameters();
        _requireNewVerifier(initialVerifier);
        verifySelector = verifySelector_;
        maxTransitionWindow = maxTransitionWindow_;
        currentVerifier = initialVerifier;
        everConfigured[initialVerifier] = true;
        emit VerifierRotated(address(0), initialVerifier, 0);
    }

    /// @notice Make `next` the current verifier; the outgoing one is consulted for `window`
    ///         more seconds (zero: not at all).
    function rotate(address next, uint64 window) external onlyOwner {
        _requireNewVerifier(next);
        if (window > maxTransitionWindow) revert WindowTooLong();
        address outgoing = currentVerifier;
        uint64 until = window == 0 ? 0 : uint64(block.timestamp) + window;
        previousVerifier = window == 0 ? address(0) : outgoing;
        previousValidUntil = until;
        currentVerifier = next;
        everConfigured[next] = true;
        emit VerifierRotated(outgoing, next, until);
    }

    /// @notice Stop consulting the previous verifier now.
    function endTransition() external onlyOwner {
        address retired = previousVerifier;
        if (retired == address(0) || block.timestamp > previousValidUntil) revert NoTransition();
        previousVerifier = address(0);
        previousValidUntil = 0;
        emit TransitionEnded(retired);
    }

    /// @notice The verifiers a proof is judged by now: the previous one is zero outside a window.
    function activeVerifiers() external view returns (address current, address previous) {
        current = currentVerifier;
        if (block.timestamp <= previousValidUntil) previous = previousVerifier;
    }

    /// @notice Which verifier accepts `verifyCalldata` (a full call of the verify function),
    ///         or zero if none does or one cannot answer.
    function acceptingVerifier(bytes calldata verifyCalldata) external view returns (address) {
        if (verifyCalldata.length < 4 || bytes4(verifyCalldata[:4]) != verifySelector) revert UnsupportedCall();
        (uint8 outcome, , address accepted) = _route(verifyCalldata);
        return outcome == ACCEPTED ? accepted : address(0);
    }

    /// @notice The circuit's verify function, with its arguments passed on unchanged.
    fallback(bytes calldata input) external returns (bytes memory) {
        if (msg.sig != verifySelector) revert UnsupportedCall();
        (uint8 outcome, bytes memory failure, ) = _route(input);
        if (outcome == ACCEPTED) return abi.encode(true);
        if (outcome == REJECTED) return abi.encode(false);
        if (failure.length == 0) revert VerifierCallFailed();
        assembly {
            revert(add(failure, 32), mload(failure))
        }
    }

    function _route(bytes calldata input)
        private
        view
        returns (uint8 outcome, bytes memory failure, address accepted)
    {
        accepted = currentVerifier;
        (outcome, failure) = _ask(accepted, input);
        if (outcome == ACCEPTED) return (outcome, failure, accepted);
        address previous = previousVerifier;
        if (previous != address(0) && block.timestamp <= previousValidUntil) {
            (uint8 earlier, bytes memory earlierFailure) = _ask(previous, input);
            if (earlier == ACCEPTED) return (ACCEPTED, earlierFailure, previous);
            // Both must reject for a wrong proof; one that could not answer leaves no verdict.
            if (outcome == REJECTED && earlier == FAILED) (outcome, failure) = (FAILED, earlierFailure);
        }
        accepted = address(0);
    }

    function _ask(address verifier, bytes calldata input) private view returns (uint8, bytes memory) {
        (bool ok, bytes memory answer) = verifier.staticcall(input);
        if (!ok) return (FAILED, answer);
        if (answer.length == 32) {
            uint256 word = abi.decode(answer, (uint256));
            if (word == 1) return (ACCEPTED, answer);
            if (word == 0) return (REJECTED, answer);
        }
        return (FAILED, abi.encodeWithSelector(MalformedVerdict.selector));
    }

    function _requireNewVerifier(address verifier) private view {
        if (verifier == address(0) || verifier.code.length == 0 || everConfigured[verifier]) revert InvalidVerifier();
    }
}
