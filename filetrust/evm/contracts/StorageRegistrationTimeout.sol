// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: StorageRegistrationTimeout
// Purpose:  Refunding an upload whose registration never arrived, without letting a
//           late registration land afterwards.
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

interface IVKEscrow_RegistrationTimeout {
    function escrowStatus(bytes32 paymentCommitment)
        external view returns (
            uint256 totalAmount,
            uint64 serviceStart,
            uint64 serviceEnd,
            bytes32 sizeCommitment,
            bytes32 linkCommitment,
            uint256 claimedAmount,
            uint256 claimableNow,
            address depositor
        );
    function registrationDeadlineOf(bytes32 paymentCommitment) external view returns (uint64);
    function refundRegistrationTimeout(bytes32 paymentCommitment) external;
}

interface IFileRegistration_RegistrationTimeout {
    function expireRegistrationCommitment(
        bytes32 registrationCommitment,
        address expectedVK,
        uint64 registrationDeadline
    ) external returns (bytes32 commitmentHash, bool registeredLate);
}

/// @title StorageRegistrationTimeout
/// @notice Resolves ambiguous/lost-response uploads after a chain-snapshotted
///         registration deadline. It verifies the VK-signed quote, fences absent
///         or late registration, and refunds escrow atomically. A registration
///         mined on time can never be expired by the DO.
/// @dev    A quote names nothing on its own: every field it must match is public, so
///         any key can sign one for any escrow. The escrow's link commitment,
///         keccak256(paymentCommitment ++ registrationCommitment ++ linkNonce), is what
///         names the registration commitment the escrow pays for; the VaultKeeper gives
///         the data owner the nonce with the quote. Only that registration can be
///         expired for a refund (Phase 1D D19).
contract StorageRegistrationTimeout {
    error InvalidParameters();
    error InvalidSignature();
    error RegistrationDeadlineActive();
    error AlreadyResolved();
    error InvalidEscrowLink();

    IVKEscrow_RegistrationTimeout public immutable vkEscrow;
    IFileRegistration_RegistrationTimeout public immutable fileRegistration;
    mapping(bytes32 => bool) public resolvedTimeouts;

    event RegistrationTimeoutResolved(
        bytes32 indexed timeoutId,
        address indexed vk,
        bytes32 indexed paymentCommitment,
        bytes32 registrationCommitment,
        bytes32 commitmentHash,
        bool registeredLate,
        address doAddress
    );

    constructor(address escrow_, address fileRegistration_) {
        if (escrow_ == address(0) || fileRegistration_ == address(0)) {
            revert InvalidParameters();
        }
        vkEscrow = IVKEscrow_RegistrationTimeout(escrow_);
        fileRegistration = IFileRegistration_RegistrationTimeout(fileRegistration_);
    }

    function resolveRegistrationTimeout(
        address vk,
        bytes32 paymentCommitment,
        bytes32 registrationCommitment,
        bytes32 linkNonce,
        uint256 quotedPriceWei,
        uint64 quoteValidUntil,
        bytes calldata quoteSignature
    ) external {
        if (
            vk == address(0) || paymentCommitment == bytes32(0) ||
            registrationCommitment == bytes32(0) || quotedPriceWei == 0 ||
            quoteValidUntil == 0
        ) revert InvalidParameters();

        bytes32 timeoutId = keccak256(abi.encodePacked(
            "registrationTimeout", vk, paymentCommitment, registrationCommitment
        ));
        if (resolvedTimeouts[timeoutId]) revert AlreadyResolved();

        (
            uint256 totalAmount,
            uint64 serviceStart,
            uint64 serviceEnd,
            bytes32 sizeCommitment,
            bytes32 linkCommitment,
            uint256 claimedAmount,
            ,
            address depositor
        ) = vkEscrow.escrowStatus(paymentCommitment);
        if (totalAmount == 0 || depositor != msg.sender || claimedAmount != 0) {
            revert InvalidParameters();
        }
        if (keccak256(abi.encodePacked(paymentCommitment, registrationCommitment, linkNonce)) != linkCommitment) {
            revert InvalidEscrowLink();
        }
        uint64 registrationDeadline = vkEscrow.registrationDeadlineOf(paymentCommitment);
        if (registrationDeadline == 0 || block.timestamp <= registrationDeadline) {
            revert RegistrationDeadlineActive();
        }
        if (serviceStart > quoteValidUntil) revert InvalidParameters();

        bytes32 digest = keccak256(abi.encodePacked(
            "FileTrustAdmissionQuoteV1",
            uint64(block.chainid),
            vk,
            address(vkEscrow),
            paymentCommitment,
            registrationCommitment,
            sizeCommitment,
            linkCommitment,
            quotedPriceWei,
            serviceEnd,
            quoteValidUntil
        ));
        if (_recoverSigner(digest, quoteSignature) != vk) revert InvalidSignature();

        (bytes32 commitmentHash, bool registeredLate) =
            fileRegistration.expireRegistrationCommitment(
                registrationCommitment, vk, registrationDeadline
            );
        resolvedTimeouts[timeoutId] = true;
        vkEscrow.refundRegistrationTimeout(paymentCommitment);
        emit RegistrationTimeoutResolved(
            timeoutId, vk, paymentCommitment, registrationCommitment,
            commitmentHash, registeredLate, msg.sender
        );
    }

    /// @notice Resolves the production V2 quote whose signature includes the
    ///         immutable, size-aware transfer deadline recorded by VKEscrow.
    function resolveRegistrationTimeout(
        address vk,
        bytes32 paymentCommitment,
        bytes32 registrationCommitment,
        bytes32 linkNonce,
        uint256 quotedPriceWei,
        uint64 quoteValidUntil,
        uint64 transferDeadline,
        bytes calldata quoteSignature
    ) external {
        if (
            vk == address(0) || paymentCommitment == bytes32(0) ||
            registrationCommitment == bytes32(0) || quotedPriceWei == 0 ||
            quoteValidUntil == 0 || transferDeadline < quoteValidUntil
        ) revert InvalidParameters();

        bytes32 timeoutId = keccak256(abi.encodePacked(
            "registrationTimeout", vk, paymentCommitment, registrationCommitment
        ));
        if (resolvedTimeouts[timeoutId]) revert AlreadyResolved();

        (
            uint256 totalAmount,
            uint64 serviceStart,
            uint64 serviceEnd,
            bytes32 sizeCommitment,
            bytes32 linkCommitment,
            uint256 claimedAmount,
            ,
            address depositor
        ) = vkEscrow.escrowStatus(paymentCommitment);
        if (totalAmount == 0 || depositor != msg.sender || claimedAmount != 0) {
            revert InvalidParameters();
        }
        if (keccak256(abi.encodePacked(paymentCommitment, registrationCommitment, linkNonce)) != linkCommitment) {
            revert InvalidEscrowLink();
        }
        uint64 registrationDeadline = vkEscrow.registrationDeadlineOf(paymentCommitment);
        if (registrationDeadline != transferDeadline) revert InvalidParameters();
        if (block.timestamp <= registrationDeadline) revert RegistrationDeadlineActive();
        if (serviceStart > quoteValidUntil) revert InvalidParameters();

        bytes32 digest = keccak256(abi.encodePacked(
            "FileTrustAdmissionQuoteV2",
            uint64(block.chainid),
            vk,
            address(vkEscrow),
            paymentCommitment,
            registrationCommitment,
            sizeCommitment,
            linkCommitment,
            quotedPriceWei,
            serviceEnd,
            quoteValidUntil,
            transferDeadline
        ));
        if (_recoverSigner(digest, quoteSignature) != vk) revert InvalidSignature();

        (bytes32 commitmentHash, bool registeredLate) =
            fileRegistration.expireRegistrationCommitment(
                registrationCommitment, vk, registrationDeadline
            );
        resolvedTimeouts[timeoutId] = true;
        vkEscrow.refundRegistrationTimeout(paymentCommitment);
        emit RegistrationTimeoutResolved(
            timeoutId, vk, paymentCommitment, registrationCommitment,
            commitmentHash, registeredLate, msg.sender
        );
    }

    function _recoverSigner(bytes32 digest, bytes calldata sig) internal pure returns (address) {
        if (sig.length != 65) revert InvalidSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignature();
        bytes32 ethHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", digest
        ));
        address signer = ecrecover(ethHash, v, r, s);
        if (signer == address(0)) revert InvalidSignature();
        return signer;
    }
}
