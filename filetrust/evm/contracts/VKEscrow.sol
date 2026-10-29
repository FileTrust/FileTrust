// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: VKEscrow
// Purpose:  The Data Owner's payment for storage, held until the Vault Keeper has
//           actually served the term it agreed to.
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

import "./PayoutLib.sol";
import {FileTrustDeprecatable} from "./governance/FileTrustDeprecatable.sol";

/// @dev Minimal read-only interface used by VKEscrow to verify file registration.
interface IFileRegistrationSC_Escrow {
    function registrationCommitmentExists(bytes32 registrationCommitment) external view returns (bool);
    function registrationCurrentProofStatus(bytes32 registrationCommitment)
        external view returns (address vk, bool current, uint64 acceptedAt);
    /// @notice serviceEnd currently recorded for a registration, or 0 when unknown.
    ///         Used to prove the VK accepted the obligation for an extended term
    ///         before it is paid for that term.
    function registrationServiceEnd(bytes32 registrationCommitment)
        external view returns (uint64);
}

/// @dev Interface used by claimEscrowOnDeletion to resolve deletion confirmation
///      time for pro-rata payment calculation.
interface IFileRegistrationSC_DeletionEscrow {
    function registrationCommitmentToCommitmentHash(bytes32 registrationCommitment)
        external view returns (bytes32);
    function getFileRecordForDeletion(bytes32 commitmentHash)
        external view returns (address vk, uint8 deadlineIndex, uint8 partitionIndex, bytes32 zkPieceCommitment);
    function isDeletionConfirmed(bytes32 commitmentHash) external view returns (bool);
    function getDeletionConfirmedAt(bytes32 commitmentHash) external view returns (uint64);
}

/// @dev What VKEscrow asks of the dispute contract and the timeout resolver it binds:
///      each must name this escrow as its own.
interface IEscrowBound_VKEscrow {
    function vkEscrow() external view returns (address);
}

interface IRewardManager_VKE {
    function creditVKFile(address vk) external;
}

/// @title VKEscrow
/// @notice Privacy-preserving escrow contract for VaultKeeper storage payments.
///
/// Payment flow (DO deposits FIRST)
/// ---------------------------------
/// 1. DO negotiates with VK off-chain: pieceSize, serviceEnd.
///    VK generates:
///      paymentCommitment    = keccak256(nullifier || secret)
///      sizeCommitment       = keccak256(uint64(pieceSize) || bytes32(sizeNonce))
///      registrationCommitment = keccak256(regNullifier || regSecret)   [private to VK]
///      linkNonce            [private to VK, never shared]
///      linkCommitment       = keccak256(paymentCommitment || registrationCommitment || linkNonce)
///    VK sends receipt to DO: paymentCommitment, sizeCommitment, linkCommitment, agreedPriceWei.
///
/// 2. DO calls depositEscrow(paymentCommitment, sizeCommitment, linkCommitment, serviceEnd)
///    with msg.value = agreedPriceWei.
///
/// 3. VK verifies the deposit on-chain (view call, no trace), then accepts the file.
///    VK verifies actual file size == agreedSize. If mismatch → rejects, nothing stored.
///
/// 4. VK stores file and calls FileRegistrationSC.registerFileStorage(..., registrationCommitment).
///
/// 5. After serviceEnd, VK calls claimEscrow(nullifier, secret, regNullifier, regSecret, linkNonce).
///    The contract verifies:
///      a. block.timestamp >= serviceEnd  (time-lock)
///      b. keccak256(nullifier, secret) == paymentCommitment
///      c. registrationCommitment = keccak256(regNullifier, regSecret)
///      d. keccak256(paymentCommitment || registrationCommitment || linkNonce) == linkCommitment
///      e. FileRegistrationSC.registrationCommitmentExists(registrationCommitment) == true
///    Full unclaimed amount is transferred to msg.sender (VK operational wallet).
///
/// Privacy guarantees
/// ------------------
///   - DO address is recorded at deposit time as depositor (needed for reclaimEscrow).
///   - paymentCommitment is on-chain but linkCommitment uses a private linkNonce so observers
///     cannot link paymentCommitment → registrationCommitment → VK identity before service end.
///   - registrationCommitment in FileRegistrationSC looks like a random hash — unlinked to
///     paymentCommitment without knowing linkNonce (computationally infeasible to brute-force).
///   - Before serviceEnd: any claimEscrow attempt is a silent revert — no state written,
///     no event emitted, no on-chain trace.
///   - After serviceEnd: VK reveals (nullifier, secret, regNullifier, regSecret, linkNonce),
///     VK-DO relationship becomes fully auditable. This is intentional — service is complete.
///
/// Bad DO protection
/// -----------------
///   VK checks escrowStatus(paymentCommitment) before accepting the file. If totalAmount is
///   too low or sizeCommitment mismatches, VK rejects. DO's deposit is locked until
///   serviceEnd + reclaimGraceSeconds, at which point DO can call reclaimEscrow() since VK
///   never registered the file (cannot pass linkCommitment check) and never claimed.
///
/// Dispute integration
/// -------------------
///   On a successful dispute, StorageReceiptDispute calls refundDisputed(paymentCommitment),
///   which immediately returns totalAmount to depositor (DO). VK stake compensation is handled
///   separately by StakingManager.slashTo(vk, amount, doAddress).
contract VKEscrow is FileTrustDeprecatable {

    // ─── Structs ─────────────────────────────────────────────────────────────

    struct EscrowRecord {
        uint256 totalAmount;      // Wei deposited by DO
        uint64  serviceStart;     // block.timestamp at deposit
        uint64  serviceEnd;       // agreed service end (Unix timestamp)
        bytes32 sizeCommitment;   // keccak256(uint64(pieceSize) || bytes32(sizeNonce))
        bytes32 linkCommitment;   // keccak256(paymentCommitment || registrationCommitment || linkNonce)
        bool    finalized;        // true when full escrow is finalized and claimable after serviceEnd
        uint64  finalizeBy;       // deadline for DO to finalize when using bond-first flow
        uint256 claimedAmount;    // Wei already claimed (or refunded)
        address paymentAddress;   // locked on first claim; zero until then
        address depositor;        // msg.sender at deposit time (for reclaimEscrow / refundDisputed)
        uint64  registrationDeadline; // immutable deadline snapshot for VK registration

        // ─── Renewal (service extension) ──────────────────────────────────────
        // A renewal is parked here until the VK proves it accepted the longer
        // term. serviceEnd and totalAmount only move on confirmExtension().
        uint256 pendingAmount;       // Wei deposited for the extension, not yet earned
        uint64  pendingServiceEnd;   // proposed new serviceEnd, 0 when none pending
        uint64  extensionConfirmBy;  // deadline for the VK to confirm the extension
        bytes32 extensionCommitment; // keccak256(extNullifier || extSecret), from the VK quote
    }

    // ─── Storage ──────────────────────────────────────────────────────────────

    address public owner;
    IFileRegistrationSC_Escrow public fileRegistration;
    address public disputeContract;     // StorageReceiptDispute — only caller allowed for refundDisputed
    address public registrationTimeoutResolver;
    address public rewardManager;       // RewardManager — credited on each successful claimEscrow
    uint64  public reclaimGraceSeconds; // seconds after serviceEnd before DO can reclaim (default 30 days)
    uint64  public finalizeRegistrationTimeoutSeconds; // deadline for bond-first escrow finalization
    uint64  public maxRegistrationTimeoutSeconds;
    /// @dev Upper bound on how long an unconfirmed extension may park DO funds.
    uint64  public maxExtensionConfirmSeconds;

    // ─── Early-deletion claim ─────────────────────────────────────────────────
    /// @dev FileRegistrationSC queried to resolve deletion confirmation time for pro-rata.
    IFileRegistrationSC_DeletionEscrow public fileRegistrationForDeletion;
    /// @dev Fixed wei amount added to VK's deletion payment to cover on-chain tx cost.
    ///      Owner-configurable; defaults to 0 (no reimbursement until set by admin).
    ///      A change applies to escrows deposited after it: see deletionTxCostOf.
    uint256 public deletionTxCostEstimate;
    /// @notice The deletion cost each escrow was deposited under. An early-deletion claim
    ///         pays the VK this, never the estimate of the day, so a later change neither
    ///         raises an existing data owner's charge nor cuts an existing VK's compensation.
    mapping(bytes32 => uint256) public deletionTxCostOf;

    /// @dev One paid stretch of the timeline, at the price agreed for it.
    ///
    ///      Early-deletion refunds must split the money by time. With a single
    ///      total that split can only ever be an average, so a renewal bought at
    ///      a different rate would silently blend the two prices. Keeping each
    ///      renewal as its own stretch makes the split exact.
    struct TermSegment {
        uint64  startTime;
        uint64  endTime;
        uint256 amount;
    }

    /// @dev paymentCommitment => EscrowRecord
    mapping(bytes32 => EscrowRecord) public escrows;

    /// @dev paymentCommitment => renewal stretches, in time order.
    ///
    ///      Holds ONLY renewals. The first term stays implicit in the record, so
    ///      an escrow that is never renewed costs nothing extra to store and
    ///      behaves exactly as before. The first term runs
    ///      [serviceStart, termSegments[0].startTime) and is worth
    ///      totalAmount minus the sum of the segments.
    mapping(bytes32 => TermSegment[]) public termSegments;

    /// @dev Bounds the early-deletion loop. Reaching it does not end the
    ///      agreement; the DO simply buys a fresh one instead of renewing again.
    uint16 public maxRenewalSegments;

    /// @dev VK wallet => number of successfully claimed (fully served) pieces
    mapping(address => uint256) public completedPieces;

    // ─── Events ───────────────────────────────────────────────────────────────

    event EscrowDeposited(
        bytes32 indexed paymentCommitment,
        bytes32         sizeCommitment,
        bytes32         linkCommitment,
        uint256         amount,
        uint64          serviceEnd,
        address         depositor
    );

    event EscrowClaimed(
        bytes32 indexed paymentCommitment,
        address indexed recipient,
        uint256         amount,
        uint256         totalClaimed
    );

    event EscrowReclaimed(
        bytes32 indexed paymentCommitment,
        address indexed depositor,
        uint256         amount
    );

    event EscrowRefundedByDispute(
        bytes32 indexed paymentCommitment,
        address indexed depositor,
        uint256         amount
    );

    event EscrowClaimedOnDeletion(
        bytes32 indexed paymentCommitment,
        address indexed recipient,
        uint256         vkAmount,
        uint256         doRefund,
        uint64          confirmedAt
    );

    event EscrowBondDeposited(
        bytes32 indexed paymentCommitment,
        uint256         amount,
        uint64          finalizeBy,
        address         depositor
    );

    event EscrowFinalized(
        bytes32 indexed paymentCommitment,
        uint256         addedAmount,
        uint256         totalAmount,
        address         depositor
    );

    event EscrowFinalizationReclaimed(
        bytes32 indexed paymentCommitment,
        address indexed depositor,
        uint256         amount
    );

    event EscrowRegistrationTimedOut(
        bytes32 indexed paymentCommitment,
        address indexed depositor,
        uint256 amount,
        uint64 registrationDeadline
    );
    event MaxRegistrationTimeoutSecondsSet(uint64 seconds_);

    /// @notice DO parked funds for a longer service term. Carries no VK address
    ///         and no registrationCommitment, so it does not link DO to VK.
    event EscrowExtensionDeposited(
        bytes32 indexed paymentCommitment,
        uint256         addedAmount,
        uint64          pendingServiceEnd,
        uint64          confirmBy,
        address         depositor
    );

    /// @notice VK opened its extension commitment; the longer term is now live.
    event EscrowExtended(
        bytes32 indexed paymentCommitment,
        uint256         addedAmount,
        uint256         totalAmount,
        uint64          previousServiceEnd,
        uint64          serviceEnd
    );

    event EscrowExtensionReclaimed(
        bytes32 indexed paymentCommitment,
        address indexed depositor,
        uint256         amount,
        uint64          pendingServiceEnd
    );

    event MaxExtensionConfirmSecondsSet(uint64 seconds_);
    event MaxRenewalSegmentsSet(uint16 segments_);

    // ─── Constructor ─────────────────────────────────────────────────────────

    constructor() {
        owner = msg.sender;
        reclaimGraceSeconds = 30 days;
        finalizeRegistrationTimeoutSeconds = 10 minutes;
        maxRegistrationTimeoutSeconds = 7 days;
        maxExtensionConfirmSeconds = 1 days;
        maxRenewalSegments = 24;
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(newOwner != address(0), "VKEscrow: zero owner");
        owner = newOwner;
    }

    /// @notice Close this version to new escrow deposits when its successor opens (Phase 2), for
    ///         good. Every escrow it holds keeps its claims,
    ///         renewals, refunds, reclaims and disputes.
    function deprecate(address successor) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        _deprecate(successor);
    }

    // The contracts that decide claims and refunds are bound once: the file registration
    // lookups (with none set, the claim checks are skipped), the dispute contract (may
    // refund any escrow) and the timeout resolver (may refund a timed-out one). The latter
    // two must name this escrow as their own.

    function setFileRegistration(address _fileRegistration) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(address(fileRegistration) == address(0) && _fileRegistration.code.length != 0,
                "VKEscrow: bad file registration");
        fileRegistration = IFileRegistrationSC_Escrow(_fileRegistration);
    }

    function setDisputeContract(address _disputeContract) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(disputeContract == address(0) && _disputeContract.code.length != 0
                && IEscrowBound_VKEscrow(_disputeContract).vkEscrow() == address(this),
                "VKEscrow: bad dispute contract");
        disputeContract = _disputeContract;
    }

    function setRegistrationTimeoutResolver(address resolver) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(registrationTimeoutResolver == address(0) && resolver.code.length != 0
                && IEscrowBound_VKEscrow(resolver).vkEscrow() == address(this),
                "VKEscrow: bad timeout resolver");
        registrationTimeoutResolver = resolver;
    }

    /// @notice How long after serviceEnd a VK may still claim before the DO may reclaim.
    ///         Bounded both ways: zero would let a DO take back money a VK had earned,
    ///         and an unbounded wait would lock the DO's money.
    function setReclaimGraceSeconds(uint64 _grace) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(_grace >= 1 days && _grace <= 90 days, "VKEscrow: grace out of bounds");
        reclaimGraceSeconds = _grace;
    }

    function setFinalizeRegistrationTimeoutSeconds(uint64 _timeout) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(_timeout >= 60, "VKEscrow: timeout too short");
        finalizeRegistrationTimeoutSeconds = _timeout;
    }

    function setMaxRegistrationTimeoutSeconds(uint64 timeout_) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(timeout_ >= 10 minutes && timeout_ <= 30 days,
                "VKEscrow: invalid registration timeout bound");
        maxRegistrationTimeoutSeconds = timeout_;
        emit MaxRegistrationTimeoutSecondsSet(timeout_);
    }

    function setMaxExtensionConfirmSeconds(uint64 seconds_) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(seconds_ >= 10 minutes && seconds_ <= 30 days,
                "VKEscrow: invalid extension confirm bound");
        maxExtensionConfirmSeconds = seconds_;
        emit MaxExtensionConfirmSecondsSet(seconds_);
    }

    function setMaxRenewalSegments(uint16 segments_) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(segments_ >= 1 && segments_ <= 100, "VKEscrow: invalid segment bound");
        maxRenewalSegments = segments_;
        emit MaxRenewalSegmentsSet(segments_);
    }

    function setRewardManager(address _rm) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        rewardManager = _rm;
    }

    function setFileRegistrationForDeletion(address _fr) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        require(address(fileRegistrationForDeletion) == address(0) && _fr.code.length != 0,
                "VKEscrow: bad file registration");
        fileRegistrationForDeletion = IFileRegistrationSC_DeletionEscrow(_fr);
    }

    function setDeletionTxCostEstimate(uint256 _wei) external {
        require(msg.sender == owner, "VKEscrow: only owner");
        deletionTxCostEstimate = _wei;
    }

    // ─── DO: deposit ─────────────────────────────────────────────────────────

    /// @notice DO deposits escrow for a storage agreement (BEFORE sending the file).
    /// @param paymentCommitment  keccak256(nullifier || secret) — received from VK receipt.
    /// @param sizeCommitment     keccak256(uint64(pieceSize) || bytes32(sizeNonce)) — from receipt.
    /// @param linkCommitment     keccak256(paymentCommitment || registrationCommitment || linkNonce) — from receipt.
    /// @param serviceEnd         Unix timestamp of agreed service end.
    function depositEscrow(
        bytes32 paymentCommitment,
        bytes32 sizeCommitment,
        bytes32 linkCommitment,
        uint64  serviceEnd
    ) external payable {
        _depositOne(
            paymentCommitment, sizeCommitment, linkCommitment, serviceEnd,
            msg.value, msg.sender, true, 0,
            uint64(block.timestamp) + finalizeRegistrationTimeoutSeconds
        );
    }

    /// @notice Capacity-backed deposit with the exact size-aware transfer
    ///         deadline signed by the VK. The deadline is immutable once mined.
    function depositEscrowV2(
        bytes32 paymentCommitment,
        bytes32 sizeCommitment,
        bytes32 linkCommitment,
        uint64 serviceEnd,
        uint64 registrationDeadline
    ) external payable {
        _validateRegistrationDeadline(serviceEnd, registrationDeadline);
        _depositOne(
            paymentCommitment, sizeCommitment, linkCommitment, serviceEnd,
            msg.value, msg.sender, true, 0, registrationDeadline
        );
    }

    /// @notice Batch version of depositEscrow. Each amount maps to the same index
    ///         in the commitment arrays; msg.value must equal sum(amounts).
    function depositEscrowBatch(
        bytes32[] calldata paymentCommitments,
        bytes32[] calldata sizeCommitments,
        bytes32[] calldata linkCommitments,
        uint64[]  calldata serviceEnds,
        uint256[] calldata amounts
    ) external payable {
        uint256 count = paymentCommitments.length;
        require(count > 0, "VKEscrow: empty batch");
        require(sizeCommitments.length == count, "VKEscrow: size length");
        require(linkCommitments.length == count, "VKEscrow: link length");
        require(serviceEnds.length == count, "VKEscrow: service length");
        require(amounts.length == count, "VKEscrow: amount length");

        uint256 total = 0;
        for (uint256 i = 0; i < count; i++) {
            total += amounts[i];
        }
        require(total == msg.value, "VKEscrow: value mismatch");

        for (uint256 i = 0; i < count; i++) {
            _depositOne(
                paymentCommitments[i],
                sizeCommitments[i],
                linkCommitments[i],
                serviceEnds[i],
                amounts[i],
                msg.sender,
                true,
                0,
                uint64(block.timestamp) + finalizeRegistrationTimeoutSeconds
            );
        }
    }

    function depositEscrowBatchV2(
        bytes32[] calldata paymentCommitments,
        bytes32[] calldata sizeCommitments,
        bytes32[] calldata linkCommitments,
        uint64[] calldata serviceEnds,
        uint64[] calldata registrationDeadlines,
        uint256[] calldata amounts
    ) external payable {
        uint256 count = paymentCommitments.length;
        require(count > 0 && sizeCommitments.length == count &&
                linkCommitments.length == count && serviceEnds.length == count &&
                registrationDeadlines.length == count && amounts.length == count,
                "VKEscrow: batch length mismatch");
        uint256 total;
        for (uint256 i = 0; i < count; i++) total += amounts[i];
        require(total == msg.value, "VKEscrow: value mismatch");
        for (uint256 i = 0; i < count; i++) {
            _validateRegistrationDeadline(serviceEnds[i], registrationDeadlines[i]);
            _depositOne(
                paymentCommitments[i], sizeCommitments[i], linkCommitments[i],
                serviceEnds[i], amounts[i], msg.sender, true, 0,
                registrationDeadlines[i]
            );
        }
    }

    /// @notice Bond-first escrow: DO deposits only an upfront bond before VK storage.
    ///         DO must call finalizeEscrow() before finalizeBy to complete the escrow.
    function depositEscrowBond(
        bytes32 paymentCommitment,
        bytes32 sizeCommitment,
        bytes32 linkCommitment,
        uint64  serviceEnd
    ) external payable {
        uint64 finalizeBy = uint64(block.timestamp) + finalizeRegistrationTimeoutSeconds;
        _depositOne(
            paymentCommitment,
            sizeCommitment,
            linkCommitment,
            serviceEnd,
            msg.value,
            msg.sender,
            false,
            finalizeBy,
            finalizeBy
        );
        emit EscrowBondDeposited(paymentCommitment, msg.value, finalizeBy, msg.sender);
    }

    function depositEscrowBondV2(
        bytes32 paymentCommitment,
        bytes32 sizeCommitment,
        bytes32 linkCommitment,
        uint64 serviceEnd,
        uint64 registrationDeadline
    ) external payable {
        _validateRegistrationDeadline(serviceEnd, registrationDeadline);
        uint64 finalizeBy = uint64(block.timestamp) + finalizeRegistrationTimeoutSeconds;
        if (finalizeBy > registrationDeadline) finalizeBy = registrationDeadline;
        _depositOne(
            paymentCommitment, sizeCommitment, linkCommitment, serviceEnd,
            msg.value, msg.sender, false, finalizeBy, registrationDeadline
        );
        emit EscrowBondDeposited(paymentCommitment, msg.value, finalizeBy, msg.sender);
    }

    /// @notice Completes a bond-first escrow by adding the remaining amount.
    function finalizeEscrow(bytes32 paymentCommitment) external payable {
        EscrowRecord storage rec = escrows[paymentCommitment];
        require(rec.totalAmount > 0, "VKEscrow: no escrow for commitment");
        require(msg.sender == rec.depositor, "VKEscrow: not depositor");
        require(!rec.finalized, "VKEscrow: already finalized");
        require(rec.claimedAmount == 0, "VKEscrow: already claimed or refunded");
        require(msg.value > 0, "VKEscrow: zero finalize value");
        require(block.timestamp <= rec.finalizeBy, "VKEscrow: finalize window elapsed");

        rec.totalAmount += msg.value;
        rec.finalized = true;
        rec.finalizeBy = 0;

        emit EscrowFinalized(paymentCommitment, msg.value, rec.totalAmount, msg.sender);
    }

    // ─── Renewal: extend a live service term ──────────────────────────────────
    //
    // Privacy: the DO's call carries only paymentCommitment. It never names the
    // VK and never names registrationCommitment, so it adds no link between the
    // two parties. The VK authenticates instead by opening extensionCommitment,
    // a fresh keccak256(extNullifier || extSecret) it generated for the signed
    // extension quote — the same primitive already used for paymentCommitment,
    // and something only the VK can open.
    //
    // Ordering: money parks first, the VK takes on the longer obligation second.
    // serviceEnd only moves once the VK has proved it accepted the new term, so
    // the VK can never be paid for a window it does not owe.

    /// @notice DO parks funds to extend a running service term.
    ///         Must be called while the service is still live — once serviceEnd
    ///         has passed the VK may already have garbage-collected the piece.
    /// @param paymentCommitment   Commitment of the escrow being extended.
    /// @param newServiceEnd       Proposed longer service end (must move forward).
    /// @param extensionCommitment keccak256(extNullifier || extSecret) from the VK quote.
    /// @param confirmBy           Deadline for the VK to confirm; DO reclaims after it.
    function extendEscrow(
        bytes32 paymentCommitment,
        uint64  newServiceEnd,
        bytes32 extensionCommitment,
        uint64  confirmBy
    ) external payable {
        EscrowRecord storage rec = escrows[paymentCommitment];

        require(rec.totalAmount > 0,          "VKEscrow: no escrow for commitment");
        require(msg.sender == rec.depositor,  "VKEscrow: not depositor");
        require(rec.finalized,                "VKEscrow: escrow not finalized");
        require(rec.claimedAmount == 0,       "VKEscrow: already claimed or refunded");
        require(msg.value > 0,                "VKEscrow: zero extension value");
        require(extensionCommitment != bytes32(0), "VKEscrow: zero extensionCommitment");
        require(rec.pendingServiceEnd == 0,   "VKEscrow: extension already pending");
        // Checked here, not at confirm time, so the DO never parks money against
        // a renewal that could not be recorded.
        require(termSegments[paymentCommitment].length < maxRenewalSegments,
                "VKEscrow: renewal limit reached");

        // The service must still be running: an expired term cannot be extended,
        // only re-bought as a fresh agreement.
        require(block.timestamp < rec.serviceEnd, "VKEscrow: service period ended");
        require(newServiceEnd > rec.serviceEnd,   "VKEscrow: newServiceEnd not later");

        require(confirmBy > block.timestamp,   "VKEscrow: confirmBy in past");
        require(uint256(confirmBy) <= block.timestamp + maxExtensionConfirmSeconds,
                "VKEscrow: confirmBy too distant");
        require(confirmBy <= rec.serviceEnd,
                "VKEscrow: confirmBy after current service end");

        rec.pendingAmount       = msg.value;
        rec.pendingServiceEnd   = newServiceEnd;
        rec.extensionConfirmBy  = confirmBy;
        rec.extensionCommitment = extensionCommitment;

        emit EscrowExtensionDeposited(
            paymentCommitment, msg.value, newServiceEnd, confirmBy, msg.sender
        );
    }

    /// @notice VK confirms it accepted the longer term by opening the extension
    ///         commitment. Only the VK can do this — it generated the preimage.
    ///         Callable by any sender holding the secret, so the VK may confirm
    ///         from whichever wallet it uses; no VK address is recorded here.
    function confirmExtension(
        bytes32 paymentCommitment,
        bytes32 extNullifier,
        bytes32 extSecret
    ) external {
        EscrowRecord storage rec = escrows[paymentCommitment];

        require(rec.totalAmount > 0,      "VKEscrow: no escrow for commitment");
        require(rec.pendingServiceEnd > 0,"VKEscrow: no extension pending");
        require(rec.claimedAmount == 0,   "VKEscrow: already claimed or refunded");
        require(block.timestamp <= rec.extensionConfirmBy,
                "VKEscrow: extension confirm window elapsed");
        require(
            keccak256(abi.encodePacked(extNullifier, extSecret)) == rec.extensionCommitment,
            "VKEscrow: extensionCommitment mismatch"
        );

        uint64  previousServiceEnd = rec.serviceEnd;
        uint256 added              = rec.pendingAmount;

        // Record the renewal as its own paid stretch, so an early-deletion refund
        // can price these days at what they actually cost rather than averaging
        // them with the first term.
        termSegments[paymentCommitment].push(TermSegment({
            startTime: previousServiceEnd,
            endTime:   rec.pendingServiceEnd,
            amount:    added
        }));

        rec.serviceEnd   = rec.pendingServiceEnd;
        rec.totalAmount += added;

        rec.pendingAmount       = 0;
        rec.pendingServiceEnd   = 0;
        rec.extensionConfirmBy  = 0;
        rec.extensionCommitment = bytes32(0);

        emit EscrowExtended(
            paymentCommitment, added, rec.totalAmount, previousServiceEnd, rec.serviceEnd
        );
    }

    /// @notice DO takes back extension funds the VK never confirmed. The original
    ///         term is untouched and keeps running to its existing serviceEnd.
    function reclaimExtension(bytes32 paymentCommitment) external {
        EscrowRecord storage rec = escrows[paymentCommitment];

        require(rec.totalAmount > 0,        "VKEscrow: no escrow for commitment");
        require(msg.sender == rec.depositor,"VKEscrow: not depositor");
        require(rec.pendingServiceEnd > 0,  "VKEscrow: no extension pending");
        require(block.timestamp > rec.extensionConfirmBy,
                "VKEscrow: extension confirm window not elapsed");

        uint256 amount            = rec.pendingAmount;
        uint64  pendingServiceEnd = rec.pendingServiceEnd;

        rec.pendingAmount       = 0;
        rec.pendingServiceEnd   = 0;
        rec.extensionConfirmBy  = 0;
        rec.extensionCommitment = bytes32(0);

        if (amount > 0) {
            PayoutLib.send(rec.depositor, amount);
        }

        emit EscrowExtensionReclaimed(paymentCommitment, rec.depositor, amount, pendingServiceEnd);
    }

    /// @dev Returns any unconfirmed extension funds to the DO and clears the
    ///      pending state. Used by every terminal path so parked money is never
    ///      swept into a VK payout or stranded in the contract.
    function _refundPendingExtension(EscrowRecord storage rec) internal returns (uint256) {
        uint256 amount = rec.pendingAmount;
        if (rec.pendingServiceEnd == 0 && amount == 0) {
            return 0;
        }
        rec.pendingAmount       = 0;
        rec.pendingServiceEnd   = 0;
        rec.extensionConfirmBy  = 0;
        rec.extensionCommitment = bytes32(0);
        return amount;
    }

    function _depositOne(
        bytes32 paymentCommitment,
        bytes32 sizeCommitment,
        bytes32 linkCommitment,
        uint64  serviceEnd,
        uint256 amount,
        address depositor,
        bool finalized,
        uint64 finalizeBy,
        uint64 registrationDeadline
    ) internal {
        _requireNotDeprecated();
        require(amount > 0,                                 "VKEscrow: zero value");
        require(serviceEnd > block.timestamp,               "VKEscrow: serviceEnd in past");
        _validateRegistrationDeadline(serviceEnd, registrationDeadline);
        require(paymentCommitment != bytes32(0),            "VKEscrow: zero paymentCommitment");
        require(sizeCommitment    != bytes32(0),            "VKEscrow: zero sizeCommitment");
        require(linkCommitment    != bytes32(0),            "VKEscrow: zero linkCommitment");
        require(escrows[paymentCommitment].totalAmount == 0,"VKEscrow: already deposited");
        if (!finalized) {
            require(finalizeBy > block.timestamp, "VKEscrow: invalid finalizeBy");
        }

        escrows[paymentCommitment] = EscrowRecord({
            totalAmount:    amount,
            serviceStart:   uint64(block.timestamp),
            serviceEnd:     serviceEnd,
            sizeCommitment: sizeCommitment,
            linkCommitment: linkCommitment,
            finalized:      finalized,
            finalizeBy:     finalizeBy,
            claimedAmount:  0,
            paymentAddress: address(0),
            depositor:      depositor,
            registrationDeadline: registrationDeadline,
            pendingAmount:       0,
            pendingServiceEnd:   0,
            extensionConfirmBy:  0,
            extensionCommitment: bytes32(0)
        });

        uint256 deletionCost = deletionTxCostEstimate;
        if (deletionCost != 0) deletionTxCostOf[paymentCommitment] = deletionCost;

        emit EscrowDeposited(paymentCommitment, sizeCommitment, linkCommitment, amount, serviceEnd, depositor);
    }

    function _validateRegistrationDeadline(uint64 serviceEnd, uint64 registrationDeadline)
        internal view
    {
        require(registrationDeadline > block.timestamp,
                "VKEscrow: registration deadline in past");
        require(uint256(registrationDeadline) <=
                block.timestamp + maxRegistrationTimeoutSeconds,
                "VKEscrow: registration deadline too distant");
        require(registrationDeadline < serviceEnd,
                "VKEscrow: registration deadline after service end");
    }

    // ─── VK: claim ───────────────────────────────────────────────────────────

    /// @notice VK claims the full escrow by revealing all private values.
    ///         May only be called after serviceEnd has fully passed.
    ///         Before serviceEnd the call reverts silently — no state is written
    ///         and no event is emitted, preserving VK-DO link privacy.
    ///         After serviceEnd the VK operational wallet is the expected caller;
    ///         the VK-DO relationship becomes auditable at that point.
    ///
    /// @param nullifier   First 32-byte payment secret component.
    /// @param secret      Second 32-byte payment secret component.
    /// @param regNullifier  First 32-byte registration secret component.
    /// @param regSecret     Second 32-byte registration secret component.
    /// @param linkNonce   Private 32-byte value binding escrow to file registration.
    function claimEscrow(
        bytes32 nullifier,
        bytes32 secret,
        bytes32 regNullifier,
        bytes32 regSecret,
        bytes32 linkNonce
    ) external {
        bytes32 paymentCommitment = keccak256(abi.encodePacked(nullifier, secret));
        EscrowRecord storage rec  = escrows[paymentCommitment];

        require(rec.totalAmount > 0,               "VKEscrow: no escrow for commitment");
        require(rec.serviceEnd > rec.serviceStart,  "VKEscrow: invalid service period");
        require(rec.finalized, "VKEscrow: escrow not finalized");

        // Silent revert before serviceEnd — no trace, no event.
        require(block.timestamp >= rec.serviceEnd, "VKEscrow: service period not ended");

        // Verify registrationCommitment and linkCommitment to prove VK registered the file.
        bytes32 registrationCommitment = keccak256(abi.encodePacked(regNullifier, regSecret));
        require(
            keccak256(abi.encodePacked(paymentCommitment, registrationCommitment, linkNonce)) == rec.linkCommitment,
            "VKEscrow: linkCommitment mismatch"
        );

        // Verify VK actually registered the file on-chain.
        if (address(fileRegistration) != address(0)) {
            require(
                fileRegistration.registrationCommitmentExists(registrationCommitment),
                "VKEscrow: no file registration found"
            );
            (address registeredVK, bool proofCurrent, uint64 acceptedAt) =
                fileRegistration.registrationCurrentProofStatus(
                    registrationCommitment
                );
            require(registeredVK == msg.sender, "VKEscrow: caller is not registered VK");
            require(
                proofCurrent && acceptedAt >= rec.serviceEnd,
                "VKEscrow: no current proof at service end"
            );
            // The VK must carry the on-chain obligation for the whole term it is
            // being paid for. Without this a renewed escrow could pay a VK whose
            // registered liability still ends at the original serviceEnd — a
            // window assessSectorRisk already treats as over, so the piece could
            // have been dropped during it with no dispute possible.
            require(
                fileRegistration.registrationServiceEnd(registrationCommitment) >= rec.serviceEnd,
                "VKEscrow: registration does not cover service end"
            );
        }

        // Block full-payment claim when the DO already confirmed deletion on-chain.
        // In that case VK must use claimEscrowOnDeletion() to receive only the
        // pro-rated portion — not the full amount for a service period it did not complete.
        if (address(fileRegistrationForDeletion) != address(0)) {
            bytes32 ch = fileRegistrationForDeletion.registrationCommitmentToCommitmentHash(registrationCommitment);
            if (ch != bytes32(0)) {
                require(
                    !fileRegistrationForDeletion.isDeletionConfirmed(ch),
                    "VKEscrow: file was deleted early; use claimEscrowOnDeletion"
                );
            }
        }

        // Lock payment address on first claim.
        if (rec.paymentAddress == address(0)) {
            rec.paymentAddress = msg.sender;
        } else {
            require(msg.sender == rec.paymentAddress, "VKEscrow: wrong payment address");
        }

        uint256 releasable = rec.totalAmount - rec.claimedAmount;
        require(releasable > 0, "VKEscrow: already fully claimed");

        // An extension the VK never confirmed was never earned: it goes back to
        // the DO rather than being swept into this payout.
        uint256 pendingRefund = _refundPendingExtension(rec);

        rec.claimedAmount += releasable;
        completedPieces[msg.sender] += 1;

        if (rewardManager != address(0)) {
            try IRewardManager_VKE(rewardManager).creditVKFile(msg.sender) {} catch {}
        }

        PayoutLib.send(msg.sender, releasable);
        if (pendingRefund > 0) {
            PayoutLib.send(rec.depositor, pendingRefund);
        }

        emit EscrowClaimed(paymentCommitment, msg.sender, releasable, rec.claimedAmount);
    }

    // ─── VK: early claim after confirmed deletion ─────────────────────────────

    /// @notice VK claims pro-rated escrow after the DO has confirmed file deletion.
    ///         Can be called before serviceEnd — the deletion confirmation is the gate.
    ///         VK receives payment for the actual storage time PLUS the on-chain deletion
    ///         transaction cost reimbursement; the remainder returns to DO automatically.
    ///
    /// @param nullifier      First 32-byte payment secret component.
    /// @param secret         Second 32-byte payment secret component.
    /// @param regNullifier   First 32-byte registration secret component.
    /// @param regSecret      Second 32-byte registration secret component.
    /// @param linkNonce      Private 32-byte value binding escrow to file registration.
    function claimEscrowOnDeletion(
        bytes32 nullifier,
        bytes32 secret,
        bytes32 regNullifier,
        bytes32 regSecret,
        bytes32 linkNonce
    ) external {
        require(address(fileRegistrationForDeletion) != address(0), "VKEscrow: deletion registry not set");

        bytes32 paymentCommitment = keccak256(abi.encodePacked(nullifier, secret));
        EscrowRecord storage rec  = escrows[paymentCommitment];

        require(rec.totalAmount > 0,               "VKEscrow: no escrow for commitment");
        require(rec.claimedAmount == 0,            "VKEscrow: already claimed or refunded");
        require(rec.serviceEnd > rec.serviceStart,  "VKEscrow: invalid service period");
        require(rec.finalized, "VKEscrow: escrow not finalized");

        // Verify linkCommitment — identical privacy model to claimEscrow().
        bytes32 registrationCommitment = keccak256(abi.encodePacked(regNullifier, regSecret));
        require(
            keccak256(abi.encodePacked(paymentCommitment, registrationCommitment, linkNonce)) == rec.linkCommitment,
            "VKEscrow: linkCommitment mismatch"
        );

        // Resolve commitmentHash from the VK's registration commitment.
        bytes32 commitmentHash = fileRegistrationForDeletion.registrationCommitmentToCommitmentHash(registrationCommitment);
        require(commitmentHash != bytes32(0), "VKEscrow: registration commitment not found");

        // Claim secrets identify the escrow, not its beneficiary. Read the original
        // VK from the same registry that confirms deletion; an active/current-proof
        // check would incorrectly reject a legitimately deleted registration.
        (address registeredVK, , , ) = fileRegistrationForDeletion.getFileRecordForDeletion(commitmentHash);
        require(registeredVK == msg.sender, "VKEscrow: caller is not registered VK");

        // Gate: deletion must be confirmed on-chain by DO.
        require(
            fileRegistrationForDeletion.isDeletionConfirmed(commitmentHash),
            "VKEscrow: deletion not confirmed"
        );

        uint64 confirmedAt = fileRegistrationForDeletion.getDeletionConfirmedAt(commitmentHash);
        require(confirmedAt > rec.serviceStart, "VKEscrow: confirmedAt out of range");

        // Pro-rata across each paid stretch at its own price.
        uint256 vkShare       = _earnedByDeletion(paymentCommitment, rec, confirmedAt);
        uint256 vkTotal       = vkShare + deletionTxCostOf[paymentCommitment];
        if (vkTotal > rec.totalAmount) vkTotal = rec.totalAmount;
        uint256 doRefund      = rec.totalAmount - vkTotal;

        // Lock payment address on first claim.
        if (rec.paymentAddress == address(0)) {
            rec.paymentAddress = msg.sender;
        } else {
            require(msg.sender == rec.paymentAddress, "VKEscrow: wrong payment address");
        }

        // An extension the VK never confirmed rides back to the DO with the
        // unused remainder. Pro-rata above deliberately ignores it: it was never
        // part of the agreed term the VK was serving.
        doRefund += _refundPendingExtension(rec);

        // Mark fully claimed to block reclaimEscrow and double-claim.
        rec.claimedAmount = rec.totalAmount;
        completedPieces[msg.sender] += 1;

        if (rewardManager != address(0)) {
            try IRewardManager_VKE(rewardManager).creditVKFile(msg.sender) {} catch {}
        }

        PayoutLib.send(msg.sender, vkTotal);

        if (doRefund > 0) {
            PayoutLib.send(rec.depositor, doRefund);
        }

        emit EscrowClaimedOnDeletion(paymentCommitment, msg.sender, vkTotal, doRefund, confirmedAt);
    }

    /// @dev What the VK has earned when the piece is deleted at `confirmedAt`.
    ///
    ///      Each paid stretch is settled at its own price: a stretch already
    ///      finished pays in full, one never started pays nothing, and the one
    ///      in progress is split by time. With no renewals this is exactly the
    ///      original single pro-rata calculation.
    function _earnedByDeletion(
        bytes32 paymentCommitment,
        EscrowRecord storage rec,
        uint64 confirmedAt
    ) internal view returns (uint256 earned) {
        TermSegment[] storage segments = termSegments[paymentCommitment];

        // The first term is implicit: it ends where the first renewal begins,
        // and is worth whatever the renewals did not pay for.
        uint64  firstTermEnd = segments.length == 0
            ? rec.serviceEnd
            : segments[0].startTime;
        uint256 renewalTotal;
        for (uint256 i = 0; i < segments.length; i++) {
            renewalTotal += segments[i].amount;
        }
        uint256 firstTermAmount = rec.totalAmount - renewalTotal;

        earned = _earnedInSegment(rec.serviceStart, firstTermEnd, firstTermAmount, confirmedAt);
        for (uint256 i = 0; i < segments.length; i++) {
            earned += _earnedInSegment(
                segments[i].startTime, segments[i].endTime, segments[i].amount, confirmedAt
            );
        }
    }

    function _earnedInSegment(
        uint64 startTime,
        uint64 endTime,
        uint256 amount,
        uint64 confirmedAt
    ) internal pure returns (uint256) {
        if (amount == 0 || endTime <= startTime) return 0;
        if (confirmedAt >= endTime)   return amount;  // stretch fully served
        if (confirmedAt <= startTime) return 0;       // stretch never started
        return (uint256(confirmedAt - startTime) * amount) / uint256(endTime - startTime);
    }

    /// @notice How many renewal stretches this agreement has, and the total they
    ///         paid for. Lets a DO see how close it is to the renewal limit.
    function termSegmentCount(bytes32 paymentCommitment) external view returns (uint256) {
        return termSegments[paymentCommitment].length;
    }

    /// @notice What the VK would earn if deletion were confirmed at `atTime`.
    ///         Mirrors claimEscrowOnDeletion's split, without the tx-cost top-up.
    function earnedIfDeletedAt(bytes32 paymentCommitment, uint64 atTime)
        external view returns (uint256)
    {
        EscrowRecord storage rec = escrows[paymentCommitment];
        if (rec.totalAmount == 0 || atTime <= rec.serviceStart) return 0;
        return _earnedByDeletion(paymentCommitment, rec, atTime);
    }

    // ─── DO: timeout reclaim ─────────────────────────────────────────────────

    /// @notice DO reclaims a deposit after serviceEnd + reclaimGraceSeconds when VK
    ///         never claimed (VK rejected the file or went offline).
    ///         This returns locked capital to an honest DO who was rejected, or
    ///         punishes a bad DO by locking their capital for the full service period.
    /// @param paymentCommitment  The commitment used when calling depositEscrow.
    function reclaimEscrow(bytes32 paymentCommitment) external {
        EscrowRecord storage rec = escrows[paymentCommitment];

        require(rec.totalAmount   > 0,          "VKEscrow: no escrow for commitment");
        require(msg.sender == rec.depositor,     "VKEscrow: not depositor");
        require(rec.claimedAmount == 0,          "VKEscrow: already claimed or refunded");
        require(rec.finalized,                   "VKEscrow: use reclaimUnfinalizedEscrow");
        require(
            block.timestamp >= rec.serviceEnd + reclaimGraceSeconds,
            "VKEscrow: grace period not elapsed"
        );

        uint256 amount = rec.totalAmount + _refundPendingExtension(rec);
        rec.claimedAmount = rec.totalAmount; // prevent re-entry

        PayoutLib.send(rec.depositor, amount);

        emit EscrowReclaimed(paymentCommitment, rec.depositor, amount);
    }

    /// @notice DO reclaims an unfinalized bond-first escrow after finalize window elapsed.
    function reclaimUnfinalizedEscrow(bytes32 paymentCommitment) external {
        EscrowRecord storage rec = escrows[paymentCommitment];

        require(rec.totalAmount > 0, "VKEscrow: no escrow for commitment");
        require(msg.sender == rec.depositor, "VKEscrow: not depositor");
        require(!rec.finalized, "VKEscrow: escrow already finalized");
        require(rec.claimedAmount == 0, "VKEscrow: already claimed or refunded");
        require(block.timestamp > rec.finalizeBy, "VKEscrow: finalize window not elapsed");
        require(registrationTimeoutResolver == address(0),
                "VKEscrow: use registration-timeout resolution");

        rec.claimedAmount = rec.totalAmount;
        uint256 amount = rec.totalAmount + _refundPendingExtension(rec);

        PayoutLib.send(rec.depositor, amount);

        emit EscrowFinalizationReclaimed(paymentCommitment, rec.depositor, amount);
    }

    /// @notice Atomically refunds a registration attempt after the dispute
    ///         contract has fenced the corresponding registration commitment.
    function refundRegistrationTimeout(bytes32 paymentCommitment) external {
        require(msg.sender == registrationTimeoutResolver, "VKEscrow: only timeout resolver");
        EscrowRecord storage rec = escrows[paymentCommitment];
        require(rec.totalAmount > 0, "VKEscrow: no escrow for commitment");
        require(rec.claimedAmount == 0, "VKEscrow: already claimed or refunded");
        require(rec.registrationDeadline > 0 && block.timestamp > rec.registrationDeadline,
                "VKEscrow: registration deadline active");

        rec.claimedAmount = rec.totalAmount;
        uint256 amount = rec.totalAmount + _refundPendingExtension(rec);
        PayoutLib.send(rec.depositor, amount);
        emit EscrowRegistrationTimedOut(
            paymentCommitment, rec.depositor, amount, rec.registrationDeadline
        );
    }

    // ─── Dispute: forced refund ───────────────────────────────────────────────

    /// @notice Called by StorageReceiptDispute on a successful dispute to immediately
    ///         refund the full escrow amount to the original depositor (DO).
    ///         VK receives nothing; DO is made whole before VK can ever claim.
    /// @param paymentCommitment  The escrow commitment being refunded.
    function refundDisputed(bytes32 paymentCommitment) external {
        require(msg.sender == disputeContract, "VKEscrow: only dispute contract");

        EscrowRecord storage rec = escrows[paymentCommitment];
        require(rec.totalAmount  > 0,  "VKEscrow: no escrow for commitment");
        require(rec.claimedAmount == 0, "VKEscrow: already claimed or refunded");

        address depositor = rec.depositor;
        require(depositor != address(0), "VKEscrow: depositor unknown");

        rec.claimedAmount = rec.totalAmount; // block future claim/reclaim
        uint256 amount    = rec.totalAmount + _refundPendingExtension(rec);

        PayoutLib.send(depositor, amount);

        emit EscrowRefundedByDispute(paymentCommitment, depositor, amount);
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    /// @notice Returns how much VK can claim right now using (nullifier, secret).
    ///         Returns 0 before serviceEnd or if linkCommitment check would fail.
    function claimableAmount(bytes32 nullifier, bytes32 secret)
        external view returns (uint256)
    {
        bytes32 pc = keccak256(abi.encodePacked(nullifier, secret));
        EscrowRecord storage rec = escrows[pc];
        if (rec.totalAmount == 0) return 0;
        if (!rec.finalized) return 0;
        if (block.timestamp < rec.serviceEnd) return 0;
        return rec.totalAmount - rec.claimedAmount;
    }

    /// @notice Returns escrow status by paymentCommitment (for DO monitoring / VK pre-check).
    function escrowStatus(bytes32 paymentCommitment)
        external view
        returns (
            uint256 totalAmount,
            uint64  serviceStart,
            uint64  serviceEnd,
            bytes32 sizeCommitment,
            bytes32 linkCommitment,
            uint256 claimedAmount,
            uint256 claimableNow,
            address depositor
        )
    {
        EscrowRecord storage rec = escrows[paymentCommitment];
        totalAmount    = rec.totalAmount;
        serviceStart   = rec.serviceStart;
        serviceEnd     = rec.serviceEnd;
        sizeCommitment = rec.sizeCommitment;
        linkCommitment = rec.linkCommitment;
        claimedAmount  = rec.claimedAmount;
        depositor      = rec.depositor;
        if (rec.totalAmount > 0 && block.timestamp >= rec.serviceEnd) {
            claimableNow = rec.totalAmount - rec.claimedAmount;
        }
    }

    /// @notice Extended escrow status including hybrid-flow finalization fields.
    function escrowStatusV2(bytes32 paymentCommitment)
        external view
        returns (
            uint256 totalAmount,
            uint64  serviceStart,
            uint64  serviceEnd,
            bytes32 sizeCommitment,
            bytes32 linkCommitment,
            uint256 claimedAmount,
            uint256 claimableNow,
            address depositor,
            bool    finalized,
            uint64  finalizeBy
        )
    {
        EscrowRecord storage rec = escrows[paymentCommitment];
        totalAmount    = rec.totalAmount;
        serviceStart   = rec.serviceStart;
        serviceEnd     = rec.serviceEnd;
        sizeCommitment = rec.sizeCommitment;
        linkCommitment = rec.linkCommitment;
        claimedAmount  = rec.claimedAmount;
        depositor      = rec.depositor;
        finalized      = rec.finalized;
        finalizeBy     = rec.finalizeBy;
        if (rec.totalAmount > 0 && rec.finalized && block.timestamp >= rec.serviceEnd) {
            claimableNow = rec.totalAmount - rec.claimedAmount;
        }
    }

    function registrationDeadlineOf(bytes32 paymentCommitment) external view returns (uint64) {
        return escrows[paymentCommitment].registrationDeadline;
    }

    /// @notice Pending-renewal view for DO monitoring and VK pre-check.
    ///         pendingServiceEnd == 0 means no extension is awaiting confirmation.
    function extensionStatus(bytes32 paymentCommitment)
        external view
        returns (
            uint256 pendingAmount,
            uint64  pendingServiceEnd,
            uint64  confirmBy,
            bytes32 extensionCommitment,
            uint64  serviceEnd,
            bool    confirmWindowOpen
        )
    {
        EscrowRecord storage rec = escrows[paymentCommitment];
        pendingAmount       = rec.pendingAmount;
        pendingServiceEnd   = rec.pendingServiceEnd;
        confirmBy           = rec.extensionConfirmBy;
        extensionCommitment = rec.extensionCommitment;
        serviceEnd          = rec.serviceEnd;
        confirmWindowOpen   = rec.pendingServiceEnd > 0 &&
                              block.timestamp <= rec.extensionConfirmBy;
    }
}
