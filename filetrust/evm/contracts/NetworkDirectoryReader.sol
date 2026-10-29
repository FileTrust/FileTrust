// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: NetworkDirectoryReader
// Purpose:  One call that returns a whole page of the Vault Keeper and Guardian
//           tables, so a reader never has to replay the chain.
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

interface IDirVaultKeeperRegistry {
    struct VaultKeeperProfile {
        address vkAddress;
        uint256 storageFee;
        uint256 stake;
        bool active;
        uint256 registeredAt;
        uint256 lastHeartbeat;
        uint64 suspendedUntil;
        uint32 maxServiceDays;
    }
    function getVaultKeeperCount() external view returns (uint256);
    function getVaultKeeperPage(uint256 offset, uint256 limit) external view returns (address[] memory);
    function getVaultKeeper(address vk) external view returns (VaultKeeperProfile memory);
    function vaultKeeperPeerId(address vk) external view returns (string memory);
    function maxPieceSizeBytes(address vk) external view returns (uint64);
    function admissionClosed(address vk) external view returns (bool);
    function admissionClosureReason(address vk) external view returns (uint8);
    function reportedAdmissionFreeBytes(address vk) external view returns (uint64);
    function minimumVaultKeeperStake() external view returns (uint256);
    function defaultAdmissionMarginBytes() external view returns (uint64);
}

interface IDirGuardianRegistry {
    struct GuardianProfile {
        address guardianAddress;
        bytes encryptionPublicKey;
        uint256 dkgBabyJubjubPublicKeyX;
        uint256 dkgBabyJubjubPublicKeyY;
        string metadataURI;
        uint256 dkgFee;
        uint256 telgFee;
        uint256 refreshFee;
        uint256 stake;
        uint32 reputationScore;
        uint32 completedJobs;
        uint32 failedJobs;
        uint32 disputes;
        bool active;
        uint64 registeredAt;
        uint64 lastHeartbeat;
    }
    function getGuardianCount() external view returns (uint256);
    function getGuardianAt(uint256 index) external view returns (address);
    function getGuardian(address guardian) external view returns (GuardianProfile memory);
    function getGuardianServiceInfo(address guardian) external view returns (
        uint256 dkgMaterialSu,
        uint256 dkgShareKeySu,
        uint256 preBatchPartialSu,
        uint256 dailyShareCustodySu,
        uint256 maxServiceDays,
        bool exists
    );
    function minStake() external view returns (uint256);
}

interface IDirReputationManager {
    function getVKStats(address vk) external view returns (
        uint32 reputationScore,
        uint32 penaltyPoints,
        uint32 disputeComplaints,
        uint32 disputePenaltyPoints,
        uint32 missedProofs,
        uint32 totalMissedPenalties,
        uint64 lastActivityAt
    );
    function getGuardianStats(address guardian) external view returns (
        uint32 reputationScore,
        uint32 completedDKG,
        uint32 failedDKG,
        uint32 completedPRE,
        uint32 failedPRE,
        uint32 dkgComplaints,
        uint32 preComplaints,
        uint32 penaltyPoints,
        uint64 lastActivityAt,
        uint32 readyButNotUsedPRE
    );
    function getTotalShareProofPenalties(address guardian) external view returns (uint32);
}

interface IDirVKEscrow {
    function completedPieces(address vk) external view returns (uint256);
}

interface IDirStorageProof {
    function lastProofAt(address vk) external view returns (uint64);
}

interface IDirCapacityProof {
    function capacityAccountingOf(address vk) external view returns (
        uint64 declaredBytes,
        uint64 registeredFree,
        uint64 registeredData,
        uint64 provedFree,
        uint64 provedData,
        uint64 quoteReserved,
        uint64 allocatedStored,
        uint64 conservativeFree,
        uint64 latestCapacityProofAt,
        bool proofFresh
    );
}

interface IDirGuardianShareProof {
    function lastProofAt(address guardian) external view returns (uint256);
    function proofPeriodSeconds() external view returns (uint256);
}

interface IDirTElGv2 {
    function preBadPartialCount(address guardian) external view returns (uint256);
}

/// @title NetworkDirectoryReader
/// @notice Everything the Vault Keeper and Guardian tables show, for a whole page
///         of entries, in one eth_call.
/// @dev Holds no state and changes nothing. A discovery node reads the network
///      through it once a minute and serves the result to every client, so the
///      chain answers one caller per discovery node instead of one per client.
///      Without it a full row costs about seven calls into five contracts, times
///      every keeper and guardian; with it a page of a hundred is one call.
///
///      Every lookup into another contract is wrapped in try/catch. A contract
///      left unset (address zero) or one older than expected leaves its fields
///      at zero instead of failing the whole page, and a row whose own registry
///      lookup fails comes back with `ok = false` so the caller can tell
///      "unknown" apart from "zero".
///
///      Deploy a new one whenever any of the source contracts is redeployed; it
///      is cheap and has nothing to migrate.
contract NetworkDirectoryReader {
    IDirVaultKeeperRegistry public immutable vaultKeeperRegistry;
    IDirGuardianRegistry public immutable guardianRegistry;
    IDirReputationManager public immutable reputationManager;
    IDirVKEscrow public immutable vkEscrow;
    IDirStorageProof public immutable storageProof;
    IDirCapacityProof public immutable capacityProof;
    IDirGuardianShareProof public immutable guardianShareProof;
    IDirTElGv2 public immutable telgV2;

    struct Meta {
        uint256 blockNumber;
        uint256 blockTimestamp;
        uint256 vaultKeeperCount;
        uint256 guardianCount;
        uint256 vaultKeeperMinStake;
        uint256 guardianMinStake;
        uint64 admissionMarginBytes;
        uint256 guardianProofPeriodSeconds;
    }

    struct VaultKeeperRow {
        address vk;
        bool ok;
        string peerId;
        uint256 storageFee;
        uint256 stake;
        bool active;
        uint64 registeredAt;
        uint64 lastHeartbeat;
        uint64 suspendedUntil;
        uint32 maxServiceDays;
        uint64 maxPieceSizeBytes;
        bool admissionClosed;
        uint8 admissionClosureReason;
        uint64 reportedFreeBytes;
        uint32 reputation;
        uint32 penaltyPoints;
        uint32 disputeCount;
        uint32 missedProofs;
        uint64 lastActivityAt;
        uint256 completedPieces;
        uint64 lastProofAt;
        uint64 declaredBytes;
        uint64 registeredFreeBytes;
        uint64 registeredDataBytes;
        uint64 provedFreeBytes;
        uint64 provedDataBytes;
        uint64 conservativeFreeBytes;
        bool capacityProofFresh;
    }

    struct GuardianRow {
        address guardian;
        bool ok;
        bool active;
        uint256 stake;
        uint32 reputation;
        uint32 completedJobs;
        uint32 failedJobs;
        uint32 disputes;
        uint256 dkgFee;
        uint256 telgFee;
        uint256 refreshFee;
        uint64 registeredAt;
        uint64 lastHeartbeat;
        bool pricingSet;
        uint256 dkgMaterialSu;
        uint256 dkgShareKeySu;
        uint256 preBatchPartialSu;
        uint256 dailyShareCustodySu;
        uint256 maxServiceDays;
        uint256 lastProofAt;
        uint32 totalProofPenalties;
        uint32 dkgComplaints;
        uint64 lastActivityAt;
        uint256 preBadPartial;
    }

    constructor(
        address vaultKeeperRegistry_,
        address guardianRegistry_,
        address reputationManager_,
        address vkEscrow_,
        address storageProof_,
        address capacityProof_,
        address guardianShareProof_,
        address telgV2_
    ) {
        vaultKeeperRegistry = IDirVaultKeeperRegistry(vaultKeeperRegistry_);
        guardianRegistry = IDirGuardianRegistry(guardianRegistry_);
        reputationManager = IDirReputationManager(reputationManager_);
        vkEscrow = IDirVKEscrow(vkEscrow_);
        storageProof = IDirStorageProof(storageProof_);
        capacityProof = IDirCapacityProof(capacityProof_);
        guardianShareProof = IDirGuardianShareProof(guardianShareProof_);
        telgV2 = IDirTElGv2(telgV2_);
    }

    /// @notice The contracts this reader looks into. A caller watching for change
    ///         asks for logs from exactly these addresses.
    function sources() external view returns (address[8] memory) {
        return [
            address(vaultKeeperRegistry),
            address(guardianRegistry),
            address(reputationManager),
            address(vkEscrow),
            address(storageProof),
            address(capacityProof),
            address(guardianShareProof),
            address(telgV2)
        ];
    }

    /// @notice Network-wide values every row is judged against, and the block the
    ///         answer was read at.
    function meta() public view returns (Meta memory m) {
        m.blockNumber = block.number;
        m.blockTimestamp = block.timestamp;
        if (address(vaultKeeperRegistry) != address(0)) {
            try vaultKeeperRegistry.getVaultKeeperCount() returns (uint256 n) { m.vaultKeeperCount = n; } catch {}
            try vaultKeeperRegistry.minimumVaultKeeperStake() returns (uint256 s) { m.vaultKeeperMinStake = s; } catch {}
            try vaultKeeperRegistry.defaultAdmissionMarginBytes() returns (uint64 b) { m.admissionMarginBytes = b; } catch {}
        }
        if (address(guardianRegistry) != address(0)) {
            try guardianRegistry.getGuardianCount() returns (uint256 n) { m.guardianCount = n; } catch {}
            try guardianRegistry.minStake() returns (uint256 s) { m.guardianMinStake = s; } catch {}
        }
        if (address(guardianShareProof) != address(0)) {
            try guardianShareProof.proofPeriodSeconds() returns (uint256 p) { m.guardianProofPeriodSeconds = p; } catch {}
        }
    }

    /// @notice Full rows for keepers [offset, offset + limit). Returns a short page
    ///         at the end of the list rather than reverting.
    function vaultKeeperPage(uint256 offset, uint256 limit)
        external
        view
        returns (Meta memory m, VaultKeeperRow[] memory rows)
    {
        m = meta();
        address[] memory page;
        if (address(vaultKeeperRegistry) != address(0)) {
            try vaultKeeperRegistry.getVaultKeeperPage(offset, limit) returns (address[] memory p) {
                page = p;
            } catch {}
        }
        rows = new VaultKeeperRow[](page.length);
        for (uint256 i = 0; i < page.length; i++) {
            rows[i] = _vaultKeeperRow(page[i]);
        }
    }

    /// @notice Full rows for guardians [offset, offset + limit). Returns a short
    ///         page at the end of the list rather than reverting.
    function guardianPage(uint256 offset, uint256 limit)
        external
        view
        returns (Meta memory m, GuardianRow[] memory rows)
    {
        m = meta();
        uint256 total = m.guardianCount;
        if (offset >= total || limit == 0) {
            return (m, new GuardianRow[](0));
        }
        uint256 end = offset + limit;
        if (end > total) {
            end = total;
        }
        rows = new GuardianRow[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            address g;
            try guardianRegistry.getGuardianAt(i) returns (address a) { g = a; } catch {}
            rows[i - offset] = _guardianRow(g);
        }
    }

    function _vaultKeeperRow(address vk) internal view returns (VaultKeeperRow memory r) {
        r.vk = vk;
        IDirVaultKeeperRegistry reg = vaultKeeperRegistry;
        try reg.getVaultKeeper(vk) returns (IDirVaultKeeperRegistry.VaultKeeperProfile memory p) {
            r.ok = true;
            r.storageFee = p.storageFee;
            r.stake = p.stake;
            r.active = p.active;
            r.registeredAt = uint64(p.registeredAt);
            r.lastHeartbeat = uint64(p.lastHeartbeat);
            r.suspendedUntil = p.suspendedUntil;
            r.maxServiceDays = p.maxServiceDays;
        } catch {
            return r;
        }
        try reg.vaultKeeperPeerId(vk) returns (string memory s) { r.peerId = s; } catch {}
        try reg.maxPieceSizeBytes(vk) returns (uint64 v) { r.maxPieceSizeBytes = v; } catch {}
        try reg.admissionClosed(vk) returns (bool v) { r.admissionClosed = v; } catch {}
        try reg.admissionClosureReason(vk) returns (uint8 v) { r.admissionClosureReason = v; } catch {}
        try reg.reportedAdmissionFreeBytes(vk) returns (uint64 v) { r.reportedFreeBytes = v; } catch {}

        if (address(reputationManager) != address(0)) {
            try reputationManager.getVKStats(vk) returns (
                uint32 rep, uint32 pen, uint32 disputes, uint32, uint32 missed, uint32, uint64 lastActivity
            ) {
                r.reputation = rep;
                r.penaltyPoints = pen;
                r.disputeCount = disputes;
                r.missedProofs = missed;
                r.lastActivityAt = lastActivity;
            } catch {}
        }
        if (address(vkEscrow) != address(0)) {
            try vkEscrow.completedPieces(vk) returns (uint256 v) { r.completedPieces = v; } catch {}
        }
        if (address(storageProof) != address(0)) {
            try storageProof.lastProofAt(vk) returns (uint64 v) { r.lastProofAt = v; } catch {}
        }
        if (address(capacityProof) != address(0)) {
            try capacityProof.capacityAccountingOf(vk) returns (
                uint64 declared, uint64 regFree, uint64 regData, uint64 provFree, uint64 provData,
                uint64, uint64, uint64 consFree, uint64, bool fresh
            ) {
                r.declaredBytes = declared;
                r.registeredFreeBytes = regFree;
                r.registeredDataBytes = regData;
                r.provedFreeBytes = provFree;
                r.provedDataBytes = provData;
                r.conservativeFreeBytes = consFree;
                r.capacityProofFresh = fresh;
            } catch {}
        }
    }

    function _guardianRow(address g) internal view returns (GuardianRow memory r) {
        r.guardian = g;
        if (g == address(0)) {
            return r;
        }
        try guardianRegistry.getGuardian(g) returns (IDirGuardianRegistry.GuardianProfile memory p) {
            r.ok = true;
            r.active = p.active;
            r.stake = p.stake;
            r.reputation = p.reputationScore;
            r.completedJobs = p.completedJobs;
            r.failedJobs = p.failedJobs;
            r.disputes = p.disputes;
            r.dkgFee = p.dkgFee;
            r.telgFee = p.telgFee;
            r.refreshFee = p.refreshFee;
            r.registeredAt = p.registeredAt;
            r.lastHeartbeat = p.lastHeartbeat;
        } catch {
            return r;
        }
        try guardianRegistry.getGuardianServiceInfo(g) returns (
            uint256 mat, uint256 shareKey, uint256 pre, uint256 custody, uint256 maxDays, bool exists
        ) {
            r.pricingSet = exists;
            r.dkgMaterialSu = mat;
            r.dkgShareKeySu = shareKey;
            r.preBatchPartialSu = pre;
            r.dailyShareCustodySu = custody;
            r.maxServiceDays = maxDays;
        } catch {}

        if (address(reputationManager) != address(0)) {
            try reputationManager.getTotalShareProofPenalties(g) returns (uint32 v) { r.totalProofPenalties = v; } catch {}
            try reputationManager.getGuardianStats(g) returns (
                uint32, uint32, uint32, uint32, uint32, uint32 dkgComplaints, uint32, uint32, uint64 lastActivity, uint32
            ) {
                r.dkgComplaints = dkgComplaints;
                r.lastActivityAt = lastActivity;
            } catch {}
        }
        if (address(guardianShareProof) != address(0)) {
            try guardianShareProof.lastProofAt(g) returns (uint256 v) { r.lastProofAt = v; } catch {}
        }
        if (address(telgV2) != address(0)) {
            try telgV2.preBadPartialCount(g) returns (uint256 v) { r.preBadPartial = v; } catch {}
        }
    }
}
