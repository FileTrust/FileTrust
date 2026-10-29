// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: DkgCommitmentBook
// Purpose:  Aggregate commitments and verify accepted DKG public shares.
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
import "./DkgAttemptTypes.sol";
import "./BabyJubjubProjective.sol";

/// @notice A controller-owned commitment ledger, separate from the near-limit
/// coordinator. Inputs are recorded only after the controller verifies their
/// exact dispute-batch hash. No private share or proving setup is stored here.
contract DkgCommitmentBook {
    struct Round {
        bool exists;
        bool refresh;
        uint8 threshold;
        uint32 assigned;
        uint32 recorded;
        uint256 pkx;
        uint256 pky;
        uint256[] xs;
        uint256[] ys;
    }
    address public immutable controller = msg.sender;
    mapping(bytes32 => Round) private _rounds;
    mapping(bytes32 => mapping(uint8 => uint256[2])) private _oldShares;
    mapping(bytes32 => mapping(uint8 => uint256)) public dealerWeight;
    error InvalidCommitments();
    modifier onlyController() { if (msg.sender != controller) revert InvalidCommitments(); _; }

    function open(DkgAttemptTypes.Request calldata r, address coordinator) external onlyController {
        Round storage a = _rounds[r.materialId];
        if (a.exists || r.newT < 2 || r.newT > 20 || r.dealerIndices.length == 0
            || (r.refresh && r.dealerIndices.length != r.oldT)) revert InvalidCommitments();
        a.exists = true; a.refresh = r.refresh; a.threshold = r.newT;
        a.pkx = r.publicKeyX; a.pky = r.publicKeyY;
        for (uint8 i; i < r.newT; ++i) { a.xs.push(0); a.ys.push(1); }
        for (uint256 i; i < r.dealerIndices.length; ++i) {
            uint8 index = r.dealerIndices[i];
            uint32 bit = uint32(1) << (index - 1);
            if (index == 0 || index > 20 || (a.assigned & bit) != 0) revert InvalidCommitments();
            a.assigned |= bit;
            if (r.refresh) {
                (bool exists, uint256 x, uint256 y) = IDkgAttemptCoordinator(coordinator).getV2SharePublicKey(r.fileId, r.epoch, r.oldVersion, index);
                if (!exists) revert InvalidCommitments();
                _oldShares[r.materialId][index] = [x, y];
                dealerWeight[r.materialId][index] = weight(index, r.dealerIndices);
            }
        }
    }

    function weight(uint8 index, uint8[] calldata indices) private view returns (uint256) {
        uint256 l = BabyJubjubProjective.L;
        uint256 numerator = 1; uint256 denominator = 1;
        for (uint256 j; j < indices.length; ++j) {
            uint256 other = indices[j];
            if (other == index) continue;
            numerator = mulmod(numerator, l - other, l);
            denominator = mulmod(denominator, addmod(index, l - other, l), l);
        }
        if (denominator == 0) revert InvalidCommitments();
        return mulmod(numerator, BabyJubjub.expmod(denominator, l - 2, l), l);
    }

    function record(bytes32 materialId, uint8 index, uint256[] calldata xs, uint256[] calldata ys) external onlyController {
        Round storage a = _rounds[materialId];
        uint32 bit = uint32(1) << (index - 1);
        if (!a.exists || xs.length != a.threshold || ys.length != a.threshold
            || (a.assigned & bit) == 0 || (a.recorded & bit) != 0) revert InvalidCommitments();
        if (a.refresh) {
            uint256[2] storage old = _oldShares[materialId][index];
            uint256 lambda = dealerWeight[materialId][index];
            uint256 x = old[0];
            if (lambda > BabyJubjubProjective.L / 2) { lambda = BabyJubjubProjective.L - lambda; x = x == 0 ? 0 : BabyJubjub.P - x; }
            (uint256 cx, uint256 cy) = BabyJubjubProjective.mul(lambda, x, old[1]);
            if (xs[0] != cx || ys[0] != cy) revert InvalidCommitments();
        }
        for (uint256 i; i < xs.length; ++i) {
            if (!BabyJubjub.isOnCurve(xs[i], ys[i])) revert InvalidCommitments();
            (a.xs[i], a.ys[i]) = BabyJubjubProjective.addAffine(a.xs[i], a.ys[i], xs[i], ys[i]);
        }
        a.recorded |= bit;
    }

    function expectedShare(bytes32 materialId, uint8 index) external view returns (uint256 x, uint256 y) {
        Round storage a = _complete(materialId);
        return BabyJubjubProjective.evaluate(a.xs, a.ys, index);
    }

    function validateKey(bytes32 materialId, uint256 x, uint256 y) external view {
        Round storage a = _complete(materialId);
        if (BabyJubjub.isIdentity(x, y) || x != a.xs[0] || y != a.ys[0]
            || (a.refresh && (x != a.pkx || y != a.pky))) revert InvalidCommitments();
    }

    function getAggregate(bytes32 materialId) external view returns (uint256[] memory xs, uint256[] memory ys) {
        Round storage a = _complete(materialId);
        return (a.xs, a.ys);
    }

    function _complete(bytes32 materialId) private view returns (Round storage a) {
        a = _rounds[materialId];
        if (!a.exists || a.recorded != a.assigned) revert InvalidCommitments();
    }
}
