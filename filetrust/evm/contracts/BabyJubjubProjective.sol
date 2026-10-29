// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: BabyJubjubProjective
// Purpose:  Bounded encryption-key multiplication and prime-subgroup checks.
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

import "./BabyJubjub.sol";

/// @dev Extended twisted Edwards coordinates: X/Z, Y/Z and XY=ZT.
/// No inversions inside the scalar loop. The existing affine implementation
/// remains unchanged for its other consumers.
library BabyJubjubProjective {
    struct Point { uint256 x; uint256 y; uint256 z; uint256 t; }
    uint256 internal constant P = BabyJubjub.P;
    uint256 internal constant L = 2736030358979909402780800718157159386076813972158567259200215660948447373041;

    function add(Point memory a, Point memory b) private pure returns (Point memory c) {
        uint256 xx = mulmod(a.x, b.x, P);
        uint256 yy = mulmod(a.y, b.y, P);
        uint256 dt = mulmod(BabyJubjub.D, mulmod(a.t, b.t, P), P);
        uint256 zz = mulmod(a.z, b.z, P);
        uint256 e = addmod(mulmod(addmod(a.x, a.y, P), addmod(b.x, b.y, P), P), P - addmod(xx, yy, P), P);
        uint256 f = addmod(zz, P - dt, P);
        uint256 g = addmod(zz, dt, P);
        uint256 h = addmod(yy, P - mulmod(BabyJubjub.A, xx, P), P);
        return Point(mulmod(e, f, P), mulmod(g, h, P), mulmod(f, g, P), mulmod(e, h, P));
    }

    function scalar(uint256 k, uint256 x, uint256 y) private pure returns (Point memory r) {
        require(BabyJubjub.isOnCurve(x, y), "BabyJub: off curve");
        return scalarPoint(k, Point(x, y, 1, mulmod(x, y, P)));
    }

    function scalarPoint(uint256 k, Point memory b) private pure returns (Point memory r) {
        r = Point(0, 1, 1, 0);
        while (k != 0) {
            if (k & 1 == 1) r = add(r, b);
            k >>= 1;
            if (k != 0) b = add(b, b);
        }
    }

    /// @dev Horner evaluation uses only the small receiver index as scalar.
    /// Stay projective through the whole polynomial; invert once at the end.
    function evaluate(uint256[] memory xs, uint256[] memory ys, uint8 index) internal view returns (uint256, uint256) {
        require(xs.length == ys.length && index != 0, "BabyJub: polynomial");
        Point memory r = Point(0, 1, 1, 0);
        for (uint256 i = xs.length; i != 0; --i) {
            r = add(scalarPoint(index, r), Point(xs[i-1], ys[i-1], 1, mulmod(xs[i-1], ys[i-1], P)));
        }
        return affine(r);
    }

    function mul(uint256 k, uint256 x, uint256 y) internal view returns (uint256 rx, uint256 ry) {
        Point memory r = scalar(k, x, y);
        return affine(r);
    }

    function addAffine(uint256 x, uint256 y, uint256 u, uint256 v) internal view returns (uint256, uint256) {
        require(BabyJubjub.isOnCurve(x, y) && BabyJubjub.isOnCurve(u, v), "BabyJub: off curve");
        return affine(add(Point(x, y, 1, mulmod(x, y, P)), Point(u, v, 1, mulmod(u, v, P))));
    }

    function affine(Point memory r) private view returns (uint256, uint256) {
        uint256 zi = BabyJubjub.inv(r.z);
        return (mulmod(r.x, zi, P), mulmod(r.y, zi, P));
    }

    function inPrimeSubgroup(uint256 x, uint256 y) internal pure returns (bool) {
        if (!BabyJubjub.isOnCurve(x, y) || BabyJubjub.isIdentity(x, y)) return false;
        Point memory r = scalar(L, x, y); // Deliberately do not reduce L.
        return r.z != 0 && r.x == 0 && r.y == r.z;
    }
}
