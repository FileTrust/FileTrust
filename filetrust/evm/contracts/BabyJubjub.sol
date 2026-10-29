// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: BabyJubjub
// Purpose:  Point arithmetic on the Baby Jubjub curve, for the threshold encryption
//           that guards a file's key.
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

/// @notice The curve is Baby Jubjub, as specified in EIP-2494 by Barry WhiteHat,
///         Marta Bellés and Jordi Baylina. The parameters below are theirs; the
///         Solidity is ours.
library BabyJubjub {
    uint256 internal constant P =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant A = 168700;
    uint256 internal constant D = 168696;
    uint256 internal constant GX =
        16540640123574156134436876038791482806971768689494387082833631921987005038935;
    uint256 internal constant GY =
        20819045374670962167435360035096875258406992893633759881276124905556507972311;

    function generator() internal pure returns (uint256 x, uint256 y) {
        return (GX, GY);
    }

    function isIdentity(uint256 x, uint256 y) internal pure returns (bool) {
        return x == 0 && y == 1;
    }

    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        if (x >= P || y >= P) return false;
        uint256 xx = mulmod(x, x, P);
        uint256 yy = mulmod(y, y, P);
        uint256 lhs = addmod(mulmod(A, xx, P), yy, P);
        uint256 rhs = addmod(1, mulmod(mulmod(D, xx, P), yy, P), P);
        return lhs == rhs;
    }

    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        internal
        view
        returns (uint256 x3, uint256 y3)
    {
        require(isOnCurve(x1, y1) && isOnCurve(x2, y2), "BabyJub: off curve");

        uint256 x1x2 = mulmod(x1, x2, P);
        uint256 y1y2 = mulmod(y1, y2, P);
        uint256 dxxyy = mulmod(D, mulmod(x1x2, y1y2, P), P);

        uint256 xNum = addmod(mulmod(x1, y2, P), mulmod(y1, x2, P), P);
        uint256 xDen = addmod(1, dxxyy, P);

        uint256 axx = mulmod(A, x1x2, P);
        uint256 yNum = addmod(y1y2, P - axx, P);
        uint256 yDen = addmod(1, P - dxxyy, P);

        x3 = mulmod(xNum, inv(xDen), P);
        y3 = mulmod(yNum, inv(yDen), P);
    }

    function mul(uint256 scalar, uint256 x, uint256 y) internal view returns (uint256 rx, uint256 ry) {
        require(isOnCurve(x, y), "BabyJub: off curve");
        rx = 0;
        ry = 1;
        uint256 bx = x;
        uint256 by = y;
        uint256 k = scalar;
        while (k != 0) {
            if (k & 1 == 1) {
                (rx, ry) = add(rx, ry, bx, by);
            }
            k >>= 1;
            if (k != 0) {
                (bx, by) = add(bx, by, bx, by);
            }
        }
    }

    function inv(uint256 x) internal view returns (uint256) {
        require(x != 0, "BabyJub: inv zero");
        return expmod(x, P - 2, P);
    }

    function expmod(uint256 base, uint256 exponent, uint256 modulus) internal view returns (uint256 output) {
        bytes memory input = abi.encodePacked(
            uint256(32),
            uint256(32),
            uint256(32),
            base,
            exponent,
            modulus
        );
        bool success;
        assembly {
            success := staticcall(gas(), 5, add(input, 32), mload(input), 0x00, 0x20)
            output := mload(0x00)
        }
        require(success, "BabyJub: modexp failed");
    }
}
