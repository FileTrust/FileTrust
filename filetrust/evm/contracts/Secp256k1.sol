// SPDX-License-Identifier: FSL-1.1-ALv2
//
//███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
//██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
//█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
//██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
//██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
//╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
//
// Contract: Secp256k1
// Purpose:  secp256k1 helpers, for recovering who signed something.
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

/// @notice secp256k1 as standardised by SECG (SEC 2). The parameters below are
///         the published ones; the Solidity is ours.
library Secp256k1 {
    uint256 internal constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 internal constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

    function isOnCurve(uint256 x, uint256 y) internal pure returns (bool) {
        if (x == 0 && y == 0) {
            return false;
        }
        if (x >= P || y >= P) {
            return false;
        }
        uint256 lhs = mulmod(y, y, P);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        return lhs == rhs;
    }

    function inv(uint256 x) internal view returns (uint256) {
        require(x != 0, "Secp256k1: inverse of zero");
        return modexp(x, P - 2, P);
    }

    function modexp(uint256 base, uint256 exponent, uint256 modulus) internal view returns (uint256 result) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exponent, modulus);
        bytes memory output = new bytes(32);
        bool success;
        assembly {
            success := staticcall(gas(), 0x05, add(input, 0x20), mload(input), add(output, 0x20), 0x20)
        }
        require(success, "Secp256k1: modexp failed");
        result = abi.decode(output, (uint256));
    }

    function add(uint256 x1, uint256 y1, uint256 x2, uint256 y2) internal view returns (uint256 x3, uint256 y3) {
        if (x1 == 0 && y1 == 0) {
            return (x2, y2);
        }
        if (x2 == 0 && y2 == 0) {
            return (x1, y1);
        }
        if (x1 == x2) {
            if (y1 != y2) {
                return (0, 0);
            }
            if (y1 == 0) {
                return (0, 0);
            }
            uint256 sDouble = mulmod(3, mulmod(x1, x1, P), P);
            sDouble = mulmod(sDouble, inv(mulmod(2, y1, P)), P);
            x3 = addmod(mulmod(sDouble, sDouble, P), P - addmod(x1, x2, P), P);
            y3 = addmod(mulmod(sDouble, addmod(x1, P - x3, P), P), P - y1, P);
            return (x3, y3);
        }
        uint256 s = mulmod(addmod(y2, P - y1, P), inv(addmod(x2, P - x1, P)), P);
        x3 = addmod(mulmod(s, s, P), P - addmod(x1, x2, P), P);
        y3 = addmod(mulmod(s, addmod(x1, P - x3, P), P), P - y1, P);
    }

    function mul(uint256 k, uint256 x, uint256 y) internal view returns (uint256 rx, uint256 ry) {
        rx = 0;
        ry = 0;
        uint256 px = x;
        uint256 py = y;

        while (k != 0) {
            if ((k & 1) != 0) {
                (rx, ry) = add(rx, ry, px, py);
            }
            (px, py) = add(px, py, px, py);
            k >>= 1;
        }
    }
}
