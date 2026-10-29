// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN5T5 {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0aaefbc734a6e7f54dccf6f389a01ea70053ec414a04aa2ae15f133d492a7493), uint256(0x123d876f55245d6a02d69c703812b21cd88deb2b796d0e48807dccfc0848cdc0));
        vk.beta = Pairing.G2Point([uint256(0x16aa77cfe1ac6f00d2242c0357e3893dd1de63c97c077e1b7fee71787b1fc86b), uint256(0x0754bf9bfc90383b899a5ff49f7f67bfee251d9768607db6fa7afd3e0b4f68d6)], [uint256(0x19180a32c60b303ba0623c227c5e709acfb3f8ddc85bbd614473e3ba98a463ad), uint256(0x2b17207e64dba00bb50aa950ac1d4bc960f77fa7c669cb84f93e4681d1ad51b2)]);
        vk.gamma = Pairing.G2Point([uint256(0x2265c26f7282ca6bdba235de50c7d95beaade35a91eb069df04780ea014c4eee), uint256(0x254d0172910f1bb5ae9950db3dcb6ebdd4e5ff4adce44b01da4ebb151e207614)], [uint256(0x2fd479c9e2c36f64c2a3f872c531c4ddfab9cdabee5628c0b5d8990f263bb003), uint256(0x299160147aa9206b3e52a5c625d94c9b7c5427b59294d3eadd8518aae1a898cd)]);
        vk.delta = Pairing.G2Point([uint256(0x26fe3a1c61d81a57023906963fcf7a66c1a8e98184e446ce414de390d261f5ea), uint256(0x163771e6e188c89150fb1356256904d9a00295221696336e41f1d00d564e69a4)], [uint256(0x03810968bd68110700bb522e1394bf18ea55246babd4b228f350cb81da1a4b0a), uint256(0x0ef4d563dec991dd34a69502d425c24938c82c5c6dfa6f887dfda2a3cb7e13c8)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x282fe5a38745829e5f9fadd31cc6e675179a039c506656cffbb47809a60dcd85), uint256(0x20a5a567f2744c67330500eeaac3359a0d579232beda1eb3d75f6f7af5e8a70f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x113aabaf2c5fd3e16c834fa1a91fed0c0a58c847616b67f79949f040623bea5d), uint256(0x02d782bba9d17ddcab01e0ad902b4f87273b401231d814b53a2d8d04eea9fe46));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x05417e6fd53f4869fef9c569c69b0d1446b89bb9716abcb1c474a5eec2c2a162), uint256(0x21cadb740c4b668a5bc03d6e42f6ab65f305e274ac9578e5f27d48a7f36a2d3e));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[2] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](2);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
