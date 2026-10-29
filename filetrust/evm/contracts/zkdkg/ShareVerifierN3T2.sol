// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN3T2 {
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
        vk.alpha = Pairing.G1Point(uint256(0x24810d2aa6891fb9f5dfaea53e630fca7c4bfdc0ce3fb0fd24c4af1cacf5ce73), uint256(0x2446a48b4cb6bd262a7a043b670f4ee6fdd4143e7cdafc079fd703574eea6824));
        vk.beta = Pairing.G2Point([uint256(0x04ff15b80f24334d5d0797f74027ca2028c0090ad17bb809750638777c8c627f), uint256(0x240adbc3e345fe380c133012c5c83994de853e761a0ac24e5258f6e36a6b64dc)], [uint256(0x256e3729ddd923d336d83590eb873549b167d1c80282da1a6aac4829ffcbe0e7), uint256(0x050d0641616b449f2963e880b5831cca4dacfb2283ea837ca10ccc784937c169)]);
        vk.gamma = Pairing.G2Point([uint256(0x0e56ebc739902f65b2d487945039f35eaa0332710242f5e3473c2d7459729c73), uint256(0x230a4ce049edb81a1dd00e1bdff85a0f954f72faf2f46b400157e81bed1ebbe9)], [uint256(0x2adc2ed642b82de45df1cc7b5504100c9ca052156ee5aed8fe810ab35cb52ee6), uint256(0x2c62b7350ba3f4cd26ce633940214cf45b7ac0751339bf28bfe1d7891d385959)]);
        vk.delta = Pairing.G2Point([uint256(0x007b062add7f860e79fab74704b9fc3626f6480e31477d64c7ad89cd80de11ba), uint256(0x0cbc974e6ba0b55f4084fec983028df01ab9d469fac0e0c8db341a0246843084)], [uint256(0x09eed9653f08e63d041d279f2a116b27968f25cfedd476a50f10000b9140678f), uint256(0x1c2369ea746784b521b26c8582e1b84273015eb80e04609bb8a31e9f30122f04)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0716878c95b43ab3e00c37c56d1d67b7d9a0eb310e601a7f03544605855951c3), uint256(0x100107fc0d3558d3da46dde3098597fa16211fa3813b479f78c3573af66690f2));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1f8d5caa074978712f79e1c2831bd3ca9f0922702f5c834d07c6d129261ca635), uint256(0x14ba5c90c675690b17c9368618a55d4fea928f8418dd7c9ee431cb710eed49dc));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x08d95b830eabe001fc33b43238531548a9804b2387b352724b300fffeca2b68a), uint256(0x0d646b0cd5b74ef5c6bde982bfd46f1383c30709682ec4f9d62c717cf82b182f));
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
