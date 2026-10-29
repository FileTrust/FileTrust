// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T14 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0be84375c9945c16a59b81a81d4853f8689ebef8412f2af6e4195c66ccfae5bf), uint256(0x20ba3b25e60742f565d989b382cb5ffb64b6290aa751c6c0299d83c353eb81de));
        vk.beta = Pairing.G2Point([uint256(0x14fadee2d0ec680803710544c5b7bbeaf1343d30693227040a2ec412ca1cdb27), uint256(0x2239f81032c47fafab7b09c882fe64e98f6523ce3980586cd3c4a84d770677d8)], [uint256(0x2b07456a564c73985c22fa4e453553b9a8894be61d7c7652cc9d4bdab737be21), uint256(0x27697332d09cb56bdae38d2a687c1a6aadb8271854170c5bafb50e291551157a)]);
        vk.gamma = Pairing.G2Point([uint256(0x2665b93f71fbf0ca8d962d463716003efea81b4061f2c3fba550954ce732dbdc), uint256(0x03fe2a8d70bfa561a122f1792423c33e0c2d2a7b8aedd5130f7a6fc845311738)], [uint256(0x09eb1a390d893a7c64e11cc1297bcd87aa79051c60fbfe3ad4cf757622628275), uint256(0x20957f6e7810643a5b319d44e1f73d262eddc7d51cb75ac66462813bf541dbea)]);
        vk.delta = Pairing.G2Point([uint256(0x18f98978b0d9aba4bba4bb4c5d882f788d3a3a6ea412b1aebf7c76408a609895), uint256(0x17d189bcafb3c6f17eb132fa79b245b8d2263916e3b8633c8fb133acc7e65a00)], [uint256(0x1caaca1ebb5428e345d18b04eb3e4d43fb44623dfe22c8b7080722bf0f598ae0), uint256(0x08223cfffc78e1db137f56eca19892345c32700c3675109d544fe8ea433d4192)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1a5cb2103f0001ea8fa1bebe401d97c374ad5b76a2c6c4de95de17dfcea12daa), uint256(0x1c2f0e40cd9eb0e1cff977a07253abbd125c27f2bc0ae87f4700d025cb5648fe));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x26aa23115f7a5b71deb075830b5abad466b0b3203fe7eca7d9e29c2f153535bd), uint256(0x01809c6d47ddd677c13737b9eebf528d4b4247acf1fea4b17811351279a758e7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1c19042d8ffffe0ca8b11f8099bd292fdb6250b60d363080cf733df44f39009d), uint256(0x168ac1f8ce6fb6dde172b06b0f8b9db2e82720ec1af0870bbae2158effb2dc47));
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
