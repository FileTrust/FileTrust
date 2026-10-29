// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T7 {
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
        vk.alpha = Pairing.G1Point(uint256(0x01389beb45f8b529885a52f1fbb25a84bc7e9b39c074691e57c51ae66a6bbe6b), uint256(0x1d33083d54e9d43ea759f550bf2424296816c88b0e48fa6d7bbd8fabb03bbccd));
        vk.beta = Pairing.G2Point([uint256(0x29798e563722a59e68e70a20275200d887588aa3871662a3b26c5b5db78ae036), uint256(0x2c01ef505b12e89119f44ea30cdf0fceb6fafe41e0ea4160da1739c6a66568c3)], [uint256(0x2754fc2e1bf34507e91eb96df919b3c09cb304b6f9b6d924e5411793be808499), uint256(0x27a4227666dec2e00ea65004d30be27d61faa1e22c4e056462b0dd8a98f0b1ce)]);
        vk.gamma = Pairing.G2Point([uint256(0x28898e445a6495e69016aaae6017b5972d83c028dbfe9b466acaa2e3059471af), uint256(0x26bf05b58350e19496cf8542e6f8f517262f4f7f992c2bfd576d2955339f6881)], [uint256(0x02a7b99f7debf6b4c03a61b29749746f02efb40d6575d9652147f1b97c4668e6), uint256(0x1f6c8bcdcc9e1f2f2e0a0c18c368f8e2741263efda4f967aba44f1bfe18ba895)]);
        vk.delta = Pairing.G2Point([uint256(0x049be461cb51c32ac9495d391be677596f29d9f4eff0c0afd7c3f3e077cd5ee0), uint256(0x1a3e18636a062a2b1dce23c9a563c5cc026b22fd4286d1d460011401e953a1d9)], [uint256(0x2740fdb716e21e3af2983bc5792ef0e1466ab16b5d56f1504b7409cc014ad3a4), uint256(0x24a0333770a7c43522963c4a9ea751fa60806290804348ae7cfa83fe2c476a2c)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x10062658b48cae8c6fefdd4ad659666567b1b3909d449da90233dc87c8626b68), uint256(0x101ee82b601907e665ad7f5c1287c6e6ef387189cde94d598cb3418a5c66859d));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x259daa834707cd5fda1f64d642d4211c0ee2421705d68383af744b945087e20f), uint256(0x0af04fcbdbba276531bbc0a1e37643b77160a8f1b62ac8c44e3fa462c020c158));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2db62fff5bf2c56fd0069579a6a24137d09f24edf384fec95acf851d53bb6f8c), uint256(0x04cf1f0a3bde9802f2dc00b37b2b5c632b0b4a114f076e7e34f8ebc8e57eea1a));
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
