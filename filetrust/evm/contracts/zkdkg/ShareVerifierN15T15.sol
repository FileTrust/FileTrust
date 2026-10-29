// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T15 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0901bf7bb4b35967af3ba9d959ce002c862110b2d21a7ea25c0acf2bf50e704c), uint256(0x0db985a28be4826a9f092ad1a6e8bb9c516237c5e38984ec1f8ecadd43106679));
        vk.beta = Pairing.G2Point([uint256(0x1c66749764d46355f5699da17816c066e36bbaf82e6b5d1a197ebbeedf034209), uint256(0x062b5b0484b5f1c5a60db4ad82c92f6c969ea26a7fbf1ddbe8f06ab168d69b57)], [uint256(0x2ffee45b9f6b18e279589c770a9b53916a227629216ec8e62d7adfd13c7bf016), uint256(0x10bd0f2690a501ed4eeebe6f929687e3fa24be2776629bdff53a8be1ba6fa56f)]);
        vk.gamma = Pairing.G2Point([uint256(0x2ebb5b0b1c965a37180d25b26439727e9e8ff4b9c2383af3564194180a1043c6), uint256(0x2f1ff33a2b79440646ccd70e8ec4ef2b41d5bd9f3ed6276e4d5d00522a9e0f93)], [uint256(0x08342270ca7574d82dbf0d5a56b2588af811607cdf9b2c05db389af18d0a1a4f), uint256(0x12c3bdd56fa02a48bc01e00dda7cdfc6b7d939da5fd64fa8a4455b50523ff003)]);
        vk.delta = Pairing.G2Point([uint256(0x103296101f003a960a1d3eda3b39faf3cfe8b82d4feaac930253ca8f56e3cf2b), uint256(0x16ef80c680a0c72f51cc9f2d87a7a58fba77edd544bc30a29e8d8ffdb331f808)], [uint256(0x24bafa4e67a792c847354f7b43df82905b58893b7dfea9c5b06eb21a52a622f9), uint256(0x052bbb22ea4a4c6b7048d5044d09fe3831a641ac47282f779c9bb0d4064fbd47)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2ce7c7abf014d63bec298fae0f947fb8b7553c10a82e54d43615d24395812fa2), uint256(0x2ff18af2fccaacf5c20b253fdbb5c00c8caae303b9fd1db16fac70c31021bdf3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1ee42f82a97990213c43dfa19173fc1fa7c7f4fb25095c5e70c53643793ee5d5), uint256(0x18f4c3eb44c911ec92b0bd86fd9ab94ae9a08d86002ab13a6a15321cc10a6d03));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x12b3db21da5a1bf4362d829995b44342bd19c12ed8930ae2fd98776339897463), uint256(0x2fccdf335e1cc5294fddb7d4b5561efe14fa39a87a04bfc3ede26ece527b15f9));
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
