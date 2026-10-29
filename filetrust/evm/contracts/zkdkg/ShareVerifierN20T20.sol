// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T20 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2cae4d07a5b25f568ee0c4021eb023ae56bfba019fd8baf86a876da5e8433267), uint256(0x1f3171d4f9ef92cdc69ca2592e63decebf60889e738aa48202647c4792bb7a56));
        vk.beta = Pairing.G2Point([uint256(0x12bbdfcb1d849cd45318c0fc40448a19778763c78bb39a856c75dd3241040492), uint256(0x2c723f7de7932f3794cfb80f0292c0cf6f0bfc676bd2d13e844ba0a72c9ce26a)], [uint256(0x13f1f6cb73de23aaa1e979097f383846f13657b815b11c00a4264085769f05d4), uint256(0x10e44089ed18d99c80a8e8b11b851ce90fc5970b0aa00e7358de04ef5d25e19c)]);
        vk.gamma = Pairing.G2Point([uint256(0x2f8e3fb5dfadeed1095fca4b11af142e0d6fe30e0862cf14ac8cce4b262611e5), uint256(0x0b6c8c458e522bca9c033597b4c51988f0b0eb2f96e9efc7fb9ef679662e3695)], [uint256(0x25c58ee0c72ce0e46fe206b699d6382d60546104e6c9e1d70ee46b67e7b6ffad), uint256(0x128868a9472e0e905542b5b8d53b3b4292b9f07c5ba9b4014dacf136245b9b8d)]);
        vk.delta = Pairing.G2Point([uint256(0x0aaf2c8e0d454145f9efc69f5b17847a1a1183cb1069fe1e03a349b9cc2e8b7b), uint256(0x0951e796f5ba3d5bf044db904b648138d6dcfb8e43b44b8fe400824c5ba8e333)], [uint256(0x2476eed3c5f982a94529ca0bba29243b137addc9c6575022b1a9ab96c1990a96), uint256(0x2ce46dd2499603df327da7c457cfa1cf569a58b444537bc9650a51ee600bb0c5)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2da32f0973ae72a9ed9a0e06fb7fb34f554d3429231cfcb32c7fdc0eba1ecb42), uint256(0x145a93b0a06a41228214459409c84c19a01956417ed8fbdf91e9e6e002326c9f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0c7b4d48df55e229eb8800512836e59558223774b230d803313e51e4785271a8), uint256(0x2c776aaf029f73da08a529cfe9b948fdb1b7d5bf547541708a6e005213430e16));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x11261c47956503ccc8c4f63f6625c953650f5876f428a0d2730f4ed04985a925), uint256(0x1f37841057fcdcffe2430abc13bea7640645e63c3575ebfc5a8e13c63069d3e8));
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
