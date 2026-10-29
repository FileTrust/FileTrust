// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN7T4 {
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
        vk.alpha = Pairing.G1Point(uint256(0x1e615e553a7b6f64b3225b45f67748c23f947c4c8bd62747cfe413428cbb01f0), uint256(0x155e735cd94a193662dad58baff1ed9d1e482a6889481f8752767cfd2747ed32));
        vk.beta = Pairing.G2Point([uint256(0x05def847e073e80f72eddf9a06bcc76313beffba57ffb94416e0e40a07aa1848), uint256(0x24464c32e08dedde85ca806393cb1293798e9e11716471e827c5352840964832)], [uint256(0x2464762b980c77a8ac0a4d982fbe5f52242a6e1be3430c55d37838fef2b5722c), uint256(0x1a5f33c334a477f7cb2f3f76afc08396bc02dec2ba0e1e898035efdb51045105)]);
        vk.gamma = Pairing.G2Point([uint256(0x2ea007f3edffbcb8a20d8c11d617fabbe2819319634429618e338cb5f8b24352), uint256(0x2aa9f53193e35ca24632ee07a4fbf94582d39ab90955d8ce9475954a8dd5415f)], [uint256(0x11bdc405cc8221ac46ce087c300488c5269b8cbe64c37683f772b93f17cea00c), uint256(0x11d3435f2ebcd0c8dea9bc7bd257984244b94ad8d2c821808767ea35d34594c4)]);
        vk.delta = Pairing.G2Point([uint256(0x177c22ac4fa9a68ce7a9bd9122e4695adf0e90ce79caf5c6f83016cc4fc123c5), uint256(0x0cf02a6024a394d3c21674b5d6de821f89796e4eccbe39af7e1b14d09d4840fa)], [uint256(0x01943afa88169070cee5476caaa3c72564429b98344a29908b26ae8dc00d0d9d), uint256(0x2f7156188c2d9da17b0d8def955470ba184e49eda4eaf6db2a250e10d3bb2197)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1f285792ffef3383c78ff786a5d965e810a3c8dd72ea9ae08928e38de10e3d61), uint256(0x1e926a5e4af2871de920baa86318534cc7735f5f7a1d6aefd024ac34c254b24f));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2debe0c8a51e56e1223fceeff620b316fc8d4ee80dbd5bafdedde16c84d4e5c0), uint256(0x29442d78a33dc3f3f848f8b2ccad75a29e2e9880fe54161ee94d9fa16e691da9));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x09ffa9ad3b569961a66ebae8f62925a7cb4b75e792298a57a5c19d2f617a4cfb), uint256(0x2fbbdd4f7dc3657edd4fba7bbec9a4360600f4b24177d219d3de552cd2aee762));
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
