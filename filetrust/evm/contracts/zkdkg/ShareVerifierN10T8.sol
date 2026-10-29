// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T8 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0b022c11755a528ec80d521a55ed4c12072c0ebf2b8768fa0ed5b7228f170484), uint256(0x23d0eaa944d6217d9970be948658edff7f3b060b9f72d3fb36cccd58706de7b5));
        vk.beta = Pairing.G2Point([uint256(0x1e94d319df763b3d1390beb7184bc4623c88cb8ed11411386f206c498b026fe7), uint256(0x2ac9bf00b64b0665e22e5e16bb23d43f0f13fb95309cca6c1450922a40e59ac1)], [uint256(0x129564e7cddd530f1903a931deb4a6f2e57109750788d63d8fae4043f3332707), uint256(0x1d83b0387e4960b62f24f7e2a29d5a8ad119e3adba1da1af141cb3fd589156f6)]);
        vk.gamma = Pairing.G2Point([uint256(0x1b67aeb027de3191392a441616bffbd5be2cc44cb4b85b9d54ffe9ab2b0c4ba3), uint256(0x2eb324b2baf4708d082d1cf2d4258f0de799845ff391e7932d905b927ab0975f)], [uint256(0x0d69ca082e02c4f20554b35dd4623c84b4686a70b795abc58af5f73d373e9d09), uint256(0x23514c317b3e4eae57c99299b321307dac7285b3b009213b71896dad51019927)]);
        vk.delta = Pairing.G2Point([uint256(0x230a690095e8e0a945622ad73cb36addd636ce7230e7db8cfadbb075c8321338), uint256(0x2aa2775b5f317714ecec20c328122f5c4b19b4f7d76bd5fd399627bd8082434a)], [uint256(0x083991f69900399c9d49cfcf1862cbb9ed5388ab69876f7e61d5185dfb45e852), uint256(0x120f60c955e8d019e247506db3901d3fba11b57f4077814d569a2eae3386cc58)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2e6c25d59b5ff09415bc0094d59eaf98085cd2dca43e50e70d739f0e3e7b3195), uint256(0x013effd21c096de6458263840045f60ad4bbb11720f4b2d67d3e1f3eee1d7718));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x005ba2aa66c881bce7b9b64f7244a2d114239f0a402461f04d0ddffc6e8cb6de), uint256(0x090cc24a060b12b6e7f0d77552e040e3bd3f880911d445c4bc2ea20ca6c098db));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1313deb61ddb5bc49f16774ff2eb4f65c6a2df36e8d5a3c9f0d58c572e73cef2), uint256(0x154cc56a6020fab23fdd684b3fc0514e18bcc3f197d45b82f2c334bd206e25a4));
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
