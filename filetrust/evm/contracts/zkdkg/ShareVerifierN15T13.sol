// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T13 {
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
        vk.alpha = Pairing.G1Point(uint256(0x073c0404d6ebb3a6e2e54526e7f5ac02097d6dd615633b7e7f318cee1fab524a), uint256(0x0a82fb4b020a1e725838b46bc50984ba5bf63cb480628076c2604fb04c36a755));
        vk.beta = Pairing.G2Point([uint256(0x09f53461ecdae345d09d40aeceadb8818f5896f4336bbf2c39130d84eba3d038), uint256(0x0a844cfca205507ed7e0df072e0e9bfb28172269dd84096f4a5bb21f3577ec76)], [uint256(0x287df8c2e38612fc60a54cd9b25943930e45d762902902f89a90b7c052e7965c), uint256(0x1ce8c33556caf8fc9d3e291fc623a4793ed036c003727f22835168bc5ff4f97e)]);
        vk.gamma = Pairing.G2Point([uint256(0x1bbf60fb6ef05b32ca291820265c02f614bc5dad5842047541a9eb8dc1d09334), uint256(0x2c57b1a01a4205a3675216160d49c78b63cbde647c3655a9e94060394c4d381a)], [uint256(0x2c4fe59dee6af6bd2290246f2b221e28c997796796b7184ac8b1eaecf0e1ef3d), uint256(0x23bcf0f7a8592d9fc028dc6ede28696b3fa149ca025c6673b457187c8030e8f5)]);
        vk.delta = Pairing.G2Point([uint256(0x2ea84f5a29f5234758fd2c466cf857902be9f1da955c2f07d743ab30adb325ac), uint256(0x0f4ebcf53887357f78d7a21bfbd9725aaaa51fa26f245193ccdbb74f04e30947)], [uint256(0x1a73fe02ba6f23146efaa4a2377046afc4236716f7255ad7eb3e8d5bdf56923c), uint256(0x1f9601e850ca7d0c0868fd9af5edf42766f319f554cac75ce2325ae8fff34b23)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x21bce24714f8bfc215349a83d8383f5c21762bc2d67d6a3bf65c9a5a8f38d108), uint256(0x2d8d9a85dff1caf39b19dc7fb4da2e6f13db2b16f3a44cd00a05c044b4a4f4ac));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0b31cffd7b586f6cb8d766aa49dcb75f125fbf29ffb8fe46996b76f855ea9248), uint256(0x175ba825bad605383ab5fcafab9d010c462cb6536092fd4207d2594d4ee4a4a0));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2c2a1ae21215b1af7433b1206364f3f6b85d74b4d9aaf2e1425b2caa92da1b36), uint256(0x2daeba8d79e67672f7140eb40b7e01a5f9ea902b1cb0010fea9aa40ef27e5b6b));
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
