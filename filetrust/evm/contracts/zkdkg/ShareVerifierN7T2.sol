// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN7T2 {
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
        vk.alpha = Pairing.G1Point(uint256(0x04493bbf662782c73cb8577318fa6d3e95f17e75439e893529fbf80fb2b2ef28), uint256(0x0eeb426048e86758fbeb34562eef09889ae49e09dff395dc1b091cc09ed9ded4));
        vk.beta = Pairing.G2Point([uint256(0x2682c92405689d66e8801510406cfc8cd6fd29e965eb76839a067e92a2621eb7), uint256(0x20dea3fc8a272783bd37ae6549cb56104b2103767176e2e32e046fd69da10f1c)], [uint256(0x242c159470eb66e775d9f3d4c8cd4178915d8da19a2494009b2a30023f49825d), uint256(0x02b1e38dde0865472f01f9fb2f446f1ff10dd3c0b7fee07c6a2bedc59fbe6e15)]);
        vk.gamma = Pairing.G2Point([uint256(0x1c35c3b46f101bd5b2da0d6fe601eecc0c351e5e6a56dee81dd3fb5397e93289), uint256(0x0a2f05c749700576c0dc37189b04ccf25cf7b76a6fc85270515ddd0fcb1c8fbc)], [uint256(0x1068e3ad65ba6b317a8377c7f2cca9efc8ebbf512d17489432da4d3884c0d790), uint256(0x0f7b18ba0dc3b218de674a90c85ae18cf2f800e9b982e5edd428b6cf9a1bdc44)]);
        vk.delta = Pairing.G2Point([uint256(0x1a3fa34fa54bc9d2335726e8351ffecaf4e150c0d37408e1ec9ab47c22462035), uint256(0x1acf49b15e651b0b1a73aa728c5340f08f969bb7d3459345e56848dc6e32d7a5)], [uint256(0x0330a24d1ab144c00cea9e41a74bc5533702e4bc378482fc264eaffe99587d83), uint256(0x0ea9c15392f762aec14a70fa8588e903d128df39a8310174896de072a654ef16)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1a1d434e3a028db6979604044f6a6e33e63b8ddfb5c5a9979101e3aa4d1dbb62), uint256(0x290c620582381ff87f79f447fc483468b1da115d9c7ec060ad5e58facd1db76d));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x27bf8718f5218e90b36cdddb1b4e9340b9aed1b70e41e205ed5a0354bbbb5fb2), uint256(0x09b6e8f23cd3a45e15fd9efd4a05eaf1a0b62579a02bed56f63f5e65463fac6f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x049aaf52ef216434742e8fe31691dffe8ea84fb5d4bcc9f9a72caf26bf65f669), uint256(0x15dcc48bc19fb45829dc01fc2bb8e1d217bb3df86324577b4efee548e128f7c4));
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
