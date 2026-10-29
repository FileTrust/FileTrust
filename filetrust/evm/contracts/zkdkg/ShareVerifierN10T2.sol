// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T2 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2cfccbe85a8d11924896cff4b66eb7e25848f6398378d2617d475da2242b0a32), uint256(0x183c0bd8fdaaac8e5840e0057c0d17792876197c2c20153242de75bb1f15bb41));
        vk.beta = Pairing.G2Point([uint256(0x217bac95a735d96736a30f1d7adb028cecf2a3b36c020cb5b4fcc373cc4672d1), uint256(0x0ab2c2b92810234fcf55d03dbcad309e72f7c48d5a26057f31f393d76d4be428)], [uint256(0x0995a2e72d3518cbe6971ce44eb0e4f570253f54e674041b7d4547590ccca0f3), uint256(0x17580cbc646a99ec8bd228d09b1fa0c9febb8cb5790a1c839b80ef4a47507b4e)]);
        vk.gamma = Pairing.G2Point([uint256(0x1000d4fdae16ebf78beded654dd323b99f4a0136bcc040871dfc16c0c2704c42), uint256(0x0af81bed546346b0ee75b4cb425e43d759dff7ef68f5773eddc1f86d607abb8e)], [uint256(0x0358e78ce29a2717c7a3947e16bae654dc718b6dd838423ba221e1297a943b68), uint256(0x0a5fc94dd6d7f3733f6aa55bebe18f5e878d0c560b5a74c9cb5119d80b468d72)]);
        vk.delta = Pairing.G2Point([uint256(0x0f60641b2766b8f615136d3b98739fd7289b0d3b0563280de066ec52d4bcca91), uint256(0x206565f0ca8934c1c4aa00a7f048cb80087b120b6f4e1a7ad30b30d646081ce1)], [uint256(0x15ca127caf421bea45376701b150b71dd08e2c9fed0ca5c25a75c3ae5ed95f91), uint256(0x2456152260909d5ad71501e267c1cd41fdcb39327e0eb6c1a63ed87719359429)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2c7c3aa2ec915c33cf39e23df9b9282a28e1576f38f7c453cb8fa7d65e1101ac), uint256(0x12eadebf33f683307b39072700df0ec629de63f414a457861c5e719f4e2a2757));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x27d43056cc673aed5382665f91d02399478d49bac54f94f3bd6655af68551d8b), uint256(0x246eb8a091125c7d65bbac6ce208ee6f368ee03db735415fa1cd7ff336c0b3bb));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1f0f8a4ed86d338eea7047b9b133af82b8b76540eb2e11536a1716c4d06af02d), uint256(0x1520e78d61e939fbf27f1bd98881fb0fd6bb64fdaefcdd8b74485236f27e8e3c));
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
