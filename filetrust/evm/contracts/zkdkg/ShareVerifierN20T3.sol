// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T3 {
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
        vk.alpha = Pairing.G1Point(uint256(0x191ab5f0d3ee3f2bea12130abacf2a83c28eb694f0d35be14f4b845a8e718844), uint256(0x102f04e80517fd8437f1e412f1954a58fcff9bc768eb7dcba8d4a52ef22278bc));
        vk.beta = Pairing.G2Point([uint256(0x0aab087b2bf0948215b0e49fd1ee5b5e4faa7ec431bf46e43e01a75e37694f5c), uint256(0x2818dec9d9284a7192b01f2441107bbb29688f1cc217aef173ac2b8377c6e0e5)], [uint256(0x0a73160b919fbab8ebec3d8bd44a3689f421067cdeb24a6314009be7bf393fb3), uint256(0x20205a4524d66f1e90cf73c5d6d5a4e83956d1bd1cfc8619d35031f0748d5331)]);
        vk.gamma = Pairing.G2Point([uint256(0x0efd23aa0ee65e2093de630baddfc0dc4689d19c88618cf6ca70e26818e38113), uint256(0x179019d89a390b3ab379d761430ea397bffbe85e8ca7df9a4a48eccf473a1d4a)], [uint256(0x219fc1690f98df3d30f3e315095ab017c33174f56e761a663eea97ea06333aed), uint256(0x2c88bb34ccbec89431cd13148a47eaeb6d5834825c99804f93b0ac6b9125416f)]);
        vk.delta = Pairing.G2Point([uint256(0x2917408b599a732e66f0747f610339503ac3ffa94daac2f3908cba0e9eafef18), uint256(0x196cf48d7bad846ef113d8e767762c982e7e4a847075195454dfe5a9923c7b57)], [uint256(0x25f82f80556bbdab60260d9735296e0d686abf2a0889ab41a90353fc63093535), uint256(0x15c368b49dbaee0411300484d3d6000884ecb5b7f0ad0946e7c9b3655322e31b)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x04d45ec868fbe2bbd53b23d03503a07092a5ec22c1f0a014b039682b5056a12d), uint256(0x270f42741a940309958c331bf0dc60bbe74938380404f726eef196abe82e7912));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x071842ea8d28f894afbbc73ce069ae3b128b5e6a926a9f8c021fe7658e8d94bc), uint256(0x14596f9476ebaa9ade4b0b9ccfbf4f90987351f86a8ffd6c7b6e5e4fb6d93cc9));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x27e3df154f879c3d0e60ec24db6b6696e4bd79e0f4b4237d379709bb43f5e708), uint256(0x10a853a44ed55daa2841453264a54e7ba3e604f9ba57074ef97389a899c1f9f4));
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
