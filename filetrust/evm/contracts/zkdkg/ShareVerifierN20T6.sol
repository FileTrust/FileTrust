// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T6 {
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
        vk.alpha = Pairing.G1Point(uint256(0x17aa5c312454c39366067d8d2305fb09c570c7bcc08ba3848b25b68de962db91), uint256(0x1692390bba7e4ad79e2f4a9fe8be43b83ac9b9044f884b89c035394b680cb6a2));
        vk.beta = Pairing.G2Point([uint256(0x13456b5e50c879d0d47c4eac2468fa60c6615e85098b3f8c2b4ec313535d633a), uint256(0x1b06b23c1ec3d22fe4f09e929863ad3491f4dd0f4413b0b850a58d313ce7c742)], [uint256(0x206f470a0ed21597a96fbbbfdd371d6c9482f0287415a8bc3726c6211492c323), uint256(0x095bc6b467a87d0bbf0b91c4cb64f5dc42c703ee8fd2bd10eaf702f0faf0490d)]);
        vk.gamma = Pairing.G2Point([uint256(0x23ca196595fe3e5571c7c2b3eb132396453ea0e6b67e719b59a0886fd99f8f73), uint256(0x01914f8eeb5f6272a1e755e19b290a676ab4c32db89891af59748c6483e4949d)], [uint256(0x019bf06062347925ab32ee6b39f562c632f9ea7aca807de4276803bfa4f38863), uint256(0x0090c089ecc76f6e180d941ee8d041970b7dd8441e79e9d77c2499d3e9ba64e0)]);
        vk.delta = Pairing.G2Point([uint256(0x10a9c41cf4311ec18855ad166be5421efdd8f22ef8afea813eb723b62c9eee59), uint256(0x240405138dc4ed1834b30eb42f3822931662425ac539daa7e59a86f0627858a5)], [uint256(0x08c3d138f7af6faedadc83f60c5f47a1013b5be1af98a4e05df12800122010a5), uint256(0x049d0df636b69a46c00c386d89ea4f7a1a2bec3e7fd0d259f681ddd3d64e6056)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x25f64b36537cc2e44ac2f6da7aa381cd7467313097d9876efdb56ed155061a2e), uint256(0x0b3fb30fb85c1431108d97f04ada9fe858e097242a45e4cd5be88aba872226ba));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2a9cc3a1cf2f36a5e74949e54e4759d017143c1b59c0dd454942b2f085514ead), uint256(0x05c4150a328404ef5f03b99ab95ba0c32907654c78ce16df9185cc6800ec9528));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0ebb65b96272c609ff5bb83ef143cc143912668d5bb5e7e3c6a3613aec084823), uint256(0x305f9f5f755a33a6ebea7f047fe3b0d6f4e35eb8ceaf134d98fc8646cdded4bb));
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
