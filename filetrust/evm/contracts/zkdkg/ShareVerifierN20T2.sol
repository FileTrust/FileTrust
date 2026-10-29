// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T2 {
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
        vk.alpha = Pairing.G1Point(uint256(0x142214d2c004c0cb2b4ebee4aba04406ec5a3d2a6623bf37c116b0d9a4202b23), uint256(0x1854b043853cb733e80de5b1721e3514909adf8540becbf1519d9d6a44943d5a));
        vk.beta = Pairing.G2Point([uint256(0x14dee8a2a438ad59e19a530f0839dd23417ad51012070897b91f9fa60114eaa9), uint256(0x2946d6ff570713779585cc9a59ee9aec99b6d8911bdc7fb7adc01b852c85f583)], [uint256(0x10acade5d7885fa1b7bf65d04b27e814f6fb9b6598062f415023a7dc1d1d372d), uint256(0x092a65fc274208a96e02da6d6bb309f722d23581633d35c1e584ecb5e38a73a4)]);
        vk.gamma = Pairing.G2Point([uint256(0x0e46b64cc66d0f7abef0cbda2324b4d92f8d9fa17dd5af23ae55419395d4a9f1), uint256(0x2d51688112aed0df9bcb03f7333e663a656236fb482596af30a1a85b12a73208)], [uint256(0x203584c91ce98d67bf2a1867c98e9fb233a244e8e0594ba6756f86a8f4432072), uint256(0x059d659fc633c27b2ff472fd22de57b348773147ce7009b538e591de90e67d8c)]);
        vk.delta = Pairing.G2Point([uint256(0x15e46989eda42dc01f73a4c12d7caeeebc59cdf8a6d1771b408f837af57efe25), uint256(0x0d6c22a8c6cb1ebc425e7ca532bd3dac78a6ef59baa3a4524b40e960abb56511)], [uint256(0x284cd895c978426ce96395d77781875657ccb5015825831c0352ff15ac779c6a), uint256(0x0ec5257c240cf75defaa9e96b8d2615b4f24691dfe0a8b991ac5fb95e8d47ce7)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1baff8b775e10713c55737563a361559894989944b437a50417d165d9e52d584), uint256(0x08a81f3659947edbb7a12cf4ff82b54ddc6b7176b62fb36604ec6874a80acc4d));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x06affbd83c779c1448135522b0a3cb834b53268d304f499664087b3a817632d5), uint256(0x26aeac75328b8ffb1a1a6d3778d69724c1d7fe5d577a5bc07c6825b018585abd));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x12200421f893f4f7602d79560bb39fd11d2e3535f951b158e31c4dbf988d2274), uint256(0x06653fa19adbbf8ad0607d121fcea3be9698bfa29e9192259ddc002aece10293));
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
