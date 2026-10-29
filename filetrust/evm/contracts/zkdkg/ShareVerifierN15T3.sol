// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T3 {
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
        vk.alpha = Pairing.G1Point(uint256(0x1087ee2bc8ac03e417552364db6b4af30a49c20183409cc7f73b630c942841a7), uint256(0x262196125e547e48cb399ecb1a03d2969d4f66c3d405d035d5ea73574dfc3e6a));
        vk.beta = Pairing.G2Point([uint256(0x19cd7dad1cb12979d3e939092d467349c3a48366d4d6312074057c39a9d62b53), uint256(0x1770505739c8021aee9c50c9b0c3a761a08238e96d1fb4e385778a89ec79a868)], [uint256(0x08ef49e2155a1c9f311c65a8cb1328dba91517094749e901b006edb39c4815a6), uint256(0x115d8481a6061daa18568ace64df8eb5fd21475b1e50174f87ba8a50d19f59db)]);
        vk.gamma = Pairing.G2Point([uint256(0x2068dff21e72f11ce06d36ece91728d1c69b10129d1fd96410bf5bc9be06efcb), uint256(0x0f871283a31038463332d567dc7b2bd9e3b9528f25560fc348844154833be722)], [uint256(0x249c529931b7ee6e210780a2f19fc4ee6cff7bbd780e27c7b88bd92d563445db), uint256(0x22a1f0904ee0b015c92db1e42091467ab3f57edb2077c14fc31b2d071fc3362c)]);
        vk.delta = Pairing.G2Point([uint256(0x253b00e5e30474fd75c0d43867f3cc68acfd2f97dbff7273f03ec7903f5148f1), uint256(0x2499833e69b55a0c23e07359de89a008609462a64af470cbcdb2742ac51bc719)], [uint256(0x23eda31fea0d97be58bbbab8f24b5bd4d65c29df1d02dc258d7435d1a65e0911), uint256(0x1e40409cfa73b439cc5d1ff62244459491799c65fbf600b71831d2dcaa8bd7a0)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2bc724d2d31fc35c6b051424acae5e6332807fc932bbb564c7536b41ed5e1a56), uint256(0x02445ba4f07f102ddc4ff5bf589f7d5a222b836ae210e49229258fecbba93b85));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x04d9b45b1c8cf00e7b872bda7de21c55c303911586a726d81f2c44c2e05e4983), uint256(0x1f0fc48222273f7773875b318c39fed781247ff47d8aefe81b48adb7889101c1));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x21dc13c8adb335ed39af486ca376ac18c1fadb63d3c1ceb317b87b99df3aa86b), uint256(0x222fb1079e3d91e160523e90ed25165a6f2c65284701fe6698720b68ef6625cd));
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
