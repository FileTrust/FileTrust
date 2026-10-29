// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T2 {
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
        vk.alpha = Pairing.G1Point(uint256(0x1bdb1ae5dae373aae48b4a24fb4801f41c353bbc30935293e1b04a19416c8b7c), uint256(0x183c20e8dab9bec0946144e102a570d2d8695fe729143b9b3aabef855fc4e54d));
        vk.beta = Pairing.G2Point([uint256(0x2c83dca6874f1079508f2fa456be620eee13491dcac18c1ac8af8eef02ee7edd), uint256(0x044d6ca46e162ab3dd8645652bf7cffd06dd0e9c229c728bbdd5c3daf7f71903)], [uint256(0x23dae63c48503d64974f4a54cb4b9986644e60915d2113be42c84c17454eab6c), uint256(0x02ea15691ef2ac2969109629b4ce91213fc1f02fb8ecfa7bfb9eed0d62abbcc2)]);
        vk.gamma = Pairing.G2Point([uint256(0x0de61d4b4315c12b270720bf7a3c32d5d9d70470a86761d183711fd96620a5e9), uint256(0x2f900d43c4107447ea75eb4cd8a187f2617339db301af41a95eb6e190b2f6bcf)], [uint256(0x1e5db330404cccd8d3cf04040e4e4f6f5fb075f40670a09246f816bfe0ddd97b), uint256(0x2bf57a17f1b6b864178eae76f4d36e4e14d505dc3f4b9ff727ee8b59dff81f5c)]);
        vk.delta = Pairing.G2Point([uint256(0x03074b1fede1db001777aa4649dedb734f37b561e6c41e51bce02a180c89c888), uint256(0x1018ee4a0c4fe25603d9bf2eabd0389694150b3d1978a037ba93f24cdab37727)], [uint256(0x2a5000f2435d1683c59defc102d2f7d49013c5845f7cb727419019c0a1ee2956), uint256(0x1b0d197a95e595ae291466dfa936b0548e0c8d55c9db6c64bdd037ccf052ac3b)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x24a006e9471a64bbf0aad89aeaa6677994de91e4b518e46c1095ed448c164fdb), uint256(0x1b43831392febc922529ab520272301ba3234c75ca7ad0f605c92fd3ed658c4c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x242e66a208f1ced155e1a295a04a359fc648440d2bfe28355e3d5bffc5465af1), uint256(0x263592faad39cda5ec9d0a6b997a99dce745dc6e80efd978a5ffc817491717df));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x08c34e2106be895dba50c270048140c08f98ab6899b22e7f8cae34b6e99d1e03), uint256(0x0cfbd36f291d0b5a4298ce111e5e48d9168b122e13b67a374e228b035a7cacd9));
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
