// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T4 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0d9bdf99d9e92598dc257a0f9264961918be444d61926748eba51eacd68713d8), uint256(0x112bc0939529b55f080d74be5671f3801838d37c39688219021f112a3bf2f26a));
        vk.beta = Pairing.G2Point([uint256(0x130c19c370cbf5c8106c3bfb350e9915dfddff11892c8508c44f7d7cf36c6c68), uint256(0x2d7e81008c4e707a50c6ca1b1fcf7ab22b202554e659d663df153c2a2b2b2c66)], [uint256(0x1c83c32e89819a269756f82a72b2facae927ff342a94594be9be8dc359f54945), uint256(0x1bb6f404080dab161a73628c03e8c8c1635b5d618c34bad12151372ce9a402be)]);
        vk.gamma = Pairing.G2Point([uint256(0x04c0229e764d46d170e2dbb5886bc7a07c73cfe87b1197053a5a2b6dc297348d), uint256(0x16a77cc72333a603969fb0d70ea061f46a2dcb6aacdb2d5ae85f5e024d3199e9)], [uint256(0x15444be0741893fcfb39b5b7d1b6ce9b869d60d5f5feda417479cf7c84b2b51f), uint256(0x09902847f991d4092f9767499890570da12d4e2436250c42f744bfd9b363bf53)]);
        vk.delta = Pairing.G2Point([uint256(0x0f370d4d7ebbb08f483753162e27754b962744216ab3c18a1db326ccbc104aca), uint256(0x04af9b3ec597ac402881465d33347faeea82e6ca7c1005dcee50f057f72545d8)], [uint256(0x2f7508b71e4407afbbb0beec231ec850387733d0dba4b6472d009db6f00dc52b), uint256(0x220d012d0786e19f8cf5f1fe00990dd06add3c169a5f8154df5e25ace1d9cf04)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x13b735fb2b2facbd61e62105141608cd10a58658fb20d16d7cdf6941aab018c7), uint256(0x179d699628131b7c34b5ee3c1689e89581d032629ba4441309fbc12b9640c4be));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2e3b373e336b3abadaa6beee7678eb15f9dfaffb5ba9ef3650dca74fdd44dfa8), uint256(0x2e609bd754d2e32693bb9a642e23c3ea5ef2e08efb899f98fdc7d0d6eed673b4));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x01068dbae1336ac1b13a6f9f04d41b674f42eb997c30942fdb67dce3561f6362), uint256(0x230fd41ead1741067276eef1dc09496f6b6a9b0b16e9a5b7724921f6dfa86369));
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
