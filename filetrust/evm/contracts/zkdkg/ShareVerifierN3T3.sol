// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN3T3 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2014731faea7331c8fbae161a8caee2bde60b99ba768e51b2977df4c0adcaaea), uint256(0x099a93dceb90aea7c6df6457ddf40cd2fb2e8e2cabe008f67b0c4e9c07a42b26));
        vk.beta = Pairing.G2Point([uint256(0x09a77d239694ca6433533efe3d25e6a6f9369bbb29fbf1c26d8a49d059798a1c), uint256(0x0bcd6c753f4bb5546be19fb8f5cb88fb7076aff324ea472b68dfa7d40a7c9ef3)], [uint256(0x0a1d33856552f07504042b342a3d621e2b926268bf594452263390c1ecc7ec64), uint256(0x06e0ce1b19a22ddecf799514e8b6fe85a585c9e655df74d8a5dfbe0b5aba2f29)]);
        vk.gamma = Pairing.G2Point([uint256(0x2b216f211d13be7aacdda5fe514203313a4a12e96721f1cca7bfd458f3c60969), uint256(0x157adbcfec36c3e850224301d0ac797f3f9e7ef3276302cddc723bc4a6a96430)], [uint256(0x2be4d36538214f5feb2bc86b8eea5397406fe614d6d35173ac96f0135ef17099), uint256(0x0d326c12cea0ae8738d2b46512d26cfa4723a94fff0926e8ecc70dd34d0269ff)]);
        vk.delta = Pairing.G2Point([uint256(0x299e9ce614d9b326a93ab702c088e525ee6573c7d31c58f718b759c52050526e), uint256(0x20b6367296a456915739b3f9f6c44eeaecf125d0b47e5b3fae9ab78ab2cd68cd)], [uint256(0x16c5e027ec09734ae8ccb30f59306954dfe56f84e0f93b749d9b1cc030b81c1e), uint256(0x122371705bcfeb0e31952a515e1778ffbd0af4efa1153d0bd7b35b505a46c87a)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x080f6ae30e515a6791ce4a94ac476aea6dab23c6c9ab07a5472a8b23f5b12525), uint256(0x167fd372f2aacf1f34b564824f633e34c70331860142d39d9f5230db60eede68));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2e5ef0284ad1292ce94ed9b98d73c0654daeeb840e4d867ae28350ab718ce1f6), uint256(0x09ddd18da062bfdd2304d09c79faf6cb1d5531bec2b06177ee195bb8e7c9417f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x07460d339ae9b5471865e1d2bc7ab0b85795d653ee2f91fb07b389be0a0ff5ad), uint256(0x184923e8fac0ae673a3dc8278cad87d9e6463b0a5617333510ebf4c20ed8dfb3));
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
