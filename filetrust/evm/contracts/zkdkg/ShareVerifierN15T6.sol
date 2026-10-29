// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T6 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0c0e67bf8c71220a511ff3a40f5c17d752ca86fa45384a944cdf2feb874ac1ef), uint256(0x1e03beeb3781bacf5ff2e82715fb0ff83b0fe3fd5803bac822a4907164f0ede7));
        vk.beta = Pairing.G2Point([uint256(0x21f35d89ce94465dc2c32c04891ddf5d4e81abd1d861e98d1e6f15fc7f05d12b), uint256(0x0620676b6e9e97d9ecee4f2ed8813346b7443a5780603aa13808c8d457d23a73)], [uint256(0x1a08341c80b8f5481d903c239703e4272ccd1fb5e3effc2f6e3f4818de0d6123), uint256(0x13eb1c11f0a36e3b90770c776302fc7fd79784bb4991653d63c5f8fc26e88bb2)]);
        vk.gamma = Pairing.G2Point([uint256(0x0401067d135c626edab7bd1b5db9cf8a10becd81eb775b761138aa446b359dd6), uint256(0x07bde76f6b0f29b78c19e50e06d9b95337b04e83aba422aa8c9fcb0421e133d2)], [uint256(0x029bf5a0965db6cb58c52a2e7054cda2c0200a6c3b9ba0f04521f01b9f88aef0), uint256(0x0bc47ee86258dcf292facff5c75acf572afaa27a037effef29b7926f5b6f95bd)]);
        vk.delta = Pairing.G2Point([uint256(0x053b0f13c0840a384cfacce9f2491a2f62a237e59087ca5cdc34fd1f0abef299), uint256(0x0debfd9f082d362e480f69fdf77b6878cf40b088c5f6a579e26061b63faa50fa)], [uint256(0x29556013952cd224118d60bb1fb466a9ed09f6ec6373ca744a014bee313c980c), uint256(0x2f3fdc234440a56c51d5b93234d22b51da6207c346362e8690807cccabd9b9e9)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x20bacaa611c739f0775c677e88425e7eb13e3687d5a7c6be75b5333484b0aa6c), uint256(0x04bfde439294c3a7d95f788c98f29ad50008965aa06ce750d41d1ab05ba3a00e));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1e1c03a9eeb031ff2b8ff6ccd0c91f1e124a49dd0e681cfaaebab9bce7b3d1a7), uint256(0x08b61f95fef4d17f7bc592f9666ee93fa059a160633d8908f1738e0b8752a062));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x03246e9a42c271d9a50a3413e38f39ababdb31a6dfdc677b0f9f65578e023d17), uint256(0x2d5254b3c68f28bd6dea717d84b4b2dd1ca35ed95958f92fb242774c8d51894d));
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
