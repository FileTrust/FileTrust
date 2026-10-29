// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifier {
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
        vk.alpha = Pairing.G1Point(uint256(0x19ca630ef2952429739415c926f53957ef13d3827ba520328c24ece5015e46ee), uint256(0x2406dd6fe8b1c93086a1ba2bf5d4607d34623932c6212ca17010b7ee407021a9));
        vk.beta = Pairing.G2Point([uint256(0x17fd2ea56ba31b482094c0a6f5d05971df9dce745a34ed00d55c8831f0120bd2), uint256(0x07ff2d8d28d50beae3eb92a450a99f4bc5644b5e52d6f3ed7b23fa2d687fac77)], [uint256(0x1a2db0ca98274c6cb1bea5450c21b12474cf90bdd1de7d0a77b79f6594fbdaae), uint256(0x24dec05583f99843a050bbd1068d35362f2ca73f77d750a6a20a9057f64517f6)]);
        vk.gamma = Pairing.G2Point([uint256(0x01964f58dac9061afa41b06e7dd0ec4a75125e3d9826060079fad7a7350ab479), uint256(0x10512f18b4f7e67ccc978621e149d49d0bea7d95300e12960f5d3a5ddbf77317)], [uint256(0x0bfdc5c39ecf70e5666c9ba2b11bf02f45fec6658886b492f6cd17ccd50ded27), uint256(0x1e2ff89169788cbb11feaf4f95513bcd0d2081d2481a4d954c70f1f21923db41)]);
        vk.delta = Pairing.G2Point([uint256(0x1d75cf0ad2748563c5a83083ea273c6989a357b91e767f6c5f356272d832ce22), uint256(0x063a8d94aba832f96d4e531f4ea45d060965595100dfcd3a8dac8b4f05e5a908)], [uint256(0x046a2348acfb40d499ffec37b2e63ab7ac517e1a0a442632b4e27e7fb353e927), uint256(0x0b92748ece69f49723e4e546411cf7ea19bade4ed041ec6356b34369a9b08bcf)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x155187ec00ac2746a29473cfb8b52cd70a4f1111c6e0593fcc84c28446c3bbb6), uint256(0x24ba53fb4d253e91cf991d0f81501c776d62ccbd56973a19c1ee5fe86aa92e17));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x25c721343691b6950608b8c1d3c32ff0e0672e6872f3cabdc3373b20d44b0ea0), uint256(0x0da7ddac4c97de682e2b03b8745eba40d5a6e45f4e7161d5199461f6af945796));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2a548cb6bc678402867cf499d58f5266da52c49b3abb8fab8a220e38fba198e1), uint256(0x13b626a8f7d0d9f72d4437d9ace5a058d1b81af91274fa4f4987b32868befea4));
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
