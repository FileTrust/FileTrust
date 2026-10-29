// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T14 {
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
        vk.alpha = Pairing.G1Point(uint256(0x201209ea9baaac06f615d2b7bcbf8c1794b3cf9ec58fb5868dbe03a5f1e9bb2e), uint256(0x284e230e0d34d12a774a160643e7bbfd57773f4ac6271a321dab06461d1289db));
        vk.beta = Pairing.G2Point([uint256(0x1e28d9a860036746953225e35e834d148b812195d1c0ed66bfd6ca1c64fa68ab), uint256(0x0d6335dc87e70fbaa25d12a6aae4c29db543e0d21e29ba73ad336f158d78dd17)], [uint256(0x1705d763b1c8398aa9f4043770d143c7bd63bbcfddbaedc45417793f4208d1d8), uint256(0x2f58dba19828d023ebf5645d3e83b1357449caf74bb4dac1784335562472204a)]);
        vk.gamma = Pairing.G2Point([uint256(0x1fb380682f06584114b976a994b74afa617e935d444369b77cbc198364677523), uint256(0x156547cec2e2333752fa46f69bce846708c43a8c6dd437ee373ca47a0d16f932)], [uint256(0x0bff41b979e35d7c1d3a198957a4a5fbbdd5739e46adc78f0e5e5234687de458), uint256(0x0684816c960a455bd35de44ffce135ca71097acf2c99b0cddc589c74a4d8d52c)]);
        vk.delta = Pairing.G2Point([uint256(0x1ee2607dd8fa85e6037df4658c25279f23db6581ef166cca3fa2562c11570137), uint256(0x10e12d98acbe001fcb32db86a363d8d65637c81bcbfa4ec6380e0098e97abd2b)], [uint256(0x24bffd6a428c4bb3f399d8d62face2dd338584668cad34ee951ad0ae33ee1e81), uint256(0x217b0a04c8491d7367ecffd4e1875d41a2c57b7415360bc3dfcb128a908f57e5)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x008b65dae7384da8abd4d73c3b1e07471ed5321a2ae8691077dfa5a555e9859f), uint256(0x2cdc76493630aa87567b98f11185870c121f695f642388e5359b28f8aa770a9a));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x06014b281ce3c5b1b577a4b7095ad92eb52fe6e77f3d57ab9f2cba0fadc47c3e), uint256(0x0320bb63e98814762b0795bb7a20785c67acd88ee272d0e676b1d14c259d1f0f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x105bc3e093f10b6357410c5522e884520981ef5bc4c9627d839fb382a96911b5), uint256(0x0c60dfdfa8fb9fc31c0be46f968f61d93fb4387f0cbb242fcbdf40e0e98472dc));
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
