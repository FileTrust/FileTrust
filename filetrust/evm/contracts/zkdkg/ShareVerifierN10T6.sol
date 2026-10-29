// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T6 {
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
        vk.alpha = Pairing.G1Point(uint256(0x271d00c7d003bbef64b276358ba59df95b41e3e1dc1465247370c775e0bea6e4), uint256(0x1e237e8977c67138bf651dd5db99fbeeac033956f4bf2230a62c87c696c435d2));
        vk.beta = Pairing.G2Point([uint256(0x261dbecfb0b7fa46444334bd851f25322af73af62b3c7e66a235e583ca65f5a4), uint256(0x1a9ba55a106b3b133d4b49a06d98b0ed0ff2bcd6909b109ae6903fc215c0c45b)], [uint256(0x0909eaaa18e741397969de8ed680af59e5b4a15609f61ca0cdb9a712602c8c6b), uint256(0x1cfa2f56d562c080f1f61a19fdec7cf2c5b963e59714be0977f5d0e95a571fd9)]);
        vk.gamma = Pairing.G2Point([uint256(0x2e31ac243c7a2264204b0945f8dbf6903917447b021e67a59d49ebf81d6bda8d), uint256(0x1176947aac25fc4856e5f2d49fdbbd04e05e5d7b3cee8ed1fcb809a0d4816366)], [uint256(0x16d106b0649648f2d70c3a5e61b6631f25a40df465b41e7b755348bdf275c6db), uint256(0x06f96b91d45d47cace4448e439f2c80c7ace424124e3d36c818bdb0b7eb0f004)]);
        vk.delta = Pairing.G2Point([uint256(0x169b71d68db8d255d0fc54a37575c3b412ea2a06a40f0d5c0818389f2f4a7991), uint256(0x0aeb0d9ad55eba931e44b300335cbec3758bd8fe2b522dc8a9492ca8da121cd4)], [uint256(0x09ddf56ca903723b11d85e0aab76407f2f9fc6a0b82a4bb0d90138a68268bfb0), uint256(0x1d6aa317252fd7bb49f6fd8a342edb4ae9a5dd6077d784fd50d44bbdcb5f075a)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x21ce4351df03d14982ded9ca7e85fd65818b1d823253fa74e916133d8d932431), uint256(0x0f98d90fe8bc33c314b95e04f2e73210c7b79be344e5e4d9f958f852851436c4));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x300e0dcadaf164247f2e6096658593735422a78e15f0436e1c56d16949890a72), uint256(0x028fe4dedd3f6e908203d9e129b5f70937abf08dd4bf268088428885cfc48bb7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1d90929f94e899bb01f299a23e81e6cc3338f24a1022e00772e61f06efddbf3f), uint256(0x152a3082a8c04a276e411111f5aa62474b822c35e337c619c09c751ed517f083));
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
