// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN7T5 {
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
        vk.alpha = Pairing.G1Point(uint256(0x1c07b4d8950079ce46cea3dfc5340c6fd82c53b953ddcf55d4c387ee3ba40b1f), uint256(0x2818dac304af2ed8c03083e5f6593feddcfc611f28744ae81fe3ddaac11a7624));
        vk.beta = Pairing.G2Point([uint256(0x258a4ec32be4c9bc57924d5a223fb4a8036deed1fb6d711c3bc9dfd39d0a48b1), uint256(0x1b97845b9b094a4f6a869bfc111aaa296df3f26fad3eb0fbcb96baf695b54ec6)], [uint256(0x1431ae0045f640f90fcc4d0ec31d01ca8c1edee315b4ca05f951c204f3fd1a26), uint256(0x12b6a16bc6ef8d703ad3a93fa7290b5f0b777c6a889c088856e30706318ff313)]);
        vk.gamma = Pairing.G2Point([uint256(0x079daae3e0096627c548dbff1c763ef396bb0bfa5223c894f0f6ba72db873815), uint256(0x142833bac8ebc27eb8269d8221608f2dedef2d572063db5a9174d222ab3b71a2)], [uint256(0x17cc96f9d25b3d30d1de4b1ca9031fd2429fb8c8f80f1c769156dd75a16170de), uint256(0x27441a78fd0e7f9cecc98830e87ec6adb7e5c1013021760953f5f4591d96c856)]);
        vk.delta = Pairing.G2Point([uint256(0x1572e4c851d770b4ef363df864f9ad5d496baad0456b715ad8cd4bcdad0f5535), uint256(0x2029c9112642b01ee4ec13f99553e0bda9c24dfe7c9918777269cef0ab9d4bbc)], [uint256(0x29be9a35d55997b074a21276017f6242bb7625d07022db9e2fed35abaaa9b6f2), uint256(0x28f8d2f137e83fdca3913d7eddcd73cae57edb660378c853e85db41d970ef85c)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0d6bcbe7badfd1d8a9f449ed15b90efa4bebd076c974ffb41b17ad85fea4ff77), uint256(0x0e32f85e61ff456fd54b17170c7ed9934ac6534d4c11bd48fc9103f275f1086b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1ddd5dafaad4793c5b696d1ed67fd4104552fa3e3fca26fc6addd3507e6992f6), uint256(0x0c52e86180be9756510d754e15f058a9adeafdf1b197eb5ad19e13462aa254da));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1035cb5eabdff594e113bf5979beef79c211a62f9a308041983356010e7c3be9), uint256(0x144ac64452b03464df6ec4c4f3bdc26804eeed1d053a51731a8e9015088ab6c4));
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
