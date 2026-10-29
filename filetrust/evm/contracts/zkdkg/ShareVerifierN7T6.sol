// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN7T6 {
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
        vk.alpha = Pairing.G1Point(uint256(0x1a50dd172a6964b4314131e7e81dbeb7b3f94db8580ddee2614d2d7b1a6f471d), uint256(0x2204fe6e13fee68dd4011417b6834bf0242230678e7852af6c8a6803cfbb3f36));
        vk.beta = Pairing.G2Point([uint256(0x20ce372665995806c284343d344b0e711a0433d5b9c0c7658bff418492d2db39), uint256(0x127e5be6956d4d6475fd418265b41f117188bbe6bf3c2adf4eac4dc686c64970)], [uint256(0x159271b9289dff431f46a3387e36a945397a232c61005f3ddf7e2c6e59860f13), uint256(0x2eacc140e0adbf1c7dd1e0b8b5ed1a3436411960fe9acaa0bcd2ab9e78ccc1fb)]);
        vk.gamma = Pairing.G2Point([uint256(0x1e9458080b3728e607252b1e4d0ad362b41021082791f9c35e37f921e9d4c5b1), uint256(0x157448af9ceac9747731de17f105164f686f385184cf0039e2cdfe1e918bb2e5)], [uint256(0x12c3ea81b2eb8ae825c6eff79b58b8d118d6adc597975728debb1d3c730fd315), uint256(0x1d8f6ee8b250524abc331790839d61565d3edff42261a96aeadbb0082bb80c22)]);
        vk.delta = Pairing.G2Point([uint256(0x09f000e9958ac48abdb20b4478bb1517b88792f53151225210aebbc0410550bd), uint256(0x1d5d425d1a4d4be42776d0a850ec679912fb309bf1260ed850baca54720b406b)], [uint256(0x0cbf86987e1c0a9b195978981d6fe1cf00bca8a2316dec625d3d10663f91bb58), uint256(0x0993fa218fa0d0dc6bdc8708d4024c71632e04f4feac461ca1d7994b4d98228b)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x20645db1a6f61e9b3426a84bcb4effa6435234cca2ee6137ff28bdcdb2517c47), uint256(0x1c48c62ea34ca04395d03a859d690f8c8a615158543157055f8bdb8e74892051));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x24881e7c0dfa50367f156fe59e22d940705a969785f4af477326958e4fd1151a), uint256(0x26ac4c506fb7d14b595d1c553fb114be9f610f45dde6bb335a3ca3907b4de347));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1e0bd2793e7cec4b818243b491758648cd8f85c982fb2504dd379afa2acf79ae), uint256(0x1457f221f6d4a93440ed6cd574d3e1c142b950fd82cc3dc53fc6a84cd40a39cf));
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
