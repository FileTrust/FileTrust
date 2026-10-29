// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T12 {
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
        vk.alpha = Pairing.G1Point(uint256(0x15489cea6258f796b827d571c0fcb16a9af8f61b24772ded0919b090cb0748fc), uint256(0x2cc361cb3481f7066797b9c10341695155d5e352ccbf2187dc057ddf78521186));
        vk.beta = Pairing.G2Point([uint256(0x2f2cf1336d8e60a49d84e211de5bd15d867910b2fc4fa71c9c3f4b77c096b992), uint256(0x2b0b5ac0eb3d14065f2c9434d511e3a9e991642446f71f01fdadbbac53a8504e)], [uint256(0x1df52b8caed4b04077aeb4665856603a86badfabedf39c3dc25606746e2d394d), uint256(0x246980994da93deee53e625a29f5fae8c6683fdb43f9e9e6b60b7cb355e0749b)]);
        vk.gamma = Pairing.G2Point([uint256(0x282d0ac2e254692f6983ff20b574d66ec4b0a3690ecdda8b0325115dfa2d9e3b), uint256(0x02869296f2ffa7cd9a10c84572bbdd501988aa5fad0cb9173ec04217beed77d7)], [uint256(0x25a5e0a8890f046c64ea3ce908b974b039cab6b558cf21d4487f90519b277626), uint256(0x2b8b11771e28049bf1e377e5f75994f07742293e7f58b90f0de213107230ef16)]);
        vk.delta = Pairing.G2Point([uint256(0x2a195b3e66aaa81b0957eca5efd306eddae9ebda8dd0387c3a6ed501e200a1f6), uint256(0x1fa5c583043cfcd9215d2d8b442333ec11362238a356d26cccde80bfb0c874d6)], [uint256(0x22febf8c24bea032fa82d8c94a92b65c5fbcd8a110a21f2214ea072c2b42cf92), uint256(0x2e620da4d76646ab8aea0a2e33cf4db14409d85b6a0d535e6b2f666f55bdff27)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2201dfda45eea97bcc1908df65d4e29c66b3ddfd816d57758af59352edf65589), uint256(0x0b281da94137112e0df9a71cf919cafab76dc20fc93bf858f6a90dc37fab3815));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2f4dbac585c1886467ca64304b22f6cc7224d95a627994573a90c13e2b6985c1), uint256(0x250a1c3639b2a5a423bf8dfdc7e17a8e41d072de398daef57ab9f5b5f1e4b310));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1b783c6397b89830f5fc3b221fb1dd810131854c2fa92010880b6b47abc8c02a), uint256(0x0817e5becf13bed58abba44d3402549931b0d484fce1fd1bfcfef0e0f7da6a7c));
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
