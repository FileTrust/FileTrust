// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN5T2 {
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
        vk.alpha = Pairing.G1Point(uint256(0x167c9063e29e50bd469fb9cbf76731907925a47de28d0ac5d90ace53ea08d3fc), uint256(0x18597c6c76ac5839c2359457371997a6e702b65b5cd14dafa4561600aeb91170));
        vk.beta = Pairing.G2Point([uint256(0x1910126dfcdb239bedb5952a97f50d242d2bb878bb18fdca99ceb2d7c214dc54), uint256(0x18b7771e83c09dbe321a25e6e4636c2a177c707a9b001cde32a9dc97923d2fd2)], [uint256(0x02516f66298c567cb4b15d4bbb1d4fd3248dcaf59e28fc4e795c5cee0104ba1b), uint256(0x207fe88bb6e57ec3a85cf5024ac0faaf40bb925b3271a72216b5be00e42c5e90)]);
        vk.gamma = Pairing.G2Point([uint256(0x1fb61022a4d63ca832c011c2909a8b8ca18925710ef1adeeb66c6655478f3ec0), uint256(0x09e07704ef07cd72e0beb981d3522571dc92f054a85d2822e84c97d83e5ffae8)], [uint256(0x16184eaa6a5da0e8633d554ddc6d901374f481e0566a0bccc6846be235409681), uint256(0x1c7f91f399e15abac379fee2039e17dafa1a57511b5bd49d37817ed206052288)]);
        vk.delta = Pairing.G2Point([uint256(0x1c0370ec75da7534952b206c77be37f52f1c7c123e00d12f50ccd9f4e580bced), uint256(0x10adfee0fb0d277e0fab5857e5bd4ef8f8999da8e3a07750c205bc0559177f86)], [uint256(0x2dfaadcf9976f3b7406a8af0e065c6a57ea0bb7a295ed847eca0ff960ddd979d), uint256(0x2a9b238c2f2201fcd974792fe1eb59c446a0c3aea4a8ceb253bbe091bdf70fee)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2e23d8151a194bd7a296df2fa084ef66b5550ea46f20b67a31bfede3722bc9e5), uint256(0x20ce486d0b14298bf7a256b5e3d7f33843f04bc2bc26f39ab62ad38fd539c42c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2e12468d973cce39afea99ea606f0542c1ee301532a3ab7e0d841245d80e2fdd), uint256(0x25d19dd6e6ead007c3ef02a5894aade9fac427c919bf94f88f2c6e6bfb55e0d6));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x121fa5aff43b482a530475c664c31b82b479823eb05f4afd0d54dade9d3cd8ab), uint256(0x2010e7f7e386add753395b01ca3eaa1fc330cb99457ba1b44df89f5480771008));
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
