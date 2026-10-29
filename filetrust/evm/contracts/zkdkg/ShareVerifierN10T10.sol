// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T10 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2a3a0d73e85f4da17063c0c7e938dd59cdb94b9c3061c3a868bcc2d32f4045b1), uint256(0x2fa58cfe1aff064af88b237c5e74df4f2ac2be6979c1056a10d3c7f9dcd7ca18));
        vk.beta = Pairing.G2Point([uint256(0x2d86a5fb14558eba44d1f7b102dec029f1f90e5747ba04754a69eac0e7eaa47c), uint256(0x098328091a8ae837bf53a08e14e8592491fe72af746d49e85f36b89959cd831e)], [uint256(0x0a0b04bd43bec835c94fd5e939f74fadf3d098ce96d61b8a2ac47ba5c964951a), uint256(0x096ffbec118b5d509b118ed100b869d6b737e7c7ffe9176931d7a4538966a9fe)]);
        vk.gamma = Pairing.G2Point([uint256(0x077d5e03f54306f52c3c9d42a2b5bd874fc51b91debeac41962593d487e0d4b6), uint256(0x1908b610ee74e9efdc14d50d2daf0f40ee465efab488cee00ec105ec202ff50e)], [uint256(0x20d26544a8102a06bdc768682edd036226b7f1b014418920edc79f3ec533b386), uint256(0x08a646cfc5482d4d4d3e7c1abade941bc9d55da192740a1f2884dfccaeb1424f)]);
        vk.delta = Pairing.G2Point([uint256(0x21f8095eac6a00fedd5fb93ecd5bf960495f2a48e5a3c9e300e69ab99782aca2), uint256(0x09589aa6402229856263cf61c8ee0b058ed5b0e2336de2b9a1aa0f362f9f2c41)], [uint256(0x0a2f782bf958dc8c50530e969a987f83638aa8c39318ba0250bb6ed2a0c11c16), uint256(0x303086b47dd630b66805b84a9fb92520483376e51b941c6a1dd9228e44923c3b)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1017d38ade77123980bdefa5bef4b2348268f21e39ad28bebfc99ec9c993e983), uint256(0x20e0d7b2d6f1287c5249e1ef6d3ac0aa05c0f37663f2fe144eb0f05ad566c7f9));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x27d35d3524f4a5ef95cf8b71b4db2d91d89c9ec60a69f59ae6ba2f3e5ef157f4), uint256(0x20652beeea9de1552a179fafbab9f0faf7f0590e5e7e97e342a5d747537bdcf7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2c2effd06579cc5eca2f52823dae01bea239f47feef7e0b643428bfa2479936a), uint256(0x1d36ae3f0eb2bb1e014c3face7fd2abeeb0a7fcf5c4eff3dce51d259fc1c2ec4));
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
