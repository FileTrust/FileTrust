// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T7 {
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
        vk.alpha = Pairing.G1Point(uint256(0x03f81b54aaf02477973deaf2ef1a97f90a3de810509086a7561fd5a2835c70f9), uint256(0x0a787e69798adfc2045f5125381103588234133329e6ed22996d5c0ca76c06eb));
        vk.beta = Pairing.G2Point([uint256(0x16887824d6e51f6d95e1179371d873b46c8f1fd533027fe65f655d380db217bf), uint256(0x185108534ae01ab0efa389f0e85fc9e824c3984a38d7e15d4c4e3856ffb995a0)], [uint256(0x2ff2a8e745a395f6a74bede10f20d0bb58b2802740cb045c1d4b980ab2a65c18), uint256(0x28969c7689d5c81ac9977c33dd75fa683dcaf1caff6b1c799da61962e4884b44)]);
        vk.gamma = Pairing.G2Point([uint256(0x27f2c1bc099562c8468ea9a329937a33623b688573f38b230489779adb3840af), uint256(0x23d78bc232a91ad48bf6822160deebb0de023b81d6ec664703f1cf99f17da73b)], [uint256(0x232e0d2fd89b61bdf27277088589bbeb262dd637942e2ee9398d0f5e0b67d756), uint256(0x2a5f342dba01f3427ac5553eca74f8ce843659c69e0ea9fb69442a96419a4ed5)]);
        vk.delta = Pairing.G2Point([uint256(0x1f26f352c68857e942b362da2acb88f1ca5ea5702eba0c5e0bd2cffbdb4cd860), uint256(0x26487786a8d7507c834d272bab01ee4bb7db98938a3d6b3b031b196a27db762c)], [uint256(0x11095d1d23a46f3943f552fbfaa2bc3fab6668837f173c02986de95c2efbf069), uint256(0x2c4c904cea01aad79ac125104fd901353836a5aa05f1859314c410a2d39aa273)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x162c8aed883e98ab33d999c76675732e7c39d9fba0be4b40fba2a0de2b821507), uint256(0x2bab8eb350c44e129fb3cfb1daeacb7d85e68259194e30dfb82c893dd5b4efe9));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x14008489b56dd6c08e691e819204a75bcb525904ff9568c9f806106a10110413), uint256(0x2cf5586acb2dae94a59c908d068e921798bc8a123e65a5f0e4548e823733d7be));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x08821c2b7a8ff43b6f9d120d1732acaee64f44f0a9aa2f871a1dfcf3e61ee103), uint256(0x0557adb43098466080770bfaffe98bcc6b8fb7562bde9bf3499b15d149397d51));
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
