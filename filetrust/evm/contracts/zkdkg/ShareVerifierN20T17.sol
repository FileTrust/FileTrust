// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T17 {
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
        vk.alpha = Pairing.G1Point(uint256(0x14de410ff586a72f594e46370e09e463b24da933152f69a4b945fa1ab3898f6a), uint256(0x1560b2be693d8ecae34745649f7728586aca008f6e912b2692ddd1cb93861ca4));
        vk.beta = Pairing.G2Point([uint256(0x25f8f04c1f928b41a282f3b549c0e85431a0a09506172cbb9e9bc537f9468369), uint256(0x1faec55d3de8d52f0b7fb8124b332a63b930107c739b274c13f6e6736ec7b6a6)], [uint256(0x2f843bb42e5b32c4c19e7997a5b0c192ea72f8c5a2c435a136288aa450bcb1d4), uint256(0x14cbba3d1efdb27ab9cf04e0f69da36df6a6be79dad09cc4bcb46c7da225518c)]);
        vk.gamma = Pairing.G2Point([uint256(0x22000ef4a864cbb240b55ddd6ed8be08c5de5ec70623e6fb25d65ee002cd9ed4), uint256(0x26ea1c450cbdcad84997eb15e32de7dd313549bf0ecdaa5fc1f67602faaa8327)], [uint256(0x263bcf0138a2da89924adf8efc4aaafe4af2a6572dc8894380296a0d329780ec), uint256(0x059882e9de736c5d3676ba17ef2ce1a2b526774651ff4e496d530608241ed7f6)]);
        vk.delta = Pairing.G2Point([uint256(0x1e49e24d91412a21e621c461d33b2c10ca0c21e150a8d9d39a7ab3baa70765e0), uint256(0x2bc91915aa497e1fdc0966d28efe6203d77ad94e3def2ed46eb7a9536ad7f9b4)], [uint256(0x17da807ff826cf792fdb9190d060df384b2d84659de638ccfc153d15d441bea4), uint256(0x1b1892a450ef78b58721d16d770207644a11ffd0373e9211596b15f794ee5b80)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x27626b20370eebb10e3be17b0f2e0bff7b3850d1940287e9dfd56936103677cc), uint256(0x1d9e359523b2f2835a0b92088c4875f4b0668177d76e25fd165573226eb425fe));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x020ce47908629a5286adaa5dd0f192bdf704bd924447ccea1ef0f795ea79dcb0), uint256(0x129627b47fb699e14284e0f99810160d6692a831c1309c2fa0121dbc2ac85b12));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2dea530491893591ded50fd22ff8aa87b015b3fb5478d82558694c3acd4b5799), uint256(0x11ccd58c1f739ba4f59c6cafed3eb3fbb3b3bae729212de6387625bc0971e732));
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
