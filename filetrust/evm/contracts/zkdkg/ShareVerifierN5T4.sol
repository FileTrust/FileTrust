// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN5T4 {
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
        vk.alpha = Pairing.G1Point(uint256(0x24d3402abc296cfae5d29977ac7ff618add91443363b32e5999310f9d020d4db), uint256(0x019a885437cc1fc2a556be96493ef1eea2cde759d3d681d4438ffb8ca1349146));
        vk.beta = Pairing.G2Point([uint256(0x1adf9c243214fb6646068c8e0bd3a51b7cfb8433ccf5258a5bb410c4b883b902), uint256(0x2e715262ec8ff4262008e7e3e63feb2b7f61c1d3e1e4ee65523175ced505c258)], [uint256(0x0b3126ebe6799c271d53fde13040c1dc7426d6c6516b80b8f949e097fc425628), uint256(0x263db98716935e2f91134807c9f3e5f971c12ab6914d3112f6562d66189eb047)]);
        vk.gamma = Pairing.G2Point([uint256(0x12b3502bffdcc0ffd0d6e85b000bf1fdaa3410edd62b61c9191b08025d48b4dd), uint256(0x15fdb5660918103384c83deb45f4807a92d2bd79c5b17592fc837d8faf3c2dab)], [uint256(0x0936589c141814c66df569ea7a2f19eb10eabe92ae319ced145ffef4d66ed7ba), uint256(0x033138b1b179a5f82abce41a940640be0c34a198d86419ebcbbcd0acef245a14)]);
        vk.delta = Pairing.G2Point([uint256(0x1756ae4638d953ddafe329980b13e1eb757ea8329a67206f7ae1180906c8706c), uint256(0x2fa427e2aa5043abc6ca36892755402f7925c22f5cd7ef970581aa37ed0b21f7)], [uint256(0x1ccda20359a807d4a252859574a94f83de18b7c3d723b18e17fe67c704463855), uint256(0x2a5df24268e828663ebdcceb5adc44e0d5264531ac0d9f4a2b62e66cb799462e)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1db588c202622e572848c099a15325e067221a4c5a8a79be955053cfd034d6c8), uint256(0x0edb0b96a31590b2c67cf87c2edccf9f8efcf35b9d35748d3c51c59b7e774554));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x25d80c71464630b8d0aaac576cf492ba85300dff709880f15701a02b2aa397d3), uint256(0x0c9a00c224888b3232373653e3e6d6880226038f31d0cd51777ce803be3761d0));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1117100ca59dd8576ba0a8c6f67426c5e8a3d759c390d56efc3301494ef47ac5), uint256(0x1cad8988f472c01b2794373f86ac2071a72abbe58792ddd05e6e3cf31301685a));
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
