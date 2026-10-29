// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T13 {
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
        vk.alpha = Pairing.G1Point(uint256(0x04c7c890fecf9b58cd66354ca2418b86a11f60251db5251c0a5bb3d3a28d3bd2), uint256(0x0b511ad3a24d7532fc35853168ff5962ef9802bdb1d3f9e84fe072290e50a3ab));
        vk.beta = Pairing.G2Point([uint256(0x2ab7c09b00f7df5edb8b1c1c8a8933b83685f500f7f813c378f11478a2702890), uint256(0x233d600b6514e79edf63be44102ac704521679b6c5929157276833f5cd6a5108)], [uint256(0x16259a4afc20050bc575b1a05367a4205d8f986bbfa22601e8b96f952c39f0a3), uint256(0x0114d51eca82d2e6dcca87011ce248596a43e62b46e6cd5439479f949bbda90e)]);
        vk.gamma = Pairing.G2Point([uint256(0x2cb150a499648e62d93c4b7b7421d6282c8626f02c591085f3311a673a14b065), uint256(0x072683519f5ce5a69bc13d6d57b0bf84a93979801ed23ed0b0e0958e7a79898f)], [uint256(0x2ae5a459a57ac0fc2707674e1b0fb6efb7f67e77a5818beef22b550eabe3ea3d), uint256(0x1763d7c316739f6c5f82dfe9258fa0fedd09492665539addc28eab783e5ebd5c)]);
        vk.delta = Pairing.G2Point([uint256(0x12779fcfeecf6aacf7a7a90bc94bedc173313851b9b1c9c97eedaea5666e342c), uint256(0x1b111f47a732ef24681353b4bce8a5e1003b3661bd9913a32b9bdac01d2238ab)], [uint256(0x1f6971280152e72fec38e8be56f57757a6a28521201ed00718eee60e045bcd12), uint256(0x1102de1a36e9f1018d16c5462a44450a539530b27d86a4556b87077f2cf648eb)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x22e213a46a231d550cd9f411dae25df3b7fbafdb2e510c3cec09cfa79940ae8d), uint256(0x1a15891397b8918d74b4a89c4de38be5c7a475cea70fe756d7ebf02b28a0c350));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x11d27a70cc2cbbe7ac06a9767d0b5758724579469a8ac3eea18958ea9e03cff5), uint256(0x219fa91962bdf67d0f42d64de71e8c84c0a38339969e1c05b8bbdc988fc4ca43));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1da4e07eb38ad0bd85c00e404dec93e530bf05eda801413fd0bb5b4115c802b8), uint256(0x203b6cb7cb461a6aebcb99e91a7abcc6654558389fe013b19e9f082fef3670f9));
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
