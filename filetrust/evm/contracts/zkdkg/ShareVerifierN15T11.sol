// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T11 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0f16281bf4d2578fc2a7c400eeee14c032a8870b53b02bf225002213641e4705), uint256(0x0d2bfe0548839b754e897cf70f9df74db652f73cad527fe02aa126405ec63854));
        vk.beta = Pairing.G2Point([uint256(0x29975928c78f612eba6bbf97ce18d240118c2d79fa8455497bb62e79e4689490), uint256(0x211e801bacfc3abc99e536f63fbb0a1dde278eabefeb6755f7ecf5389a770d69)], [uint256(0x199eeac2b0c327dca3caf0af4e5550aae4cb9fb2b7f0a033d56ea5db88c79683), uint256(0x2d6f924bd90b067434fc8e12fc8976490d8ccd019f4ca703cc0fa9691836e2ef)]);
        vk.gamma = Pairing.G2Point([uint256(0x189126cedf5ab319549c55271f5dfe1303c3e8fa33ff18d33b5e3b051417d17a), uint256(0x009e5e5bec6af29a1240bd0d48e7cafdfb8a0283abc597dc749a3d618e72f74e)], [uint256(0x018f4717400632fa5b9861711adeab9445f509bdeac23ec28380b19cd46361b7), uint256(0x1792fac84da7454011e3c1e614c29c758f7bcf687c95cd6e23611d3e5624ed50)]);
        vk.delta = Pairing.G2Point([uint256(0x20404a3a72f254e90993d6197a650f9e3a9809590760e722d6f3eddd8fa29603), uint256(0x0aad58634e9bae68c5c7a4db9dfcd3c98badde0a6944240675574f8dcaa24dec)], [uint256(0x0c16b7c5917f25b3b2305ab4b544ed2da2daabc9a17799737355e5505db87886), uint256(0x03807131502b445b9dad01a2c7bbf8a45bd882c3fef5ddf03b5d22da4d23fc1b)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x16107caa5fb885e16b4cc8e2db94713e910f99908797aeba50ca0a81e3649e6c), uint256(0x250e56641eb17346528ad546310df3f4cd0be3f18958b4904475f8e8d9b4a694));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0cff383b4d8b3f28c9595627a1bbed6b648634b14a1ea2627be439c4bbf5a7c7), uint256(0x0c26f94765ae45e0dbf5ff8ad9aa17a8c99cabd03e8a97bf97a27f6970e91c31));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1e22f6f25763dd88e19533c94e8bad421224413f88616b21a3e29ee6a0adcf63), uint256(0x0f624e085cba705ba8bd31368c263b273476dbbf1c96619f903913c147ed59d1));
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
