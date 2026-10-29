// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T7 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2cad4ab51f46aad759389ce8de050585da7174118a94cd76ab3129a11bab809d), uint256(0x1a3aa69fb00225e101eb6b2ff3809e5aeace82dab56e6c445c30c609316854ff));
        vk.beta = Pairing.G2Point([uint256(0x2748bc503ce69ff2f1799af328b058244c9a01718a559b263cf4d2226d1f9957), uint256(0x217dbf9d86da061c2d0010d8ecb8247605ede2f6143cc9ff9382f9cd75a9ce0b)], [uint256(0x143862c38a6a15087a6640dce99e568ed7a52a587a50854f940fbfe43c1c988f), uint256(0x2c18e6d288f356a47e237a63c7a01c4651211b8178759a701c802077846701ef)]);
        vk.gamma = Pairing.G2Point([uint256(0x1c2273febb3d1d715dc0528fcd0e62783d04b5adf92ea228a97a6753a6c939b3), uint256(0x137a122cf8861676db47fe7b7f663f721fd4d645fb013b7279876fd4acb3f9fd)], [uint256(0x113a3be583f3ead13134022d76751fb25ea211abd3965ef86f5cda6ae0cfdc13), uint256(0x09ba4fc120752d10db5ab5d69ea4aa0a63e5ac60a61571d05cdcc63247edf393)]);
        vk.delta = Pairing.G2Point([uint256(0x1a716a09f79dd0567dbe5df1016ad2daee8de3e069445949fef08179fb4dea57), uint256(0x0f22ac427de4dce14ade3457ef100c4e363119b5d80993792a264d357c912f4b)], [uint256(0x00acbfdc32bae24d1a0d919900339a25d2485ee18d40181c4f84dfdb4e5a8bc1), uint256(0x1abd2c1365a702bed9acbdbbf7a220117457567c69aff6a1c0d8b533a3a431d8)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x109de7654866887cf7b58badb5011f47bf10d3d7e18a07abae71f592f3640b44), uint256(0x018a6465b4eedd8e91482ac50a9eedb8d0721ef90b78eb26d27c3563b7ed6b32));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0f7e83ad0c7e6729f84f0cae5ffd861fe47b3639cd736eeadedf95e4cb2e2ae4), uint256(0x25b06b1d87e370986bab5c4758e34d7f4bc1c2c936310bd0f3363827513aa8c3));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1a5ac1e9a436f6be57c183f60b54fe78bb418751accd074d41d8ade597e8b191), uint256(0x0774d41a3e9a200d98ed8366676a3caf8dc2ff75928bd8a3d58545fd1d8a4840));
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
