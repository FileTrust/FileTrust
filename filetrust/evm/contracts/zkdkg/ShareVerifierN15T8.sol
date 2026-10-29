// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T8 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0ba2e22793ef138bdf1b6e116b5229b9e6718e4ec083533c94637c65b8999a16), uint256(0x260e459669d0485b689658d910d61acd69cf43b65fd2f7a5fcc0303ba36a8a18));
        vk.beta = Pairing.G2Point([uint256(0x1e702337779faf408def96e3d9a48bc02f1136ac74c5e837120f3c7e63d2739a), uint256(0x12ecfe05d3d0b9e7862a0429775a41971d1852cc72a33c376814e7c78714c31b)], [uint256(0x17bc4da9d63fe7a646acdc57922fd3adccc4df0664f5152ba8827fc3201cb716), uint256(0x2e7cfd4eaa097592e690a2ac59048aebc63dbf547e1ea5bfca23518d53c8f221)]);
        vk.gamma = Pairing.G2Point([uint256(0x2eca7b96e6e02052f834d0b04781c142b964c7d2abc3987dc28994cc9a6b3e33), uint256(0x2040f4788eea8944b33a5dbe451e475e6ae3148aec51a3aadc7006938c71f579)], [uint256(0x098838719eb550ddff7849953bd6c42e766f7723f441bc2c5be2d3d94852ddf9), uint256(0x0312a62543e564951f19451e77cd1d264e486fdb9e2dda4eaadc4e259a3eebbc)]);
        vk.delta = Pairing.G2Point([uint256(0x145146ed5ac3b7788960f83f9b5c2adab9478cce10d672c6d7678fbc1226a458), uint256(0x1ce98725230dcd58a8991d5ed43176452fffb52dd7cedd450eb9a077e3e269fb)], [uint256(0x06fcbc238e46b06366682890cb283f897364137db744329c43c7e3fd4c19d9c4), uint256(0x2379939a5a0128b842441ffff2833e4a2f53592fe5e8822bfb9b543ff65a218c)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2148729f4f93c5214d1b610e5d9f65834610731fced3f982a41741a64e3c2b01), uint256(0x2f5b9d10505732489d6730efd47a38dc71d19ccaffd612047aa00c3e35cf15d3));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2050d7c1ed738045b7f5ad34dfa69bb453a0afef1bc50480458434910d929e0d), uint256(0x1a25abcf84bc1a5cc6319b78e09867289d3daa990655bacbac24d9c438be9515));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2d3f6458e32d03b93112a1dad4b2ee29b3c3a39184366392590a89d168f5f35e), uint256(0x072bb6a77a1e7e4cae15012521e3b56c87524b65c64ae2acbe41bdd3f06ceeda));
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
