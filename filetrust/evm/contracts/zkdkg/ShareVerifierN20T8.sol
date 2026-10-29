// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T8 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0a108dd3534018f14428df541a438f7761d928d9ebbc3048d3fd6680cf6aeebc), uint256(0x13020c371b6f075367dd9c9a4e2de5270b0d490a465de8c09e4d2ed0b6e61b13));
        vk.beta = Pairing.G2Point([uint256(0x047a5995d01bbdb2782198de3fffcc0bc032a2dcba9e267b03793685e17aa7cf), uint256(0x16624a4fc4defe41dd5c056d770935639d30370b1733edf30208d5f289555d18)], [uint256(0x16ce1727c6f6f6e0b90ff6f0fe17a4869fe43a81ac30a425ec8d68b9b8dcff69), uint256(0x2998742622d9d12ddaa15303cb54235cae60d9c18bf5b4b019efb7ae365c61b5)]);
        vk.gamma = Pairing.G2Point([uint256(0x082a8ee0fad12dea6d53affbba3c6c82e108e5da9f183359dd3135e8617e606e), uint256(0x1411050181f0f057b455f5b589ff9116c56978bfd0c07b55dca8dd3de6eadd41)], [uint256(0x1fbf74a724c9d27a53b5f6a681e01dab288e1cbf204e67c3fd49019d2e3ca9cc), uint256(0x1927aa0da8d3ec5fcc677cb6da4d6e73e80b42367fb1733b709efeb5bf5347c1)]);
        vk.delta = Pairing.G2Point([uint256(0x03a90ffcb548da5c26a8fdde2f1d770427abc916199f5d6402c83d2fb8206cbb), uint256(0x097d807aa987a0919e7b9f3fa9c5fc53619f99d72bab7b76306ab0cb8ab40571)], [uint256(0x2af3f0a6d6aacf36950f9abe65bc8e5eb4b47e732ca8e56e97195703d6ae8991), uint256(0x22bee1e7d792e50ebd240ef642a49ddd85d78f4cd95b2b566b8337022cd955cd)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x267c4b6200ac0e46a833b6a9c0763c2a47320adf50d146699670c51d43760a7a), uint256(0x0bfe470fdc9f7ae2dd21f0ee0f85baef6212c29f1687036ce3792d26cc24b468));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1ff050b8c97d8f6dad911db11f22214dc5f9be8269483eedb036fe5ca1f8fe87), uint256(0x2148bcba79d29ba68059f20e601fe94983ae94473bcb240fb1e6ceed9ba38584));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x183aa99d8a9e84f8d79c11312d58870d19fc9b206f6f5d00a01702d2aabeaf45), uint256(0x17aa2e898b818bccaf4b35f00ad30d74166a9fba6b3328edb3b264e2f6911a6d));
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
