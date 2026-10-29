// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T15 {
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
        vk.alpha = Pairing.G1Point(uint256(0x23135bd1b5e6b1d325288ea63f8ace3e905ba16293faf348cbcfcf2b3d7f0fc7), uint256(0x192fafb0022ff0d4ae1aa3bfdb0bdd44737c5d79fbf523c17cab2b52411c4bba));
        vk.beta = Pairing.G2Point([uint256(0x12e177c6b4a34a09a816a2b13ddf46cffc738b338fcf1309b808dfdd07712513), uint256(0x1a2ebab2514a8c7acf8f68b6ee1aeb420f770e36be9150dc10041e7ca7844df2)], [uint256(0x1eba001385224c1af4dc8e30df59e090b0d758e28fd17428ffcbced4785556d2), uint256(0x00a1b9741ab36283209d562b66039f849f171082cae733f626684d416bc6726a)]);
        vk.gamma = Pairing.G2Point([uint256(0x1dd64f8c62870e34ed0eed9ddc20cc91c8e2f2bb51e3518b0967430a34e3a4a4), uint256(0x1b172ad625bfc3a40de65486929b5763f75b85a9a9d23294c7873afb8423054a)], [uint256(0x1294c24734992c946e0cf5d57bdf8a50e4d0f86bf13bd49205fdc24548f04321), uint256(0x2ebd6f486e7cb58d54a4e48393fd519406e7bf7dc331339e2f7f6e1fbe8af20c)]);
        vk.delta = Pairing.G2Point([uint256(0x2efa7fd844ea17df4da025ba4bb06ff9e04dff30e9ab1cc445ec5a4499dfd5ca), uint256(0x01fd2090b37b0a086548feb18d8e870fd3c81d16e68d7f4d44fc6fee7c0aa692)], [uint256(0x0794b78e0bc479ae7732a0b0e7d8247c532b58175155cf611540bcf87bf3b9c3), uint256(0x14bda6fabad4775182f9a862d28a24477d26c886aeb8e2fb2e298826247fa662)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1fd7e7ce36edfc72631b6da41e5954048b3d8fd87a79036f81f926e2b1c4d611), uint256(0x004c1589f8d53a80916c19afaa0bad90eb5426f9a902f120f92ba295f05a6953));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x22f186b0aff4c68d85f849661c413f550d2b68852f6c07b00fe982298fe0d836), uint256(0x28a07fe0aec5b63c40ecb2ccad93701b3917ab8bdea0544bea42f338b3dc7993));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x21650e908a1fd6c135ec06539b314bc5dce3cfdba76c85aa43cdc4dcd19bc5ce), uint256(0x0369e6b88c6ac5edeb6ac85fd7bf626971ada98942dfb01f089c2d63ea651745));
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
