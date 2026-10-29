// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T18 {
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
        vk.alpha = Pairing.G1Point(uint256(0x177ec1dc055eae79332b3d4ad1c85fd80ea715baa23346f2f219ae8194e3809f), uint256(0x0ad83fea3bba47bd101d16576d2d258daff25e4b96f6e206c598d620a7853fac));
        vk.beta = Pairing.G2Point([uint256(0x03671837ad50b49b723f019be1aacc1d5871009a79d4be4a3f1f3d67c5fa4340), uint256(0x05313d602c1dbeb0f3b657d3e4f1f85e18f0780f0ca32507227c057fcd6b752c)], [uint256(0x07abeaf8785c6c51168712403a420083674c98d8cb1b4ad82c4a3ad99018c4ba), uint256(0x2c5e450c5799f89cf5092da8569cf25e97cc74fe993636fc33d678782d17670d)]);
        vk.gamma = Pairing.G2Point([uint256(0x02395127c2f91c90451f48af9d2f0cf17e0f2f12364a55fb52fb19ff17ee63f7), uint256(0x11bede357cd7361ed18021eb23d8d01d0dae5026df20c5fb944a18adba0a8df1)], [uint256(0x0f28385406291ca7275ccc819e16de41287f662ada8088c6b2a91921b4c9d8c3), uint256(0x1bf091a7034c254e764943e2314dbf6bda441bcb84249b0be635a55030b72ca4)]);
        vk.delta = Pairing.G2Point([uint256(0x2c94eba4aa068d571c33ea339cbd8153b0eac4312d64c207452c7b5db412dc00), uint256(0x1aef0ffc634a19f6704b66e20bed06f7b8ddda7cdd8f774684192b8f1db4c30d)], [uint256(0x0505c04c628fc3407ee922f37ec2fcecc6976776b571a86f5920e25d66aef208), uint256(0x20b4123bf49dd63b9d8fa9641c083f67ae832d54f548d16965b02e08b2236b8f)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x01252d2bad6080f210cf1c15bc5ed5eb34003180b897acc4af7689ff69219192), uint256(0x0ebe4dde00c6340283772b660eb631c8e8a4ccce68e8067ce3199f653b999f54));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0251eba6eeda30183921844d0a36de1e2152815281024d18ea02a98faeae03be), uint256(0x04c918279daa34f135dddae8f3c6ba07f5039c3021939228a27c05c71dd29369));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1f1dca351e16a532fc3105d831ccd7806b699e9363d0d450dbb7b23b4ea30230), uint256(0x18054fb0d6b866ddb23fb4b00bcbdd4279995056721dc06f5853cf5465dcfea0));
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
