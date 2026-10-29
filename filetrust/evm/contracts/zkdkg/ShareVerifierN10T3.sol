// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T3 {
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
        vk.alpha = Pairing.G1Point(uint256(0x1c5ba4cbdc7dd36b69b8859f2d7b918815e59fd77c81a1ef9d1bf8d2173363e2), uint256(0x140ab4e5346a91deadb31630aa52601a52b715c2211b8a41cf1c1bcb5296576c));
        vk.beta = Pairing.G2Point([uint256(0x2d66ef47c192b02231b8e2be60df5f816cd090aeb8cc74d070458d81e079d87b), uint256(0x0a6b7a504ad89b1185b4e13c3ef1a9178476d49e4847f98234df2464ee2c0026)], [uint256(0x12101964c13499b899efbda1c9581a3eced129c323363e663f233bfcda354819), uint256(0x20dbf9cc295c728c377303cf964ece6038105dd7c18ad50da1337160007d23ee)]);
        vk.gamma = Pairing.G2Point([uint256(0x2b2662a4653a4dfabf68dbbc44783c0f8446c1f693e0eb6f239558ba4cd8a008), uint256(0x281049993908d21ac6fd107e5f6c9fabf5138ad194e771f5afee8f4eb69706ae)], [uint256(0x201e95f4fbd95da5a1ebca0bbbbf7ec9ee0a21c314a4d3ba1fbe57d0f204a6a3), uint256(0x1b362b871c308763013e9604b9a2dc1943b4f1528b6042d8891be1216546c910)]);
        vk.delta = Pairing.G2Point([uint256(0x0caf0b129aa1d7d5455f9b1b257fa33f8e5d8d1069c968ddef72c8d9f9aec5bc), uint256(0x07a762ec7b5de9070173e3cdc5b8bc6bb9feebf6aa03a869b842b98dce70a288)], [uint256(0x0d9e11f4c9a897b6dcad577c9cda36c5d7df8881f18f5842957a79209df970fd), uint256(0x17a3e30059a1cc8d3daf03ce298df0f813c08816ad4822e0e4bc24134cb08e7c)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0aaeaf8ac259fe34502067634d8714b02b974806fdf7582d348111423646b738), uint256(0x160ed36d6e2fcf040a515b01b6971c4ea57f5c302ada8b381aa940af98cde634));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x11ceb4bda871e6dca2909d5a9910aaececa1286104ad43f7bd5ce77e237bb511), uint256(0x2532fe61099abd06ba4c5ec578de703641e82912abbf32b7e405ac885d14ddee));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x10453c9471ca4406b2f20ddaf57893f592191e15332c5e960c105b8353c3192c), uint256(0x257e7eab1fcfb605b6115f9b460ff11a5da5c84c78a62275b6500ae8dfd9f913));
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
