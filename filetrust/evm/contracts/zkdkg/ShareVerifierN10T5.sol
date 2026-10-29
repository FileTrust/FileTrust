// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T5 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2b27a22c63f4d59f9b4ee9942582a405ecf40e1b4842da4a3c49c353c0f20a52), uint256(0x12ca47c032f6e6ba9087cfd3178e91906e29213121e714e2863e4ae189344929));
        vk.beta = Pairing.G2Point([uint256(0x09b181527e604dfe4bdb577328713340f801fbd3b0bb8d57c5b0c96e10e39eea), uint256(0x077caf255003c078ff6f7ab037c1bed3a817ddb38390fd8ce915867888834f2e)], [uint256(0x2a4f4ca1db25ad8bbef720ab67010804ed37fcedc1cb30e931cf95ca0f4c746f), uint256(0x269ec8fd31bc5b8dc3d7c4255a17d902d23285f0ee72c6883fd7620d7fba3342)]);
        vk.gamma = Pairing.G2Point([uint256(0x2e1396ebac7508512dfa91a59acf0b6475c0a48e3c29c281cd339b32ebcf4730), uint256(0x125ece3c50d9b09eee622461e003cf524f26744073f101a8cbf1bc06091618e2)], [uint256(0x2f8fb0893b5d9cb844f505673d57b7966feabddd81614209503bec34b9bf6eb6), uint256(0x24a5d99db48884e9f5babc73de26292fa4b238c0e099fbac19fd360253200b82)]);
        vk.delta = Pairing.G2Point([uint256(0x243de7cac1238c96cb3681bbac20a5bf8e7100eabef3e91c32428500a377b1d9), uint256(0x05163fc9402fda141560951b50b7b7e83cb8b144aa58d94187161c67798c1e4a)], [uint256(0x0a96632397581d043b9b32efe84b182ed7fc3192c6cf4fb4defd78f5051c8b5c), uint256(0x1e937b3122373173113e2d63d6fe6f6722b6c244aca0ee8a7b85d524ee2d2e50)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x23f38481d836758f4431177c95dae7eacd54679fd65c3556aea01028cc9ac1c2), uint256(0x069ab1ba145780d8f0fdbcda990480678d82d1088d1935438e3a6822f4ee4356));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1b211fa8d4a0a51969515f8d475e656dce4cb0bcd674b4af82cebf7a650affbe), uint256(0x189e63a87ba432d71ea08287c806d3f881d63545851c7449b05d698db2e0f115));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x049e74b97194bfc3a16140fb0de4a6e90cc6670d49c272aa3cb67839f3e9a770), uint256(0x23853afa187a0e1b22d0dec0a70a9a94fcda86b09bdcf8159dc29e2d848749e4));
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
