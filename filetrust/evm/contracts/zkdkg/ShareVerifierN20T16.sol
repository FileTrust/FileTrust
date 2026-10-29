// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T16 {
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
        vk.alpha = Pairing.G1Point(uint256(0x28a251b8d5a3847d2723ad9930e6cd1bad5bec88b87f38bce48fd1448190a36c), uint256(0x2cf23f4095ebc50a83c4e1a8b3e1bc954a66c661b630a57a2f43cde0407d6eda));
        vk.beta = Pairing.G2Point([uint256(0x06ab8c48d9e16297c95c35340aff1a07a673baa4cb4f9ab92c4d923c78ad076a), uint256(0x29b04edbcbe3a954cc642673fb17197eda162f56379b8d5d3ae9e45071a5a962)], [uint256(0x161f5c47699128cc64eda7eff35c6057a9b0a21971105ad5ec9dcc60f73ef796), uint256(0x0d7f916b9fe7df5481d1f68a8a9b1a7743bb4ea4e76e61274d48707d0d44bc31)]);
        vk.gamma = Pairing.G2Point([uint256(0x2a4534fc825107339987d78ab6464b58ad6c66933afb8dd8664304015ba7fbc8), uint256(0x25ce23b38c2a72d60c23e5bdeecf3001abf6f92d2333a303fa28e23741abebfe)], [uint256(0x2b9943b3798242794f2cc24070aa312e02c47c797a30ab0bbfff64948bf15765), uint256(0x226ba4d74d44e8769be5dac8076a465e3d34d7078908bb22bc7f5c791668467f)]);
        vk.delta = Pairing.G2Point([uint256(0x14672018c807490fcb411b54562ca8f60e156bb4907f160e785007afb0909cf0), uint256(0x0103c574d5c7d633ae3b2794f01a5efdf2b2232ef47934c3120bf6262322bc8e)], [uint256(0x07f941f24ae7c30b04c0d465e5c2d30051f7f4c44b9a53768cf471c8f2690ecb), uint256(0x1485139e80bcdbbe4b3148d42928edf364874a44a9ac8e8a4f3e1b3980281431)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2d456a120117e3a17124e4f6565cd9e2ff831fcb9a97030c5f69cf7955185f3b), uint256(0x213a6b9aa0749586446aae3da80684714f918dbb2a1593406bf3c55813d900d9));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2d6ff44b353cff506c2bf15a362a3f4bce4bb8aa2798be22dd4739ae3a7585e9), uint256(0x1032c7b696ad82b5aaed2d100a4ec9c7d6b974246933c6769ca4c7ba06026062));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x21bc8dbcad9297ee98c7c517e887ba59e51fa18f0dbe4fed2b876b469496f080), uint256(0x23ce675673a73bc537b584d41b47b963c1bec73e36275e7cdb022d3a6c0963e5));
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
