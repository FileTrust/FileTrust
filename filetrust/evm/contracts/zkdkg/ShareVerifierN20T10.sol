// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T10 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0b9c58f8cde8f3b1c89451a6fe7ddd2ca7863450f0636b713f27c9e0ad29527e), uint256(0x2d42512526f5cedd7f511c40fc9ecfb608f0c281cd4032230c13be016b4ee76f));
        vk.beta = Pairing.G2Point([uint256(0x1b92080cbbd1b4808f5624bc2a1eb5e736a7f3471ee1b4510e22444cc9ffd3a0), uint256(0x20dea46f17849aa82cc4a48679b3dc674bc7094fd7fb7db98c51eca262fdf87c)], [uint256(0x1ffabe41f269bb0bfdf8884a396569cf8b53d16c24a96a657d94684d639dce35), uint256(0x2f09db7ce691aaab254528965e16e28ec2d8305dead962fb19bb1efefc2fe989)]);
        vk.gamma = Pairing.G2Point([uint256(0x12f5494706d43dc77f6a03b0195b4410cc457fb2031fdd904abbdf5c3e3f66e3), uint256(0x216f09ab4797f40296bc19cb767f5a4b97e1ea06688f7c9bba8b0d30d637a4e7)], [uint256(0x0d50dc6a137f6b958400346d0497aaa878e7fab4713d109f4197b3751c137ca1), uint256(0x2750a9cfdd45278dacd656ef2c5f7f415c1da332c5ae8c613138aef02f3b1fa8)]);
        vk.delta = Pairing.G2Point([uint256(0x0bea0a7b90ceb57a89814b884817950acdc090e37608e77b9005f5ed691ad6be), uint256(0x2a5a49bfafb25a85cd45590dec0f27d6414de6ed2364fa0b578f30f15eea79ab)], [uint256(0x07eadd8a3322cdb0939ddbfb46b0d877407ddd1fefa101946fd1f3b58ffcd8f1), uint256(0x0013eba2eb82804381658ebd6086d887d285cd606825a091090e8ab2ee0072fa)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1f897278ee6861b401b24f120fffde815a88f5944e51dfa635ec53f2a79ebc1a), uint256(0x162a821a97f1df2d7ad9b2fb9d2febfc76ecf7c43165a6ea22a86c0cfb58f6cd));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1f3032ce00a6d953f02263e8ffce0455ab2ba4f4057195cb9f5e83f3bd166865), uint256(0x0d9b6e56e590a98ac053cadc1ead3765175f1d8b352f6570080e9e3fc5f1b0cd));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x050b1e736f3a421bded0a4de67c173f7651d0040333ecbabc113432ae07f032e), uint256(0x277fa1198632eacea1dd8661bd61e91237fffe3249a72f39c64f0fc57e7b5a75));
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
