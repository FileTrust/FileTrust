// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T4 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2c0edd626d61251483d16deb6b6127430dfb4582f9ab6cb2de9658b50c647f87), uint256(0x2038181b2e6d983631d92403ddb61b6ae3626f241f17a43ac8937adda56113f2));
        vk.beta = Pairing.G2Point([uint256(0x1f7435307beceec6be7ec21b0a87572001877122bdb3948dccfe55eab0ea2966), uint256(0x2d6e38324e64b5891e343c4b51df36632981e64621a230c4bfe11b4b3b97492e)], [uint256(0x00048c721d37716cd64e55b6b826c20cee0dfd3943935b7fdedfff103fb253b9), uint256(0x265376d57890f6121b1f06486c892f44706265b1244a02bbe28e34f347b6367b)]);
        vk.gamma = Pairing.G2Point([uint256(0x1b75474a7356f7fa54ea734c76d0bbe33ed5683e0039fa22192bf9946cf84d73), uint256(0x2a6a04c45c2fb6bac298f77709bcb3da92d4c7164c5417e48c9b0bc016a7c480)], [uint256(0x2182b7cc8b58f6e90e78f0a5186ca36b41a68c20f2f6726417927077c115322f), uint256(0x27f4cec306c028cf28c6a8a82bf3bf68acbf780a009e5822498ef2a9e619262e)]);
        vk.delta = Pairing.G2Point([uint256(0x2796b8784c012d0c4beec80c0cb7adefe4952ad7978e04248667991bd0daecb6), uint256(0x1fbbbdabb34ee2cf02f41093f52a60783c53b07b063f376b5f897ea1c5241b57)], [uint256(0x24827a4dfb860b5180862e4f2531780779df43811959525d202bb867f02e3ac2), uint256(0x2f6ba634b3ab3dc33b3c26942bd6595bdcf175506beb9bab3c314cc04db9b5cb)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1c192e0c0f1ecf0c401a97e6d90ddad2632504ae08c1a586ebe25bd01901cd2f), uint256(0x2bfbf98f06a4132e3412617ce4bfdc5ee8b21c363601a00862f45f075774ed76));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x21381e2a633b95a735cf06abae07bbac768df4164ef1fd97cba1b2a37bef316d), uint256(0x098b74377951f2850695b20ae94286dd5f52219d79cc907d53196a20f900bfaf));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x103da8742dddc0e5abd9f445f75bf924d8d35195f0b7475f5b117a4b8fd2f55e), uint256(0x0efabae92437ab066ea833084bdf26d4e5ba58cc751238ad66f76757382f22ae));
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
