// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T12 {
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
        vk.alpha = Pairing.G1Point(uint256(0x08b05c379faaa1bf5299fdab671d4e387ff1af643e7eacbb54037aee26bbab92), uint256(0x2a7d0e6e7953602a05578bb259926080dc51df0a3c77d4bc6c38d4fffa1da56c));
        vk.beta = Pairing.G2Point([uint256(0x0b1726251f1c69c1a27422e29300fc336bbcec94fa174fb248d7c879969910da), uint256(0x2ea9ce4169ed9f698b4d9140d04e47598157a9d43f8e734dc46b3bdc77aa89cb)], [uint256(0x04d5520e72b7f5941009ffbc282e269dc722138058713c3fd2339161dd8d5c46), uint256(0x0b81a207d76c28a7565961aacce65c9c6a4fd1641e87cb85a299e52c519f35fa)]);
        vk.gamma = Pairing.G2Point([uint256(0x15b382a40c4f0dc71de027a84b8da7354e3a18dcaa693f156484832ea03b6163), uint256(0x2b60d9806c2a22edae5c2dff592e2fb0b71826e15da3fc58dd9eefb0444f75f6)], [uint256(0x28d5a891e81fe2f6aae218296015e68400ccac313bcf116af8800ee99980862e), uint256(0x0d1dc36f1f724132649a9b42f830f6271afda52b8b70105fe6e918279394ad81)]);
        vk.delta = Pairing.G2Point([uint256(0x1a1822ea2581f9c19f60806d2ade820b26e3a703931320840bf2b096be3a8666), uint256(0x23756c7cfd7a9ea177ee7659f3dab7300f6c2138106cc7cbfbe8a88fedefdd66)], [uint256(0x256b94481d551565c56a1c40071ecd97b7afff87f2dcff36881b566ebf7de668), uint256(0x2f2aae30b2d9cc778a9a5629801698ef3f3401177fbb3f27995e65f81044886e)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2533551b81c78d26cd39397739fde6ca5e575bae5071f8377c0345c8aaf85d78), uint256(0x1133f8aaf13bab789ec67d82b0045365150bf8bd6f9520084119a16a594d5ba1));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1006909f855b3578729d2aee15a715e75ebb8efc658415d530341cdb124c3575), uint256(0x1d4e5f7a0c14e29b69124da19dc329ef87747b27ed1cb228790fccf06792068a));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1182edc025828d169ac681802370a50622304cd6122cfa1fd1ebeaae1dcebadb), uint256(0x094ea019303c6383aeb2163f2fee66a54f9a22345d8ef117fbcae122ec1b3925));
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
