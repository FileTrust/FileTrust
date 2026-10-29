// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T19 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2895bf2d22f68605f7d7881591d7a813fd627dc6f850ce3d5d5b44b19a5beace), uint256(0x112a081c328fbd97ccb65bca8dfe487dfc1c6f040a8f579ccab5d3ce723f4ffe));
        vk.beta = Pairing.G2Point([uint256(0x2c3293d9a3348c2eb2c1e8d210cf847041400b91d55ba5e2a2d733d43e80bf70), uint256(0x2ed3e68264e04b516ede83c4e0dffa66bc0fba8144ba0f479360b217d064006b)], [uint256(0x1bc2a82dcbe0497b28a697172508f86ddf9a5b4f44bd605a244790e8b74e410e), uint256(0x2f2af09692cecbf6c3fd3ab8072f9014a70fec7b5e8f845b3e34da0d42b349f5)]);
        vk.gamma = Pairing.G2Point([uint256(0x20e91fcb26ead24894a57706ca25250ce66d839e2c844f7afda1c2a0f2ed1531), uint256(0x1c625ecffd18ccb88d34099d987db78b734e65b74bc003d650eda82e284d5c6d)], [uint256(0x2120a3bba591da67bec363d3d67d48931fee50ddca8c656d2764815abf6f5590), uint256(0x031db6e56e61c934dc08101d62c41f7fc5c3bbcfe0f51b88593c44e4ffb59e78)]);
        vk.delta = Pairing.G2Point([uint256(0x243ffdad95f5b4d1137009cc95ba2ee0e0e7297be54cb7eca390cf8546d1434d), uint256(0x0d678d3003e8f7198e66f4504abf6a12e39569db2ff24767fe4c2615649e867f)], [uint256(0x085eab4121ff9b0fbc69020f419b4700945b31c5d4081006d19bc2d83f257d48), uint256(0x1636d5801a52c6444310c481379bb3e2463da8813b9ef3cf405a6df642aecff3)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2501f002cabaae27297a625c34a041c3d2456c6f9ea2ea1092d8f537e97588cf), uint256(0x2b158f6c3acb6dc239d611fc189d34d025e7fc4274b709ace0beccfaa86e5366));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x192718b7a5705e2aa5e57c18e7ca63cddaf5a6b2c06ddb6c70329a3962920f76), uint256(0x01e93d5fec61357317873db9f453ced9418bd645e792cdc9c8f4a6f19a977f64));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x08590f60f82b499b3852a0cd43f5829d4a31034017c824caef7264d455f96fc0), uint256(0x170a4dde1d34f363a0f7e269f024bbdc2dc7b7ce906d368384ecbca1b438d7a7));
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
