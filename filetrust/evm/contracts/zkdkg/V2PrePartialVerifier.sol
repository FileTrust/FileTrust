// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract V2PrePartialVerifier {
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
        vk.alpha = Pairing.G1Point(uint256(0x0f6668b653246d0d61b68600485669712701fc84cbd3a8dc7f9a558d75e28a3f), uint256(0x084b7d61c7464de1034c812ec18afd46ae1c9b91fb2c80e3adcb43bbad5920d7));
        vk.beta = Pairing.G2Point([uint256(0x2490ffa2ab20fe6e233c4ffc24f5b38a02c9aac94ee72f1783318e00dae03130), uint256(0x305e194986d3bacf44f7f15814002d950cd0ce71f5c60a89f3392ff9653a9f34)], [uint256(0x180ad010312ca48684d3c6c025898d224dc991bd5f0222a8dc3e0eb4c5bec19a), uint256(0x0a2404c9133dbc105978246349d22301dfe3d69e3df1eb6d3d3c0ad5ca9d9f31)]);
        vk.gamma = Pairing.G2Point([uint256(0x01d45c392c4d8112d87bc31d927f201b7b1b8ea214a0ee8316a086ce5bec18cf), uint256(0x1a11f3b371a326767379137c2bf7276e6fb1746e3656da7d7031592957069004)], [uint256(0x0ba2400c7cbe05fd44fabe7e75afdf61eeae19094e4e9cbc5ca6c555dbbf9d43), uint256(0x0117ff39724ac7401c1f167bd363aff0f1d2ad3c02b8a869213ba3c1e4f4846c)]);
        vk.delta = Pairing.G2Point([uint256(0x2dcd8d8e7bf410258333ce1e134fa2fcbec22d46709d81066af8118c23e8e83c), uint256(0x2dc162874d32ed50327f5ebbf1c3f1b619167098a7297500a855ca3f66676450)], [uint256(0x2b914424722e1d9a73a343ab37d94f15bab540f765f9462aee6de0e76e5ae227), uint256(0x077b5cdefb14740e50671c9b39ff999e90eb3634bd85605760e83f30646a93d8)]);
        vk.gamma_abc = new Pairing.G1Point[](13);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x19d6753f430f3515638c14a76464fd0542f8935828a8661677e5034f4f125e6b), uint256(0x0476caad9daaea97ae8341f608c52104e669fc9b985d2c68974e225070affcbe));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x214af2a9149e240e50911512e5f22914d49ef0c8a50931e1dd3e33700c1cf2d9), uint256(0x2ce2f82e00d1eeee2eced34914d1ffe18438fa8e75d1b1a0d9c7ec904cec69ab));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2eb96b9042235223964efa95f73c4b71be26ef8d73018cc1e19fcdad18df9c21), uint256(0x2309dcaf1042347d4e3e1a0e7e328b3acd69d5cda90d6fbc4c1004ffda02a3b9));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x0b350e8f1116f21d7f576519326b3f2c31c3246c04085169ca6377bdf54dfb80), uint256(0x08c1cdc43d20fcca02b23f2f75c3b828ce3d109eb10072064b4fc12024a94977));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x12939710a0fa2d892ffb016f0e1d0120c73f5709c6910f81329763787cfa4bef), uint256(0x03fcf52a8ee8d32f3418ee2142bdf94a84612835733b326cec520663b31eb7a1));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x109031708d8daaf07a379e23b39f8199e7b734bad984d1d63d4096d6f1ea7b5d), uint256(0x0a1c1e1085d3eab552c335540a6b41ccef11873a81775feb9218f228d58abcc1));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2b596cd5a5e529fe76e8f16af2159ea48bcdb8db89b60714846fc8786387c3c8), uint256(0x2d3f45701bb798899ef0fccf1337471271fdb6d239050be637c7832078a5e63c));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x0c0dfbe32630bfafd2fd84cc1c49f2f696a82ce86cb3dbce718bddd5a0204d38), uint256(0x13e2b1fbe48c8697a73267c36fcd151e04abb3c9d6a81177f9feac88b41178c7));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0da505f84f60e6b565efabfa48428af743f0c0b71975fd9e94f99eafff1251d9), uint256(0x046d3d0a58a264fef5b4418e247c395dc2d0efff5af3240bba77f252d6188df4));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x1abba6beeb3b163fadd89187b146285685daedea430a00a667852c5b4e573b2b), uint256(0x01db060e55bec05f47d9865e6513e678dd5fa4539a7d95114311cdb717802995));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x1c8333b63df6724adcf03e531bdbc8d536cd806633d693dab63326ef6abe020a), uint256(0x1fbe724e1db166fef2485018c6c34a823f083b220d7e1bc16037733d9172885d));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x14531086457b3a27cfa0ae713b31427d5e49211a9ebb50c137564ba34c638095), uint256(0x2b8650f5b9c93e9b2cb9e7c79f615a6a9d06ef8581977b67dc75913f36371865));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x04ed1f9b741999d7c80d29218ec32e2a728ba186b40b00509a51b50beefd10a9), uint256(0x283f49b9c83ac98696aa8cfc96fbef8875055dddecf040dd28ee0e576f0ff2fb));
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
            Proof memory proof, uint[12] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](12);
        
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
