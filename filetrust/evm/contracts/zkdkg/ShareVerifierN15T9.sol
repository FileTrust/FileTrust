// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T9 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2e437404616ca14252f469f6645292ce61f103f8809ff3e8bec63ffbeebeb42b), uint256(0x24f622a8dfe3343fd1d6afc7309ebf474fdf04fcbb7e72f9ac6815d7f9145ef9));
        vk.beta = Pairing.G2Point([uint256(0x28ad26dfbf2089bac0e5c41d34905d472711ec63c776730defd93a63e55895e4), uint256(0x108dd41907a8eb645f14825956e348e1d1d3676111527195db1cf62e7ce55079)], [uint256(0x0c4d5382fe678b40ea3c306f797ff9b2605243f3e16a190f085ccbac39ad7cef), uint256(0x1c8457d34d1bcc87c307da732032fbf7cdd9ee2f23dcea0c95c3dc3c34fc580f)]);
        vk.gamma = Pairing.G2Point([uint256(0x0f3156bc7de25c2b5428cb8ba9c8a6bf52a486e1b46e976ed0d7d9463b6c3fd6), uint256(0x0986b065ae37d4d477462dc6b3f50b06d098ea9d7b40a53cf7f039f220101595)], [uint256(0x1592d3f47e2944ec95d4706706d6de9a2b71d2222494715e3501577326224f5b), uint256(0x01c6a7513b8afac0365eda7e11885889d728b82aae7401188187643800513995)]);
        vk.delta = Pairing.G2Point([uint256(0x21dc06dc6427648b06b8f4a1e6c4e07844a7189536666fb0a372b1cf2b8d9cb5), uint256(0x09308a1703982830779e8fdd6530cabaaad0425c15ac49c56adbe716e052296a)], [uint256(0x26fb61afbc34a8e18d3c3a38694cb7d89223499f41901e3e28c1ee6b80e1f647), uint256(0x0e17bf9315dfceac192bd80a31d058e7fec51011a31e3d7e92d4cfc3bc841ba0)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1a5570b0f97ff30fe5581656ff6c46a1b64bb54c09798762e841d163f24e0039), uint256(0x136107d2c3fe7cbad66ac01c1de077aea8f9d0fe7565f9a448e0b0de1015c556));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1b7d227e0695829863e41dc14f6fae30f764949c99253a72b4e6a1dc291fe913), uint256(0x1f872ad0a3affa35af3f8af92b1db4c37440e131a0c943d97672922dd5f415d2));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x24f5df8a91381b3bb8fc9a11f1ad5e61cbb4555c73b9d62a34e409d3bc36ff06), uint256(0x2d4db3f4a5201db803d453af9708138ffeeb2419b7b8bff384b77f11c85c7307));
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
