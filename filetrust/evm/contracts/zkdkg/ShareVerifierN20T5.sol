// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T5 {
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
        vk.alpha = Pairing.G1Point(uint256(0x164b1d059d1431c66f44d90dbbc7bad5961149169c026ef946be3f2313d92e96), uint256(0x1d67a91ac4d8c7c6501241eb72493773541acadc7142265ee5d59ebe56f4ffee));
        vk.beta = Pairing.G2Point([uint256(0x1333146611c246dd3e3a23b485d89bb4551123d15deed45c6d9239019cb4f5be), uint256(0x07f1c1869137d17b9c1d067ae470a9abf8f6bb395b558e4fca7389c6136727cf)], [uint256(0x2162ad9bde159949fa32eb6f8337cffe16353371800d7db0edeb8edebb818684), uint256(0x1bc8d353495818eb381fb28618b4fe6bcaddd2125e422c1f531b1f82587a6f31)]);
        vk.gamma = Pairing.G2Point([uint256(0x281b5af5f26f042ba1f4f9eaf484c50ff6179633f207104ab4ba956ff067755e), uint256(0x2c0ef175f005eee8c273a8ddeee883b9ed9b6e11626fe7f3e94bec7a93c1ea52)], [uint256(0x1d840cf0ff292b2869a08da22f1b31af9c5e368e0a970571f4177085807550ac), uint256(0x0425a5712703708042e725a155906b7250294f429fa55b79eec291d0d1228a71)]);
        vk.delta = Pairing.G2Point([uint256(0x1143cf0212891e03d3bd74a68b0d92936f2277a6d3a35afcfd5195c8123387f3), uint256(0x2b7e217a0ecc900fa6f4ae43d6a348280c476abb67bd0502a899390a69093dc7)], [uint256(0x15b58918fa7999cc64cc4e7a1f86d5e948275ecf6b54cfde710ae64c6601db97), uint256(0x2932817b0e3e53cf3c680f93997646ff39673ec81d6022c716578e7663892de8)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0502e1f98f1fb98158b79d543ffb809e4963170266865c9121aad2ada1c4f8b8), uint256(0x2dc57f9d93154142fd736de248abcff7b5ad0ae7d99c44c7f74ee64ce2493f5d));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x095fc45c15a886f843158f139c8433818297b9d06ad9ab011a11cd76d137661e), uint256(0x14ae763c012060348486c369332565da975e88fafaf09934939d284ba33e22c1));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1e865e56c2169c36e7b7d1aa37c70d1b06dc21445d277af490c932e917a0f571), uint256(0x2f97bf3d0a93c888d8fc4b0a21cc3e1240c963fb8542b5977235301b9a1e2e75));
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
