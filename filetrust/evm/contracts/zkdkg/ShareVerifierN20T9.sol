// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T9 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2c6038285f41212e074d295ee631f47b0087ff6bc2a2f6b792b2bfc3bbe2ddc5), uint256(0x2017c98304e4182bd4d8fffaf7be42c19a3ed83c9d5dd89f2301949b7377f0bf));
        vk.beta = Pairing.G2Point([uint256(0x0f46edc05af674b0554b508f445b65daa6e5957209a6e43e73992bb2997acb97), uint256(0x175ccd78c682e1b97b8473bf2a50ab5cf953db9ceca767f43c743a2bff0b234e)], [uint256(0x28d74014701c1cf0f1ac565a7ffaa86a72164115b9ee7791a19cc361c36604a1), uint256(0x02384c16bcc5db6216d25550b987c911ef1f62b592e41d647b0769c1024471a7)]);
        vk.gamma = Pairing.G2Point([uint256(0x0d42c5e05179261e8447832d1ceae2ea518db5f9b70125656ad77821d18e66fd), uint256(0x19c3c9fafd3034a47ffb06c50868c85218f4423203f26f2c28bc90180d270023)], [uint256(0x1beec0e2cc60ee86d9a8cef9ed23d0f7591ecd0bcbb7315010ab0bad828a5563), uint256(0x1981c06034d663f3658f7a1dc6fb320a5b03e3bc067584d5a5774f17b448001c)]);
        vk.delta = Pairing.G2Point([uint256(0x143eef8c400291d084166a284f3250529f8d24d8509493d2442bd40def5690e5), uint256(0x0767cf06b8b3911fd7049e97ff3f5efb4c635efedc8ce87b168eed93ad6eb226)], [uint256(0x05940e813f9bd0c6cdf0838d8b17ec0a99b237ee4987e1a5edf337789ae74998), uint256(0x09405250865c0c39f779059c1b79f593cd796c28fb87137806a86e6ccf145df5)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x12108b76759af1a335990cbc8ba641bce3a28638c2d424824d8fa5ab3adedf45), uint256(0x04c818dffe61c1be79b22b822725b61648df9ef086d55bb7f871d7ead21d7425));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1fa836456c28e04d11b086abc1c1464d6505364a2254224d922d9999d554a32c), uint256(0x17d89e0730b2c6738dd2995d89bf462c00dcb8e323ac414d1bbe9b65eea84851));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x27726b2838f3934090eb03574825eed0778385d996728a3e12b4b21be9e86ece), uint256(0x0ceea96f1f247cbfbb21b32dc3a26eb4dcfd814b2b94a27a0d29771cef63a4d1));
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
