// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN7T7 {
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
        vk.alpha = Pairing.G1Point(uint256(0x277707a01d06ffdb0c118083490dbdcf89ae38e3270133dab5c1cd6692beeece), uint256(0x16c2c77f4c73a6d54f8b6c13f85ea117dba2063630e5c83fe915bbc8f03b71fd));
        vk.beta = Pairing.G2Point([uint256(0x092e00c7d5f3441971fad8bf2709bdf4099cdf11b0a3b7bee657f298e2cec3db), uint256(0x0bf93be33ef2843947677f5f1ff4da439ad84d82f6199acc635d93b0ccef7a7c)], [uint256(0x10b70f2d67395d890fbe118ef468d308d82c5d74fe600f29bfffd2d766b12eb9), uint256(0x2ec614a17fb63c2c5cc5c6b415be787dabd8d93431f70f810efcc4dfb4f485f4)]);
        vk.gamma = Pairing.G2Point([uint256(0x288063f9a673c0123d5d36cd18463f59324461cd2d3789dcd820c6cc8d973851), uint256(0x03a4bd74b0eee6ecd846fe8f5793cafe62cfaf83968c04a3c0a54a8f0984fe90)], [uint256(0x03b51bd773aaf22edafb7760e96d282b4e05cb0a5414b6662532c22dc722172c), uint256(0x04abad41c2dcd2710aba77672459e36ecbbcdf85f0f0a89ed3818afd6bd3b5df)]);
        vk.delta = Pairing.G2Point([uint256(0x27a170c3b5ed23921fa031847d7dbfd6760025fb76b0c21dfa4b8b6f25fe9dd1), uint256(0x0284f0a73dc258a6df647674fc611b920b3e3a54376b181f386fa74aace11c38)], [uint256(0x2d35afc91db9c89c92488a6ae38e39a8f6913ca17d8f272a5d689425c587d6f6), uint256(0x2868aa8427cc217c0ad491a63e35319cbbcfe8fed67807426be6e64c247e24e4)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x264c558084f92d3185a51e941d9e783a04f31c5ac4cd649bfc2b6e4a797d1663), uint256(0x20243e92478f1dafdb252d795963a1608f686cae15bc4b2610b4c95a7212d3e6));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x237a1e81da9cc4e09ba48988aaf485890350db4828f90791ad54f7e784bf69fd), uint256(0x2b430358343103cd6d655af1ba080e17c00f4e4c89629c71363c9fa37055f203));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1d3cf85041f08f8e3db2aa19a144acb74f51aa84184a6ce70b5800426b5f966d), uint256(0x1d7c33ab0afe4b0e50b2fde9b7e334f8db651b10c08bfc8da755508d9c5f1513));
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
