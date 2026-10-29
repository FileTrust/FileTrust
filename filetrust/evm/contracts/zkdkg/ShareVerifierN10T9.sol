// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T9 {
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
        vk.alpha = Pairing.G1Point(uint256(0x062dc6fb8ce862dbd636309fed4b0b07879e1faed824225b68d5283f2a2f30c4), uint256(0x247862b1f1182d5b5f24ff8cb31c17b7659dbe7fcefeb8679bf486f832d49886));
        vk.beta = Pairing.G2Point([uint256(0x2da4fed6935d86a6c5b0277eac7c13cb4df60ca6a61f04aa88f24606eb344a46), uint256(0x1d2a0668134dc41f0ac8c2f4a9d36030557d890c03a8ac522f97875f92d66855)], [uint256(0x1d7be15f90425b04bab0fd472ba492648ae12ee577a743e6e3433a7266d96c56), uint256(0x0b0c83505f63bc426830ddf106a39bae1b809a089b991b93cac088e28209c5d6)]);
        vk.gamma = Pairing.G2Point([uint256(0x0e299cadd180e1a82dd11378fd78b42938d0a90c354183220981b8bd098bae8f), uint256(0x261e16d5559ab72237a4c125f6cf62100e24a02ae3879417d42bf5866a974820)], [uint256(0x2a7a61ad0defe52b01200c248dea4d169bc6e87785e073a9a3bc82c1289c77c9), uint256(0x012c4340ed8f1ea7b61b56259322a3547b6fad79a72555bfb263813e20a57410)]);
        vk.delta = Pairing.G2Point([uint256(0x0331c3307bc853f3f3e99907b131f7afee49ee4e806026ef756324169b85597b), uint256(0x285c09afb7645b10fb3ef4a45b35736a18bbc6b1180c0f5f9ab875cf6ed7010f)], [uint256(0x1d78842fdca856e65106c0449040c5232827f74113c611af65406928e6b73c43), uint256(0x2011b52917fddac8e5005d20bcfe8307e116aa80452467f9fd18cb6f4b7085bb)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2acaacbabfad74ddab9fb56914df6f2ab125a73a7491cce3a5dfbb0018315bde), uint256(0x1c3de43eb232aeec4e9000e71e0c4bda9d9def41cf2e359b11e8c20281961196));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x18aa22e30197a25639713c55f383c0f809af675599d66c546d14cffdab73ab7d), uint256(0x0498db13cdf90d4b74cfe9e1412f59ae31aa60231df358dc744a9f92947c3f77));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x15f5153ca2ede3fce6bf5bc6249878169e1d002f9e4c274ecffd6e8daec916b9), uint256(0x0a01ceeb3f3f6498ef8ac3170ccfc9ad9175fc7b5c36d075bb196719eb62ff76));
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
