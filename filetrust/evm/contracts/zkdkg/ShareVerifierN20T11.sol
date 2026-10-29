// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN20T11 {
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
        vk.alpha = Pairing.G1Point(uint256(0x09bd455b2a84fc8b3931142306ca600162c1ce615381df75bf424b2d17e102ef), uint256(0x1be9ae3cc888c009506fafeb6ff4215979ef221953e5e2257bc211d981bbf87d));
        vk.beta = Pairing.G2Point([uint256(0x2d6fbf109d9eba22c867a9ecd5d291482797f60ff232ec0ec58ba4c25dfeb920), uint256(0x23b6dc5c1f6100bab6609f14fe7532d4cdf2ea3724f40758d60cbc50393f0ef7)], [uint256(0x165d5a82f925e17f8c82ec9d2578a7508149f0d4c5eec902a4a0df59b528e032), uint256(0x0b91fd841933cd140df0b865b1063ef9116ab71419bb4110e0f2ad672f080bf5)]);
        vk.gamma = Pairing.G2Point([uint256(0x2d4b7d24d43d7827bbd7c2b360bd9e1abb65324e6b243ab466ac8b9ba9ccb21e), uint256(0x1a4031694e3e2be0f07b9723abe5d954f25eb7d1eed443ff44109e3e3fa02d39)], [uint256(0x2b5e0e348582c7ed9db6cad70be9238de8edbf4a4e04f6b08b5b47431017484d), uint256(0x0d345c9c02095262b48d8697c532d6b2092c34b144c498275bb860a0b16cf997)]);
        vk.delta = Pairing.G2Point([uint256(0x13988c904719c697da06c2d568cdd0a86da85109f19150baa3562ece1f9d60ff), uint256(0x127e98fb6e55198652fca0c06d230a0bab8a1f26d211f8a7afb774830ae0810f)], [uint256(0x19b12dbf8c696903005d8451dd13edaed97cd52b554d5a68529819273ed6bfe0), uint256(0x1b18cee90ed2d4c188bc53b6bf7176924c00d8d7f89e80f2505a97d8113aee6b)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0c50ba90ee60b85e0cc827e294f9189334ccf7ff64529f10cf2c7f9b3c89694c), uint256(0x24c20476627e68af3fa8b27e5bea50507348f65dcffc34f8ef31c92ac075b722));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x007556bbef14bc564fede5f16905a01c65fbcb7e1269eacf15e6561c070ae20f), uint256(0x30571a21fe4d0492b962e5e94fae76def478d6616b928d9fb4fa661e79e9f7b8));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x119313e839016a301fc11cf8d91678e73fe75079135fd8a3580bd8b162de7592), uint256(0x1c3c1d9d3bc3b6518dde9fe5db74b27c130aacb8cebc41914eb3aeb93a86f6b3));
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
