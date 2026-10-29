// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T10 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0b66030243315133ce53bff377d3eb256b8c9dee68785cdd074366a263bdb7a9), uint256(0x18e39fdd22571ac5a9d3634d7d2278b9c281b422fd6a0c0d2fd2bc5fc98d2c0a));
        vk.beta = Pairing.G2Point([uint256(0x1f32ee474b074280340d553b37bb2b1fcd6c784ed48018d28c3adeffaedc986a), uint256(0x0ea91761dfa274a12ceec54ec169953b9014cdfd8287160c40ade3e31a7fdc0d)], [uint256(0x226beacace34e90a378c3b31207e2bd930ce8f946015965fd455fdf64b8e4738), uint256(0x1456b1b7e235d2bf4a3485ba54761cbbe73f288580fad79cb012af6d428b8421)]);
        vk.gamma = Pairing.G2Point([uint256(0x12ef4b9303cf423bcc3e34486bded03c31f56772c39ceaccbeb2f7a552584bd6), uint256(0x304f56c5f408c4487596ba7aa1eef46f992467769fddce0e23af30474eb981ed)], [uint256(0x2df8c746b740ae79832ee85d5b74c068f68bda2f23e1fb0d2d98fb85193edfb0), uint256(0x1a77db3a384c67ce255896e98ccf81581edfde01a17c6cc0533ee0b6ec013d9b)]);
        vk.delta = Pairing.G2Point([uint256(0x279d28943e73c7d65556e9bbebdc0e4184ba472c884a51a0c7e7043c6a360b6a), uint256(0x021f9aefa9072e033d5aafc204d4937c5ea2f182cfae3c893475ec1ff467b010)], [uint256(0x081ff1a4af19d654e50ec8e81451eec97ba73f38a61cea6dd6a6f800971af2ef), uint256(0x17e97682b1013b584798781f5ae388bc0f0335ce02af01495715d1bd6be8e1e1)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1a604a2765d0e6cfde59cec90845f6985677599333775b5448a6178aaf315ffb), uint256(0x2ac53231e60be1edc50fd4e3ebe4b16195e31b45649043da2edcbe587f0f9436));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1a9a97942cb68153347a41e263f2950e0c0fb2f211ae4fef66f3eee4db48fd31), uint256(0x2e405728ffc1c742e62b06b5e1a618b1a95153867309260155f4d829bba60d7f));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x00adfbbd181b6a333229392af83b3d43702770ff66af65ab3d09428757f84d83), uint256(0x2f576ec3099a3c16e6a7f495e7975cc784fd8602c60d50d6b38636747833b91f));
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
