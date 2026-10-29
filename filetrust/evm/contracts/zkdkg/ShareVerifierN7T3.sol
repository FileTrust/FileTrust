// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN7T3 {
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
        vk.alpha = Pairing.G1Point(uint256(0x150c6114973c47bbc5279d8d9c64b9a3b03193ebc707ed6cbc1a3e445787ed3f), uint256(0x300cf0adb9ce94f1fd42b8f1077bb41476feeb86a366671ca0b1cc1627e6389b));
        vk.beta = Pairing.G2Point([uint256(0x0f21aec9abcd0fd46933c135e51bce9d9a788af4afa07792b5b4c4ff1eb4069f), uint256(0x210d8b918c0ac657edf606340a1fc6b366944d1c5f00aed007970ab886701a8e)], [uint256(0x1247d19a1c14292817059a14eb2137307dad40920a2cc4c0bc2cc9d6780ac65a), uint256(0x215478377dc9886879a2114a9ed8a3a7662ed894f712d35fdb7243285eec43d1)]);
        vk.gamma = Pairing.G2Point([uint256(0x29220e6cf3e328cc6bb1166842525f5b231cc22797ddcef32eedc520db518d3a), uint256(0x049ed9a83df66c2823c38f00ab81e01959c2f49cc6b1103c30ba60ae10513d73)], [uint256(0x01b7b10df25297138c5a485b5d90dd884889a1a05fb1daa96fbffcec354d0395), uint256(0x18ff456049785630c28c41b53b8c216d28b3f62c7cdf9cbddb8a416ecf358637)]);
        vk.delta = Pairing.G2Point([uint256(0x06307bc43989dfd003f6d9b1488e1c358c1ffeaf302dc44b6b73ae93630ade72), uint256(0x2b70722b43482bee604ab4407e32570e3e752828305a0ce4ef1f836de0691745)], [uint256(0x1d6755cea8a1509bdd14117500781d7b59e1791699e539d2d5de435af8ad7c69), uint256(0x1bbb89c084f20cc60e32b79c9d58c2a37833bada30cb90cf2b7136c3b0d4516a)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0614e191a469a77a1b01c6d875c47f658a05ce3f4c6f9cdb35650e084df5bcb9), uint256(0x259303e96e046039f8f71441ebe5e65270f876cc449e0e8aef0affdb0120652c));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x2efd3a3a3c731e140131946562f931a5f9925f4911ae3f0f958ca22bade932a6), uint256(0x008056f1751a58fc4d0ca5d9fff29659bf0c829954a7ab2969312d013d652d30));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x0c49f4cf36effbd4c0f1f66474ddc0780cebdc7ff55824f4be44e1a190816147), uint256(0x20014b11d5f49829273e1fe7215ab66e8ac305fb3bb91f24257b8c5d575c31c9));
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
