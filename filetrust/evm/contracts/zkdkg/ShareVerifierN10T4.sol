// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN10T4 {
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
        vk.alpha = Pairing.G1Point(uint256(0x0524532cece91d8f6fa13b769579100aae4a6127015f490685023e7a798d77c8), uint256(0x0c62dc829df9e65ec0107bb621ac2785e94486e4c8fa5d6b64e823038e5d620d));
        vk.beta = Pairing.G2Point([uint256(0x0369e9b21916bb8de51454359b684e2896969e763751930d10a14beedfe1194f), uint256(0x0b83c4c43958940dbeeb6ecf2f2c45d9b9265f85c4cd5f562367bb8999ba5b00)], [uint256(0x16d7dffb78aeab5c6b3af9238aeb3d65c891a88df607417c58756e15a859032f), uint256(0x0e544bfdfd14b619c48fa582f9acb0726c08e1dad5cdd2ca52f5ba74d4d59668)]);
        vk.gamma = Pairing.G2Point([uint256(0x049127f615893c864d87751cf2b9e7dcf2bd1aa77e7219a9773e363643368adf), uint256(0x0717bdec3828f15f85bdb40767b0bda79c5a40a674f6ca5885c50511ab6a5d54)], [uint256(0x2dba3e20d9e236d044f0aca11aaeae4da36a20fee33173b9ff9bf83f8c1fe510), uint256(0x2c39442c1434c07848ac441ea61a86cce1eba9ed8e19069f580beb3e8e462487)]);
        vk.delta = Pairing.G2Point([uint256(0x2426fb5db7d5ab35cddc49bdc7d10a9d78486c5f9bec8e2a740e88f5226b5b02), uint256(0x0df45fd8fc6b3b7bcff3b74034c3d88851eee75d217db107f7e81da34c9f58b2)], [uint256(0x1f5ea39425d9c69ab68b9f25b6f9efc8b6a6fe4e07d38a16152e09c9071e11ac), uint256(0x12dfd339b5d6686b4a7f940a55753b1e0e7dc5724dec3af51a2384e542dea0dc)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2cd644c085e8565347cfe4be2098bb0279bc2c3d5be60b515fd99dea632cb9b3), uint256(0x102f77e05a12ad826eb2d9c2943ec64f6135a9de349ecf225389efaddc1a732b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1c08f50a3133287e82f878865b58c312b4d9afc29cb13a2607860851af0275e3), uint256(0x1d7477b682fa304b7089bf220ff5cfa898b77a39643ab2274498c2584f487cde));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x18be2b0ad8faf387560b854d33af990fc7c2e166a2993d6cec311e43b64d0e75), uint256(0x1f773b759c1f61a578b490163e8e591cc0a37976652d042eaa489e3a2793b801));
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
