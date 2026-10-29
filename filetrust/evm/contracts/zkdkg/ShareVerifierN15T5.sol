// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract ShareVerifierN15T5 {
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
        vk.alpha = Pairing.G1Point(uint256(0x2a5207808549d5ba2bb53d1f3c09d01d1eee7e016158de58dc91f7eb919f372d), uint256(0x05a9fd0c833e1320dad19f8cfab6099334e5f4c2c834fc03c683cec46723c1a5));
        vk.beta = Pairing.G2Point([uint256(0x09c06b1178c306faa304daa83750b6b061bbf1d5444decc78fc600d239927314), uint256(0x0d0e0150d4347cb8ada0d00c49dfa883677a582eccbf84e563eeb38d4f007c40)], [uint256(0x0120c29314f86dcaf72da53aea00a6ea7a83f400bf972ac14f743e90c4e0d623), uint256(0x02d342d4538f477674f990b62791b9882d364b7770280a1d00cdcc18192e3383)]);
        vk.gamma = Pairing.G2Point([uint256(0x223329b1708d217afd74db3268ffd1c22d342b76b438d8d705173472b182b438), uint256(0x11982003126b176ae302efe0bf241945f4601062461e93692f01f1fca125091d)], [uint256(0x22ef5a183354c025b646a0f914013a34f60148c81a3d6732bdd2d09dad25bd56), uint256(0x2c7343eb44f70e8195ad97b97e8a20f74601783b154b73ae0eb5cddb35a52b3b)]);
        vk.delta = Pairing.G2Point([uint256(0x1f2600b2abcb8126956ff99a1356b9b6d6aac97490d88804511f3dac7e857cef), uint256(0x28bc147b337dc53afac0a0b24da45ccbb3e543be6709dbe42832c4c93ad017d2)], [uint256(0x2da6ba0f50335cae1f3b5dd27054101faf6fad246aa947442085b15dcffb6aa9), uint256(0x0f6f55efddb7df5bb8f27339ac584a1313cc85c4999a7653261fd25c2ece2b0e)]);
        vk.gamma_abc = new Pairing.G1Point[](3);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x046db5c87654afbc35384fa7b0e5c62caccab84e33473d05f2f9b0785fe30d5c), uint256(0x0516be52cfd51131f06c113862591b3339646897ea31283e707e16683e57b0ad));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x048d69e0487577b461716db422a882a9a003708fad5f1f71a7ed38855c3e2460), uint256(0x1ec3c26db9257867f3551895e3d4b3c7166dafa41f530db4080853c1819a5724));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1a1f053f961fbf6a6121473c7e9eab3a342b5e6471076e17338d6eaea133625a), uint256(0x1ea58d8a78171e5407914ffd4343fb611e02111688ff4864e27212d72f9cb880));
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
