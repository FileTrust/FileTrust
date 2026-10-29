// SPDX-License-Identifier: MIT
// This file is MIT Licensed.
pragma solidity ^0.8.0;

import "./Pairing.sol";

contract SharePossessionVerifier {
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
        vk.alpha = Pairing.G1Point(uint256(0x1e742cd349fe8044121589f829856b6c0d34e3377b22f32442ebd7db2b4df33d), uint256(0x2cc0b027aa46879fb0f7706e5ddda86ec562871f21576af3a216228fa5359d62));
        vk.beta = Pairing.G2Point([uint256(0x078174f846c6c45fa6a22e4cf1ac4f7f827753f80ff4850dff7e699095531261), uint256(0x039c034a4c7e595ef146c4ee26638bd3aabd7c8dadd341df430440f7eb0e75b3)], [uint256(0x19bff593f15e655ef1e540cf8b506d274925bf2f97cf6b768420d1dcfabff359), uint256(0x013882096822026bb3d3e3a4862a95664308113019e6dd6025d8f2e74b5ac462)]);
        vk.gamma = Pairing.G2Point([uint256(0x1e60e8762dc3906c1c71d52b37e316536a761c7cfba020bd88bc97e0d851a618), uint256(0x00ce5c2b9da927990d31eb36d4f41fc2889bc58f66aa38ca2ee5134d2d29a000)], [uint256(0x2526ddfdce8b2ce32a23ba1bd8e9e9225420cefd140c511c51923309fcf3220c), uint256(0x2d67a829c2c00d351cd63b3604b2e4c5a76e6fdc3f03bcd3cea3b3842abec187)]);
        vk.delta = Pairing.G2Point([uint256(0x01d0dac64da5dabdf215eaaf0e13b50d4ebf10b4819222d871fa40c0a09b6bfd), uint256(0x12a433d41b5cbb4729fec28db7568c4e493d70465ce34daa42c5ac00be448d5a)], [uint256(0x27a58297ca44b5b72c65f915d3b9348c2e9a85fa9b959dc6b8aaa6130c1741de), uint256(0x24039c552ce46bfcda31a1db5a074ead2e7472262c3e49e7f89835c029085724)]);
        vk.gamma_abc = new Pairing.G1Point[](9);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x1cb88e6cfe1321ff69dc8d4fc9581c12dade04940c1535652d5199c9d4d923c8), uint256(0x11ed27e067147687ca8985704c912a2a3458ad092064722b45243cfd188bf365));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1fd7b4a47bef8ecc0ddcdeec3b4a9e615d57ee80b43d68be3db3f518dd83c9a2), uint256(0x0a289da5122f45d4b277d0b50e1969a08595609580e76f5107eb5cbaa512bdbc));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1f0e472755435a8445e16f22800f410721f277a359ad16944e04cae7ae89f4d1), uint256(0x18de3aad2a32f4e8db5456c1697e805f7776ea91143ac7c9ad34a9e3a05c7b67));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x1dab1461a7903ef396de9b8747ea7c2d64f426c2612d3394b5270bea5b44c68e), uint256(0x022b499fd6c3212fac2e9a23d80a905ca8d3bb2f81936c7fdfd34481e0177932));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x15cfc817dbba6bbc4cddb9fd95aee35f4fd162e60739a4103f276fd97d2692a1), uint256(0x0c3b2d7e1f340baa66c715496285ca58732314904fdebd6ca2e9554b6fc738a5));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x22493a3a746e64274a92f97747aa52bd80a5abe488cfe427febc10e0d4a5fe9b), uint256(0x2f34c9d5dfdff1bab24c880a15951dd9fdc61c5789411f410c6bd3106151b8fd));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2eefc9ef5d90fe96e5c077293a11124cc44d34395caba2f0c5f25260ff381623), uint256(0x03cbcb1ae9836dd59f6e7c9c6cf0e6c6a860c00f1597ff6c83b28cbc035c79f1));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x29760f33a02995520798b98dabaf50b22fe52521c512ee34e4d3fd8aedfce0bf), uint256(0x2611aeb634dea337f55df264f7c920280a95f85776f495e5fe1339582d3287d4));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x10b1639d8ca1e9f345416259985748a9ca1acd59c959c6c00585af67dfcdc1c1), uint256(0x0715b9a8b9a86d51310775cb7ea277e2d05990e603f88d1bd1d6b14e2b8f86dd));
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
            Proof memory proof, uint[8] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](8);
        
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
