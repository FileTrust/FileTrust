// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title BN254 field arithmetic and G1/G2 point compression helpers.
/// @notice Extracted from the gnark Groth16 verifier template so the
///         PartitionStorageProofGnarkVerifier contract stays within EIP-170's
///         24,576-byte deployment limit.
///
/// Security note: every function here is byte-for-byte identical to the
/// corresponding function in the original gnark-generated verifier.  Only the
/// organisational boundary changed — the logic did not.
/// @author Remco Bloemen, whose gnark Groth16 verifier template this is lifted
///         from. Splitting it across contracts to fit EIP-170 moved the
///         boundaries, not the code or the authorship. MIT, as the original.
library BN254MathLib {

    error ProofInvalid();

    // ─── Precompile addresses ─────────────────────────────────────────────────
    uint256 internal constant PRECOMPILE_MODEXP = 0x05;

    // ─── BN254 base field and scalar field moduli ─────────────────────────────
    uint256 internal constant P =
        0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;

    // ─── Fp constants used by G2 arithmetic ──────────────────────────────────
    uint256 internal constant FRACTION_1_2_FP =
        0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4;
    uint256 internal constant FRACTION_27_82_FP =
        0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 internal constant FRACTION_3_82_FP =
        0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775;

    // ─── Exponents for inversion and square root mod P ────────────────────────
    uint256 internal constant EXP_INVERSE_FP =
        0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45; // P - 2
    uint256 internal constant EXP_SQRT_FP =
        0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52;  // (P + 1) / 4

    // ─── Internal helpers (inlined into the library's external functions) ─────
    // These are NOT inlined into the calling contract — their bytecode lives
    // exclusively in this library's deployed code.

    function negate(uint256 a) internal pure returns (uint256 x) {
        unchecked {
            x = (P - (a % P)) % P;
        }
    }

    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            revert ProofInvalid();
        }
    }

    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        if (mulmod(a, x, P) != 1) {
            revert ProofInvalid();
        }
    }

    function sqrt_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        if (mulmod(x, x, P) != a) {
            revert ProofInvalid();
        }
    }

    function isSquare_Fp(uint256 a) internal view returns (bool) {
        uint256 x = exp(a, EXP_SQRT_FP);
        return mulmod(x, x, P) == a;
    }

    function sqrt_Fp2(uint256 a0, uint256 a1, bool hint)
        internal view
        returns (uint256 x0, uint256 x1)
    {
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);
        if (a0 != addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P)
        ||  a1 != mulmod(2, mulmod(x0, x1, P), P)) {
            revert ProofInvalid();
        }
    }

    // ─── External functions (DELEGATECALL from Verifier) ─────────────────────
    // The Verifier contract contains only thin call stubs for these; the full
    // logic (and all helpers above) lives in the library's deployed bytecode.

    function compress_g1(uint256 x, uint256 y) external view returns (uint256 c) {
        if (x >= P || y >= P) {
            revert ProofInvalid();
        }
        if (x == 0 && y == 0) {
            return 0;
        }
        uint256 y_pos = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (y == y_pos) {
            return (x << 1) | 0;
        } else if (y == negate(y_pos)) {
            return (x << 1) | 1;
        } else {
            revert ProofInvalid();
        }
    }

    function decompress_g1(uint256 c) external view returns (uint256 x, uint256 y) {
        if (c == 0) {
            return (0, 0);
        }
        bool negate_point = c & 1 == 1;
        x = c >> 1;
        if (x >= P) {
            revert ProofInvalid();
        }
        y = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (negate_point) {
            y = negate(y);
        }
    }

    function compress_g2(uint256 x0, uint256 x1, uint256 y0, uint256 y1)
        external view
        returns (uint256 c0, uint256 c1)
    {
        if (x0 >= P || x1 >= P || y0 >= P || y1 >= P) {
            revert ProofInvalid();
        }
        if ((x0 | x1 | y0 | y1) == 0) {
            return (0, 0);
        }

        uint256 y0_pos;
        uint256 y1_pos;
        {
            uint256 n3ab = mulmod(mulmod(x0, x1, P), P - 3, P);
            uint256 a_3  = mulmod(mulmod(x0, x0, P), x0, P);
            uint256 b_3  = mulmod(mulmod(x1, x1, P), x1, P);
            y0_pos = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
            y1_pos = negate(addmod(FRACTION_3_82_FP, addmod(b_3, mulmod(n3ab, x0, P), P), P));
        }

        bool hint;
        {
            uint256 d = sqrt_Fp(
                addmod(mulmod(y0_pos, y0_pos, P), mulmod(y1_pos, y1_pos, P), P)
            );
            hint = !isSquare_Fp(mulmod(addmod(y0_pos, d, P), FRACTION_1_2_FP, P));
        }

        (y0_pos, y1_pos) = sqrt_Fp2(y0_pos, y1_pos, hint);
        if (y0 == y0_pos && y1 == y1_pos) {
            c0 = (x0 << 2) | (hint ? 2 : 0) | 0;
            c1 = x1;
        } else if (y0 == negate(y0_pos) && y1 == negate(y1_pos)) {
            c0 = (x0 << 2) | (hint ? 2 : 0) | 1;
            c1 = x1;
        } else {
            revert ProofInvalid();
        }
    }

    function decompress_g2(uint256 c0, uint256 c1)
        external view
        returns (uint256 x0, uint256 x1, uint256 y0, uint256 y1)
    {
        if (c0 == 0 && c1 == 0) {
            return (0, 0, 0, 0);
        }
        bool negate_point = c0 & 1 == 1;
        bool hint         = c0 & 2 == 2;
        x0 = c0 >> 2;
        x1 = c1;
        if (x0 >= P || x1 >= P) {
            revert ProofInvalid();
        }

        uint256 n3ab = mulmod(mulmod(x0, x1, P), P - 3, P);
        uint256 a_3  = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3  = mulmod(mulmod(x1, x1, P), x1, P);

        y0 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        y1 = negate(addmod(FRACTION_3_82_FP, addmod(b_3, mulmod(n3ab, x0, P), P), P));

        (y0, y1) = sqrt_Fp2(y0, y1, hint);
        if (negate_point) {
            y0 = negate(y0);
            y1 = negate(y1);
        }
    }
}
