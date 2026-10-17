//! MT19937-64 session XOR pad recovery for ZZZ command bodies.
//!
//! Command bodies are XORed with a 4096-byte pad that restarts at `pad[0]` for every
//! body. The pad is 512 consecutive MT19937-64 outputs packed **big-endian** (retail;
//! `yixuan-rs` defaults to little-endian, which is why its pads never matched).
//!
//! Two captures of the same account, same game version, with the drive-disc inventory
//! unchanged between them share identical plaintext for static messages, so for a
//! command present in both with the same body length:
//!
//! ```text
//! C1 ^ C2 = (P ^ pad1) ^ (P ^ pad2) = pad1 ^ pad2
//! ```
//!
//! Tempering and the twist are both GF(2)-linear, so the difference obeys the same
//! recurrence and can be untempered/untwisted back to an initial-state difference.
//! The difference alone cannot separate the two seeds, but the seeding routine
//! `mt[i] = MULT * (mt[i-1] ^ (mt[i-1] >> 62)) + i` is a nonlinear mod-2^64
//! multiply-add, and that does.
//!
//! See `DRIVE_DISC_RECIPE.zh-CN.md` for the evidence tables and the procedure to
//! redo this after a game update.

pub const PAD_LEN: usize = 4096;

const NN: usize = 312;
const MM: usize = 156;
const MATRIX_A: u64 = 0xB502_6F5A_A966_19E9;
const UM: u64 = 0xFFFF_FFFF_8000_0000;
const LM: u64 = 0x7FFF_FFFF;
const MULT: u64 = 6_364_136_223_846_793_005;
/// Modular inverse of `MULT` mod 2^64, for stepping the seeding chain backwards.
const MULT_INV: u64 = 13_877_824_140_714_322_085;

fn temper(mut x: u64) -> u64 {
    x ^= (x >> 29) & 0x5555_5555_5555_5555;
    x ^= (x << 17) & 0x71D6_7FFF_EDA6_0000;
    x ^= (x << 37) & 0xFFF7_EEE0_0000_0000;
    x ^= x >> 43;
    x
}

fn untemper(y: u64) -> u64 {
    let mut x = y ^ (y >> 43);
    x ^= (x << 37) & 0xFFF7_EEE0_0000_0000;

    let base = x;
    let mut z = x;
    for _ in 0..4 {
        z = base ^ ((z << 17) & 0x71D6_7FFF_EDA6_0000);
    }

    let base = z;
    let mut w = z;
    for _ in 0..3 {
        w = base ^ ((w >> 29) & 0x5555_5555_5555_5555);
    }
    w
}

fn twist(mt: &[u64; NN]) -> [u64; NN] {
    let mag = [0_u64, MATRIX_A];
    let mut out = *mt;
    for i in 0..(NN - MM) {
        let x = (out[i] & UM) | (out[i + 1] & LM);
        out[i] = out[i + MM] ^ (x >> 1) ^ mag[(x & 1) as usize];
    }
    for i in (NN - MM)..(NN - 1) {
        let x = (out[i] & UM) | (out[i + 1] & LM);
        out[i] = out[i + MM - NN] ^ (x >> 1) ^ mag[(x & 1) as usize];
    }
    let x = (out[NN - 1] & UM) | (out[0] & LM);
    out[NN - 1] = out[MM - 1] ^ (x >> 1) ^ mag[(x & 1) as usize];
    out
}

/// Invert one twist. `out[0]`'s low 31 bits are unrecoverable and are not used.
/// Returns `None` when the recovered low word is inconsistent with the input.
fn untwist(new: &[u64; NN]) -> Option<[u64; NN]> {
    let mag = [0_u64, MATRIX_A];
    let solve = |r: u64| -> u64 {
        let b = (r >> 63) as usize;
        (((r ^ mag[b]) << 1) & !1) | b as u64
    };

    let mut hi = [0_u64; NN];
    let mut lo = [0_u64; NN];

    let x = solve(new[NN - 1] ^ new[MM - 1]);
    if (x & LM) != (new[0] & LM) {
        return None;
    }
    hi[NN - 1] = x & UM;

    for i in (NN - MM..=NN - 2).rev() {
        let x = solve(new[i] ^ new[i + MM - NN]);
        hi[i] = x & UM;
        lo[i + 1] = x & LM;
    }
    for i in (0..NN - MM).rev() {
        let x = solve(new[i] ^ (hi[i + MM] | lo[i + MM]));
        hi[i] = x & UM;
        lo[i + 1] = x & LM;
    }

    let mut out = [0_u64; NN];
    for i in 0..NN {
        out[i] = hi[i] | lo[i];
    }
    Some(out)
}

fn init_state(seed: u64) -> [u64; NN] {
    let mut mt = [0_u64; NN];
    mt[0] = seed;
    for i in 1..NN {
        let p = mt[i - 1];
        mt[i] = MULT.wrapping_mul(p ^ (p >> 62)).wrapping_add(i as u64);
    }
    mt
}

/// 512 MT19937-64 outputs. Retail ZZZ packs them big-endian.
pub fn generate_xorpad(seed: u64, big_endian: bool) -> [u8; PAD_LEN] {
    let first = twist(&init_state(seed));
    let second = twist(&first);
    let mut pad = [0_u8; PAD_LEN];
    for i in 0..512 {
        let word = temper(if i < NN { first[i] } else { second[i - NN] });
        let bytes = if big_endian {
            word.to_be_bytes()
        } else {
            word.to_le_bytes()
        };
        pad[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    pad
}

pub fn xor_in_place(body: &mut [u8], pad: &[u8; PAD_LEN]) {
    for (i, b) in body.iter_mut().enumerate() {
        *b ^= pad[i % PAD_LEN];
    }
}

/// How well `diff` obeys the MT recurrence: words 312..511 reproduced from 0..311.
pub struct RecurrenceCheck {
    pub hits: usize,
    pub total: usize,
    pub init_diff: Option<[u64; NN]>,
}

pub fn check_recurrence(diff: &[u8; PAD_LEN], big_endian: bool) -> RecurrenceCheck {
    let word = |i: usize| -> u64 {
        let mut b = [0_u8; 8];
        b.copy_from_slice(&diff[i * 8..(i + 1) * 8]);
        if big_endian {
            u64::from_be_bytes(b)
        } else {
            u64::from_le_bytes(b)
        }
    };

    let mut state = [0_u64; NN];
    for (i, value) in state.iter_mut().enumerate() {
        *value = untemper(word(i));
    }
    let next = twist(&state);
    let hits = (0..200)
        .filter(|&i| temper(next[i]) == word(NN + i))
        .count();

    RecurrenceCheck {
        hits,
        total: 200,
        init_diff: untwist(&state),
    }
}

pub fn check_pad_recurrence(pad: &[u8; PAD_LEN], big_endian: bool) -> RecurrenceCheck {
    check_recurrence(pad, big_endian)
}

/// Invert `x -> x ^ (x >> 62)`.
fn undo_shift_xor(a: u64) -> u64 {
    let mut x = a & !3;
    x |= (a & 1) ^ ((a >> 62) & 1);
    x |= (((a >> 1) & 1) ^ ((a >> 63) & 1)) << 1;
    x
}

/// Recover both absolute seeds from an initial-state difference.
///
/// Only `d_init[1]` and `d_init[2]` are used; `d_init[0]` is partially lost in the
/// twist. Because a mod-2^64 multiply-add's bit `k` depends only on bits `<= k`,
/// candidates for the first seeded word are grown one bit at a time and pruned
/// against `d_init[2]`, then verified against the whole 310-step seeding chain.
pub fn recover_seeds(d_init: &[u64; NN]) -> Vec<(u64, u64)> {
    let d1 = d_init[1];
    let d2 = d_init[2];
    let d1_low = d1 & ((1_u64 << 62) - 1);
    let mut solutions = Vec::new();

    for top in 0_u64..4 {
        let top_y = top ^ (d1 >> 62);
        let mut cands = vec![0_u64];

        for k in 1..63_u32 {
            let mask = (1_u64 << k) - 1;
            let target = d2 & mask;
            let mut next = Vec::with_capacity(cands.len() * 2);
            for v in &cands {
                for bit in 0..2_u64 {
                    let vv = v | (bit << (k - 1));
                    let gx = (vv ^ top) & mask;
                    let gy = (vv ^ d1_low ^ top_y) & mask;
                    let a = MULT.wrapping_mul(gx).wrapping_add(2) & mask;
                    let b = MULT.wrapping_mul(gy).wrapping_add(2) & mask;
                    if (a ^ b) == target {
                        next.push(vv);
                    }
                }
            }
            cands = next;
            if cands.is_empty() {
                break;
            }
        }

        for v in cands {
            let first_a = (top << 62) | v;
            let first_b = first_a ^ d1;
            let mut xa = first_a;
            let mut xb = first_b;
            let mut ok = true;
            for (i, expected) in d_init.iter().enumerate().skip(2) {
                xa = MULT.wrapping_mul(xa ^ (xa >> 62)).wrapping_add(i as u64);
                xb = MULT.wrapping_mul(xb ^ (xb >> 62)).wrapping_add(i as u64);
                if (xa ^ xb) != *expected {
                    ok = false;
                    break;
                }
            }
            if ok {
                let seed_a = undo_shift_xor(first_a.wrapping_sub(1).wrapping_mul(MULT_INV));
                let seed_b = undo_shift_xor(first_b.wrapping_sub(1).wrapping_mul(MULT_INV));
                solutions.push((seed_a, seed_b));
            }
        }
    }
    solutions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mult_inv_is_correct() {
        assert_eq!(MULT.wrapping_mul(MULT_INV), 1);
    }

    #[test]
    fn temper_roundtrips() {
        for seed in [0_u64, 1, 0x0123_4567_89AB_CDEF, u64::MAX] {
            assert_eq!(untemper(temper(seed)), seed);
        }
    }

    #[test]
    fn twist_roundtrips_above_the_lost_bits() {
        let state = init_state(0xDEAD_BEEF_CAFE_1234);
        let twisted = twist(&state);
        let back = untwist(&twisted).expect("untwist should succeed");
        assert_eq!(back[0] & UM, state[0] & UM);
        assert_eq!(back[1..], state[1..]);
    }

    #[test]
    fn synthetic_pad_difference_yields_both_seeds() {
        let (sa, sb) = (0x0123_4567_89AB_CDEF_u64, 0xFEDC_BA98_7654_3210_u64);
        let pa = generate_xorpad(sa, true);
        let pb = generate_xorpad(sb, true);
        let mut diff = [0_u8; PAD_LEN];
        for i in 0..PAD_LEN {
            diff[i] = pa[i] ^ pb[i];
        }

        let check = check_recurrence(&diff, true);
        assert_eq!(check.hits, check.total);
        let init = check.init_diff.expect("untwist should succeed");

        let sols = recover_seeds(&init);
        assert!(
            sols.iter()
                .any(|&(a, b)| (a == sa && b == sb) || (a == sb && b == sa)),
            "expected {sa:#x}/{sb:#x}, got {sols:x?}"
        );
    }

    #[test]
    fn little_endian_packing_fails_the_recurrence() {
        let pa = generate_xorpad(1, false);
        let pb = generate_xorpad(2, false);
        let mut diff = [0_u8; PAD_LEN];
        for i in 0..PAD_LEN {
            diff[i] = pa[i] ^ pb[i];
        }
        assert_eq!(check_recurrence(&diff, false).hits, 200);
        assert!(check_recurrence(&diff, true).hits < 10);
    }
}
