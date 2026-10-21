use crate::session_pad::PAD_LEN;

const ALPHABET: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct EquipPrior {
    pub list_field: u32,
    pub level_field: u32,
    pub level_xor: u64,
    pub item_field: u32,
    pub item_xor: u64,
    pub uid_field: u32,
    pub lock_field: u32,
    pub star_field: u32,
    pub star_xor: u64,
    pub main_field: u32,
    pub sub_field: u32,
    pub key_field: u32,
    pub key_xor: u64,
    pub base_field: u32,
    pub base_xor: u64,
    pub count_field: u32,
    pub count_xor: u64,
}

impl EquipPrior {
    pub fn cn30() -> Self {
        Self {
            list_field: 1,
            level_field: 12,
            level_xor: 14887,
            item_field: 13,
            item_xor: 2843,
            uid_field: 6,
            lock_field: 10,
            star_field: 4,
            star_xor: 2652,
            main_field: 11,
            sub_field: 5,
            key_field: 10,
            key_xor: 5,
            base_field: 7,
            base_xor: 853,
            count_field: 14,
            count_xor: 6931,
        }
    }

    pub fn cn31() -> Self {
        Self {
            list_field: 10,
            level_field: 1,
            level_xor: 15226,
            item_field: 3,
            item_xor: 7331,
            uid_field: 6,
            lock_field: 4,
            star_field: 11,
            star_xor: 6831,
            main_field: 9,
            sub_field: 5,
            key_field: 14,
            key_xor: 8130,
            base_field: 11,
            base_xor: 529,
            count_field: 6,
            count_xor: 14928,
        }
    }

    /// CNPRODWin3.2.0 schema measured from the retail protocol table.
    pub fn cn32() -> Self {
        Self {
            list_field: 5,
            level_field: 1,
            level_xor: 14782,
            item_field: 6,
            item_xor: 10045,
            uid_field: 14,
            lock_field: 7,
            star_field: 15,
            star_xor: 975,
            main_field: 9,
            sub_field: 4,
            key_field: 3,
            key_xor: 3263,
            base_field: 13,
            base_xor: 2174,
            count_field: 7,
            count_xor: 16373,
        }
    }
    /// Current CN 3.3 schema, verified against a complete captured inventory.
    pub fn cn33() -> Self {
        Self {
            list_field: 12,
            level_field: 14,
            level_xor: 15335,
            item_field: 1,
            item_xor: 16056,
            uid_field: 9,
            lock_field: 12,
            star_field: 7,
            star_xor: 7223,
            main_field: 4,
            sub_field: 8,
            key_field: 15,
            key_xor: 11012,
            base_field: 11,
            base_xor: 576,
            count_field: 6,
            count_xor: 8102,
        }
    }
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    while value > 0x7f {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

fn scalar(field: u32, value: u64) -> Vec<u8> {
    let mut out = varint(u64::from(field) * 8);
    out.extend(varint(value));
    out
}

fn message(field: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = varint(u64::from(field) * 8 + 2);
    out.extend(varint(payload.len() as u64));
    out.extend_from_slice(payload);
    out
}

fn coded(field: u32, xor: u64, value: u64) -> Vec<u8> {
    scalar(field, value ^ xor)
}

fn property(prior: &EquipPrior, key: u32, base: u32, count: u32) -> Vec<u8> {
    let mut out = coded(prior.count_field, prior.count_xor, u64::from(count));
    out.extend(coded(prior.base_field, prior.base_xor, u64::from(base)));
    out.extend(coded(prior.key_field, prior.key_xor, u64::from(key)));
    out
}

struct SimpleRng(u64);
impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}
fn equip_record(prior: &EquipPrior, rng: &mut SimpleRng) -> Vec<u8> {
    let level = if rng.next() % 100 < 60 {
        0
    } else if rng.next() % 100 < 75 {
        15
    } else {
        1 + rng.next() % 14
    };
    let mut out = Vec::new();
    if level != 0 {
        out.extend(coded(prior.level_field, prior.level_xor, level));
    }
    let item = (310 + rng.next() % 36) * 100 + 40 + rng.next() % 6;
    out.extend(coded(prior.item_field, prior.item_xor, item));
    if rng.next() % 100 < 40 {
        out.extend(scalar(prior.lock_field, 1));
    }
    let subs = [
        11103, 11102, 12103, 12102, 13103, 13102, 20103, 21103, 23203, 31203,
    ];
    let sub_values = [112, 300, 19, 300, 15, 480, 240, 480, 9, 9];
    let mut chosen = Vec::new();
    while chosen.len() < 3 + (rng.next() % 2) as usize {
        let i = (rng.next() % subs.len() as u64) as usize;
        if !chosen.contains(&i) {
            chosen.push(i);
        }
    }
    for i in chosen {
        let count = 1 + rng.next() % 6;
        out.extend(message(
            prior.sub_field,
            &property(prior, subs[i], sub_values[i], count as u32),
        ));
    }
    out.extend(scalar(prior.uid_field, 1 + rng.next() % 100000));
    let mains = [
        11103, 12103, 13103, 11102, 12102, 13102, 20103, 21103, 23103, 30402, 30502, 31203, 31402,
        31503, 31603, 31703, 31803, 32303,
    ];
    let main_values = [
        550, 79, 46, 750, 750, 1200, 600, 1200, 600, 750, 1500, 23, 750, 750, 750, 750, 750, 750,
    ];
    let i = (rng.next() % mains.len() as u64) as usize;
    out.extend(message(
        prior.main_field,
        &property(prior, mains[i], main_values[i], 1),
    ));
    if level >= 3 {
        out.extend(coded(prior.star_field, prior.star_xor, level / 3));
    }
    out
}

pub fn synthetic_profile(prior: &EquipPrior, samples: usize) -> Vec<f64> {
    let mut histogram = vec![0.1_f64; ALPHABET];
    let mut rng = SimpleRng::new(0x5343_4845_4d41_0001);
    for _ in 0..samples {
        let record = equip_record(prior, &mut rng);
        let framed = message(prior.list_field, &record);
        for &byte in &framed {
            histogram[byte as usize] += 1.0;
        }
    }
    let total: f64 = histogram.iter().sum();
    histogram.iter().map(|value| value / total).collect()
}

#[derive(Debug)]
pub struct SinglePadEvidence {
    pub pad: [u8; PAD_LEN],
    pub margin_min: f64,
    pub margin_median: f64,
}

pub fn recover_single_pad(
    cipher: &[u8],
    prior: &EquipPrior,
    iterations: usize,
) -> anyhow::Result<SinglePadEvidence> {
    if cipher.len() < PAD_LEN {
        anyhow::bail!("ciphertext is shorter than one pad period");
    }
    let mut profile = synthetic_profile(prior, 30000);
    let mut best = [0_u8; PAD_LEN];
    let mut margins = vec![0.0_f64; PAD_LEN];
    for _ in 0..=iterations {
        let mut histogram = vec![[0_u32; ALPHABET]; PAD_LEN];
        for (index, &byte) in cipher.iter().enumerate() {
            histogram[index % PAD_LEN][byte as usize] += 1;
        }
        let logs: Vec<f64> = profile.iter().map(|p| p.max(1e-12).ln()).collect();
        for position in 0..PAD_LEN {
            let mut best_key = 0_u8;
            let mut best_score = f64::NEG_INFINITY;
            let mut second_score = f64::NEG_INFINITY;
            for key in 0..ALPHABET {
                let mut score = 0.0_f64;
                for cipher_byte in 0..ALPHABET {
                    let count = histogram[position][cipher_byte] as f64;
                    if count != 0.0 {
                        score += count * logs[cipher_byte ^ key];
                    }
                }
                if score > best_score {
                    second_score = best_score;
                    best_score = score;
                    best_key = key as u8;
                } else if score > second_score {
                    second_score = score;
                }
            }
            best[position] = best_key;
            margins[position] = best_score - second_score;
        }
        let mut observed = vec![1.0_f64; ALPHABET];
        for (index, &byte) in cipher.iter().enumerate() {
            observed[(byte ^ best[index % PAD_LEN]) as usize] += 1.0;
        }
        let observed_total: f64 = observed.iter().sum();
        let prior_profile = synthetic_profile(prior, 3000);
        profile = observed
            .iter()
            .zip(prior_profile.iter())
            .map(|(a, b)| 0.95 * (a / observed_total) + 0.05 * b)
            .collect();
    }
    let mut sorted = margins.clone();
    if margins.iter().any(|value| value.is_nan()) {
        let nan_count = margins.iter().filter(|value| value.is_nan()).count();
        anyhow::bail!("likelihood produced {nan_count} NaN margins");
    }
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let margin_median = if sorted.is_empty() {
        0.0
    } else {
        sorted[sorted.len() / 2]
    };
    Ok(SinglePadEvidence {
        pad: best,
        margin_min: margins.iter().copied().fold(f64::INFINITY, f64::min),
        margin_median,
    })
}

#[cfg(test)]
mod single_pad_tests {
    use super::*;
    #[test]
    fn synthetic_prior_is_a_distribution() {
        let profile = synthetic_profile(&EquipPrior::cn31(), 1000);
        let total: f64 = profile.iter().sum();
        assert!((total - 1.0).abs() < 1e-9);
    }
    #[test]
    fn recovery_recovers_a_planted_pad() {
        let prior = EquipPrior::cn31();
        let pad = crate::session_pad::generate_xorpad(0x1234_5678_9abc_def0, true);
        let mut rng = SimpleRng::new(42);
        let mut plain = Vec::new();
        // A short sample does not cover each pad position often enough to make the
        // column likelihood deterministic. Keep this as a real-size response.
        for _ in 0..4000 {
            plain.extend(message(prior.list_field, &equip_record(&prior, &mut rng)));
        }
        let cipher: Vec<u8> = plain
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ pad[i % PAD_LEN])
            .collect();
        let evidence = recover_single_pad(&cipher, &prior, 2).unwrap();
        assert_eq!(&evidence.pad[..], &pad[..]);
    }
}
