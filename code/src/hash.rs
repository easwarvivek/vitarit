//! Domain-separated hash helpers used across PKEnc / VNE / proofs.

use sha2::{Digest, Sha256, Sha512};
use sha3::{
    digest::{ExtendableOutput, Update as Sha3Update, XofReader},
    Shake256,
};

/// Hm : Gp → {0,1}^{|m|} from Figure 5.
pub fn hm(point_bytes: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    Sha3Update::update(&mut hasher, b"VITARIT-Hm-v1");
    Sha3Update::update(&mut hasher, point_bytes);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; out_len];
    reader.read(&mut out);
    out
}

/// Hc : challenge hash selecting unopened set J ⊂ [2λs], |J|=λs.
pub fn hc_challenge_set(data: &[u8], lambda_s: usize) -> Vec<usize> {
    let total = 2 * lambda_s;
    let mut selected = Vec::with_capacity(lambda_s);
    let mut used = vec![false; total];
    let mut counter: u64 = 0;
    while selected.len() < lambda_s {
        let mut h = Sha256::new();
        Digest::update(&mut h, b"VITARIT-Hc-v1");
        Digest::update(&mut h, data);
        Digest::update(&mut h, counter.to_le_bytes());
        let dig = h.finalize();
        for chunk in dig.chunks_exact(4) {
            if selected.len() >= lambda_s {
                break;
            }
            let v = u32::from_le_bytes(chunk.try_into().unwrap()) as usize % total;
            if !used[v] {
                used[v] = true;
                selected.push(v);
            }
        }
        counter += 1;
    }
    selected.sort_unstable();
    selected
}

/// Generic labelled SHA-512 digest.
pub fn sha512_label(label: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    Digest::update(&mut h, label);
    for p in parts {
        Digest::update(&mut h, (p.len() as u64).to_le_bytes());
        Digest::update(&mut h, p);
    }
    let out = h.finalize();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&out);
    arr
}

/// XOR two equal-length byte slices.
pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hm_output_length() {
        for len in [0usize, 1, 32, 48, 64] {
            let out = hm(b"point", len);
            assert_eq!(out.len(), len);
        }
    }

    #[test]
    fn hm_deterministic() {
        assert_eq!(hm(b"abc", 48), hm(b"abc", 48));
    }

    #[test]
    fn hm_domain_separated_by_input() {
        assert_ne!(hm(b"a", 32), hm(b"b", 32));
    }

    #[test]
    fn hc_challenge_set_size_and_range() {
        for lambda_s in [1usize, 2, 4, 8, 16] {
            let j = hc_challenge_set(b"cts", lambda_s);
            assert_eq!(j.len(), lambda_s);
            assert!(j.windows(2).all(|w| w[0] < w[1])); // sorted unique
            assert!(j.iter().all(|&i| i < 2 * lambda_s));
        }
    }

    #[test]
    fn hc_challenge_set_deterministic() {
        assert_eq!(
            hc_challenge_set(b"seed", 8),
            hc_challenge_set(b"seed", 8)
        );
    }

    #[test]
    fn hc_challenge_set_depends_on_data() {
        assert_ne!(
            hc_challenge_set(b"seed-a", 8),
            hc_challenge_set(b"seed-b", 8)
        );
    }

    #[test]
    fn xor_involution() {
        let a = b"hello world!!!!";
        let b = b"maskmaskmaskmas";
        assert_eq!(a.len(), b.len());
        let x = xor_bytes(a, b);
        assert_eq!(xor_bytes(&x, b), a);
    }

    #[test]
    fn sha512_label_deterministic_and_sensitive() {
        let a = sha512_label(b"L", &[b"x", b"y"]);
        let b = sha512_label(b"L", &[b"x", b"y"]);
        let c = sha512_label(b"L", &[b"xy"]);
        assert_eq!(a, b);
        assert_ne!(a, c); // length-prefixing prevents ambiguity
    }
}
