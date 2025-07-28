extern crate curve25519_dalek;
extern crate bls12_381;
extern crate rand;
extern crate rand_core;
extern crate sha2;
extern crate hex;

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use bls12_381::{G1Projective, G1Affine, Scalar as BLSScalar};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Sha512, Sha256, Digest};
use rand::seq::SliceRandom;
use std::convert::{TryInto};

// Helper function to convert [u8; 32] into [u64; 4]
fn bytes_to_u64_array(bytes: [u8; 32]) -> [u64; 4] {
    let mut u64_array = [0u64; 4];
    for i in 0..4 {
        u64_array[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    u64_array
}

// Function to hash the message `m` to a point on the curve (simplified)
fn hash_to_curve(m: &[u8]) -> G1Projective {
    let mut hasher = Sha256::new();
    hasher.update(m);
    let hash_result = hasher.finalize();
    let u64_array = bytes_to_u64_array(hash_result.try_into().unwrap());
    G1Projective::generator() * BLSScalar::from_raw(u64_array)
}

// Generate a random `BLSScalar`
pub fn random_bls_scalar() -> BLSScalar {
    let mut rng = OsRng;
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    BLSScalar::from_bytes_wide(&bytes)
}

// Generate a random `DalekScalar`
fn random_dalek_scalar() -> DalekScalar {
    let mut rng = OsRng;
    let mut random_bytes = [0u8; 64];
    rng.fill_bytes(&mut random_bytes);
    DalekScalar::from_bytes_mod_order_wide(&random_bytes)
}

// Generate a random `RistrettoPoint`
fn random_ristretto_point() -> RistrettoPoint {
    let scalar = random_dalek_scalar();
    RISTRETTO_BASEPOINT_POINT * scalar
}

// Encrypt function updated to take `rj` as input and Aj_bj as the message
pub fn encrypt(ek: &RistrettoPoint, rj: DalekScalar, Aj_bj: G1Projective) -> (RistrettoPoint, RistrettoPoint, Vec<u8>) {
    let mut rng = OsRng;
    
    // Generate s inside the function
    let mut random_bytes_s = [0u8; 64];
    rng.fill_bytes(&mut random_bytes_s);
    let s = DalekScalar::from_bytes_mod_order_wide(&random_bytes_s);

    // Compute c1 = g^rj (g is the basepoint of the Ristretto curve)
    let c1 = RISTRETTO_BASEPOINT_POINT * rj;

    // Compute c2 = (ek^rj) * (g^s)
    let ek_rj = ek * rj;  // ek^rj
    let g_s = RISTRETTO_BASEPOINT_POINT * s; // g^s
    let c2 = ek_rj + g_s;  // (ek^rj) * (g^s)

    // Convert G1Projective (Aj * bj) to G1Affine, then compress and convert to bytes
    let Aj_bj_affine: G1Affine = Aj_bj.into();
    let Aj_bj_bytes = Aj_bj_affine.to_compressed();

    // Hash Aj_bj_bytes to produce shared secret for message encryption
    let mut hasher = Sha512::new();
    hasher.update(Aj_bj_bytes.as_ref());
    let hash_output = hasher.finalize();

    // XOR the hash with the Aj_bj_bytes to produce c3
    let hash_xor: Vec<u8> = hash_output.iter().cycle().take(Aj_bj_bytes.len()).cloned().collect();
    let c3: Vec<u8> = hash_xor.iter().zip(Aj_bj_bytes.iter()).map(|(&h, &m)| h ^ m).collect();

    // Return c1 and c2 as RistrettoPoints after decompression
    let decompressed_c1 = c1.compress().decompress().expect("Decompression failed");
    let decompressed_c2 = c2.compress().decompress().expect("Decompression failed");

    (decompressed_c1, decompressed_c2, c3)
}

// Main `Enc` function
pub fn enc(
    sk: BLSScalar,       // BLS secret key
    vk: G1Projective,    // BLS verification key
    wit: BLSScalar,      // BLS signature on mstar
    lambda_s: usize,     // Security parameter
    mstar: &[u8],        // The message mstar
    ek: &RistrettoPoint  // Encryption key
) -> (Vec<(RistrettoPoint, RistrettoPoint, Vec<u8>)>, Vec<(G1Affine, G1Affine, RistrettoPoint)>, Vec<(G1Affine, G1Affine, G1Affine, (usize, G1Affine, G1Affine, G1Affine, G1Affine, Vec<u8>), (BLSScalar, BLSScalar, BLSScalar))>) {
    let mut csprng = OsRng;
    let mut ct_list: Vec<(RistrettoPoint, RistrettoPoint, Vec<u8>)> = Vec::new();  // For (ctj, Aj, Bj)
    let mut sop: Vec<(G1Affine, G1Affine, RistrettoPoint)> = Vec::new();
    let mut sunop: Vec<(G1Affine, G1Affine, G1Affine, (usize, G1Affine, G1Affine, G1Affine, G1Affine, Vec<u8>), (BLSScalar, BLSScalar, BLSScalar))> = Vec::new();

    // Hash mstar to a curve point and generate BLS signature
    let bls_signature = hash_to_curve(mstar) * sk;

    // Random indices
    let mut indices: Vec<usize> = (0..2 * lambda_s).collect();
    indices.shuffle(&mut csprng);
    let J = &indices[..lambda_s]; 

    // Loop for j in 0 to 2*lambda_s
    for j in 0..2 * lambda_s {
        let aj = random_bls_scalar();
        let bj = random_bls_scalar();
        let rj = random_dalek_scalar();  // Pass this as r to encrypt
        
        let Aj = G1Projective::generator() * aj;
        let Bj = G1Projective::generator() * bj;

        // Encrypt with Aj * bj as the message and rj as input
        let (c1, c2, c3) = encrypt(ek, rj, Aj * bj);

        // Convert Aj and Bj to G1Affine before compression
        let Aj_affine: G1Affine = Aj.into();
        let Bj_affine: G1Affine = Bj.into();

        // Collect (ctj, Aj, Bj) in the list
        ct_list.push((c1, c2, c3));

        if j < lambda_s {
            // Collect in `sop`
            sop.push((Aj_affine, Bj_affine, RISTRETTO_BASEPOINT_POINT * rj));
        } else {
            // Compute Zj and collect in `sunop`
            let Zj = (Aj * bj) * wit;
            let Zj_affine: G1Affine = Zj.into();
            sunop.push((
                Aj_affine,
                Bj_affine,
                Zj_affine,
                (
                    j,
                    Aj_affine,
                    Bj_affine,
                    Zj_affine,
                    G1Affine::from(vk),
                    mstar.to_vec(),
                ),
                (bj, sk, wit),
            ));
        }
    }

    (ct_list, sop, sunop)
}

// Test the full functionality
fn main() {
    let sk = random_bls_scalar(); // BLS secret key
    let vk = G1Projective::generator() * sk; // BLS verification key
    let wit = random_bls_scalar(); // Witness (BLS signature)
    let lambda_s = 256;
    let mstar = b"Test 384-bit message";

    use std::time::Instant;
    let now = Instant::now();


    let ek = random_ristretto_point(); // Encryption key
    let (ct_list, sop, sunop) = enc(sk, vk, wit, lambda_s, mstar, &ek);

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);

    // Output the result
    //println!("Ciphertext List: {:?}", ct_list);
    //println!("Sop List: {:?}", sop);
    //println!("Sunop List: {:?}", sunop);
}
