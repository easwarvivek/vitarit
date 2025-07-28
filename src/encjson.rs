extern crate curve25519_dalek;
extern crate bls12_381;
extern crate rand;
extern crate rand_core;
extern crate sha2;
extern crate serde;
extern crate serde_json;
extern crate hex;

use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar as DalekScalar;
use bls12_381::{G1Projective, G1Affine, Scalar as BLSScalar};
use serde::{Serialize, Deserialize};
use serde_json::{to_string, from_str};
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

// Custom serializable version of `RistrettoPoint` using `CompressedRistretto`
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SerializableRistrettoPoint(pub [u8; 32]);

impl From<RistrettoPoint> for SerializableRistrettoPoint {
    fn from(point: RistrettoPoint) -> Self {
        SerializableRistrettoPoint(point.compress().to_bytes())
    }
}

impl From<CompressedRistretto> for SerializableRistrettoPoint {
    fn from(compressed: CompressedRistretto) -> Self {
        SerializableRistrettoPoint(compressed.to_bytes())
    }
}

impl Into<RistrettoPoint> for SerializableRistrettoPoint {
    fn into(self) -> RistrettoPoint {
        let compressed = CompressedRistretto(self.0);
        compressed.decompress().expect("Decompression failed")
    }
}

// JSON serializable struct for `sop`
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SopTuple {
    pub aj: String,  // Hex-encoded G1Projective
    pub bj: String,  // Hex-encoded G1Projective
    pub rj: SerializableRistrettoPoint,  // Serializable RistrettoPoint
}

// JSON serializable struct for `sunop`
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SunopTuple {
    pub Zj: String,    // Hex-encoded G1Projective
    pub stmt_j: (usize, String, String, String, String, String), // i, Aj, Bj, Zj, vk, mstar (all encoded as hex strings)
    pub wit_j: (String, String, String), // bj, sk, wit (all encoded as hex strings)
}

// Encrypt function updated to take `r` as input, while still returning (c1, c2, c3)
pub fn encrypt(ek: &RistrettoPoint, Aj_bj: G1Projective, r: DalekScalar, message: &[u8]) -> (SerializableRistrettoPoint, SerializableRistrettoPoint, Vec<u8>) {
    // Compute c1 = g^r (g is the basepoint of the Ristretto curve)
    let c1 = RISTRETTO_BASEPOINT_POINT * r;

    // Compute c2 = ek^r
    let ek_r = ek * r;
    
    // Compress c1 and c2 for storage
    let c1_compressed = c1.compress();
    let c2_compressed = ek_r.compress();

    // Convert G1Projective (Aj_bj) to G1Affine, then compress it
    let Aj_bj_affine: G1Affine = Aj_bj.into();
    let Aj_bj_compressed = Aj_bj_affine.to_compressed();

    // Hash Aj_bj to produce shared secret for message encryption
    let mut hasher = Sha512::new();
    hasher.update(Aj_bj_compressed.as_ref());
    let hash_output = hasher.finalize();

    // XOR the hash with the message to produce c3
    let hash_xor: Vec<u8> = hash_output.iter().cycle().take(message.len()).cloned().collect();
    let c3: Vec<u8> = hash_xor.iter().zip(message.iter()).map(|(&h, &m)| h ^ m).collect();

    (SerializableRistrettoPoint::from(c1_compressed), SerializableRistrettoPoint::from(c2_compressed), c3)
}

// Main `Enc` function
pub fn enc(
    sk: BLSScalar,       // BLS secret key
    vk: G1Projective,    // BLS verification key
    wit: BLSScalar,      // BLS signature on mstar
    lambda_s: usize,     // Security parameter
    mstar: &[u8],        // The message mstar
    ek: &RistrettoPoint  // Encryption key
) -> (Vec<(SerializableRistrettoPoint, SerializableRistrettoPoint, Vec<u8>)>, Vec<SopTuple>, Vec<SunopTuple>) {
    let mut csprng = OsRng;
    let mut ct_list: Vec<(SerializableRistrettoPoint, SerializableRistrettoPoint, Vec<u8>)> = Vec::new();  // For (ctj, Aj, Bj)
    let mut sop: Vec<SopTuple> = Vec::new();
    let mut sunop: Vec<SunopTuple> = Vec::new();

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
        let rj = random_dalek_scalar();  // Now using rj as input for encryption
        
        let Aj = G1Projective::generator() * aj;
        let Bj = G1Projective::generator() * bj;

        // Encrypt with rj included
        let (c1, c2, c3) = encrypt(ek, Aj * bj, rj, mstar);

        // Convert Aj and Bj to G1Affine before compression
        let Aj_affine: G1Affine = Aj.into();
        let Bj_affine: G1Affine = Bj.into();

        // Collect (ctj, Aj, Bj) in the list
        ct_list.push((c1, c2, c3));

        if j < lambda_s {
            // Collect in `sop`
            sop.push(SopTuple {
                aj: hex::encode(Aj_affine.to_compressed()),
                bj: hex::encode(Bj_affine.to_compressed()),
                rj: SerializableRistrettoPoint(rj.to_bytes()),  // Corrected to to_bytes() instead of compress
            });
        } else {
            // Compute Zj and collect in `sunop`
            let Zj = (Aj * bj) * wit;
            let Zj_affine: G1Affine = Zj.into();
            sunop.push(SunopTuple {
                Zj: hex::encode(Zj_affine.to_compressed()),
                stmt_j: (
                    j,
                    hex::encode(Aj_affine.to_compressed()),
                    hex::encode(Bj_affine.to_compressed()),
                    hex::encode(Zj_affine.to_compressed()),
                    hex::encode(G1Affine::from(vk).to_compressed()),  // Convert G1Projective to G1Affine, then compress
                    hex::encode(mstar)
                ),
                wit_j: (
                    hex::encode(bj.to_bytes()),
                    hex::encode(sk.to_bytes()),
                    hex::encode(wit.to_bytes())
                ),
            });
        }
    }

    (ct_list, sop, sunop)
}

// Test the serialization
fn main() {
    let sk = random_bls_scalar(); // BLS secret key
    let vk = G1Projective::generator() * sk; // BLS verification key
    let wit = random_bls_scalar(); // Witness (BLS signature)
    let lambda_s = 4;
    let mstar = b"Test 384-bit message";

    let ek = random_ristretto_point(); // Encryption key
    let (ct_list, sop, sunop) = enc(sk, vk, wit, lambda_s, mstar, &ek);

    // Serialize the result to JSON
    let ct_json = to_string(&ct_list).unwrap();
    let sop_json = to_string(&sop).unwrap();
    let sunop_json = to_string(&sunop).unwrap();

    println!("Serialized ct_list: {}", ct_json);
    println!("Serialized sop: {}", sop_json);
    println!("Serialized sunop: {}", sunop_json);

    // Deserialize back from JSON
    let ct_list_deserialized: Vec<(SerializableRistrettoPoint, SerializableRistrettoPoint, Vec<u8>)> = from_str(&ct_json).unwrap();
    let sop_deserialized: Vec<SopTuple> = from_str(&sop_json).unwrap();
    let sunop_deserialized: Vec<SunopTuple> = from_str(&sunop_json).unwrap();

    // Verify successful deserialization
    assert_eq!(ct_list, ct_list_deserialized);
    assert_eq!(sop, sop_deserialized);
    assert_eq!(sunop, sunop_deserialized);

    println!("Serialization and deserialization were successful!");
}
