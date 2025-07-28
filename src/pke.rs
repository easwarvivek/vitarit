extern crate curve25519_dalek;
extern crate sha2;
extern crate rand;
extern crate serde;
extern crate bincode;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT; // Correct import for the basepoint
use curve25519_dalek::traits::MultiscalarMul;
use sha2::{Sha512, Digest};
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};
use bincode::{serialize, deserialize};
use rand::Rng;

// Custom serializable version of CompressedRistretto
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SerializableCompressedRistretto(pub [u8; 32]);

impl From<CompressedRistretto> for SerializableCompressedRistretto {
    fn from(point: CompressedRistretto) -> Self {
        SerializableCompressedRistretto(point.to_bytes())
    }
}

impl Into<CompressedRistretto> for SerializableCompressedRistretto {
    fn into(self) -> CompressedRistretto {
        CompressedRistretto::from_slice(&self.0).expect("Failed to convert bytes into CompressedRistretto")
    }
}

// Custom serializable version of Scalar
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct SerializableScalar(pub [u8; 32]);

impl From<Scalar> for SerializableScalar {
    fn from(scalar: Scalar) -> Self {
        SerializableScalar(scalar.to_bytes())
    }
}

impl Into<Scalar> for SerializableScalar {
    fn into(self) -> Scalar {
        Scalar::from_bytes_mod_order(self.0)
    }
}

// Key Generation
pub struct KeyPair {
    pub ek: RistrettoPoint,
    pub dk: Scalar,
}

// Modified keygen function that generates ek = g^dk
pub fn keygen() -> KeyPair {
    let mut csprng = OsRng;
    let mut random_bytes = [0u8; 64];
    csprng.fill(&mut random_bytes);

    // Generate a random scalar `dk` (the decryption key)
    let dk = Scalar::from_bytes_mod_order_wide(&random_bytes);

    // Compute ek = g^dk where g is the base point of the Ristretto group
    let ek = RISTRETTO_BASEPOINT_POINT * dk;

    KeyPair { ek, dk }
}

// Encryption
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct CipherText {
    pub c1: SerializableCompressedRistretto,
    pub c2: SerializableCompressedRistretto,
    pub c3: Vec<u8>,
}

pub fn encrypt(ek: &RistrettoPoint, message: &[u8]) -> CipherText {
    let mut csprng = OsRng;
    let mut random_bytes_r = [0u8; 64];
    let mut random_bytes_s = [0u8; 64];
    csprng.fill(&mut random_bytes_r);
    csprng.fill(&mut random_bytes_s);

    // Generate random scalars r and s
    let r = Scalar::from_bytes_mod_order_wide(&random_bytes_r);
    let s = Scalar::from_bytes_mod_order_wide(&random_bytes_s);

    // Compute c1 = g^r (g is the basepoint of the Ristretto curve)
    let c1 = RISTRETTO_BASEPOINT_POINT * r;

    // Compute c2 = (ek^r) * (g^s)
    let ek_r = ek * r;  // ek^r
    let g_s = RISTRETTO_BASEPOINT_POINT * s;  // g^s
    let c2 = ek_r + g_s;  // (ek^r) * (g^s)

    // Compress c1 and c2 for storage
    let c1_compressed = c1.compress();
    let c2_compressed = c2.compress();

    // Compute the hash of g^s (the shared secret)
    let mut hasher = Sha512::new();
    hasher.update(g_s.compress().as_bytes());
    let hash_output = hasher.finalize();

    println!("Hash during encryption: {:?}", hash_output);

    // XOR the hash with the message to get c3
    let hash_xor: Vec<u8> = hash_output.iter().cycle().take(message.len()).cloned().collect();
    let c3: Vec<u8> = hash_xor.iter().zip(message.iter()).map(|(&h, &m)| h ^ m).collect();

    CipherText {
        c1: c1_compressed.into(),
        c2: c2_compressed.into(),
        c3,
    }
}

// Decryption
pub fn decrypt(dk: &Scalar, ciphertext: &CipherText) -> Vec<u8> {
    let c1_point: CompressedRistretto = ciphertext.c1.clone().into();
    let c2_point: CompressedRistretto = ciphertext.c2.clone().into();
    let c1_point = c1_point.decompress().expect("Decompression failed");
    let c2_point = c2_point.decompress().expect("Decompression failed");

    // Compute c1^dk
    let c1_dk = c1_point * dk;

    // Compute c2 / (c1^dk)
    let c1_dk_inverse = -c1_dk;  // Use the negation operator to invert the scalar multiplication
    let shared_point = c2_point + c1_dk_inverse; // c2 * (c1^dk)^-1

    // Hash the result
    let mut hasher = Sha512::new();
    hasher.update(shared_point.compress().as_bytes());
    let hash_output = hasher.finalize();

    println!("Hash during decryption: {:?}", hash_output);

    let hash_xor: Vec<u8> = hash_output.iter().cycle().take(ciphertext.c3.len()).cloned().collect();

    let decrypted_message: Vec<u8> = hash_xor.iter().zip(ciphertext.c3.iter()).map(|(&h, &c)| h ^ c).collect();

    decrypted_message
}

// Serialize CipherText
pub fn serialize_ciphertext(ciphertext: &CipherText) -> Vec<u8> {
    serialize(ciphertext).expect("Serialization failed")
}

// Deserialize CipherText
pub fn deserialize_ciphertext(data: &[u8]) -> CipherText {
    deserialize(data).expect("Deserialization failed")
}

// Test the correctness of the serialization/deserialization process
pub fn test_serialization(ciphertext: &CipherText) {
    let serialized = serialize_ciphertext(ciphertext);
    let deserialized: CipherText = deserialize_ciphertext(&serialized);

    assert_eq!(*ciphertext, deserialized);
    println!("Serialization and deserialization are successful and consistent!");
}

fn main() {
    // Example usage
    let keypair = keygen();

    // Generate a 384-bit (48-byte) message for testing
    let message: [u8; 48] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F
    ];

    let ciphertext = encrypt(&keypair.ek, &message);

    // Test serialization and deserialization
    test_serialization(&ciphertext);

    let decrypted_message = decrypt(&keypair.dk, &ciphertext);
    assert_eq!(message.to_vec(), decrypted_message);

    println!("Original message: {:?}", message);
    println!("Decrypted message: {:?}", decrypted_message);
    println!("Message successfully encrypted and decrypted!");
}
