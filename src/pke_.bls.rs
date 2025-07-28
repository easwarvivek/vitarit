use rand::Rng;
use sha2::{Sha384, Digest};
use bls12_381::{G1Projective, G1Affine, Scalar};

fn main() {
    // Original message
    let message = b"Your message here"; // Replace with actual message
    
    // Generator g
    let g = G1Projective::generator();

    // Generate key pair (ek, dk)
    let (ek, dk) = kgen(&g);
    println!("Public Key (ek): {:?}", ek);
    println!("Private Key (dk): {:?}", dk);

    // Encrypt the message
    let (c1, c2, c3) = encrypt_message(message, &g, &ek);
    println!("Encrypted data: c1 = {:?}, c2 = {:?}, c3 = {:?}", c1, c2, c3);

    // Decrypt the message
    let decrypted_message = decrypt_message(c1, c2, c3, &g, &dk);
    println!("Decrypted message: {:?}", String::from_utf8_lossy(&decrypted_message));

    // Check if encryption and decryption match
    if message == decrypted_message.as_slice() {
        println!("Encryption and decryption match!");
    } else {
        println!("Encryption and decryption do NOT match!");
    }
}

// Key Generation function (KGen)
fn kgen(g: &G1Projective) -> (G1Projective, Scalar) {
    let mut rng = rand::thread_rng();

    // Generate a random scalar as the private key (dk)
    let dk = Scalar::from_bytes_wide(&generate_random_64_bytes(&mut rng));

    // Compute the public key (ek) as g^dk
    let ek = g * dk;

    (ek, dk)
}

// Encryption function
fn encrypt_message(message: &[u8], g: &G1Projective, ek: &G1Projective) -> (G1Projective, G1Projective, Vec<u8>) {
    let mut rng = rand::thread_rng();

    // Generate random scalar values r and s
    let r = Scalar::from_bytes_wide(&generate_random_64_bytes(&mut rng));
    let s = Scalar::from_bytes_wide(&generate_random_64_bytes(&mut rng));

    // Compute c1 = g^r
    let c1 = g * r;

    // Compute c2 = g^s * ek^r
    let c2 = g * s + ek * r;

    // Compute hash of g^s
    let gs = g * s;
    let gs_affine = G1Affine::from(gs);
    let mut hasher = Sha384::new();
    hasher.update(gs_affine.to_compressed().as_ref());
    let hs = hasher.finalize();

    println!("Hash of gs during encryption: {:?}", hs);

    // XOR the message with the first bytes of the hash to get c3
    let mut c3 = vec![0u8; message.len()];
    for (i, byte) in message.iter().enumerate() {
        c3[i] = byte ^ hs[i % hs.len()];
    }

    (c1, c2, c3)
}

// Decryption function
fn decrypt_message(c1: G1Projective, c2: G1Projective, c3: Vec<u8>, g: &G1Projective, dk: &Scalar) -> Vec<u8> {
    // Recompute g^s = c2 - c1^dk (using c1 to compute ek^r)
    let ek_r = c1 * dk;
    let gs = c2 - ek_r;

    // Compute hash of g^s
    let gs_affine = G1Affine::from(gs);
    let mut hasher = Sha384::new();
    hasher.update(gs_affine.to_compressed().as_ref());
    let hs = hasher.finalize();

    println!("Hash of gs during decryption: {:?}", hs);

    // XOR c3 with the hash output to retrieve the original message
    let mut decrypted_message = vec![0u8; c3.len()];
    for (i, byte) in c3.iter().enumerate() {
        decrypted_message[i] = byte ^ hs[i % hs.len()];
    }

    decrypted_message
}

// Helper function to generate a 64-byte random array
fn generate_random_64_bytes(rng: &mut impl Rng) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    rng.fill(&mut bytes);
    bytes
}

