use crate::chunked_elgamal::ElGamalCiphertext;
use crate::errors::{InternalError, InvalidArgumentError, MalformedPublicKeyError};
use crate::nidkg_zk_chunk::ZkProofChunking;
use crate::nidkg_zk_share::ZkProofSharing;
use crate::public_coefficients::PublicCoefficients;

pub struct Dealing {
    pub public_coefficients: PublicCoefficients,
    pub ciphertexts: ElGamalCiphertext,
    pub zk_proof_decryptability: ZkProofChunking,
    pub zk_proof_correct_sharing: ZkProofSharing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NiDkgCreateDealingError {
    /// The threshold scheme does not support the supplied parameters.
    InvalidThresholdError(InvalidArgumentError),

    /// Precondition error: The receiver indices are invalid.  The receiver indices SHOULD be 0..n-1.
    MisnumberedReceiverError {
        receiver_index: usize,
        number_of_receivers: usize,
    },

    /// One of the receiver public keys is invalid.
    MalformedFsPublicKeyError {
        receiver_index: usize,
        error: MalformedPublicKeyError,
    },
    // An internal error, e.g. an RPC error.
    InternalError(InternalError),
}
