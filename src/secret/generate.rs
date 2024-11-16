//! Secret generation.

use rand::RngCore;

use crate::secret::length::Length;

/// Generates cryprographically secure random bytes of specified length.
pub fn generate(length: Length) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    let mut secret = vec![0; length.get()];

    rng.fill_bytes(&mut secret);

    secret
}
